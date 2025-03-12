import asyncio
import aiohttp
import re
import os
import json
import logging
import ipaddress
import io
from enum import Enum
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from collections import defaultdict
import uuid

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

# Константы
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
MIN_ACCEPTABLE_SCORE = 50.0  # Снижено, т.к. система весов переработана
MIN_CONFIG_LENGTH = 30
ALLOWED_PROTOCOLS = ["vless://", "ss://"]
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"


# --- КРАСИВОЕ ОФОРМЛЕНИЕ НАИМЕНОВАНИЯ ПРОФИЛЕЙ ---
class ProfileName(Enum):
    VLESS_FORMAT = "VLESS - {transport} - {security} - {encryption}"
    SS_FORMAT = "SS - {method}"
    UNKNOWN_FORMAT = "Неизвестный Протокол"


@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = None

    def __post_init__(self):
        if self.protocol_counts is None:
            self.protocol_counts = defaultdict(int)


class ChannelConfig:
    def __init__(self, url: str, request_timeout: int = REQUEST_TIMEOUT):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = request_timeout
        self.check_count = 0

    def _validate_url(self, url: str) -> str:
        if not isinstance(url, str):
            raise ValueError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        if not url:
            raise ValueError("URL не может быть пустым.")

        valid_protocols = ('http://', 'https://', 'vless://', 'ss://')
        if not any(url.startswith(proto) for proto in valid_protocols):
            raise ValueError(
                f"Неверный протокол URL. Ожидается: {', '.join(valid_protocols)}, "
                f"получено: {url[:url.find('://') + 3] if '://' in url else url[:10]}..."
            )
        return url

    def calculate_overall_score(self):
        """Вычисляет общий рейтинг канала."""
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = round(
                (success_ratio * ScoringWeights.CHANNEL_STABILITY.value) +
                recency_bonus + response_time_penalty, 2
            )
            self.metrics.overall_score = max(0, self.metrics.overall_score)

        except Exception as e:
            logger.error(f"Ошибка при расчете рейтинга для {self.url}: {e}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        total_checks = self.metrics.success_count + self.metrics.fail_count
        return self.metrics.success_count / total_checks if total_checks > 0 else 0.0

    def _calculate_recency_bonus(self) -> float:
        if self.metrics.last_success_time:
            time_since_last_success = datetime.now() - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0.0
        return 0.0

    def _calculate_response_time_penalty(self) -> float:
        return self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value if self.metrics.avg_response_time > 0 else 0.0

    def update_channel_stats(self, success: bool, response_time: float = 0.0):
        if not isinstance(success, bool):
            raise TypeError(f"Аргумент 'success' должен быть bool, получено {type(success)}")
        if not isinstance(response_time, (int, float)):
            raise TypeError(f"Аргумент 'response_time' должен быть числом, получено {type(response_time)}")

        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
        else:
            self.metrics.fail_count += 1

        if response_time > 0:
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * 0.7) + (response_time * 0.3)
                if self.metrics.avg_response_time
                else response_time
            )

        self.calculate_overall_score()


class ProxyConfig:
    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)

        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except ValueError as e:
                            logger.warning(f"Неверный URL в {ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"Файл URL не найден: {ALL_URLS_FILE}.  Создается пустой файл.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE

    def _normalize_url(self, url: str) -> str:
        if not url:
            raise ValueError("URL не может быть пустым для нормализации.")
        url = url.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            raise ValueError(f"Отсутствует схема в URL: '{url}'. Ожидается 'http://' или 'https://'.")
        if not parsed.netloc:
            raise ValueError(f"Отсутствует netloc (домен или IP) в URL: '{url}'.")

        path = parsed.path.rstrip('/')
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        seen_urls = set()
        unique_configs = []
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                logger.warning(f"Неверная конфигурация пропущена: {config}")
                continue
            try:
                normalized_url = self._normalize_url(config.url)
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
            except Exception:
                continue

        if not unique_configs:
            self.save_empty_config_file()
            logger.error("Не найдено валидных источников. Создан пустой файл конфигурации.")
            return []

        return unique_configs

    def get_enabled_channels(self) -> List[ChannelConfig]:
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {e}")
            return False


class ScoringWeights(Enum):
    """
    Полностью переработанные веса для скоринга.  Разделены на категории.
    """
    # --- Общие веса ---
    PROTOCOL_BASE = 20  # Базовый вес за поддерживаемый протокол
    CONFIG_LENGTH = 5   # Вес за длину конфигурации (меньше вес)
    RESPONSE_TIME = -0.1 # Штраф за время отклика

    # --- Веса канала (влияют на рейтинг канала, а не профиля) ---
    CHANNEL_STABILITY = 15 # Стабильность канала (расчитывается отдельно)

    # --- VLESS-специфичные веса ---
    VLESS_SECURITY_TLS = 15
    VLESS_SECURITY_NONE = -10
    VLESS_TRANSPORT_WS = 10
    VLESS_TRANSPORT_TCP = 2
    VLESS_ENCRYPTION_NONE = -5
    VLESS_ENCRYPTION_AUTO = 5
    VLESS_ENCRYPTION_AES_128_GCM = 8
    VLESS_ENCRYPTION_CHACHA20_POLY1305 = 8
    VLESS_UUID_PRESENT = 5
    VLESS_EARLY_DATA = 3
    VLESS_SNI_PRESENT = 7
    VLESS_ALPN_PRESENT = 5
    VLESS_PATH_PRESENT = 3

    # --- SS-специфичные веса ---
    SS_METHOD_CHACHA20_IETF_POLY1305 = 15
    SS_METHOD_AES_256_GCM = 14
    SS_METHOD_AES_128_GCM = 12
    SS_METHOD_NONE = -20  # Очень большой штраф
    SS_PASSWORD_LENGTH = 5 # За длину пароля
    SS_PLUGIN_OBFS_TLS = 10
    SS_PLUGIN_OBFS_HTTP = 8
    SS_PLUGIN_NONE = 0 # Если плагина нет

    # --- Общие для VLESS и SS ---
    COMMON_PORT_443 = 10
    COMMON_PORT_80 = 5
    COMMON_PORT_OTHER = 2
    COMMON_UTLS_CHROME = 7 # Наиболее желательный uTLS
    COMMON_UTLS_FIREFOX = 6
    COMMON_UTLS_RANDOMIZED = 5
    COMMON_UTLS_OTHER = 2
    COMMON_IPV6 = -5 # Небольшой штраф за IPv6
    COMMON_CDN = 8 # Если используется CDN
    COMMON_OBFS = 4 # Поддержка OBFS
    COMMON_HEADERS = 3 # Наличие заголовков
    COMMON_RARE_PARAM = 4  # Бонус за редкие параметры
    COMMON_HIDDEN_PARAM = 2 # Бонус за скрытые параметры

    @staticmethod
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> None:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    try:
                        ScoringWeights[name].value = value
                    except KeyError:
                        logger.warning(f"Неизвестный вес скоринга в файле: {name}. Вес проигнорирован.")
                    except ValueError:
                        logger.error(f"Неверное значение веса для {name}: {value}. Используется значение по умолчанию.")
        except FileNotFoundError:
            logger.warning(f"Файл весов скоринга не найден: {file_path}. Используются значения по умолчанию.")
            ScoringWeights._create_default_weights_file(file_path)
        except json.JSONDecodeError:
            logger.error(f"Ошибка чтения JSON файла весов: {file_path}. Используются значения по умолчанию.")
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при загрузке весов скоринга из {file_path}: {e}. Используются значения по умолчанию.")

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = {member.name: member.value for member in ScoringWeights}
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Создан файл весов скоринга по умолчанию: {file_path}")
        except Exception as e:
            logger.error(f"Ошибка создания файла весов скоринга по умолчанию: {e}")

ScoringWeights.load_weights_from_json()

def _get_value(query: Dict, key: str, default_value: Any = None) -> Any:
    """Вспомогательная функция для безопасного получения значений из query."""
    return query.get(key, [default_value])[0]

def _calculate_vless_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет оценку для VLESS-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += ScoringWeights.VLESS_SECURITY_TLS.value if security == 'tls' else ScoringWeights.VLESS_SECURITY_NONE.value

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'tcp').lower()
    score += ScoringWeights.VLESS_TRANSPORT_WS.value if transport == 'ws' else ScoringWeights.VLESS_TRANSPORT_TCP.value

    # --- Шифрование ---
    encryption = _get_value(query, 'encryption', 'none').lower()
    score += {
        'none': ScoringWeights.VLESS_ENCRYPTION_NONE.value,
        'auto': ScoringWeights.VLESS_ENCRYPTION_AUTO.value,
        'aes-128-gcm': ScoringWeights.VLESS_ENCRYPTION_AES_128_GCM.value,
        'chacha20-poly1305': ScoringWeights.VLESS_ENCRYPTION_CHACHA20_POLY1305.value
    }.get(encryption, 0)

    # --- Другие параметры VLESS ---
    if parsed.username:
        score += ScoringWeights.VLESS_UUID_PRESENT.value
    if _get_value(query, 'earlyData') == '1':
        score += ScoringWeights.VLESS_EARLY_DATA.value
    if _get_value(query, 'sni'):
        score += ScoringWeights.VLESS_SNI_PRESENT.value
    if _get_value(query, 'alpn'):
        score += ScoringWeights.VLESS_ALPN_PRESENT.value
    if _get_value(query, 'path'):
        score += ScoringWeights.VLESS_PATH_PRESENT.value

    return score


def _calculate_ss_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет оценку для SS-профиля."""
    score = 0

    # --- Метод шифрования ---
    method = parsed.username.lower() if parsed.username else 'none'
    score += {
        'chacha20-ietf-poly1305': ScoringWeights.SS_METHOD_CHACHA20_IETF_POLY1305.value,
        'aes-256-gcm': ScoringWeights.SS_METHOD_AES_256_GCM.value,
        'aes-128-gcm': ScoringWeights.SS_METHOD_AES_128_GCM.value,
        'none': ScoringWeights.SS_METHOD_NONE.value
    }.get(method, 0)

    # --- Длина пароля ---
    score += min(ScoringWeights.SS_PASSWORD_LENGTH.value, len(parsed.password or '') / 16 * ScoringWeights.SS_PASSWORD_LENGTH.value) if parsed.password else 0

     # --- Плагин ---
    plugin = _get_value(query, 'plugin', 'none').lower()
    if plugin != 'none':
        score += {
            'obfs-http': ScoringWeights.SS_PLUGIN_OBFS_HTTP.value,
            'obfs-tls': ScoringWeights.SS_PLUGIN_OBFS_TLS.value
        }.get(plugin, 0)
    else:
        score += ScoringWeights.SS_PLUGIN_NONE.value


    return score


def _calculate_common_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет общую оценку, применимую к обоим протоколам."""
    score = 0

    # --- Порт ---
    score += {
        443: ScoringWeights.COMMON_PORT_443.value,
        80: ScoringWeights.COMMON_PORT_80.value
    }.get(parsed.port, ScoringWeights.COMMON_PORT_OTHER.value)

    # --- uTLS ---
    utls = _get_value(query, 'utls', _get_value(query, 'fp', 'none')).lower()
    score += {
        'chrome': ScoringWeights.COMMON_UTLS_CHROME.value,
        'firefox': ScoringWeights.COMMON_UTLS_FIREFOX.value,
        'randomized': ScoringWeights.COMMON_UTLS_RANDOMIZED.value
    }.get(utls, ScoringWeights.COMMON_UTLS_OTHER.value)

    # --- IPv6 ---
    if ':' in parsed.hostname:
        score += ScoringWeights.COMMON_IPV6.value

    # --- CDN ---
    if _get_value(query, 'sni') and '.cdn.' in _get_value(query, 'sni'):
        score += ScoringWeights.COMMON_CDN.value

   # --- OBFS ---
    if _get_value(query, 'obfs'):
        score += ScoringWeights.COMMON_OBFS.value

    # --- Заголовки ---
    if _get_value(query, 'headers'):
        score += ScoringWeights.COMMON_HEADERS.value

    # --- Редкие и скрытые параметры ---
    known_params = (
    'security', 'type', 'encryption', 'sni', 'alpn', 'path',
    'headers', 'fp', 'utls',
    'earlyData', 'id', 'method', 'plugin',
    'bufferSize', 'tcpFastOpen', 'obfs', 'debug', 'comment'
    )
    for key, value in query.items():
        if key not in known_params:
            score += ScoringWeights.COMMON_HIDDEN_PARAM.value
            if value and value[0]:
                score += min(ScoringWeights.COMMON_RARE_PARAM.value,
                             ScoringWeights.COMMON_RARE_PARAM.value / len(value[0]))


    return score



def compute_profile_score(config: str, response_time: float = 0.0) -> float:
    """
    Вычисляет общий рейтинг профиля (новая, переработанная функция).
    """
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
    except Exception as e:
        logger.error(f"Ошибка парсинга URL {config}: {e}")
        return 0.0

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    score = ScoringWeights.PROTOCOL_BASE.value  # Базовый вес за протокол
    score += _calculate_common_score(parsed, query)  # Общие веса
    score += response_time * ScoringWeights.RESPONSE_TIME.value # Время отклика (штраф)
    score += min(ScoringWeights.CONFIG_LENGTH.value, (len(config) / 200.0) * ScoringWeights.CONFIG_LENGTH.value)


    if protocol == "vless://":
        score += _calculate_vless_score(parsed, query)
    elif protocol == "ss://":
        score += _calculate_ss_score(parsed, query)


    return round(score, 2)

def generate_custom_name(config: str) -> str:
    """Генерирует кастомное имя для профиля прокси."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return ProfileName.UNKNOWN_FORMAT.value

    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)

        if parsed.scheme == "vless":
            transport_type = query.get("type", ["tcp"])[0].upper()
            security_type = query.get("security", ["none"])[0].upper()
            encryption_type = query.get("encryption", ["none"])[0].upper()
            return ProfileName.VLESS_FORMAT.value.format(
                transport=transport_type, security=security_type, encryption=encryption_type
            )

        elif parsed.scheme == "ss":
            method = parsed.username.upper() if parsed.username else "UNKNOWN"
            return ProfileName.SS_FORMAT.value.format(method=method)


        return ProfileName.UNKNOWN_FORMAT.value

    except Exception as e:
        logger.error(f"Ошибка создания пользовательского имени для {config}: {e}")
        return "Неизвестный Прокси"



def is_valid_uuid(uuid_string: str) -> bool:
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        return False


def is_valid_ipv4(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_proxy_url(url: str) -> bool:
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.port:
            return False
        if not is_valid_ipv4(parsed.hostname) and ":" not in parsed.hostname:
            return False
        if parsed.scheme == 'vless':
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False
        return True
    except ValueError:
        return False


def create_profile_key(config: str) -> str:
    try:
        parsed = urlparse(config)
        if parsed.scheme == 'ss':
            return f"ss://{parsed.username}:{parsed.password}@{parsed.hostname}:{parsed.port}"
        else:  # vless
            match = DUPLICATE_PROFILE_REGEX.match(config)
            if match:
                protocol, host, port = match.groups()
                return f"{protocol}://{host}:{port}"
            else:
                return config

    except Exception as e:
        logger.error(f"Ошибка создания ключа профиля для {config}: {e}")
        return config

DUPLICATE_PROFILE_REGEX = re.compile(
    r"^(vless|ss)://(?:.*?@)?([^@/:]+):(\d+)"
)


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession,
                          channel_semaphore: asyncio.Semaphore,
                          existing_profiles: set,
                          proxy_config: "ProxyConfig") -> List[Dict]:
    proxies = []
    async with channel_semaphore:
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(channel.url, timeout=channel.request_timeout) as response:
                if response.status != 200:
                    logger.error(f"Канал {channel.url} вернул статус {response.status}")
                    channel.check_count += 1
                    channel.update_channel_stats(success=False)
                    return proxies

                text = await response.text()
                end_time = asyncio.get_event_loop().time()
                response_time = end_time - start_time
                logger.info(f"Контент из {channel.url} загружен за {response_time:.2f} секунд")
                channel.update_channel_stats(success=True, response_time=response_time)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Ошибка загрузки из {channel.url}: {type(e).__name__} - {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies
        except Exception as e:
            logger.exception(f"Непредвиденная ошибка при загрузке из {channel.url}: {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies

        lines = text.splitlines()
        valid_configs_from_channel = 0
        for line in lines:
            line = line.strip()
            if len(line) < MIN_CONFIG_LENGTH:
                continue

            if not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
                continue

            protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)
            if not protocol:
                continue

            try:
                if not is_valid_proxy_url(line):
                    logger.debug(f"Профиль {line} пропущен из-за неверного формата URL прокси.")
                    continue

                parsed = urlparse(line)
                if parsed.scheme == 'vless':
                    profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
                    if profile_id and not is_valid_uuid(profile_id):
                        logger.debug(f"Профиль {line} пропущен из-за неверного формата UUID: {profile_id}")
                        continue

            except ValueError as e:
                logger.debug(f"Ошибка парсинга URL {line}: {e}")
                continue

            profile_key = create_profile_key(line)
            if profile_key in existing_profiles:
                logger.debug(f"Дубликат профиля найден и пропущен: {line}")
                continue
            existing_profiles.add(profile_key)

            score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)

            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                valid_configs_from_channel += 1

        channel.metrics.valid_configs += valid_configs_from_channel
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(existing_profiles)

        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {valid_configs_from_channel} валидных конфигураций.")
        return proxies


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles = set()

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles, proxy_config) for channel
                 in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка при обработке канала: {result}")
            else:
                proxies_all.extend(result)

    return proxies_all


def save_final_configs(proxies: List[Dict], output_file: str):
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True)

    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies_sorted:
                if proxy['score'] > MIN_ACCEPTABLE_SCORE:
                    config = proxy['config'].split('#')[0].strip()
                    profile_name = generate_custom_name(config)
                    final_line = f"{config}# {profile_name}\n"
                    f.write(final_line)
        logger.info(f"Финальные конфигурации сохранены в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")


def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()

    async def runner():
        proxies = await process_all_channels(channels, proxy_config)
        save_final_configs(proxies, proxy_config.OUTPUT_FILE)

        total_channels = len(channels)
        enabled_channels = sum(1 for channel in channels)
        disabled_channels = total_channels - enabled_channels
        total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)
        total_unique_configs = sum(channel.metrics.unique_configs for channel in channels)
        total_successes = sum(channel.metrics.success_count for channel in channels)
        total_fails = sum(channel.metrics.fail_count for channel in channels)

        protocol_stats = defaultdict(int)
        for channel in channels:
            for protocol, count in channel.metrics.protocol_counts.items():
                protocol_stats[protocol] += count

        logger.info("================== СТАТИСТИКА ==================")
        logger.info(f"Всего каналов: {total_channels}")
        logger.info(f"Включено каналов: {enabled_channels}")
        logger.info(f"Отключено каналов: {disabled_channels}")
        logger.info(f"Всего валидных конфигураций: {total_valid_configs}")
        logger.info(f"Всего уникальных конфигураций: {total_unique_configs}")
        logger.info(f"Всего успешных загрузок: {total_successes}")
        logger.info(f"Всего неудачных загрузок: {total_fails}")
        logger.info("Статистика по протоколам:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")
        logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")

    asyncio.run(runner())


if __name__ == "__main__":
    main()
