import asyncio
import aiohttp
import re
import os
import json
import logging
import ipaddress
import io
from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import uuid
import numbers
import functools
import string

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

# Константы
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
MIN_ACCEPTABLE_SCORE = 50.0
MIN_CONFIG_LENGTH = 30
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://"]
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"


# --- КРАСИВОЕ ОФОРМЛЕНИЕ НАИМЕНОВАНИЯ ПРОФИЛЕЙ ---
class ProfileName(Enum):
    VLESS_FORMAT = "🌌 VLESS - {transport}{security_sep}{security}{encryption_sep}{encryption}"
    VLESS_WS_TLS_CHACHA20 = "🚀 VLESS - WS - TLS - CHACHA20"
    SS_FORMAT = "🎭 SS - {method}"
    SS_CHACHA20_IETF_POLY1305 = "🛡️ SS - CHACHA20-IETF-POLY1305"
    TROJAN_FORMAT = "🗡️ Trojan - {transport} - {security}"
    TROJAN_WS_TLS = "⚔️ Trojan - WS - TLS"
    TUIC_FORMAT = "🐢 TUIC - {transport} - {security} - {congestion_control}"
    TUIC_WS_TLS_BBR = "🐇 TUIC - WS - TLS - BBR"
    HY2_FORMAT = "💧 HY2 - {transport} - {security}"
    HY2_UDP_TLS = "🐳 HY2 - UDP - TLS"


@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = field(
        default_factory=lambda: defaultdict(int))  # Исправлено: используем default_factory


class ChannelConfig:
    RESPONSE_TIME_DECAY = 0.7
    VALID_PROTOCOLS = ["http://", "https://", "vless://", "ss://", "trojan://", "tuic://", "hy2://"]

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

        # Проверка на повторяющиеся символы:
        if re.search(r'(.)\1{100,}', url):  # Ищем 100+ повторений одного символа
            raise ValueError("URL содержит слишком много повторяющихся символов.")

        parsed = urlsplit(url)
        if parsed.scheme not in [p.replace('://', '') for p in self.VALID_PROTOCOLS]:
            raise ValueError(
                f"Неверный протокол URL. Ожидается: {', '.join(self.VALID_PROTOCOLS)}, "
                f"получено: {parsed.scheme}..." if parsed.scheme else f"получено: {url[:10]}..."
            )
        return url

    def calculate_overall_score(self):
        """Вычисляет общий рейтинг канала."""
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = max(0, round(
                (success_ratio * ScoringWeights.CHANNEL_STABILITY.value) +
                recency_bonus + response_time_penalty, 2
            ))

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
        if not isinstance(response_time, numbers.Real):
            raise TypeError(f"Аргумент 'response_time' должен быть числом, получено {type(response_time)}")

        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
        else:
            self.metrics.fail_count += 1

        if response_time > 0:
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * self.RESPONSE_TIME_DECAY) + (
                        response_time * (1 - self.RESPONSE_TIME_DECAY))
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

        if not all(c in (string.ascii_letters + string.digits + '.-:') for c in parsed.netloc):
            raise ValueError(f"Недопустимые символы в netloc URL: '{parsed.netloc}'")

        path = parsed.path.rstrip('/')
        return parsed._replace(path=path).geturl()

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
    CONFIG_LENGTH = 5  # Вес за длину конфигурации (меньше вес)
    RESPONSE_TIME = -0.1  # Штраф за время отклика

    # --- Веса канала (влияют на рейтинг канала, а не профиля) ---
    CHANNEL_STABILITY = 15  # Стабильность канала (расчитывается отдельно)

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
    SS_PASSWORD_LENGTH = 5  # За длину пароля
    SS_PLUGIN_OBFS_TLS = 10
    SS_PLUGIN_OBFS_HTTP = 8
    SS_PLUGIN_NONE = 0  # Если плагина нет

    # --- Trojan-специфичные веса ---
    TROJAN_SECURITY_TLS = 15
    TROJAN_TRANSPORT_WS = 10
    TROJAN_TRANSPORT_TCP = 2
    TROJAN_PASSWORD_LENGTH = 5
    TROJAN_SNI_PRESENT = 7
    TROJAN_ALPN_PRESENT = 5
    TROJAN_EARLY_DATA = 3

    # --- TUIC-специфичные веса ---
    TUIC_SECURITY_TLS = 15
    TUIC_TRANSPORT_WS = 10
    TUIC_TRANSPORT_UDP = 5  # UDP изначально поддерживается
    TUIC_CONGESTION_CONTROL_BBR = 8
    TUIC_CONGESTION_CONTROL_CUBIC = 5
    TUIC_CONGESTION_CONTROL_NEW_RENO = 3  # Менее предпочтительный
    TUIC_UUID_PRESENT = 5
    TUIC_PASSWORD_LENGTH = 5
    TUIC_SNI_PRESENT = 7
    TUIC_ALPN_PRESENT = 5
    TUIC_EARLY_DATA = 3
    TUIC_UDP_RELAY_MODE = 7  # Поддержка UDP relay
    TUIC_ZERO_RTT_HANDSHAKE = 6  # 0-RTT handshake

    # --- HY2-специфичные веса ---
    HY2_SECURITY_TLS = 15
    HY2_TRANSPORT_UDP = 5  # UDP изначально поддерживается
    HY2_TRANSPORT_TCP = 2  # Поддержка TCP (менее желательна)
    HY2_PASSWORD_LENGTH = 5
    HY2_SNI_PRESENT = 7
    HY2_ALPN_PRESENT = 5
    HY2_EARLY_DATA = 3
    HY2_PMTUD_ENABLED = 4  # Path MTU Discovery
    HY2_HOP_INTERVAL = 2  # За каждый интервал

    # --- Общие для VLESS, SS, Trojan, TUIC, HY2 ---
    COMMON_PORT_443 = 10
    COMMON_PORT_80 = 5
    COMMON_PORT_OTHER = 2
    COMMON_UTLS_CHROME = 7  # Наиболее желательный uTLS
    COMMON_UTLS_FIREFOX = 6
    COMMON_UTLS_RANDOMIZED = 5
    COMMON_UTLS_OTHER = 2
    COMMON_IPV6 = -5  # Небольшой штраф за IPv6
    COMMON_CDN = 8  # Если используется CDN
    COMMON_OBFS = 4  # Поддержка OBFS
    COMMON_HEADERS = 3  # Наличие заголовков
    COMMON_RARE_PARAM = 4  # Бонус за редкие параметры
    COMMON_HIDDEN_PARAM = 2  # Бонус за скрытые параметры

    @staticmethod
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> None:
        all_weights_loaded_successfully = True  # Флаг
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    try:
                        if not isinstance(value, (int, float)):  # Проверка типа
                            raise ValueError(f"Неверное значение веса (должно быть числом) для {name}: {value}")
                        ScoringWeights[name].value = value
                    except (KeyError, ValueError) as e:
                        logger.warning(f"Ошибка при загрузке веса {name}: {e}. Вес проигнорирован.")
                        all_weights_loaded_successfully = False  # Устанавливаем флаг
        except FileNotFoundError:
            logger.warning(f"Файл весов скоринга не найден: {file_path}. Используются значения по умолчанию.")
            all_weights_loaded_successfully = False  # Устанавливаем флаг
        except json.JSONDecodeError:
            logger.error(f"Ошибка чтения JSON файла весов: {file_path}. Используются значения по умолчанию.")
            all_weights_loaded_successfully = False
        except Exception as e:
            logger.error(
                f"Непредвиденная ошибка при загрузке весов скоринга из {file_path}: {e}. Используются значения по умолчанию.")
            all_weights_loaded_successfully = False

        if not all_weights_loaded_successfully:
            ScoringWeights._create_default_weights_file(file_path)  # Создаем файл, если были ошибки

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
            # sys.exit(1)


def _get_value(query: Dict, key: str, default_value: Any = None) -> Any:
    """Вспомогательная функция для безопасного получения значений из query."""
    return query.get(key, (default_value,))[0]


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
    score += min(ScoringWeights.SS_PASSWORD_LENGTH.value,
                 len(parsed.password or '') / 16 * ScoringWeights.SS_PASSWORD_LENGTH.value) if parsed.password else 0

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


def _calculate_trojan_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет оценку для Trojan-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()  # Должен быть tls
    score += ScoringWeights.TROJAN_SECURITY_TLS.value if security == 'tls' else 0  # Нет штрафа, просто 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'tcp').lower()
    score += ScoringWeights.TROJAN_TRANSPORT_WS.value if transport == 'ws' else ScoringWeights.TROJAN_TRANSPORT_TCP.value

    # --- Длина пароля ---
    score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH.value,
                 len(parsed.password or '') / 16 * ScoringWeights.TROJAN_PASSWORD_LENGTH.value) if parsed.password else 0

    # --- Другие параметры Trojan ---
    if _get_value(query, 'sni'):
        score += ScoringWeights.TROJAN_SNI_PRESENT.value
    if _get_value(query, 'alpn'):
        score += ScoringWeights.TROJAN_ALPN_PRESENT.value
    if _get_value(query, 'earlyData') == '1':
        score += ScoringWeights.TROJAN_EARLY_DATA.value

    return score


def _calculate_tuic_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет оценку для TUIC-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += ScoringWeights.TUIC_SECURITY_TLS.value if security == 'tls' else 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'udp').lower()  # Должен быть udp (или ws)
    score += ScoringWeights.TUIC_TRANSPORT_WS.value if transport == 'ws' else ScoringWeights.TUIC_TRANSPORT_UDP.value

    # --- Управление перегрузкой ---
    congestion_control = _get_value(query, 'congestion', 'bbr').lower()
    score += {
        'bbr': ScoringWeights.TUIC_CONGESTION_CONTROL_BBR.value,
        'cubic': ScoringWeights.TUIC_CONGESTION_CONTROL_CUBIC.value,
        'new-reno': ScoringWeights.TUIC_CONGESTION_CONTROL_NEW_RENO.value
    }.get(congestion_control, 0)

    # --- Другие параметры TUIC ---
    if parsed.username:  # UUID
        score += ScoringWeights.TUIC_UUID_PRESENT.value
    score += min(ScoringWeights.TUIC_PASSWORD_LENGTH.value,
                 len(parsed.password or '') / 16 * ScoringWeights.TUIC_PASSWORD_LENGTH.value) if parsed.password else 0
    if _get_value(query, 'sni'):
        score += ScoringWeights.TUIC_SNI_PRESENT.value
    if _get_value(query, 'alpn'):
        score += ScoringWeights.TUIC_ALPN_PRESENT.value
    if _get_value(query, 'earlyData') == '1':
        score += ScoringWeights.TUIC_EARLY_DATA.value
    if _get_value(query, 'udp_relay_mode', 'quic').lower() == 'quic':
        score += ScoringWeights.TUIC_UDP_RELAY_MODE.value
    if _get_value(query, 'zero_rtt_handshake') == '1':
        score += ScoringWeights.TUIC_ZERO_RTT_HANDSHAKE.value
    return score


def _calculate_hy2_score(parsed: urlparse, query: Dict) -> float:
    """Вычисляет оценку для HY2-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += ScoringWeights.HY2_SECURITY_TLS.value if security == 'tls' else 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'udp').lower()
    score += ScoringWeights.HY2_TRANSPORT_UDP.value if transport == 'udp' else ScoringWeights.HY2_TRANSPORT_TCP.value

    # --- Другие параметры HY2 ---
    score += min(ScoringWeights.HY2_PASSWORD_LENGTH.value,
                 len(parsed.password or '') / 16 * ScoringWeights.HY2_PASSWORD_LENGTH.value) if parsed.password else 0
    if _get_value(query, 'sni'):
        score += ScoringWeights.HY2_SNI_PRESENT.value
    if _get_value(query, 'alpn'):
        score += ScoringWeights.HY2_ALPN_PRESENT.value
    if _get_value(query, 'earlyData') == '1':
        score += ScoringWeights.HY2_EARLY_DATA.value
    if _get_value(query, 'pmtud') == '1':
        score += ScoringWeights.HY2_PMTUD_ENABLED.value

    # hopInterval (мульти-хоп)
    hop_interval = _get_value(query, 'hopInterval', None)
    if hop_interval:
        try:
            score += int(hop_interval) * ScoringWeights.HY2_HOP_INTERVAL.value  # Добавляем за каждый hop
        except ValueError:
            pass  # Игнорируем, если не число

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
    utls = _get_value(query, 'utls', None) or _get_value(query, 'fp', 'none')
    utls = utls.lower()
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
    known_params_general = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls', 'earlyData', 'id', 'method',
        'plugin', 'congestion', 'udp_relay_mode', 'zero_rtt_handshake', 'pmtud', 'hopInterval',
        'bufferSize', 'tcpFastOpen', 'obfs', 'debug', 'comment'
    )

    for key, value in query.items():
        if key not in known_params_general:
            score += ScoringWeights.COMMON_HIDDEN_PARAM.value
            if value and value[0]:
                score += min(ScoringWeights.COMMON_RARE_PARAM.value,
                             ScoringWeights.COMMON_RARE_PARAM.value / len(value[0]))

    return score


def compute_profile_score(config: str, channel_response_time: float = 0.0) -> float:
    """
    Вычисляет общий рейтинг профиля (новая, переработанная функция).
    """
    parse_cache: Dict[str, Tuple[urlparse, Dict]] = {}  # Кеш

    try:
        if config in parse_cache:
            parsed, query = parse_cache[config]
        else:
            parsed = urlparse(config)
            query = parse_qs(parsed.query)
            parse_cache[config] = (parsed, query)  # Сохраняем в кеш
    except Exception as e:
        logger.error(f"Ошибка парсинга URL {config}: {e}")
        return 0.0

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    score = ScoringWeights.PROTOCOL_BASE.value  # Базовый вес за протокол
    score += _calculate_common_score(parsed, query)  # Общие веса
    score += channel_response_time * ScoringWeights.RESPONSE_TIME.value  # Время отклика (штраф)
    score += min(ScoringWeights.CONFIG_LENGTH.value,
                 (len(config) / 200.0) * ScoringWeights.CONFIG_LENGTH.value)

    if protocol == "vless://":
        score += _calculate_vless_score(parsed, query)
    elif protocol == "ss://":
        score += _calculate_ss_score(parsed, query)
    elif protocol == "trojan://":
        score += _calculate_trojan_score(parsed, query)
    elif protocol == "tuic://":
        score += _calculate_tuic_score(parsed, query)
    elif protocol == "hy2://":
        score += _calculate_hy2_score(parsed, query)

    return round(score, 2)


def generate_custom_name(parsed: urlparse, query: Dict) -> str:
    """Генерирует кастомное имя для профиля прокси."""
    if parsed.scheme == "vless":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["none"])[0].upper()
        encryption_type = query.get("encryption", ["none"])[0].upper()

        if transport_type == "WS" and security_type == "TLS" and encryption_type == "CHACHA20":
            return ProfileName.VLESS_WS_TLS_CHACHA20.value
        # elif transport_type == "TCP" and security_type == "NONE" and encryption_type == "NONE": # Убрали
        #     return ProfileName.VLESS_TCP_NONE_NONE.value
        else:
            #  "🌌 VLESS - {transport}{security_sep}{security}{encryption_sep}{encryption}"
            security_sep = " - " if security_type != "NONE" else ""
            encryption_sep = " - " if encryption_type != "NONE" else ""

            return ProfileName.VLESS_FORMAT.value.format(
                transport=transport_type,
                security_sep=security_sep,
                security=security_type,
                encryption_sep=encryption_sep,
                encryption=encryption_type
            )

    elif parsed.scheme == "ss":
        method = quote_plus(parsed.username.upper() if parsed.username else "UNKNOWN")  # Экранируем
        if method == "CHACHA20-IETF-POLY1305":
            return ProfileName.SS_CHACHA20_IETF_POLY1305.value
        else:
            return ProfileName.SS_FORMAT.value.format(method=method)

    elif parsed.scheme == "trojan":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.TROJAN_WS_TLS.value
        else:
            return ProfileName.TROJAN_FORMAT.value.format(transport=transport_type, security=security_type)

    elif parsed.scheme == "tuic":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper
        congestion_control = query.get("congestion", ["bbr"])[0].upper()

        if transport_type == "WS" and security_type == "TLS" and congestion_control == "BBR":
            return ProfileName.TUIC_WS_TLS_BBR.value
        else:
            return ProfileName.TUIC_FORMAT.value.format(
                transport=transport_type,
                security=security_type,
                congestion_control=congestion_control
            )

    elif parsed.scheme == "hy2":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()

        if transport_type == "UDP" and security_type == "TLS":
            return ProfileName.HY2_UDP_TLS.value
        else:
            return ProfileName.HY2_FORMAT.value.format(transport=transport_type, security=security_type)

    else:
        return f"⚠️ Unknown Protocol: {parsed.scheme}" #информативное сообщение


@functools.lru_cache(maxsize=None)
def is_valid_ipv4(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


@functools.lru_cache(maxsize=None)
def is_valid_ipv6(hostname: str) -> bool:
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_proxy_url(url: str) -> bool:
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme in ('vless', 'trojan', 'tuic'):
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False
        if not parsed.hostname or not parsed.port:
            return False

        if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)):
            # Проверяем, является ли hostname доменом, если это не IP адрес
            if not re.match(r"^[a-zA-Z0-9.-]+$", parsed.hostname):
                return False

        return True
    except ValueError:
        return False


def is_valid_uuid(uuid_string: str) -> bool:
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        return False


PROFILE_KEY_REGEX = re.compile(
    r"^(vless|ss|trojan|tuic|hy2)://(?:.*?@)?([^@/:]+):(\d+)"
)


def create_profile_key(parsed: urlparse, query: Dict) -> Optional[str]:
    """
    Создает ключ для идентификации профиля.

    Note: Экранируем username и password для ss://, чтобы избежать проблем с спецсимволами.
    """
    try:
        if parsed.scheme == 'ss':
            # Экранируем username и password:
            username = quote_plus(parsed.username or '')
            password = quote_plus(parsed.password or '')
            netloc = f"{username}:{password}@{parsed.hostname}:{parsed.port}"
            return parsed._replace(netloc=netloc, scheme='ss', path='', params='', query='', fragment='').geturl()

        else:  # vless, trojan, tuic, hy2
            match = PROFILE_KEY_REGEX.match(parsed.geturl())
            if match:
                protocol, host, port = match.groups()
                return f"{protocol}://{host}:{port}"
            else:
                return None

    except Exception as e:
        logger.error(f"Ошибка создания ключа профиля для {parsed.geturl()}: {e}")
        return None


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession,
                          channel_semaphore: asyncio.Semaphore,
                          existing_profiles: set,
                          proxy_config: "ProxyConfig") -> List[Dict]:
    proxies = []
    profile_score_cache = {}
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
                if text is None:
                    logger.warning(f"Канал {channel.url} вернул пустой ответ.")
                    channel.check_count += 1
                    channel.update_channel_stats(success=False)
                    return proxies

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

        for line in lines:
            line = line.strip()

            try:
                parsed = urlparse(line)
                query = parse_qs(parsed.query)  # Кешируем результат
                profile_id = parsed.username or query.get('id', [None])[0] if parsed.scheme in (
                'vless', 'trojan', 'tuic') else None

                if (len(line) < MIN_CONFIG_LENGTH or
                        not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or
                        not is_valid_proxy_url(line) or
                        (parsed.scheme in ('vless', 'trojan', 'tuic') and profile_id and not is_valid_uuid(profile_id))):
                    continue


            except ValueError as e:
                logger.debug(f"Ошибка парсинга URL {line}: {e}")
                continue

            profile_key = create_profile_key(parsed, query)
            if profile_key is None:  # Добавили проверку
                continue
            if profile_key in existing_profiles:
                logger.debug(f"Дубликат профиля найден и пропущен: {line}")
                continue
            existing_profiles.add(profile_key)

            if profile_key in profile_score_cache:
                score = profile_score_cache[profile_key]
            else:
                score = compute_profile_score(line,
                                              channel_response_time=channel.metrics.avg_response_time)
                profile_score_cache[profile_key] = score

            protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)

            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                channel.metrics.protocol_counts[protocol] += 1
                await asyncio.sleep(0)

        channel.metrics.valid_configs += len(proxies)
        channel.metrics.unique_configs = len(existing_profiles)
        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {len(proxies)} валидных конфигураций.")
        return proxies


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles = set()

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles, proxy_config) for channel
                 in channels]
        results = await asyncio.gather(*tasks)  # return_exceptions=True не нужен

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка при обработке канала: {result}")
            elif result:
                proxies_all.extend(result)

    return proxies_all


def save_final_configs(proxies: List[Dict], output_file: str):
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True)

    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies_sorted:
                if proxy['score'] > MIN_ACCEPTABLE_SCORE:
                    config = proxy['config'].split('#')[0].strip()
                    parsed = urlparse(config)
                    query = parse_qs(parsed.query)
                    profile_name = generate_custom_name(parsed, query)
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
    ScoringWeights.load_weights_from_json()  # Загружаем веса
    main()

