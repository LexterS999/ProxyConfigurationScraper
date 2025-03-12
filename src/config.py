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
MIN_ACCEPTABLE_SCORE = 40.0  # Изменено: минимальный балл для записи в файл
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
    # VLESS_TCP_NONE_NONE = "🐌 VLESS - TCP - NONE - NONE"  # Убрали
    SS_FORMAT = "🎭 SS - {method}"
    SS_CHACHA20_IETF_POLY1305 = "🛡️ SS - CHACHA20-IETF-POLY1305"
    TROJAN_FORMAT = "🗡️ Trojan - {transport} - {security}"
    TROJAN_WS_TLS = "⚔️ Trojan - WS - TLS"
    TUIC_FORMAT = "🐢 TUIC - {transport} - {security} - {congestion_control}"
    TUIC_WS_TLS_BBR = "🐇 TUIC - WS - TLS - BBR"
    HY2_FORMAT = "💧 HY2 - {transport} - {security}"
    HY2_UDP_TLS = "🐳 HY2 - UDP - TLS"
    # UNKNOWN_FORMAT = "❓ Неизвестный Протокол"  # Убрали


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
    protocol_scores: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))


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

            # Нормализация к 100-балльной системе.
            # Максимальный бонус за недавнюю активность ограничен HIGH_FREQUENCY_BONUS.
            # Время отклика может только уменьшать оценку (penalty), поэтому вычитаем его.

            max_possible_score = (ScoringWeights.CHANNEL_STABILITY.value + HIGH_FREQUENCY_BONUS)
            self.metrics.overall_score = round(
                ((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus - response_time_penalty)
                / max_possible_score * 100, 2)


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
          # Преобразуем время отклика в "штрафные баллы" (инвертируем, чтобы большее время давало больший штраф)
        if self.metrics.avg_response_time > 0:
            # Шкалируем, чтобы штраф был в пределах [0, 20].
            # Например, если среднее время отклика 5 секунд, штраф будет -10.
            max_response_time_penalty = 20 # Максимальный штраф за время
            penalty = min(self.metrics.avg_response_time / 5 * max_response_time_penalty, max_response_time_penalty)
            return penalty

        else:
            return 0.0


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
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> Dict[str, Any]:
        """Загружает веса из JSON-файла и обновляет значения в ScoringWeights."""
        all_weights_loaded_successfully = True
        loaded_weights = {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    try:
                        if not isinstance(value, (int, float)):
                            raise ValueError(f"Invalid weight value (must be a number) for {name}: {value}")
                        # Не обновляем ScoringWeights здесь, а сохраняем для дальнейшего использования
                        loaded_weights[name] = value
                    except (ValueError) as e:
                        logger.warning(f"Error loading weight {name}: {e}. Weight ignored.")
                        all_weights_loaded_successfully = False
        except FileNotFoundError:
            logger.warning(f"Scoring weights file not found: {file_path}. Using default values.")
            all_weights_loaded_successfully = False
        except json.JSONDecodeError:
            logger.error(f"Error reading JSON scoring weights file: {file_path}. Using default values.")
            all_weights_loaded_successfully = False
        except Exception as e:
            logger.error(
                f"Unexpected error loading scoring weights from {file_path}: {e}. Using default values.")
            all_weights_loaded_successfully = False


        if not all_weights_loaded_successfully:
            ScoringWeights._create_default_weights_file(file_path)
            # Загружаем значения по умолчанию, если не удалось загрузить из файла
            loaded_weights = {member.name: member.value for member in ScoringWeights}

        return loaded_weights


    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = {member.name: member.value for member in ScoringWeights}
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Created default scoring weights file: {file_path}")
        except Exception as e:
            logger.error(f"Error creating default scoring weights file: {e}")

    @staticmethod
    def save_weights_to_json(weights: Dict[str, float], file_path: str = DEFAULT_SCORING_WEIGHTS_FILE):
        """Сохраняет веса (после обновления) в JSON файл."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(weights, f, indent=4)
            logger.info(f"Scoring weights saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving scoring weights to {file_path}: {e}")


def _get_value(query: Dict, key: str, default_value: Any = None) -> Any:
    """Вспомогательная функция для безопасного получения значений из query."""
    return query.get(key, (default_value,))[0]


def _calculate_vless_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет оценку для VLESS-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("VLESS_SECURITY_TLS", ScoringWeights.VLESS_SECURITY_TLS.value) if security == 'tls' else loaded_weights.get("VLESS_SECURITY_NONE", ScoringWeights.VLESS_SECURITY_NONE.value)

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'tcp').lower()
    score += loaded_weights.get("VLESS_TRANSPORT_WS", ScoringWeights.VLESS_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("VLESS_TRANSPORT_TCP", ScoringWeights.VLESS_TRANSPORT_TCP.value)

    # --- Шифрование ---
    encryption = _get_value(query, 'encryption', 'none').lower()
    score += {
        'none': loaded_weights.get("VLESS_ENCRYPTION_NONE", ScoringWeights.VLESS_ENCRYPTION_NONE.value),
        'auto': loaded_weights.get("VLESS_ENCRYPTION_AUTO", ScoringWeights.VLESS_ENCRYPTION_AUTO.value),
        'aes-128-gcm': loaded_weights.get("VLESS_ENCRYPTION_AES_128_GCM", ScoringWeights.VLESS_ENCRYPTION_AES_128_GCM.value),
        'chacha20-poly1305': loaded_weights.get("VLESS_ENCRYPTION_CHACHA20_POLY1305", ScoringWeights.VLESS_ENCRYPTION_CHACHA20_POLY1305.value)
    }.get(encryption, 0)

    # --- Другие параметры VLESS ---
    if parsed.username:
        score += loaded_weights.get("VLESS_UUID_PRESENT", ScoringWeights.VLESS_UUID_PRESENT.value)
    if _get_value(query, 'earlyData') == '1':
        score += loaded_weights.get("VLESS_EARLY_DATA", ScoringWeights.VLESS_EARLY_DATA.value)
    if _get_value(query, 'sni'):
        score += loaded_weights.get("VLESS_SNI_PRESENT", ScoringWeights.VLESS_SNI_PRESENT.value)
    if _get_value(query, 'alpn'):
        score += loaded_weights.get("VLESS_ALPN_PRESENT", ScoringWeights.VLESS_ALPN_PRESENT.value)
    if _get_value(query, 'path'):
        score += loaded_weights.get("VLESS_PATH_PRESENT", ScoringWeights.VLESS_PATH_PRESENT.value)

    return score


def _calculate_ss_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет оценку для SS-профиля."""
    score = 0

    # --- Метод шифрования ---
    method = parsed.username.lower() if parsed.username else 'none'
    score += {
        'chacha20-ietf-poly1305': loaded_weights.get("SS_METHOD_CHACHA20_IETF_POLY1305", ScoringWeights.SS_METHOD_CHACHA20_IETF_POLY1305.value),
        'aes-256-gcm': loaded_weights.get("SS_METHOD_AES_256_GCM", ScoringWeights.SS_METHOD_AES_256_GCM.value),
        'aes-128-gcm': loaded_weights.get("SS_METHOD_AES_128_GCM", ScoringWeights.SS_METHOD_AES_128_GCM.value),
        'none': loaded_weights.get("SS_METHOD_NONE", ScoringWeights.SS_METHOD_NONE.value)
    }.get(method, 0)

    # --- Длина пароля ---
    score += min(loaded_weights.get("SS_PASSWORD_LENGTH", ScoringWeights.SS_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("SS_PASSWORD_LENGTH", ScoringWeights.SS_PASSWORD_LENGTH.value)) if parsed.password else 0

    # --- Плагин ---
    plugin = _get_value(query, 'plugin', 'none').lower()
    if plugin != 'none':
        score += {
            'obfs-http': loaded_weights.get("SS_PLUGIN_OBFS_HTTP", ScoringWeights.SS_PLUGIN_OBFS_HTTP.value),
            'obfs-tls': loaded_weights.get("SS_PLUGIN_OBFS_TLS", ScoringWeights.SS_PLUGIN_OBFS_TLS.value)
        }.get(plugin, 0)
    else:
        score += loaded_weights.get("SS_PLUGIN_NONE", ScoringWeights.SS_PLUGIN_NONE.value)

    return score


def _calculate_trojan_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет оценку для Trojan-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()  # Должен быть tls
    score += loaded_weights.get("TROJAN_SECURITY_TLS", ScoringWeights.TROJAN_SECURITY_TLS.value) if security == 'tls' else 0  # Нет штрафа, просто 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'tcp').lower()
    score += loaded_weights.get("TROJAN_TRANSPORT_WS", ScoringWeights.TROJAN_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TROJAN_TRANSPORT_TCP", ScoringWeights.TROJAN_TRANSPORT_TCP.value)

    # --- Длина пароля ---
    score += min(loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value)) if parsed.password else 0

    # --- Другие параметры Trojan ---
    if _get_value(query, 'sni'):
        score += loaded_weights.get("TROJAN_SNI_PRESENT", ScoringWeights.TROJAN_SNI_PRESENT.value)
    if _get_value(query, 'alpn'):
        score += loaded_weights.get("TROJAN_ALPN_PRESENT", ScoringWeights.TROJAN_ALPN_PRESENT.value)
    if _get_value(query, 'earlyData') == '1':
        score += loaded_weights.get("TROJAN_EARLY_DATA", ScoringWeights.TROJAN_EARLY_DATA.value)

    return score


def _calculate_tuic_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет оценку для TUIC-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("TUIC_SECURITY_TLS", ScoringWeights.TUIC_SECURITY_TLS.value) if security == 'tls' else 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'udp').lower()  # Должен быть udp (или ws)
    score += loaded_weights.get("TUIC_TRANSPORT_WS", ScoringWeights.TUIC_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TUIC_TRANSPORT_UDP", ScoringWeights.TUIC_TRANSPORT_UDP.value)

    # --- Управление перегрузкой ---
    congestion_control = _get_value(query, 'congestion', 'bbr').lower()
    score += {
        'bbr': loaded_weights.get("TUIC_CONGESTION_CONTROL_BBR", ScoringWeights.TUIC_CONGESTION_CONTROL_BBR.value),
        'cubic': loaded_weights.get("TUIC_CONGESTION_CONTROL_CUBIC", ScoringWeights.TUIC_CONGESTION_CONTROL_CUBIC.value),
        'new-reno': loaded_weights.get("TUIC_CONGESTION_CONTROL_NEW_RENO", ScoringWeights.TUIC_CONGESTION_CONTROL_NEW_RENO.value)
    }.get(congestion_control, 0)

    # --- Другие параметры TUIC ---
    if parsed.username:  # UUID
        score += loaded_weights.get("TUIC_UUID_PRESENT", ScoringWeights.TUIC_UUID_PRESENT.value)
    score += min(loaded_weights.get("TUIC_PASSWORD_LENGTH", ScoringWeights.TUIC_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("TUIC_PASSWORD_LENGTH", ScoringWeights.TUIC_PASSWORD_LENGTH.value)) if parsed.password else 0
    if _get_value(query, 'sni'):
        score += loaded_weights.get("TUIC_SNI_PRESENT", ScoringWeights.TUIC_SNI_PRESENT.value)
    if _get_value(query, 'alpn'):
        score += loaded_weights.get("TUIC_ALPN_PRESENT", ScoringWeights.TUIC_ALPN_PRESENT.value)
    if _get_value(query, 'earlyData') == '1':
        score += loaded_weights.get("TUIC_EARLY_DATA", ScoringWeights.TUIC_EARLY_DATA.value)
    if _get_value(query, 'udp_relay_mode', 'quic').lower() == 'quic':
        score += loaded_weights.get("TUIC_UDP_RELAY_MODE", ScoringWeights.TUIC_UDP_RELAY_MODE.value)
    if _get_value(query, 'zero_rtt_handshake') == '1':
        score += loaded_weights.get("TUIC_ZERO_RTT_HANDSHAKE", ScoringWeights.TUIC_ZERO_RTT_HANDSHAKE.value)
    return score


def _calculate_hy2_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет оценку для HY2-профиля."""
    score = 0

    # --- Безопасность ---
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("HY2_SECURITY_TLS", ScoringWeights.HY2_SECURITY_TLS.value) if security == 'tls' else 0

    # --- Транспорт ---
    transport = _get_value(query, 'type', 'udp').lower()
    score += loaded_weights.get("HY2_TRANSPORT_UDP", ScoringWeights.HY2_TRANSPORT_UDP.value) if transport == 'udp' else loaded_weights.get("HY2_TRANSPORT_TCP", ScoringWeights.HY2_TRANSPORT_TCP.value)

    # --- Другие параметры HY2 ---
    score += min(loaded_weights.get("HY2_PASSWORD_LENGTH", ScoringWeights.HY2_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("HY2_PASSWORD_LENGTH", ScoringWeights.HY2_PASSWORD_LENGTH.value)) if parsed.password else 0
    if _get_value(query, 'sni'):
        score += loaded_weights.get("HY2_SNI_PRESENT", ScoringWeights.HY2_SNI_PRESENT.value)
    if _get_value(query, 'alpn'):
        score += loaded_weights.get("HY2_ALPN_PRESENT", ScoringWeights.HY2_ALPN_PRESENT.value)
    if _get_value(query, 'earlyData') == '1':
        score += loaded_weights.get("HY2_EARLY_DATA", ScoringWeights.HY2_EARLY_DATA.value)
    if _get_value(query, 'pmtud') == '1':
        score += loaded_weights.get("HY2_PMTUD_ENABLED", ScoringWeights.HY2_PMTUD_ENABLED.value)

    # hopInterval (мульти-хоп)
    hop_interval = _get_value(query, 'hopInterval', None)
    if hop_interval:
        try:
            score += int(hop_interval) * loaded_weights.get("HY2_HOP_INTERVAL", ScoringWeights.HY2_HOP_INTERVAL.value)  # Добавляем за каждый hop
        except ValueError:
            pass  # Игнорируем, если не число

    return score


def _calculate_common_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет общую оценку, применимую к обоим протоколам."""
    score = 0

    # --- Порт ---
    score += {
        443: loaded_weights.get("COMMON_PORT_443", ScoringWeights.COMMON_PORT_443.value),
        80: loaded_weights.get("COMMON_PORT_80", ScoringWeights.COMMON_PORT_80.value)
    }.get(parsed.port, loaded_weights.get("COMMON_PORT_OTHER", ScoringWeights.COMMON_PORT_OTHER.value))

    # --- uTLS ---
    utls = _get_value(query, 'utls', None) or _get_value(query, 'fp', 'none')
    utls = utls.lower()
    score += {
        'chrome': loaded_weights.get("COMMON_UTLS_CHROME", ScoringWeights.COMMON_UTLS_CHROME.value),
        'firefox': loaded_weights.get("COMMON_UTLS_FIREFOX", ScoringWeights.COMMON_UTLS_FIREFOX.value),
        'randomized': loaded_weights.get("COMMON_UTLS_RANDOMIZED", ScoringWeights.COMMON_UTLS_RANDOMIZED.value)
    }.get(utls, loaded_weights.get("COMMON_UTLS_OTHER", ScoringWeights.COMMON_UTLS_OTHER.value))

    # --- IPv6 ---
    if ':' in parsed.hostname:
        score += loaded_weights.get("COMMON_IPV6", ScoringWeights.COMMON_IPV6.value)

    # --- CDN ---
    if _get_value(query, 'sni') and '.cdn.' in _get_value(query, 'sni'):
        score += loaded_weights.get("COMMON_CDN", ScoringWeights.COMMON_CDN.value)

    # --- OBFS ---
    if _get_value(query, 'obfs'):
        score += loaded_weights.get("COMMON_OBFS", ScoringWeights.COMMON_OBFS.value)

    # --- Заголовки ---
    if _get_value(query, 'headers'):
        score += loaded_weights.get("COMMON_HEADERS", ScoringWeights.COMMON_HEADERS.value)

    # --- Редкие и скрытые параметры ---
    known_params_general = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls', 'earlyData', 'id', 'method',
        'plugin', 'congestion', 'udp_relay_mode', 'zero_rtt_handshake', 'pmtud', 'hopInterval',
        'bufferSize', 'tcpFastOpen', 'obfs', 'debug', 'comment'
    )

    for key, value in query.items():
        if key not in known_params_general:
            score += loaded_weights.get("COMMON_HIDDEN_PARAM", ScoringWeights.COMMON_HIDDEN_PARAM.value)
            if value and value[0]:
                score += min(loaded_weights.get("COMMON_RARE_PARAM", ScoringWeights.COMMON_RARE_PARAM.value),
                             loaded_weights.get("COMMON_RARE_PARAM", ScoringWeights.COMMON_RARE_PARAM.value) / len(value[0]))

    return score


def compute_profile_score(config: str, channel_response_time: float = 0.0, loaded_weights: Dict = None) -> float:
    """
    Вычисляет общий рейтинг профиля (новая, переработанная функция).
    """
    parse_cache: Dict[str, Tuple[urlparse, Dict]] = {}  # Кеш

    if loaded_weights is None:
        loaded_weights = ScoringWeights.load_weights_from_json()

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

    score = loaded_weights.get("PROTOCOL_BASE", ScoringWeights.PROTOCOL_BASE.value)  # Базовый вес за протокол
    score += _calculate_common_score(parsed, query, loaded_weights)  # Общие веса
    score += channel_response_time * loaded_weights.get("RESPONSE_TIME", ScoringWeights.RESPONSE_TIME.value)  # Время отклика (штраф)

    # Учитываем длину конфигурации, но инвертируем, чтобы более короткие получали БОЛЬШИЙ вес
    score += min(loaded_weights.get("CONFIG_LENGTH", ScoringWeights.CONFIG_LENGTH.value),
                 (200.0 / (len(config) + 1)) * loaded_weights.get("CONFIG_LENGTH", ScoringWeights.CONFIG_LENGTH.value))


    if protocol == "vless://":
        score += _calculate_vless_score(parsed, query, loaded_weights)
    elif protocol == "ss://":
        score += _calculate_ss_score(parsed, query, loaded_weights)
    elif protocol == "trojan://":
        score += _calculate_trojan_score(parsed, query, loaded_weights)
    elif protocol == "tuic://":
        score += _calculate_tuic_score(parsed, query, loaded_weights)
    elif protocol == "hy2://":
        score += _calculate_hy2_score(parsed, query, loaded_weights)

     # Нормализация к 100-балльной системе
    max_possible_score = sum(weight for weight in loaded_weights.values())
    normalized_score = (score / max_possible_score) * 100 if max_possible_score > 0 else 0.0

    return round(normalized_score, 2)



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
        security_type = query.get("security", ["tls"])[0].upper()
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
        return f"⚠️ Unknown Protocol: {parsed.scheme}"  # информативное сообщение


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
    loaded_weights = ScoringWeights.load_weights_from_json()  # Загружаем веса

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
                                              channel_response_time=channel.metrics.avg_response_time,
                                              loaded_weights=loaded_weights) # Передаем загруженные веса
                profile_score_cache[profile_key] = score

            protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)


            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                channel.metrics.protocol_counts[protocol] += 1
                channel.metrics.protocol_scores[protocol].append(score)  # Сохраняем оценку
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
                    final_line = f"{config}# {profile_name} - Score: {proxy['score']:.2f}\n" # Добавил score
                    f.write(final_line)
        logger.info(f"Финальные конфигурации сохранены в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")


def update_and_save_weights(channels: List[ChannelConfig], loaded_weights:Dict):
    """Обновляет веса на основе результатов обработки и сохраняет их."""

    # 1. Обновление CHANNEL_STABILITY (простой пример)
    total_success_ratio = sum(channel._calculate_success_ratio() for channel in channels) / len(channels) if channels else 0
    # Преобразуем в проценты и ограничиваем диапазоном [0, 100]
    loaded_weights['CHANNEL_STABILITY'] =  min(max(int(total_success_ratio * 100), 0), 100)


    # 2. Обновление весов на основе популярности протоколов (пример)
    protocol_counts = defaultdict(int)
    for channel in channels:
        for protocol, count in channel.metrics.protocol_counts.items():
            protocol_counts[protocol] += count

    total_configs = sum(protocol_counts.values())
    for protocol, count in protocol_counts.items():
        # Рассчитываем долю протокола от общего числа конфигураций
        ratio = (count / total_configs) * 100 if total_configs > 0 else 0

        # Пример обновления веса: увеличиваем вес для популярных, уменьшаем для непопулярных
        if protocol == "vless":
            loaded_weights['PROTOCOL_BASE'] = min(max(int(ratio * 5), 0), 100)  # Примерный расчёт
        # ... аналогично для других протоколов ...

    # 3. Другие обновления (пример с RESPONSE_TIME)
    all_response_times = [channel.metrics.avg_response_time for channel in channels if channel.metrics.avg_response_time > 0]
    if all_response_times:
        avg_response_time_all = sum(all_response_times) / len(all_response_times)
        # Устанавливаем штраф: чем больше среднее время отклика, тем больше штраф (в пределах разумного)
        loaded_weights['RESPONSE_TIME'] =  min(max(int(-avg_response_time_all * 2), -50), 0)

    ScoringWeights.save_weights_to_json(loaded_weights)


def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    loaded_weights = ScoringWeights.load_weights_from_json()  # Загружаем веса

    async def runner():
        proxies = await process_all_channels(channels, proxy_config)
        save_final_configs(proxies, proxy_config.OUTPUT_FILE)
        update_and_save_weights(channels, loaded_weights) # Обновление весов


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
    # ScoringWeights.load_weights_from_json()  # Загружаем веса -  уже в main()
    main()
