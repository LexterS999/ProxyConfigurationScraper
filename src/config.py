import asyncio
import aiohttp
import re
import os
import tempfile
import platform
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from collections import defaultdict
import logging
import ipaddress
import io
from enum import Enum
import shutil
import uuid
import zipfile
import hashlib

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"

class ScoringWeights(Enum):
    """Веса для расчета скоринга — оптимизированы для VLESS, Trojan, Tuic, Hy2."""
    PROTOCOL_BASE = 50
    CONFIG_LENGTH = 10
    SECURITY_PARAM = 15
    NUM_SECURITY_PARAMS = 5
    SECURITY_TYPE_TLS = 10
    SECURITY_TYPE_REALITY = 12
    SECURITY_TYPE_NONE = -5
    TRANSPORT_TYPE_TCP = 2
    TRANSPORT_TYPE_WS = 8
    TRANSPORT_TYPE_QUIC = 6
    ENCRYPTION_TYPE_NONE = -5
    ENCRYPTION_TYPE_AUTO = 3
    ENCRYPTION_TYPE_AES_128_GCM = 7
    ENCRYPTION_TYPE_CHACHA20_POLY1305 = 7
    ENCRYPTION_TYPE_ZERO = 2
    SNI_PRESENT = 7
    COMMON_SNI_BONUS = 3
    ALPN_PRESENT = 5
    NUM_ALPN_PROTOCOLS = 2
    PATH_PRESENT = 3
    PATH_COMPLEXITY = 2
    HEADERS_PRESENT = 4
    NUM_HEADERS = 1
    HOST_HEADER = 5
    HOST_SNI_MATCH = 10
    UTLS_PRESENT = 4
    UTLS_VALUE_CHROME = 5
    UTLS_VALUE_FIREFOX = 4
    UTLS_VALUE_IOS = 2
    UTLS_VALUE_SAFARI = 3
    UTLS_VALUE_RANDOMIZED = 7
    UTLS_VALUE_RANDOM = 6
    UDP_SUPPORT = 7
    PORT_80 = 5
    PORT_443 = 10
    PORT_OTHER = 2
    UUID_PRESENT = 5
    UUID_LENGTH = 3
    EARLY_DATA_SUPPORT = 5
    PARAMETER_CONSISTENCY = 12
    IPV6_ADDRESS = -9
    RARITY_BONUS = 4
    HIDDEN_PARAM = 6
    NEW_PARAM = 5
    RESPONSE_TIME = -0.05
    CHANNEL_STABILITY = 20
    BUFFER_SIZE_SMALL = -2
    BUFFER_SIZE_MEDIUM = 3
    BUFFER_SIZE_LARGE = 7
    BUFFER_SIZE_UNLIMITED = 5
    TCP_OPTIMIZATION = 5
    QUIC_PARAM = 3
    STREAM_ENCRYPTION = 6
    CDN_USAGE = 8
    OBFS = 4
    DEBUG_PARAM = -3
    COMMENT = 1
    TROJAN_PASSWORD_PRESENT = 8
    TROJAN_PASSWORD_LENGTH = 5

    @staticmethod
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> Dict[str, Any]:
        """Загружает веса из JSON-файла, возвращает словарь с проблемами."""
        issues = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    if not isinstance(value, (int, float)):
                        issues[name] = f"Неверный тип: {type(value)}, ожидается int или float"
                        continue
                    try:
                        ScoringWeights[name].value = value
                    except KeyError:
                        issues[name] = "Неизвестный вес"
                    except ValueError:
                        issues[name] = f"Неверное значение: {value}"
        except FileNotFoundError:
            logger.warning(f"Файл не найден: {file_path}. Создаю по умолчанию.")
            ScoringWeights._create_default_weights_file(file_path)
        except json.JSONDecodeError:
            logger.error(f"Ошибка JSON в {file_path}.")
        except Exception as e:
            logger.error(f"Ошибка загрузки весов: {e}")
        return issues

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        """Создает файл весов по умолчанию, если он отсутствует."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if not os.access(os.path.dirname(file_path), os.W_OK):
                raise PermissionError(f"Нет прав на запись в {os.path.dirname(file_path)}")
            default_weights = {member.name: member.value for member in ScoringWeights}
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Создан файл весов: {file_path}")
        except PermissionError as e:
            logger.error(f"Ошибка прав доступа: {e}")
        except Exception as e:
            logger.error(f"Ошибка создания файла весов: {e}")

# Загрузка весов при инициализации
ScoringWeights.load_weights_from_json()

# Константы
MIN_ACCEPTABLE_SCORE = 90.0
MIN_CONFIG_LENGTH = 30
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "trojan://"]
PREFERRED_PROTOCOLS = ["vless://", "trojan://", "tuic://", "hy2://"]
CHECK_USERNAME = False
CHECK_TLS_REALITY = False
CHECK_SNI = False
CHECK_CONNECTION_TYPE = False
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
MAX_CONCURRENT_HTTP_CHECKS = 60

@dataclass
class ChannelMetrics:
    """Метрики канала."""
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
    """Конфигурация канала с URL и метриками."""
    def __init__(self, url: str, request_timeout: int = REQUEST_TIMEOUT):
        if not isinstance(request_timeout, int) or request_timeout <= 0:
            raise ValueError(f"request_timeout должен быть положительным целым числом, получено: {request_timeout}")
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = request_timeout
        self.check_count = 0

    def _validate_url(self, url: str) -> str:
        """Проверяет валидность URL."""
        if not url:
            raise ValueError("URL не может быть пустым.")
        if not isinstance(url, str):
            raise ValueError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        valid_protocols = ('http://', 'https://', 'trojan://', 'vless://', 'tuic://', 'hy2://')
        if not any(url.startswith(proto) for proto in valid_protocols):
            raise ValueError(f"Неверный протокол URL: {url}. Ожидается: {', '.join(valid_protocols)}")
        return url

    def calculate_overall_score(self):
        """Рассчитывает общий скор канала."""
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()
            score = (success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus + response_time_penalty
            logger.debug(f"Канал {self.url}: success_ratio={success_ratio}, recency_bonus={recency_bonus}, penalty={response_time_penalty}")
            self.metrics.overall_score = round(max(0, score), 2)
        except Exception as e:
            logger.error(f"Ошибка расчета скора для {self.url}: {e}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        """Возвращает долю успешных проверок. Если проверок нет, возвращает 0."""
        total_checks = self.metrics.success_count + self.metrics.fail_count
        return self.metrics.success_count / total_checks if total_checks > 0 else 0.0

    def _calculate_recency_bonus(self, current_time: datetime = None) -> float:
        """Рассчитывает бонус за недавний успех."""
        current_time = current_time or datetime.now()
        if self.metrics.last_success_time:
            time_since_last_success = current_time - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0
        return 0

    def _calculate_response_time_penalty(self) -> float:
        """Рассчитывает штраф за время ответа."""
        penalty = self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value
        return max(-10, penalty) if self.metrics.avg_response_time > 0 else 0

    def update_channel_stats(self, success: bool, response_time: float = 0):
        """Обновляет статистику канала."""
        assert isinstance(success, bool), f"Аргумент 'success' должен быть bool, получено {type(success)}"
        assert isinstance(response_time, (int, float)) and response_time >= 0, f"response_time должен быть неотрицательным числом, получено {response_time}"
        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
        else:
            self.metrics.fail_count += 1
        if response_time > 0:
            if self.metrics.avg_response_time:
                self.metrics.avg_response_time = (self.metrics.avg_response_time * 0.7) + (response_time * 0.3)
            else:
                self.metrics.avg_response_time = response_time
        self.calculate_overall_score()

class ProxyConfig:
    """Управление конфигурацией прокси."""
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
            logger.warning(f"Файл URL не найден: {ALL_URLS_FILE}. Создаю пустой.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")
        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        if not self.SOURCE_URLS:
            logger.warning("Нет валидных источников URL. Создаю пустой файл конфигурации.")
            self.save_empty_config_file()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE

    def _normalize_url(self, url: str) -> str:
        """Нормализует URL для сравнения."""
        try:
            if not url:
                raise ValueError("URL не может быть пустым для нормализации.")
            url = url.strip()
            parsed = urlparse(url)
            if not parsed.scheme:
                raise ValueError(f"Отсутствует схема в URL: '{url}'.")
            if not parsed.netloc:
                raise ValueError(f"Отсутствует netloc в URL: '{url}'.")
            path = parsed.path.rstrip('/')
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"Ошибка нормализации URL '{url}': {e}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """Удаляет дубликаты URL."""
        seen_urls = set()
        unique_configs = []
        invalid_configs = []
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                invalid_configs.append(str(config))
                logger.warning(f"Неверная конфигурация: {config}")
                continue
            try:
                normalized_url = self._normalize_url(config.url)
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
            except Exception as e:
                invalid_configs.append(config.url)
                logger.warning(f"Пропущен URL {config.url}: {e}")
        if not unique_configs:
            self.save_empty_config_file()
            logger.error("Не найдено валидных источников.")
        if invalid_configs:
            logger.info(f"Пропущено {len(invalid_configs)} невалидных конфигураций.")
        return unique_configs

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Возвращает список активных каналов."""
        logger.debug(f"Возвращено {len(self.SOURCE_URLS)} активных каналов")
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        """Сохраняет пустой файл конфигурации."""
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                bytes_written = f.write("")
            if bytes_written is None:
                logger.error(f"Ошибка записи в {OUTPUT_CONFIG_FILE}: ничего не записано")
                return False
            logger.info(f"Создан пустой файл: {OUTPUT_CONFIG_FILE}")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла: {e}")
            return False

# Дополнительные константы
COMMON_DOMAINS = ('.com', '.net', '.org', '.info', '.xyz')
UDP_PROTOCOLS = {"tuic://", "hy2://"}
KNOWN_PARAMS = {
    'security', 'type', 'encryption', 'sni', 'alpn', 'path', 'headers', 'fp', 'utls',
    'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment'
}
CDN_INDICATORS = {".cdn.", "cloudflare", "akamai", "fastly"}

# Функции расчета скоринга
def _calculate_config_length_score(config: str) -> float:
    """Рассчитывает скор длины конфигурации с логарифмической шкалой."""
    from math import log
    length = len(config)
    return min(ScoringWeights.CONFIG_LENGTH.value, log(length + 1) * ScoringWeights.CONFIG_LENGTH.value / log(200))

def _calculate_security_score(query: Dict) -> float:
    """Рассчитывает скор безопасности."""
    score = 0
    security_params = query.get('security', [])
    if not isinstance(security_params, list):
        logger.warning(f"security_params ожидается список, получено: {type(security_params)}")
        return score
    if security_params:
        score += ScoringWeights.SECURITY_PARAM.value
        score += min(ScoringWeights.NUM_SECURITY_PARAMS.value, len(security_params) * (ScoringWeights.NUM_SECURITY_PARAMS.value / 3))
        security_type = security_params[0].lower() if security_params else 'none'
        score += {
            "tls": ScoringWeights.SECURITY_TYPE_TLS.value,
            "reality": ScoringWeights.SECURITY_TYPE_REALITY.value,
            "none": ScoringWeights.SECURITY_TYPE_NONE.value
        }.get(security_type, 0)
    return score

def _calculate_transport_score(query: Dict) -> float:
    """Рассчитывает скор типа транспорта."""
    transport_type = query.get('type', ['tcp'])[0].lower()
    score = {
        "tcp": ScoringWeights.TRANSPORT_TYPE_TCP.value,
        "ws": ScoringWeights.TRANSPORT_TYPE_WS.value,
        "quic": ScoringWeights.TRANSPORT_TYPE_QUIC.value
    }.get(transport_type, 0)
    if score == 0:
        logger.debug(f"Неизвестный тип транспорта: {transport_type}")
    return score

def _calculate_encryption_score(query: Dict) -> float:
    """Рассчитывает скор шифрования."""
    encryption_type = query.get('encryption', ['none'])[0].lower()
    score = {
        "none": ScoringWeights.ENCRYPTION_TYPE_NONE.value,
        "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO.value,
        "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM.value,
        "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305.value,
        "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO.value
    }.get(encryption_type, 0)
    if score == 0:
        logger.debug(f"Неизвестный тип шифрования: {encryption_type}")
    return score

def _calculate_sni_score(query: Dict) -> float:
    """Рассчитывает скор SNI."""
    score = 0
    sni = query.get('sni', [None])[0]
    if sni:
        score += ScoringWeights.SNI_PRESENT.value
        if any(sni.endswith(domain) for domain in COMMON_DOMAINS):
            score += ScoringWeights.COMMON_SNI_BONUS.value
    return score

def _calculate_alpn_score(query: Dict) -> float:
    """Рассчитывает скор ALPN."""
    score = 0
    alpn = query.get('alpn', [None])[0]
    if alpn:
        score += ScoringWeights.ALPN_PRESENT.value
        try:
            alpn_protocols = alpn.split(',')
            score += min(ScoringWeights.NUM_ALPN_PROTOCOLS.value, len(alpn_protocols) * (ScoringWeights.NUM_ALPN_PROTOCOLS.value / 2))
        except Exception as e:
            logger.warning(f"Ошибка разбора ALPN '{alpn}': {e}")
    return score

def _calculate_path_score(query: Dict) -> float:
    """Рассчитывает скор пути."""
    score = 0
    path = query.get('path', [None])[0]
    if path:
        score += ScoringWeights.PATH_PRESENT.value
        special_chars = len(set(re.findall(r'[^a-zA-Z0-9]', path)))
        complexity = special_chars + (len(path) / 10)
        score += min(ScoringWeights.PATH_COMPLEXITY.value, complexity * (ScoringWeights.PATH_COMPLEXITY.value / 5))
    return score

def _calculate_headers_score(query: Dict, sni: Optional[str]) -> float:
    """Рассчитывает скор заголовков."""
    score = 0
    headers = query.get('headers', [None])[0]
    if headers:
        score += ScoringWeights.HEADERS_PRESENT.value
        try:
            headers_dict = {}
            for item in headers.split('&'):
                if ':' in item:
                    key, value = item.split(':', 1)
                    headers_dict[key.strip()] = value.strip()
            score += min(ScoringWeights.NUM_HEADERS.value, len(headers_dict) * (ScoringWeights.NUM_HEADERS.value / 2))
            host_header = headers_dict.get('Host')
            if host_header:
                score += ScoringWeights.HOST_HEADER.value
                if sni and host_header == sni:
                    score += ScoringWeights.HOST_SNI_MATCH.value
        except Exception as e:
            logger.warning(f"Ошибка парсинга заголовков '{headers}': {e}")
    return score

def _calculate_utls_score(query: Dict) -> float:
    """Рассчитывает скор UTLS."""
    score = 0
    utls = query.get('utls', query.get('fp', [None])[0])
    if utls:
        score += ScoringWeights.UTLS_PRESENT.value
        utls = utls.lower()
        score += {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value,
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI.value,
            "randomized": ScoringWeights.UTLS_VALUE_RANDOMIZED.value,
            "random": ScoringWeights.UTLS_VALUE_RANDOM.value
        }.get(utls, 0)
        if score == ScoringWeights.UTLS_PRESENT.value:
            logger.debug(f"Неизвестное значение utls: {utls}")
    return score

def _calculate_udp_score(protocol: str) -> float:
    """Рассчитывает скор поддержки UDP."""
    return ScoringWeights.UDP_SUPPORT.value if protocol in UDP_PROTOCOLS else 0

def _calculate_port_score(port: Optional[int]) -> float:
    """Рассчитывает скор порта."""
    if port is None:
        return 0
    return {
        80: ScoringWeights.PORT_80.value,
        443: ScoringWeights.PORT_443.value
    }.get(port, ScoringWeights.PORT_OTHER.value)

def _calculate_uuid_score(parsed: urlparse, query: Dict) -> float:
    """Рассчитывает скор UUID для VLESS."""
    score = 0
    uuid_val = parsed.username or query.get('id', [None])[0]
    if uuid_val and parsed.scheme == 'vless':
        if is_valid_uuid(uuid_val):
            score += ScoringWeights.UUID_PRESENT.value
            score += min(ScoringWeights.UUID_LENGTH.value, len(uuid_val) * (ScoringWeights.UUID_LENGTH.value / 36))
        else:
            logger.debug(f"Неверный UUID для VLESS: {uuid_val}")
    return score

def _calculate_trojan_password_score(parsed: urlparse) -> float:
    """Рассчитывает скор пароля для Trojan."""
    score = 0
    password = parsed.username
    if password and parsed.scheme == 'trojan':
        score += ScoringWeights.TROJAN_PASSWORD_PRESENT.value
        score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH.value, len(password) * (ScoringWeights.TROJAN_PASSWORD_LENGTH.value / 16))
    return score

def _calculate_early_data_score(query: Dict) -> float:
    """Рассчитывает скор поддержки ранних данных."""
    early_data = query.get('earlyData', [None])[0]
    return ScoringWeights.EARLY_DATA_SUPPORT.value if early_data in ("1", "true") else 0

def _calculate_parameter_consistency_score(query: Dict, sni: Optional[str], host_header: Optional[str]) -> float:
    """Рассчитывает скор согласованности параметров."""
    score = ScoringWeights.PARAMETER_CONSISTENCY.value
    if sni and host_header and sni != host_header:
        score -= ScoringWeights.PARAMETER_CONSISTENCY.value / 2
    return score

def _calculate_ipv6_score(parsed: urlparse) -> float:
    """Рассчитывает скор для IPv6."""
    try:
        if parsed.hostname and ipaddress.ip_address(parsed.hostname).version == 6:
            return ScoringWeights.IPV6_ADDRESS.value
    except ValueError:
        pass
    return 0

def _calculate_hidden_param_score(query: Dict) -> float:
    """Рассчитывает скор скрытых параметров."""
    score = 0
    for key, value in query.items():
        if key not in KNOWN_PARAMS:
            score += ScoringWeights.HIDDEN_PARAM.value
            if value and value[0]:
                score += min(ScoringWeights.RARITY_BONUS.value, ScoringWeights.RARITY_BONUS.value / len(value[0]))
    return score

def _calculate_buffer_size_score(query: Dict) -> float:
    """Рассчитывает скор размера буфера."""
    buffer_size = query.get('bufferSize', [None])[0]
    if buffer_size:
        buffer_size = buffer_size.lower()
        score = {
            "unlimited": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "small": ScoringWeights.BUFFER_SIZE_SMALL.value,
            "medium": ScoringWeights.BUFFER_SIZE_MEDIUM.value,
            "large": ScoringWeights.BUFFER_SIZE_LARGE.value,
            "-1": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "0": ScoringWeights.BUFFER_SIZE_UNLIMITED.value
        }.get(buffer_size)
        if score is None and buffer_size.isdigit():
            size = int(buffer_size)
            if size < 1024:
                return ScoringWeights.BUFFER_SIZE_SMALL.value
            elif size < 4096:
                return ScoringWeights.BUFFER_SIZE_MEDIUM.value
            else:
                return ScoringWeights.BUFFER_SIZE_LARGE.value
        return score or 0
    return 0

def _calculate_tcp_optimization_score(query: Dict) -> float:
    """Рассчитывает скор оптимизации TCP."""
    tcp_fast_open = query.get('tcpFastOpen', [None])[0]
    return ScoringWeights.TCP_OPTIMIZATION.value if tcp_fast_open in ("true", "1") else 0

def _calculate_quic_param_score(query: Dict) -> float:
    """Рассчитывает скор параметров QUIC."""
    max_idle_time = query.get('maxIdleTime', [None])[0]
    if max_idle_time and max_idle_time.isdigit():
        return ScoringWeights.QUIC_PARAM.value if int(max_idle_time) > 0 else 0
    return 0

def _calculate_cdn_usage_score(sni: Optional[str]) -> float:
    """Рассчитывает скор использования CDN."""
    return ScoringWeights.CDN_USAGE.value if sni and any(ind in sni.lower() for ind in CDN_INDICATORS) else 0

def compute_profile_score(config: str, response_time: float = 0.0) -> float:
    """Вычисляет общий скор конфигурации."""
    score = 0.0
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
        if not protocol:
            return 0.0
        
        sni = query.get('sni', [None])[0]
        headers = query.get('headers', [None])[0]
        host_header = None
        if headers:
            headers_dict = dict(item.split(":", 1) for item in headers.split("&") if ':' in item)
            host_header = headers_dict.get('Host')

        score += ScoringWeights.PROTOCOL_BASE.value
        score += _calculate_config_length_score(config)
        score += _calculate_security_score(query)
        score += _calculate_transport_score(query)
        score += _calculate_encryption_score(query)
        score += _calculate_sni_score(query)
        score += _calculate_alpn_score(query)
        score += _calculate_path_score(query)
        score += _calculate_headers_score(query, sni)
        score += _calculate_utls_score(query)
        score += _calculate_udp_score(protocol)
        score += _calculate_port_score(parsed.port)
        score += _calculate_uuid_score(parsed, query)
        if protocol == 'trojan://':
            score += _calculate_trojan_password_score(parsed)
        score += _calculate_early_data_score(query)
        score += _calculate_parameter_consistency_score(query, sni, host_header)
        score += _calculate_ipv6_score(parsed)
        score += _calculate_hidden_param_score(query)
        score += _calculate_buffer_size_score(query)
        score += _calculate_tcp_optimization_score(query)
        score += _calculate_quic_param_score(query)
        score += ScoringWeights.STREAM_ENCRYPTION.value
        score += _calculate_cdn_usage_score(sni)
        score += response_time * ScoringWeights.RESPONSE_TIME.value
        return round(score, 2)
    except Exception as e:
        logger.error(f"Ошибка вычисления скора для {config}: {e}")
        return 0.0

def generate_custom_name(config: str) -> str:
    """Генерирует пользовательское имя для конфигурации."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return "Неизвестный Протокол"
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        name_parts = [protocol.split("://")[0].upper()]
        defaults = {
            'vless': {'type': 'tcp', 'security': 'none', 'encryption': 'none'},
            'trojan': {'type': 'tcp', 'security': 'tls', 'encryption': 'none'},
            'tuic': {'type': 'udp'}, 'hy2': {'type': 'udp'}
        }
        params = defaults.get(parsed.scheme, {})
        for param, default in params.items():
            value = query.get(param, [default])[0].upper()
            if value != 'NONE':
                name_parts.append(f"{param.capitalize()}: {value}")
        return " - ".join(name_parts)
    except Exception as e:
        logger.error(f"Ошибка создания имени для {config}: {e}")
        return "Неизвестный Прокси"

def is_valid_uuid(uuid_string: str) -> bool:
    """Проверяет валидность UUID."""
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False

def is_valid_proxy_url(url: str) -> bool:
    """Проверяет валидность URL прокси."""
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.port:
            return False
        if not is_valid_ipv4(parsed.hostname) and ":" in parsed.hostname:
            return False
        if parsed.scheme == 'vless':
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False
        return True
    except ValueError:
        return False

def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли hostname валидным IPv4."""
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def create_profile_key(config: str) -> str:
    """Создает ключ для конфигурации."""
    return config.split('#')[0].strip()

async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, existing_profiles_regex: set, proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает один канал."""
    proxies = []
    async with channel_semaphore:
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(channel.url, timeout=channel.request_timeout) as response:
                if response.status != 200:
                    logger.error(f"Канал {channel.url} вернул статус {response.status}")
                    channel.update_channel_stats(success=False)
                    return proxies
                text = await response.text()
                response_time = asyncio.get_event_loop().time() - start_time
                logger.info(f"Контент из {channel.url} загружен за {response_time:.2f} сек")
                channel.update_channel_stats(success=True, response_time=response_time)
        except Exception as e:
            logger.error(f"Ошибка загрузки {channel.url}: {e}")
            channel.update_channel_stats(success=False)
            return proxies

        lines = text.splitlines()
        valid_configs_from_channel = 0
        for line in lines:
            line = line.strip()
            if len(line) < MIN_CONFIG_LENGTH or not any(line.startswith(p) for p in ALLOWED_PROTOCOLS):
                continue
            try:
                parsed = urlparse(line)
                if not parsed.hostname or not parsed.port or (not is_valid_ipv4(parsed.hostname) and ":" in parsed.hostname):
                    continue
                if parsed.scheme == 'vless':
                    profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
                    if profile_id and not is_valid_uuid(profile_id):
                        logger.debug(f"Пропущен {line}: неверный UUID")
                        continue
                if not is_valid_proxy_url(line):
                    continue
                profile_key = create_profile_key(line)
                if profile_key in existing_profiles_regex:
                    continue
                existing_profiles_regex.add(profile_key)
                score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)
                if score > MIN_ACCEPTABLE_SCORE:
                    proxies.append({"config": line, "protocol": parsed.scheme + "://", "score": score})
                    valid_configs_from_channel += 1
            except ValueError as e:
                logger.debug(f"Ошибка парсинга {line}: {e}")
                continue
        channel.metrics.valid_configs += valid_configs_from_channel
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(existing_profiles_regex)
        logger.info(f"Канал {channel.url}: {valid_configs_from_channel} конфигураций")
        return proxies

async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы асинхронно."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all = []
    existing_profiles_regex = set()
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles_regex, proxy_config) for channel in channels]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=1200)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Ошибка обработки канала: {result}")
                else:
                    proxies_all.extend(result)
        except asyncio.TimeoutError:
            logger.error("Обработка каналов превысила время ожидания 20 минут")
    return proxies_all

def save_final_configs(proxies: List[Dict], output_file: str):
    """Сохраняет финальные конфигурации в файл."""
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True)
    seen_configs = set()
    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies_sorted:
                if proxy['score'] > MIN_ACCEPTABLE_SCORE:
                    config = proxy['config'].split('#')[0].strip()
                    profile_name = generate_custom_name(config)
                    final_line = f"{config}# {profile_name}\n"
                    if final_line not in seen_configs:
                        seen_configs.add(final_line)
                        f.write(final_line)
        logger.info(f"Сохранено {len(seen_configs)} конфигураций в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка сохранения: {e}")

def main():
    """Главная функция скрипта."""
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    async def runner():
        try:
            proxies = await process_all_channels(channels, proxy_config)
            save_final_configs(proxies, proxy_config.OUTPUT_FILE)
            total_channels = len(channels)
            enabled_channels = sum(1 for channel in channels)
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
            logger.info(f"Всего валидных конфигураций: {total_valid_configs}")
            logger.info(f"Всего уникальных конфигураций: {total_unique_configs}")
            logger.info(f"Успешных загрузок: {total_successes}")
            logger.info(f"Неудачных загрузок: {total_fails}")
            for protocol, count in protocol_stats.items():
                logger.info(f"  {protocol}: {count}")
            logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")
        except Exception as e:
            logger.error(f"Ошибка в main: {e}")
    asyncio.run(runner())

if __name__ == "__main__":
    main()
