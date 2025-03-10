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
import hashlib # Import for hash-based cache

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"

class ScoringWeights(Enum):
    """Scoring weights - Optimized for VLESS, Trojan, Tuic, Hy2."""
    PROTOCOL_BASE = 50
    CONFIG_LENGTH = 10
    SECURITY_PARAM = 15
    NUM_SECURITY_PARAMS = 5
    SECURITY_TYPE_TLS = 10
    SECURITY_TYPE_REALITY = 12 # Keep for Reality, if used
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
    UTLS_PRESENT = 4 # Keep UTLS related weights as they can be present
    UTLS_VALUE_CHROME = 5
    UTLS_VALUE_FIREFOX = 4
    UTLS_VALUE_IOS = 2
    UTLS_VALUE_SAFARI = 3
    UTLS_VALUE_RANDOMIZED = 7
    UTLS_VALUE_RANDOM = 6
    UDP_SUPPORT = 7 # Keep UDP support as Tuic and Hy2 use it
    PORT_80 = 5
    PORT_443 = 10
    PORT_OTHER = 2
    UUID_PRESENT = 5 # Keep UUID for VLESS
    UUID_LENGTH = 3
    EARLY_DATA_SUPPORT = 5 # Keep Early Data - relevant for some protocols/setups
    PARAMETER_CONSISTENCY = 12 # Keep Parameter Consistency
    IPV6_ADDRESS = -9 # Keep IPv6 penalty
    RARITY_BONUS = 4 # Keep Rarity Bonus for less common params
    HIDDEN_PARAM = 6 # Keep Hidden Param score
    NEW_PARAM = 5 # Keep New Param score
    RESPONSE_TIME = -0.05
    CHANNEL_STABILITY = 20
    BUFFER_SIZE_SMALL = -2 # Keep Buffer Size related weights - can be present
    BUFFER_SIZE_MEDIUM = 3
    BUFFER_SIZE_LARGE = 7
    BUFFER_SIZE_UNLIMITED = 5
    TCP_OPTIMIZATION = 5 # Keep TCP Optimization - can be present
    QUIC_PARAM = 3 # Keep QUIC Param - relevant for QUIC transport
    STREAM_ENCRYPTION = 6 # Keep Stream Encryption
    CDN_USAGE = 8 # Keep CDN Usage
    OBFS = 4 # Keep OBFS - can be present
    DEBUG_PARAM = -3 # Keep Debug Param
    COMMENT = 1 # Keep Comment
    TROJAN_PASSWORD_PRESENT = 8 # Keep Trojan Password related weights
    TROJAN_PASSWORD_LENGTH = 5

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

MIN_ACCEPTABLE_SCORE = 90.0 # Optimized Constant
MIN_CONFIG_LENGTH = 30 # Optimized Constant
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "trojan://"]
PREFERRED_PROTOCOLS = ["vless://", "trojan://", "tuic://", "hy2://"]
CHECK_USERNAME = False # Optimized Constant - Disabled checks
CHECK_TLS_REALITY = False # Optimized Constant - Disabled checks
CHECK_SNI = False # Optimized Constant - Disabled checks
CHECK_CONNECTION_TYPE = False # Optimized Constant - Disabled checks
MAX_CONCURRENT_CHANNELS = 200 # Optimized Constant
REQUEST_TIMEOUT = 60 # Optimized Constant
HIGH_FREQUENCY_THRESHOLD_HOURS = 12 # Optimized Constant
HIGH_FREQUENCY_BONUS = 3 # Optimized Constant
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
TEST_URL_FOR_PROXY_CHECK = "http://speed.cloudflare.com" # Removed
MAX_CONCURRENT_HTTP_CHECKS = 60 # Replaced TCP_HANDSHAKE with HTTP Checks, keeping concurrency limit # Removed


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
        if not url:
            raise ValueError("URL не может быть пустым.")
        if not isinstance(url, str):
            raise ValueError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        valid_protocols = ('http://', 'https://', 'trojan://', 'vless://', 'tuic://', 'hy2://') # Убрали ssconf://
        if not any(url.startswith(proto) for proto in valid_protocols):
            raise ValueError(f"Неверный протокол URL. Ожидается: {', '.join(valid_protocols)}, получено: {url[:url.find('://') + 3] if '://' in url else url[:10]}...")
        return url

    def calculate_overall_score(self):
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = round((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus + response_time_penalty, 2) # Use .value
            self.metrics.overall_score = max(0, self.metrics.overall_score)

        except Exception as e:
            logger.error(f"Ошибка при расчете скора для {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        total_checks = self.metrics.success_count + self.metrics.fail_count
        return self.metrics.success_count / total_checks if total_checks > 0 else 0

    def _calculate_recency_bonus(self) -> float:
        if self.metrics.last_success_time:
            time_since_last_success = datetime.now() - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0
        return 0

    def _calculate_response_time_penalty(self) -> float:
        return self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value if self.metrics.avg_response_time > 0 else 0 # Use .value

    def update_channel_stats(self, success: bool, response_time: float = 0):
        assert isinstance(success, bool), f"Аргумент 'success' должен быть bool, получено {type(success)}"
        assert isinstance(response_time, (int, float)), f"Аргумент 'response_time' должен быть числом, получено {type(response_time)}"

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
            logger.warning(f"Файл URL не найден: {ALL_URLS_FILE}. Создается пустой файл.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        # self.TEST_URL_FOR_PROXY_CHECK = TEST_URL_FOR_PROXY_CHECK # Removed

    def _normalize_url(self, url: str) -> str:
        try:
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
        except Exception as e:
            logger.error(f"Ошибка нормализации URL: {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        try:
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
        except Exception as e:
            logger.error(f"Ошибка удаления дубликатов URL: {str(e)}")
            self.save_empty_config_file()
            return []

    def get_enabled_channels(self) -> List[ChannelConfig]:
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {str(e)}")
            return False

def _calculate_config_length_score(config: str) -> float:
    return min(ScoringWeights.CONFIG_LENGTH.value, (len(config) / 200.0) * ScoringWeights.CONFIG_LENGTH.value) # Use .value

def _calculate_security_score(query: Dict) -> float:
    score = 0
    security_params = query.get('security', [])
    if security_params:
        score += ScoringWeights.SECURITY_PARAM.value # Use .value
        score += min(ScoringWeights.NUM_SECURITY_PARAMS.value, len(security_params) * (ScoringWeights.NUM_SECURITY_PARAMS.value / 3)) # Use .value
        security_type = security_params[0].lower() if security_params else 'none'
        score += {
            "tls": ScoringWeights.SECURITY_TYPE_TLS.value, # Use .value
            "reality": ScoringWeights.SECURITY_TYPE_REALITY.value, # Use .value # Keep Reality
            "none": ScoringWeights.SECURITY_TYPE_NONE.value # Use .value
        }.get(security_type, 0)
    return score

def _calculate_transport_score(query: Dict) -> float:
    transport_type = query.get('type', ['tcp'])[0].lower()
    return {
        "tcp": ScoringWeights.TRANSPORT_TYPE_TCP.value, # Use .value
        "ws": ScoringWeights.TRANSPORT_TYPE_WS.value, # Use .value
        "quic": ScoringWeights.TRANSPORT_TYPE_QUIC.value, # Use .value
    }.get(transport_type, 0)

def _calculate_encryption_score(query: Dict) -> float:
    encryption_type = query.get('encryption', ['none'])[0].lower()
    return {
        "none": ScoringWeights.ENCRYPTION_TYPE_NONE.value, # Use .value
        "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO.value, # Use .value
        "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM.value, # Use .value
        "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305.value, # Use .value
        "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO.value # Use .value
    }.get(encryption_type, 0)

def _calculate_sni_score(query: Dict) -> float:
    score = 0
    sni = query.get('sni', [None])[0]
    if sni:
        score += ScoringWeights.SNI_PRESENT.value # Use .value
        if sni.endswith(('.com', '.net', '.org', '.info', '.xyz')):
            score += ScoringWeights.COMMON_SNI_BONUS.value # Use .value
    return score

def _calculate_alpn_score(query: Dict) -> float:
    score = 0
    alpn = query.get('alpn', [None])[0]
    if alpn:
        score += ScoringWeights.ALPN_PRESENT.value # Use .value
        alpn_protocols = alpn.split(',')
        score += min(ScoringWeights.NUM_ALPN_PROTOCOLS.value, len(alpn_protocols) * (ScoringWeights.NUM_ALPN_PROTOCOLS.value / 2)) # Use .value
    return score

def _calculate_path_score(query: Dict) -> float:
    score = 0
    path = query.get('path', [None])[0]
    if path:
        score += ScoringWeights.PATH_PRESENT.value # Use .value
        complexity = len(re.findall(r'[^a-zA-Z0-9]', path)) + (len(path) / 10)
        score += min(ScoringWeights.PATH_COMPLEXITY.value, complexity * (ScoringWeights.PATH_COMPLEXITY.value / 5)) # Use .value
    return score

def _calculate_headers_score(query: Dict, sni: Optional[str]) -> float:
    score = 0
    headers = query.get('headers', [None])[0]
    if headers:
        score += ScoringWeights.HEADERS_PRESENT.value # Use .value
        try:
            headers_dict = dict(item.split(":") for item in headers.split("&"))
            score += min(ScoringWeights.NUM_HEADERS.value, len(headers_dict) * (ScoringWeights.NUM_HEADERS.value / 2)) # Use .value
            host_header = headers_dict.get('Host', None)
            if host_header:
                score += ScoringWeights.HOST_HEADER.value # Use .value
                if sni and host_header == sni:
                    score += ScoringWeights.HOST_SNI_MATCH.value # Use .value
        except Exception:
            pass
    return score


def _calculate_tls_fingerprint_score(query: Dict) -> float:
    return _calculate_utls_score(query) # если fp это utls, используем _calculate_utls_score

def _calculate_utls_score(query: Dict) -> float:
    score = 0
    utls = query.get('utls', query.get('fp', [None]))[0] # fp fallback for utls
    if utls:
        score += ScoringWeights.UTLS_PRESENT.value # Use .value
        utls_score = {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value, # Use .value
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value, # Use .value
            "ios": ScoringWeights.UTLS_VALUE_IOS.value, # Use .value
            "safari": ScoringWeights.UTLS_VALUE_SAFARI.value, # Use .value
            "randomized": ScoringWeights.UTLS_VALUE_RANDOMIZED.value, # Use .value
            "random": ScoringWeights.UTLS_VALUE_RANDOM.value, # Use .value
            "edge": ScoringWeights.UTLS_VALUE_EDGE.value if hasattr(ScoringWeights, 'UTLS_VALUE_EDGE') else ScoringWeights.UTLS_VALUE_CHROME.value # Use .value # Edge fallback
        }.get(utls.lower(), 0)
        if utls_score is not None:
            score += utls_score
    return score

def _calculate_udp_score(protocol: str) -> float:
    return ScoringWeights.UDP_SUPPORT.value if protocol in ("tuic://", "hy2://") else 0 # Use .value

def _calculate_port_score(port: Optional[int]) -> float:
    if port:
        return {
            80: ScoringWeights.PORT_80.value, # Use .value
            443: ScoringWeights.PORT_443.value # Use .value
        }.get(port, ScoringWeights.PORT_OTHER.value) # Use .value
    return 0

def _calculate_uuid_score(parsed: urlparse, query: Dict) -> float:
    score = 0
    uuid_val = parsed.username or query.get('id', [None])[0]
    if uuid_val and parsed.scheme == 'vless':
        score += ScoringWeights.UUID_PRESENT.value # Use .value
        score += min(ScoringWeights.UUID_LENGTH.value, len(uuid_val) * (ScoringWeights.UUID_LENGTH.value / 36)) # Use .value
    return score

def _calculate_trojan_password_score(parsed: urlparse) -> float:
    score = 0
    password = parsed.password
    if password:
        score += ScoringWeights.TROJAN_PASSWORD_PRESENT.value # Use .value
        score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH.value, len(password) * (ScoringWeights.TROJAN_PASSWORD_LENGTH.value / 16)) # Use .value
    return score


def _calculate_early_data_score(query: Dict) -> float:
    return ScoringWeights.EARLY_DATA_SUPPORT.value if query.get('earlyData', [None])[0] == "1" else 0 # Use .value

def _calculate_parameter_consistency_score(query: Dict, sni: Optional[str], host_header: Optional[str]) -> float:
    score = 0
    if sni and host_header and sni != host_header:
        score -= (ScoringWeights.PARAMETER_CONSISTENCY.value / 2) # Use .value
    return score

def _calculate_ipv6_score(parsed: urlparse) -> float:
    return ScoringWeights.IPV6_ADDRESS.value if ":" in parsed.hostname else 0 # Use .value

def _calculate_hidden_param_score(query: Dict) -> float:
    score = 0
    known_params = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls',
        'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment'
    )
    for key, value in query.items():
        if key not in known_params:
            score += ScoringWeights.HIDDEN_PARAM.value # Use .value
            if value and value[0]:
                score += min(ScoringWeights.RARITY_BONUS.value, ScoringWeights.RARITY_BONUS.value / len(value[0])) # Use .value
    return score

def _calculate_buffer_size_score(query: Dict) -> float:
    score = 0
    buffer_size = query.get('bufferSize', [None])[0]
    if buffer_size:
        buffer_size = buffer_size.lower()
        score_val = {
            "unlimited": ScoringWeights.BUFFER_SIZE_UNLIMITED.value, # Use .value
            "small": ScoringWeights.BUFFER_SIZE_SMALL.value, # Use .value
            "medium": ScoringWeights.BUFFER_SIZE_MEDIUM.value, # Use .value
            "large": ScoringWeights.BUFFER_SIZE_LARGE.value, # Use .value
            "-1": ScoringWeights.BUFFER_SIZE_UNLIMITED.value, # Use .value
            "0": ScoringWeights.BUFFER_SIZE_UNLIMITED.value, # Use .value
        }.get(buffer_size, 0)
        if score_val is not None:
            score += score_val
    return score

def _calculate_tcp_optimization_score(query: Dict) -> float:
    return ScoringWeights.TCP_OPTIMIZATION.value if query.get('tcpFastOpen', [None])[0] == "true" else 0 # Use .value

def _calculate_quic_param_score(query: Dict) -> float:
    return ScoringWeights.QUIC_PARAM.value if query.get('maxIdleTime', [None])[0] else 0 # Use .value


def _calculate_cdn_usage_score(sni: Optional[str]) -> float:
    return ScoringWeights.CDN_USAGE.value if sni and ".cdn." in sni else 0 # Use .value

def _calculate_mtu_size_score(query: Dict) -> float:
    return 0.0

def _calculate_obfs_score(query: Dict) -> float:
    return ScoringWeights.OBFS.value if query.get('obfs', [None])[0] else 0 # Use .value

def _calculate_debug_param_score(query: Dict) -> float:
    return ScoringWeights.DEBUG_PARAM.value if query.get('debug', [None])[0] == "true" else 0 # Use .value

def _calculate_comment_score(query: Dict) -> float:
    return ScoringWeights.COMMENT.value if query.get('comment', [None])[0] else 0 # Use .value

def _calculate_client_compatibility_score(query: Dict) -> float:
    return 0.0

def _calculate_session_resumption_score(query: Dict) -> float:
    return 0.0

def _calculate_fallback_type_score(query: Dict) -> float:
    return 0.0

def _calculate_webtransport_score(query: Dict) -> float:
    return 0.0

def _calculate_security_direct_score(query: Dict) -> float:
    return 0.0

def _calculate_tls_version_score(query: Dict) -> float:
    return 0.0

def _calculate_multiplexing_score(query: Dict) -> float:
    return 0.0


def is_valid_uuid(uuid_string: str) -> bool:
    """Validates UUID v4 or v6 format."""
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        try:
            uuid.UUID(uuid_string, version=6)
            return True
        except ValueError:
            return False

def is_valid_proxy_url(url: str) -> bool:
    """Проверяет, является ли URL валидным URL прокси одного из разрешенных протоколов."""
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.port:
            return False
        if not is_valid_ipv4(parsed.hostname) and ":" in parsed.hostname: # Добавлена проверка IPv6 в hostname
            return False
        if parsed.scheme == 'vless' or parsed.scheme == 'trojan': # Исправлено: scheme is 'vless' or 'trojan'
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False
        return True
    except ValueError:
        return False


def compute_profile_score(config: str, response_time: float = 0.0) -> float:
    """Computes score for a given proxy profile configuration."""
    score = 0.0
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
    except Exception as e:
        logger.error(f"Ошибка парсинга URL {config}: {e}")
        return 0.0

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    score += ScoringWeights.PROTOCOL_BASE.value # Use .value
    score += _calculate_config_length_score(config)
    score += _calculate_security_score(query)
    score += _calculate_transport_score(query)
    score += _calculate_encryption_score(query)
    score += _calculate_sni_score(query)
    score += _calculate_alpn_score(query)
    score += _calculate_path_score(query)
    sni = query.get('sni', [None])[0]
    score += _calculate_headers_score(query, sni)
    tls_fingerprint_score = _calculate_tls_fingerprint_score(query) # Using UTLS score now
    if tls_fingerprint_score is not None:
        score += tls_fingerprint_score
    # utls_score_val = _calculate_utls_score(query) # No need to call again, already in tls_fingerprint_score
    # if utls_score_val is not None:
    #     score += utls_score_val
    score += _calculate_udp_score(protocol)
    score += _calculate_port_score(parsed.port)
    score += _calculate_uuid_score(parsed, query)
    if protocol == 'trojan://':
        score += _calculate_trojan_password_score(parsed)
    score += _calculate_early_data_score(query)
    host_header = None
    headers = query.get('headers', [None])[0]
    if headers:
        try:
            headers_dict = dict(item.split(":") for item in headers.split("&"))
            host_header = headers_dict.get('Host', None)
        except:
            pass
    score += _calculate_hidden_param_score(query)
    score += response_time * ScoringWeights.RESPONSE_TIME.value # Use .value
    buffer_size_score = _calculate_buffer_size_score(query)
    if buffer_size_score is not None:
        score += buffer_size_score
    tcp_optimization_score = _calculate_tcp_optimization_score(query)
    if tcp_optimization_score is not None:
        score += tcp_optimization_score
    quic_param_score = _calculate_quic_param_score(query)
    if quic_param_score is not None:
        score += quic_param_score
    score += ScoringWeights.STREAM_ENCRYPTION.value # Use .value
    score += _calculate_cdn_usage_score(sni)
    mtu_size_score = _calculate_mtu_size_score(query) # always 0
    if mtu_size_score is not None:
        score += mtu_size_score
    score += _calculate_obfs_score(query)
    score += _calculate_debug_param_score(query)
    score += _calculate_comment_score(query)
    client_compatibility_score = _calculate_client_compatibility_score(query) # always 0
    if client_compatibility_score is not None:
        score += client_compatibility_score
    session_resumption_score = _calculate_session_resumption_score(query) # always 0
    if session_resumption_score is not None:
        score += session_resumption_score
    fallback_type_score = _calculate_fallback_type_score(query) # always 0
    if fallback_type_score is not None:
        score += fallback_type_score
    webtransport_score = _calculate_webtransport_score(query) # always 0
    if webtransport_score is not None:
        score += webtransport_score
    security_direct_score = _calculate_security_direct_score(query) # always 0
    if security_direct_score is not None:
        score += security_direct_score
    tls_version_score = _calculate_tls_version_score(query) # always 0
    if tls_version_score is not None:
        score += tls_version_score
    multiplexing_score = _calculate_multiplexing_score(query) # always 0
    if multiplexing_score is not None:
        score += multiplexing_score

    return round(score, 2)


def generate_custom_name(config: str) -> str:
    """Generates a custom name for proxy profile from config URL."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return "Неизвестный Протокол"

    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        name_parts = [protocol.split("://")[0].upper()] # Протокол всегда в начале

        if parsed.scheme == "vless":
            transport_type = query.get("type", ["tcp"])[0].upper()
            security_type = query.get("security", ["none"])[0].upper()
            encryption_type = query.get("encryption", ["none"])[0].upper()
            name_parts.extend([f"Транспорт: {transport_type}", f"Безопасность: {security_type}", f"Шифрование: {encryption_type}"])

        elif parsed.scheme == "trojan":
            transport_type = query.get("type", ["tcp"])[0].upper()
            security_type = query.get("security", ["tls"])[0].upper() # Trojan defaults to TLS
            encryption_type = query.get("encryption", ["none"])[0].upper()
            name_parts.extend([f"Транспорт: {transport_type}", f"Безопасность: {security_type}", f"Шифрование: {encryption_type}"])

        elif parsed.scheme in ("tuic", "hy2"): # Для tuic и hy2 просто протокол и транспорт (UDP)
            name_parts.append(parsed.scheme.upper())
            transport_type = "UDP"
            name_parts.append(f"Транспорт: {transport_type}")

        # Финальная сборка, убираем "NONE" и пустые строки, форматируем разделителем
        return " - ".join(part for part in name_parts if part and part.replace(":", "").strip().upper() != "NONE")

    except Exception as e:
        logger.error(f"Ошибка создания пользовательского имени для {config}: {e}")
        return "Неизвестный Прокси"


def is_valid_ipv4(hostname: str) -> bool:
    """Checks if hostname is a valid IPv4 address."""
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def create_profile_key(config: str) -> str:
    """Creates a unique key for proxy profile to identify duplicates."""
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)

        # Normalize query parameters for consistent key generation - sort parameters
        normalized_query_str = urlencode(sorted(query.items()))

        core_pattern = re.compile(r"^(vless|tuic|hy2|trojan)://.*?@([\w\d\.\:]+):(\d+)")
        match = core_pattern.match(config)

        if match:
            protocol, host_port, port = match.groups()
            host = host_port.split(':')[0] if ':' in host_port else host_port
            key_parts = [
                protocol,
                host,
                port,
                normalized_query_str # Включаем нормализованные query параметры
            ]
            return "|".join(key_parts)
        else:
            return config # Если не удалось распарсить, используем полную конфигурацию как ключ (менее идеально, но лучше, чем ничего)

    except Exception as e:
        logger.error(f"Ошибка создания ключа профиля для {config}: {e}")
        raise ValueError(f"Не удалось создать ключ профиля: {config}") from e


DUPLICATE_PROFILE_REGEX = re.compile(
    r"^(vless|tuic|hy2|trojan)://(?:.*?@)?([^@/:]+):(\d+)"
)


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, existing_profiles_regex: set, proxy_config: "ProxyConfig") -> List[Dict]:
    """Processes a single channel URL to extract proxy configurations."""
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
                parsed = urlparse(line)
                hostname = parsed.hostname
                port = parsed.port

                if not hostname or not port:
                    continue
                if not is_valid_ipv4(hostname) and ":" in hostname:
                  continue

                profile_id = None
                if protocol == 'vless://':
                    profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
                elif protocol == 'trojan://':
                    profile_id = parsed.username

                if profile_id:
                    if not is_valid_uuid(profile_id):
                        logger.debug(f"Профиль {line} пропущен из-за неверного формата UUID: {profile_id}")
                        continue
                if not is_valid_proxy_url(line): # Используем новую функцию проверки URL прокси
                    logger.debug(f"Профиль {line} пропущен из-за неверного формата URL прокси.")
                    continue


            except ValueError as e:
                logger.debug(f"Ошибка парсинга URL {line}: {e}")
                continue

            profile_key = create_profile_key(line) # Используем улучшенный create_profile_key
            if profile_key in existing_profiles_regex:
                logger.debug(f"Дубликат профиля найден и пропущен: {line}")
                continue
            existing_profiles_regex.add(profile_key)


            score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)

            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                valid_configs_from_channel += 1

        channel.metrics.valid_configs += valid_configs_from_channel
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(existing_profiles_regex) # Уникальность теперь считаем по ключам

        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {valid_configs_from_channel} валидных конфигураций.")
        return proxies


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Processes all channels to extract and verify proxy configurations."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles_regex = set() # Set для хранения ключей уникальных профилей

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles_regex, proxy_config) for channel in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка при обработке канала: {result}")
            else:
                proxies_all.extend(result)

    return proxies_all


# Removed verify_proxies_availability_http and _verify_proxy_http functions


def save_final_configs(proxies: List[Dict], output_file: str):
    """Saves final proxy configurations to output file."""
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
        logger.error(f"Ошибка сохранения конфигураций: {str(e)}")

def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()

    async def runner():
        proxies = await process_all_channels(channels, proxy_config)
        # verified_proxies, verified_count, non_verified_count = await verify_proxies_availability_http(proxies, proxy_config) # Removed HTTP check
        save_final_configs(proxies, proxy_config.OUTPUT_FILE) # Save all proxies directly

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
        # logger.info(f"Прокси прошли проверку (HTTP): {verified_count}") # Removed HTTP check stats
        # logger.info(f"Прокси не прошли проверку (HTTP): {non_verified_count}") # Removed HTTP check stats
        logger.info("Статистика по протоколам:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")
        logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
