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
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from collections import defaultdict
import logging
import ipaddress
import io
from enum import Enum
import shutil
import uuid
import zipfile

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"

class ScoringWeights(Enum):
    """Scoring weights."""
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
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> None:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    try:
                        ScoringWeights[name].value = value
                    except KeyError:
                        logger.warning(f"Unknown scoring weight in file: {name}. Weight ignored.")
                    except ValueError:
                        logger.error(f"Invalid weight value for {name}: {value}. Using default.")
        except FileNotFoundError:
            logger.warning(f"Scoring weights file not found: {file_path}. Using defaults.")
            ScoringWeights._create_default_weights_file(file_path)
        except json.JSONDecodeError:
            logger.error(f"Error reading JSON weights file: {file_path}. Using defaults.")
        except Exception as e:
            logger.error(f"Unexpected error loading scoring weights from {file_path}: {e}. Using defaults.")

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

ScoringWeights.load_weights_from_json()

MIN_ACCEPTABLE_SCORE = 100.0
MIN_CONFIG_LENGTH = 40
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "trojan://"]
PREFERRED_PROTOCOLS = ["vless://", "trojan://", "tuic://", "hy2://"]
CHECK_USERNAME = True
CHECK_TLS_REALITY = True
CHECK_SNI = True
CHECK_CONNECTION_TYPE = True
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
TEST_URL_FOR_PROXY_CHECK = "http://speed.cloudflare.com"


MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS = 60


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
            raise ValueError("URL cannot be empty.")
        if not isinstance(url, str):
            raise ValueError(f"URL must be a string, got: {type(url).__name__}")
        url = url.strip()
        valid_protocols = ('http://', 'https://', 'ssconf://', 'trojan://')
        if not any(url.startswith(proto) for proto in valid_protocols):
            raise ValueError(f"Invalid URL protocol. Expected: {', '.join(valid_protocols)}, got: {url[:url.find('://') + 3] if '://' in url else url[:10]}...")
        return url

    def calculate_overall_score(self):
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = round((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus + response_time_penalty, 2)
            self.metrics.overall_score = max(0, self.metrics.overall_score)

        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
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
        return self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value if self.metrics.avg_response_time > 0 else 0

    def update_channel_stats(self, success: bool, response_time: float = 0):
        assert isinstance(success, bool), f"Argument 'success' must be bool, got {type(success)}"
        assert isinstance(response_time, (int, float)), f"Argument 'response_time' must be a number, got {type(response_time)}"

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
                            logger.warning(f"Invalid URL in {ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"URLs file not found: {ALL_URLS_FILE}. Creating empty file.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Error reading {ALL_URLS_FILE}: {e}")

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.TEST_URL_FOR_PROXY_CHECK = TEST_URL_FOR_PROXY_CHECK # Добавлено для HTTP проверки

    def _normalize_url(self, url: str) -> str:
        try:
            if not url:
                raise ValueError("URL cannot be empty for normalization.")
            url = url.strip()
            if url.startswith('ssconf://'):
                url = url.replace('ssconf://', 'https://', 1)
            parsed = urlparse(url)
            if not parsed.scheme:
                raise ValueError(f"Missing scheme in URL: '{url}'. Expected 'http://' or 'https://'.")
            if not parsed.netloc:
                raise ValueError(f"Missing netloc (domain or IP) in URL: '{url}'.")

            path = parsed.path.rstrip('/')
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"URL normalization error: {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        try:
            seen_urls = set()
            unique_configs = []
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Invalid config skipped: {config}")
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
                logger.error("No valid sources found. Created empty config file.")
                return []
            return unique_configs
        except Exception as e:
            logger.error(f"Error removing duplicate URLs: {str(e)}")
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
            logger.error(f"Error saving empty config file: {str(e)}")
            return False

def _calculate_config_length_score(config: str) -> float:
    return min(ScoringWeights.CONFIG_LENGTH.value, (len(config) / 200.0) * ScoringWeights.CONFIG_LENGTH.value)

def _calculate_security_score(query: Dict) -> float:
    score = 0
    security_params = query.get('security', [])
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
    transport_type = query.get('type', ['tcp'])[0].lower()
    return {
        "tcp": ScoringWeights.TRANSPORT_TYPE_TCP.value,
        "ws": ScoringWeights.TRANSPORT_TYPE_WS.value,
        "quic": ScoringWeights.TRANSPORT_TYPE_QUIC.value,
    }.get(transport_type, 0)

def _calculate_encryption_score(query: Dict) -> float:
    encryption_type = query.get('encryption', ['none'])[0].lower()
    return {
        "none": ScoringWeights.ENCRYPTION_TYPE_NONE.value,
        "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO.value,
        "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM.value,
        "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305.value,
        "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO.value
    }.get(encryption_type, 0)

def _calculate_sni_score(query: Dict) -> float:
    score = 0
    sni = query.get('sni', [None])[0]
    if sni:
        score += ScoringWeights.SNI_PRESENT.value
        if sni.endswith(('.com', '.net', '.org', '.info', '.xyz')):
            score += ScoringWeights.COMMON_SNI_BONUS.value
    return score

def _calculate_alpn_score(query: Dict) -> float:
    score = 0
    alpn = query.get('alpn', [None])[0]
    if alpn:
        score += ScoringWeights.ALPN_PRESENT.value
        alpn_protocols = alpn.split(',')
        score += min(ScoringWeights.NUM_ALPN_PROTOCOLS.value, len(alpn_protocols) * (ScoringWeights.NUM_ALPN_PROTOCOLS.value / 2))
    return score

def _calculate_path_score(query: Dict) -> float:
    score = 0
    path = query.get('path', [None])[0]
    if path:
        score += ScoringWeights.PATH_PRESENT.value
        complexity = len(re.findall(r'[^a-zA-Z0-9]', path)) + (len(path) / 10)
        score += min(ScoringWeights.PATH_COMPLEXITY.value, complexity * (ScoringWeights.PATH_COMPLEXITY.value / 5))
    return score

def _calculate_headers_score(query: Dict, sni: Optional[str]) -> float:
    score = 0
    headers = query.get('headers', [None])[0]
    if headers:
        score += ScoringWeights.HEADERS_PRESENT.value
        try:
            headers_dict = dict(item.split(":") for item in headers.split("&"))
            score += min(ScoringWeights.NUM_HEADERS.value, len(headers_dict) * (ScoringWeights.NUM_HEADERS.value / 2))
            host_header = headers_dict.get('Host', None)
            if host_header:
                score += ScoringWeights.HOST_HEADER.value
                if sni and host_header == sni:
                    score += ScoringWeights.HOST_SNI_MATCH.value
        except Exception:
            pass
    return score


def _calculate_tls_fingerprint_score(query: Dict) -> float:
    score = 0
    fp = query.get('fp', [None])[0]
    if fp:
        fingerprint_score = {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value,
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI.value,
            "edge": ScoringWeights.UTLS_VALUE_EDGE.value if hasattr(ScoringWeights, 'UTLS_VALUE_EDGE') else ScoringWeights.UTLS_VALUE_CHROME.value
        }.get(fp.lower(), 0)
        if fingerprint_score is not None:
            score += fingerprint_score
        else:
            score += 0
    return score

def _calculate_utls_score(query: Dict) -> float:
    score = 0
    utls = query.get('utls', [None])[0]
    if utls:
        score += ScoringWeights.UTLS_PRESENT.value
        utls_score = {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value,
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI,
            "randomized": ScoringWeights.UTLS_VALUE_RANDOMIZED.value,
            "random": ScoringWeights.UTLS_VALUE_RANDOM.value
        }.get(utls.lower(), 0)
        if utls_score is not None:
            score += utls_score
        else:
            score += 0
    return score

def _calculate_udp_score(protocol: str) -> float:
    return ScoringWeights.UDP_SUPPORT.value if protocol in ("tuic://", "hy2://") else 0

def _calculate_port_score(port: Optional[int]) -> float:
    if port:
        return {
            80: ScoringWeights.PORT_80.value,
            443: ScoringWeights.PORT_443.value
        }.get(port, ScoringWeights.PORT_OTHER.value)
    return 0

def _calculate_uuid_score(parsed: urlparse, query: Dict) -> float:
    score = 0
    uuid_val = parsed.username or query.get('id', [None])[0]
    if uuid_val and parsed.scheme == 'vless':
        score += ScoringWeights.UUID_PRESENT.value
        score += min(ScoringWeights.UUID_LENGTH.value, len(uuid_val) * (ScoringWeights.UUID_LENGTH.value / 36))
    return score

def _calculate_trojan_password_score(parsed: urlparse) -> float:
    score = 0
    password = parsed.password
    if password:
        score += ScoringWeights.TROJAN_PASSWORD_PRESENT.value
        score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH.value, len(password) * (ScoringWeights.TROJAN_PASSWORD_LENGTH.value / 16))
    return score


def _calculate_early_data_score(query: Dict) -> float:
    return ScoringWeights.EARLY_DATA_SUPPORT.value if query.get('earlyData', [None])[0] == "1" else 0

def _calculate_parameter_consistency_score(query: Dict, sni: Optional[str], host_header: Optional[str]) -> float:
    score = 0
    if sni and host_header and sni != host_header:
        score -= (ScoringWeights.PARAMETER_CONSISTENCY.value / 2)
    return score

def _calculate_ipv6_score(parsed: urlparse) -> float:
    return ScoringWeights.IPV6_ADDRESS.value if ":" in parsed.hostname else 0

def _calculate_hidden_param_score(query: Dict) -> float:
    score = 0
    known_params = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls',
        'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment'
    )
    for key, value in query.items():
        if key not in known_params:
            score += ScoringWeights.HIDDEN_PARAM.value
            if value and value[0]:
                score += min(ScoringWeights.RARITY_BONUS.value, ScoringWeights.RARITY_BONUS.value / len(value[0]))
    return score

def _calculate_buffer_size_score(query: Dict) -> float:
    score = 0
    buffer_size = query.get('bufferSize', [None])[0]
    if buffer_size:
        buffer_size = buffer_size.lower()
        score_val = {
            "unlimited": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "small": ScoringWeights.BUFFER_SIZE_SMALL.value,
            "medium": ScoringWeights.BUFFER_SIZE_MEDIUM.value,
            "large": ScoringWeights.BUFFER_SIZE_LARGE.value,
            "-1": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "0": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
        }.get(buffer_size, 0)
        if score_val is not None:
            score += score_val
        else:
            score += 0
    return score

def _calculate_tcp_optimization_score(query: Dict) -> float:
    return ScoringWeights.TCP_OPTIMIZATION.value if query.get('tcpFastOpen', [None])[0] == "true" else 0

def _calculate_quic_param_score(query: Dict) -> float:
    return ScoringWeights.QUIC_PARAM.value if query.get('maxIdleTime', [None])[0] else 0


def _calculate_cdn_usage_score(sni: Optional[str]) -> float:
    return ScoringWeights.CDN_USAGE.value if sni and ".cdn." in sni else 0

def _calculate_mtu_size_score(query: Dict) -> float:
    return 0.0

def _calculate_obfs_score(query: Dict) -> float:
    return ScoringWeights.OBFS.value if query.get('obfs', [None])[0] else 0

def _calculate_debug_param_score(query: Dict) -> float:
    return ScoringWeights.DEBUG_PARAM.value if query.get('debug', [None])[0] == "true" else 0

def _calculate_comment_score(query: Dict) -> float:
    return ScoringWeights.COMMENT.value if query.get('comment', [None])[0] else 0

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
        logger.error(f"Error parsing URL {config}: {e}")
        return 0.0

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    score += ScoringWeights.PROTOCOL_BASE.value
    score += _calculate_config_length_score(config)
    score += _calculate_security_score(query)
    score += _calculate_transport_score(query)
    score += _calculate_encryption_score(query)
    score += _calculate_sni_score(query)
    score += _calculate_alpn_score(query)
    score += _calculate_path_score(query)
    sni = query.get('sni', [None])[0]
    score += _calculate_headers_score(query, sni)
    tls_fingerprint_score = _calculate_tls_fingerprint_score(query)
    if tls_fingerprint_score is not None:
        score += tls_fingerprint_score
    utls_score_val = _calculate_utls_score(query)
    if utls_score_val is not None:
        score += utls_score_val
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
    score += response_time * ScoringWeights.RESPONSE_TIME.value
    buffer_size_score = _calculate_buffer_size_score(query)
    if buffer_size_score is not None:
        score += buffer_size_score
    tcp_optimization_score = _calculate_tcp_optimization_score(query)
    if tcp_optimization_score is not None:
        score += tcp_optimization_score
    quic_param_score = _calculate_quic_param_score(query)
    if quic_param_score is not None:
        score += quic_param_score
    score += ScoringWeights.STREAM_ENCRYPTION.value
    score += _calculate_cdn_usage_score(sni)
    mtu_size_score = _calculate_mtu_size_score(query)
    if mtu_size_score is not None:
        score += mtu_size_score
    score += _calculate_obfs_score(query)
    score += _calculate_debug_param_score(query)
    score += _calculate_comment_score(query)
    client_compatibility_score = _calculate_client_compatibility_score(query)
    if client_compatibility_score is not None:
        score += client_compatibility_score
    session_resumption_score = _calculate_session_resumption_score(query)
    if session_resumption_score is not None:
        score += session_resumption_score
    fallback_type_score = _calculate_fallback_type_score(query)
    if fallback_type_score is not None:
        score += fallback_type_score
    webtransport_score = _calculate_webtransport_score(query)
    if webtransport_score is not None:
        score += webtransport_score
    security_direct_score = _calculate_security_direct_score(query)
    if security_direct_score is not None:
        score += security_direct_score
    tls_version_score = _calculate_tls_version_score(query)
    if tls_version_score is not None:
        score += tls_version_score
    multiplexing_score = _calculate_multiplexing_score(query)
    if multiplexing_score is not None:
        score += multiplexing_score

    return round(score, 2)


def generate_custom_name(config: str) -> str:
    """Generates a custom name for proxy profile from config URL."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return "UNKNOWN"

    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        name_parts = [protocol.split("://")[0].upper()]

        if parsed.scheme in ("vless"):
            transport_type = query.get("type", ["NONE"])[0].upper()
            security_type = query.get("security", ["NONE"])[0].upper()
            name_parts.append(transport_type)
            name_parts.append(security_type)
        elif parsed.scheme in ("tuic", "hy2"):
            name_parts.append(parsed.scheme.upper())
        elif parsed.scheme in ("trojan"):
            transport_type = query.get("type", ["NONE"])[0].upper()
            security_type = query.get("security", ["NONE"])[0].upper()
            name_parts.append(transport_type)
            name_parts.append(security_type)

        return " - ".join(filter(lambda x: x != "NONE" and x, name_parts))
    except Exception as e:
        logger.error(f"Error creating custom name for {config}: {e}")
        return "UNKNOWN"

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

        core_pattern = re.compile(r"^(vless|tuic|hy2|trojan)://.*?@([\w\d\.\:]+):(\d+)")
        match = core_pattern.match(config)

        if match:
            protocol, host_port, port = match.groups()
            host = host_port.split(':')[0] if ':' in host_port else host_port
            key_parts = [
                protocol,
                host,
                port,
            ]

            if CHECK_USERNAME or protocol == 'trojan':
                user = parsed.username
                password = parsed.password
                id_value = query.get('id', [None])[0]
                if user:
                    key_parts.append(f"user:{user}")
                elif password and protocol == 'trojan':
                    key_parts.append(f"password:***")
                elif id_value:
                    key_parts.append(f"id:{id_value}")

            if CHECK_TLS_REALITY:
                 key_parts.append(f"security:{query.get('security', [''])[0]}")
                 key_parts.append(f"encryption:{query.get('encryption', [''])[0]}")

            if CHECK_SNI:
                key_parts.append(f"sni:{query.get('sni', [''])[0]}")

            if CHECK_CONNECTION_TYPE:
                key_parts.append(f"type:{query.get('type', [''])[0]}")

            return "|".join(key_parts)
        else:
            return config

    except Exception as e:
        logger.error(f"Error creating profile key for {config}: {e}")
        raise ValueError(f"Failed to create profile key: {config}") from e

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
                    logger.error(f"Channel {channel.url} returned status {response.status}")
                    channel.check_count += 1
                    channel.update_channel_stats(success=False)
                    return proxies

                text = await response.text()
                end_time = asyncio.get_event_loop().time()
                response_time = end_time - start_time
                logger.info(f"Content from {channel.url} loaded in {response_time:.2f} seconds")
                channel.update_channel_stats(success=True, response_time=response_time)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Error loading from {channel.url}: {type(e).__name__} - {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies
        except Exception as e:
            logger.exception(f"Unexpected error loading from {channel.url}: {e}")
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
                        logger.debug(f"Profile {line} skipped due to invalid UUID format: {profile_id}")
                        continue
                if not is_valid_proxy_url(line): # Используем новую функцию проверки URL прокси
                    logger.debug(f"Profile {line} skipped due to invalid proxy URL format.")
                    continue


            except ValueError as e:
                logger.debug(f"URL parsing error {line}: {e}")
                continue

            match = DUPLICATE_PROFILE_REGEX.match(line)
            if match:
                duplicate_key = f"{match.group(1)}://{match.group(2)}:{match.group(3)}"
                if duplicate_key in existing_profiles_regex:
                    continue
                existing_profiles_regex.add(duplicate_key)
            else:
                logger.warning(f"Failed to create duplicate filter key for: {line}")
                continue

            score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)

            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                valid_configs_from_channel += 1

        channel.metrics.valid_configs += valid_configs_from_channel
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(set(create_profile_key(l["config"]) for l in proxies))

        channel.check_count += 1
        logger.info(f"Channel {channel.url}: Found {valid_configs_from_channel} valid configurations.")
        return proxies


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Processes all channels to extract and verify proxy configurations."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles_regex = set()

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles_regex, proxy_config) for channel in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Exception processing channel: {result}")
            else:
                proxies_all.extend(result)

    return proxies_all


async def verify_proxies_availability(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Verifies proxy availability using TCP handshake and HTTP check."""
    available_proxies_tcp, verified_count_tcp, non_verified_count_tcp = await verify_proxies_availability_tcp_handshake(proxies, proxy_config)
    available_proxies_http, verified_count_http, non_verified_count_http = await verify_proxies_availability_http(available_proxies_tcp, proxy_config) # Проверяем HTTP только TCP-прошедшие

    verified_count_total = verified_count_http
    non_verified_count_total = len(proxies) - verified_count_total

    return available_proxies_http, verified_count_total, non_verified_count_total


async def verify_proxies_availability_tcp_handshake(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Verifies proxy availability via TCP handshake with concurrency control."""
    available_proxies_tcp = []
    verified_count_tcp = 0
    non_verified_count_tcp = 0

    logger.info("Starting proxy availability check via TCP handshake...")

    tcp_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS)

    tasks = []
    for proxy_item in proxies:
        config = proxy_item['config']
        parsed_url = urlparse(config)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if hostname and port:
            tasks.append(_verify_proxy_tcp_handshake(hostname, port, tcp_semaphore, proxy_item))
        else:
            non_verified_count_tcp += 1
            logger.warning(f"Could not determine host and port for proxy {config}. Skipping TCP check.")

    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            is_available, proxy_item = result
            if is_available:
                available_proxies_tcp.append(proxy_item)
                verified_count_tcp += 1
            else:
                non_verified_count_tcp += 1

    logger.info(f"TCP handshake availability check complete. Available: {len(available_proxies_tcp)} of {len(proxies)} proxies.")
    return available_proxies_tcp, verified_count_tcp, non_verified_count_tcp


async def _verify_proxy_tcp_handshake(hostname: str, port: int, tcp_semaphore: asyncio.Semaphore, proxy_item: Dict) -> Tuple[bool, Dict]:
    """Verifies TCP server availability with semaphore for concurrency control."""
    try:
        async with tcp_semaphore:
            async with asyncio.timeout(5):
                reader, writer = await asyncio.open_connection(hostname, port)
                writer.close()
                await writer.wait_closed()
                logger.debug(f"TCP handshake: Proxy {hostname}:{port} passed.")
                return True, proxy_item
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug(f"TCP handshake failed for {hostname}:{port}: {type(e).__name__} - {e}")
        return False, proxy_item


async def verify_proxies_availability_http(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Verifies proxy availability via HTTP GET request through proxy."""
    available_proxies_http = []
    verified_count_http = 0
    non_verified_count_http = 0

    logger.info("Starting proxy availability check via HTTP...")

    http_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS) # Используем тот же лимит concurrency, можно сделать отдельный

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as session: # Используем ClientSession
        tasks = []
        for proxy_item in proxies:
            config = proxy_item['config']
            tasks.append(_verify_proxy_http(config, session, http_semaphore, proxy_item, proxy_config.TEST_URL_FOR_PROXY_CHECK))

        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                is_available, proxy_item = result
                if is_available:
                    available_proxies_http.append(proxy_item)
                    verified_count_http += 1
                else:
                    non_verified_count_http += 1

    logger.info(f"HTTP availability check complete. Available: {len(available_proxies_http)} of {len(proxies)} proxies.")
    return available_proxies_http, verified_count_http, non_verified_count_http


async def _verify_proxy_http(config: str, session: aiohttp.ClientSession, http_semaphore: asyncio.Semaphore, proxy_item: Dict, test_url: str) -> Tuple[bool, Dict]:
    """Verifies HTTP доступность прокси."""
    try:
        async with http_semaphore:
            async with asyncio.timeout(10): # Таймаут HTTP проверки
                proxy_url = f"http://{urlparse(config).hostname}:{urlparse(config).port}" # Формируем URL прокси для aiohttp
                async with session.get(test_url, proxy=proxy_url) as response: # Используем proxy параметр aiohttp
                    if response.status == 200:
                        logger.debug(f"HTTP check: Proxy {config} passed.")
                        return True, proxy_item
                    else:
                        logger.debug(f"HTTP check failed for {config}, status: {response.status}")
                        return False, proxy_item
    except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
        logger.debug(f"HTTP check error for {config}: {type(e).__name__} - {e}")
        return False, proxy_item


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
        logger.info(f"Final configurations saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving configurations: {str(e)}")

def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()

    async def runner():
        proxies = await process_all_channels(channels, proxy_config)
        verified_proxies, verified_count, non_verified_count = await verify_proxies_availability(proxies, proxy_config)
        save_final_configs(verified_proxies, proxy_config.OUTPUT_FILE)

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

        logger.info("================== STATISTICS ==================")
        logger.info(f"Total channels: {total_channels}")
        logger.info(f"Enabled channels: {enabled_channels}")
        logger.info(f"Disabled channels: {disabled_channels}")
        logger.info(f"Total valid configurations: {total_valid_configs}")
        logger.info(f"Total unique configurations: {total_unique_configs}")
        logger.info(f"Total download successes: {total_successes}")
        logger.info(f"Total download failures: {total_fails}")
        logger.info(f"Proxies passed check: {verified_count}") # Обновлено: показывает количество прокси, прошедших ОБЕ проверки (TCP и HTTP)
        logger.info(f"Proxies failed check: {non_verified_count}") # Обновлено: показывает количество прокси, не прошедших ОБЕ проверки
        logger.info("Protocol Statistics:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")
        logger.info("================== END STATISTICS ==============")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
