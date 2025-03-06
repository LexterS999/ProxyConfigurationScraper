import asyncio
import aiohttp
import re
import os
import tempfile
import platform
import subprocess
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, quote
from dataclasses import dataclass
from collections import defaultdict
import logging
import socket # Import socket for catching socket.gaierror # import socket
from enum import Enum
import shutil
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Настройка logging на DEBUG для более подробных сообщений
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)


class ScoringWeights(Enum):
    PROTOCOL_BASE = 50
    CONFIG_LENGTH = 10
    SECURITY_PARAM = 15
    NUM_SECURITY_PARAMS = 5
    SECURITY_TYPE_TLS = 10
    SECURITY_TYPE_REALITY = 12 # Reality is TLS extension, relevant
    SECURITY_TYPE_NONE = -5
    TRANSPORT_TYPE_TCP = 2
    TRANSPORT_TYPE_WS = 8
    TRANSPORT_TYPE_QUIC = 6 # Relevant for tuic and hy2
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
    UTLS_PRESENT = 4 # Relevant for TLS-based protocols
    UTLS_VALUE_CHROME = 5
    UTLS_VALUE_FIREFOX = 4
    UTLS_VALUE_IOS = 2
    UTLS_VALUE_SAFARI = 3
    UTLS_VALUE_RANDOMIZED = 7
    UTLS_VALUE_RANDOM = 6
    UDP_SUPPORT = 7 # Relevant for tuic and hy2
    PORT_80 = 5
    PORT_443 = 10
    PORT_OTHER = 2
    UUID_PRESENT = 5 # Relevant for vless
    UUID_LENGTH = 3    # Relevant for vless
    EARLY_DATA_SUPPORT = 5 # TLS related, potentially relevant
    PARAMETER_CONSISTENCY = 12 # General config quality
    IPV6_ADDRESS = -9 # General network characteristic - Keep for IPv6 detection in config
    RARITY_BONUS = 4 # General parameter score - Keep for hidden parameter scoring
    HIDDEN_PARAM = 6  # General parameter score - Keep for hidden parameter scoring
    NEW_PARAM = 5     # General parameter score - Keep for new parameter scoring (if you add new params in future)
    RESPONSE_TIME = -0.05 # Channel metric, general - Keep channel related metrics
    CHANNEL_STABILITY = 20 # Channel metric, general - Keep channel related metrics
    BUFFER_SIZE_SMALL = -2 # General performance parameter - Keep if buffer size is part of profile
    BUFFER_SIZE_MEDIUM = 3 # General performance parameter - Keep if buffer size is part of profile
    BUFFER_SIZE_LARGE = 7 # General performance parameter - Keep if buffer size is part of profile
    BUFFER_SIZE_UNLIMITED = 5 # General performance parameter - Keep if buffer size is part of profile
    TCP_OPTIMIZATION = 5 # TCP related, might be relevant for some transports - Keep if tcpFastOpen is part of profile
    QUIC_PARAM = 3 # QUIC related, relevant for tuic and hy2 - Keep for QUIC params
    STREAM_ENCRYPTION = 6 # General security parameter - Keep if streamEncryption is part of profile
    CDN_USAGE = 8       # Network characteristic - Keep if CDN usage can be inferred from SNI
    OBFS = 4            # General obfuscation - Keep if obfs is part of profile
    DEBUG_PARAM = -3    # General - bad parameter - Keep for debug parameters
    COMMENT = 1         # General informational - Keep for comment parameters


MIN_ACCEPTABLE_SCORE = 100.0 # Changed to 100.0 as per instruction
MIN_CONFIG_LENGTH = 40
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://"] # Allowed protocols updated
PREFERRED_PROTOCOLS = ["vless://"]
CHECK_USERNAME = True
CHECK_TLS_REALITY = True
CHECK_SNI = True
CHECK_CONNECTION_TYPE = True
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60 # Общий таймаут для запросов к каналам
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
VLESS_VERSION = b"\x00"
CLIENT_ID = uuid.uuid4()
VLESS_CHECK_TIMEOUT = 5 # Timeout for VLESS handshake check in seconds

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

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
    def __init__(self, url: str):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = REQUEST_TIMEOUT
        self.check_count = 0


    def _validate_url(self, url: str) -> str:
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL")
        url = url.strip()
        if not url.startswith(('http://', 'https://', 'ssconf://')):
            raise ValueError("Invalid URL protocol")
        return url

    def calculate_overall_score(self):
        try:
            total_checks = self.metrics.success_count + self.metrics.fail_count
            success_ratio = self.metrics.success_count / total_checks if total_checks > 0 else 0

            recency_bonus = 0
            if self.metrics.last_success_time:
                time_since_last_success = datetime.now() - self.metrics.last_success_time
                recency_bonus = HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0

            response_time_penalty = self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value if self.metrics.avg_response_time > 0 else 0

            self.metrics.overall_score = round((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus + response_time_penalty, 2)
            self.metrics.overall_score = max(0, self.metrics.overall_score) # Removed min(100, ...) to allow scores > 100

        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

    def update_channel_stats(self, success: bool, response_time: float = 0):
        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
        else:
            self.metrics.fail_count += 1
        if response_time > 0:
            self.metrics.avg_response_time = (self.metrics.avg_response_time * 0.7) + (response_time * 0.3) if self.metrics.avg_response_time else response_time
        self.calculate_overall_score()

class ProxyConfig:
    def __init__(self):
        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except ValueError as e:
                            logger.warning(f"Неверный URL в файле {ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.error(f"Файл с URL-ами не найден: {ALL_URLS_FILE}. Пожалуйста, убедитесь, что файл существует и находится в правильной директории.")
        except Exception as e:
            logger.error(f"Ошибка при чтении файла {ALL_URLS_FILE}: {e}")

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.HEADERS = HEADERS


    def _normalize_url(self, url: str) -> str:
        try:
            if not url:
                raise ValueError("Empty URL")
            url = url.strip()
            if url.startswith('ssconf://'):
                url = url.replace('ssconf://', 'https://', 1)
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")

            path = parsed.path.rstrip('/')
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"URL normalization error: {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        try:
            seen_urls = {}
            unique_configs = []
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Invalid config skipped: {config}")
                    continue
                try:
                    normalized_url = self._normalize_url(config.url)
                    if normalized_url not in seen_urls:
                        seen_urls[normalized_url] = True
                        unique_configs.append(config)
                except Exception:
                    continue
            if not unique_configs:
                self.save_empty_config_file()
                logger.error("Не найдено валидных источников. Создан пустой файл конфигурации.")
                return []
            return unique_configs
        except Exception as e:
            logger.error(f"Ошибка при удалении дубликатов URL: {str(e)}")
            self.save_empty_config_file()
            return []

    def get_enabled_channels(self) -> List[ChannelConfig]:
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        try:
            os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка при сохранении пустого файла конфигурации: {str(e)}")
            return False

def _calculate_config_length_score(config: str) -> float:
    return min(ScoringWeights.CONFIG_LENGTH.value, (len(config) / 200.0) * ScoringWeights.CONFIG_LENGTH.value)

def _calculate_security_score(query: Dict) -> float:
    score = 0
    security_params = query.get('security', [])
    if security_params:
        score += ScoringWeights.SECURITY_PARAM.value
        score += min(ScoringWeights.NUM_SECURITY_PARAMS.value, len(security_params) * (ScoringWeights.NUM_SECURITY_PARAMS.value / 3))
        security_type = security_params[0].lower()
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
    }.get(transport_type, 0) # Removed irrelevant transport types

def _calculate_encryption_score(query: Dict) -> float:
    encryption_type = query.get('encryption', ['none'])[0].lower()
    return {
        "none": ScoringWeights.ENCRYPTION_TYPE_NONE.value,
        "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO.value,
        "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM.value,
        "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305.value,
        "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO.value # Maybe remove ZERO encryption? But keep for now.
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
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value, # Reusing UTLS values as they represent similar client types
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI.value, # Assuming Safari is also a valid fingerprint
            "edge": ScoringWeights.UTLS_VALUE_EDGE.value if hasattr(ScoringWeights, 'UTLS_VALUE_EDGE') else ScoringWeights.UTLS_VALUE_CHROME.value # Fallback in case EDGE value is removed and to avoid errors
        }.get(fp.lower(), 0)
        if fingerprint_score is not None: # Check to ensure score is not None
            score += fingerprint_score
        else:
            score += 0 # Default to 0 if fingerprint is not recognized
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
        if utls_score is not None: # Check to ensure score is not None
            score += utls_score
        else:
            score += 0 # Default to 0 if utls value is not recognized
    return score

def _calculate_udp_score(protocol: str) -> float:
    return ScoringWeights.UDP_SUPPORT.value if protocol == "tuic://" or protocol == "hy2://" else 0 # UDP support for tuic and hy2

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
    if uuid_val:
        score += ScoringWeights.UUID_PRESENT.value
        score += min(ScoringWeights.UUID_LENGTH.value, len(uuid_val) * (ScoringWeights.UUID_LENGTH.value / 36))
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
        'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment' # Added back potentially relevant params that might be in profile strings
    )
    for key, value in query.items():
        if key not in known_params:
            score += ScoringWeights.HIDDEN_PARAM.value
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
        if score_val is not None: # Check to ensure score is not None
            score += score_val
        else:
            score += 0 # Default to 0 if bufferSize value is not recognized
    return score

def _calculate_tcp_optimization_score(query: Dict) -> float:
    return ScoringWeights.TCP_OPTIMIZATION.value if query.get('tcpFastOpen', [None])[0] == "true" else 0 # Assuming tcpFastOpen is a string 'true' or 'false'

def _calculate_quic_param_score(query: Dict) -> float:
    return ScoringWeights.QUIC_PARAM.value if query.get('maxIdleTime', [None])[0] else 0 # Relevant for QUIC based protocols


def _calculate_cdn_usage_score(sni: Optional[str]) -> float:
    return ScoringWeights.CDN_USAGE.value if sni and ".cdn." in sni else 0 # CDN still could be relevant based on SNI

def _calculate_mtu_size_score(query: Dict) -> float:
    return 0.0 # MTU Size removed as it's not usually in profile

def _calculate_obfs_score(query: Dict) -> float:
    return ScoringWeights.OBFS.value if query.get('obfs', [None])[0] else 0 # OBFS could be relevant

def _calculate_debug_param_score(query: Dict) -> float:
    return ScoringWeights.DEBUG_PARAM.value if query.get('debug', [None])[0] == "true" else 0

def _calculate_comment_score(query: Dict) -> float:
    return ScoringWeights.COMMENT.value if query.get('comment', [None])[0] else 0

def _calculate_client_compatibility_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_session_resumption_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_fallback_type_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_webtransport_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_security_direct_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_tls_version_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile

def _calculate_multiplexing_score(query: Dict) -> float:
    return 0.0 # Removed - Not directly derived from profile


def compute_profile_score(config: str, response_time: float = 0.0) -> float:
    score = 0.0
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
    except Exception as e:
        logger.error(f"Ошибка при парсинге URL {config}: {e}")
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
    if tls_fingerprint_score is not None: # Check for None to avoid TypeError
        score += tls_fingerprint_score
    utls_score_val = _calculate_utls_score(query)
    if utls_score_val is not None: # Check for None to avoid TypeError
        score += utls_score_val
    score += _calculate_udp_score(protocol)
    score += _calculate_port_score(parsed.port)
    score += _calculate_uuid_score(parsed, query) # Relevant for vless
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
    if buffer_size_score is not None: # Check for None to avoid TypeError
        score += buffer_size_score
    tcp_optimization_score = _calculate_tcp_optimization_score(query)
    if tcp_optimization_score is not None: # Check for None to avoid TypeError
        score += tcp_optimization_score
    quic_param_score = _calculate_quic_param_score(query)
    if quic_param_score is not None: # Check for None to avoid TypeError
        score += quic_param_score
    score += ScoringWeights.STREAM_ENCRYPTION.value # Stream encryption is quite general and could be relevant
    score += _calculate_cdn_usage_score(sni)
    mtu_size_score = _calculate_mtu_size_score(query) # MTU removed from scoring
    if mtu_size_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += mtu_size_score
    score += _calculate_obfs_score(query) # Obfs could be relevant
    score += _calculate_debug_param_score(query)
    score += _calculate_comment_score(query)
    client_compatibility_score = _calculate_client_compatibility_score(query) # Removed - not profile related
    if client_compatibility_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += client_compatibility_score
    session_resumption_score = _calculate_session_resumption_score(query) # Removed - not profile related
    if session_resumption_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += session_resumption_score
    fallback_type_score = _calculate_fallback_type_score(query) # Removed - not profile related
    if fallback_type_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += fallback_type_score
    webtransport_score = _calculate_webtransport_score(query) # Removed - not profile related
    if webtransport_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += webtransport_score
    security_direct_score = _calculate_security_direct_score(query) # Removed - not profile related
    if security_direct_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += security_direct_score
    tls_version_score = _calculate_tls_version_score(query) # Removed - not profile related
    if tls_version_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += tls_version_score
    multiplexing_score = _calculate_multiplexing_score(query) # Removed - not profile related
    if multiplexing_score is not None: # Check for None to avoid TypeError - Although function now always returns float, keeping check for robustness
        score += multiplexing_score


    return round(score, 2)

def generate_custom_name(config: str) -> str:
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

        return " - ".join(filter(lambda x: x != "NONE" and x, name_parts))
    except Exception as e:
        logger.error(f"Error generating custom name for {config}: {e}")
        return "UNKNOWN"

def is_valid_ipv4(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        parts = hostname.split('.')
        return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False

def create_profile_key(config: str) -> str:
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)

        core_pattern = re.compile(r"^(vless|tuic|hy2)://.*?@([\w\d\.\:]+):(\d+)")
        match = core_pattern.match(config)

        if match:
            protocol, host_port, port = match.groups()
            host = host_port.split(':')[0] if ':' in host_port else host_port
            key_parts = [
                protocol,
                host,
                port,
            ]

            if CHECK_USERNAME:
                user = parsed.username
                id_value = query.get('id', [None])[0]
                if user:
                    key_parts.append(f"user:{user}")
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
        logger.error(f"Ошибка при создании ключа для профиля {config}: {e}")
        raise ValueError(f"Не удалось создать ключ для профиля: {config}") from e

# REGEX для фильтрации дубликатов профилей
DUPLICATE_PROFILE_REGEX = re.compile(
    r"^(vless|tuic|hy2)://(?:.*?@)?([^@/:]+):(\d+)"
)

def generate_vless_header(client_id: uuid.UUID) -> bytes:
    """Генерирует VLESS header."""
    header = b""
    header += VLESS_VERSION  # Version
    header += client_id.bytes  # UUID
    header += b"\x00"  # Options (none)
    return header

async def check_profile_availability(config: str, timeout: int = VLESS_CHECK_TIMEOUT) -> bool:
    """Проверяет VLESS прокси, выполняя handshake."""
    writer = None
    try:
        parsed_url = urlparse(config)
        if parsed_url.scheme != 'vless':
            return True  # Skip VLESS check for non-VLESS protocols

        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logger.warning(f"Invalid proxy URL, missing host or port for VLESS check: {config}")
            return False

        try:
            reader, writer = await asyncio.open_connection(host, port)
        except ConnectionRefusedError as e:
            logger.debug(f"VLESS Proxy {config}: Connection refused - {e}") # Log as DEBUG
            return False
        except socket.gaierror as e:
            logger.debug(f"VLESS Proxy {config}: DNS resolution failed - {e}") # Log as DEBUG
            return False
        except TimeoutError as e:
            logger.debug(f"VLESS Proxy {config}: Connection timeout - {e}") # Log as DEBUG
            return False
        except Exception as e:
            logger.error(f"Error checking VLESS proxy {config}: Connection error - {e}")
            return False


        # VLESS Handshake
        vless_header = generate_vless_header(CLIENT_ID)
        try:
            writer.write(vless_header)
        except Exception as e:
            logger.error(f"Error sending VLESS header to {config}: {e}")
            return False

        # Dummy request (HTTP GET) - for basic connectivity check
        http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        try:
            writer.write(http_request)
            await writer.drain()
        except Exception as e:
            logger.error(f"Error sending HTTP request to {config}: {e}")
            return False


        try:
            response = await asyncio.wait_for(reader.read(1024), timeout=timeout) # Читаем до 1024 байт
            if response:
                logger.debug(f"VLESS Proxy {config} is reachable.")
                return True
            else:
                logger.debug(f"VLESS Proxy {config} - No response received.")
                return False
        except asyncio.TimeoutError:
            logger.debug(f"VLESS Proxy {config} - Timeout waiting for response.")
            return False
        except Exception as e:
            logger.error(f"Error reading response from {config}: {e}")
            return False


    except Exception as e:
        logger.error(f"Unexpected error during VLESS proxy check for {config}: {e}")
        return False
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionResetError as e: # Catch ConnectionResetError during wait_closed
                logger.debug(f"ConnectionResetError while closing writer for {config}: {e}") # Log as DEBUG
            except Exception as e:
                logger.error(f"Error closing writer for {config}: {e}")


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, existing_profiles_regex: set, proxy_config: "ProxyConfig") -> List[Dict]:
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
                logger.info(f"Контент с {channel.url} загружен за {response_time:.2f} секунд")
                channel.update_channel_stats(success=True, response_time=response_time)


        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Ошибка загрузки с {channel.url}: {type(e).__name__} - {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies
        except Exception as e:
            logger.exception(f"Непредвиденная ошибка при загрузке с {channel.url}: {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies

        lines = text.splitlines()
        valid_configs_from_channel = 0 # Счетчик валидных конфигов для текущего канала
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

            except ValueError as e:
                logger.debug(f"Ошибка парсинга URL {line}: {e}")
                continue

            # Фильтрация дубликатов с помощью REGEX
            match = DUPLICATE_PROFILE_REGEX.match(line)
            if match:
                duplicate_key = f"{match.group(1)}://{match.group(2)}:{match.group(3)}" # protocol://host:port
                if duplicate_key in existing_profiles_regex:
                    continue # Пропускаем дубликат
                existing_profiles_regex.add(duplicate_key) # Добавляем уникальный ключ
            else:
                logger.warning(f"Не удалось создать ключ для фильтрации дубликатов по REGEX для: {line}")
                continue # Если не удалось создать ключ, пропускаем для безопасности, или можно рассмотреть добавление как уникального

            # Проверка доступности VLESS профиля перед подсчетом очков
            if protocol == 'vless://':
                is_available = await check_profile_availability(line)
                if not is_available:
                    logger.debug(f"VLESS Proxy {line} is not available, skipping scoring.")
                    continue # Пропускаем scoring, если прокси не доступен

            score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)

            if score > MIN_ACCEPTABLE_SCORE: # Changed to > 100.0 from >= MIN_ACCEPTABLE_SCORE which was 60 before change. Now MIN_ACCEPTABLE_SCORE is 100.0
                proxies.append({"config": line, "protocol": protocol, "score": score}) # download_speed removed
                valid_configs_from_channel += 1


        channel.metrics.valid_configs += valid_configs_from_channel # Обновляем метрику для канала
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(set(create_profile_key(l["config"]) for l in proxies))

        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {valid_configs_from_channel} валидных конфигураций.") # Вывод кол-ва валидных конфигов с канала
        return proxies

async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles_regex = set() # Используем set для хранения уникальных ключей regex

    async with aiohttp.ClientSession(headers=proxy_config.HEADERS, timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles_regex, proxy_config) for channel in channels] # speed_check_semaphore removed
        results = await asyncio.gather(*tasks)
        for result in results:
            proxies_all.extend(result)
    return proxies_all

def save_final_configs(proxies: List[Dict], output_file: str):
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True) # Sort by score descending

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for proxy in proxies_sorted:
                if proxy['score'] > 100.0: # Condition to write profiles with score > 100.0
                    config = proxy['config'].split('#')[0].strip()
                    profile_name = generate_custom_name(config)
                    final_line = f"{config}# {profile_name}\n" # Score removed from output line
                    f.write(final_line)
        logger.info(f"Итоговые конфигурации сохранены в {output_file}") # Speed check related text removed
    except Exception as e:
        logger.error(f"Ошибка при сохранении конфигураций: {str(e)}")

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
        logger.info(f"Включенных каналов: {enabled_channels}")
        logger.info(f"Отключенных каналов: {disabled_channels}")
        logger.info(f"Всего валидных конфигураций: {total_valid_configs}")
        logger.info(f"Всего уникальных конфигураций: {total_unique_configs}")
        logger.info(f"Всего успехов (загрузок): {total_successes}")
        logger.info(f"Всего неудач (загрузок): {total_fails}")

        logger.info("Статистика по протоколам:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")

        sorted_channels = sorted(channels, key=lambda ch: ch.metrics.overall_score, reverse=True)
        logger.info("Статистика по каналам (отсортировано по стабильности):")
        for channel in sorted_channels:
            logger.info(f"  URL: {channel.url}, Валидных конфигураций: {channel.metrics.valid_configs}, Оценка стабильности: {channel.metrics.overall_score:.2f}, Успехов: {channel.metrics.success_count}, Неудач: {channel.metrics.fail_count}") # Добавили вывод valid_configs для каждого канала

        logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")


    asyncio.run(runner())

if __name__ == "__main__":
    main()
