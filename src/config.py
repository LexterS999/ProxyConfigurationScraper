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
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from collections import defaultdict
import logging
import ipaddress
import io
from enum import Enum
import shutil
import uuid
from pydantic import BaseModel, Field, field_validator
from abc import ABC, abstractmethod
import base64
import urllib.parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SCORING_WEIGHTS_FILE = "scoring_weights.json"
DEFAULT_CHANNEL_SOURCES_FILE = "all_urls.txt" # Added DEFAULT_CHANNEL_SOURCES_FILE

class ScoringWeightsModel(BaseModel):
    """Data model for scoring weights with validation."""
    PROTOCOL_BASE: float = Field(50, ge=-100, le=100)
    CONFIG_LENGTH: float = Field(10, ge=0, le=50)
    SECURITY_PARAM: float = Field(15, ge=0, le=50)
    NUM_SECURITY_PARAMS: float = Field(5, ge=0, le=20)
    SECURITY_TYPE_TLS: float = Field(10, ge=-20, le=20)
    SECURITY_TYPE_REALITY: float = Field(12, ge=-20, le=25)
    SECURITY_TYPE_NONE: float = Field(-5, ge=-20, le=10)
    TRANSPORT_TYPE_TCP: float = Field(2, ge=-10, le=20)
    TRANSPORT_TYPE_WS: float = Field(8, ge=-5, le=25)
    TRANSPORT_TYPE_QUIC: float = Field(6, ge=-5, le=20)
    ENCRYPTION_TYPE_NONE: float = Field(-5, ge=-20, le=10)
    ENCRYPTION_TYPE_AUTO: float = Field(3, ge=0, le=15)
    ENCRYPTION_TYPE_AES_128_GCM: float = Field(7, ge=0, le=20)
    ENCRYPTION_TYPE_CHACHA20_POLY1305: float = Field(7, ge=0, le=20)
    ENCRYPTION_TYPE_ZERO: float = Field(2, ge=0, le=10)
    SNI_PRESENT: float = Field(7, ge=0, le=15)
    COMMON_SNI_BONUS: float = Field(3, ge=0, le=10)
    ALPN_PRESENT: float = Field(5, ge=0, le=10)
    NUM_ALPN_PROTOCOLS: float = Field(2, ge=0, le=10)
    PATH_PRESENT: float = Field(3, ge=0, le=10)
    PATH_COMPLEXITY: float = Field(2, ge=0, le=10)
    HEADERS_PRESENT: float = Field(4, ge=0, le=10)
    NUM_HEADERS: float = Field(1, ge=0, le=5)
    HOST_HEADER: float = Field(5, ge=0, le=10)
    HOST_SNI_MATCH: float = Field(10, ge=0, le=20)
    UTLS_PRESENT: float = Field(4, ge=0, le=10)
    UTLS_VALUE_CHROME: float = Field(5, ge=0, le=10)
    UTLS_VALUE_FIREFOX: float = Field(4, ge=0, le=10)
    UTLS_VALUE_IOS: float = Field(2, ge=0, le=5)
    UTLS_VALUE_SAFARI: float = Field(3, ge=0, le=10)
    UTLS_VALUE_RANDOMIZED: float = Field(7, ge=0, le=15)
    UTLS_VALUE_RANDOM: float = Field(6, ge=0, le=15)
    UDP_SUPPORT: float = Field(7, ge=0, le=15)
    PORT_80: float = Field(5, ge=0, le=10)
    PORT_443: float = Field(10, ge=0, le=20)
    PORT_OTHER: float = Field(2, ge=0, le=10)
    UUID_PRESENT: float = Field(5, ge=0, le=10)
    UUID_LENGTH: float = Field(3, ge=0, le=10)
    EARLY_DATA_SUPPORT: float = Field(5, ge=0, le=10)
    PARAMETER_CONSISTENCY: float = Field(12, ge=0, le=25)
    IPV6_ADDRESS: float = Field(-9, ge=-20, le=10)
    RARITY_BONUS: float = Field(4, ge=0, le=10)
    HIDDEN_PARAM: float = Field(6, ge=0, le=15)
    NEW_PARAM: float = Field(5, ge=0, le=10)
    RESPONSE_TIME: float = Field(-0.05, ge=-1, le=0)
    CHANNEL_STABILITY: float = Field(20, ge=0, le=30)
    BUFFER_SIZE_SMALL: float = Field(-2, ge=-10, le=10)
    BUFFER_SIZE_MEDIUM: float = Field(3, ge=0, le=10)
    BUFFER_SIZE_LARGE: float = Field(7, ge=0, le=15)
    BUFFER_SIZE_UNLIMITED: float = Field(5, ge=0, le=10)
    TCP_OPTIMIZATION: float = Field(5, ge=0, le=10)
    QUIC_PARAM: float = Field(3, ge=0, le=10)
    STREAM_ENCRYPTION: float = Field(6, ge=0, le=15)
    CDN_USAGE: float = Field(8, ge=0, le=15)
    OBFS: float = Field(4, ge=0, le=10)
    DEBUG_PARAM: float = Field(-3, ge=-10, le=10)
    COMMENT: float = Field(1, ge=0, le=5)
    TROJAN_PASSWORD_PRESENT: float = Field(8, ge=0, le=15)
    TROJAN_PASSWORD_LENGTH: float = Field(5, ge=0, le=10)
    SS_BASE64_BONUS: float = Field(10, ge=0, le=20)
    SS_METHOD_BONUS: float = Field(8, ge=0, le=15)
    SS_PASSWORD_BONUS: float = Field(7, ge=0, le=15)
    SS_PLUGIN_BONUS: float = Field(6, ge=0, le=15)
    SS_OBFS_BONUS: float = Field(5, ge=0, le=10)


    @field_validator('*', mode='before')
    def ensure_numeric(cls, value):
        if not isinstance(value, (int, float)):
            raise ValueError(f"Weight value must be numeric, got: {type(value).__name__}")
        return float(value)

    @classmethod
    def load_from_json(cls, file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> 'ScoringWeightsModel':
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data = json.load(f)
                return cls(**weights_data)
        except FileNotFoundError:
            logger.warning(f"Scoring weights file not found: {file_path}. Using defaults.") # Updated log message
            return cls.create_default_weights_file(file_path)
        except json.JSONDecodeError:
            logger.error(f"Error reading JSON weights file: {file_path}. Using defaults.")
            return cls()
        except Exception as e:
            logger.error(f"Unexpected error loading scoring weights from {file_path}: {e}. Using defaults.")
            return cls()

    @classmethod
    def create_default_weights_file(cls, file_path: str) -> 'ScoringWeightsModel':
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = cls().model_dump()
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Created default scoring weights file: {file_path}")
            return cls(**default_weights)
        except Exception as e:
            logger.error(f"Error creating default scoring weights file: {e}")
            return cls()

ScoringWeights = ScoringWeightsModel.load_from_json()

MIN_ACCEPTABLE_SCORE = 100.0
MIN_CONFIG_LENGTH = 40
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "trojan://", "ss://"]
PREFERRED_PROTOCOLS = ["vless://", "trojan://", "tuic://", "hy2://", "ss://"]
CHECK_USERNAME = True
CHECK_TLS_REALITY = True
CHECK_SNI = True
CHECK_CONNECTION_TYPE = True
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt" # Removed unused ALL_URLS_FILE
TEST_URL_FOR_PROXY_CHECK = "http://speed.cloudflare.com"
MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS = 60


class ChannelStatus(Enum):
    """Enum for channel status."""
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"
    CHECKING = "checking"


@dataclass
class ChannelMetrics:
    """Metrics for a channel."""
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = field(default_factory=defaultdict)


class ChannelConfig:
    """Configuration and metrics for a channel URL."""
    def __init__(self, url: str, request_timeout: int = REQUEST_TIMEOUT):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = request_timeout
        self.check_count = 0
        self._parsed_url_data: Dict[str, Any] = self._parse_url_details()
        self.status: ChannelStatus = ChannelStatus.PENDING

    def _validate_url(self, url: str) -> str:
        """Validates the channel URL."""
        if not url:
            raise ValueError("URL cannot be empty.")
        if not isinstance(url, str):
            raise ValueError(f"URL must be a string, got: {type(url).__name__}")
        url = url.strip()
        valid_protocols = ('http://', 'https://', 'ssconf://', 'trojan://', 'vless://', 'tuic://', 'hy2://', 'ss://')
        if not any(url.startswith(proto) for proto in valid_protocols):
            raise ValueError(f"Invalid URL protocol. Expected: {', '.join(valid_protocols)}, got: {url[:url.find('://') + 3] if '://' in url else url[:10]}...")
        return url

    def _parse_url_details(self) -> Dict[str, Any]:
        """Parses URL and extracts protocol-specific details."""
        parsed = urlparse(self.url)
        query = parse_qs(parsed.query)
        protocol = next((p for p in ALLOWED_PROTOCOLS if self.url.startswith(p)), None)

        details = {
            'protocol': protocol,
            'parsed_url': parsed,
            'query_params': query,
            'hostname': parsed.hostname,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password,
            'path': parsed.path,
            'fragment': parsed.fragment, # Added fragment
            'sni': query.get('sni', [None])[0],
            'security': query.get('security', [None])[0],
            'type': query.get('type', [None])[0],
        }

        if protocol == 'vless://':
            profile_id = details['username'] or details['query_params'].get('id', [None])[0]
            if not profile_id or not is_valid_uuid(profile_id):
                raise ValueError(f"Invalid VLESS URL: missing or invalid UUID: {self.url}")
        elif protocol == 'ss://':
            try:
                userinfo_base64 = parsed.netloc.split('@')[0]
                userinfo_decoded = base64.b64decode(userinfo_base64 + '===').decode('utf-8') # Pad for correct base64 decoding
                method, password = userinfo_decoded.split(':')
                details['ss_method'] = method
                details['ss_password'] = password
                host_port = parsed.netloc.split('@')[1]
                details['hostname'] = host_port.split(':')[0]
                details['port'] = int(host_port.split(':')[1]) if ':' in host_port else 80 # Default port for ss
            except Exception as e:
                raise ValueError(f"Invalid SS URL format: {self.url} - {e}")

        return details

    def get_detail(self, key: str) -> Any:
        """Returns a parsed URL detail by key."""
        return self._parsed_url_data.get(key)

    def calculate_overall_score(self):
        """Calculates the overall score for the channel."""
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = round((success_ratio * ScoringWeights.CHANNEL_STABILITY) + recency_bonus + response_time_penalty, 2)
            self.metrics.overall_score = max(0, self.metrics.overall_score)

        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        """Calculates the success ratio of channel checks."""
        total_checks = self.metrics.success_count + self.metrics.fail_count
        return self.metrics.success_count / total_checks if total_checks > 0 else 0

    def _calculate_recency_bonus(self) -> float:
        """Calculates the recency bonus based on last success time."""
        if self.metrics.last_success_time:
            time_since_last_success = datetime.now() - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0
        return 0

    def _calculate_response_time_penalty(self) -> float:
        """Calculates the response time penalty."""
        return self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME if self.metrics.avg_response_time > 0 else 0

    def update_channel_stats(self, success: bool, response_time: float = 0):
        """Updates channel statistics after a check."""
        assert isinstance(success, bool), f"Argument 'success' must be bool, got {type(success)}"
        assert isinstance(response_time, (int, float)), f"Argument 'response_time' must be a number, got {type(response_time)}"

        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
            self.status = ChannelStatus.ACTIVE
        else:
            self.metrics.fail_count += 1
            self.status = ChannelStatus.INACTIVE # Or FAILED depending on logic
        if response_time > 0:
            if self.metrics.avg_response_time:
                self.metrics.avg_response_time = (self.metrics.avg_response_time * 0.7) + (response_time * 0.3)
            else:
                self.metrics.avg_response_time = response_time
        self.calculate_overall_score()


class ProxyConfig:
    """Manages proxy configurations, loading, saving, and deduplication."""
    CONFIG_SOURCES_FILE = DEFAULT_CHANNEL_SOURCES_FILE # Use DEFAULT_CHANNEL_SOURCES_FILE

    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.SOURCE_URLS = self._load_channels_from_sources()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE

    def _load_channel_sources_config(self) -> List[Dict]:
        """Loads channel sources configuration from JSON file."""
        try:
            with open(self.CONFIG_SOURCES_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Channel sources config file not found: {self.CONFIG_SOURCES_FILE}. Using default empty sources.") # Updated log message
            return []
        except json.JSONDecodeError:
            logger.error(f"Error reading JSON config file: {self.CONFIG_SOURCES_FILE}. Using default empty sources.")
            return []

    def _load_channels_from_sources(self) -> List[ChannelConfig]:
        """Loads channels from various sources defined in configuration."""
        channel_configs = []
        sources_config = self._load_channel_sources_config()

        for source in sources_config:
            source_type = source.get('type')
            source_location = source.get('location')
            if not source_type or not source_location:
                logger.warning(f"Invalid channel source config: {source}. Skipping.")
                continue

            try:
                if source_type == 'file':
                    channel_configs.extend(self._load_from_file_source(source_location))
                elif source_type == 'url':
                    channel_configs.extend(asyncio.run(self._load_from_url_source(source_location))) # Use asyncio.run here
                elif source_type == 'directory':
                    channel_configs.extend(self._load_from_directory_source(source_location))
                else:
                    logger.warning(f"Unknown channel source type: {source_type}. Skipping source: {source}")
            except Exception as e:
                logger.error(f"Error loading channels from source {source}: {e}")

        return self._remove_duplicate_urls(channel_configs)

    def _load_from_file_source(self, file_path: str) -> List[ChannelConfig]:
        """Loads channels from a text file."""
        configs = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            configs.append(ChannelConfig(url))
                        except ValueError as e:
                            logger.warning(f"Invalid URL in file {file_path}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"Channel source file not found: {file_path}")
        return configs

    async def _load_from_url_source(self, source_url: str) -> List[ChannelConfig]:
        """Loads channels from a web page URL."""
        configs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(source_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        lines = text.splitlines()
                        for line in lines:
                            url = line.strip()
                            if url:
                                try:
                                    configs.append(ChannelConfig(url))
                                except ValueError as e:
                                    logger.warning(f"Invalid URL from source {source_url}: {url} - {e}")
                    else:
                        logger.error(f"Failed to fetch channel source from {source_url}, status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching channel source from {source_url}: {e}")
        return configs

    def _load_from_directory_source(self, dir_path: str) -> List[ChannelConfig]:
        """Loads channels from all text files in a directory."""
        configs = []
        if not os.path.isdir(dir_path):
            logger.warning(f"Channel source directory not found: {dir_path}")
            return configs
        for filename in os.listdir(dir_path):
            if filename.endswith(".txt"):
                file_path = os.path.join(dir_path, filename)
                configs.extend(self._load_from_file_source(file_path))
        return configs

    def _normalize_url(self, url: str) -> str:
        """Normalizes a URL for deduplication."""
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
        """Removes duplicate URLs based on normalization."""
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
        """Returns the list of enabled channel configurations."""
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        """Saves an empty configuration file."""
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Error saving empty config file: {str(e)}")
            return False


class ScoringFeature(ABC):
    """Abstract base class for scoring features."""
    weight: float = 1.0

    def __init__(self, weight: Optional[float] = None):
        if weight is not None:
            self.weight = weight

    @abstractmethod
    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        """Calculates the score for this feature."""
        pass

class ProtocolBaseScore(ScoringFeature):
    """Scores based on protocol."""
    weight = ScoringWeights.PROTOCOL_BASE

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return self.weight

class ConfigLengthScore(ScoringFeature):
    """Scores based on config length."""
    weight = ScoringWeights.CONFIG_LENGTH

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        config_len = len(channel_details['protocol'] + "://" + channel_details['parsed_url'].netloc + channel_details['parsed_url'].path + channel_details['parsed_url'].query + channel_details['parsed_url'].fragment)
        return min(self.weight, (config_len / 200.0) * self.weight)

class SecurityScore(ScoringFeature):
    """Scores based on security parameters."""
    weight = ScoringWeights.SECURITY_PARAM

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        query = channel_details['query_params']
        security_params = query.get('security', [])
        if security_params:
            score += ScoringWeights.SECURITY_PARAM
            score += min(ScoringWeights.NUM_SECURITY_PARAMS, len(security_params) * (ScoringWeights.NUM_SECURITY_PARAMS / 3))
            security_type = security_params[0].lower() if security_params else 'none'
            score += {
                "tls": ScoringWeights.SECURITY_TYPE_TLS,
                "reality": ScoringWeights.SECURITY_TYPE_REALITY,
                "none": ScoringWeights.SECURITY_TYPE_NONE
            }.get(security_type, 0)
        return score

class TransportScore(ScoringFeature):
    """Scores based on transport type."""
    weight = ScoringWeights.TRANSPORT_TYPE_TCP

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        transport_type = query.get('type', ['tcp'])[0].lower()
        return {
            "tcp": ScoringWeights.TRANSPORT_TYPE_TCP,
            "ws": ScoringWeights.TRANSPORT_TYPE_WS,
            "quic": ScoringWeights.TRANSPORT_TYPE_QUIC,
        }.get(transport_type, 0)

class EncryptionScore(ScoringFeature):
    """Scores based on encryption type."""
    weight = ScoringWeights.ENCRYPTION_TYPE_NONE

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        encryption_type = query.get('encryption', ['none'])[0].lower()
        return {
            "none": ScoringWeights.ENCRYPTION_TYPE_NONE,
            "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO,
            "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM,
            "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305,
            "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO
        }.get(encryption_type, 0)

class SniScore(ScoringFeature):
    """Scores based on SNI presence and commonality."""
    weight = ScoringWeights.SNI_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        sni = channel_details['query_params'].get('sni', [None])[0]
        if sni:
            score += ScoringWeights.SNI_PRESENT
            if sni.endswith(('.com', '.net', '.org', '.info', '.xyz')):
                score += ScoringWeights.COMMON_SNI_BONUS
        return score

class AlpnScore(ScoringFeature):
    """Scores based on ALPN protocol."""
    weight = ScoringWeights.ALPN_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        alpn = channel_details['query_params'].get('alpn', [None])[0]
        if alpn:
            score += ScoringWeights.ALPN_PRESENT
            alpn_protocols = alpn.split(',')
            score += min(ScoringWeights.NUM_ALPN_PROTOCOLS, len(alpn_protocols) * (ScoringWeights.NUM_ALPN_PROTOCOLS / 2))
        return score

class PathScore(ScoringFeature):
    """Scores based on path complexity."""
    weight = ScoringWeights.PATH_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        path = channel_details['query_params'].get('path', [None])[0]
        if path:
            score += ScoringWeights.PATH_PRESENT
            complexity = len(re.findall(r'[^a-zA-Z0-9]', path)) + (len(path) / 10)
            score += min(ScoringWeights.PATH_COMPLEXITY, complexity * (ScoringWeights.PATH_COMPLEXITY / 5))
        return score

class HeadersScore(ScoringFeature):
    """Scores based on headers and Host header matching SNI."""
    weight = ScoringWeights.HEADERS_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        query = channel_details['query_params']
        sni = channel_details['sni']
        headers = query.get('headers', [None])[0]
        if headers:
            score += ScoringWeights.HEADERS_PRESENT
            try:
                headers_dict = dict(item.split(":") for item in headers.split("&"))
                score += min(ScoringWeights.NUM_HEADERS, len(headers_dict) * (ScoringWeights.NUM_HEADERS / 2))
                host_header = headers_dict.get('Host', None)
                if host_header:
                    score += ScoringWeights.HOST_HEADER
                    if sni and host_header == sni:
                        score += ScoringWeights.HOST_SNI_MATCH
            except Exception:
                pass
        return score

class UtlsScore(ScoringFeature):
    """Scores based on uTLS fingerprint."""
    weight = ScoringWeights.UTLS_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        query = channel_details['query_params']
        utls = query.get('utls', [None])[0]
        if utls:
            score += ScoringWeights.UTLS_PRESENT
            utls_score = {
                "chrome": ScoringWeights.UTLS_VALUE_CHROME,
                "firefox": ScoringWeights.UTLS_VALUE_FIREFOX,
                "ios": ScoringWeights.UTLS_VALUE_IOS,
                "safari": ScoringWeights.UTLS_VALUE_SAFARI,
                "randomized": ScoringWeights.UTLS_VALUE_RANDOMIZED,
                "random": ScoringWeights.UTLS_VALUE_RANDOM
            }.get(utls.lower(), 0)
            if utls_score is not None:
                score += utls_score
            else:
                score += 0
        return score

class UDPScore(ScoringFeature):
    """Scores if UDP is supported by protocol."""
    weight = ScoringWeights.UDP_SUPPORT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        protocol = channel_details['protocol']
        return ScoringWeights.UDP_SUPPORT if protocol in ("tuic://", "hy2://", "ss://") else 0 # Added ss://

class PortScore(ScoringFeature):
    """Scores based on port number."""
    weight = ScoringWeights.PORT_OTHER

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        port = channel_details['port']
        if port:
            return {
                80: ScoringWeights.PORT_80,
                443: ScoringWeights.PORT_443
            }.get(port, ScoringWeights.PORT_OTHER)
        return 0

class UUIDScore(ScoringFeature):
    """Scores based on UUID presence and length in vless protocol."""
    weight = ScoringWeights.UUID_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        parsed = channel_details['parsed_url']
        query = channel_details['query_params']
        uuid_val = parsed.username or query.get('id', [None])[0]
        if uuid_val and parsed.scheme == 'vless':
            score += ScoringWeights.UUID_PRESENT
            score += min(ScoringWeights.UUID_LENGTH, len(uuid_val) * (ScoringWeights.UUID_LENGTH / 36))
        return score

class TrojanPasswordScore(ScoringFeature):
    """Scores based on trojan password presence and length."""
    weight = ScoringWeights.TROJAN_PASSWORD_PRESENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        parsed = channel_details['parsed_url']
        password = parsed.password
        if password:
            score += ScoringWeights.TROJAN_PASSWORD_PRESENT
            score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH, len(password) * (ScoringWeights.TROJAN_PASSWORD_LENGTH / 16))
        return score

class EarlyDataScore(ScoringFeature):
    """Scores if early data is supported."""
    weight = ScoringWeights.EARLY_DATA_SUPPORT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.EARLY_DATA_SUPPORT if query.get('earlyData', [None])[0] == "1" else 0

class ParameterConsistencyScore(ScoringFeature):
    """Penalizes score for inconsistent parameters."""
    weight = ScoringWeights.PARAMETER_CONSISTENCY

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        sni = channel_details['sni']
        query = channel_details['query_params']
        headers = query.get('headers', [None])[0]
        host_header = None
        if headers:
            try:
                headers_dict = dict(item.split(":") for item in headers.split("&"))
                host_header = headers_dict.get('Host', None)
            except:
                pass
        if sni and host_header and sni != host_header:
            score -= (ScoringWeights.PARAMETER_CONSISTENCY / 2)
        return score

class IPv6Score(ScoringFeature):
    """Penalizes score for IPv6 addresses."""
    weight = ScoringWeights.IPV6_ADDRESS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        parsed = channel_details['parsed_url']
        return ScoringWeights.IPV6_ADDRESS if ":" in parsed.hostname else 0

class HiddenParamScore(ScoringFeature):
    """Scores for hidden or unknown parameters."""
    weight = ScoringWeights.HIDDEN_PARAM

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        query = channel_details['query_params']
        known_params = (
            'security', 'type', 'encryption', 'sni', 'alpn', 'path',
            'headers', 'fp', 'utls',
            'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment', 'plugin', 'obfs-host', 'obfs-uri', 'remarks' # Added for ss
        )
        for key, value in query.items():
            if key not in known_params:
                score += ScoringWeights.HIDDEN_PARAM
                if value and value[0]:
                    score += min(ScoringWeights.RARITY_BONUS, ScoringWeights.RARITY_BONUS / len(value[0]))
        return score

class BufferSizeScore(ScoringFeature):
    """Scores based on buffer size parameter."""
    weight = ScoringWeights.BUFFER_SIZE_UNLIMITED

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        score = 0
        query = channel_details['query_params']
        buffer_size = query.get('bufferSize', [None])[0]
        if buffer_size:
            buffer_size = buffer_size.lower()
            score_val = {
                "unlimited": ScoringWeights.BUFFER_SIZE_UNLIMITED,
                "small": ScoringWeights.BUFFER_SIZE_SMALL,
                "medium": ScoringWeights.BUFFER_SIZE_MEDIUM,
                "large": ScoringWeights.BUFFER_SIZE_LARGE,
                "-1": ScoringWeights.BUFFER_SIZE_UNLIMITED,
                "0": ScoringWeights.BUFFER_SIZE_UNLIMITED,
            }.get(buffer_size, 0)
            if score_val is not None:
                score += score_val
            else:
                score += 0
        return score

class TCPOptimizationScore(ScoringFeature):
    """Scores if TCP Fast Open is enabled."""
    weight = ScoringWeights.TCP_OPTIMIZATION

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.TCP_OPTIMIZATION if query.get('tcpFastOpen', [None])[0] == "true" else 0

class QuicParamScore(ScoringFeature):
    """Scores if QUIC parameters are present."""
    weight = ScoringWeights.QUIC_PARAM

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.QUIC_PARAM if query.get('maxIdleTime', [None])[0] else 0

class CDNUsageScore(ScoringFeature):
    """Scores for CDN usage based on SNI."""
    weight = ScoringWeights.CDN_USAGE

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        sni = channel_details['sni']
        return ScoringWeights.CDN_USAGE if sni and ".cdn." in sni else 0

class MTUSizeScore(ScoringFeature):
    """Scores based on MTU size parameter (currently no scoring)."""
    weight = 0.0 # No weight for MTU size yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class ObfsScore(ScoringFeature):
    """Scores if obfuscation is used."""
    weight = ScoringWeights.OBFS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.OBFS if query.get('obfs', [None])[0] else 0

class DebugParamScore(ScoringFeature):
    """Penalizes score if debug parameter is present."""
    weight = ScoringWeights.DEBUG_PARAM

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.DEBUG_PARAM if query.get('debug', [None])[0] == "true" else 0

class CommentScore(ScoringFeature):
    """Scores if comment parameter is present."""
    weight = ScoringWeights.COMMENT

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.COMMENT if query.get('comment', [None])[0] else 0

class ClientCompatibilityScore(ScoringFeature):
    """Scores for client compatibility (currently no scoring)."""
    weight = 0.0 # No weight for client compatibility yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class SessionResumptionScore(ScoringFeature):
    """Scores for session resumption (currently no scoring)."""
    weight = 0.0 # No weight for session resumption yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class FallbackTypeScore(ScoringFeature):
    """Scores for fallback type (currently no scoring)."""
    weight = 0.0 # No weight for fallback type yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class WebtransportScore(ScoringFeature):
    """Scores for webtransport (currently no scoring)."""
    weight = 0.0 # No weight for webtransport yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class SecurityDirectScore(ScoringFeature):
    """Scores for security direct (currently no scoring)."""
    weight = 0.0 # No weight for security direct yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class TLSVersionScore(ScoringFeature):
    """Scores for TLS version (currently no scoring)."""
    weight = 0.0 # No weight for TLS version yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class MultiplexingScore(ScoringFeature):
    """Scores for multiplexing (currently no scoring)."""
    weight = 0.0 # No weight for multiplexing yet

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return 0.0

class SSBase64Score(ScoringFeature):
    """Bonus for SS protocol being base64 encoded."""
    weight = ScoringWeights.SS_BASE64_BONUS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return ScoringWeights.SS_BASE64_BONUS if channel_details['protocol'] == 'ss://' else 0

class SSMethodScore(ScoringFeature):
    """Bonus for specific SS methods."""
    weight = ScoringWeights.SS_METHOD_BONUS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        method = channel_details.get('ss_method', '').lower()
        if channel_details['protocol'] == 'ss://' and method in ('chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm'):
            return ScoringWeights.SS_METHOD_BONUS
        return 0

class SSPasswordScore(ScoringFeature):
    """Bonus for SS password presence."""
    weight = ScoringWeights.SS_PASSWORD_BONUS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        return ScoringWeights.SS_PASSWORD_BONUS if channel_details.get('ss_password') else 0

class SSPluginScore(ScoringFeature):
    """Bonus for SS plugin parameter."""
    weight = ScoringWeights.SS_PLUGIN_BONUS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.SS_PLUGIN_BONUS if channel_details['protocol'] == 'ss://' and query.get('plugin') else 0

class SSObfsScore(ScoringFeature):
    """Bonus for SS obfs parameter."""
    weight = ScoringWeights.SS_OBFS_BONUS

    def calculate_score(self, channel_details: Dict[str, Any]) -> float:
        query = channel_details['query_params']
        return ScoringWeights.SS_OBFS_BONUS if channel_details['protocol'] == 'ss://' and query.get('obfs') else 0


SCORING_FEATURES_CONFIG = [
    {'feature': ProtocolBaseScore, 'enabled': True},
    {'feature': ConfigLengthScore, 'enabled': True},
    {'feature': SecurityScore, 'enabled': True},
    {'feature': TransportScore, 'enabled': True},
    {'feature': EncryptionScore, 'enabled': True},
    {'feature': SniScore, 'enabled': True},
    {'feature': AlpnScore, 'enabled': True},
    {'feature': PathScore, 'enabled': True},
    {'feature': HeadersScore, 'enabled': True},
    {'feature': UtlsScore, 'enabled': True},
    {'feature': UDPScore, 'enabled': True},
    {'feature': PortScore, 'enabled': True},
    {'feature': UUIDScore, 'enabled': True},
    {'feature': TrojanPasswordScore, 'enabled': True},
    {'feature': EarlyDataScore, 'enabled': True},
    {'feature': ParameterConsistencyScore, 'enabled': True},
    {'feature': IPv6Score, 'enabled': True},
    {'feature': HiddenParamScore, 'enabled': True},
    {'feature': BufferSizeScore, 'enabled': True},
    {'feature': TCPOptimizationScore, 'enabled': True},
    {'feature': QuicParamScore, 'enabled': True},
    {'feature': CDNUsageScore, 'enabled': True},
    {'feature': MTUSizeScore, 'enabled': False},
    {'feature': ObfsScore, 'enabled': True},
    {'feature': DebugParamScore, 'enabled': True},
    {'feature': CommentScore, 'enabled': True},
    {'feature': ClientCompatibilityScore, 'enabled': False},
    {'feature': SessionResumptionScore, 'enabled': False},
    {'feature': FallbackTypeScore, 'enabled': False},
    {'feature': WebtransportScore, 'enabled': False},
    {'feature': SecurityDirectScore, 'enabled': False},
    {'feature': TLSVersionScore, 'enabled': False},
    {'feature': MultiplexingScore, 'enabled': False},
    {'feature': SSBase64Score, 'enabled': True}, # SS Protocol Specific Scores
    {'feature': SSMethodScore, 'enabled': True},
    {'feature': SSPasswordScore, 'enabled': True},
    {'feature': SSPluginScore, 'enabled': True},
    {'feature': SSObfsScore, 'enabled': True},
]

def compute_profile_score(channel: ChannelConfig) -> float:
    """Computes score for a given proxy profile configuration using ScoringFeature classes."""
    total_score = 0.0
    channel_details = channel.get_detail

    for feature_config in SCORING_FEATURES_CONFIG:
        if feature_config.get('enabled', True):
            feature_class = feature_config['feature']
            feature = feature_class()
            try:
                score = feature.calculate_score(channel_details())
                total_score += score
            except Exception as e:
                logger.error(f"Error calculating score for feature {feature_class.__name__} for {channel.url}: {e}")

    return round(total_score, 2)


PROFILE_NAME_TEMPLATE = "{protocol} | {server} | {port} | {security} | {transport} | {sni_short}"

def generate_custom_name(channel: ChannelConfig) -> str:
    """Generates a custom name for proxy profile from ChannelConfig, using a template."""
    channel_details = channel.get_detail()
    protocol_part = channel_details['protocol'].split("://")[0].upper() if channel_details['protocol'] else "UNKNOWN"
    transport_type = channel_details['query_params'].get("type", ["NONE"])[0].upper()
    security_type = channel_details['query_params'].get("security", ["NONE"])[0].upper()
    sni = channel_details['sni']
    sni_short = sni[:10] + "..." if sni and len(sni) > 10 else sni if sni else "NoSNI"
    server_name = channel_details['hostname'] if channel_details['hostname'] else "UnknownServer"
    port_number = str(channel_details['port']) if channel_details['port'] else "DefPort"

    name_components = {
        'protocol': protocol_part,
        'transport': transport_type if transport_type != "NONE" else '',
        'security': security_type if security_type != "NONE" else '',
        'sni_short': f"SNI:{sni_short}" if sni_short != "NoSNI" else '',
        'server': server_name[:15], # Shorten server name
        'port': port_number
    }

    # Filter out empty strings and "NONE" components for cleaner names
    filtered_components = [v for k, v in name_components.items() if v and v.upper() != 'NONE']

    return " | ".join(filtered_components)


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

def create_profile_key(config: str) -> str:
    """Creates a unique key for proxy profile to identify duplicates."""
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)

        core_pattern = re.compile(r"^(vless|tuic|hy2|trojan|ss)://.*?@([\w\d\.\:]+):(\d+)") # Added ss
        match = core_pattern.match(config)

        if match:
            protocol, host_port, port = match.groups()
            host = host_port.split(':')[0] if ':' in host_port else host_port
            key_parts = [
                protocol,
                host,
                port,
            ]

            if CHECK_USERNAME or protocol in ('trojan', 'ss'): # Added ss
                user = parsed.username
                password = parsed.password
                id_value = query.get('id', [None])[0]
                if user:
                    key_parts.append(f"user:{user}")
                elif password and protocol == 'trojan':
                    key_parts.append(f"password:***")
                elif password and protocol == 'ss': # Added ss password
                    key_parts.append(f"password:***")
                elif id_value:
                    key_parts.append(f"id:{id_value}")

            if CHECK_TLS_REALITY and protocol != 'ss': # TLS Reality check, exclude ss
                 key_parts.append(f"security:{query.get('security', [''])[0]}")
                 key_parts.append(f"encryption:{query.get('encryption', [''])[0]}")

            if CHECK_SNI and protocol != 'ss': # SNI check, exclude ss
                key_parts.append(f"sni:{query.get('sni', [''])[0]}")

            if CHECK_CONNECTION_TYPE and protocol != 'ss': # Connection type check, exclude ss
                key_parts.append(f"type:{query.get('type', [''])[0]}")

            return "|".join(key_parts)
        else:
            return config

    except Exception as e:
        logger.error(f"Error creating profile key for {config}: {e}")
        raise ValueError(f"Failed to create profile key: {config}") from e

DUPLICATE_PROFILE_REGEX = re.compile(
    r"^(vless|tuic|hy2|trojan|ss)://(?:.*?@)?([^@/:]+):(\d+)" # Added ss
)


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, existing_profiles_regex: set, proxy_config: "ProxyConfig") -> List[Dict]:
    """Processes a single channel URL to extract proxy configurations."""
    proxies = []
    channel.status = ChannelStatus.CHECKING # Update channel status to checking
    async with channel_semaphore:
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(channel.url, timeout=channel.request_timeout) as response:
                if response.status != 200:
                    logger.error(f"Channel {channel.url} returned status {response.status}")
                    channel.check_count += 1
                    channel.update_channel_stats(success=False)
                    channel.status = ChannelStatus.FAILED # Update channel status to failed
                    return proxies

                text = await response.text()
                end_time = asyncio.get_event_loop().time()
                response_time = end_time - start_time
                logger.info(f"Content from {channel.url} loaded in {response_time:.2f} seconds")
                channel.update_channel_stats(success=True, response_time=response_time)
                channel.status = ChannelStatus.ACTIVE # Update channel status to active

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Error loading from {channel.url}: {type(e).__name__} - {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            channel.status = ChannelStatus.FAILED # Update channel status to failed
            return proxies
        except Exception as e:
            logger.exception(f"Unexpected error loading from {channel.url}: {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            channel.status = ChannelStatus.FAILED # Update channel status to failed
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
                elif protocol == 'ss://':
                    userinfo_base64 = parsed.netloc.split('@')[0]
                    try:
                        base64.b64decode(userinfo_base64 + '===') # Test base64 decoding for ss
                    except:
                        logger.debug(f"Profile {line} skipped due to invalid base64 encoding in ss url")
                        continue


                if profile_id and protocol in ('vless://', 'trojan://'): # UUID check for vless and trojan
                    if not is_valid_uuid(profile_id):
                        logger.debug(f"Profile {line} skipped due to invalid UUID format: {profile_id}")
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

            try:
                score = compute_profile_score(ChannelConfig(line), response_time=channel.metrics.avg_response_time) # Create ChannelConfig object for scoring
            except Exception as e:
                logger.error(f"Error computing score for config {line}: {e}")
                continue


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


VERIFICATION_METHODS_CONFIG = [
    {'method': 'tcp_handshake', 'enabled': True},
    {'method': 'http_get', 'enabled': True, 'test_url': TEST_URL_FOR_PROXY_CHECK},
]

async def verify_proxies_availability(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Verifies proxy availability using configurable methods."""
    available_proxies = []
    verified_count = 0
    non_verified_count = 0

    logger.info("Starting proxy availability check...")

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        for proxy_item in proxies:
            config = proxy_item['config']
            is_available = False
            verification_details = {}

            for method_config in VERIFICATION_METHODS_CONFIG:
                if method_config.get('enabled', True):
                    method_name = method_config['method']
                    try:
                        if method_name == 'tcp_handshake':
                            hostname = urlparse(config).hostname
                            port = urlparse(config).port
                            if hostname and port:
                                is_available, method_details = await _verify_proxy_tcp_handshake(hostname, port)
                                verification_details['tcp_handshake'] = method_details
                        elif method_name == 'http_get':
                            test_url = method_config.get('test_url', TEST_URL_FOR_PROXY_CHECK)
                            is_available, method_details = await _verify_proxy_http_get(session, config, test_url)
                            verification_details['http_get'] = method_details

                        if is_available:
                            break # Stop on first successful method (optional)
                    except Exception as e:
                        logger.error(f"Error during proxy verification method {method_name} for {config}: {e}")
                        verification_details[method_name] = {'error': str(e)}

            if is_available:
                available_proxies.append(proxy_item)
                verified_count += 1
                logger.debug(f"Proxy {config} passed verification. Details: {verification_details}")
            else:
                non_verified_count += 1
                logger.debug(f"Proxy {config} failed verification. Details: {verification_details}")

    logger.info(f"Proxy availability check complete. Available: {len(available_proxies)} of {len(proxies)} proxies.")
    return available_proxies, verified_count, non_verified_count


async def _verify_proxy_tcp_handshake(hostname: str, port: int) -> Tuple[bool, Dict]:
    """Verifies TCP server availability."""
    start_time = asyncio.get_event_loop().time()
    try:
        async with asyncio.timeout(5):
            reader, writer = await asyncio.open_connection(hostname, port)
            writer.close()
            await writer.wait_closed()
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            logger.debug(f"TCP handshake: Proxy {hostname}:{port} passed in {response_time:.2f} seconds.")
            return True, {'status': 'success', 'response_time': response_time}
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        end_time = asyncio.get_event_loop().time()
        response_time = end_time - start_time
        logger.debug(f"TCP handshake failed for {hostname}:{port} in {response_time:.2f} seconds: {type(e).__name__} - {e}")
        return False, {'status': 'failed', 'error_type': type(e).__name__, 'error_message': str(e), 'response_time': response_time}


async def _verify_proxy_http_get(session: aiohttp.ClientSession, proxy_url: str, test_url: str) -> Tuple[bool, Dict]:
    """Verifies proxy by making a GET request through it."""
    start_time = asyncio.get_event_loop().time()
    try:
        async with asyncio.timeout(10):
            async with session.get(test_url, proxy=proxy_url) as response:
                end_time = asyncio.get_event_loop().time()
                response_time = end_time - start_time
                if response.status == 200:
                    logger.debug(f"HTTP GET via proxy {proxy_url} to {test_url} passed in {response_time:.2f} seconds.")
                    return True, {'status': 'success', 'http_status': response.status, 'response_time': response_time}
                else:
                    logger.debug(f"HTTP GET via proxy {proxy_url} to {test_url} failed with status {response.status} in {response_time:.2f} seconds.")
                    return False, {'status': 'failed', 'http_status': response.status, 'response_time': response_time}
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        end_time = asyncio.get_event_loop().time()
        response_time = end_time - start_time
        logger.debug(f"HTTP GET via proxy {proxy_url} to {test_url} error in {response_time:.2f} seconds: {type(e).__name__} - {e}")
        return False, {'status': 'failed', 'error_type': type(e).__name__, 'error_message': str(e), 'response_time': response_time}


def save_final_configs(proxies: List[Dict], output_file: str):
    """Saves final proxy configurations to output file, sorted by score."""
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True)

    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies_sorted:
                if proxy['score'] > MIN_ACCEPTABLE_SCORE:
                    config = proxy['config'].split('#')[0].strip()
                    channel_config = ChannelConfig(config) # Create ChannelConfig for naming
                    profile_name = generate_custom_name(channel_config)
                    final_line = f"{config}# {profile_name} | Score: {proxy['score']:.2f}\n" # Added score to output
                    f.write(final_line)
        logger.info(f"Final configurations saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving configurations: {str(e)}")


def is_valid_ipv4(hostname: str) -> bool:
    """Checks if hostname is a valid IPv4 address."""
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


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
        logger.info(f"Proxies passed check: {verified_count}")
        logger.info(f"Proxies failed check: {non_verified_count}")
        logger.info("Protocol Statistics:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")
        logger.info("================== END STATISTICS ==============")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
