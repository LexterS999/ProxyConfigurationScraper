import asyncio
import aiohttp
import re
import os
import json
import logging
import ipaddress
import io
import uuid
import numbers
import functools
import string
import socket

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict

import aiodns
import numpy as np
from sklearn.linear_model import LinearRegression


# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(process)s - %(message)s'
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Логирование в файл (уровень WARNING и выше)
file_handler = logging.FileHandler('proxy_checker.log', encoding='utf-8')
file_handler.setLevel(logging.WARNING)
formatter_file = logging.Formatter('%(asctime)s - %(levelname)s - %(process)s - %(message)s')
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Логирование в консоль (уровень INFO и выше)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s') # Упрощенный формат для консоли
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


# Константы
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
MIN_ACCEPTABLE_SCORE = 40.0
MIN_CONFIG_LENGTH = 30
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"] # Добавлен ssconf://
MAX_CONCURRENT_CHANNELS = 200
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 50
MAX_CONCURRENT_PROXIES_GLOBAL = 500
REQUEST_TIMEOUT = 120  # Увеличено REQUEST_TIMEOUT до 120 секунд
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2
AGE_PENALTY_PER_DAY = 0.1


# --- Исключения ---
class InvalidURLError(ValueError):
    """Неверный формат URL."""
    pass

class UnsupportedProtocolError(ValueError):
    """Неподдерживаемый протокол."""
    pass

class InvalidParameterError(ValueError):
    """Неверный параметр в URL."""
    pass

class ConfigParseError(ValueError):
    """Ошибка при разборе параметров конфигурации."""
    pass


# --- Enum для имен профилей ---
class ProfileName(Enum):
    VLESS_FORMAT = "🌌 VLESS - {transport} - {security}"
    VLESS_WS_TLS = "🚀 VLESS - WS - TLS"
    SS_FORMAT = "🎭 SS - {method}"
    SS_CHACHA20_IETF_POLY1305 = "🛡️ SS - CHACHA20-IETF-POLY1305"
    SSCONF_FORMAT = "📦 SSCONF" # Добавлен SSCONF
    TROJAN_FORMAT = "🗡️ Trojan - {transport} - {security}"
    TROJAN_WS_TLS = "⚔️ Trojan - WS - TLS"
    TUIC_FORMAT = "🐢 TUIC - {transport} - {security} - {congestion_control}"
    TUIC_WS_TLS_BBR = "🐇 TUIC - WS - TLS - BBR"
    HY2_FORMAT = "💧 HY2 - {transport} - {security}"
    HY2_UDP_TLS = "🐳 HY2 - UDP - TLS"


# --- Data classes для конфигураций ---
@dataclass(frozen=True)
class VlessConfig:
    """Конфигурация VLESS прокси."""
    uuid: str
    address: str
    port: int
    security: str
    transport: str
    encryption: str
    sni: Optional[str] = None
    alpn: Optional[Tuple[str, ...]] = None
    path: Optional[str] = None
    early_data: Optional[bool] = None
    utls: Optional[str] = None
    obfs: Optional[str] = None
    headers: Optional[Dict[str,str]] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "VlessConfig":
        """Создает объект VlessConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers"))
        alpn = tuple(sorted(query.get('alpn', []))) if 'alpn' in query else None

        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
            security=query.get('security', ['none'])[0].lower(),
            transport=query.get('type', ['tcp'])[0].lower(),
            encryption=query.get('encryption', ['none'])[0].lower(),
            sni=query.get('sni', [None])[0],
            alpn=alpn,
            path=query.get('path', [None])[0],
            early_data=_get_value(query, 'earlyData') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs = query.get('obfs',[None])[0],
            headers=headers,
            first_seen = datetime.now()
        )


@dataclass(frozen=True)
class SSConfig:
    """Конфигурация Shadowsocks прокси."""
    method: str
    password: str
    address: str
    port: int
    plugin: Optional[str] = None
    obfs:Optional[str] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "SSConfig":
        """Создает объект SSConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            method=parsed_url.username.lower() if parsed_url.username else 'none',
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
            plugin=query.get('plugin', [None])[0],
            obfs = query.get('obfs',[None])[0],
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class SSConfConfig: # Data class for ssconf protocol
    """Конфигурация Shadowsocks Conf прокси."""
    server: str
    server_port: int
    local_address: str
    local_port: int
    password: str
    timeout: int
    method: str
    protocol: str
    protocol_param: Optional[str] = None
    obfs: str
    obfs_param: Optional[str] = None
    remarks: Optional[str] = None
    group: Optional[str] = None
    udp_over_tcp: bool = False
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, config_string: str, resolver: aiodns.DNSResolver) -> "SSConfConfig":
        """Создает объект SSConfConfig из строки конфигурации."""
        try:
            config_b64 = config_string.split("ssconf://")[1]
            config_json_str = base64.urlsafe_b64decode(config_b64 + '=' * (4 - len(config_b64) % 4)).decode('utf-8')
            config_json = json.loads(config_json_str)

            # Normalize keys to lowercase for case-insensitive access
            config_json = {k.lower(): v for k, v in config_json.items()}

            return cls(
                server=config_json.get('server'),
                server_port=int(config_json.get('server_port')),
                local_address=config_json.get('local_address', '127.0.0.1'), # Default values if missing
                local_port=int(config_json.get('local_port', 1080)),        # Default values if missing
                password=config_json.get('password'),
                timeout=int(config_json.get('timeout', 300)),              # Default values if missing
                method=config_json.get('method'),
                protocol=config_json.get('protocol', 'origin'),          # Default values if missing
                protocol_param=config_json.get('protocol_param'),
                obfs=config_json.get('obfs', 'plain'),                   # Default values if missing
                obfs_param=config_json.get('obfs_param'),
                remarks=config_json.get('remarks'),
                group=config_json.get('group'),
                udp_over_tcp=bool(config_json.get('udp_over_tcp', False)), # Default values if missing
                first_seen=datetime.now()
            )
        except json.JSONDecodeError as e:
            raise ConfigParseError(f"JSON decode error: {e}")
        except KeyError as e:
            raise ConfigParseError(f"Missing key in config: {e}")
        except ValueError as e:
            raise ConfigParseError(f"Value error: {e}")
        except Exception as e:
            raise ConfigParseError(f"Unexpected error parsing ssconf: {e}")


@dataclass(frozen=True)
class TrojanConfig:
    """Конфигурация Trojan прокси."""
    password: str
    address: str
    port: int
    security: str
    transport: str
    sni: Optional[str] = None
    alpn: Optional[Tuple[str, ...]] = None
    early_data: Optional[bool] = None
    utls: Optional[str] = None
    obfs: Optional[str] = None
    headers: Optional[Dict[str,str]] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "TrojanConfig":
        """Создает объект TrojanConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers"))
        alpn = tuple(sorted(_get_value(query, 'alpn', []).split(','))) if 'alpn' in query else None

        return cls(
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
            security=_get_value(query, 'security', 'tls').lower(),
            transport=_get_value(query, 'type', 'tcp').lower(),
            sni=_get_value(query, 'sni'),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs = _get_value(query, 'obfs'),
            headers=headers,
            first_seen=datetime.now()
        )


@dataclass(frozen=True)
class TuicConfig:
    """Конфигурация TUIC прокси."""
    uuid: str
    address: str
    port: int
    security: str
    transport: str
    congestion_control: str
    sni: Optional[str] = None
    alpn: Optional[Tuple[str, ...]] = None
    early_data: Optional[bool] = None
    udp_relay_mode: Optional[str] = None
    zero_rtt_handshake: Optional[bool] = None
    utls: Optional[str] = None
    password: Optional[str] = None
    obfs: Optional[str] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "TuicConfig":
        """Создает объект TuicConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        alpn = tuple(sorted(_get_value(query, 'alpn', []).split(','))) if 'alpn' in query else None

        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
            security=_get_value(query, 'security', 'tls').lower(),
            transport=_get_value(query, 'type', 'udp').lower(),
            congestion_control=_get_value(query, 'congestion', 'bbr').lower(),
            sni=_get_value(query, 'sni'),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            udp_relay_mode=_get_value(query, 'udp_relay_mode', 'quic').lower(),
            zero_rtt_handshake=_get_value(query, 'zero_rtt_handshake') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            password=parsed_url.password,
            obfs = _get_value(query, 'obfs'),
            first_seen=datetime.now()
        )


@dataclass(frozen=True)
class Hy2Config:
    """Конфигурация HY2 прокси."""
    address: str
    port: int
    security: str
    transport: str
    sni: Optional[str] = None
    alpn: Optional[Tuple[str, ...]] = None
    early_data: Optional[bool] = None
    pmtud: Optional[bool] = None
    hop_interval: Optional[int] = None
    password: Optional[str] = None
    utls: Optional[str] = None
    obfs: Optional[str] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "Hy2Config":
        """Создает объект Hy2Config из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)

        hop_interval_str = _get_value(query, 'hopInterval')
        hop_interval = _parse_hop_interval(hop_interval_str)
        alpn = tuple(sorted(_get_value(query, 'alpn', []).split(','))) if 'alpn' in query else None

        return cls(
            address=address,
            port=parsed_url.port,
            security=_get_value(query, 'security', 'tls').lower(),
            transport=_get_value(query, 'type', 'udp').lower(),
            sni=_get_value(query, 'sni'),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            pmtud=_get_value(query, 'pmtud') == '1',
            hop_interval=hop_interval,
            password = parsed_url.password,
            utls = _get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs = _get_value(query, 'obfs'),
            first_seen = datetime.now()
        )


# --- Data classes для метрик и конфигураций каналов ---
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
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    protocol_scores: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    first_seen: Optional[datetime] = None


class ChannelConfig:
    """Конфигурация канала для проверки прокси."""
    RESPONSE_TIME_DECAY = 0.7
    VALID_PROTOCOLS = ["http://", "https://", "vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"] # Добавлен ssconf://

    def __init__(self, url: str, request_timeout: int = REQUEST_TIMEOUT):
        """Инициализирует объект ChannelConfig."""
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = request_timeout
        self.check_count = 0
        self.metrics.first_seen = datetime.now()

    def _validate_url(self, url: str) -> str:
        """Проверяет и нормализует URL канала."""
        if not isinstance(url, str):
            raise InvalidURLError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        if not url:
            raise InvalidURLError("URL не может быть пустым.")
        if re.search(r'(.)\1{100,}', url):
            raise InvalidURLError("URL содержит слишком много повторяющихся символов.")

        parsed = urlsplit(url)
        if parsed.scheme not in [p.replace('://', '') for p in self.VALID_PROTOCOLS]:
            expected_protocols = ', '.join(self.VALID_PROTOCOLS)
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError(
                f"Неверный протокол URL. Ожидается: {expected_protocols}, получено: {received_protocol_prefix}..."
            )
        return url

    def calculate_overall_score(self):
        """Вычисляет общий рейтинг канала на основе метрик."""
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            max_possible_score = (ScoringWeights.CHANNEL_STABILITY.value + HIGH_FREQUENCY_BONUS)
            self.metrics.overall_score = round(
                ((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus - response_time_penalty)
                / max_possible_score * 100, 2)

        except Exception as e:
            logger.error(f"Ошибка при расчете рейтинга для {self.url}: {e}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        """Вычисляет долю успешных проверок канала."""
        total_checks = self.metrics.success_count + self.metrics.fail_count
        return self.metrics.success_count / total_checks if total_checks > 0 else 0.0

    def _calculate_recency_bonus(self) -> float:
        """Вычисляет бонус за недавние успешные проверки."""
        if self.metrics.last_success_time:
            time_since_last_success = datetime.now() - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 else 0.0
        return 0.0

    def _calculate_response_time_penalty(self) -> float:
        """Вычисляет штраф за среднее время ответа."""
        if self.metrics.avg_response_time > 0:
            max_response_time_penalty = 20
            penalty = min(self.metrics.avg_response_time / 5 * max_response_time_penalty, max_response_time_penalty)
            return penalty
        return 0.0

    def update_channel_stats(self, success: bool, response_time: float = 0.0):
        """Обновляет статистику канала."""
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
    """Управляет конфигурациями прокси."""
    def __init__(self):
        """Инициализирует объект ProxyConfig, загружает URL каналов и настраивает окружение."""
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.resolver = None
        self.failed_channels = []
        self.processed_configs = set()
        self.SOURCE_URLS = self._load_source_urls()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.ALL_URLS_FILE = ALL_URLS_FILE

    def _load_source_urls(self) -> List[ChannelConfig]:
        """Загружает URL каналов из файла и удаляет дубликаты."""
        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except (InvalidURLError, UnsupportedProtocolError) as e:
                            logger.warning(f"Неверный URL в {ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"Файл URL не найден: {ALL_URLS_FILE}. Создается пустой файл.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")

        unique_configs = self._remove_duplicate_urls(initial_urls)
        if not unique_configs:
            self.save_empty_config_file()
            logger.error("Не найдено валидных источников. Создан пустой файл конфигурации.")
        return unique_configs

    async def _normalize_url(self, url: str) -> str:
        """Нормализует URL прокси."""
        if not url:
            raise InvalidURLError("URL не может быть пустым для нормализации.")
        url = url.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            raise InvalidURLError(f"Отсутствует схема в URL: '{url}'. Ожидается 'http://' или 'https://'.")
        if not parsed.netloc:
            raise InvalidURLError(f"Отсутствует netloc (домен или IP) в URL: '{url}'.")
        if not all(c in (string.ascii_letters + string.digits + '.-:') for c in parsed.netloc):
            raise InvalidURLError(f"Недопустимые символы в netloc URL: '{parsed.netloc}'")

        path = parsed.path.rstrip('/')
        return parsed._replace(path=path).geturl()

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """Удаляет дубликаты URL каналов из списка."""
        seen_urls = set()
        unique_configs = []
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                logger.warning(f"Неверная конфигурация пропущена: {config}")
                continue
            try:
                normalized_url = asyncio.run(self._normalize_url(config.url))
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
            except Exception:
                continue
        return unique_configs

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Возвращает список включенных каналов."""
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        """Сохраняет пустой файл конфигурации."""
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {e}")
            return False

    def set_event_loop(self, loop):
        """Устанавливает event loop для асинхронного DNS resolver."""
        self.resolver = aiodns.DNSResolver(loop=loop)

    def remove_failed_channels_from_file(self):
        """Удаляет URL нерабочих каналов из файла all_urls.txt."""
        if not self.failed_channels:
            return

        try:
            with open(self.ALL_URLS_FILE, 'r', encoding='utf-8') as f_read:
                lines = f_read.readlines()
            updated_lines = [line for line in lines if line.strip() not in self.failed_channels]
            with open(self.ALL_URLS_FILE, 'w', encoding='utf-8') as f_write:
                f_write.writelines(updated_lines)
            logger.info(f"Удалены нерабочие каналы из {self.ALL_URLS_FILE}: {', '.join(self.failed_channels)}")
            self.failed_channels = []
        except FileNotFoundError:
            logger.error(f"Файл не найден: {self.ALL_URLS_FILE}. Невозможно удалить нерабочие каналы.")
        except Exception as e:
            logger.error(f"Ошибка при удалении нерабочих каналов из {self.ALL_URLS_FILE}: {e}")


# --- Enum для весов скоринга ---
class ScoringWeights(Enum):
    """Перечисление весов, используемых для скоринга конфигураций прокси."""
    PROTOCOL_BASE = 20
    CONFIG_LENGTH = 5
    RESPONSE_TIME = -0.1
    AGE_PENALTY = -0.05
    CHANNEL_STABILITY = 15

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

    SS_METHOD_CHACHA20_IETF_POLY1305 = 15
    SS_METHOD_AES_256_GCM = 14
    SS_METHOD_AES_128_GCM = 12
    SS_METHOD_NONE = -20
    SS_PASSWORD_LENGTH = 5
    SS_PLUGIN_OBFS_TLS = 10
    SS_PLUGIN_OBFS_HTTP = 8
    SS_PLUGIN_NONE = 0

    SSCONF_SERVER_PORT = 5 # Example weights for SSCONF
    SSCONF_METHOD_CHACHA20_IETF_POLY1305 = 15
    SSCONF_METHOD_AES_256_GCM = 14
    SSCONF_METHOD_AES_128_GCM = 12
    SSCONF_METHOD_NONE = -20
    SSCONF_PASSWORD_LENGTH = 5
    SSCONF_PROTOCOL_ORIGIN = 3
    SSCONF_PROTOCOL_AUTH_SHA1_V4 = 7
    SSCONF_PROTOCOL_AUTH_AES128_CFB = 7
    SSCONF_OBFS_PLAIN = 0
    SSCONF_OBFS_TLS = 10
    SSCONF_OBFS_HTTP = 8
    SSCONF_OBFS_WEBSOCKET = 10
    SSCONF_UDP_OVER_TCP = 5


    TROJAN_SECURITY_TLS = 15
    TROJAN_TRANSPORT_WS = 10
    TROJAN_TRANSPORT_TCP = 2
    TROJAN_PASSWORD_LENGTH = 5
    TROJAN_SNI_PRESENT = 7
    TROJAN_ALPN_PRESENT = 5
    TROJAN_EARLY_DATA = 3

    TUIC_SECURITY_TLS = 15
    TUIC_TRANSPORT_WS = 10
    TUIC_TRANSPORT_UDP = 5
    TUIC_CONGESTION_CONTROL_BBR = 8
    TUIC_CONGESTION_CONTROL_CUBIC = 5
    TUIC_CONGESTION_CONTROL_NEW_RENO = 3
    TUIC_UUID_PRESENT = 5
    TUIC_PASSWORD_LENGTH = 5
    TUIC_SNI_PRESENT = 7
    TUIC_ALPN_PRESENT = 5
    TUIC_EARLY_DATA = 3
    TUIC_UDP_RELAY_MODE = 7
    TUIC_ZERO_RTT_HANDSHAKE = 6

    HY2_SECURITY_TLS = 15
    HY2_TRANSPORT_UDP = 5
    HY2_TRANSPORT_TCP = 2
    HY2_PASSWORD_LENGTH = 5
    HY2_SNI_PRESENT = 7
    HY2_ALPN_PRESENT = 5
    HY2_EARLY_DATA = 3
    HY2_PMTUD_ENABLED = 4
    HY2_HOP_INTERVAL = 2

    COMMON_PORT_443 = 10
    COMMON_PORT_80 = 5
    COMMON_PORT_OTHER = 2
    COMMON_UTLS_CHROME = 7
    COMMON_UTLS_FIREFOX = 6
    COMMON_UTLS_RANDOMIZED = 5
    COMMON_UTLS_OTHER = 2
    COMMON_CDN = 8
    COMMON_OBFS = 4
    COMMON_HEADERS = 3
    COMMON_RARE_PARAM = 4
    COMMON_HIDDEN_PARAM = 2

    @staticmethod
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> Dict[str, Any]:
        """Загружает веса скоринга из JSON-файла."""
        all_weights_loaded_successfully = True
        loaded_weights = {}

        try:
            if not os.path.exists(file_path):
                ScoringWeights._create_default_weights_file(file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    try:
                        if not isinstance(value, (int, float)):
                            raise ValueError(f"Invalid weight value (must be a number) for {name}: {value}")
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
            loaded_weights = {member.name: member.value for member in ScoringWeights}
        return loaded_weights

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        """Создает файл с весами скоринга по умолчанию в формате JSON."""
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
        """Сохраняет веса скоринга в JSON-файл."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(weights, f, indent=4)
            logger.info(f"Scoring weights saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving scoring weights to {file_path}: {e}")

    @staticmethod
    def calibrate_weights(training_data: List[Dict], features: List[str], target: str = 'score',
                          file_path: str = DEFAULT_SCORING_WEIGHTS_FILE):
        """Калибрует веса скоринга с использованием линейной регрессии."""
        if not training_data:
            logger.warning("No training data provided for weight calibration. Skipping.")
            return

        X = []
        y = []
        for profile_data in training_data:
            feature_vector = [profile_data.get(feature, 0) for feature in features]
            X.append(feature_vector)
            y.append(profile_data.get(target, 0))

        X = np.array(X)
        y = np.array(y)

        if X.shape[0] <= X.shape[1]:
            logger.warning("Not enough data for weight calibration (need more data points than features). Skipping.")
            return

        model = LinearRegression()
        try:
            model.fit(X, y)
        except Exception as e:
            logger.error(f"Error during model fitting: {e}")
            return

        new_weights = {feature: abs(coef) for feature, coef in zip(features, model.coef_)}
        total_weight = sum(new_weights.values())

        if total_weight > 0:
            normalized_weights = {k: (v / total_weight) * 100 for k, v in new_weights.items()}
            saved_weights = {k: v for k,v in normalized_weights.items() if k in features}
            ScoringWeights.save_weights_to_json(saved_weights, file_path)
            logger.info(f"Weights calibrated and saved: {saved_weights}")
        else:
            logger.warning("Total weight is zero after calibration. Skipping weight update.")


# --- Вспомогательные функции ---
def _get_value(query: Dict, key: str, default_value: Any = None) -> Any:
    """Безопасно извлекает значение из словаря query."""
    return query.get(key, (default_value,))[0]


def _parse_headers(headers_str: Optional[str]) -> Optional[Dict[str, str]]:
    """Парсит строку заголовков в словарь."""
    if not headers_str:
        return None
    try:
        headers = json.loads(headers_str)
        if not isinstance(headers, dict):
            raise ValueError("Headers must be a JSON object")
        return headers
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Invalid headers format: {headers_str} - {e}. Ignoring headers.")
        return None

def _parse_hop_interval(hop_interval_str: Optional[str]) -> Optional[int]:
    """Парсит hopInterval в целое число или None."""
    if hop_interval_str is None:
        return None
    try:
        return int(hop_interval_str)
    except ValueError:
        logger.warning(f"Invalid hopInterval value, using None: {hop_interval_str}")
        return None

import base64 # Import for ssconf decode

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> str:
    """Резолвит доменное имя в IP-адрес."""
    if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
        return hostname
    try:
        result = await resolver.query(hostname, 'A')
        return result[0].host
    except aiodns.error.DNSError as e:
        logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}")
        return hostname
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при резолвинге {hostname}: {e}")
        return hostname


# --- Функции для расчета скоринга ---
def _calculate_vless_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет скор для VLESS конфигурации."""
    score = 0
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("VLESS_SECURITY_TLS", ScoringWeights.VLESS_SECURITY_TLS.value) if security == 'tls' else loaded_weights.get("VLESS_SECURITY_NONE", ScoringWeights.VLESS_SECURITY_NONE.value)
    transport = _get_value(query, 'type', 'tcp').lower()
    score += loaded_weights.get("VLESS_TRANSPORT_WS", ScoringWeights.VLESS_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("VLESS_TRANSPORT_TCP", ScoringWeights.VLESS_TRANSPORT_TCP.value)
    encryption = _get_value(query, 'encryption', 'none').lower()
    encryption_scores = {
        'none': loaded_weights.get("VLESS_ENCRYPTION_NONE", ScoringWeights.VLESS_ENCRYPTION_NONE.value),
        'auto': loaded_weights.get("VLESS_ENCRYPTION_AUTO", ScoringWeights.VLESS_ENCRYPTION_AUTO.value),
        'aes-128-gcm': loaded_weights.get("VLESS_ENCRYPTION_AES_128_GCM", ScoringWeights.VLESS_ENCRYPTION_AES_128_GCM.value),
        'chacha20-poly1305': loaded_weights.get("VLESS_ENCRYPTION_CHACHA20_POLY1305", ScoringWeights.VLESS_ENCRYPTION_CHACHA20_POLY1305.value)
    }
    score += encryption_scores.get(encryption, 0)

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
    """Вычисляет скор для Shadowsocks конфигурации."""
    score = 0
    method = parsed.username.lower() if parsed.username else 'none'
    method_scores = {
        'chacha20-ietf-poly1305': loaded_weights.get("SS_METHOD_CHACHA20_IETF_POLY1305", ScoringWeights.SS_METHOD_CHACHA20_IETF_POLY1305.value),
        'aes-256-gcm': loaded_weights.get("SS_METHOD_AES_256_GCM", ScoringWeights.SS_METHOD_AES_256_GCM.value),
        'aes-128-gcm': loaded_weights.get("SS_METHOD_AES_128_GCM", ScoringWeights.SS_METHOD_AES_128_GCM.value),
        'none': loaded_weights.get("SS_METHOD_NONE", ScoringWeights.SS_METHOD_NONE.value)
    }
    score += method_scores.get(method, 0)
    score += min(loaded_weights.get("SS_PASSWORD_LENGTH", ScoringWeights.SS_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("SS_PASSWORD_LENGTH", ScoringWeights.SS_PASSWORD_LENGTH.value)) if parsed.password else 0

    plugin = _get_value(query, 'plugin', 'none').lower()
    plugin_scores = {
        'obfs-http': loaded_weights.get("SS_PLUGIN_OBFS_HTTP", ScoringWeights.SS_PLUGIN_OBFS_HTTP.value),
        'obfs-tls': loaded_weights.get("SS_PLUGIN_OBFS_TLS", ScoringWeights.SS_PLUGIN_OBFS_TLS.value)
    }
    if plugin != 'none':
        score += plugin_scores.get(plugin, 0)
    else:
        score += loaded_weights.get("SS_PLUGIN_NONE", ScoringWeights.SS_PLUGIN_NONE.value)
    return score

def _calculate_ssconf_score(config_obj: SSConfConfig, loaded_weights: Dict) -> float:
    """Вычисляет скор для Shadowsocks Conf конфигурации."""
    score = 0

    score += loaded_weights.get("SSCONF_SERVER_PORT", ScoringWeights.SSCONF_SERVER_PORT.value) if config_obj.server_port in [80, 443, 8080, 8443] else 0

    method_scores = {
        'chacha20-ietf-poly1305': loaded_weights.get("SSCONF_METHOD_CHACHA20_IETF_POLY1305", ScoringWeights.SSCONF_METHOD_CHACHA20_IETF_POLY1305.value),
        'aes-256-gcm': loaded_weights.get("SSCONF_METHOD_AES_256_GCM", ScoringWeights.SSCONF_METHOD_AES_256_GCM.value),
        'aes-128-gcm': loaded_weights.get("SSCONF_METHOD_AES_128_GCM", ScoringWeights.SSCONF_METHOD_AES_128_GCM.value),
        'none': loaded_weights.get("SSCONF_METHOD_NONE", ScoringWeights.SSCONF_METHOD_NONE.value) # Consider if 'none' is valid for ssconf
    }
    score += method_scores.get(config_obj.method, 0)

    score += min(loaded_weights.get("SSCONF_PASSWORD_LENGTH", ScoringWeights.SSCONF_PASSWORD_LENGTH.value),
                 len(config_obj.password or '') / 16 * loaded_weights.get("SSCONF_PASSWORD_LENGTH", ScoringWeights.SSCONF_PASSWORD_LENGTH.value)) if config_obj.password else 0

    protocol_scores = {
        'origin': loaded_weights.get("SSCONF_PROTOCOL_ORIGIN", ScoringWeights.SSCONF_PROTOCOL_ORIGIN.value),
        'auth_sha1_v4': loaded_weights.get("SSCONF_PROTOCOL_AUTH_SHA1_V4", ScoringWeights.SSCONF_PROTOCOL_AUTH_SHA1_v4.value),
        'auth_aes128_cfb': loaded_weights.get("SSCONF_PROTOCOL_AUTH_AES128_CFB", ScoringWeights.SSCONF_PROTOCOL_AUTH_AES128_CFB.value),
    }
    score += protocol_scores.get(config_obj.protocol, loaded_weights.get("SSCONF_PROTOCOL_ORIGIN", ScoringWeights.SSCONF_PROTOCOL_ORIGIN.value)) # Default to origin if not found

    obfs_scores = {
        'plain': loaded_weights.get("SSCONF_OBFS_PLAIN", ScoringWeights.SSCONF_OBFS_PLAIN.value),
        'tls': loaded_weights.get("SSCONF_OBFS_TLS", ScoringWeights.SSCONF_OBFS_TLS.value),
        'http': loaded_weights.get("SSCONF_OBFS_HTTP", ScoringWeights.SSCONF_OBFS_HTTP.value),
        'websocket': loaded_weights.get("SSCONF_OBFS_WEBSOCKET", ScoringWeights.SSCONF_OBFS_WEBSOCKET.value),
    }
    score += obfs_scores.get(config_obj.obfs, loaded_weights.get("SSCONF_OBFS_PLAIN", ScoringWeights.SSCONF_OBFS_PLAIN.value)) # Default to plain if not found

    if config_obj.udp_over_tcp:
        score += loaded_weights.get("SSCONF_UDP_OVER_TCP", ScoringWeights.SSCONF_UDP_OVER_TCP.value)

    return score


def _calculate_trojan_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет скор для Trojan конфигурации."""
    score = 0
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("TROJAN_SECURITY_TLS", ScoringWeights.TROJAN_SECURITY_TLS.value) if security == 'tls' else 0
    transport = _get_value(query, 'type', 'tcp').lower()
    score += loaded_weights.get("TROJAN_TRANSPORT_WS", ScoringWeights.TROJAN_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TROJAN_TRANSPORT_TCP", ScoringWeights.TROJAN_TRANSPORT_TCP.value)

    score += min(loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value)) if parsed.password else 0

    if _get_value(query, 'sni'):
        score += loaded_weights.get("TROJAN_SNI_PRESENT", ScoringWeights.TROJAN_SNI_PRESENT.value)
    if _get_value(query, 'alpn'):
        score += loaded_weights.get("TROJAN_ALPN_PRESENT", ScoringWeights.TROJAN_ALPN_PRESENT.value)
    if _get_value(query, 'earlyData') == '1':
        score += loaded_weights.get("TROJAN_EARLY_DATA", ScoringWeights.TROJAN_EARLY_DATA.value)
    return score


def _calculate_tuic_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет скор для TUIC конфигурации."""
    score = 0
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("TUIC_SECURITY_TLS", ScoringWeights.TUIC_SECURITY_TLS.value) if security == 'tls' else 0
    transport = _get_value(query, 'type', 'udp').lower()
    score += loaded_weights.get("TUIC_TRANSPORT_WS", ScoringWeights.TUIC_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TUIC_TRANSPORT_UDP", ScoringWeights.TUIC_TRANSPORT_UDP.value)
    congestion_control = _get_value(query, 'congestion', 'bbr').lower()
    congestion_scores = {
        'bbr': loaded_weights.get("TUIC_CONGESTION_CONTROL_BBR", ScoringWeights.TUIC_CONGESTION_CONTROL_BBR.value),
        'cubic': loaded_weights.get("TUIC_CONGESTION_CONTROL_CUBIC", ScoringWeights.TUIC_CONGESTION_CONTROL_CUBIC.value),
        'new-reno': loaded_weights.get("TUIC_CONGESTION_CONTROL_NEW_RENO", ScoringWeights.TUIC_CONGESTION_CONTROL_NEW_RENO.value)
    }
    score += congestion_scores.get(congestion_control, 0)

    if parsed.username:
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
    """Вычисляет скор для HY2 конфигурации."""
    score = 0
    security = _get_value(query, 'security', 'none').lower()
    score += loaded_weights.get("HY2_SECURITY_TLS", ScoringWeights.HY2_SECURITY_TLS.value) if security == 'tls' else 0
    transport = _get_value(query, 'type', 'udp').lower()
    score += loaded_weights.get("HY2_TRANSPORT_UDP", ScoringWeights.HY2_TRANSPORT_UDP.value) if transport == 'udp' else loaded_weights.get("HY2_TRANSPORT_TCP", ScoringWeights.HY2_TRANSPORT_TCP.value)
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

    hop_interval = _get_value(query, 'hopInterval', None)
    if hop_interval:
        try:
            score += int(hop_interval) * loaded_weights.get("HY2_HOP_INTERVAL", ScoringWeights.HY2_HOP_INTERVAL.value)
        except ValueError:
            pass
    return score


def _calculate_common_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    """Вычисляет общий скор для всех типов конфигураций."""
    score = 0
    port_scores = {
        443: loaded_weights.get("COMMON_PORT_443", ScoringWeights.COMMON_PORT_443.value),
        80: loaded_weights.get("COMMON_PORT_80", ScoringWeights.COMMON_PORT_80.value)
    }
    score += port_scores.get(parsed.port, loaded_weights.get("COMMON_PORT_OTHER", ScoringWeights.COMMON_PORT_OTHER.value))

    utls = _get_value(query, 'utls', None) or _get_value(query, 'fp', 'none')
    utls = utls.lower()
    utls_scores = {
        'chrome': loaded_weights.get("COMMON_UTLS_CHROME", ScoringWeights.COMMON_UTLS_CHROME.value),
        'firefox': loaded_weights.get("COMMON_UTLS_FIREFOX", ScoringWeights.COMMON_UTLS_FIREFOX.value),
        'randomized': loaded_weights.get("COMMON_UTLS_RANDOMIZED", ScoringWeights.COMMON_UTLS_RANDOMIZED.value)
    }
    score += utls_scores.get(utls, loaded_weights.get("COMMON_UTLS_OTHER", ScoringWeights.COMMON_UTLS_OTHER.value))

    if _get_value(query, 'sni') and '.cdn.' in _get_value(query, 'sni'):
        score += loaded_weights.get("COMMON_CDN", ScoringWeights.COMMON_CDN.value)
    if _get_value(query, 'obfs'):
        score += loaded_weights.get("COMMON_OBFS", ScoringWeights.COMMON_OBFS.value)
    if _get_value(query, 'headers'):
        score += loaded_weights.get("COMMON_HEADERS", ScoringWeights.COMMON_HEADERS.value)

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


def compute_profile_score(config: str, channel_response_time: float = 0.0, loaded_weights: Dict = None, channel_score:float = 100.0, first_seen: Optional[datetime] = None) -> float:
    """Вычисляет общий рейтинг профиля прокси."""
    if loaded_weights is None:
        loaded_weights = ScoringWeights.load_weights_from_json()

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    if protocol == "ssconf://":
        try:
            config_obj = SSConfConfig.from_url(config, None) # resolver not needed for ssconf scoring
            score = _calculate_ssconf_score(config_obj, loaded_weights)
        except ConfigParseError as e:
            logger.error(f"Error parsing ssconf config for scoring: {e}")
            return 0.0

    else: # Handle URL based protocols
        try:
            parsed = urlparse(config)
            query = parse_qs(parsed.query)
        except Exception as e:
            logger.error(f"Ошибка парсинга URL {config}: {e}")
            return 0.0

        score = loaded_weights.get("PROTOCOL_BASE", ScoringWeights.PROTOCOL_BASE.value)
        score += _calculate_common_score(parsed, query, loaded_weights)
        score += channel_response_time * loaded_weights.get("RESPONSE_TIME", ScoringWeights.RESPONSE_TIME.value)
        score *= (channel_score / 100.0)

        score += min(loaded_weights.get("CONFIG_LENGTH", ScoringWeights.CONFIG_LENGTH.value),
                     (200.0 / (len(config) + 1)) * loaded_weights.get("CONFIG_LENGTH", ScoringWeights.CONFIG_LENGTH.value))

        if first_seen:
            days_old = (datetime.now() - first_seen).days
            score += days_old * loaded_weights.get("AGE_PENALTY", ScoringWeights.AGE_PENALTY.value)

        protocol_calculators = {
            "vless://": _calculate_vless_score,
            "ss://": _calculate_ss_score,
            "trojan://": _calculate_trojan_score,
            "tuic://": _calculate_tuic_score,
            "hy2://": _calculate_hy2_score,
        }
        score += protocol_calculators.get(protocol, lambda *args: 0)(parsed, query, loaded_weights) # Use get with default lambda

    max_possible_score = sum(weight for weight in loaded_weights.values())
    normalized_score = (score / max_possible_score) * 100 if max_possible_score > 0 else 0.0
    return round(normalized_score, 2)


def generate_custom_name(parsed: urlparse, query: Dict) -> str:
    """Генерирует пользовательское имя профиля на основе URL и параметров."""
    scheme = parsed.scheme
    if scheme == "vless":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["none"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.VLESS_WS_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = "" if transport_type == "NONE" else transport_type
        parts = [part for part in [transport_str, security_str] if part]
        return "🌌 VLESS - " + " - ".join(parts)

    elif scheme == "ss":
        method = quote_plus(parsed.username.upper() if parsed.username else "UNKNOWN")
        if method == "CHACHA20-IETF-POLY1305":
            return ProfileName.SS_CHACHa20_IETF_POLY1305.value
        return ProfileName.SS_FORMAT.value.format(method=method)

    elif scheme == "ssconf": # Custom name for ssconf
        return ProfileName.SSCONF_FORMAT.value

    elif scheme == "trojan":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.TROJAN_WS_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = "" if transport_type == "NONE" else transport_type
        parts = [part for part in [transport_str, security_str] if part]
        return "🗡️ Trojan - " + " - ".join(parts)

    elif scheme == "tuic":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        congestion_control = query.get("congestion", ["bbr"])[0].upper()
        if transport_type == "WS" and security_type == "TLS" and congestion_control == "BBR":
            return ProfileName.TUIC_WS_TLS_BBR.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = "" if transport_type == "NONE" else transport_type
        parts = [part for part in [transport_str, security_str, congestion_control] if part]
        return "🐢 TUIC - " + " - ".join(parts)

    elif scheme == "hy2":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "UDP" and security_type == "TLS":
            return ProfileName.HY2_UDP_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = "" if transport_type == "NONE" else transport_type
        parts = [part for part in [transport_str, security_str] if part]
        return "💧 HY2 - " + " - ".join(parts)

    return f"⚠️ Unknown Protocol: {scheme}"


@functools.lru_cache(maxsize=None)
def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли hostname валидным IPv4 адресом."""
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


@functools.lru_cache(maxsize=None)
def is_valid_ipv6(hostname: str) -> bool:
    """Проверяет, является ли hostname валидным IPv6 адресом."""
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_proxy_url(url: str) -> bool:
    """Проверяет, является ли URL валидным URL прокси."""
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False

    if url.startswith("ssconf://"): # Basic validation for ssconf
        return url.startswith("ssconf://") and len(url) > len("ssconf://")

    try: # URL based protocols validation
        parsed = urlparse(url)
        scheme = parsed.scheme
        if scheme in ('vless', 'trojan', 'tuic'):
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False

        if scheme != "ss":
            if not parsed.hostname or not parsed.port:
                return False
        else:
            if not parsed.hostname and not (parsed.username and "@" in parsed.netloc):
                return False
            if parsed.username:
                valid_methods = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'none']
                if parsed.username.lower() not in valid_methods:
                    logger.debug(f"Недопустимый метод шифрования для ss://: {parsed.username}")
                    return False

        if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)):
            if not re.match(r"^[a-zA-Z0-9.-]+$", parsed.hostname):
                return False
        return True
    except ValueError:
        return False


def is_valid_uuid(uuid_string: str) -> bool:
    """Проверяет, является ли строка валидным UUID."""
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        return False


async def parse_config(config_string: str, resolver: aiodns.DNSResolver) -> Optional[object]:
    """Парсит строку конфигурации прокси и возвращает объект конфигурации."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)

    if protocol == "ssconf://": # Parse ssconf
        try:
            return await SSConfConfig.from_url(config_string, resolver) # Resolver not actually used in SSConfConfig.from_url for now
        except ConfigParseError as e:
            logger.error(f"Ошибка парсинга ssconf конфигурации: {config_string} - {e}")
            return None

    else: # Parse URL based protocols
        try:
            parsed = urlparse(config_string)
            if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)):
                return None
            query = parse_qs(parsed.query)
            scheme = parsed.scheme

            config_parsers = {
                "vless": VlessConfig.from_url,
                "ss": SSConfig.from_url,
                "trojan": TrojanConfig.from_url,
                "tuic": TuicConfig.from_url,
                "hy2": Hy2Config.from_url,
            }
            if scheme in config_parsers:
                return await config_parsers[scheme](parsed, query, resolver)
            return None

        except (InvalidURLError, UnsupportedProtocolError, InvalidParameterError, ConfigParseError) as e:
            logger.error(f"Ошибка парсинга конфигурации: {config_string} - {e}")
            return None
        except Exception as e:
            logger.exception(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
            return None


# --- Функции для обработки каналов и прокси ---
async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession,
                          channel_semaphore: asyncio.Semaphore,
                          proxy_config: "ProxyConfig",
                          global_proxy_semaphore: asyncio.Semaphore
                          ) -> List[Dict]:
    """Обрабатывает один канал, загружает конфигурации прокси и проверяет их."""
    proxies = []
    loaded_weights = ScoringWeights.load_weights_from_json()

    async with channel_semaphore:
        retries = 0
        success = False
        response_time = 0
        text = ""

        while retries < MAX_RETRIES and not success:
            start_time = asyncio.get_event_loop().time()
            try:
                async with session.get(channel.url, timeout=channel.request_timeout) as response:
                    response.raise_for_status()
                    text = await response.text()
                    end_time = asyncio.get_event_loop().time()
                    response_time = end_time - start_time
                    success = True

            except aiohttp.ClientResponseError as e:  # Более конкретное логирование ошибок HTTP
                retries += 1
                retry_delay = RETRY_DELAY_BASE * (2 ** (retries - 1))
                logger.warning(
                    f"HTTP ошибка при загрузке из {channel.url} (попытка {retries}/{MAX_RETRIES}): "
                    f"{e.status} {e.message}. Повтор через {retry_delay} сек."
                )
                await asyncio.sleep(retry_delay)
            except asyncio.TimeoutError:  # Более конкретное логирование ошибок таймаута
                retries += 1
                retry_delay = RETRY_DELAY_BASE * (2 ** (retries - 1))
                logger.warning(
                    f"Таймаут при загрузке из {channel.url} (попытка {retries}/{MAX_RETRIES}). "
                    f"Повтор через {retry_delay} сек."
                )
                await asyncio.sleep(retry_delay)
            except aiohttp.ClientError as e:  # Более конкретное логирование ошибок клиента aiohttp
                retries += 1
                retry_delay = RETRY_DELAY_BASE * (2 ** (retries - 1))
                logger.warning(
                    f"Ошибка клиента aiohttp при загрузке из {channel.url} (попытка {retries}/{MAX_RETRIES}): "
                    f"{type(e).__name__} - {e}. Повтор через {retry_delay} сек."
                )
                await asyncio.sleep(retry_delay)

            except Exception as e:
                logger.exception(f"Непредвиденная ошибка при загрузке из {channel.url}: {e}")
                channel.check_count += 1
                channel.update_channel_stats(success=False)
                return []

        if not success:
            logger.error(f"Не удалось загрузить данные из {channel.url} после {MAX_RETRIES} попыток.")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            proxy_config.failed_channels.append(channel.url)
            return []

        logger.info(f"Контент из {channel.url} загружен за {response_time:.2f} секунд")
        channel.update_channel_stats(success=True, response_time=response_time)

        lines = text.splitlines()
        proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
        tasks = []

        for line in lines:
            line = line.strip()
            if len(line) < MIN_CONFIG_LENGTH or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line):
                continue
            task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                        loaded_weights, proxy_semaphore, global_proxy_semaphore))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                proxies.append(result)

        channel.metrics.valid_configs += len(proxies)
        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {len(proxies)} валидных конфигураций.")
        return proxies


async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig, loaded_weights: Dict,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    """Обрабатывает одну конфигурацию прокси: парсит, скорит и сохраняет результат."""
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            return None

        score = compute_profile_score(
            line,
            channel_response_time=channel.metrics.avg_response_time,
            loaded_weights=loaded_weights,
            channel_score=channel.metrics.overall_score,
            first_seen = config_obj.first_seen
        )

        result = {
            "config": line,
            "protocol": config_obj.__class__.__name__.replace("Config", "").lower(),
            "score": score,
            "config_obj": config_obj
        }
        protocol_name = config_obj.__class__.__name__.replace("Config", "").lower()
        channel.metrics.protocol_counts[protocol_name] += 1
        channel.metrics.protocol_scores[protocol_name].append(score)
        return result


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы в списке."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict] = []

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [
            process_channel(channel, session, channel_semaphore, proxy_config, global_proxy_semaphore)
            for channel in channels
        ]
        results = await asyncio.gather(*tasks)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка при обработке канала: {result}")
            elif result:
                proxies_all.extend(result)
    return proxies_all


# --- Функции для сохранения и сортировки результатов ---
def sort_proxies(proxies: List[Dict]) -> List[Dict]:
    """Сортирует список прокси по полноте конфигурации."""
    def config_completeness(proxy_dict):
        config_obj = proxy_dict['config_obj']
        return sum(1 for field_value in astuple(config_obj) if field_value is not None)
    return sorted(proxies, key=config_completeness, reverse=True)


def save_final_configs(proxies: List[Dict], output_file: str):
    """Сохраняет финальные конфигурации прокси в выходной файл, обеспечивая уникальность по IP и порту."""
    proxies_sorted = sort_proxies(proxies)
    profile_names = set()
    unique_proxies = defaultdict(set)  # Track unique proxies by protocol and (ip, port)
    unique_proxy_count = 0

    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies_sorted:
                config = proxy['config'].split('#')[0].strip()
                parsed = urlparse(config)
                ip_address = parsed.hostname
                port = parsed.port
                protocol = proxy['protocol']
                ip_port_tuple = (ip_address, port)

                if ip_port_tuple not in unique_proxies[protocol]:
                    unique_proxies[protocol].add(ip_port_tuple)
                    unique_proxy_count += 1

                    query = parse_qs(parsed.query)
                    profile_name = generate_custom_name(parsed, query)
                    base_name = profile_name
                    suffix = 1
                    while profile_name in profile_names:
                        profile_name = f"{base_name} ({suffix})"
                        suffix += 1
                    profile_names.add(profile_name)

                    final_line = f"{config}#{profile_name} - Score: {proxy['score']:.2f}\n"
                    f.write(final_line)
        logger.info(f"Финальные конфигурации сохранены в {output_file}. Уникальность прокси обеспечена.")
        logger.info(f"Всего уникальных прокси сохранено: {unique_proxy_count}")  # Лог количества уникальных прокси
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")


def update_and_save_weights(channels: List[ChannelConfig], loaded_weights: Dict):
    """Обновляет и сохраняет веса скоринга на основе статистики каналов."""
    total_success_ratio = sum(channel._calculate_success_ratio() for channel in channels) / len(channels) if channels else 0
    loaded_weights['CHANNEL_STABILITY'] = min(max(int(total_success_ratio * 100), 0), 100)

    protocol_counts = defaultdict(int)
    for channel in channels:
        for protocol, count in channel.metrics.protocol_counts.items():
            protocol_counts[protocol] += count

    total_configs = sum(protocol_counts.values())
    for protocol, count in protocol_counts.items():
        ratio = (count / total_configs) * 100 if total_configs > 0 else 0
        if protocol == "vless":
            loaded_weights['PROTOCOL_BASE'] = min(max(int(ratio * 5), 0), 100)

    all_response_times = [channel.metrics.avg_response_time for channel in channels if channel.metrics.avg_response_time > 0]
    if all_response_times:
        avg_response_time_all = sum(all_response_times) / len(all_response_times)
        loaded_weights['RESPONSE_TIME'] = min(max(int(-avg_response_time_all * 2), -50), 0)

    ScoringWeights.save_weights_to_json(loaded_weights)


def prepare_training_data(proxies: List[Dict]) -> List[Dict]:
    """Подготавливает данные для обучения модели калибровки весов."""
    training_data = []
    for proxy in proxies:
        config = proxy['config']
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        data = {
            'score': proxy['score'],
            'vless_security_tls': 1 if _get_value(query, 'security', 'none').lower() == 'tls' else 0,
            'vless_transport_ws': 1 if _get_value(query, 'type', 'tcp').lower() == 'ws' else 0,
            'vless_encryption_none': 1 if _get_value(query, 'encryption', 'none').lower() == 'none' else 0,
        }
        training_data.append(data)
    return training_data


def main():
    """Основная функция для запуска проверки прокси."""
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    loaded_weights = ScoringWeights.load_weights_from_json()
    statistics_logged = False  # Флаг для предотвращения дублирования статистики

    async def runner():
        nonlocal statistics_logged  # Разрешить изменение флага

        loop = asyncio.get_running_loop()
        proxy_config.set_event_loop(loop)
        proxies = await process_all_channels(channels, proxy_config)

        training_data = prepare_training_data(proxies)
        features = [
            'vless_security_tls',
            'vless_transport_ws',
            'vless_encryption_none',
        ]
        ScoringWeights.calibrate_weights(training_data, features)

        save_final_configs(proxies, proxy_config.OUTPUT_FILE)
        update_and_save_weights(channels, loaded_weights)
        proxy_config.remove_failed_channels_from_file()

        if not statistics_logged:  # Проверка, не была ли статистика уже залогирована
            total_channels = len(channels)
            enabled_channels = sum(1 for channel in channels)
            disabled_channels = total_channels - enabled_channels
            total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)
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
            logger.info(f"Всего успешных загрузок: {total_successes}")
            logger.info(f"Всего неудачных загрузок: {total_fails}")
            logger.info("Статистика по протоколам:")
            for protocol, count in protocol_stats.items():
                logger.info(f"  {protocol}: {count}")
            logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")
            statistics_logged = True  # Устанавливаем флаг после логирования статистики

    asyncio.run(runner())


if __name__ == "__main__":
    main()
