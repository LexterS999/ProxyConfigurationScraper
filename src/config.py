import asyncio
import aiodns
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
import base64
import aiohttp

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict

import numpy as np
from sklearn.linear_model import LinearRegression

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_checker.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Логирование в файл (WARNING и выше)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Логирование в консоль (INFO и выше)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)

# Цветной вывод в консоль
class LogColors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def colored_log(level, message: str, *args, **kwargs):
    """Выводит цветное сообщение в консоль и стандартный лог."""
    color = LogColors.RESET
    if level == logging.INFO:
        color = LogColors.GREEN
    elif level == logging.WARNING:
        color = LogColors.YELLOW
    elif level == logging.ERROR:
        color = LogColors.RED
    elif level == logging.CRITICAL:
        color = LogColors.BOLD + LogColors.RED
    logger.log(level, f"{color}{message}{LogColors.RESET}", *args, **kwargs)

# Константы
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120
MAX_CONCURRENT_PROXIES_GLOBAL = 120
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
MAX_RETRIES = 1
RETRY_DELAY_BASE = 1
SS_VALID_METHODS = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'none'] # Константа для валидных методов SS

PROTOCOL_TIMEOUTS = {
    "vless": 4.0,
    "trojan": 4.0,
    "ss": 4.0,
    "ssconf": 4.0,
    "tuic": 4.0,
    "hy2": 4.0,
    "default": 4.0
}

# --- Исключения ---
class InvalidURLError(ValueError):
    pass

class UnsupportedProtocolError(ValueError):
    pass

class InvalidParameterError(ValueError):
    pass

class ConfigParseError(ValueError):
    pass

# --- Enum для имен профилей ---
class ProfileName(Enum):
    VLESS_FORMAT = "🌌 VLESS - {transport} - {security}"
    VLESS_WS_TLS = "🚀 VLESS - WS - TLS"
    SS_FORMAT = "🎭 SS - {method}"
    SS_CHACHA20_IETF_POLY1305 = "🛡️ SS - CHACHA20-IETF-POLY1305"
    SSCONF_FORMAT = "📦 SSCONF"
    TROJAN_FORMAT = "🗡️ Trojan - {transport} - {security}"
    TROJAN_WS_TLS = "⚔️ Trojan - WS - TLS"
    TUIC_FORMAT = "🐢 TUIC - {transport} - {security} - {congestion_control}"
    TUIC_WS_TLS_BBR = "🐇 TUIC - WS - TLS - BBR"
    HY2_FORMAT = "💧 HY2 - {transport} - {security}"
    HY2_UDP_TLS = "🐳 HY2 - UDP - TLS"

# --- Data classes для конфигураций ---
@dataclass(frozen=True)
class VlessConfig:
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
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers"))
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['none'])[0].lower()
        if security not in ('tls', 'none'):
            raise InvalidParameterError(f"Недопустимое значение security: {security}")

        transport = query.get('type', ['tcp'])[0].lower()
        if transport not in ('tcp', 'ws'):
            raise InvalidParameterError(f"Недопустимое значение type: {transport}")

        encryption = query.get('encryption', ['none'])[0].lower()
        if encryption not in ('none', 'auto', 'aes-128-gcm', 'chacha20-poly1305'):
            raise InvalidParameterError(f"Недопустимое значение encryption: {encryption}")

        try:
            port = int(parsed_url.port)
        except (ValueError, TypeError):
            raise InvalidParameterError(f"Недопустимый порт: {parsed_url.port}")

        return cls(
            uuid=parsed_url.username,
            address=address,
            port=port,
            security=security,
            transport=transport,
            encryption=encryption,
            sni=query.get('sni', [None])[0],
            alpn=alpn,
            path=query.get('path', [None])[0],
            early_data=query.get('earlyData', ['0'])[0] == '1', # Используем query.get
            utls=query.get('utls') or query.get('fp', ['none'])[0], # Используем query.get
            obfs=query.get('obfs',[None])[0],
            headers=headers,
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class SSConfig:
    method: str
    password: str
    address: str
    port: int
    plugin: Optional[str] = None
    obfs: Optional[str] = None
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "SSConfig":
        address = await resolve_address(parsed_url.hostname, resolver)
        method = parsed_url.username.lower() if parsed_url.username else 'none'
        if method not in SS_VALID_METHODS:
            raise InvalidParameterError(f"Недопустимый метод шифрования для ss://: {method}")
        try:
            port = int(parsed_url.port)
        except (ValueError, TypeError):
            raise InvalidParameterError(f"Недопустимый порт: {parsed_url.port}")
        return cls(
            method=method,
            password=parsed_url.password,
            address=address,
            port=port,
            plugin=query.get('plugin', [None])[0],
            obfs=query.get('obfs',[None])[0],
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class SSConfConfig:
    server: str
    server_port: int
    local_address: str
    local_port: int
    password: str
    timeout: int
    method: str
    protocol: str
    obfs: str
    protocol_param: Optional[str] = None
    obfs_param: Optional[str] = None
    remarks: Optional[str] = None
    group: Optional[str] = None
    udp_over_tcp: bool = False
    first_seen: Optional[datetime] = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(astuple(self))

    @classmethod
    async def from_url(cls, config_string: str, resolver: aiodns.DNSResolver) -> "SSConfConfig":
        try:
            config_b64 = config_string.split("ssconf://")[1]
            config_json_str = base64.urlsafe_b64decode(config_b64 + '=' * (4 - len(config_b64) % 4)).decode('utf-8')
            config_json = json.loads(config_json_str)
            config_json = {k.lower(): v for k, v in config_json.items()}

            server_port_str = config_json.get('server_port')
            timeout_str = config_json.get('timeout')
            local_port_str = config_json.get('local_port', '1080') # default value as string to handle potential errors
            udp_over_tcp_str = config_json.get('udp_over_tcp', False) # default value as bool to handle potential errors

            try:
                server_port = int(server_port_str) if server_port_str is not None else None
            except (ValueError, TypeError):
                raise ConfigParseError(f"Ошибка разбора ssconf: Неверный server_port: {server_port_str}")
            try:
                timeout = int(timeout_str) if timeout_str is not None else None
            except (ValueError, TypeError):
                raise ConfigParseError(f"Ошибка разбора ssconf: Неверный timeout: {timeout_str}")
            try:
                local_port = int(local_port_str)
            except (ValueError, TypeError):
                raise ConfigParseError(f"Ошибка разбора ssconf: Неверный local_port: {local_port_str}")
            try:
                udp_over_tcp = bool(udp_over_tcp_str)
            except (ValueError, TypeError):
                raise ConfigParseError(f"Ошибка разбора ssconf: Неверный udp_over_tcp: {udp_over_tcp_str}")


            return cls(
                server=config_json.get('server'),
                server_port=server_port,
                local_address=config_json.get('local_address', '127.0.0.1'),
                local_port=local_port,
                password=config_json.get('password'),
                timeout=timeout,
                method=config_json.get('method'),
                protocol=config_json.get('protocol', 'origin'),
                protocol_param=config_json.get('protocol_param'),
                obfs=config_json.get('obfs', 'plain'),
                obfs_param=config_json.get('obfs_param'),
                remarks=config_json.get('remarks'),
                group=config_json.get('group'),
                udp_over_tcp=udp_over_tcp,
                first_seen=datetime.now()
            )
        except (json.JSONDecodeError, KeyError, ValueError, ConfigParseError) as e:
            raise ConfigParseError(f"Ошибка разбора ssconf: {e}")

@dataclass(frozen=True)
class TrojanConfig:
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
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers"))
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in ('tls', 'none'):
            raise InvalidParameterError(f"Недопустимое значение security: {security}")

        transport = query.get('type', ['tcp'])[0].lower() # default 'tcp' as in original code
        if transport not in ('tcp', 'ws'):
            raise InvalidParameterError(f"Недопустимое значение type: {transport}")

        try:
            port = int(parsed_url.port)
        except (ValueError, TypeError):
            raise InvalidParameterError(f"Недопустимый порт: {parsed_url.port}")

        return cls(
            password=parsed_url.password,
            address=address,
            port=port,
            security=security,
            transport=transport,
            sni=query.get('sni', [None])[0],
            alpn=alpn,
            early_data=query.get('earlyData', ['0'])[0] == '1', # Используем query.get
            utls=query.get('utls') or query.get('fp', ['none'])[0], # Используем query.get
            obfs=query.get('obfs',[None])[0],
            headers=headers,
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class TuicConfig:
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
        address = await resolve_address(parsed_url.hostname, resolver)
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in ('tls', 'none'):
            raise InvalidParameterError(f"Недопустимое значение security: {security}")

        transport = query.get('type', ['udp'])[0].lower() # default 'udp' as in original code
        if transport not in ('udp', 'ws'):
            raise InvalidParameterError(f"Недопустимое значение type: {transport}")

        congestion_control = query.get('congestion', ['bbr'])[0].lower() # default 'bbr' as in original code
        if congestion_control not in ('bbr', 'cubic', 'new-reno'):
            raise InvalidParameterError(f"Недопустимое значение congestion: {congestion_control}")

        try:
            port = int(parsed_url.port)
        except (ValueError, TypeError):
            raise InvalidParameterError(f"Недопустимый порт: {parsed_url.port}")


        return cls(
            uuid=parsed_url.username,
            address=address,
            port=port,
            security=security,
            transport=transport,
            congestion_control=congestion_control,
            sni=query.get('sni', [None])[0],
            alpn=alpn,
            early_data=query.get('earlyData', ['0'])[0] == '1', # Используем query.get
            udp_relay_mode=query.get('udp_relay_mode', ['quic'])[0].lower(), # Используем query.get, default 'quic'
            zero_rtt_handshake=query.get('zero_rtt_handshake', ['0'])[0] == '1', # Используем query.get, default '0'
            utls=query.get('utls') or query.get('fp', ['none'])[0], # Используем query.get
            password=parsed_url.password,
            obfs=query.get('obfs',[None])[0],
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class Hy2Config:
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
        address = await resolve_address(parsed_url.hostname, resolver)
        hop_interval_str = query.get('hopInterval', [None])[0] # Используем query.get
        hop_interval = None
        if hop_interval_str is not None:
            try:
                hop_interval = int(hop_interval_str)
            except ValueError:
                raise InvalidParameterError(f"Неверное значение hopInterval: {hop_interval_str}")

        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in ('tls', 'none'):
            raise InvalidParameterError(f"Недопустимое значение security: {security}")

        transport = query.get('type', ['udp'])[0].lower() # default 'udp' as in original code
        if transport not in ('udp', 'tcp'):
            raise InvalidParameterError(f"Недопустимое значение type: {transport}")

        try:
            port = int(parsed_url.port)
        except (ValueError, TypeError):
            raise InvalidParameterError(f"Недопустимый порт: {parsed_url.port}")


        return cls(
            address=address,
            port=port,
            security=security,
            transport=transport,
            sni=query.get('sni', [None])[0],
            alpn=alpn,
            early_data=query.get('earlyData', ['0'])[0] == '1', # Используем query.get
            pmtud=query.get('pmtud', ['0'])[0] == '1', # Используем query.get, default '0'
            hop_interval=hop_interval,
            password=parsed_url.password,
            utls=query.get('utls') or query.get('fp', ['none'])[0], # Используем query.get
            obfs=query.get('obfs',[None])[0],
            first_seen=datetime.now()
        )

# --- Data classes для метрик и конфигураций каналов ---
@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    unique_configs: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    protocol_scores: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    first_seen: Optional[datetime] = None

class ChannelConfig:
    RESPONSE_TIME_DECAY = 0.7
    VALID_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
    REPEATED_CHARS_THRESHOLD = 100 # Константа для порога повторяющихся символов

    def __init__(self, url: str):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.check_count = 0
        self.metrics.first_seen = datetime.now()

    def _validate_url(self, url: str) -> str:
        if not isinstance(url, str):
            raise InvalidURLError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        if not url:
            raise InvalidURLError("URL не может быть пустым.")
        if re.search(r'(.)\1{' + str(self.REPEATED_CHARS_THRESHOLD) + r',}', url): # Используем константу
            raise InvalidURLError("URL содержит слишком много повторяющихся символов.")
        parsed = urlsplit(url)
        if parsed.scheme not in ["http", "https"] and parsed.scheme not in [p.replace('://', '') for p in self.VALID_PROTOCOLS]:
            expected_protocols = ", ".join(["http", "https"] + self.VALID_PROTOCOLS)
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError( # Улучшенное сообщение об ошибке
                f"Неподдерживаемый протокол URL: '{received_protocol_prefix}...'. Ожидаются протоколы: {expected_protocols}."
            )
        return url

class ProxyConfig:
    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.resolver = None
        self.failed_channels = []
        self.processed_configs = set()
        self.SOURCE_URLS = self._load_source_urls()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.ALL_URLS_FILE = ALL_URLS_FILE

    def _load_source_urls(self) -> List[ChannelConfig]:
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
        except UnicodeDecodeError as e: # Более гранулярная обработка исключений
            logger.error(f"Ошибка декодирования при чтении {ALL_URLS_FILE}: {e}")
        except Exception as e: # Общая ошибка
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")
        unique_configs = self._remove_duplicate_urls(initial_urls)
        if not unique_configs:
            self.save_empty_config_file()
            logger.error("Не найдено валидных источников. Создан пустой файл конфигурации.")
        return unique_configs

    async def _normalize_url(self, url: str) -> str:
        if not url:
            raise InvalidURLError("URL не может быть пустым для нормализации.")
        url = url.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            raise InvalidURLError(f"Отсутствует схема в URL: '{url}'. Ожидается схема прокси.")
        if not parsed.netloc:
            raise InvalidURLError(f"Отсутствует netloc (домен или IP) в URL: '{url}'.")
        if not all(c in (string.ascii_letters + string.digits + '.-:') for c in parsed.netloc):
            raise InvalidURLError(f"Недопустимые символы в netloc URL: '{parsed.netloc}'")
        path = parsed.path.rstrip('/')
        return parsed._replace(scheme=parsed.scheme.lower(), path=path).geturl() # Приводим схему к нижнему регистру

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        seen_urls = set()
        unique_configs = []
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                logger.debug(f"Неверная конфигурация пропущена: {config}") # Debug level logging
                continue
            try:
                normalized_url = asyncio.run(self._normalize_url(config.url))
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
                    logger.debug(f"Добавлен уникальный URL: {normalized_url}") # Debug level logging for successful addition
                else:
                    logger.debug(f"Дубликат URL пропущен: {normalized_url}") # Debug level logging for duplicates
            except Exception:
                continue
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

    def set_event_loop(self, loop):
        self.resolver = aiodns.DNSResolver(loop=loop)

    def remove_failed_channels_from_file(self):
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
    PROTOCOL_BASE = 20
    CONFIG_LENGTH = 5
    AGE_PENALTY = -0.05
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
    SSCONF_SERVER_PORT = 5
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
        all_weights_loaded_successfully = True
        loaded_weights = {}
        try:
            if not os.path.exists(file_path):
                ScoringWeights._create_default_weights_file(file_path)
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                for name, value in weights_data.items():
                    if not isinstance(value, (int, float)):
                        raise ValueError(f"Invalid weight value (must be a number) for {name}: {value}")
                    loaded_weights[name] = value
            # Проверка наличия всех ключей из Enum в загруженных весах
            for member in ScoringWeights:
                if member.name not in loaded_weights:
                    logger.error(f"Файл весов не содержит значение для '{member.name}'. Используются значения по умолчанию.")
                    all_weights_loaded_successfully = False

        except FileNotFoundError as e: # Более информативные сообщения об ошибках
            logger.warning(f"Файл весов не найден: {file_path}. Используются значения по умолчанию. Ошибка: {e}")
            all_weights_loaded_successfully = False
        except json.JSONDecodeError as e:
            logger.warning(f"Ошибка разбора JSON в файле весов {file_path}. Используются значения по умолчанию. Ошибка: {e}")
            all_weights_loaded_successfully = False
        except ValueError as e:
            logger.warning(f"Ошибка валидации значений весов в {file_path}. Используются значения по умолчанию. Ошибка: {e}")
            all_weights_loaded_successfully = False
        except Exception as e:
            logger.critical(f"Критическая ошибка при загрузке весов из {file_path}: {e}. Используются значения по умолчанию.") # Critical error
            all_weights_loaded_successfully = False

        if not all_weights_loaded_successfully:
            loaded_weights = {member.name: member.value for member in ScoringWeights}
        return loaded_weights

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = {member.name: member.value for member in ScoringWeights}
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Создан файл весов по умолчанию: {file_path}")
            logger.debug(f"Содержимое файла весов по умолчанию: {default_weights}") # Debug logging of content
        except Exception as e:
            logger.error(f"Ошибка создания файла весов: {e}")

    @staticmethod
    def save_weights_to_json(weights: Dict[str, float], file_path: str = DEFAULT_SCORING_WEIGHTS_FILE):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(weights, f, indent=4)
            logger.info(f"Веса сохранены в {file_path}")
        except Exception as e:
            logger.error(f"Ошибка сохранения весов в {file_path}: {e}")

# --- Вспомогательные функции ---
def _get_value(query: Dict, key: str, default_value: Any = None) -> Any:
    return query.get(key, (default_value,))[0]

def _parse_headers(headers_str: Optional[str]) -> Optional[Dict[str, str]]:
    if not headers_str:
        return None
    try:
        headers = json.loads(headers_str)
        if not isinstance(headers, dict):
            raise ValueError("Headers must be a JSON object")
        return headers
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Неверный формат заголовков, ожидается JSON-объект: {headers_str} - {e}. Заголовки игнорируются.") # More informative message
        return None

def _parse_hop_interval(hop_interval_str: Optional[str]) -> Optional[int]:
    if hop_interval_str is None:
        return None
    try:
        return int(hop_interval_str)
    except ValueError:
        logger.warning(f"Неверное значение hopInterval, ожидается целое число, используется None: {hop_interval_str}") # More informative message
        return None

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> str:
    if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
        return hostname
    try:
        result = await resolver.query(hostname, 'A')
        resolved_address = result[0].host
        logger.debug(f"Hostname '{hostname}' успешно разрешен в IP-адрес: {resolved_address}") # Debug logging for success
        return resolved_address
    except aiodns.error.DNSError as e:
        logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}") # Warning for DNSError
        return hostname
    except Exception as e:
        logger.error(f"Неожиданная ошибка при резолвинге {hostname}: {e}") # Error for other exceptions
        return hostname

# --- Функции для расчета скоринга ---
def _calculate_vless_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    score = 0
    security = query.get('security', ['none'])[0].lower()
    score += loaded_weights.get("VLESS_SECURITY_TLS", ScoringWeights.VLESS_SECURITY_TLS.value) if security == 'tls' else loaded_weights.get("VLESS_SECURITY_NONE", ScoringWeights.VLESS_SECURITY_NONE.value)
    transport = query.get('type', ['tcp'])[0].lower()
    score += loaded_weights.get("VLESS_TRANSPORT_WS", ScoringWeights.VLESS_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("VLESS_TRANSPORT_TCP", ScoringWeights.VLESS_TRANSPORT_TCP.value)
    encryption = query.get('encryption', ['none'])[0].lower()
    encryption_scores = {
        'none': loaded_weights.get("VLESS_ENCRYPTION_NONE", ScoringWeights.VLESS_ENCRYPTION_NONE.value),
        'auto': loaded_weights.get("VLESS_ENCRYPTION_AUTO", ScoringWeights.VLESS_ENCRYPTION_AUTO.value),
        'aes-128-gcm': loaded_weights.get("VLESS_ENCRYPTION_AES_128_GCM", ScoringWeights.VLESS_ENCRYPTION_AES_128_GCM.value),
        'chacha20-poly1305': loaded_weights.get("VLESS_ENCRYPTION_CHACHA20_POLY1305", ScoringWeights.VLESS_ENCRYPTION_CHACHA20_POLY1305.value)
    }
    score += encryption_scores.get(encryption, 0)
    if parsed.username:
        score += loaded_weights.get("VLESS_UUID_PRESENT", ScoringWeights.VLESS_UUID_PRESENT.value)
    if query.get('earlyData', ['0'])[0] == '1':
        score += loaded_weights.get("VLESS_EARLY_DATA", ScoringWeights.VLESS_EARLY_DATA.value)
    if query.get('sni'):
        score += loaded_weights.get("VLESS_SNI_PRESENT", ScoringWeights.VLESS_SNI_PRESENT.value)
    if query.get('alpn'):
        score += loaded_weights.get("VLESS_ALPN_PRESENT", ScoringWeights.VLESS_ALPN_PRESENT.value)
    if query.get('path'):
        score += loaded_weights.get("VLESS_PATH_PRESENT", ScoringWeights.VLESS_PATH_PRESENT.value)
    return score

def _calculate_ss_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
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
    plugin = query.get('plugin', ['none'])[0].lower()
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
    score = 0
    score += loaded_weights.get("SSCONF_SERVER_PORT", ScoringWeights.SSCONF_SERVER_PORT.value) if config_obj.server_port in [80, 443, 8080, 8443] else 0
    method_scores = {
        'chacha20-ietf-poly1305': loaded_weights.get("SSCONF_METHOD_CHACHA20_IETF_POLY1305", ScoringWeights.SSCONF_METHOD_CHACHA20_IETF_POLY1305.value),
        'aes-256-gcm': loaded_weights.get("SSCONF_METHOD_AES_256_GCM", ScoringWeights.SSCONF_METHOD_AES_256_GCM.value),
        'aes-128-gcm': loaded_weights.get("SSCONF_METHOD_AES_128_GCM", ScoringWeights.SSCONF_METHOD_AES_128_GCM.value),
        'none': loaded_weights.get("SSCONF_METHOD_NONE", ScoringWeights.SSCONF_METHOD_NONE.value)
    }
    score += method_scores.get(config_obj.method, 0)
    score += min(loaded_weights.get("SSCONF_PASSWORD_LENGTH", ScoringWeights.SSCONF_PASSWORD_LENGTH.value),
                 len(config_obj.password or '') / 16 * loaded_weights.get("SSCONF_PASSWORD_LENGTH", ScoringWeights.SSCONF_PASSWORD_LENGTH.value)) if config_obj.password else 0
    protocol_scores = {
        'origin': loaded_weights.get("SSCONF_PROTOCOL_ORIGIN", ScoringWeights.SSCONF_PROTOCOL_ORIGIN.value),
        'auth_sha1_v4': loaded_weights.get("SSCONF_PROTOCOL_AUTH_SHA1_V4", ScoringWeights.SSCONF_PROTOCOL_AUTH_SHA1_V4.value),
        'auth_aes128_cfb': loaded_weights.get("SSCONF_PROTOCOL_AUTH_AES128_CFB", ScoringWeights.SSCONF_PROTOCOL_AUTH_AES128_CFB.value),
    }
    score += protocol_scores.get(config_obj.protocol, loaded_weights.get("SSCONF_PROTOCOL_ORIGIN", ScoringWeights.SSCONF_PROTOCOL_ORIGIN.value))
    obfs_scores = {
        'plain': loaded_weights.get("SSCONF_OBFS_PLAIN", ScoringWeights.SSCONF_OBFS_PLAIN.value),
        'tls': loaded_weights.get("SSCONF_OBFS_TLS", ScoringWeights.SSCONF_OBFS_TLS.value),
        'http': loaded_weights.get("SSCONF_OBFS_HTTP", ScoringWeights.SSCONF_OBFS_HTTP.value),
        'websocket': loaded_weights.get("SSCONF_OBFS_WEBSOCKET", ScoringWeights.SSCONF_OBFS_WEBSOCKET.value),
    }
    score += obfs_scores.get(config_obj.obfs, loaded_weights.get("SSCONF_OBFS_PLAIN", ScoringWeights.SSCONF_OBFS_PLAIN.value))
    if config_obj.udp_over_tcp:
        score += loaded_weights.get("SSCONF_UDP_OVER_TCP", ScoringWeights.SSCONF_UDP_OVER_TCP.value)
    return score

def _calculate_trojan_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    score = 0
    security = query.get('security', ['tls'])[0].lower()
    score += loaded_weights.get("TROJAN_SECURITY_TLS", ScoringWeights.TROJAN_SECURITY_TLS.value) if security == 'tls' else 0
    transport = query.get('type', ['tcp'])[0].lower()
    score += loaded_weights.get("TROJAN_TRANSPORT_WS", ScoringWeights.TROJAN_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TROJAN_TRANSPORT_TCP", ScoringWeights.TROJAN_TRANSPORT_TCP.value)
    score += min(loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("TROJAN_PASSWORD_LENGTH", ScoringWeights.TROJAN_PASSWORD_LENGTH.value)) if parsed.password else 0
    if query.get('sni'):
        score += loaded_weights.get("TROJAN_SNI_PRESENT", ScoringWeights.TROJAN_SNI_PRESENT.value)
    if query.get('alpn'):
        score += loaded_weights.get("TROJAN_ALPN_PRESENT", ScoringWeights.TROJAN_ALPN_PRESENT.value)
    if query.get('earlyData', ['0'])[0] == '1':
        score += loaded_weights.get("TROJAN_EARLY_DATA", ScoringWeights.TROJAN_EARLY_DATA.value)
    return score

def _calculate_tuic_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    score = 0
    security = query.get('security', ['tls'])[0].lower()
    score += loaded_weights.get("TUIC_SECURITY_TLS", ScoringWeights.TUIC_SECURITY_TLS.value) if security == 'tls' else 0
    transport = query.get('type', ['udp'])[0].lower()
    score += loaded_weights.get("TUIC_TRANSPORT_WS", ScoringWeights.TUIC_TRANSPORT_WS.value) if transport == 'ws' else loaded_weights.get("TUIC_TRANSPORT_UDP", ScoringWeights.TUIC_TRANSPORT_UDP.value)
    congestion_control = query.get('congestion', ['bbr'])[0].lower()
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
    if query.get('sni'):
        score += loaded_weights.get("TUIC_SNI_PRESENT", ScoringWeights.TUIC_SNI_PRESENT.value)
    if query.get('alpn'):
        score += loaded_weights.get("TUIC_ALPN_PRESENT", ScoringWeights.TUIC_ALPN_PRESENT.value)
    if query.get('earlyData', ['0'])[0] == '1':
        score += loaded_weights.get("TUIC_EARLY_DATA", ScoringWeights.TUIC_EARLY_DATA.value)
    if query.get('udp_relay_mode', ['quic'])[0].lower() == 'quic':
        score += loaded_weights.get("TUIC_UDP_RELAY_MODE", ScoringWeights.TUIC_UDP_RELAY_MODE.value)
    if query.get('zero_rtt_handshake', ['0'])[0] == '1':
        score += loaded_weights.get("TUIC_ZERO_RTT_HANDSHAKE", ScoringWeights.TUIC_ZERO_RTT_HANDSHAKE.value)
    return score

def _calculate_hy2_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    score = 0
    security = query.get('security', ['tls'])[0].lower()
    score += loaded_weights.get("HY2_SECURITY_TLS", ScoringWeights.HY2_SECURITY_TLS.value) if security == 'tls' else 0
    transport = query.get('type', ['udp'])[0].lower()
    score += loaded_weights.get("HY2_TRANSPORT_UDP", ScoringWeights.HY2_TRANSPORT_UDP.value) if transport == 'udp' else loaded_weights.get("HY2_TRANSPORT_TCP", ScoringWeights.HY2_TRANSPORT_TCP.value)
    score += min(loaded_weights.get("HY2_PASSWORD_LENGTH", ScoringWeights.HY2_PASSWORD_LENGTH.value),
                 len(parsed.password or '') / 16 * loaded_weights.get("HY2_PASSWORD_LENGTH", ScoringWeights.HY2_PASSWORD_LENGTH.value)) if parsed.password else 0
    if query.get('sni'):
        score += loaded_weights.get("HY2_SNI_PRESENT", ScoringWeights.HY2_SNI_PRESENT.value)
    if query.get('alpn'):
        score += loaded_weights.get("HY2_ALPN_PRESENT", ScoringWeights.HY2_ALPN_PRESENT.value)
    if query.get('earlyData', ['0'])[0] == '1':
        score += loaded_weights.get("HY2_EARLY_DATA", ScoringWeights.HY2_EARLY_DATA.value)
    if query.get('pmtud', ['0'])[0] == '1':
        score += loaded_weights.get("HY2_PMTUD_ENABLED", ScoringWeights.HY2_PMTUD_ENABLED.value)
    hop_interval = query.get('hopInterval', [None])[0]
    if hop_interval:
        try:
            score += int(hop_interval) * loaded_weights.get("HY2_HOP_INTERVAL", ScoringWeights.HY2_HOP_INTERVAL.value)
        except ValueError:
            pass
    return score

def _calculate_common_score(parsed: urlparse, query: Dict, loaded_weights: Dict) -> float:
    score = 0
    port_scores = {
        443: loaded_weights.get("COMMON_PORT_443", ScoringWeights.COMMON_PORT_443.value),
        80: loaded_weights.get("COMMON_PORT_80", ScoringWeights.COMMON_PORT_80.value)
    }
    score += port_scores.get(parsed.port, loaded_weights.get("COMMON_PORT_OTHER", ScoringWeights.COMMON_PORT_OTHER.value))
    utls = query.get('utls') or query.get('fp', ['none'])[0]
    utls = utls.lower()
    utls_scores = {
        'chrome': loaded_weights.get("COMMON_UTLS_CHROME", ScoringWeights.COMMON_UTLS_CHROME.value),
        'firefox': loaded_weights.get("COMMON_UTLS_FIREFOX", ScoringWeights.COMMON_UTLS_FIREFOX.value),
        'randomized': loaded_weights.get("COMMON_UTLS_RANDOMIZED", ScoringWeights.COMMON_UTLS_RANDOMIZED.value)
    }
    score += utls_scores.get(utls, loaded_weights.get("COMMON_UTLS_OTHER", ScoringWeights.COMMON_UTLS_OTHER.value))
    if query.get('sni') and '.cdn.' in query.get('sni', [''])[0]:
        score += loaded_weights.get("COMMON_CDN", ScoringWeights.COMMON_CDN.value)
    if query.get('obfs'):
        score += loaded_weights.get("COMMON_OBFS", ScoringWeights.COMMON_OBFS.value)
    if query.get('headers'):
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

async def compute_profile_score(config: str, loaded_weights: Dict = None, first_seen: Optional[datetime] = None) -> float:
    if loaded_weights is None:
        loaded_weights = ScoringWeights.load_weights_from_json()
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0
    if protocol == "ssconf://":
        try:
            config_obj = await SSConfConfig.from_url(config, None)
            score = _calculate_ssconf_score(config_obj, loaded_weights)
        except ConfigParseError as e:
            logger.error(f"Ошибка парсинга ssconf: {e}")
            raise ConfigParseError(f"Ошибка парсинга ssconf при вычислении score: {e}") # Проброс исключения
    else:
        try:
            parsed = urlparse(config)
            query = parse_qs(parsed.query)
        except Exception as e:
            logger.error(f"Ошибка парсинга URL {config}: {e}")
            raise InvalidURLError(f"Ошибка парсинга URL при вычислении score {config}: {e}") # Проброс исключения
        score = loaded_weights.get("PROTOCOL_BASE", ScoringWeights.PROTOCOL_BASE.value)
        score += _calculate_common_score(parsed, query, loaded_weights)
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
        score += protocol_calculators.get(protocol, lambda *args: 0)(parsed, query, loaded_weights)
    max_possible_score = sum(weight for weight in loaded_weights.values())
    normalized_score = (score / max_possible_score) * 100 if max_possible_score > 0 else 0.0
    return round(normalized_score, 2)

def _generate_profile_name_suffix(profile_names: Set[str], base_name: str) -> str:
    """Генерирует уникальное имя профиля с суффиксом, если имя уже существует."""
    suffix = 1
    profile_name = base_name
    while profile_name in profile_names:
        profile_name = f"{base_name} ({suffix})"
        suffix += 1
    return profile_name

def generate_custom_name(parsed: urlparse, query: Dict) -> str:
    """Генерирует кастомное имя профиля на основе URL."""
    scheme = parsed.scheme
    if scheme == "vless":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["none"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.VLESS_WS_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return "🌌 VLESS - " + " - ".join(filter(None, [transport_str, security_str]))
    elif scheme == "ss":
        method = quote_plus(parsed.username.upper() if parsed.username else "UNKNOWN")
        if method == "CHACHA20-IETF-POLY1305":
            return ProfileName.SS_CHACHA20_IETF_POLY1305.value
        return ProfileName.SS_FORMAT.value.format(method=method)
    elif scheme == "ssconf":
        return ProfileName.SSCONF_FORMAT.value
    elif scheme == "trojan":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.TROJAN_WS_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return "🗡️ Trojan - " + " - ".join(filter(None, [transport_str, security_str]))
    elif scheme == "tuic":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        congestion_control = query.get("congestion", ["bbr"])[0].upper()
        if transport_type == "WS" and security_type == "TLS" and congestion_control == "BBR":
            return ProfileName.TUIC_WS_TLS_BBR.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return "🐢 TUIC - " + " - ".join(filter(None, [transport_str, security_str, congestion_control]))
    elif scheme == "hy2":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "UDP" and security_type == "TLS":
            return ProfileName.HY2_UDP_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return "💧 HY2 - " + " - ".join(filter(None, [transport_str, security_str]))
    return f"⚠️ Неизвестный протокол: {scheme}. Проверьте URL или добавьте поддержку протокола." # Improved unknown protocol message

@functools.lru_cache(maxsize=1024) # Ограничение размера кэша lru_cache
def is_valid_ipv4(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

@functools.lru_cache(maxsize=1024) # Ограничение размера кэша lru_cache
def is_valid_ipv6(hostname: str) -> bool:
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_proxy_url(url: str) -> bool:
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    if url.startswith("ssconf://"):
        return url.startswith("ssconf://") and len(url) > len("ssconf://")
    try:
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
            # Уточненная логика проверки hostname для ss://
            if not parsed.hostname and not parsed.netloc.startswith('@'): # Проверка netloc для ss://
                return False
            if parsed.username:
                if parsed.username.lower() not in SS_VALID_METHODS:
                    logger.debug(f"Недопустимый метод шифрования для ss://: {parsed.username}")
                    return False
        if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)):
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

async def parse_config(config_string: str, resolver: aiodns.DNSResolver) -> Optional[object]:
    protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
    if protocol == "ssconf://":
        try:
            return await SSConfConfig.from_url(config_string, resolver)
        except ConfigParseError as e:
            logger.error(f"Ошибка парсинга ssconf конфигурации: {config_string} - {e}")
            raise ConfigParseError(f"Ошибка парсинга ssconf конфигурации: {config_string} - {e}") # Проброс исключения
    else:
        try:
            parsed = urlparse(config_string)
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
            raise # Проброс исключения
        except Exception as e:
            logger.exception(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
            raise # Проброс исключения

async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig, loaded_weights: Dict,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            return None
        # is_reachable = True # Удален вводящий в заблуждение код
        # if not is_reachable:
        #     logger.debug(f"❌ Прокси {line} не прошла проверку.")
        #     return None
        # else:
        logger.debug(f"✅ Прокси {line} считается доступной.")
        try:
            score = await compute_profile_score(
                line,
                loaded_weights=loaded_weights,
                first_seen=config_obj.first_seen
            )
        except (InvalidURLError, ConfigParseError) as e: # Обработка исключений compute_profile_score
            logger.error(f"Ошибка при вычислении score для {line}: {e}")
            return None

        result = {
            "config": line,
            "protocol": config_obj.__class__.__name__.replace("Config", "").lower(),
            "score": score,
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[result["protocol"]] += 1
        channel.metrics.protocol_scores[result["protocol"]].append(score)
        return result

async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы в списке с улучшенным логированием и обработкой ошибок."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict] = []

    async with aiohttp.ClientSession() as session:
        session_timeout = aiohttp.ClientTimeout(total=15)
        for channel in channels:
            # Логируем начало обработки канала
            colored_log(logging.INFO, f"🚀 Начало обработки канала: {channel.url}")
            proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
            proxy_tasks = []
            loaded_weights = ScoringWeights.load_weights_from_json()
            lines = []

            try:
                async with session.get(channel.url, timeout=session_timeout) as response:
                    if response.status == 200:
                        try:
                            # Исправляем UnicodeDecodeError с помощью errors='ignore'
                            text = await response.text(encoding='utf-8', errors='ignore')
                            lines = text.splitlines()
                        except UnicodeDecodeError as e:
                            colored_log(logging.WARNING, f"⚠️ Ошибка декодирования для {channel.url}: {e}. Пропуск.")
                            continue
                    elif response.status in (403, 404):
                        logger.debug(f"ℹ️ Канал {channel.url} вернул статус {response.status}. Пропускаем.") # Debug logging for 403/404
                        continue
                    else:
                        colored_log(logging.ERROR, f"❌ Ошибка при получении {channel.url}, статус: {response.status}")
                        continue
            except aiohttp.ClientError as e:
                colored_log(logging.ERROR, f"❌ Ошибка при получении {channel.url}: {e}")
                continue
            except asyncio.TimeoutError:
                colored_log(logging.ERROR, f"⌛ Таймаут при получении {channel.url}")
                continue

            for line in lines:
                line = line.strip()
                if len(line) < 1 or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line):
                    continue
                task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                                loaded_weights, proxy_semaphore, global_proxy_semaphore))
                proxy_tasks.append(task)
            results = await asyncio.gather(*proxy_tasks)
            valid_results = [result for result in results if result]
            for result in valid_results:
                proxies_all.append(result)
            channel.metrics.valid_configs = len(valid_results)
            # Логируем завершение обработки канала с количеством конфигураций
            colored_log(logging.INFO, f"✅ Завершена обработка канала: {channel.url}. Найдено конфигураций: {len(valid_results)}")

    return proxies_all

def sort_proxies(proxies: List[Dict]) -> List[Dict]:
    def config_completeness(proxy_dict):
        config_obj = proxy_dict['config_obj']
        return sum(1 for field_value in astuple(config_obj) if field_value is not None)
    return sorted(proxies, key=config_completeness, reverse=True)

def save_final_configs(proxies: List[Dict], output_file: str):
    proxies_sorted = sort_proxies(proxies)
    profile_names = set()
    unique_proxies = defaultdict(set)
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
                    base_name = generate_custom_name(parsed, query)
                    profile_name = _generate_profile_name_suffix(profile_names, base_name) # Refactored profile name generation
                    profile_names.add(profile_name)
                    final_line = f"{config}#{profile_name} - Score: {proxy['score']:.2f}\n"
                    f.write(final_line)
        colored_log(logging.INFO, f"✅ Финальные конфигурации сохранены в {output_file}. Уникальность прокси обеспечена.")
        colored_log(logging.INFO, f"✨ Всего уникальных прокси сохранено: {unique_proxy_count}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")

def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    loaded_weights = ScoringWeights.load_weights_from_json()
    statistics_logged = False

    async def runner():
        nonlocal statistics_logged
        loop = asyncio.get_running_loop()
        proxy_config.set_event_loop(loop)
        colored_log(logging.INFO, "🚀 Начало проверки прокси...")
        proxies = await process_all_channels(channels, proxy_config)
        save_final_configs(proxies, proxy_config.OUTPUT_FILE)
        proxy_config.remove_failed_channels_from_file()
        if not statistics_logged:
            total_channels = len(channels)
            enabled_channels = sum(1 for channel in channels)
            disabled_channels = total_channels - enabled_channels
            total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)
            protocol_stats = defaultdict(int)
            for channel in channels:
                for protocol, count in channel.metrics.protocol_counts.items():
                    protocol_stats[protocol] += count
            colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ПРОВЕРКИ ПРОКСИ ====================")
            colored_log(logging.INFO, f"🔄 Всего файлов-каналов обработано: {total_channels}")
            colored_log(logging.INFO, f"✅ Включено файлов-каналов: {enabled_channels}")
            colored_log(logging.INFO, f"❌ Отключено файлов-каналов: {disabled_channels}")
            colored_log(logging.INFO, f"✨ Всего найдено валидных конфигураций: {total_valid_configs}")
            colored_log(logging.INFO, "\n breakdown by protocol:")
            if protocol_stats:
                for protocol, count in protocol_stats.items():
                    colored_log(logging.INFO, f"   - {protocol}: {count} configs")
            else:
                colored_log(logging.INFO, "   No protocol statistics available.")
            colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
            statistics_logged = True
            colored_log(logging.INFO, "✅ Проверка прокси завершена.")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
