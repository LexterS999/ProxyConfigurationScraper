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
import concurrent.futures

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
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json" # Убрать неиспользуемые константы
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120 # Увеличено для ускорения
MAX_CONCURRENT_PROXIES_GLOBAL = 240 # Глобальный лимит также увеличен
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
MAX_RETRIES = 1
RETRY_DELAY_BASE = 1
SS_VALID_METHODS = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'none'] # Константа для валидных методов SS
VALID_VLESS_TRANSPORTS = ['tcp', 'ws']
VALID_TROJAN_TRANSPORTS = ['tcp', 'ws']
VALID_TUIC_TRANSPORTS = ['udp', 'ws']
VALID_HY2_TRANSPORTS = ['udp', 'tcp']
VALID_SECURITY_TYPES = ['tls', 'none']
VALID_ENCRYPTION_TYPES_VLESS = ['none', 'auto', 'aes-128-gcm', 'chacha20-poly1305']
VALID_CONGESTION_CONTROL_TUIC = ['bbr', 'cubic', 'new-reno']
MAX_ZERO_RESULTS_COUNT = 4 # Новая константа для максимального количества нулевых результатов

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
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["VlessConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            logger.debug(f"Пропущен VLESS конфиг из-за не IPv4 адреса: {parsed_url.hostname}")
            return None
        headers = _parse_headers(query.get("headers"))
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['none'])[0].lower()
        if security not in VALID_SECURITY_TYPES:
            logger.debug(f"Недопустимое значение security: {security} для vless, пропуск конфигурации.")
            return None

        transport = query.get('type', ['tcp'])[0].lower()
        if transport not in VALID_VLESS_TRANSPORTS:
            logger.debug(f"Недопустимое значение type: {transport} для vless, пропуск конфигурации.")
            return None

        encryption = query.get('encryption', ['none'])[0].lower()
        if encryption not in VALID_ENCRYPTION_TYPES_VLESS:
            logger.debug(f"Недопустимое значение encryption: {encryption} для vless, пропуск конфигурации.")
            return None

        port_str = parsed_url.port
        if port_str is None:
            logger.debug(f"Отсутствует порт в URL для vless, пропуск конфигурации.")
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"Недопустимый порт: {port_str} для vless, пропуск конфигурации.")
            return None

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
        return None # Добавлено для явного возврата None в случае ошибок

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
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["SSConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            logger.debug(f"Пропущен SS конфиг из-за не IPv4 адреса: {parsed_url.hostname}")
            return None
        method = parsed_url.username.lower() if parsed_url.username else 'none'
        if method not in SS_VALID_METHODS:
            logger.debug(f"Недопустимый метод шифрования для ss://: {method}, пропуск конфигурации.")
            return None
        port_str = parsed_url.port
        if port_str is None:
            logger.debug(f"Отсутствует порт в URL для ss, пропуск конфигурации.")
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"Недопустимый порт: {port_str} для ss, пропуск конфигурации.")
            return None
        return cls(
            method=method,
            password=parsed_url.password,
            address=address,
            port=port,
            plugin=query.get('plugin', [None])[0],
            obfs=query.get('obfs',[None])[0],
            first_seen=datetime.now()
        )
        return None # Добавлено для явного возврата None в случае ошибок

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
    async def from_url(cls, config_string: str, resolver: aiodns.DNSResolver) -> Optional["SSConfConfig"]:
        try:
            config_b64 = config_string.split("ssconf://")[1]
            config_json_str = base64.urlsafe_b64decode(config_b64 + '=' * (4 - len(config_b64) % 4)).decode('utf-8')
            config_json = json.loads(config_json_str)
            config_json = {k.lower(): v for k, v in config_json.items()}

            server_host = config_json.get('server')
            server_address = await resolve_address(server_host, resolver)
            if server_address is None:
                logger.debug(f"Пропущен SSCONF конфиг из-за не IPv4 адреса: {server_host}")
                return None

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
                server=server_address, # Use resolved IPv4 address
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
            logger.debug(f"Ошибка разбора ssconf: {e}, пропуск конфигурации.") # Debug level
            return None
        return None # Добавлено для явного возврата None в случае ошибок

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
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["TrojanConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            logger.debug(f"Пропущен Trojan конфиг из-за не IPv4 адреса: {parsed_url.hostname}")
            return None
        headers = _parse_headers(query.get("headers"))
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in VALID_SECURITY_TYPES:
            logger.debug(f"Недопустимое значение security: {security} для trojan, пропуск конфигурации.")
            return None

        transport = query.get('type', ['tcp'])[0].lower() # default 'tcp' as in original code
        if transport not in VALID_TROJAN_TRANSPORTS:
            logger.debug(f"Недопустимое значение type: {transport} для trojan, пропуск конфигурации.")
            return None

        port_str = parsed_url.port
        if port_str is None:
            logger.debug(f"Отсутствует порт в URL для trojan, пропуск конфигурации.")
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"Недопустимый порт: {port_str} для trojan, пропуск конфигурации.")
            return None

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
        return None # Добавлено для явного возврата None в случае ошибок

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
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["TuicConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            logger.debug(f"Пропущен TUIC конфиг из-за не IPv4 адреса: {parsed_url.hostname}")
            return None
        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in VALID_SECURITY_TYPES:
            logger.debug(f"Недопустимое значение security: {security} для tuic, пропуск конфигурации.")
            return None

        transport = query.get('type', ['udp'])[0].lower() # default 'udp' as in original code
        if transport not in VALID_TUIC_TRANSPORTS:
            logger.debug(f"Недопустимое значение type: {transport} для tuic, пропуск конфигурации.")
            return None

        congestion_control = query.get('congestion', ['bbr'])[0].lower() # default 'bbr' as in original code
        if congestion_control not in VALID_CONGESTION_CONTROL_TUIC:
            logger.debug(f"Недопустимое значение congestion: {congestion_control} для tuic, пропуск конфигурации.")
            return None

        port_str = parsed_url.port
        if port_str is None:
            logger.debug(f"Отсутствует порт в URL для tuic, пропуск конфигурации.")
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"Недопустимый порт: {port_str} для tuic, пропуск конфигурации.")
            return None


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
        return None # Добавлено для явного возврата None в случае ошибок

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
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["Hy2Config"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            logger.debug(f"Пропущен HY2 конфиг из-за не IPv4 адреса: {parsed_url.hostname}")
            return None
        hop_interval_str = query.get('hopInterval', [None])[0] # Используем query.get
        hop_interval = None
        if hop_interval_str is not None:
            try:
                hop_interval = int(hop_interval_str)
            except ValueError:
                logger.debug(f"Неверное значение hopInterval: {hop_interval_str} для hy2, используется None.")
                hop_interval = None # Use None instead of raising error, as in original logic

        alpn_list = query.get('alpn', []) # Используем query.get и получаем список
        alpn = tuple(sorted(alpn_list)) if alpn_list else None

        security = query.get('security', ['tls'])[0].lower() # default 'tls' as in original code
        if security not in VALID_SECURITY_TYPES:
            logger.debug(f"Недопустимое значение security: {security} для hy2, пропуск конфигурации.")
            return None

        transport = query.get('type', ['udp'])[0].lower() # default 'udp' as in original code
        if transport not in VALID_HY2_TRANSPORTS:
            logger.debug(f"Недопустимое значение type: {transport} для hy2, пропуск конфигурации.")
            return None

        port_str = parsed_url.port
        if port_str is None:
            logger.debug(f"Отсутствует порт в URL для hy2, пропуск конфигурации.")
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"Недопустимый порт: {port_str} для hy2, пропуск конфигурации.")
            return None


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
        return None # Добавлено для явного возврата None в случае ошибок

# --- Data classes для метрик и конфигураций каналов ---
@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    unique_configs: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
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
        self.zero_results_count = 0 # Добавляем счетчик нулевых результатов

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
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True) # Исправлено: os.True -> True
        self.resolver = None
        self.failed_channels = []
        self.processed_configs = set()
        self.SOURCE_URLS = self._load_source_urls()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.ALL_URLS_FILE = ALL_URLS_FILE
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=32) # Пул потоков для CPU-bound задач

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


# --- Вспомогательные функции ---
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


async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    if is_valid_ipv4(hostname):
        return hostname # Return IPv4 directly if already valid
    if is_valid_ipv6(hostname): # Skip IPv6 addresses
        logger.debug(f"Пропущен hostname {hostname} так как это IPv6 адрес.")
        return None
    try:
        result = await resolver.query(hostname, 'A')
        resolved_address = result[0].host
        if is_valid_ipv4(resolved_address):
            logger.debug(f"Hostname '{hostname}' успешно разрешен в IPv4-адрес: {resolved_address}") # Debug logging for success
            return resolved_address
        else:
            logger.debug(f"Hostname '{hostname}' разрешен в не IPv4 адрес: {resolved_address}. Пропускаем.")
            return None
    except aiodns.error.DNSError as e:
        if e.args[0] == 4: # Domain name not found
            logger.debug(f"Не удалось разрешить hostname: {hostname} - {e}") # Debug level for "Domain name not found"
        elif e.args[0] == 8: # Misformatted domain name
            logger.debug(f"Не удалось разрешить hostname: {hostname} - {e} (Misformatted domain name)") # Debug level for "Misformatted domain name" - теперь DEBUG
        elif not is_valid_ipv4(hostname) and not is_valid_ipv6(hostname): # Only log warning if hostname is not already IP
            logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}") # Warning for other DNSError
        return None # Return None if DNS resolution fails
    except Exception as e:
        logger.error(f"Неожиданная ошибка при резолвинге {hostname}: {e}") # Error for other exceptions
        return None


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

@functools.lru_cache(maxsize=1024) # Ограничение размера кэша lru_cache # Убрать неиспользуемую функцию
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
        if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)): # Оставить только IPv4
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
            logger.debug(f"Ошибка парсинга ssconf конфигурации: {config_string} - {e}") # Debug level
            return None
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
        except (InvalidURLError, UnsupportedProtocolError) as e: # Removed InvalidParameterError and ConfigParseError from here
            logger.debug(f"Ошибка парсинга конфигурации: {config_string} - {e}") # Debug level
            return None
        except Exception as e:
            logger.exception(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
            return None

async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver) # Передаем executor
        if config_obj is None:
            return None

        logger.debug(f"✅ Прокси {line} считается доступной.")

        result = {
            "config": line,
            "protocol": config_obj.__class__.__name__.replace("Config", "").lower(),
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[result["protocol"]] += 1
        return result

async def process_channel(channel: ChannelConfig, proxy_config: "ProxyConfig", session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, global_proxy_semaphore: asyncio.Semaphore):
    """Обрабатывает один канал, скачивая и обрабатывая прокси."""
    async with channel_semaphore: # Semaphore на канал, чтобы ограничить количество параллельных каналов
        colored_log(logging.INFO, f"🚀 Начало обработки канала: {channel.url}")
        proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
        proxy_tasks = []
        lines = []
        session_timeout = aiohttp.ClientTimeout(total=15)

        try:
            async with session.get(channel.url, timeout=session_timeout) as response:
                if response.status == 200:
                    try:
                        text = await response.text(encoding='utf-8', errors='ignore')
                        lines = text.splitlines()
                    except UnicodeDecodeError as e:
                        colored_log(logging.WARNING, f"⚠️ Ошибка декодирования для {channel.url}: {e}. Пропуск.")
                        return [] # Возвращаем пустой список прокси для этого канала
                elif response.status in (403, 404):
                    logger.debug(f"ℹ️ Канал {channel.url} вернул статус {response.status}. Пропускаем.") # Debug logging for 403/404
                    return [] # Возвращаем пустой список прокси для этого канала
                else:
                    colored_log(logging.ERROR, f"❌ Ошибка при получении {channel.url}, статус: {response.status}")
                    return [] # Возвращаем пустой список прокси для этого канала
        except aiohttp.ClientError as e:
            colored_log(logging.ERROR, f"❌ Ошибка при получении {channel.url}: {e}")
            return [] # Возвращаем пустой список прокси для этого канала
        except asyncio.TimeoutError:
            colored_log(logging.ERROR, f"⌛ Таймаут при получении {channel.url}")
            return [] # Возвращаем пустой список прокси для этого канала

        for line in lines:
            line = line.strip()
            if len(line) < 1 or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line):
                continue
            task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                            proxy_semaphore, global_proxy_semaphore))
            proxy_tasks.append(task)

        results = await asyncio.gather(*proxy_tasks)
        valid_results = [result for result in results if result]
        channel.metrics.valid_configs = len(valid_results)

        if channel.metrics.valid_configs == 0: # Проверяем количество валидных конфигов
            channel.zero_results_count += 1 # Увеличиваем счетчик нулевых результатов
            colored_log(logging.WARNING, f"⚠️ Канал {channel.url} не вернул конфигураций. Нулевой результат {channel.zero_results_count}/{MAX_ZERO_RESULTS_COUNT}.")
            if channel.zero_results_count >= MAX_ZERO_RESULTS_COUNT: # Проверяем, достигнут ли предел
                proxy_config.failed_channels.append(channel.url) # Добавляем URL канала в список нерабочих
                colored_log(logging.CRITICAL, f"🔥 Канал {channel.url} удален из-за {MAX_ZERO_RESULTS_COUNT} последовательных нулевых результатов.")
        else:
            channel.zero_results_count = 0 # Сбрасываем счетчик, если есть валидные результаты
            # Логируем завершение обработки канала с количеством конфигураций
            colored_log(logging.INFO, f"✅ Завершена обработка канала: {channel.url}. Найдено конфигураций: {len(valid_results)}")
        return valid_results


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы в списке параллельно."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict] = []

    async with aiohttp.ClientSession() as session:
        channel_tasks = [
            asyncio.create_task(process_channel(channel, proxy_config, session, channel_semaphore, global_proxy_semaphore))
            for channel in channels
        ]
        channel_results = await asyncio.gather(*channel_tasks) # Запускаем задачи параллельно

        for channel_proxies in channel_results:
            proxies_all.extend(channel_proxies) # Собираем прокси со всех каналов

    return proxies_all


def save_final_configs(proxies: List[Dict], output_file: str, executor=None): # Executor для CPU-bound save_final_configs
    profile_names = set()
    unique_proxies = defaultdict(set)
    unique_proxy_count = 0
    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies:
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
                    profile_name = generate_custom_name(parsed, query) # Use base name directly
                    profile_names.add(profile_name)
                    final_line = f"{config}#{profile_name}\n" # Removed score from output
                    f.write(final_line)
        colored_log(logging.INFO, f"✅ Финальные конфигурации сохранены в {output_file}. Уникальность прокси обеспечена.")
        colored_log(logging.INFO, f"✨ Всего уникальных прокси сохранено: {unique_proxy_count}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")


def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    statistics_logged = False

    async def runner():
        nonlocal statistics_logged
        loop = asyncio.get_running_loop()
        proxy_config.set_event_loop(loop)
        colored_log(logging.INFO, "🚀 Начало проверки прокси...")
        proxies = await process_all_channels(channels, proxy_config)
        save_final_configs(proxies, proxy_config.OUTPUT_FILE, proxy_config.executor) # Передаем executor
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
        proxy_config.executor.shutdown(wait=True) # Очистка пула потоков

    asyncio.run(runner())

if __name__ == "__main__":
    main()
