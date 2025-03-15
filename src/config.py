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
import colorlog

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable, Awaitable
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_checker.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Логируем все уровни для обработки фильтрами

# Логирование в файл (WARNING и выше)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Логирование в консоль (настраиваемый уровень и выше)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = colorlog.ColoredFormatter(
    '%(log_color)s[%(levelname)-8s]%(reset)s %(message_log_color)s%(message)s%(reset)s',
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'bold_red',
    },
    secondary_log_colors={
        'message': {
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red'
        }
    }
)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)

def colored_log(level: int, message: str, *args, **kwargs):
    """Улучшенная функция цветного логирования с поддержкой форматирования."""
    logger.log(level, message, *args, **kwargs)

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

PROTOCOL_TIMEOUTS = {
    "vless": 4.0,
    "trojan": 4.0,
    "ss": 4.0,
    "ssconf": 4.0,
    "tuic": 4.0,
    "hy2": 4.0,
    "default": 4.0
}

RESPONSE_TIME_DECAY = 0.7
VALID_PROTOCOLS = ALLOWED_PROTOCOLS

ConfigType = Union["VlessConfig", "SSConfig", "SSConfConfig", "TrojanConfig", "TuicConfig", "Hy2Config"]
ParserFunction = Callable[[str, aiodns.DNSResolver], Awaitable[Optional[ConfigType]]]
CONFIG_PARSERS: Dict[str, ParserFunction] = {}

# --- Декоратор для регистрации парсеров ---
def register_parser(protocol: str):
    """Декоратор для регистрации функций парсинга конфигураций."""
    def decorator(func: ParserFunction) -> ParserFunction:
        CONFIG_PARSERS[protocol] = func
        return func
    return decorator

# --- Исключения ---
class InvalidURLError(ValueError):
    """Исключение для невалидных URL."""
    pass

class UnsupportedProtocolError(ValueError):
    """Исключение для неподдерживаемых протоколов."""
    pass

class InvalidParameterError(ValueError):
    """Исключение для невалидных параметров конфигурации."""
    pass

class ConfigParseError(ValueError):
    """Исключение для ошибок парсинга конфигурации."""
    pass

class InvalidHeadersFormatError(ValueError):
    """Исключение для неверного формата заголовков."""
    pass

class InvalidHopIntervalError(ValueError):
    """Исключение для неверного значения hopInterval."""
    pass

class ChannelFetchError(Exception):
    """Исключение для ошибок при получении контента канала."""
    pass

class ChannelDecodeError(Exception):
    """Исключение для ошибок декодирования контента канала."""
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
    """Датакласс для хранения конфигурации VLESS."""
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
    async def from_url(cls, parsed_url: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> "VlessConfig":
        """Создает объект VlessConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers", [None])[0])
        alpn_str = _get_value(query, 'alpn', '')
        alpn = tuple(sorted(alpn_str.split(','))) if alpn_str else None

        security = _get_value(query, 'security', 'none').lower()
        if security not in ['tls', 'none']:
            raise InvalidParameterError(f"Недопустимое значение security: {security}. Допустимые значения: tls, none.")

        transport = _get_value(query, 'type', 'tcp').lower()
        if transport not in ['tcp', 'ws']:
            raise InvalidParameterError(f"Недопустимое значение type: {transport}. Допустимые значения: tcp, ws.")

        encryption = _get_value(query, 'encryption', 'none').lower()
        if encryption not in ['none', 'auto', 'aes-128-gcm', 'chacha20-poly1305']:
            raise InvalidParameterError(f"Недопустимое значение encryption: {encryption}. Допустимые значения: none, auto, aes-128-gcm, chacha20-poly1305.")

        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
            security=security,
            transport=transport,
            encryption=encryption,
            sni=_get_value(query, 'sni', None),
            alpn=alpn,
            path=_get_value(query, 'path', None),
            early_data=_get_value(query, 'earlyData') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs=_get_value(query, 'obfs', None),
            headers=headers,
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class SSConfig:
    """Датакласс для хранения конфигурации Shadowsocks (SS)."""
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
    async def from_url(cls, parsed_url: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> "SSConfig":
        """Создает объект SSConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        method = parsed_url.username.lower() if parsed_url.username else 'none'
        valid_methods = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'none']
        if method not in valid_methods:
            raise InvalidParameterError(f"Недопустимый метод шифрования для ss://: {method}. Допустимые методы: {', '.join(valid_methods)}.")
        return cls(
            method=method,
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
            plugin=_get_value(query, 'plugin', None),
            obfs=_get_value(query, 'obfs', None),
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class SSConfConfig:
    """Датакласс для хранения конфигурации SSConf."""
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
        """Создает объект SSConfConfig из строки конфигурации."""
        try:
            config_b64 = config_string.split("ssconf://")[1]
            config_json_str = base64.urlsafe_b64decode(config_b64 + '=' * (4 - len(config_b64) % 4)).decode('utf-8')
            config_json = json.loads(config_json_str)
            config_json = {k.lower(): v for k, v in config_json.items()}
            return cls(
                server=config_json.get('server'),
                server_port=int(config_json.get('server_port')),
                local_address=config_json.get('local_address', '127.0.0.1'),
                local_port=int(config_json.get('local_port', 1080)),
                password=config_json.get('password'),
                timeout=int(config_json.get('timeout', 300)),
                method=config_json.get('method'),
                protocol=config_json.get('protocol', 'origin'),
                protocol_param=config_json.get('protocol_param'),
                obfs=config_json.get('obfs', 'plain'),
                obfs_param=config_json.get('obfs_param'),
                remarks=config_json.get('remarks'),
                group=config_json.get('group'),
                udp_over_tcp=bool(config_json.get('udp_over_tcp', False)),
                first_seen=datetime.now()
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ConfigParseError(f"Ошибка разбора ssconf: {e}")

@dataclass(frozen=True)
class TrojanConfig:
    """Датакласс для хранения конфигурации Trojan."""
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
    async def from_url(cls, parsed_url: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> "TrojanConfig":
        """Создает объект TrojanConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        headers = _parse_headers(query.get("headers", [None])[0])
        alpn_str = _get_value(query, 'alpn', '')
        alpn = tuple(sorted(alpn_str.split(','))) if alpn_str else None

        security = _get_value(query, 'security', 'tls').lower()
        if security not in ['tls']:
            raise InvalidParameterError(f"Недопустимое значение security: {security}. Допустимые значения: tls.")

        transport = _get_value(query, 'type', 'tcp').lower()
        if transport not in ['tcp', 'ws']:
            raise InvalidParameterError(f"Недопустимое значение type: {transport}. Допустимые значения: tcp, ws.")

        return cls(
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
            security=security,
            transport=transport,
            sni=_get_value(query, 'sni', None),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs=_get_value(query, 'obfs', None),
            headers=headers,
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class TuicConfig:
    """Датакласс для хранения конфигурации TUIC."""
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
    async def from_url(cls, parsed_url: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> "TuicConfig":
        """Создает объект TuicConfig из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        alpn_str = _get_value(query, 'alpn', '')
        alpn = tuple(sorted(alpn_str.split(','))) if alpn_str else None

        security = _get_value(query, 'security', 'tls').lower()
        if security not in ['tls']:
            raise InvalidParameterError(f"Недопустимое значение security: {security}. Допустимые значения: tls.")

        transport = _get_value(query, 'type', 'udp').lower()
        if transport not in ['udp', 'ws']:
            raise InvalidParameterError(f"Недопустимое значение type: {transport}. Допустимые значения: udp, ws.")

        congestion_control = _get_value(query, 'congestion', 'bbr').lower()
        valid_congestion_controls = ['bbr', 'cubic', 'new-reno']
        if congestion_control not in valid_congestion_controls:
            raise InvalidParameterError(f"Недопустимое значение congestion: {congestion_control}. Допустимые значения: {', '.join(valid_congestion_controls)}.")

        udp_relay_mode = _get_value(query, 'udp_relay_mode', 'quic').lower()
        if udp_relay_mode not in ['quic', 'none']:
            raise InvalidParameterError(f"Недопустимое значение udp_relay_mode: {udp_relay_mode}. Допустимые значения: quic, none.")


        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
            security=security,
            transport=transport,
            congestion_control=congestion_control,
            sni=_get_value(query, 'sni', None),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            udp_relay_mode=udp_relay_mode,
            zero_rtt_handshake=_get_value(query, 'zero_rtt_handshake') == '1',
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            password=parsed_url.password,
            obfs=_get_value(query, 'obfs', None),
            first_seen=datetime.now()
        )

@dataclass(frozen=True)
class Hy2Config:
    """Датакласс для хранения конфигурации HY2."""
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
    async def from_url(cls, parsed_url: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> "Hy2Config":
        """Создает объект Hy2Config из URL."""
        address = await resolve_address(parsed_url.hostname, resolver)
        hop_interval_str = _get_value(query, 'hopInterval')
        hop_interval = _parse_hop_interval(hop_interval_str)
        alpn_str = _get_value(query, 'alpn', '')
        alpn = tuple(sorted(alpn_str.split(','))) if alpn_str else None

        security = _get_value(query, 'security', 'tls').lower()
        if security not in ['tls']:
            raise InvalidParameterError(f"Недопустимое значение security: {security}. Допустимые значения: tls.")

        transport = _get_value(query, 'type', 'udp').lower()
        if transport not in ['udp', 'tcp']:
            raise InvalidParameterError(f"Недопустимое значение type: {transport}. Допустимые значения: udp, tcp.")


        return cls(
            address=address,
            port=parsed_url.port,
            security=security,
            transport=transport,
            sni=_get_value(query, 'sni', None),
            alpn=alpn,
            early_data=_get_value(query, 'earlyData') == '1',
            pmtud=_get_value(query, 'pmtud') == '1',
            hop_interval=hop_interval,
            password=parsed_url.password,
            utls=_get_value(query, 'utls') or _get_value(query, 'fp', 'none'),
            obfs=_get_value(query, 'obfs', None),
            first_seen=datetime.now()
        )

# --- Data classes для метрик и конфигураций каналов ---
@dataclass
class ChannelMetrics:
    """Датакласс для хранения метрик канала."""
    valid_configs: int = 0
    unique_configs: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    protocol_scores: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    first_seen: Optional[datetime] = None

class ChannelConfig:
    """Класс для представления конфигурации канала."""

    def __init__(self, url: str):
        """Инициализирует объект ChannelConfig."""
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.check_count = 0
        self.metrics.first_seen = datetime.now()
        self.enabled = True # Добавлено состояние канала (включен/выключен)

    def _validate_url(self, url: str) -> str:
        """Валидирует URL канала."""
        if not isinstance(url, str):
            raise InvalidURLError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        if not url:
            raise InvalidURLError("URL не может быть пустым.")
        if re.search(r'(.)\1{100,}', url):
            raise InvalidURLError("URL содержит слишком много повторяющихся символов (подозрение на спам).")
        parsed = urlsplit(url)
        if parsed.scheme not in ["http", "https"] and parsed.scheme not in [p.replace('://', '') for p in VALID_PROTOCOLS]:
            expected_protocols = ", ".join(["http", "https"] + VALID_PROTOCOLS)
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError(
                f"Неверный протокол URL. Ожидается: {expected_protocols}, получено: {received_protocol_prefix}..."
            )
        return url

    def enable(self):
        """Включает канал."""
        self.enabled = True

    def disable(self):
        """Выключает канал."""
        self.enabled = False

    def is_enabled(self) -> bool:
        """Проверяет, включен ли канал."""
        return self.enabled

    def mark_failed(self):
        """Помечает канал как failed (например, после нескольких неудачных попыток загрузки)."""
        self.enabled = False # Или другое состояние, в зависимости от логики обработки failed каналов

class ProxyConfig:
    """Класс для управления конфигурациями прокси."""
    OUTPUT_FILE = OUTPUT_CONFIG_FILE
    ALL_URLS_FILE = ALL_URLS_FILE

    def __init__(self, all_urls_file: str = ALL_URLS_FILE, output_config_file: str = OUTPUT_CONFIG_FILE):
        """Инициализирует объект ProxyConfig."""
        os.makedirs(os.path.dirname(output_config_file), exist_ok=True)
        self.resolver: Optional[aiodns.DNSResolver] = None
        self.failed_channels: List[str] = []
        self.processed_configs: Set[str] = set()
        self.ALL_URLS_FILE = all_urls_file
        self.OUTPUT_FILE = output_config_file
        self.SOURCE_URLS: List[ChannelConfig] = self._load_source_urls()

    def _load_source_urls(self) -> List[ChannelConfig]:
        """Загружает URL каналов из файла."""
        initial_urls: List[ChannelConfig] = []
        try:
            if not os.path.exists(self.ALL_URLS_FILE):
                logger.warning(f"Файл URL не найден: {self.ALL_URLS_FILE}. Создается пустой файл.")
                open(self.ALL_URLS_FILE, 'w', encoding='utf-8').close()
                return []

            with open(self.ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except (InvalidURLError, UnsupportedProtocolError) as e:
                            logger.warning(f"Неверный URL в {self.ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"Файл URL не найден: {self.ALL_URLS_FILE}. Создается пустой файл.")
            open(self.ALL_URLS_FILE, 'w', encoding='utf-8').close()
            return []
        except Exception as e:
            logger.error(f"Ошибка чтения {self.ALL_URLS_FILE}: {e}")
            return []

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
            raise InvalidURLError(f"Отсутствует схема в URL: '{url}'. Ожидается схема прокси.")
        if not parsed.netloc:
            raise InvalidURLError(f"Отсутствует netloc (домен или IP) в URL: '{url}'.")
        if not all(c in (string.ascii_letters + string.digits + '.-:') for c in parsed.netloc):
            raise InvalidURLError(f"Недопустимые символы в netloc URL: '{parsed.netloc}'")
        path = parsed.path.rstrip('/')
        return parsed._replace(path=path).geturl()

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """Удаляет дубликаты URL каналов."""
        seen_urls: Set[str] = set()
        unique_configs: List[ChannelConfig] = []
        loop = asyncio.get_event_loop()
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                logger.warning(f"Неверная конфигурация пропущена: {config}")
                continue
            try:
                normalized_url = loop.run_until_complete(self._normalize_url(config.url))
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
            except Exception:
                continue
        return unique_configs

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Возвращает список включенных каналов."""
        return [channel for channel in self.SOURCE_URLS if channel.is_enabled()]

    def save_empty_config_file(self) -> bool:
        """Сохраняет пустой файл конфигурации."""
        try:
            with open(self.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {e}")
            return False

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """Устанавливает event loop для DNS resolver."""
        self.resolver = aiodns.DNSResolver(loop=loop)

    def remove_failed_channels_from_file(self):
        """Удаляет нерабочие каналы из файла URL."""
        if not self.failed_channels:
            return
        try:
            with open(self.ALL_URLS_FILE, 'r', encoding='utf-8') as f_read:
                lines = f_read.readlines()
            updated_lines = [line for line in lines if line.strip() not in self.failed_channels]
            with open(self.ALL_URLS_FILE, 'w', encoding='utf-8') as f_write:
                f_write.writelines(updated_lines)
            colored_log(logging.INFO, f"Удалены нерабочие каналы из {self.ALL_URLS_FILE}: {', '.join(self.failed_channels)}")
            self.failed_channels = []
        except FileNotFoundError:
            logger.error(f"Файл не найден: {self.ALL_URLS_FILE}. Невозможно удалить нерабочие каналы.")
        except Exception as e:
            logger.error(f"Ошибка при удалении нерабочих каналов из {self.ALL_URLS_FILE}: {e}")

    def filter_channels(self, protocol_filter: Optional[List[str]] = None) -> List[ChannelConfig]:
        """Фильтрует каналы по протоколам."""
        if not protocol_filter:
            return self.SOURCE_URLS
        filtered_channels: List[ChannelConfig] = []
        for channel in self.SOURCE_URLS:
            if any(channel.url.startswith(proto) for proto in protocol_filter):
                filtered_channels.append(channel)
        return filtered_channels

# --- Enum для весов скоринга ---
class ScoringWeights(Enum):
    """Enum для весов скоринга прокси."""
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
        """Загружает веса скоринга из JSON файла."""
        all_weights_loaded_successfully = True
        loaded_weights: Dict[str, Any] = {}
        try:
            if not os.path.exists(file_path):
                ScoringWeights._create_default_weights_file(file_path)
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)
                ScoringWeights._validate_weights_data(weights_data)
                for name, value in weights_data.items():
                    if not isinstance(value, (int, float)):
                        raise ValueError(f"Invalid weight value (must be a number) for {name}: {value}")
                    loaded_weights[name] = value
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Ошибка загрузки весов из {file_path}: {e}. Используются значения по умолчанию.")
            all_weights_loaded_successfully = False
        if not all_weights_loaded_successfully:
            loaded_weights = {member.name: member.value for member in ScoringWeights.__members__.values()}
        return loaded_weights

    @staticmethod
    def _validate_weights_data(weights_data: Dict[str, Any]) -> None:
        """Валидирует структуру данных весов скоринга."""
        if not isinstance(weights_data, dict):
            raise ValueError("Данные весов должны быть JSON объектом (словарем).")
        for name in ScoringWeights.__members__.keys():
            if name not in weights_data:
                raise ValueError(f"Отсутствует вес для параметра: {name} в файле конфигурации весов.")

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        """Создает файл весов по умолчанию."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = {member.name: member.value for member in ScoringWeights}
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            colored_log(logging.INFO, f"Создан файл весов по умолчанию: {file_path}")
        except Exception as e:
            logger.error(f"Ошибка создания файла весов: {e}")

    @staticmethod
    def save_weights_to_json(weights: Dict[str, float], file_path: str = DEFAULT_SCORING_WEIGHTS_FILE):
        """Сохраняет веса скоринга в JSON файл."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(weights, f, indent=4)
            colored_log(logging.INFO, f"Веса сохранены в {file_path}")
        except Exception as e:
            logger.error(f"Ошибка сохранения весов в {file_path}: {e}")

# --- Вспомогательные функции ---
def _get_value(query: Dict[str, List[str]], key: str, default_value: Any = None) -> Any:
    """Извлекает значение из query dict, возвращает default_value если ключ отсутствует."""
    if not isinstance(query, dict):
        raise TypeError(f"query должен быть dict, а не {type(query).__name__}")
    return query.get(key, [default_value])[0]

def _parse_headers(headers_str: Optional[str]) -> Optional[Dict[str, str]]:
    """Парсит строку заголовков JSON в словарь."""
    if not headers_str:
        return None
    try:
        headers = json.loads(headers_str)
        if not isinstance(headers, dict):
            raise InvalidHeadersFormatError("Заголовки должны быть JSON объектом (словарем).")
        return headers
    except json.JSONDecodeError as e:
        raise InvalidHeadersFormatError(f"Ошибка декодирования JSON заголовков: {e}")
    except InvalidHeadersFormatError as e:
        logger.warning(f"Неверный формат заголовков: {headers_str} - {e}. Заголовки игнорируются.")
        return None

def _parse_hop_interval(hop_interval_str: Optional[str]) -> Optional[int]:
    """Парсит строку hopInterval в целое число."""
    if hop_interval_str is None:
        return None
    try:
        return int(hop_interval_str)
    except ValueError:
        raise InvalidHopIntervalError(f"Неверное значение hopInterval: {hop_interval_str}. Ожидается целое число.")
    except InvalidHopIntervalError as e:
        logger.warning(f"{e} Используется None.")
        return None

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> str:
    """Разрешает hostname в IP-адрес, возвращает hostname если не удалось."""
    if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
        return hostname
    try:
        result = await asyncio.wait_for(resolver.query(hostname, 'A'), timeout=5.0)
        return result[0].host
    except aiodns.error.DNSError as e:
        logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}")
        return hostname
    except socket.gaierror as e:
        logger.warning(f"Ошибка при резолвинге hostname {hostname}: {e}")
        return hostname
    except asyncio.TimeoutError:
        logger.warning(f"Таймаут при резолвинге hostname: {hostname}")
        return hostname
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при резолвинге {hostname}: {e}")
        return hostname

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
    if not _is_valid_protocol(url, ALLOWED_PROTOCOLS):
        logger.debug(f"URL не начинается с допустимого протокола: {url}")
        return False

    if url.startswith("ssconf://"):
        return _is_valid_ssconf_url(url)
    else:
        return _is_valid_generic_proxy_url(url)

def _is_valid_protocol(url: str, allowed_protocols: List[str]) -> bool:
    """Проверяет, начинается ли URL с одного из допустимых протоколов."""
    return any(url.startswith(protocol) for protocol in allowed_protocols)

def _is_valid_ssconf_url(url: str) -> bool:
    """Проверяет валидность ssconf:// URL."""
    return url.startswith("ssconf://") and len(url) > len("ssconf://")

def _is_valid_generic_proxy_url(url: str) -> bool:
    """Проверяет валидность URL для протоколов vless, ss, trojan, tuic, hy2."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme

        if scheme in ('vless', 'trojan', 'tuic'):
            if not _is_valid_profile_id(parsed):
                logger.debug(f"Невалидный UUID/ID в URL: {url}")
                return False

        if scheme != "ss":
            if not parsed.hostname or not parsed.port:
                logger.debug(f"Отсутствует hostname или port в URL: {url}")
                return False
        else:
            if not _is_valid_ss_netloc(parsed):
                logger.debug(f"Невалидный netloc для ss:// URL: {url}")
                return False
            if not _is_valid_ss_method(parsed):
                logger.debug(f"Недопустимый метод шифрования для ss:// URL: {url}")
                return False

        if not _is_valid_hostname(parsed.hostname):
            logger.debug(f"Невалидный hostname: {parsed.hostname} в URL: {url}")
            return False

        return True

    except ValueError:
        logger.debug(f"Ошибка парсинга URL: {url}")
        return False

def _is_valid_profile_id(parsed: urlparse) -> bool:
    """Проверяет валидность profile_id (UUID для vless, trojan, tuic)."""
    profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
    return not profile_id or is_valid_uuid(profile_id)

def _is_valid_ss_netloc(parsed: urlparse) -> bool:
    """Проверяет валидность netloc для ss:// URL."""
    return parsed.hostname or (parsed.username and "@" in parsed.netloc)

def _is_valid_ss_method(parsed: urlparse) -> bool:
    """Проверяет валидность метода шифрования для ss:// URL."""
    valid_methods = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm', 'none']
    return not parsed.username or parsed.username.lower() in valid_methods

def _is_valid_hostname(hostname: str) -> bool:
    """Проверяет валидность hostname (IPv4, IPv6 или доменное имя)."""
    return is_valid_ipv4(hostname) or is_valid_ipv6(hostname) or re.match(r"^[a-zA-Z0-9.-]+$", hostname) is not None

def is_valid_uuid(uuid_string: str) -> bool:
    """Проверяет, является ли строка валидным UUID v4."""
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        return False

@register_parser("vless://")
async def _parse_vless_config(parsed: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> Optional[VlessConfig]:
    """Парсит VLESS конфигурацию из URL."""
    return await VlessConfig.from_url(parsed, query, resolver)

@register_parser("ss://")
async def _parse_ss_config(parsed: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> Optional[SSConfig]:
    """Парсит Shadowsocks (SS) конфигурацию из URL."""
    return await SSConfig.from_url(parsed, query, resolver)

@register_parser("ssconf://")
async def _parse_ssconf_config(config_string: str, resolver: aiodns.DNSResolver) -> Optional[SSConfConfig]:
    """Парсит SSConf конфигурацию из строки."""
    return await SSConfConfig.from_url(config_string, resolver)

@register_parser("trojan://")
async def _parse_trojan_config(parsed: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> Optional[TrojanConfig]:
    """Парсит Trojan конфигурацию из URL."""
    return await TrojanConfig.from_url(parsed, query, resolver)

@register_parser("tuic://")
async def _parse_tuic_config(parsed: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> Optional[TuicConfig]:
    """Парсит TUIC конфигурацию из URL."""
    return await TuicConfig.from_url(parsed, query, resolver)

@register_parser("hy2://")
async def _parse_hy2_config(parsed: urlparse, query: Dict[str, List[str]], resolver: aiodns.DNSResolver) -> Optional[Hy2Config]:
    """Парсит HY2 конфигурацию из URL."""
    return await Hy2Config.from_url(parsed, query, resolver)

async def parse_config(config_string: str, resolver: aiodns.DNSResolver) -> Optional[ConfigType]:
    """Парсит строку конфигурации и возвращает объект конфигурации."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
    if not protocol:
        return None

    try:
        if protocol == "ssconf://":
            return await _parse_ssconf_config(config_string, resolver)
        else:
            parsed = urlparse(config_string)
            if not (is_valid_ipv4(parsed.hostname) or is_valid_ipv6(parsed.hostname)):
                return None
            query = parse_qs(parsed.query)
            parser_func = CONFIG_PARSERS.get(protocol)
            if parser_func:
                return await parser_func(parsed, query, resolver)
            return None
    except InvalidURLError as e:
        logger.error(f"Ошибка URL в конфигурации: {config_string} - {e}")
        return None
    except UnsupportedProtocolError as e:
        logger.error(f"Неподдерживаемый протокол в конфигурации: {config_string} - {e}")
        return None
    except ConfigParseError as e:
        logger.error(f"Ошибка парсинга конфигурации: {config_string} - {e}")
        return None
    except InvalidParameterError as e:
        logger.error(f"Неверный параметр в конфигурации: {config_string} - {e}")
        return None
    except Exception as e:
        logger.exception(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
        return None

async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig, loaded_weights: Dict[str, Any],
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    """Обрабатывает одну прокси-конфигурацию."""
    logger.debug(f"⏳ Начало обработки прокси: {line}")
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            logger.debug(f"❌ Не удалось распарсить конфигурацию: {line}")
            return None

        score = await compute_profile_score(
            config_obj=config_obj,
            loaded_weights=loaded_weights
        )
        result: Dict[str, Any] = {
            "config": line,
            "protocol": config_obj.__class__.__name__.replace("Config", "").lower(),
            "score": score,
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[result["protocol"]] += 1
        channel.metrics.protocol_scores[result["protocol"]].append(score)
        logger.debug(f"✅ Прокси {line} обработана, score: {score:.2f}")
        return result

async def _fetch_channel_content(channel: ChannelConfig, session: aiohttp.ClientSession, session_timeout: aiohttp.ClientTimeout) -> List[str]:
    """Получает контент канала по URL."""
    try:
        async with session.get(channel.url, timeout=session_timeout) as response:
            if response.status == 200:
                try:
                    text = await response.text(encoding='utf-8', errors='ignore')
                    return text.splitlines()
                except UnicodeDecodeError as e:
                    raise ChannelDecodeError(f"Ошибка декодирования: {e}")
            elif response.status in (403, 404):
                return []
            else:
                raise ChannelFetchError(f"Ошибка HTTP, статус: {response.status}")
    except aiohttp.ClientError as e:
        raise ChannelFetchError(f"Ошибка aiohttp: {e}")
    except asyncio.TimeoutError:
        raise ChannelFetchError("Таймаут")

async def _process_channel_lines(lines: List[str], channel: ChannelConfig, proxy_config: ProxyConfig,
                                     loaded_weights: Dict[str, Any], proxy_semaphore: asyncio.Semaphore,
                                     global_proxy_semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
    """Обрабатывает строки контента канала, извлекая и обрабатывая прокси."""
    proxy_tasks: List[asyncio.Task] = []
    for line in lines:
        line = line.strip()
        if not line or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line):
            continue
        task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                        loaded_weights, proxy_semaphore, global_proxy_semaphore))
        proxy_tasks.append(task)
    results = await asyncio.gather(*proxy_tasks)
    return [result for result in results if result]

async def process_all_channels(channels: List[ChannelConfig], proxy_config: ProxyConfig) -> List[Dict[str, Any]]:
    """Обрабатывает все каналы в списке."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict[str, Any]] = []

    async with aiohttp.ClientSession() as session:
        session_timeout = aiohttp.ClientTimeout(total=15)
        for channel in channels:
            colored_log(logging.INFO, f"🚀 Начало обработки канала: {channel.url}")
            proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
            loaded_weights = ScoringWeights.load_weights_from_json()

            try:
                lines = await _fetch_channel_content(channel, session, session_timeout)
                channel_proxies = await _process_channel_lines(lines, channel, proxy_config, loaded_weights, proxy_semaphore, global_proxy_semaphore)
                proxies_all.extend(channel_proxies)
                channel.metrics.valid_configs = len(channel_proxies)
                colored_log(logging.INFO, f"✅ Завершена обработка канала: {channel.url}. Найдено конфигураций: {len(channel_proxies)}")

            except ChannelFetchError as e:
                colored_log(logging.ERROR, f"❌ Ошибка при получении канала {channel.url}: {e}")
                proxy_config.failed_channels.append(channel.url)
            except ChannelDecodeError as e:
                colored_log(logging.WARNING, f"⚠️ Ошибка декодирования канала {channel.url}: {e}. Пропуск.")
            except Exception as e:
                colored_log(logging.ERROR, f"❌ Непредвиденная ошибка при обработке канала {channel.url}: {e}")

    return proxies_all

def sort_proxies(proxies: List[Dict[str, Any]], key_func: Optional[Callable[[Dict[str, Any]], Any]] = None, reverse: bool = True) -> List[Dict[str, Any]]:
    """Сортирует список прокси по заданному критерию."""
    if key_func is None:
        key_func = config_completeness
    return sorted(proxies, key=key_func, reverse=reverse)

def config_completeness(proxy_dict: Dict[str, Any]) -> int:
    """Критерий сортировки: полнота конфигурации."""
    config_obj = proxy_dict['config_obj']
    return sum(1 for field_value in astuple(config_obj) if field_value is not None)

def save_final_configs(proxies: List[Dict[str, Any]], output_file: str):
    """Сохраняет финальные конфигурации прокси в файл, обеспечивая уникальность."""
    proxies_sorted = sort_proxies(proxies)
    profile_names: Set[str] = set()
    unique_proxies: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
    unique_proxy_counts: Dict[str, int] = defaultdict(int)

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
                    unique_proxy_counts[protocol] += 1

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

        colored_log(logging.INFO, f"✅ Финальные конфигурации сохранены в {output_file}. Уникальность прокси обеспечена.")
        total_unique_proxies = sum(unique_proxy_counts.values())
        colored_log(logging.INFO, f"✨ Всего уникальных прокси сохранено: {total_unique_proxies}")
        if unique_proxy_counts:
            colored_log(logging.INFO, " breakdown by protocol:")
            for protocol, count in unique_proxy_counts.items():
                colored_log(logging.INFO, f"   - {protocol}: {count} configs")

    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")

def generate_custom_name(parsed: urlparse, query: Dict[str, List[str]]) -> str:
    """Генерирует кастомное имя профиля на основе параметров URL."""
    scheme = parsed.scheme.lower()
    if scheme == "vless":
        transport_type = query.get("type", ["tcp"])[0].upper()
        security_type = query.get("security", ["none"])[0].upper()
        if transport_type == "WS" and security_type == "TLS":
            return ProfileName.VLESS_WS_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return ProfileName.VLESS_FORMAT.value.format(transport=transport_str, security=security_str).strip(" - ")
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
        return ProfileName.TROJAN_FORMAT.value.format(transport=transport_str, security=security_str).strip(" - ")
    elif scheme == "tuic":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        congestion_control = query.get("congestion", ["bbr"])[0].upper()
        if transport_type == "WS" and security_type == "TLS" and congestion_control == "BBR":
            return ProfileName.TUIC_WS_TLS_BBR.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        congestion_control_str = congestion_control if congestion_control != "NONE" else ""
        return ProfileName.TUIC_FORMAT.value.format(transport=transport_str, security=security_str, congestion_control=congestion_control_str).strip(" - ")
    elif scheme == "hy2":
        transport_type = query.get("type", ["udp"])[0].upper()
        security_type = query.get("security", ["tls"])[0].upper()
        if transport_type == "UDP" and security_type == "TLS":
            return ProfileName.HY2_UDP_TLS.value
        security_str = "" if security_type == "NONE" else security_type
        transport_str = transport_type if transport_type != "NONE" else ""
        return ProfileName.HY2_FORMAT.value.format(transport=transport_str, security=security_str).strip(" - ")
    return f"⚠️ Unknown Protocol: {scheme}"

def _apply_weight(score: float, weight_name: str, loaded_weights: Dict[str, Any]) -> float:
    """Применяет вес к скору, возвращает обновленный скор."""
    return score + loaded_weights.get(weight_name, 0)

def _apply_password_length_weight(score: float, password: Optional[str], weight_name: str, loaded_weights: Dict[str, Any], factor: int = 16) -> float:
    """Применяет вес, зависящий от длины пароля."""
    if password:
        return score + min(loaded_weights.get(weight_name, 0),
                         len(password) / factor * loaded_weights.get(weight_name, 0))
    return score

def _calculate_common_protocol_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Общая логика скоринга для протоколов (без ssconf)."""
    score = 0.0
    score = _apply_weight(score, "COMMON_PORT_443" if parsed.port == 443 else ("COMMON_PORT_80" if parsed.port == 80 else "COMMON_PORT_OTHER"), loaded_weights)
    utls = _get_value(query, 'utls', None) or _get_value(query, 'fp', 'none')
    utls = utls.lower()
    score = _apply_weight(score, "COMMON_UTLS_CHROME" if utls == 'chrome' else ("COMMON_UTLS_FIREFOX" if utls == 'firefox' else ("COMMON_UTLS_RANDOMIZED" if utls == 'randomized' else "COMMON_UTLS_OTHER")), loaded_weights)
    if _get_value(query, 'sni') and '.cdn.' in _get_value(query, 'sni'):
        score = _apply_weight(score, "COMMON_CDN", loaded_weights)
    if _get_value(query, 'obfs'):
        score = _apply_weight(score, "COMMON_OBFS", loaded_weights)
    if _get_value(query, 'headers'):
        score = _apply_weight(score, "COMMON_HEADERS", loaded_weights)
    known_params_general = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls', 'earlyData', 'id', 'method',
        'plugin', 'congestion', 'udp_relay_mode', 'zero_rtt_handshake', 'pmtud', 'hopInterval',
        'bufferSize', 'tcpFastOpen', 'obfs', 'debug', 'comment'
    )
    for key, value in query.items():
        if key not in known_params_general:
            score = _apply_weight(score, "COMMON_HIDDEN_PARAM", loaded_weights)
            if value and value[0]:
                score = _apply_weight(score, "COMMON_RARE_PARAM", loaded_weights)
    return score

def _calculate_vless_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для VLESS конфигурации."""
    score = _calculate_common_protocol_score(parsed, query, loaded_weights)
    security = _get_value(query, 'security', 'none').lower()
    score = _apply_weight(score, "VLESS_SECURITY_TLS" if security == 'tls' else "VLESS_SECURITY_NONE", loaded_weights)
    transport = _get_value(query, 'type', 'tcp').lower()
    score = _apply_weight(score, "VLESS_TRANSPORT_WS" if transport == 'ws' else "VLESS_TRANSPORT_TCP", loaded_weights)
    encryption = _get_value(query, 'encryption', 'none').lower()
    encryption_weights = {
        'none': "VLESS_ENCRYPTION_NONE",
        'auto': "VLESS_ENCRYPTION_AUTO",
        'aes-128-gcm': "VLESS_ENCRYPTION_AES_128_GCM",
        'chacha20-poly1305': "VLESS_ENCRYPTION_CHACHA20_POLY1305"
    }
    score = _apply_weight(score, encryption_weights.get(encryption, ""), loaded_weights)
    if parsed.username:
        score = _apply_weight(score, "VLESS_UUID_PRESENT", loaded_weights)
    if _get_value(query, 'earlyData') == '1':
        score = _apply_weight(score, "VLESS_EARLY_DATA", loaded_weights)
    if _get_value(query, 'sni'):
        score = _apply_weight(score, "VLESS_SNI_PRESENT", loaded_weights)
    if _get_value(query, 'alpn'):
        score = _apply_weight(score, "VLESS_ALPN_PRESENT", loaded_weights)
    if _get_value(query, 'path'):
        score = _apply_weight(score, "VLESS_PATH_PRESENT", loaded_weights)
    return score

def _calculate_ss_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для SS конфигурации."""
    score = _calculate_common_protocol_score(parsed, query, loaded_weights)
    method = parsed.username.lower() if parsed.username else 'none'
    method_weights = {
        'chacha20-ietf-poly1305': "SS_METHOD_CHACHA20_IETF_POLY1305",
        'aes-256-gcm': "SS_METHOD_AES_256_GCM",
        'aes-128-gcm': "SS_METHOD_AES_128_GCM",
        'none': "SS_METHOD_NONE"
    }
    score = _apply_weight(score, method_weights.get(method, ""), loaded_weights)
    score = _apply_password_length_weight(score, parsed.password, "SS_PASSWORD_LENGTH", loaded_weights)
    plugin = _get_value(query, 'plugin', 'none').lower()
    plugin_weights = {
        'obfs-http': "SS_PLUGIN_OBFS_HTTP",
        'obfs-tls': "SS_PLUGIN_OBFS_TLS",
        'none': "SS_PLUGIN_NONE"
    }
    score = _apply_weight(score, plugin_weights.get(plugin, "SS_PLUGIN_NONE"), loaded_weights)
    return score

def _calculate_ssconf_score(config_obj: SSConfConfig, loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для SSConf конфигурации."""
    score = 0.0
    score = _apply_weight(score, "SSCONF_SERVER_PORT" if config_obj.server_port in [80, 443, 8080, 8443] else "", loaded_weights)
    method_weights = {
        'chacha20-ietf-poly1305': "SSCONF_METHOD_CHACHA20_IETF_POLY1305",
        'aes-256-gcm': "SSCONF_METHOD_AES_256_GCM",
        'aes-128-gcm': "SSCONF_METHOD_AES_128_GCM",
        'none': "SSCONF_METHOD_NONE"
    }
    score = _apply_weight(score, method_weights.get(config_obj.method, ""), loaded_weights)
    score = _apply_password_length_weight(score, config_obj.password, "SSCONF_PASSWORD_LENGTH", loaded_weights)
    protocol_weights = {
        'origin': "SSCONF_PROTOCOL_ORIGIN",
        'auth_sha1_v4': "SSCONF_PROTOCOL_AUTH_SHA1_V4",
        'auth_aes128_cfb': "SSCONF_PROTOCOL_AUTH_AES128_CFB",
    }
    score = _apply_weight(score, protocol_weights.get(config_obj.protocol, "SSCONF_PROTOCOL_ORIGIN"), loaded_weights)
    obfs_weights = {
        'plain': "SSCONF_OBFS_PLAIN",
        'tls': "SSCONF_OBFS_TLS",
        'http': "SSCONF_OBFS_HTTP",
        'websocket': "SSCONF_OBFS_WEBSOCKET",
    }
    score = _apply_weight(score, obfs_weights.get(config_obj.obfs, "SSCONF_OBFS_PLAIN"), loaded_weights)
    if config_obj.udp_over_tcp:
        score = _apply_weight(score, "SSCONF_UDP_OVER_TCP", loaded_weights)
    return score

def _calculate_trojan_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для Trojan конфигурации."""
    score = _calculate_common_protocol_score(parsed, query, loaded_weights)
    security = _get_value(query, 'security', 'none').lower()
    score = _apply_weight(score, "TROJAN_SECURITY_TLS" if security == 'tls' else "", loaded_weights)
    transport = _get_value(query, 'type', 'tcp').lower()
    score = _apply_weight(score, "TROJAN_TRANSPORT_WS" if transport == 'ws' else "TROJAN_TRANSPORT_TCP", loaded_weights)
    score = _apply_password_length_weight(score, parsed.password, "TROJAN_PASSWORD_LENGTH", loaded_weights)
    if _get_value(query, 'sni'):
        score = _apply_weight(score, "TROJAN_SNI_PRESENT", loaded_weights)
    if _get_value(query, 'alpn'):
        score = _apply_weight(score, "TROJAN_ALPN_PRESENT", loaded_weights)
    if _get_value(query, 'earlyData') == '1':
        score = _apply_weight(score, "TROJAN_EARLY_DATA", loaded_weights)
    return score

def _calculate_tuic_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для TUIC конфигурации."""
    score = _calculate_common_protocol_score(parsed, query, loaded_weights)
    security = _get_value(query, 'security', 'none').lower()
    score = _apply_weight(score, "TUIC_SECURITY_TLS" if security == 'tls' else "", loaded_weights)
    transport = _get_value(query, 'type', 'udp').lower()
    score = _apply_weight(score, "TUIC_TRANSPORT_WS" if transport == 'ws' else "TUIC_TRANSPORT_UDP", loaded_weights)
    congestion_control = _get_value(query, 'congestion', 'bbr').lower()
    congestion_weights = {
        'bbr': "TUIC_CONGESTION_CONTROL_BBR",
        'cubic': "TUIC_CONGESTION_CONTROL_CUBIC",
        'new-reno': "TUIC_CONGESTION_CONTROL_NEW_RENO"
    }
    score = _apply_weight(score, congestion_weights.get(congestion_control, ""), loaded_weights)
    if parsed.username:
        score = _apply_weight(score, "TUIC_UUID_PRESENT", loaded_weights)
    score = _apply_password_length_weight(score, parsed.password, "TUIC_PASSWORD_LENGTH", loaded_weights)
    if _get_value(query, 'sni'):
        score = _apply_weight(score, "TUIC_SNI_PRESENT", loaded_weights)
    if _get_value(query, 'alpn'):
        score = _apply_weight(score, "TUIC_ALPN_PRESENT", loaded_weights)
    if _get_value(query, 'earlyData') == '1':
        score = _apply_weight(score, "TUIC_EARLY_DATA", loaded_weights)
    if _get_value(query, 'udp_relay_mode', 'quic').lower() == 'quic':
        score = _apply_weight(score, "TUIC_UDP_RELAY_MODE", loaded_weights)
    if _get_value(query, 'zero_rtt_handshake') == '1':
        score = _apply_weight(score, "TUIC_ZERO_RTT_HANDSHAKE", loaded_weights)
    return score

def _calculate_hy2_score(parsed: urlparse, query: Dict[str, List[str]], loaded_weights: Dict[str, Any]) -> float:
    """Рассчитывает скор для HY2 конфигурации."""
    score = _calculate_common_protocol_score(parsed, query, loaded_weights)
    security = _get_value(query, 'security', 'none').lower()
    score = _apply_weight(score, "HY2_SECURITY_TLS" if security == 'tls' else "", loaded_weights)
    transport = _get_value(query, 'type', 'udp').lower()
    score = _apply_weight(score, "HY2_TRANSPORT_UDP" if transport == 'udp' else "HY2_TRANSPORT_TCP", loaded_weights)
    score = _apply_password_length_weight(score, parsed.password, "HY2_PASSWORD_LENGTH", loaded_weights)
    if _get_value(query, 'sni'):
        score = _apply_weight(score, "HY2_SNI_PRESENT", loaded_weights)
    if _get_value(query, 'alpn'):
        score = _apply_weight(score, "HY2_ALPN_PRESENT", loaded_weights)
    if _get_value(query, 'earlyData') == '1':
        score = _apply_weight(score, "HY2_EARLY_DATA", loaded_weights)
    if _get_value(query, 'pmtud') == '1':
        score = _apply_weight(score, "HY2_PMTUD_ENABLED", loaded_weights)
    hop_interval = _get_value(query, 'hopInterval', None)
    if hop_interval:
        try:
            score = _apply_weight(score, "HY2_HOP_INTERVAL", loaded_weights) * int(hop_interval)
        except ValueError:
            pass
    return score

async def compute_profile_score(config_obj: ConfigType, loaded_weights: Optional[Dict[str, Any]] = None) -> float:
    """Вычисляет общий скор профиля прокси."""
    if loaded_weights is None:
        loaded_weights = ScoringWeights.load_weights_from_json()

    config_str = ""
    if isinstance(config_obj, SSConfConfig):
        score = ScoringWeights.PROTOCOL_BASE.value
        score += _calculate_ssconf_score(config_obj, loaded_weights)
        config_str = f"ssconf://{config_obj.remarks}" # Example, adjust as needed
    else:
        config_str = "" #config_obj. #TODO: how to get config string from config object?
        parsed_url_unparsed = urlparse(config_str) #TODO: how to get config string from config object?
        parsed = urlparse(config_str) if config_str else parsed_url_unparsed
        query = parse_qs(parsed.query)
        protocol_name = parsed.scheme
        score = ScoringWeights.PROTOCOL_BASE.value
        score += _calculate_common_score(parsed, query, loaded_weights) # Assuming _calculate_common_score is defined somewhere, if not, consider removing or implementing it.
        score += min(ScoringWeights.CONFIG_LENGTH.value,
                     (200.0 / (len(config_str) + 1)) * ScoringWeights.CONFIG_LENGTH.value)
        if hasattr(config_obj, 'first_seen') and config_obj.first_seen:
            days_old = (datetime.now() - config_obj.first_seen).days
            score += days_old * ScoringWeights.AGE_PENALTY.value

        protocol_calculators: Dict[str, Callable[[urlparse, Dict[str, List[str]], Dict[str, Any]], float]] = {
            "vless": _calculate_vless_score,
            "ss": _calculate_ss_score,
            "trojan": _calculate_trojan_score,
            "tuic": _calculate_tuic_score,
            "hy2": _calculate_hy2_score,
        }
        if protocol_name and protocol_name in protocol_calculators:
            score += protocol_calculators[protocol_name](parsed, query, loaded_weights)

    max_possible_score = sum(weight.value for weight in ScoringWeights)
    normalized_score = (score / max_possible_score) * 100 if max_possible_score > 0 else 0.0
    return round(normalized_score, 2)

def main():
    """Основная функция запуска проверки прокси."""
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
            protocol_scores_stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'total': 0, 'count': 0})

            for channel in channels:
                for protocol, count in channel.metrics.protocol_counts.items():
                    protocol_stats[protocol] += count
                for protocol, scores in channel.metrics.protocol_scores.items():
                    for score in scores:
                        protocol_scores_stats[protocol]['min'] = min(protocol_scores_stats[protocol]['min'], score)
                        protocol_scores_stats[protocol]['max'] = max(protocol_scores_stats[protocol]['max'], score)
                        protocol_scores_stats[protocol]['total'] += score
                        protocol_scores_stats[protocol]['count'] += 1

            colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ПРОВЕРКИ ПРОКСИ ====================")
            colored_log(logging.INFO, f"🔄 Всего файлов-каналов обработано: {total_channels}")
            colored_log(logging.INFO, f"✅ Включено файлов-каналов: {enabled_channels}")
            colored_log(logging.INFO, f"❌ Отключено файлов-каналов: {disabled_channels}")
            colored_log(logging.INFO, f"✨ Всего найдено валидных конфигураций: {total_valid_configs}")
            colored_log(logging.INFO, "\n breakdown by protocol:")
            if protocol_stats:
                for protocol, count in protocol_stats.items():
                    colored_log(logging.INFO, f"   - {protocol}: {count} configs")
                    if protocol_scores_stats[protocol]['count'] > 0:
                        avg_score = protocol_scores_stats[protocol]['total'] / protocol_scores_stats[protocol]['count']
                        min_score = protocol_scores_stats[protocol]['min']
                        max_score = protocol_scores_stats[protocol]['max']
                        colored_log(logging.INFO, f"     - Scores: Avg={avg_score:.2f}, Min={min_score:.2f}, Max={max_score:.2f}")
            else:
                colored_log(logging.INFO, "   No protocol statistics available.")
            colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
            statistics_logged = True
            colored_log(logging.INFO, "✅ Проверка прокси завершена.")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
