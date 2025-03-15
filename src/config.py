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
import statistics  # For standard deviation

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict

import numpy as np
from sklearn.linear_model import LinearRegression
import aiohttp # Import aiohttp for making HTTP requests


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

# Дополнительно: функция для цветного вывода в консоль (опционально)
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

def colored_log(level, message):
    color = LogColors.RESET
    if level == logging.INFO:
        color = LogColors.GREEN
    elif level == logging.WARNING:
        color = LogColors.YELLOW
    elif level == logging.ERROR:
        color = LogColors.RED
    elif level == logging.CRITICAL:
        color = LogColors.BOLD + LogColors.RED

    logger.log(level, f"{color}{message}{LogColors.RESET}")


# Константы
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120
MAX_CONCURRENT_PROXIES_GLOBAL = 120
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
BAD_CHANNELS_FILE = "configs/bad_channels.txt" # Файл для сохранения URL не прошедших фильтрацию каналов
MAX_RETRIES = 1
RETRY_DELAY_BASE = 1

# Периоды для расчета метрик (в днях)
METRIC_PERIOD_SHORT = 1  # 1 день для краткосрочных метрик
METRIC_PERIOD_MEDIUM = 7 # 7 дней для среднесрочных метрик
METRIC_PERIOD_LONG = 30  # 30 дней для долгосрочных метрик

# Веса метрик для общего скора канала (настраиваемые)
CHANNEL_SCORE_WEIGHTS = {
    "load_success_rate": 0.30,
    "update_frequency_score": 0.20,
    "success_rate_stability_score": 0.15,
    "average_proxy_score": 0.15,
    "protocol_diversity_score": 0.10,
    "config_diversity_score": 0.05, # New metric
    "uniqueness_ratio": 0.05,
    "invalid_config_ratio_penalty": -0.20, # Штрафы
    "duplicate_config_ratio_penalty": -0.10,
    "spam_config_penalty": -0.50, # Сильный штраф за спам
    "spam_detected_penalty": -50.0 # Единоразовый штраф, если спам обнаружен в канале
}

# Пороговые значения для классификации каналов (настраиваемые)
CHANNEL_QUALITY_THRESHOLDS = {
    "excellent": 90,
    "good": 75,
    "medium": 50,
    "low": 25,
    "bad": 0,
}

# Минимальная категория качества канала для использования (настраиваемая)
MIN_CHANNEL_QUALITY_CATEGORY = "medium" # Каналы ниже этой категории будут игнорироваться

# Ключевые слова для обнаружения спама (настраиваемые)
SPAM_KEYWORDS = [
    "free proxy",
    "join channel",
    "join @channel",
    "join",
    "telegram channel",
    "get free",
    "daily proxy",
    "бесплатный прокси",
    "прокси бесплатно",
    "халява",
    "подпишись",
    "subscribe",
    "follow us",
    "vip proxy",
    "premium proxy",
    "best proxy",
    "fast proxy",
    "top proxy",
    "working proxy",
    "fresh proxy",
    "unlimited proxy",
    "gift proxy",
    "promo proxy",
]

# Таймауты для протоколов (в секундах) - **ДОБАВЛЕНО**
PROTOCOL_TIMEOUTS = {
    "vless": 3.0, # Reduced timeouts for faster processing
    "ss": 3.0,
    "trojan": 3.0,
    "tuic": 3.0,
    "hy2": 3.0,
    "ssconf": 3.0,
}
CHANNEL_LOAD_TIMEOUT = 10 # Timeout for loading channel URLs


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
class SSConfConfig:
    """Конфигурация Shadowsocks Conf прокси."""
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
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    protocol_scores: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    first_seen: Optional[datetime] = None

    # Метрики стабильности и надежности
    load_success_history: List[Tuple[datetime, bool]] = field(default_factory=list) # История успешности загрузок (время, успех)
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0

    # Метрики качества контента
    average_proxy_score: float = 0.0
    protocol_diversity_score: float = 0.0
    config_diversity_score: float = 0.0 # New metric
    uniqueness_ratio: float = 0.0

    # Точечные метрики (чистота и глубина)
    invalid_config_ratio: float = 0.0
    duplicate_config_ratio: float = 0.0
    config_completeness_score: float = 0.0 # Средняя полнота конфигураций
    spam_configs_count: int = 0 # Количество спам-конфигураций

    overall_quality_score: float = 0.0 # Общий скор качества канала
    quality_category: str = "Unknown"
    spam_detected: bool = False # Флаг обнаружения спама в канале


class ChannelConfig:
    """Конфигурация канала для проверки прокси."""
    RESPONSE_TIME_DECAY = 0.7
    VALID_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
    GLOBAL_CONFIG_HISTORY = set() # Глобальный набор для отслеживания уникальности конфигураций

    def __init__(self, url: str):
        """Инициализирует объект ChannelConfig."""
        self.url = self._validate_url(url) # Сохраняем URL внешнего источника, а не файла
        self.metrics = ChannelMetrics()
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
        if parsed.scheme not in ['http', 'https']: # Разрешаем http и https для внешних ссылок
            expected_protocols = 'http, https'
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError(
                f"Неверный протокол URL. Ожидается: {expected_protocols}, получено: {received_protocol_prefix}..."
            )
        return url

    def update_load_success_history(self, success: bool):
        """Обновляет историю успешности загрузок."""
        self.metrics.load_success_history.append((datetime.now(), success))
        # Ограничение истории, например, до METRIC_PERIOD_LONG дней
        cutoff_time = datetime.now() - timedelta(days=METRIC_PERIOD_LONG)
        self.metrics.load_success_history = [(t, s) for t, s in self.metrics.load_success_history if t > cutoff_time]

    def calculate_load_success_rate(self, period_days=METRIC_PERIOD_MEDIUM):
        """Вычисляет процент успешных загрузок за период."""
        start_time = datetime.now() - timedelta(days=period_days)
        recent_history = [(t, s) for t, s in self.metrics.load_success_history if t >= start_time]
        if not recent_history:
            return 0.0  # Если нет данных за период, считаем 0%
        successful_loads = sum(1 for _, success in recent_history if success)
        total_loads = len(recent_history)
        return (successful_loads / total_loads) * 100 if total_loads > 0 else 0.0

    def calculate_update_frequency_score(self):
        """Вычисляет оценку частоты обновлений (улучшенная формула)."""
        success_times = sorted([t for t, success in self.metrics.load_success_history if success], reverse=True)
        if len(success_times) < 2:
            return 0.0  # Недостаточно данных для расчета интервала
        time_diffs = []
        for i in range(len(success_times) - 1):
            time_diffs.append((success_times[i] - success_times[i+1]).total_seconds() / 3600) # Интервалы в часах
        if not time_diffs:
            return 0.0
        average_interval_hours = sum(time_diffs) / len(time_diffs)

        # Улучшенная шкала оценки частоты обновлений
        if average_interval_hours < 1:
            return 100.0
        elif average_interval_hours < 6:
            return 100 - (average_interval_hours - 1) * (50 / 5) # Линейное снижение до 50
        elif average_interval_hours < 24:
            return 50 - (average_interval_hours - 6) * (30 / 18) # Линейное снижение до 20
        else:
            return 0.0 # Ниже 20 если интервал больше 24 часов

    def calculate_success_rate_stability_score(self, period_days=METRIC_PERIOD_MEDIUM):
        """Вычисляет стабильность успешности загрузок (стандартное отклонение, улучшенная формула)."""
        daily_success_rates = []
        today = datetime.now().date()
        for day_offset in range(period_days):
            current_day = today - timedelta(days=day_offset)
            day_history = [(t, s) for t, s in self.metrics.load_success_history if t.date() == current_day]
            if day_history:
                successful_loads = sum(1 for _, success in day_history if success)
                total_loads = len(day_history)
                daily_rate = (successful_loads / total_loads) * 100 if total_loads > 0 else 0.0
                daily_success_rates.append(daily_rate)
            else:
                daily_success_rates.append(0.0) # Если в какой-то день не было попыток, считаем 0%

        if len(daily_success_rates) < 2: # Нужно минимум 2 точки для std dev
            return 50.0 # Нейтральное значение, если недостаточно данных
        std_dev = statistics.stdev(daily_success_rates)
        # Улучшенная формула: нелинейное снижение score с ростом std_dev
        stability_score = max(0, 100 - (std_dev ** 1.5)) #  ** 1.5 для более резкого снижения при увеличении std_dev
        return stability_score

    def calculate_protocol_diversity_score(self):
        """Вычисляет оценку разнообразия протоколов."""
        protocol_counts = self.metrics.protocol_counts
        total_configs = sum(protocol_counts.values())
        if total_configs == 0:
            return 0.0
        unique_protocols = len(protocol_counts)
        max_possible_protocols = len(ALLOWED_PROTOCOLS)
        return (unique_protocols / max_possible_protocols) * 100

    def calculate_config_diversity_score(self):
        """Вычисляет оценку разнообразия параметров конфигураций (простой подсчет уникальных комбинаций)."""
        config_signatures = set()
        for protocol, configs in self.metrics.protocol_scores.items(): # Assuming protocol_scores stores config objects now
            for score in configs: # We only need config type for diversity, not scores directly
                config_obj_type_name = score.__class__.__name__ if isinstance(score, object) else "UnknownType" # Get config object type name
                config_signatures.add(f"{protocol}-{config_obj_type_name}") # Create a simple signature
        unique_config_types = len(config_signatures)
        max_possible_config_types = len(ALLOWED_PROTOCOLS) * 5 # Estimating max types per protocol (adjust as needed)
        return (unique_config_types / max_possible_config_types) * 100 if max_possible_config_types > 0 else 0.0


    def calculate_uniqueness_ratio(self, current_configs):
        """Вычисляет долю уникальных конфигураций среди новых."""
        new_unique_configs_count = 0
        total_new_configs = len(current_configs)
        for config_str in current_configs:
            if config_str not in ChannelConfig.GLOBAL_CONFIG_HISTORY:
                new_unique_configs_count += 1
                ChannelConfig.GLOBAL_CONFIG_HISTORY.add(config_str) # Добавляем в глобальную историю

        return (new_unique_configs_count / total_new_configs) * 100 if total_new_configs > 0 else 0.0

    def calculate_average_proxy_score(self):
        """Вычисляет средний скор прокси."""
        scores = self.metrics.protocol_scores # Используем накопленные скоры
        all_scores = []
        for protocol_score_list in scores.values():
            all_scores.extend(protocol_score_list)
        if not all_scores:
            return 50.0 # Нейтральный скор, если нет данных
        return sum(all_scores) / len(all_scores) if all_scores else 0.0

    def calculate_invalid_config_ratio(self, invalid_count, total_count):
        """Вычисляет долю невалидных конфигураций."""
        return (invalid_count / total_count) * 100 if total_count > 0 else 0.0

    def calculate_duplicate_config_ratio(self, duplicate_count, total_count):
        """Вычисляет долю дубликатов конфигураций."""
        return (duplicate_count / total_count) * 100 if total_count > 0 else 0.0

    def calculate_config_completeness_score(self, config_objects):
        """Вычисляет среднюю полноту конфигураций."""
        if not config_objects:
            return 50.0 # Нейтральное значение, если нет конфигураций
        completeness_scores = []
        for config_obj in config_objects:
            fields = astuple(config_obj)
            filled_fields = sum(1 for field_value in fields if field_value is not None and field_value != 'none' and field_value != False) # Adjust condition for "filled" as needed
            max_fields = len(fields)
            completeness_scores.append((filled_fields / max_fields) * 100 if max_fields > 0 else 0.0)
        return sum(completeness_scores) / len(completeness_scores) if completeness_scores else 0.0


    def calculate_overall_quality_score(self):
        """Вычисляет общий скор качества канала на основе взвешенных метрик."""
        weights = CHANNEL_SCORE_WEIGHTS
        score = 0.0

        score += self.calculate_load_success_rate() * weights["load_success_rate"]
        score += self.calculate_update_frequency_score() * weights["update_frequency_score"]
        score += self.calculate_success_rate_stability_score() * weights["success_rate_stability_score"]
        score += self.calculate_average_proxy_score() * weights["average_proxy_score"]
        score += self.calculate_protocol_diversity_score() * weights["protocol_diversity_score"]
        score += self.calculate_config_diversity_score() * weights["config_diversity_score"] # New metric
        score += self.calculate_uniqueness_ratio([]) * weights["uniqueness_ratio"] # Uniqueness needs current configs, calculated later

        # Штрафы
        score += self.metrics.invalid_config_ratio * weights["invalid_config_ratio_penalty"]
        score += self.metrics.duplicate_config_ratio * weights["duplicate_config_ratio_penalty"]
        if self.metrics.spam_detected: # применяем штраф только если spam_detected == True
            score += weights["spam_detected_penalty"] # Единоразовый штраф за обнаружение спама

        return max(0, min(100, score)) # Clamp score between 0 and 100

    def classify_quality_category(self):
        """Классифицирует канал по категориям качества на основе скора."""
        score = self.metrics.overall_quality_score
        thresholds = CHANNEL_QUALITY_THRESHOLDS
        if score >= thresholds["excellent"]:
            return "Excellent"
        elif score >= thresholds["good"]:
            return "Good"
        elif score >= thresholds["medium"]:
            return "Medium"
        elif score >= thresholds["low"]:
            return "Low"
        else:
            return "Bad"

    def update_channel_metrics(self, proxies, invalid_configs_count, duplicate_configs_count):
        """Обновляет все метрики канала после обработки."""
        self.metrics.average_proxy_score = self.calculate_average_proxy_score()
        self.metrics.protocol_diversity_score = self.calculate_protocol_diversity_score()
        self.metrics.config_diversity_score = self.calculate_config_diversity_score() # Calculate config diversity
        self.metrics.invalid_config_ratio = self.calculate_invalid_config_ratio(invalid_configs_count, len(proxies) + invalid_configs_count) # Total checked configs
        self.metrics.duplicate_config_ratio = self.calculate_duplicate_config_ratio(duplicate_configs_count, len(proxies) + duplicate_configs_count)
        self.metrics.config_completeness_score = self.calculate_config_completeness_score([p['config_obj'] for p in proxies]) # Calculate completeness based on parsed config objects

        self.metrics.overall_quality_score = self.calculate_overall_quality_score()
        self.metrics.quality_category = self.classify_quality_category()


class ProxyConfig:
    """Управляет конфигурациями прокси."""
    def __init__(self):
        """Инициализирует объект ProxyConfig, загружает URL каналов и настраивает окружение."""
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.resolver = None
        self.failed_channels = []
        self.processed_configs = set()
        self.SOURCE_URLS = self._load_source_urls() # Still load source URLs, but need to adjust loading logic
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.ALL_URLS_FILE = ALL_URLS_FILE
        self.BAD_CHANNELS_FILE = BAD_CHANNELS_FILE
        self.known_configs = set() # Set to store known configurations globally
        self.min_quality_category = MIN_CHANNEL_QUALITY_CATEGORY # Минимальная категория качества канала
        self.bad_channels_list = self._load_bad_channels() # Load existing bad channels

    def _load_bad_channels(self) -> set:
        """Загружает список URL плохих каналов из файла в set для быстрой проверки."""
        bad_channels = set()
        if os.path.exists(self.BAD_CHANNELS_FILE):
            try:
                with open(self.BAD_CHANNELS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            bad_channels.add(url)
            except Exception as e:
                logger.error(f"Ошибка чтения файла {self.BAD_CHANNELS_FILE}: {e}")
        return bad_channels


    async def _fetch_url_content(self, url: str) -> Optional[str]:
        """Загружает содержимое URL асинхронно."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=CHANNEL_LOAD_TIMEOUT) as response: # Добавлен таймаут для запроса
                    if response.status == 200:
                        return await response.text(encoding='utf-8')
                    else:
                        logger.warning(f"HTTP ошибка {response.status} при загрузке URL: {url}")
                        self.save_bad_channel_url(url) # Save bad channel URL for HTTP errors
                        return None
        except aiohttp.ClientError as e:
            logger.warning(f"Ошибка при загрузке URL: {url} - {e}")
            self.save_bad_channel_url(url) # Save bad channel URL for client errors
            return None
        except asyncio.TimeoutError:
            logger.warning(f"Таймаут при загрузке URL: {url}")
            self.save_bad_channel_url(url) # Save bad channel URL for timeouts
            return None
        except aiodns.error.DNSError as e: # Catch DNS errors explicitly
            logger.warning(f"DNS ошибка при загрузке URL: {url} - {e}")
            self.save_bad_channel_url(url) # Save bad channel URL for DNS errors
            return None
        except Exception as e:
            logger.warning(f"Неизвестная ошибка при загрузке URL: {url} - {e}")
            return None


    def _load_source_urls(self) -> List[ChannelConfig]:
        """Загружает URL каналов из файла и удаляет дубликаты."""
        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url)) # Теперь сохраняем URL как внешний источник
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
            raise InvalidURLError(f"Отсутствует схема в URL: '{url}'. Ожидается схема прокси.")
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
                normalized_url = await self._normalize_url(config.url)
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

    async def save_bad_channel_url(self, channel_url: str):
        """Сохраняет URL канала в файл bad_channels.txt, избегая дубликатов."""
        normalized_url = await self._normalize_url(channel_url) # Normalize URL before saving

        if normalized_url in self.bad_channels_list: # Check if already in bad channels list
            logger.debug(f"URL плохого канала уже существует в {BAD_CHANNELS_FILE}: {channel_url}")
            return

        os.makedirs(os.path.dirname(BAD_CHANNELS_FILE), exist_ok=True) # Ensure directory exists
        try:
            with open(BAD_CHANNELS_FILE, 'a', encoding='utf-8') as f: # Append mode
                f.write(normalized_url + '\n') # Save normalized URL
            self.bad_channels_list.add(normalized_url) # Add to the set to prevent future duplicates
            logger.info(f"URL плохого канала сохранен в {BAD_CHANNELS_FILE}: {channel_url}")
        except Exception as e:
            logger.error(f"Ошибка сохранения URL плохого канала в {BAD_CHANNELS_FILE}: {e}")


# --- Enum для весов скоринга ---
class ScoringWeights(Enum):
    """Перечисление весов, используемых для скоринга конфигураций прокси."""
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
    CONFIG_DIVERSITY = 5 # New weight for config diversity


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


async def compute_profile_score(config: str, loaded_weights: Dict = None, first_seen: Optional[datetime] = None) -> float:
    """Вычисляет общий рейтинг профиля прокси."""
    if loaded_weights is None:
        loaded_weights = ScoringWeights.load_weights_from_json()

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    if protocol == "ssconf://":
        try:
            config_obj = await SSConfConfig.from_url(config, None) # resolver not needed for ssconf scoring
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

    return round(max(0, min(100, score)), 2) # Ensure score is within 0-100 range and rounded


def generate_custom_name(parsed: urlparse, query: Dict) -> str:
    """Генерирует пользовательское имя профиля на основе URL и параметров."""
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

    elif scheme == "ssconf": # Custom name for ssconf
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


def is_spam_config(config_string: str) -> bool:
    """Проверяет, является ли конфигурация прокси спамом на основе ключевых слов."""
    config_lower = config_string.lower()
    for keyword in SPAM_KEYWORDS:
        if keyword in config_lower:
            return True
    return False


# --- Функции для протокол-специфичных проверок (Улучшенные) ---
async def test_vless_connection(config_obj: VlessConfig, timeout: float = PROTOCOL_TIMEOUTS.get("vless")) -> bool:
    """Проверка VLESS соединения: TCP handshake."""
    return await _vless_handshake(config_obj, timeout)

async def test_trojan_connection(config_obj: TrojanConfig, timeout: float = PROTOCOL_TIMEOUTS.get("trojan")) -> bool:
    """Проверка Trojan соединения: TCP handshake."""
    return await _trojan_handshake(config_obj, timeout)

async def test_ss_connection(config_obj: SSConfig, timeout: float = PROTOCOL_TIMEOUTS.get("ss")) -> bool:
    """Проверка Shadowsocks соединения: TCP handshake."""
    return await _ss_handshake(config_obj, timeout)

async def test_ssconf_connection(config_obj: SSConfConfig, timeout: float = PROTOCOL_TIMEOUTS.get("ssconf")) -> bool:
    """Проверка SSConf соединения: TCP handshake."""
    return await test_ss_connection(SSConfig(method=config_obj.method, password=config_obj.password, address=config_obj.server, port=config_obj.server_port, plugin=None, obfs=config_obj.obfs), timeout=timeout) # Reuse SS handshake

async def test_tuic_connection(config_obj: TuicConfig, timeout: float = PROTOCOL_TIMEOUTS.get("tuic")) -> bool:
    """Проверка TUIC соединения: TCP connect (для UDP-based протокола, минимальная TCP проверка)."""
    return await _minimal_tcp_connection_test(config_obj.address, config_obj.port, timeout, protocol_name="TUIC")

async def test_hy2_connection(config_obj: Hy2Config, timeout: float = PROTOCOL_TIMEOUTS.get("hy2")) -> bool:
    """Проверка HY2 соединения: TCP connect (для UDP-based протокола, минимальная TCP проверка)."""
    return await _minimal_tcp_connection_test(config_obj.address, config_obj.port, timeout, protocol_name="HY2")


async def _minimal_tcp_connection_test(host: str, port: int, timeout: float, protocol_name: str) -> bool:
    """Вспомогательная функция для минимальной TCP проверки с настраиваемым таймаутом."""
    try:
        await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
        logger.debug(f"✅ {protocol_name} проверка: TCP соединение с {host}:{port} установлено за {timeout:.2f} секунд.")
        return True
    except asyncio.TimeoutError:
        logger.debug(f"❌ {protocol_name} проверка: TCP таймаут ({timeout:.2f} сек) при подключении к {host}:{port}:{timeout:.2f} секунд.") # Исправлено логирование таймаута
        return False
    except (ConnectionRefusedError, OSError, socket.gaierror) as e:
        logger.debug(f"❌ {protocol_name} проверка: Ошибка TCP соединения с {host}:{port}: {e}.")
        return False


async def _vless_handshake(config_obj: VlessConfig, timeout: float) -> bool:
    """Минимальный handshake для VLESS (TCP connect - для начала). **НУЖНО РЕАЛИЗОВАТЬ VLESS HANDSHAKE!**"""
    return await _minimal_tcp_connection_test(config_obj.address, config_obj.port, timeout, protocol_name="VLESS")


async def _trojan_handshake(config_obj: TrojanConfig, timeout: float) -> bool:
    """Минимальный handshake для Trojan (TCP connect - для начала). **НУЖНО РЕАЛИЗОВАТЬ TROJAN HANDSHAKE!**"""
    return await _minimal_tcp_connection_test(config_obj.address, config_obj.port, timeout, protocol_name="Trojan")


async def _ss_handshake(config_obj: SSConfig, timeout: float) -> bool:
    """Минимальный handshake для Shadowsocks (TCP connect - для начала). **НУЖНО РЕАЛИЗОВАТЬ SS HANDSHAKE!**"""
    return await _minimal_tcp_connection_test(config_obj.address, config_obj.port, timeout, protocol_name="Shadowsocks")



async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig, loaded_weights: Dict,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    """Обрабатывает одну конфигурацию прокси: парсит, проверяет доступность (протокол-специфично), скорит и сохраняет результат."""
    async with proxy_semaphore, global_proxy_semaphore:
        if is_spam_config(line): # Проверка на спам в начале обработки
            channel.metrics.spam_configs_count += 1
            logger.debug(f"🚫 Обнаружена спам-конфигурация: {line}")
            return None # Возвращаем None, если конфигурация - спам

        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            return None

        protocol_type = config_obj.__class__.__name__.replace("Config", "").lower()
        is_reachable = False

        if protocol_type == "vless":
            is_reachable = await test_vless_connection(config_obj)
        elif protocol_type == "trojan":
            is_reachable = await test_trojan_connection(config_obj)
        elif protocol_type == "ss":
            is_reachable = await test_ss_connection(config_obj)
        elif protocol_type == "ssconf":
            is_reachable = await test_ssconf_connection(config_obj)
        elif protocol_type == "tuic":
            is_reachable = await test_tuic_connection(config_obj)
        elif protocol_type == "hy2":
            is_reachable = await test_hy2_connection(config_obj)
        else:
            logger.warning(f"Неизвестный тип протокола для проверки: {protocol_type}")
            return None

        if not is_reachable:
            logger.debug(f"❌ Прокси {line} не прошла протокол-специфичную проверку.")
            return None
        else:
            logger.debug(f"✅ Прокси {line} прошла протокол-специфичную проверку.")


        score = await compute_profile_score( # Вызов асинхронной функции compute_profile_score должен быть с await
            line,
            loaded_weights=loaded_weights,
            first_seen = config_obj.first_seen
        )

        result = {
            "config": line,
            "protocol": protocol_type,
            "score": score,
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[protocol_type] += 1
        channel.metrics.protocol_scores[protocol_type].append(score) # Store score instead of config_obj
        return result


# --- Функции process_all_channels, sort_proxies, save_final_configs, update_and_save_weights, prepare_training_data, main ---
async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы в списке."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict] = []
    min_quality_category = proxy_config.min_quality_category.lower() # Получаем минимальную категорию из ProxyConfig

    for channel in channels:
        channel.update_load_success_history(False) # Assume failure at start, corrected on success
        invalid_configs_count = 0
        duplicate_configs_count = 0
        spam_configs_count = 0 # Сброс счетчика спам-конфигураций для канала
        current_channel_configs = [] # Для расчета Uniqueness Ratio

        lines_str = ""
        try:
            logger.info(f"🔄 Загрузка прокси конфигураций из URL: {channel.url}") # Логируем начало загрузки из внешнего URL
            lines_str = await proxy_config._fetch_url_content(channel.url) # Загружаем содержимое из внешнего URL
            if lines_str is None: # Если не удалось загрузить содержимое
                logger.warning(f"⚠️ Не удалось загрузить содержимое из URL: {channel.url}. Пропускаем канал.")
                channel.update_load_success_history(False) # Помечаем загрузку как неудачную
                continue # Переходим к следующему каналу
            channel.update_load_success_history(True) # Помечаем загрузку как успешную, если содержимое загружено
            logger.info(f"✅ Прокси конфигурации успешно загружены из URL: {channel.url}") # Логируем успешную загрузку
        except Exception as e: # Обработка ошибок при загрузке URL
            logger.error(f"Ошибка при обработке URL канала: {channel.url}. Ошибка: {e}")
            channel.update_load_success_history(False) # Помечаем загрузку как неудачную
            continue

        lines = lines_str.splitlines() if lines_str else [] # Разделяем на строки, если содержимое было загружено

        proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
        proxy_tasks = []
        loaded_weights = ScoringWeights.load_weights_from_json()

        for line in lines:
            line = line.strip()
            if len(line) < 1 or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line): # Removed MIN_CONFIG_LENGTH
                invalid_configs_count += 1 # Count invalid lines
                continue
            if line in proxy_config.known_configs: # Check for duplicates before processing
                duplicate_configs_count += 1
                continue
            proxy_config.known_configs.add(line) # Add to known configs set immediately to avoid further duplicates in same channel processing

            task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                        loaded_weights, proxy_semaphore, global_proxy_semaphore))
            proxy_tasks.append(task)
            current_channel_configs.append(line) # Сохраняем для расчета Uniqueness Ratio

        results = await asyncio.gather(*proxy_tasks)
        valid_proxies = []
        for result in results:
            if result:
                valid_proxies.append(result)
                proxies_all.append(result)

        # Calculate channel-level metrics AFTER processing all proxies in the channel
        channel.metrics.unique_configs = len(valid_proxies) # Valid proxies are unique within channel processing scope
        channel.metrics.uniqueness_ratio = channel.calculate_uniqueness_ratio(current_channel_configs) # Calculate uniqueness ratio based on current configs
        channel.update_channel_metrics(valid_proxies, invalid_configs_count, duplicate_configs_count) # Обновляем метрики канала

        if channel.metrics.spam_configs_count > 0: # Если спам был обнаружен в канале, устанавливаем флаг
            channel.metrics.spam_detected = True

        logger.info(f"📊 Канал {channel.url}: Качество - {channel.metrics.quality_category}, Общий скор - {channel.metrics.overall_quality_score:.2f} (Успешность загрузки: {channel.calculate_load_success_rate():.2f}%, Частота обновлений: {channel.calculate_update_frequency_score():.2f}, Разнообразие протоколов: {channel.calculate_protocol_diversity_score():.2f}%, Разнообразие конфигов: {channel.calculate_config_diversity_score():.2f}%, Уникальность: {channel.metrics.uniqueness_ratio:.2f}%, Спам конфигов: {channel.metrics.spam_configs_count})") # Расширенная статистика

        # Фильтрация каналов по качеству
        quality_category = channel.metrics.quality_category.lower()
        if quality_category == "bad": # Check for "Bad" quality and skip
            logger.info(f"⛔️ Канал {channel.url} пропущен из-за низкого качества ({channel.metrics.quality_category}). Прокси из канала не будут сохранены.")
            proxy_config.save_bad_channel_url(channel.url) # Сохраняем URL плохого канала
            continue # Пропускаем канал, если качество 'bad'
        elif quality_category not in ["excellent", "good", "medium", "low"]: # Defensive check for other unexpected categories
            logger.warning(f"⚠️ Неверная категория качества для канала {channel.url}: {channel.metrics.quality_category}. Пропускаем канал.")
            continue # Пропускаем канал, если категория не распознана
        elif quality_category in ["medium", "good", "excellent", "low"]: # Now also include 'low' or adjust as needed based on MIN_CHANNEL_QUALITY_CATEGORY
            logger.info(f"✔️ Канал {channel.url} прошел фильтрацию по качеству ({channel.metrics.quality_category} >= {min_quality_category}).")

        proxies_all.extend(valid_proxies) # Добавляем прокси только если канал прошел фильтрацию

    return proxies_all


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
        colored_log(logging.INFO, f"✨ Всего уникальных прокси сохранено: {unique_proxy_count}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")



def main():
    """Основная функция для запуска проверки прокси."""
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
        proxy_config.remove_failed_channels_from_file() # Keep for file management, but might need to adjust logic

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
            colored_log(logging.INFO, f"🔄 Всего файлов-каналов обработано: {total_channels}") # Adjusted log message
            colored_log(logging.INFO, f"✅ Включено файлов-каналов: {enabled_channels}") # Adjusted log message
            colored_log(logging.INFO, f"❌ Отключено файлов-каналов: {disabled_channels}") # Adjusted log message
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
