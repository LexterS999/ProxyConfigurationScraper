import asyncio
import aiodns
import re
import os
import json
import logging
import ipaddress
import io
import uuid
import string
import base64
import aiohttp
import time

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict
import functools

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_downloader.log'

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
ALLOWED_PROTOCOLS = ["vless://", "ss://", "tuic://", "hy2://"]
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120
MAX_CONCURRENT_PROXIES_GLOBAL = 240
OUTPUT_CONFIG_FILE = "proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
MAX_RETRIES = 3 # Увеличено количество попыток
RETRY_DELAY_BASE = 2 # Увеличена базовая задержка

# --- Исключения ---
class InvalidURLError(ValueError):
    pass

class UnsupportedProtocolError(ValueError):
    pass

class InvalidParameterError(ValueError):
    pass

class ConfigParseError(ValueError):
    pass

# --- Enum для имен профилей --- (Упрощен)
class ProfileName(Enum):
    VLESS = "VLESS"
    SS = "SS"
    TUIC = "TUIC"
    HY2 = "HY2"
    UNKNOWN = "Unknown Protocol"


# --- Data classes для конфигураций ---
@dataclass(frozen=True)
class VlessConfig:
    address: str
    port: int

    def __hash__(self):
        return hash((self.address, self.port))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["VlessConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            return None

        port_str = parsed_url.port
        if port_str is None:
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            return None

        return cls(
            address=address,
            port=port,
        )

@dataclass(frozen=True)
class SSConfig:
    address: str
    port: int

    def __hash__(self):
        return hash((self.address, self.port))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["SSConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            return None

        port_str = parsed_url.port
        if port_str is None:
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            return None
        return cls(
            address=address,
            port=port,
        )

@dataclass(frozen=True)
class TuicConfig:
    address: str
    port: int

    def __hash__(self):
        return hash((self.address, self.port))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["TuicConfig"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            return None

        port_str = parsed_url.port
        if port_str is None:
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            return None
        return cls(
            address=address,
            port=port,
        )

@dataclass(frozen=True)
class Hy2Config:
    address: str
    port: int

    def __hash__(self):
        return hash((self.address, self.port))

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> Optional["Hy2Config"]:
        address = await resolve_address(parsed_url.hostname, resolver)
        if address is None:
            return None

        port_str = parsed_url.port
        if port_str is None:
            return None
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            return None

        return cls(
            address=address,
            port=port,
        )

# --- Data classes для метрик и конфигураций каналов ---
@dataclass
class ChannelMetrics:
    url: str # Добавлено для хранения URL канала в metrics
    valid_configs: int = 0
    unique_configs: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    fetch_status: str = "pending" # pending, success, warning, error, critical
    retries_count: int = 0
    first_seen: Optional[datetime] = None

    def update_status_from_exception(self, exception_type: str):
        if exception_type in ["aiohttp.ClientError", "asyncio.TimeoutError"]:
            if self.retries_count <= MAX_RETRIES:
                self.fetch_status = "warning" # Transient issue, retrying
            else:
                self.fetch_status = "error"   # Retries exhausted, but not critical yet
        else:
            self.fetch_status = "critical" # Other errors are more serious

class ChannelConfig:
    RESPONSE_TIME_DECAY = 0.7
    VALID_PROTOCOLS = ["vless://", "ss://", "tuic://", "hy2://"]
    REPEATED_CHARS_THRESHOLD = 100

    def __init__(self, url: str):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics(url=url) # Передаём URL в ChannelMetrics
        self.check_count = 0
        self.metrics.first_seen = datetime.now()

    def _validate_url(self, url: str) -> str:
        if not isinstance(url, str):
            raise InvalidURLError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        if not url:
            raise InvalidURLError("URL не может быть пустым.")
        if re.search(r'(.)\1{' + str(self.REPEATED_CHARS_THRESHOLD) + r',}', url):
            raise InvalidURLError("URL содержит слишком много повторяющихся символов.")
        parsed = urlsplit(url)
        if parsed.scheme not in ["http", "https"] and parsed.scheme not in [p.replace('://', '') for p in self.VALID_PROTOCOLS]:
            expected_protocols = ", ".join(["http", "https"] + self.VALID_PROTOCOLS)
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError(
                f"Неподдерживаемый протокол URL: '{received_protocol_prefix}...'. Ожидаются протоколы: {expected_protocols}."
            )
        return url

class ProxyConfig:
    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.resolver = None
        self.failed_channels = [] # failed_channels list is kept but not used in logic anymore
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
        except UnicodeDecodeError as e:
            logger.error(f"Ошибка декодирования при чтении {ALL_URLS_FILE}: {e}")
        except Exception as e:
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
        return parsed._replace(scheme=parsed.scheme.lower(), path=path).geturl()

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        seen_urls = set()
        unique_configs = []
        for config in channel_configs:
            if not isinstance(config, ChannelConfig):
                continue
            try:
                normalized_url = asyncio.run(self._normalize_url(config.url))
                if normalized_url not in seen_urls:
                    seen_urls.add(normalized_url)
                    unique_configs.append(config)
                else:
                    pass
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
        # Functionality to remove failed channels is removed. Kept as empty function to avoid breaking calls.
        pass


# --- Вспомогательные функции ---
async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    if is_valid_ipv4(hostname):
        return hostname
    try:
        result = await resolver.query(hostname, 'A')
        resolved_address = result[0].host
        if is_valid_ipv4(resolved_address):
            return resolved_address
        else:
            return None
    except aiodns.error.DNSError as e:
        if e.args[0] == 4: # Domain name not found
            pass
        elif e.args[0] == 8: # Misformatted domain name
            pass
        elif not is_valid_ipv4(hostname): # Only log warning if hostname is not already IP
            logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при резолвинге {hostname}: {e}")
        return None


@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_proxy_url(url: str) -> bool:
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme
        if scheme in ('vless', 'tuic'):
            profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
            if profile_id and not is_valid_uuid(profile_id):
                return False
        if scheme != "ss":
            if not parsed.hostname or not parsed.port:
                return False
        else:
            if not parsed.hostname and not parsed.netloc.startswith('@'):
                return False
        if not is_valid_ipv4(parsed.hostname):
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
    if protocol:
        try:
            parsed = urlparse(config_string)
            query = parse_qs(parsed.query)
            scheme = parsed.scheme
            config_parsers = {
                "vless": VlessConfig.from_url,
                "ss": SSConfig.from_url,
                "tuic": TuicConfig.from_url,
                "hy2": Hy2Config.from_url,
            }
            if scheme in config_parsers:
                return await config_parsers[scheme](parsed, query, resolver)
            return None
        except (InvalidURLError, UnsupportedProtocolError) as e:
            return None
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
            return None
    return None


async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            return None

        result = {
            "config": line,
            "protocol": config_obj.__class__.__name__.replace("Config", "").lower(),
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[result["protocol"]] += 1
        return result

async def process_channel(channel: ChannelConfig, proxy_config: "ProxyConfig", session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, global_proxy_semaphore: asyncio.Semaphore):
    """Обрабатывает один канал, скачивая и обрабатывая прокси с retry logic."""
    async with channel_semaphore:
        colored_log(logging.INFO, f"🚀 Начало обработки канала: {channel.url}")
        proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
        proxy_tasks = []
        lines = []
        session_timeout = aiohttp.ClientTimeout(total=15)
        retries_attempted = 0
        channel_content_received = False # Flag to track if content was received

        while retries_attempted <= MAX_RETRIES:
            channel.metrics.retries_count = retries_attempted # Update retry count in metrics
            try:
                async with session.get(channel.url, timeout=session_timeout) as response:
                    if response.status == 200:
                        try:
                            text = await response.text(encoding='utf-8', errors='ignore')
                            lines = text.splitlines()
                            channel_content_received = True # Mark content as received
                            channel.metrics.fetch_status = "success"
                            break # Успешно получили, выходим из цикла retry
                        except UnicodeDecodeError as e:
                            colored_log(logging.WARNING, f"⚠️ Ошибка декодирования для {channel.url}: {e}. Пропуск.")
                            channel.metrics.fetch_status = "warning" # Decoding issue
                            return [] # Не можем декодировать, нет смысла retry
                    elif response.status in (403, 404):
                        if retries_attempted == 0: # Логируем 403/404 только при первой попытке, чтобы не спамить в лог при retry
                            colored_log(logging.WARNING, f"⚠️ Канал {channel.url} вернул статус {response.status}. Пропуск.")
                        channel.metrics.fetch_status = "warning" # Treat 403/404 as warning for channel status
                        return [] # 403/404 скорее всего постоянная проблема, нет смысла retry
                    else:
                        colored_log(logging.ERROR, f"❌ Ошибка при получении {channel.url}, статус: {response.status}")
                        if retries_attempted == MAX_RETRIES:
                            channel.metrics.fetch_status = "error" # Max retries reached, error status
                            return [] # Достигнуто макс. количество попыток, выходим
                    # Для других ошибок, статус не 200, но и не 403/404, продолжаем retry
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted)
                colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel.url} (попытка {retries_attempted+1}/{MAX_RETRIES+1}): {e}. Пауза {retry_delay} сек перед повтором...")
                if retries_attempted == MAX_RETRIES:
                    colored_log(logging.ERROR, f"❌ Максимальное количество попыток ({MAX_RETRIES+1}) исчерпано для {channel.url}. Канал пропускается.")
                    channel.metrics.fetch_status = "error" # Max retries exhausted due to network issues
                    channel.metrics.update_status_from_exception(e.__class__.__module__ + '.' + e.__class__.__name__) # Более детальный статус по Exception
                    return [] # Достигнуто макс. количество попыток, выходим
                await asyncio.sleep(retry_delay)
            retries_attempted += 1

        if not channel_content_received: # If loop completes without receiving content (no break)
             channel.metrics.fetch_status = "critical" # Mark as critical if content was never received after retries
             colored_log(logging.CRITICAL, f"🔥 Не удалось получить данные из канала {channel.url} после {MAX_RETRIES+1} попыток. Канал пропускается.")
             return []

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
        channel.metrics.unique_configs = len(set(r['config'] for r in valid_results)) # Count unique configs

        if channel.metrics.valid_configs == 0 and channel.metrics.fetch_status == "success": # Only warn if fetch was successful but no configs found
            colored_log(logging.WARNING, f"⚠️ Канал {channel.url} успешно обработан, но временно не вернул конфигураций.")
            channel.metrics.fetch_status = "warning" # Update status to warning if no configs but successful fetch
        elif channel.metrics.valid_configs > 0:
            colored_log(logging.INFO, f"✅ Завершена обработка канала: {channel.url}. Найдено {channel.metrics.valid_configs} конфигураций ({channel.metrics.unique_configs} уникальных).")

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
        channel_results = await asyncio.gather(*channel_tasks)

        for channel_proxies in channel_results:
            proxies_all.extend(channel_proxies)

    return proxies_all


def save_final_configs(proxies: List[Dict], output_file: str):
    unique_proxies = defaultdict(set)
    unique_proxy_count = 0
    protocol_order = ["vless", "tuic", "hy2", "ss"] # протоколы в нужном порядке
    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for protocol_name in protocol_order: # проходимся по протоколам в заданном порядке
                colored_log(logging.INFO, f"\n🛡️  Протокол: {ProfileName[protocol_name.upper()].value}") # Выводим название протокола
                protocol_proxies = [p for p in proxies if p['protocol'] == protocol_name]
                if not protocol_proxies:
                    colored_log(logging.INFO, f"   Нет прокси для протокола {ProfileName[protocol_name.upper()].value}.")
                    continue

                for proxy in protocol_proxies:
                    config = proxy['config'].split('#')[0].strip()
                    parsed = urlparse(config)
                    ip_address = parsed.hostname
                    port = parsed.port
                    ip_port_tuple = (ip_address, port)
                    if ip_port_tuple not in unique_proxies[protocol_name]:
                        unique_proxies[protocol_name].add(ip_port_tuple)
                        unique_proxy_count += 1
                        profile_name = f"{ProfileName[proxy['protocol'].upper()].value}"
                        final_line = f"{config}#{profile_name}\n"
                        f.write(final_line)
                        colored_log(logging.INFO, f"   ✨ Добавлен прокси: {config}#{profile_name}") # Логируем добавление прокси
        colored_log(logging.INFO, f"\n✅ Финальные конфигурации сохранены в {output_file}. Уникальность прокси по IP:порт в пределах протокола обеспечена.")
        colored_log(logging.INFO, f"📊 Всего уникальных прокси сохранено: {unique_proxy_count}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")
    return unique_proxies # Return unique_proxies for statistics

def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()
    statistics_logged = False
    start_time = time.time() # Record start time

    async def runner():
        nonlocal statistics_logged, start_time
        loop = asyncio.get_running_loop()
        proxy_config.set_event_loop(loop)
        colored_log(logging.INFO, "🚀 Начало скачивания и обработки прокси...")
        proxies = await process_all_channels(channels, proxy_config)
        unique_proxy_stats = save_final_configs(proxies, proxy_config.OUTPUT_FILE) # Get unique proxy stats
        proxy_config.remove_failed_channels_from_file() # remove_failed_channels_from_file call is kept, but it's empty now.

        if not statistics_logged:
            end_time = time.time() # Record end time
            elapsed_time = end_time - start_time # Calculate elapsed time

            total_channels = len(channels)
            enabled_channels = sum(1 for channel in channels)
            disabled_channels = total_channels - enabled_channels
            total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)
            total_unique_configs_saved = sum(len(protos) for protos in unique_proxy_stats.values()) # Count saved unique proxies
            protocol_stats = defaultdict(int)
            channel_status_counts = defaultdict(int) # Track channel status counts

            for channel in channels:
                for protocol, count in channel.metrics.protocol_counts.items():
                    protocol_stats[protocol] += count
                channel_status_counts[channel.metrics.fetch_status] += 1 # Count channel status

            colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
            colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
            colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")

            # Detailed Channel Status Section
            colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
            for status in ["success", "warning", "error", "critical", "pending"]: # Explicit order
                count = channel_status_counts.get(status, 0)
                if count > 0:
                    status_text = status.upper()
                    color = LogColors.GREEN if status == "success" else (LogColors.YELLOW if status == "warning" else (LogColors.RED if status in ["error", "critical"] else LogColors.RESET))
                    colored_log(logging.INFO, f"  - {color}{status_text}{LogColors.RESET}: {count} каналов")

            colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_valid_configs}")
            colored_log(logging.INFO, f"✅ Всего уникальных прокси сохранено: {total_unique_configs_saved}")

            # Protocol Breakdown
            colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
            if protocol_stats:
                for protocol, count in protocol_stats.items():
                    colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
            else:
                colored_log(logging.INFO, "   Нет статистики по протоколам.")

            # Example URLs for each status (optional, can be verbose)
            if logger.level <= logging.DEBUG: # Only show detailed URL status in DEBUG mode to avoid verbose output in normal runs.
                colored_log(logging.DEBUG, "\n🔎 Детализация по URL-источникам (DEBUG):")
                for status in ["success", "warning", "error", "critical"]:
                    colored_log(logging.DEBUG, f"  --- URL-источники со статусом {status.upper()}:")
                    for channel in channels:
                        if channel.metrics.fetch_status == status:
                            log_level = logging.DEBUG if status == "success" else (logging.WARNING if status == "warning" else logging.ERROR)
                            colored_log(log_level, f"    - {channel.url} (Найдено: {channel.metrics.valid_configs}, Уникальных: {channel.metrics.unique_configs}, Попыток: {channel.metrics.retries_count})")

            colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
            statistics_logged = True
            colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
