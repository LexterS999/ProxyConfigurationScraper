import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import io
import uuid
import string
import base64
import aiohttp
import time
import concurrent.futures # Import for thread pool

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
import functools

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_downloader.log'
LOG_LEVEL_FILE = "WARNING"  # Уровень логирования для файла
LOG_LEVEL_CONSOLE = "INFO" # Уровень логирования для консоли

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(getattr(logging, LOG_LEVEL_FILE.upper(), logging.WARNING)) # Уровень логирования из константы
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(getattr(logging, LOG_LEVEL_CONSOLE.upper(), logging.INFO)) # Уровень логирования из константы
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)

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

# --- Константы ---
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "ss://"]
ALL_URLS_FILE = "channel_urls.txt"
OUTPUT_ALL_CONFIG_FILE = "configs/proxy_configs_all.txt" # Возвращено к .txt
MAX_RETRIES = 4
RETRY_DELAY_BASE = 2
MAX_CONCURRENT_CHANNELS = 60
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 50
MAX_CONCURRENT_PROXIES_GLOBAL = 50
DOWNLOAD_TIMEOUT_SEC = 15

# --- Thread Pool Executor for CPU-bound tasks ---
CPU_BOUND_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) # Adjust max_workers as needed

class ProfileName(Enum):
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    UNKNOWN = "Unknown Protocol"

class InvalidURLError(ValueError):
    pass

class UnsupportedProtocolError(ValueError):
    pass

@dataclass(frozen=True)
class ProxyParsedConfig:
    config_string: str
    protocol: str
    address: str
    port: int

    def __hash__(self):
        return hash((self.protocol, self.address, self.port, self.config_string)) # config_string for full deduplication

    def __eq__(self, other):
        if isinstance(other, ProxyParsedConfig):
            return (self.protocol, self.address, self.port, self.config_string) == \
                   (other.protocol, other.address, other.port, other.config_string)
        return False

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
        if not protocol:
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                return None
            return cls(
                config_string=config_string,
                protocol=protocol.replace("://", ""),
                address=address,
                port=port
            )
        except ValueError:
            return None

@dataclass(frozen=True)
class VlessParsedConfig(ProxyParsedConfig):
    uuid: Optional[str] = None
    encryption: Optional[str] = None
    flow: Optional[str] = None
    security: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["VlessParsedConfig"]:
        if not config_string.startswith("vless://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            username = parsed_url.username
            password = parsed_url.password
            userinfo = f"{username}:{password}" if username and password else username if username else None # исправлено

            query_params = parse_qs(parsed_url.query)

            uuid_val = parsed_url.username if parsed_url.username else None
            if not uuid_val and "uuid" in query_params:
                uuid_val = query_params["uuid"][0]

            return cls(
                config_string=config_string,
                protocol="vless",
                address=address,
                port=port,
                uuid=uuid_val,
                encryption=query_params.get("encryption", [None])[0],
                flow=query_params.get("flow", [None])[0],
                security=query_params.get("security", [None])[0],
                sni=query_params.get("sni", [None])[0],
                alpn=query_params.get("alpn", [None])[0],
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn))

    def __eq__(self, other):
        if not isinstance(other, VlessParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn) == \
               (other.uuid, other.encryption, other.flow, other.security, other.sni, other.alpn)

# --- Добавьте классы TuicParsedConfig, Hy2ParsedConfig, SsParsedConfig по аналогии, если необходимо парсить специфичные параметры ---
@dataclass(frozen=True)
class TuicParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    congestion_control: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["TuicParsedConfig"]:
        if not config_string.startswith("tuic://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="tuic",
                address=address,
                port=port,
                congestion_control=query_params.get("c", [None])[0], # 'c' for congestion control is a guess, check TUIC spec
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.congestion_control))

    def __eq__(self, other):
        if not isinstance(other, TuicParsedConfig):
            return False
        return super().__eq__(other) and self.congestion_control == other.congestion_control

@dataclass(frozen=True)
class Hy2ParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    encryption_method: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["Hy2ParsedConfig"]:
        if not config_string.startswith("hy2://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="hy2",
                address=address,
                port=port,
                encryption_method=query_params.get("enc", [None])[0], # 'enc' for encryption is a guess, check HY2 spec
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method))

    def __eq__(self, other):
        if not isinstance(other, Hy2ParsedConfig):
            return False
        return super().__eq__(other) and self.encryption_method == other.encryption_method


@dataclass(frozen=True)
class SsParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    encryption_method: Optional[str] = None
    password: Optional[str] = None
    plugin: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["SsParsedConfig"]:
        if not config_string.startswith("ss://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port

            userinfo = parsed_url.username
            password = parsed_url.password
            encryption_password_b64 = parsed_url.netloc.split('@')[0] # extract b64 encoded part
            try:
                encryption_password_decoded = base64.b64decode(encryption_password_b64 + "==").decode('utf-8') # Padding might be needed
                encryption_method = encryption_password_decoded.split(':')[0]
                password = encryption_password_decoded.split(':')[1] if len(encryption_password_decoded.split(':')) > 1 else None
            except Exception: # Decoding errors, handle as needed
                encryption_method = None
                password = None

            query_params = parse_qs(parsed_url.query)
            plugin = query_params.get('plugin', [None])[0]

            return cls(
                config_string=config_string,
                protocol="ss",
                address=address,
                port=port,
                encryption_method=encryption_method,
                password=password,
                plugin=plugin
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method, self.password, self.plugin))

    def __eq__(self, other):
        if not isinstance(other, SsParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.encryption_method, self.password, self.plugin) == \
               (other.encryption_method, other.password, other.plugin)


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
        return None
    except Exception:
        return None

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a single channel URL with retry logic."""
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT_SEC)
    while retries_attempted <= MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout) as response:
                if response.status == 200:
                    text = await response.text(encoding='utf-8', errors='ignore')
                    return text.splitlines(), "success"
                else:
                    colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул статус {response.status}")
                    return [], "warning" # Treat as warning, don't retry immediately for HTTP errors
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{MAX_RETRIES+1}): {e}. Пауза {retry_delay} сек")
            if retries_attempted == MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Макс. попыток ({MAX_RETRIES+1}) исчерпано для {channel_url}")
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1
    return [], "critical" # Should not reach here, but for type hinting

def parse_and_filter_proxies_sync(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters valid proxy configurations from lines with protocol-specific parsing (SYNCHRONOUS version). Returns list of configs to resolve."""
    parsed_configs = []
    configs_to_resolve = [] # NOW just holding config objects *before* async DNS resolution
    unique_configs = set()

    for line in lines: # Первый проход: парсим и собираем на разрешение
        line = line.strip()
        if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
            continue

        protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)
        if protocol:
            if protocol == "vless://":
                parsed_config = VlessParsedConfig.from_url(line)
            elif protocol == "tuic://":
                parsed_config = TuicParsedConfig.from_url(line)
            elif protocol == "hy2://":
                parsed_config = Hy2ParsedConfig.from_url(line)
            elif protocol == "ss://":
                parsed_config = SsParsedConfig.from_url(line)
            else:
                parsed_config = ProxyParsedConfig.from_url(line) # Fallback for unknown protocols in ALLOWED_PROTOCOLS

            if parsed_config and parsed_config not in unique_configs:
                unique_configs.add(parsed_config) # Дедупликация на раннем этапе
                configs_to_resolve.append(parsed_config)

    # Instead of resolving here synchronously, just return list of configurations to be resolved.
    return configs_to_resolve # Just return configs needing resolution now - NO DNS resolution happens here anymore.


async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Asynchronously parses and filters proxies using thread pool for CPU-bound parsing AND doing async DNS resolution in main loop."""

    # First, parse SYNCHRONOUSLY in the thread pool and prepare list of configs to resolve (address strings).
    parsed_configs_unresolved = await asyncio.get_running_loop().run_in_executor(
        CPU_BOUND_EXECUTOR,
        parse_and_filter_proxies_sync, # Calling sync function DIRECTLY now
        lines,
        resolver, # Passing resolver argument as well.
    )

    async def resolve_single_config(config): # inner async function for single config resolution.
        resolved_ip = await resolve_address(config.address, resolver) # async DNS resolution now in main loop
        if resolved_ip and is_valid_ipv4(resolved_ip):
            return config, resolved_ip
        return config, None

    # Now perform the ASYNCHRONOUS DNS resolution for all the extracted configs in the MAIN event loop.
    resolution_tasks = [resolve_single_config(config) for config in parsed_configs_unresolved]
    resolution_results_async = await asyncio.gather(*resolution_tasks) # Run async resolution in main loop

    parsed_configs_resolved = []
    seen_ipv4_addresses = set()
    for config, resolved_ip in resolution_results_async: # process results as before.
        if resolved_ip:
            if resolved_ip not in seen_ipv4_addresses:
                parsed_configs_resolved.append(config)
                seen_ipv4_addresses.add(resolved_ip)
            else:
                colored_log(logging.DEBUG, f"ℹ️  Пропущен дубликат прокси по IPv4: {resolved_ip} (протокол: {config.protocol})")
        else:
            colored_log(logging.DEBUG, f"ℹ️  Пропущен прокси без IPv4: {config.address} (протокол: {config.protocol})")

    return parsed_configs_resolved


def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves all downloaded proxies to the output file with protocol names (including duplicates) in text format."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            protocol_grouped_proxies = defaultdict(list)
            for proxy_conf in all_proxies:
                protocol_grouped_proxies[proxy_conf.protocol].append(proxy_conf)

            for protocol in ["vless", "tuic", "hy2", "ss"]: # сохраняем в нужном порядке
                if protocol in protocol_grouped_proxies:
                    protocol_name = ProfileName[protocol.upper()].value
                    colored_log(logging.INFO, f"\n📝 Протокол ({LogColors.CYAN}{protocol_name}{LogColors.RESET}, всего, уникальные IPv4):")
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        # Красивое и компактное именование
                        proxy_name_parts = [f"{LogColors.CYAN}{protocol_name}{LogColors.RESET}"] # Начинаем с протокола в цвете
                        proxy_name_parts.append(f"{LogColors.GREEN}{proxy_conf.address}:{proxy_conf.port}{LogColors.RESET}") # IP:PORT зеленым

                        if isinstance(proxy_conf, VlessParsedConfig) and proxy_conf.sni:
                            proxy_name_parts.append(f"sni:{LogColors.YELLOW}{proxy_conf.sni}{LogColors.RESET}") # sni желтым
                        if isinstance(proxy_conf, SsParsedConfig) and proxy_conf.encryption_method:
                            proxy_name_parts.append(f"enc:{LogColors.MAGENTA}{proxy_conf.encryption_method}{LogColors.RESET}") # enc фиолетовым

                        proxy_name = " ".join(proxy_name_parts) # Разделитель пробел
                        config_line = proxy_conf.config_string + f"#{proxy_name}" # Имя как комментарий
                        f.write(config_line + "\n")
                        colored_log(logging.INFO, f"   - {config_line}") # Выводим в консоль с оформлением
                        total_proxies_count += 1

        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} прокси (всего, уникальные IPv4) в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении всех прокси в файл: {e}")
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from the specified file."""
    channel_urls = []
    try:
        content = await asyncio.to_thread(lambda: open(all_urls_file, 'r', encoding='utf-8').readlines())
        for line in content:
            url = line.strip()
            if url:
                channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"Файл {all_urls_file} не найден. Проверьте наличие файла с URL каналов.")
        await asyncio.to_thread(lambda: open(all_urls_file, 'w').close()) # Create empty file
    return channel_urls


async def main():
    # Set debug level for more detailed logging of skipped proxies (optional)
    logger.setLevel(logging.DEBUG) # or logging.INFO for less verbose

    start_time = time.time()
    channel_urls = await load_channel_urls(ALL_URLS_FILE)
    if not channel_urls:
        colored_log(logging.WARNING, "Нет URL каналов для обработки.")
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
    channels_processed_with_issues = 0 # счетчик каналов, обработанных с предупреждениями или ошибками
    total_proxies_downloaded = 0
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)

    resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)

    async with aiohttp.ClientSession() as session:
        channel_tasks = []
        for channel_url in channel_urls:
            async def process_channel_task(url):
                channel_proxies_count_channel = 0 # Initialize count here
                channel_success = 0 # Initialize success count
                channel_issue = 0 # Initialize issue flag
                async with channel_semaphore:
                    colored_log(logging.INFO, f"🚀 Начало обработки канала: {url}")
                    lines, status = await download_proxies_from_channel(url, session)
                    channel_status_counts[status] += 1
                    if status == "success":
                        parsed_proxies = await parse_and_filter_proxies(lines, resolver) # Now uses thread pool
                        channel_proxies_count_channel = len(parsed_proxies)
                        channel_success = 1 # Mark channel as success after processing
                        for proxy in parsed_proxies:
                            protocol_counts[proxy.protocol] += 1
                        return channel_proxies_count_channel, channel_success, 0, parsed_proxies # Return counts, success flag, no-issue flag and proxies
                    else:
                        colored_log(logging.WARNING, f"⚠️ Канал {url} обработан со статусом: {status}.")
                        channel_issue = 1 # Mark channel as having issues
                        return 0, 0, channel_issue, [] # Return zero counts, no success, issue-flag and empty list for failed channels

            task = asyncio.create_task(process_channel_task(channel_url))
            channel_tasks.append(task)

        channel_results = await asyncio.gather(*channel_tasks)
        all_proxies = []
        for proxies_count, success_flag, issue_flag, proxies_list in channel_results: # Unpack returned values, including issue_flag
            total_proxies_downloaded += proxies_count # Aggregate proxy counts
            channels_processed_successfully += success_flag # Aggregate success flags
            channels_processed_with_issues += issue_flag # Aggregate issue flags
            all_proxies.extend(proxies_list) # Collect proxies

    # Сохранение всех загруженных прокси (включая дубликаты) в отдельный файл
    all_proxies_saved_count = save_all_proxies_to_file(all_proxies, OUTPUT_ALL_CONFIG_FILE)
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
    colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
    colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")

    success_channels_percent = (channels_processed_successfully / total_channels) * 100 if total_channels else 0
    issue_channels_percent = (channels_processed_with_issues / total_channels) * 100 if total_channels else 0
    failed_channels_count = total_channels - channels_processed_successfully - channels_processed_with_issues # Calculate failed explicitly

    colored_log(logging.INFO, "\n✅ Успешно обработано URL-источников: {} из {} ({:.2f}%)".format(
        channels_processed_successfully, total_channels, success_channels_percent))
    if channels_processed_with_issues > 0:
        colored_log(logging.WARNING, "⚠️ URL-источников с предупреждениями/ошибками: {} из {} ({:.2f}%)".format(
            channels_processed_with_issues, total_channels, issue_channels_percent))
    if failed_channels_count > 0: # If there are genuinely failed channels
        failed_channels_percent = (failed_channels_count / total_channels) * 100 if total_channels else 0
        colored_log(logging.ERROR, f"❌ Не удалось обработать URL-источников: {failed_channels_count} из {total_channels} ({:.2f}%)".format( # Исправленная строка
            failed_channels_count, total_channels, failed_channels_percent))

    colored_log(logging.INFO, "\n✨ Всего найдено уникальных IPv4 прокси-конфигураций: {}".format(total_proxies_downloaded))
    colored_log(logging.INFO, f"📝 Всего (все, уникальные IPv4) прокси-конфигураций сохранено в файл: {} ({})".format(
        all_proxies_saved_count, OUTPUT_ALL_CONFIG_FILE))

    colored_log(logging.INFO, "\n🔬 Разбивка найденных прокси-конфигураций по протоколам (уникальные IPv4):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   Нет статистики по протоколам (прокси не найдены).")

    colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
    colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
