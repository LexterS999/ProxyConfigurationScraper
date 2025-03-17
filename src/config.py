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

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
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
ALL_URLS_FILE = "channel_urls.txt" # Файл с URL каналов (переименован для ясности)
OUTPUT_CONFIG_FILE = "proxy_configs_unique.txt" # Файл для уникальных прокси (переименован для ясности)
OUTPUT_ALL_CONFIG_FILE = "proxy_configs_all.txt" # Новый файл для всех прокси
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120
MAX_CONCURRENT_PROXIES_GLOBAL = 240

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
        return hash((self.protocol, self.address, self.port))

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
    session_timeout = aiohttp.ClientTimeout(total=15)
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

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters valid proxy configurations from lines."""
    parsed_configs = []
    for line in lines:
        line = line.strip()
        if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
            continue
        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config:
            resolved_ip = await resolve_address(parsed_config.address, resolver)
            if resolved_ip:
                 parsed_configs.append(parsed_config)
    return parsed_configs

def deduplicate_proxies(parsed_proxies: List[ProxyParsedConfig]) -> Dict[str, Set[ProxyParsedConfig]]:
    """Deduplicates proxies based on IP and port within each protocol."""
    unique_proxies_by_protocol = defaultdict(set)
    for proxy in parsed_proxies:
        unique_proxies_by_protocol[proxy.protocol].add(proxy)
    return unique_proxies_by_protocol

def save_proxies_to_file(unique_proxies_by_protocol: Dict[str, Set[ProxyParsedConfig]], output_file: str) -> int:
    """Saves unique proxies to the output file with protocol names."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for protocol in ["vless", "tuic", "hy2", "ss"]: # сохраняем в нужном порядке
                if protocol in unique_proxies_by_protocol:
                    colored_log(logging.INFO, f"\n🛡️  Протокол (уникальные): {ProfileName[protocol.upper()].value}")
                    for proxy_conf in unique_proxies_by_protocol[protocol]:
                        config_line = proxy_conf.config_string + f"#{ProfileName[protocol.upper()].value}"
                        f.write(config_line + "\n")
                        colored_log(logging.INFO, f"   ✨ Добавлен уникальный прокси: {config_line}")
                        total_proxies_count += 1
        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} уникальных прокси в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении уникальных прокси в файл: {e}")
    return total_proxies_count

def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves all downloaded proxies to the output file with protocol names (including duplicates)."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            protocol_grouped_proxies = defaultdict(list)
            for proxy_conf in all_proxies:
                protocol_grouped_proxies[proxy_conf.protocol].append(proxy_conf)

            for protocol in ["vless", "tuic", "hy2", "ss"]: # сохраняем в нужном порядке
                if protocol in protocol_grouped_proxies:
                    colored_log(logging.INFO, f"\n📝 Протокол (все): {ProfileName[protocol.upper()].value}")
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        config_line = proxy_conf.config_string + f"#{ProfileName[protocol.upper()].value}"
                        f.write(config_line + "\n")
                        colored_log(logging.INFO, f"   ➕ Добавлен прокси (все): {config_line}")
                        total_proxies_count += 1
        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} прокси (все) в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении всех прокси в файл: {e}")
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from the specified file."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"Файл {all_urls_file} не найден. Проверьте наличие файла с URL каналов.")
        open(all_urls_file, 'w').close() # Create empty file if not exists
    return channel_urls


async def main():
    start_time = time.time()
    channel_urls = await load_channel_urls(ALL_URLS_FILE)
    if not channel_urls:
        colored_log(logging.WARNING, "Нет URL каналов для обработки.")
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
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
                async with channel_semaphore:
                    colored_log(logging.INFO, f"🚀 Начало обработки канала: {url}")
                    lines, status = await download_proxies_from_channel(url, session)
                    channel_status_counts[status] += 1
                    if status == "success":
                        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
                        channel_proxies_count_channel = len(parsed_proxies)
                        channel_success = 1 # Mark channel as success after processing
                        for proxy in parsed_proxies:
                            protocol_counts[proxy.protocol] += 1
                        colored_log(logging.INFO, f"✅ Канал {url} обработан. Найдено {channel_proxies_count_channel} прокси.")
                        return channel_proxies_count_channel, channel_success, parsed_proxies # Return counts and proxies
                    else:
                        colored_log(logging.WARNING, f"⚠️ Канал {url} обработан со статусом: {status}.")
                        return 0, 0, [] # Return zero counts and empty list for failed channels

            task = asyncio.create_task(process_channel_task(channel_url))
            channel_tasks.append(task)

        channel_results = await asyncio.gather(*channel_tasks)
        all_proxies = []
        for proxies_count, success_flag, proxies_list in channel_results: # Unpack returned values
            total_proxies_downloaded += proxies_count # Aggregate proxy counts
            channels_processed_successfully += success_flag # Aggregate success flags
            all_proxies.extend(proxies_list) # Collect proxies

    # Сохранение всех загруженных прокси (включая дубликаты) в отдельный файл
    all_proxies_saved_count = save_all_proxies_to_file(all_proxies, OUTPUT_ALL_CONFIG_FILE)

    unique_proxies_by_protocol = deduplicate_proxies(all_proxies)
    unique_proxies_saved_count = save_proxies_to_file(unique_proxies_by_protocol, OUTPUT_CONFIG_FILE)

    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
    colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
    colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")

    colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
    for status in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status, 0)
        if count > 0:
            status_text = status.upper()
            color = LogColors.GREEN if status == "success" else (LogColors.YELLOW if status == "warning" else (LogColors.RED if status in ["error", "critical"] else LogColors.RESET))
            colored_log(logging.INFO, f"  - {color}{status_text}{LogColors.RESET}: {count} каналов")

    colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}")
    colored_log(logging.INFO, f"✅ Всего уникальных прокси сохранено: {unique_proxies_saved_count} (в {OUTPUT_CONFIG_FILE})")
    colored_log(logging.INFO, f"📝 Всего прокси (все) сохранено: {all_proxies_saved_count} (в {OUTPUT_ALL_CONFIG_FILE})")


    colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   Нет статистики по протоколам.")

    colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
    colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
