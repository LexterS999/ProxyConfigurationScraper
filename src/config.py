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
import json
import functools

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict


# --- Настройка улучшенного логирования ---
LOG_FORMAT = {"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "process": "%(process)s"}
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_downloader.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)

class JsonFormatter(logging.Formatter): # Кастомный JSON formatter
    def format(self, record):
        log_record = LOG_FORMAT.copy()
        log_record["message"] = record.getMessage() # Получаем сообщение
        log_record["level"] = record.levelname
        log_record["process"] = record.process
        log_record["time"] = self.formatTime(record, self.default_time_format) # Форматируем время
        return json.dumps(log_record, ensure_ascii=False) # JSON dump

formatter_file = JsonFormatter() # Используем JSON formatter
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


def colored_log(level, message: str, *args, **kwargs):
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD_RED = '\033[1m\033[91m' # Bold Red

    color = RESET
    if level == logging.INFO:
        color = GREEN
    elif level == logging.WARNING:
        color = YELLOW
    elif level == logging.ERROR:
        color = RED
    elif level == logging.CRITICAL:
        color = BOLD_RED # Используем BOLD_RED

    record = logging.LogRecord(
        name=logger.name,
        level=level,
        pathname='proxy_downloader.py', # Или __file__ если в модуле
        lineno=0, # Можно получить номер строки откуда вызвано, но сейчас 0
        msg=f"{color}{message}{RESET}",
        args=args,
        exc_info=kwargs.get('exc_info'), # Передаем информацию об исключении, если есть
        func='colored_log', # Имя функции
        sinfo=None # Stack info
    )
    logger.handle(record) # Используем handle для обработки LogRecord


# --- Константы ---
from enum import Enum
from dataclasses import dataclass

class Protocols(Enum):
    VLESS = "vless://"
    TUIC = "tuic://"
    HY2 = "hy2://"
    SS = "ss://"

@dataclass(frozen=True)
class ConfigFiles:
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt"

@dataclass(frozen=True)
class RetrySettings:
    MAX_RETRIES: int = 4
    RETRY_DELAY_BASE: int = 2

@dataclass(frozen=True)
class ConcurrencyLimits:
    MAX_CHANNELS: int = 60
    MAX_PROXIES_PER_CHANNEL: int = 50
    MAX_PROXIES_GLOBAL: int = 50

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]
CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()

OUTPUT_ALL_CONFIG_FILE = os.path.join("configs", "proxy_configs_all.txt")
ALL_URLS_FILE = "channel_urls.txt" # Или os.path.join(".") для текущей директории


class ProfileName(Enum):
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    UNKNOWN = "Unknown Protocol"

class InvalidURLError(ValueError):
    """Исключение, выбрасываемое при обнаружении невалидного URL."""
    pass

class UnsupportedProtocolError(ValueError):
    """Исключение, выбрасываемое при обнаружении неподдерживаемого протокола."""
    pass

@dataclass(frozen=True)
class ProxyParsedConfig:
    config_string: str
    protocol: str
    address: str
    port: int

    def __hash__(self):
        return hash((self.protocol, self.address, self.port))

    def __str__(self):
        return f"ProxyConfig(protocol={self.protocol}, address={self.address}, port={self.port}, config_string='{self.config_string[:50]}...')" # Обрезаем config_string для краткости

    @classmethod
    def from_url(cls, config_string: str) -> "ProxyParsedConfig": # Убираем Optional, выбрасываем исключение
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
        if not protocol:
            raise UnsupportedProtocolError(f"Неподдерживаемый протокол в URL: {config_string}") # Выбрасываем исключение

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                raise InvalidURLError(f"Не удалось извлечь адрес или порт из URL: {config_string}") # Выбрасываем исключение
            return cls(
                config_string=config_string,
                protocol=protocol.replace("://", ""),
                address=address,
                port=port
            )
        except ValueError as e:
            raise InvalidURLError(f"Ошибка при парсинге URL: {config_string}. Ошибка: {e}") from e # Пробрасываем исключение с контекстом


async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Resolves a hostname to an IPv4 address using DNS."""
    if is_valid_ipv4(hostname):
        return hostname
    try:
        async with asyncio.timeout(10): # Добавляем таймаут 10 секунд
            result = await resolver.query(hostname, 'A')
            resolved_address = result[0].host
            if is_valid_ipv4(resolved_address):
                return resolved_address
            else:
                colored_log(logging.WARNING, f"⚠️ DNS resolved {hostname} to non-IPv4 address: {resolved_address}") # Логируем не-IPv4
                return None
    except asyncio.TimeoutError:
        colored_log(logging.WARNING, f"⚠️ DNS resolution timed out for {hostname}") # Логируем таймаут
        return None
    except aiodns.error.DNSError as e:
        colored_log(logging.WARNING, f"⚠️ DNS resolution failed for {hostname}: {e}") # Более информативное сообщение
        return None
    except Exception as e: # Ловим все остальные исключения
        logger.error(f"Неожиданная ошибка при DNS resolution для {hostname}: {e}", exc_info=True) # Логируем с traceback
        return None

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли hostname валидным IPv4 адресом."""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a single channel URL with retry logic."""
    headers = {'User-Agent': 'ProxyDownloader/1.0'} # Добавляем User-Agent
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=15)
    while retries_attempted <= RETRY.MAX_RETRIES: # Используем константу из RetrySettings
        try:
            async with session.get(channel_url, timeout=session_timeout, headers=headers) as response: # Передаем headers в get
                response.raise_for_status() # Выбросит исключение для ошибок 4xx и 5xx
                text = await response.text(encoding='utf-8', errors='ignore')
                return text.splitlines(), "success"
        except aiohttp.ClientResponseError as e: # Ловим именно ClientResponseError
            colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул HTTP ошибку {e.status}: {e.message}")
            return [], "warning" # Treat as warning, don't retry immediately for HTTP errors
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted) # Используем константу
            colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {e}. Пауза {retry_delay} сек")
            if retries_attempted == RETRY.MAX_RETRIES: # Используем константу
                colored_log(logging.ERROR, f"❌ Макс. попыток ({RETRY.MAX_RETRIES+1}) исчерпано для {channel_url}")
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1
    return [], "critical" # Should not reach here, but for type hinting

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters valid proxy configurations from lines, resolving addresses."""
    parsed_configs = []
    for line in lines:
        line = line.strip()
        if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
            continue
        try:
            parsed_config = ProxyParsedConfig.from_url(line) # from_url теперь выбрасывает исключения
        except (InvalidURLError, UnsupportedProtocolError) as e: # Ловим наши исключения
            colored_log(logging.WARNING, f"⚠️ Ошибка парсинга URL '{line}': {e}") # Логируем ошибку парсинга
            continue # Переходим к следующей строке
        if parsed_config:
            resolved_ip = await resolve_address(parsed_config.address, resolver)
            if resolved_ip:
                 parsed_configs.append(parsed_config)
    return parsed_configs

def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves all downloaded proxies to the output file, grouped by protocol."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            protocol_grouped_proxies = defaultdict(list)
            for proxy_conf in all_proxies:
                protocol_grouped_proxies[proxy_conf.protocol].append(proxy_conf)

            for protocol_name in ProfileName: # Итерируемся по Enum ProfileName
                protocol = protocol_name.name.lower() # Получаем имя протокола в нижнем регистре
                if protocol in protocol_grouped_proxies:
                    colored_log(logging.INFO, f"\n📝 Протокол (все): {protocol_name.value}") # Используем value из Enum
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        config_line = proxy_conf.config_string + f"#{protocol_name.value}" # Используем value из Enum
                        f.write(config_line + "\n")
                        colored_log(logging.INFO, f"   ➕ Добавлен прокси (все): {config_line}")
                        total_proxies_count += 1
        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} прокси (все) в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении всех прокси в файл: {e}", exc_info=True)
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
        colored_log(logging.WARNING, f"⚠️ Файл {all_urls_file} не найден. Проверьте наличие файла с URL каналов в директории скрипта.") # Уточняем сообщение
        open(all_urls_file, 'w').close() # Create empty file if not exists
    except Exception as e: # Ловим другие возможные ошибки открытия файла
        logger.error(f"Ошибка при открытии файла {all_urls_file}: {e}", exc_info=True) # Логируем с traceback
    return channel_urls


async def main():
    """Main function to download and process proxy configurations."""
    try:
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
        global_proxy_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_PROXIES_GLOBAL) # Используем константу
        channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS) # Используем константу

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
        end_time = time.time()
        elapsed_time = end_time - start_time

        colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
        colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
        colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")
        colored_log(logging.INFO, f"✅ Успешно обработано каналов: {channels_processed_successfully}/{total_channels}") # Добавляем статистику успешных каналов

        colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
        for status in ["success", "warning", "error", "critical"]:
            count = channel_status_counts.get(status, 0)
            if count > 0:
                status_text = status.upper()
                color = '\033[92m' if status == "success" else ('\033[93m' if status == "warning" else ('\033[91m' if status in ["error", "critical"] else '\033[0m'))
                colored_log(logging.INFO, f"  - {color}{status_text}\033[0m: {count} каналов")

        colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}")
        colored_log(logging.INFO, f"📝 Всего прокси (все) сохранено: {all_proxies_saved_count} (в {OUTPUT_ALL_CONFIG_FILE})")


        colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
        if protocol_counts:
            for protocol, count in protocol_counts.items():
                colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
        else:
            colored_log(logging.INFO, "   Нет статистики по протоколам.")

        colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")

    except Exception as e:
        logger.critical(f"Неожиданная ошибка в main(): {e}", exc_info=True) # Логируем критическую ошибку с traceback
    finally: # Гарантируем вывод "Загрузка и обработка прокси завершена." даже при ошибке
        colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
