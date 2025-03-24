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
import inspect
import sys
import argparse  # Добавили импорт argparse

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

# --- Настройка улучшенного логирования ---
LOG_FORMAT = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "module": "%(module)s",
    "funcName": "%(funcName)s",
    "lineno": "%(lineno)d",
}
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"  # Формат для консольного вывода
LOG_FILE = 'proxy_downloader.log'  # Имя файла лога

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Обработчик файла (уровень WARNING и выше, формат JSON)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)


class JsonFormatter(logging.Formatter):
    """Форматтер для записи логов в JSON."""

    def format(self, record):
        """Форматирует запись лога в JSON."""
        log_record = LOG_FORMAT.copy()
        log_record["message"] = record.getMessage()
        log_record["level"] = record.levelname
        log_record["process"] = record.process
        log_record["time"] = self.formatTime(record, self.default_time_format)
        log_record["module"] = record.module
        log_record["funcName"] = record.funcName
        log_record["lineno"] = record.lineno
        # Обработка исключений, если есть
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Обработчик консоли (уровень INFO и выше, цветной вывод)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


USE_COLOR_LOGS = True  # Глобальная настройка для цветных логов (можно вынести в config)

def colored_log(level: int, message: str, *args, **kwargs):
    """Выводит сообщение с цветом в зависимости от уровня логирования.
       Цветное логирование можно отключить глобально через USE_COLOR_LOGS.
    """
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD_RED = '\033[1m\033[91m'

    color = RESET
    if USE_COLOR_LOGS:
        if level == logging.INFO:
            color = GREEN
        elif level == logging.WARNING:
            color = YELLOW
        elif level == logging.ERROR:
            color = RED
        elif level == logging.CRITICAL:
            color = BOLD_RED
    else:
        color = RESET  # No color if USE_COLOR_LOGS is False

    # Получаем информацию о вызывающей стороне.  Фрейм стека 1 - это вызывающая сторона colored_log.
    frame = inspect.currentframe().f_back
    pathname = frame.f_code.co_filename
    lineno = frame.f_lineno
    func = frame.f_code.co_name

    formatted_message = f"{color}{message}{RESET}" if USE_COLOR_LOGS else message  # Conditional coloring

    record = logging.LogRecord(
        name=logger.name,
        level=level,
        pathname=pathname,
        lineno=lineno,
        msg=formatted_message,
        args=args,
        exc_info=kwargs.get('exc_info'),
        func=func,
        sinfo=None
    )
    logger.handle(record)


# --- Константы и перечисления ---
class Protocols(Enum):
    """Перечисление поддерживаемых протоколов."""
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"


@dataclass(frozen=True)
class ConfigFiles:
    """Конфигурационные файлы."""
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt"


@dataclass(frozen=True)
class RetrySettings:
    """Настройки повторных попыток."""
    MAX_RETRIES: int = 4
    RETRY_DELAY_BASE: int = 2


@dataclass(frozen=True)
class ConcurrencyLimits:
    """Ограничения параллелизма."""
    MAX_CHANNELS: int = 60
    MAX_PROXIES_PER_CHANNEL: int = 50
    MAX_PROXIES_GLOBAL: int = 50


ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]
CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()

# --- Вспомогательные функции ---

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """
    Проверяет, является ли данная строка допустимым IPv4-адресом.

    Args:
        hostname: Строка для проверки.

    Returns:
        True, если строка является допустимым IPv4-адресом, иначе False.
    """
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False


async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """
    Разрешает имя хоста в IPv4-адрес, используя асинхронный DNS-резолвер.

    Args:
        hostname: Имя хоста для разрешения.
        resolver: Экземпляр aiodns.DNSResolver для выполнения DNS-запросов.

    Returns:
        Строка, представляющая IPv4-адрес, если разрешение успешно, иначе None.
    """
    if is_valid_ipv4(hostname):
        return hostname  # Уже IP-адрес

    try:
        async with asyncio.timeout(10):  # Таймаут DNS разрешения
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            if is_valid_ipv4(resolved_ip):
                return resolved_ip
            else:
                logger.debug(f"DNS resolved {hostname} to non-IPv4: {resolved_ip}") # Debug level
                return None
    except asyncio.TimeoutError:
        logger.debug(f"DNS resolution timeout for {hostname}") # Debug level
        return None
    except aiodns.error.DNSError as e:
        logger.debug(f"DNS resolution error for {hostname}: {e}") # Debug level
        return None
    except Exception as e:
        logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True)
        return None


# --- Структуры данных ---

class ProfileName(Enum):
    """Перечисление для названий профилей прокси."""
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    SSR = "SSR"
    TROJAN = "TROJAN"
    UNKNOWN = "Unknown Protocol"


class InvalidURLError(ValueError):
    """Исключение, выбрасываемое при обнаружении недопустимого URL-адреса."""
    pass


class UnsupportedProtocolError(ValueError):
    """Исключение, выбрасываемое при обнаружении неподдерживаемого протокола."""
    pass


@dataclass(frozen=True, eq=True) # Добавили eq=True для сравнения в списках/множествах
class ProxyParsedConfig:
    """Представляет разобранную конфигурацию прокси."""
    config_string: str
    protocol: str
    address: str
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        """Хеширует конфигурацию для эффективных операций с множествами (дедупликация)."""
        return hash((self.config_string)) # Хешируем по config_string для более точной дедупликации

    def __str__(self):
        """Предоставляет удобное строковое представление объекта."""
        return (f"ProxyConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')")

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """
        Разбирает строку конфигурации прокси (URL) в объект ProxyParsedConfig.

        Поддерживает base64-декодирование для строк, не начинающихся со стандартных протоколов.

        Args:
            config_string: Строка конфигурации прокси (URL).

        Returns:
            Объект ProxyParsedConfig, если разбор успешен, иначе None.

        Raises:
            ValueError: Если URL не может быть разобран или порт не является числом.
        """
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p + "://")), None)
        if not protocol:
            # Попытка декодировать base64, если это не стандартный URL
            try:
                decoded_config = base64.b64decode(config_string).decode('utf-8')
                protocol = next((p for p in ALLOWED_PROTOCOLS if decoded_config.startswith(p + "://")), None)
                if protocol:
                    config_string = decoded_config # Используем декодированную строку
                else:
                    logger.debug(f"Unsupported protocol after base64 decode: {config_string}") # Debug level
                    return None
            except (ValueError, UnicodeDecodeError) as e: # Ловим конкретные исключения base64
                logger.debug(f"Base64 decode error for '{config_string}': {e}") # Debug level
                return None

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                logger.debug(f"Could not extract address or port from URL: {config_string}") # Debug level
                return None

            if not 1 <= port <= 65535:  # Валидация порта
                logger.debug(f"Invalid port number: {port} in URL: {config_string}") # Debug level
                return None

            remark = parsed_url.fragment if parsed_url.fragment else ""
            query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()} if parsed_url.query else {}

            return cls(
                config_string=config_string.split("#")[0], # Убираем исходное примечание из config_string
                protocol=protocol,
                address=address,
                port=port,
                remark=remark,
                query_params=query_params,
            )

        except ValueError as e:
            logger.debug(f"URL parsing error for '{config_string}': {e}") # Debug level
            return None


# --- Основная логика ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """
    Загружает конфигурации прокси из одного URL-адреса канала.

    Выполняет повторные попытки при ошибках сети или HTTP, обрабатывает base64-контент.

    Args:
        channel_url: URL-адрес канала для загрузки прокси.
        session: Асинхронная HTTP-сессия aiohttp.ClientSession.

    Returns:
        Кортеж: (список строк конфигурации прокси, строка статуса).
        Статус может быть: "success", "warning", "error", "critical".
    """
    headers = {'User-Agent': 'ProxyDownloader/1.0'}
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=15)

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout, headers=headers) as response:
                response.raise_for_status()
                text = await response.text(encoding='utf-8', errors='ignore')

                if not text.strip():
                    colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул пустой ответ.")
                    return [], "warning"

                try:
                    decoded_text = base64.b64decode(text.strip()).decode('utf-8')
                    return decoded_text.splitlines(), "success"
                except:
                    return text.splitlines(), "success"

        except aiohttp.ClientResponseError as e:
            colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул HTTP ошибку {e.status}: {e.message}")
            return [], "warning"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {e}. Повтор через {retry_delay} сек...")
            if retries_attempted == RETRY.MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Достигнуто максимальное количество попыток ({RETRY.MAX_RETRIES+1}) для {channel_url}")
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1

    return [], "critical"


async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """
    Разбирает и фильтрует конфигурации прокси из списка строк.

    Выполняет разрешение имен хостов в IP-адреса, удаляет дубликаты и неверные конфигурации.

    Args:
        lines: Список строк, содержащих конфигурации прокси.
        resolver: Асинхронный DNS-резолвер aiodns.DNSResolver.

    Returns:
        Список объектов ProxyParsedConfig после разбора и фильтрации.
    """
    parsed_configs: List[ProxyParsedConfig] = [] # Явное указание типа
    processed_configs: Set[str] = set() # Set для config_string

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            parsed_config = ProxyParsedConfig.from_url(line)
            if parsed_config is None:
                logger.debug(f"Skipping invalid proxy URL: {line}") # Debug level
                continue

            resolved_ip = await resolve_address(parsed_config.address, resolver)

            if parsed_config.config_string in processed_configs:
                logger.debug(f"Skipping duplicate proxy: {parsed_config.config_string}") # Debug level
                continue
            processed_configs.add(parsed_config.config_string)

            if resolved_ip:
                parsed_configs.append(parsed_config)

        except Exception as e: #  Ловим более общие исключения, чтобы не прервать обработку других строк
            logger.error(f"Unexpected error parsing proxy URL '{line}': {e}", exc_info=True) # Логируем unexpected errors
            continue # Continue to next line

    return parsed_configs


def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    """
    Генерирует имя профиля прокси на основе протокола и параметров запроса.

    Args:
        proxy_config: Объект ProxyParsedConfig.

    Returns:
        Строка, представляющая имя профиля прокси.
    """
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', 'unknown').lower()
    security = proxy_config.query_params.get('security', 'none').lower()

    if protocol == 'SS' and type_ == 'unknown':
        type_ = 'tcp'

    return f"{protocol}_{type_}_{security}"


def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """
    Сохраняет все конфигурации прокси в файл, удаляя дубликаты перед сохранением.

    Args:
        all_proxies: Список объектов ProxyParsedConfig для сохранения.
        output_file: Путь к файлу для сохранения прокси.

    Returns:
        Количество сохраненных прокси.
    """
    total_proxies_count = 0
    unique_proxies: List[ProxyParsedConfig] = [] # Явное указание типа
    seen_config_strings: Set[str] = set()

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        for proxy_conf in all_proxies:
            if proxy_conf.config_string not in seen_config_strings:
                unique_proxies.append(proxy_conf)
                seen_config_strings.add(proxy_conf.config_string)

        with open(output_file, 'w', encoding='utf-8') as f:
            for proxy_conf in unique_proxies:
                profile_name = generate_proxy_profile_name(proxy_conf)
                config_line = f"{proxy_conf.config_string}#{profile_name}"
                f.write(config_line + "\n")
                total_proxies_count += 1

    except Exception as e:
        logger.error(f"Error saving proxies to file '{output_file}': {e}", exc_info=True) # Added filename to log
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """
    Загружает URL-адреса каналов из файла.

    Создает файл, если он не существует.

    Args:
        all_urls_file: Путь к файлу, содержащему URL-адреса каналов.

    Returns:
        Список URL-адресов каналов, загруженных из файла.
    """
    channel_urls: List[str] = [] # Явное указание типа
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ Файл {all_urls_file} не найден. Создаю пустой файл.")
        try:  # Добавлена обработка ошибки создания файла
            open(all_urls_file, 'w').close()
        except Exception as e:
            logger.error(f"Ошибка создания файла {all_urls_file}: {e}", exc_info=True) # Логируем ошибку создания файла
    except Exception as e:
        logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls


async def process_channel_task(channel_url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, protocol_counts: defaultdict[str, int]) -> Tuple[int, str, List[ProxyParsedConfig]]:
    """
    Обрабатывает один URL-адрес канала: загружает, разбирает и фильтрует прокси.

    Args:
        channel_url: URL-адрес канала.
        session: Асинхронная HTTP-сессия aiohttp.ClientSession.
        resolver: Асинхронный DNS-резолвер aiodns.DNSResolver.
        protocol_counts: Словарь для подсчета протоколов.

    Returns:
        Кортеж: (количество найденных прокси, статус обработки, список ProxyParsedConfig).
    """
    colored_log(logging.INFO, f"🚀 Обработка канала: {channel_url}")
    lines, status = await download_proxies_from_channel(channel_url, session)
    if status == "success":
        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
        channel_proxies_count_channel = len(parsed_proxies)
        for proxy in parsed_proxies:
            protocol_counts[proxy.protocol] += 1
        colored_log(logging.INFO, f"✅ Канал {channel_url} обработан. Найдено {channel_proxies_count_channel} прокси.")
        return channel_proxies_count_channel, status, parsed_proxies
    else:
        colored_log(logging.WARNING, f"⚠️ Канал {channel_url} обработан со статусом: {status}.")
        return 0, status, []


async def load_and_process_channels(channel_urls: List[str], session: aiohttp.ClientSession, resolver: aiodns.DNSResolver) -> Tuple[int, int, defaultdict[str, int], List[ProxyParsedConfig], defaultdict[str, int]]:
    """
    Загружает и обрабатывает все URL-адреса каналов, используя асинхронный параллелизм.

    Args:
        channel_urls: Список URL-адресов каналов.
        session: Асинхронная HTTP-сессия aiohttp.ClientSession.
        resolver: Асинхронный DNS-резолвер aiodns.DNSResolver.

    Returns:
        Кортеж: (общее количество загруженных прокси, количество успешно обработанных каналов,
                 счетчик протоколов, список всех прокси, счетчик статусов каналов).
    """
    channels_processed_successfully = 0
    total_proxies_downloaded = 0
    protocol_counts: defaultdict[str, int] = defaultdict(int)
    channel_status_counts: defaultdict[str, int] = defaultdict(int)
    all_proxies: List[ProxyParsedConfig] = []

    channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)
    channel_tasks = []

    for channel_url in channel_urls:
        async def task_wrapper(url): # Wrapper function to manage semaphore and handle exceptions in tasks
            async with channel_semaphore:
                return await process_channel_task(url, session, resolver, protocol_counts) # Pass protocol_counts

        task = asyncio.create_task(task_wrapper(channel_url))
        channel_tasks.append(task)

    channel_results = await asyncio.gather(*channel_tasks) # Await all tasks

    for proxies_count, status, proxies_list in channel_results: # Process results from each channel
        total_proxies_downloaded += proxies_count
        if status == "success":
            channels_processed_successfully += 1
        channel_status_counts[status] += 1 # Count channel statuses
        all_proxies.extend(proxies_list) # Extend list of all proxies

    return total_proxies_downloaded, channels_processed_successfully, protocol_counts, all_proxies, channel_status_counts


def output_statistics(start_time: float, total_channels: int, channels_processed_successfully: int, channel_status_counts: defaultdict[str, int], total_proxies_downloaded: int, all_proxies_saved_count: int, protocol_counts: defaultdict[str, int], output_file: str):
    """
    Выводит статистику загрузки и обработки прокси.

    Args:
        start_time: Время начала выполнения скрипта.
        total_channels: Общее количество URL-источников.
        channels_processed_successfully: Количество успешно обработанных каналов.
        channel_status_counts: Словарь со статусами обработки каналов.
        total_proxies_downloaded: Общее количество найденных конфигураций прокси.
        all_proxies_saved_count: Количество прокси, сохраненных в файл (без дубликатов).
        protocol_counts: Словарь с количеством прокси по протоколам.
        output_file: Путь к файлу, куда были сохранены прокси.
    """
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
    colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
    colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")
    colored_log(logging.INFO, f"✅ Успешно обработано каналов: {channels_processed_successfully}/{total_channels}")

    colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
    for status_key in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            status_text, color = "", "" # Initialize to avoid unbound variable error
            if status_key == "success":
                status_text, color = "УСПЕШНО", '\033[92m'
            elif status_key == "warning":
                status_text, color = "ПРЕДУПРЕЖДЕНИЕ", '\033[93m'
            elif status_key in ["error", "critical"]:
                status_text, color = "ОШИБКА", '\033[91m'
            else:
                status_text, color = status_key.upper(), '\033[0m'

            colored_log(logging.INFO, f"  - {status_text}: {count} каналов")

    colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}")
    colored_log(logging.INFO, f"📝 Всего прокси (все, без дубликатов) сохранено: {all_proxies_saved_count} (в {output_file})")

    colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   Нет статистики по протоколам.")

    colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")


async def main() -> None:
    """
    Основная асинхронная функция для запуска загрузки и обработки прокси.

    Загружает URL-адреса каналов, обрабатывает их параллельно, сохраняет прокси и выводит статистику.
    """
    parser = argparse.ArgumentParser(description="Proxy Downloader Script") # Create argument parser
    parser.add_argument('--nocolorlogs', action='store_true', help='Disable colored console logs') # Add --nocolorlogs flag
    args = parser.parse_args() # Parse arguments

    global USE_COLOR_LOGS # Access global flag
    if args.nocolorlogs: # If flag is set
        USE_COLOR_LOGS = False # Disable colored logs

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        if not channel_urls:
            colored_log(logging.WARNING, "Нет URL-адресов каналов для обработки.")
            return  # Exit if no URLs

        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        async with aiohttp.ClientSession() as session:
            total_proxies_downloaded, channels_processed_successfully, protocol_counts, all_proxies, channel_status_counts = await load_and_process_channels(channel_urls, session, resolver)

        all_proxies_saved_count = save_all_proxies_to_file(all_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        output_statistics(start_time, len(channel_urls), channels_processed_successfully, channel_status_counts, total_proxies_downloaded, all_proxies_saved_count, protocol_counts, CONFIG_FILES.OUTPUT_ALL_CONFIG) # Pass output file

    except Exception as e:
        logger.critical(f"Unexpected error in main(): {e}", exc_info=True)
        sys.exit(1) # Exit with error code on critical error
    finally:
        colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
