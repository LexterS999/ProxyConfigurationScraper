import asyncio
import aiodns
import os
import logging
import ipaddress
import time
import json
import functools
import random # Для jitter
import binascii # Для обработки ошибок base64.decode
from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp
from collections import defaultdict
import base64

# --- Настройка логирования (БЕЗ coloredlogs, ручной цветной вывод) ---

LOG_FILE = 'proxy_downloader.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Обработчик файла (уровень WARNING и выше, формат JSON)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)

class JsonFormatter(logging.Formatter):
    """Форматтер для записи логов в JSON."""
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.default_time_format),
            "level": record.levelname,
            "message": record.getMessage(),
            "process": record.process,
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
            log_record['exc_text'] = '\n'.join(traceback.format_exception(*record.exc_info)) # Добавляем exc_text
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Обработчик консоли (уровень INFO, РУЧНОЙ цветной вывод)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

class ColoredFormatter(logging.Formatter):
    """Форматтер для цветного вывода в консоль (ручная реализация)."""

    RESET = '\033[0m'
    RED   = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    CYAN  = '\033[36m'
    BOLD    = '\033[1m'

    FORMATS = {
        logging.DEBUG:    CYAN + "%(levelname)s" + RESET + ": %(message)s",
        logging.INFO:     GREEN + "%(levelname)s" + RESET + ": %(message)s",
        logging.WARNING:  YELLOW + "%(levelname)s" + RESET + ": %(message)s",
        logging.ERROR:    RED + "%(levelname)s" + RESET + ": %(message)s",
        logging.CRITICAL: BOLD + RED + "%(levelname)s" + RESET + ": %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

formatter_console = ColoredFormatter()
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)

# --- Константы и перечисления ---
class Protocols(str, Enum):
    """Перечисление поддерживаемых протоколов прокси."""
    VLESS = "vless"  # Протокол VLESS
    TUIC = "tuic"    # Протокол TUIC
    HY2 = "hy2"     # Протокол HY2
    SS = "ss"       # Протокол Shadowsocks
    SSR = "ssr"     # Протокол ShadowsocksR
    TROJAN = "trojan" # Протокол Trojan

@dataclass(frozen=True)
class ConfigFiles:
    """Конфигурация файлов."""
    ALL_URLS: str = "channel_urls.txt"  # Файл со списком URL каналов
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt" # Файл для сохранения всех конфигураций прокси

@dataclass(frozen=True)
class RetrySettings:
    """Настройки повторных попыток."""
    MAX_RETRIES: int = 4  # Максимальное количество повторных попыток
    RETRY_DELAY_BASE: int = 2 # Базовая задержка между попытками (в секундах)

@dataclass(frozen=True)
class ConcurrencyLimits:
    """Лимиты конкурентности."""
    MAX_CHANNELS: int = 60 # Максимальное количество каналов для одновременной обработки (не используется в текущей версии, но можно использовать в будущем)
    MAX_PROXIES_PER_CHANNEL: int = 50 # Максимальное количество одновременных запросов к одному каналу
    MAX_PROXIES_GLOBAL: int = 50 # Глобальный лимит на количество прокси (не используется в текущей версии)

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]
CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()
USER_AGENT = 'ProxyDownloader/1.1' # User-Agent для HTTP-запросов
SESSION_TIMEOUT_SEC = 15 # Общий таймаут для HTTP-сессии (в секундах)

# --- Пользовательские исключения ---
class InvalidURLError(ValueError):
    """Недопустимый URL-адрес."""
    def __init__(self, url: str, message="Invalid URL format"):
        self.url = url
        super().__init__(f"{message}: {url}")

class UnsupportedProtocolError(ValueError):
    """Неподдерживаемый протокол.""" # Не используется явно в коде, но можно использовать в будущем
    pass

class DownloadError(Exception):
    """Ошибка загрузки."""
    pass

# --- Структуры данных ---
@dataclass(frozen=True)
class ProxyParsedConfig:
    """Структура для хранения разобранной конфигурации прокси."""
    config_string: str # Исходная строка конфигурации
    protocol: str      # Протокол прокси
    address: str       # Адрес прокси (hostname или IP)
    port: int          # Порт прокси
    remark: str = ""     # Remark (комментарий) из URL, если есть
    query_params: Dict[str, str] = field(default_factory=dict) # Query параметры из URL

    def __hash__(self):
        """Хэширование на основе config_string для дедупликации."""
        return hash(self.config_string) # Хэшируем config_string целиком для полной дедупликации

    def __str__(self):
        """Информативное строковое представление объекта."""
        return (f"ProxyConfig({self.address}:{self.port}, protocol={self.protocol}, " # address:port в начале
                f"config_string='{self.config_string[:50]}...')") # config_string обрезается для краткости

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """Разбирает строку конфигурации прокси в объект ProxyParsedConfig.

        Выполняет следующие шаги:
        1. Проверяет длину строки конфигурации.
        2. Определяет протокол.
        3. Декодирует base64, если необходимо.
        4. Парсит URL.
        5. Извлекает адрес, порт, remark и query параметры.
        6. Валидирует порт.

        Args:
            config_string: Строка конфигурации прокси.

        Returns:
            Объект ProxyParsedConfig или None, если разбор не удался.
        """
        max_config_len = 1024 # Максимальная длина config_string
        if len(config_string) > max_config_len:
            logger.warning("Пропускаем слишком длинный URL ( > %s символов): %s...", max_config_len, config_string[:70], stacklevel=2) # Лог с укороченной строкой
            return None

        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p + "://")), None)
        decoded_by_base64 = False # Флаг, был ли URL декодирован из base64

        if not protocol:
            try:
                decoded_config = base64.b64decode(config_string, validate=True).decode('utf-8', errors='ignore')
                protocol = next((p for p in ALLOWED_PROTOCOLS if decoded_config.startswith(p + "://")), None)
                if protocol:
                    config_string = decoded_config
                    decoded_by_base64 = True
                else:
                    return None # После base64 декодирования протокол все равно не найден
            except binascii.Error as e: # Ловим конкретную ошибку base64 декодирования
                logger.debug("Не удалось декодировать Base64: %s для config: %s...", e, config_string[:50], stacklevel=2) # DEBUG уровень для ошибок декодирования
                return None
            except Exception as e:
                logger.error("Неожиданная ошибка при Base64 декодировании: %s, config: %s...", e, config_string[:50], exc_info=True, stacklevel=2)
                return None

        try:
            parsed_url = urlparse(config_string)
            if not parsed_url.scheme or parsed_url.scheme.lower() not in ('http', 'https') and not decoded_by_base64: # Проверка схемы URL, если не base64 декодировано
                logger.debug("Пропускаем URL с недопустимой схемой: %s, схема: %s", config_string, parsed_url.scheme, stacklevel=2)
                return None
            address = parsed_url.hostname
            port = parsed_url.port

            if not address:
                logger.debug("Пропущен URL без адреса хоста: %s", config_string, stacklevel=2)
                return None
            if port is None:
                logger.debug("Пропущен URL без порта: %s", config_string, stacklevel=2)
                return None

            if not isinstance(port, int) or not (1 <= port <= 65535): # Явная проверка порта на число и диапазон
                logger.debug("Пропущен URL с неверным портом: %s, порт: %s", config_string, port, stacklevel=2)
                return None

            remark = parsed_url.fragment if parsed_url.fragment else ""
            query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()} if parsed_url.query else {}

            return cls(
                config_string=parsed_url.geturl().split("#")[0], # Используем geturl для сохранения структуры URL, удаляем fragment
                protocol=protocol,
                address=address,
                port=port,
                remark=remark,
                query_params=query_params,
            )
        except ValueError as e: # Ловим ValueError от urlparse, если URL совсем невалидный
            logger.debug("Ошибка разбора URL: %s, ошибка: %s", config_string, e, stacklevel=2)
            return None
        except Exception as e:
            logger.error("Неожиданная ошибка при разборе URL: %s, ошибка: %s", config_string, e, exc_info=True, stacklevel=2)
            return None

# --- Вспомогательные функции ---

@functools.lru_cache(maxsize=1024)
def is_valid_ip_address(hostname: str) -> bool:
    """Проверяет, является ли строка допустимым IPv4 или IPv6-адресом."""
    try:
        ipaddress.ip_address(hostname) # Поддержка IPv4 и IPv6
        return True
    except ValueError:
        return False

@functools.lru_cache(maxsize=128) # Кэшируем результаты DNS резолва
async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Разрешает имя хоста в IPv4-адрес, используя DNS-кэширование."""
    if is_valid_ip_address(hostname): # Проверяем IP-адрес в начале
        return hostname

    try:
        async with asyncio.timeout(10): # Таймаут 10 секунд на DNS-запрос (можно вынести в константу)
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            return resolved_ip if is_valid_ip_address(resolved_ip) else None # Проверяем, что резолвится в IP
    except asyncio.TimeoutError as e:
        logger.debug("Timeout при DNS запросе для %s: %s", hostname, e, stacklevel=2) # Debug уровень для таймаутов DNS
        return None
    except aiodns.error.DNSError as e:
        logger.debug("DNS ошибка для %s: %s, код ошибки: %s, имя ошибки: %s", hostname, e, e.args[0], e.args[1], stacklevel=2) # Детальный лог DNS ошибок
        return None
    except Exception as e:
        logger.error("Неожиданная ошибка при DNS разрешении для %s: %s", hostname, e, exc_info=True, stacklevel=2)
        return None

# --- Функции загрузки и обработки ---
async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession, channel_proxy_semaphore: asyncio.Semaphore) -> Tuple[List[str], str]:
    """Загружает конфигурации прокси из одного URL-адреса канала.

    Выполняет HTTP GET запрос к URL канала, обрабатывает ошибки,
    повторные попытки и декодирование base64 (если необходимо).

    Args:
        channel_url: URL-адрес канала.
        session: aiohttp.ClientSession для выполнения запросов.
        channel_proxy_semaphore: Семафор для ограничения параллельных запросов к каналу.

    Returns:
        Кортеж из списка строк (конфигурации прокси) и статуса ("success", "warning", "error", "critical").
    """
    headers = {'User-Agent': USER_AGENT} # Используем константу USER_AGENT
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=SESSION_TIMEOUT_SEC) # Используем константу SESSION_TIMEOUT_SEC

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            async with channel_proxy_semaphore: # Ограничиваем кол-во одновременных запросов к каналу
                async with session.get(channel_url, timeout=session_timeout, headers=headers) as response:
                    response.raise_for_status() # Вызываем исключение для HTTP ошибок
                    text = await response.text(encoding='utf-8', errors='ignore')

                    if not text.strip():
                        logger.warning("Канал %s вернул пустой ответ.", channel_url, stacklevel=2)
                        return [], "warning"

                    try:
                        decoded_text = base64.b64decode(text.strip(), validate=True).decode('utf-8', errors='ignore')
                        return decoded_text.splitlines(), "success"
                    except binascii.Error as e: # Ловим конкретную ошибку base64
                        logger.debug("Канал %s вернул base64, но декодирование не удалось: %s. Попытка обработки как есть.", channel_url, e, stacklevel=2) # DEBUG уровень
                        return text.splitlines(), "success" # Пытаемся обработать как обычный текст
                    except Exception as e:
                        logger.error("Ошибка при Base64 декодировании ответа от %s: %s", channel_url, e, exc_info=True, stacklevel=2)
                        return text.splitlines(), "success" # Пытаемся обработать как обычный текст

        except aiohttp.ClientResponseError as e: # HTTP ошибки (4xx, 5xx)
            logger.warning("Канал %s вернул HTTP ошибку %s: %s, URL: %s", channel_url, e.status, e.message, e.request_info.url, stacklevel=2) # Логируем URL
            if e.status == 429: # Обработка 429 Too Many Requests (можно добавить доп. логику, если нужно)
                retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** (retries_attempted + 2)) # Увеличиваем задержку для 429
                logger.warning("Сервер вернул 429 для %s. Увеличена задержка до %s сек.", channel_url, retry_delay, stacklevel=2)
            else:
                retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            if retries_attempted == RETRY.MAX_RETRIES:
                logger.error("Достигнуто макс. кол-во попыток (%s) для %s после HTTP ошибки %s", RETRY.MAX_RETRIES+1, channel_url, e.status, stacklevel=2)
                return [], "error"
            await asyncio.sleep(retry_delay + random.uniform(0, 1)) # Добавляем jitter к задержке
        except (aiohttp.ClientError, asyncio.TimeoutError) as e: # Ошибки соединения, таймауты
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            logger.warning("Ошибка при получении %s (попытка %s/%s): %s (%s). Повтор через %s сек...", channel_url, retries_attempted+1, RETRY.MAX_RETRIES+1, e, e.__class__.__name__, retry_delay, stacklevel=2) # Логируем тип ошибки
            if retries_attempted == RETRY.MAX_RETRIES:
                logger.error("Достигнуто макс. кол-во попыток (%s) для %s: %s (%s)", RETRY.MAX_RETRIES+1, channel_url, e, e.__class__.__name__, stacklevel=2)
                return [], "critical"
            await asyncio.sleep(retry_delay + random.uniform(0, 1)) # Добавляем jitter к задержке
        retries_attempted += 1

    return [], "critical" # Если все попытки исчерпаны

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Разбирает и фильтрует конфигурации прокси из списка строк.

    Выполняет разбор каждой строки в ProxyParsedConfig, фильтрацию
    невалидных конфигураций и разрешение DNS для адреса прокси.

    Args:
        lines: Список строк с конфигурациями прокси.
        resolver: aiodns.DNSResolver для разрешения имен хостов.

    Returns:
        Список объектов ProxyParsedConfig после разбора и фильтрации.
    """
    parsed_configs = []
    processed_configs = set() # Для дедупликации в пределах одного канала
    for line in lines:
        line = line.strip()
        if not line:
            continue

        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config is None:
            logger.debug("Пропускаем неверный прокси URL: %s", line, stacklevel=2) # Логируем строку целиком
            continue

        if parsed_config.config_string in processed_configs:
            continue # Дедупликация в пределах канала
        processed_configs.add(parsed_config.config_string)

        resolved_ip = await resolve_address(parsed_config.address, resolver) # Разрешаем DNS для каждого прокси
        if resolved_ip:
            parsed_configs.append(parsed_config) # Добавляем только если DNS резолвится

    return parsed_configs

PROFILE_NAME_MAPPING = {
    'type': {'tcp': 'TCP', 'udp': 'UDP', 'unknown': 'GEN'},
    'security': {'none': 'None', 'tls': 'TLS', 'reality': 'REALITY', 'unknown': 'GEN'},
}

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig, mapping: Dict = PROFILE_NAME_MAPPING) -> str:
    """Генерирует имя профиля прокси на основе параметров конфигурации.

    Использует PROFILE_NAME_MAPPING для преобразования параметров в части имени.

    Args:
        proxy_config: Объект ProxyParsedConfig.
        mapping: Словарь соответствий для параметров профиля (опционально).

    Returns:
        Строка - имя профиля прокси.
    """
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', 'unknown').lower()
    security = proxy_config.query_params.get('security', 'none').lower()

    type_part = mapping['type'].get(type_, type_.upper()) # Используем mapping или значение в верхнем регистре
    security_part = mapping['security'].get(security, security.upper())

    if protocol == 'SS' and type_ == 'unknown': # Default type for SS
        type_part = 'TCP'

    return f"{protocol}_{type_part}_{security_part}"

async def save_proxies_from_queue(queue: asyncio.Queue, output_file: str) -> int:
    """Сохраняет прокси из очереди в файл (с дедупликацией).

    Читает объекты ProxyParsedConfig из очереди, дедуплицирует их
    и сохраняет в указанный файл в формате: config_string#profile_name.

    Args:
        queue: asyncio.Queue с объектами ProxyParsedConfig.
        output_file: Путь к выходному файлу.

    Returns:
        Количество сохраненных прокси.
    """
    total_proxies_count = 0
    seen_config_strings = set() # Global дедупликация между каналами
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True) # Создаем директорию, если нет
        temp_output_file = output_file + ".tmp" # Временный файл для атомарного сохранения
        with open(temp_output_file, 'w', encoding='utf-8') as f: # Пишем во временный файл
            while True:
                proxy_conf = await queue.get()
                if proxy_conf is None:  # Сигнал остановки
                    break
                if proxy_conf.config_string not in seen_config_strings: # Глобальная дедупликация
                    seen_config_strings.add(proxy_conf.config_string)
                    profile_name = generate_proxy_profile_name(proxy_conf)
                    config_line = f"{proxy_conf.config_string}#{profile_name}"
                    f.write(config_line + "\n")
                    total_proxies_count += 1
                queue.task_done()
        os.replace(temp_output_file, output_file) # Атомарное перемещение временного файла в основной
    except Exception as e:
        logger.error("Ошибка сохранения прокси в файл %s: %s", output_file, e, exc_info=True, stacklevel=2) # Логируем имя файла
    return total_proxies_count

async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Загружает URL-адреса каналов из файла.

    Читает файл построчно, проверяет валидность URL и возвращает список URL-адресов.

    Args:
        all_urls_file: Путь к файлу со списком URL-адресов каналов.

    Returns:
        Список URL-адресов каналов.
    """
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and _is_valid_url(url):  # Проверяем URL на валидность
                    channel_urls.append(url)
                elif url:
                    logger.warning("Пропускаем невалидный URL канала: %s", url, stacklevel=2)
    except FileNotFoundError:
        logger.warning("Файл %s не найден. Создаю пустой файл.", all_urls_file, stacklevel=2) # Уточнение в логе
        open(all_urls_file, 'w').close() # Создаем пустой файл, если не найден
    except Exception as e:
        logger.error("Ошибка открытия/чтения файла %s: %s", all_urls_file, e, exc_info=True, stacklevel=2) # Логируем имя файла
    return channel_urls

def _is_valid_url(url: str) -> bool:
    """Внутренняя функция для проверки URL на валидность.

    Проверяет наличие схемы и домена, а также что схема 'http' или 'https'.

    Args:
        url: URL-адрес для проверки.

    Returns:
        True, если URL валидный, False в противном случае.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.scheme.lower() in ('http', 'https')]) # Проверка схемы на http/https
    except ValueError:
        return False

async def process_channel(url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, proxy_queue: asyncio.Queue, channel_proxy_semaphore: asyncio.Semaphore) -> Tuple[int, bool]:
    """Обрабатывает один URL-адрес канала.

    Загружает прокси из канала, разбирает, фильтрует и добавляет в очередь.

    Args:
        url: URL-адрес канала.
        session: aiohttp.ClientSession для запросов.
        resolver: aiodns.DNSResolver для разрешения имен хостов.
        proxy_queue: asyncio.Queue для добавления объектов ProxyParsedConfig.
        channel_proxy_semaphore: Семафор для ограничения параллельных запросов к каналу.

    Returns:
        Кортеж: (количество найденных прокси, флаг успеха обработки).
    """
    channel_id = url # Используем URL как ID канала (можно заменить на что-то более короткое, если нужно)
    logger.info("🚀 Обработка канала: %s", channel_id, stacklevel=2) # Используем channel_id в логах
    lines, status = await download_proxies_from_channel(url, session, channel_proxy_semaphore)
    if status == "success":
        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
        channel_proxies_count = len(parsed_proxies)
        for proxy in parsed_proxies:
            await proxy_queue.put(proxy)
        logger.info("✅ Канал %s обработан. Найдено %s прокси.", channel_id, channel_proxies_count, stacklevel=2) # Используем channel_id в логах
        return channel_proxies_count, True
    else:
        logger.warning("⚠️ Канал %s обработан со статусом: %s.", channel_id, status, stacklevel=2) # Используем channel_id в логах
        return 0, False

def print_statistics(start_time: float, total_channels: int, channels_processed_successfully: int, total_proxies_downloaded: int, all_proxies_saved_count: int, protocol_counts: Dict[str, int], channel_status_counts: Dict[str, int], output_file: str):
    """Выводит статистику загрузки и обработки прокси.

    Args:
        start_time: Время начала выполнения скрипта.
        total_channels: Общее количество URL-источников.
        channels_processed_successfully: Количество успешно обработанных каналов.
        total_proxies_downloaded: Общее количество найденных конфигураций прокси.
        all_proxies_saved_count: Количество прокси, сохраненных в файл (без дубликатов).
        protocol_counts: Словарь со статистикой по протоколам.
        channel_status_counts: Словарь со статистикой статусов обработки каналов.
        output_file: Путь к файлу, в который сохранены прокси.
    """
    end_time = time.time()
    elapsed_time = end_time - start_time

    logger.info("==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================", stacklevel=2)
    logger.info("⏱️  Время выполнения скрипта: %.2f сек", elapsed_time, stacklevel=2)
    logger.info("🔗 Всего URL-источников: %s", total_channels, stacklevel=2)
    logger.info("✅ Успешно обработано каналов: %s/%s", channels_processed_successfully, total_channels, stacklevel=2)

    logger.info("\n📊 Статус обработки URL-источников:", stacklevel=2)
    for status_key in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            status_text = status_key.upper() # Упрощаем код, status_text определяется напрямую
            logger.info("  - %s: %s каналов", status_text, count, stacklevel=2)

    logger.info("\n✨ Всего найдено конфигураций: %s", total_proxies_downloaded, stacklevel=2)
    logger.info("📝 Всего прокси (все, без дубликатов) сохранено: %s (в %s)", all_proxies_saved_count, output_file, stacklevel=2) # Используем переданный output_file

    logger.info("\n🔬 Разбивка по протоколам (найдено):", stacklevel=2)
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            logger.info("   - %s: %s", protocol.upper(), count, stacklevel=2)
    else:
        logger.info("   Нет статистики по протоколам.", stacklevel=2)

    logger.info("======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================", stacklevel=2)


async def main():
    """Основная функция скрипта.

    Загружает URL-адреса каналов, обрабатывает каждый канал параллельно,
    сохраняет полученные прокси в файл и выводит статистику.
    """
    start_time = time.time()
    channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
    if not channel_urls:
        logger.warning("Нет URL-адресов каналов для обработки.", stacklevel=2)
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
    total_proxies_downloaded = 0
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)

    resolver = aiodns.DNSResolver() # Создаем DNS Resolver
    proxy_queue = asyncio.Queue() # Очередь для прокси
    channel_proxy_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_PROXIES_PER_CHANNEL) # Семафор для ограничения запросов

    try:
        async with aiohttp.ClientSession() as session: # Создаем aiohttp Session
            async with asyncio.TaskGroup() as tg: # TaskGroup для параллельной обработки каналов
                channel_tasks = [tg.create_task(process_channel(url, session, resolver, proxy_queue, channel_proxy_semaphore)) for url in channel_urls]

            channel_results = [task.result() for task in channel_tasks]  # Получаем результаты задач в порядке запуска

            for proxies_count, success_flag in channel_results:
                total_proxies_downloaded += proxies_count
                channels_processed_successfully += int(success_flag) # Явное преобразование bool в int

            await proxy_queue.join()  # Ждем, пока все задачи из очереди не будут выполнены
            await proxy_queue.put(None)  # Сигнал остановки для save_proxies_from_queue
            save_task = asyncio.create_task(save_proxies_from_queue(proxy_queue, CONFIG_FILES.OUTPUT_ALL_CONFIG)) # Запускаем задачу сохранения
            all_proxies_saved_count = await save_task # Ждем завершения сохранения

            # Подсчитываем протоколы после обработки всех каналов и сохранения в файл
            for proxy in [item for q in channel_results for item in (await parse_and_filter_proxies(await download_proxies_from_channel(q[2], session, channel_proxy_semaphore)[0], resolver)) if item]:
               protocol_counts[proxy.protocol] += 1
            channel_status_counts = defaultdict(int, {k: sum(1 for r in channel_results if r[1] == (k == "success")) for k in ["success", "warning", "error", "critical"]})


    except Exception as e: # Ловим все исключения в main
        logger.critical("Неожиданная ошибка в main(): %s", e, exc_info=True, stacklevel=2) # Логируем с traceback
    finally:
        logger.info("✅ Загрузка и обработка прокси завершена.", stacklevel=2)
        print_statistics(start_time, total_channels, channels_processed_successfully, total_proxies_downloaded, all_proxies_saved_count, protocol_counts, channel_status_counts, CONFIG_FILES.OUTPUT_ALL_CONFIG) # Выводим статистику

if __name__ == "__main__":
    import traceback # Импортируем traceback для более полного логирования ошибок в JSON
    asyncio.run(main())
