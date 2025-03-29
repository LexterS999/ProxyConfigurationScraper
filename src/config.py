import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import json
import functools
import inspect
import sys
import argparse
import dataclasses
import random  # For jitter
import aiohttp  # Импортируем aiohttp
import base64  # Импортируем base64
import time
import binascii

from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Set, DefaultDict # <-- Уточнил DefaultDict
from dataclasses import dataclass, field
from collections import defaultdict
from string import Template  # For flexible profile names

# --- Constants ---
LOG_FILE = 'proxy_downloader.log'
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FORMAT = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "module": "%(module)s",
    "funcName": "%(funcName)s",
    "lineno": "%(lineno)d",
}

DNS_TIMEOUT = 15  # seconds
HTTP_TIMEOUT = 15  # seconds
MAX_RETRIES = 4
RETRY_DELAY_BASE = 2
HEADERS = {'User-Agent': 'ProxyDownloader/1.0'}
PROTOCOL_REGEX = re.compile(r"^(vless|tuic|hy2|ss|ssr|trojan)://", re.IGNORECASE)
# Простой regex для базовой валидации hostname (допускает буквы, цифры, дефисы, точки)
HOSTNAME_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}")  # Concise profile names

COLOR_MAP = {
    logging.INFO: '\033[92m',    # GREEN
    logging.WARNING: '\033[93m', # YELLOW
    logging.ERROR: '\033[91m',   # RED
    logging.CRITICAL: '\033[1m\033[91m', # BOLD_RED
    'RESET': '\033[0m'
}

QUALITY_SCORE_WEIGHTS = {
    "protocol": {"vless": 5, "trojan": 5, "tuic": 4, "hy2": 3, "ss": 2, "ssr": 1},
    "security": {"tls": 3, "none": 0},
    "transport": {"ws": 2, "websocket": 2, "grpc": 2, "tcp": 1, "udp": 0},
}

QUALITY_CATEGORIES = {
    "High": range(8, 15),
    "Medium": range(4, 8),
    "Low": range(0, 4),
}

# --- Data Structures ---
class Protocols(Enum):
    """Enumeration of supported proxy protocols."""
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]


# --- Logging Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)

class JsonFormatter(logging.Formatter):
    """Formatter for JSON log output."""
    def format(self, record):
        log_record = LOG_FORMAT.copy()
        log_record["message"] = record.getMessage()
        log_record["level"] = record.levelname
        log_record["process"] = record.process
        log_record["time"] = self.formatTime(record, self.default_time_format)
        log_record["module"] = record.module
        log_record["funcName"] = record.funcName
        log_record["lineno"] = record.lineno
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

class ColoredFormatter(logging.Formatter):
    """Formatter for colored console output."""
    def __init__(self, fmt=CONSOLE_LOG_FORMAT, use_colors=True):
        super().__init__(fmt)
        self.use_colors = use_colors

    def format(self, record):
        # Применяем предложенное изменение: сначала форматируем, потом окрашиваем
        message = super().format(record)
        if self.use_colors:
            color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET'])
            color_reset = COLOR_MAP['RESET']
            message = f"{color_start}{message}{color_reset}"
        return message

console_formatter = ColoredFormatter()
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)


def colored_log(level: int, message: str, *args, **kwargs):
    """Logs a message with color to the console using standard logging."""
    # Оставляем эту функцию, т.к. она используется в нескольких местах для цветного вывода
    logger.log(level, message, *args, **kwargs)


# --- Data Structures ---
@dataclass(frozen=True)
class ConfigFiles:
    """Configuration file paths."""
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt"

@dataclass(frozen=True)
class RetrySettings:
    """Settings for retry attempts."""
    MAX_RETRIES: int = MAX_RETRIES
    RETRY_DELAY_BASE: int = RETRY_DELAY_BASE

@dataclass(frozen=True)
class ConcurrencyLimits:
    """Limits for concurrency."""
    MAX_CHANNELS: int = 60
    MAX_PROXIES_PER_CHANNEL: int = 50 # Этот лимит теперь не используется напрямую в коде
    MAX_PROXIES_GLOBAL: int = 50 # Этот лимит теперь не используется напрямую в коде

CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()


class ProfileName(Enum):
    """Enumeration for proxy profile names."""
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    SSR = "SSR"
    TROJAN = "TROJAN"
    UNKNOWN = "Unknown Protocol"

# --- Custom Exceptions ---
class InvalidURLError(ValueError):
    """Exception for invalid URLs."""
    pass

class UnsupportedProtocolError(ValueError):
    """Exception for unsupported protocols."""
    pass

class EmptyChannelError(Exception): # <-- Новое исключение
    """Exception raised when a channel returns an empty response."""
    pass

class DownloadError(Exception): # <-- Новое исключение
    """General exception for download failures (retries exhausted, critical errors)."""
    pass


@dataclass(frozen=True, eq=True)
class ProxyParsedConfig:
    """Represents a parsed proxy configuration."""
    config_string: str
    protocol: str
    address: str
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    quality_score: int = 0 # Будет добавлено позже в resolve_and_assess_proxies

    def __hash__(self):
        """Hashes the configuration string for deduplication."""
        # Хешируем именно config_string, т.к. он используется для дедупликации
        # до этапа резолвинга и оценки
        return hash(self.config_string)

    def __str__(self):
        """String representation of the ProxyConfig object."""
        # Убрали quality_score отсюда, т.к. он добавляется позже
        return (f"ProxyParsedConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')")

    @staticmethod
    def _decode_base64_if_needed(config_string: str) -> Tuple[str, bool]:
        """
        Decodes base64 if the string doesn't start with a known protocol.
        Applies padding and specific error handling.
        """
        if PROTOCOL_REGEX.match(config_string):
            return config_string, False
        try:
            # Убираем пробельные символы, которые могут мешать декодированию
            possible_base64 = "".join(config_string.split())
            # Добавляем padding, если его не хватает
            missing_padding = len(possible_base64) % 4
            if missing_padding:
                possible_base64 += '=' * (4 - missing_padding)

            # Используем validate=True для строгой проверки Base64
            decoded_bytes = base64.b64decode(possible_base64, validate=True)
            decoded_config = decoded_bytes.decode('utf-8')

            if PROTOCOL_REGEX.match(decoded_config):
                return decoded_config, True
            else:
                # Декодировалось, но не похоже на известный протокол
                logger.debug(f"Decoded string doesn't match known protocols: {decoded_config[:50]}...")
                return config_string, False
        except (binascii.Error, UnicodeDecodeError) as e: # <-- Ловим конкретные ошибки
            # Не удалось декодировать как Base64 или UTF-8
            logger.debug(f"Base64/UTF-8 decoding failed for '{config_string[:50]}...': {e}")
            return config_string, False
        except Exception as e:
             # Ловим остальные неожиданные ошибки, но логируем их отдельно
             logger.error(f"Unexpected error decoding base64 for '{config_string[:50]}...': {e}", exc_info=True)
             return config_string, False

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """
        Parses a proxy configuration URL, performs basic validation,
        and handles query parameters safely.
        """
        original_string_for_hash = config_string.strip() # Сохраняем для хеша
        config_string, was_decoded = cls._decode_base64_if_needed(original_string_for_hash)

        protocol_match = PROTOCOL_REGEX.match(config_string)
        if not protocol_match:
            # Логирование уже произошло в _decode_base64_if_needed или это не URL
            # logger.debug(f"Not a valid proxy URL format: {config_string[:100]}...")
            return None
        protocol = protocol_match.group(1).lower()

        try:
            parsed_url = urlparse(config_string)

            # Проверка совпадения схемы (хотя PROTOCOL_REGEX уже проверил начало)
            if parsed_url.scheme.lower() != protocol:
                logger.debug(f"URL scheme '{parsed_url.scheme}' mismatch for protocol '{protocol}': {config_string}")
                return None

            address = parsed_url.hostname
            port = parsed_url.port

            # Базовая валидация адреса/порта
            if not address or not port:
                logger.debug(f"Address or port missing in URL: {config_string}")
                return None

            # <-- Добавлена базовая валидация hostname
            if not is_valid_ipv4(address) and not HOSTNAME_REGEX.match(address):
                 logger.debug(f"Invalid hostname format: {address} in URL: {config_string}")
                 return None

            if not 1 <= port <= 65535:
                logger.debug(f"Invalid port number: {port} in URL: {config_string}")
                return None

            remark = parsed_url.fragment or ""
            # <-- Безопасная обработка query parameters (берем первое значение)
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v} # Убедимся, что список v не пустой

            # Используем original_string_for_hash или config_string без fragment для config_string?
            # Лучше использовать декодированную строку без fragment для консистентности
            config_string_to_store = config_string.split('#')[0]

            return cls(
                config_string=config_string_to_store, # Сохраняем URL без fragment
                protocol=protocol,
                address=address,
                port=port,
                remark=remark,
                query_params=query_params,
                # quality_score будет добавлен позже
            )

        except ValueError as e:
            logger.debug(f"URL parsing error for '{config_string[:100]}...': {e}")
            return None


# --- Helper Functions ---
@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """Checks if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Resolves a hostname to an IPv4 address with timeout and error handling."""
    if is_valid_ipv4(hostname):
        return hostname

    try:
        # Используем asyncio.timeout для таймаута
        async with asyncio.timeout(DNS_TIMEOUT):
            result = await resolver.query(hostname, 'A')
            if result:
                resolved_ip = result[0].host
                if is_valid_ipv4(resolved_ip):
                    logger.debug(f"DNS resolved {hostname} to {resolved_ip}")
                    return resolved_ip
                else:
                    logger.debug(f"DNS resolved {hostname} to non-IPv4: {resolved_ip}")
                    return None
            else:
                 logger.debug(f"DNS query for {hostname} returned no results.")
                 return None
    except asyncio.TimeoutError:
        logger.debug(f"DNS resolution timeout for {hostname}")
        return None
    except aiodns.error.DNSError as e:
        error_code = e.args[0] if e.args else "Unknown"
        # Уточняем логирование для распространенных ошибок
        if error_code == 4: # NXDOMAIN
             logger.debug(f"DNS resolution error for {hostname}: Host not found (NXDOMAIN)")
        elif error_code == 1: # FORMERR
             logger.debug(f"DNS resolution error for {hostname}: Format error (FORMERR)")
        else:
             logger.debug(f"DNS resolution error for {hostname}: {e}, Code: {error_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True)
        return None

def assess_proxy_quality(proxy_config: ProxyParsedConfig) -> int:
    """Assesses proxy quality based on configuration using weights."""
    score = 0
    protocol = proxy_config.protocol.lower()
    query_params = proxy_config.query_params

    score += QUALITY_SCORE_WEIGHTS["protocol"].get(protocol, 0)
    # Используем 'security' из query_params, если есть, иначе 'none'
    security = query_params.get("security", "none").lower()
    score += QUALITY_SCORE_WEIGHTS["security"].get(security, 0)
    # Используем 'type' или 'transport' из query_params, если есть, иначе 'tcp'
    transport = query_params.get("type", query_params.get("transport", "tcp")).lower()
    score += QUALITY_SCORE_WEIGHTS["transport"].get(transport, 0)

    return score

def get_quality_category(score: int) -> str:
    """Determines quality category based on the score."""
    for category, score_range in QUALITY_CATEGORIES.items():
        if score in score_range:
            return category
    return "Unknown" # Или "Low" по умолчанию?

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    """Generates a concise proxy profile name using a template."""
    protocol = proxy_config.protocol.upper()
    # Используем 'type' или 'transport' для имени, отдавая предпочтение 'type'
    type_ = proxy_config.query_params.get('type', proxy_config.query_params.get('transport', 'tcp')).lower()
    security = proxy_config.query_params.get('security', 'none').lower()

    profile_name_values = {
        "protocol": protocol,
        "type": type_,
        "security": security
    }
    # Используем безопасную подстановку, чтобы избежать ошибок при отсутствии ключа
    return PROFILE_NAME_TEMPLATE.safe_substitute(profile_name_values)


# --- Core Logic Functions ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> List[str]:
    """
    Downloads proxy configurations from a channel URL with retry logic.
    Handles Base64 decoding and returns a list of lines or raises exceptions.
    """
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            logger.debug(f"Attempting download from {channel_url} (Attempt {retries_attempted + 1})")
            async with session.get(channel_url, timeout=session_timeout, headers=HEADERS) as response:
                # Выбросит ClientResponseError при 4xx/5xx
                response.raise_for_status()
                logger.debug(f"Successfully connected to {channel_url}, status: {response.status}")

                # Используем read(), чтобы получить байты и определить кодировку надежнее
                content_bytes = await response.read()
                if not content_bytes.strip():
                    logger.warning(f"Channel {channel_url} returned empty response.")
                    raise EmptyChannelError(f"Channel {channel_url} returned empty response.")

                # Попытка определить кодировку (aiohttp делает это автоматически для text(), но можно и вручную)
                text: str
                try:
                    text = content_bytes.decode('utf-8')
                    logger.debug(f"Decoded content from {channel_url} as UTF-8")
                except UnicodeDecodeError:
                    # Попробовать другую кодировку или использовать replace/ignore
                    logger.warning(f"UTF-8 decoding failed for {channel_url}, replacing errors.")
                    text = content_bytes.decode('utf-8', errors='replace') # Используем replace

                # Попытка декодирования Base64 (логика похожа на _decode_base64_if_needed)
                try:
                    possible_base64 = "".join(text.strip().split())
                    missing_padding = len(possible_base64) % 4
                    if missing_padding:
                        possible_base64 += '=' * (4 - missing_padding)

                    decoded_bytes = base64.b64decode(possible_base64, validate=True)
                    decoded_text = decoded_bytes.decode('utf-8')
                    # Проверяем, что результат декодирования похож на прокси-ссылки
                    if PROTOCOL_REGEX.search(decoded_text): # Ищем вхождение, не только в начале
                        logger.debug(f"Content from {channel_url} successfully decoded as Base64.")
                        return decoded_text.splitlines()
                    else:
                        logger.debug(f"Content from {channel_url} decoded from Base64, but no protocol found. Using original text.")
                        return text.splitlines()
                except (binascii.Error, UnicodeDecodeError):
                    # Не Base64 или ошибка декодирования после Base64 -> используем как есть
                    logger.debug(f"Content from {channel_url} is not valid Base64 or UTF-8 after decode. Using as plain text.")
                    return text.splitlines()

        except aiohttp.ClientResponseError as e:
            # Логируем и выбрасываем кастомное исключение
            colored_log(logging.WARNING, f"⚠️ Channel {channel_url} returned HTTP error {e.status}: {e.message}")
            logger.debug(f"Response headers for {channel_url} on error: {response.headers}")
            # Не ретраим на ошибки клиента/сервера (4xx/5xx) - выбрасываем сразу
            raise DownloadError(f"HTTP error {e.status} for {channel_url}") from e
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            # Ошибки соединения, таймауты - ретраим
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted) + random.uniform(-0.5, 0.5)
            retry_delay = max(0.5, retry_delay) # Минимальная задержка
            colored_log(logging.WARNING, f"⚠️ Error getting {channel_url} (attempt {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {type(e).__name__}. Retry in {retry_delay:.2f}s...")
            if retries_attempted == RETRY.MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Max retries ({RETRY.MAX_RETRIES+1}) reached for {channel_url}")
                raise DownloadError(f"Max retries reached for {channel_url}") from e
            await asyncio.sleep(retry_delay)
        except EmptyChannelError as e: # Ловим наше исключение
             # Не ретраим пустой ответ
             raise e # Пробрасываем дальше
        except Exception as e:
             # Неожиданные ошибки - не ретраим, выбрасываем
             logger.error(f"Unexpected error downloading {channel_url}: {e}", exc_info=True)
             raise DownloadError(f"Unexpected error downloading {channel_url}") from e

        retries_attempted += 1

    # Если цикл завершился (не должно произойти при правильной логике)
    logger.critical(f"Download loop finished unexpectedly for {channel_url}")
    raise DownloadError(f"Download failed unexpectedly after retries for {channel_url}")


# --- Разделенные функции парсинга и резолвинга ---

def parse_proxy_lines(lines: List[str]) -> Tuple[List[ProxyParsedConfig], int, int]:
    """
    Parses lines into ProxyParsedConfig objects, performs basic validation,
    and initial deduplication based on the config string.
    Returns: List of parsed configs, count of invalid urls, count of duplicates.
    """
    parsed_configs: List[ProxyParsedConfig] = []
    processed_strings: Set[str] = set() # Для дедупликации по строке конфига
    invalid_url_count = 0
    duplicate_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Используем ProxyParsedConfig.from_url для парсинга и базовой валидации
        parsed_config = ProxyParsedConfig.from_url(line)

        if parsed_config is None:
            # Логирование происходит внутри from_url или _decode_base64
            invalid_url_count += 1
            continue

        # Проверка на дубликат по исходной строке ДО резолвинга
        # Используем config_string, который был сохранен в объекте
        if parsed_config.config_string in processed_strings:
            logger.debug(f"Skipping duplicate proxy (based on string): {parsed_config.config_string[:50]}...")
            duplicate_count += 1
            continue
        processed_strings.add(parsed_config.config_string)

        parsed_configs.append(parsed_config)

    logger.info(f"Initial parsing: {len(parsed_configs)} potentially valid configs found. "
                f"Skipped {invalid_url_count} invalid lines, {duplicate_count} duplicates (string-based).")
    return parsed_configs, invalid_url_count, duplicate_count


async def resolve_and_assess_proxies(
    configs: List[ProxyParsedConfig], resolver: aiodns.DNSResolver
) -> Tuple[List[ProxyParsedConfig], int]:
    """
    Resolves DNS addresses and assesses quality for a list of parsed configs.
    Returns: List of resolved and assessed configs, count of DNS resolution failures.
    """
    resolved_configs_with_score: List[ProxyParsedConfig] = []
    dns_resolution_failed_count = 0

    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal dns_resolution_failed_count
        resolved_ip = await resolve_address(config.address, resolver)
        if resolved_ip:
            # Адрес разрешился, оцениваем качество
            quality_score = assess_proxy_quality(config)
            # Возвращаем новый объект с добавленным score
            # Можно также добавить resolved_ip в объект, если нужно
            return dataclasses.replace(config, quality_score=quality_score)
        else:
            # DNS resolution failed
            logger.debug(f"DNS resolution failed for proxy address: {config.address} from config: {config.config_string[:50]}...")
            dns_resolution_failed_count += 1
            return None

    # Запускаем задачи резолвинга параллельно
    tasks = [resolve_task(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks)

    # Собираем успешные результаты
    resolved_configs_with_score = [res for res in results if res is not None]

    logger.info(f"DNS Resolution & Assessment: {len(resolved_configs_with_score)} configs resolved and assessed. "
                f"{dns_resolution_failed_count} DNS resolution failures.")
    return resolved_configs_with_score, dns_resolution_failed_count


# --- Функция сохранения (переименована и упрощена) ---

def save_unique_proxies_to_file(unique_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """
    Saves a list of unique, assessed proxies to a file.
    Assumes the input list `unique_proxies` is already deduplicated.
    Returns the number of proxies successfully written.
    """
    count = 0
    try:
        # Создаем директорию, если она не существует
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        logger.info(f"Attempting to save {len(unique_proxies)} unique proxies to {output_file}")

        lines_to_write = []
        for proxy_conf in unique_proxies: # Предполагаем, что список уже уникален
            profile_name = generate_proxy_profile_name(proxy_conf)
            quality_category = get_quality_category(proxy_conf.quality_score)
            # Формируем строку с добавлением информации через #
            config_line = (f"{proxy_conf.config_string}#{profile_name}_"
                           f"Q{proxy_conf.quality_score}_{quality_category}\n")
                           # Пример: vless://...@host?params#VLESS-WS-TLS_Q10_High
            lines_to_write.append(config_line)
            count += 1

        # Используем writelines для эффективности
        with open(output_file, 'w', encoding='utf-8') as f:
            f.writelines(lines_to_write)

        logger.info(f"Successfully wrote {count} proxies to {output_file}")

    except IOError as e:
        logger.error(f"IOError saving proxies to file '{output_file}': {e}", exc_info=True)
        return 0 # Возвращаем 0 при ошибке
    except Exception as e:
        logger.error(f"Unexpected error saving proxies to file '{output_file}': {e}", exc_info=True)
        return 0 # Возвращаем 0 при ошибке
    return count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from a file, handling BOM, encoding, and comments."""
    channel_urls: List[str] = []
    try:
        # Используем utf-8-sig для автоматической обработки BOM
        with open(all_urls_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    channel_urls.append(url)
        logger.info(f"Loaded {len(channel_urls)} channel URLs from {all_urls_file}")
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ File {all_urls_file} not found. Creating an empty file.")
        try:
            # Создаем директорию, если нужно
            os.makedirs(os.path.dirname(all_urls_file) or '.', exist_ok=True)
            open(all_urls_file, 'w').close()
        except Exception as e:
            logger.error(f"Error creating file {all_urls_file}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls


# --- Обновленная функция обработки канала ---

async def process_channel_task(channel_url: str, session: aiohttp.ClientSession,
                              resolver: aiodns.DNSResolver
                              ) -> List[ProxyParsedConfig]: # Возвращает только список прокси
    """
    Processes a single channel: downloads, parses, resolves, and assesses proxies.
    Returns a list of valid ProxyParsedConfig objects found in the channel.
    """
    colored_log(logging.INFO, f"🚀 Processing channel: {channel_url}")
    try:
        # Шаг 1: Скачивание (может выбросить DownloadError, EmptyChannelError)
        lines = await download_proxies_from_channel(channel_url, session)

        # Шаг 2: Первичный парсинг и дедупликация строк
        parsed_proxies_basic, _, _ = parse_proxy_lines(lines) # Счетчики пока не используем здесь
        if not parsed_proxies_basic:
             logger.info(f"No potentially valid configs found after parsing {channel_url}")
             return []

        # Шаг 3: Резолвинг DNS и оценка качества
        resolved_proxies, _ = await resolve_and_assess_proxies(parsed_proxies_basic, resolver) # Счетчик DNS ошибок не используем здесь

        channel_proxies_count = len(resolved_proxies)
        colored_log(logging.INFO, f"✅ Channel {channel_url} processed. Found {channel_proxies_count} valid proxies.")
        return resolved_proxies

    except EmptyChannelError:
         colored_log(logging.WARNING, f"⚠️ Channel {channel_url} was empty or returned no parsable content.")
         return [] # Успешно обработан, но пуст
    except DownloadError as e:
         # Ошибка уже залогирована в download_proxies_from_channel
         colored_log(logging.ERROR, f"❌ Failed to process channel {channel_url} after retries: {e}")
         return [] # Ошибка обработки канала
    except Exception as e:
         # Неожиданные ошибки при парсинге/резолвинге
         logger.error(f"Unexpected error processing channel {channel_url}: {e}", exc_info=True)
         return [] # Ошибка обработки канала


# --- Обновленная функция загрузки и обработки каналов ---

async def load_and_process_channels(channel_urls: List[str], session: aiohttp.ClientSession,
                                     resolver: aiodns.DNSResolver
                                     ) -> Tuple[int, int, DefaultDict[str, int], List[ProxyParsedConfig], DefaultDict[str, int], DefaultDict[str, int]]:
    """
    Loads and processes all channel URLs concurrently, performs final deduplication,
    and aggregates statistics.
    Returns:
        - total_proxies_found_before_dedup: Total configs found across all channels before final deduplication.
        - channels_processed_count: Number of channels processed (regardless of success/failure).
        - protocol_counts: Counts of each protocol among unique proxies.
        - all_unique_proxies: List of unique ProxyParsedConfig objects.
        - channel_status_counts: Counts of channel processing outcomes (success, empty_or_failed, critical_error).
        - quality_category_counts: Counts of quality categories among unique proxies.
    """
    channels_processed_count = 0
    total_proxies_found_before_dedup = 0
    # Статусы: success (нашли >0 прокси), empty_or_failed (0 прокси или ошибка скачивания/парсинга), critical_error (ошибка самой задачи)
    channel_status_counts: DefaultDict[str, int] = defaultdict(int)
    all_proxies_nested: List[List[ProxyParsedConfig]] = [] # Список списков прокси с каждого канала

    channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)

    async def task_wrapper(url):
        # Обертка для обработки исключений на уровне задачи и контроля семафора
        nonlocal channels_processed_count
        async with channel_semaphore:
            try:
                result = await process_channel_task(url, session, resolver)
                channels_processed_count += 1 # Считаем канал обработанным
                return result
            except Exception as e:
                # Ловим критические ошибки, не пойманные внутри process_channel_task
                logger.error(f"Critical task failure for {url}: {e}", exc_info=True)
                channels_processed_count += 1 # Считаем канал обработанным (с ошибкой)
                return e # Возвращаем исключение для агрегации статуса

    tasks = [asyncio.create_task(task_wrapper(channel_url)) for channel_url in channel_urls]
    channel_results = await asyncio.gather(*tasks) # Собираем результаты (списки прокси или исключения)

    # Агрегация результатов
    for result in channel_results:
        if isinstance(result, Exception):
            # Критическая ошибка выполнения задачи
            channel_status_counts["critical_error"] += 1
        elif isinstance(result, list):
            # Результат от process_channel_task (список прокси)
            all_proxies_nested.append(result)
            if result: # Если список не пустой
                channel_status_counts["success"] += 1
                total_proxies_found_before_dedup += len(result)
            else: # Пустой список (из-за пустого канала или ошибки внутри process_channel_task)
                channel_status_counts["empty_or_failed"] += 1
        else:
             logger.warning(f"Unexpected result type from gather: {type(result)}")
             channel_status_counts["unknown_error"] += 1


    # Финальная дедупликация (используя __hash__ и __eq__ из ProxyParsedConfig)
    unique_proxies_set: Set[ProxyParsedConfig] = set()
    for proxy_list in all_proxies_nested:
        unique_proxies_set.update(proxy_list)

    all_unique_proxies: List[ProxyParsedConfig] = sorted(list(unique_proxies_set), key=lambda p: p.quality_score, reverse=True) # Сортируем по качеству
    logger.info(f"Total unique proxies found after deduplication: {len(all_unique_proxies)}")

    # Подсчет протоколов и категорий качества по УНИКАЛЬНЫМ прокси
    protocol_counts: DefaultDict[str, int] = defaultdict(int)
    quality_category_counts: DefaultDict[str, int] = defaultdict(int)
    for proxy in all_unique_proxies:
        protocol_counts[proxy.protocol] += 1
        quality_category = get_quality_category(proxy.quality_score)
        quality_category_counts[quality_category] += 1

    # Возвращаем все собранные данные
    return (total_proxies_found_before_dedup,
            channels_processed_count,
            protocol_counts,
            all_unique_proxies,
            channel_status_counts,
            quality_category_counts)


# --- Обновленная функция вывода статистики ---

def output_statistics(start_time: float, total_channels_requested: int, channels_processed_count: int,
                      channel_status_counts: DefaultDict[str, int], total_proxies_found_before_dedup: int,
                      all_proxies_saved_count: int, protocol_counts: DefaultDict[str, int],
                      quality_category_counts: DefaultDict[str, int], # <-- Принимаем готовые данные
                      output_file: str):
    """Outputs download and processing statistics."""
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    colored_log(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    colored_log(logging.INFO, f"🔗 Total channel URLs requested: {total_channels_requested}")
    colored_log(logging.INFO, f"🛠️ Total channels processed (attempted): {channels_processed_count}/{total_channels_requested}")

    colored_log(logging.INFO, "\n📊 Channel Processing Status:")
    # Определяем порядок вывода статусов
    status_order = ["success", "empty_or_failed", "critical_error", "unknown_error"]
    status_colors = {
        "success": '\033[92m', # GREEN
        "empty_or_failed": '\033[93m', # YELLOW
        "critical_error": '\033[91m', # RED
        "unknown_error": '\033[91m', # RED
    }
    status_texts = {
        "success": "SUCCESS (found proxies)",
        "empty_or_failed": "EMPTY / FAILED (0 proxies)",
        "critical_error": "CRITICAL TASK ERROR",
        "unknown_error": "UNKNOWN ERROR",
    }

    for status_key in status_order:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            color_start = status_colors.get(status_key, '\033[0m')
            status_text = status_texts.get(status_key, status_key.upper())
            colored_log(logging.INFO, f"  - {color_start}{status_text}{COLOR_MAP['RESET']}: {count} channels")

    colored_log(logging.INFO, f"\n✨ Total configurations found (before deduplication): {total_proxies_found_before_dedup}")
    colored_log(logging.INFO, f"📝 Total unique proxies saved: {all_proxies_saved_count} (to {output_file})")

    colored_log(logging.INFO, "\n🔬 Protocol Breakdown (unique proxies):")
    if protocol_counts:
        # Сортируем для консистентного вывода
        for protocol, count in sorted(protocol_counts.items()):
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   No protocol statistics available.")

    colored_log(logging.INFO, "\n⭐️ Proxy Quality Category Distribution (unique proxies):")
    if quality_category_counts:
         # Сортируем категории (High, Medium, Low)
         category_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
         for category, count in sorted(quality_category_counts.items(), key=lambda item: category_order.get(item[0], 99)):
             colored_log(logging.INFO, f"   - {category}: {count} proxies")
    else:
        colored_log(logging.INFO, "   No quality category statistics available.")

    colored_log(logging.INFO, "======================== 🏁 STATISTICS END =========================")


# --- Обновленная main функция ---

async def main() -> None:
    """Main function to run the proxy downloader script."""
    parser = argparse.ArgumentParser(description="Proxy Downloader Script")
    parser.add_argument('--nocolorlogs', action='store_true', help='Disable colored console logs')
    args = parser.parse_args()

    # Применяем настройку цвета к форматерру
    console_formatter.use_colors = not args.nocolorlogs

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        total_channels_requested = len(channel_urls) # Сохраняем исходное количество

        if not channel_urls:
            colored_log(logging.WARNING, "No channel URLs to process.")
            return

        # Создаем резолвер один раз
        # Проверка показала, что aiodns.DNSResolver не требует явного close()
        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())

        # Используем сессию aiohttp как контекстный менеджер
        async with aiohttp.ClientSession() as session:
            # Вызываем обновленную функцию обработки
            (total_proxies_found_before_dedup, channels_processed_count,
             protocol_counts, all_unique_proxies, channel_status_counts,
             quality_category_counts) = await load_and_process_channels(
                channel_urls, session, resolver)

        # Сохраняем уникальные прокси
        all_proxies_saved_count = save_unique_proxies_to_file(all_unique_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        # Выводим статистику, передавая все необходимые данные
        output_statistics(start_time, total_channels_requested, channels_processed_count,
                          channel_status_counts, total_proxies_found_before_dedup,
                          all_proxies_saved_count, protocol_counts, quality_category_counts,
                          CONFIG_FILES.OUTPUT_ALL_CONFIG)

    except Exception as e:
        # Ловим любые неожиданные ошибки на верхнем уровне
        logger.critical(f"Unexpected critical error in main execution: {e}", exc_info=True)
        sys.exit(1) # Выходим с кодом ошибки
    finally:
        # Это сообщение будет выведено всегда, даже при ошибке
        colored_log(logging.INFO, "✅ Proxy download and processing script finished.")


if __name__ == "__main__":
    # Запускаем асинхронную main функцию
    asyncio.run(main())
