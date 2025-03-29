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
import aiohttp
import base64
import time
import binascii # <-- Убедитесь, что импортирован

from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Set, DefaultDict
from dataclasses import dataclass, field
from collections import defaultdict
from string import Template

# --- Constants --- (без изменений)
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

DNS_TIMEOUT = 15
HTTP_TIMEOUT = 15
MAX_RETRIES = 4
RETRY_DELAY_BASE = 2
HEADERS = {'User-Agent': 'ProxyDownloader/1.0'}
PROTOCOL_REGEX = re.compile(r"^(vless|tuic|hy2|ss|ssr|trojan)://", re.IGNORECASE)
HOSTNAME_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}")

COLOR_MAP = {
    logging.INFO: '\033[92m',
    logging.WARNING: '\033[93m',
    logging.ERROR: '\033[91m',
    logging.CRITICAL: '\033[1m\033[91m',
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

# --- Data Structures --- (без изменений)
class Protocols(Enum):
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]

# --- Logging Setup --- (без изменений)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)

class JsonFormatter(logging.Formatter):
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
    def __init__(self, fmt=CONSOLE_LOG_FORMAT, use_colors=True):
        super().__init__(fmt)
        self.use_colors = use_colors

    def format(self, record):
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
    logger.log(level, message, *args, **kwargs)

# --- Data Structures --- (без изменений)
@dataclass(frozen=True)
class ConfigFiles:
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt"

@dataclass(frozen=True)
class RetrySettings:
    MAX_RETRIES: int = MAX_RETRIES
    RETRY_DELAY_BASE: int = RETRY_DELAY_BASE

@dataclass(frozen=True)
class ConcurrencyLimits:
    MAX_CHANNELS: int = 60
    MAX_PROXIES_PER_CHANNEL: int = 50
    MAX_PROXIES_GLOBAL: int = 50

CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()

class ProfileName(Enum):
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    SSR = "SSR"
    TROJAN = "TROJAN"
    UNKNOWN = "Unknown Protocol"

# --- Custom Exceptions --- (без изменений)
class InvalidURLError(ValueError): pass
class UnsupportedProtocolError(ValueError): pass
class EmptyChannelError(Exception): pass
class DownloadError(Exception): pass

@dataclass(frozen=True, eq=True)
class ProxyParsedConfig:
    """Represents a parsed proxy configuration."""
    config_string: str # Строка, как она будет сохранена (обычно URL без fragment)
    protocol: str
    address: str
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    quality_score: int = 0 # Будет добавлено позже

    def __hash__(self):
        # Хешируем по основным компонентам, которые определяют уникальность прокси
        # после резолвинга (если адрес - IP) и парсинга.
        # config_string может отличаться из-за fragment (#remark), поэтому не используем его одного.
        # Используем кортеж для хеширования.
        return hash((self.protocol, self.address, self.port, frozenset(self.query_params.items())))

    def __str__(self):
        return (f"ProxyParsedConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')")

    # Убрали _decode_base64_if_needed, т.к. основное декодирование теперь в download_proxies_from_channel

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """
        Parses a proxy configuration URL (assumed already decoded if needed),
        performs basic validation, and handles query parameters safely.
        """
        original_string = config_string.strip() # Исходная строка для парсинга
        if not original_string:
            return None

        # Проверяем, начинается ли строка с известного протокола
        protocol_match = PROTOCOL_REGEX.match(original_string)
        if not protocol_match:
            logger.debug(f"Not a valid proxy URL format (no protocol prefix): {original_string[:100]}...")
            return None
        protocol = protocol_match.group(1).lower()

        try:
            # Парсим URL
            parsed_url = urlparse(original_string)

            # Дополнительная проверка схемы (хотя regex уже проверил)
            if parsed_url.scheme.lower() != protocol:
                logger.debug(f"URL scheme '{parsed_url.scheme}' mismatch for protocol '{protocol}': {original_string}")
                return None

            address = parsed_url.hostname
            port = parsed_url.port

            # Базовая валидация адреса/порта
            if not address or not port:
                logger.debug(f"Address or port missing in URL: {original_string}")
                return None

            if not is_valid_ipv4(address) and not HOSTNAME_REGEX.match(address):
                 logger.debug(f"Invalid hostname format: {address} in URL: {original_string}")
                 return None

            if not 1 <= port <= 65535:
                logger.debug(f"Invalid port number: {port} in URL: {original_string}")
                return None

            remark = parsed_url.fragment or ""
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v}

            # Сохраняем URL без fragment для консистентности и возможной записи в файл
            config_string_to_store = original_string.split('#')[0]

            return cls(
                config_string=config_string_to_store,
                protocol=protocol,
                address=address,
                port=port,
                remark=remark, # Remark сохраняем отдельно
                query_params=query_params,
            )

        except ValueError as e:
            logger.debug(f"URL parsing error for '{original_string[:100]}...': {e}")
            return None


# --- Helper Functions --- (без изменений)
@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    if is_valid_ipv4(hostname):
        return hostname
    try:
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
    score = 0
    protocol = proxy_config.protocol.lower()
    query_params = proxy_config.query_params
    score += QUALITY_SCORE_WEIGHTS["protocol"].get(protocol, 0)
    security = query_params.get("security", "none").lower()
    score += QUALITY_SCORE_WEIGHTS["security"].get(security, 0)
    transport = query_params.get("type", query_params.get("transport", "tcp")).lower()
    score += QUALITY_SCORE_WEIGHTS["transport"].get(transport, 0)
    return score

def get_quality_category(score: int) -> str:
    for category, score_range in QUALITY_CATEGORIES.items():
        if score in score_range:
            return category
    return "Unknown"

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', proxy_config.query_params.get('transport', 'tcp')).lower()
    security = proxy_config.query_params.get('security', 'none').lower()
    profile_name_values = {"protocol": protocol, "type": type_, "security": security}
    return PROFILE_NAME_TEMPLATE.safe_substitute(profile_name_values)


# --- Core Logic Functions ---

# !!! ИЗМЕНЕННАЯ ФУНКЦИЯ !!!
async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> List[str]:
    """
    Downloads proxy configurations from a channel URL with retry logic.
    Attempts Base64 decoding on raw bytes first, then falls back to plain text.
    Returns a list of lines or raises exceptions.
    """
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            logger.debug(f"Attempting download from {channel_url} (Attempt {retries_attempted + 1})")
            async with session.get(channel_url, timeout=session_timeout, headers=HEADERS) as response:
                response.raise_for_status()
                logger.debug(f"Successfully connected to {channel_url}, status: {response.status}")

                content_bytes = await response.read()
                if not content_bytes.strip():
                    logger.warning(f"Channel {channel_url} returned empty response.")
                    raise EmptyChannelError(f"Channel {channel_url} returned empty response.")

                # --- Логика декодирования ---
                decoded_text: Optional[str] = None

                # 1. Попытка декодировать как Base64 из БАЙТОВ
                try:
                    # Удаляем пробельные символы из байтов (используя latin-1 для безопасности)
                    # и добавляем padding, если нужно
                    base64_bytes_stripped = bytes("".join(content_bytes.decode('latin-1').split()), 'latin-1')
                    missing_padding = len(base64_bytes_stripped) % 4
                    if missing_padding:
                        base64_bytes_padded = base64_bytes_stripped + b'=' * (4 - missing_padding)
                    else:
                        base64_bytes_padded = base64_bytes_stripped

                    # Декодируем Base64 из подготовленных байтов
                    b64_decoded_bytes = base64.b64decode(base64_bytes_padded, validate=True)

                    # Пытаемся декодировать РЕЗУЛЬТАТ как UTF-8
                    decoded_text_from_b64 = b64_decoded_bytes.decode('utf-8')

                    # Проверяем, похож ли результат на прокси-ссылки
                    if PROTOCOL_REGEX.search(decoded_text_from_b64): # Используем search
                        logger.debug(f"Content from {channel_url} successfully decoded as Base64.")
                        decoded_text = decoded_text_from_b64
                    else:
                        logger.debug(f"Content from {channel_url} decoded from Base64, but no protocol found. Trying original content as text.")
                        # Не присваиваем decoded_text, переходим к попытке 2

                except (binascii.Error, ValueError) as e: # Ошибки декодирования Base64
                    logger.debug(f"Content from {channel_url} is not valid Base64 ({type(e).__name__}). Treating as plain text.")
                    # Не присваиваем decoded_text, переходим к попытке 2
                except UnicodeDecodeError as e:
                    # Ошибка декодирования результата Base64 как UTF-8
                    logger.warning(f"Content from {channel_url} decoded from Base64, but result is not valid UTF-8: {e}. Treating as plain text.")
                    # Не присваиваем decoded_text, переходим к попытке 2
                except Exception as e:
                    # Неожиданные ошибки при обработке Base64
                    logger.error(f"Unexpected error during Base64 processing for {channel_url}: {e}", exc_info=True)
                    # Не присваиваем decoded_text, переходим к попытке 2


                # 2. Если Base64 не сработал или результат не подошел, пытаемся декодировать как UTF-8 (plain text)
                if decoded_text is None:
                    try:
                        logger.debug(f"Attempting to decode content from {channel_url} as plain UTF-8 text.")
                        decoded_text = content_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        logger.warning(f"UTF-8 decoding failed for {channel_url} (plain text), replacing errors.")
                        decoded_text = content_bytes.decode('utf-8', errors='replace')

                # Возвращаем строки, если удалось что-то декодировать
                if decoded_text is not None:
                    return decoded_text.splitlines()
                else:
                    # Эта ситуация маловероятна при текущей логике, но на всякий случай
                    logger.error(f"Failed to decode content from {channel_url} using any method.")
                    raise DownloadError(f"Failed to decode content from {channel_url}")

        except aiohttp.ClientResponseError as e:
            colored_log(logging.WARNING, f"⚠️ Channel {channel_url} returned HTTP error {e.status}: {e.message}")
            logger.debug(f"Response headers for {channel_url} on error: {response.headers}")
            raise DownloadError(f"HTTP error {e.status} for {channel_url}") from e
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted) + random.uniform(-0.5, 0.5)
            retry_delay = max(0.5, retry_delay)
            colored_log(logging.WARNING, f"⚠️ Error getting {channel_url} (attempt {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {type(e).__name__}. Retry in {retry_delay:.2f}s...")
            if retries_attempted == RETRY.MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Max retries ({RETRY.MAX_RETRIES+1}) reached for {channel_url}")
                raise DownloadError(f"Max retries reached for {channel_url}") from e
            await asyncio.sleep(retry_delay)
        except EmptyChannelError as e:
             raise e
        except Exception as e:
             logger.error(f"Unexpected error downloading/processing {channel_url}: {e}", exc_info=True)
             raise DownloadError(f"Unexpected error downloading/processing {channel_url}") from e

        retries_attempted += 1

    logger.critical(f"Download loop finished unexpectedly for {channel_url}")
    raise DownloadError(f"Download failed unexpectedly after retries for {channel_url}")


# --- Разделенные функции парсинга и резолвинга --- (без изменений)

def parse_proxy_lines(lines: List[str]) -> Tuple[List[ProxyParsedConfig], int, int]:
    parsed_configs: List[ProxyParsedConfig] = []
    # Используем set для хранения хешей ProxyParsedConfig для дедупликации ПОСЛЕ парсинга
    processed_configs_hashes: Set[int] = set()
    invalid_url_count = 0
    duplicate_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parsed_config = ProxyParsedConfig.from_url(line)

        if parsed_config is None:
            invalid_url_count += 1
            continue

        # Проверка на дубликат ПОСЛЕ парсинга, используя __hash__ объекта
        config_hash = hash(parsed_config)
        if config_hash in processed_configs_hashes:
            logger.debug(f"Skipping duplicate proxy (based on parsed components): {parsed_config}")
            duplicate_count += 1
            continue
        processed_configs_hashes.add(config_hash)

        parsed_configs.append(parsed_config)

    logger.info(f"Initial parsing: {len(parsed_configs)} potentially valid configs found. "
                f"Skipped {invalid_url_count} invalid lines, {duplicate_count} duplicates (parsed).")
    return parsed_configs, invalid_url_count, duplicate_count


async def resolve_and_assess_proxies(
    configs: List[ProxyParsedConfig], resolver: aiodns.DNSResolver
) -> Tuple[List[ProxyParsedConfig], int]:
    resolved_configs_with_score: List[ProxyParsedConfig] = []
    dns_resolution_failed_count = 0
    # Используем set для дедупликации ПОСЛЕ резолвинга (на случай если разные домены резолвятся в один IP)
    # Ключ - кортеж (protocol, resolved_ip, port, frozenset(query_params))
    final_unique_keys: Set[tuple] = set()

    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal dns_resolution_failed_count
        resolved_ip = await resolve_address(config.address, resolver)
        if resolved_ip:
            quality_score = assess_proxy_quality(config)
            # Создаем ключ для финальной дедупликации
            final_key = (config.protocol, resolved_ip, config.port, frozenset(config.query_params.items()))

            # Проверяем уникальность по ключу
            if final_key not in final_unique_keys:
                final_unique_keys.add(final_key)
                # Возвращаем новый объект с добавленным score и, возможно, замененным address на IP
                # Решаем оставить оригинальный address для сохранения исходной информации,
                # но дедупликация идет по resolved_ip.
                return dataclasses.replace(config, quality_score=quality_score)
            else:
                logger.debug(f"Skipping duplicate proxy after DNS resolution: {config.address} -> {resolved_ip}")
                return None # Это дубликат после резолвинга
        else:
            logger.debug(f"DNS resolution failed for proxy address: {config.address} from config: {config.config_string[:50]}...")
            dns_resolution_failed_count += 1
            return None

    tasks = [resolve_task(cfg) for cfg in configs]
    results = await asyncio.gather(*tasks)

    resolved_configs_with_score = [res for res in results if res is not None]

    logger.info(f"DNS Resolution & Assessment: {len(resolved_configs_with_score)} unique configs resolved and assessed. "
                f"{dns_resolution_failed_count} DNS resolution failures.")
    return resolved_configs_with_score, dns_resolution_failed_count


# --- Функция сохранения --- (без изменений)
def save_unique_proxies_to_file(unique_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        logger.info(f"Attempting to save {len(unique_proxies)} unique proxies to {output_file}")

        lines_to_write = []
        for proxy_conf in unique_proxies:
            profile_name = generate_proxy_profile_name(proxy_conf)
            quality_category = get_quality_category(proxy_conf.quality_score)
            # Используем config_string, который был сохранен (URL без fragment)
            config_line = (f"{proxy_conf.config_string}#{profile_name}_"
                           f"Q{proxy_conf.quality_score}_{quality_category}\n")
            lines_to_write.append(config_line)
            count += 1

        with open(output_file, 'w', encoding='utf-8') as f:
            f.writelines(lines_to_write)

        logger.info(f"Successfully wrote {count} proxies to {output_file}")

    except IOError as e:
        logger.error(f"IOError saving proxies to file '{output_file}': {e}", exc_info=True)
        return 0
    except Exception as e:
        logger.error(f"Unexpected error saving proxies to file '{output_file}': {e}", exc_info=True)
        return 0
    return count

# --- Загрузка URL каналов --- (без изменений)
async def load_channel_urls(all_urls_file: str) -> List[str]:
    channel_urls: List[str] = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    channel_urls.append(url)
        logger.info(f"Loaded {len(channel_urls)} channel URLs from {all_urls_file}")
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ File {all_urls_file} not found. Creating an empty file.")
        try:
            os.makedirs(os.path.dirname(all_urls_file) or '.', exist_ok=True)
            open(all_urls_file, 'w').close()
        except Exception as e:
            logger.error(f"Error creating file {all_urls_file}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls


# --- Обновленная функция обработки канала --- (без изменений в логике вызовов)
async def process_channel_task(channel_url: str, session: aiohttp.ClientSession,
                              resolver: aiodns.DNSResolver
                              ) -> List[ProxyParsedConfig]:
    colored_log(logging.INFO, f"🚀 Processing channel: {channel_url}")
    try:
        lines = await download_proxies_from_channel(channel_url, session) # Использует исправленную функцию
        parsed_proxies_basic, _, _ = parse_proxy_lines(lines) # Использует исправленную функцию
        if not parsed_proxies_basic:
             logger.info(f"No potentially valid configs found after parsing {channel_url}")
             return []
        resolved_proxies, _ = await resolve_and_assess_proxies(parsed_proxies_basic, resolver) # Использует исправленную функцию
        channel_proxies_count = len(resolved_proxies)
        colored_log(logging.INFO, f"✅ Channel {channel_url} processed. Found {channel_proxies_count} valid proxies.")
        return resolved_proxies
    except EmptyChannelError:
         colored_log(logging.WARNING, f"⚠️ Channel {channel_url} was empty or returned no parsable content.")
         return []
    except DownloadError as e:
         colored_log(logging.ERROR, f"❌ Failed to process channel {channel_url} after retries: {e}")
         return []
    except Exception as e:
         logger.error(f"Unexpected error processing channel {channel_url}: {e}", exc_info=True)
         return []


# --- Обновленная функция загрузки и обработки каналов --- (без изменений в логике вызовов)
async def load_and_process_channels(channel_urls: List[str], session: aiohttp.ClientSession,
                                     resolver: aiodns.DNSResolver
                                     ) -> Tuple[int, int, DefaultDict[str, int], List[ProxyParsedConfig], DefaultDict[str, int], DefaultDict[str, int]]:
    channels_processed_count = 0
    total_proxies_found_before_dedup = 0
    channel_status_counts: DefaultDict[str, int] = defaultdict(int)
    all_proxies_nested: List[List[ProxyParsedConfig]] = []
    channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)

    async def task_wrapper(url):
        nonlocal channels_processed_count
        async with channel_semaphore:
            try:
                result = await process_channel_task(url, session, resolver)
                channels_processed_count += 1
                return result
            except Exception as e:
                logger.error(f"Critical task failure for {url}: {e}", exc_info=True)
                channels_processed_count += 1
                return e

    tasks = [asyncio.create_task(task_wrapper(channel_url)) for channel_url in channel_urls]
    channel_results = await asyncio.gather(*tasks)

    # Агрегация и финальная дедупликация (используя set и __hash__/__eq__)
    unique_proxies_set: Set[ProxyParsedConfig] = set()
    for result in channel_results:
        if isinstance(result, Exception):
            channel_status_counts["critical_error"] += 1
        elif isinstance(result, list):
            # Добавляем прокси из успешного результата в set для дедупликации
            unique_proxies_set.update(result) # set сам обработает дубликаты
            if result:
                channel_status_counts["success"] += 1
                total_proxies_found_before_dedup += len(result) # Считаем до финальной дедупликации
            else:
                channel_status_counts["empty_or_failed"] += 1
        else:
             logger.warning(f"Unexpected result type from gather: {type(result)}")
             channel_status_counts["unknown_error"] += 1

    all_unique_proxies: List[ProxyParsedConfig] = sorted(list(unique_proxies_set), key=lambda p: p.quality_score, reverse=True)
    logger.info(f"Total unique proxies found after final deduplication: {len(all_unique_proxies)}")

    protocol_counts: DefaultDict[str, int] = defaultdict(int)
    quality_category_counts: DefaultDict[str, int] = defaultdict(int)
    for proxy in all_unique_proxies:
        protocol_counts[proxy.protocol] += 1
        quality_category = get_quality_category(proxy.quality_score)
        quality_category_counts[quality_category] += 1

    return (total_proxies_found_before_dedup,
            channels_processed_count,
            protocol_counts,
            all_unique_proxies,
            channel_status_counts,
            quality_category_counts)


# --- Обновленная функция вывода статистики --- (без изменений)
def output_statistics(start_time: float, total_channels_requested: int, channels_processed_count: int,
                      channel_status_counts: DefaultDict[str, int], total_proxies_found_before_dedup: int,
                      all_proxies_saved_count: int, protocol_counts: DefaultDict[str, int],
                      quality_category_counts: DefaultDict[str, int],
                      output_file: str):
    end_time = time.time()
    elapsed_time = end_time - start_time
    colored_log(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    colored_log(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    colored_log(logging.INFO, f"🔗 Total channel URLs requested: {total_channels_requested}")
    colored_log(logging.INFO, f"🛠️ Total channels processed (attempted): {channels_processed_count}/{total_channels_requested}")
    colored_log(logging.INFO, "\n📊 Channel Processing Status:")
    status_order = ["success", "empty_or_failed", "critical_error", "unknown_error"]
    status_colors = {"success": '\033[92m', "empty_or_failed": '\033[93m', "critical_error": '\033[91m', "unknown_error": '\033[91m'}
    status_texts = {"success": "SUCCESS (found proxies)", "empty_or_failed": "EMPTY / FAILED (0 proxies)", "critical_error": "CRITICAL TASK ERROR", "unknown_error": "UNKNOWN ERROR"}
    for status_key in status_order:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            color_start = status_colors.get(status_key, '\033[0m')
            status_text = status_texts.get(status_key, status_key.upper())
            colored_log(logging.INFO, f"  - {color_start}{status_text}{COLOR_MAP['RESET']}: {count} channels")
    colored_log(logging.INFO, f"\n✨ Total configurations found (before final deduplication): {total_proxies_found_before_dedup}")
    colored_log(logging.INFO, f"📝 Total unique proxies saved: {all_proxies_saved_count} (to {output_file})")
    colored_log(logging.INFO, "\n🔬 Protocol Breakdown (unique proxies):")
    if protocol_counts:
        for protocol, count in sorted(protocol_counts.items()):
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   No protocol statistics available.")
    colored_log(logging.INFO, "\n⭐️ Proxy Quality Category Distribution (unique proxies):")
    if quality_category_counts:
         category_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
         for category, count in sorted(quality_category_counts.items(), key=lambda item: category_order.get(item[0], 99)):
             colored_log(logging.INFO, f"   - {category}: {count} proxies")
    else:
        colored_log(logging.INFO, "   No quality category statistics available.")
    colored_log(logging.INFO, "======================== 🏁 STATISTICS END =========================")


# --- Обновленная main функция --- (без изменений)
async def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy Downloader Script")
    parser.add_argument('--nocolorlogs', action='store_true', help='Disable colored console logs')
    args = parser.parse_args()
    console_formatter.use_colors = not args.nocolorlogs

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        total_channels_requested = len(channel_urls)

        if not channel_urls:
            colored_log(logging.WARNING, "No channel URLs to process.")
            return

        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())

        async with aiohttp.ClientSession() as session:
            (total_proxies_found_before_dedup, channels_processed_count,
             protocol_counts, all_unique_proxies, channel_status_counts,
             quality_category_counts) = await load_and_process_channels(
                channel_urls, session, resolver)

        all_proxies_saved_count = save_unique_proxies_to_file(all_unique_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        output_statistics(start_time, total_channels_requested, channels_processed_count,
                          channel_status_counts, total_proxies_found_before_dedup,
                          all_proxies_saved_count, protocol_counts, quality_category_counts,
                          CONFIG_FILES.OUTPUT_ALL_CONFIG)

    except Exception as e:
        logger.critical(f"Unexpected critical error in main execution: {e}", exc_info=True)
        sys.exit(1)
    finally:
        colored_log(logging.INFO, "✅ Proxy download and processing script finished.")


if __name__ == "__main__":
    asyncio.run(main())
