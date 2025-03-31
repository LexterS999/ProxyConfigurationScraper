import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import json
import sys
import argparse
import dataclasses
import random
import aiohttp
import base64
import time
import binascii
import ssl # Для TLS-тестирования
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlunparse
from typing import Dict, List, Optional, Tuple, Set, DefaultDict, Any, Union # Добавлен Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from string import Template
from functools import lru_cache

# --- Новые зависимости ---
try:
    from tqdm.asyncio import tqdm # Для прогресс-баров
except ImportError:
    print("Please install tqdm: pip install tqdm")
    sys.exit(1)

try:
    import yaml # Для формата Clash
except ImportError:
    # Не выходим, если yaml не нужен
    yaml = None


# --- Constants ---
LOG_FILE = 'proxy_downloader.log'
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FORMAT: Dict[str, str] = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "threadName": "%(threadName)s",
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
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}") # Базовый шаблон

# --- Новые константы для тестирования ---
TEST_URL = "www.google.com" # URL для проверки соединения (не используется для запроса, только для TLS SNI)
TEST_PORT = 443 # Порт для проверки соединения (обычно 443 для TLS)
TEST_TIMEOUT = 10 # Таймаут для одного теста соединения (секунды)
TEST_RESULT_TYPE = Dict[str, Union[str, Optional[float], Optional[str]]] # Тип для результата теста

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

# --- Новые константы для форматов вывода ---
class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    CLASH = "clash"
    # V2RAYN = "v2rayn" # Пока не реализован сложный формат

# --- Data Structures ---
class Protocols(Enum):
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]

# --- Logging Setup ---
# (Без изменений, tqdm обычно хорошо работает с logging)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record: Dict[str, Any] = {}
        for key, format_specifier in LOG_FORMAT.items():
             try: # Добавим try-except на случай отсутствия атрибута
                 temp_formatter = logging.Formatter(format_specifier)
                 log_record[key] = temp_formatter.format(record)
             except AttributeError:
                 log_record[key] = None # Или другое значение по умолчанию
        log_record["message"] = record.getMessage()
        log_record["level"] = record.levelname
        log_record["time"] = self.formatTime(record, self.default_time_format)
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        if hasattr(record, 'taskName') and record.taskName:
             log_record['taskName'] = record.taskName
        return json.dumps(log_record, ensure_ascii=False, default=str)
formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)
class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt: str = CONSOLE_LOG_FORMAT, use_colors: bool = True):
        super().__init__(fmt)
        self.use_colors = use_colors
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if self.use_colors:
            color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET'])
            color_reset = COLOR_MAP['RESET']
            # Используем print для вывода логов, чтобы tqdm не перекрывал
            # print(f"{color_start}{message}{color_reset}", file=sys.stderr if record.levelno >= logging.WARNING else sys.stdout)
            # return "" # Возвращаем пустую строку, т.к. уже напечатали
            # --- ИЛИ --- Оставляем стандартное логирование, tqdm должен справиться
            message = f"{color_start}{message}{color_reset}"
        return message
console_formatter = ColoredFormatter()
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)
def colored_log(level: int, message: str, *args, **kwargs):
    logger.log(level, message, *args, **kwargs)

# --- Data Structures ---
@dataclass(frozen=True)
class ConfigFiles:
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt" # Будет дополнено форматом

@dataclass(frozen=True)
class RetrySettings:
    MAX_RETRIES: int = MAX_RETRIES
    RETRY_DELAY_BASE: int = RETRY_DELAY_BASE

@dataclass(frozen=True)
class ConcurrencyLimits:
    MAX_CHANNELS: int = 60
    MAX_DNS: int = 50 # Переименовано из MAX_PROXIES_GLOBAL
    MAX_TESTS: int = 30 # Новый лимит для тестов

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

# --- Custom Exceptions ---
class InvalidURLError(ValueError): pass
class UnsupportedProtocolError(ValueError): pass
class EmptyChannelError(Exception): pass
class DownloadError(Exception): pass
class ProxyTestError(Exception): pass # Новое исключение

@dataclass(frozen=True, eq=True)
class ProxyParsedConfig:
    """(Докстринг без изменений)"""
    config_string: str
    protocol: str
    address: str
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    quality_score: int = 0

    def __hash__(self):
        return hash((self.protocol, self.address, self.port, frozenset(self.query_params.items())))

    def __str__(self):
        return (f"ProxyParsedConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')")

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """(Докстринг без изменений)"""
        original_string = config_string.strip()
        if not original_string: return None
        protocol_match = PROTOCOL_REGEX.match(original_string)
        if not protocol_match: return None
        protocol = protocol_match.group(1).lower()
        try:
            parsed_url = urlparse(original_string)
            if parsed_url.scheme.lower() != protocol: return None
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port: return None
            # if not is_valid_ipv4(address) and not HOSTNAME_REGEX.match(address): return None # Ослабляем проверку здесь
            if not 1 <= port <= 65535: return None
            remark = parsed_url.fragment or ""
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v}
            config_string_to_store = original_string.split('#')[0]
            return cls(
                config_string=config_string_to_store, protocol=protocol, address=address,
                port=port, remark=remark, query_params=query_params,
            )
        except ValueError as e:
            logger.debug(f"URL parsing error for '{original_string[:100]}...': {e}")
            return None
        except Exception as e:
             logger.error(f"Unexpected error parsing URL '{original_string[:100]}...': {e}", exc_info=True)
             return None

# --- Helper Functions ---
@lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """(Докстринг без изменений)"""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """(Докстринг без изменений)"""
    if is_valid_ipv4(hostname): return hostname
    try:
        async with asyncio.timeout(DNS_TIMEOUT):
            logger.debug(f"Attempting DNS query for {hostname}")
            result = await resolver.query(hostname, 'A')
            if result:
                resolved_ip = result[0].host
                if is_valid_ipv4(resolved_ip):
                    logger.debug(f"DNS resolved {hostname} to {resolved_ip}")
                    return resolved_ip
                else:
                    logger.warning(f"DNS resolved {hostname} to non-IPv4 address: {resolved_ip}")
                    return None
            else:
                 logger.debug(f"DNS query for {hostname} returned no results.")
                 return None
    except asyncio.TimeoutError:
        logger.debug(f"DNS resolution timeout for {hostname}")
        return None
    except aiodns.error.DNSError as e:
        error_code = e.args[0] if e.args else "Unknown"
        if error_code == 4: logger.debug(f"DNS resolution error for {hostname}: Host not found (NXDOMAIN)")
        elif error_code == 1: logger.debug(f"DNS resolution error for {hostname}: Format error (FORMERR)")
        else: logger.warning(f"DNS resolution error for {hostname}: {e}, Code: {error_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True)
        return None

def assess_proxy_quality(proxy_config: ProxyParsedConfig) -> int:
    """(Докстринг без изменений)"""
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
    """(Докстринг без изменений)"""
    for category, score_range in QUALITY_CATEGORIES.items():
        if score in score_range:
            return category
    return "Unknown"

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE] = None) -> str:
    """
    Генерирует имя профиля для прокси, опционально добавляя задержку.

    Args:
        proxy_config: Конфигурация прокси.
        test_result: Результат теста соединения (если есть).

    Returns:
        Имя профиля (строка).
    """
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', proxy_config.query_params.get('transport', 'tcp')).lower()
    security = proxy_config.query_params.get('security', 'none').lower()
    quality_category = get_quality_category(proxy_config.quality_score)

    name_parts = {
        "protocol": protocol,
        "type": type_,
        "security": security,
        "quality": f"Q{proxy_config.quality_score}",
        "category": quality_category,
    }

    # Формируем базовое имя
    base_name = f"{protocol}-{type_}-{security}-Q{proxy_config.quality_score}-{quality_category}"

    # Добавляем задержку, если тест пройден
    if test_result and test_result.get('status') == 'ok' and test_result.get('latency') is not None:
        latency_ms = int(test_result['latency'] * 1000)
        base_name += f"-{latency_ms}ms"

    # Добавляем оригинальный remark, если он был
    if proxy_config.remark:
        # Убираем потенциально конфликтующие символы из remark
        safe_remark = re.sub(r'[#\s]+', '_', proxy_config.remark)
        base_name += f"_{safe_remark}"

    # Ограничиваем длину имени, если нужно
    max_len = 60
    if len(base_name) > max_len:
        base_name = base_name[:max_len-3] + "..."

    return base_name


# --- Core Logic Functions ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> List[str]:
    """(Докстринг без изменений)"""
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
                    logger.warning(f"Channel {channel_url} returned empty or whitespace-only response.")
                    raise EmptyChannelError(f"Channel {channel_url} returned empty response.")
                decoded_text: Optional[str] = None
                decode_method: str = "Unknown"
                try: # Попытка Base64
                    base64_bytes_stripped = bytes("".join(content_bytes.decode('latin-1').split()), 'latin-1')
                    missing_padding = len(base64_bytes_stripped) % 4
                    if missing_padding: base64_bytes_padded = base64_bytes_stripped + b'=' * (4 - missing_padding)
                    else: base64_bytes_padded = base64_bytes_stripped
                    b64_decoded_bytes = base64.b64decode(base64_bytes_padded, validate=True)
                    decoded_text_from_b64 = b64_decoded_bytes.decode('utf-8')
                    if PROTOCOL_REGEX.search(decoded_text_from_b64):
                        logger.debug(f"Content from {channel_url} successfully decoded as Base64.")
                        decoded_text = decoded_text_from_b64
                        decode_method = "Base64"
                    else:
                        logger.debug(f"Content from {channel_url} decoded from Base64, but no protocol found. Trying plain text.")
                except (binascii.Error, ValueError) as e: logger.debug(f"Content from {channel_url} is not valid Base64 ({type(e).__name__}). Treating as plain text.")
                except UnicodeDecodeError as e: logger.warning(f"Content from {channel_url} decoded from Base64, but result is not valid UTF-8: {e}. Treating as plain text.")
                except Exception as e: logger.error(f"Unexpected error during Base64 processing for {channel_url}: {e}", exc_info=True)

                if decoded_text is None: # Попытка Plain Text
                    try:
                        logger.debug(f"Attempting to decode content from {channel_url} as plain UTF-8 text.")
                        decoded_text = content_bytes.decode('utf-8')
                        decode_method = "Plain UTF-8"
                    except UnicodeDecodeError:
                        logger.warning(f"UTF-8 decoding failed for {channel_url} (plain text), replacing errors.")
                        decoded_text = content_bytes.decode('utf-8', errors='replace')
                        decode_method = "Plain UTF-8 (with replace)"

                if decoded_text is not None:
                    logger.info(f"Successfully decoded content from {channel_url} using method: {decode_method}")
                    return decoded_text.splitlines()
                else:
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
        except EmptyChannelError as e: raise e
        except Exception as e:
             logger.error(f"Unexpected error downloading/processing {channel_url}: {e}", exc_info=True)
             raise DownloadError(f"Unexpected error downloading/processing {channel_url}") from e
        retries_attempted += 1
    logger.critical(f"Download loop finished unexpectedly for {channel_url}")
    raise DownloadError(f"Download failed unexpectedly after retries for {channel_url}")

def parse_proxy_lines(lines: List[str]) -> Tuple[List[ProxyParsedConfig], int, int]:
    """(Докстринг без изменений)"""
    parsed_configs: List[ProxyParsedConfig] = []
    processed_configs_hashes: Set[int] = set()
    invalid_url_count = 0
    duplicate_count = 0
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'): continue
        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config is None:
            # logger.debug(f"Line {line_num}: Invalid proxy format skipped: {line[:100]}...") # Уже логируется в from_url
            invalid_url_count += 1
            continue
        config_hash = hash(parsed_config)
        if config_hash in processed_configs_hashes:
            logger.debug(f"Line {line_num}: Skipping duplicate proxy (parsed): {parsed_config}")
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
    """
    Асинхронно разрешает адреса прокси и оценивает их качество.

    Использует `tqdm` для отображения прогресса DNS-резолвинга.
    (Остальной докстринг без изменений)
    """
    resolved_configs_with_score: List[ProxyParsedConfig] = []
    dns_resolution_failed_count = 0
    final_unique_keys: Set[tuple] = set()
    dns_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_DNS)

    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal dns_resolution_failed_count
        async with dns_semaphore:
            resolved_ip = await resolve_address(config.address, resolver)
        if resolved_ip:
            quality_score = assess_proxy_quality(config)
            final_key = (config.protocol, resolved_ip, config.port, frozenset(config.query_params.items()))
            if final_key not in final_unique_keys:
                final_unique_keys.add(final_key)
                return dataclasses.replace(config, quality_score=quality_score)
            else:
                logger.debug(f"Skipping duplicate proxy after DNS resolution: {config.address} -> {resolved_ip} (Port: {config.port}, Proto: {config.protocol})")
                return None
        else:
            dns_resolution_failed_count += 1
            return None

    tasks = [resolve_task(cfg) for cfg in configs]
    # Используем tqdm.gather для прогресс-бара
    results = await tqdm.gather(*tasks, desc="Resolving DNS", unit="proxy", disable=not sys.stdout.isatty())

    resolved_configs_with_score = [res for res in results if res is not None]
    logger.info(f"DNS Resolution & Assessment: {len(resolved_configs_with_score)} unique configs resolved and assessed. "
                f"{dns_resolution_failed_count} DNS resolution failures or post-resolution duplicates.")
    return resolved_configs_with_score, dns_resolution_failed_count

# --- Новые функции для тестирования прокси ---
async def test_proxy_connectivity(proxy_config: ProxyParsedConfig) -> TEST_RESULT_TYPE:
    """
    Выполняет базовую проверку соединения с хостом:портом прокси.

    Пытается установить TCP-соединение и, если security=tls, выполняет TLS handshake.
    Измеряет время, затраченное на установку соединения.
    **ВНИМАНИЕ:** Это НЕ полноценная проверка работы протокола прокси (VLESS/Trojan и т.д.).

    Args:
        proxy_config: Конфигурация прокси для теста.

    Returns:
        Словарь с результатами: {'status': 'ok'/'failed', 'latency': float/None, 'error': str/None}
    """
    start_time = time.monotonic()
    writer = None
    reader = None
    host = proxy_config.address # Используем оригинальный адрес (может быть IP или hostname)
    port = proxy_config.port
    use_tls = proxy_config.query_params.get('security', 'none').lower() == 'tls'

    try:
        logger.debug(f"Testing connection to {host}:{port} (TLS: {use_tls})")
        async with asyncio.timeout(TEST_TIMEOUT):
            reader, writer = await asyncio.open_connection(host, port)

            if use_tls:
                logger.debug(f"Attempting TLS handshake with {host}:{port}")
                ssl_context = ssl.create_default_context()
                # Используем адрес как server_hostname для SNI, если это не IP
                server_hostname = host if not is_valid_ipv4(host) else None
                transport = writer.get_extra_info('transport')
                if not transport:
                     raise ProxyTestError("Could not get transport info for TLS")

                # Запускаем TLS handshake
                # В новых версиях asyncio/Python это может делаться через start_tls
                # Для совместимости используем wrap_socket (может быть блокирующим!)
                # Правильнее было бы использовать неблокирующий handshake, но это сложнее.
                # Это упрощенная проверка!
                loop = asyncio.get_running_loop()
                # Выполняем wrap_socket в executor, чтобы не блокировать основной поток
                # Это компромисс, полноценный асинхронный TLS handshake сложнее
                try:
                    new_transport = await loop.start_tls(transport, ssl_context, server_hostname=server_hostname)
                    # Обновляем reader/writer, если start_tls вернул новый транспорт
                    # (зависит от реализации asyncio)
                    # В данном случае нам достаточно знать, что handshake прошел без ошибок
                    logger.debug(f"TLS handshake successful for {host}:{port}")
                except ssl.SSLError as tls_err:
                    raise ProxyTestError(f"TLS handshake failed: {tls_err}") from tls_err
                except Exception as handshake_err: # Ловим другие ошибки start_tls
                    raise ProxyTestError(f"TLS start_tls error: {handshake_err}") from handshake_err


            latency = time.monotonic() - start_time
            logger.debug(f"Connection test OK for {host}:{port}, latency: {latency:.4f}s")
            return {'status': 'ok', 'latency': latency, 'error': None}

    except asyncio.TimeoutError:
        logger.debug(f"Connection test TIMEOUT for {host}:{port}")
        return {'status': 'failed', 'latency': None, 'error': 'Timeout'}
    except (OSError, ConnectionRefusedError, ProxyTestError, ssl.SSLError, Exception) as e:
        logger.debug(f"Connection test FAILED for {host}:{port}: {type(e).__name__}: {e}")
        return {'status': 'failed', 'latency': None, 'error': f"{type(e).__name__}: {str(e)[:100]}"}
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass # Игнорируем ошибки при закрытии

async def run_proxy_tests(
    proxies: List[ProxyParsedConfig]
) -> List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]]:
    """
    Асинхронно запускает тесты соединения для списка прокси.

    Использует семафор для ограничения параллелизма и `tqdm` для прогресса.

    Args:
        proxies: Список прокси для тестирования.

    Returns:
        Список кортежей: [(ProxyParsedConfig, test_result_dict), ...]
    """
    if not proxies:
        return []

    test_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_TESTS)
    results_with_proxies: List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]] = []

    async def test_task_wrapper(proxy: ProxyParsedConfig) -> Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]:
        """Обертка для запуска теста с семафором."""
        async with test_semaphore:
            result = await test_proxy_connectivity(proxy)
        return proxy, result

    tasks = [test_task_wrapper(p) for p in proxies]
    results_with_proxies = await tqdm.gather(*tasks, desc="Testing Proxies", unit="proxy", disable=not sys.stdout.isatty())

    # Логируем статистику тестов
    ok_count = sum(1 for _, res in results_with_proxies if res['status'] == 'ok')
    failed_count = len(results_with_proxies) - ok_count
    logger.info(f"Proxy Connectivity Test Results: {ok_count} OK, {failed_count} Failed.")

    return results_with_proxies


# --- Функции сохранения в разных форматах ---

def _save_as_text(proxies_with_results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в текстовом формате (URL#remark)."""
    count = 0
    lines_to_write = []
    for proxy_conf, test_result in proxies_with_results:
        # Генерируем имя профиля, включая результат теста, если он есть
        profile_name = generate_proxy_profile_name(proxy_conf, test_result)
        # Используем config_string (URL без исходного fragment)
        config_line = f"{proxy_conf.config_string}#{profile_name}\n"
        lines_to_write.append(config_line)
        count += 1

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines_to_write)
    return count

def _save_as_json(proxies_with_results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в формате JSON списка объектов."""
    count = 0
    output_list = []
    for proxy_conf, test_result in proxies_with_results:
        proxy_dict = asdict(proxy_conf)
        # Добавляем результат теста, если он есть
        if test_result:
            proxy_dict['test_status'] = test_result.get('status')
            proxy_dict['latency_sec'] = test_result.get('latency')
            proxy_dict['test_error'] = test_result.get('error')
        else:
            proxy_dict['test_status'] = None
            proxy_dict['latency_sec'] = None
            proxy_dict['test_error'] = None
        output_list.append(proxy_dict)
        count += 1

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(output_list, f, indent=2, ensure_ascii=False)
    return count

def _proxy_to_clash_dict(proxy_conf: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE]) -> Optional[Dict[str, Any]]:
    """Преобразует ProxyParsedConfig в словарь для Clash YAML."""
    clash_proxy: Dict[str, Any] = {}
    params = proxy_conf.query_params
    protocol = proxy_conf.protocol.lower()

    # Базовые поля
    clash_proxy['name'] = generate_proxy_profile_name(proxy_conf, test_result)
    clash_proxy['server'] = proxy_conf.address
    clash_proxy['port'] = proxy_conf.port

    # Определение типа для Clash
    if protocol == 'vless':
        clash_proxy['type'] = 'vless'
        clash_proxy['uuid'] = proxy_conf.config_string.split('://')[1].split('@')[0] # Извлекаем UUID
        clash_proxy['tls'] = params.get('security', 'none') == 'tls'
        clash_proxy['network'] = params.get('type', 'tcp') # ws, grpc, tcp
        # Дополнительные параметры VLESS
        if 'flow' in params: clash_proxy['flow'] = params['flow']
        if 'sni' in params: clash_proxy['servername'] = params['sni']
        if clash_proxy['network'] == 'ws':
            clash_proxy['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', proxy_conf.address)}}
        elif clash_proxy['network'] == 'grpc':
            clash_proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        # ... другие параметры vless ...
    elif protocol == 'trojan':
        clash_proxy['type'] = 'trojan'
        clash_proxy['password'] = proxy_conf.config_string.split('://')[1].split('@')[0] # Извлекаем пароль
        clash_proxy['tls'] = params.get('security', 'none') == 'tls' # Trojan обычно с TLS
        if 'sni' in params: clash_proxy['sni'] = params['sni']
        if 'allowInsecure' in params: clash_proxy['skip-cert-verify'] = params['allowInsecure'].lower() == 'true'
        network = params.get('type', 'tcp')
        if network == 'ws':
             clash_proxy['network'] = 'ws'
             clash_proxy['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', proxy_conf.address)}}
        elif network == 'grpc':
             clash_proxy['network'] = 'grpc'
             clash_proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        # ... другие параметры trojan ...
    elif protocol == 'ss':
        clash_proxy['type'] = 'ss'
        # Парсинг SS URL (может быть сложным из-за base64 части)
        try:
            user_info, server_info = proxy_conf.config_string.split('://')[1].split('@')
            server_part = server_info.split('#')[0] # Убираем remark если он есть в строке
            # Декодируем user_info (method:password)
            decoded_user = base64.urlsafe_b64decode(user_info + '===').decode('utf-8') # Добавляем padding
            clash_proxy['cipher'], clash_proxy['password'] = decoded_user.split(':', 1)
        except Exception as e:
            logger.warning(f"Could not parse SS URL for Clash: {proxy_conf.config_string} - {e}")
            return None # Не можем создать конфиг
        # ... параметры ss (plugin, etc.) ...
    # Добавить поддержку TUIC, HY2, SSR если нужно (потребует знания их структуры в Clash)
    else:
        logger.debug(f"Protocol {protocol} not currently supported for Clash output format.")
        return None # Пропускаем неподдерживаемые протоколы

    return clash_proxy

def _save_as_clash(proxies_with_results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в формате Clash YAML."""
    if not yaml:
        logger.error("PyYAML is not installed. Cannot save in Clash format. Please install: pip install pyyaml")
        return 0

    count = 0
    clash_proxies_list = []
    for proxy_conf, test_result in proxies_with_results:
        clash_dict = _proxy_to_clash_dict(proxy_conf, test_result)
        if clash_dict:
            clash_proxies_list.append(clash_dict)
            count += 1

    # Создаем базовую структуру Clash config
    clash_config = {
        'proxies': clash_proxies_list,
        # Можно добавить базовые proxy-groups, rules и т.д.
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': [p['name'] for p in clash_proxies_list] + ['DIRECT']}
        ],
        'rules': [
            'MATCH,PROXY'
        ]
    }

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=None)
    except Exception as e:
        logger.error(f"Error writing Clash YAML file: {e}", exc_info=True)
        return 0 # Ошибка записи
    return count

def save_proxies(
    proxies_with_results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    output_file_base: str,
    output_format: OutputFormat
) -> int:
    """
    Сохраняет список прокси в указанном формате.

    Args:
        proxies_with_results: Список кортежей (прокси, результат_теста).
                              Результат теста может быть None, если тестирование не проводилось.
        output_file_base: Базовый путь к файлу (без расширения).
        output_format: Формат для сохранения (enum OutputFormat).

    Returns:
        Количество успешно записанных прокси.
    """
    if not proxies_with_results:
        logger.warning("No proxies to save.")
        return 0

    # Определяем расширение и функцию сохранения
    if output_format == OutputFormat.JSON:
        file_path = f"{output_file_base}.json"
        save_func = _save_as_json
    elif output_format == OutputFormat.CLASH:
        file_path = f"{output_file_base}.yaml"
        save_func = _save_as_clash
    else: # По умолчанию TEXT
        file_path = f"{output_file_base}.txt"
        save_func = _save_as_text

    saved_count = 0
    try:
        os.makedirs(os.path.dirname(file_path) or '.', exist_ok=True)
        logger.info(f"Attempting to save {len(proxies_with_results)} proxies to {file_path} (Format: {output_format.value})")
        saved_count = save_func(proxies_with_results, file_path)
        if saved_count > 0:
            logger.info(f"Successfully wrote {saved_count} proxies to {file_path}")
        else:
            # Логирование ошибки происходит внутри save_func
             logger.warning(f"No proxies were written to {file_path}")

    except IOError as e:
        logger.error(f"IOError saving proxies to file '{file_path}': {e}", exc_info=True)
        return 0
    except Exception as e:
        logger.error(f"Unexpected error saving proxies to file '{file_path}': {e}", exc_info=True)
        return 0
    return saved_count


# --- Загрузка URL каналов ---
async def load_channel_urls(all_urls_file: str) -> List[str]:
    """(Докстринг без изменений)"""
    channel_urls: List[str] = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'): channel_urls.append(url)
        logger.info(f"Loaded {len(channel_urls)} channel URLs from {all_urls_file}")
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ File {all_urls_file} not found. Creating an empty file.")
        try:
            os.makedirs(os.path.dirname(all_urls_file) or '.', exist_ok=True)
            open(all_urls_file, 'w').close()
        except Exception as e: logger.error(f"Error creating file {all_urls_file}: {e}", exc_info=True)
    except Exception as e: logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls


# --- Функция обработки канала ---
async def process_channel_task(channel_url: str, session: aiohttp.ClientSession,
                              resolver: aiodns.DNSResolver
                              ) -> List[ProxyParsedConfig]:
    """
    Полный цикл обработки одного канала: скачивание, парсинг, резолвинг, оценка.
    (Остальной докстринг без изменений)
    """
    # colored_log(logging.INFO, f"🚀 Processing channel: {channel_url}") # Убрано, т.к. есть tqdm
    try:
        lines = await download_proxies_from_channel(channel_url, session)
        if not lines: return []
        parsed_proxies_basic, _, _ = parse_proxy_lines(lines)
        if not parsed_proxies_basic: return []
        # Резолвинг теперь возвращает только список прокси
        resolved_proxies, _ = await resolve_and_assess_proxies(parsed_proxies_basic, resolver)
        channel_proxies_count = len(resolved_proxies)
        # Логируем результат канала после завершения задачи
        # logger.info(f"Channel {channel_url} processed. Found {channel_proxies_count} potentially valid proxies after DNS.")
        return resolved_proxies
    except EmptyChannelError:
         logger.warning(f"Channel {channel_url} was empty.")
         return []
    except DownloadError as e:
         logger.error(f"Failed to process channel {channel_url} due to download/decode error: {e}")
         return []
    except Exception as e:
         logger.error(f"Unexpected error processing channel {channel_url}: {e}", exc_info=True)
         return []


# --- Функция загрузки и обработки каналов ---
async def load_and_process_channels(channel_urls: List[str], session: aiohttp.ClientSession,
                                     resolver: aiodns.DNSResolver
                                     ) -> Tuple[int, int, List[ProxyParsedConfig], DefaultDict[str, int]]:
    """
    Асинхронно обрабатывает список URL каналов с ограничением параллелизма.

    Использует `tqdm` для отображения прогресса обработки каналов.
    Выполняет финальную дедупликацию между всеми каналами.

    Args:
        (Аргументы без изменений)

    Returns:
        Tuple: Кортеж со статистикой и результатами:
            - total_proxies_found_before_final_dedup (int)
            - channels_processed_count (int)
            - all_unique_proxies (List[ProxyParsedConfig]): Список уникальных прокси
              *после* резолвинга, но *до* тестирования.
            - channel_status_counts (DefaultDict[str, int])
    """
    channels_processed_count = 0
    total_proxies_found_before_final_dedup = 0
    channel_status_counts: DefaultDict[str, int] = defaultdict(int)
    channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)
    all_proxies_from_channels: List[ProxyParsedConfig] = [] # Собираем все прокси сюда

    async def task_wrapper(url: str) -> Optional[List[ProxyParsedConfig]]:
        """Обертка для задачи обработки канала с семафором и обработкой ошибок."""
        nonlocal channels_processed_count
        async with channel_semaphore:
            try:
                result = await process_channel_task(url, session, resolver)
                channels_processed_count += 1
                return result # Возвращаем список прокси (может быть пустым)
            except Exception as e:
                logger.error(f"Critical task failure wrapper for {url}: {e}", exc_info=True)
                channels_processed_count += 1
                channel_status_counts["critical_wrapper_error"] += 1
                return None # Ошибка в самой обертке

    tasks = [asyncio.create_task(task_wrapper(channel_url)) for channel_url in channel_urls]
    # Используем tqdm.gather для прогресс-бара
    channel_results = await tqdm.gather(*tasks, desc="Processing channels", unit="channel", disable=not sys.stdout.isatty())

    # Агрегация результатов
    unique_proxies_set: Set[ProxyParsedConfig] = set()
    for result in channel_results:
        if result is None: # Ошибка в обертке
            continue
        elif isinstance(result, list):
            proxies_from_channel = result
            unique_proxies_set.update(proxies_from_channel)
            if proxies_from_channel:
                channel_status_counts["success_found_proxies"] += 1
                total_proxies_found_before_final_dedup += len(proxies_from_channel)
            else:
                channel_status_counts["success_no_proxies"] += 1
        else:
             logger.warning(f"Unexpected result type from channel gather: {type(result)}")
             channel_status_counts["unknown_error"] += 1

    # Преобразуем set в список (сортировка будет позже, после тестов)
    all_unique_proxies: List[ProxyParsedConfig] = list(unique_proxies_set)
    final_unique_count = len(all_unique_proxies)
    logger.info(f"Total unique proxies found after DNS/deduplication: {final_unique_count}")

    return (total_proxies_found_before_final_dedup,
            channels_processed_count,
            all_unique_proxies, # Возвращаем список до тестов
            channel_status_counts)


# --- Обновленная функция вывода статистики ---
def output_statistics(start_time: float, total_channels_requested: int, channels_processed_count: int,
                      channel_status_counts: DefaultDict[str, int], total_proxies_found_before_dedup: int,
                      proxies_after_dns_count: int,
                      proxies_after_test_count: Optional[int], # Может быть None
                      all_proxies_saved_count: int,
                      protocol_counts: DefaultDict[str, int], # Статистика по сохраненным
                      quality_category_counts: DefaultDict[str, int], # Статистика по сохраненным
                      output_file_path: str, # Полный путь к файлу
                      output_format: OutputFormat):
    """Выводит итоговую статистику выполнения скрипта в консоль."""
    end_time = time.time()
    elapsed_time = end_time - start_time
    colored_log(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    colored_log(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    colored_log(logging.INFO, f"🔗 Total channel URLs requested: {total_channels_requested}")
    colored_log(logging.INFO, f"🛠️ Total channels processed (attempted): {channels_processed_count}/{total_channels_requested}")

    colored_log(logging.INFO, "\n📊 Channel Processing Status:")
    status_order = ["success_found_proxies", "success_no_proxies", "critical_wrapper_error", "unknown_error"]
    status_colors = {"success_found_proxies": '\033[92m', "success_no_proxies": '\033[93m', "critical_wrapper_error": '\033[91m', "unknown_error": '\033[91m'}
    status_texts = {"success_found_proxies": "SUCCESS (found proxies)", "success_no_proxies": "SUCCESS (0 valid proxies found)", "critical_wrapper_error": "CRITICAL TASK ERROR", "unknown_error": "UNKNOWN ERROR"}
    processed_keys = set()
    for status_key in status_order:
        if status_key in channel_status_counts:
            count = channel_status_counts[status_key]
            color_start = status_colors.get(status_key, COLOR_MAP['RESET'])
            status_text = status_texts.get(status_key, status_key.upper())
            colored_log(logging.INFO, f"  - {color_start}{status_text}{COLOR_MAP['RESET']}: {count} channels")
            processed_keys.add(status_key)
    for status_key, count in channel_status_counts.items():
         if status_key not in processed_keys:
             color_start = status_colors.get(status_key, COLOR_MAP['RESET'])
             status_text = status_texts.get(status_key, status_key.replace('_', ' ').upper())
             colored_log(logging.INFO, f"  - {color_start}{status_text}{COLOR_MAP['RESET']}: {count} channels")

    colored_log(logging.INFO, f"\n✨ Proxies found (before final deduplication): {total_proxies_found_before_dedup}")
    colored_log(logging.INFO, f"🧬 Proxies after DNS resolution & deduplication: {proxies_after_dns_count}")
    if proxies_after_test_count is not None:
        colored_log(logging.INFO, f"✅ Proxies passed connectivity test: {proxies_after_test_count}")
    colored_log(logging.INFO, f"📝 Total proxies saved: {all_proxies_saved_count} (to {output_file_path}, format: {output_format.value})")

    colored_log(logging.INFO, "\n🔬 Protocol Breakdown (saved proxies):")
    if protocol_counts:
        for protocol, count in sorted(protocol_counts.items()):
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   No protocol statistics available for saved proxies.")

    colored_log(logging.INFO, "\n⭐️ Proxy Quality Category Distribution (saved proxies):")
    if quality_category_counts:
         category_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
         for category, count in sorted(quality_category_counts.items(), key=lambda item: category_order.get(item[0], 99)):
             colored_log(logging.INFO, f"   - {category}: {count} proxies")
    else:
        colored_log(logging.INFO, "   No quality category statistics available for saved proxies.")
    colored_log(logging.INFO, "======================== 🏁 STATISTICS END =========================")


# --- Обновленная main функция ---
async def main() -> None:
    """Основная асинхронная функция запуска скрипта."""
    parser = argparse.ArgumentParser(description="Proxy Downloader Script")
    parser.add_argument('--nocolorlogs', action='store_true', help='Disable colored console logs')
    parser.add_argument('--test-proxies', action='store_true', help='Enable basic connectivity test for proxies')
    parser.add_argument(
        '--output-format',
        type=str,
        choices=[f.value for f in OutputFormat],
        default=OutputFormat.TEXT.value,
        help=f'Output file format (default: {OutputFormat.TEXT.value})'
    )
    parser.add_argument(
        '--input', '-i',
        type=str,
        default=CONFIG_FILES.ALL_URLS,
        help=f'Input file with channel URLs (default: {CONFIG_FILES.ALL_URLS})'
     )
    parser.add_argument(
         '--output', '-o',
         type=str,
         default=CONFIG_FILES.OUTPUT_ALL_CONFIG,
         help=f'Output file path base (without extension) (default: {CONFIG_FILES.OUTPUT_ALL_CONFIG})'
     )

    args = parser.parse_args()

    console_formatter.use_colors = not args.nocolorlogs
    output_format_enum = OutputFormat(args.output_format)
    input_file = args.input
    output_file_base = args.output

    # Проверка зависимостей для форматов
    if output_format_enum == OutputFormat.CLASH and not yaml:
         colored_log(logging.ERROR, "❌ PyYAML is required for Clash output format. Please install: pip install pyyaml")
         sys.exit(1)

    try:
        start_time = time.time()
        # 1. Загрузка URL каналов
        channel_urls = await load_channel_urls(input_file)
        total_channels_requested = len(channel_urls)
        if not channel_urls:
            colored_log(logging.WARNING, "No channel URLs found in the input file. Exiting.")
            return

        # 2. Инициализация
        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        async with aiohttp.ClientSession() as session:
            # 3. Обработка каналов (скачивание, парсинг, DNS)
            (total_proxies_found_before_dedup, channels_processed_count,
             proxies_after_dns, # Список уникальных прокси после DNS
             channel_status_counts) = await load_and_process_channels(
                channel_urls, session, resolver)

        proxies_after_dns_count = len(proxies_after_dns)
        proxies_to_save_with_results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]] = []
        proxies_after_test_count: Optional[int] = None # Статистика

        # 4. Тестирование (если включено)
        if args.test_proxies:
            test_results_with_proxies = await run_proxy_tests(proxies_after_dns)
            # Фильтруем только рабочие прокси
            working_proxies_with_results = [
                (proxy, result) for proxy, result in test_results_with_proxies if result['status'] == 'ok'
            ]
            proxies_after_test_count = len(working_proxies_with_results)
            # Сортируем рабочие прокси по задержке (возрастание)
            working_proxies_with_results.sort(key=lambda item: item[1]['latency'] or float('inf'))
            proxies_to_save_with_results = working_proxies_with_results
            logger.info(f"Filtered proxies after testing. Kept {proxies_after_test_count} working proxies.")
        else:
            # Если тесты не запускались, сортируем по качеству и готовим к сохранению
            proxies_after_dns.sort(key=lambda p: p.quality_score, reverse=True)
            proxies_to_save_with_results = [(proxy, None) for proxy in proxies_after_dns] # Результат теста None
            logger.info("Skipping proxy connectivity tests.")


        # 5. Сохранение результатов
        # Определяем полный путь к файлу на основе формата
        if output_format_enum == OutputFormat.JSON: file_ext = ".json"
        elif output_format_enum == OutputFormat.CLASH: file_ext = ".yaml"
        else: file_ext = ".txt"
        output_file_path = output_file_base + file_ext

        all_proxies_saved_count = save_proxies(
            proxies_to_save_with_results,
            output_file_base, # Передаем базу имени
            output_format_enum
        )

        # 6. Сбор статистики для сохраненных прокси
        saved_protocol_counts: DefaultDict[str, int] = defaultdict(int)
        saved_quality_category_counts: DefaultDict[str, int] = defaultdict(int)
        for proxy, _ in proxies_to_save_with_results: # Берем только сохраненные
             if all_proxies_saved_count > 0: # Считаем статистику только если что-то сохранено
                 saved_protocol_counts[proxy.protocol] += 1
                 quality_category = get_quality_category(proxy.quality_score)
                 saved_quality_category_counts[quality_category] += 1


        # 7. Вывод итоговой статистики
        output_statistics(start_time, total_channels_requested, channels_processed_count,
                          channel_status_counts, total_proxies_found_before_dedup,
                          proxies_after_dns_count, proxies_after_test_count,
                          all_proxies_saved_count, saved_protocol_counts,
                          saved_quality_category_counts, output_file_path, # Передаем полный путь
                          output_format_enum)

    except Exception as e:
        logger.critical(f"Unexpected critical error in main execution: {e}", exc_info=True)
        sys.exit(1)
    finally:
        colored_log(logging.INFO, "✅ Proxy download and processing script finished.")


if __name__ == "__main__":
    # Установка политики цикла событий для Windows, если нужно (для ProactorEventLoop)
    # if sys.platform == 'win32':
    #     asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())
