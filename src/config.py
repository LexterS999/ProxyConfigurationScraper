import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import json
import sys
# import argparse # Убрали argparse
import dataclasses
import random
import aiohttp
import base64
import time
import binascii
import ssl
import contextlib # Для asynccontextmanager
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlunparse, unquote
from typing import ( # Импорты typing сгруппированы для читаемости
    Dict, List, Optional, Tuple, Set, DefaultDict, Any, Union, NamedTuple, Sequence, AsyncIterator
)
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from string import Template
from functools import lru_cache

# --- Зависимости с проверкой ---
try:
    from tqdm.asyncio import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Определяем заглушку для tqdm.gather, если tqdm недоступен
    async def gather_stub(*tasks, desc=None, unit=None, disable=False, **kwargs):
        log_func = logger.info if 'logger' in globals() and logger.hasHandlers() else print
        if not disable and desc and sys.stdout.isatty():
             log_func(f"Processing: {desc}...")
        return await asyncio.gather(*tasks)
    class TqdmStub:
        gather = gather_stub
    tqdm = TqdmStub() # type: ignore
    print("Optional dependency 'tqdm' not found. Progress bars will be disabled. Install with: pip install tqdm", file=sys.stderr)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None # type: ignore
    YAML_AVAILABLE = False
    # Предупреждение будет выдано позже, если выбран формат Clash

# --- КОНФИГУРАЦИЯ (Замена аргументов командной строки) ---

# --- Input/Output ---
INPUT_FILE = "channel_urls.txt" # Файл со списком URL каналов подписок.
OUTPUT_BASE = "configs/proxy_configs_all" # Базовый путь для сохранения файлов результатов (без расширения).
OUTPUT_FORMAT = "text" # Формат выходного файла: "text", "json", "clash"

# --- Network ---
DNS_TIMEOUT = 15 # Таймаут для одного DNS запроса (секунды).
HTTP_TIMEOUT = 15 # Общий таймаут для HTTP запроса к каналу (секунды).
MAX_RETRIES = 4 # Максимальное количество повторных попыток скачивания канала.
RETRY_DELAY_BASE = 2.0 # Базовая задержка перед повторной попыткой (секунды, удваивается).
USER_AGENT = 'ProxyDownloader/1.2' # User-Agent для HTTP запросов.

# --- Testing ---
ENABLE_TESTING = True # Включить базовое тестирование соединения прокси (TCP/TLS).
TEST_TIMEOUT = 10 # Таймаут для одного теста соединения (секунды).
TEST_SNI = "www.google.com" # Hostname (SNI) для использования при TLS тестировании (если не указан в URL).
TEST_PORT = 443 # Порт для тестирования соединения (обычно 443 для TLS).

# --- Concurrency ---
MAX_CHANNELS_CONCURRENT = 60 # Максимальное количество одновременно обрабатываемых каналов.
MAX_DNS_CONCURRENT = 50 # Максимальное количество одновременных DNS запросов.
MAX_TESTS_CONCURRENT = 30 # Максимальное количество одновременных тестов соединения.

# --- Logging ---
LOG_LEVEL = "INFO" # Уровень логирования для консоли: 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
LOG_FILE_PATH = 'proxy_downloader.log' # Путь к файлу логов (JSON формат)
NO_COLOR_LOGS = False # Отключить цветной вывод логов в консоли.

# --- Differential Output (Diff Mode) ---
ENABLE_DIFF_MODE = True # Включить режим сравнения с предыдущим результатом.
# ВНИМАНИЕ: При ENABLE_DIFF_MODE = True, рекомендуется OUTPUT_FORMAT = "text",
# так как чтение предыдущего состояния реализовано только для .txt файла.
# Если предыдущий файл не найден или не .txt, все текущие прокси будут показаны как "Added".
DIFF_PREVIOUS_FILE_PATH = None # Путь к файлу предыдущего результата для сравнения.
                               # Если None, используется стандартный выходной файл (OUTPUT_BASE + ".txt").
DIFF_REPORT_FILE_PATH = None # Путь для сохранения отчета об изменениях.
                             # Если None, используется OUTPUT_BASE + ".diff.txt".
# ВНИМАНИЕ: DIFF_LATENCY_THRESHOLD не используется, т.к. текстовый формат не хранит latency.
# DIFF_LATENCY_THRESHOLD_PERCENT = 25.0
UPDATE_OUTPUT_IN_DIFF = False # В режиме diff, обновлять ли основной выходной файл (OUTPUT_BASE + ext)?
                              # По умолчанию False, чтобы сохранить историю для следующего diff.

# --- Проверка зависимостей для форматов при старте ---
if OUTPUT_FORMAT == "clash" and not YAML_AVAILABLE:
    print(f"Error: Output format '{OUTPUT_FORMAT}' requires PyYAML library.", file=sys.stderr)
    print("Please install it: pip install pyyaml", file=sys.stderr)
    sys.exit(1)
# ---------------------------------------------------------


# --- Constants ---
# LOG_FILE = 'proxy_downloader.log' # Заменено на LOG_FILE_PATH
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
# Формат для JSON логов (ключи - имена полей в JSON)
LOG_FORMAT_JSON_KEYS: Dict[str, str] = {
    "time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s",
    "logger": "%(name)s", "module": "%(module)s", "funcName": "%(funcName)s",
    "lineno": "%(lineno)d", "process": "%(process)d", "threadName": "%(threadName)s",
}

# --- Регулярные выражения ---
PROTOCOL_REGEX = re.compile(r"^(vless|tuic|hy2|ss|ssr|trojan)://", re.IGNORECASE)

# --- Шаблоны и Веса ---
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}") # Базовый шаблон
QUALITY_SCORE_WEIGHTS = {
    "protocol": {"vless": 5, "trojan": 5, "tuic": 4, "hy2": 3, "ss": 2, "ssr": 1},
    "security": {"tls": 3, "none": 0},
    "transport": {"ws": 2, "websocket": 2, "grpc": 2, "tcp": 1, "udp": 0},
}
QUALITY_CATEGORIES = {
    "High": range(8, 15), "Medium": range(4, 8), "Low": range(0, 4),
}

# --- Цвета для логов ---
COLOR_MAP = {
    logging.INFO: '\033[92m', logging.DEBUG: '\033[94m', logging.WARNING: '\033[93m',
    logging.ERROR: '\033[91m', logging.CRITICAL: '\033[1m\033[91m', 'RESET': '\033[0m'
}

# --- Форматы вывода ---
class OutputFormatEnum(Enum):
    TEXT = "text"
    JSON = "json"
    CLASH = "clash"

# --- Типы данных ---
TEST_RESULT_TYPE = Dict[str, Union[str, Optional[float], Optional[str]]]

class Statistics(NamedTuple):
    start_time: float
    total_channels_requested: int
    channels_processed_count: int
    channel_status_counts: DefaultDict[str, int]
    total_proxies_found_before_dedup: int
    proxies_after_dns_count: int
    proxies_after_test_count: Optional[int]
    final_saved_count: int # Количество прокси в основном файле или 0 в diff-режиме (если не обновляется)
    output_file_path: str # Путь к основному файлу или diff-отчету
    output_format: OutputFormatEnum # Формат основного файла или diff-отчета
    is_diff_mode: bool
    diff_details: Optional[Dict[str, int]] # Статистика diff {'added': N, 'removed': N}

# --- Data Structures ---
class Protocols(Enum):
    VLESS = "vless"; TUIC = "tuic"; HY2 = "hy2"; SS = "ss"; SSR = "ssr"; TROJAN = "trojan"
ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]

# --- Исключения ---
class InvalidURLError(ValueError): pass
class UnsupportedProtocolError(ValueError): pass
class EmptyChannelError(Exception): pass
class DownloadError(Exception): pass
class ProxyTestError(Exception): pass
class ConfigError(Exception): pass

# --- Датаклассы ---
@dataclass(frozen=True)
class ProxyParsedConfig:
    """Представление распарсенной конфигурации прокси."""
    config_string: str
    protocol: str
    address: str # Оригинальный адрес (может быть hostname или IP)
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    quality_score: int = 0 # Рассчитывается позже

    # Используем оригинальный адрес для хеша/равенства до этапа DNS
    def __hash__(self):
        return hash((self.protocol, self.address.lower(), self.port, frozenset(self.query_params.items())))

    def __eq__(self, other):
        if not isinstance(other, ProxyParsedConfig): return NotImplemented
        return (self.protocol == other.protocol and
                self.address.lower() == other.address.lower() and
                self.port == other.port and
                self.query_params == other.query_params)

    def __str__(self):
        return (f"ProxyParsedConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, quality={self.quality_score}, remark='{self.remark[:30]}...')")

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
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
            if not address or not port or not 1 <= port <= 65535 or ' ' in address: return None

            remark = unquote(parsed_url.fragment) if parsed_url.fragment else ""
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v}
            config_string_to_store = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                 parsed_url.params, parsed_url.query, ''))
            return cls(config_string=config_string_to_store, protocol=protocol, address=address,
                       port=port, remark=remark, query_params=query_params)
        except ValueError as e:
            logger.debug(f"URL parsing ValueError for '{original_string[:100]}...': {e}")
            return None
        except Exception as e:
             logger.error(f"Unexpected error parsing URL '{original_string[:100]}...': {e}", exc_info=False) # Меньше шума в логах
             return None

# --- Глобальный логгер ---
logger = logging.getLogger(__name__)

# --- Функции настройки ---
def setup_logging(log_level_str: str = "INFO", log_file: str = "app.log", nocolor: bool = False) -> None:
    """Настраивает логирование в файл (JSON) и консоль (Цветной/Простой)."""
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers(): logger.handlers.clear()

    # --- Файловый обработчик (JSON) ---
    class JsonFormatter(logging.Formatter):
        default_msec_format = '%s.%03d'
        def format(self, record: logging.LogRecord) -> str:
            log_record: Dict[str, Any] = {}
            for key, format_specifier in LOG_FORMAT_JSON_KEYS.items():
                if hasattr(record, key): log_record[key] = getattr(record, key)
                elif key == 'time': log_record[key] = self.formatTime(record, self.default_time_format)
                elif key == 'message': log_record[key] = record.getMessage()
                else: log_record[key] = record.__dict__.get(key, None)
            log_record["level"] = record.levelname
            log_record["message"] = record.getMessage()
            log_record["time"] = self.formatTime(record, self.datefmt or self.default_time_format)
            if hasattr(record, 'taskName') and record.taskName: log_record['taskName'] = record.taskName
            if record.exc_info: log_record['exception'] = self.formatException(record.exc_info)
            if record.stack_info: log_record['stack_info'] = self.formatStack(record.stack_info)
            extra_keys = set(record.__dict__) - set(LOG_FORMAT_JSON_KEYS.keys()) - {'args', 'exc_info', 'exc_text', 'levelno', 'msg', 'pathname', 'relativeCreated', 'stack_info', 'taskName', 'created', 'msecs', 'name'}
            for key in extra_keys: log_record[key] = record.__dict__[key]
            try: return json.dumps(log_record, ensure_ascii=False, default=str)
            except Exception as e: return f'{{"level": "ERROR", "logger": "{record.name}", "message": "Failed to serialize log record to JSON: {e}", "original_record": "{str(log_record)[:200]}..."}}'
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir): os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
        file_handler.setLevel(logging.DEBUG)
        formatter_file = JsonFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
        file_handler.setFormatter(formatter_file)
        logger.addHandler(file_handler)
    except Exception as e: print(f"Error setting up file logger to '{log_file}': {e}", file=sys.stderr)

    # --- Консольный обработчик ---
    class ColoredFormatter(logging.Formatter):
        def __init__(self, fmt: str = CONSOLE_LOG_FORMAT, datefmt: Optional[str] = None, use_colors: bool = True):
            super().__init__(fmt, datefmt=datefmt)
            self.use_colors = use_colors and sys.stdout.isatty()
        def format(self, record: logging.LogRecord) -> str:
            message = super().format(record)
            if self.use_colors:
                color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET'])
                return f"{color_start}{message}{COLOR_MAP['RESET']}"
            return message

    console_handler_out = logging.StreamHandler(sys.stdout)
    console_handler_out.addFilter(lambda record: record.levelno < logging.WARNING)
    console_handler_out.setLevel(log_level)
    console_formatter_out = ColoredFormatter(use_colors=not nocolor)
    console_handler_out.setFormatter(console_formatter_out)
    logger.addHandler(console_handler_out)

    console_handler_err = logging.StreamHandler(sys.stderr)
    console_handler_err.setLevel(logging.WARNING)
    if log_level < logging.WARNING: console_handler_err.setLevel(logging.WARNING)
    else: console_handler_err.setLevel(log_level)
    console_formatter_err = ColoredFormatter(use_colors=not nocolor)
    console_handler_err.setFormatter(console_formatter_err)
    logger.addHandler(console_handler_err)

    logging.getLogger("aiodns").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)

# --- Вспомогательные функции ---
@lru_cache(maxsize=2048)
def is_valid_ipv4(hostname: str) -> bool:
    if not hostname: return False
    try: ipaddress.IPv4Address(hostname); return True
    except ipaddress.AddressValueError: return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver, timeout: int) -> Optional[str]:
    if is_valid_ipv4(hostname): return hostname
    try:
        async with asyncio.timeout(timeout):
            logger.debug(f"Attempting DNS query for {hostname}")
            result = await resolver.query(hostname, 'A')
            if result:
                resolved_ip = result[0].host
                if is_valid_ipv4(resolved_ip):
                    logger.debug(f"DNS resolved {hostname} to {resolved_ip}")
                    return resolved_ip
                else: logger.warning(f"DNS query for A record of {hostname} returned non-IPv4 address: {resolved_ip}"); return None
            else: logger.debug(f"DNS query for {hostname} returned no results."); return None
    except asyncio.TimeoutError: logger.debug(f"DNS resolution timeout for {hostname} after {timeout}s"); return None
    except aiodns.error.DNSError as e:
        error_code = e.args[0] if e.args else "Unknown"; error_msg = str(e.args[1]) if len(e.args) > 1 else "No details"
        if error_code == aiodns.error.ARES_ENOTFOUND or error_code == 3: logger.debug(f"DNS resolution error for {hostname}: Host not found (NXDOMAIN / {error_code})")
        elif error_code == aiodns.error.ARES_ECONNREFUSED or error_code == 5: logger.debug(f"DNS resolution error for {hostname}: Connection refused by server (REFUSED / {error_code})")
        elif error_code == aiodns.error.ARES_ETIMEOUT: logger.debug(f"DNS resolution error for {hostname}: Internal timeout (ARES_ETIMEOUT / {error_code})")
        else: logger.warning(f"DNS resolution error for {hostname}: Code={error_code}, Msg='{error_msg}'")
        return None
    except TypeError as e: logger.warning(f"DNS resolution TypeError for hostname '{hostname}': {e}"); return None
    except Exception as e: logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True); return None

def assess_proxy_quality(proxy_config: ProxyParsedConfig) -> int:
    score = 0; protocol = proxy_config.protocol.lower(); query_params = proxy_config.query_params
    score += QUALITY_SCORE_WEIGHTS["protocol"].get(protocol, 0)
    security = query_params.get("security", "none").lower()
    score += QUALITY_SCORE_WEIGHTS["security"].get(security, 0)
    transport = query_params.get("type", query_params.get("transport", "tcp")).lower()
    if transport == "websocket": transport = "ws"
    score += QUALITY_SCORE_WEIGHTS["transport"].get(transport, 0)
    return score

def get_quality_category(score: int) -> str:
    for category, score_range in QUALITY_CATEGORIES.items():
        if score_range.start <= score < score_range.stop: return category
    if score >= QUALITY_CATEGORIES["High"].start: return "High"
    if score < QUALITY_CATEGORIES["Low"].stop: return "Low"
    return "Unknown"

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE] = None) -> str:
    protocol = proxy_config.protocol.upper()
    transport = proxy_config.query_params.get('type', proxy_config.query_params.get('transport', 'tcp')).lower()
    if transport == "websocket": transport = "ws"
    security = proxy_config.query_params.get('security', 'none').lower()
    quality_category = get_quality_category(proxy_config.quality_score)
    name_parts = [protocol, transport, security, f"Q{proxy_config.quality_score}", quality_category]
    if test_result and test_result.get('status') == 'ok' and isinstance(test_result.get('latency'), (int, float)):
        latency_ms = int(test_result['latency'] * 1000)
        name_parts.append(f"{latency_ms}ms")
    base_name = "-".join(name_parts)
    if proxy_config.remark:
        safe_remark = re.sub(r'[^\w\-\_]+', '_', proxy_config.remark, flags=re.UNICODE).strip('_')
        if safe_remark: base_name += f"_{safe_remark}"
    max_len = 70
    if len(base_name) > max_len:
        try:
            base_name_bytes = base_name.encode('utf-8')
            if len(base_name_bytes) > max_len - 3: base_name = base_name_bytes[:max_len-3].decode('utf-8', errors='ignore') + "..."
            else: base_name = base_name[:max_len-3] + "..."
        except Exception: base_name = base_name[:max_len-3] + "..."
    return base_name

# --- Основные функции обработки ---
async def download_proxies_from_channel(
    channel_url: str, session: aiohttp.ClientSession, http_timeout: int,
    max_retries: int, retry_delay_base: float, user_agent: str
) -> List[str]:
    retries_attempted = 0; last_exception: Optional[Exception] = None
    headers = {'User-Agent': user_agent}
    session_timeout = aiohttp.ClientTimeout(total=http_timeout)

    while retries_attempted <= max_retries:
        try:
            logger.debug(f"Attempting download from {channel_url} (Attempt {retries_attempted + 1}/{max_retries + 1})")
            async with session.get(channel_url, timeout=session_timeout, headers=headers, allow_redirects=True, verify_ssl=False) as response:
                content_type = response.headers.get('Content-Type', 'N/A')
                logger.debug(f"Received response from {channel_url}: Status={response.status}, Content-Type='{content_type}'")
                response.raise_for_status()
                content_bytes = await response.read()
                if not content_bytes or content_bytes.isspace():
                    logger.warning(f"Channel {channel_url} returned empty or whitespace-only response.")
                    raise EmptyChannelError(f"Channel {channel_url} returned empty response.")

                decoded_text: Optional[str] = None; decode_method: str = "Unknown"
                try: # Попытка Base64
                    base64_text_no_spaces = "".join(content_bytes.decode('latin-1').split())
                    base64_bytes_stripped = base64_text_no_spaces.encode('latin-1')
                    missing_padding = len(base64_bytes_stripped) % 4
                    base64_bytes_padded = base64_bytes_stripped + b'=' * (4 - missing_padding) if missing_padding else base64_bytes_stripped
                    b64_decoded_bytes = base64.b64decode(base64_bytes_padded, validate=True)
                    decoded_text_from_b64 = b64_decoded_bytes.decode('utf-8')
                    if PROTOCOL_REGEX.search(decoded_text_from_b64):
                        logger.debug(f"Content from {channel_url} successfully decoded as Base64 -> UTF-8.")
                        decoded_text = decoded_text_from_b64; decode_method = "Base64 -> UTF-8"
                    else: logger.debug(f"Content from {channel_url} decoded from Base64, but no protocol found. Assuming plain text.")
                except (binascii.Error, ValueError): logger.debug(f"Content from {channel_url} is not valid Base64. Assuming plain text.")
                except UnicodeDecodeError as e: logger.warning(f"Content from {channel_url} decoded from Base64, but result is not valid UTF-8: {e}. Assuming plain text.")
                except Exception as e: logger.error(f"Unexpected error during Base64 processing for {channel_url}: {e}", exc_info=False)

                if decoded_text is None: # Попытка Plain Text
                    try:
                        logger.debug(f"Attempting to decode content from {channel_url} as plain UTF-8 text.")
                        decoded_text = content_bytes.decode('utf-8'); decode_method = "Plain UTF-8"
                        if decode_method == "Base64 -> UTF-8" and not PROTOCOL_REGEX.search(decoded_text): logger.warning(f"Content from {channel_url} decoded as UTF-8, but still no protocol found.")
                    except UnicodeDecodeError:
                        logger.warning(f"UTF-8 decoding failed for {channel_url} (plain text). Attempting with 'replace' errors.")
                        try:
                            decoded_text = content_bytes.decode('utf-8', errors='replace'); decode_method = "Plain UTF-8 (with replace)"
                            if not PROTOCOL_REGEX.search(decoded_text): logger.warning(f"Content from {channel_url} decoded with replace errors, but still no protocol found.")
                        except Exception as e: logger.error(f"Failed to decode content from {channel_url} even with errors='replace': {e}", exc_info=True); raise DownloadError(f"Failed to decode content from {channel_url}") from e

                if decoded_text is not None:
                    logger.info(f"Successfully decoded content from {channel_url} using method: {decode_method}")
                    lines = [line for line in decoded_text.splitlines() if line.strip() and not line.strip().startswith('#')]
                    if not lines: logger.warning(f"Channel {channel_url} decoded successfully but contains no non-empty/non-comment lines."); raise EmptyChannelError(f"Channel {channel_url} has no valid lines after decoding.")
                    return lines
                else: logger.error(f"Failed to decode content from {channel_url} using any method."); raise DownloadError(f"Failed to decode content from {channel_url}")

        except (aiohttp.ClientResponseError, aiohttp.ClientHttpProxyError, aiohttp.ClientProxyConnectionError) as e:
            status = getattr(e, 'status', 'N/A'); logger.warning(f"HTTP/Proxy error getting {channel_url}: Status={status}, Error='{e}'"); last_exception = DownloadError(f"HTTP/Proxy error {status} for {channel_url}"); break
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError) as e:
            logger.warning(f"Connection/Timeout error getting {channel_url} (attempt {retries_attempted+1}/{max_retries+1}): {type(e).__name__}. Retrying..."); last_exception = e
            retry_delay = retry_delay_base * (2 ** retries_attempted) + random.uniform(-0.5 * retry_delay_base, 0.5 * retry_delay_base); retry_delay = max(0.5, retry_delay); await asyncio.sleep(retry_delay)
        except EmptyChannelError as e: last_exception = e; break
        except Exception as e: logger.error(f"Unexpected error downloading/processing {channel_url}: {e}", exc_info=False); last_exception = DownloadError(f"Unexpected error for {channel_url}"); break
        retries_attempted += 1

    if last_exception:
        if retries_attempted > max_retries: logger.error(f"Max retries ({max_retries+1}) reached for {channel_url}. Last error: {type(last_exception).__name__}"); raise DownloadError(f"Max retries reached for {channel_url}") from last_exception
        else: logger.error(f"Failed to download {channel_url} due to non-retriable error: {type(last_exception).__name__}"); raise last_exception
    else: logger.critical(f"Download loop finished unexpectedly without error/success for {channel_url}"); raise DownloadError(f"Download failed unexpectedly for {channel_url}")

def parse_proxy_lines(lines: List[str], channel_url: str = "N/A") -> Tuple[List[ProxyParsedConfig], int, int]:
    parsed_configs: List[ProxyParsedConfig] = []; processed_configs_set: Set[ProxyParsedConfig] = set()
    invalid_url_count = 0; duplicate_count = 0
    for line_num, line in enumerate(lines, 1):
        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config is None: invalid_url_count += 1; continue
        if parsed_config in processed_configs_set: logger.debug(f"Channel '{channel_url}': Skipping duplicate proxy (initial parse): {parsed_config.address}:{parsed_config.port}"); duplicate_count += 1; continue
        processed_configs_set.add(parsed_config); parsed_configs.append(parsed_config)
    logger.debug(f"Channel '{channel_url}': Initial parsing yielded {len(parsed_configs)} potentially valid configs. Skipped {invalid_url_count} invalid lines, {duplicate_count} duplicates.")
    return parsed_configs, invalid_url_count, duplicate_count

async def resolve_and_assess_proxies(
    configs: List[ProxyParsedConfig], resolver: aiodns.DNSResolver, dns_timeout: int,
    dns_semaphore: asyncio.Semaphore, channel_url: str = "N/A"
) -> Tuple[List[ProxyParsedConfig], int]:
    resolved_configs_with_score: List[ProxyParsedConfig] = []; dns_failed_or_duplicate_count = 0
    final_unique_keys: Set[tuple] = set()

    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal dns_failed_or_duplicate_count; resolved_ip: Optional[str] = None
        try:
            async with dns_semaphore: resolved_ip = await resolve_address(config.address, resolver, dns_timeout)
        except Exception as e: logger.error(f"Unexpected error in resolve_task for {config.address} from {channel_url}: {e}", exc_info=False); dns_failed_or_duplicate_count += 1; return None
        if resolved_ip:
            quality_score = assess_proxy_quality(config)
            final_key = (config.protocol, resolved_ip, config.port, frozenset(config.query_params.items()))
            if final_key not in final_unique_keys:
                final_unique_keys.add(final_key)
                return dataclasses.replace(config, quality_score=quality_score)
            else: logger.debug(f"Channel '{channel_url}': Skipping duplicate proxy after DNS resolution: {config.address} -> {resolved_ip}"); dns_failed_or_duplicate_count += 1; return None
        else: logger.debug(f"Channel '{channel_url}': DNS resolution failed for {config.address}"); dns_failed_or_duplicate_count += 1; return None

    tasks = [resolve_task(cfg) for cfg in configs]
    results = await tqdm.gather(
        *tasks, desc=f"Resolving DNS ({channel_url.split('/')[-1][:20]}...)", unit="proxy",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty()
    )
    resolved_configs_with_score = [res for res in results if res is not None]
    logger.debug(f"Channel '{channel_url}': DNS Resolution & Assessment finished. {len(resolved_configs_with_score)} unique configs resolved. {dns_failed_or_duplicate_count} DNS failures or post-resolution duplicates.")
    return resolved_configs_with_score, dns_failed_or_duplicate_count

async def test_proxy_connectivity(
    proxy_config: ProxyParsedConfig, test_timeout: int, test_sni: str, test_port: int
) -> TEST_RESULT_TYPE:
    start_time = time.monotonic(); writer = None
    host = proxy_config.address; connect_port = proxy_config.port
    use_tls = proxy_config.query_params.get('security', 'none').lower() == 'tls'
    sni_host = proxy_config.query_params.get('sni', proxy_config.query_params.get('host'))
    if not sni_host and not is_valid_ipv4(host): sni_host = host
    elif not sni_host and is_valid_ipv4(host): sni_host = test_sni
    result: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': 'Unknown error'}

    try:
        logger.debug(f"Testing connection to {host}:{connect_port} (TLS: {use_tls}, SNI: {sni_host or 'N/A'})")
        async with asyncio.timeout(test_timeout):
            reader, writer = await asyncio.open_connection(host, connect_port)
            if use_tls:
                logger.debug(f"Attempting TLS handshake with {host}:{connect_port} (SNI: {sni_host or 'N/A'})")
                ssl_context = ssl.create_default_context()
                allow_insecure = proxy_config.query_params.get('allowInsecure', '0').lower()
                if allow_insecure == '1' or allow_insecure == 'true':
                    ssl_context.check_hostname = False; ssl_context.verify_mode = ssl.CERT_NONE
                    logger.debug(f"TLS verification disabled for {host}:{connect_port} due to allowInsecure=True")
                transport = writer.get_extra_info('transport')
                if not transport: raise ProxyTestError("Could not get transport info for TLS handshake")
                loop = asyncio.get_running_loop()
                await loop.start_tls(transport, ssl_context, server_hostname=sni_host if sni_host else None)
                logger.debug(f"TLS handshake successful for {host}:{connect_port}")
            latency = time.monotonic() - start_time
            logger.debug(f"Connection test OK for {host}:{connect_port}, Latency: {latency:.4f}s")
            result = {'status': 'ok', 'latency': latency, 'error': None}
    except asyncio.TimeoutError: logger.debug(f"Connection test TIMEOUT for {host}:{connect_port} after {test_timeout}s"); result = {'status': 'failed', 'latency': None, 'error': f'Timeout ({test_timeout}s)'}
    except ssl.SSLCertVerificationError as e: logger.debug(f"Connection test FAILED for {host}:{connect_port}: TLS Cert Verify Error: {getattr(e, 'reason', e)}"); result = {'status': 'failed', 'latency': None, 'error': f"TLS Cert Verify Error: {getattr(e, 'reason', e)}"}
    except ssl.SSLError as e: logger.debug(f"Connection test FAILED for {host}:{connect_port}: TLS Handshake Error: {e}"); result = {'status': 'failed', 'latency': None, 'error': f"TLS Handshake Error: {e}"}
    except ConnectionRefusedError: logger.debug(f"Connection test FAILED for {host}:{connect_port}: Connection Refused"); result = {'status': 'failed', 'latency': None, 'error': 'Connection Refused'}
    except OSError as e: error_msg = getattr(e, 'strerror', str(e)); error_no = getattr(e, 'errno', 'N/A'); logger.debug(f"Connection test FAILED for {host}:{connect_port}: OS Error: {error_msg} (errno={error_no})"); result = {'status': 'failed', 'latency': None, 'error': f"OS Error: {error_msg}"}
    except ProxyTestError as e: logger.debug(f"Connection test FAILED for {host}:{connect_port}: ProxyTestError: {e}"); result = {'status': 'failed', 'latency': None, 'error': f"Test Logic Error: {e}"}
    except Exception as e: logger.error(f"Unexpected error during connection test for {host}:{connect_port}: {e}", exc_info=False); result = {'status': 'failed', 'latency': None, 'error': f"Unexpected Error: {type(e).__name__}"}
    finally:
        if writer:
            try:
                if not writer.is_closing(): writer.close(); await writer.wait_closed()
            except Exception as e: logger.debug(f"Error closing writer for {host}:{connect_port}: {e}")
    return result

async def run_proxy_tests(
    proxies: List[ProxyParsedConfig], test_timeout: int, test_sni: str,
    test_port: int, test_semaphore: asyncio.Semaphore
) -> List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]]:
    if not proxies: return []
    results_with_proxies: List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]] = []

    async def test_task_wrapper(proxy: ProxyParsedConfig) -> Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]:
        try:
            async with test_semaphore: result = await test_proxy_connectivity(proxy, test_timeout, test_sni, test_port)
            return proxy, result
        except Exception as e:
            logger.error(f"Critical error in test_task_wrapper for {proxy.address}:{proxy.port}: {e}", exc_info=False)
            error_result: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': f'Wrapper Error: {type(e).__name__}'}
            return proxy, error_result

    tasks = [test_task_wrapper(p) for p in proxies]
    results_with_proxies = await tqdm.gather(
        *tasks, desc="Testing Proxies", unit="proxy",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty()
    )
    ok_count = sum(1 for _, res in results_with_proxies if res['status'] == 'ok')
    failed_count = len(results_with_proxies) - ok_count
    logger.info(f"Proxy Connectivity Test Results: {ok_count} OK, {failed_count} Failed.")
    return results_with_proxies

# --- Функции сохранения результатов ---
def _proxy_to_clash_dict(proxy_conf: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE]) -> Optional[Dict[str, Any]]:
    clash_proxy: Dict[str, Any] = {}; params = proxy_conf.query_params; protocol = proxy_conf.protocol.lower()
    try: parsed_original_url = urlparse(proxy_conf.config_string); url_username = unquote(parsed_original_url.username) if parsed_original_url.username else None
    except Exception as e: logger.warning(f"Could not re-parse original URL for Clash conversion: {proxy_conf.config_string} - {e}"); return None

    clash_proxy['name'] = generate_proxy_profile_name(proxy_conf, test_result)
    clash_proxy['server'] = proxy_conf.address; clash_proxy['port'] = proxy_conf.port; clash_proxy['udp'] = True
    try:
        if protocol == 'vless':
            clash_proxy['type'] = 'vless'; clash_proxy['uuid'] = url_username; clash_proxy['tls'] = params.get('security', 'none').lower() == 'tls'
            clash_proxy['network'] = params.get('type', 'tcp').lower(); clash_proxy['flow'] = params.get('flow')
            clash_proxy['servername'] = params.get('sni', params.get('host')) or (proxy_conf.address if not is_valid_ipv4(proxy_conf.address) else None)
            allow_insecure = params.get('allowInsecure', '0').lower(); clash_proxy['skip-cert-verify'] = allow_insecure == '1' or allow_insecure == 'true'
            if clash_proxy['network'] == 'ws': ws_host = params.get('host', clash_proxy.get('servername', proxy_conf.address)); ws_path = params.get('path', '/'); clash_proxy['ws-opts'] = {'path': ws_path, 'headers': {'Host': ws_host}}
            elif clash_proxy['network'] == 'grpc': grpc_service_name = params.get('serviceName', ''); clash_proxy['grpc-opts'] = {'grpc-service-name': grpc_service_name}
        elif protocol == 'trojan':
            clash_proxy['type'] = 'trojan'; clash_proxy['password'] = url_username; clash_proxy['tls'] = params.get('security', 'tls').lower() == 'tls'
            clash_proxy['sni'] = params.get('sni', params.get('peer')) or (proxy_conf.address if not is_valid_ipv4(proxy_conf.address) else None)
            allow_insecure = params.get('allowInsecure', '0').lower(); clash_proxy['skip-cert-verify'] = allow_insecure == '1' or allow_insecure == 'true'
            network = params.get('type', 'tcp').lower()
            if network == 'ws': clash_proxy['network'] = 'ws'; ws_host = params.get('host', clash_proxy.get('sni', proxy_conf.address)); ws_path = params.get('path', '/'); clash_proxy['ws-opts'] = {'path': ws_path, 'headers': {'Host': ws_host}}
            elif network == 'grpc': clash_proxy['network'] = 'grpc'; grpc_service_name = params.get('serviceName', ''); clash_proxy['grpc-opts'] = {'grpc-service-name': grpc_service_name}
        elif protocol == 'ss':
            clash_proxy['type'] = 'ss'
            if not url_username: raise ValueError("Missing user info in SS URL")
            try: user_info_padded = url_username + '=' * (-len(url_username) % 4); decoded_user = base64.urlsafe_b64decode(user_info_padded).decode('utf-8'); clash_proxy['cipher'], clash_proxy['password'] = decoded_user.split(':', 1)
            except (binascii.Error, ValueError, UnicodeDecodeError) as e: raise ValueError(f"Failed to decode SS user info: {e}") from e
            plugin = params.get('plugin', '').lower()
            if plugin.startswith('obfs'): clash_proxy['plugin'] = 'obfs'; obfs_mode = params.get('obfs', 'http'); obfs_host = params.get('obfs-host', 'www.bing.com'); clash_proxy['plugin-opts'] = {'mode': obfs_mode, 'host': obfs_host}
            elif plugin.startswith('v2ray-plugin'):
                 clash_proxy['plugin'] = 'v2ray-plugin'; plugin_opts: Dict[str, Any] = {'mode': 'websocket'}
                 if params.get('tls', 'false') == 'true': plugin_opts['tls'] = True; plugin_opts['host'] = params.get('host', proxy_conf.address); plugin_opts['skip-cert-verify'] = params.get('allowInsecure', 'false') == 'true'
                 plugin_opts['path'] = params.get('path', '/'); ws_host_header = params.get('host', proxy_conf.address); plugin_opts['headers'] = {'Host': ws_host_header}; clash_proxy['plugin-opts'] = plugin_opts
        elif protocol in ['tuic', 'hy2', 'ssr']: logger.debug(f"Protocol {protocol.upper()} not fully supported for Clash output. Skipping."); return None
        else: logger.warning(f"Unknown protocol '{protocol}' for Clash conversion. Skipping."); return None
    except (binascii.Error, ValueError, UnicodeDecodeError, IndexError, KeyError, AttributeError) as e: logger.warning(f"Could not parse or convert proxy for Clash: {proxy_conf.config_string} - Error: {type(e).__name__}: {e}"); return None
    except Exception as e: logger.error(f"Unexpected error converting proxy to Clash dict: {proxy_conf.config_string} - {e}", exc_info=False); return None
    return clash_proxy

def _save_as_text(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    count = 0; lines_to_write = []
    for proxy_conf, test_result in proxies_with_results:
        profile_name = generate_proxy_profile_name(proxy_conf, test_result)
        config_line = f"{proxy_conf.config_string}#{profile_name}\n"
        lines_to_write.append(config_line); count += 1
    if count == 0: return 0
    try:
        with open(file_path, 'w', encoding='utf-8') as f: f.writelines(lines_to_write); f.flush()
        return count
    except IOError as e: logger.error(f"IOError saving TEXT proxies to '{file_path}': {e}"); return 0
    except Exception as e: logger.error(f"Unexpected error saving TEXT proxies to '{file_path}': {e}", exc_info=False); return 0

def _save_as_json(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    count = 0; output_list = []
    for proxy_conf, test_result in proxies_with_results:
        proxy_dict = asdict(proxy_conf)
        if test_result:
            proxy_dict['test_status'] = test_result.get('status'); latency = test_result.get('latency')
            proxy_dict['latency_sec'] = round(latency, 4) if isinstance(latency, (int, float)) else None
            proxy_dict['test_error'] = test_result.get('error')
        else: proxy_dict['test_status'] = None; proxy_dict['latency_sec'] = None; proxy_dict['test_error'] = None
        output_list.append(proxy_dict); count += 1
    if count == 0: return 0
    try:
        with open(file_path, 'w', encoding='utf-8') as f: json.dump(output_list, f, indent=2, ensure_ascii=False); f.flush()
        return count
    except IOError as e: logger.error(f"IOError saving JSON proxies to '{file_path}': {e}"); return 0
    except TypeError as e: logger.error(f"TypeError saving JSON proxies to '{file_path}': {e}"); return 0
    except Exception as e: logger.error(f"Unexpected error saving JSON proxies to '{file_path}': {e}", exc_info=False); return 0

def _save_as_clash(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    if not YAML_AVAILABLE: logger.error("PyYAML is not installed. Cannot save in Clash format."); return 0
    count = 0; clash_proxies_list = []
    for proxy_conf, test_result in proxies_with_results:
        clash_dict = _proxy_to_clash_dict(proxy_conf, test_result)
        if clash_dict: clash_proxies_list.append(clash_dict); count += 1
    if count == 0: logger.warning("No compatible proxies found to generate Clash config."); return 0
    clash_config = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'proxies': clash_proxies_list,
        'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': [p['name'] for p in clash_proxies_list] + ['DIRECT', 'REJECT']},
                         {'name': 'Auto-Fastest', 'type': 'url-test', 'proxies': [p['name'] for p in clash_proxies_list], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                         {'name': 'Fallback-Group', 'type': 'fallback', 'proxies': [p['name'] for p in clash_proxies_list], 'url': 'http://www.gstatic.com/generate_204', 'interval': 60}],
        'rules': ['DOMAIN-SUFFIX,cn,DIRECT', 'GEOIP,CN,DIRECT', 'DOMAIN-KEYWORD,google,PROXY', 'DOMAIN-SUFFIX,telegram.org,PROXY', 'MATCH,PROXY']}
    try:
        with open(file_path, 'w', encoding='utf-8') as f: yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=None, indent=2, Dumper=yaml.Dumper); f.flush()
        return count
    except IOError as e: logger.error(f"IOError writing Clash YAML file '{file_path}': {e}"); return 0
    except Exception as e: logger.error(f"Error writing Clash YAML file '{file_path}': {e}", exc_info=False); return 0

# --- Функции оркестрации ---
def load_channels(input_file: str) -> List[str]:
    channel_urls: List[str] = []; logger.info(f"Loading channel URLs from '{input_file}'...")
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            for i, line in enumerate(f):
                url = line.strip()
                if url and not url.startswith('#'):
                    if url.startswith(('http://', 'https://')): channel_urls.append(url)
                    else: logger.warning(f"Skipping invalid URL in '{input_file}' (line {i+1}): '{url[:100]}...'")
        logger.info(f"Loaded {len(channel_urls)} valid channel URLs.")
    except FileNotFoundError: logger.warning(f"Input file '{input_file}' not found. No channels to process.")
    except IOError as e: logger.error(f"IOError reading input file '{input_file}': {e}")
    except Exception as e: logger.error(f"Unexpected error loading channel URLs from '{input_file}': {e}", exc_info=False)
    return channel_urls

@contextlib.asynccontextmanager
async def create_clients(user_agent: str) -> AsyncIterator[Tuple[aiohttp.ClientSession, aiodns.DNSResolver]]:
    session = None; resolver = None
    try:
        headers = {'User-Agent': user_agent}; conn = aiohttp.TCPConnector(limit_per_host=20, limit=100)
        session = aiohttp.ClientSession(headers=headers, connector=conn)
        resolver = aiodns.DNSResolver(); logger.debug("Initialized aiohttp.ClientSession and aiodns.DNSResolver.")
        yield session, resolver
    except Exception as e: logger.critical(f"Failed to initialize HTTP/DNS clients: {e}", exc_info=True); raise ConfigError(f"Client initialization failed: {e}") from e
    finally:
        if session: await session.close(); logger.debug("Closed aiohttp.ClientSession.")

async def process_channel_task(
    channel_url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver,
    http_timeout: int, max_retries: int, retry_delay: float, user_agent: str, # Передаем нужные параметры
    dns_timeout: int, dns_semaphore: asyncio.Semaphore
) -> Tuple[str, str, List[ProxyParsedConfig]]:
    status = "processing_error"; proxies: List[ProxyParsedConfig] = []
    try:
        lines = await download_proxies_from_channel(channel_url, session, http_timeout, max_retries, retry_delay, user_agent)
        parsed_proxies_basic, _, _ = parse_proxy_lines(lines, channel_url)
        if not parsed_proxies_basic: logger.info(f"Channel {channel_url}: No valid proxy formats found after initial parsing."); return channel_url, "success", []
        resolved_proxies, _ = await resolve_and_assess_proxies(parsed_proxies_basic, resolver, dns_timeout, dns_semaphore, channel_url)
        proxies = resolved_proxies; status = "success"
        logger.info(f"Channel {channel_url}: Processing finished. Found {len(proxies)} unique & resolved proxies.")
    except EmptyChannelError: logger.warning(f"Channel {channel_url} processing stopped: Channel was empty or contained no valid lines."); status = "empty"
    except DownloadError: status = "download_error" # Ошибка уже залогирована
    except Exception as e: logger.error(f"Unexpected error processing channel {channel_url}: {e}", exc_info=False); status = "processing_error"
    return channel_url, status, proxies

async def run_processing(
    channel_urls: List[str], session: aiohttp.ClientSession, resolver: aiodns.DNSResolver,
    # Передаем нужные параметры конфигурации
    http_timeout: int, max_retries: int, retry_delay: float, user_agent: str,
    dns_timeout: int, max_channels_conc: int, max_dns_conc: int
) -> Tuple[List[ProxyParsedConfig], int, DefaultDict[str, int]]:
    channels_processed_count = 0; total_proxies_found_before_final_dedup = 0
    channel_status_counts: DefaultDict[str, int] = defaultdict(int)
    channel_semaphore = asyncio.Semaphore(max_channels_conc)
    dns_semaphore = asyncio.Semaphore(max_dns_conc)
    final_unique_proxies_set: Set[ProxyParsedConfig] = set()

    async def task_wrapper(url: str) -> Optional[Tuple[str, str, List[ProxyParsedConfig]]]:
        nonlocal channels_processed_count
        async with channel_semaphore:
            try:
                result = await process_channel_task(url, session, resolver, http_timeout, max_retries, retry_delay, user_agent, dns_timeout, dns_semaphore)
                channels_processed_count += 1; return result
            except Exception as e: logger.critical(f"Critical task failure in wrapper for {url}: {e}", exc_info=False); channels_processed_count += 1; return url, "critical_wrapper_error", []

    tasks = [task_wrapper(channel_url) for channel_url in channel_urls]
    channel_results = await tqdm.gather(
        *tasks, desc="Processing channels", unit="channel",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty()
    )
    for result in channel_results:
        if result is None: channel_status_counts["critical_wrapper_error"] += 1; continue
        url, status, proxies_from_channel = result
        channel_status_counts[status] += 1
        if status == "success" and proxies_from_channel:
            total_proxies_found_before_final_dedup += len(proxies_from_channel)
            final_unique_proxies_set.update(proxies_from_channel)

    all_unique_proxies: List[ProxyParsedConfig] = list(final_unique_proxies_set)
    logger.info(f"Total unique proxies found after DNS resolution & inter-channel deduplication: {len(all_unique_proxies)}")
    return all_unique_proxies, total_proxies_found_before_final_dedup, channel_status_counts

async def run_testing(
    proxies: List[ProxyParsedConfig],
    # Передаем нужные параметры
    enable_testing: bool, test_timeout: int, test_sni: str, test_port: int, max_tests_conc: int
) -> List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]:
    if not enable_testing or not proxies:
        logger.info("Skipping proxy connectivity tests (disabled or no proxies).")
        return [(proxy, None) for proxy in proxies]

    logger.info(f"Starting connectivity tests for {len(proxies)} proxies...")
    test_semaphore = asyncio.Semaphore(max_tests_conc)
    results_with_tests = await run_proxy_tests(proxies, test_timeout, test_sni, test_port, test_semaphore)
    return results_with_tests

def filter_and_sort_results(
    results_with_tests: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    test_enabled: bool
) -> List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]:
    if test_enabled:
        working_proxies_with_results = [(proxy, result) for proxy, result in results_with_tests if result and result.get('status') == 'ok' and isinstance(result.get('latency'), (int, float))]
        working_proxies_with_results.sort(key=lambda item: item[1].get('latency') if item[1] else float('inf'))
        logger.info(f"Filtered proxies after testing. Kept {len(working_proxies_with_results)} working proxies.")
        return working_proxies_with_results
    else:
        results_with_tests.sort(key=lambda item: item[0].quality_score, reverse=True)
        logger.info(f"Sorted {len(results_with_tests)} proxies by quality score (testing disabled).")
        return results_with_tests

def save_results(
    proxies_to_save: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    output_file_base: str, output_format_str: str
) -> Tuple[int, str]:
    num_proxies_to_save = len(proxies_to_save)
    output_format = OutputFormatEnum(output_format_str)
    if num_proxies_to_save == 0:
        logger.warning("No proxies to save (either none found or all failed tests).")
        return 0, f"{output_file_base}.(no_output_empty)"

    if output_format == OutputFormatEnum.JSON: file_ext = ".json"; save_func = _save_as_json
    elif output_format == OutputFormatEnum.CLASH: file_ext = ".yaml"; save_func = _save_as_clash
    else: file_ext = ".txt"; save_func = _save_as_text # Default TEXT

    file_path = os.path.normpath(output_file_base + file_ext); saved_count = 0
    try:
        output_dir = os.path.dirname(file_path)
        if output_dir and not os.path.exists(output_dir): os.makedirs(output_dir, exist_ok=True); logger.info(f"Created output directory: '{output_dir}'")
        logger.info(f"Attempting to save {num_proxies_to_save} proxies to '{file_path}' (Format: {output_format.value})...")
        saved_count = save_func(proxies_to_save, file_path)
        if saved_count > 0:
            logger.info(f"Successfully wrote {saved_count} proxies to '{file_path}'")
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0: logger.debug(f"File '{file_path}' exists and is not empty.")
                else: logger.warning(f"File '{file_path}' reported saved ({saved_count}), but seems missing or empty.")
            except Exception as e: logger.warning(f"Could not verify saved file '{file_path}': {e}")
        elif num_proxies_to_save > 0: logger.error(f"Attempted to save {num_proxies_to_save}, but 0 written to '{file_path}'. Check errors.")
    except IOError as e: logger.error(f"IOError saving proxies to '{file_path}': {e}. Check permissions.", exc_info=False); return 0, file_path
    except Exception as e: logger.error(f"Unexpected error saving proxies to '{file_path}': {e}", exc_info=False); return 0, file_path
    return saved_count, file_path

# --- Функции для Diff Mode (Ограниченная версия) ---

ProxyKey = Tuple[str, str, int] # (protocol, address_lower, port)

def load_previous_results_text(file_path: str) -> Set[ProxyKey]:
    """
    Загружает ключи прокси (protocol, address_lower, port) из ТЕКСТОВОГО файла
    предыдущего запуска. Не содержит информации о latency или статусе теста.
    """
    previous_keys: Set[ProxyKey] = set()
    logger.info(f"Attempting to load previous proxy keys from TEXT file '{file_path}' for diff...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        count = 0
        invalid_count = 0
        for line in lines:
            url = line.strip()
            if not url or url.startswith('#'): continue

            # Парсим URL только для получения ключа
            try:
                parsed_url = urlparse(url)
                protocol_match = PROTOCOL_REGEX.match(parsed_url.scheme + "://") # Проверяем схему
                if not protocol_match: invalid_count += 1; continue
                protocol = protocol_match.group(1).lower()
                address = parsed_url.hostname
                port = parsed_url.port
                if protocol and address and isinstance(port, int):
                    proxy_key: ProxyKey = (protocol, address.lower(), port)
                    previous_keys.add(proxy_key)
                    count += 1
                else:
                    invalid_count += 1
            except Exception: # Ловим ошибки парсинга URL
                invalid_count += 1

        logger.info(f"Successfully loaded {count} proxy keys from previous text file '{file_path}'. Skipped {invalid_count} invalid lines.")
        return previous_keys

    except FileNotFoundError:
        logger.warning(f"Previous results text file '{file_path}' not found. Reporting all current proxies as new.")
        return set()
    except IOError as e:
        logger.error(f"IOError reading previous results text file '{file_path}': {e}. Skipping diff.")
        return set()
    except Exception as e:
         logger.error(f"Unexpected error loading previous results from text file '{file_path}': {e}. Skipping diff.", exc_info=False)
         return set()

class DiffResultSimple(TypedDict):
    added: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]
    removed: List[ProxyKey] # Храним только ключ удаленных
    # Поля changed и unchanged не имеют смысла в этой ограниченной версии

def compare_results_simple(
    old_keys: Set[ProxyKey],
    new_results_list: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]
) -> DiffResultSimple:
    """
    Сравнивает текущие результаты с ключами из предыдущего текстового файла.
    Определяет только добавленные (added) и удаленные (removed) прокси.
    """
    diff: DiffResultSimple = {"added": [], "removed": []}
    current_keys: Set[ProxyKey] = set()

    logger.info(f"Comparing {len(new_results_list)} current proxies against {len(old_keys)} previous proxy keys...")

    for proxy_conf, test_result in new_results_list:
        proxy_key: ProxyKey = (proxy_conf.protocol, proxy_conf.address.lower(), proxy_conf.port)
        current_keys.add(proxy_key)
        if proxy_key not in old_keys:
            # Этот ключ новый
            diff["added"].append((proxy_conf, test_result))
        # else:
            # Ключ существует, но мы не можем сравнить детали (latency/status)

    # Ключи, которые были в старом наборе, но нет в текущем - удаленные
    removed_keys = old_keys - current_keys
    diff["removed"] = list(removed_keys)

    # Считаем количество неизменных (присутствовавших и там, и там)
    unchanged_count = len(old_keys.intersection(current_keys))

    logger.info(
        f"Simple Diff comparison complete: "
        f"{len(diff['added'])} Added, "
        f"{len(diff['removed'])} Removed, "
        f"{unchanged_count} Unchanged (present in both)."
        f" (Change detection based on latency/status is NOT possible with text input)"
    )
    return diff

def save_diff_report_text_simple(diff_data: DiffResultSimple, file_path: str) -> int:
    """Сохраняет упрощенный отчет об изменениях (только added/removed) в текст."""
    lines = []
    total_changes = len(diff_data["added"]) + len(diff_data["removed"])

    lines.append("--- Proxy Diff Report (Simple: Added/Removed Only) ---")
    lines.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    if diff_data["added"]:
        lines.append(f"+++ Added ({len(diff_data['added'])}):")
        # Сортируем добавленные по качеству или latency для консистентности
        sorted_added = sorted(diff_data['added'], key=lambda item: item[1]['latency'] if item[1] and item[1].get('latency') is not None else (item[0].quality_score * -1), reverse=False if ENABLE_TESTING else True)
        for proxy_conf, test_result in sorted_added:
             profile_name = generate_proxy_profile_name(proxy_conf, test_result)
             latency_str = f"{test_result['latency']*1000:.0f}ms" if test_result and test_result.get('latency') is not None else "N/A"
             lines.append(f"  + {profile_name} ({proxy_conf.protocol}, {proxy_conf.address}:{proxy_conf.port}, Latency: {latency_str})")
        lines.append("") # Пустая строка для разделения

    if diff_data["removed"]:
        lines.append(f"--- Removed ({len(diff_data['removed'])}):")
        # Сортируем удаленные ключи для консистентности
        sorted_removed = sorted(list(diff_data['removed']))
        for p_key in sorted_removed:
             # Выводим информацию из ключа
             protocol, address, port = p_key
             lines.append(f"  - Removed Key: ({protocol}, {address}:{port})")
        lines.append("")

    if total_changes == 0:
         lines.append(">>> No added or removed proxies detected compared to the previous text file.")

    # Предупреждение об ограничениях
    lines.append("\nNote: This diff only shows added/removed proxies.")
    lines.append("Changes in latency or test status for existing proxies cannot be detected when comparing against a .txt file.")

    try:
        with open(file_path, 'w', encoding='utf-8') as f: f.write("\n".join(lines)); f.flush()
        logger.info(f"Successfully wrote simple text diff report to '{file_path}'")
        return total_changes
    except IOError as e: logger.error(f"IOError saving simple text diff report to '{file_path}': {e}"); return -1
    except Exception as e: logger.error(f"Unexpected error saving simple text diff report to '{file_path}': {e}", exc_info=False); return -1

# --- Статистика и вывод ---
def generate_statistics(
    start_time: float, config: Dict[str, Any], # Передаем конфиг вместо args
    total_channels_requested: int,
    proxies_after_dns: List[ProxyParsedConfig],
    total_proxies_found_before_dedup: int,
    channel_status_counts: DefaultDict[str, int],
    final_results_to_save: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    final_saved_count: int, # Переименовано для ясности
    output_file_path: str,
    is_diff_mode: bool,
    diff_details: Optional[Dict[str, int]] = None
) -> Statistics:
    proxies_after_dns_count = len(proxies_after_dns)
    proxies_after_test_count: Optional[int] = None
    if config['ENABLE_TESTING']: proxies_after_test_count = len(final_results_to_save)

    saved_protocol_counts: DefaultDict[str, int] = defaultdict(int)
    saved_quality_category_counts: DefaultDict[str, int] = defaultdict(int)
    # Статистику считаем по списку, который *был бы* сохранен в основном файле
    if final_results_to_save:
        proxies_for_stats = final_results_to_save
        # Если в diff-режиме основной файл не обновлялся, но мы хотим статистику
        # по всем найденным рабочим прокси, используем final_results_to_save
        if is_diff_mode and not config['UPDATE_OUTPUT_IN_DIFF']:
             pass # Используем final_results_to_save
        # Если не diff или файл обновлялся, тоже используем final_results_to_save
        # (по сути, всегда используем его)

        for proxy, _ in proxies_for_stats:
             saved_protocol_counts[proxy.protocol] += 1
             quality_category = get_quality_category(proxy.quality_score)
             saved_quality_category_counts[quality_category] += 1

    channels_processed_count = sum(channel_status_counts.values())
    output_format_enum = OutputFormatEnum.TEXT if is_diff_mode else OutputFormatEnum(config['OUTPUT_FORMAT'])

    return Statistics(
        start_time=start_time, total_channels_requested=total_channels_requested,
        channels_processed_count=channels_processed_count, channel_status_counts=channel_status_counts,
        total_proxies_found_before_dedup=total_proxies_found_before_dedup,
        proxies_after_dns_count=proxies_after_dns_count,
        proxies_after_test_count=proxies_after_test_count,
        final_saved_count=final_saved_count, # Количество, реально записанное в основной файл
        saved_protocol_counts=saved_protocol_counts, # Статистика по всем найденным/прошедшим тест
        saved_quality_category_counts=saved_quality_category_counts,
        output_file_path=output_file_path, # Путь к отчету или основному файлу
        output_format=output_format_enum, # Формат отчета или основного файла
        is_diff_mode=is_diff_mode,
        diff_details=diff_details
    )

def display_statistics(stats: Statistics, nocolor: bool = False) -> None:
    end_time = time.time(); elapsed_time = end_time - stats.start_time
    def cprint(level: int, message: str):
        if nocolor or not sys.stdout.isatty(): print(f"[{logging.getLevelName(level)}] {message}", file=sys.stderr if level >= logging.WARNING else sys.stdout)
        else: color_start = COLOR_MAP.get(level, COLOR_MAP['RESET']); print(f"{color_start}[{logging.getLevelName(level)}]{COLOR_MAP['RESET']} {message}", file=sys.stderr if level >= logging.WARNING else sys.stdout)

    mode_str = "Diff Mode" if stats.is_diff_mode else "Normal Mode"
    cprint(logging.INFO, f"==================== 📊 PROXY DOWNLOAD STATISTICS ({mode_str}) ====================")
    cprint(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    cprint(logging.INFO, f"🔗 Total channel URLs requested: {stats.total_channels_requested}")
    cprint(logging.INFO, f"🛠️ Total channels processed: {stats.channels_processed_count}/{stats.total_channels_requested}")

    cprint(logging.INFO, "\n📊 Channel Processing Status:")
    status_order = ["success", "empty", "download_error", "processing_error", "critical_wrapper_error"]
    status_texts = {"success": "SUCCESS", "empty": "EMPTY", "download_error": "DOWNLOAD/DECODE ERROR", "processing_error": "PROCESSING ERROR", "critical_wrapper_error": "CRITICAL TASK ERROR"}
    status_levels = {"success": logging.INFO, "empty": logging.WARNING, "download_error": logging.ERROR, "processing_error": logging.ERROR, "critical_wrapper_error": logging.CRITICAL}
    processed_keys = set()
    for status_key in status_order:
        if status_key in stats.channel_status_counts:
            count = stats.channel_status_counts[status_key]; level = status_levels.get(status_key, logging.ERROR); status_text = status_texts.get(status_key, status_key.upper())
            cprint(level, f"  - {status_text}: {count} channels"); processed_keys.add(status_key)
    for status_key, count in stats.channel_status_counts.items():
         if status_key not in processed_keys: level = status_levels.get(status_key, logging.ERROR); status_text = status_texts.get(status_key, status_key.replace('_', ' ').upper()); cprint(level, f"  - {status_text}: {count} channels")

    cprint(logging.INFO, f"\n✨ Proxies found (before final deduplication): {stats.total_proxies_found_before_dedup}")
    cprint(logging.INFO, f"🧬 Proxies after DNS resolution & final deduplication: {stats.proxies_after_dns_count}")
    if stats.proxies_after_test_count is not None: cprint(logging.INFO, f"✅ Proxies passed connectivity test: {stats.proxies_after_test_count} / {stats.proxies_after_dns_count}")

    if stats.is_diff_mode:
        cprint(logging.INFO, "\n🔄 Diff Report Summary:")
        if stats.diff_details:
            cprint(logging.INFO, f"  +++ Added: {stats.diff_details.get('added', 0)}")
            cprint(logging.INFO, f"  --- Removed: {stats.diff_details.get('removed', 0)}")
            cprint(logging.WARNING, "      (Change detection based on latency/status is NOT possible)")
        cprint(logging.INFO, f"📝 Diff report saved to: '{stats.output_file_path}' (Format: {stats.output_format.value})")
        if stats.final_saved_count > 0: # Если основной файл обновлялся
             main_ext = "." + stats.output_format.value if stats.output_format != OutputFormatEnum.CLASH else ".yaml"
             main_path = os.path.normpath(OUTPUT_BASE + main_ext) # Восстанавливаем путь
             cprint(logging.INFO, f"📝 Main output file updated: {stats.final_saved_count} proxies (to '{main_path}')")
        else: cprint(logging.INFO, "📝 Main output file was NOT updated (as configured).")
    else: # Normal mode
        if stats.final_saved_count > 0: cprint(logging.INFO, f"📝 Total proxies saved: {stats.final_saved_count} (to '{stats.output_file_path}', format: {stats.output_format.value})")
        else: cprint(logging.WARNING, f"📝 Total proxies saved: 0")

    # Статистика по протоколам и качеству (выводится всегда, на основе всех найденных/прошедших тест)
    if stats.proxies_after_dns_count > 0: # Показываем, если были прокси после DNS
        cprint(logging.INFO, "\n🔬 Protocol Breakdown (all unique/resolved proxies):")
        if stats.saved_protocol_counts:
            for protocol, count in sorted(stats.saved_protocol_counts.items()): cprint(logging.INFO, f"   - {protocol.upper()}: {count}")
        else: cprint(logging.WARNING, "   No protocol statistics available.")
        cprint(logging.INFO, "\n⭐️ Quality Distribution (all unique/resolved proxies):")
        if stats.saved_quality_category_counts:
             category_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
             for category, count in sorted(stats.saved_quality_category_counts.items(), key=lambda item: category_order.get(item[0], 99)): cprint(logging.INFO, f"   - {category}: {count} proxies")
        else: cprint(logging.WARNING, "   No quality category statistics available.")
    else: cprint(logging.WARNING, "\nNo proxies found after DNS/deduplication, skipping breakdown statistics.")

    cprint(logging.INFO, "======================== 🏁 STATISTICS END =========================")

# --- Главная функция ---
async def amain() -> int:
    start_time = time.time()
    # Используем константы конфигурации
    config = {k: v for k, v in globals().items() if k.isupper() and not k.startswith('_')}

    setup_logging(
        log_level_str=config['LOG_LEVEL'],
        log_file=config['LOG_FILE_PATH'],
        nocolor=config['NO_COLOR_LOGS']
    )

    logger.info("🚀 Starting Proxy Downloader Script...")
    logger.debug(f"Using configuration: {config}")

    channel_urls = load_channels(config['INPUT_FILE'])
    total_channels_requested = len(channel_urls)
    if not channel_urls:
        logger.error("No valid channel URLs loaded. Exiting.")
        return 1

    final_saved_count = 0
    output_path = "(not generated)"
    diff_summary: Optional[Dict[str, int]] = None

    try:
        async with create_clients(config['USER_AGENT']) as (session, resolver):
            proxies_after_dns, total_found_before_dedup, channel_stats = await run_processing(
                channel_urls, session, resolver,
                http_timeout=config['HTTP_TIMEOUT'], max_retries=config['MAX_RETRIES'],
                retry_delay=config['RETRY_DELAY_BASE'], user_agent=config['USER_AGENT'],
                dns_timeout=config['DNS_TIMEOUT'], max_channels_conc=config['MAX_CHANNELS_CONCURRENT'],
                max_dns_conc=config['MAX_DNS_CONCURRENT']
            )
            results_with_tests = await run_testing(
                proxies_after_dns,
                enable_testing=config['ENABLE_TESTING'], test_timeout=config['TEST_TIMEOUT'],
                test_sni=config['TEST_SNI'], test_port=config['TEST_PORT'],
                max_tests_conc=config['MAX_TESTS_CONCURRENT']
            )
            final_results_to_save = filter_and_sort_results(results_with_tests, config['ENABLE_TESTING'])

            # --- Логика режима DIFF ---
            if config['ENABLE_DIFF_MODE']:
                logger.info("--- Diff Mode Enabled (Text-based: Added/Removed only) ---")
                previous_file_path = config['DIFF_PREVIOUS_FILE_PATH']
                if not previous_file_path:
                    # Определяем путь к предыдущему текстовому файлу
                    previous_file_path = os.path.normpath(config['OUTPUT_BASE'] + ".txt")
                    logger.info(f"No DIFF_PREVIOUS_FILE_PATH set, assuming previous output file: '{previous_file_path}'")

                # Загружаем ключи из предыдущего текстового файла
                old_proxy_keys = load_previous_results_text(previous_file_path)

                # Сравниваем (упрощенная версия)
                diff_result_data = compare_results_simple(old_proxy_keys, final_results_to_save)
                diff_summary = {
                    "added": len(diff_result_data['added']),
                    "removed": len(diff_result_data['removed'])
                }

                # Сохраняем текстовый отчет об изменениях
                diff_report_path = config['DIFF_REPORT_FILE_PATH']
                if not diff_report_path:
                    diff_report_path = os.path.normpath(config['OUTPUT_BASE'] + ".diff.txt")
                save_diff_report_text_simple(diff_result_data, diff_report_path)
                output_path = diff_report_path # Путь к отчету как основной результат

                # Обновляем основной файл, только если указано
                if config['UPDATE_OUTPUT_IN_DIFF']:
                    logger.info("UPDATE_OUTPUT_IN_DIFF is True: Updating main output file as well.")
                    final_saved_count, _ = save_results(
                         final_results_to_save, config['OUTPUT_BASE'], config['OUTPUT_FORMAT']
                    )
                else:
                     logger.info("UPDATE_OUTPUT_IN_DIFF is False: Main output file NOT updated.")
                     final_saved_count = 0

            else:
                # --- Обычный режим (не diff) ---
                logger.info("--- Normal Mode (Full Output) ---")
                final_saved_count, output_path = save_results(
                    final_results_to_save, config['OUTPUT_BASE'], config['OUTPUT_FORMAT']
                )

            # --- Статистика (выполняется в обоих режимах) ---
            stats = generate_statistics(
                start_time, config, total_channels_requested,
                proxies_after_dns, total_found_before_dedup, channel_stats,
                final_results_to_save, final_saved_count, output_path,
                is_diff_mode=config['ENABLE_DIFF_MODE'], diff_details=diff_summary
            )
            display_statistics(stats, config['NO_COLOR_LOGS'])

    except ConfigError as e: return 1
    except KeyboardInterrupt: logger.warning("Script interrupted by user."); return 1
    except Exception as e: logger.critical(f"Unexpected critical error: {e}", exc_info=True); return 1
    finally: logger.info("✅ Proxy download and processing script finished.")
    return 0

# --- Точка входа ---
if __name__ == "__main__":
    exit_code = asyncio.run(amain())
    sys.exit(exit_code)
