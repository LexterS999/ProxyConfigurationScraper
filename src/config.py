import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import json
import sys
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
    Dict, List, Optional, Tuple, Set, DefaultDict, Any, Union, NamedTuple, Sequence, AsyncIterator, TypedDict
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

# --- КОНФИГУРАЦИЯ ---
INPUT_FILE = "channel_urls.txt"
OUTPUT_BASE = "configs/proxy_configs_all"
OUTPUT_FORMAT = "text" # "text", "json", "clash"
DNS_TIMEOUT = 15
HTTP_TIMEOUT = 15
MAX_RETRIES = 4
RETRY_DELAY_BASE = 2.0
USER_AGENT = 'ProxyDownloader/1.2'
ENABLE_TESTING = True
TEST_TIMEOUT = 10
TEST_SNI = "www.google.com"
TEST_PORT = 443
MAX_CHANNELS_CONCURRENT = 60
MAX_DNS_CONCURRENT = 50
MAX_TESTS_CONCURRENT = 30
LOG_LEVEL = "INFO" # 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
LOG_FILE_PATH = 'proxy_downloader.log'
NO_COLOR_LOGS = False
ENABLE_DIFF_MODE = True
DIFF_PREVIOUS_FILE_PATH = None # Если None, используется OUTPUT_BASE + ".txt"
DIFF_REPORT_FILE_PATH = None # Если None, используется OUTPUT_BASE + ".diff.txt"
UPDATE_OUTPUT_IN_DIFF = False

if OUTPUT_FORMAT == "clash" and not YAML_AVAILABLE:
    print(f"Error: Output format '{OUTPUT_FORMAT}' requires PyYAML library.", file=sys.stderr)
    print("Please install it: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# --- Constants ---
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FORMAT_JSON_KEYS: Dict[str, str] = {
    "time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s",
    "logger": "%(name)s", "module": "%(module)s", "funcName": "%(funcName)s",
    "lineno": "%(lineno)d", "process": "%(process)d", "threadName": "%(threadName)s",
}
PROTOCOL_REGEX = re.compile(r"^(vless|tuic|hy2|ss|ssr|trojan)://", re.IGNORECASE)
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}")
QUALITY_SCORE_WEIGHTS = {
    "protocol": {"vless": 5, "trojan": 5, "tuic": 4, "hy2": 3, "ss": 2, "ssr": 1},
    "security": {"tls": 3, "none": 0},
    "transport": {"ws": 2, "websocket": 2, "grpc": 2, "tcp": 1, "udp": 0},
}
QUALITY_CATEGORIES = { "High": range(8, 15), "Medium": range(4, 8), "Low": range(0, 4) }
COLOR_MAP = {
    logging.INFO: '\033[92m', logging.DEBUG: '\033[94m', logging.WARNING: '\033[93m',
    logging.ERROR: '\033[91m', logging.CRITICAL: '\033[1m\033[91m', 'RESET': '\033[0m'
}

# --- Форматы вывода ---
class OutputFormatEnum(Enum): TEXT = "text"; JSON = "json"; CLASH = "clash"

# --- Исключения ---
class InvalidURLError(ValueError): pass
class UnsupportedProtocolError(ValueError): pass
class EmptyChannelError(Exception): pass
class DownloadError(Exception): pass
class ProxyTestError(Exception): pass
class ConfigError(Exception): pass

# --- Глобальный логгер ---
logger = logging.getLogger(__name__)


# --- Датаклассы (Определение ПЕРЕД использованием в других типах) ---
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
            address = parsed_url.hostname; port = parsed_url.port
            if not address or not port or not 1 <= port <= 65535: return None
            if not address.strip() or ' ' in address: return None
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else ""
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v}
            config_string_to_store = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                 parsed_url.params, parsed_url.query, ''))
            return cls(config_string=config_string_to_store, protocol=protocol, address=address,
                       port=port, remark=remark, query_params=query_params)
        except ValueError as e: logger.debug(f"URL parsing ValueError for '{original_string[:100]}...': {e}"); return None
        except Exception as e: logger.error(f"Unexpected error parsing URL '{original_string[:100]}...': {e}", exc_info=False); return None

# --- Типы данных (Теперь ProxyParsedConfig определен) ---
TEST_RESULT_TYPE = Dict[str, Union[str, Optional[float], Optional[str]]]
ProxyKey = Tuple[str, str, int] # (protocol, address_lower, port)

class Statistics(NamedTuple):
    start_time: float
    total_channels_requested: int
    channels_processed_count: int
    channel_status_counts: DefaultDict[str, int]
    total_proxies_found_before_dedup: int
    proxies_after_dns_count: int
    proxies_after_test_count: Optional[int]
    final_saved_count: int
    saved_protocol_counts: DefaultDict[str, int]
    saved_quality_category_counts: DefaultDict[str, int]
    output_file_path: str
    output_format: OutputFormatEnum
    is_diff_mode: bool
    diff_details: Optional[Dict[str, int]]

class DiffResultSimple(TypedDict):
    added: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]] # Теперь ProxyParsedConfig известен
    removed: List[ProxyKey]

# --- Data Structures ---
class Protocols(Enum): VLESS = "vless"; TUIC = "tuic"; HY2 = "hy2"; SS = "ss"; SSR = "ssr"; TROJAN = "trojan"
ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]

# --- Функции настройки ---
def setup_logging(log_level_str: str = "INFO", log_file: str = "app.log", nocolor: bool = False) -> None:
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers(): logger.handlers.clear()
    # --- Файловый обработчик (JSON) ---
    class JsonFormatter(logging.Formatter):
        default_msec_format = '%s.%03d'
        def format(self, record: logging.LogRecord) -> str:
            log_record: Dict[str, Any] = {}
            for key, format_specifier in LOG_FORMAT_JSON_KEYS.items():
                val = None
                if hasattr(record, key): val = getattr(record, key)
                elif key == 'time': val = self.formatTime(record, self.datefmt or self.default_time_format)
                elif key == 'message': val = record.getMessage()
                else: val = record.__dict__.get(key, None)
                log_record[key] = val
            log_record["level"] = record.levelname
            log_record["message"] = record.getMessage()
            log_record["time"] = self.formatTime(record, self.datefmt or self.default_time_format)
            if hasattr(record, 'taskName') and record.taskName: log_record['taskName'] = record.taskName
            if record.exc_info: log_record['exception'] = self.formatException(record.exc_info)
            if record.stack_info: log_record['stack_info'] = self.formatStack(record.stack_info)
            standard_keys = set(LOG_FORMAT_JSON_KEYS.keys()) | {'args', 'exc_info', 'exc_text', 'levelno', 'msg', 'pathname', 'relativeCreated', 'stack_info', 'taskName', 'created', 'msecs', 'name', 'filename', 'levelname', 'processName', 'thread'}
            extra_keys = set(record.__dict__) - standard_keys
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
    # --- Консольный обработчик (Цветной/Простой) ---
    class ColoredFormatter(logging.Formatter):
        def __init__(self, fmt: str = CONSOLE_LOG_FORMAT, datefmt: Optional[str] = None, use_colors: bool = True):
            super().__init__(fmt, datefmt=datefmt)
            self.use_colors = use_colors and sys.stdout.isatty()
        def format(self, record: logging.LogRecord) -> str:
            message = super().format(record)
            if self.use_colors: color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET']); return f"{color_start}{message}{COLOR_MAP['RESET']}"
            return message
    console_handler_out = logging.StreamHandler(sys.stdout)
    console_handler_out.addFilter(lambda record: record.levelno < logging.WARNING)
    console_handler_out.setLevel(log_level)
    console_formatter_out = ColoredFormatter(use_colors=not nocolor)
    console_handler_out.setFormatter(console_formatter_out)
    logger.addHandler(console_handler_out)
    console_handler_err = logging.StreamHandler(sys.stderr)
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
                if is_valid_ipv4(resolved_ip): logger.debug(f"DNS resolved {hostname} to {resolved_ip}"); return resolved_ip
                else: logger.warning(f"DNS query for A record of {hostname} returned non-IPv4 address: {resolved_ip}"); return None
            else: logger.debug(f"DNS query for {hostname} returned no results."); return None
    except asyncio.TimeoutError: logger.debug(f"DNS resolution timeout for {hostname} after {timeout}s"); return None
    except aiodns.error.DNSError as e:
        error_code = e.args[0] if e.args else "Unknown"; error_msg = str(e.args[1]) if len(e.args) > 1 else "No details"
        if error_code == 3: logger.debug(f"DNS resolution error for {hostname}: Host not found (NXDOMAIN / {error_code})")
        elif error_code == 5: logger.debug(f"DNS resolution error for {hostname}: Connection refused (REFUSED / {error_code})")
        elif error_code == aiodns.error.ARES_ETIMEOUT: logger.debug(f"DNS resolution error for {hostname}: Internal timeout (ARES_ETIMEOUT / {error_code})")
        elif error_code == 4: logger.debug(f"DNS resolution error for {hostname}: Not implemented (NOTIMP / {error_code})")
        elif error_code == 2: logger.warning(f"DNS resolution error for {hostname}: Server failure (SERVFAIL / {error_code})")
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
        latency_ms = int(test_result['latency'] * 1000); name_parts.append(f"{latency_ms}ms")
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
    headers = {'User-Agent': user_agent}; session_timeout = aiohttp.ClientTimeout(total=http_timeout)
    while retries_attempted <= max_retries:
        try:
            logger.debug(f"Attempting download from {channel_url} (Attempt {retries_attempted + 1}/{max_retries + 1})")
            async with session.get(channel_url, timeout=session_timeout, headers=headers, allow_redirects=True, verify_ssl=False) as response:
                content_type = response.headers.get('Content-Type', 'N/A'); logger.debug(f"Received response from {channel_url}: Status={response.status}, Content-Type='{content_type}'")
                response.raise_for_status(); content_bytes = await response.read()
                if not content_bytes or content_bytes.isspace(): logger.warning(f"Channel {channel_url} returned empty."); raise EmptyChannelError(f"Channel {channel_url} empty.")
                decoded_text: Optional[str] = None; decode_method: str = "Unknown"
                try: # Base64
                    b64_no_spaces = "".join(content_bytes.decode('latin-1').split()); b64_stripped = b64_no_spaces.encode('latin-1')
                    pad = len(b64_stripped) % 4; b64_padded = b64_stripped + b'=' * (4 - pad) if pad else b64_stripped
                    b64_decoded = base64.b64decode(b64_padded, validate=True); decoded_from_b64 = b64_decoded.decode('utf-8')
                    if PROTOCOL_REGEX.search(decoded_from_b64): logger.debug(f"Decoded {channel_url} as Base64."); decoded_text = decoded_from_b64; decode_method = "Base64"
                    else: logger.debug(f"Decoded {channel_url} Base64, but no protocol found.")
                except (binascii.Error, ValueError): logger.debug(f"{channel_url} not valid Base64.")
                except UnicodeDecodeError: logger.warning(f"{channel_url} Base64 decoded, but not valid UTF-8.");
                except Exception as e: logger.error(f"Base64 processing error for {channel_url}: {e}", exc_info=False)
                if decoded_text is None: # Plain Text
                    try: logger.debug(f"Decoding {channel_url} as plain UTF-8."); decoded_text = content_bytes.decode('utf-8'); decode_method = "Plain UTF-8"
                    except UnicodeDecodeError:
                        logger.warning(f"UTF-8 decoding failed for {channel_url}. Trying with 'replace'.")
                        try: decoded_text = content_bytes.decode('utf-8', errors='replace'); decode_method = "Plain UTF-8 (replace)"
                        except Exception as e: logger.error(f"Failed decode {channel_url} even with replace: {e}", exc_info=True); raise DownloadError(f"Failed decode {channel_url}") from e
                if decoded_text is not None:
                    logger.info(f"Decoded {channel_url} via {decode_method}")
                    lines = [line for line in decoded_text.splitlines() if line.strip() and not line.strip().startswith('#')]
                    if not lines: logger.warning(f"{channel_url} decoded but no valid lines."); raise EmptyChannelError(f"{channel_url} no valid lines.")
                    return lines
                else: logger.error(f"Failed decode {channel_url}."); raise DownloadError(f"Failed decode {channel_url}")
        except (aiohttp.ClientResponseError, aiohttp.ClientHttpProxyError, aiohttp.ClientProxyConnectionError) as e: status = getattr(e, 'status', 'N/A'); logger.warning(f"HTTP/Proxy error {channel_url}: Status={status}, Error='{e}'"); last_exception = DownloadError(f"HTTP/Proxy error {status}"); break
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError) as e: logger.warning(f"Connection/Timeout error {channel_url} (attempt {retries_attempted+1}): {type(e).__name__}. Retrying..."); last_exception = e; delay = retry_delay_base * (2 ** retries_attempted) + random.uniform(-0.5 * retry_delay_base, 0.5 * retry_delay_base); await asyncio.sleep(max(0.5, delay))
        except EmptyChannelError as e: last_exception = e; break
        except Exception as e: logger.error(f"Unexpected error downloading {channel_url}: {e}", exc_info=False); last_exception = DownloadError(f"Unexpected error"); break
        retries_attempted += 1
    if last_exception:
        if retries_attempted > max_retries: logger.error(f"Max retries ({max_retries+1}) reached for {channel_url}. Last error: {type(last_exception).__name__}"); raise DownloadError(f"Max retries reached") from last_exception
        else: logger.error(f"Failed download {channel_url}: {type(last_exception).__name__}"); raise last_exception
    else: logger.critical(f"Download loop finished unexpectedly {channel_url}"); raise DownloadError(f"Download failed unexpectedly")

def parse_proxy_lines(lines: List[str], channel_url: str = "N/A") -> Tuple[List[ProxyParsedConfig], int, int]:
    parsed: List[ProxyParsedConfig] = []; processed: Set[ProxyParsedConfig] = set(); invalid = 0; duplicate = 0
    for line in lines:
        cfg = ProxyParsedConfig.from_url(line)
        if cfg is None: invalid += 1; continue
        if cfg in processed: logger.debug(f"{channel_url}: Skip duplicate {cfg.address}:{cfg.port}"); duplicate += 1; continue
        processed.add(cfg); parsed.append(cfg)
    logger.debug(f"{channel_url}: Parsed {len(parsed)}. Invalid: {invalid}, Duplicates: {duplicate}.")
    return parsed, invalid, duplicate

async def resolve_and_assess_proxies(
    configs: List[ProxyParsedConfig], resolver: aiodns.DNSResolver, dns_timeout: int,
    dns_semaphore: asyncio.Semaphore, channel_url: str = "N/A"
) -> Tuple[List[ProxyParsedConfig], int]:
    resolved_w_score: List[ProxyParsedConfig] = []; failed_or_dup = 0; final_keys: Set[tuple] = set()
    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal failed_or_dup; resolved_ip: Optional[str] = None
        try:
            async with dns_semaphore: resolved_ip = await resolve_address(config.address, resolver, dns_timeout)
        except Exception as e: logger.error(f"Resolve task error {config.address} from {channel_url}: {e}", exc_info=False); failed_or_dup += 1; return None
        if resolved_ip:
            score = assess_proxy_quality(config)
            key = (config.protocol, resolved_ip, config.port, frozenset(config.query_params.items()))
            if key not in final_keys: final_keys.add(key); return dataclasses.replace(config, quality_score=score)
            else: logger.debug(f"{channel_url}: Skip duplicate after DNS {config.address} -> {resolved_ip}"); failed_or_dup += 1; return None
        else: logger.debug(f"{channel_url}: DNS failed for {config.address}"); failed_or_dup += 1; return None
    tasks = [resolve_task(cfg) for cfg in configs]
    results = await tqdm.gather(*tasks, desc=f"Resolving DNS ({channel_url.split('/')[-1][:20]}...)", unit="proxy", disable=not TQDM_AVAILABLE or not sys.stdout.isatty())
    resolved_w_score = [res for res in results if res is not None]
    logger.debug(f"{channel_url}: DNS finished. {len(resolved_w_score)} resolved. {failed_or_dup} failures/duplicates.")
    return resolved_w_score, failed_or_dup

async def test_proxy_connectivity(
    proxy_config: ProxyParsedConfig, test_timeout: int, test_sni: str, test_port: int
) -> TEST_RESULT_TYPE:
    start = time.monotonic(); writer = None; host = proxy_config.address; port = proxy_config.port
    use_tls = proxy_config.query_params.get('security', 'none').lower() == 'tls'
    sni = proxy_config.query_params.get('sni', proxy_config.query_params.get('host')) or (host if not is_valid_ipv4(host) else test_sni)
    res: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': 'Unknown'}
    try:
        logger.debug(f"Test {host}:{port} (TLS:{use_tls}, SNI:{sni or 'N/A'})")
        async with asyncio.timeout(test_timeout):
            _, writer = await asyncio.open_connection(host, port)
            if use_tls:
                logger.debug(f"TLS Handshake {host}:{port} (SNI:{sni or 'N/A'})")
                ssl_ctx = ssl.create_default_context()
                allow_insecure = proxy_config.query_params.get('allowInsecure', '0').lower() in ('1', 'true')
                if allow_insecure: ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE; logger.debug(f"TLS verify disabled {host}:{port}")
                transport = writer.get_extra_info('transport'); loop = asyncio.get_running_loop()
                if not transport: raise ProxyTestError("No transport for TLS")
                await loop.start_tls(transport, ssl_ctx, server_hostname=sni if sni else None)
                logger.debug(f"TLS OK {host}:{port}")
            latency = time.monotonic() - start; logger.debug(f"Test OK {host}:{port}, Latency: {latency:.4f}s")
            res = {'status': 'ok', 'latency': latency, 'error': None}
    except asyncio.TimeoutError: logger.debug(f"Test TIMEOUT {host}:{port} ({test_timeout}s)"); res = {'status': 'failed', 'latency': None, 'error': f'Timeout ({test_timeout}s)'}
    except ssl.SSLCertVerificationError as e: logger.debug(f"Test FAIL {host}:{port}: TLS Cert Verify Error: {getattr(e, 'reason', e)}"); res = {'status': 'failed', 'latency': None, 'error': f"TLS Cert Verify Error: {getattr(e, 'reason', e)}"}
    except ssl.SSLError as e: logger.debug(f"Test FAIL {host}:{port}: TLS Handshake Error: {e}"); res = {'status': 'failed', 'latency': None, 'error': f"TLS Handshake Error: {e}"}
    except ConnectionRefusedError: logger.debug(f"Test FAIL {host}:{port}: Connection Refused"); res = {'status': 'failed', 'latency': None, 'error': 'Connection Refused'}
    except OSError as e: msg = getattr(e, 'strerror', str(e)); no = getattr(e, 'errno', 'N/A'); logger.debug(f"Test FAIL {host}:{port}: OS Error: {msg} (errno={no})"); res = {'status': 'failed', 'latency': None, 'error': f"OS Error: {msg}"}
    except ProxyTestError as e: logger.debug(f"Test FAIL {host}:{port}: ProxyTestError: {e}"); res = {'status': 'failed', 'latency': None, 'error': f"Test Logic Error: {e}"}
    except Exception as e: logger.error(f"Unexpected test error {host}:{port}: {e}", exc_info=False); res = {'status': 'failed', 'latency': None, 'error': f"Unexpected Error: {type(e).__name__}"}
    finally:
        if writer:
            try:
                if not writer.is_closing(): writer.close(); await writer.wait_closed()
            except Exception as e: logger.debug(f"Error closing writer {host}:{port}: {e}")
    return res

async def run_proxy_tests(
    proxies: List[ProxyParsedConfig], test_timeout: int, test_sni: str,
    test_port: int, test_semaphore: asyncio.Semaphore
) -> List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]]:
    if not proxies: return []
    async def wrapper(proxy: ProxyParsedConfig) -> Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]:
        try:
            async with test_semaphore: result = await test_proxy_connectivity(proxy, test_timeout, test_sni, test_port)
            return proxy, result
        except Exception as e: logger.error(f"Test wrapper error {proxy.address}:{proxy.port}: {e}", exc_info=False); err_res: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': f'Wrapper Error: {type(e).__name__}'}; return proxy, err_res
    tasks = [wrapper(p) for p in proxies]
    results = await tqdm.gather(*tasks, desc="Testing Proxies", unit="proxy", disable=not TQDM_AVAILABLE or not sys.stdout.isatty())
    ok = sum(1 for _, r in results if r['status'] == 'ok'); failed = len(results) - ok
    logger.info(f"Proxy Test Results: {ok} OK, {failed} Failed.")
    return results

# --- Функции сохранения результатов ---
def _proxy_to_clash_dict(proxy_conf: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE]) -> Optional[Dict[str, Any]]:
    clash: Dict[str, Any] = {}; params = proxy_conf.query_params; proto = proxy_conf.protocol.lower()
    try: url = urlparse(proxy_conf.config_string); user = unquote(url.username) if url.username else None
    except Exception as e: logger.warning(f"Clash re-parse error: {proxy_conf.config_string} - {e}"); return None
    clash['name'] = generate_proxy_profile_name(proxy_conf, test_result); clash['server'] = proxy_conf.address; clash['port'] = proxy_conf.port; clash['udp'] = True
    try:
        if proto == 'vless':
            clash['type'] = 'vless'; clash['uuid'] = user; clash['tls'] = params.get('security', 'none').lower() == 'tls'
            clash['network'] = params.get('type', 'tcp').lower(); clash['flow'] = params.get('flow')
            clash['servername'] = params.get('sni', params.get('host')) or (proxy_conf.address if not is_valid_ipv4(proxy_conf.address) else None)
            insecure = params.get('allowInsecure', '0').lower() in ('1', 'true'); clash['skip-cert-verify'] = insecure
            if clash['network'] == 'ws': host = params.get('host', clash.get('servername', proxy_conf.address)); path = params.get('path', '/'); clash['ws-opts'] = {'path': path, 'headers': {'Host': host}}
            elif clash['network'] == 'grpc': service = params.get('serviceName', ''); clash['grpc-opts'] = {'grpc-service-name': service}
        elif proto == 'trojan':
            clash['type'] = 'trojan'; clash['password'] = user; clash['tls'] = params.get('security', 'tls').lower() == 'tls'
            clash['sni'] = params.get('sni', params.get('peer')) or (proxy_conf.address if not is_valid_ipv4(proxy_conf.address) else None)
            insecure = params.get('allowInsecure', '0').lower() in ('1', 'true'); clash['skip-cert-verify'] = insecure
            net = params.get('type', 'tcp').lower()
            if net == 'ws': clash['network'] = 'ws'; host = params.get('host', clash.get('sni', proxy_conf.address)); path = params.get('path', '/'); clash['ws-opts'] = {'path': path, 'headers': {'Host': host}}
            elif net == 'grpc': clash['network'] = 'grpc'; service = params.get('serviceName', ''); clash['grpc-opts'] = {'grpc-service-name': service}
        elif proto == 'ss':
            clash['type'] = 'ss'
            if not user: raise ValueError("Missing SS user info")
            try: pad = user + '=' * (-len(user) % 4); decoded = base64.urlsafe_b64decode(pad).decode('utf-8'); clash['cipher'], clash['password'] = decoded.split(':', 1)
            except Exception as e: raise ValueError(f"Decode SS user info error: {e}") from e
            plugin = params.get('plugin', '').lower()
            if plugin.startswith('obfs'): clash['plugin'] = 'obfs'; mode = params.get('obfs', 'http'); host = params.get('obfs-host', 'bing.com'); clash['plugin-opts'] = {'mode': mode, 'host': host}
            elif plugin.startswith('v2ray-plugin'):
                 clash['plugin'] = 'v2ray-plugin'; opts: Dict[str, Any] = {'mode': 'websocket'}
                 if params.get('tls', 'false') == 'true': opts['tls'] = True; opts['host'] = params.get('host', proxy_conf.address); opts['skip-cert-verify'] = params.get('allowInsecure', 'false') == 'true'
                 opts['path'] = params.get('path', '/'); ws_host = params.get('host', proxy_conf.address); opts['headers'] = {'Host': ws_host}; clash['plugin-opts'] = opts
        elif proto in ['tuic', 'hy2', 'ssr']: logger.debug(f"{proto.upper()} not fully supported for Clash. Skipping."); return None
        else: logger.warning(f"Unknown protocol '{proto}' for Clash. Skipping."); return None
    except Exception as e: logger.warning(f"Clash conversion error: {proxy_conf.config_string} - {type(e).__name__}: {e}"); return None
    return clash

def _save_as_text(proxies: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], path: str) -> int:
    count = 0; lines = []
    for cfg, res in proxies: name = generate_proxy_profile_name(cfg, res); lines.append(f"{cfg.config_string}#{name}\n"); count += 1
    if count == 0: return 0
    try:
        with open(path, 'w', encoding='utf-8') as f: f.writelines(lines); f.flush()
        return count
    except IOError as e: logger.error(f"IOError saving TEXT to '{path}': {e}"); return 0
    except Exception as e: logger.error(f"Error saving TEXT to '{path}': {e}", exc_info=False); return 0

def _save_as_json(proxies: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], path: str) -> int:
    count = 0; output = []
    for cfg, res in proxies:
        d = asdict(cfg); name = generate_proxy_profile_name(cfg, res); d['profile_name'] = name
        if res: d['test_status'] = res.get('status'); lat = res.get('latency'); d['latency_sec'] = round(lat, 4) if isinstance(lat, (int, float)) else None; d['test_error'] = res.get('error')
        else: d['test_status'] = None; d['latency_sec'] = None; d['test_error'] = None
        output.append(d); count += 1
    if count == 0: return 0
    try:
        with open(path, 'w', encoding='utf-8') as f: json.dump(output, f, indent=2, ensure_ascii=False); f.flush()
        return count
    except IOError as e: logger.error(f"IOError saving JSON to '{path}': {e}"); return 0
    except TypeError as e: logger.error(f"TypeError saving JSON to '{path}': {e}"); return 0
    except Exception as e: logger.error(f"Error saving JSON to '{path}': {e}", exc_info=False); return 0

def _save_as_clash(proxies: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], path: str) -> int:
    if not YAML_AVAILABLE: logger.error("PyYAML needed for Clash format."); return 0
    count = 0; clash_list = []
    for cfg, res in proxies: d = _proxy_to_clash_dict(cfg, res);
    if d: clash_list.append(d); count += 1
    if count == 0: logger.warning("No compatible proxies for Clash config."); return 0
    clash_cfg = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'proxies': clash_list,
        'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': [p['name'] for p in clash_list] + ['DIRECT', 'REJECT']},
                         {'name': 'Auto', 'type': 'url-test', 'proxies': [p['name'] for p in clash_list], 'url': 'http://cp.cloudflare.com/generate_204', 'interval': 300}, # Changed URL
                         {'name': 'Fallback', 'type': 'fallback', 'proxies': [p['name'] for p in clash_list], 'url': 'http://cp.cloudflare.com/generate_204', 'interval': 60}],
        'rules': ['GEOIP,CN,DIRECT', 'DOMAIN-SUFFIX,cn,DIRECT', 'DOMAIN-KEYWORD,google,PROXY', 'MATCH,PROXY']} # Simplified rules
    try:
        with open(path, 'w', encoding='utf-8') as f: yaml.dump(clash_cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=None, indent=2, Dumper=yaml.Dumper); f.flush()
        return count
    except IOError as e: logger.error(f"IOError writing Clash YAML '{path}': {e}"); return 0
    except Exception as e: logger.error(f"Error writing Clash YAML '{path}': {e}", exc_info=False); return 0

# --- Функции оркестрации ---
def load_channels(fpath: str) -> List[str]:
    urls: List[str] = []; logger.info(f"Loading channels from '{fpath}'...")
    try:
        with open(fpath, 'r', encoding='utf-8-sig') as f:
            for i, line in enumerate(f):
                url = line.strip()
                if url and not url.startswith('#') and url.startswith(('http://', 'https://')): urls.append(url)
                elif url and not url.startswith('#'): logger.warning(f"Skip invalid URL line {i+1} in '{fpath}': '{url[:100]}...'")
        logger.info(f"Loaded {len(urls)} valid URLs.")
    except FileNotFoundError: logger.warning(f"Input file '{fpath}' not found.")
    except IOError as e: logger.error(f"IOError reading '{fpath}': {e}")
    except Exception as e: logger.error(f"Error loading channels from '{fpath}': {e}", exc_info=False)
    return urls

@contextlib.asynccontextmanager
async def create_clients(ua: str) -> AsyncIterator[Tuple[aiohttp.ClientSession, aiodns.DNSResolver]]:
    session = None; resolver = None
    try:
        headers = {'User-Agent': ua}; conn = aiohttp.TCPConnector(limit_per_host=20, limit=100)
        session = aiohttp.ClientSession(headers=headers, connector=conn); resolver = aiodns.DNSResolver()
        logger.debug("Clients initialized."); yield session, resolver
    except Exception as e: logger.critical(f"Client init failed: {e}", exc_info=True); raise ConfigError(f"Client init failed: {e}") from e
    finally:
        if session: await session.close(); logger.debug("Session closed.")

async def process_channel_task(
    url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver,
    http_timeout: int, retries: int, delay: float, ua: str, dns_timeout: int, dns_sem: asyncio.Semaphore
) -> Tuple[str, str, List[ProxyParsedConfig]]:
    status = "processing_error"; proxies: List[ProxyParsedConfig] = []
    try:
        lines = await download_proxies_from_channel(url, session, http_timeout, retries, delay, ua)
        parsed, _, _ = parse_proxy_lines(lines, url)
        if not parsed: logger.info(f"{url}: No valid proxies parsed."); return url, "success", []
        resolved, _ = await resolve_and_assess_proxies(parsed, resolver, dns_timeout, dns_sem, url)
        proxies = resolved; status = "success"
        logger.info(f"{url}: Processed. Found {len(proxies)} unique proxies.")
    except EmptyChannelError: logger.warning(f"{url}: Empty/No valid lines."); status = "empty"
    except DownloadError: status = "download_error"
    except Exception as e: logger.error(f"Error processing {url}: {e}", exc_info=False); status = "processing_error"
    return url, status, proxies

async def run_processing(
    urls: List[str], session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, cfg: Dict[str, Any]
) -> Tuple[List[ProxyParsedConfig], int, DefaultDict[str, int]]:
    processed_count = 0; found_before_dedup = 0; status_counts: DefaultDict[str, int] = defaultdict(int)
    chan_sem = asyncio.Semaphore(cfg['MAX_CHANNELS_CONCURRENT']); dns_sem = asyncio.Semaphore(cfg['MAX_DNS_CONCURRENT'])
    final_unique_set: Set[ProxyParsedConfig] = set()
    async def wrapper(u: str) -> Optional[Tuple[str, str, List[ProxyParsedConfig]]]:
        nonlocal processed_count
        async with chan_sem:
            try:
                res = await process_channel_task(u, session, resolver, cfg['HTTP_TIMEOUT'], cfg['MAX_RETRIES'], cfg['RETRY_DELAY_BASE'], cfg['USER_AGENT'], cfg['DNS_TIMEOUT'], dns_sem)
                processed_count += 1; return res
            except Exception as e: logger.critical(f"Wrapper failure for {u}: {e}", exc_info=False); processed_count += 1; return u, "critical_wrapper_error", []
    tasks = [wrapper(u) for u in urls]
    results = await tqdm.gather(*tasks, desc="Processing channels", unit="channel", disable=not TQDM_AVAILABLE or not sys.stdout.isatty())
    for res in results:
        if res is None: status_counts["critical_wrapper_error"] += 1; continue
        _, status, proxies_list = res; status_counts[status] += 1
        if status == "success" and proxies_list: found_before_dedup += len(proxies_list); final_unique_set.update(proxies_list)
    all_unique = list(final_unique_set); logger.info(f"Total unique proxies after DNS & deduplication: {len(all_unique)}")
    return all_unique, found_before_dedup, status_counts

async def run_testing(proxies: List[ProxyParsedConfig], cfg: Dict[str, Any]) -> List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]:
    if not cfg['ENABLE_TESTING'] or not proxies:
        logger.info("Skipping tests (disabled or no proxies)."); return [(p, None) for p in proxies]
    logger.info(f"Starting tests for {len(proxies)} proxies...")
    test_sem = asyncio.Semaphore(cfg['MAX_TESTS_CONCURRENT'])
    results = await run_proxy_tests(proxies, cfg['TEST_TIMEOUT'], cfg['TEST_SNI'], cfg['TEST_PORT'], test_sem)
    return results

def filter_and_sort_results(results: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], enabled: bool) -> List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]:
    if enabled:
        working = [(p, r) for p, r in results if r and r.get('status') == 'ok' and isinstance(r.get('latency'), (int, float))]
        working.sort(key=lambda item: item[1].get('latency') if item[1] else float('inf'))
        logger.info(f"Filtered. Kept {len(working)} working proxies.")
        return working
    else:
        results.sort(key=lambda item: item[0].quality_score, reverse=True)
        logger.info(f"Sorted {len(results)} by quality (testing disabled).")
        return results

def save_results(proxies: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], base: str, format_str: str) -> Tuple[int, str]:
    num = len(proxies)
    try: fmt = OutputFormatEnum(format_str.lower())
    except ValueError: logger.warning(f"Invalid OUTPUT_FORMAT '{format_str}'. Defaulting to TEXT."); fmt = OutputFormatEnum.TEXT
    if num == 0: logger.warning("No proxies to save."); return 0, f"{base}.(no_output_empty)"
    if fmt == OutputFormatEnum.JSON: ext = ".json"; func = _save_as_json
    elif fmt == OutputFormatEnum.CLASH: ext = ".yaml"; func = _save_as_clash
    else: ext = ".txt"; func = _save_as_text
    fpath = os.path.normpath(base + ext); saved = 0
    try:
        d = os.path.dirname(fpath);
        if d and not os.path.exists(d): os.makedirs(d, exist_ok=True); logger.info(f"Created dir: '{d}'")
        logger.info(f"Saving {num} proxies to '{fpath}' (Format: {fmt.value})...")
        saved = func(proxies, fpath)
        if saved > 0:
            logger.info(f"Saved {saved} proxies to '{fpath}'")
            try: # Verify file
                if os.path.exists(fpath) and os.path.getsize(fpath) > 0: logger.debug(f"Verified '{fpath}' exists and not empty.")
                else: logger.warning(f"'{fpath}' saved ({saved}), but missing/empty?")
            except Exception as e: logger.warning(f"Verify error '{fpath}': {e}")
        elif num > 0: logger.error(f"Attempted save {num}, but 0 written to '{fpath}'. Check errors.")
    except IOError as e: logger.error(f"IOError saving to '{fpath}': {e}. Check permissions.", exc_info=False); return 0, fpath
    except Exception as e: logger.error(f"Error saving to '{fpath}': {e}", exc_info=False); return 0, fpath
    return saved, fpath

# --- Функции для Diff Mode (Ограниченная версия) ---
def load_previous_results_text(fpath: str) -> Set[ProxyKey]:
    keys: Set[ProxyKey] = set(); logger.info(f"Loading previous keys from TEXT '{fpath}' for diff...")
    try:
        with open(fpath, 'r', encoding='utf-8') as f: lines = f.readlines()
        count = 0; invalid = 0
        for line in lines:
            url_part = line.strip().split('#')[0]
            if not url_part: continue
            try:
                url = urlparse(url_part); scheme = url.scheme or ""
                match = PROTOCOL_REGEX.match(scheme + "://") if scheme else None
                if not match: invalid += 1; continue
                proto = match.group(1).lower(); addr = url.hostname; port = url.port
                if proto and addr and isinstance(port, int): keys.add((proto, addr.lower(), port)); count += 1
                else: invalid += 1
            except Exception: invalid += 1
        logger.info(f"Loaded {count} keys from '{fpath}'. Skipped {invalid} invalid lines.")
        return keys
    except FileNotFoundError: logger.warning(f"Previous file '{fpath}' not found. All current proxies reported as new."); return set()
    except IOError as e: logger.error(f"IOError reading '{fpath}': {e}. Skipping diff."); return set()
    except Exception as e: logger.error(f"Error loading previous text '{fpath}': {e}. Skipping diff.", exc_info=False); return set()

def compare_results_simple(old: Set[ProxyKey], new: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]) -> DiffResultSimple:
    diff: DiffResultSimple = {"added": [], "removed": []}; current: Set[ProxyKey] = set()
    logger.info(f"Comparing {len(new)} current vs {len(old)} previous keys...")
    for cfg, res in new:
        key: ProxyKey = (cfg.protocol, cfg.address.lower(), cfg.port)
        current.add(key)
        if key not in old: diff["added"].append((cfg, res))
    removed_keys = old - current; diff["removed"] = list(removed_keys)
    unchanged = len(old.intersection(current))
    logger.info(f"Diff: {len(diff['added'])} Added, {len(diff['removed'])} Removed, {unchanged} Unchanged keys. (No latency/status change check)")
    return diff

def save_diff_report_text_simple(diff: DiffResultSimple, fpath: str) -> int:
    lines = []; changes = len(diff["added"]) + len(diff["removed"])
    lines.append("--- Proxy Diff Report (Simple: Added/Removed Only) ---"); lines.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    if diff["added"]:
        lines.append(f"+++ Added ({len(diff['added'])}):")
        # Сортируем добавленные по latency (если есть), потом по качеству (убывание)
        sort_key = lambda item: (item[1]['latency'] if item[1] and item[1].get('status') == 'ok' and item[1].get('latency') is not None else float('inf'), -item[0].quality_score)
        sorted_added = sorted(diff['added'], key=sort_key)
        for cfg, res in sorted_added:
             name = generate_proxy_profile_name(cfg, res)
             lat = f"{res['latency']*1000:.0f}ms" if res and res.get('status') == 'ok' and res.get('latency') is not None else "N/A"
             lines.append(f"  + {name} ({cfg.protocol}, {cfg.address}:{cfg.port}, Latency: {lat})")
        lines.append("")
    if diff["removed"]:
        lines.append(f"--- Removed ({len(diff['removed'])}):")
        sorted_removed = sorted(list(diff['removed']))
        for key in sorted_removed: proto, addr, port = key; lines.append(f"  - Removed Key: ({proto}, {addr}:{port})")
        lines.append("")
    if changes == 0: lines.append(">>> No added or removed proxies detected.")
    lines.append("\nNote: Diff based on protocol:address:port. Latency/status changes not detected from .txt input.")
    try:
        d = os.path.dirname(fpath);
        if d and not os.path.exists(d): os.makedirs(d, exist_ok=True)
        with open(fpath, 'w', encoding='utf-8') as f: f.write("\n".join(lines)); f.flush()
        logger.info(f"Saved simple text diff report to '{fpath}'")
        return changes
    except IOError as e: logger.error(f"IOError saving diff report to '{fpath}': {e}"); return -1
    except Exception as e: logger.error(f"Error saving diff report to '{fpath}': {e}", exc_info=False); return -1

# --- Статистика и вывод ---
def generate_statistics(
    start: float, cfg: Dict[str, Any], total_req: int, after_dns: List[ProxyParsedConfig],
    found_before_dedup: int, chan_stats: DefaultDict[str, int], final_list: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    saved_count: int, out_path: str, is_diff: bool, diff_details: Optional[Dict[str, int]] = None
) -> Statistics:
    after_dns_count = len(after_dns); after_test_count: Optional[int] = None
    if cfg['ENABLE_TESTING']: after_test_count = len(final_list)
    proto_counts: DefaultDict[str, int] = defaultdict(int); quality_counts: DefaultDict[str, int] = defaultdict(int)
    if final_list:
        for proxy, _ in final_list: proto_counts[proxy.protocol] += 1; quality_counts[get_quality_category(proxy.quality_score)] += 1
    processed_count = sum(chan_stats.values())
    try: out_fmt = OutputFormatEnum.TEXT if is_diff else OutputFormatEnum(cfg['OUTPUT_FORMAT'].lower())
    except ValueError: out_fmt = OutputFormatEnum.TEXT # Fallback
    return Statistics(
        start_time=start, total_channels_requested=total_req, channels_processed_count=processed_count,
        channel_status_counts=chan_stats, total_proxies_found_before_dedup=found_before_dedup,
        proxies_after_dns_count=after_dns_count, proxies_after_test_count=after_test_count,
        final_saved_count=saved_count, saved_protocol_counts=proto_counts, saved_quality_category_counts=quality_counts,
        output_file_path=out_path, output_format=out_fmt, is_diff_mode=is_diff, diff_details=diff_details
    )

def display_statistics(stats: Statistics, nocolor: bool = False, config: Dict[str, Any] = {}) -> None:
    end = time.time(); elapsed = end - stats.start_time
    def cprint(level: int, msg: str):
        if nocolor or not sys.stdout.isatty(): print(f"[{logging.getLevelName(level)}] {msg}", file=sys.stderr if level >= logging.WARNING else sys.stdout)
        else: color = COLOR_MAP.get(level, COLOR_MAP['RESET']); print(f"{color}[{logging.getLevelName(level)}]{COLOR_MAP['RESET']} {msg}", file=sys.stderr if level >= logging.WARNING else sys.stdout)
    mode = "Diff Mode (Text-based)" if stats.is_diff_mode else "Normal Mode"
    cprint(logging.INFO, f"==================== 📊 PROXY DOWNLOAD STATISTICS ({mode}) ====================")
    cprint(logging.INFO, f"⏱️  Runtime: {elapsed:.2f} seconds")
    cprint(logging.INFO, f"🔗 Channels Requested: {stats.total_channels_requested}")
    cprint(logging.INFO, f"🛠️ Channels Processed: {stats.channels_processed_count}/{stats.total_channels_requested}")
    cprint(logging.INFO, "\n📊 Channel Status:")
    status_order = ["success", "empty", "download_error", "processing_error", "critical_wrapper_error"]
    texts = {"success": "SUCCESS", "empty": "EMPTY", "download_error": "DL/DECODE ERR", "processing_error": "PROCESS ERR", "critical_wrapper_error": "CRITICAL ERR"}
    levels = {"success": logging.INFO, "empty": logging.WARNING, "download_error": logging.ERROR, "processing_error": logging.ERROR, "critical_wrapper_error": logging.CRITICAL}
    processed = set()
    for key in status_order:
        if key in stats.channel_status_counts: cnt = stats.channel_status_counts[key]; lvl = levels.get(key, logging.ERROR); txt = texts.get(key, key.upper()); cprint(lvl, f"  - {txt}: {cnt}"); processed.add(key)
    for key, cnt in stats.channel_status_counts.items():
         if key not in processed: lvl = levels.get(key, logging.ERROR); txt = texts.get(key, key.replace('_', ' ').upper()); cprint(lvl, f"  - {txt}: {cnt}")
    cprint(logging.INFO, f"\n✨ Proxies Found (Before Final Dedup): {stats.total_proxies_found_before_dedup}")
    cprint(logging.INFO, f"🧬 Proxies After DNS & Final Dedup: {stats.proxies_after_dns_count}")
    if stats.proxies_after_test_count is not None: cprint(logging.INFO, f"✅ Proxies Passed Test: {stats.proxies_after_test_count} / {stats.proxies_after_dns_count}")
    if stats.is_diff_mode:
        cprint(logging.INFO, "\n🔄 Diff Report Summary:")
        if stats.diff_details: cprint(logging.INFO, f"  +++ Added: {stats.diff_details.get('added', 0)}"); cprint(logging.INFO, f"  --- Removed: {stats.diff_details.get('removed', 0)}"); cprint(logging.WARNING, "      (Latency/status change detection N/A)")
        else: cprint(logging.WARNING, "      Diff details N/A.")
        cprint(logging.INFO, f"📝 Diff Report Saved: '{stats.output_file_path}' (Format: {stats.output_format.value})")
        if stats.final_saved_count > 0 and 'OUTPUT_BASE' in config and 'OUTPUT_FORMAT' in config:
             try:
                 fmt = OutputFormatEnum(config['OUTPUT_FORMAT'].lower()); ext = ".yaml" if fmt == OutputFormatEnum.CLASH else f".{fmt.value}"
                 path = os.path.normpath(config['OUTPUT_BASE'] + ext); cprint(logging.INFO, f"📝 Main Output Updated: {stats.final_saved_count} proxies (to '{path}')")
             except ValueError: cprint(logging.WARNING, f"Could not determine main output path (Invalid OUTPUT_FORMAT '{config['OUTPUT_FORMAT']}').")
        elif config.get('UPDATE_OUTPUT_IN_DIFF'): cprint(logging.WARNING, "Main output update requested, but 0 proxies saved.")
        else: cprint(logging.INFO, "📝 Main Output NOT Updated (as configured).")
    else:
        if stats.final_saved_count > 0: cprint(logging.INFO, f"📝 Total Saved: {stats.final_saved_count} (to '{stats.output_file_path}', format: {stats.output_format.value})")
        else: cprint(logging.WARNING, f"📝 Total Saved: 0")
    total_valid = stats.proxies_after_test_count if stats.proxies_after_test_count is not None else stats.proxies_after_dns_count
    if total_valid > 0:
        basis = "tested" if stats.proxies_after_test_count is not None else "resolved/dedup"
        cprint(logging.INFO, f"\n🔬 Protocol Breakdown ({total_valid} {basis} proxies):")
        if stats.saved_protocol_counts: [cprint(logging.INFO, f"   - {p.upper()}: {c}") for p, c in sorted(stats.saved_protocol_counts.items())]
        else: cprint(logging.WARNING, "   N/A.")
        cprint(logging.INFO, f"\n⭐️ Quality Distribution ({total_valid} {basis} proxies):")
        if stats.saved_quality_category_counts: cat_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}; [cprint(logging.INFO, f"   - {cat}: {cnt}") for cat, cnt in sorted(stats.saved_quality_category_counts.items(), key=lambda i: cat_order.get(i[0], 99))]
        else: cprint(logging.WARNING, "   N/A.")
    else: cprint(logging.WARNING, "\nNo proxies after DNS/testing, skipping breakdown.")
    cprint(logging.INFO, "======================== 🏁 STATISTICS END =========================")

# --- Главная функция ---
async def amain() -> int:
    start = time.time()
    cfg = {k: v for k, v in globals().items() if k.isupper() and not k.startswith('_') and k not in ('TQDM_AVAILABLE', 'YAML_AVAILABLE')}
    setup_logging(cfg.get('LOG_LEVEL', 'INFO'), cfg.get('LOG_FILE_PATH', 'pd.log'), cfg.get('NO_COLOR_LOGS', False))
    logger.info("🚀 Starting Proxy Downloader..."); logger.debug(f"Config: {cfg}")
    urls = load_channels(cfg.get('INPUT_FILE', 'urls.txt'))
    total_req = len(urls);
    if not urls: logger.error("No valid URLs loaded. Exiting."); return 1
    saved_count = 0; out_path = "(not generated)"; diff_summary: Optional[Dict[str, int]] = None
    try:
        async with create_clients(cfg.get('USER_AGENT', 'PD/1.2')) as (session, resolver):
            after_dns, found_before_dedup, chan_stats = await run_processing(urls, session, resolver, cfg)
            with_tests = await run_testing(after_dns, cfg)
            final_list = filter_and_sort_results(with_tests, cfg.get('ENABLE_TESTING', True))
            if cfg.get('ENABLE_DIFF_MODE', False):
                logger.info("--- Diff Mode Enabled (Text-based) ---")
                prev_path = cfg.get('DIFF_PREVIOUS_FILE_PATH') or os.path.normpath(cfg.get('OUTPUT_BASE', 'out') + ".txt")
                logger.info(f"Assuming previous output: '{prev_path}'")
                old_keys = load_previous_results_text(prev_path)
                diff_data = compare_results_simple(old_keys, final_list)
                diff_summary = {"added": len(diff_data['added']), "removed": len(diff_data['removed'])}
                report_path = cfg.get('DIFF_REPORT_FILE_PATH') or os.path.normpath(cfg.get('OUTPUT_BASE', 'out') + ".diff.txt")
                save_diff_report_text_simple(diff_data, report_path); out_path = report_path
                if cfg.get('UPDATE_OUTPUT_IN_DIFF', False):
                    logger.info("UPDATE_OUTPUT_IN_DIFF=True: Updating main output file.")
                    saved_count, _ = save_results(final_list, cfg.get('OUTPUT_BASE', 'out'), cfg.get('OUTPUT_FORMAT', 'text'))
                else: logger.info("UPDATE_OUTPUT_IN_DIFF=False: Main output file NOT updated."); saved_count = 0
            else:
                logger.info("--- Normal Mode (Full Output) ---")
                saved_count, out_path = save_results(final_list, cfg.get('OUTPUT_BASE', 'out'), cfg.get('OUTPUT_FORMAT', 'text'))
            stats = generate_statistics(start, cfg, total_req, after_dns, found_before_dedup, chan_stats, final_list, saved_count, out_path, cfg.get('ENABLE_DIFF_MODE', False), diff_summary)
            display_statistics(stats, cfg.get('NO_COLOR_LOGS', False), cfg)
    except ConfigError: return 1
    except KeyboardInterrupt: logger.warning("Script interrupted."); return 1
    except Exception as e: logger.critical(f"Critical error: {e}", exc_info=True); return 1
    finally: logger.info("✅ Script finished.")
    return 0

# --- Точка входа ---
if __name__ == "__main__":
    try: import uvloop; uvloop.install(); print("INFO: Using uvloop.", file=sys.stderr)
    except ImportError: pass
    exit_code = asyncio.run(amain())
    sys.exit(exit_code)
