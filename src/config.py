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
import concurrent.futures  # Import for thread pool
import validators # For URL validation
import yaml # For config file
from tqdm import tqdm # For progress bar
import argparse # For command line arguments

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Type
from dataclasses import dataclass, field
from collections import defaultdict
import functools

# --- Конфигурация из YAML файла ---
CONFIG_FILE = 'config.yaml'
DEFAULT_CONFIG = {
    'log_level_file': 'WARNING',
    'log_level_console': 'INFO',
    'log_file': 'proxy_downloader.log',
    'all_urls_file': 'channel_urls.txt',
    'output_all_config_file': 'configs/proxy_configs_all.txt',
    'max_retries': 4,
    'retry_delay_base': 2,
    'max_concurrent_channels': 60,
    'max_concurrent_proxies_per_channel': 50,
    'max_concurrent_proxies_global': 50,
    'download_timeout_sec': 15,
    'allowed_protocols': ["vless://", "tuic://", "hy2://", "ss://"],
    'enable_dns_cache': True,
}

def load_config(config_file_path):
    try:
        with open(config_file_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return {**DEFAULT_CONFIG, **config} # Merge with defaults, config file overrides defaults
    except FileNotFoundError:
        colored_log(logging.WARNING, f"Файл конфигурации {config_file_path} не найден. Используются значения по умолчанию.")
        return DEFAULT_CONFIG
    except yaml.YAMLError as e:
        colored_log(logging.ERROR, f"Ошибка чтения файла конфигурации {config_file_path}: {e}. Используются значения по умолчанию.")
        return DEFAULT_CONFIG

config = load_config(CONFIG_FILE)

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set root logger level to DEBUG, handlers will filter

file_handler = logging.FileHandler(config['log_file'], encoding='utf-8')
file_handler.setLevel(getattr(logging, config['log_level_file'].upper(), logging.WARNING))
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(getattr(logging, config['log_level_console'].upper(), logging.INFO))
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
    if console_handler.level > level and file_handler.level > level: # Early exit if no handler will log it
        return
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

# --- Константы из конфигурации ---
ALLOWED_PROTOCOLS = config['allowed_protocols']
ALL_URLS_FILE = config['all_urls_file']
OUTPUT_ALL_CONFIG_FILE = config['output_all_config_file']
MAX_RETRIES = config['max_retries']
RETRY_DELAY_BASE = config['retry_delay_base']
MAX_CONCURRENT_CHANNELS = config['max_concurrent_channels']
MAX_CONCURRENT_PROXIES_PER_CHANNEL = config['max_concurrent_proxies_per_channel']
MAX_CONCURRENT_PROXIES_GLOBAL = config['max_concurrent_proxies_global']
DOWNLOAD_TIMEOUT_SEC = config['download_timeout_sec']
ENABLE_DNS_CACHE = config['enable_dns_cache']

# --- Thread Pool Executor for CPU-bound tasks ---
CPU_BOUND_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

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
class ParsedConfig:
    config_string: str
    protocol: str
    address: str
    port: int

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ParsedConfig"]:
        protocol = next((p.replace("://", "") for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
        if not protocol:
            return None, "Unsupported protocol"

        if not validators.url(config_string): # Строгая валидация URL
            return None, "Invalid URL format"

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                return None, "Missing address or port"
            return cls(
                config_string=config_string,
                protocol=protocol,
                address=address,
                port=port
            ), None
        except ValueError as e:
            return None, f"Parsing error: {e}"

    def __hash__(self):
        return hash((self.protocol, self.address, self.port, self.config_string))

    def __eq__(self, other):
        if isinstance(other, ParsedConfig):
            return (self.protocol, self.address, self.port, self.config_string) == \
                   (other.protocol, other.address, other.port, other.config_string)
        return False

PARSER_REGISTRY: Dict[str, Type[ParsedConfig]] = {} # Registry for protocol-specific parsers

def register_parser(protocol_name: str):
    def decorator(parser_class):
        PARSER_REGISTRY[protocol_name] = parser_class
        return parser_class
    return decorator

@register_parser("vless")
@dataclass(frozen=True)
class VlessParsedConfig(ParsedConfig):
    uuid: Optional[str] = None
    encryption: Optional[str] = None
    flow: Optional[str] = None
    security: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Tuple[Optional["VlessParsedConfig"], Optional[str]]: # Return tuple for error info
        base_config, error = ParsedConfig.from_url(config_string) # Reuse base parser
        if error or not base_config:
            return None, error

        if base_config.protocol != "vless": # Double check protocol
             return None, "Incorrect protocol for VlessParser"

        try:
            parsed_url = urlparse(config_string)
            query_params = parse_qs(parsed_url.query)

            uuid_val = parsed_url.username if parsed_url.username else query_params.get("uuid", [None])[0]

            return cls(
                config_string=config_string,
                protocol="vless",
                address=base_config.address,
                port=base_config.port,
                uuid=uuid_val,
                encryption=query_params.get("encryption", [None])[0],
                flow=query_params.get("flow", [None])[0],
                security=query_params.get("security", [None])[0],
                sni=query_params.get("sni", [None])[0],
                alpn=query_params.get("alpn", [None])[0],
            ), None
        except ValueError as e:
            return None, f"Vless parsing error: {e}"

    def __hash__(self):
        return hash((super().__hash__(), self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn))

    def __eq__(self, other):
        if not isinstance(other, VlessParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn) == \
               (other.uuid, other.encryption, other.flow, other.security, other.sni, other.alpn)

@register_parser("tuic")
@dataclass(frozen=True)
class TuicParsedConfig(ParsedConfig):
    congestion_control: Optional[str] = None
    uuid: Optional[str] = None # Example of more detailed parsing, even if not used now

    @classmethod
    def from_url(cls, config_string: str) -> Tuple[Optional["TuicParsedConfig"], Optional[str]]:
        base_config, error = ParsedConfig.from_url(config_string)
        if error or not base_config:
            return None, error
        if base_config.protocol != "tuic":
             return None, "Incorrect protocol for TuicParser"
        try:
            parsed_url = urlparse(config_string)
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="tuic",
                address=base_config.address,
                port=base_config.port,
                congestion_control=query_params.get("c", [None])[0],
                uuid=query_params.get("uuid", [None])[0], # Example of extra param
            ), None
        except ValueError as e:
            return None, f"Tuic parsing error: {e}"

    def __hash__(self):
        return hash((super().__hash__(), self.congestion_control, self.uuid))

    def __eq__(self, other):
        if not isinstance(other, TuicParsedConfig):
            return False
        return super().__eq__(other) and (self.congestion_control, self.uuid) == (other.congestion_control, other.uuid)

@register_parser("hy2")
@dataclass(frozen=True)
class Hy2ParsedConfig(ParsedConfig):
    encryption_method: Optional[str] = None
    mode: Optional[str] = None # Example of more detailed parsing

    @classmethod
    def from_url(cls, config_string: str) -> Tuple[Optional["Hy2ParsedConfig"], Optional[str]]:
        base_config, error = ParsedConfig.from_url(config_string)
        if error or not base_config:
            return None, error
        if base_config.protocol != "hy2":
             return None, "Incorrect protocol for Hy2Parser"
        try:
            parsed_url = urlparse(config_string)
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="hy2",
                address=base_config.address,
                port=base_config.port,
                encryption_method=query_params.get("enc", [None])[0],
                mode=query_params.get("mode", [None])[0], # Example extra parameter
            ), None
        except ValueError as e:
            return None, f"Hy2 parsing error: {e}"

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method, self.mode))

    def __eq__(self, other):
        if not isinstance(other, Hy2ParsedConfig):
            return False
        return super().__eq__(other) and (self.encryption_method, self.mode) == (other.encryption_method, other.mode)


@register_parser("ss")
@dataclass(frozen=True)
class SsParsedConfig(ParsedConfig):
    encryption_method: Optional[str] = None
    password: Optional[str] = None
    plugin: Optional[str] = None
    remarks: Optional[str] = None # Example of more detailed parsing

    @classmethod
    def from_url(cls, config_string: str) -> Tuple[Optional["SsParsedConfig"], Optional[str]]:
        base_config, error = ParsedConfig.from_url(config_string)
        if error or not base_config:
            return None, error
        if base_config.protocol != "ss":
             return None, "Incorrect protocol for SsParser"
        try:
            parsed_url = urlparse(config_string)

            encryption_password_b64 = parsed_url.netloc.split('@')[0] # extract b64 encoded part
            try:
                encryption_password_decoded = base64.b64decode(encryption_password_b64 + "==").decode('utf-8') # Padding might be needed
                encryption_method = encryption_password_decoded.split(':')[0]
                password = encryption_password_decoded.split(':')[1] if len(encryption_password_decoded.split(':')) > 1 else None
            except Exception as e_b64decode: # Decoding errors, handle as needed
                return None, f"Base64 decode error: {e_b64decode}"
                encryption_method = None
                password = None

            query_params = parse_qs(parsed_url.query)
            plugin = query_params.get('plugin', [None])[0]
            remarks = query_params.get('remarks', [None])[0] # Example extra parameter

            return cls(
                config_string=config_string,
                protocol="ss",
                address=base_config.address,
                port=base_config.port,
                encryption_method=encryption_method,
                password=password,
                plugin=plugin,
                remarks=remarks, # Example extra parameter
            ), None
        except ValueError as e:
            return None, f"SS parsing error: {e}"

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method, self.password, self.plugin, self.remarks))

    def __eq__(self, other):
        if not isinstance(other, SsParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.encryption_method, self.password, self.plugin, self.remarks) == \
               (other.encryption_method, other.password, other.plugin, other.remarks)


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
        colored_log(logging.DEBUG, f"DNS resolution error for {hostname}: {e}") # Log DNS errors at DEBUG
        return None
    except Exception as e:
        colored_log(logging.DEBUG, f"Unexpected error during DNS resolution for {hostname}: {e}") # Log unexpected errors at DEBUG
        return None

@functools.lru_cache(maxsize=1024) # Simple DNS cache
def is_valid_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def download_channel_content(channel_url: str, session: aiohttp.ClientSession, timeout: aiohttp.ClientTimeout) -> Tuple[Optional[str], str]:
    """Downloads content from a channel URL, handling HTTP errors and timeouts. Returns content and status."""
    try:
        async with session.get(channel_url, timeout=timeout) as response:
            if response.status == 200:
                return await response.text(encoding='utf-8', errors='ignore'), "success"
            else:
                return None, f"http_error_{response.status}" # Detailed HTTP error status
    except aiohttp.ClientError as e:
        return None, f"client_error_{type(e).__name__}" # Client error type
    except asyncio.TimeoutError:
        return None, "timeout_error" # Timeout error

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a single channel URL with retry logic and detailed error handling."""
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT_SEC)
    last_status = "unknown" # Track last status for logging

    while retries_attempted <= MAX_RETRIES:
        content, status = await download_channel_content(channel_url, session, session_timeout)
        last_status = status # Update last status

        if status == "success":
            return content.splitlines(), "success"
        else:
            retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул статус: {status} (попытка {retries_attempted+1}/{MAX_RETRIES+1}). Пауза {retry_delay} сек")
            if retries_attempted == MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Макс. попыток ({MAX_RETRIES+1}) исчерпано для {channel_url}, статус: {status}")
                return [], "error_" + last_status # Include last status in error type
            await asyncio.sleep(retry_delay)
        retries_attempted += 1
    return [], "critical_" + last_status # Should not reach here, but for type hinting, include last status

def parse_proxy_config(line: str) -> Tuple[Optional[ParsedConfig], Optional[str]]:
    """Parses a single line into a ProxyParsedConfig object using the registry."""
    line = line.strip()
    if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
        return None, "Skipped: invalid line or protocol"

    for protocol_prefix in ALLOWED_PROTOCOLS:
        if line.startswith(protocol_prefix):
            protocol_name = protocol_prefix.replace("://", "")
            parser_class = PARSER_REGISTRY.get(protocol_name)
            if parser_class:
                parsed_config, error_msg = parser_class.from_url(line) # Use parser from registry
                if parsed_config:
                    return parsed_config, None
                else:
                    return None, f"Parsing failed: {error_msg} for line: '{line[:100]}...'" # Limit line length in log
            else:
                return None, f"No parser found for protocol: {protocol_name}" # Should not happen if registry is correctly populated

    return None, "Skipped: no matching protocol parser" # Should not reach here, loop covers all prefixes


async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ParsedConfig]:
    """Asynchronously parses and filters proxies using thread pool for CPU-bound parsing and async DNS resolution."""

    parsed_configs_with_errors: List[Tuple[Optional[ParsedConfig], Optional[str]]] = await asyncio.get_running_loop().run_in_executor(
        CPU_BOUND_EXECUTOR,
        lambda: [parse_proxy_config(line) for line in lines] # Run parsing in thread pool
    )

    configs_to_resolve = []
    for config, error in parsed_configs_with_errors:
        if config:
            configs_to_resolve.append(config)
        elif error and logger.level <= logging.DEBUG: # Log skipped lines only in DEBUG mode
            colored_log(logging.DEBUG, f"ℹ️ {error}")

    async def resolve_single_config(config):
        resolved_ip = await resolve_address(config.address, resolver)
        if resolved_ip and is_valid_ipv4(resolved_ip):
            return config, resolved_ip
        return config, None

    resolution_tasks = [resolve_single_config(config) for config in configs_to_resolve]
    resolution_results_async = await asyncio.gather(*resolution_tasks)

    parsed_configs_resolved = []
    seen_ipv4_addresses = set()
    for config, resolved_ip in resolution_results_async:
        if resolved_ip:
            if resolved_ip not in seen_ipv4_addresses:
                parsed_configs_resolved.append(config)
                seen_ipv4_addresses.add(resolved_ip)
            elif logger.level <= logging.DEBUG: # Log duplicate IPs only in DEBUG mode
                colored_log(logging.DEBUG, f"ℹ️  Пропущен дубликат прокси по IPv4: {resolved_ip} (протокол: {config.protocol})")
        elif logger.level <= logging.DEBUG: # Log no IPv4 only in DEBUG mode
            colored_log(logging.DEBUG, f"ℹ️  Пропущен прокси без IPv4: {config.address} (протокол: {config.protocol})")

    return parsed_configs_resolved


def save_all_proxies_to_file(all_proxies: List[ParsedConfig], output_file: str) -> int:
    """Saves all downloaded proxies to the output file, grouped by protocol, with enhanced naming."""
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
                    colored_log(logging.INFO, f"\n📝 Протокол ({LogColors.CYAN}{protocol_name}{LogColors.RESET}, всего, уникальные IPv4): {len(protocol_grouped_proxies[protocol])}")
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        proxy_name = generate_proxy_name(proxy_conf, protocol_name)
                        config_line = proxy_conf.config_string + f"#{proxy_name}"
                        f.write(config_line + "\n")
                        colored_log(logging.INFO, f"   - {config_line}")
                        total_proxies_count += 1

        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} прокси (всего, уникальные IPv4) в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении всех прокси в файл: {e}")
    return total_proxies_count

def generate_proxy_name(proxy_conf: ParsedConfig, protocol_name: str) -> str:
    """Generates a colored and informative proxy name for logging and comments."""
    proxy_name_parts = [f"{LogColors.CYAN}{protocol_name}{LogColors.RESET}"]
    proxy_name_parts.append(f"{LogColors.GREEN}{proxy_conf.address}:{proxy_conf.port}{LogColors.RESET}")

    if isinstance(proxy_conf, VlessParsedConfig) and proxy_conf.sni:
        proxy_name_parts.append(f"sni:{LogColors.YELLOW}{proxy_conf.sni}{LogColors.RESET}")
    if isinstance(proxy_conf, SsParsedConfig) and proxy_conf.encryption_method:
        proxy_name_parts.append(f"enc:{LogColors.MAGENTA}{proxy_conf.encryption_method}{LogColors.RESET}")
    return " ".join(proxy_name_parts)

async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from the specified file using buffered reading."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f: # Buffered reading
            while True:
                line = f.readline()
                if not line:
                    break
                url = line.strip()
                if url:
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"Файл {all_urls_file} не найден. Проверьте наличие файла с URL каналов.")
        open(all_urls_file, 'w').close() # Create empty file if not exists (sync ok here)
    return channel_urls


async def main(verbosity: str): # Add verbosity argument
    """Main function to download and process proxy configurations from channel URLs."""
    # Set verbosity level from command line argument
    log_level = getattr(logging, verbosity.upper(), logging.INFO)
    console_handler.setLevel(log_level)
    logger.setLevel(logging.DEBUG) # Keep debug level for internal logs, console is controlled by arg

    if ENABLE_DNS_CACHE:
        aiodns_resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop(), cache=True) # Enable cache
        colored_log(logging.INFO, "DNS кэширование включено.")
    else:
        aiodns_resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        colored_log(logging.INFO, "DNS кэширование выключено.")

    start_time = time.time()
    channel_urls = await load_channel_urls(ALL_URLS_FILE)
    if not channel_urls:
        colored_log(logging.WARNING, "Нет URL каналов для обработки.")
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
    channels_processed_with_issues = 0
    total_proxies_downloaded = 0
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)
    blacklisted_channels = set() # Basic blacklist

    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)

    progress_bar = tqdm(total=total_channels, desc="Обработка каналов", unit="канал", dynamic_ncols=True) # Progress bar

    async with aiohttp.ClientSession() as session:
        channel_tasks = []
        for channel_url in channel_urls:
            if channel_url in blacklisted_channels: # Skip blacklisted channels
                colored_log(logging.INFO, f"ℹ️  Канал {channel_url} пропущен (в черном списке).")
                progress_bar.update(1) # still update progress bar even if skipped
                continue

            async def process_channel_task(url):
                nonlocal channels_processed_successfully, channels_processed_with_issues, total_proxies_downloaded # Declare nonlocal
                channel_proxies_count_channel = 0
                channel_success = 0
                channel_issue = 0
                async with channel_semaphore:
                    colored_log(logging.INFO, f"🚀 Обработка канала: {url}")
                    lines, status = await download_proxies_from_channel(url, session)
                    channel_status_counts[status] += 1

                    if status == "success":
                        parsed_proxies = await parse_and_filter_proxies(lines, aiodns_resolver)
                        channel_proxies_count_channel = len(parsed_proxies)
                        channel_success = 1
                        for proxy in parsed_proxies:
                            protocol_counts[proxy.protocol] += 1
                        return channel_proxies_count_channel, channel_success, 0, parsed_proxies
                    else:
                        colored_log(logging.WARNING, f"⚠️ Канал {url} обработан со статусом: {status}.")
                        channels_processed_with_issues += 1 # Increment issue count here
                        if status.startswith("error") or status.startswith("critical"): # Blacklist on errors
                            blacklisted_channels.add(url) # Add to blacklist if download error
                            colored_log(logging.INFO, f"⛔ Канал {url} добавлен в черный список.")
                        return 0, 0, 1, [] # Indicate issue with flag

            task = asyncio.create_task(process_channel_task(channel_url))
            task.add_done_callback(lambda future: progress_bar.update(1)) # Update progress bar when task finishes
            channel_tasks.append(task)

        channel_results = await asyncio.gather(*channel_tasks)
        all_proxies = []
        for proxies_count, success_flag, issue_flag, proxies_list in channel_results:
            total_proxies_downloaded += proxies_count
            channels_processed_successfully += success_flag
            all_proxies.extend(proxies_list)

    progress_bar.close() # Close progress bar

    all_proxies_saved_count = save_all_proxies_to_file(all_proxies, OUTPUT_ALL_CONFIG_FILE)
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
    colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
    colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")

    success_channels_percent = (channels_processed_successfully / total_channels) * 100 if total_channels else 0
    issue_channels_percent = (channels_processed_with_issues / total_channels) * 100 if total_channels else 0
    failed_channels_count = total_channels - channels_processed_successfully - channels_processed_with_issues

    colored_log(logging.INFO, "\n✅ Успешно обработано URL-источников: {} из {} ({:.2f}%)".format(
        channels_processed_successfully, total_channels, success_channels_percent))
    if channels_processed_with_issues > 0:
        colored_log(logging.WARNING, "⚠️ URL-источников с предупреждениями/ошибками: {} из {} ({:.2f}%)".format(
            channels_processed_with_issues, total_channels, issue_channels_percent))
    if failed_channels_count > 0:
        failed_channels_percent = (failed_channels_count / total_channels) * 100 if total_channels else 0
        colored_log(logging.ERROR, f"❌ Не удалось обработать URL-источников: {failed_channels_count} из {total_channels} ({failed_channels_percent:.2f}%)")
    colored_log(logging.INFO, "\n✨ Всего найдено уникальных IPv4 прокси-конфигураций: {}".format(total_proxies_downloaded))
    colored_log(logging.INFO, f"📝 Всего (все, уникальные IPv4) прокси-конфигураций сохранено в файл: {all_proxies_saved_count} ({OUTPUT_ALL_CONFIG_FILE})")

    colored_log(logging.INFO, "\n🔬 Разбивка найденных прокси-конфигураций по протоколам (уникальные IPv4):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   Нет статистики по протоколам (прокси не найдены).")

    colored_log(logging.INFO, "Статистика статусов загрузки каналов:")
    for status, count in channel_status_counts.items():
        colored_log(logging.INFO, f"   - {status}: {count}")
    if blacklisted_channels:
        colored_log(logging.INFO, f"Каналы, добавленные в черный список ({len(blacklisted_channels)}):")
        for url in blacklisted_channels:
            colored_log(logging.INFO, f"   - {url}")


    colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
    colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Загрузчик и обработчик прокси-конфигураций.")
    parser.add_argument(
        "-v", "--verbosity",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Уровень verbosity вывода в консоль: DEBUG, INFO, WARNING, ERROR, CRITICAL. По умолчанию INFO."
    )
    args = parser.parse_args()

    asyncio.run(main(verbosity=args.verbosity))
