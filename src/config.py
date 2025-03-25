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

from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Set
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
        record.color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET']) if self.use_colors else ''
        record.color_reset = COLOR_MAP['RESET'] if self.use_colors else ''
        return super().format(record)

console_formatter = ColoredFormatter()
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)


def colored_log(level: int, message: str, *args, **kwargs):
    """Logs a message with color to the console using standard logging."""
    logger.log(level, message, *args, **kwargs)


# --- Data Structures ---
class Protocols(Enum):
    """Enumeration of supported proxy protocols."""
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

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
    MAX_PROXIES_PER_CHANNEL: int = 50
    MAX_PROXIES_GLOBAL: int = 50

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

class InvalidURLError(ValueError):
    """Exception for invalid URLs."""
    pass

class UnsupportedProtocolError(ValueError):
    """Exception for unsupported protocols."""
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
    quality_score: int = 0

    def __hash__(self):
        """Hashes the configuration string for deduplication."""
        return hash((self.config_string))

    def __str__(self):
        """String representation of the ProxyConfig object."""
        return (f"ProxyConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...', quality_score={self.quality_score}")

    @staticmethod
    def _decode_base64_if_needed(config_string: str) -> Tuple[str, bool]:
        """Decodes base64 if the string doesn't start with a known protocol."""
        if PROTOCOL_REGEX.match(config_string):
            return config_string, False

        try:
            decoded_config = base64.b64decode(config_string).decode('utf-8')
            if PROTOCOL_REGEX.match(decoded_config):
                return decoded_config, True
            else:
                return config_string, False
        except (ValueError, UnicodeDecodeError):
            return config_string, False

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """Parses a proxy configuration URL."""
        config_string, _ = cls._decode_base64_if_needed(config_string)

        protocol_match = PROTOCOL_REGEX.match(config_string)
        if not protocol_match:
            logger.debug(f"Unsupported protocol in: {config_string[:100]}...")
            return None
        protocol = protocol_match.group(1).lower()

        try:
            parsed_url = urlparse(config_string)

            if parsed_url.scheme.lower() != protocol:
                logger.debug(f"URL scheme '{parsed_url.scheme}' mismatch for protocol '{protocol}': {config_string}")
                return None

            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                logger.debug(f"Address or port missing in URL: {config_string}")
                return None

            if not 1 <= port <= 65535:
                logger.debug(f"Invalid port number: {port} in URL: {config_string}")
                return None

            remark = parsed_url.fragment or ""
            query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()} if parsed_url.query else {}

            return cls(
                config_string=config_string.split("#")[0],
                protocol=protocol,
                address=address,
                port=port,
                remark=remark,
                query_params=query_params,
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
        async with asyncio.timeout(DNS_TIMEOUT):
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            if is_valid_ipv4(resolved_ip):
                return resolved_ip
            else:
                logger.debug(f"DNS resolved {hostname} to non-IPv4: {resolved_ip}")
                return None
    except asyncio.TimeoutError:
        logger.debug(f"DNS resolution timeout for {hostname}")
        return None
    except aiodns.error.DNSError as e:
        error_code = e.args[0] if e.args else "Unknown"
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
    security = query_params.get("security", "none").lower()
    score += QUALITY_SCORE_WEIGHTS["security"].get(security, 0)
    transport = query_params.get("transport", "tcp").lower()
    score += QUALITY_SCORE_WEIGHTS["transport"].get(transport, 0)

    return score

def get_quality_category(score: int) -> str:
    """Determines quality category based on the score."""
    for category, score_range in QUALITY_CATEGORIES.items():
        if score in score_range:
            return category
    return "Unknown"

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    """Generates a concise proxy profile name using a template."""
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', 'tcp').lower()
    security = proxy_config.query_params.get('security', 'none').lower()

    profile_name_values = {
        "protocol": protocol,
        "type": type_,
        "security": security
    }
    return PROFILE_NAME_TEMPLATE.substitute(profile_name_values)


# --- Core Logic Functions ---
async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a channel URL with retry logic."""
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)

    while retries_attempted <= MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout, headers=HEADERS) as response:
                response.raise_for_status()
                logger.debug(f"Successfully downloaded from {channel_url}, status: {response.status}")
                text = await response.text(encoding='utf-8', errors='ignore')

                if not text.strip():
                    colored_log(logging.WARNING, f"⚠️ Channel {channel_url} returned empty response.")
                    return [], "warning"

                try:
                    decoded_text = base64.b64decode(text.strip()).decode('utf-8')
                    return decoded_text.splitlines(), "success"
                except:
                    return text.splitlines(), "success"

        except aiohttp.ClientResponseError as e:
            colored_log(logging.WARNING, f"⚠️ Channel {channel_url} returned HTTP error {e.status}: {e.message}")
            logger.debug(f"Response headers for {channel_url} on error: {response.headers if 'response' in locals() else 'N/A'}")
            return [], "warning"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted) + random.uniform(-0.5, 0.5)
            retry_delay = max(0.5, retry_delay)
            colored_log(logging.WARNING, f"⚠️ Error getting {channel_url} (attempt {retries_attempted+1}/{MAX_RETRIES+1}): {e}. Retry in {retry_delay:.2f}s...")
            if retries_attempted == MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Max retries ({MAX_RETRIES+1}) reached for {channel_url}")
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1

    return [], "critical"

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters proxy configurations, logging filter counts."""
    parsed_configs: List[ProxyParsedConfig] = []
    processed_configs: Set[str] = set()
    invalid_url_count = 0
    dns_resolution_failed_count = 0
    duplicate_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        try:
            parsed_config = ProxyParsedConfig.from_url(line)
            if parsed_config is None:
                logger.debug(f"Skipping invalid proxy URL: {line}")
                invalid_url_count += 1
                continue

            resolved_ip = await resolve_address(parsed_config.address, resolver)

            if parsed_config.config_string in processed_configs:
                logger.debug(f"Skipping duplicate proxy: {parsed_config.config_string}")
                duplicate_count += 1
                continue
            processed_configs.add(parsed_config.config_string)

            if resolved_ip:
                quality_score = assess_proxy_quality(parsed_config)
                parsed_config_with_score = dataclasses.replace(parsed_config, quality_score=quality_score)
                parsed_configs.append(parsed_config_with_score)
            else:
                dns_resolution_failed_count += 1
                logger.debug(f"DNS resolution failed for proxy address: {parsed_config.address} from URL: {line}")

        except Exception as e:
            logger.error(f"Unexpected error parsing proxy URL '{line}': {e}", exc_info=True)
            continue

    logger.info(f"Parsed {len(parsed_configs)} proxies, skipped {invalid_url_count} invalid URLs, "
                f"{duplicate_count} duplicates, {dns_resolution_failed_count} DNS resolution failures.")
    return parsed_configs

def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves proxies to a file, handling file system errors and buffering writes."""
    total_proxies_count = 0
    unique_proxies: List[ProxyParsedConfig] = []
    seen_config_strings: Set[str] = set()

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        for proxy_conf in all_proxies:
            if proxy_conf.config_string not in seen_config_strings:
                unique_proxies.append(proxy_conf)
                seen_config_strings.add(proxy_conf.config_string)

        with open(output_file, 'w', encoding='utf-8') as f:
            lines_to_write = []
            for proxy_conf in unique_proxies:
                profile_name = generate_proxy_profile_name(proxy_conf)
                quality_category = get_quality_category(proxy_conf.quality_score)
                config_line = (f"{proxy_conf.config_string}#PROFILE={profile_name};"
                               f"QUALITY_SCORE={proxy_conf.quality_score};QUALITY_CATEGORY={quality_category}\n")
                lines_to_write.append(config_line)
                total_proxies_count += 1
            f.writelines(lines_to_write)

    except IOError as e:
        logger.error(f"IOError saving proxies to file '{output_file}': {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error saving proxies to file '{output_file}': {e}", exc_info=True)
    return total_proxies_count

async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from a file, handling BOM, encoding, and comments."""
    channel_urls: List[str] = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ File {all_urls_file} not found. Creating an empty file.")
        try:
            open(all_urls_file, 'w').close()
        except Exception as e:
            logger.error(f"Error creating file {all_urls_file}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls

async def process_channel_task(channel_url: str, session: aiohttp.ClientSession,
                              resolver: aiodns.DNSResolver, protocol_counts: defaultdict[str, int]
                              ) -> Tuple[int, str, List[ProxyParsedConfig]]:
    """Processes a single channel URL."""
    colored_log(logging.INFO, f"🚀 Processing channel: {channel_url}")
    lines, status = await download_proxies_from_channel(channel_url, session)
    if status == "success":
        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
        channel_proxies_count = len(parsed_proxies)
        for proxy in parsed_proxies:
            protocol_counts[proxy.protocol] += 1
        colored_log(logging.INFO, f"✅ Channel {channel_url} processed. Found {channel_proxies_count} proxies.")
        return channel_proxies_count, status, parsed_proxies
    else:
        colored_log(logging.WARNING, f"⚠️ Channel {channel_url} processed with status: {status}.")
        return 0, status, []

async def load_and_process_channels(channel_urls: List[str], session: aiohttp.ClientSession,
                                     resolver: aiodns.DNSResolver
                                     ) -> Tuple[int, int, defaultdict[str, int], List[ProxyParsedConfig], defaultdict[str, int]]:
    """Loads and processes all channel URLs concurrently."""
    channels_processed_successfully = 0
    total_proxies_downloaded = 0
    protocol_counts: defaultdict[str, int] = defaultdict(int)
    channel_status_counts: defaultdict[str, int] = defaultdict(int)
    all_proxies: List[ProxyParsedConfig] = []

    channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)
    channel_tasks = []

    for channel_url in channel_urls:
        async def task_wrapper(url):
            async with channel_semaphore:
                return await process_channel_task(url, session, resolver, protocol_counts)

        task = asyncio.create_task(task_wrapper(channel_url))
        channel_tasks.append(task)

    channel_results = await asyncio.gather(*channel_tasks, return_exceptions=True)

    for result in channel_results:
        if isinstance(result, Exception):
            logger.error(f"Task raised an exception: {result}", exc_info=result)
            channel_status_counts["error"] += 1
        else:
            proxies_count, status, proxies_list = result
            total_proxies_downloaded += proxies_count
            if status == "success":
                channels_processed_successfully += 1
            channel_status_counts[status] += 1
            all_proxies.extend(proxies_list)

    return total_proxies_downloaded, channels_processed_successfully, protocol_counts, all_proxies, channel_status_counts

def output_statistics(start_time: float, total_channels: int, channels_processed_successfully: int,
                      channel_status_counts: defaultdict[str, int], total_proxies_downloaded: int,
                      all_proxies_saved_count: int, protocol_counts: defaultdict[str, int],
                      output_file: str, all_proxies: List[ProxyParsedConfig]):
    """Outputs download and processing statistics."""
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    colored_log(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    colored_log(logging.INFO, f"🔗 Total channel URLs: {total_channels}")
    colored_log(logging.INFO, f"✅ Successfully processed channels: {channels_processed_successfully}/{total_channels}")

    colored_log(logging.INFO, "\n📊 Channel Processing Status:")
    for status_key in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            status_text, color_start = "", ""
            if status_key == "success":
                status_text, color_start = "SUCCESS", '\033[92m'
            elif status_key == "warning":
                status_text, color_start = "WARNING", '\033[93m'
            elif status_key in ["error", "critical"]:
                status_text, color_start = "ERROR", '\033[91m'
            else:
                status_text, color_start = status_key.upper(), '\033[0m'

            colored_log(logging.INFO, f"  - {status_text}: {count} channels")

    colored_log(logging.INFO, f"\n✨ Total configurations found: {total_proxies_downloaded}")
    colored_log(logging.INFO, f"📝 Total unique proxies saved: {all_proxies_saved_count} (to {output_file})")

    colored_log(logging.INFO, "\n🔬 Protocol Breakdown (found):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   No protocol statistics available.")

    quality_category_counts = defaultdict(int)
    for proxy in all_proxies:
        quality_category = get_quality_category(proxy.quality_score)
        quality_category_counts[quality_category] += 1

    colored_log(logging.INFO, "\n⭐️ Proxy Quality Category Distribution:")
    if quality_category_counts:
        for category, count in quality_category_counts.items():
            colored_log(logging.INFO, f"   - {category}: {count} proxies")
    else:
        colored_log(logging.INFO, "   No quality category statistics available.")

    colored_log(logging.INFO, "======================== 🏁 STATISTICS END =========================")


async def main() -> None:
    """Main function to run the proxy downloader script."""
    parser = argparse.ArgumentParser(description="Proxy Downloader Script")
    parser.add_argument('--nocolorlogs', action='store_true', help='Disable colored console logs')
    args = parser.parse_args()

    console_formatter.use_colors = not args.nocolorlogs

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        if not channel_urls:
            colored_log(logging.WARNING, "No channel URLs to process.")
            return

        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        async with aiohttp.ClientSession() as session:
            total_proxies_downloaded, channels_processed_successfully, protocol_counts, \
            all_proxies, channel_status_counts = await load_and_process_channels(
                channel_urls, session, resolver)

        all_proxies_saved_count = save_all_proxies_to_file(all_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        output_statistics(start_time, len(channel_urls), channels_processed_successfully,
                          channel_status_counts, total_proxies_downloaded, all_proxies_saved_count,
                          protocol_counts, CONFIG_FILES.OUTPUT_ALL_CONFIG, all_proxies)

    except Exception as e:
        logger.critical(f"Unexpected error in main(): {e}", exc_info=True)
        sys.exit(1)
    finally:
        colored_log(logging.INFO, "✅ Proxy download and processing completed.")


if __name__ == "__main__":
    asyncio.run(main())
