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


# --- Enhanced Logging Setup ---
LOG_FORMAT = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "module": "%(module)s",  # Added module name
    "funcName": "%(funcName)s",  # Added function name
    "lineno": "%(lineno)d",  # Added line number
}
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_downloader.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# File Handler (WARNING level and above, JSON format)
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
        # Handle exceptions, if present
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Console Handler (INFO level and above, colored output)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


def colored_log(level, message: str, *args, **kwargs):
    """Logs a message with color based on the logging level."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD_RED = '\033[1m\033[91m'

    color = RESET
    if level == logging.INFO:
        color = GREEN
    elif level == logging.WARNING:
        color = YELLOW
    elif level == logging.ERROR:
        color = RED
    elif level == logging.CRITICAL:
        color = BOLD_RED

    # Get caller information.  Stack frame 1 is the caller of colored_log.
    frame = inspect.currentframe().f_back  # Use f_back to get the caller frame
    pathname = frame.f_code.co_filename
    lineno = frame.f_lineno
    func = frame.f_code.co_name

    record = logging.LogRecord(
        name=logger.name,
        level=level,
        pathname=pathname,  # Full path
        lineno=lineno,  # Correct line number
        msg=f"{color}{message}{RESET}",
        args=args,
        exc_info=kwargs.get('exc_info'),
        func=func,  # Correct function name
        sinfo=None
    )
    logger.handle(record)




# --- Constants and Enums ---
class Protocols(Enum):
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"

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
    MAX_PROXIES_GLOBAL: int = 50  # Global limit on concurrent proxy checks

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]
CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()

# --- Utility Functions ---

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """Checks if a given string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Resolves a hostname to an IPv4 address.  Returns None on failure."""
    if is_valid_ipv4(hostname):
        return hostname  # Already an IP

    try:
        async with asyncio.timeout(10):  # Timeout DNS resolution
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            if is_valid_ipv4(resolved_ip): # Validate the resolved IP
               return resolved_ip
            else:
                colored_log(logging.WARNING, f"⚠️ DNS resolved {hostname} to non-IPv4: {resolved_ip}")
                return None
    except asyncio.TimeoutError:
        colored_log(logging.WARNING, f"⚠️ DNS resolution timed out for {hostname}")
        return None
    except aiodns.error.DNSError as e:
        colored_log(logging.WARNING, f"⚠️ DNS resolution failed for {hostname}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True)  # Log unexpected errors
        return None
# --- Data Structures ---

class ProfileName(Enum): # Kept for potential future use in differentiating output formats.
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    UNKNOWN = "Unknown Protocol"  # Added for handling unknown protocols

class InvalidURLError(ValueError):
    """Custom exception for invalid URLs."""
    pass

class UnsupportedProtocolError(ValueError):
    """Custom exception for unsupported protocols."""
    pass

@dataclass(frozen=True)
class ProxyParsedConfig:
    """Represents a parsed proxy configuration."""
    config_string: str  # Original config string (without remark, if present)
    protocol: str       # Protocol (e.g., "vless", "tuic")
    address: str        # IP address or hostname
    port: int           # Port number
    remark: str = ""    # Remark field

    def __hash__(self):
        """Hashes the configuration for efficient set operations (deduplication)."""
        return hash((self.protocol, self.address, self.port))

    def __str__(self):
        """Provides a user-friendly string representation."""
        return (f"ProxyConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')") # Show part of the config


    @classmethod
    def from_url(cls, config_string: str) -> "ProxyParsedConfig":
        """Parses a proxy configuration string (URL) into a ProxyParsedConfig object."""
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p + "://")), None)
        if not protocol:
            raise UnsupportedProtocolError(f"Unsupported protocol in URL: {config_string}")

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                raise InvalidURLError(f"Could not extract address or port from URL: {config_string}")

             # Extract remark, if present
            remark = ""
            if parsed_url.fragment:
                remark = parsed_url.fragment

            return cls(
                config_string=config_string.split("#")[0], # Remove the original remark
                protocol=protocol,
                address=address,
                port=port,
                remark=remark, # Store the original remark
            )


        except ValueError as e:
            raise InvalidURLError(f"Error parsing URL: {config_string}. Error: {e}") from e


# --- Core Logic ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a single channel URL.
       Returns a tuple: (list of proxy config strings, status string).
       Status can be: "success", "warning", "error", "critical".
    """
    headers = {'User-Agent': 'ProxyDownloader/1.0'}  # Set a user agent
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=15) # Set a timeout

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout, headers=headers) as response:
                response.raise_for_status()  # Raise an exception for bad status codes
                text = await response.text(encoding='utf-8', errors='ignore')  # Handle potential encoding issues
                return text.splitlines(), "success"

        except aiohttp.ClientResponseError as e:
            colored_log(logging.WARNING, f"⚠️ Channel {channel_url} returned HTTP error {e.status}: {e.message}")
            return [], "warning"  # Treat non-200 responses as warnings
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Error fetching {channel_url} (attempt {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {e}. Retrying in {retry_delay} seconds...")
            if retries_attempted == RETRY.MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Max retries ({RETRY.MAX_RETRIES+1}) reached for {channel_url}")
                return [], "error"  # Mark as error after max retries
            await asyncio.sleep(retry_delay)
        retries_attempted += 1

    return [], "critical"  # Should not reach here, but added for completeness



async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters proxy configurations, resolving hostnames to IP addresses."""
    parsed_configs = []

    for line in lines:
        line = line.strip()
        if not line or not any(line.startswith(proto + "://") for proto in ALLOWED_PROTOCOLS):
            continue

        try:
            parsed_config = ProxyParsedConfig.from_url(line)
            # Resolve the hostname to an IP address
            resolved_ip = await resolve_address(parsed_config.address, resolver)
            if resolved_ip:
                parsed_configs.append(parsed_config) # Only add if resolution successful

        except (InvalidURLError, UnsupportedProtocolError) as e:
            colored_log(logging.WARNING, f"⚠️ Skipping invalid or unsupported proxy URL '{line}': {e}")
            continue


    return parsed_configs


def generate_v2rayng_config_name(proxy_config: ProxyParsedConfig) -> str:
    """Generates a name for the proxy configuration, suitable for v2rayNG."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    # Construct the config name.
    return f"{proxy_config.protocol}-{proxy_config.address}-{timestamp}"


def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves all parsed proxy configurations to a file, one per line."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Ensure directory exists
        with open(output_file, 'w', encoding='utf-8') as f:
            for proxy_conf in all_proxies:
                config_name = generate_v2rayng_config_name(proxy_conf)
                # Combine config string and name
                config_line = f"{proxy_conf.config_string}#{config_name}"
                f.write(config_line + "\n")
                colored_log(logging.INFO, f"   ➕ Added proxy (all): {config_line}")
                total_proxies_count += 1
        colored_log(logging.INFO, f"\n✅ Saved {total_proxies_count} proxies (all) to {output_file}")

    except Exception as e:
        logger.error(f"Error saving all proxies to file: {e}", exc_info=True)
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from a file, handling file not found and other errors."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:  # Ignore blank lines
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ File {all_urls_file} not found.  Creating an empty file.")
        open(all_urls_file, 'w').close() # Create the file if it doesn't exist.
    except Exception as e:
        logger.error(f"Error opening/reading file {all_urls_file}: {e}", exc_info=True)
    return channel_urls


async def main():
    """Main function to orchestrate the proxy download and processing."""

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        if not channel_urls:
            colored_log(logging.WARNING, "No channel URLs to process.")
            return  # Exit if no URLs

        total_channels = len(channel_urls)
        channels_processed_successfully = 0
        total_proxies_downloaded = 0
        protocol_counts = defaultdict(int)  # Track counts of each protocol
        channel_status_counts = defaultdict(int) # Track channel success/failure

        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        global_proxy_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_PROXIES_GLOBAL)  # Global limit
        channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)

        async with aiohttp.ClientSession() as session:
            channel_tasks = []

            for channel_url in channel_urls:
                async def process_channel_task(url):
                    nonlocal channels_processed_successfully, total_proxies_downloaded  # Access outer scope variables
                    channel_proxies_count_channel = 0
                    channel_success = 0
                    async with channel_semaphore: # Limit concurrent channel processing
                        colored_log(logging.INFO, f"🚀 Processing channel: {url}")
                        lines, status = await download_proxies_from_channel(url, session)
                        channel_status_counts[status] += 1
                        if status == "success":
                            parsed_proxies = await parse_and_filter_proxies(lines, resolver)
                            channel_proxies_count_channel = len(parsed_proxies)
                            channel_success = 1 # Increment on successful channel processing
                            for proxy in parsed_proxies:
                                protocol_counts[proxy.protocol] += 1 # Count by protocol
                            colored_log(logging.INFO, f"✅ Channel {url} processed. Found {channel_proxies_count_channel} proxies.")
                            return channel_proxies_count_channel, channel_success, parsed_proxies # Return parsed proxies
                        else:
                             colored_log(logging.WARNING, f"⚠️ Channel {url} processed with status: {status}.")
                             return 0, 0, []


                task = asyncio.create_task(process_channel_task(channel_url))
                channel_tasks.append(task)

            channel_results = await asyncio.gather(*channel_tasks)
            all_proxies: List[ProxyParsedConfig] = []
            for proxies_count, success_flag, proxies_list in channel_results:
                total_proxies_downloaded += proxies_count
                channels_processed_successfully += success_flag
                all_proxies.extend(proxies_list)


        all_proxies_saved_count = save_all_proxies_to_file(all_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        end_time = time.time()
        elapsed_time = end_time - start_time

        # --- Statistics and Reporting ---
        colored_log(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
        colored_log(logging.INFO, f"⏱️  Script execution time: {elapsed_time:.2f} seconds")
        colored_log(logging.INFO, f"🔗 Total channel URLs: {total_channels}")
        colored_log(logging.INFO, f"✅ Successfully processed channels: {channels_processed_successfully}/{total_channels}")

        colored_log(logging.INFO, "\n📊 Channel Processing Status:")
        for status in ["success", "warning", "error", "critical"]:
            count = channel_status_counts.get(status, 0)
            if count > 0:
                status_text = status.upper()
                color = '\033[92m' if status == "success" else ('\033[93m' if status == "warning" else ('\033[91m' if status in ["error", "critical"] else '\033[0m'))
                colored_log(logging.INFO, f"  - {color}{status_text}\033[0m: {count} channels")

        colored_log(logging.INFO, f"\n✨ Total proxy configurations found: {total_proxies_downloaded}")
        colored_log(logging.INFO, f"📝 Total proxies (all) saved: {all_proxies_saved_count} (in {CONFIG_FILES.OUTPUT_ALL_CONFIG})")

        colored_log(logging.INFO, "\n🔬 Protocol Breakdown (found):")
        if protocol_counts:
            for protocol, count in protocol_counts.items():
                colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
        else:
            colored_log(logging.INFO, "   No protocol statistics available.")


        colored_log(logging.INFO, "======================== 🏁 END OF STATISTICS =========================")

    except Exception as e:
        logger.critical(f"Unexpected error in main(): {e}", exc_info=True)  # Log critical errors
    finally:
        colored_log(logging.INFO, "✅ Proxy download and processing complete.")


import inspect  # Import the inspect module

if __name__ == "__main__":
    asyncio.run(main())
