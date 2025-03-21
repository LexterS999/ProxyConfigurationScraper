import asyncio
import aiodns
import os
import logging
import ipaddress
import aiohttp
import time
import structlog

from enum import Enum
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Literal, Final
from dataclasses import dataclass
from collections import defaultdict
from async_lru import alru_cache

# --- Настройка структурированного логирования ---
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

formatter = structlog.stdlib.ProcessorFormatter(
    processor=structlog.dev.ConsoleRenderer(colors=True),
)

LOG_FILE: Final[str] = 'proxy_downloader.log'
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

logger = structlog.get_logger(__name__)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)


# --- Константы ---
ALLOWED_PROTOCOLS: Final[List[Literal["vless://", "tuic://", "hy2://", "ss://"]]] = ["vless://", "tuic://", "hy2://", "ss://"]
ALL_URLS_FILE: Final[str] = "channel_urls.txt"
OUTPUT_ALL_CONFIG_FILE: Final[str] = "configs/proxy_configs_all.txt"
MAX_RETRIES: Final[int] = 4
RETRY_DELAY_BASE: Final[int] = 2
MAX_CONCURRENT_CHANNELS: Final[int] = 60
MAX_CONCURRENT_PROXIES_PER_CHANNEL: Final[int] = 50  # Не используется, но оставлено для информации
MAX_CONCURRENT_PROXIES_GLOBAL: Final[int] = 50
RESOLVER_TIMEOUT: Final[float] = 5.0  # Таймаут для DNS резолвера


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
class ProxyParsedConfig:
    config_string: str
    protocol: str
    address: str
    port: int

    def __hash__(self):
        return hash((self.protocol, self.address, self.port))

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        parsed_url = urlparse(config_string)
        protocol = parsed_url.scheme
        if protocol not in ALLOWED_PROTOCOLS:
            return None

        address = parsed_url.hostname
        port = parsed_url.port
        if not address or not port or not (0 < port <= 65535):
            return None

        return cls(
            config_string=config_string,
            protocol=protocol.replace("://", ""),
            address=address,
            port=port,
        )

@alru_cache(maxsize=1024)
async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    if is_ipv4(hostname):
        return hostname
    try:
        result = await asyncio.wait_for(resolver.query(hostname, 'A'), timeout=RESOLVER_TIMEOUT)
        resolved_address = result[0].host
        if is_ipv4(resolved_address):
            return resolved_address
        else:
            return None
    except aiodns.error.DNSError as e:
        return None
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        logger.warning("Timeout resolving DNS", hostname=hostname)
        return None
    except Exception:
        return None

def is_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    retries_attempted = 0
    while retries_attempted <= MAX_RETRIES:
        try:
            async with session.get(channel_url) as response:
                if response.status == 200:
                    text = await response.text(encoding='utf-8', errors='ignore')
                    return text.splitlines(), "success"
                else:
                    logger.warning("Channel returned status", channel=channel_url, status=response.status)
                    return [], "warning"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted)
            logger.warning("Error getting channel", channel=channel_url, attempt=retries_attempted + 1, max_attempts=MAX_RETRIES + 1, error=e, delay=retry_delay)
            if retries_attempted == MAX_RETRIES:
                logger.error("Max attempts reached", channel=channel_url)
                raise
            await asyncio.sleep(retry_delay)
        retries_attempted += 1
    return [], "critical"

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    parsed_configs = []
    tasks = []
    for line in lines:
        line = line.strip()
        if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
            continue
        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config:
            tasks.append(resolve_address(parsed_config.address, resolver))
            parsed_configs.append(parsed_config)
    resolved_ips = await asyncio.gather(*tasks, return_exceptions=True)

    filtered_configs = []
    for parsed_config, resolved_ip in zip(parsed_configs, resolved_ips):
        if isinstance(resolved_ip, str):
            filtered_configs.append(parsed_config)

    return filtered_configs

async def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    import aiofiles

    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        async with aiofiles.open(output_file, 'w', encoding='utf-8') as f:
            protocol_grouped_proxies = defaultdict(list)
            for proxy_conf in all_proxies:
                protocol_grouped_proxies[proxy_conf.protocol].append(proxy_conf)

            for protocol in ["vless", "tuic", "hy2", "ss"]:
                if protocol in protocol_grouped_proxies:
                    await f.write(f"\n📝 Протокол (все): {ProfileName[protocol.upper()].value}\n")
                    logger.info("Writing protocol to file", protocol=ProfileName[protocol.upper()].value)
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        config_line = proxy_conf.config_string + f"#{ProfileName[protocol.upper()].value}"
                        await f.write(config_line + "\n")
                        logger.info("Added proxy to file", proxy=config_line)
                        total_proxies_count += 1
        logger.info("Saved proxies to file", count=total_proxies_count, file=output_file)
    except Exception as e:
        logger.error("Error saving proxies to file", error=e)
    return total_proxies_count

async def load_channel_urls(all_urls_file: str) -> List[str]:
    import aiofiles

    channel_urls = []
    try:
        async with aiofiles.open(all_urls_file, 'r', encoding='utf-8') as f:
            async for line in f:
                url = line.strip()
                if url:
                    channel_urls.append(url)
    except FileNotFoundError:
        logger.warning("File not found", file=all_urls_file)
        open(all_urls_file, 'w').close()
    return channel_urls

async def download_and_parse(url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, channel_semaphore: asyncio.Semaphore, protocol_counts: Dict[str, int], channel_status_counts: Dict[str, int]) -> List[ProxyParsedConfig]:
    async with channel_semaphore:
        logger.info("Starting channel processing", channel=url)
        try:
            lines, status = await download_proxies_from_channel(url, session)
            channel_status_counts[status] += 1
            if status == "success":
                parsed_proxies = await parse_and_filter_proxies(lines, resolver)
                channel_proxies_count_channel = len(parsed_proxies)

                for proxy in parsed_proxies:
                    protocol_counts[proxy.protocol] += 1
                logger.info("Channel processed successfully", channel=url, count=channel_proxies_count_channel)
                return parsed_proxies
            else:
                logger.warning("Channel processed with status", channel=url, status=status)
                return []
        except Exception as e:
            logger.error("Error processing channel", channel=url, error=e)
            channel_status_counts["error"] += 1
            return []

def print_statistics(elapsed_time: float, total_channels: int, channel_status_counts: Dict[str, int], total_proxies_downloaded: int, all_proxies_saved_count: int, protocol_counts: Dict[str, int]):
    logger.info("==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    logger.info("⏱️  Script execution time", time=f"{elapsed_time:.2f}s")
    logger.info("🔗 Total URL sources", count=total_channels)

    logger.info("\n📊 URL source processing status:")
    for status in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status, 0)
        if count > 0:
            status_text = status.upper()
            logger.info(f"  - {status_text}: {count} channels")

    logger.info("\n✨ Total configurations found", count=total_proxies_downloaded)
    logger.info("📝 Total proxies (all) saved", count=all_proxies_saved_count, file=OUTPUT_ALL_CONFIG_FILE)

    logger.info("\n🔬 Protocol breakdown (found):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            logger.info("   - %s: %s", protocol.upper(), count)
    else:
        logger.info("   No protocol statistics.")

    logger.info("======================== 🏁 END OF STATISTICS =========================")
    logger.info("✅ Proxy download and processing completed.")

async def main():
    start_time = time.monotonic()
    channel_urls = await load_channel_urls(ALL_URLS_FILE)
    if not channel_urls:
        logger.warning("No channel URLs to process.")
        return

    total_channels = len(channel_urls)
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)

    resolver = aiodns.DNSResolver()
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)

    all_proxies = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        async with asyncio.TaskGroup() as tg:
            for channel_url in channel_urls:
                tg.create_task(download_and_parse(channel_url, session, resolver, channel_semaphore, protocol_counts, channel_status_counts))

        for task in tg:
            if task.exception() is not None:
                logger.error("Task exception", exception=task.exception())  # Log exception
            else:
                result = task.result()
                if result: # Check for empty lists.
                    all_proxies.extend(result)

    all_proxies_saved_count = await save_all_proxies_to_file(all_proxies, OUTPUT_ALL_CONFIG_FILE)
    end_time = time.monotonic()
    elapsed_time = end_time - start_time
    print_statistics(elapsed_time, total_channels, channel_status_counts, len(all_proxies), all_proxies_saved_count, protocol_counts)

if __name__ == "__main__":
    asyncio.run(main(), debug=True)
