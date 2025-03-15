import asyncio
import aiodns
import re
import os
import json
import logging
import ipaddress
import io
import uuid
import string
import socket
import base64

from enum import Enum
from urllib.parse import urlparse, parse_qs, quote_plus, urlsplit
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, astuple, replace
from collections import defaultdict

import aiohttp

# --- Настройка логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_checker.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


# --- Константы ---
DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"
ALLOWED_PROTOCOLS = ["vless://", "ss://", "trojan://", "tuic://", "hy2://", "ssconf://"]
MAX_CONCURRENT_CHANNELS = 90
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 120
MAX_CONCURRENT_PROXIES_GLOBAL = 120
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
PROTOCOL_TIMEOUT = 4.0
SOURCE_URL_TIMEOUT = 10.0


# --- Исключения ---
class InvalidURLError(ValueError):
    pass

class UnsupportedProtocolError(ValueError):
    pass

class ConfigParseError(ValueError):
    pass


# --- Data classes для конфигураций (минимум для примера) ---
@dataclass(frozen=True)
class VlessConfig:
    uuid: str
    address: str
    port: int

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "VlessConfig":
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
        )

@dataclass(frozen=True)
class SSConfig:
    method: str
    password: str
    address: str
    port: int

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "SSConfig":
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            method=parsed_url.username.lower() if parsed_url.username else 'none',
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
        )

@dataclass(frozen=True)
class TrojanConfig:
    password: str
    address: str
    port: int

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "TrojanConfig":
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
        )

@dataclass(frozen=True)
class TuicConfig:
    uuid: str
    address: str
    port: int

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "TuicConfig":
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            uuid=parsed_url.username,
            address=address,
            port=parsed_url.port,
        )

@dataclass(frozen=True)
class Hy2Config:
    password: str
    address: str
    port: int

    @classmethod
    async def from_url(cls, parsed_url: urlparse, query: Dict, resolver: aiodns.DNSResolver) -> "Hy2Config":
        address = await resolve_address(parsed_url.hostname, resolver)
        return cls(
            password=parsed_url.password,
            address=address,
            port=parsed_url.port,
        )

@dataclass(frozen=True)
class SSConfConfig:
    server: str
    server_port: int
    password: str
    method: str

    @classmethod
    async def from_url(cls, config_string: str, resolver: aiodns.DNSResolver) -> "SSConfConfig":
        try:
            config_b64 = config_string.split("ssconf://")[1]
            config_json_str = base64.urlsafe_b64decode(config_b64 + '=' * (4 - len(config_b64) % 4)).decode('utf-8')
            config_json = json.loads(config_json_str)
            return cls(
                server=config_json.get('server'),
                server_port=int(config_json.get('server_port')),
                password=config_json.get('password'),
                method=config_json.get('method')
            )
        except json.JSONDecodeError as e:
            raise ConfigParseError(f"JSON decode error: {e}")
        except KeyError as e:
            raise ConfigParseError(f"Missing key in config: {e}")


# --- Data classes для метрик и каналов ---
@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

class ChannelConfig:
    VALID_PROTOCOLS_SOURCE = ["https://", "http://"]
    VALID_PROTOCOLS_PROXY = ALLOWED_PROTOCOLS

    def __init__(self, url: str):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()

    def _validate_url(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in [p.replace('://', '') for p in self.VALID_PROTOCOLS_SOURCE]:
            expected_protocols = ', '.join(self.VALID_PROTOCOLS_SOURCE)
            received_protocol_prefix = parsed.scheme or url[:10]
            raise UnsupportedProtocolError(
                f"Неверный протокол URL источника. Ожидается: {expected_protocols}, получено: {received_protocol_prefix}..."
            )
        return url



class ProxyConfig:
    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)
        self.resolver = None
        self.SOURCE_URLS = self._load_source_urls()
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE
        self.ALL_URLS_FILE = ALL_URLS_FILE

    def _load_source_urls(self) -> List[ChannelConfig]:
        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except (InvalidURLError, UnsupportedProtocolError) as e:
                            logger.warning(f"Неверный URL в {ALL_URLS_FILE}: {url} - {e}. Ожидается URL источника (http/https).")
        except FileNotFoundError:
            logger.warning(f"Файл URL не найден: {ALL_URLS_FILE}. Создается пустой файл.")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")
        return initial_urls

    def get_enabled_channels(self) -> List[ChannelConfig]:
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        try:
            with open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {e}")
            return False

    def set_event_loop(self, loop):
        self.resolver = aiodns.DNSResolver(loop=loop)


# --- Вспомогательные функции ---
async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> str:
    if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
        return hostname
    try:
        result = await resolver.query(hostname, 'A')
        return result[0].host
    except aiodns.error.DNSError as e:
        logger.warning(f"Не удалось разрешить hostname: {hostname} - {e}")
        return hostname
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при резолвинге {hostname}: {e}")
        return hostname

def is_valid_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv6(hostname: str) -> bool:
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_proxy_url(url: str) -> bool:
    if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.port:
            return False
        return True
    except ValueError:
        return False


async def parse_config(config_string: str, resolver: aiodns.DNSResolver) -> Optional[object]:
    protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
    if not protocol:
        return None

    try:
        parsed = urlparse(config_string)
        query = parse_qs(parsed.query)
        scheme = parsed.scheme

        config_parsers = {
            "vless": VlessConfig.from_url,
            "ss": SSConfig.from_url,
            "trojan": TrojanConfig.from_url,
            "tuic": TuicConfig.from_url,
            "hy2": Hy2Config.from_url,
            "ssconf": SSConfConfig.from_url, # ssconf does not use urlparse directly for parsing
        }
        if scheme in config_parsers:
            if scheme == "ssconf":
                return await config_parsers[scheme](config_string, resolver) # Pass full string for ssconf
            else:
                return await config_parsers[scheme](parsed, query, resolver)
        return None

    except (InvalidURLError, UnsupportedProtocolError, ConfigParseError) as e:
        logger.error(f"Ошибка парсинга конфигурации: {config_string} - {e}")
        return None
    except Exception as e:
        logger.exception(f"Непредвиденная ошибка при парсинге конфигурации {config_string}: {e}")
        return None


# --- Функции для протокол-специфичных проверок ---
async def test_connection(host: str, port: int, timeout: float, protocol_name: str) -> bool:
    try:
        await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
        logger.debug(f"✅ {protocol_name} проверка: TCP соединение с {host}:{port} установлено за {timeout:.2f} секунд.")
        return True
    except asyncio.TimeoutError:
        logger.debug(f"❌ {protocol_name} проверка: TCP таймаут ({timeout:.2f} сек) при подключении к {host}:{port}.")
        return False
    except (ConnectionRefusedError, OSError, socket.gaierror) as e:
        logger.debug(f"❌ {protocol_name} проверка: Ошибка TCP соединения с {host}:{port}: {e}.")
        return False


async def process_single_proxy(line: str, channel: ChannelConfig,
                              proxy_config: ProxyConfig,
                              proxy_semaphore: asyncio.Semaphore,
                              global_proxy_semaphore: asyncio.Semaphore) -> Optional[Dict]:
    async with proxy_semaphore, global_proxy_semaphore:
        config_obj = await parse_config(line, proxy_config.resolver)
        if config_obj is None:
            return None

        protocol_type = config_obj.__class__.__name__.replace("Config", "").lower()
        is_reachable = False

        if protocol_type in ["vless", "trojan", "ss", "tuic", "hy2"]:
            is_reachable = await test_connection(config_obj.address, config_obj.port, PROTOCOL_TIMEOUT, protocol_type.upper())
        elif protocol_type == "ssconf":
            is_reachable = await test_connection(config_obj.server, config_obj.server_port, PROTOCOL_TIMEOUT, protocol_type.upper())
        else:
            logger.warning(f"Неизвестный тип протокола для проверки: {protocol_type}")
            return None

        if not is_reachable:
            return None

        result = {
            "config": line,
            "protocol": protocol_type,
            "config_obj": config_obj
        }
        channel.metrics.protocol_counts[protocol_type] += 1
        return result


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    proxies_all: List[Dict] = []

    async with aiohttp.ClientSession() as session:
        session_timeout = aiohttp.ClientTimeout(total=SOURCE_URL_TIMEOUT)
        for channel in channels:
            lines = []
            try:
                async with session.get(channel.url, timeout=session_timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        lines = text.splitlines()
                    else:
                        logger.error(f"Не удалось получить данные из {channel.url}, статус: {response.status}")
                        continue
            except aiohttp.ClientError as e:
                logger.error(f"Ошибка при получении данных из {channel.url}: {e}")
                continue
            except asyncio.TimeoutError:
                logger.error(f"Таймаут при получении данных из {channel.url}")
                continue

            proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_PER_CHANNEL)
            proxy_tasks = []

            for line in lines:
                line = line.strip()
                if not line or not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS) or not is_valid_proxy_url(line):
                    continue
                task = asyncio.create_task(process_single_proxy(line, channel, proxy_config,
                                                            proxy_semaphore, global_proxy_semaphore))
                proxy_tasks.append(task)
            results = await asyncio.gather(*proxy_tasks)
            for result in results:
                if result:
                    proxies_all.append(result)
            channel.metrics.valid_configs += len(proxies_all)

    return proxies_all


def save_final_configs(proxies: List[Dict], output_file: str):
    unique_proxies = set()
    unique_proxy_count = 0
    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            for proxy in proxies:
                config = proxy['config'].strip()
                parsed = urlparse(config)
                ip_address = parsed.hostname
                port = parsed.port
                protocol = proxy['protocol']
                ip_port_tuple = (ip_address, port, protocol)

                if ip_port_tuple not in unique_proxies:
                    unique_proxies.add(ip_port_tuple)
                    unique_proxy_count += 1
                    f.write(f"{config}\n")
        logger.info(f"Финальные конфигурации сохранены в {output_file}. Уникальных прокси: {unique_proxy_count}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {e}")


def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_enabled_channels()

    if not channels:
        logger.error("Нет URL источников для проверки. Пожалуйста, добавьте URL в all_urls.txt")
        proxy_config.save_empty_config_file()
        return

    async def runner():
        loop = asyncio.get_running_loop()
        proxy_config.set_event_loop(loop)

        logger.info("🚀 Начало загрузки и проверки прокси...")
        proxies = await process_all_channels(channels, proxy_config)

        if not proxies:
            logger.warning("Не найдено валидных прокси конфигураций.")
            proxy_config.save_empty_config_file()
        else:
            save_final_configs(proxies, proxy_config.OUTPUT_FILE)

        total_channels = len(channels)
        enabled_channels = total_channels
        disabled_channels = 0 # No disable logic in this version
        total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)

        protocol_stats = defaultdict(int)
        for channel in channels:
            for protocol, count in channel.metrics.protocol_counts.items():
                protocol_stats[protocol] += count

        logger.info("==================== 📊 СТАТИСТИКА ПРОВЕРКИ ПРОКСИ ====================")
        logger.info(f"🔄 Всего файлов-каналов обработано: {total_channels}")
        logger.info(f"✅ Включено файлов-каналов: {enabled_channels}")
        logger.info(f"❌ Отключено файлов-каналов: {disabled_channels}")
        logger.info(f"✨ Всего найдено валидных конфигураций: {total_valid_configs}")

        logger.info("\n breakdown by protocol:")
        if protocol_stats:
            for protocol, count in protocol_stats.items():
                logger.info(f"   - {protocol}: {count} configs")
        else:
            logger.info("   No protocol statistics available.")

        logger.info("======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
        logger.info("✅ Проверка прокси завершена.")


    asyncio.run(runner())


if __name__ == "__main__":
    main()
