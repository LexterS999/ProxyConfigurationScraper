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

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
import functools

# --- Настройка улучшенного логирования ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s (Process: %(process)s)"
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FILE = 'proxy_downloader.log'
LOG_LEVEL_FILE = "WARNING"  # Уровень логирования для файла
LOG_LEVEL_CONSOLE = "INFO" # Уровень логирования для консоли

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(getattr(logging, LOG_LEVEL_FILE.upper(), logging.WARNING)) # Уровень логирования из константы
formatter_file = logging.Formatter(LOG_FORMAT)
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(getattr(logging, LOG_LEVEL_CONSOLE.upper(), logging.INFO)) # Уровень логирования из константы
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

# --- Константы ---
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "ss://"]
ALL_URLS_FILE = "channel_urls.txt"
OUTPUT_ALL_CONFIG_FILE = "configs/proxy_configs_all.txt" # Возвращено к .txt
MAX_RETRIES = 4
RETRY_DELAY_BASE = 2
MAX_CONCURRENT_CHANNELS = 60
MAX_CONCURRENT_PROXIES_PER_CHANNEL = 50
MAX_CONCURRENT_PROXIES_GLOBAL = 50
DOWNLOAD_TIMEOUT_SEC = 15


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
        return hash((self.protocol, self.address, self.port, self.config_string)) # config_string for full deduplication

    def __eq__(self, other):
        if isinstance(other, ProxyParsedConfig):
            return (self.protocol, self.address, self.port, self.config_string) == \
                   (other.protocol, other.address, other.port, other.config_string)
        return False

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p)), None)
        if not protocol:
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                return None
            return cls(
                config_string=config_string,
                protocol=protocol.replace("://", ""),
                address=address,
                port=port
            )
        except ValueError:
            return None

@dataclass(frozen=True)
class VlessParsedConfig(ProxyParsedConfig):
    uuid: Optional[str] = None
    encryption: Optional[str] = None
    flow: Optional[str] = None
    security: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["VlessParsedConfig"]:
        if not config_string.startswith("vless://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            userinfo = parsed_url.username + ":" + parsed_url.password if parsed_url.username else None
            query_params = parse_qs(parsed_url.query)

            uuid_val = parsed_url.username if parsed_url.username else None
            if not uuid_val and "uuid" in query_params:
                uuid_val = query_params["uuid"][0]

            return cls(
                config_string=config_string,
                protocol="vless",
                address=address,
                port=port,
                uuid=uuid_val,
                encryption=query_params.get("encryption", [None])[0],
                flow=query_params.get("flow", [None])[0],
                security=query_params.get("security", [None])[0],
                sni=query_params.get("sni", [None])[0],
                alpn=query_params.get("alpn", [None])[0],
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn))

    def __eq__(self, other):
        if not isinstance(other, VlessParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.uuid, self.encryption, self.flow, self.security, self.sni, self.alpn) == \
               (other.uuid, other.encryption, other.flow, other.security, other.sni, other.alpn)

# --- Добавьте классы TuicParsedConfig, Hy2ParsedConfig, SsParsedConfig по аналогии, если необходимо парсить специфичные параметры ---
@dataclass(frozen=True)
class TuicParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    congestion_control: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["TuicParsedConfig"]:
        if not config_string.startswith("tuic://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="tuic",
                address=address,
                port=port,
                congestion_control=query_params.get("c", [None])[0], # 'c' for congestion control is a guess, check TUIC spec
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.congestion_control))

    def __eq__(self, other):
        if not isinstance(other, TuicParsedConfig):
            return False
        return super().__eq__(other) and self.congestion_control == other.congestion_control

@dataclass(frozen=True)
class Hy2ParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    encryption_method: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["Hy2ParsedConfig"]:
        if not config_string.startswith("hy2://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)

            return cls(
                config_string=config_string,
                protocol="hy2",
                address=address,
                port=port,
                encryption_method=query_params.get("enc", [None])[0], # 'enc' for encryption is a guess, check HY2 spec
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method))

    def __eq__(self, other):
        if not isinstance(other, Hy2ParsedConfig):
            return False
        return super().__eq__(other) and self.encryption_method == other.encryption_method


@dataclass(frozen=True)
class SsParsedConfig(ProxyParsedConfig): # Пример, расширьте по необходимости
    encryption_method: Optional[str] = None
    password: Optional[str] = None
    plugin: Optional[str] = None

    @classmethod
    def from_url(cls, config_string: str) -> Optional["SsParsedConfig"]:
        if not config_string.startswith("ss://"):
            return None
        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port

            userinfo = parsed_url.username + ":" + parsed_url.password if parsed_url.username else None
            encryption_password_b64 = parsed_url.netloc.split('@')[0] # extract b64 encoded part
            try:
                encryption_password_decoded = base64.b64decode(encryption_password_b64 + "==").decode('utf-8') # Padding might be needed
                encryption_method = encryption_password_decoded.split(':')[0]
                password = encryption_password_decoded.split(':')[1] if len(encryption_password_decoded.split(':')) > 1 else None
            except Exception: # Decoding errors, handle as needed
                encryption_method = None
                password = None

            query_params = parse_qs(parsed_url.query)
            plugin = query_params.get('plugin', [None])[0]

            return cls(
                config_string=config_string,
                protocol="ss",
                address=address,
                port=port,
                encryption_method=encryption_method,
                password=password,
                plugin=plugin
            )
        except ValueError:
            return None

    def __hash__(self):
        return hash((super().__hash__(), self.encryption_method, self.password, self.plugin))

    def __eq__(self, other):
        if not isinstance(other, SsParsedConfig):
            return False
        return super().__eq__(other) and \
               (self.encryption_method, self.password, self.plugin) == \
               (other.encryption_method, other.password, other.plugin)


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
        return None
    except Exception:
        return None

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Downloads proxy configurations from a single channel URL with retry logic."""
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT_SEC)
    while retries_attempted <= MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout) as response:
                if response.status == 200:
                    text = await response.text(encoding='utf-8', errors='ignore')
                    return text.splitlines(), "success"
                else:
                    colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул статус {response.status}")
                    return [], "warning" # Treat as warning, don't retry immediately for HTTP errors
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{MAX_RETRIES+1}): {e}. Пауза {retry_delay} сек")
            if retries_attempted == MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Макс. попыток ({MAX_RETRIES+1}) исчерпано для {channel_url}")
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1
    return [], "critical" # Should not reach here, but for type hinting

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Parses and filters valid proxy configurations from lines with batched DNS resolution and protocol-specific parsing."""
    parsed_configs = []
    configs_to_resolve = []
    unique_configs = set()

    for line in lines: # Первый проход: парсим и собираем на разрешение
        line = line.strip()
        if not line or not any(line.startswith(proto) for proto in ALLOWED_PROTOCOLS):
            continue

        protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)
        if protocol:
            if protocol == "vless://":
                parsed_config = VlessParsedConfig.from_url(line)
            elif protocol == "tuic://":
                parsed_config = TuicParsedConfig.from_url(line)
            elif protocol == "hy2://":
                parsed_config = Hy2ParsedConfig.from_url(line)
            elif protocol == "ss://":
                parsed_config = SsParsedConfig.from_url(line)
            else:
                parsed_config = ProxyParsedConfig.from_url(line) # Fallback for unknown protocols in ALLOWED_PROTOCOLS

            if parsed_config and parsed_config not in unique_configs:
                unique_configs.add(parsed_config) # Дедупликация на раннем этапе
                configs_to_resolve.append(parsed_config)

    async def resolve_config(config): # Функция для разрешения одного конфига
        resolved_ip = await resolve_address(config.address, resolver)
        if resolved_ip:
            return config, resolved_ip
        return config, None

    resolution_tasks = [resolve_config(config) for config in configs_to_resolve] # Создаем задачи
    resolution_results = await asyncio.gather(*resolution_tasks) # Запускаем все асинхронно

    for config, resolved_ip in resolution_results: # Обрабатываем результаты
        if resolved_ip:
            parsed_configs.append(config) # Добавляем только успешно разрешенные
    return parsed_configs


def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Saves all downloaded proxies to the output file with protocol names (including duplicates) in text format."""
    total_proxies_count = 0
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            protocol_grouped_proxies = defaultdict(list)
            for proxy_conf in all_proxies:
                protocol_grouped_proxies[proxy_conf.protocol].append(proxy_conf)

            for protocol in ["vless", "tuic", "hy2", "ss"]: # сохраняем в нужном порядке
                if protocol in protocol_grouped_proxies:
                    colored_log(logging.INFO, f"\n📝 Протокол (все): {ProfileName[protocol.upper()].value}")
                    for proxy_conf in protocol_grouped_proxies[protocol]:
                        # Beautiful naming for logs and file output
                        proxy_name_parts = [ProfileName[protocol.upper()].value, proxy_conf.address, str(proxy_conf.port)]
                        if isinstance(proxy_conf, VlessParsedConfig) and proxy_conf.sni:
                            proxy_name_parts.append(f"sni:{proxy_conf.sni}")
                        if isinstance(proxy_conf, SsParsedConfig) and proxy_conf.encryption_method:
                            proxy_name_parts.append(f"enc:{proxy_conf.encryption_method}")
                        proxy_name = " - ".join(proxy_name_parts)
                        colored_log(logging.INFO, f"   ➕ Добавлен прокси (все): {proxy_name}")

                        config_line = proxy_conf.config_string + f"#{proxy_name}" # Beautiful name as comment
                        f.write(config_line + "\n")
                        total_proxies_count += 1
        colored_log(logging.INFO, f"\n✅ Сохранено {total_proxies_count} прокси (все) в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении всех прокси в файл: {e}")
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Loads channel URLs from the specified file."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"Файл {all_urls_file} не найден. Проверьте наличие файла с URL каналов.")
        open(all_urls_file, 'w').close() # Create empty file if not exists
    return channel_urls


async def main():
    start_time = time.time()
    channel_urls = await load_channel_urls(ALL_URLS_FILE)
    if not channel_urls:
        colored_log(logging.WARNING, "Нет URL каналов для обработки.")
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
    total_proxies_downloaded = 0
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)

    resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
    global_proxy_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROXIES_GLOBAL)
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)

    async with aiohttp.ClientSession() as session:
        channel_tasks = []
        for channel_url in channel_urls:
            async def process_channel_task(url):
                channel_proxies_count_channel = 0 # Initialize count here
                channel_success = 0 # Initialize success count
                async with channel_semaphore:
                    colored_log(logging.INFO, f"🚀 Начало обработки канала: {url}")
                    lines, status = await download_proxies_from_channel(url, session)
                    channel_status_counts[status] += 1
                    if status == "success":
                        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
                        channel_proxies_count_channel = len(parsed_proxies)
                        channel_success = 1 # Mark channel as success after processing
                        for proxy in parsed_proxies:
                            protocol_counts[proxy.protocol] += 1
                        colored_log(logging.INFO, f"✅ Канал {url} обработан. Найдено {channel_proxies_count_channel} прокси.")
                        return channel_proxies_count_channel, channel_success, parsed_proxies # Return counts and proxies
                    else:
                        colored_log(logging.WARNING, f"⚠️ Канал {url} обработан со статусом: {status}.")
                        return 0, 0, [] # Return zero counts and empty list for failed channels

            task = asyncio.create_task(process_channel_task(channel_url))
            channel_tasks.append(task)

        channel_results = await asyncio.gather(*channel_tasks)
        all_proxies = []
        for proxies_count, success_flag, proxies_list in channel_results: # Unpack returned values
            total_proxies_downloaded += proxies_count # Aggregate proxy counts
            channels_processed_successfully += success_flag # Aggregate success flags
            all_proxies.extend(proxies_list) # Collect proxies

    # Сохранение всех загруженных прокси (включая дубликаты) в отдельный файл
    all_proxies_saved_count = save_all_proxies_to_file(all_proxies, OUTPUT_ALL_CONFIG_FILE)
    end_time = time.time()
    elapsed_time = end_time - start_time

    colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
    colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
    colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")

    colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
    for status in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status, 0)
        if count > 0:
            status_text = status.upper()
            color = LogColors.GREEN if status == "success" else (LogColors.YELLOW if status == "warning" else (LogColors.RED if status in ["error", "critical"] else LogColors.RESET))
            colored_log(logging.INFO, f"  - {color}{status_text}{LogColors.RESET}: {count} каналов")

    colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}")
    colored_log(logging.INFO, f"📝 Всего прокси (все) сохранено: {all_proxies_saved_count} (в {OUTPUT_ALL_CONFIG_FILE})")


    colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
    else:
        colored_log(logging.INFO, "   Нет статистики по протоколам.")

    colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")
    colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
