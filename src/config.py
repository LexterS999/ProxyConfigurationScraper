import asyncio
import aiodns
import os
import logging
import ipaddress
import time
import json
import functools
from enum import Enum
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp

# --- Настройка логирования (с использованием coloredlogs) ---
import coloredlogs

LOG_FILE = 'proxy_downloader.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Устанавливаем общий уровень на DEBUG

# Обработчик файла (уровень WARNING и выше, формат JSON)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)

class JsonFormatter(logging.Formatter):
    """Пользовательский форматтер для записи логов в JSON."""
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, self.default_time_format),
            "level": record.levelname,
            "message": record.getMessage(),
            "process": record.process,
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Обработчик консоли (уровень INFO, цветной вывод с помощью coloredlogs)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
coloredlogs.install(level='INFO', logger=logger, stream=console_handler,
                    fmt='[%(levelname)s] %(message)s')  # Простой формат для coloredlogs

# --- Константы и перечисления ---
class Protocols(str, Enum):
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

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
    MAX_PROXIES_GLOBAL: int = 50

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]
CONFIG_FILES = ConfigFiles()
RETRY = RetrySettings()
CONCURRENCY = ConcurrencyLimits()

# --- Пользовательские исключения ---
class InvalidURLError(ValueError):
    """Недопустимый URL-адрес."""
    pass

class UnsupportedProtocolError(ValueError):
    """Неподдерживаемый протокол."""
    pass

class DownloadError(Exception):
    """Ошибка загрузки."""
    pass

# --- Структуры данных ---
@dataclass(frozen=True)
class ProxyParsedConfig:
    config_string: str
    protocol: str
    address: str
    port: int
    remark: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.protocol, self.address, self.port))

    def __str__(self):
        return (f"ProxyConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')")

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """Разбирает строку конфигурации прокси в объект ProxyParsedConfig."""
        if len(config_string) > 1024: # Ограничиваем максимальную длину config_string
            logger.warning(f"Пропускаем слишком длинный URL: {config_string[:100]}...")
            return None

        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p + "://")), None)
        if not protocol:
            try:
                decoded_config = base64.b64decode(config_string, validate=True).decode('utf-8', errors='ignore')
                protocol = next((p for p in ALLOWED_PROTOCOLS if decoded_config.startswith(p + "://")), None)
                if protocol:
                    config_string = decoded_config
                else:
                    return None
            except:
                return None

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                return None

            remark = parsed_url.fragment if parsed_url.fragment else ""
            query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()} if parsed_url.query else {}

            return cls(
                config_string=config_string.split("#")[0],
                protocol=protocol,
                address=address,
                port=port,
                remark=remark,
                query_params=query_params,
            )
        except ValueError:
            return None

# --- Вспомогательные функции ---

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли строка допустимым IPv4-адресом."""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Разрешает имя хоста в IPv4-адрес."""
    if is_valid_ipv4(hostname):
        return hostname

    try:
        async with asyncio.timeout(10):
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            return resolved_ip if is_valid_ipv4(resolved_ip) else None
    except (asyncio.TimeoutError, aiodns.error.DNSError) as e:
        logger.warning(f"Ошибка разрешения DNS для {hostname}: {e}", stacklevel=2)
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при разрешении DNS для {hostname}: {e}", exc_info=True, stacklevel=2)
        return None

# --- Функции загрузки и обработки ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession, channel_proxy_semaphore: asyncio.Semaphore) -> Tuple[List[str], str]:
    """Загружает конфигурации прокси из одного URL-адреса канала."""
    headers = {'User-Agent': 'ProxyDownloader/1.0'}
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=15)

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            async with channel_proxy_semaphore: # Ограничиваем кол-во одновременных запросов
                async with session.get(channel_url, timeout=session_timeout, headers=headers) as response:
                    response.raise_for_status()
                    text = await response.text(encoding='utf-8', errors='ignore')

                    if not text.strip():
                        logger.warning(f"Канал {channel_url} вернул пустой ответ.", stacklevel=2)
                        return [], "warning"

                    try:
                        decoded_text = base64.b64decode(text.strip(), validate=True).decode('utf-8', errors='ignore')
                        return decoded_text.splitlines(), "success"
                    except:
                        return text.splitlines(), "success"

        except aiohttp.ClientResponseError as e:
            logger.warning(f"Канал {channel_url} вернул HTTP ошибку {e.status}: {e.message}", stacklevel=2)
            return [], "warning"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            logger.warning(f"Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {e}. Повтор через {retry_delay} сек...", stacklevel=2)
            if retries_attempted == RETRY.MAX_RETRIES:
                logger.error(f"Достигнуто максимальное количество попыток ({RETRY.MAX_RETRIES+1}) для {channel_url}", stacklevel=2)
                return [], "error"
            await asyncio.sleep(retry_delay)
        retries_attempted += 1

    return [], "critical"

async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Разбирает и фильтрует конфигурации прокси."""
    parsed_configs = []
    processed_configs = set()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parsed_config = ProxyParsedConfig.from_url(line)
        if parsed_config is None:
            logger.warning(f"Пропускаем неверный прокси URL: {line}", stacklevel=2)  # Логируем
            continue

        if parsed_config.config_string in processed_configs:
            continue
        processed_configs.add(parsed_config.config_string)

        resolved_ip = await resolve_address(parsed_config.address, resolver)
        if resolved_ip:
            parsed_configs.append(parsed_config)

    return parsed_configs

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    """Генерирует имя профиля прокси."""
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', 'unknown').lower()
    security = proxy_config.query_params.get('security', 'none').lower()
    if protocol == 'SS' and type_ == 'unknown':
        type_ = 'tcp'
    return f"{protocol}_{type_}_{security}"

async def save_proxies_from_queue(queue: asyncio.Queue, output_file: str) -> int:
    """Сохраняет прокси из очереди в файл (с дедупликацией)."""
    total_proxies_count = 0
    seen_config_strings = set()
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            while True:
                proxy_conf = await queue.get()
                if proxy_conf is None:  # Сигнал остановки
                    break
                if proxy_conf.config_string not in seen_config_strings:
                    seen_config_strings.add(proxy_conf.config_string)
                    profile_name = generate_proxy_profile_name(proxy_conf)
                    config_line = f"{proxy_conf.config_string}#{profile_name}"
                    f.write(config_line + "\n")
                    total_proxies_count += 1
                queue.task_done()
    except Exception as e:
        logger.error(f"Ошибка сохранения прокси из очереди в файл: {e}", exc_info=True, stacklevel=2)
    return total_proxies_count

async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Загружает URL-адреса каналов из файла."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and _is_valid_url(url):  # Проверяем URL
                    channel_urls.append(url)
                elif url:
                    logger.warning(f"Пропускаем невалидный URL канала: {url}", stacklevel=2)
    except FileNotFoundError:
        logger.warning(f"Файл {all_urls_file} не найден. Создаю пустой файл.", stacklevel=2)
        open(all_urls_file, 'w').close()
    except Exception as e:
        logger.error(f"Ошибка открытия/чтения файла {all_urls_file}: {e}", exc_info=True, stacklevel=2)
    return channel_urls

def _is_valid_url(url: str) -> bool:
    """Внутренняя функция для проверки URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

async def process_channel(url: str, session: aiohttp.ClientSession, resolver: aiodns.DNSResolver, proxy_queue: asyncio.Queue, channel_proxy_semaphore: asyncio.Semaphore) -> Tuple[int, bool]:
    """Обрабатывает один канал."""
    logger.info(f"🚀 Обработка канала: {url}", stacklevel=2)
    lines, status = await download_proxies_from_channel(url, session, channel_proxy_semaphore)
    if status == "success":
        parsed_proxies = await parse_and_filter_proxies(lines, resolver)
        channel_proxies_count = len(parsed_proxies)
        for proxy in parsed_proxies:
            await proxy_queue.put(proxy)
        logger.info(f"✅ Канал {url} обработан. Найдено {channel_proxies_count} прокси.", stacklevel=2)
        return channel_proxies_count, True
    else:
        logger.warning(f"⚠️ Канал {url} обработан со статусом: {status}.", stacklevel=2)
        return 0, False

async def main():
    """Основная функция."""
    start_time = time.time()
    channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
    if not channel_urls:
        logger.warning("Нет URL-адресов каналов для обработки.", stacklevel=2)
        return

    total_channels = len(channel_urls)
    channels_processed_successfully = 0
    total_proxies_downloaded = 0
    protocol_counts = defaultdict(int)
    channel_status_counts = defaultdict(int)

    resolver = aiodns.DNSResolver()
    proxy_queue = asyncio.Queue()
    channel_proxy_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_PROXIES_PER_CHANNEL)

    try:
        async with aiohttp.ClientSession() as session:
            async with asyncio.TaskGroup() as tg:
                channel_tasks = [tg.create_task(process_channel(url, session, resolver, proxy_queue, channel_proxy_semaphore)) for url in channel_urls]

            channel_results = [task.result() for task in channel_tasks]  # Результаты в том же порядке

            for proxies_count, success_flag in channel_results:
                total_proxies_downloaded += proxies_count
                channels_processed_successfully += int(success_flag) # Явное преобразование
                # Подсчет протоколов ведется *после* обработки всех каналов
                # (чтобы учесть все прокси, добавленные в очередь)

            await proxy_queue.join()  # Ждем, пока очередь опустеет
            await proxy_queue.put(None)  # Посылаем сигнал остановки
            save_task = asyncio.create_task(save_proxies_from_queue(proxy_queue, CONFIG_FILES.OUTPUT_ALL_CONFIG))
            all_proxies_saved_count = await save_task

            # Подсчитываем протоколы после обработки всех каналов и сохранения в файл
            for proxy in [item for q in channel_results for item in (await parse_and_filter_proxies(await download_proxies_from_channel(q[2], session, channel_proxy_semaphore)[0], resolver)) if item]:
               protocol_counts[proxy.protocol] += 1
            channel_status_counts = defaultdict(int, {k: sum(1 for r in channel_results if r[1] == (k == "success")) for k in ["success", "warning", "error", "critical"]})


    except Exception as e:
        logger.critical(f"Неожиданная ошибка в main(): {e}", exc_info=True, stacklevel=2)
    finally:
        logger.info("✅ Загрузка и обработка прокси завершена.", stacklevel=2)


    end_time = time.time()
    elapsed_time = end_time - start_time

    # --- Статистика и отчетность ---
    logger.info("==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================", stacklevel=2)
    logger.info(f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек", stacklevel=2)
    logger.info(f"🔗 Всего URL-источников: {total_channels}", stacklevel=2)
    logger.info(f"✅ Успешно обработано каналов: {channels_processed_successfully}/{total_channels}", stacklevel=2)

    logger.info("\n📊 Статус обработки URL-источников:", stacklevel=2)
    for status_key in ["success", "warning", "error", "critical"]:
        count = channel_status_counts.get(status_key, 0)
        if count > 0:
            if status_key == "success":
                status_text = "УСПЕШНО"
            elif status_key == "warning":
                status_text = "ПРЕДУПРЕЖДЕНИЕ"
            elif status_key in ["error", "critical"]:
                status_text = "ОШИБКА"
            else:
                status_text = status_key.upper()
            logger.info(f"  - {status_text}: {count} каналов", stacklevel=2)

    logger.info(f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}", stacklevel=2)
    logger.info(f"📝 Всего прокси (все, без дубликатов) сохранено: {all_proxies_saved_count} (в {CONFIG_FILES.OUTPUT_ALL_CONFIG})", stacklevel=2)

    logger.info("\n🔬 Разбивка по протоколам (найдено):", stacklevel=2)
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            logger.info(f"   - {protocol.upper()}: {count}", stacklevel=2)
    else:
        logger.info("   Нет статистики по протоколам.", stacklevel=2)

    logger.info("======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================", stacklevel=2)
if __name__ == "__main__":
    asyncio.run(main())
