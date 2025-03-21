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
import inspect

from enum import Enum
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict


# --- Настройка улучшенного логирования ---
LOG_FORMAT = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "module": "%(module)s",
    "funcName": "%(funcName)s",
    "lineno": "%(lineno)d",
}
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"  # Формат для консольного вывода
LOG_FILE = 'proxy_downloader.log'  # Имя файла лога

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Обработчик файла (уровень WARNING и выше, формат JSON)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.WARNING)


class JsonFormatter(logging.Formatter):
    """Пользовательский форматтер для записи логов в JSON."""

    def format(self, record):
        log_record = LOG_FORMAT.copy()
        log_record["message"] = record.getMessage()
        log_record["level"] = record.levelname
        log_record["process"] = record.process
        log_record["time"] = self.formatTime(record, self.default_time_format)
        log_record["module"] = record.module
        log_record["funcName"] = record.funcName
        log_record["lineno"] = record.lineno
        # Обработка исключений, если есть
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)

formatter_file = JsonFormatter()
file_handler.setFormatter(formatter_file)
logger.addHandler(file_handler)

# Обработчик консоли (уровень INFO и выше, цветной вывод)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter_console = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(formatter_console)
logger.addHandler(console_handler)


def colored_log(level, message: str, *args, **kwargs):
    """Выводит сообщение с цветом в зависимости от уровня логирования."""
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

    # Получаем информацию о вызывающей стороне.  Фрейм стека 1 - это вызывающая сторона colored_log.
    frame = inspect.currentframe().f_back  # Используем f_back, чтобы получить вызывающий фрейм
    pathname = frame.f_code.co_filename
    lineno = frame.f_lineno
    func = frame.f_code.co_name  # Исправлено на co_name

    #  !!!  ИЗМЕНЕНИЕ ТУТ: Применяем форматирование *ДО* создания LogRecord
    formatted_message = f"{color}{message}{RESET}"

    record = logging.LogRecord(
        name=logger.name,
        level=level,
        pathname=pathname,  # Полный путь
        lineno=lineno,  # Правильный номер строки
        msg=formatted_message,  #  !!!  Передаем уже отформатированное сообщение
        args=args,
        exc_info=kwargs.get('exc_info'),
        func=func,  # Правильное имя функции
        sinfo=None
    )
    logger.handle(record)



# --- Константы и перечисления ---
class Protocols(Enum):
    """Перечисление поддерживаемых протоколов."""
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    # Добавили shadowsocksr, т.к. некоторые ссылки используют его
    SSR = "ssr"
    TROJAN = "trojan"
    # VMESS = "vmess" # Убрано

@dataclass(frozen=True)
class ConfigFiles:
    """Конфигурационные файлы."""
    ALL_URLS: str = "channel_urls.txt"
    OUTPUT_ALL_CONFIG: str = "configs/proxy_configs_all.txt"

@dataclass(frozen=True)
class RetrySettings:
    """Настройки повторных попыток."""
    MAX_RETRIES: int = 4
    RETRY_DELAY_BASE: int = 2

@dataclass(frozen=True)
class ConcurrencyLimits:
    """Ограничения параллелизма."""
    MAX_CHANNELS: int = 60  # Максимальное количество каналов для одновременной обработки
    MAX_PROXIES_PER_CHANNEL: int = 50 # Макс. прокси
    MAX_PROXIES_GLOBAL: int = 50  # Глобальный лимит на одновременные проверки прокси

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]  # Список разрешенных протоколов
CONFIG_FILES = ConfigFiles()  # Конфигурационные файлы
RETRY = RetrySettings()  # Настройки повторных попыток
CONCURRENCY = ConcurrencyLimits()  # Ограничения параллелизма

# --- Вспомогательные функции ---

@functools.lru_cache(maxsize=1024)
def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли данная строка допустимым IPv4-адресом."""
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver) -> Optional[str]:
    """Разрешает имя хоста в IPv4-адрес. Возвращает None в случае неудачи."""
    if is_valid_ipv4(hostname):
        return hostname  # Уже IP-адрес

    try:
        async with asyncio.timeout(10):  # Таймаут разрешения DNS
            result = await resolver.query(hostname, 'A')
            resolved_ip = result[0].host
            if is_valid_ipv4(resolved_ip):  # Проверяем разрешенный IP
               return resolved_ip
            else:
                #  colored_log(logging.WARNING, f"⚠️ DNS разрешил {hostname} в не-IPv4: {resolved_ip}") # Убрали показ
                return None
    except asyncio.TimeoutError:
        # colored_log(logging.WARNING, f"⚠️ Время ожидания разрешения DNS истекло для {hostname}") # Убрали показ
        return None
    except aiodns.error.DNSError as e:
        # colored_log(logging.WARNING, f"⚠️ Ошибка разрешения DNS для {hostname}: {e}") # Убрали показ
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при разрешении DNS для {hostname}: {e}", exc_info=True)  # Логируем неожиданные ошибки
        return None
# --- Структуры данных ---

class ProfileName(Enum):
    """Перечисление для названий профилей (для единообразия)."""
    VLESS = "VLESS"
    TUIC = "TUIC"
    HY2 = "HY2"
    SS = "SS"
    SSR = "SSR" # Добавлено
    TROJAN = "TROJAN" # Добавлено
    # VMESS = "VMESS" # Убрано
    UNKNOWN = "Unknown Protocol"  # Добавлено для обработки неизвестных протоколов

class InvalidURLError(ValueError):
    """Пользовательское исключение для недопустимых URL-адресов."""
    pass

class UnsupportedProtocolError(ValueError):
    """Пользовательское исключение для неподдерживаемых протоколов."""
    pass

@dataclass(frozen=True)
class ProxyParsedConfig:
    """Представляет разобранную конфигурацию прокси."""
    config_string: str  # Исходная строка конфигурации (без примечания, если есть)
    protocol: str       # Протокол (например, "vless", "tuic")
    address: str        # IP-адрес или имя хоста
    port: int           # Номер порта
    remark: str = ""    # Поле примечания (исходное)
    query_params: Dict[str, str] = field(default_factory=dict) # Добавили query параметры

    def __hash__(self):
        """Хеширует конфигурацию для эффективных операций с множествами (дедупликация)."""
        return hash((self.protocol, self.address, self.port))

    def __str__(self):
        """Предоставляет удобное строковое представление."""
        return (f"ProxyConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, config_string='{self.config_string[:50]}...')") # Отображаем часть config


    @classmethod
    def from_url(cls, config_string: str) -> "ProxyParsedConfig":
        """Разбирает строку конфигурации прокси (URL) в объект ProxyParsedConfig."""
        protocol = next((p for p in ALLOWED_PROTOCOLS if config_string.startswith(p + "://")), None)
        if not protocol:
            # Попытка декодировать base64, если это не стандартный URL
            try:
                decoded_config = base64.b64decode(config_string).decode('utf-8')
                protocol = next((p for p in ALLOWED_PROTOCOLS if decoded_config.startswith(p + "://")), None)
                if protocol:
                    config_string = decoded_config # Используем декодированную строку
                else:
                    # raise UnsupportedProtocolError(f"Неподдерживаемый протокол в URL: {config_string}") # Изменено!
                    #  Вместо ошибки, если протокол не поддерживается - просто пропускаем
                    return None
            except:
                # raise UnsupportedProtocolError(f"Неподдерживаемый протокол в URL: {config_string}") # Изменено!
                #  Вместо ошибки, если не удалось декодировать - просто пропускаем
                return None

        try:
            parsed_url = urlparse(config_string)
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port:
                # raise InvalidURLError(f"Не удалось извлечь адрес или порт из URL: {config_string}") # Изменено!
                return None # Вместо ошибки возвращаем None

             # Извлекаем примечание, если есть
            remark = ""
            if parsed_url.fragment:
                remark = parsed_url.fragment

            # Извлекаем параметры запроса
            query_params = {}
            if parsed_url.query:
                query_params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}

            return cls(
                config_string=config_string.split("#")[0], # Убираем исходное примечание
                protocol=protocol,
                address=address,
                port=port,
                remark=remark, # Сохраняем исходное примечание
                query_params=query_params, # Сохраняем query
            )


        except ValueError as e:
            # raise InvalidURLError(f"Ошибка разбора URL: {config_string}. Ошибка: {e}") from e # Изменено!
            return None  # Вместо ошибки возвращаем None


# --- Основная логика ---

async def download_proxies_from_channel(channel_url: str, session: aiohttp.ClientSession) -> Tuple[List[str], str]:
    """Загружает конфигурации прокси из одного URL-адреса канала.
       Возвращает кортеж: (список строк конфигурации прокси, строка состояния).
       Статус может быть: "success", "warning", "error", "critical".
    """
    headers = {'User-Agent': 'ProxyDownloader/1.0'}  # Устанавливаем User-Agent
    retries_attempted = 0
    session_timeout = aiohttp.ClientTimeout(total=15) # Устанавливаем таймаут

    while retries_attempted <= RETRY.MAX_RETRIES:
        try:
            async with session.get(channel_url, timeout=session_timeout, headers=headers) as response:
                response.raise_for_status()  # Генерируем исключение для плохих кодов состояния
                text = await response.text(encoding='utf-8', errors='ignore')  # Обрабатываем потенциальные проблемы с кодировкой

                #  Добавлено: Проверяем, есть ли содержимое в ответе
                if not text.strip():
                    colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул пустой ответ.")
                    return [], "warning"  # Пустой ответ - это предупреждение

                # Попытка декодировать base64, если это необходимо
                try:
                    # Если контент похож на base64, декодируем его
                    decoded_text = base64.b64decode(text.strip()).decode('utf-8')
                    return decoded_text.splitlines(), "success"
                except:
                    # Если не base64, возвращаем как есть
                    return text.splitlines(), "success"


        except aiohttp.ClientResponseError as e:
            colored_log(logging.WARNING, f"⚠️ Канал {channel_url} вернул HTTP ошибку {e.status}: {e.message}")
            return [], "warning"  # Считаем не-200 ответы предупреждениями
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_delay = RETRY.RETRY_DELAY_BASE * (2 ** retries_attempted)
            colored_log(logging.WARNING, f"⚠️ Ошибка при получении {channel_url} (попытка {retries_attempted+1}/{RETRY.MAX_RETRIES+1}): {e}. Повтор через {retry_delay} сек...")
            if retries_attempted == RETRY.MAX_RETRIES:
                colored_log(logging.ERROR, f"❌ Достигнуто максимальное количество попыток ({RETRY.MAX_RETRIES+1}) для {channel_url}")
                return [], "error"  # Помечаем как ошибку после максимального количества попыток
            await asyncio.sleep(retry_delay)
        retries_attempted += 1

    return [], "critical"  # Не должны сюда доходить, но добавлено для полноты


async def parse_and_filter_proxies(lines: List[str], resolver: aiodns.DNSResolver) -> List[ProxyParsedConfig]:
    """Разбирает и фильтрует конфигурации прокси, разрешая имена хостов в IP-адреса."""
    parsed_configs = []
    processed_configs = set()  # Множество для отслеживания обработанных строк

    for line in lines:
        line = line.strip()
        if not line:  # Пропускаем пустые строки
            continue

        try:
            parsed_config = ProxyParsedConfig.from_url(line)
            if parsed_config is None:  #  Если from_url вернул None, пропускаем
                continue

             # Разрешаем имя хоста в IP-адрес
            resolved_ip = await resolve_address(parsed_config.address, resolver)

            # Добавлено: Проверяем, был ли уже обработан такой config_string
            if parsed_config.config_string in processed_configs:
                #colored_log(logging.INFO, f"ℹ️ Пропускаем дубликат: {parsed_config.config_string}") # Убрали излишнее логирование
                continue  # Пропускаем дубликат
            processed_configs.add(parsed_config.config_string)

            if resolved_ip:
                parsed_configs.append(parsed_config)  # Добавляем, только если разрешение успешно

        except (InvalidURLError, UnsupportedProtocolError) as e:
            # colored_log(logging.WARNING, f"⚠️ Пропускаем неверный или неподдерживаемый прокси URL '{line}': {e}") #  Убрали!
            continue


    return parsed_configs


def generate_proxy_profile_name(proxy_config: ProxyParsedConfig) -> str:
    """Генерирует имя профиля прокси, извлекая type и security."""
    protocol = proxy_config.protocol.upper()
    type_ = proxy_config.query_params.get('type', 'unknown').lower()
    security = proxy_config.query_params.get('security', 'none').lower()

    # Добавляем обработку для ss, если нет type, то подставляем tcp
    if protocol == 'SS' and type_ == 'unknown':
        type_ = 'tcp'

    return f"{protocol}_{type_}_{security}"



def save_all_proxies_to_file(all_proxies: List[ProxyParsedConfig], output_file: str) -> int:
    """Сохраняет все разобранные конфигурации прокси в файл, по одной на строку.
       Удаляет дубликаты на основе config_string ПЕРЕД сохранением.
    """
    total_proxies_count = 0
    unique_proxies = []
    seen_config_strings = set() # Используем set() для быстрого O(1) поиска

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Убеждаемся, что каталог существует

        # Дедупликация ПЕРЕД записью в файл
        for proxy_conf in all_proxies:
            if proxy_conf.config_string not in seen_config_strings:
                unique_proxies.append(proxy_conf)
                seen_config_strings.add(proxy_conf.config_string)

        with open(output_file, 'w', encoding='utf-8') as f:
            for proxy_conf in unique_proxies:
                profile_name = generate_proxy_profile_name(proxy_conf)  # Генерируем новое имя профиля
                # Записываем строку конфигурации с *новым* именем профиля
                config_line = f"{proxy_conf.config_string}#{profile_name}"
                f.write(config_line + "\n")
                total_proxies_count += 1

    except Exception as e:
        logger.error(f"Ошибка сохранения всех прокси в файл: {e}", exc_info=True)
    return total_proxies_count


async def load_channel_urls(all_urls_file: str) -> List[str]:
    """Загружает URL-адреса каналов из файла, обрабатывая отсутствие файла и другие ошибки."""
    channel_urls = []
    try:
        with open(all_urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url:  # Игнорируем пустые строки
                    channel_urls.append(url)
    except FileNotFoundError:
        colored_log(logging.WARNING, f"⚠️ Файл {all_urls_file} не найден. Создаю пустой файл.")
        open(all_urls_file, 'w').close()  # Создаем файл, если он не существует.
    except Exception as e:
        logger.error(f"Ошибка открытия/чтения файла {all_urls_file}: {e}", exc_info=True)
    return channel_urls


async def main():
    """Основная функция для организации загрузки и обработки прокси."""

    try:
        start_time = time.time()
        channel_urls = await load_channel_urls(CONFIG_FILES.ALL_URLS)
        if not channel_urls:
            colored_log(logging.WARNING, "Нет URL-адресов каналов для обработки.")
            return  # Выход, если нет URL

        total_channels = len(channel_urls)
        channels_processed_successfully = 0
        total_proxies_downloaded = 0
        protocol_counts = defaultdict(int)  # Отслеживаем количество каждого протокола
        channel_status_counts = defaultdict(int) # Отслеживаем успешность/неудачу канала

        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        global_proxy_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_PROXIES_GLOBAL)  # Глобальный лимит
        channel_semaphore = asyncio.Semaphore(CONCURRENCY.MAX_CHANNELS)

        async with aiohttp.ClientSession() as session:
            channel_tasks = []

            for channel_url in channel_urls:
                async def process_channel_task(url):
                    nonlocal channels_processed_successfully, total_proxies_downloaded  # Доступ к переменным внешней области видимости
                    channel_proxies_count_channel = 0
                    channel_success = 0
                    async with channel_semaphore: # Ограничиваем одновременную обработку каналов
                        colored_log(logging.INFO, f"🚀 Обработка канала: {url}")
                        lines, status = await download_proxies_from_channel(url, session)
                        channel_status_counts[status] += 1
                        if status == "success":
                            parsed_proxies = await parse_and_filter_proxies(lines, resolver)
                            channel_proxies_count_channel = len(parsed_proxies)
                            channel_success = 1  # Увеличиваем при успешной обработке канала
                            for proxy in parsed_proxies:
                                protocol_counts[proxy.protocol] += 1  # Считаем по протоколу
                            colored_log(logging.INFO, f"✅ Канал {url} обработан. Найдено {channel_proxies_count_channel} прокси.")
                            return channel_proxies_count_channel, channel_success, parsed_proxies  # Возвращаем разобранные прокси
                        else:
                            colored_log(logging.WARNING, f"⚠️ Канал {url} обработан со статусом: {status}.")
                            return 0, 0, []


                task = asyncio.create_task(process_channel_task(channel_url))
                channel_tasks.append(task)

            channel_results = await asyncio.gather(*channel_tasks)
            all_proxies: List[ProxyParsedConfig] = []  # Явное указание типа
            for proxies_count, success_flag, proxies_list in channel_results:
                total_proxies_downloaded += proxies_count
                channels_processed_successfully += success_flag
                all_proxies.extend(proxies_list)


        all_proxies_saved_count = save_all_proxies_to_file(all_proxies, CONFIG_FILES.OUTPUT_ALL_CONFIG)

        end_time = time.time()
        elapsed_time = end_time - start_time

        # --- Статистика и отчетность ---
        colored_log(logging.INFO, "==================== 📊 СТАТИСТИКА ЗАГРУЗКИ ПРОКСИ ====================")
        colored_log(logging.INFO, f"⏱️  Время выполнения скрипта: {elapsed_time:.2f} сек")
        colored_log(logging.INFO, f"🔗 Всего URL-источников: {total_channels}")
        colored_log(logging.INFO, f"✅ Успешно обработано каналов: {channels_processed_successfully}/{total_channels}")

        colored_log(logging.INFO, "\n📊 Статус обработки URL-источников:")
        for status_key in ["success", "warning", "error", "critical"]:
            count = channel_status_counts.get(status_key, 0)
            if count > 0:
                if status_key == "success":
                    status_text, color = "УСПЕШНО", '\033[92m'
                elif status_key == "warning":
                    status_text, color = "ПРЕДУПРЕЖДЕНИЕ", '\033[93m'
                elif status_key in ["error", "critical"]:
                    status_text, color = "ОШИБКА", '\033[91m'
                else:
                    status_text, color = status_key.upper(), '\033[0m'

                colored_log(logging.INFO, f"  - {status_text}: {count} каналов")

        colored_log(logging.INFO, f"\n✨ Всего найдено конфигураций: {total_proxies_downloaded}")
        colored_log(logging.INFO, f"📝 Всего прокси (все, без дубликатов) сохранено: {all_proxies_saved_count} (в {CONFIG_FILES.OUTPUT_ALL_CONFIG})")

        colored_log(logging.INFO, "\n🔬 Разбивка по протоколам (найдено):")
        if protocol_counts:
            for protocol, count in protocol_counts.items():
                colored_log(logging.INFO, f"   - {protocol.upper()}: {count}")
        else:
            colored_log(logging.INFO, "   Нет статистики по протоколам.")


        colored_log(logging.INFO, "======================== 🏁 КОНЕЦ СТАТИСТИКИ =========================")

    except Exception as e:
        logger.critical(f"Неожиданная ошибка в main(): {e}", exc_info=True)  # Логируем критические ошибки
    finally:
        colored_log(logging.INFO, "✅ Загрузка и обработка прокси завершена.")


if __name__ == "__main__":
    asyncio.run(main())
