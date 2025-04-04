import asyncio
import aiodns
import re
import os
import logging
import ipaddress
import json
import sys
import argparse
import dataclasses
import random
import aiohttp
import base64
import time
import binascii
import ssl
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlunparse, unquote # Добавлен unquote
from typing import Dict, List, Optional, Tuple, Set, DefaultDict, Any, Union, NamedTuple, Sequence
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from string import Template
from functools import lru_cache
import contextlib # Для asynccontextmanager

# --- Зависимости с проверкой ---
try:
    from tqdm.asyncio import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Определяем заглушку для tqdm.gather, если tqdm недоступен
    async def gather_stub(*tasks, desc=None, unit=None, disable=False, **kwargs):
        # Просто выполняем asyncio.gather без прогресс-бара
        # Логируем сообщение, если прогресс-бар был бы показан
        if not disable and desc:
            logger.info(f"Processing: {desc}...")
        return await asyncio.gather(*tasks)
    # Заменяем tqdm.gather на заглушку
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

# --- Constants ---
LOG_FILE = 'proxy_downloader.log'
CONSOLE_LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_FORMAT: Dict[str, str] = {
    "time": "%(asctime)s",
    "level": "%(levelname)s",
    "message": "%(message)s",
    "process": "%(process)s",
    "threadName": "%(threadName)s",
    "module": "%(module)s",
    "funcName": "%(funcName)s",
    "lineno": "%(lineno)d",
}

# --- Настройки по умолчанию (могут быть переопределены аргументами) ---
DEFAULT_DNS_TIMEOUT = 15
DEFAULT_HTTP_TIMEOUT = 15
DEFAULT_TEST_TIMEOUT = 10
DEFAULT_MAX_RETRIES = 4
DEFAULT_RETRY_DELAY_BASE = 2.0 # Используем float
DEFAULT_USER_AGENT = 'ProxyDownloader/1.1' # Версия обновлена
DEFAULT_TEST_URL_SNI = "www.google.com" # Используется только для SNI в TLS тесте
DEFAULT_TEST_PORT = 443
DEFAULT_MAX_CHANNELS_CONCURRENT = 60
DEFAULT_MAX_DNS_CONCURRENT = 50
DEFAULT_MAX_TESTS_CONCURRENT = 30
DEFAULT_INPUT_FILE = "channel_urls.txt"
DEFAULT_OUTPUT_BASE = "configs/proxy_configs_all"

# --- Регулярные выражения ---
PROTOCOL_REGEX = re.compile(r"^(vless|tuic|hy2|ss|ssr|trojan)://", re.IGNORECASE)
# HOSTNAME_REGEX больше не нужен, полагаемся на urlparse и проверку IP

# --- Шаблоны и Веса ---
PROFILE_NAME_TEMPLATE = Template("${protocol}-${type}-${security}") # Базовый шаблон
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

# --- Цвета для логов ---
COLOR_MAP = {
    logging.INFO: '\033[92m', # Green
    logging.DEBUG: '\033[94m', # Blue
    logging.WARNING: '\033[93m', # Yellow
    logging.ERROR: '\033[91m', # Red
    logging.CRITICAL: '\033[1m\033[91m', # Bold Red
    'RESET': '\033[0m'
}

# --- Форматы вывода ---
class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    CLASH = "clash"
    # V2RAYN = "v2rayn" # Пример для будущего расширения

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
    all_proxies_saved_count: int
    saved_protocol_counts: DefaultDict[str, int]
    saved_quality_category_counts: DefaultDict[str, int]
    output_file_path: str
    output_format: OutputFormat

# --- Data Structures ---
class Protocols(Enum):
    VLESS = "vless"
    TUIC = "tuic"
    HY2 = "hy2"
    SS = "ss"
    SSR = "ssr"
    TROJAN = "trojan"

ALLOWED_PROTOCOLS = [proto.value for proto in Protocols]

# --- Исключения ---
class InvalidURLError(ValueError): pass
class UnsupportedProtocolError(ValueError): pass
class EmptyChannelError(Exception): pass
class DownloadError(Exception): pass
class ProxyTestError(Exception): pass
class ConfigError(Exception): pass # Для ошибок конфигурации

# --- Датаклассы ---
@dataclass(frozen=True) # Оставляем frozen для неизменяемости базовых данных
class ProxyParsedConfig:
    """Представление распарсенной конфигурации прокси."""
    config_string: str # Оригинальная строка (или нормализованная)
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
        if not isinstance(other, ProxyParsedConfig):
            return NotImplemented
        return (self.protocol == other.protocol and
                self.address.lower() == other.address.lower() and
                self.port == other.port and
                self.query_params == other.query_params)

    def __str__(self):
        return (f"ProxyParsedConfig(protocol={self.protocol}, address={self.address}, "
                f"port={self.port}, quality={self.quality_score}, remark='{self.remark[:30]}...')")

    @classmethod
    def from_url(cls, config_string: str) -> Optional["ProxyParsedConfig"]:
        """Парсит строку конфигурации прокси. Возвращает объект или None."""
        original_string = config_string.strip()
        if not original_string:
            return None

        # Проверяем наличие схемы в начале
        protocol_match = PROTOCOL_REGEX.match(original_string)
        if not protocol_match:
            # logger.debug(f"Skipping line: No valid protocol prefix found in '{original_string[:100]}...'")
            return None
        protocol = protocol_match.group(1).lower()

        try:
            # Используем urlparse для основного разбора
            parsed_url = urlparse(original_string)

            # Дополнительная проверка схемы (urlparse может быть нестрогим)
            if parsed_url.scheme.lower() != protocol:
                logger.debug(f"Skipping line: Parsed scheme '{parsed_url.scheme}' mismatch protocol '{protocol}' in '{original_string[:100]}...'")
                return None

            address = parsed_url.hostname
            port = parsed_url.port

            if not address or not port:
                logger.debug(f"Skipping line: Missing address or port in '{original_string[:100]}...'")
                return None

            # Проверка валидности порта
            if not 1 <= port <= 65535:
                logger.debug(f"Skipping line: Invalid port {port} in '{original_string[:100]}...'")
                return None

            # Проверка адреса (может быть IP или hostname) - базовая
            # if not is_valid_ipv4(address) and not HOSTNAME_REGEX.match(address): # Убрали сложную regex
            #     logger.debug(f"Skipping line: Invalid address format '{address}' in '{original_string[:100]}...'")
            #     return None
            # Более простая проверка - не пустой и без пробелов (urlparse должен это обеспечить)
            if not address.strip() or ' ' in address:
                 logger.debug(f"Skipping line: Invalid address format '{address}' in '{original_string[:100]}...'")
                 return None


            # Извлекаем remark из fragment, декодируем URL-encoded символы
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else ""

            # Извлекаем параметры запроса
            query_params_raw = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params_raw.items() if v} # Берем первое значение

            # Сохраняем URL без fragment (remark) для единообразия при сохранении
            # и потенциальной дедупликации (хотя hash/eq уже это делают)
            config_string_to_store = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                 parsed_url.params, parsed_url.query, ''))

            return cls(
                config_string=config_string_to_store, # Сохраняем нормализованную строку
                protocol=protocol,
                address=address, # Сохраняем оригинальный hostname/IP
                port=port,
                remark=remark,
                query_params=query_params,
                # quality_score будет рассчитан позже
            )
        except ValueError as e:
            # urlparse может вызвать ValueError при некорректных символах и т.д.
            logger.debug(f"URL parsing ValueError for '{original_string[:100]}...': {e}")
            return None
        except Exception as e:
             # Ловим другие неожиданные ошибки парсинга
             logger.error(f"Unexpected error parsing URL '{original_string[:100]}...': {e}", exc_info=True)
             return None

# --- Глобальный логгер ---
# Настраивается в setup_logging
logger = logging.getLogger(__name__)

# --- Функции настройки ---

def setup_logging(log_level: int = logging.INFO, log_file: str = LOG_FILE, nocolor: bool = False) -> None:
    """Настраивает логирование в файл и консоль."""
    logger.setLevel(logging.DEBUG) # Устанавливаем самый низкий уровень здесь

    # --- Файловый обработчик (JSON) ---
    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_record: Dict[str, Any] = {}
            # Используем предопределенные атрибуты LogRecord для надежности
            log_record["time"] = self.formatTime(record, self.default_time_format)
            log_record["level"] = record.levelname
            log_record["message"] = record.getMessage() # Форматирует сообщение с аргументами
            log_record["module"] = record.module
            log_record["funcName"] = record.funcName
            log_record["lineno"] = record.lineno
            # Добавляем опциональные поля
            if hasattr(record, 'taskName') and record.taskName:
                log_record['taskName'] = record.taskName
            if record.exc_info:
                log_record['exc_info'] = self.formatException(record.exc_info)
            if record.stack_info:
                log_record['stack_info'] = self.formatStack(record.stack_info)
            return json.dumps(log_record, ensure_ascii=False, default=str)

    try:
        # Убедимся, что директория для лога существует
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a') # Добавляем в файл
        file_handler.setLevel(logging.DEBUG) # Пишем все debug и выше в файл
        formatter_file = JsonFormatter()
        file_handler.setFormatter(formatter_file)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Error setting up file logger to '{log_file}': {e}", file=sys.stderr)


    # --- Консольный обработчик (Цветной/Простой) ---
    class ColoredFormatter(logging.Formatter):
        def __init__(self, fmt: str = CONSOLE_LOG_FORMAT, use_colors: bool = True):
            super().__init__(fmt)
            self.use_colors = use_colors and sys.stdout.isatty() # Проверяем tty

        def format(self, record: logging.LogRecord) -> str:
            message = super().format(record)
            if self.use_colors:
                color_start = COLOR_MAP.get(record.levelno, COLOR_MAP['RESET'])
                return f"{color_start}{message}{COLOR_MAP['RESET']}"
            return message

    console_handler = logging.StreamHandler(sys.stdout) # Используем stdout для INFO/DEBUG
    console_handler.setLevel(log_level) # Уровень для консоли берем из аргументов
    console_formatter = ColoredFormatter(use_colors=not nocolor)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Добавляем обработчик для WARNING и выше в stderr (для лучшего разделения)
    error_handler = logging.StreamHandler(sys.stderr)
    error_handler.setLevel(logging.WARNING)
    error_formatter = ColoredFormatter(use_colors=not nocolor) # Тоже цветной
    error_handler.setFormatter(error_formatter)
    logger.addHandler(error_handler)

    # Подавление слишком шумных логов от библиотек
    logging.getLogger("aiodns").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)

def parse_arguments() -> argparse.Namespace:
    """Парсит аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="Асинхронный загрузчик и тестер прокси-конфигураций.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Показывает значения по умолчанию
    )
    parser.add_argument(
        '--input', '-i', type=str, default=DEFAULT_INPUT_FILE,
        help='Файл со списком URL каналов подписок.'
    )
    parser.add_argument(
        '--output', '-o', type=str, default=DEFAULT_OUTPUT_BASE,
        help='Базовый путь для сохранения файлов результатов (без расширения).'
    )
    parser.add_argument(
        '--output-format', type=str, choices=[f.value for f in OutputFormat],
        default=OutputFormat.TEXT.value,
        help='Формат выходного файла.'
    )
    parser.add_argument(
        '--test-proxies', action='store_true',
        help='Включить базовое тестирование соединения прокси (TCP/TLS).'
    )
    parser.add_argument(
        '--test-timeout', type=int, default=DEFAULT_TEST_TIMEOUT,
        help='Таймаут для одного теста соединения (секунды).'
    )
    parser.add_argument(
        '--test-sni', type=str, default=DEFAULT_TEST_URL_SNI,
        help='Hostname (SNI) для использования при TLS тестировании.'
    )
    parser.add_argument(
        '--test-port', type=int, default=DEFAULT_TEST_PORT,
        help='Порт для тестирования соединения (обычно 443 для TLS).'
    )
    parser.add_argument(
        '--dns-timeout', type=int, default=DEFAULT_DNS_TIMEOUT,
        help='Таймаут для одного DNS запроса (секунды).'
    )
    parser.add_argument(
        '--http-timeout', type=int, default=DEFAULT_HTTP_TIMEOUT,
        help='Общий таймаут для HTTP запроса к каналу (секунды).'
    )
    parser.add_argument(
        '--max-retries', type=int, default=DEFAULT_MAX_RETRIES,
        help='Максимальное количество повторных попыток скачивания канала.'
    )
    parser.add_argument(
        '--retry-delay', type=float, default=DEFAULT_RETRY_DELAY_BASE,
        help='Базовая задержка перед повторной попыткой (секунды, удваивается).'
    )
    parser.add_argument(
        '--max-channels', type=int, default=DEFAULT_MAX_CHANNELS_CONCURRENT,
        help='Максимальное количество одновременно обрабатываемых каналов.'
    )
    parser.add_argument(
        '--max-dns', type=int, default=DEFAULT_MAX_DNS_CONCURRENT,
        help='Максимальное количество одновременных DNS запросов.'
    )
    parser.add_argument(
        '--max-tests', type=int, default=DEFAULT_MAX_TESTS_CONCURRENT,
        help='Максимальное количество одновременных тестов соединения.'
    )
    parser.add_argument(
        '--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Уровень логирования для консоли.'
    )
    parser.add_argument(
        '--nocolor', action='store_true',
        help='Отключить цветной вывод логов в консоли.'
    )
    parser.add_argument(
        '--user-agent', type=str, default=DEFAULT_USER_AGENT,
        help='User-Agent для HTTP запросов.'
    )

    args = parser.parse_args()

    # Проверка зависимостей для форматов
    if args.output_format == OutputFormat.CLASH.value and not YAML_AVAILABLE:
        parser.error(f"Формат вывода '{OutputFormat.CLASH.value}' требует библиотеки PyYAML. Установите: pip install pyyaml")

    return args

# --- Вспомогательные функции ---

@lru_cache(maxsize=2048) # Увеличил кэш для IP
def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли строка валидным IPv4 адресом."""
    if not hostname: return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

async def resolve_address(hostname: str, resolver: aiodns.DNSResolver, timeout: int) -> Optional[str]:
    """
    Асинхронно разрешает hostname в IPv4 адрес.
    Возвращает IP или None при ошибке/таймауте.
    Улучшена обработка ошибок aiodns.
    """
    if is_valid_ipv4(hostname):
        return hostname

    try:
        # Используем asyncio.timeout для контроля общего времени операции
        async with asyncio.timeout(timeout):
            logger.debug(f"Attempting DNS query for {hostname}")
            result = await resolver.query(hostname, 'A') # Запрашиваем только A запись (IPv4)
            if result:
                # Берем первый IP из списка
                resolved_ip = result[0].host
                if is_valid_ipv4(resolved_ip): # Доп. проверка, что вернулся IPv4
                    logger.debug(f"DNS resolved {hostname} to {resolved_ip}")
                    return resolved_ip
                else:
                    # Это не должно происходить при запросе 'A', но на всякий случай
                    logger.warning(f"DNS query for A record of {hostname} returned non-IPv4 address: {resolved_ip}")
                    return None
            else:
                 # resolver.query обычно вызывает исключение, если ничего не найдено,
                 # но если он вернет пустой список - логируем.
                 logger.debug(f"DNS query for {hostname} returned no results.")
                 return None
    except asyncio.TimeoutError:
        logger.debug(f"DNS resolution timeout for {hostname} after {timeout}s")
        return None
    except aiodns.error.DNSError as e:
        # Коды ошибок: 1 (FORMERR), 2 (SERVFAIL), 3 (NXDOMAIN), 4 (NOTIMP), 5 (REFUSED) и т.д.
        error_code = e.args[0] if e.args else "Unknown"
        error_msg = str(e.args[1]) if len(e.args) > 1 else "No details"
        if error_code == aiodns.error.ARES_ENOTFOUND or error_code == 3: # NXDOMAIN
            logger.debug(f"DNS resolution error for {hostname}: Host not found (NXDOMAIN / {error_code})")
        elif error_code == aiodns.error.ARES_ECONNREFUSED or error_code == 5: # REFUSED
             logger.debug(f"DNS resolution error for {hostname}: Connection refused by server (REFUSED / {error_code})")
        elif error_code == aiodns.error.ARES_ETIMEOUT: # Таймаут на уровне C-Ares (редко, т.к. есть asyncio.timeout)
             logger.debug(f"DNS resolution error for {hostname}: Internal timeout (ARES_ETIMEOUT / {error_code})")
        else:
            # Логируем другие ошибки DNS как warning
            logger.warning(f"DNS resolution error for {hostname}: Code={error_code}, Msg='{error_msg}'")
        return None
    except TypeError as e:
        # Иногда aiodns может выбросить TypeError при некорректном hostname
        logger.warning(f"DNS resolution TypeError for hostname '{hostname}': {e}")
        return None
    except Exception as e:
        # Ловим все остальные неожиданные ошибки
        logger.error(f"Unexpected error during DNS resolution for {hostname}: {e}", exc_info=True)
        return None

def assess_proxy_quality(proxy_config: ProxyParsedConfig) -> int:
    """Оценивает качество прокси на основе его параметров."""
    score = 0
    protocol = proxy_config.protocol.lower()
    query_params = proxy_config.query_params

    # Оценка по протоколу
    score += QUALITY_SCORE_WEIGHTS["protocol"].get(protocol, 0)

    # Оценка по шифрованию (security=tls/none)
    security = query_params.get("security", "none").lower()
    score += QUALITY_SCORE_WEIGHTS["security"].get(security, 0)

    # Оценка по транспорту (type=ws/grpc/tcp/udp или transport=...)
    # Ищем 'type', потом 'transport', по умолчанию 'tcp'
    transport = query_params.get("type", query_params.get("transport", "tcp")).lower()
    # Нормализуем 'websocket' к 'ws' для оценки
    if transport == "websocket":
        transport = "ws"
    score += QUALITY_SCORE_WEIGHTS["transport"].get(transport, 0)

    return score

def get_quality_category(score: int) -> str:
    """Возвращает категорию качества по числовому скору."""
    for category, score_range in QUALITY_CATEGORIES.items():
        if score in score_range:
            return category
    # Если скор вне всех диапазонов (например, отрицательный или очень большой)
    if score >= QUALITY_CATEGORIES["High"].stop: return "High"
    if score < QUALITY_CATEGORIES["Low"].start: return "Low"
    return "Unknown" # По умолчанию

def generate_proxy_profile_name(proxy_config: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE] = None) -> str:
    """
    Генерирует информативное имя профиля для прокси.
    Включает протокол, транспорт, шифрование, качество, опционально задержку и исходный remark.
    """
    protocol = proxy_config.protocol.upper()
    # Определяем транспорт
    transport = proxy_config.query_params.get('type', proxy_config.query_params.get('transport', 'tcp')).lower()
    if transport == "websocket": transport = "ws" # Нормализация
    # Определяем шифрование
    security = proxy_config.query_params.get('security', 'none').lower()
    # Получаем категорию качества
    quality_category = get_quality_category(proxy_config.quality_score)

    # Формируем базовое имя
    name_parts = [
        protocol,
        transport,
        security,
        f"Q{proxy_config.quality_score}",
        quality_category,
    ]

    # Добавляем задержку, если тест пройден успешно и задержка есть
    if test_result and test_result.get('status') == 'ok' and isinstance(test_result.get('latency'), (int, float)):
        latency_ms = int(test_result['latency'] * 1000)
        name_parts.append(f"{latency_ms}ms")

    base_name = "-".join(name_parts)

    # Добавляем оригинальный remark, если он был, очистив его
    if proxy_config.remark:
        # Заменяем пробелы и другие потенциально проблемные символы на '_'
        # Оставляем буквы, цифры, дефисы, подчеркивания
        safe_remark = re.sub(r'[^\w\-\_]+', '_', proxy_config.remark).strip('_')
        if safe_remark: # Добавляем только если что-то осталось после очистки
            base_name += f"_{safe_remark}"

    # Ограничиваем общую длину имени (например, для некоторых клиентов)
    max_len = 70 # Немного увеличил лимит
    if len(base_name) > max_len:
        base_name = base_name[:max_len-3] + "..."

    return base_name

# --- Основные функции обработки ---

async def download_proxies_from_channel(
    channel_url: str,
    session: aiohttp.ClientSession,
    http_timeout: int,
    max_retries: int,
    retry_delay_base: float,
    user_agent: str
) -> List[str]:
    """
    Скачивает и декодирует содержимое канала (подписки).
    Обрабатывает Base64 и Plain Text, выполняет повторные попытки.
    Улучшена обработка ошибок и добавлена проверка Content-Type (для логов).
    """
    retries_attempted = 0
    last_exception: Optional[Exception] = None
    headers = {'User-Agent': user_agent}
    session_timeout = aiohttp.ClientTimeout(total=http_timeout)

    while retries_attempted <= max_retries:
        try:
            logger.debug(f"Attempting download from {channel_url} (Attempt {retries_attempted + 1}/{max_retries + 1})")
            async with session.get(channel_url, timeout=session_timeout, headers=headers, allow_redirects=True) as response:
                # Логируем Content-Type, если есть
                content_type = response.headers.get('Content-Type', 'N/A')
                logger.debug(f"Received response from {channel_url}: Status={response.status}, Content-Type='{content_type}'")

                response.raise_for_status() # Проверяем на HTTP ошибки (4xx, 5xx)

                content_bytes = await response.read()
                if not content_bytes or content_bytes.isspace():
                    logger.warning(f"Channel {channel_url} returned empty or whitespace-only response.")
                    # Считаем это ошибкой канала, не повторяем
                    raise EmptyChannelError(f"Channel {channel_url} returned empty response.")

                # --- Попытка декодирования ---
                decoded_text: Optional[str] = None
                decode_method: str = "Unknown"

                # 1. Попытка Base64
                try:
                    # Удаляем пробельные символы перед декодированием
                    base64_bytes_stripped = bytes("".join(content_bytes.decode('latin-1').split()), 'latin-1')
                    # Добавляем padding, если нужен
                    missing_padding = len(base64_bytes_stripped) % 4
                    if missing_padding:
                        base64_bytes_padded = base64_bytes_stripped + b'=' * (4 - missing_padding)
                    else:
                        base64_bytes_padded = base64_bytes_stripped

                    # Декодируем Base64
                    b64_decoded_bytes = base64.b64decode(base64_bytes_padded, validate=True)

                    # Пытаемся декодировать результат как UTF-8
                    decoded_text_from_b64 = b64_decoded_bytes.decode('utf-8')

                    # Проверяем, похож ли результат на список прокси
                    if PROTOCOL_REGEX.search(decoded_text_from_b64):
                        logger.debug(f"Content from {channel_url} successfully decoded as Base64 -> UTF-8.")
                        decoded_text = decoded_text_from_b64
                        decode_method = "Base64 -> UTF-8"
                    else:
                        logger.debug(f"Content from {channel_url} decoded from Base64, but no protocol found. Assuming plain text.")
                        # Не устанавливаем decoded_text, переходим к попытке Plain Text
                except (binascii.Error, ValueError) as e:
                    logger.debug(f"Content from {channel_url} is not valid Base64 ({type(e).__name__}). Assuming plain text.")
                except UnicodeDecodeError as e:
                    logger.warning(f"Content from {channel_url} decoded from Base64, but result is not valid UTF-8: {e}. Assuming plain text.")
                except Exception as e:
                    # Ловим другие ошибки при обработке Base64
                    logger.error(f"Unexpected error during Base64 processing for {channel_url}: {e}", exc_info=True)

                # 2. Попытка Plain Text (если Base64 не удался или не содержал прокси)
                if decoded_text is None:
                    try:
                        logger.debug(f"Attempting to decode content from {channel_url} as plain UTF-8 text.")
                        decoded_text = content_bytes.decode('utf-8')
                        decode_method = "Plain UTF-8"
                        # Дополнительная проверка: если текст был успешно декодирован из Base64, но не содержал прокси,
                        # и теперь он успешно декодирован как UTF-8, но все еще не содержит прокси - это странно.
                        if decode_method == "Base64 -> UTF-8" and not PROTOCOL_REGEX.search(decoded_text):
                             logger.warning(f"Content from {channel_url} decoded as UTF-8, but still no protocol found.")

                    except UnicodeDecodeError:
                        logger.warning(f"UTF-8 decoding failed for {channel_url} (plain text). Attempting with 'replace' errors.")
                        try:
                            decoded_text = content_bytes.decode('utf-8', errors='replace')
                            decode_method = "Plain UTF-8 (with replace)"
                        except Exception as e:
                             logger.error(f"Failed to decode content from {channel_url} even with errors='replace': {e}", exc_info=True)
                             # Считаем это ошибкой канала
                             raise DownloadError(f"Failed to decode content from {channel_url}") from e

                # --- Результат ---
                if decoded_text is not None:
                    logger.info(f"Successfully decoded content from {channel_url} using method: {decode_method}")
                    # Разделяем на строки, убираем пустые строки
                    lines = [line for line in decoded_text.splitlines() if line.strip()]
                    if not lines:
                         logger.warning(f"Channel {channel_url} decoded successfully but contains no non-empty lines.")
                         raise EmptyChannelError(f"Channel {channel_url} has no non-empty lines after decoding.")
                    return lines
                else:
                    # Сюда не должны попасть, если decode с replace не вызвал исключение
                    logger.error(f"Failed to decode content from {channel_url} using any method.")
                    raise DownloadError(f"Failed to decode content from {channel_url}")

        except (aiohttp.ClientResponseError, aiohttp.ClientHttpProxyError, aiohttp.ClientProxyConnectionError) as e:
            # Ошибки HTTP (4xx, 5xx) или ошибки прокси при соединении
            status = e.status if hasattr(e, 'status') else 'N/A'
            logger.warning(f"HTTP/Proxy error getting {channel_url}: Status={status}, Error='{e}'")
            # Не повторяем попытки при явных ошибках клиента/сервера
            last_exception = DownloadError(f"HTTP/Proxy error {status} for {channel_url}") from e
            break # Выходим из цикла ретраев
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError) as e:
            # Ошибки соединения, чтения или таймауты - можно повторить
            logger.warning(f"Connection/Timeout error getting {channel_url} (attempt {retries_attempted+1}/{max_retries+1}): {type(e).__name__}. Retrying...")
            last_exception = e
            # Расчет задержки с джиттером
            retry_delay = retry_delay_base * (2 ** retries_attempted) + random.uniform(-0.5 * retry_delay_base, 0.5 * retry_delay_base)
            retry_delay = max(0.5, retry_delay) # Минимум 0.5 сек
            await asyncio.sleep(retry_delay)
        except EmptyChannelError as e:
            # Канал пуст, нет смысла повторять
            last_exception = e
            break
        except Exception as e:
             # Неожиданные ошибки - логируем и не повторяем
             logger.error(f"Unexpected error downloading/processing {channel_url}: {e}", exc_info=True)
             last_exception = DownloadError(f"Unexpected error for {channel_url}") from e
             break
        retries_attempted += 1

    # Если цикл завершился без успешного скачивания
    if last_exception:
        if retries_attempted > max_retries:
             logger.error(f"Max retries ({max_retries+1}) reached for {channel_url}. Last error: {type(last_exception).__name__}")
             raise DownloadError(f"Max retries reached for {channel_url}") from last_exception
        else:
             # Вышли из цикла из-за не-ретрайбл ошибки
             logger.error(f"Failed to download {channel_url} due to non-retriable error: {type(last_exception).__name__}")
             raise last_exception # Перевыбрасываем исходную ошибку (или обертку DownloadError)
    else:
        # Сюда не должны попасть, если цикл завершился нормально (т.е. был return)
        logger.critical(f"Download loop finished unexpectedly without error/success for {channel_url}")
        raise DownloadError(f"Download failed unexpectedly for {channel_url}")


def parse_proxy_lines(lines: List[str], channel_url: str = "N/A") -> Tuple[List[ProxyParsedConfig], int, int]:
    """
    Парсит строки из канала в объекты ProxyParsedConfig.
    Возвращает список валидных конфигов, количество невалидных и дубликатов (в рамках этого списка).
    """
    parsed_configs: List[ProxyParsedConfig] = []
    # Используем set для отслеживания уникальных конфигов (по hash/eq ProxyParsedConfig) в рамках этого вызова
    processed_configs_hashes: Set[ProxyParsedConfig] = set()
    invalid_url_count = 0
    duplicate_count = 0

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue # Пропускаем комментарии и пустые строки

        parsed_config = ProxyParsedConfig.from_url(line)

        if parsed_config is None:
            # Логирование невалидных строк происходит внутри from_url на уровне DEBUG
            invalid_url_count += 1
            continue

        # Проверяем на дубликаты в рамках текущего канала/списка
        if parsed_config in processed_configs_hashes:
            logger.debug(f"Channel '{channel_url}': Skipping duplicate proxy (initial parse): {parsed_config.address}:{parsed_config.port}")
            duplicate_count += 1
            continue

        # Добавляем валидный и уникальный конфиг
        processed_configs_hashes.add(parsed_config)
        parsed_configs.append(parsed_config)

    logger.debug(f"Channel '{channel_url}': Initial parsing yielded {len(parsed_configs)} potentially valid configs. "
                 f"Skipped {invalid_url_count} invalid lines, {duplicate_count} duplicates.")
    return parsed_configs, invalid_url_count, duplicate_count

async def resolve_and_assess_proxies(
    configs: List[ProxyParsedConfig],
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    dns_semaphore: asyncio.Semaphore,
    channel_url: str = "N/A"
) -> Tuple[List[ProxyParsedConfig], int]:
    """
    Асинхронно разрешает адреса прокси (если hostname), оценивает качество
    и выполняет дедупликацию по РЕЗУЛЬТАТУ резолвинга (IP).
    Возвращает список уникальных прокси с оценкой качества и количество ошибок DNS.
    """
    resolved_configs_with_score: List[ProxyParsedConfig] = []
    dns_resolution_failed_count = 0
    # Множество для дедупликации ПОСЛЕ резолвинга (протокол, IP, порт, параметры)
    final_unique_keys: Set[tuple] = set()

    async def resolve_task(config: ProxyParsedConfig) -> Optional[ProxyParsedConfig]:
        nonlocal dns_resolution_failed_count
        resolved_ip: Optional[str] = None
        try:
            async with dns_semaphore: # Ограничиваем конкурентность DNS запросов
                resolved_ip = await resolve_address(config.address, resolver, dns_timeout)
        except Exception as e:
            # Ловим ошибки, которые могли возникнуть в resolve_address или семафоре
            logger.error(f"Unexpected error in resolve_task for {config.address} from {channel_url}: {e}", exc_info=True)
            dns_resolution_failed_count += 1
            return None

        if resolved_ip:
            # Оцениваем качество (не зависит от resolved_ip)
            quality_score = assess_proxy_quality(config)

            # Ключ для финальной дедупликации ПОСЛЕ разрешения DNS.
            final_key = (config.protocol, resolved_ip, config.port, frozenset(config.query_params.items()))

            if final_key not in final_unique_keys:
                final_unique_keys.add(final_key)
                # Возвращаем исходный конфиг, но с добавленным качеством.
                # НЕ меняем config.address на resolved_ip, чтобы сохранить hostname для SNI.
                # resolved_ip использовался только для дедупликации.
                # Используем dataclasses.replace для создания нового объекта с обновленным полем.
                return dataclasses.replace(config, quality_score=quality_score)
            else:
                logger.debug(f"Channel '{channel_url}': Skipping duplicate proxy after DNS resolution: "
                             f"{config.address} -> {resolved_ip} (Port: {config.port}, Proto: {config.protocol})")
                # Считаем это как "неудачу" резолвинга, т.к. прокси отброшен
                dns_resolution_failed_count += 1
                return None # Это дубликат по resolved_ip
        else:
            # DNS не разрешился
            logger.debug(f"Channel '{channel_url}': DNS resolution failed for {config.address}")
            dns_resolution_failed_count += 1
            return None

    # Создаем задачи для всех конфигов
    tasks = [resolve_task(cfg) for cfg in configs]

    # Запускаем задачи с прогресс-баром (если tqdm доступен)
    results = await tqdm.gather(
        *tasks,
        desc=f"Resolving DNS ({channel_url.split('/')[-1][:20]}...)", # Краткое имя канала в описании
        unit="proxy",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty() # Отключаем, если нет tqdm или не tty
    )

    # Фильтруем None результаты (ошибки, дубликаты)
    resolved_configs_with_score = [res for res in results if res is not None]

    logger.debug(f"Channel '{channel_url}': DNS Resolution & Assessment finished. "
                 f"{len(resolved_configs_with_score)} unique configs resolved and assessed. "
                 f"{dns_resolution_failed_count} DNS failures or post-resolution duplicates.")

    return resolved_configs_with_score, dns_resolution_failed_count

async def test_proxy_connectivity(
    proxy_config: ProxyParsedConfig,
    test_timeout: int,
    test_sni: str,
    test_port: int # Принимаем порт для теста отдельно (хотя обычно он совпадает с proxy_config.port)
) -> TEST_RESULT_TYPE:
    """
    Выполняет базовую проверку соединения с хостом:портом прокси.
    Проверяет TCP соединение и опционально TLS handshake.
    """
    start_time = time.monotonic()
    writer = None
    # Используем оригинальный адрес (может быть IP или hostname) для соединения
    host = proxy_config.address
    # Используем порт из конфига прокси для соединения
    connect_port = proxy_config.port
    # Определяем, нужно ли TLS на основе параметра 'security'
    use_tls = proxy_config.query_params.get('security', 'none').lower() == 'tls'
    # Определяем SNI: используем параметр 'sni', 'host', или test_sni (если адрес - IP)
    sni_host = proxy_config.query_params.get('sni', proxy_config.query_params.get('host'))
    if not sni_host and not is_valid_ipv4(host):
        sni_host = host # Используем сам хост, если он не IP
    elif not sni_host and is_valid_ipv4(host):
        sni_host = test_sni # Используем глобальный test_sni, если адрес - IP и нет явного sni/host

    result: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': 'Unknown error'}

    try:
        logger.debug(f"Testing connection to {host}:{connect_port} (TLS: {use_tls}, SNI: {sni_host or 'N/A'})")
        # Используем asyncio.open_connection с таймаутом
        async with asyncio.timeout(test_timeout):
            reader, writer = await asyncio.open_connection(host, connect_port)

            # Если требуется TLS, выполняем handshake
            if use_tls:
                logger.debug(f"Attempting TLS handshake with {host}:{connect_port} (SNI: {sni_host or 'N/A'})")
                ssl_context = ssl.create_default_context()
                # Проверяем параметр allowInsecure (может быть '1' или 'true')
                allow_insecure = proxy_config.query_params.get('allowInsecure', '0').lower()
                if allow_insecure == '1' or allow_insecure == 'true':
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    logger.debug(f"TLS verification disabled for {host}:{connect_port} due to allowInsecure=True")

                transport = writer.get_extra_info('transport')
                if not transport:
                     raise ProxyTestError("Could not get transport info for TLS handshake")

                loop = asyncio.get_running_loop()
                # Выполняем TLS handshake асинхронно
                # Передаем server_hostname=sni_host, если он определен
                await loop.start_tls(transport, ssl_context, server_hostname=sni_host if sni_host else None)
                logger.debug(f"TLS handshake successful for {host}:{connect_port}")

            # Если дошли сюда, соединение (и TLS, если нужно) успешно
            latency = time.monotonic() - start_time
            logger.debug(f"Connection test OK for {host}:{connect_port}, Latency: {latency:.4f}s")
            result = {'status': 'ok', 'latency': latency, 'error': None}

    except asyncio.TimeoutError:
        logger.debug(f"Connection test TIMEOUT for {host}:{connect_port} after {test_timeout}s")
        result = {'status': 'failed', 'latency': None, 'error': f'Timeout ({test_timeout}s)'}
    except ssl.SSLCertVerificationError as e:
        logger.debug(f"Connection test FAILED for {host}:{connect_port}: TLS Certificate Verification Error: {e.reason}")
        result = {'status': 'failed', 'latency': None, 'error': f"TLS Cert Verify Error: {e.reason}"}
    except ssl.SSLError as e:
        # Другие ошибки SSL/TLS
        logger.debug(f"Connection test FAILED for {host}:{connect_port}: TLS Handshake Error: {e}")
        result = {'status': 'failed', 'latency': None, 'error': f"TLS Handshake Error: {e}"}
    except ConnectionRefusedError:
        logger.debug(f"Connection test FAILED for {host}:{connect_port}: Connection Refused")
        result = {'status': 'failed', 'latency': None, 'error': 'Connection Refused'}
    except OSError as e:
        # Другие ошибки ОС, например, "No route to host", "Network is unreachable"
        logger.debug(f"Connection test FAILED for {host}:{connect_port}: OS Error: {e.strerror} (errno={e.errno})")
        result = {'status': 'failed', 'latency': None, 'error': f"OS Error: {e.strerror}"}
    except ProxyTestError as e:
        # Ошибки, сгенерированные внутри логики теста
        logger.debug(f"Connection test FAILED for {host}:{connect_port}: ProxyTestError: {e}")
        result = {'status': 'failed', 'latency': None, 'error': f"Test Logic Error: {e}"}
    except Exception as e:
        # Ловим все остальные неожиданные ошибки
        logger.error(f"Unexpected error during connection test for {host}:{connect_port}: {e}", exc_info=True)
        result = {'status': 'failed', 'latency': None, 'error': f"Unexpected Error: {type(e).__name__}"}
    finally:
        # Гарантированно закрываем соединение
        if writer:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing writer for {host}:{connect_port}: {e}")

    return result

async def run_proxy_tests(
    proxies: List[ProxyParsedConfig],
    test_timeout: int,
    test_sni: str,
    test_port: int,
    test_semaphore: asyncio.Semaphore
) -> List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]]:
    """
    Асинхронно запускает тесты соединения для списка прокси с ограничением параллелизма.
    Возвращает список кортежей (прокси, результат_теста).
    """
    if not proxies:
        return []

    results_with_proxies: List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]] = []

    async def test_task_wrapper(proxy: ProxyParsedConfig) -> Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]:
        """Обертка для запуска теста с семафором и обработкой ошибок."""
        try:
            async with test_semaphore: # Ограничиваем конкурентность тестов
                result = await test_proxy_connectivity(proxy, test_timeout, test_sni, test_port)
            return proxy, result
        except Exception as e:
            # Ловим ошибки, которые могли возникнуть вне test_proxy_connectivity (например, в семафоре)
            logger.error(f"Critical error in test_task_wrapper for {proxy.address}:{proxy.port}: {e}", exc_info=True)
            # Возвращаем результат с ошибкой
            error_result: TEST_RESULT_TYPE = {'status': 'failed', 'latency': None, 'error': f'Wrapper Error: {type(e).__name__}'}
            return proxy, error_result

    tasks = [test_task_wrapper(p) for p in proxies]

    # Запускаем тесты с прогресс-баром
    results_with_proxies = await tqdm.gather(
        *tasks,
        desc="Testing Proxies",
        unit="proxy",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty()
    )

    # Логируем статистику тестов
    ok_count = sum(1 for _, res in results_with_proxies if res['status'] == 'ok')
    failed_count = len(results_with_proxies) - ok_count
    logger.info(f"Proxy Connectivity Test Results: {ok_count} OK, {failed_count} Failed.")

    return results_with_proxies

# --- Функции сохранения результатов ---

def _proxy_to_clash_dict(proxy_conf: ProxyParsedConfig, test_result: Optional[TEST_RESULT_TYPE]) -> Optional[Dict[str, Any]]:
    """
    Преобразует ProxyParsedConfig в словарь для Clash YAML.
    Улучшен парсинг URL с использованием urlparse.
    """
    clash_proxy: Dict[str, Any] = {}
    params = proxy_conf.query_params
    protocol = proxy_conf.protocol.lower()

    # Используем urlparse для надежного извлечения компонентов
    try:
        # Парсим исходную строку еще раз, т.к. нам нужны user/pass части
        parsed_original_url = urlparse(proxy_conf.config_string)
        # username может содержать UUID, пароль или base64(user:pass)
        url_username = unquote(parsed_original_url.username) if parsed_original_url.username else None
        # password обычно None, если не используется формат user:pass@host
        url_password = unquote(parsed_original_url.password) if parsed_original_url.password else None
    except Exception as e:
        logger.warning(f"Could not re-parse original URL for Clash conversion: {proxy_conf.config_string} - {e}")
        return None

    # --- Базовые поля ---
    clash_proxy['name'] = generate_proxy_profile_name(proxy_conf, test_result)
    clash_proxy['server'] = proxy_conf.address # Используем оригинальный адрес
    clash_proxy['port'] = proxy_conf.port
    clash_proxy['udp'] = True # Включаем UDP по умолчанию для большинства протоколов в Clash

    # --- Специфичные для протокола поля ---
    try:
        if protocol == 'vless':
            clash_proxy['type'] = 'vless'
            if not url_username: raise ValueError("Missing UUID in VLESS URL")
            clash_proxy['uuid'] = url_username
            clash_proxy['tls'] = params.get('security', 'none') == 'tls'
            clash_proxy['network'] = params.get('type', 'tcp') # ws, grpc, tcp
            # Дополнительные параметры VLESS
            if 'flow' in params: clash_proxy['flow'] = params['flow']
            # SNI: используем 'sni', 'host', или оригинальный адрес (если не IP)
            clash_proxy['servername'] = params.get('sni', params.get('host'))
            if not clash_proxy['servername'] and not is_valid_ipv4(proxy_conf.address):
                clash_proxy['servername'] = proxy_conf.address
            # Проверка сертификата
            allow_insecure = params.get('allowInsecure', '0').lower()
            clash_proxy['skip-cert-verify'] = allow_insecure == '1' or allow_insecure == 'true'

            # Опции транспорта
            if clash_proxy['network'] == 'ws':
                ws_host = params.get('host', clash_proxy.get('servername', proxy_conf.address)) # Host для WS заголовка
                clash_proxy['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': ws_host}}
            elif clash_proxy['network'] == 'grpc':
                clash_proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}

        elif protocol == 'trojan':
            clash_proxy['type'] = 'trojan'
            if not url_username: raise ValueError("Missing password in Trojan URL")
            clash_proxy['password'] = url_username
            # Trojan почти всегда TLS, но проверим параметр 'security'
            clash_proxy['tls'] = params.get('security', 'tls') == 'tls'
            # SNI: используем 'sni', 'peer', или оригинальный адрес (если не IP)
            clash_proxy['sni'] = params.get('sni', params.get('peer'))
            if not clash_proxy['sni'] and not is_valid_ipv4(proxy_conf.address):
                clash_proxy['sni'] = proxy_conf.address
            # Проверка сертификата
            allow_insecure = params.get('allowInsecure', '0').lower()
            clash_proxy['skip-cert-verify'] = allow_insecure == '1' or allow_insecure == 'true'
            # Опции транспорта
            network = params.get('type', 'tcp')
            if network == 'ws':
                 clash_proxy['network'] = 'ws'
                 ws_host = params.get('host', clash_proxy.get('sni', proxy_conf.address))
                 clash_proxy['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': ws_host}}
            elif network == 'grpc':
                 clash_proxy['network'] = 'grpc'
                 clash_proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
            # Для TCP network не указывается явно

        elif protocol == 'ss':
            clash_proxy['type'] = 'ss'
            # Парсинг SS URL: userinfo = base64(method:password)
            if not url_username: raise ValueError("Missing user info in SS URL")
            # Декодируем user_info (method:password) из Base64
            user_info_padded = url_username + '=' * (-len(url_username) % 4) # Добавляем padding
            decoded_user = base64.urlsafe_b64decode(user_info_padded).decode('utf-8')
            if ':' not in decoded_user: raise ValueError("Invalid format in decoded SS user info")
            clash_proxy['cipher'], clash_proxy['password'] = decoded_user.split(':', 1)
            # Параметры плагинов (obfs, v2ray-plugin) - требуют доп. парсинга params
            plugin = params.get('plugin', '').lower()
            if plugin.startswith('obfs'):
                clash_proxy['plugin'] = 'obfs'
                obfs_host = params.get('obfs-host', 'www.bing.com') # Стандартное значение
                obfs_type = params.get('obfs', 'http') # http или tls
                clash_proxy['plugin-opts'] = {'mode': obfs_type, 'host': obfs_host}
            # Добавить поддержку v2ray-plugin если нужно

        # Поддержка TUIC, HY2, SSR для Clash требует знания их точной структуры в YAML
        elif protocol in ['tuic', 'hy2', 'ssr']:
             logger.debug(f"Protocol {protocol.upper()} is not fully supported for Clash output yet. Skipping {proxy_conf.address}:{proxy_conf.port}")
             return None
        else:
            # Неизвестный протокол (не должен сюда попасть из-за PROTOCOL_REGEX, но на всякий случай)
            logger.warning(f"Unknown protocol '{protocol}' encountered for Clash conversion. Skipping {proxy_conf.address}:{proxy_conf.port}")
            return None

    except (binascii.Error, ValueError, UnicodeDecodeError, IndexError, KeyError, AttributeError) as e:
        logger.warning(f"Could not parse or convert proxy for Clash: {proxy_conf.config_string} - Error: {type(e).__name__}: {e}")
        return None # Не можем создать конфиг
    except Exception as e:
        logger.error(f"Unexpected error converting proxy to Clash dict: {proxy_conf.config_string} - {e}", exc_info=True)
        return None

    return clash_proxy

def _save_as_text(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в текстовом формате (URL#remark)."""
    count = 0
    lines_to_write = []
    for proxy_conf, test_result in proxies_with_results:
        profile_name = generate_proxy_profile_name(proxy_conf, test_result)
        # Используем config_string (URL без исходного fragment) и добавляем новый remark
        config_line = f"{proxy_conf.config_string}#{profile_name}\n"
        lines_to_write.append(config_line)
        count += 1

    if count == 0: return 0 # Нечего записывать

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines_to_write)
            f.flush() # Гарантируем сброс буфера
        return count
    except IOError as e:
        logger.error(f"IOError saving TEXT proxies to '{file_path}': {e}")
        return 0

def _save_as_json(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в формате JSON списка объектов."""
    count = 0
    output_list = []
    for proxy_conf, test_result in proxies_with_results:
        proxy_dict = asdict(proxy_conf) # Преобразуем dataclass в dict
        # Добавляем результат теста, если он есть
        if test_result:
            proxy_dict['test_status'] = test_result.get('status')
            proxy_dict['latency_sec'] = test_result.get('latency')
            proxy_dict['test_error'] = test_result.get('error')
        else: # Если тестов не было
            proxy_dict['test_status'] = None
            proxy_dict['latency_sec'] = None
            proxy_dict['test_error'] = None
        output_list.append(proxy_dict)
        count += 1

    if count == 0: return 0

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output_list, f, indent=2, ensure_ascii=False)
            f.flush()
        return count
    except IOError as e:
        logger.error(f"IOError saving JSON proxies to '{file_path}': {e}")
        return 0
    except TypeError as e:
         logger.error(f"TypeError saving JSON proxies to '{file_path}' (serialization issue?): {e}")
         return 0

def _save_as_clash(proxies_with_results: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]], file_path: str) -> int:
    """Сохраняет прокси в формате Clash YAML."""
    if not YAML_AVAILABLE: # Дополнительная проверка
        logger.error("PyYAML is not installed. Cannot save in Clash format.")
        return 0

    count = 0
    clash_proxies_list = []
    for proxy_conf, test_result in proxies_with_results:
        clash_dict = _proxy_to_clash_dict(proxy_conf, test_result)
        if clash_dict:
            clash_proxies_list.append(clash_dict)
            count += 1

    if count == 0:
         logger.warning("No compatible proxies found to generate Clash config.")
         return 0 # Не создаем пустой файл

    # Создаем базовую структуру Clash config
    clash_config = {
        'proxies': clash_proxies_list,
        # Добавляем базовые группы и правила для удобства
        'proxy-groups': [
            {
                'name': 'PROXY', # Имя группы выбора
                'type': 'select', # Тип группы - ручной выбор
                'proxies': [p['name'] for p in clash_proxies_list] + ['DIRECT'] # Список прокси + DIRECT
            },
             {
                 'name': 'Auto-Fastest', # Группа автоматического выбора по скорости
                 'type': 'url-test', # Тип группы - тест скорости
                 'proxies': [p['name'] for p in clash_proxies_list], # Список прокси для теста
                 'url': 'http://www.gstatic.com/generate_204', # URL для теста скорости
                 'interval': 300 # Интервал теста (секунды)
             }
        ],
        'rules': [
            # Примеры правил (можно расширить)
            'DOMAIN-SUFFIX,cn,DIRECT', # Китайские домены напрямую
            'GEOIP,CN,DIRECT', # Китайские IP напрямую
            'MATCH,PROXY' # Все остальное через выбранный прокси
        ]
    }

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            # Используем Dumper с отступами и без якорей/алиасов для лучшей читаемости
            # sort_keys=False сохраняет порядок добавления (важно для proxy-groups)
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=None, indent=2, Dumper=yaml.Dumper)
            f.flush()
        return count
    except IOError as e:
        logger.error(f"IOError writing Clash YAML file '{file_path}': {e}")
        return 0
    except Exception as e: # Ловим ошибки yaml.dump
        logger.error(f"Error writing Clash YAML file '{file_path}': {e}", exc_info=True)
        return 0

# --- Функции оркестрации (ранее часть main) ---

def load_channels(input_file: str) -> List[str]:
    """Загружает список URL каналов из файла."""
    channel_urls: List[str] = []
    logger.info(f"Loading channel URLs from '{input_file}'...")
    try:
        # Используем utf-8-sig для обработки возможного BOM в начале файла
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            for i, line in enumerate(f):
                url = line.strip()
                if url and not url.startswith('#'):
                    # Простая валидация URL
                    if url.startswith(('http://', 'https://')):
                        channel_urls.append(url)
                    else:
                        logger.warning(f"Skipping invalid URL in '{input_file}' (line {i+1}): '{url[:100]}...' (must start with http/https)")
        logger.info(f"Loaded {len(channel_urls)} valid channel URLs.")
    except FileNotFoundError:
        logger.warning(f"Input file '{input_file}' not found. No channels to process.")
        # Опционально: создать пустой файл? Решил не создавать, лучше явная ошибка.
        # try:
        #     os.makedirs(os.path.dirname(input_file) or '.', exist_ok=True)
        #     open(input_file, 'w').close()
        #     logger.info(f"Created empty input file: '{input_file}'")
        # except Exception as e: logger.error(f"Error creating empty input file '{input_file}': {e}")
    except IOError as e:
        logger.error(f"IOError reading input file '{input_file}': {e}")
    except Exception as e:
        logger.error(f"Unexpected error loading channel URLs from '{input_file}': {e}", exc_info=True)

    return channel_urls

@contextlib.asynccontextmanager
async def create_clients(user_agent: str) -> AsyncIterator[Tuple[aiohttp.ClientSession, aiodns.DNSResolver]]:
    """Асинхронный контекстный менеджер для создания и закрытия клиентов."""
    session = None
    resolver = None
    try:
        # Создаем сессию с заголовками по умолчанию
        headers = {'User-Agent': user_agent}
        session = aiohttp.ClientSession(headers=headers)
        # Создаем DNS резолвер
        resolver = aiodns.DNSResolver() # Можно передать nameservers=['8.8.8.8', '1.1.1.1']
        logger.debug("Initialized aiohttp.ClientSession and aiodns.DNSResolver.")
        yield session, resolver
    except Exception as e:
         logger.critical(f"Failed to initialize HTTP/DNS clients: {e}", exc_info=True)
         # Перевыбрасываем, чтобы прервать выполнение
         raise ConfigError(f"Client initialization failed: {e}") from e
    finally:
        # Гарантированно закрываем сессию
        if session:
            await session.close()
            logger.debug("Closed aiohttp.ClientSession.")
        # У aiodns нет явного close метода

async def process_channel_task(
    channel_url: str,
    session: aiohttp.ClientSession,
    resolver: aiodns.DNSResolver,
    args: argparse.Namespace, # Передаем все аргументы для настроек
    dns_semaphore: asyncio.Semaphore
) -> Tuple[str, str, List[ProxyParsedConfig]]:
    """
    Полный цикл обработки одного канала: скачивание, парсинг, резолвинг, оценка.
    Возвращает URL канала, статус ('success', 'empty', 'download_error', 'processing_error') и список прокси.
    """
    status = "processing_error" # Статус по умолчанию
    proxies: List[ProxyParsedConfig] = []
    try:
        # 1. Скачивание и декодирование
        lines = await download_proxies_from_channel(
            channel_url, session, args.http_timeout, args.max_retries, args.retry_delay, args.user_agent
        )
        if not lines: # Это не должно происходить, т.к. download_proxies_from_channel кидает EmptyChannelError
             logger.warning(f"Channel {channel_url} download returned empty list unexpectedly.")
             return channel_url, "empty", []

        # 2. Первичный парсинг строк
        parsed_proxies_basic, _, _ = parse_proxy_lines(lines, channel_url)
        if not parsed_proxies_basic:
            logger.info(f"Channel {channel_url}: No valid proxy formats found after initial parsing.")
            return channel_url, "success", [] # Успешно скачали, но ничего валидного

        # 3. Резолвинг DNS, оценка качества и дедупликация по IP
        resolved_proxies, _ = await resolve_and_assess_proxies(
            parsed_proxies_basic, resolver, args.dns_timeout, dns_semaphore, channel_url
        )
        proxies = resolved_proxies
        status = "success"
        logger.info(f"Channel {channel_url}: Processing finished. Found {len(proxies)} unique & resolved proxies.")

    except EmptyChannelError:
         logger.warning(f"Channel {channel_url} processing stopped: Channel was empty or contained no valid lines.")
         status = "empty"
    except DownloadError as e:
         logger.error(f"Failed to process channel {channel_url} due to download/decode error: {e}")
         status = "download_error"
    except Exception as e:
         logger.error(f"Unexpected error processing channel {channel_url}: {e}", exc_info=True)
         status = "processing_error" # Общая ошибка обработки

    return channel_url, status, proxies


async def run_processing(
    channel_urls: List[str],
    session: aiohttp.ClientSession,
    resolver: aiodns.DNSResolver,
    args: argparse.Namespace # Передаем все аргументы
) -> Tuple[List[ProxyParsedConfig], int, DefaultDict[str, int]]:
    """
    Асинхронно обрабатывает список URL каналов с ограничением параллелизма.
    Выполняет скачивание, парсинг, DNS резолвинг, оценку качества и финальную дедупликацию.
    Возвращает список уникальных прокси, общее количество найденных до дедупликации и статистику по каналам.
    """
    channels_processed_count = 0
    total_proxies_found_before_final_dedup = 0
    channel_status_counts: DefaultDict[str, int] = defaultdict(int)
    # Семафоры для ограничения конкурентности
    channel_semaphore = asyncio.Semaphore(args.max_channels)
    dns_semaphore = asyncio.Semaphore(args.max_dns)
    # Используем set для финальной дедупликации МЕЖДУ каналами (по hash/eq ProxyParsedConfig)
    final_unique_proxies_set: Set[ProxyParsedConfig] = set()

    async def task_wrapper(url: str) -> Optional[Tuple[str, str, List[ProxyParsedConfig]]]:
        """Обертка для задачи обработки канала с семафором и обработкой ошибок."""
        nonlocal channels_processed_count
        async with channel_semaphore: # Ограничиваем конкурентность обработки каналов
            try:
                # Запускаем обработку одного канала
                result = await process_channel_task(url, session, resolver, args, dns_semaphore)
                channels_processed_count += 1
                return result # Возвращаем (url, status, proxies)
            except Exception as e:
                # Ловим критические ошибки в самой обертке (маловероятно)
                logger.critical(f"Critical task failure in wrapper for {url}: {e}", exc_info=True)
                channels_processed_count += 1
                # Возвращаем статус ошибки для статистики
                return url, "critical_wrapper_error", []

    # Создаем задачи для всех URL
    tasks = [task_wrapper(channel_url) for channel_url in channel_urls]

    # Запускаем задачи с прогресс-баром
    channel_results = await tqdm.gather(
        *tasks,
        desc="Processing channels",
        unit="channel",
        disable=not TQDM_AVAILABLE or not sys.stdout.isatty()
    )

    # --- Агрегация результатов ---
    for result in channel_results:
        if result is None: # Ошибка в обертке
            # Статус уже должен был быть записан внутри task_wrapper, но добавим на всякий случай
            channel_status_counts["critical_wrapper_error"] += 1
            continue

        url, status, proxies_from_channel = result
        channel_status_counts[status] += 1 # Обновляем статистику статусов

        if status == "success" and proxies_from_channel:
            # Считаем прокси до финальной дедупликации
            total_proxies_found_before_final_dedup += len(proxies_from_channel)
            # Обновляем set уникальных конфигов (дедупликация по hash/eq ProxyParsedConfig)
            # update добавляет элементы, которых еще нет в set
            final_unique_proxies_set.update(proxies_from_channel)
        # Если статус не success или список пуст, ничего не добавляем в финальный set

    # Преобразуем set в список для дальнейшей обработки
    all_unique_proxies: List[ProxyParsedConfig] = list(final_unique_proxies_set)
    final_unique_count = len(all_unique_proxies)
    logger.info(f"Total unique proxies found after DNS resolution & inter-channel deduplication: {final_unique_count}")

    return all_unique_proxies, total_proxies_found_before_final_dedup, channel_status_counts


async def run_testing(
    proxies: List[ProxyParsedConfig],
    args: argparse.Namespace # Передаем все аргументы
) -> List[Tuple[ProxyParsedConfig, TEST_RESULT_TYPE]]:
    """
    Запускает тестирование прокси, если включено в аргументах.
    Возвращает список кортежей (прокси, результат_теста).
    """
    if not args.test_proxies or not proxies:
        logger.info("Skipping proxy connectivity tests (disabled or no proxies).")
        # Возвращаем список с None в качестве результата теста
        return [(proxy, None) for proxy in proxies]

    logger.info(f"Starting connectivity tests for {len(proxies)} proxies...")
    test_semaphore = asyncio.Semaphore(args.max_tests)
    results_with_tests = await run_proxy_tests(
        proxies, args.test_timeout, args.test_sni, args.test_port, test_semaphore
    )
    return results_with_tests

def filter_and_sort_results(
    results_with_tests: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    test_enabled: bool
) -> List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]]:
    """
    Фильтрует и сортирует результаты.
    Если тесты были включены, оставляет только рабочие ('ok') и сортирует по задержке.
    Если тесты не проводились, сортирует по качеству (quality_score).
    """
    if test_enabled:
        # Фильтруем только рабочие прокси
        working_proxies_with_results = [
            (proxy, result) for proxy, result in results_with_tests
            if result and result.get('status') == 'ok' and isinstance(result.get('latency'), (int, float))
        ]
        # Сортируем рабочие прокси по задержке (возрастание)
        working_proxies_with_results.sort(key=lambda item: item[1]['latency']) # type: ignore
        logger.info(f"Filtered proxies after testing. Kept {len(working_proxies_with_results)} working proxies.")
        return working_proxies_with_results
    else:
        # Если тесты не запускались, сортируем по качеству (убывание)
        # Результат теста у всех будет None
        results_with_tests.sort(key=lambda item: item[0].quality_score, reverse=True)
        logger.info(f"Sorted {len(results_with_tests)} proxies by quality score (testing disabled).")
        return results_with_tests

def save_results(
    proxies_to_save: Sequence[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    output_file_base: str,
    output_format: OutputFormat
) -> Tuple[int, str]:
    """
    Сохраняет отфильтрованный и отсортированный список прокси в указанном формате.
    Возвращает количество сохраненных прокси и полный путь к файлу.
    """
    num_proxies_to_save = len(proxies_to_save)
    if num_proxies_to_save == 0:
        logger.warning("No proxies to save (either none found or all failed tests).")
        # Возвращаем 0 и "пустой" путь, т.к. файл не будет создан
        return 0, f"{output_file_base}.(no_format_empty)"

    # Определяем расширение и функцию сохранения
    if output_format == OutputFormat.JSON:
        file_ext = ".json"
        save_func = _save_as_json
    elif output_format == OutputFormat.CLASH:
        file_ext = ".yaml"
        save_func = _save_as_clash
    else: # По умолчанию TEXT
        file_ext = ".txt"
        save_func = _save_as_text

    # Формируем полный путь к файлу
    file_path = os.path.normpath(output_file_base + file_ext)
    saved_count = 0

    try:
        # Убедимся, что директория существует
        output_dir = os.path.dirname(file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"Created output directory: '{output_dir}'")

        logger.info(f"Attempting to save {num_proxies_to_save} proxies to '{file_path}' (Format: {output_format.value})...")

        # Вызываем соответствующую функцию сохранения
        saved_count = save_func(proxies_to_save, file_path)

        if saved_count > 0:
            logger.info(f"Successfully wrote {saved_count} proxies to '{file_path}'")
            # Дополнительная проверка файла (опционально, но полезно)
            try:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    logger.debug(f"File '{file_path}' exists and is not empty after saving.")
                else:
                    logger.warning(f"File '{file_path}' was reported as saved ({saved_count} proxies), but seems missing or empty.")
            except Exception as e:
                logger.warning(f"Could not verify saved file '{file_path}': {e}")
        elif num_proxies_to_save > 0: # Пытались сохранить, но не вышло (0 записано)
             logger.error(f"Attempted to save {num_proxies_to_save} proxies, but 0 were written to '{file_path}'. Check previous errors.")
        # Если num_proxies_to_save было 0, мы уже вывели warning раньше

    except IOError as e:
        logger.error(f"IOError saving proxies to file '{file_path}': {e}. Check permissions and disk space.", exc_info=True)
        return 0, file_path # Возвращаем 0 и путь, где пытались сохранить
    except Exception as e:
        logger.error(f"Unexpected error saving proxies to file '{file_path}': {e}", exc_info=True)
        return 0, file_path

    return saved_count, file_path # Возвращаем количество и финальный путь

def generate_statistics(
    start_time: float,
    args: argparse.Namespace,
    total_channels_requested: int,
    proxies_after_dns: List[ProxyParsedConfig],
    total_proxies_found_before_dedup: int,
    channel_status_counts: DefaultDict[str, int],
    final_results_to_save: List[Tuple[ProxyParsedConfig, Optional[TEST_RESULT_TYPE]]],
    all_proxies_saved_count: int,
    output_file_path: str
) -> Statistics:
    """Собирает всю статистику выполнения в один объект."""
    proxies_after_dns_count = len(proxies_after_dns)
    proxies_after_test_count: Optional[int] = None
    if args.test_proxies:
        # Считаем количество прокси, которые *пытались* сохранить (т.е. прошли тест)
        proxies_after_test_count = len(final_results_to_save)

    # Сбор статистики по протоколам и качеству для СОХРАНЕННЫХ прокси
    saved_protocol_counts: DefaultDict[str, int] = defaultdict(int)
    saved_quality_category_counts: DefaultDict[str, int] = defaultdict(int)
    if all_proxies_saved_count > 0:
        for proxy, _ in final_results_to_save: # Используем список, который пошел на сохранение
             saved_protocol_counts[proxy.protocol] += 1
             quality_category = get_quality_category(proxy.quality_score)
             saved_quality_category_counts[quality_category] += 1

    # Определяем количество обработанных каналов (сумма всех статусов)
    channels_processed_count = sum(channel_status_counts.values())

    return Statistics(
        start_time=start_time,
        total_channels_requested=total_channels_requested,
        channels_processed_count=channels_processed_count,
        channel_status_counts=channel_status_counts,
        total_proxies_found_before_dedup=total_proxies_found_before_dedup,
        proxies_after_dns_count=proxies_after_dns_count,
        proxies_after_test_count=proxies_after_test_count,
        all_proxies_saved_count=all_proxies_saved_count,
        saved_protocol_counts=saved_protocol_counts,
        saved_quality_category_counts=saved_quality_category_counts,
        output_file_path=output_file_path,
        output_format=OutputFormat(args.output_format)
    )

def display_statistics(stats: Statistics, nocolor: bool = False) -> None:
    """Выводит итоговую статистику выполнения скрипта в консоль."""
    end_time = time.time()
    elapsed_time = end_time - stats.start_time

    # Функция для цветного вывода (если не nocolor)
    def cprint(level: int, message: str):
        if nocolor or not sys.stdout.isatty():
            prefix = f"[{logging.getLevelName(level)}] "
            print(prefix + message, file=sys.stderr if level >= logging.WARNING else sys.stdout)
        else:
            color_start = COLOR_MAP.get(level, COLOR_MAP['RESET'])
            print(f"{color_start}[{logging.getLevelName(level)}]{COLOR_MAP['RESET']} {message}",
                  file=sys.stderr if level >= logging.WARNING else sys.stdout)

    cprint(logging.INFO, "==================== 📊 PROXY DOWNLOAD STATISTICS ====================")
    cprint(logging.INFO, f"⏱️  Script runtime: {elapsed_time:.2f} seconds")
    cprint(logging.INFO, f"🔗 Total channel URLs requested: {stats.total_channels_requested}")
    cprint(logging.INFO, f"🛠️ Total channels processed (attempted): {stats.channels_processed_count}/{stats.total_channels_requested}")

    cprint(logging.INFO, "\n📊 Channel Processing Status:")
    # Определяем порядок и тексты статусов для красивого вывода
    status_order = ["success", "empty", "download_error", "processing_error", "critical_wrapper_error"]
    status_texts = {
        "success": "SUCCESS (processed, found proxies or validly empty)",
        "empty": "EMPTY (downloaded empty or no valid lines)",
        "download_error": "DOWNLOAD/DECODE ERROR",
        "processing_error": "PROCESSING ERROR (after download)",
        "critical_wrapper_error": "CRITICAL TASK ERROR"
    }
    status_levels = { # Уровни для цвета
        "success": logging.INFO,
        "empty": logging.WARNING,
        "download_error": logging.ERROR,
        "processing_error": logging.ERROR,
        "critical_wrapper_error": logging.CRITICAL
    }
    processed_keys = set()
    # Выводим в заданном порядке
    for status_key in status_order:
        if status_key in stats.channel_status_counts:
            count = stats.channel_status_counts[status_key]
            level = status_levels.get(status_key, logging.ERROR)
            status_text = status_texts.get(status_key, status_key.upper())
            cprint(level, f"  - {status_text}: {count} channels")
            processed_keys.add(status_key)
    # Выводим остальные статусы, если вдруг появились новые
    for status_key, count in stats.channel_status_counts.items():
         if status_key not in processed_keys:
             level = status_levels.get(status_key, logging.ERROR)
             status_text = status_texts.get(status_key, status_key.replace('_', ' ').upper())
             cprint(level, f"  - {status_text}: {count} channels")


    cprint(logging.INFO, f"\n✨ Proxies found (before final inter-channel deduplication): {stats.total_proxies_found_before_dedup}")
    cprint(logging.INFO, f"🧬 Proxies after DNS resolution & final deduplication: {stats.proxies_after_dns_count}")
    if stats.proxies_after_test_count is not None:
        cprint(logging.INFO, f"✅ Proxies passed connectivity test: {stats.proxies_after_test_count} / {stats.proxies_after_dns_count}")
    cprint(logging.INFO, f"📝 Total proxies saved: {stats.all_proxies_saved_count} (to '{stats.output_file_path}', format: {stats.output_format.value})")

    # Выводим статистику только если что-то сохранено
    if stats.all_proxies_saved_count > 0:
        cprint(logging.INFO, "\n🔬 Protocol Breakdown (saved proxies):")
        if stats.saved_protocol_counts:
            for protocol, count in sorted(stats.saved_protocol_counts.items()):
                cprint(logging.INFO, f"   - {protocol.upper()}: {count}")
        else:
            cprint(logging.WARNING, "   No protocol statistics available for saved proxies.")

        cprint(logging.INFO, "\n⭐️ Proxy Quality Category Distribution (saved proxies):")
        if stats.saved_quality_category_counts:
             category_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
             # Сортируем по порядку High -> Medium -> Low -> Unknown
             for category, count in sorted(stats.saved_quality_category_counts.items(), key=lambda item: category_order.get(item[0], 99)):
                 cprint(logging.INFO, f"   - {category}: {count} proxies")
        else:
            cprint(logging.WARNING, "   No quality category statistics available for saved proxies.")
    else:
         cprint(logging.WARNING, "\nNo proxies were saved, skipping breakdown statistics.")

    cprint(logging.INFO, "======================== 🏁 STATISTICS END =========================")


# --- Главная функция ---
async def amain() -> int: # Возвращает код выхода
    """Основная асинхронная функция запуска скрипта."""
    start_time = time.time()
    args = parse_arguments()
    setup_logging(
        log_level=getattr(logging, args.log_level),
        log_file=LOG_FILE, # Пока используем константу, можно добавить аргумент --log-file
        nocolor=args.nocolor
    )

    logger.info("🚀 Starting Proxy Downloader Script...")
    logger.debug(f"Parsed arguments: {args}")

    # 1. Загрузка URL каналов
    channel_urls = load_channels(args.input)
    total_channels_requested = len(channel_urls)
    if not channel_urls:
        logger.error("No valid channel URLs loaded. Exiting.")
        return 1 # Код ошибки

    # 2. Инициализация клиентов (HTTP сессия, DNS резолвер)
    try:
        async with create_clients(args.user_agent) as (session, resolver):

            # 3. Обработка каналов (скачивание, парсинг, DNS, оценка, дедупликация)
            proxies_after_dns, total_found_before_dedup, channel_stats = await run_processing(
                channel_urls, session, resolver, args
            )

            # 4. Тестирование (если включено)
            results_with_tests = await run_testing(proxies_after_dns, args)

            # 5. Фильтрация и сортировка результатов
            final_results_to_save = filter_and_sort_results(results_with_tests, args.test_proxies)

            # 6. Сохранение результатов
            saved_count, output_path = save_results(
                final_results_to_save, args.output, OutputFormat(args.output_format)
            )

            # 7. Сбор и вывод статистики
            stats = generate_statistics(
                start_time, args, total_channels_requested,
                proxies_after_dns, total_found_before_dedup, channel_stats,
                final_results_to_save, saved_count, output_path
            )
            display_statistics(stats, args.nocolor)

    except ConfigError as e:
         # Ошибка инициализации клиентов
         logger.critical(f"Configuration error: {e}", exc_info=True)
         return 1 # Код ошибки
    except Exception as e:
        # Ловим все остальные неожиданные ошибки на верхнем уровне
        logger.critical(f"Unexpected critical error during main execution: {e}", exc_info=True)
        return 1 # Код ошибки
    finally:
        logger.info("✅ Proxy download and processing script finished.")

    return 0 # Успешное завершение

# --- Точка входа ---
if __name__ == "__main__":
    # Установка политики цикла событий для Windows (если Proactor нужен для SSL и т.д.)
    # if sys.platform == 'win32' and sys.version_info >= (3, 8):
    #     # ProactorEventLoop может быть нужен для асинхронного SSL в некоторых случаях
    #     # asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    #     # Однако, SelectorEventLoop обычно работает лучше с aiohttp/aiodns
    #     pass # Оставляем стандартный SelectorEventLoop

    exit_code = asyncio.run(amain())
    sys.exit(exit_code)
