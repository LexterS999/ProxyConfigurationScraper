import asyncio
import aiohttp
import re
import os
import tempfile
import platform
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from collections import defaultdict
import logging
import ipaddress
import io
from enum import Enum
import shutil
import uuid
import zipfile

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(process)s - %(process)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_SCORING_WEIGHTS_FILE = "configs/scoring_weights.json"

class ScoringWeights(Enum):
    """Веса для оценки."""
    PROTOCOL_BASE = 50
    CONFIG_LENGTH = 10
    SECURITY_PARAM = 15
    NUM_SECURITY_PARAMS = 5
    SECURITY_TYPE_TLS = 10
    SECURITY_TYPE_REALITY = 12
    SECURITY_TYPE_NONE = -5
    TRANSPORT_TYPE_TCP = 2
    TRANSPORT_TYPE_WS = 8
    TRANSPORT_TYPE_QUIC = 6
    ENCRYPTION_TYPE_NONE = -5
    ENCRYPTION_TYPE_AUTO = 3
    ENCRYPTION_TYPE_AES_128_GCM = 7
    ENCRYPTION_TYPE_CHACHA20_POLY1305 = 7
    ENCRYPTION_TYPE_ZERO = 2
    SNI_PRESENT = 7
    COMMON_SNI_BONUS = 3
    ALPN_PRESENT = 5
    NUM_ALPN_PROTOCOLS = 2
    PATH_PRESENT = 3
    PATH_COMPLEXITY = 2
    HEADERS_PRESENT = 4
    NUM_HEADERS = 1
    HOST_HEADER = 5
    HOST_SNI_MATCH = 10
    UTLS_PRESENT = 4
    UTLS_VALUE_CHROME = 5
    UTLS_VALUE_FIREFOX = 4
    UTLS_VALUE_IOS = 2
    UTLS_VALUE_SAFARI = 3
    UTLS_VALUE_RANDOMIZED = 7
    UTLS_VALUE_RANDOM = 6
    UDP_SUPPORT = 7
    PORT_80 = 5
    PORT_443 = 10
    PORT_OTHER = 2
    UUID_PRESENT = 5
    UUID_LENGTH = 3
    EARLY_DATA_SUPPORT = 5
    PARAMETER_CONSISTENCY = 12
    IPV6_ADDRESS = -9
    RARITY_BONUS = 4
    HIDDEN_PARAM = 6
    NEW_PARAM = 5
    RESPONSE_TIME = -0.05
    CHANNEL_STABILITY = 20
    BUFFER_SIZE_SMALL = -2
    BUFFER_SIZE_MEDIUM = 3
    BUFFER_SIZE_LARGE = 7
    BUFFER_SIZE_UNLIMITED = 5
    TCP_OPTIMIZATION = 5
    QUIC_PARAM = 3
    STREAM_ENCRYPTION = 6
    CDN_USAGE = 8
    OBFS = 4
    DEBUG_PARAM = -3
    COMMENT = 1
    TROJAN_PASSWORD_PRESENT = 8
    TROJAN_PASSWORD_LENGTH = 5

    @staticmethod
    def load_weights_from_json(file_path: str = DEFAULT_SCORING_WEIGHTS_FILE) -> None:
        """
        Загружает веса для оценки из JSON файла. Если файл не найден,
        используются веса по умолчанию и создается файл по умолчанию.
        Обрабатывает ошибки декодирования JSON и некорректные значения весов.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                weights_data: Dict[str, Any] = json.load(f)

                # Базовая проверка структуры JSON - убедиться, что это словарь
                if not isinstance(weights_data, dict):
                    raise json.JSONDecodeError("Корневой элемент не является объектом JSON", doc=str(weights_data), pos=0)

                for name, value in weights_data.items():
                    try:
                        if name not in ScoringWeights.__members__:
                            logger.warning(f"Неизвестный вес оценки в файле: {name}. Вес игнорируется.")
                            continue
                        current_weight = ScoringWeights[name]
                        if not isinstance(value, (int, float)):
                            raise ValueError(f"Значение веса должно быть числом, получено: {type(value).__name__}")
                        current_weight.value = value
                        logger.debug(f"Загружен вес {name} со значением {value} из файла.")
                    except ValueError as ve:
                        logger.error(f"Некорректное значение веса для {name}: {value}. Используется значение по умолчанию {current_weight.value}. Ошибка: {ve}")
                    except Exception as e:
                        logger.error(f"Неожиданная ошибка при обработке веса {name}: {e}. Используется значение по умолчанию {current_weight.value}.")

        except FileNotFoundError:
            logger.warning(f"Файл весов оценки не найден: {file_path}. Используются значения по умолчанию и создается файл по умолчанию.")
            ScoringWeights._create_default_weights_file(file_path)
        except json.JSONDecodeError as e:
            logger.error(f"Ошибка чтения JSON файла весов: {file_path}. JSONDecodeError: {e}. Используются значения по умолчанию.")
        except Exception as e:
            logger.error(f"Неожиданная ошибка при загрузке весов оценки из {file_path}: {e}. Используются значения по умолчанию.")

    @staticmethod
    def _create_default_weights_file(file_path: str) -> None:
        """Создает файл JSON с весами оценки по умолчанию."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        default_weights = {member.name: member.value for member in ScoringWeights}
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_weights, f, indent=4)
            logger.info(f"Создан файл весов оценки по умолчанию: {file_path}")
        except Exception as e:
            logger.error(f"Ошибка создания файла весов оценки по умолчанию: {e}")

ScoringWeights.load_weights_from_json()

# Конфигурация и константы
MIN_ACCEPTABLE_SCORE = 100.0
MIN_CONFIG_LENGTH = 40
ALLOWED_PROTOCOLS = ["vless://", "tuic://", "hy2://", "trojan://"]
PREFERRED_PROTOCOLS = ["vless://", "trojan://", "tuic://", "hy2://"]
CHECK_USERNAME = True
CHECK_TLS_REALITY = True
CHECK_SNI = True
CHECK_CONNECTION_TYPE = True
MAX_CONCURRENT_CHANNELS = 200
REQUEST_TIMEOUT = 60
HIGH_FREQUENCY_THRESHOLD_HOURS = 12
HIGH_FREQUENCY_THRESHOLD_SECONDS = HIGH_FREQUENCY_THRESHOLD_HOURS * 3600 # Константа для секунд
HIGH_FREQUENCY_BONUS = 3
OUTPUT_CONFIG_FILE = "configs/proxy_configs.txt"
ALL_URLS_FILE = "all_urls.txt"
TEST_URL_FOR_PROXY_CHECK = "http://speed.cloudflare.com"
MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS = 60
CONFIG_LENGTH_NORMALIZATION_FACTOR = 200.0 # Константа для нормализации длины конфигурации


@dataclass
class ChannelMetrics:
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = None

    def __post_init__(self):
        if self.protocol_counts is None:
            self.protocol_counts = defaultdict(int)

class ChannelConfig:
    def __init__(self, url: str, request_timeout: int = REQUEST_TIMEOUT):
        self.url = self._validate_url(url)
        self.metrics = ChannelMetrics()
        self.request_timeout = request_timeout
        self.check_count = 0

    def _validate_url(self, url: str) -> str:
        """Проверяет URL канала."""
        if not url:
            raise ValueError("URL не может быть пустым.")
        if not isinstance(url, str):
            raise ValueError(f"URL должен быть строкой, получено: {type(url).__name__}")
        url = url.strip()
        valid_protocols = ('http://', 'https://', 'trojan://', 'vless://', 'tuic://', 'hy2://') # ssconf removed
        if not any(url.startswith(proto) for proto in valid_protocols):
            detected_protocol = url[:url.find('://') + 3] if '://' in url else url[:10]
            raise ValueError(f"Неверный протокол URL: '{detected_protocol}...'. Ожидается один из: {', '.join(valid_protocols)}.")
        return url

    def calculate_overall_score(self):
        try:
            success_ratio = self._calculate_success_ratio()
            recency_bonus = self._calculate_recency_bonus()
            response_time_penalty = self._calculate_response_time_penalty()

            self.metrics.overall_score = round((success_ratio * ScoringWeights.CHANNEL_STABILITY.value) + recency_bonus + response_time_penalty, 2)
            self.metrics.overall_score = max(0, self.metrics.overall_score)

        except Exception as e:
            logger.error(f"Ошибка при расчете оценки для {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

    def _calculate_success_ratio(self) -> float:
        """Вычисляет коэффициент успешности, обрабатывая возможное деление на ноль."""
        total_checks = self.metrics.success_count + self.metrics.fail_count
        if total_checks == 0:
            return 0.0
        return float(self.metrics.success_count) / total_checks

    def _calculate_recency_bonus(self) -> float:
        """Вычисляет бонус на основе давности последней успешной проверки."""
        if self.metrics.last_success_time:
            time_since_last_success = datetime.now() - self.metrics.last_success_time
            return HIGH_FREQUENCY_BONUS if time_since_last_success.total_seconds() <= HIGH_FREQUENCY_THRESHOLD_SECONDS else 0
        return 0

    def _calculate_response_time_penalty(self) -> float:
        """Вычисляет штраф за время ответа."""
        assert self.metrics.avg_response_time >= 0, "Среднее время ответа не должно быть отрицательным" # Добавлено утверждение
        return self.metrics.avg_response_time * ScoringWeights.RESPONSE_TIME.value if self.metrics.avg_response_time > 0 else 0

    def update_channel_stats(self, success: bool, response_time: float = 0):
        """Обновляет статистику канала после проверки."""
        assert isinstance(success, bool), f"Ожидаемый тип для 'success' - bool, получено {type(success).__name__}" # Улучшено сообщение утверждения
        assert isinstance(response_time, (int, float)), f"Ожидаемый тип для 'response_time' - int или float, получено {type(response_time).__name__}" # Улучшено сообщение утверждения

        if success:
            self.metrics.success_count += 1
            self.metrics.last_success_time = datetime.now()
        else:
            self.metrics.fail_count += 1
        if response_time > 0:
            # Экспоненциальное скользящее среднее с коэффициентом сглаживания 0.3
            if self.metrics.avg_response_time:
                self.metrics.avg_response_time = (self.metrics.avg_response_time * 0.7) + (response_time * 0.3)
            else:
                self.metrics.avg_response_time = response_time
        self.calculate_overall_score()

class ProxyConfig:
    def __init__(self):
        os.makedirs(os.path.dirname(OUTPUT_CONFIG_FILE), exist_ok=True)

        initial_urls = []
        try:
            with open(ALL_URLS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            initial_urls.append(ChannelConfig(url))
                        except ValueError as e:
                            logger.warning(f"Неверный URL в {ALL_URLS_FILE}: {url} - {e}")
        except FileNotFoundError:
            logger.warning(f"Файл URLs не найден: {ALL_URLS_FILE}. Создается пустой файл по адресу: {ALL_URLS_FILE}")
            open(ALL_URLS_FILE, 'w', encoding='utf-8').close()
        except Exception as e:
            logger.error(f"Ошибка чтения {ALL_URLS_FILE}: {e}")

        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.OUTPUT_FILE = OUTPUT_CONFIG_FILE

    def _normalize_url(self, url: str) -> str:
        try:
            if not url:
                raise ValueError("URL не может быть пустым для нормализации.")
            url = url.strip()
            parsed = urlparse(url)
            if not parsed.scheme:
                raise ValueError(f"Отсутствует схема в URL: '{url}'. Ожидается 'http://' или 'https://' или протокол прокси.")
            if not parsed.netloc:
                raise ValueError(f"Отсутствует netloc (домен или IP) в URL: '{url}'.")

            path = parsed.path.rstrip('/')
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"Ошибка нормализации URL для url '{url}': {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        try:
            seen_urls = set()
            unique_configs = []
            duplicates_removed_count = 0
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Неверная конфигурация пропущена при удалении дубликатов: {config}")
                    continue
                try:
                    normalized_url = self._normalize_url(config.url)
                    if normalized_url not in seen_urls:
                        seen_urls.add(normalized_url)
                        unique_configs.append(config)
                    else:
                        duplicates_removed_count += 1
                except Exception:
                    continue
            if duplicates_removed_count > 0:
                logger.info(f"Удалено {duplicates_removed_count} дубликатов URL.")
            if not unique_configs:
                self.save_empty_config_file()
                logger.error("Не найдено действительных источников после удаления дубликатов. Создан пустой файл конфигурации.")
                return []
            return unique_configs
        except Exception as e:
            logger.error(f"Ошибка удаления дубликатов URL: {str(e)}")
            self.save_empty_config_file()
            return []

    def get_channel_configs(self) -> List[ChannelConfig]: # Переименовано из get_enabled_channels
        """Возвращает список конфигураций каналов."""
        return self.SOURCE_URLS

    def save_empty_config_file(self) -> bool:
        try:
            with io.open(OUTPUT_CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения пустого файла конфигурации: {str(e)}")
            return False

def _calculate_config_length_score(config: str) -> float:
    """
    Вычисляет оценку на основе длины строки конфигурации.
    Более длинные конфигурации могут считаться более сложными или многофункциональными.
    """
    return min(ScoringWeights.CONFIG_LENGTH.value, (len(config) / CONFIG_LENGTH_NORMALIZATION_FACTOR) * ScoringWeights.CONFIG_LENGTH.value)

def _calculate_security_score(query: Dict) -> float:
    score = 0
    security_params = query.get('security', [])
    if security_params:
        score += ScoringWeights.SECURITY_PARAM.value
        score += min(ScoringWeights.NUM_SECURITY_PARAMS.value, len(security_params) * (ScoringWeights.NUM_SECURITY_PARAMS.value / 3))
        security_type = security_params[0].lower() if security_params else 'none'
        score += {
            "tls": ScoringWeights.SECURITY_TYPE_TLS.value,
            "reality": ScoringWeights.SECURITY_TYPE_REALITY.value,
            "none": ScoringWeights.SECURITY_TYPE_NONE.value
        }.get(security_type, 0)
    return score

def _calculate_transport_score(query: Dict) -> float:
    transport_type = query.get('type', ['tcp'])[0].lower()
    return {
        "tcp": ScoringWeights.TRANSPORT_TYPE_TCP.value,
        "ws": ScoringWeights.TRANSPORT_TYPE_WS.value,
        "quic": ScoringWeights.TRANSPORT_TYPE_QUIC.value,
    }.get(transport_type, 0)

def _calculate_encryption_score(query: Dict) -> float:
    encryption_type = query.get('encryption', ['none'])[0].lower()
    return {
        "none": ScoringWeights.ENCRYPTION_TYPE_NONE.value,
        "auto": ScoringWeights.ENCRYPTION_TYPE_AUTO.value,
        "aes-128-gcm": ScoringWeights.ENCRYPTION_TYPE_AES_128_GCM.value,
        "chacha20-poly1305": ScoringWeights.ENCRYPTION_TYPE_CHACHA20_POLY1305.value,
        "zero": ScoringWeights.ENCRYPTION_TYPE_ZERO.value
    }.get(encryption_type, 0)

def _calculate_sni_score(query: Dict) -> float:
    score = 0
    sni = query.get('sni', [None])[0]
    if sni:
        score += ScoringWeights.SNI_PRESENT.value
        if sni.endswith(('.com', '.net', '.org', '.info', '.xyz')):
            score += ScoringWeights.COMMON_SNI_BONUS.value
    return score

def _calculate_alpn_score(query: Dict) -> float:
    score = 0
    alpn = query.get('alpn', [None])[0]
    if alpn:
        score += ScoringWeights.ALPN_PRESENT.value
        alpn_protocols = alpn.split(',')
        score += min(ScoringWeights.NUM_ALPN_PROTOCOLS.value, len(alpn_protocols) * (ScoringWeights.NUM_ALPN_PROTOCOLS.value / 2))
    return score

def _calculate_path_score(query: Dict) -> float:
    score = 0
    path = query.get('path', [None])[0]
    if path:
        score += ScoringWeights.PATH_PRESENT.value
        complexity = len(re.findall(r'[^a-zA-Z0-9]', path)) + (len(path) / 10)
        score += min(ScoringWeights.PATH_COMPLEXITY.value, complexity * (ScoringWeights.PATH_COMPLEXITY.value / 5))
    return score

def _calculate_headers_score(query: Dict, sni: Optional[str]) -> float:
    score = 0
    headers = query.get('headers', [None])[0]
    if headers:
        score += ScoringWeights.HEADERS_PRESENT.value
        try:
            headers_dict = dict(item.split(":") for item in headers.split("&"))
            score += min(ScoringWeights.NUM_HEADERS.value, len(headers_dict) * (ScoringWeights.NUM_HEADERS.value / 2))
            host_header = headers_dict.get('Host', None)
            if host_header:
                score += ScoringWeights.HOST_HEADER.value
                if sni and host_header == sni:
                    score += ScoringWeights.HOST_SNI_MATCH.value
        except Exception:
            pass
    return score


def _calculate_tls_fingerprint_score(query: Dict) -> float:
    score = 0
    fp = query.get('fp', [None])[0]
    if fp:
        fingerprint_score = {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value,
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI.value,
            "edge": ScoringWeights.UTLS_VALUE_EDGE.value if hasattr(ScoringWeights, 'UTLS_VALUE_EDGE') else ScoringWeights.UTLS_VALUE_CHROME.value
        }.get(fp.lower(), 0)
        if fingerprint_score is not None:
            score += fingerprint_score
        else:
            score += 0
    return score

def _calculate_utls_score(query: Dict) -> float:
    score = 0
    utls = query.get('utls', [None])[0]
    if utls:
        score += ScoringWeights.UTLS_PRESENT.value
        utls_score = {
            "chrome": ScoringWeights.UTLS_VALUE_CHROME.value,
            "firefox": ScoringWeights.UTLS_VALUE_FIREFOX.value,
            "ios": ScoringWeights.UTLS_VALUE_IOS.value,
            "safari": ScoringWeights.UTLS_VALUE_SAFARI,
            "randomized": ScoringWeights.UTLS_VALUE_RANDOMIZED.value,
            "random": ScoringWeights.UTLS_VALUE_RANDOM.value
        }.get(utls.lower(), 0)
        if utls_score is not None:
            score += utls_score
        else:
            score += 0
    return score

def _calculate_udp_score(protocol: str) -> float:
    return ScoringWeights.UDP_SUPPORT.value if protocol in ("tuic://", "hy2://") else 0

def _calculate_port_score(port: Optional[int]) -> float:
    if port:
        return {
            80: ScoringWeights.PORT_80.value,
            443: ScoringWeights.PORT_443.value
        }.get(port, ScoringWeights.PORT_OTHER.value)
    return 0

def _calculate_uuid_score(parsed: urlparse, query: Dict) -> float:
    score = 0
    uuid_val = parsed.username or query.get('id', [None])[0]
    if uuid_val and parsed.scheme == 'vless':
        score += ScoringWeights.UUID_PRESENT.value
        score += min(ScoringWeights.UUID_LENGTH.value, len(uuid_val) * (ScoringWeights.UUID_LENGTH.value / 36))
    return score

def _calculate_trojan_password_score(parsed: urlparse) -> float:
    score = 0
    password = parsed.password
    if password:
        score += ScoringWeights.TROJAN_PASSWORD_PRESENT.value
        score += min(ScoringWeights.TROJAN_PASSWORD_LENGTH.value, len(password) * (ScoringWeights.TROJAN_PASSWORD_LENGTH.value / 16))
    return score


def _calculate_early_data_score(query: Dict) -> float:
    return ScoringWeights.EARLY_DATA_SUPPORT.value if query.get('earlyData', [None])[0] == "1" else 0

def _calculate_parameter_consistency_score(query: Dict, sni: Optional[str], host_header: Optional[str]) -> float:
    score = 0
    if sni and host_header and sni != host_header:
        score -= (ScoringWeights.PARAMETER_CONSISTENCY.value / 2)
    return score

def _calculate_ipv6_score(parsed: urlparse) -> float:
    return ScoringWeights.IPV6_ADDRESS.value if ":" in parsed.hostname else 0

def _calculate_hidden_param_score(query: Dict) -> float:
    score = 0
    known_params = (
        'security', 'type', 'encryption', 'sni', 'alpn', 'path',
        'headers', 'fp', 'utls',
        'earlyData', 'id', 'bufferSize', 'tcpFastOpen', 'maxIdleTime', 'streamEncryption', 'obfs', 'debug', 'comment'
    )
    for key, value in query.items():
        if key not in known_params:
            score += ScoringWeights.HIDDEN_PARAM.value
            if value and value[0]:
                score += min(ScoringWeights.RARITY_BONUS.value, ScoringWeights.RARITY_BONUS.value / len(value[0]))
    return score

def _calculate_buffer_size_score(query: Dict) -> float:
    score = 0
    buffer_size = query.get('bufferSize', [None])[0]
    if buffer_size:
        buffer_size = buffer_size.lower()
        score_val = {
            "unlimited": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "small": ScoringWeights.BUFFER_SIZE_SMALL.value,
            "medium": ScoringWeights.BUFFER_SIZE_MEDIUM.value,
            "large": ScoringWeights.BUFFER_SIZE_LARGE.value,
            "-1": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
            "0": ScoringWeights.BUFFER_SIZE_UNLIMITED.value,
        }.get(buffer_size, 0)
        if score_val is not None:
            score += score_val
        else:
            score += 0
    return score

def _calculate_tcp_optimization_score(query: Dict) -> float:
    return ScoringWeights.TCP_OPTIMIZATION.value if query.get('tcpFastOpen', [None])[0] == "true" else 0

def _calculate_quic_param_score(query: Dict) -> float:
    return ScoringWeights.QUIC_PARAM.value if query.get('maxIdleTime', [None])[0] else 0


def _calculate_cdn_usage_score(sni: Optional[str]) -> float:
    return ScoringWeights.CDN_USAGE.value if sni and ".cdn." in sni else 0

def _calculate_mtu_size_score(query: Dict) -> float:
    return 0.0

def _calculate_obfs_score(query: Dict) -> float:
    return ScoringWeights.OBFS.value if query.get('obfs', [None])[0] else 0

def _calculate_debug_param_score(query: Dict) -> float:
    return ScoringWeights.DEBUG_PARAM.value if query.get('debug', [None])[0] == "true" else 0

def _calculate_comment_score(query: Dict) -> float:
    return ScoringWeights.COMMENT.value if query.get('comment', [None])[0] else 0

def _calculate_client_compatibility_score(query: Dict) -> float:
    return 0.0

def _calculate_session_resumption_score(query: Dict) -> float:
    return 0.0

def _calculate_fallback_type_score(query: Dict) -> float:
    return 0.0

def _calculate_webtransport_score(query: Dict) -> float:
    return 0.0

def _calculate_security_direct_score(query: Dict) -> float:
    return 0.0

def _calculate_tls_version_score(query: Dict) -> float:
    return 0.0

def _calculate_multiplexing_score(query: Dict) -> float:
    return 0.0


def is_valid_uuid(uuid_string: str) -> bool:
    """Проверяет формат UUID v4 или v6."""
    try:
        uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        try:
            uuid.UUID(uuid_string, version=6) # Рассмотреть, нужен ли v6 или достаточно только v4
            return True
        except ValueError:
            return False

def _compute_protocol_score(protocol: str) -> float:
    """Вычисляет базовую оценку на основе протокола."""
    return ScoringWeights.PROTOCOL_BASE.value

def _compute_config_features_score(query: Dict, config: str) -> float:
    """Вычисляет оценку на основе различных особенностей конфигурации."""
    score = 0.0
    score += _calculate_config_length_score(config)
    score += _calculate_security_score(query)
    score += _calculate_transport_score(query)
    score += _calculate_encryption_score(query)
    score += _calculate_sni_score(query)
    score += _calculate_alpn_score(query)
    score += _calculate_path_score(query)
    sni = query.get('sni', [None])[0]
    score += _calculate_headers_score(query, sni)
    tls_fingerprint_score = _calculate_tls_fingerprint_score(query)
    if tls_fingerprint_score is not None:
        score += tls_fingerprint_score
    utls_score_val = _calculate_utls_score(query)
    if utls_score_val is not None:
        score += utls_score_val
    score += _calculate_udp_score(next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None) or "")
    return score

def _compute_performance_tuning_score(query: Dict) -> float:
    """Вычисляет оценку, связанную с параметрами настройки производительности."""
    score = 0.0
    score += _calculate_early_data_score(query)
    buffer_size_score = _calculate_buffer_size_score(query)
    if buffer_size_score is not None:
        score += buffer_size_score
    tcp_optimization_score = _calculate_tcp_optimization_score(query)
    if tcp_optimization_score is not None:
        score += tcp_optimization_score
    quic_param_score = _calculate_quic_param_score(query)
    if quic_param_score is not None:
        score += quic_param_score
    score += ScoringWeights.STREAM_ENCRYPTION.value # Предполагается, что STREAM_ENCRYPTION относится к производительности/настройке
    score += _calculate_obfs_score(query) # Предполагается, что OBFS относится к производительности/настройке
    return score

def _compute_misc_score_and_penalties(parsed: urlparse, query: Dict, sni: Optional[str], host_header: Optional[str], response_time: float) -> float:
    """Вычисляет различные оценки и штрафы."""
    score = 0.0
    score += _calculate_port_score(parsed.port)
    score += _calculate_uuid_score(parsed, query)
    if parsed.scheme == 'trojan://':
        score += _calculate_trojan_password_score(parsed)
    score += _calculate_parameter_consistency_score(query, sni, host_header)
    score += _calculate_ipv6_score(parsed)
    score += _calculate_hidden_param_score(query)
    score += response_time * ScoringWeights.RESPONSE_TIME.value
    score += _calculate_cdn_usage_score(sni)
    mtu_size_score = _calculate_mtu_size_score(query) # В настоящее время возвращает 0.0
    if mtu_size_score is not None:
        score += mtu_size_score
    score += _calculate_debug_param_score(query)
    score += _calculate_comment_score(query)
    client_compatibility_score = _calculate_client_compatibility_score(query) # В настоящее время возвращает 0.0
    if client_compatibility_score is not None:
        score += client_compatibility_score
    session_resumption_score = _calculate_session_resumption_score(query) # В настоящее время возвращает 0.0
    if session_resumption_score is not None:
        score += session_resumption_score
    fallback_type_score = _calculate_fallback_type_score(query) # В настоящее время возвращает 0.0
    if fallback_type_score is not None:
        score += fallback_type_score
    webtransport_score = _calculate_webtransport_score(query) # В настоящее время возвращает 0.0
    if webtransport_score is not None:
        score += webtransport_score
    security_direct_score = _calculate_security_direct_score(query) # В настоящее время возвращает 0.0
    if security_direct_score is not None:
        score += security_direct_score
    tls_version_score = _calculate_tls_version_score(query) # В настоящее время возвращает 0.0
    if tls_version_score is not None:
        score += tls_version_score
    multiplexing_score = _calculate_multiplexing_score(query) # В настоящее время возвращает 0.0
    if multiplexing_score is not None:
        score += multiplexing_score

    return score


def compute_profile_score(config: str, response_time: float = 0.0) -> float:
    """Вычисляет оценку для заданной конфигурации прокси-профиля, суммируя оценки из разных категорий."""
    score = 0.0
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
    except Exception as e:
        logger.error(f"Ошибка разбора URL {config}: {e}")
        return 0.0

    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return 0.0

    score += _compute_protocol_score(protocol)
    score += _compute_config_features_score(query, config)
    score += _compute_performance_tuning_score(query)

    sni = query.get('sni', [None])[0]
    host_header = None
    headers = query.get('headers', [None])[0]
    if headers:
        try:
            headers_dict = dict(item.split(":") for item in headers.split("&"))
            host_header = headers_dict.get('Host', None)
        except:
            pass

    score += _compute_misc_score_and_penalties(parsed, query, sni, host_header, response_time)

    return round(score, 2)


def generate_custom_name(config: str) -> str:
    """Генерирует пользовательское имя для прокси-профиля из URL конфигурации."""
    protocol = next((p for p in ALLOWED_PROTOCOLS if config.startswith(p)), None)
    if not protocol:
        return "UNKNOWN"

    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)
        name_parts = [protocol.split("://")[0].upper()]

        if parsed.scheme in ("vless"):
            transport_type = query.get("type", ["NONE"])[0].upper()
            security_type = query.get("security", ["NONE"])[0].upper()
            name_parts.append(transport_type)
            name_parts.append(security_type)
        elif parsed.scheme in ("tuic", "hy2"):
            name_parts.append(parsed.scheme.upper()) # Базовое имя протокола для tuic/hy2 пока что
        elif parsed.scheme in ("trojan"):
            transport_type = query.get("type", ["NONE"])[0].upper()
            security_type = query.get("security", ["NONE"])[0].upper()
            name_parts.append(transport_type)
            name_parts.append(security_type)

        return " - ".join(filter(lambda x: x != "NONE" and x, name_parts))
    except Exception as e:
        logger.error(f"Ошибка создания пользовательского имени для {config}: {e}")
        return "UNKNOWN"

def is_valid_ipv4(hostname: str) -> bool:
    """Проверяет, является ли hostname действительным IPv4 адресом."""
    if not hostname:
        return False
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def create_profile_key(config: str, check_username=CHECK_USERNAME, check_tls_reality=CHECK_TLS_REALITY, check_sni=CHECK_SNI, check_connection_type=CHECK_CONNECTION_TYPE) -> str:
    """Создает уникальный ключ для прокси-профиля для идентификации дубликатов, на основе настраиваемых параметров."""
    try:
        parsed = urlparse(config)
        query = parse_qs(parsed.query)

        core_pattern = re.compile(r"^(vless|tuic|hy2|trojan)://.*?@([\w\d\.\:]+):(\d+)") # Более надежное regex для host:port
        match = core_pattern.match(config)

        if match:
            protocol, host_port, port = match.groups()
            host = host_port.split(':')[0] if ':' in host_port else host_port
            key_parts = [
                protocol,
                host,
                port,
            ]

            if check_username or protocol == 'trojan':
                user = parsed.username
                password = parsed.password
                id_value = query.get('id', [None])[0]
                if user:
                    key_parts.append(f"user:{user}")
                elif password and protocol == 'trojan':
                    key_parts.append(f"password:***")
                elif id_value:
                    key_parts.append(f"id:{id_value}")

            if check_tls_reality:
                 key_parts.append(f"security:{query.get('security', [''])[0]}")
                 key_parts.append(f"encryption:{query.get('encryption', [''])[0]}")

            if check_sni:
                key_parts.append(f"sni:{query.get('sni', [''])[0]}")

            if check_connection_type:
                key_parts.append(f"type:{query.get('type', [''])[0]}")

            return "|".join(key_parts)
        else:
            return config

    except Exception as e:
        logger.error(f"Ошибка создания ключа профиля для {config}: {e}")
        raise ValueError(f"Не удалось создать ключ профиля для: {config}. Ошибка: {e}") from e

DUPLICATE_PROFILE_REGEX = re.compile(
    r"^(vless|tuic|hy2|trojan)://(?:.*?@)?([^@/:]+):(\d+)" # Более надежное regex для сопоставления дубликатов
)


async def process_channel(channel: ChannelConfig, session: aiohttp.ClientSession, channel_semaphore: asyncio.Semaphore, existing_profiles_regex: set, proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает один URL канала для извлечения конфигураций прокси."""
    proxies = []
    async with channel_semaphore:
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(channel.url, timeout=channel.request_timeout) as response:
                if response.status != 200:
                    logger.error(f"Канал {channel.url} вернул статус {response.status}: {response.reason}") # Больше деталей об ошибке HTTP
                    channel.check_count += 1
                    channel.update_channel_stats(success=False)
                    return proxies

                text = await response.text()
                end_time = asyncio.get_event_loop().time()
                response_time = end_time - start_time
                logger.info(f"Контент из {channel.url} загружен за {response_time:.2f} секунд")
                channel.update_channel_stats(success=True, response_time=response_time)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Ошибка загрузки из {channel.url}: {type(e).__name__} - {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies
        except Exception as e:
            logger.exception(f"Неожиданная ошибка загрузки из {channel.url}: {e}")
            channel.check_count += 1
            channel.update_channel_stats(success=False)
            return proxies

        lines = text.splitlines()
        valid_configs_from_channel = 0
        for line in lines:
            line = line.strip()
            if len(line) < MIN_CONFIG_LENGTH:
                continue

            if not any(line.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
                continue

            protocol = next((p for p in ALLOWED_PROTOCOLS if line.startswith(p)), None)
            if not protocol:
                continue
            try:
                parsed = urlparse(line)
                hostname = parsed.hostname
                port = parsed.port

                if not hostname or not port:
                    continue
                if not is_valid_ipv4(hostname) and ":" in hostname: # Более надежная проверка IPv6, хотя IPv6 адреса могут быть валидными
                  continue

                profile_id = None
                if protocol == 'vless://':
                    profile_id = parsed.username or parse_qs(parsed.query).get('id', [None])[0]
                elif protocol == 'trojan://':
                    profile_id = parsed.username

                if profile_id:
                    if not is_valid_uuid(profile_id):
                        logger.debug(f"Профиль {line} пропущен из-за неверного формата UUID: {profile_id}")
                        continue

            except ValueError as e:
                logger.debug(f"Ошибка разбора URL {line}: {e}")
                continue

            match = DUPLICATE_PROFILE_REGEX.match(line)
            if match:
                duplicate_key = f"{match.group(1)}://{match.group(2)}:{match.group(3)}"
                if duplicate_key in existing_profiles_regex:
                    continue
                existing_profiles_regex.add(duplicate_key)
            else:
                logger.warning(f"Не удалось создать ключ фильтра дубликатов для: {line}")
                continue

            score = compute_profile_score(line, response_time=channel.metrics.avg_response_time)

            if score > MIN_ACCEPTABLE_SCORE:
                proxies.append({"config": line, "protocol": protocol, "score": score})
                valid_configs_from_channel += 1

        channel.metrics.valid_configs += valid_configs_from_channel
        for p in proxies:
            channel.metrics.protocol_counts[p["protocol"]] += 1
        channel.metrics.unique_configs = len(set(create_profile_key(l["config"]) for l in proxies))

        channel.check_count += 1
        logger.info(f"Канал {channel.url}: Найдено {valid_configs_from_channel} действительных конфигураций.")
        return proxies


async def process_all_channels(channels: List["ChannelConfig"], proxy_config: "ProxyConfig") -> List[Dict]:
    """Обрабатывает все каналы для извлечения и проверки конфигураций прокси."""
    channel_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHANNELS)
    proxies_all: List[Dict] = []
    existing_profiles_regex = set()

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600)) as session:
        tasks = [process_channel(channel, session, channel_semaphore, existing_profiles_regex, proxy_config) for channel in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка при обработке канала: {result}") # Рассмотреть логирование трассировки для подробной информации об ошибке, если необходимо
            else:
                proxies_all.extend(result)

    return proxies_all


async def verify_proxies_availability(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Проверяет доступность прокси с использованием TCP рукопожатия."""
    return await verify_proxies_availability_tcp_handshake(proxies, proxy_config)


async def verify_proxies_availability_tcp_handshake(proxies: List[Dict], proxy_config: "ProxyConfig") -> Tuple[List[Dict], int, int]:
    """Проверяет доступность прокси через TCP рукопожатие с контролем параллелизма."""
    available_proxies_tcp = []
    verified_count_tcp = 0
    non_verified_count_tcp = 0

    logger.info("Начинается проверка доступности прокси через TCP рукопожатие...")

    tcp_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TCP_HANDSHAKE_CHECKS)

    tasks = []
    for proxy_item in proxies:
        config = proxy_item['config']
        parsed_url = urlparse(config)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if hostname and port:
            tasks.append(_verify_proxy_tcp_handshake(hostname, port, tcp_semaphore, proxy_item))
        else:
            non_verified_count_tcp += 1
            logger.warning(f"Не удалось определить хост и порт для прокси {config}. Проверка пропущена.")

    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            is_available, proxy_item = result
            if is_available:
                available_proxies_tcp.append(proxy_item)
                verified_count_tcp += 1
            else:
                non_verified_count_tcp += 1

    logger.info(f"Проверка доступности TCP рукопожатием завершена. Доступно: {len(available_proxies_tcp)} из {len(proxies)} прокси.")
    return available_proxies_tcp, verified_count_tcp, non_verified_count_tcp


async def _verify_proxy_tcp_handshake(hostname: str, port: int, tcp_semaphore: asyncio.Semaphore, proxy_item: Dict) -> Tuple[bool, Dict]:
    """Проверяет доступность TCP сервера с семафором для контроля параллелизма."""
    try:
        async with tcp_semaphore:
            async with asyncio.timeout(5):
                reader, writer = await asyncio.open_connection(hostname, port)
                writer.close()
                await writer.wait_closed()
                logger.debug(f"TCP рукопожатие: Прокси {hostname}:{port} пройдена.")
                return True, proxy_item
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug(f"TCP рукопожатие не удалось для {hostname}:{port}: {type(e).__name__} - {e}")
        return False, proxy_item


def save_final_configs(proxies: List[Dict], output_file: str):
    """Сохраняет окончательные конфигурации прокси в файл вывода, отсортированные по оценке."""
    proxies_sorted = sorted(proxies, key=lambda x: x['score'], reverse=True)

    try:
        with io.open(output_file, 'w', encoding='utf-8', buffering=io.DEFAULT_BUFFER_SIZE) as f:
            f.write("# Окончательные конфигурации прокси (Отсортированы по оценке)\n") # Добавлен заголовок в файл вывода
            f.write("# Минимальная приемлемая оценка: {}\n".format(MIN_ACCEPTABLE_SCORE))
            f.write("# Сгенерировано: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            for proxy in proxies_sorted:
                if proxy['score'] > MIN_ACCEPTABLE_SCORE:
                    config = proxy['config'].split('#')[0].strip()
                    profile_name = generate_custom_name(config)
                    final_line = f"{config}# {profile_name} (Оценка: {proxy['score']:.2f})\n" # Оценка в выводе
                    f.write(final_line)
        logger.info(f"Окончательные конфигурации сохранены в {output_file}")
    except Exception as e:
        logger.error(f"Ошибка сохранения конфигураций: {str(e)}")

def main():
    proxy_config = ProxyConfig()
    channels = proxy_config.get_channel_configs() # Переименован вызов функции

    async def runner():
        proxies = await process_all_channels(channels, proxy_config)
        verified_proxies, verified_count, non_verified_count = await verify_proxies_availability(verified_proxies, proxy_config)
        save_final_configs(verified_proxies, proxy_config.OUTPUT_FILE)

        total_channels = len(channels)
        enabled_channels = sum(1 for channel in channels) # Все каналы считаются 'включенными' после инициализации ProxyConfig
        disabled_channels = total_channels - enabled_channels # В текущей логике всегда будет 0
        total_valid_configs = sum(channel.metrics.valid_configs for channel in channels)
        total_unique_configs = sum(channel.metrics.unique_configs for channel in channels)
        total_successes = sum(channel.metrics.success_count for channel in channels)
        total_fails = sum(channel.metrics.fail_count for channel in channels)
        protocol_stats = defaultdict(int)
        for channel in channels:
            for protocol, count in channel.metrics.protocol_counts.items():
                protocol_stats[protocol] += count

        logger.info("================== СТАТИСТИКА ==================")
        logger.info(f"Всего каналов: {total_channels}")
        logger.info(f"Включено каналов: {enabled_channels}")
        logger.info(f"Отключено каналов: {disabled_channels}") # В текущей логике всегда 0
        logger.info(f"Всего действительных конфигураций: {total_valid_configs}")
        logger.info(f"Всего уникальных конфигураций: {total_unique_configs}")
        logger.info(f"Всего успешных загрузок: {total_successes}")
        logger.info(f"Всего неудачных загрузок: {total_fails}")
        logger.info(f"Прокси прошли проверку: {verified_count}")
        logger.info(f"Прокси не прошли проверку: {non_verified_count}")
        logger.info("Статистика по протоколам:")
        for protocol, count in protocol_stats.items():
            logger.info(f"  {protocol}: {count}")
        logger.info("================== КОНЕЦ СТАТИСТИКИ ==============")

    asyncio.run(runner())

if __name__ == "__main__":
    main()
