import logging
import re
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from ..dns.zone_transfer import PUBLIC_DNS_SERVERS

logger = logging.getLogger(__name__)

# Паттерны для технических поддоменов
TECHNICAL_PATTERNS = [
    # CDN и серверы контента
    r"^cdn[0-9-]*\.",
    r"^s[0-9]+\.",
    r"^scontent",
    r"^content[0-9-]*\.",
    r"^static[0-9-]*\.",
    r"^media[0-9-]*\.",
    r"^img[0-9-]*\.",
    r"^image[0-9-]*\.",
    r"^assets[0-9-]*\.",
    # Серверы баз данных
    r"^db[0-9-]*\.",
    r"^database[0-9-]*\.",
    r"^sql[0-9-]*\.",
    r"^mysql[0-9-]*\.",
    r"^postgres[0-9-]*\.",
    r"^mongo[0-9-]*\.",
    # Почтовые серверы
    r"^mail[0-9-]*\.",
    r"^smtp[0-9-]*\.",
    r"^pop[0-9-]*\.",
    r"^imap[0-9-]*\.",
    r"^zmail\.",
    r"^relay\.",
    # API и вспомогательные серверы
    r"^api[0-9-]*\.",
    r"^ws[0-9-]*\.",
    r"^websocket\.",
    r"^gateway\.",
    # Серверы мониторинга и логов
    r"^monitor\.",
    r"^log[0-9-]*\.",
    r"^stats\.",
    r"^metrics\.",
    # Шардированные серверы
    r".*-shard[0-9]+\.",
    r"^shard[0-9]+\.",
    # Кэширующие серверы
    r"^cache[0-9-]*\.",
    r"^redis\.",
    r"^memcache\.",
    # Серверы тестирования и разработки
    r"^dev\.",
    r"^test\.",
    r"^staging\.",
    r"^qa\.",
    r"^uat\.",
    # IP-подобные субдомены
    r"^[0-9]+\.[0-9]+\.[0-9]+\.",
]

# Паттерны для пользовательских поддоменов
USER_PATTERNS = [
    r"^www\.",
    r"^app\.",
    r"^m\.",
    r"^mobile\.",
    r"^login\.",
    r"^account\.",
    r"^shop\.",
    r"^store\.",
    r"^blog\.",
    r"^news\.",
    r"^support\.",
    r"^help\.",
    r"^community\.",
    r"^forum\.",
    r"^docs\.",
    r"^dashboard\.",
]


def is_technical_subdomain(subdomain):
    """Проверяет, является ли поддомен техническим по паттернам в имени"""
    for pattern in TECHNICAL_PATTERNS:
        if re.search(pattern, subdomain, re.IGNORECASE):
            return True
    return False


def is_user_subdomain(subdomain):
    """Проверяет, является ли поддомен пользовательским по паттернам в имени"""
    for pattern in USER_PATTERNS:
        if re.search(pattern, subdomain, re.IGNORECASE):
            return True
    return False


def check_http_response(subdomain):
    """Проверяет ответ по HTTP/HTTPS для определения типа поддомена"""
    result = {
        "subdomain": subdomain,
        "has_website": False,
        "status_code": None,
        "server": None,
        "content_type": None,
        "title": None,
        "classification": "unknown",
    }

    # Пробуем сначала HTTPS, затем HTTP
    for protocol in ["https", "http"]:
        url = f"{protocol}://{subdomain}"
        try:
            response = requests.get(
                url,
                timeout=3,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Subdomain Scanner)"},
            )

            result["has_website"] = True
            result["status_code"] = response.status_code
            result["server"] = response.headers.get("Server")
            result["content_type"] = response.headers.get("Content-Type")

            # Извлекаем title, если есть
            if "text/html" in response.headers.get("Content-Type", ""):
                title_match = re.search(
                    r"<title>(.*?)</title>", response.text, re.IGNORECASE
                )
                if title_match:
                    result["title"] = title_match.group(1).strip()

            # Прерываем цикл, если получили ответ
            break

        except Exception:
            continue

    # Классификация на основе наличия веб-сайта и типа контента
    if result["has_website"]:
        if result["status_code"] == 200:
            if result["content_type"] and "text/html" in result["content_type"]:
                result["classification"] = "user"
            elif result["content_type"] and (
                "image" in result["content_type"]
                or "javascript" in result["content_type"]
                or "css" in result["content_type"]
                or "font" in result["content_type"]
            ):
                result["classification"] = "technical"
            else:
                # Сначала проверяем по имени
                if is_technical_subdomain(subdomain):
                    result["classification"] = "technical"
                elif is_user_subdomain(subdomain):
                    result["classification"] = "user"
        else:
            # Если код не 200, используем паттерны имен
            if is_technical_subdomain(subdomain):
                result["classification"] = "technical"
            elif is_user_subdomain(subdomain):
                result["classification"] = "user"
    else:
        # Если веб-сайт не доступен, используем только паттерны имен
        if is_technical_subdomain(subdomain):
            result["classification"] = "technical"
        elif is_user_subdomain(subdomain):
            result["classification"] = "user"

    return result


def check_dns_records(subdomain):
    """Проверяет DNS-записи для определения типа поддомена"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS[:3]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    result = {
        "subdomain": subdomain,
        "has_a": False,
        "has_cname": False,
        "has_mx": False,
        "has_txt": False,
        "ips": [],
    }

    # Проверяем A запись
    try:
        answers = resolver.resolve(subdomain, "A")
        result["has_a"] = True
        result["ips"] = [rdata.address for rdata in answers]
    except Exception:
        pass

    # Проверяем CNAME запись
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        result["has_cname"] = True
    except Exception:
        pass

    # Проверяем MX запись
    try:
        answers = resolver.resolve(subdomain, "MX")
        result["has_mx"] = True
    except Exception:
        pass

    # Проверяем TXT запись
    try:
        answers = resolver.resolve(subdomain, "TXT")
        result["has_txt"] = True
    except Exception:
        pass

    return result


def classify_subdomains(subdomains, max_workers=10):
    """Классифицирует список поддоменов на пользовательские и технические"""
    if not subdomains:
        return [], []

    logger.info(f"Классификация {len(subdomains)} поддоменов...")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Сначала проверяем HTTP/HTTPS
        http_futures = {
            executor.submit(check_http_response, subdomain): subdomain
            for subdomain in subdomains
        }

        # Отображаем прогресс
        with tqdm(total=len(subdomains), desc="Проверка HTTP/HTTPS") as pbar:
            for future in as_completed(http_futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.debug(
                        f"Ошибка при HTTP проверке {http_futures[future]}: {e}"
                    )
                pbar.update(1)

        # Если после HTTP проверки остались неклассифицированные поддомены,
        # проверяем их DNS записи
        unclassified = [
            r["subdomain"] for r in results if r["classification"] == "unknown"
        ]
        if unclassified:
            logger.info(
                f"Дополнительная проверка DNS для {len(unclassified)} поддоменов..."
            )

            dns_futures = {
                executor.submit(check_dns_records, subdomain): subdomain
                for subdomain in unclassified
            }

            with tqdm(total=len(unclassified), desc="Проверка DNS записей") as pbar:
                for future in as_completed(dns_futures):
                    subdomain = dns_futures[future]
                    try:
                        dns_result = future.result()
                        # Находим соответствующий HTTP результат и обновляем классификацию
                        for r in results:
                            if r["subdomain"] == subdomain:
                                # Если есть MX-запись, это, вероятно, почтовый сервер
                                if dns_result["has_mx"]:
                                    r["classification"] = "technical"
                                # Если нет A или CNAME записи, но есть TXT, это технический поддомен
                                elif (
                                    not dns_result["has_a"]
                                    and not dns_result["has_cname"]
                                    and dns_result["has_txt"]
                                ):
                                    r["classification"] = "technical"
                                # Если всё ещё неизвестно, используем паттерны
                                elif r["classification"] == "unknown":
                                    if is_technical_subdomain(subdomain):
                                        r["classification"] = "technical"
                                    elif is_user_subdomain(subdomain):
                                        r["classification"] = "user"
                                    else:
                                        # Если ничего не помогло, считаем технческим по умолчанию
                                        r["classification"] = "technical"
                                break
                    except Exception as e:
                        logger.debug(f"Ошибка при DNS проверке {subdomain}: {e}")
                    pbar.update(1)

    # Разделяем результаты на пользовательские и технические
    user_subdomains = []
    technical_subdomains = []

    for r in results:
        if r["classification"] == "user":
            user_subdomains.append(r["subdomain"])
        else:
            technical_subdomains.append(r["subdomain"])

    logger.info(
        f"Классификация завершена: {len(user_subdomains)} пользовательских, {len(technical_subdomains)} технических"
    )
    return user_subdomains, technical_subdomains
