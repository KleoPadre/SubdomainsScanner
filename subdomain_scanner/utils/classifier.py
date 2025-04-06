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
    r"^video[0-9-]*\.",
    r"^audio[0-9-]*\.",
    r"^stream[0-9-]*\.",
    r"^storage[0-9-]*\.",
    r"^files?[0-9-]*\.",
    # Facebook/fbcdn специфические шаблоны
    r"^scontent-[a-z0-9-]+\.",
    r"^[a-z0-9]+\.xx\.",
    r"^[a-z0-9]+\.xy\.",
    r"^[a-z0-9]+\.xz\.",
    r"^[a-z0-9]+\.fbcdn\.",
    r"^scontent-[a-z]+[0-9]-[0-9]+\.",
    r"^static\.xx\.",
    r"^scontent-[a-z]+[0-9]-[0-9]+\.xx\.",  # Для шаблонов типа scontent-lhr8-2.xx.fbcdn.net
    r"^[a-z][0-9]?\.ak\.",
    r"^[a-z]?[0-9]{1,3}\.",
    r"^star[0-9]*\.",
    r"^[a-z]?-[a-z][0-9]+\.",
    r"^edge-[a-z0-9-]+\.",
    r"^graph\.",
    r"^connect\.",
    # Серверы баз данных
    r"^db[0-9-]*\.",
    r"^database[0-9-]*\.",
    r"^sql[0-9-]*\.",
    r"^mysql[0-9-]*\.",
    r"^postgres[0-9-]*\.",
    r"^mongo[0-9-]*\.",
    r"^redis[0-9-]*\.",
    r"^nosql[0-9-]*\.",
    r"^cassandra[0-9-]*\.",
    r"^elastic[0-9-]*\.",
    r"^couchdb[0-9-]*\.",
    r"^memcached[0-9-]*\.",
    # Балансировщики и прокси
    r"^lb[0-9-]*\.",
    r"^balancer[0-9-]*\.",
    r"^proxy[0-9-]*\.",
    r"^router[0-9-]*\.",
    r"^gateway[0-9-]*\.",
    r"^edge[0-9-]*\.",
    # Почтовые серверы
    r"^mail[0-9-]*\.",
    r"^smtp[0-9-]*\.",
    r"^pop[0-9-]*\.",
    r"^imap[0-9-]*\.",
    r"^zmail\.",
    r"^relay\.",
    r"^mx[0-9]*\.",
    r"^email[0-9-]*\.",
    r"^webmail[0-9-]*\.",
    r"^mta[0-9-]*\.",
    # API и вспомогательные серверы
    r"^api[0-9-]*\.",
    r"^ws[0-9-]*\.",
    r"^websocket\.",
    r"^gateway\.",
    r"^auth[0-9-]*\.",
    r"^oauth[0-9-]*\.",
    r"^sso\.",
    r"^rpc\.",
    r"^graphql\.",
    r"^rest[0-9-]*\.",
    # Серверы мониторинга и логов
    r"^monitor\.",
    r"^log[0-9-]*\.",
    r"^stats\.",
    r"^metrics\.",
    r"^kibana\.",
    r"^grafana\.",
    r"^prometheus\.",
    r"^zabbix\.",
    r"^nagios\.",
    r"^sentry\.",
    r"^piwik\.",
    r"^analytics\.",
    # Шардированные серверы
    r".*-shard[0-9]+\.",
    r"^shard[0-9]+\.",
    r"^cluster[0-9]+\.",
    r"^node[0-9]+\.",
    r"^pod[0-9]+\.",
    # Кэширующие серверы
    r"^cache[0-9-]*\.",
    r"^redis\.",
    r"^memcache\.",
    r"^varnish\.",
    r"^cdn-cache\.",
    # Серверы тестирования и разработки
    r"^dev\.",
    r"^test\.",
    r"^staging\.",
    r"^qa\.",
    r"^uat\.",
    r"^beta\.",
    r"^alpha\.",
    r"^sandbox\.",
    r"^demo\.",
    # Другие технические поддомены
    r"^internal\.",
    r"^private\.",
    r"^mgmt\.",
    r"^admin-[a-z0-9]+\.",
    r"^status\.",
    r"^uptime\.",
    r"^health\.",
    r"^debug\.",
    r"^stg\.",
    r"^git\.",
    r"^ci\.",
    r"^jenkins\.",
    r"^build\.",
    r"^deploy\.",
    r"^puppet\.",
    r"^chef\.",
    r"^ansible\.",
    r"^docker\.",
    r"^kube\.",
    r"^k8s\.",
    # IP-подобные субдомены
    r"^[0-9]+\.[0-9]+\.[0-9]+\.",
    r"^ip-[0-9]+-[0-9]+-[0-9]+-[0-9]+\.",
]

# Паттерны для пользовательских поддоменов
USER_PATTERNS = [
    r"^www\.",
    r"^app\.",
    r"^m\.",
    r"^mobile\.",
    r"^www-[a-z0-9]+\.",
    r"^web\.",
    r"^portal\.",
    r"^login\.",
    r"^signup\.",
    r"^register\.",
    r"^account\.",
    r"^accounts\.",
    r"^profile\.",
    r"^user\.",
    r"^shop\.",
    r"^store\.",
    r"^marketplace\.",
    r"^ecommerce\.",
    r"^cart\.",
    r"^checkout\.",
    r"^pay\.",
    r"^payment\.",
    r"^billing\.",
    r"^blog\.",
    r"^news\.",
    r"^events\.",
    r"^press\.",
    r"^media-center\.",
    r"^support\.",
    r"^help\.",
    r"^faq\.",
    r"^kb\.",
    r"^knowledge\.",
    r"^community\.",
    r"^forum\.",
    r"^discuss\.",
    r"^chat\.",
    r"^feedback\.",
    r"^contact\.",
    r"^about\.",
    r"^company\.",
    r"^corporate\.",
    r"^career\.",
    r"^jobs\.",
    r"^status\.",
    r"^docs\.",
    r"^documentation\.",
    r"^learn\.",
    r"^course\.",
    r"^edu\.",
    r"^education\.",
    r"^online\.",
    r"^dashboard\.",
    r"^console\.",
    r"^mail\.",
    r"^webmail\.",
    r"^cloud\.",
    r"^drive\.",
    r"^photos\.",
    r"^games\.",
    r"^play\.",
    r"^music\.",
    r"^video\.",
    r"^tv\.",
    r"^watch\.",
    r"^social\.",
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

    # Первый проход - быстрая классификация по шаблонам имен
    user_subdomains = []
    technical_subdomains = []
    unknown_subdomains = []

    for subdomain in subdomains:
        if is_technical_subdomain(subdomain):
            technical_subdomains.append(subdomain)
        elif is_user_subdomain(subdomain):
            user_subdomains.append(subdomain)
        else:
            unknown_subdomains.append(subdomain)

    logger.info(
        f"Предварительная классификация: {len(user_subdomains)} пользовательских, "
        f"{len(technical_subdomains)} технических, {len(unknown_subdomains)} неопределенных"
    )

    # Если есть неопределенные поддомены, проверяем их через HTTP и DNS
    if unknown_subdomains:
        logger.info(
            f"Дополнительная проверка для {len(unknown_subdomains)} неопределенных поддоменов..."
        )

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Сначала проверяем HTTP/HTTPS
            http_futures = {
                executor.submit(check_http_response, subdomain): subdomain
                for subdomain in unknown_subdomains
            }

            # Отображаем прогресс
            with tqdm(
                total=len(unknown_subdomains), desc="Проверка HTTP/HTTPS"
            ) as pbar:
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
                                    # Если всё ещё неизвестно, считаем технческим по умолчанию
                                    elif r["classification"] == "unknown":
                                        r["classification"] = "technical"
                                    break
                        except Exception as e:
                            logger.debug(f"Ошибка при DNS проверке {subdomain}: {e}")
                        pbar.update(1)

        # Добавляем результаты неопределенных поддоменов
        for r in results:
            if r["classification"] == "user":
                user_subdomains.append(r["subdomain"])
            else:
                technical_subdomains.append(r["subdomain"])

    logger.info(
        f"Классификация завершена: {len(user_subdomains)} пользовательских, {len(technical_subdomains)} технических"
    )
    return user_subdomains, technical_subdomains
