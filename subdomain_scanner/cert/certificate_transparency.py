import requests
import logging
import time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Импортируем список публичных DNS-серверов
from ..dns.zone_transfer import PUBLIC_DNS_SERVERS

logger = logging.getLogger(__name__)


def verify_subdomain(subdomain):
    """Проверяет существование поддомена с помощью DNS-запроса"""
    # Используем кастомный резолвер с публичными DNS-серверами
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = 1.0
    resolver.lifetime = 2.0

    try:
        resolver.resolve(subdomain, "A")
        return True
    except:
        try:
            resolver.resolve(subdomain, "CNAME")
            return True
        except:
            try:
                resolver.resolve(subdomain, "MX")
                return True
            except:
                return False


def search_certificate_transparency(domain):
    """Ищет поддомены через логи прозрачности сертификатов (Certificate Transparency)"""
    logger.info(
        f"Поиск поддоменов через логи прозрачности сертификатов для {domain}..."
    )
    found_subdomains = set()

    # Метод 1: crt.sh
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if "name_value" in entry:
                    names = entry["name_value"].split("\n")
                    for name in names:
                        if domain in name and name.endswith(domain) and name != domain:
                            found_subdomains.add(name)
            logger.info(f"Найдено {len(found_subdomains)} поддоменов через crt.sh")
        else:
            logger.warning(
                f"Ошибка при запросе к crt.sh: статус {response.status_code}"
            )
    except Exception as e:
        logger.error(f"Ошибка при поиске через crt.sh: {e}")

    # Метод 2: Использование Censys.io API (требует API ключ)
    # Заглушка для потенциального использования в будущем

    # Метод 3: Дополнительный источник - CertSpotter
    try:
        response = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                if "dns_names" in cert:
                    for name in cert["dns_names"]:
                        if domain in name and name.endswith(domain) and name != domain:
                            found_subdomains.add(name)
            logger.info(f"Найдено {len(found_subdomains)} поддоменов через CertSpotter")
        else:
            logger.warning(
                f"Ошибка при запросе к CertSpotter: статус {response.status_code}"
            )
    except Exception as e:
        logger.debug(f"Ошибка при поиске через CertSpotter: {e}")

    # Проверяем найденные поддомены через DNS
    logger.info(f"Проверка {len(found_subdomains)} найденных поддоменов через DNS...")

    subdomains_list = list(found_subdomains)
    verified_subdomains = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        # Запускаем проверку в параллельных потоках
        futures = {
            executor.submit(verify_subdomain, subdomain): subdomain
            for subdomain in subdomains_list
        }

        # Отображаем прогресс
        with tqdm(
            total=len(subdomains_list), desc="Проверка поддоменов через DNS"
        ) as pbar:
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        verified_subdomains.append(subdomain)
                except Exception as e:
                    logger.debug(f"Ошибка при проверке {subdomain}: {e}")
                pbar.update(1)

    logger.info(
        f"Подтверждено {len(verified_subdomains)} поддоменов из {len(found_subdomains)}"
    )

    return verified_subdomains
