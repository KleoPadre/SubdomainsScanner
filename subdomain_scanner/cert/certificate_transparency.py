import requests
import logging
import time

logger = logging.getLogger(__name__)


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

    return list(found_subdomains)
