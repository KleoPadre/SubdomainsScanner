import requests
import logging
import time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re
import json

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

    # Метод 4: Facebook Certificate Transparency API для лучшего поиска fbcdn.net и facebook.com поддоменов
    if "facebook.com" in domain or "fbcdn.net" in domain:
        try:
            logger.info(f"Используем специальный источник для {domain}...")
            response = requests.get(
                f"https://developers.facebook.com/tools/ct/search?q=%.{domain}",
                timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                },
            )
            if response.status_code == 200:
                # Парсим результаты из HTML (упрощенно)
                domain_pattern = domain.replace(".", "\\.")
                pattern = r"([a-zA-Z0-9.-]+\." + domain_pattern + r")"
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if match.endswith(domain) and match != domain:
                        found_subdomains.add(match)
                logger.info(
                    f"Найдено {len(found_subdomains)} поддоменов через Facebook CT API"
                )
            else:
                logger.debug(
                    f"Ошибка при запросе к Facebook CT API: статус {response.status_code}"
                )
        except Exception as e:
            logger.debug(f"Ошибка при поиске через Facebook CT API: {e}")

    # Метод 5: Google Certificate Transparency API для лучшего поиска YouTube и Google поддоменов
    if (
        "youtube.com" in domain
        or "googlevideo.com" in domain
        or "ggpht.com" in domain
        or "ytimg.com" in domain
        or "google.com" in domain
    ):
        try:
            logger.info(f"Используем специальный источник для {domain}...")
            response = requests.get(
                f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={domain}",
                timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                },
            )
            if response.status_code == 200:
                # Парсим результаты из ответа
                content = response.text
                if content.startswith(")]}'\n"):
                    content = content[5:]  # Убираем префикс защиты от XSS

                try:
                    # Попытка разобрать JSON
                    data = json.loads(content)
                    if (
                        isinstance(data, list)
                        and len(data) > 1
                        and isinstance(data[1], list)
                    ):
                        for item in data[1]:
                            if isinstance(item, list) and len(item) > 0:
                                hostname = item[1]
                                if (
                                    isinstance(hostname, str)
                                    and hostname.endswith(domain)
                                    and hostname != domain
                                ):
                                    found_subdomains.add(hostname)
                except:
                    # Если не получилось через JSON, используем регулярное выражение
                    domain_pattern = domain.replace(".", "\\.")
                    pattern = r"([a-zA-Z0-9.-]+\." + domain_pattern + r")"
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if match.endswith(domain) and match != domain:
                            found_subdomains.add(match)

                logger.info(
                    f"Найдено {len(found_subdomains)} поддоменов через Google CT API"
                )
            else:
                logger.debug(
                    f"Ошибка при запросе к Google CT API: статус {response.status_code}"
                )
        except Exception as e:
            logger.debug(f"Ошибка при поиске через Google CT API: {e}")

    # Дополнительный метод для googlevideo.com: поиск через YouTube API CDN Endpoint
    if "googlevideo.com" in domain:
        try:
            logger.info(f"Используем специальный источник YouTube CDN для {domain}...")
            # Делаем запросы к известным YouTube API для получения информации о CDN
            video_ids = ["dQw4w9WgXcQ", "9bZkp7q19f0", "jNQXAC9IVRw", "kJQP7kiw5Fk"]

            for video_id in video_ids:
                # Пробуем несколько API эндпоинтов для получения информации о CDN
                urls = [
                    f"https://www.youtube.com/get_video_info?video_id={video_id}",
                    f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={video_id}&format=json",
                    f"https://www.googleapis.com/youtube/v3/videos?part=contentDetails&id={video_id}",
                ]

                for url in urls:
                    try:
                        response = requests.get(
                            url,
                            timeout=5,
                            headers={
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                            },
                        )

                        if response.status_code == 200:
                            # Ищем URL CDN с помощью регулярных выражений
                            content = response.text

                            # Шаблон для поиска googlevideo.com URL
                            googlevideo_pattern = r"https?://r[0-9]+\.sn-[a-z0-9-]+\.googlevideo\.com/[a-zA-Z0-9?=&%_/.-]+"
                            cdn_urls = re.findall(googlevideo_pattern, content)

                            # Извлекаем поддомены из найденных URL
                            for cdn_url in cdn_urls:
                                match = re.search(
                                    r"//([^/]+)\.googlevideo\.com", cdn_url
                                )
                                if match:
                                    subdomain = f"{match.group(1)}.googlevideo.com"
                                    if (
                                        subdomain.endswith(domain)
                                        and subdomain != domain
                                    ):
                                        found_subdomains.add(subdomain)
                    except Exception as e:
                        logger.debug(f"Ошибка при запросе к YouTube API: {e}")

            # Дополнительно пробуем использовать YouTube Embed API
            try:
                response = requests.get(
                    "https://www.youtube.com/embed/dQw4w9WgXcQ",
                    timeout=5,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                    },
                )

                if response.status_code == 200:
                    content = response.text
                    # Шаблон для поиска googlevideo.com URL
                    googlevideo_pattern = r"https?://r[0-9]+\.sn-[a-z0-9-]+\.googlevideo\.com/[a-zA-Z0-9?=&%_/.-]+"
                    cdn_urls = re.findall(googlevideo_pattern, content)

                    for cdn_url in cdn_urls:
                        match = re.search(r"//([^/]+)\.googlevideo\.com", cdn_url)
                        if match:
                            subdomain = f"{match.group(1)}.googlevideo.com"
                            if subdomain.endswith(domain) and subdomain != domain:
                                found_subdomains.add(subdomain)
            except Exception as e:
                logger.debug(f"Ошибка при запросе к YouTube Embed API: {e}")

            logger.info(
                f"Найдено {len(found_subdomains)} поддоменов через YouTube CDN API"
            )
        except Exception as e:
            logger.debug(f"Ошибка при поиске через YouTube CDN API: {e}")

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
