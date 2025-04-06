import dns.resolver
import concurrent.futures
import logging
from tqdm import tqdm

logger = logging.getLogger(__name__)

# Импортируем список публичных DNS-серверов
from .zone_transfer import PUBLIC_DNS_SERVERS


def check_subdomain(subdomain, domain):
    """Проверяет существование поддомена с помощью DNS-запроса"""
    full_domain = f"{subdomain}.{domain}"

    # Используем кастомный резолвер с публичными DNS-серверами
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = 1.0  # Короткий таймаут для одного запроса
    resolver.lifetime = 2.0  # Общее время жизни запроса

    try:
        resolver.resolve(full_domain, "A")
        return full_domain
    except dns.resolver.NXDOMAIN:
        # Домен точно не существует
        return None
    except dns.resolver.NoAnswer:
        # Нет A-записи, но попробуем другие типы записей
        try:
            resolver.resolve(full_domain, "CNAME")
            return full_domain
        except:
            return None
    except dns.exception.Timeout:
        # При таймауте повторяем запрос с другим сервером
        try:
            # Берем другие DNS-серверы
            backup_servers = PUBLIC_DNS_SERVERS[2:] + PUBLIC_DNS_SERVERS[:2]
            resolver.nameservers = backup_servers
            resolver.resolve(full_domain, "A")
            return full_domain
        except:
            return None
    except Exception as e:
        logger.debug(f"Ошибка при проверке {full_domain}: {e}")
        return None


def load_wordlist(wordlist_file):
    """Загружает список возможных имен поддоменов из файла"""
    try:
        with open(wordlist_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        logger.error(f"Ошибка при чтении файла словаря: {e}")
        return []


def find_subdomains(
    domain, wordlist_file="wordlists/subdomains-top1million-5000.txt", threads=10
):
    """Находит поддомены используя параллельные запросы"""
    found_subdomains = []

    # Загружаем словарь
    wordlist = load_wordlist(wordlist_file)
    if not wordlist:
        logger.error(f"Не удалось загрузить словарь из {wordlist_file}")
        return found_subdomains

    logger.info(
        f"Поиск поддоменов для {domain} с использованием {len(wordlist)} возможных имен..."
    )
    logger.info(
        f"Используем публичные DNS-серверы: {', '.join(PUBLIC_DNS_SERVERS[:3])}..."
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, word, domain): word for word in wordlist
        }

        with tqdm(total=len(wordlist), desc="Проверка поддоменов") as pbar:
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                pbar.update(1)

    logger.info(f"Найдено {len(found_subdomains)} поддоменов методом брутфорса")
    return found_subdomains
