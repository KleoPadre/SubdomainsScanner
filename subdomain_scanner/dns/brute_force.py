import dns.resolver
import concurrent.futures
import logging
from tqdm import tqdm

logger = logging.getLogger(__name__)


def check_subdomain(subdomain, domain):
    """Проверяет существование поддомена с помощью DNS-запроса"""
    full_domain = f"{subdomain}.{domain}"
    try:
        dns.resolver.resolve(full_domain, "A")
        return full_domain
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
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

    return found_subdomains
