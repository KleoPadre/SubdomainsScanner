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

    # Добавляем специальные префиксы для Facebook и fbcdn.net
    if "facebook.com" in domain or "fbcdn.net" in domain:
        logger.info(f"Добавляем специальные префиксы для {domain}...")
        fb_prefixes = [
            "static",
            "static.xx",
            "scontent",
            "scontent-lhr8-1",
            "scontent-lhr8-2",
            "scontent-fra5-1",
            "scontent-iad3-1",
            "scontent-atl3-1",
            "scontent-dfw5-1",
            "scontent-lga3-1",
            "scontent-lax3-1",
            "scontent-sin6-1",
            "scontent-syd2-1",
            "scontent-nrt1-1",
            "scontent-hkg4-1",
            "scontent-gmp1-1",
            "video",
            "video-lhr8-1",
        ]

        # Добавляем все варианты городов и индексов для scontent
        for city in [
            "lhr",
            "fra",
            "iad",
            "atl",
            "dfw",
            "lga",
            "lax",
            "sin",
            "syd",
            "nrt",
            "hkg",
            "gmp",
        ]:
            for idx in range(1, 10):
                for subidx in range(1, 4):
                    fb_prefixes.append(f"scontent-{city}{idx}-{subidx}")
                    fb_prefixes.append(f"scontent-{city}{idx}-{subidx}.xx")

        # Добавляем префиксы в словарь, если их там нет
        for prefix in fb_prefixes:
            if prefix not in wordlist:
                wordlist.append(prefix)

        logger.info(f"Добавлено {len(fb_prefixes)} специальных префиксов для {domain}")

    # Добавляем специальные префиксы для YouTube/Google
    if (
        "youtube.com" in domain
        or "googlevideo.com" in domain
        or "ggpht.com" in domain
        or "ytimg.com" in domain
    ):
        logger.info(f"Добавляем специальные префиксы для {domain}...")
        yt_prefixes = [
            "yt3",
            "i1",
            "i2",
            "i3",
            "i4",
            "i5",
            "s0",
            "s1",
            "s2",
            "s3",
            "s4",
            "s5",
            "lh1",
            "lh2",
            "lh3",
            "lh4",
            "lh5",
            "lh6",
            "gm1",
            "gm2",
            "gm3",
            "gm4",
            "gm5",
            "geo1",
            "geo2",
            "geo3",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "beacons",
            "redirector",
            "manifest",
            "v1",
            "v2",
            "v3",
            "v4",
            "v5",
            "img",
            "vid",
            "stream",
            "rr1",
            "rr2",
            "rr3",
            "rr4",
            "rr5",
        ]

        # Добавляем варианты с цифрами
        for num in range(1, 21):
            yt_prefixes.append(f"i{num}")
            yt_prefixes.append(f"s{num}")
            yt_prefixes.append(f"r{num}")
            yt_prefixes.append(f"rr{num}")
            yt_prefixes.append(f"v{num}")
            yt_prefixes.append(f"lh{num}")

        # Добавляем префиксы в словарь, если их там нет
        for prefix in yt_prefixes:
            if prefix not in wordlist:
                wordlist.append(prefix)

        logger.info(f"Добавлено {len(yt_prefixes)} специальных префиксов для {domain}")

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
