import dns.resolver
import dns.query
import dns.zone
import logging
import time

logger = logging.getLogger(__name__)

# Публичные DNS-серверы для повышения надежности сканирования
PUBLIC_DNS_SERVERS = [
    # Google DNS
    "8.8.8.8",
    "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    # Яндекс DNS
    "77.88.8.8",
    "77.88.8.1",
]


def try_zone_transfer(domain):
    """Пытается выполнить передачу зоны DNS (Zone Transfer)"""
    logger.info(f"Попытка передачи зоны для {domain}...")
    found_subdomains = []

    # Настраиваем резолвер для использования публичных DNS-серверов
    custom_resolver = dns.resolver.Resolver()
    custom_resolver.nameservers = PUBLIC_DNS_SERVERS
    custom_resolver.timeout = 3.0  # Уменьшаем таймаут до 3 секунд
    custom_resolver.lifetime = 6.0  # Общее время жизни запроса - 6 секунд

    try:
        # Получаем NS-записи для домена через кастомный резолвер
        logger.info(f"Запрос NS-записей для {domain} через публичные DNS-серверы...")
        answers = custom_resolver.resolve(domain, "NS")
        nameservers = [
            (
                rdata.target.to_text()[:-1]
                if rdata.target.to_text().endswith(".")
                else rdata.target.to_text()
            )
            for rdata in answers
        ]

        logger.info(f"Найдены NS-серверы для {domain}: {', '.join(nameservers)}")

        for ns in nameservers:
            logger.info(f"Попытка передачи зоны с {ns}...")
            try:
                # Устанавливаем короткий таймаут для xfr запроса
                # Пытаемся передать зону
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                for name, node in z.nodes.items():
                    name = str(name)
                    if name != "@":
                        found_subdomains.append(f"{name}.{domain}")
                logger.info(f"Успешная передача зоны с {ns}!")
                break  # Если успешно, прерываем цикл
            except dns.exception.FormError:
                logger.debug(f"Сервер {ns} не поддерживает передачу зоны")
            except dns.exception.Timeout:
                logger.debug(f"Таймаут при запросе к {ns}")
            except Exception as e:
                logger.debug(f"Передача зоны с {ns} не удалась: {e}")

    except dns.resolver.NXDOMAIN:
        logger.error(f"Домен {domain} не существует")
    except dns.resolver.NoAnswer:
        logger.error(f"Нет NS-записей для домена {domain}")
    except dns.resolver.Timeout:
        logger.error(f"Таймаут при запросе NS-записей для {domain}")
    except Exception as e:
        logger.error(f"Не удалось получить NS-записи: {e}")

    if found_subdomains:
        logger.info(f"Найдено {len(found_subdomains)} поддоменов через передачу зоны")
    else:
        logger.info("Не найдено поддоменов через передачу зоны")

    return found_subdomains
