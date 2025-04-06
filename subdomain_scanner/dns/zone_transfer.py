import dns.resolver
import dns.query
import dns.zone
import logging
import time
import random

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
    # Quad9
    "9.9.9.9",
    "149.112.112.112",
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
]


def try_zone_transfer(domain):
    """Пытается выполнить передачу зоны DNS (Zone Transfer)"""
    logger.info(f"Попытка передачи зоны для {domain}...")
    found_subdomains = []

    # Перемешиваем список DNS-серверов для распределения нагрузки
    dns_servers = PUBLIC_DNS_SERVERS.copy()
    random.shuffle(dns_servers)

    # Настраиваем резолвер для использования публичных DNS-серверов
    custom_resolver = dns.resolver.Resolver()
    custom_resolver.nameservers = dns_servers[:3]  # Начинаем с 3 случайных серверов
    custom_resolver.timeout = 2.0  # Таймаут отдельного запроса
    custom_resolver.lifetime = 4.0  # Общее время жизни запроса

    # Флаг для отслеживания, удалось ли получить NS-записи
    ns_records_retrieved = False
    nameservers = []

    # Делаем несколько попыток с разными DNS-серверами
    for attempt in range(3):
        if attempt > 0:
            logger.info(
                f"Повторная попытка {attempt} получения NS-записей для {domain}..."
            )
            # Меняем DNS-серверы для следующей попытки
            next_servers = dns_servers[3 * (attempt) : 3 * (attempt + 1)]
            if not next_servers:
                next_servers = dns_servers[
                    :3
                ]  # Возвращаемся к первым серверам, если исчерпали список

            custom_resolver.nameservers = next_servers
            logger.info(
                f"Используем DNS-серверы: {', '.join(custom_resolver.nameservers)}"
            )

        try:
            # Получаем NS-записи для домена через кастомный резолвер
            logger.info(
                f"Запрос NS-записей для {domain} через публичные DNS-серверы..."
            )
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
            ns_records_retrieved = True
            break

        except dns.resolver.NXDOMAIN:
            logger.error(f"Домен {domain} не существует")
            return found_subdomains
        except dns.resolver.NoAnswer:
            logger.warning(f"Нет NS-записей для домена {domain}")
            # Продолжаем, возможно другой сервер даст ответ
        except dns.resolver.Timeout:
            logger.warning(
                f"Таймаут при запросе NS-записей для {domain} (попытка {attempt+1})"
            )
            # Продолжаем, возможно другой сервер будет быстрее
        except Exception as e:
            logger.error(f"Не удалось получить NS-записи: {e}")

    # Если не удалось получить NS-записи, пробуем альтернативный подход
    if not ns_records_retrieved or not nameservers:
        logger.warning(
            f"Не удалось получить NS-записи для {domain} через все DNS-серверы"
        )
        # Возвращаем пустой список, основная логика будет использовать другие методы
        return found_subdomains

    # Если получили NS-записи, пробуем выполнить передачу зоны
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

    if found_subdomains:
        logger.info(f"Найдено {len(found_subdomains)} поддоменов через передачу зоны")
    else:
        logger.info("Не найдено поддоменов через передачу зоны")

    return found_subdomains
