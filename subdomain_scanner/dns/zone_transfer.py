import dns.resolver
import dns.query
import dns.zone
import logging

logger = logging.getLogger(__name__)


def try_zone_transfer(domain):
    """Пытается выполнить передачу зоны DNS (Zone Transfer)"""
    logger.info(f"Попытка передачи зоны для {domain}...")
    found_subdomains = []

    try:
        # Получаем NS-записи для домена
        answers = dns.resolver.resolve(domain, "NS")
        nameservers = [
            (
                rdata.target.to_text()[:-1]
                if rdata.target.to_text().endswith(".")
                else rdata.target.to_text()
            )
            for rdata in answers
        ]

        for ns in nameservers:
            logger.info(f"Попытка передачи зоны с {ns}...")
            try:
                # Пытаемся передать зону
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                for name, node in z.nodes.items():
                    name = str(name)
                    if name != "@":
                        found_subdomains.append(f"{name}.{domain}")
                logger.info(f"Успешная передача зоны с {ns}!")
                break  # Если успешно, прерываем цикл
            except Exception as e:
                logger.debug(f"Передача зоны с {ns} не удалась: {e}")

    except Exception as e:
        logger.error(f"Не удалось получить NS-записи: {e}")

    return found_subdomains
