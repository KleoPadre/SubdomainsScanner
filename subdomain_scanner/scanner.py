import logging
import os
import asyncio
import aiodns
from .dns import try_zone_transfer, find_subdomains
from .cert import search_certificate_transparency
from .utils import save_results, classify_subdomains

logger = logging.getLogger(__name__)


class SubdomainScanner:
    """Класс для сканирования поддоменов разными методами"""

    def __init__(
        self,
        domain,
        wordlist_path="wordlists/subdomains-top1million-5000.txt",
        threads=10,
    ):
        """
        Инициализирует сканер поддоменов

        Args:
            domain (str): Домен для сканирования
            wordlist_path (str): Путь к файлу словаря
            threads (int): Количество потоков для параллельного сканирования
        """
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.found_subdomains = set()

        # Дополнительные настройки
        self.resolver = aiodns.DNSResolver()

    async def _async_dns_query(self, subdomain):
        """Асинхронный DNS-запрос для дополнительной проверки"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            await self.resolver.query(full_domain, "A")
            return full_domain
        except Exception:
            return None

    def scan_zone_transfer(self):
        """Сканирование с использованием передачи зоны DNS"""
        logger.info(f"Запуск сканирования через передачу зоны для {self.domain}")
        subdomains = try_zone_transfer(self.domain)

        if subdomains:
            logger.info(f"Найдено {len(subdomains)} поддоменов через передачу зоны")
            self.found_subdomains.update(subdomains)
        else:
            logger.info("Через передачу зоны не найдено поддоменов")

    def scan_certificate_transparency(self):
        """Сканирование через логи прозрачности сертификатов"""
        logger.info(f"Запуск сканирования через логи сертификатов для {self.domain}")
        subdomains = search_certificate_transparency(self.domain)

        if subdomains:
            logger.info(f"Найдено {len(subdomains)} поддоменов через логи сертификатов")
            self.found_subdomains.update(subdomains)
        else:
            logger.info("Через логи сертификатов не найдено поддоменов")

    def scan_brute_force(self):
        """Сканирование методом перебора из словаря"""
        logger.info(f"Запуск сканирования перебором для {self.domain}")

        if not os.path.exists(self.wordlist_path):
            logger.error(f"Файл словаря {self.wordlist_path} не найден")
            logger.info(
                "Скачайте словарь или укажите путь к существующему. "
                "Пример: https://github.com/danielmiessler/SecLists/raw/master/"
                "Discovery/DNS/subdomains-top1million-5000.txt"
            )
            return

        subdomains = find_subdomains(self.domain, self.wordlist_path, self.threads)

        if subdomains:
            logger.info(f"Найдено {len(subdomains)} поддоменов методом перебора")
            self.found_subdomains.update(subdomains)
        else:
            logger.info("Методом перебора не найдено поддоменов")

    async def verify_subdomains(self):
        """Дополнительная асинхронная проверка найденных поддоменов"""
        if not self.found_subdomains:
            return

        logger.info(
            f"Дополнительная проверка {len(self.found_subdomains)} найденных поддоменов..."
        )

        tasks = []
        for subdomain in self.found_subdomains:
            # Если это полный домен, извлекаем часть поддомена
            if subdomain.endswith(self.domain):
                subdomain_part = subdomain.replace(f".{self.domain}", "")
                tasks.append(self._async_dns_query(subdomain_part))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        verified_subdomains = set(filter(None, results))

        logger.info(f"Подтверждено {len(verified_subdomains)} поддоменов")
        self.found_subdomains = verified_subdomains

    def scan_all(self):
        """Запускает все методы сканирования"""
        logger.info(f"Запуск полного сканирования поддоменов для {self.domain}")
        total_methods = 3
        successful_methods = 0

        # Метод 1: Zone Transfer
        try:
            self.scan_zone_transfer()
            successful_methods += 1
        except Exception as e:
            logger.error(f"Ошибка при сканировании через Zone Transfer: {e}")
            logger.info("Продолжаем сканирование другими методами...")

        # Метод 2: Сертификаты
        try:
            self.scan_certificate_transparency()
            successful_methods += 1
        except Exception as e:
            logger.error(f"Ошибка при сканировании через Certificate Transparency: {e}")
            logger.info("Продолжаем сканирование другими методами...")

        # Метод 3: Перебор
        try:
            self.scan_brute_force()
            successful_methods += 1
        except Exception as e:
            logger.error(f"Ошибка при сканировании методом перебора: {e}")

        # Статистика по методам сканирования
        logger.info(
            f"Выполнено {successful_methods} из {total_methods} методов сканирования"
        )

        # Дополнительная проверка (опционально)
        # asyncio.run(self.verify_subdomains())

        logger.info(
            f"Сканирование завершено. Всего найдено {len(self.found_subdomains)} поддоменов"
        )
        return sorted(list(self.found_subdomains))

    def save_results(self, output_file, no_filter_wildcards=False):
        """Сохраняет результаты в файл"""
        if not self.found_subdomains:
            logger.warning("Нет данных для сохранения")
            return False

        # Убедимся, что путь к файлу не пустой
        if not output_file:
            logger.error("Не указан путь для сохранения результатов")
            return False

        return save_results(
            sorted(list(self.found_subdomains)), output_file, no_filter_wildcards
        )

    def classify_subdomains(self, max_workers=10, subdomains_list=None):
        """
        Классифицирует найденные поддомены на пользовательские и технические

        Args:
            max_workers (int): Количество параллельных потоков для проверки поддоменов
            subdomains_list (list, optional): Список поддоменов для классификации.
                                              По умолчанию None (используются найденные поддомены)

        Returns:
            tuple: Кортеж из двух списков (пользовательские, технические)
        """
        if subdomains_list is None:
            if not self.found_subdomains:
                logger.warning("Нет поддоменов для классификации")
                return [], []
            subdomains_list = sorted(list(self.found_subdomains))
        else:
            if not subdomains_list:
                logger.warning("Передан пустой список поддоменов для классификации")
                return [], []

        logger.info(f"Запуск классификации для {len(subdomains_list)} поддоменов...")
        return classify_subdomains(subdomains_list, max_workers)
