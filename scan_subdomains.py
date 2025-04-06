#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from datetime import datetime
from subdomain_scanner.utils import setup_logger, ensure_wordlist_exists
from subdomain_scanner.scanner import SubdomainScanner


def main():
    parser = argparse.ArgumentParser(
        description="Сканер поддоменов - инструмент для обнаружения поддоменов"
    )
    parser.add_argument(
        "domain", nargs="?", help="Домен для сканирования (например, example.com)"
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Путь к файлу словаря для перебора поддоменов",
        default="wordlists/subdomains-top1million-5000.txt",
    )
    parser.add_argument(
        "-t",
        "--threads",
        help="Количество потоков для параллельного поиска",
        type=int,
        default=10,
    )
    parser.add_argument("-o", "--output", help="Файл для сохранения результатов")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Включить подробный вывод"
    )

    args = parser.parse_args()

    # Настраиваем логирование
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level=log_level)

    # Проверяем наличие домена
    if not args.domain:
        # Запрашиваем адрес домена у пользователя
        args.domain = input(
            "Введите домен для сканирования (например, example.com): "
        ).strip()
        if not args.domain:
            logging.error("Домен не указан. Завершение работы.")
            sys.exit(1)

    # Проверяем формат домена
    if "://" in args.domain:
        # Если пользователь ввел URL, извлекаем домен
        try:
            from urllib.parse import urlparse

            parsed = urlparse(args.domain)
            args.domain = parsed.netloc or parsed.path
        except Exception as e:
            logging.error(f"Не удалось разобрать URL: {e}")

    # Удаляем 'www.' если есть
    if args.domain.startswith("www."):
        args.domain = args.domain[4:]

    # Убираем слеш в конце, если есть
    args.domain = args.domain.rstrip("/")

    # Проверяем наличие словаря или скачиваем его
    wordlist_url = "https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt"
    if not os.path.exists(args.wordlist):
        ensure_wordlist_exists(args.wordlist, wordlist_url)

    # Если выходной файл не указан, создаем его в папке finds с именем домена
    if not args.output:
        # Проверяем наличие директории finds, если нет - создаем
        finds_dir = "finds"
        if not os.path.exists(finds_dir):
            os.makedirs(finds_dir)

        # Формируем имя файла на основе домена
        domain_file_name = args.domain.replace(".", "_")
        args.output = f"{finds_dir}/{domain_file_name}.txt"

    # Запускаем сканирование
    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads)

    print(f"\nНачинаем сканирование поддоменов для: {args.domain}")
    print("=" * 60)
    print("Используемые методы:")
    print("- DNS Zone Transfer")
    print("- Certificate Transparency Logs")
    print("- Перебор из словаря")
    print("=" * 60)

    found_subdomains = scanner.scan_all()

    # Вывод результатов
    print("\nРезультаты сканирования:")
    print("=" * 60)

    if found_subdomains:
        # Считаем поддомены со звездочками и без
        wildcard_subdomains = [s for s in found_subdomains if s.startswith("*")]
        regular_subdomains = [s for s in found_subdomains if not s.startswith("*")]

        print(f"Найдено {len(found_subdomains)} поддоменов:")
        print(f"- Обычные поддомены: {len(regular_subdomains)}")
        print(
            f"- Поддомены со звездочками (будут отфильтрованы): {len(wildcard_subdomains)}"
        )

        # Ограничиваем вывод, чтобы терминал не был переполнен
        max_display = 20
        display_count = min(len(found_subdomains), max_display)

        print(
            f"\nПримеры найденных поддоменов (показано {display_count} из {len(found_subdomains)}):"
        )
        for subdomain in found_subdomains[:display_count]:
            print(subdomain)

        if len(found_subdomains) > max_display:
            print(f"... и еще {len(found_subdomains) - max_display} поддоменов")

        # Сохранение в файл
        scanner.save_results(args.output)
        print(f"\nРезультаты сохранены в файл: {args.output}")
        print(f"Примечание: поддомены со звездочками были отфильтрованы при сохранении")
    else:
        print(f"Поддомены для {args.domain} не найдены.")

    print("\nСканирование завершено.")


if __name__ == "__main__":
    main()
