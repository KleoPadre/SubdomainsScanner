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
    parser.add_argument(
        "-c",
        "--classify",
        action="store_true",
        help="Классифицировать поддомены на пользовательские и технические",
    )
    parser.add_argument(
        "--save-classified",
        action="store_true",
        help="Сохранить классифицированные поддомены в отдельные файлы",
    )
    parser.add_argument(
        "--max-classify",
        type=int,
        default=100,
        help="Максимальное количество поддоменов для классификации (0 = без ограничений)",
    )
    parser.add_argument(
        "--filter",
        help="Фильтр для вывода только поддоменов, содержащих указанную строку",
    )
    parser.add_argument(
        "--no-filter-wildcards",
        action="store_true",
        help="Не фильтровать поддомены со звездочками при сохранении",
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
    print(f"\nРезультаты сканирования:")
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

        # Если указан фильтр, применяем его
        display_subdomains = found_subdomains
        if args.filter:
            filtered_subdomains = [
                s for s in found_subdomains if args.filter.lower() in s.lower()
            ]
            print(
                f"\nПрименен фильтр '{args.filter}': найдено {len(filtered_subdomains)} поддоменов"
            )
            display_subdomains = filtered_subdomains
        else:
            display_count = min(len(found_subdomains), max_display)
            print(
                f"\nПримеры найденных поддоменов (показано {display_count} из {len(found_subdomains)}):"
            )
            display_subdomains = found_subdomains[:display_count]

        # Выводим поддомены
        for subdomain in display_subdomains:
            print(subdomain)

        if len(found_subdomains) > max_display and not args.filter:
            print(f"... и еще {len(found_subdomains) - max_display} поддоменов")

        # Сохранение в файл
        scanner.save_results(args.output, args.no_filter_wildcards)
        print(f"\nРезультаты сохранены в файл: {args.output}")
        if args.no_filter_wildcards:
            print(f"Сохранены все поддомены, включая поддомены со звездочками")
        else:
            print(
                f"Примечание: поддомены со звездочками были отфильтрованы при сохранении"
            )

        # Классификация поддоменов, если указан соответствующий флаг
        if args.classify:
            print("\nКлассификация поддоменов...")
            print("=" * 60)

            # Классифицируем только обычные поддомены (без звездочек)
            # При необходимости ограничиваем количество поддоменов для классификации
            subdomains_to_classify = regular_subdomains
            if (
                args.max_classify > 0
                and len(subdomains_to_classify) > args.max_classify
            ):
                print(
                    f"\nВНИМАНИЕ: Ограничение классификации до {args.max_classify} из {len(subdomains_to_classify)} поддоменов"
                )
                print(
                    f"Для классификации всех поддоменов используйте: --max-classify 0"
                )
                subdomains_to_classify = subdomains_to_classify[: args.max_classify]

            user_subdomains, technical_subdomains = scanner.classify_subdomains(
                args.threads, subdomains_to_classify
            )

            print(f"\nРезультаты классификации:")
            print(f"- Пользовательские поддомены: {len(user_subdomains)}")
            print(f"- Технические поддомены: {len(technical_subdomains)}")

            # Выводим примеры пользовательских поддоменов
            if user_subdomains:
                print("\nПримеры пользовательских поддоменов:")
                for subdomain in user_subdomains[: min(10, len(user_subdomains))]:
                    print(f"  - {subdomain}")
                if len(user_subdomains) > 10:
                    print(f"  ... и еще {len(user_subdomains) - 10}")

            # Выводим примеры технических поддоменов
            if technical_subdomains:
                print("\nПримеры технических поддоменов:")
                for subdomain in technical_subdomains[
                    : min(10, len(technical_subdomains))
                ]:
                    print(f"  - {subdomain}")
                if len(technical_subdomains) > 10:
                    print(f"  ... и еще {len(technical_subdomains) - 10}")

            # Сохраняем классифицированные поддомены в отдельные файлы, если указан флаг
            if args.save_classified:
                # Создаем базовое имя файла на основе выходного файла
                base_output = os.path.splitext(args.output)[0]

                # Сохраняем пользовательские поддомены
                user_output = f"{base_output}_user.txt"
                with open(user_output, "w") as f:
                    for subdomain in sorted(user_subdomains):
                        f.write(f"{subdomain}\n")
                print(f"\nПользовательские поддомены сохранены в: {user_output}")

                # Сохраняем технические поддомены
                tech_output = f"{base_output}_technical.txt"
                with open(tech_output, "w") as f:
                    for subdomain in sorted(technical_subdomains):
                        f.write(f"{subdomain}\n")
                print(f"Технические поддомены сохранены в: {tech_output}")
    else:
        print(f"Поддомены для {args.domain} не найдены.")

    print("\nСканирование завершено.")


if __name__ == "__main__":
    main()
