import os
import logging

logger = logging.getLogger(__name__)


def ensure_wordlist_exists(wordlist_path, download_url=None):
    """
    Проверяет существование словаря, при необходимости скачивает по указанному URL
    """
    if os.path.exists(wordlist_path):
        logger.info(f"Словарь найден: {wordlist_path}")
        return True

    if download_url:
        try:
            import requests

            logger.info(f"Скачиваем словарь с {download_url}")
            response = requests.get(download_url)
            if response.status_code == 200:
                os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
                with open(wordlist_path, "w") as f:
                    f.write(response.text)
                logger.info(f"Словарь успешно скачан и сохранен в {wordlist_path}")
                return True
            else:
                logger.error(
                    f"Не удалось скачать словарь. Статус: {response.status_code}"
                )
        except Exception as e:
            logger.error(f"Ошибка при скачивании словаря: {e}")

    logger.error(f"Словарь не найден: {wordlist_path}")
    return False


def save_results(subdomains, output_file, no_filter_wildcards=False):
    """
    Сохраняет результаты в файл, исключая поддомены со звездочками (если no_filter_wildcards=False)

    Args:
        subdomains (list): Список поддоменов для сохранения
        output_file (str): Путь к файлу для сохранения
        no_filter_wildcards (bool): Если True, то поддомены со звездочками не будут отфильтрованы
    """
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Фильтруем поддомены, начинающиеся со звездочки, если не указан флаг no_filter_wildcards
        if no_filter_wildcards:
            filtered_subdomains = subdomains
        else:
            filtered_subdomains = [
                subdomain for subdomain in subdomains if not subdomain.startswith("*")
            ]

        with open(output_file, "w") as f:
            for subdomain in filtered_subdomains:
                f.write(f"{subdomain}\n")

        logger.info(f"Результаты сохранены в файл: {output_file}")
        if no_filter_wildcards:
            logger.info(f"Всего поддоменов: {len(subdomains)}")
        else:
            logger.info(
                f"Всего поддоменов: {len(subdomains)}, после фильтрации: {len(filtered_subdomains)}"
            )
        return True
    except Exception as e:
        logger.error(f"Ошибка при сохранении результатов: {e}")
        return False
