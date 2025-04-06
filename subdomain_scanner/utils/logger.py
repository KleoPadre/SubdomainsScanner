import logging
import os
import sys
from datetime import datetime


def setup_logger(log_level=logging.INFO, log_to_file=True):
    """
    Настраивает логгирование для приложения
    """
    # Создадим директорию для логов если её нет
    logs_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs"
    )
    os.makedirs(logs_dir, exist_ok=True)

    # Форматирование логов
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(log_format)

    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Очистим существующие обработчики
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Вывод в консоль
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Вывод в файл
    if log_to_file:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(logs_dir, f"subdomain_scanner_{timestamp}.log")

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)

    return root_logger
