# Subdomain Scanner

Инструмент для поиска поддоменов с использованием различных методов:
- DNS Zone Transfer
- Certificate Transparency Logs
- Брутфорс из словаря

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/username/subdomain-scanner.git
cd subdomain-scanner

# Установка зависимостей
pip install -r requirements.txt
```

## Использование

```bash
# Базовое использование
python scan_subdomains.py example.com

# С указанием своего словаря
python scan_subdomains.py example.com -w wordlist.txt

# С указанием количества потоков
python scan_subdomains.py example.com -t 20

# С сохранением результатов в файл
python scan_subdomains.py example.com -o results.txt

# С подробным выводом
python scan_subdomains.py example.com -v
```

Если запустить скрипт без указания домена, он запросит его ввод интерактивно:

```bash
python scan_subdomains.py
```

## Структура проекта

- `scan_subdomains.py` - Основной исполняемый файл
- `subdomain_scanner/` - Пакет со всеми модулями
  - `dns/` - Модули для работы с DNS
    - `zone_transfer.py` - Передача зоны DNS
    - `brute_force.py` - Перебор поддоменов из словаря
  - `cert/` - Модули для работы с сертификатами
    - `certificate_transparency.py` - Поиск через логи прозрачности сертификатов
  - `utils/` - Вспомогательные модули
    - `file_handler.py` - Работа с файлами
    - `logger.py` - Настройка логирования

## Зависимости

- dnspython - Для работы с DNS
- requests - Для HTTP-запросов
- tqdm - Для отображения прогресса
- aiodns - Для асинхронных DNS-запросов

## Примечания

Если файл словаря не найден, скрипт предложит скачать его автоматически. 