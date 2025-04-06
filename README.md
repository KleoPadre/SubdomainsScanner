# Subdomain Scanner

Инструмент для поиска поддоменов с использованием различных методов:
- DNS Zone Transfer
- Certificate Transparency Logs
- Брутфорс из словаря

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/KleoPadre/SubdomainsScanner.git
cd SubdomainsScanner

# Установка зависимостей
pip install -r requirements.txt
```

## Использование

```bash
# Базовое использование
python3 scan_subdomains.py example.com

# С указанием своего словаря
python3 scan_subdomains.py example.com -w wordlist.txt

# С указанием количества потоков
python3 scan_subdomains.py example.com -t 20

# С сохранением результатов в другой файл (по умолчанию сохраняется в папку finds)
python3 scan_subdomains.py example.com -o results.txt

# С подробным выводом
python3 scan_subdomains.py example.com -v

# С классификацией поддоменов на пользовательские и технические
python3 scan_subdomains.py example.com -c

# С сохранением классифицированных поддоменов в отдельные файлы
python3 scan_subdomains.py example.com -c --save-classified

# С ограничением количества поддоменов для классификации
python3 scan_subdomains.py example.com -c --max-classify 50

# Для классификации всех найденных поддоменов (может занять много времени)
python3 scan_subdomains.py example.com -c --max-classify 0

# Сохранение всех поддоменов, включая поддомены со звездочками
python3 scan_subdomains.py example.com --no-filter-wildcards

# Сохранение всех обычных поддоменов (без звездочек) в один файл без классификации
python3 scan_subdomains.py example.com --all-in-one

# Фильтрация результатов по строке
python3 scan_subdomains.py example.com --filter static.xx
```

Если запустить скрипт без указания домена, он запросит его ввод интерактивно:

```bash
python3 scan_subdomains.py
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
- `finds/` - Папка для сохранения результатов сканирования
- `wordlists/` - Папка с файлами словарей для перебора поддоменов

## Сохранение результатов

По умолчанию, найденные поддомены сохраняются в файл в папке `finds/` с именем, соответствующим сканируемому домену:
- Например, при сканировании `example.com` результаты будут сохранены в `finds/example_com.txt`
- Вы можете указать свой путь для сохранения с помощью параметра `-o`

### Фильтрация

Для повышения качества результатов, скрипт автоматически фильтрует:
- Поддомены со звездочками (например, `*.example.com`)
- При сохранении в файл используются только обычные поддомены

### Расширенные опции сохранения

Доступны дополнительные опции для управления сохранением результатов:

#### Сохранение без фильтрации

Для сохранения всех найденных поддоменов, включая поддомены со звездочками:
```bash
python3 scan_subdomains.py example.com --no-filter-wildcards
```

Результат: все найденные поддомены, включая поддомены со звездочками, будут сохранены в выходной файл.

#### Сохранение в один файл без классификации

Для сохранения всех обычных поддоменов (без звездочек) в один файл без классификации:
```bash
python3 scan_subdomains.py example.com --all-in-one
```

Результат: все поддомены, кроме тех, что начинаются со звездочки, будут сохранены в один файл без разделения на пользовательские и технические.

#### Фильтрация результатов по строке

Для поиска конкретных поддоменов, содержащих указанную строку:
```bash
python3 scan_subdomains.py example.com --filter static.xx
```

Результат: в консоли будут отображены только поддомены, содержащие указанную строку (в данном примере "static.xx").

### Классификация поддоменов

Сканер может автоматически классифицировать найденные поддомены на две категории:

1. **Пользовательские поддомены** - предназначены для конечных пользователей:
   - Основные веб-сайты (www, app, mobile)
   - Сервисы для пользователей (login, account, store)
   - Информационные ресурсы (blog, news, support)

2. **Технические поддомены** - используются для инфраструктуры:
   - CDN и серверы контента (cdn, content, static)
   - Серверы баз данных (db, sql, mongo)
   - Почтовые серверы (mail, smtp, pop)
   - API и серверы мониторинга

#### Опции классификации

- **Классификация поддоменов**: `-c` или `--classify`
- **Сохранение в отдельные файлы**: `--save-classified`
- **Ограничение количества**: `--max-classify N`
  - По умолчанию классифицируется до 100 поддоменов
  - Для классификации всех поддоменов: `--max-classify 0`

#### Примеры использования

Базовая классификация (до 100 поддоменов):
```bash
python3 scan_subdomains.py example.com -c
```

Классификация с сохранением результатов в отдельные файлы:
```bash
python3 scan_subdomains.py example.com -c --save-classified
```

Классификация ограниченного числа поддоменов (для быстрого анализа):
```bash
python3 scan_subdomains.py example.com -c --max-classify 20
```

Классификация всех найденных поддоменов (может занять много времени):
```bash
python3 scan_subdomains.py example.com -c --max-classify 0
```

### Методы классификации

Сканер использует многоуровневый подход к классификации:

1. **Анализ имени поддомена** - быстрая классификация по шаблонам имен
2. **HTTP/HTTPS проверка** - если доступен веб-сайт, анализ содержимого и заголовков
3. **DNS записи** - проверка DNS-записей (A, CNAME, MX, TXT) для определения назначения поддомена

## Надежность сканирования

Для повышения надежности сканирования используются следующие механизмы:

### Публичные DNS-серверы
Сканер использует набор публичных DNS-серверов для выполнения запросов:
- Google DNS (8.8.8.8, 8.8.4.4)
- Cloudflare DNS (1.1.1.1, 1.0.0.1)
- Яндекс DNS (77.88.8.8, 77.88.8.1)
- Quad9 (9.9.9.9, 149.112.112.112)
- OpenDNS (208.67.222.222, 208.67.220.220)

Это позволяет:
- Избежать проблем с таймаутами при использовании локального DNS
- Повысить точность результатов
- Обеспечить работоспособность сканера в различных сетях

### Устойчивость к ошибкам
Сканер спроектирован с учетом возможных ошибок в сети:
- Автоматические повторные попытки с разными DNS-серверами при таймаутах
- Продолжение сканирования другими методами, даже если один из методов не сработал
- Разумные таймауты для предотвращения зависания
- Случайное перемешивание списка DNS-серверов для распределения нагрузки

## Зависимости

- dnspython - Для работы с DNS
- requests - Для HTTP-запросов
- tqdm - Для отображения прогресса
- aiodns - Для асинхронных DNS-запросов

## Примечания

Если файл словаря не найден, скрипт предложит скачать его автоматически. 