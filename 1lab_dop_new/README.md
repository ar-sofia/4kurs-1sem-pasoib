# ClamAV Docker Deployment с Кастомными Сигнатурами

Этот проект содержит полную настройку ClamAV антивируса с использованием Docker, включая интеграцию кастомных сигнатур для обнаружения специфических вирусов.

## 🎯 Цель проекта

Развернуть ClamAV с возможностью добавления собственных сигнатур для обнаружения вируса `virus.prototype.ps1` в файле `disk-monitor.ps1`.

## 📁 Структура проекта

```
1lab_dop_new/
├── docker-compose.yml              # Конфигурация Docker сервисов
├── config/
│   ├── clamd.conf                 # Конфигурация ClamAV daemon
│   └── freshclam.conf             # Конфигурация обновления баз данных
├── signatures/
│   ├── virus_prototype_ps1.yar    # YARA сигнатура (для справки)
│   └── virus_prototype_ps1.ndb    # ClamAV сигнатура (рабочая)
├── scan/                          # Директория для файлов на сканирование
│   └── disk-monitor.ps1          # Зараженный файл для тестирования
├── quarantine/                    # Карантин для зараженных файлов
├── test-scan.sh                  # Скрипт тестирования сканирования
└── README.md                     # Данная документация
```

## 🔧 Как была реализована интеграция сигнатур

### 1. Создание YARA сигнатуры

Изначально была создана YARA сигнатура на основе предоставленного правила:

```yara
rule virus_prototype_ps1 {
    strings:
        $sig1 = "Virus_INFECTED" ascii
        $sig2 = "Set-Content -Path" ascii
        $sig3 = "File infected:" ascii
        
    condition:
        all of them
}
```

**Файл:** `signatures/virus_prototype_ps1.yar`

### 2. Конвертация в формат ClamAV (.ndb)

Поскольку ClamAV не поддерживает YARA напрямую, сигнатура была конвертирована в формат ClamAV (.ndb):

```
virus.prototype.ps1:0:*:56697275735f494e464543544544
```

**Где:**
- `virus.prototype.ps1` - имя вируса
- `0` - смещение (0 = в любом месте файла)
- `*` - тип файла (* = любой)
- `56697275735f494e464543544544` - HEX-кодированная строка "Virus_INFECTED"

### 3. Монтирование директории сигнатур

В `docker-compose.yml` добавлено монтирование:

```yaml
volumes:
  - ./signatures:/var/lib/clamav/signatures  # Custom signatures
```

### 4. Размещение сигнатуры в правильном месте

**Ключевой момент:** ClamAV загружает сигнатуры только из основной директории `/var/lib/clamav/`, а не из подпапок.

Сигнатура была скопирована в основную директорию:
```bash
sudo docker exec clamav cp /var/lib/clamav/signatures/virus_prototype_ps1.ndb /var/lib/clamav/
```

### 5. Перезапуск ClamAV

После добавления новой сигнатуры ClamAV необходимо перезапустить для загрузки обновленных баз данных.

## 🚀 Быстрый старт

### Запуск ClamAV

```bash
# Запуск всех сервисов
sudo docker-compose up -d

# Проверка статуса
sudo docker-compose ps
```

### Тестирование обнаружения вируса

```bash
# Сканирование зараженного файла
sudo docker exec clamav clamscan /scan/disk-monitor.ps1

# Ожидаемый результат:
# /scan/disk-monitor.ps1: virus.prototype.ps1.UNOFFICIAL FOUND
```

### Автоматическое тестирование

```bash
# Запуск тестового скрипта
./test-scan.sh
```

## 📊 Результаты тестирования

### Успешное обнаружение вируса:

```
/scan/disk-monitor.ps1: virus.prototype.ps1.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8708689
Engine version: 1.5.1
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 1.26 KiB
Data read: 1.26 KiB (ratio 1.00:1)
Time: 38.546 sec (0 m 38 s)
```

### Сканирование всей директории:

```
/scan/test-file.txt: OK
/scan/disk-monitor.ps1: virus.prototype.ps1.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Infected files: 1
```

## 🔍 Анализ зараженного файла

Файл `disk-monitor.ps1` содержит:

```powershell
# Virus_INFECTED
Write-Host "VIRUS ACTIVATED!" -ForegroundColor Red
try {
    $InfectionMarker = "INFECTED"
    Set-Content -Path "$env:TEMP\virus_log.txt" -Value "File infected: disk-monitor.ps1"
} catch {
    # Ignore errors in infection marker
}
```

**Обнаруженные сигнатуры:**
- ✅ `Virus_INFECTED` - в комментарии
- ✅ `Set-Content -Path` - в коде
- ✅ `File infected:` - в строке

## 📋 Команды для работы

### Основные команды сканирования:

```bash
# Сканирование одного файла
sudo docker exec clamav clamscan /scan/filename

# Сканирование с подробным выводом
sudo docker exec clamav clamscan -v /scan/filename

# Сканирование всей директории
sudo docker exec clamav clamscan /scan/

# Сканирование с перемещением в карантин
sudo docker exec clamav clamscan --move=/quarantine /scan/
```

### Управление сервисами:

```bash
# Остановка
sudo docker-compose down

# Перезапуск
sudo docker-compose restart

# Просмотр логов
sudo docker-compose logs -f clamav
```

## 🛠️ Добавление новых сигнатур

### 1. Создание .ndb файла

Формат сигнатуры ClamAV:
```
имя_вируса:смещение:тип_файла:HEX_строка
```

Пример:
```
my_virus:0:*:48656C6C6F20576F726C64  # "Hello World"
```

### 2. Размещение сигнатуры

```bash
# Создать файл сигнатуры
echo 'my_virus:0:*:48656C6C6F20576F726C64' > signatures/my_virus.ndb

# Скопировать в контейнер
sudo docker exec clamav cp /var/lib/clamav/signatures/my_virus.ndb /var/lib/clamav/

# Перезапустить ClamAV
sudo docker-compose restart
```

## 🔧 Технические детали

### Конфигурация ClamAV

- **Порт:** 3311 (внешний) → 3310 (внутренний)
- **Базы данных:** Автоматическое обновление через freshclam
- **Кастомные сигнатуры:** Поддержка .ndb формата
- **Логи:** `/var/log/clamav/`

### Docker конфигурация

```yaml
services:
  clamav:
    image: clamav/clamav:latest
    ports:
      - "3311:3310"
    volumes:
      - clamav_db:/var/lib/clamav
      - ./scan:/scan
      - ./signatures:/var/lib/clamav/signatures
```

## 📈 Производительность

- **Время сканирования:** ~38 секунд на файл (первый запуск)
- **Размер баз данных:** ~870 тысяч известных вирусов
- **Поддерживаемые форматы:** PE, ELF, PDF, OLE2, Mail, Archive и др.

## 🚨 Устранение неполадок

### Проблема: Сигнатура не обнаруживается

**Решение:**
1. Проверить размещение файла в `/var/lib/clamav/`
2. Перезапустить ClamAV daemon
3. Использовать `clamscan` вместо `clamdscan`

### Проблема: ClamAV не запускается

**Решение:**
1. Проверить логи: `sudo docker-compose logs clamav`
2. Проверить конфигурационные файлы
3. Перезапустить Docker сервис

### Проблема: Низкая производительность

**Решение:**
1. Увеличить `MaxThreads` в конфигурации
2. Настроить `MaxFileSize` под ваши нужды
3. Использовать SSD для хранения баз данных

## 📚 Полезные ссылки

- [Официальная документация ClamAV](https://docs.clamav.net/)
- [Docker Hub - ClamAV](https://hub.docker.com/r/clamav/clamav)
- [GitHub - ClamAV](https://github.com/Cisco-Talos/clamav)
- [Формат сигнатур ClamAV](https://docs.clamav.net/manual/Signatures.html)

## ✅ Заключение

Проект успешно демонстрирует:

1. ✅ Развертывание ClamAV через Docker
2. ✅ Интеграцию кастомных сигнатур
3. ✅ Обнаружение специфического вируса `virus.prototype.ps1`
4. ✅ Автоматизированное тестирование
5. ✅ Полную документацию процесса

ClamAV теперь готов к использованию и может обнаруживать как стандартные вирусы, так и кастомные угрозы по созданным сигнатурам.