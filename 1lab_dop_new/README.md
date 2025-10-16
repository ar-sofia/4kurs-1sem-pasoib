# ClamAV Docker Deployment

Простой и эффективный способ развертывания ClamAV антивируса с использованием Docker и интеграцией кастомных сигнатур.

## 🚀 Быстрый старт

```bash
# Запуск ClamAV
./start.sh

# Тестирование системы
./test.sh

# Проверка вируса
./check-virus.sh
```

## 📁 Структура проекта

```
1lab_dop_new/
├── docker-compose.yml              # Конфигурация Docker
├── config/
│   ├── clamd.conf                 # Конфигурация ClamAV daemon
│   └── freshclam.conf             # Конфигурация обновления баз
├── signatures/
│   ├── virus_prototype_ps1.yar    # YARA сигнатура (для справки)
│   └── virus_prototype_ps1.ndb    # ClamAV HEX сигнатура
├── scan/                          # Директория для сканирования
│   └── disk-monitor.ps1          # Зараженный файл для тестирования
├── quarantine/                    # Карантин для зараженных файлов
├── start.sh                      # Скрипт запуска
├── test.sh                       # Скрипт тестирования
├── check-virus.sh                # Скрипт проверки вируса
└── README.md                     # Данная документация
```

## 🔧 Использование

### Основные команды:

```bash
# Сканирование файла
sudo docker exec clamav clamscan /scan/your_file.txt

# Сканирование с подробным выводом
sudo docker exec clamav clamscan -v /scan/your_file.txt

# Сканирование всей директории
sudo docker exec clamav clamscan /scan/
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

## 🎯 Интеграция сигнатур

### YARA правило:
```yara
rule Signatures_PS1 {
    strings:
        $sig1 = "Virus_INFECTED" ascii
        $sig2 = "Set-Content -Path" ascii
        $sig3 = "File infected:" ascii
        
    condition:
        all of them
}
```

### ClamAV HEX сигнатура:
```
virus.prototype.ps1:0:*:56697275735f494e464543544544
```

**Где:** `56697275735f494e464543544544` = HEX для "Virus_INFECTED"

## 📊 Результаты тестирования

### Успешное обнаружение:
```
🎯 РЕЗУЛЬТАТ: ВИРУС ОБНАРУЖЕН!
   Обнаружена хотя бы одна сигнатура, так как clamav останавливаеться на первой найденной сигнатуре и помечает файл как зараженный
   Файл содержит virus.prototype.ps1

🔍 Сканирование ClamAV:
/scan/disk-monitor.ps1: virus.prototype.ps1.UNOFFICIAL FOUND
```

## 🌐 Доступные сервисы

- **ClamAV daemon**: `localhost:3311` (внешний порт 3311 → внутренний 3310)

## 📚 Полезные ссылки

- [Официальная документация ClamAV](https://docs.clamav.net/)
- [Docker Hub - ClamAV](https://hub.docker.com/r/clamav/clamav)
- [GitHub - ClamAV](https://github.com/Cisco-Talos/clamav)