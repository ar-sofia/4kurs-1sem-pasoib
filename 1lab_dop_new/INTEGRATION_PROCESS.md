# Схема интеграции кастомных сигнатур в ClamAV

## 🔄 Процесс интеграции сигнатур

```
1. YARA Правило (исходное)
   ↓
   rule Signatures_PS1 {
       strings:
           $sig1 = "Virus_INFECTED" ascii
           $sig2 = "Set-Content -Path" ascii
           $sig3 = "File infected:" ascii
       condition: all of them
   }
   ↓

2. Конвертация в ClamAV формат (.ndb)
   ↓
   virus.prototype.ps1:0:*:56697275735f494e464543544544
   ↓
   [имя]:[смещение]:[тип]:[HEX_строка]

3. Размещение в Docker контейнере
   ↓
   ./signatures/virus_prototype_ps1.ndb
   ↓
   /var/lib/clamav/signatures/virus_prototype_ps1.ndb
   ↓
   /var/lib/clamav/virus_prototype_ps1.ndb  ← ВАЖНО: основная директория!

4. Перезапуск ClamAV для загрузки сигнатур
   ↓
   sudo docker-compose restart

5. Тестирование обнаружения
   ↓
   sudo docker exec clamav clamscan /scan/disk-monitor.ps1
   ↓
   Результат: virus.prototype.ps1.UNOFFICIAL FOUND
```

## 🎯 Ключевые моменты

### ✅ Что работает:
- ClamAV успешно обнаруживает вирус по кастомной сигнатуре
- Сигнатура размещена в `/var/lib/clamav/virus_prototype_ps1.ndb`
- Используется `clamscan` (не `clamdscan`) для прямого сканирования

### ⚠️ Важные детали:
1. **Местоположение сигнатур:** Только в `/var/lib/clamav/`, не в подпапках
2. **Формат сигнатур:** .ndb (не .yar для ClamAV)
3. **HEX кодирование:** Строки должны быть в HEX формате
4. **Перезапуск:** Обязателен после добавления новых сигнатур

### 🔧 Техническая реализация:

```
HEX конвертация:
"Virus_INFECTED" → "56697275735f494e464543544544"

Формат .ndb:
virus.prototype.ps1:0:*:56697275735f494e464543544544
│                    │ │  │
│                    │ │  └─ HEX строка для поиска
│                    │ └──── Тип файла (* = любой)
│                    └────── Смещение (0 = в любом месте)
└─────────────────────────── Имя вируса
```

## 📊 Результат интеграции

```
Было:  ClamAV не обнаруживает virus.prototype.ps1
Стало: ClamAV успешно обнаруживает virus.prototype.ps1.UNOFFICIAL

Тестирование:
✅ Сканирование одного файла
✅ Сканирование директории  
✅ Подробный вывод результатов
✅ Автоматизированное тестирование
```
