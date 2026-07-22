# scanutil

Обёртка над masscan: сканит диапазоны/ASN, смотрит открытые порты, через nmap уточняет сервис, сравнивает с прошлой БД, шлёт алерты в Telegram/email. По желанию — searchsploit, Vulners, веб-дашборд, cron.

## Сборка

```bash
# masscan (из корня репо)
make -j

# утилита
cd scanner
go build -o ../bin/scanutil ./cmd/scanutil
```

Нужны: `masscan`, `nmap`, опционально `searchsploit`. Запуск masscan — от root/sudo.

## Конфиг

`configs/config.example.yaml` → `configs/config.yaml`  
Секреты в `.env` (пример: `.env.example`):

```
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
VULNERS_API_KEY=...
```

## Команды

```bash
cd scanner
sudo ../bin/scanutil scan -c configs/config.yaml
../bin/scanutil serve -c configs/config.yaml   # http://127.0.0.1:8080
```

На localhost/docker masscan часто пустой — в конфиге есть `masscan.fallback_nmap`.

## Структура

```
scanner/
  cmd/scanutil/     CLI
  internal/         masscan, nmap, store, notify, cve, exploitdb, asn, api, …
  configs/          yaml
  web/              дашборд
```

Результаты в SQLite (`persistence.sqlite_path`).
