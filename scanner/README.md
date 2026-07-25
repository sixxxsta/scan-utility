# scanutil

Обёртка над masscan: сканит диапазоны/ASN, смотрит открытые порты, через nmap уточняет сервис, сравнивает с прошлой БД, шлёт алерты в Telegram/email. По желанию — searchsploit, Vulners, веб-дашборд, cron.

## Download

Готовый архив: [Releases](https://github.com/sixxxsta/scan-utility/releases) → `scanutil-linux-amd64.tar.gz`.

```bash
tar xzf scanutil-linux-amd64.tar.gz
cd scanutil-linux-amd64
cp configs/config.example.yaml configs/config.yaml
cp .env.example .env
# targets/ports в config.yaml; секреты в .env
sudo ./scanutil scan -c configs/config.yaml -env .env
```

### Зависимости на хосте

- **nmap** — обязательно (сервисы / NSE)
- **searchsploit** (`apt install exploitdb`) — для блока Exploits
- **sudo** — для masscan

### API / боты (полная работа)

В `.env`:

| Переменная | Откуда |
|------------|--------|
| `TELEGRAM_BOT_TOKEN` | [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | id чата (бот должен быть добавлен в чат) |
| `VULNERS_API_KEY` | [vulners.com](https://vulners.com) |

В `config.yaml` включи `notifications.telegram.enabled`, `vulners.enabled`, `exploitdb.enabled` (см. корневой README).

## Сборка

```bash
# masscan (из корня репо)
make -j

# утилита
cd scanner
go build -o ../bin/scanutil ./cmd/scanutil
```

## Конфиг

`configs/config.example.yaml` → `configs/config.yaml`  
Секреты в `.env` (пример: `.env.example`).

## Команды

```bash
cd scanner
sudo ../bin/scanutil scan -c configs/config.yaml -env .env
../bin/scanutil serve -c configs/config.yaml -env .env   # http://127.0.0.1:8080
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
