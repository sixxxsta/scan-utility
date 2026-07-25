# scan-utility

Репозиторий: upstream [masscan](https://github.com/robertdavidgraham/masscan) + утилита `scanner/` (scanutil).

Подробности — в [scanner/README.md](scanner/README.md).

## Download (готовые бинарники)

1. Скачай `scanutil-linux-amd64.tar.gz` с [Releases](https://github.com/sixxxsta/scan-utility/releases).
2. Распакуй и настрой:

```bash
tar xzf scanutil-linux-amd64.tar.gz
cd scanutil-linux-amd64
cp configs/config.example.yaml configs/config.yaml
cp .env.example .env
```

3. В `configs/config.yaml` укажи `targets.ranges` и `ports`.
4. Для полной работы (см. ниже) заполни `.env` и включи нужные блоки в yaml.
5. Запуск:

```bash
sudo ./scanutil scan -c configs/config.yaml -env .env
./scanutil serve -c configs/config.yaml -env .env   # дашборд http://127.0.0.1:8080
```

В архиве уже есть `scanutil` и `masscan` — `go`/`make` не нужны.

### Что установить на машине

| Компонент | Зачем | Обязательно? |
|-----------|--------|--------------|
| **nmap** | уточнение сервисов, NSE | да |
| **searchsploit** (exploitdb) | список известных эксплойтов | нет, но для полной картины да |
| root/`sudo` | masscan (raw sockets) | да для `scan` |

Ubuntu/Kali:

```bash
sudo apt update
sudo apt install -y nmap exploitdb   # searchsploit из пакета exploitdb
```

### Секреты для полной работы (`.env`)

```
TELEGRAM_BOT_TOKEN=...   # токен бота от @BotFather
TELEGRAM_CHAT_ID=...     # id чата (личка или группа)
VULNERS_API_KEY=...      # ключ с https://vulners.com
```

В `config.yaml` включи:

```yaml
notifications:
  telegram:
    enabled: true
    bot_token_env: "TELEGRAM_BOT_TOKEN"
    chat_id_env: "TELEGRAM_CHAT_ID"

vulners:
  enabled: true
  api_key_env: "VULNERS_API_KEY"

exploitdb:
  enabled: true
  path: "searchsploit"
```

Без Telegram алерты не уходят в чат. Без Vulners не будет блока **CVEs**. Без searchsploit — не будет **Exploits**. Скан портов при этом всё равно работает.

## Сборка из исходников

```bash
make -j
cd scanner && go build -o ../bin/scanutil ./cmd/scanutil
```
