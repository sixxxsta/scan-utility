#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?usage: package-release.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="scanutil-linux-amd64"
STAGE="${ROOT}/dist/${NAME}"

rm -rf "${STAGE}"
mkdir -p "${STAGE}/configs"

cp "${ROOT}/bin/masscan" "${STAGE}/masscan"
cp "${ROOT}/bin/scanutil" "${STAGE}/scanutil"
chmod +x "${STAGE}/masscan" "${STAGE}/scanutil"

# Prefer local masscan next to scanutil in the release layout.
sed 's|path: "masscan"|path: "./masscan"|' \
  "${ROOT}/scanner/configs/config.example.yaml" \
  > "${STAGE}/configs/config.example.yaml"

cp "${ROOT}/scanner/.env.example" "${STAGE}/.env.example"

cat > "${STAGE}/README.md" <<EOF
# scanutil ${VERSION} (linux/amd64)

Готовые \`scanutil\` + \`masscan\`. \`go\` / \`make\` не нужны.

## 1. Зависимости на хосте

\`\`\`bash
sudo apt update
sudo apt install -y nmap exploitdb   # searchsploit из exploitdb
\`\`\`

- **nmap** — обязательно
- **searchsploit** — для списка эксплойтов (опционально)
- **sudo** — masscan нужен root

## 2. Настройка

\`\`\`bash
cp configs/config.example.yaml configs/config.yaml
cp .env.example .env
\`\`\`

В \`configs/config.yaml\`: \`targets.ranges\`, \`ports\`.

В \`.env\` для полной работы:

\`\`\`
TELEGRAM_BOT_TOKEN=...   # @BotFather
TELEGRAM_CHAT_ID=...     # id чата; бот должен быть в чате
VULNERS_API_KEY=...      # https://vulners.com
\`\`\`

Включи в \`config.yaml\`:

\`\`\`yaml
notifications:
  telegram:
    enabled: true
vulners:
  enabled: true
exploitdb:
  enabled: true
\`\`\`

Без Telegram/Vulners/searchsploit скан портов всё равно работает — не будет алертов в чат и блоков CVEs/Exploits.

## 3. Запуск

\`\`\`bash
sudo ./scanutil scan -c configs/config.yaml -env .env
./scanutil serve -c configs/config.yaml -env .env   # http://127.0.0.1:8080
\`\`\`

Документация репозитория: https://github.com/sixxxsta/scan-utility
EOF

mkdir -p "${ROOT}/dist"
tar -C "${ROOT}/dist" -czf "${ROOT}/dist/${NAME}.tar.gz" "${NAME}"
echo "Wrote dist/${NAME}.tar.gz"
