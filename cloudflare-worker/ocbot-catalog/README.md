# ocbot-catalog (Cloudflare Worker)

Исходник воркера `ocbot-catalog` (приём и раздача общего каталога пресетов, курсы монет).
Раньше жил только в самом Cloudflare, без git-истории — теперь исходник хранится здесь, чтобы
изменения было видно и можно было откатить. Деплой пока делается через Cloudflare API вручную
(см. комментарии в коде); привязка к GitHub Actions не настроена.

Биндинги (Settings → Variables and Secrets в Cloudflare, без изменений этим коммитом):
`ADMIN_KEY`, `CATALOG` (KV namespace), `CATALOG_WORKER_URL`, `MIN_RIGS`, `SALT` (secret),
`TG_BOT_TOKEN` (secret), `TG_OWNER_CHAT_ID` (secret).
