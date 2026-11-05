# OCBot — дистрибутив

**Бот-диспетчер для майнинг-ригов: сам подбирает разгон каждой карты, проверяет пресеты часами реальной работы и поднимает ферму при сбоях. Управление и отчёты — в Telegram.**

[![VirusTotal: 0/75](https://img.shields.io/badge/VirusTotal-0%2F75%20clean-brightgreen)](https://www.virustotal.com/gui/file/c68f4a50807fb4ab2dbe1472b1668635b05c0342978cf8a91a541f59b15a848e)
[![Сайт](https://img.shields.io/badge/site-ocbot.org-2ea44f)](https://ocbot.org)
[![Telegram-канал](https://img.shields.io/badge/telegram-%40ocbot__auto-26A5E4)](https://t.me/ocbot_auto)

## Что внутри

| Файл | Назначение |
|---|---|
| `ocbot.zip` | Защищённая сборка бота (обфусцированная, с проверкой лицензии) |
| `ocbot.zip.sig` | Подпись сборки для верификации |
| `verify_protected.py` | Скрипт проверки: в архиве именно защищённая сборка, без исходников |
| `vt-status.json` | Свежий отчёт VirusTotal по архиву |

Здесь публикуются **только защищённые сборки**. Исходный код бота не публикуется.

## Быстрый старт

1. Скачайте `ocbot.zip` и положите его вместе с вашим `license.json` в папку `/root` рига.
2. Откройте Hive Shell и выполните одну команду из раздела «Установка»:
   **[ocbot.org/guide.ru.html](https://ocbot.org/guide.ru.html)**
3. Мастер сам найдёт карты и майнер, предложит включить триал — **3 дня бесплатно, без привязки карты**.

Перед установкой очистите разгон в панели Hive и отключите перезагрузку по хешрейту.

## Проверка перед установкой

```bash
python3 verify_protected.py ocbot.zip
```

Код возврата `0` — сборка чистая. Дополнительно: отчёт VirusTotal по кнопке-бейджу выше.

## Ссылки

- Сайт: **[ocbot.org](https://ocbot.org)** — гайд, калькулятор дохода, ответы на вопросы
- Каталог проверенных пресетов: **[ocbot.org/catalog.ru.html](https://ocbot.org/catalog.ru.html)** — реальные цифры с живых ригов по моделям карт и памяти
- Канал: **[t.me/ocbot_auto](https://t.me/ocbot_auto)** — статьи и новости
- Поддержка: **[@OCBotSupport_bot](https://t.me/OCBotSupport_bot)** — отвечаем в течение суток

---

## English

**OCBot is an autopilot for GPU mining rigs: it tunes overclocking per card, verifies presets with hours of real mining, and recovers the farm from failures on its own. Controlled via Telegram.**

- Download `ocbot.zip`, place it with your `license.json` in the rig's `/root`, then run the single command from the guide: **[ocbot.org/guide.html](https://ocbot.org/guide.html)**
- 3-day trial, no card required.
- Verify the build before installing: `python3 verify_protected.py ocbot.zip` (exit code `0` = clean).
- Only protected (obfuscated, license-enforced) builds are published here — no source code.

Disclaimer: mining involves hardware and financial risks; use at your own risk. / Майнинг связан с рисками для железа и финансов — используйте на свой страх и риск.
