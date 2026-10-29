> **Legacy / optional:** this agent-based design requires software on the test host. It is NOT used in the Wireshark-only setup. For the current requirement, follow [wireshark-only-host.md](wireshark-only-host.md).

# Непрерывный сбор журналов тестового хоста

Этот механизм состоит из двух компонентов:

- `scripts/host-log-agent.py` запускается **на тестируемом хосте**. Он автоматически создаёт локальный JSONL-журнал и передаёт события по TCP на Raspberry Pi.
- `scripts/host-log-receiver.py` запускается **на Raspberry Pi**. Он создаёт `host-HOSTNAME.log` (текст для сигнатурного поиска фаззером) и `host-HOSTNAME.jsonl` (структурированные события). Receiver также контролирует heartbeat; после 15 секунд без сообщений по умолчанию пишет `HOST_AGENT_HEARTBEAT_MISSED` в оба журнала. Это сигнал потери связи/агента, не доказательство сбоя ОС. Порог настраивается через `--heartbeat-timeout`.

Поддерживаются Linux с `journalctl` и Windows с PowerShell / Windows Event Log. Агент Windows опрашивает System events 41 (Kernel-Power), 1001 (BugCheck), 6008 (unexpected shutdown), 6005/6006 (EventLog start/stop). Агент Linux пересылает сообщения журнала с приоритетом warning и выше. Heartbeat записывается в JSONL, но не засоряет текстовый crash-журнал.

## 1. Запустить receiver на Raspberry Pi

В корне проекта:

```bash
mkdir -p secrets runs/host-logs
umask 077
python3 -c 'import secrets; print(secrets.token_hex(32))' > secrets/host-log-token.txt
chmod 600 secrets/host-log-token.txt
ip -brief address
python3 scripts/host-log-receiver.py \
  --listen 192.168.1.20 \
  --port 8765 \
  --token-file secrets/host-log-token.txt \
  --out-dir runs/host-logs
```

Замените `192.168.1.20` на IP Raspberry Pi в отдельной лабораторной сети. Передайте секретный файл на тестируемый хост защищённым способом; не публикуйте токен. Разрешите входящий TCP/8765 только из лабораторной сети. Протокол использует общий токен, но без TLS: не выставляйте порт в Интернет и используйте изолированную сеть.

## 2. Запустить агент на тестируемом хосте

Скопируйте на хост `scripts/host-log-agent.py` и секретный токен в файл с ограниченными правами. Установленный Python 3 требуется на обеих машинах.

Linux:

```bash
python3 host-log-agent.py \
  --server 192.168.1.20 --port 8765 \
  --token-file /etc/usb-research/host-log-token.txt \
  --local-log /var/log/usb-research/host-events.jsonl
```

Windows PowerShell (запустите от имени пользователя, которому разрешено читать System Event Log):

```powershell
py .\host-log-agent.py `
  --server 192.168.1.20 --port 8765 `
  --token-file C:\ProgramData\UsbResearch\host-log-token.txt `
  --local-log C:\ProgramData\UsbResearch\host-events.jsonl
```

На Windows агент периодически опрашивает Event Log. На Linux он следует за system journal. Агент пытается переподключиться после временной потери TCP-соединения. Локальный JSONL пишется до отправки события, поэтому он остаётся доступен даже при временном обрыве связи. При запуске агент помечает старые Windows-события как базовые и не отправляет их как новые события кампании.

## 3. Использовать удалённый журнал в кампании

Сначала узнайте имя хоста: receiver создаёт `host-<hostname>.log`. Например, для `WIN-TEST01` путь на Raspberry Pi будет:

```bash
runs/host-logs/host-WIN-TEST01.log
```

Передайте этот путь в кампанию:

```bash
python3 scripts/usb-fuzz.py campaign \
  --base profiles/templates/hid-mouse.json \
  --count 100 --seed 20261028 --mutations 3 \
  --out-dir runs/fuzz/hid-campaign \
  --runner 'python scripts/my_lab_runner.py --profile {profile}' \
  --timeout 30 --confirm-lab \
  --host-log runs/host-logs/host-WIN-TEST01.log \
  --host-log-settle 6 --stop-on-crash
```

`--host-log-settle 6` ждёт до чтения журнала, чтобы дать агенту с интервалом опроса 5 секунд время переслать событие. Этот параметр увеличивает длительность кампании. События, пришедшие вне окна конкретного запуска, могут быть обнаружены, но их точная причинная связь с профилем не гарантируется без отдельного протокола маркировки начала/конца теста. Если нужно дождаться watchdog-события о потере heartbeat, укажите `--host-log-settle 16` или больше; это добавляет задержку к каждому тесту.

## 4. Автозапуск после перезагрузки

Для постоянной работы настройте службу ОС отдельно:

- Raspberry Pi: создайте systemd unit для `host-log-receiver.py`, с `WorkingDirectory` каталога проекта и абсолютными путями к токену/выходному каталогу.
- Linux-хост: создайте systemd unit для `host-log-agent.py`.
- Windows-хост: создайте Task Scheduler task «At startup» для запуска `py.exe` с аргументами агента и включите «Restart on failure».

Сначала запустите вручную и проверьте, что на Raspberry Pi появились оба файла `host-HOSTNAME.log` и `host-HOSTNAME.jsonl`. Затем настройте автозапуск. Службы не создаются автоматически установщиком, чтобы не менять системную конфигурацию без согласия администратора.

## Ограничения

- Потеря heartbeat или сетевого соединения указывает на недоступность агента/хоста, но не доказывает BSOD или kernel panic.
- Windows Event ID 41 обычно фиксируется после следующей загрузки; для уверенной привязки к профилю нужны внешний монитор питания/сети, отметки времени и сохранение дампов.
- `--host-log` читает только новые данные после начала кампании; ранее записанные события не приписываются текущему тесту.
- Передача по TCP с токеном не шифруется. Используйте изолированную лабораторную сеть или добавьте защищённый туннель.
