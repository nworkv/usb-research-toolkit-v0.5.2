# USB Research Toolkit 0.5.2 — пошаговое руководство

## Сначала: распаковка архива

Скопируйте `usb-research-toolkit-v0.5.2-byte-report.zip` в `~/Downloads`, затем в терминале Raspberry Pi выполните:

```bash
cd ~
unzip ~/Downloads/usb-research-toolkit-v0.5.2-byte-report.zip
cd ~/usb-research-toolkit-v0.5.2
```

Если вы работаете с уже склонированным Git-репозиторием, переходите в его корень вместо пути выше. Все команды ниже запускаются из корня проекта.

USB Research Toolkit — исследовательский проект для эмуляции типовых USB-устройств на Linux/Raspberry Pi, тестирования их перечисления на **собственном изолированном хосте** и сопоставления событий Raw Gadget с захватом Wireshark/USBPcap.

> **Важно о поддержке классов.** Версия 0.5.2 расширяет рабочие сценарии классов, но не пытается обещать «любой USB-девайс без ограничений». USB HID позволяет задавать произвольные отчёты, однако каждому устройству нужен соответствующий HID report descriptor и формат report-данных. Реализованы готовые примеры клавиатуры, мыши, геймпада/джойстика и consumer control; CDC ACM с обычными class control requests и loopback для serial data; Mass Storage BOT с backing file и основными SCSI-командами. CDC ECM/NCM, произвольные фирменные протоколы, isochronous-передачи и полноценное runtime-переключение alternate settings пока не реализованы. Composite-профили зависят от возможностей UDC и числа доступных endpoint.

Raw Gadget — низкоуровневый debug-интерфейс ядра Linux, не production backend. Контролируйте все тесты только на своём тестовом хосте: даже нормальный отказ USB-устройства возможен, а экспериментальный дескриптор может привести к зависанию или перезапуску хоста.

## Содержание

1. Что требуется
2. Сборка и автоматические тесты
3. Проверка USB Device Controller (UDC)
4. Подготовка Wireshark/USBPcap
5. Первый запуск без фаззинга
6. Каталог профилей
7. Подготовка виртуального Mass Storage-диска
8. Запуск HID, CDC ACM, MSC и composite устройств
9. Генерация вариантов
10. Запуск кампании фаззинга с live-консолью
11. Просмотр результатов и изменений профилей
12. Анализ PCAPNG и статусы корреляции
13. Побайтовый TXT/HTML отчёт всей кампании
14. Повтор конкретного случая
15. Решение частых проблем

---

## 1. Что требуется

### Raspberry Pi / Linux Gadget-side

- Raspberry Pi 4 Model B с USB-C-разъёмом, поддерживающим USB device/OTG в соответствующей конфигурации;
- Raspberry Pi OS/Debian, CMake 3.20+, C++20-компилятор, Python 3.10+;
- ядро с USB Gadget, UDC и `CONFIG_USB_RAW_GADGET`; устройство `/dev/raw-gadget` должно существовать;
- `tshark` нужен для анализа PCAPNG на Pi (необязательно для самого запуска Gadget);
- `dosfstools` (`mkfs.vfat`) — только если хотите создавать FAT-образ для виртуального диска.

Установка базовых инструментов:

```bash
sudo apt update
sudo apt install -y build-essential cmake python3 python3-venv tshark
# Необязательно, для форматирования образа Mass Storage:
sudo apt install -y dosfstools
```

### Windows host-side

- Wireshark с USBPcap;
- правильный USBPcap-интерфейс для физического USB Root Hub, к которому подключён Raspberry Pi;
- права, позволяющие захватывать USBPcap;
- тестовый компьютер, на котором разрешено наблюдать отказы USB. В этом проекте не требуется устанавливать агент на Windows.

На Raspberry Pi 4 Model B используйте USB-C data-порт платы как device-side соединение с тестовым Windows-ПК; USB-A порты Raspberry Pi — host-порты для периферии. Используйте исправный data-кабель, а питание организуйте так, чтобы плата не перезапускалась от просадки питания.

## 2. Сборка и автоматические тесты

Откройте терминал Raspberry Pi и перейдите в корень проекта (там, где лежит `CMakeLists.txt`):

```bash
cd ~/usb-research-toolkit-v0.5.2
```

Если вы используете другой каталог, укажите его вместо `~/usb-research-toolkit-v0.5.0`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUSB_RESEARCH_BUILD_TESTS=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Проверка Python-скриптов и окружения:

```bash
python3 scripts/usb-lab.py doctor
python3 scripts/usb-gadget-campaign.py --help
python3 scripts/review-usb-campaign.py --help
python3 scripts/usb-lab.py profiles
```

Команда `doctor` проверяет инструменты, бинарники, `/dev/raw-gadget` и `/sys/class/udc/`. Тесты проекта проверяют сборку, обработку профилей, нормализацию и вспомогательные сценарии; они **не заменяют физическую проверку на реальной Pi и Windows**.

## 3. Проверь UDC и задавай его явно

Выполни:

```bash
ls -l /dev/raw-gadget
ls -l /sys/class/udc/
sudo build/usb-connect probe
```

`probe` показывает два значения: UDC driver name из uevent и имя UDC device. Не угадывайте их — используйте вывод `probe`. Для стандартной конфигурации Raspberry Pi в вашей лаборатории они могут быть одинаковыми:

```bash
export UDC_DRIVER='fe980000.usb'
export UDC_DEVICE='fe980000.usb'
printf 'driver=<%s> device=<%s>\n' "$UDC_DRIVER" "$UDC_DEVICE"
```

Если `probe` выводит другие имена, экспортируйте именно их. Важно: переменные `export` действуют только в текущем терминале; после открытия нового терминала их нужно задать снова. Чтобы избежать пустых переменных внутри `sudo`, можно передавать значения в командах напрямую.

Если `/dev/raw-gadget` отсутствует или `/sys/class/udc/` пуст, **не запускайте кампанию**. Проверьте режим peripheral/OTG, overlay DWC2 и не занят ли UDC другим gadget. Не добавляйте `dtoverlay=dwc2,dr_mode=peripheral` вслепую: сначала проверьте существующую загрузочную конфигурацию (`/boot/firmware/config.txt` или путь, применяемый вашим образом).

## 4. Подготовка Wireshark и папки захватов

Настроить SMB-шару на Pi можно так:

```bash
sudo bash scripts/setup-wireshark-share.sh
sudo testparm -s
hostname -I
ls -ld /srv/usb-captures
```

Если в `smb.conf` уже есть секция `[usb-captures]`, скрипт предупредит, что новый дубликат не добавлен. Проверьте текущую секцию вручную.

На Windows:

1. Запустите Wireshark.
2. Откройте **Capture → Options** и найдите интерфейс `USBPcapN`, соответствующий Root Hub нужного физического порта.
3. Уберите display filter, который может скрывать пакеты.
4. Начните захват **до** подключения/запуска тестового Gadget.
5. После теста остановите захват и сохраните `.pcapng` в сетевую папку Raspberry Pi, например:

```text
\\IP_RASPBERRY_PI\usb-captures\baseline-hid.pcapng
```

Замените `IP_RASPBERRY_PI` адресом из `hostname -I`. Убедитесь, что Windows действительно создала файл в `/srv/usb-captures`:

```bash
ls -lh /srv/usb-captures
```

`USBPcap` захватывает запросы на программном уровне host stack. Пустой захват может означать неверный USBPcap-интерфейс, отсутствие захвата или отсутствие запросов; это не само по себе доказательство сбоя Windows.

## 5. Первый запуск — без мутаций

До фаззинга убедитесь, что простое устройство запускается. На Windows заранее начните захват. На Pi:

```bash
cd ~/usb-research-toolkit-v0.5.2
mkdir -p runs/baseline
sudo build/usb-connect run \
  profiles/valid/minimal-device.json \
  --backend raw-gadget \
  --udc-driver "$UDC_DRIVER" \
  --udc-device "$UDC_DEVICE" \
  --speed high \
  --trace runs/baseline/device.jsonl \
  --run-id baseline-minimal
```

Ожидается `Raw Gadget running. Press Ctrl+C to stop.`. Подождите 10–15 секунд, затем остановите процесс через `Ctrl+C`. В другом терминале можно просматривать trace во время теста:

```bash
tail -f runs/baseline/device.jsonl
```

Ищите `UDC_BOUND`, `CONTROL_REQUEST`, `CONTROL_RESPONSE_COMPLETE` и `SET_CONFIGURATION`. После теста остановите Wireshark, сохраните PCAPNG и проверьте его существование. Если базовый запуск не работает, исправьте это прежде, чем мутировать профили.

## 6. Каталог профилей

Посмотреть все встроенные профили и описание runtime-готовности:

```bash
python3 scripts/usb-lab.py profiles
```

Основные шаблоны:

| Шаблон | Что эмулирует | Примечание |
|---|---|---|
| `profiles/templates/hid-mouse.json` | HID-мышь | Нейтральные отчёты без движения |
| `profiles/templates/hid-keyboard.json` | HID Boot Keyboard | Передаёт только нулевой (не нажата ни одна клавиша) отчёт |
| `profiles/templates/hid-gamepad.json` | Общий HID gamepad | 16 кнопок, 4 оси и hat; нейтральное состояние |
| `profiles/templates/hid-joystick.json` | Общий HID joystick | Пример отчётной раскладки joystick |
| `profiles/templates/hid-consumer-control.json` | Consumer Control | Нейтральный отчёт |
| `profiles/templates/cdc-acm-serial.json` | CDC ACM serial | Class requests плюс bulk OUT→IN loopback |
| `profiles/templates/msc-bot-disk.json` | Mass Storage BOT | Требуется backing image `runs/storage/usb-lab.img` |
| `profiles/templates/composite-cdc-hid-keyboard.json` | CDC ACM + HID keyboard | Одна конфигурация, три интерфейса |
| `profiles/templates/composite-msc-hid-gamepad.json` | MSC BOT + HID gamepad | Одна конфигурация, два интерфейса |
| `profiles/templates/composite-hid-keyboard-mouse-consumer.json` | HID keyboard + mouse + consumer control | Одна конфигурация, три HID-интерфейса |
| `profiles/templates/composite-cdc-msc-hid-gamepad.json` | CDC ACM + MSC BOT + HID gamepad | Одна конфигурация, четыре интерфейса; нужен образ диска и UDC с достаточным числом endpoints |
| `profiles/templates/multi-config-keyboard-mouse.json` | Две конфигурации | Хост выбирает клавиатуру **или** мышь; не обе одновременно |
| `profiles/templates/vendor-bulk.json` | Vendor-specific bulk | Generic endpoint worker, OS-драйвер зависит от тестового профиля |
| `profiles/templates/msc-bot-descriptor-only.json` | Только MSC-дескрипторы | Не является рабочим диском; используй `msc-bot-disk.json` для BOT-исполнения |

HID-отчёт — это бинарный контракт, описывающий формат кнопок/осей/usage; не каждый коммерческий контроллер использует один стандартный report layout. Для другого HID скопируйте профиль, задайте корректный `raw_descriptors`/`interface_descriptors`, `interrupt_in_payload_hex` и endpoint. Нулевые keyboard/gamepad reports намеренно ничего не нажимают и не двигают указатель.

## 7. Создание виртуального Mass Storage-диска

MSC BOT использует файл-образ как блоковое хранилище. Создайте 64 MiB образ в пути, который указан в `profiles/templates/msc-bot-disk.json`:

```bash
cd ~/usb-research-toolkit-v0.5.2
python3 scripts/create-msd-image.py --path runs/storage/usb-lab.img --size-mib 64 --format-vfat
```

Для `--format-vfat` нужен пакет `dosfstools` с `mkfs.vfat`/`mkfs.fat`, поддерживающим параметр `--offset` (актуальные версии dosfstools). Образ создаётся с MBR и разделом, смещённым на LBA 2048, чтобы хост видел стандартную схему removable disk. Если хотите пустой неформатированный образ:

```bash
python3 scripts/create-msd-image.py --path runs/storage/usb-lab.img --size-mib 64
```

Скрипт отказывается перезаписывать существующий образ без `--force`; этот флаг уничтожит данные в старом файле. Путь `backing_file` внутри JSON можно изменить, но он разрешается относительно текущего каталога процесса. Запускайте проект из корня репозитория либо задавайте абсолютный путь.

**Критически важно:** пока Windows держит виртуальный диск подключённым, не монтируйте и не редактируйте тот же backing image на Raspberry Pi. Это может повредить файловую систему. Используйте отдельный образ для каждой одновременной лабораторной сессии. Реализация нацелена на тестирование, а не на production storage.

## 8. Ручной запуск классов

Для всех команд ниже предполагается, что `$UDC_DRIVER` и `$UDC_DEVICE` заданы в текущем shell, как в разделе 3. Перед каждым ручным тестом начинайте захват Wireshark, после него останавливайте захват и анализируйте PCAPNG.

### HID keyboard — нейтральный отчёт

```bash
sudo build/usb-connect run profiles/templates/hid-keyboard.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/hid-keyboard/device.jsonl --run-id hid-keyboard
```

### HID gamepad / joystick

```bash
sudo build/usb-connect run profiles/templates/hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/hid-gamepad/device.jsonl --run-id hid-gamepad
```

Для джойстика замените путь на `profiles/templates/hid-joystick.json` и имя каталога trace.

### CDC ACM serial

```bash
sudo build/usb-connect run profiles/templates/cdc-acm-serial.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/cdc-acm/device.jsonl --run-id cdc-acm
```

Профиль отвечает на GET/SET_LINE_CODING, SET_CONTROL_LINE_STATE и SEND_BREAK. Bulk-данные, полученные на OUT endpoint, можно получить обратно на парном IN endpoint. Для теста данных откройте соответствующий COM-порт в терминальном приложении на тестовом Windows-ПК и отправьте текст; один только Wireshark не посылает CDC serial data.

### Mass Storage BOT

Сначала создайте образ из раздела 7, потом:

```bash
sudo build/usb-connect run profiles/templates/msc-bot-disk.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/msc-bot/device.jsonl --run-id msc-bot
```

Реализованы один LUN и типичные SCSI-команды INQUIRY, TEST UNIT READY, REQUEST SENSE, MODE SENSE, READ CAPACITY, READ/WRITE(10/12/16), START STOP UNIT, PREVENT/ALLOW REMOVAL и SYNCHRONIZE CACHE. Устройства могут запросить другие команды; тогда расширяйте SCSI-обработчик под конкретный host trace. Это не полная замена Linux `usb-storage`/`f_mass_storage` для всех вариантов протокола.

### Composite / multi-configuration

Профиль CDC+HID keyboard:

```bash
sudo build/usb-connect run profiles/templates/composite-cdc-hid-keyboard.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-cdc-hid/device.jsonl --run-id composite-cdc-hid
```

Профиль Mass Storage + gamepad требует созданного образа из раздела 7:

```bash
sudo build/usb-connect run profiles/templates/composite-msc-hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-msc-hid/device.jsonl --run-id composite-msc-hid
```

Три HID-интерфейса в одной конфигурации (клавиатура, мышь, consumer control):

```bash
sudo build/usb-connect run profiles/templates/composite-hid-keyboard-mouse-consumer.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-hid/device.jsonl --run-id composite-hid
```

Расширенный вариант CDC ACM + Mass Storage BOT + HID gamepad (нужен образ диска и больше ресурсов UDC):

```bash
sudo build/usb-connect run profiles/templates/composite-cdc-msc-hid-gamepad.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/composite-cdc-msc-hid/device.jsonl --run-id composite-cdc-msc-hid
```

Две альтернативные конфигурации keyboard/mouse:

```bash
sudo build/usb-connect run profiles/templates/multi-config-keyboard-mouse.json \
  --backend raw-gadget --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --speed high --trace runs/multi-config/device.jsonl --run-id multi-config
```

Составные профили содержат несколько endpoints и потому зависят от их числа/направления, packet-size и поддержки типов endpoint конкретным UDC. Если `ENDPOINT_ENABLE_ERROR` фиксируется, посмотрите `ENDPOINT_CAPABILITIES` в trace. Runtime alternate-setting switching и isochronous I/O пока не реализованы.

## 9. Генерация профилей для проверки до реального старта

Сперва создайте план `dry-run` — он не подключает USB:

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
PLAN="runs/fuzz/dry-run-$STAMP"
python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --count 5 --seed 20261028 --mutations 1 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --out-dir "$PLAN" --dry-run
```

Посмотреть манифест и профили:

```bash
cat "$PLAN/summary.json"
less "$PLAN/manifest.json"
ls "$PLAN"/case-*.json
```

`--mutations N` — максимум N отдельных изменений поля на профиль. Уникальность профилей следует проверять отдельно: 1000 записей не гарантируют 1000 уникальных USB-конфигураций.

## 10. Малый запуск фаззинга с Live Console

Сначала убедитесь, что базовый profile стартует и Wireshark действительно фиксирует USB-запросы. Затем проведите кампанию из пяти случаев. Новые имена каталогов предотвращают затирание предыдущих результатов:

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="runs/fuzz/hid-smoke-$STAMP"
CAPTURE_DIR="/srv/usb-captures/hid-smoke-$STAMP"
sudo install -d -m 2770 -o "$USER" -g "$(id -gn)" "$CAPTURE_DIR"
echo "Результаты: $OUT"
echo "Захваты: $CAPTURE_DIR"
```

На Windows начните USBPcap захват. Затем на Pi:

```bash
sudo python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --count 5 --seed 20261028 --mutations 1 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --dwell-seconds 10 --settle-seconds 3 \
  --live-progress-interval 1 \
  --capture-dir "$CAPTURE_DIR" --out-dir "$OUT" \
  --allow-research --confirm-lab
```

Во время запуска Live Console показывает имя профиля, SHA-256, изменённые параметры, события GET_DESCRIPTOR/EP0, SET_CONFIGURATION, STALL/RESET и статус процесса по мере появления trace-событий.

- `START_FAILED` означает, что сам процесс не запустился; это не свидетельство реакции Windows.
- `RUNNING` означает, что процесс Gadget жив.
- `CONTROL_REQUEST` означает, что Raw Gadget получил управляющий запрос хоста.
- `SET_CONFIGURATION` означает, что в журнале зафиксирован ненулевой выбранный конфиг.
- `COMPLETED` означает только, что процесс проработал заданное время и был корректно завершён; это не обещает, что Windows успешно приняла устройство.

Не переходите к сотням вариантов, если почти все случаи — `START_FAILED` или trace не показывает запросов хоста. Сначала исправьте UDC/descriptor/runtime.

## 11. Результаты и изменения каждого профиля

После кампании поправьте владельца файлов (процесс обычно запускается через `sudo`):

```bash
sudo chown -R "$USER:$(id -gn)" "$OUT"
```

Сводка:

```bash
python3 -m json.tool "$OUT/summary.json" | less
```

Один объект кампании на строку:

```bash
less "$OUT/campaign.jsonl"
```

Trace и ошибки:

```bash
find "$OUT/traces" -maxdepth 1 -type f -print
cat "$OUT/traces/case-00001.stderr.log"
less "$OUT/traces/case-00001.device.jsonl"
```

Проще всего вывести изменения, статусы всех случаев и краткую статистику trace отдельным скриптом:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT"
```

Только один случай (например, `case-00018`):

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --case 18
```

Только случаи из очереди дополнительной проверки:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --only-review
python3 scripts/show-review-changes.py --campaign-dir "$OUT"
```

Сохранить структурированный JSON-отчёт:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT" --out "$OUT/all-changes.json"
```

Показать отличия всех `case-*.json` от исходного шаблона вручную (резервный вариант):

```bash
python3 - "$OUT" profiles/templates/hid-mouse.json <<'PY'
import json, sys
from pathlib import Path
campaign=Path(sys.argv[1]); base=json.loads(Path(sys.argv[2]).read_text())

def diff(a,b,path='$'):
    if isinstance(a,dict) and isinstance(b,dict):
        for k in sorted(set(a)|set(b)):
            p=f'{path}.{k}'
            if k not in a: print(f'  + {p}: {b[k]!r}')
            elif k not in b: print(f'  - {p}: {a[k]!r}')
            else: diff(a[k],b[k],p)
    elif isinstance(a,list) and isinstance(b,list):
        for i in range(max(len(a),len(b))):
            p=f'{path}[{i}]'
            if i>=len(a): print(f'  + {p}: {b[i]!r}')
            elif i>=len(b): print(f'  - {p}: {a[i]!r}')
            else: diff(a[i],b[i],p)
    elif a != b and path != '$.profile_name': print(f'  ~ {path}: {a!r} -> {b!r}')

for p in sorted(campaign.glob('case-*.json')):
    print(f'\n=== {p.name} ===')
    diff(base,json.loads(p.read_text()))
PY
```

Если установлен `scripts/show-all-changes.py`, он может вывести компактный отчёт по каждому случаю:

```bash
python3 scripts/show-all-changes.py --campaign-dir "$OUT"
```

Поле `profile_sha256` идентифицирует точный JSON, полезно для воспроизведения и сравнения.

## 12. PCAPNG анализ и статусы

После завершения кампании остановите захват Wireshark, сохраните PCAPNG и проверьте путь:

```bash
find "$CAPTURE_DIR" -maxdepth 2 -type f -print
```

Запустите анализатор после того, как файлы PCAPNG сохранены:

```bash
python3 scripts/review-usb-campaign.py \
  --campaign-dir "$OUT" --capture-dir "$CAPTURE_DIR"
python3 -m json.tool "$OUT/review-queue.json" | less
```

Для сопоставления одного случая с одним PCAPNG используйте `usb-lab compare` или отдельный вызов `compare` с фактическими путями. Если одна непрерывная PCAPNG покрывает десятки тестов, её нельзя считать независимой трассой каждого случая без разделения по времени; иначе события разных профилей могут смешаться.

Статусы сопоставления:

- `CORRELATED` — сравнимые сигнатуры совпали;
- `PARTIAL_CORRELATION` — есть совпавшие и непарные наблюдения;
- `NO_CORRELATION` — сравнимые сигнатуры не сопоставились;
- `DISCONNECT_OBSERVED` — явное событие отключения по данным источника;
- `RESET_OR_DISCONNECT_OBSERVED` — UDC сообщил неоднозначное событие reset/disconnect;
- `ERROR_OR_STALL_OBSERVED` — обнаружена ошибка/STALL/тайм-аут;
- `NO_HOST_EVIDENCE` — в нормализованном захвате нет событий;
- `POSSIBLE_DISCONNECT` — host status совместим с исчезновением устройства, но требует проверки.

Это статусы наблюдений, не диагноз Windows. `NO_HOST_EVIDENCE` может означать неправильный USBPcap interface; `NO_CORRELATION` — несовпадающий формат событий; `ERROR_OR_STALL_OBSERVED` может быть обычным ответом на некорректный дескриптор. PCAPNG сам по себе не подтверждает kernel panic/BSOD.

## 13. Повтор одного случая

Например, повторить `case 18` из завершённой кампании:

```bash
REPLAY_OUT="runs/fuzz/replay-case-18-$(date +%Y%m%d-%H%M%S)"
REPLAY_CAPTURE="/srv/usb-captures/replay-case-18-$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 2770 -o "$USER" -g "$(id -gn)" "$REPLAY_CAPTURE"
```

Начните новый USBPcap захват, затем выполните:

```bash
sudo python3 scripts/usb-gadget-campaign.py \
  --base profiles/templates/hid-mouse.json \
  --replay-from "$OUT" --replay-case 18 \
  --udc-driver "$UDC_DRIVER" --udc-device "$UDC_DEVICE" \
  --dwell-seconds 10 --settle-seconds 0 \
  --capture-dir "$REPLAY_CAPTURE" --out-dir "$REPLAY_OUT" \
  --allow-research --confirm-lab --stop-on-error
```

После теста остановите захват, сохраните PCAPNG, поправьте владельца файлов и запустите `review-usb-campaign.py` для каталога `REPLAY_OUT`. Для точного повторения сохраняйте оригинальный JSON, seed и SHA-256; не генерируйте новую мутацию вместо replay.

## 14. Частые проблемы

### В консоли `UDC driver= | UDC device=`

Переменные пустые в текущем терминале. Повторите:

```bash
export UDC_DRIVER='fe980000.usb'
export UDC_DEVICE='fe980000.usb'
printf '%s / %s\n' "$UDC_DRIVER" "$UDC_DEVICE"
```

Либо подставьте значения прямо в аргументы команды. Используйте фактические имена из `sudo build/usb-connect probe`.

### `START_FAILED` за 0.1–0.2 секунды

Посмотрите `traces/case-NNNNN.stderr.log` и `stdout.log`. Типичные причины: невалидный профиль, отсутствующий backing image для MSC, неподдерживаемые endpoint-адрес/тип/packet-size или занятый UDC. `profile_valid: true` не означает, что endpoint можно активировать на конкретном UDC. Теперь runner сразу отклоняет пустые `--udc-driver`/`--udc-device`, чтобы не выполнять бесполезную кампанию.

### `--out-dir уже существует и не пуст`

Защита от случайной перезаписи предыдущей кампании. Создайте новое имя каталога, например с датой/временем:

```bash
OUT="runs/fuzz/hid-$(date +%Y%m%d-%H%M%S)"
```

И передайте его как `--out-dir "$OUT"`.

### В trace есть `CONTROL_REQUEST`, в Wireshark ноль кадров

Проверьте USBPcap interface / Root Hub и отсутствие display filter. Не считайте пустой PCAP доказательством, что обмена USB не было.

### `/sys/class/udc/.../state` показывает `not attached`

Проверяйте его во время работы, в отдельном терминале:

```bash
watch -n 0.5 cat /sys/class/udc/fe980000.usb/state
```

После остановки Gadget `not attached` ожидаем. Дополнительно изучайте `UDC_BOUND`, `CONTROL_REQUEST`, `SET_CONFIGURATION` и физическое соединение.

### `PermissionError` для результатов, созданных `sudo`

```bash
sudo chown -R "$USER:$(id -gn)" runs/fuzz/ИМЯ_КАМПАНИИ
```

### MSC image already exists

Не добавляйте `--force`, если хотите сохранить содержимое диска. Укажите новый путь и обновите `runtime.mass_storage.backing_file` в профиле.

### Композитный профиль не запускается

Посмотрите `ENDPOINT_CAPABILITIES` и `ENDPOINT_ENABLE_ERROR` в trace. Некоторые UDC имеют фиксированную раскладку endpoint и не смогут отобразить всякий дескриптор. Попробуйте профиль с меньшим числом интерфейсов; это ограничение hardware backend, а не обязательно ошибка Windows.

---

## Источники и спецификации

- Linux Kernel documentation: [USB Raw Gadget](https://docs.kernel.org/usb/raw-gadget.html) — низкоуровневый userspace API, debugging-only характер интерфейса.
- USB-IF: [Mass Storage Bulk-Only Transport](https://www.usb.org/sites/default/files/usbmassbulk_10.pdf) — форматы CBW/CSW и требования BOT.
- USB-IF: [HID Specifications and Tools](https://usb.org/hid) — HID class и Usage Tables.
- Microsoft Learn: [HID Usages](https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/hid-usages) — классы Generic Desktop, Keyboard, Joystick и Game Pad.

VID/PID в шаблонах — учебные значения. Используйте только идентификаторы, разрешённые для вашей среды.


## Побайтовый отчёт по всей кампании: ожидаемый профиль слева, USBPcap справа

Если нужен ответ не просто «сколько было запросов», а **какие дескрипторы ожидались и какие байты ответа увидел Windows USBPcap**, остановите захват после кампании, сохраните один общий PCAPNG и запустите новый анализатор. Он создаёт три отчёта: HTML с двумя боковыми панелями, TXT с таблицей байт по смещениям и JSON с машинно-читаемыми результатами.

```bash
python3 scripts/report-usb-campaign.py \
  --campaign-dir runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS \
  --host-pcap /srv/usb-captures/hid-campaign-YYYYMMDD-HHMMSS/campaign.pcapng \
  --time-tolerance 0.75
```

Фактические имена каталогов и PCAPNG нужно заменить своими. По умолчанию отчёты сохраняются в каталоге кампании:

- `protocol-report.html` — каждый GET_DESCRIPTOR: слева HEX профиля, справа байты ответа из USBPcap, различия подсвечены, под ними декодирование Device/Configuration/Interface/Endpoint/String/HID headers;
- `protocol-report.txt` — те же данные в текстовом виде, включая таблицу `offset | expected | USBPcap | result`;
- `protocol-report.json` — статусы, кадры, временные окна и детали сравнения для автоматической обработки.

Откройте HTML в браузере:

```bash
xdg-open runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/protocol-report.html
```

Или посмотрите TXT прямо в терминале:

```bash
less runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/protocol-report.txt
```

Скрипт берёт ожидаемые байты из **точного `case-NNNNN.json` данного запуска**, а не из исходного шаблона, поэтому учитывает фактические мутации. Он связывает PCAP кадры со случаем по `started_epoch`/`ended_epoch` из `campaign.jsonl` и времени `frame.time_epoch` из TShark. Часы Windows и Pi должны быть синхронизированы. По умолчанию задан допуск 0,75 секунды у краёв каждого временного окна. Если Windows clock опережает Pi на 2 секунды, вычтите такую разницу из timestamp хоста:

```bash
python3 scripts/report-usb-campaign.py \
  --campaign-dir runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS \
  --host-pcap /srv/usb-captures/hid-campaign-YYYYMMDD-HHMMSS/campaign.pcapng \
  --host-clock-offset-seconds 2.0
```

Это работает надёжно только при отдельном/изолированном тестовом USB-порту и корректных временных метках. В общий захват могут попасть другие устройства той же шины. Если TShark не смог извлечь байты ответа, отчёт покажет `HOST_BYTES_NOT_EXTRACTED`, а не выдаст совпадение по умолчанию. Если дескриптор не виден в PCAP, состояние будет `NOT_OBSERVED_IN_PCAP`; оно не доказывает, что хост никогда его не запрашивал — возможны неправильный интерфейс USBPcap, неполный захват или сдвиг часов.

Основные статусы:

- `EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED` — все полученные и сравнимые ответы дескрипторов совпали с профилем; ненулевая конфигурация наблюдалась и на хосте, и в trace устройства.
- `EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL` — байты совпали, но факт конфигурирования подтвердил только один источник.
- `EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE` — сравнимые байты совпали, но CONFIGURED не подтверждён.
- `HOST_DESCRIPTOR_BYTES_MISMATCH` — в ответе USBPcap есть байты или длина, отличающиеся от ожидаемого дескриптора. Отчёт показывает первое смещение и всю побайтовую таблицу.
- `HOST_RESPONSE_BYTES_UNAVAILABLE` — запрос замечен, но ответные байты не удалось извлечь.
- `HOST_TRANSFER_ERROR_OBSERVED` — TShark обнаружил ошибочный статус host transfer.
- `HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE` — хост запросил дескриптор, которого нет в ожидаемом каталоге профиля.
- `NO_HOST_EVIDENCE_FOR_CASE` — в временном окне не найден подходящий USB-трафик.
- `DEVICE_START_FAILED` — устройство не запустилось; хостовые кадры этого окна не выдаются за данные данного профиля.

Этот отчёт сравнивает **ожидаемые байты профиля с байтами, видимыми в PCAPNG** и отдельно показывает события из Raw Gadget trace. Он не является анализатором электрического USB-уровня и не подтверждает физические ACK/NAK/CRC. Для передачи данных после конфигурации итог следует толковать с учётом класса устройства; полное совпадение дескрипторов не гарантирует корректность всей реализации CDC/MSC/HID.

### Тест отчёта без реального USB

```bash
python3 tests/test_campaign_byte_report.py scripts/report-usb-campaign.py
```

Тест использует имитированный TShark, поэтому проверяет формирование отчётов и обнаружение byte mismatch, но не заменяет анализ реального захвата.

## Проверка корректности одного случая: профиль → trace → Wireshark

Одного статуса `COMPLETED` недостаточно. После сохранения отдельного PCAPNG для выбранного случая можно проверить байты дескрипторов в trace относительно точного JSON-профиля, состояние `SET_CONFIGURATION`, ожидаемые/enabled endpoints, HID IN payloads и сопоставление с наблюдениями host stack:

```bash
python3 scripts/verify-usb-case.py \
  --profile runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/case-00002.json \
  --device-trace runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/traces/case-00002.device.jsonl \
  --host-pcap /srv/usb-captures/case-00002.pcapng \
  --source windows_host \
  --out runs/fuzz/hid-campaign-YYYYMMDD-HHMMSS/verify-case-00002.json
```

`case-00002.pcapng` должен содержать захват именно этого одного теста. Если у тебя один непрерывный PCAPNG на всю кампанию, сначала раздели его по временным окнам случаев; простое сравнение общего файла с одним trace может сопоставить одинаковые запросы из разных вариантов. Без `--host-pcap` скрипт проверяет только локальный profile/trace и честно вернёт неполный вердикт.

Возможные итоговые вердикты: `PASS_OBSERVED_CORRELATED` (профиль/trace совпали, конфигурация зафиксирована, локальные проверки прошли и per-case host correlation совпала), `EXPECTED_REJECTION_POSSIBLE_NOT_CONFIGURED` (профиль не проходит strict validation и enumeration не дошло до CONFIGURED), `REVIEW_PROTOCOL_ANOMALY`, `INCOMPLETE_HOST_BYTES_NOT_VERIFIED`, `INCONCLUSIVE_SHARED_PCAP_NEEDS_PER_CASE_CAPTURE`, а также fail при несовпадении ожидаемых и trace descriptor bytes. Даже `PASS_OBSERVED_CORRELATED` означает программное подтверждение через USBPcap/host stack, а не проверку физического уровня USB; для проверки ACK/NAK/CRC требуется аппаратный USB-анализатор.
