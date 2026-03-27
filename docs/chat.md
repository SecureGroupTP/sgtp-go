# SGTP Web Chat — Протокол медиа-сообщений

> **Версия:** 1.0 · Дата: 2026-03

---

## Введение

SGTP передаёт произвольные байты в поле `ciphertext` пакета `MESSAGE`. Веб-клиент использует эту возможность, кодируя в этих байтах **JSON-объект ChatPayload**. Сам протокол SGTP не знает ни о каком JSON — он просто шифрует и доставляет байты.

```
SGTP MESSAGE.ciphertext = ChaCha20-Poly1305(CK, nonce, JSON(ChatPayload))
```

Все ChatPayload-ы подписаны ed25519 самим SGTP-фреймом, поэтому аутентентичность гарантирована на уровне протокола.

---

## Архитектура веб-клиента

```
Browser (web/index.html)
    │  WebSocket JSON API
    ▼
cmd/webbridge  ─── SGTP protocol (TCP) ──▶  cmd/server (relay)
    │                                            │
    │                                        TCP broadcast
    │                                            ▼
    └─────────────────────────────────  other SGTP clients
                                        (Go CLI, other browsers)
```

Мост (`webbridge`) создаёт один SGTP-клиент на каждое WebSocket-соединение. Криптография (ed25519, x25519, ChaCha20-Poly1305) работает на стороне Go, браузер получает чистый JSON.

---

## ChatPayload — универсальная структура

```ts
interface ChatPayload {
  v:    1;          // версия формата
  type: MessageType;
  // дополнительные поля зависят от type
}

type MessageType =
  | "text"          // текстовое сообщение
  | "file"          // произвольный файл
  | "image"         // изображение (inline preview)
  | "audio"         // голосовое сообщение
  | "video"         // видеозапись
  | "call_offer"    // WebRTC: инициатор звонка (SDP offer)
  | "call_answer"   // WebRTC: принятие звонка (SDP answer)
  | "call_ice"      // WebRTC: ICE candidate
  | "call_hangup"   // завершение звонка
  | "call_reject"   // отказ от звонка
  | "system";       // системное событие (не отображается пользователю)
```

---

## Текстовое сообщение — `type: "text"`

```jsonc
{
  "v": 1,
  "type": "text",
  "text": "Привет! Как дела?"
}
```

| Поле | Тип | Обязательное | Описание |
|------|-----|:---:|---------|
| `text` | string | ✅ | UTF-8 текст сообщения. Максимум 65 535 символов. |

---

## Файлы — `type: "file" | "image" | "audio" | "video"`

Файлы до **~10 MiB** (с учётом MAX_PAYLOAD_LENGTH = 16 MiB и накладных расходов) передаются в одном сообщении. Файлы крупнее разбиваются на чанки.

### Однофреймовая передача (≤ ~10 MiB)

```jsonc
{
  "v": 1,
  "type": "image",          // или "file", "audio", "video"
  "file_id": "uuid-v4",    // уникальный ID файла (генерирует отправитель)
  "name": "photo.jpg",
  "mime": "image/jpeg",
  "size": 204800,           // размер в байтах
  "data": "<base64>",       // содержимое файла (base64 standard encoding)
  "thumb": "<base64>",      // JPEG превью 120×120 (только для image/video, опционально)
  "duration": 12.4          // секунды (только для audio/video, опционально)
}
```

### Чанкованная передача (> ~10 MiB)

Отправитель режет файл на части по 8 MiB. Каждая часть — отдельное MESSAGE:

```jsonc
// Chunk N из M
{
  "v": 1,
  "type": "file",
  "file_id": "uuid-v4",    // один и тот же для всех чанков
  "name": "archive.tar.gz",
  "mime": "application/gzip",
  "size": 52428800,         // полный размер файла
  "chunk": 0,               // индекс чанка (0-based)
  "chunks": 7,              // всего чанков
  "data": "<base64>"        // данные этого чанка
}
```

Получатель собирает чанки по `file_id` + `chunk`, после получения всех `chunks` предлагает скачать файл.

---

## Голосовые сообщения — `type: "audio"`

```jsonc
{
  "v": 1,
  "type": "audio",
  "file_id": "uuid-v4",
  "name": "voice_2026-03-27.ogg",
  "mime": "audio/ogg; codecs=opus",
  "size": 45678,
  "duration": 8.3,
  "data": "<base64>"
}
```

Веб-клиент записывает аудио через `MediaRecorder` API с кодеком Opus в контейнере OGG или WebM. Битрейт рекомендуется 32 kbps. Для длинных голосовых (> ~3 минут) применяется чанкование с `chunk`/`chunks`.

---

## Аудио/видео звонки — WebRTC через SGTP

SGTP используется **только как сигнальный канал**. Медиапотоки передаются через WebRTC (peer-to-peer) и **не проходят через relay-сервер**.

Шифрование WebRTC (DTLS-SRTP) независимо от SGTP; в сочетании с SGTP-шифрованием сигналов обеспечивается end-to-end защита сессии.

### call_offer — звонящий

```jsonc
{
  "v": 1,
  "type": "call_offer",
  "call_id": "uuid-v4",
  "call_type": "audio",    // "audio" | "video"
  "sdp": "v=0\r\no=- ..."  // SDP offer (строка)
}
```

### call_answer — принявший

```jsonc
{
  "v": 1,
  "type": "call_answer",
  "call_id": "uuid-v4",
  "sdp": "v=0\r\no=- ..."  // SDP answer
}
```

### call_ice — ICE-кандидат (оба направления)

```jsonc
{
  "v": 1,
  "type": "call_ice",
  "call_id": "uuid-v4",
  "candidate": {
    "candidate": "candidate:...",
    "sdpMLineIndex": 0,
    "sdpMid": "0"
  }
}
```

### call_hangup / call_reject

```jsonc
{ "v": 1, "type": "call_hangup", "call_id": "uuid-v4" }
{ "v": 1, "type": "call_reject",  "call_id": "uuid-v4" }
```

### Флоу звонка

```
Alice                      (SGTP broadcast)                      Bob
  │                                                               │
  │──[ call_offer {call_id, call_type, sdp} ]────────────────────▶│
  │                                                               │
  │◀─[ call_answer {call_id, sdp} ]──────────────────────────────│
  │                                                               │
  │──[ call_ice ... ]◀──────────────────────────────[ call_ice ]──│
  │  (обмен ICE идёт параллельно)                                 │
  │                                                               │
  ╔═══════════════════════════════════════════════════════════════╗
  ║         WebRTC P2P медиапоток (DTLS-SRTP, вне SGTP)          ║
  ╚═══════════════════════════════════════════════════════════════╝
  │                                                               │
  │──[ call_hangup {call_id} ]────────────────────────────────────▶│
```

**Групповые звонки**: для N участников сигнальные сообщения рассылаются через SGTP broadcast. WebRTC-соединение устанавливается либо как mesh (каждый с каждым, до 4 человек), либо через SFU.

---

## WebSocket API (браузер ↔ webbridge)

### Команды браузера → мост

| Поле `cmd` | Описание |
|-----------|----------|
| `init` | Подключиться к SGTP. Поля: `server` (адрес relay), `room` (hex UUID или пусто = новая), `key` (hex 64B ed25519 privkey или пусто = генерировать), `nick` (никнейм) |
| `msg` | Отправить сообщение. Поле `payload`: объект ChatPayload |
| `history` | Запросить историю |
| `quit` | Отключиться от SGTP |

```jsonc
// Пример: подключение
{"cmd": "init", "server": "localhost:7777", "room": "", "nick": "Alice"}

// Пример: отправка текста
{"cmd": "msg", "payload": {"v":1,"type":"text","text":"Привет!"}}

// Пример: отправка изображения
{"cmd": "msg", "payload": {"v":1,"type":"image","file_id":"...","name":"cat.jpg","mime":"image/jpeg","size":12345,"data":"<base64>"}}
```

### События мост → браузер

| Поле `evt` | Описание |
|-----------|----------|
| `ready` | Успешное подключение. Поля: `uuid`, `room`, `pubkey`, `nick` |
| `peer_join` | Новый участник. Поля: `uuid`, `pubkey` |
| `peer_leave` | Участник отключился. Поле: `uuid` |
| `peer_kick` | Участник исключён. Поле: `uuid` |
| `msg` | Входящее сообщение. Поля: `uuid`, `from`, `ts`, `seq`, `payload` |
| `msg_echo` | Эхо отправленного (для немедленного отображения в UI). Те же поля |
| `msg_failed` | Сообщение отклонено при ротации CK. Поле: `uuid` |
| `ck_rotated` | Chat Key обновлён |
| `history_done` | История доставлена |
| `error` | Ошибка. Поле: `msg` |

---

## Размеры и ограничения

| Параметр | Значение |
|---------|---------|
| MAX_PAYLOAD_LENGTH (SGTP) | 16 MiB |
| Рекомендуемый чанк | 8 MiB (base64 ≈ 10.9 MiB в JSON) |
| Максимальный текст | 65 535 символов |
| Аудио битрейт | 32 kbps Opus |
| Видео битрейт (превью) | не отправляется, только thumb |
| Максимальная длительность voice | без ограничений (чанкование) |

---

## Безопасность

- **Шифрование файлов** — аналогично тексту: ChaCha20-Poly1305 с Chat Key. Relay-сервер видит только зашифрованные байты.
- **Аутентичность** — каждый фрейм (включая файловые чанки) подписан ed25519 отправителя.
- **WebRTC** — медиапотоки шифруются DTLS-SRTP независимо. SDP/ICE сигналы защищены SGTP.
- **Превью изображений** — thumbnail генерируется на стороне браузера до отправки и передаётся вместе с файлом в одном зашифрованном сообщении.
- **Nickname** — хранится только в bridge-сессии и передаётся в `call_offer`/`call_answer` для UI. Не аутентифицируется протоколом — доверие основано на ed25519-ключе.

---

*Конец спецификации chat.md v1.0*
