# SGTP Client — документация

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Ключи и whitelist](#ключи-и-whitelist)
3. [Запуск](#запуск)
4. [Жизненный цикл сессии](#жизненный-цикл-сессии)
5. [История сообщений](#история-сообщений)
6. [Использование как библиотека](#использование-как-библиотека)
7. [Интерфейс IClient](#интерфейс-iclient)
8. [Конфигурация Config](#конфигурация-config)
9. [События и каналы](#события-и-каналы)
10. [HistoryStore](#historystore)
11. [Ограничения и известные факты](#ограничения-и-известные-факты)

---

## Быстрый старт

```bash
# 1. Сгенерировать ключи для всех участников (одноразово)
ssh-keygen -t ed25519 -f ./keys/alice -N ""
ssh-keygen -t ed25519 -f ./keys/bob   -N ""
ssh-keygen -t ed25519 -f ./keys/carol -N ""
# в ./keys/ теперь: alice, alice.pub, bob, bob.pub, carol, carol.pub

# 2. Поднять relay-сервер (нужен один раз, на любой машине)
go run ./cmd/server -addr :7777

# 3. Alice создаёт комнату, указывает папку с ключами как whitelist
go run ./cmd/chat \
    -key       ./keys/alice \
    -whitelist ./keys/ \
    -server    localhost:7777
# → выводит Room UUID, скопировать его

# 4. Остальные подключаются с тем же UUID комнаты
go run ./cmd/chat \
    -key       ./keys/bob \
    -whitelist ./keys/ \
    -room      <room-uuid-от-alice> \
    -server    localhost:7777
```

При старте клиент сканирует папку и печатает что загрузил:

```
Whitelist directory: ./keys/
  Loaded 3 key(s):
    ✓ alice.pub
    ✓ bob.pub
    ✓ carol.pub
  Skipped 3 file(s) (not a valid ed25519 public key):
    – alice
    – bob
    – carol
```

Приватные ключи, RSA, ECDSA и любые другие файлы, которые не парсятся как ed25519 публичный ключ, молча пропускаются.

После обмена ключами (PING/PONG) мастер автоматически выдаёт Chat Key, и оба участника могут переписываться.

---

## Ключи и whitelist

### Форматы ключей

Клиент принимает приватные ключи в двух форматах:

| Формат | Пример файла | Как создать |
|--------|-------------|-------------|
| OpenSSH | `~/.ssh/id_ed25519` | `ssh-keygen -t ed25519` |
| Raw bytes | 64 байта приватного ключа | `protocol.GenerateEd25519()` |

Публичные ключи (для `-peer`) принимаются в форматах:
- OpenSSH authorized_keys: `ssh-ed25519 AAAA… comment`
- Raw bytes: 32 байта

### Принцип whitelist

**Клиент принимает PING и PONG только от пиров, чей публичный ключ ed25519 есть в whitelist.**

Whitelist строится из директории, переданной через `-whitelist`. Клиент сканирует все файлы в директории и пробует загрузить каждый как ed25519 публичный ключ. Файлы, которые не парсятся (приватные ключи, RSA, ECDSA, бинарный мусор), молча пропускаются — это намеренно, чтобы можно было указать папку, где вперемешку лежат и приватные, и публичные ключи.

> Whitelist привязан к **публичному ключу**, а не к UUID. UUID генерируется случайно при каждом запуске и не аутентифицирует участника.

---

## Запуск

### Флаги `cmd/chat`

| Флаг | Обязательный | По умолчанию | Описание |
|------|-------------|--------------|----------|
| `-key <path>` | ✅ | — | Путь к файлу приватного ключа |
| `-whitelist <dir>` | ❌ | — | Директория с публичными ключами доверенных пиров |
| `-room <hex>` | ❌ | новый UUID | UUID комнаты в виде 32 hex-символов |
| `-server <addr>` | ❌ | `localhost:7777` | Адрес relay-сервера |
| `-infodelay <dur>` | ❌ | `500ms` | Задержка перед отправкой INFO после первого PONG |

`-whitelist` сканирует директорию и пробует загрузить каждый файл как ed25519 публичный ключ (OpenSSH или raw 32 байта). Файлы, которые не являются ed25519 публичным ключом (приватные ключи, RSA, ECDSA и т.д.), молча пропускаются. При старте печатается список загруженных и пропущенных файлов.

### Команды в чате

| Команда | Действие |
|---------|----------|
| `/peers` | Показать список известных пиров с UUID |
| `/master` | Показать, является ли текущий клиент мастером |
| `/history` | Запросить и показать историю сообщений вручную |
| `/quit` или `/exit` | Отключиться и завершить работу |

---

## Жизненный цикл сессии

```
Client A                    Relay Server              Client B (master)
    │                            │                          │
    │─── TCP connect ───────────>│                          │
    │─── intent frame ──────────>│──── broadcast ──────────>│
    │                            │                          │
    │<── PING (x25519+ed25519) ──│<─────────────────────────│
    │─── PONG (x25519+ed25519) ─>│─────────────────────────>│
    │                            │                          │
    │  (ждёт InfoDelay)          │                          │
    │─── INFO request ──────────>│─────────────────────────>│
    │<── INFO response ──────────│<─────────────────────────│
    │                            │                          │
    │─── CHAT_REQUEST ──────────>│─────────────────────────>│
    │                            │   (мастер проверяет      │
    │                            │    whitelist всех пиров) │
    │<── CHAT_KEY (зашифр.) ─────│<─────────────────────────│
    │─── CHAT_KEY_ACK ──────────>│─────────────────────────>│
    │                            │                          │
    │  ✓ Chat Key активен        │                          │
    │                            │                          │
    │─── MESSAGE (broadcast) ───>│──── broadcast ──────────>│
    │<── MESSAGE ────────────────│<─────────────────────────│
```

### Роль мастера

Мастер — участник с наименьшим UUID в комнате. Мастер:
- Принимает `CHAT_REQUEST` от новых участников и выдаёт Chat Key
- Ротирует Chat Key каждые 180 секунд
- Обрабатывает `KICK_REQUEST` — проверяет доступность пира и рассылает `KICKED`
- При уходе пира (`FIN`) немедленно ротирует Chat Key

Если мастер уходит офлайн, следующий по UUID участник автоматически принимает роль мастера (§7.3 спецификации).

---

## История сообщений

### Автоматический запрос при входе

Когда клиент подключается к **уже активной комнате** (в которой есть другие участники), он автоматически запрашивает историю сразу после получения первого Chat Key.

Поведение:
```
(waiting for Chat Key …)
✓ Chat Key active.

─── history: 3 message(s) ─────────────────────────────────────
[~14:22:01] ab12…> привет всем
[~14:23:45] cd34…> как дела?
[~14:25:10] ab12…> отлично
─── end of history ─────────────────────────────────────────────
─── ready ─── Commands: /quit  /peers  /master  /history
>
```

Сообщения из истории помечаются тильдой `~` перед временем.

Если клиент первым заходит в пустую комнату — запрос истории не производится.

### Ручной запрос

```
> /history
─── history: 5 message(s) ─────────────────────────────────────
[~14:22:01] ab12…> hello
...
─── end of history ─────────────────────────────────────────────
>
```

### Что хранится в истории

Каждый клиент хранит историю **только того Chat Key (эпохи)**, который был активен во время получения сообщений. Сообщения из предыдущих эпох не могут быть расшифрованы новым участником — это намеренно и обеспечивает **forward secrecy**.

Протокол выбирает участника с наибольшим количеством сообщений для ответа на запрос истории (`HSIR → HSI → HSR → HSRA`).

---

## Использование как библиотека

```go
import (
    sgtp "github.com/SecureGroupTP/sgtp-go/client"
    "github.com/SecureGroupTP/sgtp-go/protocol"
)

// 1. Загрузить ключи
pub, priv, _ := protocol.LoadEd25519FromOpenSSHFile("./keys/alice")

```go
// Whitelist из директории
wl := make(map[[32]byte]struct{})
entries, _ := os.ReadDir("./keys/")
for _, e := range entries {
    pub, _, err := protocol.LoadEd25519FromOpenSSHFile(filepath.Join("./keys/", e.Name()))
    if err == nil {
        var arr [32]byte
        copy(arr[:], pub)
        wl[arr] = struct{}{}
    }
}

// 3. Создать клиент
c, err := sgtp.New(sgtp.Config{
    ServerAddr: "relay.example.com:7777",
    RoomUUID:   roomID,   // [16]byte
    UUID:       myUUID,   // [16]byte — случайный
    PrivateKey: priv,
    PublicKey:  pub,
    Whitelist:  whitelist,
})

// 4. Слушать события
go func() {
    for ev := range c.Events() {
        switch ev.Kind {
        case sgtp.EventChatKeyRotated:
            // Теперь можно отправлять сообщения
        case sgtp.EventPeerJoined:
            fmt.Println("joined:", ev.PeerUUID)
        case sgtp.EventError:
            log.Println("error:", ev.Err)
        }
    }
}()

// 5. Слушать входящие сообщения
go func() {
    for msg := range c.Messages() {
        fmt.Printf("[%s] %s\n", msg.ReceivedAt.Format("15:04"), msg.Data)
    }
}()

// 6. Подключиться
c.Connect()

// 7. Отправить сообщение (после EventChatKeyRotated)
msgID, err := c.SendMessage([]byte("hello!"))

// 8. Запросить историю
batches, _ := c.RequestHistory()
for batch := range batches {
    if batch.IsLast { break }
    for _, raw := range batch.ExtractMessages() {
        msg, err := c.DecryptMessageFrame(raw)
        if err == nil {
            fmt.Printf("[history] %s\n", msg.Data)
        }
    }
}

// 9. Отключиться
c.Disconnect()
```

---

## Интерфейс IClient

```go
type IClient interface {
    Connect() error
    Disconnect() error
    SendMessage(data []byte) ([16]byte, error)
    SendFIN() error
    Messages() <-chan InboundMessage
    Events() <-chan Event
    KnownPeers() []*Peer
    IsMaster() bool
}
```

### Дополнительные методы (только *Client)

| Метод | Описание |
|-------|----------|
| `DecryptMessageFrame(raw []byte) (InboundMessage, error)` | Расшифровывает сырой фрейм MESSAGE (из истории) текущим Chat Key |
| `RequestHistory() (<-chan HistoryBatch, error)` | Запускает HSIR → HSI → HSR → HSRA flow |
| `IssueChatKeyToAll() error` | (только мастер) Явная ротация Chat Key |
| `StartRotationTimer()` | (только мастер) Запустить периодическую ротацию |

---

## Конфигурация Config

```go
type Config struct {
    ServerAddr   string                    // адрес relay (обязательно)
    RoomUUID     [16]byte                  // UUID комнаты
    UUID         [16]byte                  // UUID этого клиента (уникальный)
    PrivateKey   ed25519.PrivateKey        // долгосрочный ключ подписи (обязательно)
    PublicKey    ed25519.PublicKey         // соответствующий публичный ключ
    Whitelist    map[[32]byte]struct{}     // доверенные публичные ключи
    MessageBufferSize int                  // ёмкость канала Messages() [64]
    EventBufferSize   int                  // ёмкость канала Events() [32]
    DialTimeout       time.Duration        // таймаут TCP dial [10s]
    InfoDelay         time.Duration        // задержка перед INFO [500ms]
    HistoryStore      HistoryStore         // хранилище истории (опционально)
}
```

---

## События и каналы

### EventKind

| Константа | Когда возникает | Поля Event |
|-----------|----------------|------------|
| `EventPeerJoined` | Завершён PONG-хендшейк с пиром | `PeerUUID` |
| `EventPeerLeft` | Получен FIN от пира | `PeerUUID` |
| `EventPeerKicked` | Мастер выслал KICKED | `PeerUUID` |
| `EventChatKeyRotated` | Получен новый Chat Key | — |
| `EventMessageFailed` | Мастер отклонил сообщение во время ротации | `MessageUUID` |
| `EventError` | Нефатальная ошибка (подпись, timestamp) | `Err` |

### InboundMessage

```go
type InboundMessage struct {
    SenderUUID  [16]byte  // UUID отправителя
    MessageUUID [16]byte  // уникальный ID сообщения
    Data        []byte    // расшифрованный payload
    ReceivedAt  time.Time // время получения (или время из timestamp для истории)
}
```

> **Важно:** оба канала (`Messages()` и `Events()`) необходимо читать непрерывно. При переполнении буфера новые элементы молча отбрасываются и генерируется `EventError`.

---

## HistoryStore

```go
type HistoryStore interface {
    Count() uint64
    Fetch(offset, limit uint64) [][]byte  // limit=0 → все с offset
    Append(raw []byte)
}
```

`Append` вызывается автоматически при каждом успешно расшифрованном входящем `MESSAGE`. `raw` — полный wire-фрейм (header + payload + signature).

По умолчанию (`HistoryStore: nil`) клиент не хранит историю и отвечает на HSIR счётчиком 0.

Пример простой in-memory реализации см. в `cmd/chat/main.go` (`memStore`).

---

## Ограничения и известные факты

### Forward secrecy и история

История хранится как зашифрованные `MESSAGE`-фреймы. При ротации Chat Key (каждые 180 с или при смене состава) новый участник **не может расшифровать** сообщения из предыдущих эпох — это штатное поведение, обеспечивающее forward secrecy. `DecryptMessageFrame` вернёт ошибку для таких фреймов.

### Один экземпляр на сессию

Объект `Client` не переиспользуется после `Disconnect()`. Для переподключения создайте новый `Client` через `New()`.

### Relay-сервер — прозрачный роутер

Сервер (`cmd/server`) видит только UUID отправителя и получателя. Он не расшифровывает payload и не проверяет подписи. Все криптографические операции выполняются на клиентах.

### Порядок подключения и роль мастера

Роль мастера определяется по наименьшему UUID. Клиент генерирует UUID версии 7 (RFC 9562) — в старших 48 битах закодировано текущее время в миллисекундах. Это гарантирует, что более ранний участник всегда имеет меньший UUID и остаётся мастером. Новый участник, подключившийся позже, не может случайно стать мастером в уже активной комнате.
