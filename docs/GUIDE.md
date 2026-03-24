# SGTP — Пошаговый гайд (v2)

Этот гайд описывает полный сценарий: два человека запускают `cmd/chat` и общаются через relay-сервер. Клиентам **не нужен белый IP** — только серверу.

---

## Структура клиентского пакета

```
client/
├── types.go      — Config, Event, InboundMessage, Peer, HistoryBatch
├── client.go     — Client struct, New, Connect, SendMessage, Disconnect, readLoop
├── handshake.go  — PING/PONG/INFO обработчики + peer-discovery таймер
├── session.go    — ChatKey, Message, MessageFailed, Status, FIN, Kicked
├── history.go    — HSIR/HSI/HSRA flow
├── send.go       — sendSigned, sendPingTo, sendInfoRequest/Response
├── master.go     — IssueChatKey, IssueChatKeyToAll (роль мастера)
└── log.go        — внутренний логгер → stderr
```

---

## Требования

- Go 1.22+
- `golang.org/x/crypto` (`go get golang.org/x/crypto@latest`)
- Машина с публичным IP для relay-сервера (или localhost для теста)

---

## Шаг 1 — Запустить relay-сервер

На машине с публичным IP (или локально для теста):

```bash
go run ./cmd/server --addr :7777
```

Вывод сервера идёт в stdout. Клиентам порт открывать не нужно.

---

## Шаг 2 — Запустить первый клиент

```bash
go run ./cmd/chat -server <адрес>:7777
```

Клиент выводит в **stdout** (для копирования):

```
─── Share with your peer ───────────────────────────────────────
UUID  : a3f1c2d4e5b6a7f8091234567890abcd
PUBKEY: 4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920304050607080
────────────────────────────────────────────────────────────────
```

Затем просит ввести UUID и PUBKEY собеседника.

---

## Шаг 3 — Запустить второй клиент

В другом терминале (или на другой машине):

```bash
go run ./cmd/chat -server <адрес>:7777
```

Скопируйте UUID и PUBKEY первого клиента во второй, и наоборот. После ввода оба клиента соединятся, выполнят хендшейк, и мастер (тот у кого UUID меньше) выдаст Chat Key.

---

## Шаг 4 — Общение

После появления строки:

```
✓ Chat Key received. You can type now.
```

Просто пишите сообщения и нажимайте Enter. Полученные сообщения выводятся с префиксом `peer>`.

**Команды:**
- `/quit` — отключиться и выйти
- `/peers` — показать список известных участников
- `/master` — показать, является ли этот клиент мастером

---

## Поток хендшейка (что происходит внутри)

```
Клиент A                  Relay Server             Клиент B
    |                          |                       |
    |-- intent frame --------->|                       |
    |                          |-- intent frame ------>|  (broadcast)
    |                          |                       |
    |<-------------------------|<------ PING ----------|  (B→A)
    |-- PONG ----------------->|---------------------->|
    |                          |                       |
    | (500ms INFO delay)       |                       |
    |-- INFO request --------->|---------------------->|  (→ master=B если UUID_B < UUID_A)
    |<-- INFO response --------|<----------------------|
    |                          |                       |
    | [мастер = меньший UUID]  |                       |
    |<-- CHAT_KEY -------------|<----------------------|  (зашифровано shared key)
    |-- CHAT_KEY_ACK --------->|---------------------->|
    |                          |                       |
    | ✓ готово к отправке      |                       | ✓ готово к отправке
```

---

## Логи

Все логи идут в **stderr**, сообщения — в **stdout**. Можно разделить:

```bash
go run ./cmd/chat -server localhost:7777 2>chat.log
```

Уровни логов: `DBG`, `INF`, `WRN`, `ERR`.

---

## Флаги команды chat

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-server` | `localhost:7777` | Адрес relay-сервера |
| `-infodelay` | `500ms` | Задержка перед INFO-запросом после хендшейка |

---

## Интеграция клиента в свой проект

```go
import (
    sgtp "github.com/SecureGroupTP/sgtp-go/client"
    "github.com/SecureGroupTP/sgtp-go/protocol"
    "crypto/ed25519"
)

// 1. Ключи (сохраните privKey — это идентичность)
pub, priv, _ := protocol.GenerateEd25519()

// 2. Клиент
c, _ := sgtp.New(sgtp.Config{
    ServerAddr: "relay.example.com:7777",
    RoomUUID:   roomID,
    UUID:       myUUID,
    PrivateKey: priv,
    Whitelist: map[[16]byte]ed25519.PublicKey{
        peerUUID: peerPubKey,
    },
})

// 3. Подключение
c.Connect()

// 4. События и сообщения
go func() {
    for ev := range c.Events() {
        if ev.Kind == sgtp.EventPeerJoined && c.IsMaster() {
            c.IssueChatKey(ev.PeerUUID) // мастер раздаёт ключ
        }
        if ev.Kind == sgtp.EventChatKeyRotated {
            // теперь можно отправлять
        }
    }
}()
go func() {
    for msg := range c.Messages() {
        fmt.Printf("%s: %s\n", msg.SenderUUID, msg.Data)
    }
}()

// 5. Отправка
c.SendMessage([]byte("привет"))

// 6. Отключение
c.Disconnect()
```

---

## Расширение до n участников

Для комнаты с 3+ участниками используйте `IssueChatKeyToAll()` вместо `IssueChatKey()`:

```go
if ev.Kind == sgtp.EventChatKeyRotated {
    // Подождать пока все участники прошли хендшейк, затем:
    c.IssueChatKeyToAll()
}
```

Мастер должен подождать PONG от всех участников прежде чем раздавать CK.
