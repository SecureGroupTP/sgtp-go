# SGTP Go Client

Go-реализация клиента и relay-сервера для протокола **SGTP v0.2**.

---

## Структура проекта

```
github.com/SecureGroupTP/sgtp-go/
├── go.mod                  # единственная зависимость: golang.org/x/crypto
├── protocol/
│   ├── packet.go           # все 17 типов пакетов + Header + Marshal/Unmarshal
│   ├── parser.go           # ReadFrame, Parse (generic), BuildIntentFrame
│   └── crypto.go           # ed25519, x25519, ChaCha20-Poly1305
├── client/
│   ├── types.go            # Config, Event, InboundMessage, Peer, HistoryBatch
│   ├── client.go           # Client struct, New, Connect, SendMessage, readLoop
│   ├── handshake.go        # PING/PONG/INFO + peer-discovery timer
│   ├── session.go          # ChatKey, Message, FIN, Kicked, Status, MessageFailed
│   ├── history.go          # HSIR/HSI/HSRA flow
│   ├── send.go             # sendSigned, sendPingTo, sendInfoRequest/Response
│   ├── master.go           # IssueChatKey, IssueChatKeyToAll
│   └── log.go              # структурированный логгер → stderr
├── server/
│   └── server.go           # relay-сервер (byte forwarder)
└── cmd/
    ├── server/main.go      # исполняемый relay-сервер
    └── chat/main.go        # интерактивный консольный клиент
```

---

## Зависимости

```
golang.org/x/crypto   # x25519 DH + ChaCha20-Poly1305
```

Всё остальное — стандартная библиотека Go.

```bash
go get golang.org/x/crypto@latest
```

---

## Быстрый старт

```bash
# Терминал 1 — relay-сервер
go run ./cmd/server

# Терминал 2 — первый клиент
go run ./cmd/chat -server localhost:7777

# Терминал 3 — второй клиент
go run ./cmd/chat -server localhost:7777
```

Скопируйте UUID и PUBKEY между клиентами когда будет предложено. После хендшейка можно общаться.

Подробнее — в [docs/GUIDE.md](GUIDE.md).

---

## Архитектура

```
cmd/chat
    └── client.Client        (публичный API)
            ├── handshake.go (PING/PONG/INFO)
            ├── session.go   (CK, MSG, FIN…)
            ├── history.go   (HSIR/HSRA)
            ├── master.go    (IssueChatKey)
            └── send.go      (подпись + отправка)
                    └── protocol (wire-формат + крипто)

cmd/server
    └── server.Server (TCP relay, broadcast/unicast)
            └── protocol (заголовок для маршрутизации)
```

Зависимость строго сверху вниз. `protocol` ничего не знает о `client`.

---

## Ключевые решения

**Relay-сервер транслирует intent frame.** Когда клиент A подключается, сервер рассылает его intent frame существующим участникам — это сигнал начать PING-хендшейк (§3 Step 2). Клиентам не нужен белый IP.

**Мастер = наименьший UUID.** После PONG клиент проверяет `IsMaster()`. Если да — вызывает `IssueChatKey(peerUUID)`, который генерирует CK, шифрует его shared key получателя и отправляет.

**Единый путь подписи.** `sendSigned(marshalFn)` — всё исходящее проходит через него: создаётся фрейм с нулевым слотом подписи, ed25519 подпись вычисляется и вставляется перед отправкой.

**I/O разделены.** `cmd/chat`: сообщения → stdout, логи → stderr. Можно перенаправить независимо.

---

## Публичный API клиента

```go
c, err := client.New(client.Config{...})
err = c.Connect()

msgs   := c.Messages()          // <-chan InboundMessage
events := c.Events()            // <-chan Event
peers  := c.KnownPeers()        // []*Peer (snapshot)
master := c.IsMaster()          // bool

msgUUID, err := c.SendMessage([]byte("data"))
err = c.IssueChatKey(peerUUID)   // вызывать только если IsMaster()
err = c.IssueChatKeyToAll()      // для n участников
err = c.Disconnect()
```

---

## Криптография

| Механизм | Алгоритм |
|----------|----------|
| Аутентификация фреймов | ed25519 (каждый фрейм) |
| Согласование ключей | x25519 Diffie-Hellman (PING/PONG) |
| Шифрование сообщений | ChaCha20-Poly1305 с Chat Key |
| Шифрование CK при раздаче | ChaCha20-Poly1305 с shared key |
| Nonce | монотонный uint64 per (sender, epoch), сброс при ротации |
