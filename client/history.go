package client

import (
	"fmt"
	"time"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// RequestHistory sends an HSIR broadcast and returns a channel on which
// HistoryBatch values are delivered. The channel is closed after the
// end-of-stream batch (IsLast == true) is received.
//
// Only one history request may be in flight at a time.
func (c *Client) RequestHistory() (<-chan HistoryBatch, error) {
	logInfo("history", "sending HSIR broadcast")

	// Reset the HSI accumulation map.
	c.hsiMu.Lock()
	c.hsiResult = make(map[[16]byte]uint64)
	c.hsiMu.Unlock()

	pkt := &protocol.HSIR{}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = protocol.BroadcastUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(pkt.Marshal); err != nil {
		return nil, fmt.Errorf("history: send HSIR: %w", err)
	}

	ch := make(chan HistoryBatch, 128)
	c.histMu.Lock()
	c.histCh = ch
	c.histMu.Unlock()

	// Give peers 2 s to reply with HSI, then pick the richest and send HSR.
	go c.awaitHSIThenRequest()

	logDebug("history", "HSIR sent, waiting for HSI responses")
	return ch, nil
}

// awaitHSIThenRequest waits for HSI replies to arrive, picks the peer with the
// most messages, and sends HSR to them.
func (c *Client) awaitHSIThenRequest() {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-c.done:
		return
	}

	c.hsiMu.Lock()
	results := c.hsiResult
	c.hsiResult = make(map[[16]byte]uint64)
	c.hsiMu.Unlock()

	if len(results) == 0 {
		logInfo("history", "no HSI responses received — closing history channel")
		c.closeHistCh()
		return
	}

	// Pick the peer with the maximum message count.
	var bestPeer [16]byte
	var bestCount uint64
	for uid, count := range results {
		if count > bestCount {
			bestCount = count
			bestPeer = uid
		}
	}

	logInfo("history", "best peer=%s with %d messages — sending HSR", fmtUUID(bestPeer), bestCount)

	hsr := &protocol.HSR{Offset: 0, Limit: 0} // 0 limit = all messages
	h := hsr.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = bestPeer
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(hsr.Marshal); err != nil {
		logError("history", "send HSR: %v", err)
		c.closeHistCh()
	}
}

func (c *Client) closeHistCh() {
	c.histMu.Lock()
	ch := c.histCh
	c.histCh = nil
	c.histMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// ─── HSI handler ──────────────────────────────────────────────────────────────

// handleHSI records the message count from a peer responding to our HSIR.
func (c *Client) handleHSI(p *protocol.HSI) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("history", "HSI from=%s count=%d", fmtUUID(senderID), p.MessageCount)

	c.hsiMu.Lock()
	if c.hsiResult == nil {
		c.hsiResult = make(map[[16]byte]uint64)
	}
	c.hsiResult[senderID] = p.MessageCount
	c.hsiMu.Unlock()
	return nil
}

// ─── HSRA handler ─────────────────────────────────────────────────────────────

// handleHSRA forwards a history batch to the in-flight request channel.
func (c *Client) handleHSRA(p *protocol.HSRA) error {
	c.histMu.Lock()
	ch := c.histCh
	c.histMu.Unlock()

	if ch == nil {
		logWarn("history", "HSRA received but no active request — dropped")
		return nil
	}

	batch := historyBatchFromHSRA(p)
	logDebug("history", "HSRA batch=%d messages=%d isLast=%v",
		batch.BatchNumber, batch.MessageCount, batch.IsLast)

	select {
	case ch <- batch:
	default:
		logWarn("history", "history batch channel full — dropping batch=%d", batch.BatchNumber)
	}

	if batch.IsLast {
		c.histMu.Lock()
		c.histCh = nil
		c.histMu.Unlock()
		close(ch)
		logInfo("history", "history stream complete, total=%d msgs", batch.BatchNumber)
	}
	return nil
}
