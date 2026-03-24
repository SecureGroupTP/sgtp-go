package client

import (
	"fmt"

	"github.com/SecureGroupTP/sgtp-go/protocol"
)

// RequestHistory sends an HSIR broadcast and returns a channel on which
// HistoryBatch values are delivered. The channel is closed after the
// end-of-stream batch (IsLast == true) is received.
//
// Only one history request may be in flight at a time. Starting a second
// one replaces the first channel.
func (c *Client) RequestHistory() (<-chan HistoryBatch, error) {
	logInfo("history", "sending HSIR broadcast")

	pkt := &protocol.HSIR{}
	h := pkt.GetHeader()
	h.RoomUUID = c.cfg.RoomUUID
	h.ReceiverUUID = protocol.BroadcastUUID
	h.SenderUUID = c.uuid
	h.Timestamp = protocol.NowMillis()
	if err := c.sendSigned(pkt.Marshal); err != nil {
		return nil, fmt.Errorf("github.com/SecureGroupTP/sgtp-go/history: send HSIR: %w", err)
	}

	ch := make(chan HistoryBatch, 64)
	c.histMu.Lock()
	c.histCh = ch
	c.histMu.Unlock()

	logDebug("history", "HSIR sent, waiting for HSRA batches")
	return ch, nil
}

// ─── HSI handler ──────────────────────────────────────────────────────────────

// handleHSI logs the message count reported by a peer in response to HSIR.
// A richer implementation would track counts per peer and pick the richest one
// before issuing HSR.
func (c *Client) handleHSI(p *protocol.HSI) error {
	senderID := p.GetHeader().SenderUUID
	logInfo("history", "HSI from=%s count=%d", fmtUUID(senderID), p.MessageCount)
	// Future: select the peer with the highest count and send HSR.
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
		logInfo("history", "history stream complete, total batches=%d", batch.BatchNumber)
	}
	return nil
}
