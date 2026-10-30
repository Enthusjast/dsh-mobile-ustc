package relay

import (
	"context"
	"encoding/json"
	"net"
)

const ordinaryQueueFrames = 16
const controlQueueFrames = 8
const controlQueueBytes = 128 * 1024
const controlQueueBurst = 4

// Only protocol control metadata uses the reserve. Full approval context and
// fragments, session content and command bodies keep their ordinary FIFO.
func priorityControlFrame(data []byte) bool {
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return false
	}
	switch envelope.Type {
	case "access.revoked", "runtime.changed", "server.draining",
		"approval.invalidate", "approval.decision", "approval.reference", "approval.snapshot",
		"approval.registered", "approval.result.ack", "approval.details.get", "approval.unsubscribed":
		return true
	}
	return false
}

func (live *liveConnection) queueFrame(ctx context.Context, frame outboundFrame) error {
	live.queueMu.Lock()
	defer live.queueMu.Unlock()
	select {
	case <-live.done:
		return net.ErrClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	queue := live.sendQueue
	if frame.control {
		if live.controlQueuedBytes+int64(len(frame.body)) > controlQueueBytes {
			return errRelayQueueFull
		}
		queue = live.controlQueue
	}
	select {
	case queue <- frame:
		live.queuedMessages++
		live.queuedBytes += int64(len(frame.body))
		if frame.control {
			live.controlQueuedBytes += int64(len(frame.body))
		}
		select {
		case live.queueWake <- struct{}{}:
		default:
		}
		return nil
	default:
		return errRelayQueueFull
	}
}

// Selection and accounting share the admission lock, so priority is evaluated
// over one coherent queue state. Socket I/O and beforeWrite never hold it.
func (live *liveConnection) nextFrame(burst *int) (outboundFrame, bool) {
	for {
		live.queueMu.Lock()
		select {
		case <-live.done:
			live.queueMu.Unlock()
			return outboundFrame{}, false
		default:
		}
		frame, ok := live.popFrameLocked(burst)
		if ok {
			live.queuedMessages--
			live.queuedBytes -= int64(len(frame.body))
			if frame.control {
				live.controlQueuedBytes -= int64(len(frame.body))
			}
			live.inflightBytes = int64(len(frame.body))
		}
		live.queueMu.Unlock()
		if ok {
			return frame, true
		}
		select {
		case <-live.done:
			return outboundFrame{}, false
		case <-live.queueWake:
		}
	}
}

func (live *liveConnection) popFrameLocked(burst *int) (outboundFrame, bool) {
	if *burst >= controlQueueBurst {
		select {
		case frame := <-live.sendQueue:
			*burst = 0
			return frame, true
		default:
		}
	}
	select {
	case frame := <-live.controlQueue:
		*burst = min(*burst+1, controlQueueBurst)
		return frame, true
	default:
	}
	select {
	case frame := <-live.sendQueue:
		*burst = 0
		return frame, true
	default:
	}
	return outboundFrame{}, false
}

func (live *liveConnection) clearQueuedFramesLocked() {
	for _, queue := range []chan outboundFrame{live.controlQueue, live.sendQueue} {
		for {
			select {
			case <-queue:
				continue
			default:
			}
			break
		}
	}
	live.queuedMessages, live.queuedBytes, live.controlQueuedBytes = 0, 0, 0
}
