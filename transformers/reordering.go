package transformers

import (
	"sort"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ReorderingTransform struct {
	GenericTransformer
	buffer      []dnsutils.DNSMessage
	mutex       sync.Mutex
	flushTicker *time.Ticker
	flushSignal chan struct{}
	stopChan    chan struct{}
	nextWorkers []chan dnsutils.DNSMessage
}

// NewLogReorderTransform creates an instance of the transformer.
func NewReorderingTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ReorderingTransform {
	t := &ReorderingTransform{
		GenericTransformer: NewTransformer(config, logger, "reordering", name, instance, nextWorkers),
		stopChan:           make(chan struct{}),
		flushSignal:        make(chan struct{}),
		nextWorkers:        nextWorkers,
	}

	return t
}

// GetTransforms returns the available subtransformations.
func (t *ReorderingTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Reordering.Enable {
		subtransforms = append(subtransforms, Subtransform{name: "reordering:sort-by-timestamp", processFunc: t.ReorderLogs})
		// Start a goroutine to handle periodic flushing.
		t.flushTicker = time.NewTicker(time.Duration(t.config.Reordering.FlushInterval) * time.Second)
		t.buffer = make([]dnsutils.DNSMessage, 0)
		go t.flushPeriodically()

	}
	return subtransforms, nil
}

// ReorderLogs adds a log to the buffer and flushes if the buffer is full.
func (t *ReorderingTransform) ReorderLogs(dm *dnsutils.DNSMessage) (int, error) {
	// Add the log to the buffer.
	t.mutex.Lock()
	t.buffer = append(t.buffer, *dm)
	t.mutex.Unlock()
	// If the buffer exceeds a certain size, flush it.
	if len(t.buffer) >= t.config.Reordering.MaxBufferSize {
		select {
		case t.flushSignal <- struct{}{}:
		default:
		}
	}

	return ReturnDrop, nil
}

// Close stops the periodic flushing.
func (t *ReorderingTransform) Reset() {
	select {
	case <-t.stopChan:
	default:
		close(t.stopChan)
	}
}

// flushPeriodically periodically flushes the buffer based on a timer.
func (t *ReorderingTransform) flushPeriodically() {
	for {
		select {
		case <-t.flushTicker.C:
			t.flushBuffer()
		case <-t.flushSignal:
			t.flushBuffer()
		case <-t.stopChan:
			t.flushTicker.Stop()
			return
		}
	}
}

// flushBuffer sorts and sends the logs in the buffer to the next workers.
func (t *ReorderingTransform) flushBuffer() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(t.buffer) == 0 {
		return
	}

	// Sort the buffer by timestamp.
	sort.SliceStable(t.buffer, func(i, j int) bool {
		ti, err1 := time.Parse(time.RFC3339Nano, t.buffer[i].DNSTap.TimestampRFC3339)
		tj, err2 := time.Parse(time.RFC3339Nano, t.buffer[j].DNSTap.TimestampRFC3339)
		if err1 != nil || err2 != nil {
			// If timestamps are invalid, maintain the original order.
			return false
		}
		return ti.Before(tj)
	})

	// Send sorted logs to the next workers.
	for _, sortedMsg := range t.buffer {
		for _, worker := range t.nextWorkers {
			// Non-blocking send to avoid worker congestion.
			select {
			case worker <- sortedMsg:
			default:
				// Log or handle if the worker channel is full.
				t.logger.Info("Worker channel is full, dropping message")
			}
		}
	}

	// Clear the buffer.
	t.buffer = t.buffer[:0]
}
