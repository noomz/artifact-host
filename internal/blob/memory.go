package blob

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
)

type memObj struct {
	body        []byte
	contentType string
}

type Memory struct {
	mu   sync.RWMutex
	objs map[string]memObj
}

func NewMemory() *Memory {
	return &Memory{objs: make(map[string]memObj)}
}

func (m *Memory) Put(_ context.Context, key string, body []byte, contentType string) error {
	cp := make([]byte, len(body))
	copy(cp, body)
	m.mu.Lock()
	m.objs[key] = memObj{body: cp, contentType: contentType}
	m.mu.Unlock()
	return nil
}

func (m *Memory) DeletePrefix(_ context.Context, prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.objs {
		if strings.HasPrefix(k, prefix) {
			delete(m.objs, k)
		}
	}
	return nil
}

func (m *Memory) Get(_ context.Context, key string) (io.ReadCloser, string, error) {
	m.mu.RLock()
	obj, ok := m.objs[key]
	m.mu.RUnlock()
	if !ok {
		return nil, "", ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(obj.body)), obj.contentType, nil
}
