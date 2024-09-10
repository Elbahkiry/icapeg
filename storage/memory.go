package storage

import (
	"bytes"
	"io"
	"os"
	"sync"
)

type MemoryStorage struct {
	storage map[string][]byte
	sizes   map[string]int64
	mutex   sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		storage: make(map[string][]byte),
		sizes:   make(map[string]int64),
	}
}

func (ms *MemoryStorage) Save(key string, data []byte) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.storage[key] = data
	ms.sizes[key] = int64(len(data))
	return nil
}

func (ms *MemoryStorage) Load(key string) ([]byte, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	data, exists := ms.storage[key]
	if !exists {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (ms *MemoryStorage) Delete(key string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	delete(ms.storage, key)
	delete(ms.sizes, key)
	return nil
}

func (ms *MemoryStorage) Size(key string) (int64, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	size, exists := ms.sizes[key]
	if !exists {
		return 0, os.ErrNotExist
	}
	return size, nil
}

func (ms *MemoryStorage) Append(key string, data []byte) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	_, exists := ms.storage[key]
	if !exists {
		ms.storage[key] = data
		ms.sizes[key] = int64(len(data))
		return nil
	}
	ms.storage[key] = append(ms.storage[key], data...)
	ms.sizes[key] += int64(len(data))
	return nil
}

func (ms *MemoryStorage) AppendFromReader(key string, r io.Reader) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	var buffer bytes.Buffer
	written, err := io.Copy(&buffer, r)
	if err != nil {
		return err
	}
	_, exists := ms.storage[key]
	if !exists {
		ms.storage[key] = buffer.Bytes()
		ms.sizes[key] = written
		return nil
	}
	ms.storage[key] = append(ms.storage[key], buffer.Bytes()...)
	ms.sizes[key] += written
	return nil
}
