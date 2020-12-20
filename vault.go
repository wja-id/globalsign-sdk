package globalsign

import (
	"sync"
	"time"
)

// VaultItem represents a record identity
type VaultItem struct {
	sync.RWMutex
	data    *DSSIdentity
	expires *time.Time
}

// immediate expiration
func (item *VaultItem) expire() {
	item.Lock()
	expiration := time.Now()
	item.expires = &expiration
	item.Unlock()
}

func (item *VaultItem) touch(duration time.Duration) {
	item.Lock()
	expiration := time.Now().Add(duration)
	item.expires = &expiration
	item.Unlock()
}

func (item *VaultItem) expired() bool {
	var value bool
	item.RLock()
	if item.expires == nil {
		value = true
	} else {
		value = item.expires.Before(time.Now())
	}
	item.RUnlock()
	return value
}

// ExpiredIdentityFunc is a callback which will be called once identity expired
type ExpiredIdentityFunc func(key string, identity *DSSIdentity)

// IdentityVault store DSS identity until its expired
type IdentityVault struct {
	mutex   sync.RWMutex
	ttl     time.Duration
	items   map[string]*VaultItem
	expfunc ExpiredIdentityFunc
}

// Set is a thread-safe way to add identity to cache
func (cache *IdentityVault) Set(key string, identity *DSSIdentity) {
	cache.mutex.Lock()
	item := &VaultItem{data: identity}
	item.touch(cache.ttl)

	cache.items[key] = item
	cache.mutex.Unlock()
}

// Get is a thread-safe way to lookup items
func (cache *IdentityVault) Get(key string) (data *DSSIdentity, found bool) {
	cache.mutex.Lock()
	item, exists := cache.items[key]
	if !exists || item.expired() {
		data = nil
		found = false
	} else {
		data = item.data
		found = true
	}
	cache.mutex.Unlock()
	return
}

// Count returns the number of items in the cache
// (helpful for tracking memory leaks)
func (cache *IdentityVault) Count() int {
	cache.mutex.RLock()
	count := len(cache.items)
	cache.mutex.RUnlock()
	return count
}

// Del remove item without trigger callback
func (cache *IdentityVault) Del(key string) {
	cache.mutex.Lock()
	_, exists := cache.items[key]
	if exists {
		delete(cache.items, key)
	}
	cache.mutex.Unlock()
	return
}

func (cache *IdentityVault) cleanup() {
	cache.mutex.Lock()
	for key, item := range cache.items {
		if item.expired() {
			delete(cache.items, key)

			if cache.expfunc != nil {
				cache.expfunc(key, item.data)
			}
		}
	}
	cache.mutex.Unlock()
}

func (cache *IdentityVault) startCleanupTimer() {
	duration := cache.ttl / 2
	if duration < time.Second {
		duration = time.Second
	}
	ticker := time.Tick(duration)
	go (func() {
		for {
			select {
			case <-ticker:
				cache.cleanup()
			}
		}
	})()
}

// NewIdentityVault is a helper to create instance of the indetities vault struct
func NewIdentityVault(duration time.Duration) *IdentityVault {
	cache := &IdentityVault{
		ttl:   duration,
		items: map[string]*VaultItem{},
	}
	cache.startCleanupTimer()
	return cache
}
