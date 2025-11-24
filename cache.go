package client

import (
	"sync"
	"time"

	authv1 "github.com/octawire/auth-service/internal/proto"
)

// cachedKeyInfo содержит информацию о закэшированном ключе
type cachedKeyInfo struct {
	KeyInfo   *authv1.PublicKeyInfo
	ExpiresAt time.Time
}

// KeyCache представляет in-memory кэш для публичных ключей
type KeyCache struct {
	mu    sync.RWMutex
	cache map[string]map[string]*cachedKeyInfo // project_id -> key_id -> cachedKeyInfo
	config *KeyCacheConfig
}

// NewKeyCache создает новый кэш ключей
func NewKeyCache(config *KeyCacheConfig) *KeyCache {
	if config == nil {
		config = &KeyCacheConfig{
			TTL:     0,
			MaxSize: 100,
		}
	}
	return &KeyCache{
		cache: make(map[string]map[string]*cachedKeyInfo),
		config: config,
	}
}

// Get возвращает ключ из кэша по project_id и key_id
func (kc *KeyCache) Get(projectID, keyID string) (*authv1.PublicKeyInfo, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	projectKeys, ok := kc.cache[projectID]
	if !ok {
		return nil, false
	}

	cached, ok := projectKeys[keyID]
	if !ok {
		return nil, false
	}

	// Проверяем, не истек ли кэш
	if !cached.ExpiresAt.IsZero() && time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.KeyInfo, true
}

// Set сохраняет ключ в кэш
func (kc *KeyCache) Set(projectID string, keyInfo *authv1.PublicKeyInfo, cacheUntil int64) {
	if keyInfo == nil {
		return
	}

	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Проверяем ограничение размера
	if kc.config.MaxSize > 0 && len(kc.cache) >= kc.config.MaxSize {
		// Если достигнут лимит, удаляем самый старый проект (простая стратегия)
		// В реальности можно использовать LRU, но для простоты удаляем первый
		for pid := range kc.cache {
			delete(kc.cache, pid)
			break
		}
	}

	// Инициализируем map для проекта, если его нет
	if kc.cache[projectID] == nil {
		kc.cache[projectID] = make(map[string]*cachedKeyInfo)
	}

	// Вычисляем время истечения кэша
	var expiresAt time.Time
	if cacheUntil > 0 {
		expiresAt = time.Unix(cacheUntil, 0)
	} else if kc.config.TTL > 0 {
		expiresAt = time.Now().Add(kc.config.TTL)
	} else {
		// Если не указано время истечения, используем время истечения самого ключа
		if keyInfo.ExpiresAt > 0 {
			expiresAt = time.Unix(keyInfo.ExpiresAt, 0)
		}
	}

	kc.cache[projectID][keyInfo.KeyId] = &cachedKeyInfo{
		KeyInfo:   keyInfo,
		ExpiresAt: expiresAt,
	}
}

// SetAllActive сохраняет все активные ключи из ответа GetPublicKey
func (kc *KeyCache) SetAllActive(projectID string, activeKeys []*authv1.PublicKeyInfo, cacheUntil int64) {
	if len(activeKeys) == 0 {
		return
	}

	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Проверяем ограничение размера
	if kc.config.MaxSize > 0 && len(kc.cache) >= kc.config.MaxSize {
		for pid := range kc.cache {
			delete(kc.cache, pid)
			break
		}
	}

	// Инициализируем map для проекта
	if kc.cache[projectID] == nil {
		kc.cache[projectID] = make(map[string]*cachedKeyInfo)
	}

	// Вычисляем время истечения кэша
	var expiresAt time.Time
	if cacheUntil > 0 {
		expiresAt = time.Unix(cacheUntil, 0)
	} else if kc.config.TTL > 0 {
		expiresAt = time.Now().Add(kc.config.TTL)
	}

	// Сохраняем все активные ключи
	for _, keyInfo := range activeKeys {
		if keyInfo == nil {
			continue
		}

		keyExpiresAt := expiresAt
		// Если не указано общее время истечения, используем время истечения ключа
		if keyExpiresAt.IsZero() && keyInfo.ExpiresAt > 0 {
			keyExpiresAt = time.Unix(keyInfo.ExpiresAt, 0)
		}

		kc.cache[projectID][keyInfo.KeyId] = &cachedKeyInfo{
			KeyInfo:   keyInfo,
			ExpiresAt: keyExpiresAt,
		}
	}
}

// GetAllActive возвращает все активные ключи для проекта
func (kc *KeyCache) GetAllActive(projectID string) []*authv1.PublicKeyInfo {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	projectKeys, ok := kc.cache[projectID]
	if !ok {
		return nil
	}

	var activeKeys []*authv1.PublicKeyInfo
	now := time.Now()

	for _, cached := range projectKeys {
		// Проверяем, не истек ли кэш
		if !cached.ExpiresAt.IsZero() && now.After(cached.ExpiresAt) {
			continue
		}

		// Проверяем, не истек ли сам ключ
		if cached.KeyInfo.ExpiresAt > 0 {
			keyExpiresAt := time.Unix(cached.KeyInfo.ExpiresAt, 0)
			if now.After(keyExpiresAt) {
				continue
			}
		}

		activeKeys = append(activeKeys, cached.KeyInfo)
	}

	return activeKeys
}

// Invalidate удаляет все ключи для проекта из кэша
func (kc *KeyCache) Invalidate(projectID string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	delete(kc.cache, projectID)
}

// Clear очищает весь кэш
func (kc *KeyCache) Clear() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	kc.cache = make(map[string]map[string]*cachedKeyInfo)
}

// CleanupExpired удаляет истекшие ключи из кэша
func (kc *KeyCache) CleanupExpired() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	now := time.Now()
	for projectID, projectKeys := range kc.cache {
		for keyID, cached := range projectKeys {
			// Удаляем, если истек кэш или сам ключ
			shouldRemove := false

			if !cached.ExpiresAt.IsZero() && now.After(cached.ExpiresAt) {
				shouldRemove = true
			} else if cached.KeyInfo.ExpiresAt > 0 {
				keyExpiresAt := time.Unix(cached.KeyInfo.ExpiresAt, 0)
				if now.After(keyExpiresAt) {
					shouldRemove = true
				}
			}

			if shouldRemove {
				delete(projectKeys, keyID)
			}
		}

		// Удаляем пустые проекты
		if len(projectKeys) == 0 {
			delete(kc.cache, projectID)
		}
	}
}

