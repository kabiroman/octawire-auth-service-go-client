package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kabiroman/octawire-auth-service"
	authv1 "github.com/octawire/auth-service/internal/proto"
)

func main() {
	// Создаем конфигурацию с настройками кэша
	config := client.DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"

	// Настраиваем кэш ключей
	config.KeyCache = &client.KeyCacheConfig{
		TTL:     1 * time.Hour, // Время жизни в кэше (если не указано cache_until)
		MaxSize: 100,            // Максимальное количество проектов в кэше
	}

	// Создаем клиент
	cl, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cl.Close()

	ctx := context.Background()

	// Пример 1: Получение публичного ключа (будет закэширован)
	fmt.Println("=== GetPublicKey (first request - from server) ===")
	getKeyReq := &authv1.GetPublicKeyRequest{
		ProjectId: "default-project-id",
	}

	start := time.Now()
	keyResp, err := cl.GetPublicKey(ctx, getKeyReq)
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
	elapsed := time.Since(start)

	fmt.Printf("Public Key: %s\n", keyResp.PublicKeyPem)
	fmt.Printf("Algorithm: %s\n", keyResp.Algorithm)
	fmt.Printf("Key ID: %s\n", keyResp.KeyId)
	fmt.Printf("Cache Until: %s\n", time.Unix(keyResp.CacheUntil, 0))
	fmt.Printf("Time taken: %v\n", elapsed)
	fmt.Printf("Active Keys Count: %d\n", len(keyResp.ActiveKeys))

	// Показываем все активные ключи (для graceful ротации)
	if len(keyResp.ActiveKeys) > 0 {
		fmt.Println("\nActive Keys:")
		for i, key := range keyResp.ActiveKeys {
			fmt.Printf("  [%d] Key ID: %s, Primary: %v, Expires At: %s\n",
				i+1, key.KeyId, key.IsPrimary, time.Unix(key.ExpiresAt, 0))
		}
	}

	// Пример 2: Повторный запрос (будет взят из кэша)
	fmt.Println("\n=== GetPublicKey (second request - from cache) ===")
	start = time.Now()
	keyResp2, err := cl.GetPublicKey(ctx, getKeyReq)
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
	elapsed = time.Since(start)

	fmt.Printf("Public Key: %s\n", keyResp2.PublicKeyPem)
	fmt.Printf("Time taken: %v (should be much faster)\n", elapsed)

	// Пример 3: Получение всех активных ключей из кэша
	fmt.Println("\n=== GetAllActive from cache ===")
	keyCache := cl.GetKeyCache()
	activeKeys := keyCache.GetAllActive("default-project-id")
	fmt.Printf("Active Keys in Cache: %d\n", len(activeKeys))
	for i, key := range activeKeys {
		fmt.Printf("  [%d] Key ID: %s, Primary: %v\n", i+1, key.KeyId, key.IsPrimary)
	}

	// Пример 4: Инвалидация кэша
	fmt.Println("\n=== Invalidate Cache ===")
	keyCache.Invalidate("default-project-id")
	fmt.Println("Cache invalidated for project")

	// Пример 5: Запрос после инвалидации (будет запрошен у сервера)
	fmt.Println("\n=== GetPublicKey (after invalidation - from server) ===")
	start = time.Now()
	keyResp3, err := cl.GetPublicKey(ctx, getKeyReq)
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
	elapsed = time.Since(start)

	fmt.Printf("Public Key: %s\n", keyResp3.PublicKeyPem)
	fmt.Printf("Time taken: %v\n", elapsed)
}

