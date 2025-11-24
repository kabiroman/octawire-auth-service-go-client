package client

import (
	"context"
	"math/rand"
	"time"
)

// WithRetry выполняет функцию с retry логикой и экспоненциальным backoff
func WithRetry(ctx context.Context, fn func() error, config *RetryConfig) error {
	if config == nil {
		config = &RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     5 * time.Second,
		}
	}

	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Выполняем функцию
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Проверяем, можно ли повторить
		if !IsRetryableError(err) {
			return err
		}

		// Если это последняя попытка, не ждем
		if attempt == config.MaxAttempts-1 {
			break
		}

		// Вычисляем задержку с экспоненциальным backoff
		delay := backoff
		// Добавляем jitter для предотвращения thundering herd
		jitter := time.Duration(rand.Float64() * float64(delay) * 0.1) // 10% jitter
		delay += jitter

		// Ограничиваем максимальной задержкой
		if delay > config.MaxBackoff {
			delay = config.MaxBackoff
		}

		// Ждем перед следующей попыткой
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		// Увеличиваем backoff для следующей попытки
		backoff = time.Duration(float64(backoff) * 1.5) // Увеличиваем на 50%
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}
	}

	return lastErr
}

