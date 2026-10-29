package blob

import (
	"context"
	"errors"
	"io"
)

var ErrNotFound = errors.New("blob not found")

type Store interface {
	Put(ctx context.Context, key string, body []byte, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, string, error)
}
