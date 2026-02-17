//go:build !windows

package input

import (
	"context"
	"errors"
)

func RunRawInput(ctx context.Context, cfg RawInputConfig, out chan<- Event) error {
	return errors.New("raw input only supported on windows")
}
