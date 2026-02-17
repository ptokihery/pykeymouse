package input

import "time"

type RawInputConfig struct {
	EnableKeyboard bool
	EnableMouse    bool
	MouseAggregate time.Duration
}
