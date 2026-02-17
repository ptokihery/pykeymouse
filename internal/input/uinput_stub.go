//go:build !linux

package input

import "errors"

var errUInputUnsupported = errors.New("uinput only supported on linux")

type UInputDevice struct{}

func OpenUInput(enableKeyboard, enableMouse bool, keyCodes []uint16) (*UInputDevice, error) {
	return nil, errUInputUnsupported
}

func (d *UInputDevice) EmitKey(code uint16, value int32) error {
	return errUInputUnsupported
}

func (d *UInputDevice) EmitRel(code uint16, value int32) error {
	return errUInputUnsupported
}

func (d *UInputDevice) Sync() error {
	return errUInputUnsupported
}

func (d *UInputDevice) Close() error {
	return nil
}
