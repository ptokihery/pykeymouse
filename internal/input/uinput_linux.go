//go:build linux

package input

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type UInputDevice struct {
	file *os.File
}

type inputID struct {
	Bustype uint16
	Vendor  uint16
	Product uint16
	Version uint16
}

type uinputUserDev struct {
	Name         [80]byte
	ID           inputID
	FFEffectsMax uint32
	Absmax       [64]int32
	Absmin       [64]int32
	Absfuzz      [64]int32
	Absflat      [64]int32
}

type inputEvent struct {
	Time  unix.Timeval
	Type  uint16
	Code  uint16
	Value int32
}

func OpenUInput(enableKeyboard, enableMouse bool, keyCodes []uint16) (*UInputDevice, error) {
	if !enableKeyboard && !enableMouse {
		return nil, errors.New("both keyboard and mouse are disabled")
	}
	file, err := openUInputDevice()
	if err != nil {
		return nil, err
	}
	dev := &UInputDevice{file: file}
	if err := dev.configure(enableKeyboard, enableMouse, keyCodes); err != nil {
		_ = file.Close()
		return nil, err
	}
	return dev, nil
}

func openUInputDevice() (*os.File, error) {
	paths := []string{"/dev/uinput", "/dev/input/uinput"}
	var lastErr error
	for _, p := range paths {
		file, err := os.OpenFile(p, os.O_WRONLY|os.O_NONBLOCK, 0)
		if err == nil {
			return file, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("uinput not found")
	}
	return nil, fmt.Errorf("open uinput: %w", lastErr)
}

func (d *UInputDevice) configure(enableKeyboard, enableMouse bool, keyCodes []uint16) error {
	fd := int(d.file.Fd())
	if enableKeyboard || enableMouse {
		if err := unix.IoctlSetInt(fd, unix.UI_SET_EVBIT, EV_KEY); err != nil {
			return fmt.Errorf("UI_SET_EVBIT EV_KEY: %w", err)
		}
	}
	if enableMouse {
		if err := unix.IoctlSetInt(fd, unix.UI_SET_EVBIT, EV_REL); err != nil {
			return fmt.Errorf("UI_SET_EVBIT EV_REL: %w", err)
		}
		_ = unix.IoctlSetInt(fd, unix.UI_SET_RELBIT, REL_X)
		_ = unix.IoctlSetInt(fd, unix.UI_SET_RELBIT, REL_Y)
		_ = unix.IoctlSetInt(fd, unix.UI_SET_RELBIT, REL_WHEEL)
	}
	if enableKeyboard {
		for _, code := range keyCodes {
			_ = unix.IoctlSetInt(fd, unix.UI_SET_KEYBIT, int(code))
		}
	}
	if enableMouse {
		_ = unix.IoctlSetInt(fd, unix.UI_SET_KEYBIT, int(BTN_LEFT))
		_ = unix.IoctlSetInt(fd, unix.UI_SET_KEYBIT, int(BTN_RIGHT))
		_ = unix.IoctlSetInt(fd, unix.UI_SET_KEYBIT, int(BTN_MIDDLE))
	}

	var u uinputUserDev
	copy(u.Name[:], []byte("pykeymouse"))
	u.ID.Bustype = unix.BUS_USB
	u.ID.Vendor = 0x1
	u.ID.Product = 0x1
	u.ID.Version = 1
	if err := binary.Write(d.file, binary.LittleEndian, &u); err != nil {
		return fmt.Errorf("write uinput_user_dev: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.UI_DEV_CREATE, 0); err != nil {
		return fmt.Errorf("UI_DEV_CREATE: %w", err)
	}
	return nil
}

func (d *UInputDevice) EmitKey(code uint16, value int32) error {
	return d.emit(EV_KEY, code, value)
}

func (d *UInputDevice) EmitRel(code uint16, value int32) error {
	return d.emit(EV_REL, code, value)
}

func (d *UInputDevice) Sync() error {
	return d.emit(EV_SYN, SYN_REPORT, 0)
}

func (d *UInputDevice) emit(typ uint16, code uint16, value int32) error {
	if d == nil || d.file == nil {
		return errors.New("uinput device not initialized")
	}
	ev := inputEvent{Type: typ, Code: code, Value: value}
	return binary.Write(d.file, binary.LittleEndian, &ev)
}

func (d *UInputDevice) Close() error {
	if d == nil || d.file == nil {
		return nil
	}
	fd := int(d.file.Fd())
	_ = unix.IoctlSetInt(fd, unix.UI_DEV_DESTROY, 0)
	return d.file.Close()
}
