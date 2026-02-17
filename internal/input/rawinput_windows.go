//go:build windows

package input

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"pykeymouse/internal/keymap"
	"pykeymouse/internal/proto"
)

const (
	wmInput         = 0x00FF
	wmDestroy       = 0x0002
	ridInput        = 0x10000003
	rimTypeMouse    = 0
	rimTypeKeyboard = 1

	ridevInputSink = 0x00000100

	hidUsagePageGeneric = 0x01
	hidUsageMouse       = 0x02
	hidUsageKeyboard    = 0x06

	riKeyBreak = 0x0001

	riMouseLeftButtonDown   = 0x0001
	riMouseLeftButtonUp     = 0x0002
	riMouseRightButtonDown  = 0x0004
	riMouseRightButtonUp    = 0x0008
	riMouseMiddleButtonDown = 0x0010
	riMouseMiddleButtonUp   = 0x0020
	riMouseWheel            = 0x0400

	mouseMoveAbsolute = 0x0001
)

const hwndMessage = ^uintptr(2) // (HWND)-3

type rawInputContext struct {
	out      chan<- Event
	mouseAdd func(dx, dy int32)
}

var currentRawContext *rawInputContext

var (
	modUser32                   = windows.NewLazySystemDLL("user32.dll")
	procRegisterClassExW        = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW         = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW          = modUser32.NewProc("DefWindowProcW")
	procGetMessageW             = modUser32.NewProc("GetMessageW")
	procTranslateMessage        = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW        = modUser32.NewProc("DispatchMessageW")
	procRegisterRawInputDevices = modUser32.NewProc("RegisterRawInputDevices")
	procGetRawInputData         = modUser32.NewProc("GetRawInputData")
	procPostQuitMessage         = modUser32.NewProc("PostQuitMessage")
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type winPoint struct {
	X int32
	Y int32
}

type winMsg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      winPoint
}

type rawInputDevice struct {
	UsagePage uint16
	Usage     uint16
	Flags     uint32
	Target    windows.Handle
}

type rawInputHeader struct {
	dwType  uint32
	dwSize  uint32
	hDevice windows.Handle
	wParam  uintptr
}

type rawMouse struct {
	Flags            uint16
	ButtonFlags      uint16
	ButtonData       uint16
	Padding          uint16
	RawButtons       uint32
	LastX            int32
	LastY            int32
	ExtraInformation uint32
}

type rawKeyboard struct {
	MakeCode         uint16
	Flags            uint16
	Reserved         uint16
	VKey             uint16
	Message          uint32
	ExtraInformation uint32
}

type rawInput struct {
	Header rawInputHeader
	Data   rawInputData
}

type rawInputData struct {
	Mouse rawMouse
}

func RunRawInput(ctx context.Context, cfg RawInputConfig, out chan<- Event) error {
	if out == nil {
		return errors.New("out channel required")
	}
	if !cfg.EnableKeyboard && !cfg.EnableMouse {
		return errors.New("both keyboard and mouse are disabled")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	className, _ := syscall.UTF16PtrFromString("PKMRawInputWindow")
	wndProc := syscall.NewCallback(wndProc)
	hInstance, err := moduleHandle()
	if err != nil {
		return err
	}
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   wndProc,
		hInstance:     hInstance,
		lpszClassName: className,
	}
	ret, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		return err
	}

	hwnd, _, err := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(className)),
		0,
		0, 0, 0, 0,
		hwndMessage,
		0,
		uintptr(wc.hInstance),
		0,
	)
	if hwnd == 0 {
		return err
	}

	if err := registerRawDevices(cfg, windows.Handle(hwnd)); err != nil {
		return err
	}

	mouseInterval := cfg.MouseAggregate
	if mouseInterval <= 0 {
		mouseInterval = time.Millisecond
	}
	mouseAdd := startMouseAggregator(ctx, mouseInterval, out)
	currentRawContext = &rawInputContext{out: out, mouseAdd: mouseAdd}

	go func() {
		<-ctx.Done()
		procPostQuitMessage.Call(0)
	}()

	var msg winMsg
	for {
		res, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(res) == -1 {
			return errors.New("GetMessageW failed")
		}
		if res == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}

func registerRawDevices(cfg RawInputConfig, hwnd windows.Handle) error {
	devices := make([]rawInputDevice, 0, 2)
	if cfg.EnableKeyboard {
		devices = append(devices, rawInputDevice{
			UsagePage: hidUsagePageGeneric,
			Usage:     hidUsageKeyboard,
			Flags:     ridevInputSink,
			Target:    hwnd,
		})
	}
	if cfg.EnableMouse {
		devices = append(devices, rawInputDevice{
			UsagePage: hidUsagePageGeneric,
			Usage:     hidUsageMouse,
			Flags:     ridevInputSink,
			Target:    hwnd,
		})
	}
	if len(devices) == 0 {
		return errors.New("no devices registered")
	}
	ret, _, err := procRegisterRawInputDevices.Call(
		uintptr(unsafe.Pointer(&devices[0])),
		uintptr(len(devices)),
		unsafe.Sizeof(devices[0]),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func wndProc(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case wmInput:
		handleRawInput(lParam)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	default:
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	}
}

func handleRawInput(lParam uintptr) {
	if currentRawContext == nil {
		return
	}
	raw, err := readRawInput(lParam)
	if err != nil {
		return
	}
	switch raw.Header.dwType {
	case rimTypeKeyboard:
		kb := (*rawKeyboard)(unsafe.Pointer(&raw.Data))
		value := int32(1)
		if kb.Flags&riKeyBreak != 0 {
			value = 0
		}
		code, ok := keymap.MapScanCode(kb.MakeCode, kb.Flags, kb.VKey)
		if !ok {
			return
		}
		sendEvent(currentRawContext.out, Event{Type: EventKey, Code: code, Value: value})
	case rimTypeMouse:
		ms := (*rawMouse)(unsafe.Pointer(&raw.Data))
		if ms.Flags&mouseMoveAbsolute == 0 {
			if ms.LastX != 0 || ms.LastY != 0 {
				currentRawContext.mouseAdd(ms.LastX, ms.LastY)
			}
		}
		if ms.ButtonFlags&riMouseLeftButtonDown != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_LEFT, Value: 1})
		}
		if ms.ButtonFlags&riMouseLeftButtonUp != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_LEFT, Value: 0})
		}
		if ms.ButtonFlags&riMouseRightButtonDown != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_RIGHT, Value: 1})
		}
		if ms.ButtonFlags&riMouseRightButtonUp != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_RIGHT, Value: 0})
		}
		if ms.ButtonFlags&riMouseMiddleButtonDown != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_MIDDLE, Value: 1})
		}
		if ms.ButtonFlags&riMouseMiddleButtonUp != 0 {
			sendEvent(currentRawContext.out, Event{Type: EventMouseButton, Code: BTN_MIDDLE, Value: 0})
		}
		if ms.ButtonFlags&riMouseWheel != 0 {
			delta := int16(ms.ButtonData)
			sendEvent(currentRawContext.out, Event{Type: EventWheel, Code: REL_WHEEL, Value: int32(delta)})
		}
	}
}

func readRawInput(lParam uintptr) (*rawInput, error) {
	var size uint32
	ret, _, err := procGetRawInputData.Call(
		lParam,
		ridInput,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Sizeof(rawInputHeader{})),
	)
	if ret == 0 && size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	ret, _, err = procGetRawInputData.Call(
		lParam,
		ridInput,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Sizeof(rawInputHeader{})),
	)
	if ret == 0xFFFFFFFF {
		return nil, err
	}
	return (*rawInput)(unsafe.Pointer(&buf[0])), nil
}

func startMouseAggregator(ctx context.Context, interval time.Duration, out chan<- Event) func(dx, dy int32) {
	var mu sync.Mutex
	var accX int32
	var accY int32

	send := func(dx, dy int32) {
		value := proto.PackMouseDelta(dx, dy)
		sendEvent(out, Event{Type: EventMouseMove, Code: 0, Value: value})
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				dx, dy := accX, accY
				accX, accY = 0, 0
				mu.Unlock()
				if dx != 0 || dy != 0 {
					send(dx, dy)
				}
			}
		}
	}()

	return func(dx, dy int32) {
		if dx == 0 && dy == 0 {
			return
		}
		mu.Lock()
		accX += dx
		accY += dy
		mu.Unlock()
	}
}

func sendEvent(out chan<- Event, ev Event) {
	select {
	case out <- ev:
	default:
	}
}

func moduleHandle() (windows.Handle, error) {
	var handle windows.Handle
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nil, &handle)
	if err != nil {
		return 0, err
	}
	return handle, nil
}
