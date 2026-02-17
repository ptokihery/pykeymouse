package keymap

import "sort"

const (
	riKeyE0 = 0x02
	riKeyE1 = 0x04

	vkSnapshot = 0x2C
	vkPause    = 0x13

	KEY_102ND     = 86
	KEY_KPENTER   = 96
	KEY_RIGHTCTRL = 97
	KEY_KPSLASH   = 98
	KEY_SYSRQ     = 99
	KEY_RIGHTALT  = 100

	KEY_HOME     = 102
	KEY_UP       = 103
	KEY_PAGEUP   = 104
	KEY_LEFT     = 105
	KEY_RIGHT    = 106
	KEY_END      = 107
	KEY_DOWN     = 108
	KEY_PAGEDOWN = 109
	KEY_INSERT   = 110
	KEY_DELETE   = 111

	KEY_POWER     = 116
	KEY_PAUSE     = 119
	KEY_LEFTMETA  = 125
	KEY_RIGHTMETA = 126
	KEY_MENU      = 139
	KEY_SLEEP     = 142
	KEY_WAKEUP    = 143
)

func MapScanCode(makeCode uint16, flags uint16, vkey uint16) (uint16, bool) {
	if flags&riKeyE1 != 0 || vkey == vkPause {
		return KEY_PAUSE, true
	}
	if vkey == vkSnapshot {
		return KEY_SYSRQ, true
	}
	if flags&riKeyE0 != 0 {
		switch makeCode {
		case 0x1C:
			return KEY_KPENTER, true
		case 0x1D:
			return KEY_RIGHTCTRL, true
		case 0x35:
			return KEY_KPSLASH, true
		case 0x37:
			return KEY_SYSRQ, true
		case 0x38:
			return KEY_RIGHTALT, true
		case 0x47:
			return KEY_HOME, true
		case 0x48:
			return KEY_UP, true
		case 0x49:
			return KEY_PAGEUP, true
		case 0x4B:
			return KEY_LEFT, true
		case 0x4D:
			return KEY_RIGHT, true
		case 0x4F:
			return KEY_END, true
		case 0x50:
			return KEY_DOWN, true
		case 0x51:
			return KEY_PAGEDOWN, true
		case 0x52:
			return KEY_INSERT, true
		case 0x53:
			return KEY_DELETE, true
		case 0x5B:
			return KEY_LEFTMETA, true
		case 0x5C:
			return KEY_RIGHTMETA, true
		case 0x5D:
			return KEY_MENU, true
		case 0x5E:
			return KEY_POWER, true
		case 0x5F:
			return KEY_SLEEP, true
		case 0x63:
			return KEY_WAKEUP, true
		default:
			return 0, false
		}
	}

	if isBaseScanCode(makeCode) {
		return makeCode, true
	}
	return 0, false
}

func isBaseScanCode(code uint16) bool {
	if code >= 0x01 && code <= 0x53 {
		return true
	}
	switch code {
	case 0x56, 0x57, 0x58:
		return true
	default:
		return false
	}
}

func SupportedKeyCodes() []uint16 {
	codes := make([]uint16, 0, 96)
	for c := uint16(0x01); c <= 0x53; c++ {
		codes = append(codes, c)
	}
	codes = append(codes, 0x56, 0x57, 0x58)
	codes = append(codes,
		KEY_102ND,
		KEY_KPENTER,
		KEY_RIGHTCTRL,
		KEY_KPSLASH,
		KEY_SYSRQ,
		KEY_RIGHTALT,
		KEY_HOME,
		KEY_UP,
		KEY_PAGEUP,
		KEY_LEFT,
		KEY_RIGHT,
		KEY_END,
		KEY_DOWN,
		KEY_PAGEDOWN,
		KEY_INSERT,
		KEY_DELETE,
		KEY_POWER,
		KEY_PAUSE,
		KEY_LEFTMETA,
		KEY_RIGHTMETA,
		KEY_MENU,
		KEY_SLEEP,
		KEY_WAKEUP,
	)
	return uniqueSorted(codes)
}

func uniqueSorted(in []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(in))
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
