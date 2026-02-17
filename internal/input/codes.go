package input

// Linux input event codes and key codes used by the protocol.
// Values sourced from include/uapi/linux/input-event-codes.h.
const (
	EV_SYN = 0x00
	EV_KEY = 0x01
	EV_REL = 0x02

	SYN_REPORT = 0

	REL_X     = 0x00
	REL_Y     = 0x01
	REL_WHEEL = 0x08

	BTN_LEFT   = 0x110
	BTN_RIGHT  = 0x111
	BTN_MIDDLE = 0x112

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
