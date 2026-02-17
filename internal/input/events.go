package input

const (
	EventKey         uint8 = 1
	EventMouseMove   uint8 = 2
	EventMouseButton uint8 = 3
	EventWheel       uint8 = 4
	EventHeartbeat   uint8 = 5

	HeartbeatFlagPing uint8 = 1 << 0
	HeartbeatFlagPong uint8 = 1 << 1
)

type Event struct {
	Type  uint8
	Flags uint8
	Code  uint16
	Value int32
}
