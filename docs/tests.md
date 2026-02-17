TESTS

Latency (requires server test echo):
- Set "test.enable_echo" to true in server config.
- Run: pykeymouse-sim -mode latency -count 50

Invalid password:
- Run: pykeymouse-sim -mode invalid-password

Replay attack:
- Run: pykeymouse-sim -mode replay

Session expiration:
- Set session.timeout_seconds to a small value (e.g. 10).
- Connect with client and wait for expiration; server should close the session.

Reconnect:
- Run: pykeymouse-sim -mode reconnect -count 20

Load (long run):
- Run: pykeymouse-sim -mode load -duration 8h -rate 2000
