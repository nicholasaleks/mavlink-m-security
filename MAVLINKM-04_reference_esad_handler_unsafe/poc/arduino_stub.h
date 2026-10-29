// Minimal Arduino shim so nucleo_mavlink_m.ino compiles on the host.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <deque>
#include <vector>

#define HIGH 1
#define LOW 0
#define OUTPUT 1
#define LED_BUILTIN 13
#define PA9 9
#define PA10 10

extern uint32_t g_fake_micros;
extern int g_led;
static inline uint32_t micros() { return g_fake_micros; }
static inline uint32_t millis() { return g_fake_micros / 1000; }
static inline void pinMode(uint8_t, uint8_t) {}
static inline void digitalWrite(uint8_t pin, uint8_t v) { if (pin == LED_BUILTIN) g_led = v; }

class Stream {
public:
	std::deque<uint8_t> rx;
	std::vector<uint8_t> tx;
	virtual ~Stream() {}
	void begin(uint32_t) {}
	int available() { return (int)rx.size(); }
	int read() { if (rx.empty()) return -1; uint8_t c = rx.front(); rx.pop_front(); return c; }
	size_t write(const uint8_t *b, size_t n) { tx.insert(tx.end(), b, b + n); return n; }
	void feed(const uint8_t *b, size_t n) { rx.insert(rx.end(), b, b + n); }
};

class HardwareSerial : public Stream {
public:
	HardwareSerial() {}
	HardwareSerial(uint32_t, uint32_t) {}
};

extern HardwareSerial Serial;
