package client

import (
	"fmt"
	"log"
	"os"
	"time"
)

// logger is an internal structured logger that always writes to stderr so it
// does not mix with application stdout (message I/O).
var stderr = log.New(os.Stderr, "", 0)

// logf formats and writes a log line to stderr with timestamp and level.
func logf(level, component, format string, args ...any) {
	ts := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	stderr.Printf("%s [%s] [%s] %s", ts, level, component, msg)
}

func logDebug(component, format string, args ...any) {
	logf("DBG", component, format, args...)
}

func logInfo(component, format string, args ...any) {
	logf("INF", component, format, args...)
}

func logWarn(component, format string, args ...any) {
	logf("WRN", component, format, args...)
}

func logError(component, format string, args ...any) {
	logf("ERR", component, format, args...)
}

// fmtUUID returns a short hex representation of a UUID for log lines.
func fmtUUID(u [16]byte) string {
	return fmt.Sprintf("%x", u[:4]) // first 4 bytes — short but distinctive
}
