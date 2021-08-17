package loggers

import (
	"log"
	"os"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestLogfileWrite(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "temp_logfile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	// config
	config := dnsutils.GetFakeConfig()
	config.Generators.LogFile.FilePath = f.Name()

	// init generator in testing mode
	g := NewLogFile(config, logger.New(false))

	// write fake dns message
	dm := dnsutils.GetFakeDnsMessage()
	g.Write(dm.Bytes())
	g.Flush()

	// read temp file and check content
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		log.Fatal(err)
	}
	if string(data[:count]) != dm.String() {
		t.Errorf("invalid logfile output - %s", data[:count])
	}
}
