package generators

import (
	"log"
	"os"
	"testing"

	"github.com/dmachard/go-dnscollector/common"
	"github.com/dmachard/go-dnscollector/dnsmessage"
	"github.com/dmachard/go-logger"
)

func TestLogfileRun(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "temp_logfile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	// config
	config := &common.Config{}
	config.Generators.LogFile.FilePath = f.Name()
	logger := logger.New(false)

	// init generator in testing mode
	g := NewLogFile(config, logger)
	g.testing = true

	// fake dns message
	dm := dnsmessage.DnsMessage{}
	dm.Init()

	// send dns message in the channel and run-it
	g.Channel() <- dm
	g.Run()

	// read temp file and check content
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		log.Fatal(err)
	}
	if string(data[:count]) != "1970-01-01T00:00:00Z - - - - - - - 0b - - 0.000000\n" {
		t.Errorf("invalid logfile output - %s", data[:count])
	}
}
