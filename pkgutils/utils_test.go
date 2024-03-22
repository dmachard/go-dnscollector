package pkgutils

import "testing"

func TestFakeLoggerImplementsWorkerInterface(t *testing.T) {
	var _ Worker = &FakeLogger{}
}
