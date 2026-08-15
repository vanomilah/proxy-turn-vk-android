package main

var (
	keeneticNoNAT    bool
	keeneticNatIface string
)

// countActiveDevices — устройства с активной сессией (WG/raw), не relay UDP.
func countActiveDevices() int32 {
	activeDevicesMu.Lock()
	n := int32(len(activeDevices))
	activeDevicesMu.Unlock()
	return n
}
