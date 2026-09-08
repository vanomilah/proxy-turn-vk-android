package main

import "testing"

// Регресс #869: два независимых wdtt-сервера с одинаковым числом абонентов
// выдавали клиенту один адрес — пул был общий, обход всегда с 10.66.0.1.
// Теперь обход начинается со смещения, выведенного из ключа сервера.

func withPoolStart(t *testing.T, start uint16) {
	t.Helper()
	old := addrPoolStart
	addrPoolStart = start
	t.Cleanup(func() { addrPoolStart = old })
}

// Фиксированные ключи (32 нулевых байта и 32 байта 0x01): смещения известны
// заранее, тест детерминирован — со случайными ключами соседние смещения,
// упирающиеся в один пропуск, давали бы ложное падение раз в ~20 000 прогонов.
const (
	testPubKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // sha256[:2] = 0x6668
	testPubKeyB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" // sha256[:2] = 0x72CD
)

func TestPoolStart_DerivedFromKeyAndStable(t *testing.T) {
	if got := poolStart(testPubKeyA); got != 0x6668 {
		t.Fatalf("смещение ключа A = %#x, ожидали 0x6668", got)
	}
	if got := poolStart(testPubKeyB); got != 0x72CD {
		t.Fatalf("смещение ключа B = %#x, ожидали 0x72cd", got)
	}
	if poolStart("не base64") != 0 {
		t.Fatal("битый ключ → смещение 0 (сегодняшний порядок)")
	}
}

func TestIssue869_ServersWithDifferentKeysHandOutDifferentIPs(t *testing.T) {
	first := func(pub string) (string, string) {
		setTestDB(t, "", map[string]*PasswordEntry{})
		withPoolStart(t, poolStart(pub))
		return getNextIP(), getNextRawIP()
	}
	wgA, rawA := first(testPubKeyA)
	wgB, rawB := first(testPubKeyB)
	if wgA != "10.66.102.104" || rawA != "10.70.102.104" {
		t.Fatalf("сервер A: wg=%q raw=%q, ожидали 10.66.102.104 / 10.70.102.104", wgA, rawA)
	}
	if wgB != "10.66.114.205" || rawB != "10.70.114.205" {
		t.Fatalf("сервер B: wg=%q raw=%q, ожидали 10.66.114.205 / 10.70.114.205", wgB, rawB)
	}
}

func TestPool_ZeroStartKeepsLegacyOrder(t *testing.T) {
	setTestDB(t, "", map[string]*PasswordEntry{})
	withPoolStart(t, 0)
	if got := getNextIP(); got != "10.66.0.2" {
		t.Fatalf("WG: %q, ожидали 10.66.0.2", got)
	}
	if got := getNextRawIP(); got != "10.70.0.2" {
		t.Fatalf("raw: %q, ожидали 10.70.0.2", got)
	}
}

func TestPool_StartsAtOffsetAndSkipsHostZeroAnd255(t *testing.T) {
	setTestDB(t, "", map[string]*PasswordEntry{})
	// idx 0x2AFF → 10.66.42.255: хост .255 пропускается, следующий — 10.66.43.0,
	// хост .0 тоже пропускается, значит первый выданный — 10.66.43.1.
	withPoolStart(t, 0x2AFF)
	if got := getNextIP(); got != "10.66.43.1" {
		t.Fatalf("WG: %q, ожидали 10.66.43.1", got)
	}
}

func TestPool_SkipsUsedAndGatewaysAndWraps(t *testing.T) {
	setTestDB(t, "", map[string]*PasswordEntry{})
	db.Devices["d1"] = &ClientDevice{DeviceID: "d1", IP: "10.66.255.254", RawIP: "10.70.255.254"}
	// Старт в самом конце /16: .254 занят, .255 пропуск, заворот на 10.66.0.0 →
	// .0 пропуск, 10.66.0.1 — шлюз NDMS, значит выдаётся 10.66.0.2.
	withPoolStart(t, 0xFFFE)
	if got := getNextIP(); got != "10.66.0.2" {
		t.Fatalf("WG: %q, ожидали 10.66.0.2", got)
	}
	if got := getNextRawIP(); got != "10.70.0.2" {
		t.Fatalf("raw: %q, ожидали 10.70.0.2", got)
	}
}

func TestPool_SkipsLegacyServerAddr(t *testing.T) {
	setTestDB(t, "", map[string]*PasswordEntry{})
	withPoolStart(t, 0x4201) // 10.66.66.1 — адрес wdtt0 апстрима, клиенту нельзя
	if got := getNextIP(); got != "10.66.66.2" {
		t.Fatalf("WG: %q, ожидали 10.66.66.2", got)
	}
}

func TestPool_ExistingDevicesKeepAddresses(t *testing.T) {
	setTestDB(t, "", map[string]*PasswordEntry{})
	db.Devices["old"] = &ClientDevice{DeviceID: "old", IP: "10.66.0.2", RawIP: "10.70.0.2"}
	withPoolStart(t, 0x1000)
	_ = getNextIP()
	_ = getNextRawIP()
	if db.Devices["old"].IP != "10.66.0.2" || db.Devices["old"].RawIP != "10.70.0.2" {
		t.Fatalf("старое устройство перенумеровано: %+v", db.Devices["old"])
	}
}
