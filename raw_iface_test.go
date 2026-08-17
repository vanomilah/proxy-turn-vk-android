package main

import (
	"testing"
)

// 10.70.0.1 вешает NDMS на raw-интерфейсе, когда awg-manager регистрирует его
// как OpkgTunN. Выданный клиенту, этот адрес локален на сервере: обратный
// трафик к нему не уйдёт в туннель, и абонент молча остаётся без связи.
func TestGetNextRawIPSkipsNDMSGateway(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{})

	if got := getNextRawIP(); got != "10.70.0.2" {
		t.Fatalf("первый raw-адрес = %q, ожидали 10.70.0.2 (10.70.0.1 — шлюз NDMS)", got)
	}
}
