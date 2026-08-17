package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Стражи raw-пути: при -no-nat сервер не трогает netfilter вовсе (ни NAT, ни
// FORWARD) — таблицы принадлежат awg-manager. Раньше WG-половина выходила ДО
// setupForwardRules, а raw-половина ставила FORWARD-правила WDTT_MANAGED и
// оставляла их в таблице после смерти процесса: снять их было некому, наш
// teardown матчит только свою форму.

// fakeIptablesPATH подменяет PATH каталогом с исполняемой заглушкой iptables,
// которая дописывает свои аргументы в файл. Так проверяется РЕАЛЬНЫЙ путь кода
// без швов в продукте: правило поставлено ⇔ файл появился. Настоящий iptables
// машины при этом недосягаем.
func fakeIptablesPATH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n"
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0o755); err != nil {
		t.Fatalf("заглушка iptables: %v", err)
	}
	t.Setenv("PATH", dir)
	return log
}

func iptablesCalls(t *testing.T, log string) string {
	t.Helper()
	data, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("чтение вызовов: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func withNoNAT(t *testing.T) {
	t.Helper()
	old := keeneticNoNAT
	keeneticNoNAT = true
	t.Cleanup(func() { keeneticNoNAT = old })
}

func TestSetupRawNATTouchesNothingWithNoNAT(t *testing.T) {
	log := fakeIptablesPATH(t)
	withNoNAT(t)

	if err := setupRawNAT("wdttraw0"); err != nil {
		t.Fatalf("setupRawNAT: %v", err)
	}
	if calls := iptablesCalls(t, log); calls != "" {
		t.Fatalf("при -no-nat raw-путь трогал netfilter:\n%s", calls)
	}
}

// Вторая половина той же симметрии: WG-путь уже был чист, и обязан остаться.
func TestSetupFullConeNATTouchesNothingWithNoNAT(t *testing.T) {
	log := fakeIptablesPATH(t)
	withNoNAT(t)

	if err := setupFullConeNAT("wdtt0"); err != nil {
		t.Fatalf("setupFullConeNAT: %v", err)
	}
	if calls := iptablesCalls(t, log); calls != "" {
		t.Fatalf("при -no-nat WG-путь трогал netfilter:\n%s", calls)
	}
}

// 10.70.0.1 вешает NDMS на raw-интерфейсе, когда awg-manager регистрирует его
// как OpkgTunN. Выданный клиенту, этот адрес локален на сервере: обратный
// трафик к нему не уйдёт в туннель, и абонент молча остаётся без связи.
func TestGetNextRawIPSkipsNDMSGateway(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{})

	if got := getNextRawIP(); got != "10.70.0.2" {
		t.Fatalf("первый raw-адрес = %q, ожидали 10.70.0.2 (10.70.0.1 — шлюз NDMS)", got)
	}
}
