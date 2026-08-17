package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Сторожа новой модели доступа: пароль абонента даёт подключение, главный
// пароль — только администрирование. Проверяется и диагностика отказа:
// «истёк» и «нет такого» — разные ответы клиенту, схлопывание их в один
// компилируется и работает, поэтому ловится только прогоном.

// setTestDB подменяет глобальную БД на время теста и возвращает её обратно.
func setTestDB(t *testing.T, mainPassword string, passwords map[string]*PasswordEntry) {
	t.Helper()
	old := db
	db = &Database{
		MainPassword: mainPassword,
		Passwords:    passwords,
		Devices:      make(map[string]*ClientDevice),
	}
	t.Cleanup(func() { db = old })
}

func TestPasswordAcceptedRejectsMainPassword(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"abonent1": {Label: "Абонент 1"},
	})

	if entry, ok := passwordAccepted("adminkey"); ok || entry != nil {
		t.Fatalf("главный пароль принят как пароль абонента: entry=%v ok=%v", entry, ok)
	}
	if _, ok := passwordAccepted("abonent1"); !ok {
		t.Fatalf("пароль абонента отвергнут")
	}
}

func TestPasswordAcceptedRejectsExpired(t *testing.T) {
	now := time.Now().Unix()
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"expired":   {Label: "истёк", ExpiresAt: now - 1},
		"forever":   {Label: "бессрочный", ExpiresAt: 0},
		"stillgood": {Label: "живой", ExpiresAt: now + 3600},
	})

	if _, ok := passwordAccepted("expired"); ok {
		t.Fatalf("истёкший пароль принят")
	}
	if _, ok := passwordAccepted("forever"); !ok {
		t.Fatalf("бессрочный пароль (ExpiresAt=0) отвергнут")
	}
	if _, ok := passwordAccepted("stillgood"); !ok {
		t.Fatalf("непросроченный пароль отвергнут")
	}
}

func TestPasswordAcceptedReturnsEntryForExpired(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"expired": {Label: "истёк", ExpiresAt: time.Now().Unix() - 1},
	})

	// Ветки отказа (DENIED:expired против DENIED:wrong_password) отличают
	// истёкший пароль от неизвестного ровно по этой записи.
	entry, ok := passwordAccepted("expired")
	if ok {
		t.Fatalf("истёкший пароль принят")
	}
	if entry == nil {
		t.Fatalf("запись истёкшего пароля не возвращена — отказ выродится в wrong_password")
	}
	if !isPasswordExpired(entry) {
		t.Fatalf("возвращена не та запись: %+v", entry)
	}

	unknown, ok := passwordAccepted("nosuchpassword")
	if ok {
		t.Fatalf("неизвестный пароль принят")
	}
	if unknown != nil {
		t.Fatalf("для неизвестного пароля вернулась запись %+v", unknown)
	}
}

func TestRefreshWrapKeysExcludesMainPassword(t *testing.T) {
	now := time.Now().Unix()
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"abonent1": {Label: "Абонент 1"},
		"abonent2": {Label: "Абонент 2", ExpiresAt: now + 3600},
		"expired":  {Label: "истёк", ExpiresAt: now - 1},
	})
	t.Cleanup(func() { serverWrapKeys.SetPasswords(nil) })

	if err := refreshWrapKeysFromDBLocked(); err != nil {
		t.Fatalf("обновление WRAP-ключей: %v", err)
	}
	if got := serverWrapKeys.Count(); got != 2 {
		t.Fatalf("ключей %d, ожидалось 2 (по числу живых абонентов, без главного пароля)", got)
	}
}

// denialProbe прогоняет один запрос через обработчик по net.Pipe и возвращает
// первый ответ сервера. Клиент закрывается до ожидания обработчика: после
// отказа классический handleConn ждёт следующий пакет, а не выходит сразу.
func denialProbe(t *testing.T, request string, handler func(net.Conn)) string {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handler(server)
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte(request)); err != nil {
		client.Close()
		t.Fatalf("отправка %q: %v", request, err)
	}
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	client.Close()
	if err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}
	<-done
	return string(buf[:n])
}

// denialCases — один и тот же набор отказов для обоих путей протокола.
// Истёкший пароль обязан получать DENIED:expired, а не DENIED:wrong_password:
// вырождение диагностики компилируется и работает, поэтому ловится только
// прогоном — и обязано ловиться на КАЖДОМ из двух путей.
var denialCases = []struct {
	name     string
	password string
	want     string
}{
	{"главный пароль", "adminkey", "DENIED:wrong_password"},
	{"неизвестный пароль", "nosuchpassword", "DENIED:wrong_password"},
	{"истёкший пароль", "expiredpass", "DENIED:expired"},
	{"деактивированный абонент", "deactivpass", "DENIED:deactivated"},
}

func setDenialTestDB(t *testing.T) {
	t.Helper()
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"abonent1pass": {Label: "Абонент 1"},
		"expiredpass":  {Label: "истёк", ExpiresAt: time.Now().Unix() - 1},
		"deactivpass":  {Label: "выключен", IsDeactivated: true},
	})
}

// TestHandleConnRawDeniesByPasswordKind — raw-IP путь (GETCONF_RAW).
func TestHandleConnRawDeniesByPasswordKind(t *testing.T) {
	setDenialTestDB(t)

	for _, tc := range denialCases {
		t.Run(tc.name, func(t *testing.T) {
			got := denialProbe(t, "GETCONF_RAW:device-1|"+tc.password, func(c net.Conn) {
				handleConnRaw(context.Background(), c, nil)
			})
			if got != tc.want {
				t.Fatalf("ответ %q, ожидался %q", got, tc.want)
			}
		})
	}
}

// TestHandleConnDeniesByPasswordKind — классический WireGuard-путь (GETCONF).
// Вторая копия проверки жила именно здесь, и защита от вырождения
// expired -> wrong_password нужна на обоих путях, а не на одном.
func TestHandleConnDeniesByPasswordKind(t *testing.T) {
	setDenialTestDB(t)

	for _, tc := range denialCases {
		t.Run(tc.name, func(t *testing.T) {
			// wgDev/keys в отказных ветках не разыменовываются — до них
			// доходит только принимающая ветка.
			got := denialProbe(t, "GETCONF:9000|device-1|"+tc.password, func(c net.Conn) {
				handleConn(context.Background(), c, "", nil, nil)
			})
			if got != tc.want {
				t.Fatalf("ответ %q, ожидался %q", got, tc.want)
			}
		})
	}
}

// TestHandleConnRawPersistsDeviceBinding сторожит saveDB() в принимающей
// ветке: canConnectAndBind привязывает устройство к паролю прямо в памяти, и
// без записи привязка исчезнет при рестарте — молча, потому что подключение
// при этом проходит.
func TestHandleConnRawPersistsDeviceBinding(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"abonent1pass": {Label: "Абонент 1", MaxDevices: 2},
	})
	// Устройство уже существует и с адресом — иначе принимающая ветка
	// сохранила бы БД ещё и по своей причине (выдача RawIP).
	db.Devices["device-1"] = &ClientDevice{DeviceID: "device-1", IP: "10.66.0.2", RawIP: "10.67.0.2"}

	oldFile := dbFile
	dbFile = filepath.Join(t.TempDir(), "passwords.json")
	t.Cleanup(func() { dbFile = oldFile })
	saveDB() // исходное состояние файла: привязки ещё нет

	router := &rawRouter{sessions: make(map[string]*rawClientSessions)}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleConnRaw(context.Background(), server, router)
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("GETCONF_RAW:device-1|abonent1pass")); err != nil {
		client.Close()
		t.Fatalf("отправка GETCONF_RAW: %v", err)
	}
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		client.Close()
		t.Fatalf("чтение ответа: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "RAWCONF:") {
		client.Close()
		t.Fatalf("ответ %q, ожидался RAWCONF:", got)
	}
	client.Close()
	<-done

	data, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("чтение %s: %v", dbFile, err)
	}
	var saved Database
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("разбор сохранённой БД: %v", err)
	}
	entry := saved.Passwords["abonent1pass"]
	if entry == nil {
		t.Fatalf("пароль абонента не сохранён вовсе: %s", data)
	}
	found := false
	for _, id := range entry.DeviceIDs {
		if id == "device-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("привязка device-1 не доехала до файла: device_ids=%v device_id=%q", entry.DeviceIDs, entry.DeviceID)
	}
}
