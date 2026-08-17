package main

import (
	"context"
	"net"
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

// TestHandleConnRawDeniesByPasswordKind проверяет ЖИВУЮ ветку протокола:
// какой именно отказ уезжает клиенту. Истёкший пароль обязан получать
// DENIED:expired, а не DENIED:wrong_password — вырождение диагностики
// компилируется и работает, поэтому ловится только прогоном.
func TestHandleConnRawDeniesByPasswordKind(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"abonent1pass": {Label: "Абонент 1"},
		"expiredpass":  {Label: "истёк", ExpiresAt: time.Now().Unix() - 1},
	})

	cases := []struct {
		name     string
		password string
		want     string
	}{
		{"главный пароль", "adminkey", "DENIED:wrong_password"},
		{"неизвестный пароль", "nosuchpassword", "DENIED:wrong_password"},
		{"истёкший пароль", "expiredpass", "DENIED:expired"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				handleConnRaw(context.Background(), server, nil)
			}()

			client.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Write([]byte("GETCONF_RAW:device-1|" + tc.password)); err != nil {
				t.Fatalf("отправка GETCONF_RAW: %v", err)
			}
			buf := make([]byte, 128)
			n, err := client.Read(buf)
			if err != nil {
				t.Fatalf("чтение ответа: %v", err)
			}
			if got := string(buf[:n]); got != tc.want {
				t.Fatalf("ответ %q, ожидался %q", got, tc.want)
			}
			<-done
		})
	}
}
