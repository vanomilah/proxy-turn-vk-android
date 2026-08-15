package main

import (
	"os"
	"testing"
	"time"
)

// Страж пути трафика: слот TUN → fdPacketConn → pendingPacketConn → читатель
// диспетчера. Контракт протокола (state/attach-tun/detach-tun) отвечает верно и
// при разорванном пути — `attached:true` приходит от поля слота, а не от
// прикреплённого дескриптора. Поэтому проверка тут поведенческая: в дескриптор
// пишут, из клиента читают.
//
// Дескриптор берётся из os.Pipe, а не из /dev/net/tun: слоту нужен *os.File, а
// не именно tun, и так тест не требует ни root, ни сетевого namespace.

type readRes struct {
	data []byte
	err  error
}

// readOnce читает один пакет в отдельной горутине. Одноразовая, поэтому на
// зелёном прогоне не остаётся висящих горутин.
func readOnce(p *pendingPacketConn) <-chan readRes {
	ch := make(chan readRes, 1)
	go func() {
		buf := make([]byte, 64)
		n, _, err := p.ReadFrom(buf)
		ch <- readRes{data: append([]byte(nil), buf[:n]...), err: err}
	}()
	return ch
}

func expectPacket(t *testing.T, ch <-chan readRes, want string, whatBroke string) {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: чтение вернуло ошибку %v", whatBroke, r.err)
		}
		if string(r.data) != want {
			t.Fatalf("%s: прочитано %q, ждали %q", whatBroke, r.data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(whatBroke)
	}
}

// pipeFD отдаёт «дескриптор от менеджера» и конец, в который пишут за него.
func pipeFD(t *testing.T) (fd *os.File, peer *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	return r, w
}

// RAWCONF раньше дескриптора: bind уже сделан, attach обязан прикрепить fd
// сразу.
func TestAwgmTunSlotAttachAfterBindDeliversTraffic(t *testing.T) {
	pend := newPendingPacketConn()
	var slot awgmTunSlot
	slot.bind(pend)

	fd, peer := pipeFD(t)
	if err := slot.attach("awgmt-a", fd); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if iface, attached := slot.status(); !attached || iface != "awgmt-a" {
		t.Fatalf("status после attach = %q/%v", iface, attached)
	}

	got := readOnce(pend)
	if _, err := peer.Write([]byte("A")); err != nil {
		t.Fatalf("запись в дескриптор: %v", err)
	}
	expectPacket(t, got, "A",
		"attach не прикрепил дескриптор к клиенту: state скажет attached:true, а трафик не пойдёт")
}

// Дескриптор раньше RAWCONF: attach отработал в пустоту, прикрепить обязан
// bind. Ради этого случая слот и заведён.
func TestAwgmTunSlotBindAfterAttachDeliversTraffic(t *testing.T) {
	pend := newPendingPacketConn()
	var slot awgmTunSlot

	fd, peer := pipeFD(t)
	if err := slot.attach("awgmt-b", fd); err != nil {
		t.Fatalf("attach: %v", err)
	}
	slot.bind(pend)

	got := readOnce(pend)
	if _, err := peer.Write([]byte("B")); err != nil {
		t.Fatalf("запись в дескриптор: %v", err)
	}
	expectPacket(t, got, "B",
		"bind не подобрал дескриптор, пришедший раньше RAWCONF: трафик не пойдёт никогда")
}

// detach обязан открепить клиента, иначе читающий цикл диспетчера останется на
// закрытом дескрипторе и будет жечь CPU до следующего attach-tun.
func TestAwgmTunSlotDetachUnwiresClient(t *testing.T) {
	pend := newPendingPacketConn()
	var slot awgmTunSlot
	slot.bind(pend)

	fd, peer := pipeFD(t)
	if err := slot.attach("awgmt-c", fd); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got := readOnce(pend)
	if _, err := peer.Write([]byte("C")); err != nil {
		t.Fatalf("запись в дескриптор: %v", err)
	}
	expectPacket(t, got, "C", "дескриптор не доехал до клиента ещё до detach")

	slot.detach()

	if iface, attached := slot.status(); attached || iface != "" {
		t.Fatalf("status после detach = %q/%v", iface, attached)
	}
	pend.mu.Lock()
	real, ready := pend.real, pend.ready
	pend.mu.Unlock()
	if real != nil {
		t.Fatal("detach не открепил клиента: диспетчер останется на закрытом дескрипторе и будет крутиться на ошибках")
	}
	select {
	case <-ready:
		t.Fatal("после detach канал ready закрыт — чтение не заблокируется")
	default:
	}

	// Ренумерация OpkgTun17 → OpkgTun18: после detach слот обязан принять новый
	// дескриптор и снова довести трафик.
	fd2, peer2 := pipeFD(t)
	if err := slot.attach("awgmt-c2", fd2); err != nil {
		t.Fatalf("повторный attach: %v", err)
	}
	got2 := readOnce(pend)
	if _, err := peer2.Write([]byte("D")); err != nil {
		t.Fatalf("запись во второй дескриптор: %v", err)
	}
	expectPacket(t, got2, "D", "после detach слот не принимает новый дескриптор: смена интерфейса сломана")
}
