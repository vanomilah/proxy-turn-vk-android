package main

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakePC — источник, который отдаёт пакеты из канала, а после Close только
// ошибки; считает попытки чтения.
type fakePC struct {
	pkt   chan byte
	done  chan struct{}
	reads atomic.Int64
}

func newFakePC() *fakePC {
	return &fakePC{pkt: make(chan byte, 1), done: make(chan struct{})}
}

func (f *fakePC) ReadFrom(b []byte) (int, net.Addr, error) {
	f.reads.Add(1)
	select {
	case v := <-f.pkt:
		b[0] = v
		return 1, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
	case <-f.done:
		return 0, nil, errors.New("closed")
	}
}
func (f *fakePC) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (f *fakePC) Close() error                          { close(f.done); return nil }
func (f *fakePC) LocalAddr() net.Addr                   { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (f *fakePC) SetDeadline(time.Time) error           { return nil }
func (f *fakePC) SetReadDeadline(time.Time) error       { return nil }
func (f *fakePC) SetWriteDeadline(time.Time) error      { return nil }

func TestPendingAttachDetachAttach(t *testing.T) {
	p := newPendingPacketConn()
	got := make(chan byte, 4)
	go func() {
		buf := make([]byte, 8)
		for {
			n, _, err := p.ReadFrom(buf)
			if err != nil {
				t.Errorf("ReadFrom вынес ошибку открепления наружу: %v", err)
				return
			}
			if n > 0 {
				got <- buf[0]
			}
		}
	}()

	// 1. До Attach читатель обязан блокироваться.
	select {
	case b := <-got:
		t.Fatalf("прочитал %q до Attach", b)
	case <-time.After(100 * time.Millisecond):
	}

	// 2. Первое прикрепление.
	a := newFakePC()
	p.Attach(a)
	a.pkt <- 'a'
	select {
	case b := <-got:
		if b != 'a' {
			t.Fatalf("после Attach прочитал %q, ждали 'a'", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("после Attach читатель ничего не отдал")
	}

	// 3. Открепление в порядке слота: сначала Detach, потом закрытие
	// дескриптора. Ошибка чтения на закрытом источнике наружу выйти не должна.
	p.Detach()
	_ = a.Close()
	time.Sleep(300 * time.Millisecond)

	// Читатель обязан снова блокироваться, а не крутиться: канал ready заведён
	// заново. Закрытый ready дал бы busy-loop без единого чтения источника.
	p.mu.Lock()
	ready := p.ready
	p.mu.Unlock()
	select {
	case <-ready:
		t.Fatal("после Detach канал ready закрыт — ReadFrom будет крутиться вхолостую")
	default:
	}
	select {
	case b := <-got:
		t.Fatalf("после Detach прочитал %q", b)
	default:
	}

	// 4. Повторное прикрепление — Attach обязан закрыть новый ready.
	c := newFakePC()
	p.Attach(c)
	c.pkt <- 'b'
	select {
	case b := <-got:
		if b != 'b' {
			t.Fatalf("после второго Attach прочитал %q, ждали 'b'", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("после второго Attach читатель ничего не отдал")
	}

	// 5. Attach без Detach между ними не должен ронять процесс закрытием уже
	// закрытого канала. Сегодня слот так не зовёт, но цена ошибки — паника в
	// рабочем процессе, а не отказ команды.
	p.Attach(newFakePC())
}
