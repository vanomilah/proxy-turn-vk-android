package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// nopConn — минимальный net.Conn: воркеру нужен только Write.
type nopConn struct{ net.Conn }

func (nopConn) Write(b []byte) (int, error) { return len(b), nil }

// Страж гонки «send on closed channel». Раньше downlinkLoop брал воркера
// (pickDownlinkConn отпускал r.mu) и только потом слал ему в sendCh, а
// unregister в этом окне успевал снять воркера и закрыть канал — отправка
// в закрытый канал роняла паникой ВЕСЬ сервер. Тест гоняет регистрацию,
// снятие и раздачу пакетов параллельно: до фикса падает, после — зелёный,
// в том числе под -race.
func TestDispatchDownlinkVsUnregisterChurn(t *testing.T) {
	r := &rawRouter{sessions: make(map[string]*rawClientSessions)}
	const ip = "10.10.0.2"

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Раздача пакетов — как downlinkLoop.
	pkt := make([]byte, 300)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r.dispatchDownlink(ip, pkt)
			}
		}()
	}

	// Churn воркеров: relay на мобильных клиентах переподключаются постоянно.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				w := r.register(ip, nopConn{}, fmt.Sprintf("dev-%d", n))
				r.unregister(ip, w)
			}
		}(i)
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// Пейсер отключается нулём — на этом держится смысл флагов
// -raw-downlink-rate/-raw-downlink-burst.
func TestNewPacerZeroDisables(t *testing.T) {
	if newPacer(0, rawDownlinkBurst) != nil {
		t.Fatal("rate=0 должен выключать пейсер")
	}
	if newPacer(rawDownlinkRate, 0) != nil {
		t.Fatal("burst=0 должен выключать пейсер")
	}
	if newPacer(rawDownlinkRate, rawDownlinkBurst) == nil {
		t.Fatal("дефолтные значения должны включать пейсер")
	}
	if err := (*pacer)(nil).await(t.Context(), 1500); err != nil {
		t.Fatalf("await на nil-пейсере: %v", err)
	}
}
