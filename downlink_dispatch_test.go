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

// Страж ступеней downlinkChunkSizeFor. Верхняя ступень поднята 64 → 256:
// на стенде KN-1010 (MT7621) чанк 64 размазывал один TCP-поток по реле с
// разным latency → reorder на клиенте → DupACK-шторм и обрыв cwnd. Замер
// (одно железо/канал/время): 10-15 Мбит/с при CPU до 90% → 18.6 Мбит/с при
// CPU 43.2%; бюджет CPU на ДОСТАВЛЕННЫЙ пакет 749 → 242 мкс, то есть до
// правки ~68% работы шифрования уходило в ретрансмиссии.
// Границы проверяются на ТОЧНЫХ значениях: ступень задана строгим ">" сверху
// и нестрогим ">=" на остальных, случайная замена одного на другое ловится.
func TestDownlinkChunkSizeForSteps(t *testing.T) {
	cases := []struct {
		pktSize int
		want    int
	}{
		{1500, 256}, // типичный MTU-пакет downlink
		{1101, 256}, // первое значение верхней ступени
		{1100, 24},  // ещё не верхняя ступень
		{702, 24},
		{701, 24}, // нижняя граница ступени 24
		{700, 8},
		{302, 8},
		{301, 8}, // нижняя граница ступени 8
		{300, 3},
		{102, 3},
		{101, 3}, // нижняя граница ступени 3
		{100, 1},
		{40, 1}, // keepalive-размер
		{1, 1},
		{0, 1},
	}
	for _, c := range cases {
		if got := downlinkChunkSizeFor(c.pktSize); got != c.want {
			t.Errorf("downlinkChunkSizeFor(%d) = %d, ожидалось %d", c.pktSize, got, c.want)
		}
	}
}

// Страж значения потолка воркеров на клиентский IP.
func TestRawMaxWorkersPerIPValue(t *testing.T) {
	if rawMaxWorkersPerIP != 64 {
		t.Fatalf("потолок воркеров = %d, ожидалось 64 (36 штатных + 28 запаса)", rawMaxWorkersPerIP)
	}
	// Потолок обязан лежать ВЫШЕ штатного максимума клиента: клиент кратен 9
	// (9/18/27/36), поэтому 36 — рабочая конфигурация, а не край. Потолок на
	// уровне 36 или ниже упирался бы в неё циклом переподключений.
	const clientMaxWorkers = 36
	if rawMaxWorkersPerIP <= clientMaxWorkers {
		t.Fatalf("потолок %d не выше штатного максимума клиента %d", rawMaxWorkersPerIP, clientMaxWorkers)
	}
}

// Страж формы отказа: сверх потолка register возвращает nil (вызывающий
// закрывает соединение и логирует), а не паникует, не вытесняет живое реле
// и не роняет пакеты молча. Освободившийся слот снова принимает — потолок
// не залипает после отключения клиента.
func TestRegisterRejectsAboveWorkerCap(t *testing.T) {
	r := &rawRouter{sessions: make(map[string]*rawClientSessions)}
	const ip = "10.10.0.3"

	workers := make([]*downlinkWorker, 0, rawMaxWorkersPerIP)
	defer func() {
		for _, w := range workers {
			r.unregister(ip, w)
		}
	}()

	for i := 0; i < rawMaxWorkersPerIP; i++ {
		w := r.register(ip, nopConn{}, "dev")
		if w == nil {
			t.Fatalf("register #%d отвергнут ниже потолка %d", i+1, rawMaxWorkersPerIP)
		}
		workers = append(workers, w)
	}

	if w := r.register(ip, nopConn{}, "dev"); w != nil {
		r.unregister(ip, w)
		t.Fatalf("register сверх потолка %d вернул воркера, ожидался nil", rawMaxWorkersPerIP)
	}
	r.mu.Lock()
	n := len(r.sessions[ip].workers)
	r.mu.Unlock()
	if n != rawMaxWorkersPerIP {
		t.Fatalf("после отказа зарегистрировано %d воркеров, ожидалось %d", n, rawMaxWorkersPerIP)
	}

	r.unregister(ip, workers[0])
	workers = workers[1:]
	w := r.register(ip, nopConn{}, "dev")
	if w == nil {
		t.Fatal("после освобождения слота register всё ещё отвергает")
	}
	workers = append(workers, w)
}
