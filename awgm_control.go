package main

// Обвязка awg-manager для wdtt-server: управляющий сокет, журнал, отпечатки.
// Живёт коммитом в ветке awg-server форка, рядом с server.go и keenetic.go.

import (
	"context"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hoaxisr/awg-manager/awgmproto"
)

const (
	awgmImpl = "wdtt-server"
	awgmRole = "server"
)

// awgmDefaultListen повторяет дефолт флага -listen у форка (server.go).
// Без него state соврал бы при запуске без -listen: сервер слушает 56000, а
// поле dtls было бы нулём, то есть «транспорт выключен».
const awgmDefaultListen = "0.0.0.0:56000"

var (
	awgmOpts    awgmproto.Options
	awgmSrv     *awgmproto.Server
	awgmLog     *awgmproto.Log
	awgmStarted = time.Now()
	awgmState   awgmServerState
)

// awgmServerState — то, что сервер рассказывает о себе.
//
// Адресов прослушивания три, а не два: -listen (DTLS), -listen-direct
// (клиенты без DTLS, RTP-obfs AEAD напрямую) и -listen-raw (raw-IP клиенты без
// WireGuard). Пустой флаг у двух последних означает «выключено» — это ноль в
// state, законное значение, а не «неизвестно».
type awgmServerState struct {
	mu           sync.Mutex
	instance     string
	configHash   string
	binarySHA256 string
	dtlsPort     int
	directPort   int
	rawPort      int
	lastError    string
}

// awgmSetup — ПЕРВАЯ строка main.
func awgmSetup() []string {
	full := os.Args[1:]
	rest, opts := awgmproto.SplitArgs(full)
	awgmOpts = opts

	if opts.Protocol {
		// attach-tun/detach-tun сервер поддерживает с этой версии: обе половины
		// (WireGuard и raw) работают на TUN, который создал и настроил NDMS, а
		// не на своём. Раньше сервер сносил чужой интерфейс `ip link del` и
		// поднимал одноимённый свой — после его выхода запись NDMS оставалась
		// без устройства, и роутер каждые 30 секунд писал «no such device».
		if err := awgmproto.PrintProtocol(os.Stdout, awgmproto.ProtocolInfo{
			Impl: awgmImpl, Role: awgmRole,
			Commands: []string{awgmproto.CmdState, awgmproto.CmdAttachTun, awgmproto.CmdDetachTun},
		}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	awgmproto.IgnoreSIGPIPE()

	// Отказы обвязки на старте копятся, а не затирают друг друга: без журнала
	// менеджер слепнет целиком, и терять эту причину под отказом отпечатка
	// нельзя. Других писателей lastError, кроме этих трёх мест, нет.
	var setupErrs []string

	if opts.LogFile != "" {
		lg, err := awgmproto.OpenLog(opts.LogFile)
		if err != nil {
			// Отказ журнала — тот единственный случай, о котором роль обязана
			// сказать в last_error (§6.1). Мотив «видимость ошибок несёт журнал»
			// перестаёт работать ровно тогда, когда журнала нет: сообщение ушло
			// бы в унаследованный stderr, а менеджер не узнал бы вообще ничего.
			// Классификатора строк журнала здесь нет и не появляется: это наш
			// собственный, точно известный отказ нашей же обвязки.
			log.Printf("[AWGM] журнал %s: %v", opts.LogFile, err)
			setupErrs = append(setupErrs, "журнал недоступен: "+err.Error())
		} else {
			awgmLog = lg
			if err := awgmproto.RedirectStdio(lg); err != nil {
				// Слепота та же, а вводит в заблуждение сильнее: файл открыт и
				// пуст, и менеджер прочитает это как «процессу нечего сказать»,
				// а не как «мы ничего не видим».
				log.Printf("[AWGM] вывод в журнал: %v", err)
				setupErrs = append(setupErrs, "вывод не перенаправлен в журнал: "+err.Error())
			}
			go lg.WatchCap(context.Background(), awgmproto.CapPeriod)
		}
	}

	// Отказ отпечатка не фатален: поле уедет пустым, причина — в last_error и в
	// журнале (§5.2: пустая строка в обязательном поле — «неизвестно»).
	sum, err := awgmproto.BinarySHA256()

	awgmState.mu.Lock()
	if err != nil {
		log.Printf("[AWGM] отпечаток бинаря: %v", err)
		setupErrs = append(setupErrs, "отпечаток бинаря: "+err.Error())
	}
	awgmState.lastError = strings.Join(setupErrs, "; ")
	awgmState.binarySHA256 = sum
	awgmState.instance = awgmproto.InstanceFromPath(opts.Socket, awgmImpl, awgmRole)
	// Отпечаток конфигурации считается ОДИН раз при старте и только по
	// аргументам. Файловых конфигов в нём нет ни одного, в том числе
	// passwords.json: сервер перезаписывает его сам (saveDB), и хеш содержимого
	// разошёлся бы при первом же подключившемся клиенте — не потому, что
	// что-то не так, а потому, что так работает сервер. В отпечаток идёт только
	// то, что даём процессу мы (§5.5 спеки).
	awgmState.configHash = awgmproto.ConfigHash(full)
	listen := awgmproto.FlagValue(rest, "listen")
	if listen == "" {
		listen = awgmDefaultListen
	}
	awgmState.dtlsPort = awgmPortOf(listen)
	awgmState.directPort = awgmPortOf(awgmproto.FlagValue(rest, "listen-direct"))
	awgmState.rawPort = awgmPortOf(awgmproto.FlagValue(rest, "listen-raw"))
	awgmState.mu.Unlock()

	os.Args = append(os.Args[:1], rest...)
	awgmStartControl()
	return rest
}

// awgmPortOf вынимает порт из адреса вида "host:port" или ":port".
func awgmPortOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

func awgmStartControl() {
	if awgmOpts.Socket == "" {
		return
	}
	srv, err := awgmproto.Listen(awgmproto.ServerConfig{
		Path: awgmOpts.Socket, Impl: awgmImpl, Role: awgmRole,
		Instance: awgmState.snapshot().Instance,
		Handler:  awgmHandler{},
		OnError:  func(err error) { log.Printf("[AWGM] %v", err) },
	})
	if err != nil {
		log.Fatalf("[AWGM] управляющий сокет: %v", err)
	}
	awgmSrv = srv
	go srv.Serve()
}

func (s *awgmServerState) snapshot() awgmproto.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Клиенты и адреса — обязательные поля роли (§6), поэтому заполняются
	// ВСЕГДА. Ноль клиентов и выключенный транспорт — законные значения:
	// «поля нет» менеджер читает как unknown, и пустой сервер стал бы
	// неотличим от неотвечающего.
	clients := int(countActiveDevices())
	return awgmproto.State{
		Role: awgmRole, Instance: s.instance, PID: os.Getpid(),
		ConfigHash: s.configHash, BinarySHA256: s.binarySHA256,
		UptimeS: int64(time.Since(awgmStarted).Seconds()), LastError: s.lastError,
		Listen: &awgmproto.ListenState{
			DTLS: s.dtlsPort, Direct: s.directPort, Raw: s.rawPort,
		},
		Clients: &clients,
		// Половин две, поэтому Tuns, а не Tun: менеджер держит по ресурсу на
		// интерфейс и ищет в списке свой. Пустой список = ни одного
		// дескриптора, законное состояние до первого attach-tun.
		Tuns: awgmTun.states(),
	}
}

// awgmSetError запоминает последнюю ошибку и будит менеджера.
//
// Вызывающего нет — намеренно, см. конец задачи: общей точки печати ошибок у
// монолита не существует, а классификатор строк журнала мы не заводим. Отказы
// самой обвязки (журнал, отпечаток бинаря) пишут lastError прямо в awgmSetup:
// они случаются раньше, чем поднят слушатель, и пушить их было бы некуда.
// Из OnError слушателя её звать НЕЛЬЗЯ: OnError зовётся в том числе из Push, и
// получилась бы рекурсия «push не прошёл → пушим об этом».
func awgmSetError(message string, fatal bool) {
	awgmState.mu.Lock()
	awgmState.lastError = message
	awgmState.mu.Unlock()
	awgmPush(awgmproto.Event{Event: awgmproto.EventError, Message: message, Fatal: fatal})
}

// awgmPushExit — best effort: смерть процесса менеджер и так увидит по закрытию
// соединения, но у сервера между решением завершиться и os.Exit лежат две
// секунды сохранения базы, и push экономит их.
//
// Через PushExit, а не через общий Push: врезка стоит ПЕРЕД cancel(), то есть на
// пути выключения. С обычным сроком записи (5 с) недоступный менеджер задержал
// бы выключение сервера на пять секунд ровно тогда, когда сообщение всё равно
// некому прочитать. PushExit укладывается в секунду (farewellTimeout).
func awgmPushExit(code int) {
	if awgmSrv != nil {
		awgmSrv.PushExit(code)
	}
}

func awgmPush(ev awgmproto.Event) {
	if awgmSrv != nil {
		awgmSrv.Push(ev)
	}
}

// awgmHandler — команды протокола для сервера.
type awgmHandler struct{}

func (awgmHandler) State() awgmproto.State { return awgmState.snapshot() }

func (awgmHandler) AttachTun(iface string, f *os.File) error {
	return awgmTun.attach(iface, f)
}

func (awgmHandler) DetachTun() error {
	awgmTun.detachAll()
	return nil
}

// awgmTunSlots — дескрипторы TUN, переданные менеджером.
//
// У сервера их ДВА: WireGuard-половина и raw-половина, поэтому слоты именованы
// интерфейсом, а не единственным полем как у клиента. Дескриптор приходит
// после hello, то есть уже на работающем сокете, а половины поднимаются на
// старте — поэтому старт ЖДЁТ своего дескриптора (awgmTakeTun).
type awgmTunSlots struct {
	mu sync.Mutex
	// expected — половины, дескрипторы которых сервер ждёт: они попадают в
	// state с attached=false, чтобы менеджеру было что наблюдать.
	expected []string
	files    map[string]*os.File
	// waiters — по одному на ожидающий интерфейс: attach будит того, кто ждёт.
	waiters map[string]chan struct{}
}

var awgmTun = &awgmTunSlots{
	files:   make(map[string]*os.File),
	waiters: make(map[string]chan struct{}),
}

func (s *awgmTunSlots) attach(iface string, f *os.File) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return awgmproto.Errf(awgmproto.CodeBadRequest, "attach-tun без имени интерфейса")
	}
	s.mu.Lock()
	if _, busy := s.files[iface]; busy {
		s.mu.Unlock()
		// Молча подменять дескриптор нельзя: сервер уже читает из старого.
		return awgmproto.Errf(awgmproto.CodeBusy, "дескриптор %s уже прикреплён", iface)
	}
	s.files[iface] = f
	w := s.waiters[iface]
	delete(s.waiters, iface)
	s.mu.Unlock()
	if w != nil {
		close(w)
	}
	yes := true
	awgmPush(awgmproto.Event{Event: awgmproto.EventTun, Iface: iface, Attached: &yes})
	return nil
}

// detachAll отпускает все дескрипторы: команда протокола адресует процесс
// целиком, а не отдельный интерфейс.
func (s *awgmTunSlots) detachAll() {
	s.mu.Lock()
	files := s.files
	s.files = make(map[string]*os.File)
	s.mu.Unlock()
	no := false
	for iface, f := range files {
		if f != nil {
			_ = f.Close()
		}
		awgmPush(awgmproto.Event{Event: awgmproto.EventTun, Iface: iface, Attached: &no})
	}
}

// awgmExpectTun объявляет половину, дескриптор которой сервер ждёт от
// менеджера. Зовётся при разборе флагов, до старта половин.
func awgmExpectTun(iface string) {
	iface = strings.TrimSpace(iface)
	if iface == "" || !awgmEnabled() {
		return
	}
	awgmTun.mu.Lock()
	awgmTun.expected = append(awgmTun.expected, iface)
	awgmTun.mu.Unlock()
}

// states — что рассказать менеджеру о дескрипторах.
//
// Список включает ОЖИДАЕМЫЕ половины с attached=false, а не только уже
// прикреплённые: пока сервер молчал о них вовсе, ресурс менеджера не мог
// наблюдать состояние и не выполнял attach — обе стороны ждали друг друга,
// и половины поднимались по таймауту своим устройством (стенд 2026-08-28).
func (s *awgmTunSlots) states() []awgmproto.TunState {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make(map[string]bool, len(s.expected)+len(s.files))
	for _, iface := range s.expected {
		names[iface] = false
	}
	for iface := range s.files {
		names[iface] = true
	}
	if len(names) == 0 {
		return nil
	}
	out := make([]awgmproto.TunState, 0, len(names))
	for iface, attached := range names {
		out = append(out, awgmproto.TunState{Iface: iface, Attached: attached})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}

// awgmTakeTun забирает дескриптор интерфейса, дожидаясь его прихода.
//
// Ждём, потому что порядок задаёт менеджер: он поднимает интерфейс в NDMS,
// стартует процесс и только потом передаёт дескриптор. Без ожидания сервер
// падал бы на старте гонкой с собственным менеджером. Возврат nil означает
// «под менеджером не работаем или не дождались» — вызывающий сам решает,
// поднимать ли половину по-старому.
func awgmTakeTun(iface string, wait time.Duration) *os.File {
	if !awgmEnabled() {
		return nil
	}
	return awgmTun.take(iface, wait)
}

func (s *awgmTunSlots) take(iface string, wait time.Duration) *os.File {
	s.mu.Lock()
	if f, ok := s.files[iface]; ok {
		s.mu.Unlock()
		return f
	}
	w, ok := s.waiters[iface]
	if !ok {
		w = make(chan struct{})
		s.waiters[iface] = w
	}
	s.mu.Unlock()

	select {
	case <-w:
	case <-time.After(wait):
		s.mu.Lock()
		delete(s.waiters, iface)
		s.mu.Unlock()
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.files[iface]
}

// awgmEnabled — работаем ли под менеджером.
func awgmEnabled() bool { return awgmOpts.Socket != "" }
