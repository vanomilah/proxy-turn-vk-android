package main

// Обвязка awg-manager для wdtt-server: управляющий сокет, журнал, отпечатки.
// Живёт коммитом в ветке awg-server форка, рядом с server.go и keenetic.go.

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hoaxisr/awg-manager/awgmproto"
)

const (
	awgmImpl = "wdtt-server"
	awgmRole = "server"
)

const awgmCapPeriod = 30 * time.Second

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
		// attach-tun/detach-tun сервер не поддерживает (матрица ролей §6):
		// в commands их нет, и менеджер, собравшийся их звать, откажет на гейте.
		if err := awgmproto.PrintProtocol(os.Stdout, awgmproto.ProtocolInfo{
			Impl: awgmImpl, Role: awgmRole, Commands: []string{awgmproto.CmdState},
		}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	awgmproto.IgnoreSIGPIPE()

	if opts.LogFile != "" {
		lg, err := awgmproto.OpenLog(opts.LogFile)
		if err != nil {
			log.Printf("[AWGM] журнал %s: %v", opts.LogFile, err)
		} else {
			awgmLog = lg
			if err := awgmproto.RedirectStdio(lg); err != nil {
				log.Printf("[AWGM] вывод в журнал: %v", err)
			}
			go lg.WatchCap(context.Background(), awgmCapPeriod)
		}
	}

	// Отказ отпечатка не фатален: поле уедет пустым, причина — в last_error и в
	// журнале (§5.2: пустая строка в обязательном поле — «неизвестно»).
	sum, err := awgmproto.BinarySHA256()

	awgmState.mu.Lock()
	if err != nil {
		log.Printf("[AWGM] отпечаток бинаря: %v", err)
		awgmState.lastError = "отпечаток бинаря: " + err.Error()
	}
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
	}
}

// awgmSetError запоминает последнюю ошибку и будит менеджера.
//
// Вызывающего нет — намеренно, см. конец задачи: общей точки печати ошибок у
// монолита не существует, а классификатор строк журнала мы не заводим. Отказ
// отпечатка бинаря пишет lastError напрямую, потому что случается внутри уже
// взятого лока.
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

// awgmHandler — команды протокола для сервера. TUN у него нет.
type awgmHandler struct{}

func (awgmHandler) State() awgmproto.State           { return awgmState.snapshot() }
func (awgmHandler) AttachTun(string, *os.File) error { return awgmproto.ErrNotSupported }
func (awgmHandler) DetachTun() error                 { return awgmproto.ErrNotSupported }
