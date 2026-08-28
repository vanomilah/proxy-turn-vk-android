package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hoaxisr/awg-manager/awgmproto"
	"golang.org/x/sys/unix"
)

// Тесты ниже сторожат связки, которые ломаются МОЛЧА: код продолжает
// собираться и работать, а протокол начинает врать менеджеру. Проверять их
// глазами при каждом подтягивании апстрима — ровно та дисциплина, на которую
// нельзя опираться, поэтому связки проверяет прогон.

func parseServerGo(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("разбор server.go: %v", err)
	}
	return fset, f
}

func findMain(t *testing.T, f *ast.File) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "main" {
			return fn
		}
	}
	t.Fatal("в server.go нет func main")
	return nil
}

// TestAwgmSetupIsFirstInMain — awgmSetup обязан стоять ПЕРВЫМ выражением main.
//
// Уехав ниже flag.Parse, он ломается тихо и полностью: flag.Parse встречает
// неизвестный --awgm-protocol, печатает usage и завершает процесс кодом 2 —
// проба пригодности у менеджера отвечает мусором, а сокет не поднимается
// вовсе. Сборка при этом идёт, и локальный запуск без awgm-флагов выглядит
// исправным.
func TestAwgmSetupIsFirstInMain(t *testing.T) {
	_, f := parseServerGo(t)
	fn := findMain(t, f)
	if len(fn.Body.List) == 0 {
		t.Fatal("main пуст")
	}
	es, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("первое выражение main — не вызов, а %T", fn.Body.List[0])
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		t.Fatalf("первое выражение main — не вызов: %T", es.X)
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "awgmSetup" {
		t.Fatalf("первым в main зовётся не awgmSetup: %v", call.Fun)
	}
}

// TestAwgmDefaultListenMatchesFlag — константа обвязки обязана совпадать с
// дефолтом флага -listen в server.go.
//
// Разъехавшись, они дают враньё в state, а не отказ: менеджер, запустивший
// сервер без -listen, увидит не тот порт DTLS и построит по нему ссылку для
// клиентов. Дефолт живёт в апстримовом коде и меняется не нами.
func TestAwgmDefaultListenMatchesFlag(t *testing.T) {
	_, f := parseServerGo(t)
	fn := findMain(t, f)

	var got string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "String" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		name, err := strconv.Unquote(litOf(call.Args[0]))
		if err != nil || name != "listen" {
			return true
		}
		def, err := strconv.Unquote(litOf(call.Args[1]))
		if err == nil {
			got = def
		}
		return false
	})

	if got == "" {
		t.Fatal("в main не найден flag.String(\"listen\", …) — якорь уехал")
	}
	if got != awgmDefaultListen {
		t.Fatalf("awgmDefaultListen = %q, а флаг -listen по умолчанию %q", awgmDefaultListen, got)
	}
}

func litOf(e ast.Expr) string {
	if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
		return l.Value
	}
	return ""
}

// TestSnapshotState — состав и значения полей state для роли server.
//
// Сторожит обязательства §5.2 и матрицы §6, которых не видит ни сборка, ни vet:
// поле, потерявшее место в JSON (например `Clients` с omitempty вместо
// указателя), делает пустой сервер неотличимым от неотвечающего, а
// переставленные местами direct и raw уводят менеджера строить ссылку на
// ВЫКЛЮЧЕННЫЙ транспорт. Проверяем именно JSON: менеджер видит его, а не
// структуру.
func TestSnapshotState(t *testing.T) {
	// Три порта заведомо разные — перестановка полей местами обязана быть видна.
	s := &awgmServerState{
		instance:     "main",
		configHash:   "деадбиф",
		binarySHA256: "кафе",
		dtlsPort:     56000,
		directPort:   56002,
		rawPort:      56003,
	}

	withActiveDevices(t, "устройство-1", "устройство-2")

	got := map[string]any{}
	raw, err := json.Marshal(s.snapshot())
	if err != nil {
		t.Fatalf("сериализация state: %v", err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("разбор state: %v", err)
	}

	// Набор ключей ровно такой: обязательные для всех ролей плюс listen и
	// clients (матрица §6). Полей чужих ролей — mode, tun, address, mtu, wg —
	// быть не должно.
	wantKeys := []string{
		"role", "instance", "pid", "config_hash", "binary_sha256",
		"uptime_s", "last_error", "listen", "clients",
	}
	gotKeys := make([]string, 0, len(got))
	for k := range got {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(wantKeys)
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(wantKeys, gotKeys) {
		t.Fatalf("состав полей state:\n получили %v\n ожидали  %v", gotKeys, wantKeys)
	}

	if got["role"] != awgmRole {
		t.Errorf("role = %v, ожидали %q", got["role"], awgmRole)
	}
	if got["instance"] != "main" {
		t.Errorf("instance = %v", got["instance"])
	}
	if got["pid"] != float64(os.Getpid()) {
		t.Errorf("pid = %v, ожидали %d", got["pid"], os.Getpid())
	}
	if got["last_error"] != "" {
		t.Errorf("last_error = %v, у этой роли он пуст всегда (§6.1)", got["last_error"])
	}
	// Ровно столько, сколько насчитал countActiveDevices: цифра, взятая не
	// оттуда, разъедется с панелью сервера и заметна не будет.
	if got["clients"] != float64(2) {
		t.Errorf("clients = %v, ожидали 2", got["clients"])
	}

	listen, ok := got["listen"].(map[string]any)
	if !ok {
		t.Fatalf("listen не объект: %T", got["listen"])
	}
	for name, want := range map[string]float64{"dtls": 56000, "direct": 56002, "raw": 56003} {
		if listen[name] != want {
			t.Errorf("listen.%s = %v, ожидали %v", name, listen[name], want)
		}
	}
}

// TestSnapshotKeepsZeroClients — ноль клиентов остаётся В JSON.
//
// Отдельным тестом, а не случаем предыдущего: ноль — законное значение (§5.2),
// и стирающий его omitempty ломает ровно этот случай, оставляя тест с
// непустым счётчиком зелёным.
func TestSnapshotKeepsZeroClients(t *testing.T) {
	withActiveDevices(t)

	raw, err := json.Marshal((&awgmServerState{}).snapshot())
	if err != nil {
		t.Fatalf("сериализация state: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("разбор state: %v", err)
	}
	v, ok := got["clients"]
	if !ok {
		t.Fatal("поле clients исчезло при нуле клиентов: пустой сервер стал неотличим от неотвечающего")
	}
	if v != float64(0) {
		t.Errorf("clients = %v, ожидали 0", v)
	}
	if _, ok := got["listen"]; !ok {
		t.Error("поле listen исчезло при всех выключенных транспортах")
	}
}

// withActiveDevices подменяет счётчик устройств на время теста.
func withActiveDevices(t *testing.T, ids ...string) {
	t.Helper()
	activeDevicesMu.Lock()
	saved := activeDevices
	activeDevices = make(map[string]int32, len(ids))
	for _, id := range ids {
		activeDevices[id] = 1
	}
	activeDevicesMu.Unlock()
	t.Cleanup(func() {
		activeDevicesMu.Lock()
		activeDevices = saved
		activeDevicesMu.Unlock()
	})
}

// TestInstanceNamingMatchesManagerSocket — impl и role обязаны совпадать с
// именем сокета, которое даёт менеджер.
//
// Путь взят ЛИТЕРАЛОМ, а не собран из awgmImpl/awgmRole: собранный из тех же
// констант он совпал бы с ними всегда, и дрейф остался бы невидимым. Разъехавшись
// с менеджером, константы дают пустой instance — процесс отвечает, но своим не
// опознаётся.
func TestInstanceNamingMatchesManagerSocket(t *testing.T) {
	const path = "/tmp/awgm/wdtt-server-server-main.sock"
	if got := awgmproto.InstanceFromPath(path, awgmImpl, awgmRole); got != "main" {
		t.Fatalf("InstanceFromPath(%q) = %q, ожидали \"main\"; impl=%q role=%q разошлись с именем сокета менеджера",
			path, got, awgmImpl, awgmRole)
	}
}

// TestAwgmSetupReadsArgs — разбор argv обвязкой целиком: подстановка дефолта
// -listen, вычитывание двух остальных адресов, перезапись os.Args и увод
// вывода в журнал.
//
// Подстановка дефолта проверяется ЗДЕСЬ, а не в тесте константы: тот сторожит
// лишь совпадение литералов и переживает удаление самой подстановки.
// Перезапись os.Args — условие того, что flag.Parse форка не увидит awgm-флагов
// и не завершит процесс кодом 2.
func TestAwgmSetupReadsArgs(t *testing.T) {
	withAwgmGlobals(t)

	logPath := t.TempDir() + "/awgm.log"
	// -listen намеренно НЕ передан: сервер слушает свой дефолт, и state обязан
	// сказать именно его, а не ноль «транспорт выключен».
	// Сокета нет — слушатель не поднимается, тест ничего не занимает.
	os.Args = []string{"wdtt-server",
		"--awgm-log-file=" + logPath,
		"-listen-raw", "0.0.0.0:56003",
		"-config-dir", "/etc/wdtt",
	}
	rest := awgmSetup()

	const marker = "строка-в-журнал"
	fmt.Println(marker)
	if b, err := os.ReadFile(logPath); err != nil {
		t.Errorf("журнал %s не открылся: %v", logPath, err)
	} else if !strings.Contains(string(b), marker) {
		t.Errorf("вывод процесса не уехал в журнал: %q", string(b))
	}

	want := []string{"-listen-raw", "0.0.0.0:56003", "-config-dir", "/etc/wdtt"}
	if !reflect.DeepEqual(rest, want) {
		t.Errorf("остаток argv = %v, ожидали %v", rest, want)
	}
	if !reflect.DeepEqual(os.Args, append([]string{"wdtt-server"}, want...)) {
		t.Errorf("os.Args = %v — форк увидит awgm-флаги и умрёт на flag.Parse", os.Args)
	}

	st := awgmState.snapshot()
	if st.Listen.DTLS != awgmPortOf(awgmDefaultListen) {
		t.Errorf("listen.dtls = %d без флага -listen, ожидали дефолт %d",
			st.Listen.DTLS, awgmPortOf(awgmDefaultListen))
	}
	if st.Listen.Raw != 56003 {
		t.Errorf("listen.raw = %d, ожидали 56003", st.Listen.Raw)
	}
	if st.Listen.Direct != 0 {
		t.Errorf("listen.direct = %d, ожидали 0 (флаг не передан — транспорт выключен)", st.Listen.Direct)
	}
	// Журнал открылся — значит last_error пуст: у этой роли он заполняется
	// РОВНО отказами самой обвязки и ничем больше (§6.1).
	if st.LastError != "" {
		t.Errorf("last_error = %q при исправном старте, ожидали пустую строку", st.LastError)
	}
}

// TestAwgmSetupReportsJournalFailure — недоступный журнал обязан доехать до
// менеджера полем last_error.
//
// Это единственный отказ, о котором роль говорит в last_error, и обойтись
// журналом здесь нельзя по построению: журнала-то и нет. Сообщение уехало бы в
// унаследованный stderr, а менеджер не узнал бы ни причины, ни факта.
func TestAwgmSetupReportsJournalFailure(t *testing.T) {
	withAwgmGlobals(t)

	// Каталога нет — OpenLog отказывает предсказуемо и без прав root.
	os.Args = []string{"wdtt-server",
		"--awgm-log-file=" + t.TempDir() + "/нет-каталога/awgm.log",
		"-listen", "0.0.0.0:56000",
	}
	awgmSetup()

	// Через JSON: проверяем, что причина именно ДОЕЗЖАЕТ в state, а не просто
	// лежит в поле структуры.
	raw, err := json.Marshal(awgmState.snapshot())
	if err != nil {
		t.Fatalf("сериализация state: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("разбор state: %v", err)
	}
	msg, _ := got["last_error"].(string)
	if msg == "" {
		t.Fatal("last_error пуст при недоступном журнале: менеджер не узнает ни причины, ни факта")
	}
	// Префикс короткий и стабильный — его показывают в интерфейсе, и он не
	// зависит от текста ошибки ядра.
	const prefix = "журнал недоступен: "
	if !strings.HasPrefix(msg, prefix) {
		t.Errorf("last_error = %q, ожидали префикс %q", msg, prefix)
	}
	if awgmLog != nil {
		t.Error("журнал не открылся, а awgmLog выставлен")
	}
}

// TestSetupWritesLastErrorOnce — в awgmSetup ровно одно присвоение lastError.
//
// Отказов обвязки на старте три (журнал, перенаправление вывода, отпечаток
// бинаря), и они копятся в один список: причина слепоты не должна затираться
// причиной помельче. Второе присвоение вернуло бы затирание — молча, потому
// что одновременный отказ двух подсистем в тесте не воспроизвести (BinarySHA256
// отказывает только при недоступном /proc/self/exe).
func TestSetupWritesLastErrorOnce(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "awgm_control.go", nil, 0)
	if err != nil {
		t.Fatalf("разбор awgm_control.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Recv == nil && d.Name.Name == "awgmSetup" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("в awgm_control.go нет func awgmSetup")
	}

	var at []string
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "lastError" {
				continue
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "awgmState" {
				at = append(at, fset.Position(as.Pos()).String())
			}
		}
		return true
	})

	if len(at) != 1 {
		t.Fatalf("присвоений awgmState.lastError в awgmSetup: %d (%v), ожидали одно — иначе отказы затирают друг друга", len(at), at)
	}
}

// withAwgmGlobals изолирует тест от глобального состояния обвязки.
//
// Сохраняет и возвращает os.Args, awgmOpts и awgmState, а заодно дескрипторы
// 1 и 2: RedirectStdio внутри awgmSetup накрывает дескрипторы САМОГО процесса,
// а процесс здесь — тестовый бинарь. Без их возврата весь дальнейший вывод
// прогона уходит в журнал, и падение соседнего теста остаётся без текста.
func withAwgmGlobals(t *testing.T) {
	t.Helper()
	restoreStdio(t)
	savedArgs, savedOpts := os.Args, awgmOpts
	t.Cleanup(func() {
		os.Args, awgmOpts, awgmLog = savedArgs, savedOpts, nil
		// Глобальное состояние обвязки после теста обнуляется целиком: в этом
		// пакете его наполняет только awgmSetup, и другого владельца у него нет.
		awgmState.mu.Lock()
		defer awgmState.mu.Unlock()
		awgmState.instance, awgmState.configHash, awgmState.binarySHA256 = "", "", ""
		awgmState.lastError = ""
		awgmState.dtlsPort, awgmState.directPort, awgmState.rawPort = 0, 0, 0
	})
}

// restoreStdio запоминает дескрипторы 1 и 2 и возвращает их после теста.
func restoreStdio(t *testing.T) {
	t.Helper()
	saved := make(map[int]int, 2)
	for _, fd := range []int{1, 2} {
		dup, err := unix.Dup(fd)
		if err != nil {
			t.Fatalf("сохранение дескриптора %d: %v", fd, err)
		}
		saved[fd] = dup
	}
	t.Cleanup(func() {
		for fd, dup := range saved {
			_ = unix.Dup3(dup, fd, 0)
			_ = unix.Close(dup)
		}
	})
}

// TestAwgmPortOf — формы адресов, которые обвязка реально встречает: полный
// адрес, только порт и пустая строка («транспорт выключен»).
func TestAwgmPortOf(t *testing.T) {
	cases := map[string]int{
		"0.0.0.0:56000":   56000,
		":56001":          56001,
		"[::]:56002":      56002,
		"":                0,
		"0.0.0.0":         0,
		"0.0.0.0:нетпорт": 0,
	}
	for addr, want := range cases {
		if got := awgmPortOf(addr); got != want {
			t.Errorf("awgmPortOf(%q) = %d, ожидали %d", addr, got, want)
		}
	}
}

// Дескриптор ждут ОБЕ половины сервера, и приходит он после старта процесса:
// менеджер шлёт attach-tun уже на работающем сокете. Без ожидания старт
// проигрывал бы гонку собственному менеджеру.
func TestAwgmTunSlotWaitsForAttach(t *testing.T) {
	slots := &awgmTunSlots{
		files:   make(map[string]*os.File),
		waiters: make(map[string]chan struct{}),
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	done := make(chan *os.File, 1)
	go func() { done <- slots.take("opkgtun1", 5*time.Second) }()

	time.Sleep(50 * time.Millisecond) // ожидающий уже встал в очередь
	if err := slots.attach("opkgtun1", r); err != nil {
		t.Fatalf("attach: %v", err)
	}

	select {
	case got := <-done:
		if got != r {
			t.Fatalf("ожидающий получил не тот дескриптор: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ожидающий не разбужен приходом дескриптора")
	}
}

// Второй attach на занятый интерфейс — отказ, а не молчаливая подмена: сервер
// уже читает из первого дескриптора.
func TestAwgmTunSlotRejectsSecondAttach(t *testing.T) {
	slots := &awgmTunSlots{
		files:   make(map[string]*os.File),
		waiters: make(map[string]chan struct{}),
	}
	r1, w1, _ := os.Pipe()
	defer r1.Close()
	defer w1.Close()
	r2, w2, _ := os.Pipe()
	defer r2.Close()
	defer w2.Close()

	if err := slots.attach("opkgtun0", r1); err != nil {
		t.Fatalf("первый attach: %v", err)
	}
	if err := slots.attach("opkgtun0", r2); err == nil {
		t.Fatal("второй attach на занятый интерфейс прошёл")
	}
}

// Таймаут ожидания — не тупик: половина поднимется по-старому, своим TUN.
func TestAwgmTunSlotTimesOut(t *testing.T) {
	slots := &awgmTunSlots{
		files:   make(map[string]*os.File),
		waiters: make(map[string]chan struct{}),
	}
	if f := slots.take("opkgtun9", 80*time.Millisecond); f != nil {
		t.Fatalf("дескриптор взялся из ниоткуда: %v", f)
	}
}

// Менеджер держит по ресурсу на интерфейс и ищет свой в списке: без Tuns
// второй ресурс читал бы состояние первого и гонял attach по кругу.
func TestAwgmTunStatesListsBothHalves(t *testing.T) {
	slots := &awgmTunSlots{
		files:   make(map[string]*os.File),
		waiters: make(map[string]chan struct{}),
	}
	if got := slots.states(); got != nil {
		t.Fatalf("до attach список не пуст: %v", got)
	}

	r0, w0, _ := os.Pipe()
	defer r0.Close()
	defer w0.Close()
	r1, w1, _ := os.Pipe()
	defer r1.Close()
	defer w1.Close()
	_ = slots.attach("opkgtun1", r1)
	_ = slots.attach("opkgtun0", r0)

	got := slots.states()
	if len(got) != 2 {
		t.Fatalf("половин в списке: %v", got)
	}
	// Порядок устойчив — иначе отпечаток наблюдения дрожал бы на ровном месте.
	if got[0].Iface != "opkgtun0" || got[1].Iface != "opkgtun1" {
		t.Fatalf("порядок: %v", got)
	}
	if !got[0].Attached || !got[1].Attached {
		t.Fatalf("прикреплённые половины не помечены: %v", got)
	}
}
