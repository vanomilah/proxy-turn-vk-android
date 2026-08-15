package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Оба теста ниже сторожат связки, которые ломаются МОЛЧА: код продолжает
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
