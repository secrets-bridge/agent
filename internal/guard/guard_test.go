// Package guard holds source-level guards for the agent's runtime
// invariants (skills#116). They parse every non-test Go file in the
// module, so a change anywhere that breaks an invariant fails CI.
//
//   - The runtime never opens a file for writing: only the CLI bundle
//     output (internal/cli/output.go) may create, write or remove a file.
//   - The runtime never generates a key: only internal/cli/keygen.go (and
//     the test-only sealtest package) may call GenerateKey.
//   - Runtime packages never import the CLI, and only tests import
//     sealtest.
//   - The removed enrollment and key-registration surface stays removed.
package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/secrets-bridge/agent"

// writeAllowed may write files: the operator's bundle output.
var writeAllowed = map[string]bool{"internal/cli/output.go": true}

// keygenAllowed may call GenerateKey.
var keygenAllowed = map[string]bool{
	"internal/cli/keygen.go":                true,
	"internal/sealing/sealtest/sealtest.go": true,
}

// forbiddenCalls lists, per import path, the functions that create,
// modify or delete a file. os.OpenFile is refused outright: os.Open is the
// read-only way to open a file, so no write-capable *os.File can exist
// outside writeAllowed.
var forbiddenCalls = map[string]map[string]bool{
	"os": set("WriteFile", "Create", "CreateTemp", "OpenFile", "Mkdir", "MkdirAll", "MkdirTemp",
		"Rename", "Remove", "RemoveAll", "Link", "Symlink", "Chmod", "Chown", "Lchown", "Truncate", "Chtimes",
		"NewFile", "OpenInRoot", "OpenRoot", "CopyFS"),
	"io/ioutil": set("WriteFile", "TempFile", "TempDir"),
	"syscall": set("Open", "Openat", "Creat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Unlink", "Unlinkat",
		"Chmod", "Fchmod", "Fchmodat", "Link", "Symlink", "Truncate", "Ftruncate", "Write", "Pwrite"),
	"golang.org/x/sys/unix": set("Open", "Openat", "Openat2", "Creat", "Mkdir", "Mkdirat", "Rename", "Renameat",
		"Unlink", "Unlinkat", "Chmod", "Fchmod", "Fchmodat", "Link", "Symlink", "Truncate", "Ftruncate", "Write", "Pwrite"),
}

// removedSurface must not appear in non-test code.
var removedSurface = []string{
	"SB_ENROLLMENT_ENABLED", "SB_ENROLLMENT_TOKEN", "SB_IDENTITY_FILE",
	"SB_AGENT_PRIVATE_KEY", "SB_AGENT_ID", "SB_AGENT_SECRET",
	"/public-key", "SetPublicKey", "identity.json", "ephemeral keypair",
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

type source struct {
	rel  string
	file *ast.File
	text string
}

// sources parses every non-test .go file of the module.
func sources(t *testing.T) []source {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s", root)
	}
	var out []source
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, data, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, source{rel: filepath.ToSlash(rel), file: f, text: string(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 20 {
		t.Fatalf("parsed only %d files; the guard is not seeing the module", len(out))
	}
	return out
}

// imports maps each local import name in f to its path.
func imports(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		m[name] = path
	}
	return m
}

// calls reports every pkg.Func selector in f, resolved to its import path.
func calls(f *ast.File, visit func(path, name string, pos token.Pos)) {
	imps := imports(f)
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if path, ok := imps[id.Name]; ok {
				visit(path, sel.Sel.Name, sel.Pos())
			}
		}
		return true
	})
}

func TestGuard_RuntimeNeverWritesFiles(t *testing.T) {
	for _, s := range sources(t) {
		if writeAllowed[s.rel] {
			continue
		}
		calls(s.file, func(path, name string, _ token.Pos) {
			if forbiddenCalls[path][name] {
				t.Errorf("%s: %s.%s can write the filesystem; only %v may", s.rel, path, name, keys(writeAllowed))
			}
		})
	}
}

func TestGuard_RuntimeNeverGeneratesKeys(t *testing.T) {
	for _, s := range sources(t) {
		if keygenAllowed[s.rel] {
			continue
		}
		ast.Inspect(s.file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "GenerateKey" || sel.Sel.Name == "GenerateKeypair") {
				t.Errorf("%s: calls %s; only %v may generate a key", s.rel, sel.Sel.Name, keys(keygenAllowed))
			}
			return true
		})
	}
}

func TestGuard_ImportBoundaries(t *testing.T) {
	for _, s := range sources(t) {
		for _, path := range imports(s.file) {
			if path == module+"/internal/sealing/sealtest" {
				t.Errorf("%s imports sealtest, which is for tests only", s.rel)
			}
			if path == module+"/internal/cli" && !strings.HasPrefix(s.rel, "cmd/agent/") {
				t.Errorf("%s imports internal/cli; only the binary's dispatch may", s.rel)
			}
		}
	}
}

func TestGuard_RemovedSurfaceStaysRemoved(t *testing.T) {
	for _, s := range sources(t) {
		for _, word := range removedSurface {
			if strings.Contains(s.text, word) {
				t.Errorf("%s mentions %q, which the stateless enrollment removed", s.rel, word)
			}
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
