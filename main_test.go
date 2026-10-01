package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"
)

// These processes never read a vault. Values are synthetic and passed via the
// test environment; only invocation metadata (never stdin/values) is recorded.
func TestMain(m *testing.M) {
	if os.Getenv("OE_TEST_HELPER") == "1" {
		os.Exit(fakeCLI())
	}
	os.Exit(m.Run())
}

const synthetic = "SYNTHETIC-DO-NOT-LOG-42"

func testEnvelope(data string) string {
	return "ENC[AES256_GCM,data:" + base64.StdEncoding.EncodeToString([]byte(data)) + ",iv:" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + ",tag:" + base64.StdEncoding.EncodeToString(make([]byte, 16)) + ",type:str]"
}

func fakeCLI() int {
	role := filepath.Base(os.Args[0])
	cwd, _ := os.Getwd()
	entries, _ := filepath.Glob(filepath.Join(cwd, ".op-encrypt-secrets-*"))
	if len(entries) != 0 {
		return 91
	} // No staging, especially plaintext, during resolution/encryption.
	args := os.Args[1:]
	for _, arg := range args {
		if strings.Contains(arg, synthetic) {
			return 92
		}
	}
	if trace := os.Getenv("OE_TRACE"); trace != "" {
		f, err := os.OpenFile(trace, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return 93
		}
		_ = json.NewEncoder(f).Encode(map[string]any{"role": role, "args": args, "cwd": cwd})
		_ = f.Close()
	}
	if role == "op" {
		if len(args) != 3 || args[0] != "read" || args[1] != "--no-newline" {
			return 94
		}
		if strings.HasSuffix(args[2], os.Getenv("OE_OP_FAIL")) && os.Getenv("OE_OP_FAIL") != "" {
			fmt.Fprint(os.Stderr, synthetic+" "+args[2])
			fmt.Fprint(os.Stdout, synthetic)
			return 2
		}
		if os.Getenv("OE_INVALID_UTF8") == "1" {
			_, _ = os.Stdout.Write([]byte{0xff})
			return 0
		}
		var values map[string]string
		if json.Unmarshal([]byte(os.Getenv("OE_VALUES")), &values) != nil {
			return 95
		}
		value, ok := values[args[2]]
		if !ok {
			return 96
		}
		fmt.Fprint(os.Stdout, value)
		return 0
	}
	if role != "sops" {
		return 97
	}
	expected := []string{"--config", os.Getenv("OE_CONFIG"), "--encrypt", "--input-type", "json", "--output-type", "yaml", "--filename-override", filepath.Join(cwd, os.Getenv("OE_NAME")+".secret.sops.yaml"), "/dev/stdin"}
	// Batch tests have multiple names; filename must still be the actual final sibling.
	if os.Getenv("OE_NAME") == "" && len(args) == 10 {
		expected[8] = args[8]
	}
	if !reflect.DeepEqual(args, expected) || !strings.HasSuffix(args[8], ".secret.sops.yaml") {
		return 98
	}
	plain, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 99
	}
	if os.Getenv("OE_SOPS_FAIL") == "1" || strings.HasSuffix(args[8], os.Getenv("OE_SOPS_FAIL_OUTPUT")) && os.Getenv("OE_SOPS_FAIL_OUTPUT") != "" {
		_, _ = os.Stderr.Write(plain)
		fmt.Fprint(os.Stdout, synthetic)
		return 3
	}
	var doc map[string]any
	if json.Unmarshal(plain, &doc) != nil {
		return 100
	}
	values, ok := doc["stringData"].(map[string]any)
	if !ok {
		return 101
	}
	if want := os.Getenv("OE_EXPECT_VALUES"); want != "" {
		var expectedValues map[string]any
		_ = json.Unmarshal([]byte(want), &expectedValues)
		if !reflect.DeepEqual(values, expectedValues) {
			return 102
		}
	}
	for key, value := range values {
		if value != "" {
			values[key] = testEnvelope("new-ciphertext-" + key)
		}
	}
	doc["sops"] = map[string]any{"mac": testEnvelope("synthetic-mac")}
	if os.Getenv("OE_PASSTHROUGH") == "1" {
		_, _ = os.Stdout.Write(plain)
		return 0
	}
	data, _ := yaml.Marshal(doc)
	_, _ = os.Stdout.Write(data)
	return 0
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func fakeTools(t *testing.T, values map[string]string, realSOPS bool) string {
	t.Helper()
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(executable, filepath.Join(dir, "op")); err != nil {
		t.Fatal(err)
	}
	if !realSOPS {
		if err = os.Symlink(executable, filepath.Join(dir, "sops")); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(values)
	t.Setenv("OE_VALUES", string(data))
	t.Setenv("OE_TEST_HELPER", "1")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func fixture(t *testing.T, name, contents string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, ".sops.yaml")
	writeTestFile(t, config, "creation_rules:\n  - path_regex: '\\.secret\\.sops\\.yaml$'\n    encrypted_regex: '^(stringData)$'\n    age: age1synthetic\n")
	writeTestFile(t, filepath.Join(dir, name+inputSuffix), contents)
	t.Setenv("OE_CONFIG", config)
	t.Setenv("OE_NAME", name)
	return dir, filepath.Join(dir, name+".secret.sops.yaml")
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, ".op-encrypt-secrets-*"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("temporary files remain: %v %v", paths, err)
	}
}

func TestParseDotenv(t *testing.T) {
	good := []string{
		"# comment\n\n A = \"op://vault/item/field\" # inline\nB='op://vault/item/section/field'\t# inline\nC=op://vault/item/field # unquoted\n",
		"A=op://My Vault/My Item/field\r\nB=op://v/i/f?attribute=otp\n",
	}
	for _, data := range good {
		refs, err := parseDotenv([]byte(data))
		if err != nil || len(refs) == 0 {
			t.Fatalf("valid literal rejected: %v", err)
		}
	}
	refs, err := parseDotenv([]byte(good[0]))
	want := map[string]string{"A": "op://vault/item/field", "B": "op://vault/item/section/field", "C": "op://vault/item/field"}
	if err != nil || !reflect.DeepEqual(refs, want) {
		t.Fatalf("literal parsing: %v %v", refs, err)
	}
	bad := []string{"", "# only comments\n", "A=op://v/i/f\nA=op://v/i/g", "NO_EQUALS", "1A=op://v/i/f", "export A=op://v/i/f", "A=", "A=\"\"", "A='op://v/i/f", "A=\"op://v/i/f\"junk", "A=\"op://v/i/f\"#comment", "A=$(touch /tmp/not-executed)", "A=$OTHER", "A=op://v/i", "A=op://v/i/f/extra/extra", "A=op://v//f", "A=op://v/i/ ", "A=https://v/i/f", "A=op://v/i/f;echo unsafe", "A=op://v/i/f#comment", "A=\"op://v/i/f\\n\"", "A=op://v/i/f?attribute=otp&attribute=otp", "A=op://v/i/f?", "A=op://v/i/f?x=%ZZ", "A=op://v/i/f?x=$(id)", string([]byte{'A', '=', 0xff})}
	for i, data := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := parseDotenv([]byte(data)); err == nil {
				t.Fatal("invalid dotenv accepted")
			}
		})
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"app", "app-1", "a.b", strings.Repeat("a", 63), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)} {
		if !validName(name) {
			t.Fatalf("valid name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "App", "-app", "app-", "a..b", "a_1", "é", strings.Repeat("a", 64), strings.Repeat("a", 254)} {
		if validName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}

func TestEncryptExactValuesAndInvocation(t *testing.T) {
	values := map[string]string{"op://v/i/quotes": "\"quoted\" 'apostrophe' \\ $() # : true", "op://v/i/unicode": "Привет 世界 🎉", "op://v/i/newlines": "first\nsecond\n\n", "op://v/i/crlf": "a\r\nb\r\n", "op://v/i/empty": "", "op://v/i/nul": "zero\x00byte"}
	tools := fakeTools(t, values, false)
	tracePath := filepath.Join(tools, "invocations.jsonl")
	t.Setenv("OE_TRACE", tracePath)
	dir, output := fixture(t, "app", "QUOTES=op://v/i/quotes\nUNICODE=op://v/i/unicode\nNEWLINES=op://v/i/newlines\nCRLF=op://v/i/crlf\nEMPTY=op://v/i/empty\nNUL=op://v/i/nul\n")
	expected := map[string]string{"QUOTES": values["op://v/i/quotes"], "UNICODE": values["op://v/i/unicode"], "NEWLINES": values["op://v/i/newlines"], "CRLF": values["op://v/i/crlf"], "EMPTY": "", "NUL": values["op://v/i/nul"]}
	data, _ := json.Marshal(expected)
	t.Setenv("OE_EXPECT_VALUES", string(data))
	writeTestFile(t, output, "old ciphertext")
	if err := os.Chmod(output, 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{dir}); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal(actual, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 6 || doc["kind"] != "Secret" || doc["apiVersion"] != "v1" || doc["type"] != "Opaque" {
		t.Fatal("not an encrypted Kubernetes Secret")
	}
	metadata := doc["metadata"].(map[string]any)
	if !reflect.DeepEqual(metadata, map[string]any{"name": "app"}) {
		t.Fatal("unexpected metadata or namespace")
	}
	if doc["stringData"].(map[string]any)["EMPTY"] != "" {
		t.Fatal("empty value changed")
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %o", info.Mode().Perm())
	}
	for _, plain := range expected {
		if plain != "" && bytes.Contains(actual, []byte(plain)) {
			t.Fatal("plaintext in output")
		}
	}
	assertNoTemps(t, dir)
	trace, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(trace), []byte("\n"))
	if len(lines) != len(expected)+1 {
		t.Fatal("wrong number of resolver/encryptor invocations")
	}
	for i, line := range lines {
		var event struct {
			Role string   `json:"role"`
			Args []string `json:"args"`
			CWD  string   `json:"cwd"`
		}
		if json.Unmarshal(line, &event) != nil || event.CWD != dir {
			t.Fatal("subprocess invoked outside target directory")
		}
		if i < len(expected) {
			if event.Role != "op" || len(event.Args) != 3 || event.Args[0] != "read" || event.Args[1] != "--no-newline" {
				t.Fatal("resolver command differs from literal no-newline contract")
			}
			if _, ok := values[event.Args[2]]; !ok {
				t.Fatal("resolver argv is not a literal input reference")
			}
		} else if event.Role != "sops" {
			t.Fatal("encryption did not follow all resolution")
		}
	}
}

func TestDirectoryDiscoveryAndDefaultCWD(t *testing.T) {
	fakeTools(t, map[string]string{"op://v/i/f": synthetic}, false)
	dir, a := fixture(t, "a", "KEY=op://v/i/f\n")
	writeTestFile(t, filepath.Join(dir, "b.env.plain"), "KEY=op://v/i/f\n")
	writeTestFile(t, filepath.Join(dir, "ignored.env"), "not dotenv")
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(nested, "invalid.env.plain"), "bad")
	t.Setenv("OE_NAME", "")
	inputs, err := collectInputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || inputs[0].name != "a" || inputs[1].name != "b" {
		t.Fatal("directory ordering/naming")
	}
	t.Chdir(dir)
	if err := run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a, filepath.Join(dir, "b.secret.sops.yaml")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(nested, "invalid.secret.sops.yaml")); !os.IsNotExist(err) {
		t.Fatal("recursed into subdirectory")
	}
	assertNoTemps(t, dir)
}

func TestConfigUsesFinalPathOutsideCWD(t *testing.T) {
	fakeTools(t, map[string]string{"op://v/i/f": synthetic}, false)
	root := t.TempDir()
	dir := filepath.Join(root, "nested")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, ".sops.yaml")
	writeTestFile(t, config, "creation_rules:\n  - path_regex: '^nested/app\\.secret\\.sops\\.yaml$'\n    age: age1synthetic\n")
	path := filepath.Join(dir, "app.env.plain")
	writeTestFile(t, path, "KEY=op://v/i/f")
	other := t.TempDir()
	writeTestFile(t, filepath.Join(other, ".sops.yaml"), "creation_rules: []")
	t.Chdir(other)
	t.Setenv("SOPS_CONFIG", filepath.Join(other, ".sops.yaml"))
	t.Setenv("OE_CONFIG", config)
	t.Setenv("OE_NAME", "app")
	if err := run(context.Background(), []string{path}); err != nil {
		t.Fatal(err)
	}
	in, err := prepareInput(path)
	if err != nil || in.config != config {
		t.Fatal("wrong ancestor configuration")
	}
	// The nearest config is authoritative even if its rule matches only the input.
	nearest := filepath.Join(dir, ".sops.yaml")
	writeTestFile(t, nearest, "creation_rules:\n  - path_regex: '\\.env\\.plain$'\n")
	if _, err := collectInputs(path); err == nil {
		t.Fatal("input-path rule or farther config used")
	}
	writeTestFile(t, nearest, "creation_rules:\n  - path_regex: '['\n")
	if _, err := collectInputs(path); err == nil {
		t.Fatal("invalid regexp accepted")
	}
}

func TestFailuresPreserveWholeBatchAndSanitize(t *testing.T) {
	for _, mode := range []string{"op", "sops", "passthrough", "utf8", "invalid-input", "invalid-name"} {
		t.Run(mode, func(t *testing.T) {
			fakeTools(t, map[string]string{"op://v/i/first": synthetic, "op://v/i/second": synthetic}, false)
			dir, a := fixture(t, "a", "KEY=op://v/i/first")
			b := filepath.Join(dir, "b.secret.sops.yaml")
			writeTestFile(t, filepath.Join(dir, "b.env.plain"), "KEY=op://v/i/second")
			writeTestFile(t, a, "original-a")
			writeTestFile(t, b, "original-b")
			t.Setenv("OE_NAME", "")
			switch mode {
			case "op":
				t.Setenv("OE_OP_FAIL", "/second")
			case "sops":
				t.Setenv("OE_SOPS_FAIL_OUTPUT", "b.secret.sops.yaml")
			case "passthrough":
				t.Setenv("OE_PASSTHROUGH", "1")
			case "utf8":
				t.Setenv("OE_INVALID_UTF8", "1")
			case "invalid-input":
				writeTestFile(t, filepath.Join(dir, "b.env.plain"), "KEY=op://v/i/second\nKEY=op://v/i/second")
			case "invalid-name":
				writeTestFile(t, filepath.Join(dir, "INVALID.env.plain"), "KEY=op://v/i/second")
			}
			err := run(context.Background(), []string{dir})
			if err == nil {
				t.Fatal("failure accepted")
			}
			if strings.Contains(err.Error(), synthetic) || strings.Contains(err.Error(), "op://") || strings.Contains(err.Error(), dir) {
				t.Fatal("sensitive diagnostic exposed")
			}
			for path, want := range map[string]string{a: "original-a", b: "original-b"} {
				got, e := os.ReadFile(path)
				if e != nil || string(got) != want {
					t.Fatal("existing batch output changed")
				}
			}
			assertNoTemps(t, dir)
		})
	}
}

func TestSymlinkAndHardlinkSafety(t *testing.T) {
	for _, which := range []string{"input", "directory", "output", "config", "hardlink", "fifo"} {
		t.Run(which, func(t *testing.T) {
			dir, output := fixture(t, "app", "KEY=op://v/i/f")
			path := filepath.Join(dir, "app.env.plain")
			victim := filepath.Join(t.TempDir(), "victim")
			writeTestFile(t, victim, "untouched")
			target := dir
			switch which {
			case "input":
				_ = os.Remove(path)
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				target = filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(dir, target); err != nil {
					t.Fatal(err)
				}
			case "output":
				if err := os.Symlink(victim, output); err != nil {
					t.Fatal(err)
				}
			case "config":
				config := filepath.Join(dir, ".sops.yaml")
				_ = os.Remove(config)
				if err := os.Symlink(victim, config); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, output); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(output, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := collectInputs(target); err == nil {
				t.Fatal("unsafe path accepted")
			}
			got, _ := os.ReadFile(victim)
			if string(got) != "untouched" {
				t.Fatal("symlink target changed")
			}
			assertNoTemps(t, dir)
		})
	}
}

func TestCiphertextValidationRejectsMutations(t *testing.T) {
	original := secret{APIVersion: "v1", Kind: "Secret", Type: "Opaque", StringData: map[string]string{"KEY": synthetic, "EMPTY": ""}}
	original.Metadata.Name = "app"
	valid := map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": map[string]any{"name": "app"}, "stringData": map[string]any{"KEY": testEnvelope("encrypted"), "EMPTY": ""}, "sops": map[string]any{"mac": testEnvelope("mac")}}
	encoded, _ := yaml.Marshal(valid)
	if err := validateCiphertext(encoded, original); err != nil {
		t.Fatal("independent valid envelope rejected", err)
	}
	mutations := map[string]func(map[string]any){
		"plaintext":              func(d map[string]any) { d["stringData"].(map[string]any)["KEY"] = synthetic },
		"plaintext-empty-source": func(d map[string]any) { d["stringData"].(map[string]any)["EMPTY"] = "leak" },
		"nonempty-to-empty":      func(d map[string]any) { d["stringData"].(map[string]any)["KEY"] = "" },
		"missing":                func(d map[string]any) { delete(d["stringData"].(map[string]any), "KEY") },
		"extra":                  func(d map[string]any) { d["stringData"].(map[string]any)["EXTRA"] = testEnvelope("x") },
		"renamed-key":            func(d map[string]any) { v := d["stringData"].(map[string]any); v["OTHER"] = v["KEY"]; delete(v, "KEY") },
		"non-string":             func(d map[string]any) { d["stringData"].(map[string]any)["KEY"] = 42 },
		"wrong-name":             func(d map[string]any) { d["metadata"].(map[string]any)["name"] = "other" },
		"namespace":              func(d map[string]any) { d["metadata"].(map[string]any)["namespace"] = "forbidden" },
		"wrong-kind":             func(d map[string]any) { d["kind"] = "ConfigMap" },
		"no-mac":                 func(d map[string]any) { d["sops"] = map[string]any{} },
		"plaintext-mac":          func(d map[string]any) { d["sops"].(map[string]any)["mac"] = "not encrypted" },
		"bad-envelope": func(d map[string]any) {
			d["stringData"].(map[string]any)["KEY"] = "ENC[AES256_GCM,data:YQ==,iv:YQ==,tag:YQ==,type:str]"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			_ = yaml.Unmarshal(encoded, &doc)
			mutate(doc)
			data, _ := yaml.Marshal(doc)
			if validateCiphertext(data, original) == nil {
				t.Fatal("unsafe ciphertext accepted")
			}
		})
	}
	for name, data := range map[string][]byte{
		"duplicate-root":  append(append([]byte{}, encoded...), []byte("kind: Secret\n")...),
		"duplicate-value": []byte(strings.Replace(string(encoded), "stringData:\n", "stringData:\n    KEY: ignored\n", 1)),
		"alias":           []byte(strings.Replace(string(encoded), "name: app", "name: &n app\n    namespace: *n", 1)),
		"anchored-value":  []byte(strings.Replace(string(encoded), "KEY: ENC", "KEY: &n ENC", 1)),
		"extra-document":  append(append([]byte{}, encoded...), []byte("---\nkind: Secret\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if validateCiphertext(data, original) == nil {
				t.Fatal("unsafe YAML accepted")
			}
		})
	}
	// An already envelope-shaped vault value must not be mistaken for encryption.
	original.StringData["KEY"] = valid["stringData"].(map[string]any)["KEY"].(string)
	if validateCiphertext(encoded, original) == nil {
		t.Fatal("unchanged envelope-shaped plaintext accepted")
	}
}

func TestPublishRechecksAllOutputsAndCleansCiphertextTemps(t *testing.T) {
	dir, a := fixture(t, "a", "KEY=op://v/i/f")
	bpath := filepath.Join(dir, "b.env.plain")
	writeTestFile(t, bpath, "KEY=op://v/i/f")
	inputs, err := collectInputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, a, "original")
	for i := range inputs {
		inputs[i].ciphertext = []byte("synthetic ciphertext only")
	}
	victim := filepath.Join(t.TempDir(), "victim")
	writeTestFile(t, victim, "untouched")
	if err = os.Symlink(victim, inputs[1].output); err != nil {
		t.Fatal(err)
	}
	if publish(inputs) == nil {
		t.Fatal("late unsafe output accepted")
	}
	got, _ := os.ReadFile(a)
	if string(got) != "original" {
		t.Fatal("early output changed")
	}
	got, _ = os.ReadFile(victim)
	if string(got) != "untouched" {
		t.Fatal("symlink target changed")
	}
	assertNoTemps(t, dir)
	// Failure while creating a later staging file also preserves all outputs.
	_ = os.Remove(inputs[1].output)
	inputs[1].output = filepath.Join(dir, "missing-parent", "b.secret.sops.yaml")
	if publish(inputs) == nil {
		t.Fatal("filesystem error accepted")
	}
	got, _ = os.ReadFile(a)
	if string(got) != "original" {
		t.Fatal("early output changed")
	}
	assertNoTemps(t, dir)
}

func TestMissingConfigAndArguments(t *testing.T) {
	if err := run(context.Background(), []string{"--bad=" + synthetic}); err == nil || strings.Contains(err.Error(), synthetic) {
		t.Fatal("invalid flag error unsafe")
	}
	if err := run(context.Background(), []string{"one", "two"}); err == nil {
		t.Fatal("extra args accepted")
	}
	if _, err := collectInputs(t.TempDir()); err == nil {
		t.Fatal("empty directory accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "app.env.plain")
	writeTestFile(t, path, "KEY=op://v/i/f")
	if _, err := collectInputs(path); err == nil {
		t.Fatal("missing config accepted")
	}
	writeTestFile(t, filepath.Join(dir, ".sops.yaml"), "creation_rules: []")
	if _, err := collectInputs(path); err == nil {
		t.Fatal("empty rules accepted")
	}
}

// Real cryptographic integration is intentionally explicit in test logs: without
// SOPS/age-keygen, unit tests remain portable but do not claim this proof.
func TestRealSOPSAgeRoundtrip(t *testing.T) {
	sops, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("real SOPS not installed")
	}
	keygen, err := exec.LookPath("age-keygen")
	if err != nil {
		t.Skip("real age-keygen not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	for _, key := range []string{"SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY_CMD", "SOPS_AGE_SSH_PRIVATE_KEY_FILE", "SOPS_AGE_SSH_PRIVATE_KEY_CMD", "SOPS_AGE_RECIPIENTS", "SOPS_KMS_ARN", "SOPS_PGP_FP", "SOPS_GCP_KMS_IDS", "SOPS_AZURE_KEYVAULT_URLS", "SOPS_KEYSERVICE", "SOPS_DECRYPTION_ORDER"} {
		// Register restoration, then really unset: empty *_CMD is still a
		// configured command to SOPS, not an absent command.
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	// The ephemeral private key is only in memory/environment, never a file/log.
	cmd := exec.Command(keygen)
	var key, stderr bytes.Buffer
	cmd.Stdout = &key
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		t.Fatal("ephemeral key generation failed")
	}
	t.Setenv("SOPS_AGE_KEY", key.String())
	recipientCmd := exec.Command(keygen, "-y")
	recipientCmd.Stdin = bytes.NewReader(key.Bytes())
	recipientCmd.Stderr = io.Discard
	recipient, err := recipientCmd.Output()
	if err != nil {
		t.Fatal("recipient derivation failed")
	}
	values := map[string]string{"op://test/item/quotes": "\"quoted\" 'single' \\ $() # :", "op://test/item/unicode": "Привет 世界 🎉", "op://test/item/newlines": "line1\nline2\n\n", "op://test/item/empty": "", "op://test/item/crlf": "a\r\nb\r\n", "op://test/item/nul": "a\x00b"}
	fakeTools(t, values, true)
	dir := filepath.Join(t.TempDir(), "inputs")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(filepath.Dir(dir), ".sops.yaml")
	writeTestFile(t, config, "creation_rules:\n  - path_regex: '^inputs/roundtrip\\.secret\\.sops\\.yaml$'\n    encrypted_regex: '^(stringData)$'\n    age: "+strings.TrimSpace(string(recipient))+"\n")
	inputPath := filepath.Join(dir, "roundtrip.env.plain")
	writeTestFile(t, inputPath, "QUOTES=op://test/item/quotes\nUNICODE=op://test/item/unicode\nNEWLINES=op://test/item/newlines\nEMPTY=op://test/item/empty\nCRLF=op://test/item/crlf\nNUL=op://test/item/nul\n")
	outside := t.TempDir()
	t.Chdir(outside)
	writeTestFile(t, filepath.Join(outside, ".sops.yaml"), "creation_rules: []")
	t.Setenv("SOPS_CONFIG", filepath.Join(outside, ".sops.yaml"))
	binary := compiledCLI(t)
	cli := exec.Command(binary, inputPath)
	cli.Dir = outside
	var cliOutput bytes.Buffer
	cli.Stdout, cli.Stderr = &cliOutput, &cliOutput
	if err = cli.Run(); err != nil {
		t.Fatal("compiled CLI real SOPS encryption failed (details suppressed)")
	}
	if cliOutput.Len() != 0 {
		t.Fatal("successful compiled command was not silent")
	}
	output := filepath.Join(dir, "roundtrip.secret.sops.yaml")
	ciphertext, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value != "" && bytes.Contains(ciphertext, []byte(value)) {
			t.Fatal("plaintext persisted")
		}
	}
	decrypt := exec.Command(sops, "--decrypt", output)
	decrypt.Dir = outside
	var decryptError bytes.Buffer
	decrypt.Stderr = &decryptError
	plaintext, err := decrypt.Output()
	if err != nil {
		// Classify known errors without printing subprocess output or key material.
		for _, category := range []string{"MAC mismatch", "Failed to get the data key", "no matching creation rules", "no creation rules", "Could not unmarshal", "Error unmarshalling", "failed to load age identities", "failed to decrypt"} {
			if strings.Contains(decryptError.String(), category) {
				t.Fatal("real SOPS decryption failed: " + category)
			}
		}
		t.Fatal("real SOPS decryption failed (details suppressed)")
	}
	var doc map[string]any
	if err = yaml.Unmarshal(plaintext, &doc); err != nil {
		t.Fatal("decrypted document is not YAML")
	}
	expected := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "roundtrip"}, "type": "Opaque", "stringData": map[string]any{"QUOTES": values["op://test/item/quotes"], "UNICODE": values["op://test/item/unicode"], "NEWLINES": values["op://test/item/newlines"], "EMPTY": "", "CRLF": values["op://test/item/crlf"], "NUL": values["op://test/item/nul"]}}
	if !reflect.DeepEqual(doc, expected) {
		t.Fatal("decrypted Secret differs from exact independent expected values/metadata")
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("output permissions not private")
	}
	assertNoTemps(t, dir)
	// A real matching rule excluding stringData must fail closed and preserve output.
	writeTestFile(t, config, "creation_rules:\n  - path_regex: '^inputs/roundtrip\\.secret\\.sops\\.yaml$'\n    encrypted_regex: '^(metadata)$'\n    age: "+strings.TrimSpace(string(recipient))+"\n")
	if run(context.Background(), []string{inputPath}) == nil {
		t.Fatal("real SOPS plaintext scope accepted")
	}
	preserved, _ := os.ReadFile(output)
	if !bytes.Equal(preserved, ciphertext) {
		t.Fatal("real SOPS scope failure changed output")
	}
	assertNoTemps(t, dir)
	t.Log("real SOPS + ephemeral age key passed; op was simulated; no real vault reads")
	t.Logf("synthetic ciphertext output: %s (test cleanup removes it)", output)
}

// OE_TEST_CLI_PATH lets the same black-box contract verify the installed binary.
func compiledCLI(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("OE_TEST_CLI_PATH"); binary != "" {
		if !filepath.IsAbs(binary) {
			t.Fatal("OE_TEST_CLI_PATH must be absolute")
		}
		return binary
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate CLI source")
	}
	binary := filepath.Join(t.TempDir(), "op-encrypt-secrets")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = filepath.Dir(source)
	build.Stdout, build.Stderr = io.Discard, io.Discard
	if err := build.Run(); err != nil {
		t.Fatal("black-box CLI build failed")
	}
	return binary
}

func TestCompiledCLIHelpSuccessAndFailures(t *testing.T) {
	binary := compiledCLI(t)
	fakeTools(t, map[string]string{"op://v/i/f": synthetic}, false)
	dir, output := fixture(t, "app", "KEY=op://v/i/f\n")
	outside := t.TempDir()
	invoke := func(args ...string) ([]byte, error) {
		cmd := exec.Command(binary, args...)
		cmd.Dir = outside
		return cmd.CombinedOutput()
	}
	help, err := invoke("--help")
	if err != nil || !strings.Contains(string(help), "Usage: op-encrypt-secrets") {
		t.Fatal("compiled --help failed")
	}
	data, err := invoke(filepath.Join(dir, "app.env.plain"))
	if err != nil || len(data) != 0 {
		t.Fatal("compiled success failed or not silent")
	}
	ciphertext, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(synthetic)) {
		t.Fatal("compiled output contains plaintext")
	}
	for _, mode := range []string{"bad-flag", "op-failure", "sops-failure"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{dir}
			switch mode {
			case "bad-flag":
				args = []string{"--invalid=" + synthetic}
			case "op-failure":
				t.Setenv("OE_OP_FAIL", "/f")
			case "sops-failure":
				t.Setenv("OE_SOPS_FAIL", "1")
			}
			outputText, err := invoke(args...)
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 {
				t.Fatal("compiled failure did not return exit 1")
			}
			if bytes.Contains(outputText, []byte(synthetic)) || bytes.Contains(outputText, []byte("op://")) || bytes.Contains(outputText, []byte(dir)) {
				t.Fatal("compiled stderr/stdout contains sensitive data")
			}
			after, _ := os.ReadFile(output)
			if !bytes.Equal(after, ciphertext) {
				t.Fatal("compiled failure replaced prior output")
			}
			assertNoTemps(t, dir)
		})
	}
}

func TestMissingRuntimeExecutables(t *testing.T) {
	dir, _ := fixture(t, "app", "KEY=op://v/i/f")
	emptyPATH := t.TempDir()
	t.Setenv("PATH", emptyPATH)
	err := run(context.Background(), []string{dir})
	if err == nil || !strings.Contains(err.Error(), "op)") {
		t.Fatal("missing op not diagnosed")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(executable, filepath.Join(emptyPATH, "op")); e != nil {
		t.Fatal(e)
	}
	err = run(context.Background(), []string{dir})
	if err == nil || !strings.Contains(err.Error(), "sops)") {
		t.Fatal("missing sops not diagnosed")
	}
}
