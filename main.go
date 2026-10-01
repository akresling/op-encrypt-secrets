package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const inputSuffix = ".env.plain"

var (
	envKey    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	dnsLabel  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	refPart   = regexp.MustCompile(`^[A-Za-z0-9_. -]+$`)
	queryPart = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	envelope  = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/]*={0,2}),iv:([A-Za-z0-9+/]+={0,2}),tag:([A-Za-z0-9+/]+={0,2}),type:str\]$`)
)

type input struct {
	path, output, name, config string
	refs                       map[string]string
	ciphertext                 []byte
}

type secret struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Type       string            `json:"type"`
	StringData map[string]string `json:"stringData"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "op-encrypt-secrets:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("op-encrypt-secrets", flag.ContinueOnError)
	// Never echo arbitrary arguments (which might contain sensitive text).
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stdout, "Usage: op-encrypt-secrets [FILE.env.plain | DIRECTORY]\nDefault: current directory; immediate *.env.plain files only.")
			return nil
		}
		return errors.New("invalid arguments; use --help")
	}
	if flags.NArg() > 1 {
		return errors.New("expected at most one input path")
	}
	path := "."
	if flags.NArg() == 1 {
		path = flags.Arg(0)
	}
	inputs, err := collectInputs(path)
	if err != nil {
		return err
	}
	op, err := exec.LookPath("op")
	if err != nil {
		return errors.New("1Password CLI (op) not found in PATH")
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		return errors.New("SOPS CLI (sops) not found in PATH")
	}
	// Finish all validation and encryption before replacing any existing output.
	for i := range inputs {
		if err := encrypt(ctx, op, sops, &inputs[i]); err != nil {
			return fmt.Errorf("input %d: %w", i+1, err)
		}
	}
	return publish(inputs)
}

func collectInputs(path string) ([]input, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("cannot locate input")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, errors.New("cannot inspect input")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input symlinks are not allowed")
	}
	var paths []string
	if info.IsDir() {
		dir, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, errors.New("cannot locate input directory")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, errors.New("cannot read input directory")
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), inputSuffix) {
				paths = append(paths, filepath.Join(dir, entry.Name()))
			}
		}
	} else {
		dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return nil, errors.New("cannot locate input directory")
		}
		paths = []string{filepath.Join(dir, filepath.Base(absolute))}
	}
	if len(paths) == 0 {
		return nil, errors.New("no immediate *.env.plain inputs found")
	}
	inputs := make([]input, 0, len(paths))
	for i, path := range paths {
		in, err := prepareInput(path)
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", i+1, err)
		}
		inputs = append(inputs, in)
	}
	return inputs, nil
}

func prepareInput(path string) (input, error) {
	in := input{path: path}
	base := filepath.Base(path)
	if !strings.HasSuffix(base, inputSuffix) {
		return in, errors.New("input filename must end in .env.plain")
	}
	in.name = strings.TrimSuffix(base, inputSuffix)
	if !validName(in.name) {
		return in, errors.New("filename stem must be a Kubernetes DNS-subdomain name (at most 253 bytes)")
	}
	in.output = filepath.Join(filepath.Dir(path), in.name+".secret.sops.yaml")
	data, err := readRegular(path)
	if err != nil {
		return in, errors.New("cannot read regular, non-symlink input file")
	}
	in.refs, err = parseDotenv(data)
	if err != nil {
		return in, err
	}
	if err := checkOutput(in); err != nil {
		return in, err
	}
	in.config, err = findConfig(filepath.Dir(in.output))
	if err != nil {
		return in, err
	}
	if err := checkCreationRule(in.config, in.output); err != nil {
		return in, err
	}
	return in, nil
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// O_NOFOLLOW also closes the lstat/open race for the final input component.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(f)
}

func parseDotenv(data []byte) (map[string]string, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("dotenv must be UTF-8")
	}
	refs := make(map[string]string)
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		lineError := func(message string) (map[string]string, error) {
			return nil, fmt.Errorf("dotenv line %d: %s", i+1, message)
		}
		if !found || !envKey.MatchString(key) {
			return lineError("invalid ENV assignment")
		}
		if _, duplicate := refs[key]; duplicate {
			return lineError("duplicate ENV key")
		}
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			quote := value[0]
			end := strings.IndexByte(value[1:], quote)
			if end < 0 {
				return lineError("unterminated reference quote")
			}
			end++
			rest := value[end+1:]
			if strings.TrimSpace(rest) != "" && !(len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') && strings.HasPrefix(strings.TrimSpace(rest), "#")) {
				return lineError("unexpected text after reference")
			}
			value = value[1:end]
		} else {
			// A whitespace-delimited # introduces an inline comment, not shell syntax.
			for j := 1; j < len(value); j++ {
				if value[j] == '#' && (value[j-1] == ' ' || value[j-1] == '\t') {
					value = strings.TrimSpace(value[:j])
					break
				}
			}
		}
		if !validReference(value) {
			return lineError("invalid or empty literal op:// reference")
		}
		refs[key] = value
	}
	if len(refs) == 0 {
		return nil, errors.New("dotenv contains no ENV references")
	}
	return refs, nil
}

func validReference(ref string) bool {
	if !strings.HasPrefix(ref, "op://") {
		return false
	}
	path, query, hasQuery := strings.Cut(strings.TrimPrefix(ref, "op://"), "?")
	parts := strings.Split(path, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || !refPart.MatchString(part) {
			return false
		}
	}
	if hasQuery {
		values, err := url.ParseQuery(query)
		if err != nil || len(values) == 0 {
			return false
		}
		for key, vals := range values {
			if !queryPart.MatchString(key) || len(vals) != 1 || !queryPart.MatchString(vals[0]) {
				return false
			}
		}
	}
	return true
}

func findConfig(dir string) (string, error) {
	for {
		path := filepath.Join(dir, ".sops.yaml")
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return "", errors.New(".sops.yaml must be a regular non-symlink file")
			}
			return path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("cannot inspect .sops.yaml")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no .sops.yaml found in input directory or its ancestors")
		}
		dir = parent
	}
}

func checkCreationRule(config, output string) error {
	data, err := readRegular(config)
	if err != nil {
		return errors.New("cannot read .sops.yaml")
	}
	var cfg struct {
		Rules []struct {
			PathRegex string `yaml:"path_regex"`
		} `yaml:"creation_rules"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return errors.New("invalid .sops.yaml creation rules")
	}
	if len(cfg.Rules) == 0 {
		return errors.New(".sops.yaml has no creation rules")
	}
	// Match exactly the config-relative final filename, as SOPS does.
	relative := strings.TrimPrefix(output, filepath.Dir(config)+string(filepath.Separator))
	for _, rule := range cfg.Rules {
		if rule.PathRegex == "" {
			return nil
		}
		re, err := regexp.Compile(rule.PathRegex)
		if err != nil {
			return errors.New("invalid creation-rule path_regex")
		}
		if re.MatchString(relative) {
			return nil
		}
	}
	return errors.New("no SOPS creation rule matches the final output path")
}

func checkOutput(in input) error {
	info, err := os.Lstat(in.output)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect output path")
	}
	if !info.Mode().IsRegular() {
		return errors.New("output must not be a symlink or non-regular file")
	}
	original, err := os.Lstat(in.path)
	if err != nil || os.SameFile(info, original) {
		return errors.New("output must not overwrite input")
	}
	return nil
}

// Child stderr is captured but never exposed: even failures can contain secrets.
func command(ctx context.Context, executable, dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New("subprocess failed (details suppressed)")
	}
	return stdout.Bytes(), nil
}

func encrypt(ctx context.Context, op, sops string, in *input) error {
	doc := secret{APIVersion: "v1", Kind: "Secret", Type: "Opaque", StringData: make(map[string]string)}
	doc.Metadata.Name = in.name
	keys := make([]string, 0, len(in.refs))
	for key := range in.refs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, err := command(ctx, op, filepath.Dir(in.path), nil, "read", "--no-newline", in.refs[key])
		if err != nil {
			return errors.New("op read failed; check CLI authentication and reference access independently (details suppressed)")
		}
		if !utf8.Valid(value) {
			return errors.New("op returned non-UTF-8 bytes; Kubernetes stringData requires text")
		}
		doc.StringData[key] = string(value)
	}
	// JSON is safe, lossless serialization of strings (including CR/LF and NUL).
	// SOPS accepts it on stdin and emits the final YAML format.
	plain, err := json.Marshal(doc)
	if err != nil {
		return errors.New("cannot serialize Secret")
	}
	ciphertext, err := command(ctx, sops, filepath.Dir(in.output), plain,
		"--config", in.config, "--encrypt", "--input-type", "json", "--output-type", "yaml", "--filename-override", in.output, "/dev/stdin")
	if err != nil {
		return errors.New("SOPS encryption failed; check config, recipients and CLI independently (details suppressed)")
	}
	if err := validateCiphertext(ciphertext, doc); err != nil {
		return err
	}
	in.ciphertext = ciphertext
	return nil
}

func encryptedString(value string) bool {
	parts := envelope.FindStringSubmatch(value)
	if parts == nil {
		return false
	}
	for i, size := range []int{-1, 32, 16} {
		decoded, err := base64.StdEncoding.DecodeString(parts[i+1])
		if err != nil || (size < 0 && len(decoded) == 0) || (size >= 0 && len(decoded) != size) {
			return false
		}
	}
	return true
}

// Decode to nodes, not strings: reject duplicate keys, aliases and coercion.
func mapping(node *yaml.Node) (map[string]*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" || node.Anchor != "" {
		return nil, errors.New("invalid ciphertext structure")
	}
	result := make(map[string]*yaml.Node)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
			return nil, errors.New("invalid ciphertext key")
		}
		if _, exists := result[key.Value]; exists {
			return nil, errors.New("duplicate ciphertext key")
		}
		result[key.Value] = node.Content[i+1]
	}
	return result, nil
}

func stringValue(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Anchor != "" {
		return "", false
	}
	return node.Value, true
}

func validateCiphertext(data []byte, original secret) error {
	invalid := errors.New("SOPS output failed encryption/structure checks; no output written")
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc, extra yaml.Node
	if decoder.Decode(&doc) != nil || decoder.Decode(&extra) != io.EOF || len(doc.Content) != 1 {
		return invalid
	}
	root, err := mapping(doc.Content[0])
	if err != nil || len(root) != 6 {
		return invalid
	}
	for key, expected := range map[string]string{"apiVersion": original.APIVersion, "kind": original.Kind, "type": original.Type} {
		value, ok := stringValue(root[key])
		if !ok || (value != expected && !encryptedString(value)) {
			return invalid
		}
	}
	metadata, err := mapping(root["metadata"])
	if err != nil || len(metadata) != 1 {
		return invalid
	}
	name, ok := stringValue(metadata["name"])
	if !ok || (name != original.Metadata.Name && !encryptedString(name)) {
		return invalid
	}
	values, err := mapping(root["stringData"])
	if err != nil || len(values) != len(original.StringData) {
		return invalid
	}
	for key, plain := range original.StringData {
		value, ok := stringValue(values[key])
		if !ok {
			return invalid
		}
		// SOPS intentionally leaves empty strings empty. No nonempty exemption.
		if plain == "" && value == "" {
			continue
		}
		if value == plain || !encryptedString(value) {
			return invalid
		}
	}
	sops, err := mapping(root["sops"])
	if err != nil {
		return invalid
	}
	mac, ok := stringValue(sops["mac"])
	if !ok || !encryptedString(mac) {
		return invalid
	}
	return nil
}

func publish(inputs []input) error {
	temps := make([]string, len(inputs))
	defer func() {
		for _, path := range temps {
			if path != "" {
				_ = os.Remove(path)
			}
		}
	}()
	for i, in := range inputs {
		f, err := os.CreateTemp(filepath.Dir(in.output), ".op-encrypt-secrets-*")
		if err != nil {
			return errors.New("cannot create ciphertext temporary file")
		}
		temps[i] = f.Name()
		// CreateTemp uses 0600, including when refreshing a more permissive output.
		_, writeErr := f.Write(in.ciphertext)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("cannot write ciphertext temporary file")
		}
	}
	// Recheck all destinations before committing any ciphertext. Rename replaces
	// the directory entry atomically and never follows a destination symlink.
	for _, in := range inputs {
		if err := checkOutput(in); err != nil {
			return err
		}
	}
	for i, in := range inputs {
		if err := os.Rename(temps[i], in.output); err != nil {
			return errors.New("cannot atomically replace ciphertext output (earlier batch outputs may have completed)")
		}
		temps[i] = ""
	}
	return nil
}
