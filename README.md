# op-encrypt-secrets

Generate SOPS-encrypted Kubernetes Secrets from literal 1Password references.

## Requirements

- Go 1.24+ to build (`go build .`).
- Trusted `op` (1Password CLI 2, supporting `read --no-newline`) and `sops`
  (supporting `--filename-override`, JSON input and YAML output) on `PATH`.
- Authenticate `op` separately using your normal CLI setup. This command does
  not sign in, create accounts, change vaults, or configure recipients.
- A `.sops.yaml` in the input/output directory or an ancestor, with a creation
  rule matching the **final** `*.secret.sops.yaml` path. The nearest config is
  used explicitly, regardless of working directory or `SOPS_CONFIG`.

SOPS handles age recipients internally; this command does not invoke `age`.
Install/configure any other key-provider dependencies required by your rules.
Dependencies and authentication are not installed or verified by building.

## Verification

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests use fake `op` processes and synthetic values only; no vault is read.
`TestRealSOPSAgeRoundtrip` uses real `sops` and `age-keygen` when available
(otherwise it explicitly skips), with an ephemeral in-memory key and isolated
config/home. It decrypts in memory and compares exact Kubernetes Secret values.
To verify an installed binary with the same black-box tests:

```sh
OE_TEST_CLI_PATH="$HOME/.local/bin/op-encrypt-secrets" go test -count=1 ./...
```

## Usage

```text
op-encrypt-secrets [FILE.env.plain | DIRECTORY]
op-encrypt-secrets --help
```

No argument means the current directory. Directory scans are immediate,
lexically ordered, and limited to `*.env.plain`; there is no recursion.
Success is silent. Failures return nonzero with sanitized diagnostics.

For `app-credentials.env.plain`:

```dotenv
# Literal references only (these are examples, not real vault locations).
USERNAME="op://example-vault/example-item/username"
PASSWORD='op://example-vault/example-item/password'
TOKEN=op://example-vault/example-item/credentials/token
```

Output: sibling `app-credentials.secret.sops.yaml`, containing a `v1` `Secret`
named `app-credentials`, `type: Opaque`, and `stringData` with the resolved keys.
**No namespace** is emitted; Kustomize supplies it.

Blank lines and full-line comments are ignored; whitespace-delimited inline
comments are accepted. Keys must match `[A-Za-z_][A-Za-z0-9_]*` and be unique.
Filename stems must be Kubernetes DNS-subdomain names. References must contain
vault/item/field or vault/item/section/field; path components use letters,
digits, spaces, `_`, `-`, or `.`. Simple reference query parameters are passed
literally to `op`, which validates their supported semantics. Unsupported
names should use the corresponding 1Password IDs.

No `export`, shell commands, escape decoding, multiline references, `$VAR`
expansion, or dotenv interpolation is supported. Empty references and files
with no assignments are errors. File contents are never executed by a shell.

## Encryption and safety

- `op read --no-newline` avoids an added CLI newline. Resolved UTF-8 strings
  are preserved exactly, including trailing newlines, empty strings, CR/LF,
  quotes, and special characters; binary/non-UTF-8 values are rejected.
- Plaintext is serialized losslessly as JSON in memory, piped into SOPS, and
  emitted as encrypted YAML. It is never written to disk or printed. Only
  references, not resolved secrets, appear in subprocess arguments.
- SOPS receives `--config` and `--filename-override` for the actual final path.
  Encryption scope comes from that configuration; the command never forces
  a replacement `encrypted_regex` or changes recipients.
- Output must retain exactly the expected Secret structure and stringData
  keys; every nonempty value must be a new SOPS encrypted string. Configs
  excluding any nonempty stringData value fail closed. **SOPS's built-in
  exception:** an originally empty string may remain exactly empty; there is
  no secret content to disclose. SOPS metadata and an encrypted MAC are required.
- External stderr is captured and suppressed, even on failure, because it can
  contain secrets. Troubleshoot CLI authentication/configuration independently;
  do not run secret-reading commands where output is logged.
- All selected inputs, names, references, destinations, and matching creation
  rules are prevalidated. All files finish encryption and ciphertext checks
  before any existing output is replaced. Validation, `op`, and SOPS failures
  leave all existing encrypted outputs untouched.
- Ciphertext alone is staged in sibling `0600` temporary files, then renamed
  atomically per file; refreshed outputs also become `0600`. Input/config and
  existing output symlinks or non-regular files are rejected. Output hardlinks
  to inputs are rejected. Renames do not follow destination symlinks.
- This is a Unix CLI using `O_NOFOLLOW`. Use trusted directories and binaries;
  it is not a sandbox against an attacker changing ancestor directories,
  configs, or executables concurrently. Publication is atomic **per file**,
  not a multi-file transaction: a late filesystem rename failure may leave
  earlier batch outputs refreshed. No deployment or Kubernetes mutation occurs.

Keep `.env.plain` files private even though they contain references rather
than resolved secrets. Process memory/pipes are not a guarantee against
privileged observers, swap, core dumps, or logging by externally configured
CLI/key-provider software.
