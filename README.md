# 🐺 Cerberus-Lint

`Cerberus-Lint` is a memory-bounded, security-hardened CLI that ingests authentication/access logs, detects brute-force credential-stuffing patterns via a stateful sliding-window aggregator, and emits a versioned, machine-readable JSON event stream suitable for direct ingestion by SIEMs, firewalls, and alerting webhooks.

## Architecture

```
[Reader] → [Parser strategy] → [Normalizer] → [Aggregator] → [Detector] → [Sink(s)]
```

- **Reader** — streams lines from a file, stdin, or live tail mode
- **Parser strategy** — interface with implementations for `sshd`, `nginx`, and generic formats
- **Aggregator** — TTL-based in-memory cache for sliding-window correlation
- **Detector** — rule evaluation against configured thresholds
- **Sink** — output to stdout, file, or Slack webhook

## Installation

### From Source

```bash
go install github.com/ryakikayi/cerberus-lint/cmd/cerberus-lint@latest
```

### Docker

```bash
docker run -v /var/log:/logs ghcr.io/ryakikayi/cerberus-lint/cerberus-lint scan /logs/auth.log
```

## Quick Start

### Scan a log file

```bash
cerberus-lint scan /var/log/auth.log
```

### Scan from stdin

```bash
cat /var/log/auth.log | cerberus-lint scan -
```

### Watch a log file (live mode)

```bash
cerberus-lint watch /var/log/auth.log
```

### Validate a config file

```bash
cerberus-lint validate-config config.yaml
```

## Configuration

```yaml
log_format: sshd
window_seconds: 30

rules:
  - name: brute_force
    threshold_count: 10
    severity: high
    event_type: brute_force_login

sinks:
  - type: stdout
    enabled: true
```

## Supported Log Formats

| Format | Description |
|--------|-------------|
| `sshd` | OpenSSH authentication logs |
| `nginx` | Nginx combined access log format |
| `generic` | Generic log format (not yet implemented) |

## Output JSON Schema

```json
{
  "schema_version": "1.0",
  "incident_id": "192.168.1.100-1781785313823100625",
  "detected_at": "2026-06-18T12:21:53Z",
  "source_ip": "192.168.1.100",
  "target_usernames": ["root", "admin", "test"],
  "event_type": "brute_force_login",
  "severity": "high",
  "attempt_count": 10,
  "window_start": "2026-06-18T12:21:53Z",
  "window_end": "2026-06-18T12:21:53Z",
  "sample_raw_lines": ["Jun 12 14:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22"]
}
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `cerberus-lint scan <file>` | One-off run against a static log file |
| `cerberus-lint watch <file>` | Continuous tail-mode for live logs |
| `cerberus-lint validate-config <path>` | Validate a config file |

## Global Flags

| Flag | Description |
|------|-------------|
| `--config` | Path to config file |
| `--output` | Output destination (stdout or file path) |
| `--verbosity` | Log verbosity (debug, info, warn, error) |

## Development

### Build

```bash
go build -o cerberus-lint ./cmd/cerberus-lint
```

### Test

```bash
go test -v ./...
```

### Lint

```bash
golangci-lint run ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.
