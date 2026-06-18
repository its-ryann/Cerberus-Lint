# Contributing to Cerberus-Lint

Thank you for your interest in contributing to Cerberus-Lint! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork and clone the repository
2. Install Go 1.22+
3. Install development tools:
   ```bash
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   go install github.com/goreleaser/goreleaser@latest
   ```

## Running Tests

```bash
go test -v ./...
```

## Code Style

- Follow standard Go conventions
- Run `golangci-lint` before submitting PRs
- Write table-driven tests
- Add adversarial test cases for security-sensitive code

## Adding a New Parser

1. Create a new file in `internal/parser/` (e.g., `apache.go`)
2. Implement the `Parser` interface
3. Add the parser type to `parser.go`
4. Update `getParserForFormat()` in `main.go`
5. Add tests in `internal/parser/`

## Adding a New Sink

1. Create a new file in `internal/sink/` (e.g., `syslog.go`)
2. Implement the `Sink` interface
3. Add the sink type to `sink.go`
4. Add tests in `internal/sink/`

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Add your changes to CHANGELOG.md
4. Submit PR with clear description of changes