# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure with Go modules
- SSHD parser for OpenSSH authentication logs
- Nginx parser for combined access log format
- TTL-based in-memory aggregator for sliding-window detection
- Detector with rule-based incident generation
- Stdout, file, and Slack sinks
- Cobra CLI with `scan`, `watch`, and `validate-config` commands
- Viper configuration support
- Golden file testing
- Adversarial test cases for security hardening
- Dockerfile for containerized deployment
- GitHub Actions CI workflow
- Goreleaser configuration for releases