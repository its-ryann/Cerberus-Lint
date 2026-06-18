package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/ryakikayi/cerberus-lint/internal/aggregator"
	"github.com/ryakikayi/cerberus-lint/internal/config"
	"github.com/ryakikayi/cerberus-lint/internal/detector"
	"github.com/ryakikayi/cerberus-lint/internal/parser"
	"github.com/ryakikayi/cerberus-lint/internal/sink"
)

var (
	configPath string
	outputPath string
	verbosity  string
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "cerberus-lint",
		Short: "Security log analyzer for brute-force detection",
		Long:  "Cerberus-Lint analyzes authentication logs to detect brute-force and credential-stuffing attacks.",
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to config file")
	rootCmd.PersistentFlags().StringVar(&outputPath, "output", "stdout", "Output destination (stdout or file path)")
	rootCmd.PersistentFlags().StringVar(&verbosity, "verbosity", "info", "Log verbosity (debug, info, warn, error)")

	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newWatchCommand())
	rootCmd.AddCommand(newValidateConfigCommand())

	return rootCmd
}

func newScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <file>",
		Short: "Scan a log file for security incidents",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			return runScan(filePath)
		},
	}
}

func newWatchCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "watch <file>",
		Short: "Watch a log file for security incidents (live mode)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			return runWatch(filePath)
		},
	}
}

func newValidateConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-config <path>",
		Short: "Validate a config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			cfg, err := config.Load(path)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			fmt.Fprintf(os.Stdout, "Config is valid!\n")
			fmt.Fprintf(os.Stdout, "Log format: %s\n", cfg.LogFormat)
			fmt.Fprintf(os.Stdout, "Window: %ds\n", cfg.WindowSeconds)
			fmt.Fprintf(os.Stdout, "Rules: %d\n", len(cfg.Rules))
			return nil
		},
	}
}

func runScan(filePath string) error {
	// Load config
	var cfg *config.Config
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// Open file or stdin
	var reader *bufio.Reader
	if filePath == "-" {
		reader = bufio.NewReader(os.Stdin)
	} else {
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()
		reader = bufio.NewReader(f)
	}

	// Create parser, aggregator, detector, and sink
	p, err := getParserForFormat(cfg.LogFormat)
	if err != nil {
		return err
	}
	agg := aggregator.NewAggregator(cfg.GetWindowDuration())
	det := detector.NewDetector(cfg.GetRules())

	var s sink.Sink
	if outputPath == "stdout" {
		s = sink.NewStdoutSink()
	} else {
		s, err = sink.NewFileSink(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create file sink: %w", err)
		}
	}
	defer s.Close()
	defer agg.Stop()

	// Process lines
	scanner := bufio.NewScanner(reader)
	processed := 0
	skipped := 0
	now := time.Now()

	for scanner.Scan() {
		line := scanner.Text()
		evt, err := p.Parse(line)
		if err != nil {
			skipped++
			continue
		}
		if evt == nil {
			skipped++
			continue
		}
		processed++

		// Add to aggregator
		agg.Add(evt)

		// Check for incidents
		record := agg.Get(evt.SourceIP)
		if record != nil {
			count, usernames := agg.GetWindowStats(evt.SourceIP)
			incident := det.Check(evt.SourceIP, count, usernames, now, now, record.Events)
			if incident != nil {
				if err := s.Write(incident); err != nil {
					fmt.Fprintf(os.Stderr, "error writing incident: %v\n", err)
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Processed: %d events, Skipped: %d lines\n", processed, skipped)
	return scanner.Err()
}

func runWatch(filePath string) error {
	// Load config
	var cfg *config.Config
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// Create parser, aggregator, detector, and sink
	p, err := getParserForFormat(cfg.LogFormat)
	if err != nil {
		return err
	}
	agg := aggregator.NewAggregator(cfg.GetWindowDuration())
	det := detector.NewDetector(cfg.GetRules())

	var s sink.Sink
	if outputPath == "stdout" {
		s = sink.NewStdoutSink()
	} else {
		s, err = sink.NewFileSink(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create file sink: %w", err)
		}
	}
	defer s.Close()
	defer agg.Stop()

	// Open file for tailing
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Seek to end
	if _, err := f.Seek(0, 2); err != nil {
		return fmt.Errorf("failed to seek to end: %w", err)
	}

	// Setup signal handling
	done := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "Shutting down...")
		close(done)
	}()

	// Process lines as they come in
	scanner := bufio.NewScanner(f)
	processed := 0
	skipped := 0
	now := time.Now()

	for {
		select {
		case <-done:
			fmt.Fprintf(os.Stderr, "Processed: %d events, Skipped: %d lines\n", processed, skipped)
			return nil
		default:
			if scanner.Scan() {
				line := scanner.Text()
				evt, err := p.Parse(line)
				if err != nil {
					skipped++
					continue
				}
				if evt == nil {
					skipped++
					continue
				}
				processed++

				// Add to aggregator
				agg.Add(evt)

				// Check for incidents
				record := agg.Get(evt.SourceIP)
				if record != nil {
					count, usernames := agg.GetWindowStats(evt.SourceIP)
					incident := det.Check(evt.SourceIP, count, usernames, now, now, record.Events)
					if incident != nil {
						if err := s.Write(incident); err != nil {
							fmt.Fprintf(os.Stderr, "error writing incident: %v\n", err)
						}
					}
				}
			} else {
				// No new data, wait a bit
				if err := scanner.Err(); err != nil {
					// File might have been rotated, try to reopen
					f.Close()
					f, err = os.Open(filePath)
					if err != nil {
						time.Sleep(1 * time.Second)
						continue
					}
					scanner = bufio.NewScanner(f)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// getParserForFormat returns the appropriate parser based on format string.
func getParserForFormat(format string) (parser.Parser, error) {
	switch parser.ParserType(strings.ToLower(format)) {
	case parser.ParserSSHD:
		return parser.NewSSHDParser(), nil
	case parser.ParserNginx:
		return parser.NewNginxParser(), nil
	case parser.ParserGeneric:
		return nil, fmt.Errorf("generic parser not implemented yet")
	default:
		return nil, fmt.Errorf("unknown log format: %s", format)
	}
}