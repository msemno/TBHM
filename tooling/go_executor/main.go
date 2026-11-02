// TBHM optional bounded process executor for Kali/Linux.
//
// The helper receives one JSON job on stdin and executes an argv array with
// shell=false semantics. It is not a C2 component and does not interpret shell
// fragments. Scope, approval, rate limits and finding status remain controlled
// by the Python plane.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Job struct {
	Argv      []string          `json:"argv"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutMS int               `json:"timeout_ms"`
	LogPath   string            `json:"log_path"`
	Input     string            `json:"input,omitempty"`
	TailBytes int               `json:"tail_bytes,omitempty"`
	StdoutFD  int               `json:"stdout_fd,omitempty"`
	StderrFD  int               `json:"stderr_fd,omitempty"`
}

type Result struct {
	ExitCode   int    `json:"exit_code"`
	StdoutTail string `json:"stdout_tail"`
	StderrTail string `json:"stderr_tail"`
	Error      string `json:"error,omitempty"`
	TimedOut   bool   `json:"timed_out"`
}

type tailWriter struct {
	file io.Writer
	buf  []byte
	max  int
	mu   sync.Mutex
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.file.Write(p)
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.max {
		copy(w.buf, w.buf[len(w.buf)-w.max:])
		w.buf = w.buf[:w.max]
	}
	return n, err
}

func emit(result Result) { _ = json.NewEncoder(os.Stdout).Encode(result) }

func validate(job Job) error {
	if len(job.Argv) == 0 || strings.TrimSpace(job.Argv[0]) == "" {
		return errors.New("argv must contain an executable")
	}
	if job.TimeoutMS <= 0 || job.TimeoutMS > 24*60*60*1000 {
		return errors.New("timeout_ms outside allowed range")
	}
	if job.LogPath == "" {
		return errors.New("log_path is required")
	}
	return nil
}

func terminateGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	time.Sleep(250 * time.Millisecond)
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func main() {
	// Internal helper negotiation; this is not a TBHM argparse action.
	if len(os.Args) == 2 && os.Args[1] == "--evidence-protocol" {
		fmt.Println("2")
		return
	}
	var job Job
	if err := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 4<<20))).Decode(&job); err != nil {
		emit(Result{ExitCode: 2, Error: "invalid job JSON: " + err.Error()})
		return
	}
	if err := validate(job); err != nil {
		emit(Result{ExitCode: 2, Error: err.Error()})
		return
	}
	if job.TailBytes <= 0 || job.TailBytes > 4<<20 {
		job.TailBytes = 256 << 10
	}
	if err := os.MkdirAll(filepath.Dir(job.LogPath), 0700); err != nil {
		emit(Result{ExitCode: 2, Error: err.Error()})
		return
	}
	logf, err := os.OpenFile(job.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		emit(Result{ExitCode: 2, Error: err.Error()})
		return
	}
	defer logf.Close()

	cmd := exec.Command(job.Argv[0], job.Argv[1:]...)
	deadline := time.Now().Add(time.Duration(job.TimeoutMS) * time.Millisecond)
	// Bound pipe-copy shutdown when a descendant retains a stream descriptor.
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if job.Cwd != "" {
		cmd.Dir = job.Cwd
	}
	cmd.Env = os.Environ()
	for k, v := range job.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(job.Input)
	var outSink, errSink io.Writer = io.Discard, io.Discard
	if job.StdoutFD > 2 && job.StderrFD > 2 && job.StdoutFD != job.StderrFD {
		outFile := os.NewFile(uintptr(job.StdoutFD), "evidence-stdout")
		errFile := os.NewFile(uintptr(job.StderrFD), "evidence-stderr")
		defer outFile.Close()
		defer errFile.Close()
		outSink, errSink = outFile, errFile
	}
	// Legacy standalone jobs retain JSON tails, but raw streams are withheld
	// from disk. Runner v2 routes both pipes through Python evidence_redaction.
	stdout := &tailWriter{file: outSink, max: job.TailBytes}
	stderr := &tailWriter{file: errSink, max: job.TailBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Do not log argv values; they can contain temporary secrets. Python writes
	// a separately redacted command header before invoking this helper.
	_, _ = fmt.Fprintf(logf, "\n=== TBHM GO EXECUTOR ===\nexecutable=%s argc=%d\n",
		filepath.Base(job.Argv[0]), len(job.Argv))

	if err := cmd.Start(); err != nil {
		emit(Result{ExitCode: 1, Error: err.Error()})
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	result := Result{ExitCode: 0}
	select {
	case err = <-done:
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				result.ExitCode = exitErr.ExitCode()
			} else {
				result.ExitCode = 1
				result.Error = err.Error()
			}
		}
	case <-timer.C:
		terminateGroup(cmd)
		<-done
		result.ExitCode = 124
		result.TimedOut = true
		result.Error = "timeout"
	case <-sigCh:
		terminateGroup(cmd)
		<-done
		result.ExitCode = 130
		result.Error = "cancelled"
	}
	stdout.mu.Lock()
	result.StdoutTail = string(stdout.buf)
	stdout.mu.Unlock()
	stderr.mu.Lock()
	result.StderrTail = string(stderr.buf)
	stderr.mu.Unlock()
	emit(result)
}
