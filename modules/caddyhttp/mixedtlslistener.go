// Copyright 2026 The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

const (
	mixedTLSMaxPending       = 128
	mixedTLSInitialReadLimit = 10 * time.Second
)

func init() {
	caddy.RegisterModule(MixedTLSListenerWrapper{})
}

// MixedTLSListenerWrapper enables HTTP/1.x and TLS connections on one TCP
// listener. Plain HTTP connections are returned to the HTTP server without a
// TLS handshake, while other connections are wrapped with the server's TLS
// configuration.
type MixedTLSListenerWrapper struct{}

func (MixedTLSListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.mixed_tls",
		New: func() caddy.Module { return new(MixedTLSListenerWrapper) },
	}
}

func (MixedTLSListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// WrapListener is a no-op for compatibility with caddy.ListenerWrapper.
// The HTTP app invokes wrapTLSListener at the TLS boundary so it can provide
// the connection policy to the mixed listener.
func (MixedTLSListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return l
}

func (MixedTLSListenerWrapper) wrapTLSListener(l net.Listener, cfg *tls.Config) net.Listener {
	return newMixedTLSListener(l, cfg)
}

type mixedTLSListenerWrapper interface {
	caddy.ListenerWrapper
	wrapTLSListener(net.Listener, *tls.Config) net.Listener
}

type mixedTLSListener struct {
	net.Listener
	tlsConfig *tls.Config
	ready     chan net.Conn
	done      chan struct{}
	sem       chan struct{}
	once      sync.Once
	workers   sync.WaitGroup

	errMu sync.Mutex
	err   error
}

func newMixedTLSListener(l net.Listener, cfg *tls.Config) *mixedTLSListener {
	ml := &mixedTLSListener{
		Listener:  l,
		tlsConfig: cfg,
		ready:     make(chan net.Conn),
		done:      make(chan struct{}),
		sem:       make(chan struct{}, mixedTLSMaxPending),
	}
	go ml.dispatch()
	return ml
}

func (l *mixedTLSListener) dispatch() {
	defer func() {
		l.workers.Wait()
		close(l.ready)
	}()

	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.errMu.Lock()
			l.err = err
			l.errMu.Unlock()
			return
		}

		select {
		case l.sem <- struct{}{}:
		case <-l.done:
			_ = conn.Close()
			return
		default:
			_ = conn.Close()
			continue
		}

		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			defer func() { <-l.sem }()
			l.classify(conn)
		}()
	}
}

func (l *mixedTLSListener) classify(conn net.Conn) {
	if err := conn.SetReadDeadline(time.Now().Add(mixedTLSInitialReadLimit)); err != nil {
		_ = conn.Close()
		return
	}

	reader := bufio.NewReader(conn)
	first, err := reader.ReadByte()
	if err != nil {
		_ = conn.Close()
		return
	}
	method := ""
	prefix := []byte{first}
	if first >= 'A' && first <= 'Z' {
		method, prefix, err = readMixedTLSMethod(reader, first)
		if err != nil {
			_ = conn.Close()
			return
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}

	conn = &mixedTLSPrefixedConn{
		Conn: conn,
		r:    bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), reader)),
	}
	if method == "PRI" {
		// h2c is intentionally not enabled by mixed_tls. The HTTP/2
		// preface must not be handed to the HTTP/1 parser.
		_ = conn.Close()
		return
	} else if method == "" {
		conn = tls.Server(conn, l.tlsConfig)
	}

	select {
	case l.ready <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func readMixedTLSMethod(r *bufio.Reader, first byte) (string, []byte, error) {
	method := []byte{first}
	for len(method) < 32 {
		b, err := r.ReadByte()
		if err != nil {
			return "", method, err
		}
		method = append(method, b)
		if b == ' ' {
			if len(method) < 3 {
				return "", method, nil
			}
			for _, c := range method[:len(method)-1] {
				if c < 'A' || c > 'Z' {
					return "", method, nil
				}
			}
			return string(method[:len(method)-1]), method, nil
		}
		if b == '\r' || b == '\n' {
			return "", method, nil
		}
	}
	return "", method, nil
}

func (l *mixedTLSListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ready
	if ok {
		return conn, nil
	}

	l.errMu.Lock()
	err := l.err
	l.errMu.Unlock()
	if err != nil {
		return nil, err
	}
	return nil, net.ErrClosed
}

func (l *mixedTLSListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
}

type mixedTLSPrefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *mixedTLSPrefixedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (*mixedTLSPrefixedConn) mixedTLSPlaintext() {}

var (
	_ caddy.ListenerWrapper = (*MixedTLSListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*MixedTLSListenerWrapper)(nil)
)
