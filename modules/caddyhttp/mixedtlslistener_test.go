package caddyhttp

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMixedTLSListenerClassifiesHTTPAndTLS(t *testing.T) {
	base := newTestListener()
	ml := newMixedTLSListener(base, &tls.Config{})
	t.Cleanup(func() { _ = ml.Close() })

	plainClient, plainServer := net.Pipe()
	base.conns <- plainServer
	go func() {
		_, _ = plainClient.Write([]byte("GET /plain HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	}()
	plainConn, err := ml.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plainConn.(*tls.Conn); ok {
		t.Fatal("plain HTTP connection was wrapped with TLS")
	}
	request, err := io.ReadAll(io.LimitReader(plainConn, 43))
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "GET /plain HTTP/1.1\r\nHost: example.test\r\n\r\n" {
		t.Fatalf("unexpected request: %q", request)
	}
	_ = plainClient.Close()
	_ = plainConn.Close()

	tlsClient, tlsServer := net.Pipe()
	base.conns <- tlsServer
	if _, err := tlsClient.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	tlsConn, err := ml.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tlsConn.(*tls.Conn); !ok {
		t.Fatalf("TLS connection type is %T", tlsConn)
	}
	_ = tlsClient.Close()
	_ = tlsConn.Close()
}

func TestMixedTLSListenerServesHTTPAndHTTPS(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	certificates := certServer.TLS.Certificates
	certServer.Close()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ml := newMixedTLSListener(base, &tls.Config{Certificates: certificates})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			_, _ = io.WriteString(w, "plain-http")
			return
		}
		_, _ = io.WriteString(w, "secure-https")
	})}
	go func() { _ = server.Serve(ml) }()
	t.Cleanup(func() { _ = server.Close() })

	for _, tc := range []struct {
		scheme string
		want   string
	}{
		{scheme: "http", want: "plain-http"},
		{scheme: "https", want: "secure-https"},
	} {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Transport: transport}
		resp, err := client.Get(tc.scheme + "://" + base.Addr().String())
		if err != nil {
			t.Fatalf("%s request: %v", tc.scheme, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		transport.CloseIdleConnections()
		if err != nil {
			t.Fatalf("%s response: %v", tc.scheme, err)
		}
		if string(body) != tc.want {
			t.Fatalf("%s response: got %q, want %q", tc.scheme, body, tc.want)
		}
	}
}

type testListener struct {
	conns chan net.Conn
}

func newTestListener() *testListener {
	return &testListener{conns: make(chan net.Conn)}
}

func (l *testListener) Accept() (net.Conn, error) {
	conn, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *testListener) Close() error {
	close(l.conns)
	return nil
}

func (l *testListener) Addr() net.Addr {
	return testAddr("mixed-tls")
}

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }
