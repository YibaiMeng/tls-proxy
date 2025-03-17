package main

import (
	"io"
	"log"
	"net"

	"pault.ag/go/sniff/parser"
)

var signalHostnames = map[string]struct{}{
	"chat.signal.org":             {},
	"ud-chat.signal.org":          {},
	"storage.signal.org":          {},
	"cdn.signal.org":              {},
	"cdn2.signal.org":             {},
	"cdn3.signal.org":             {},
	"cdsi.signal.org":             {},
	"contentproxy.signal.org":     {},
	"sfu.voip.signal.org":         {},
	"svr2.signal.org":             {},
	"updates.signal.org":          {},
	"updates2.signal.org":         {},
	"chat.staging.signal.org":     {},
	"ud-chat.staging.signal.org":  {},
	"storage-staging.signal.org":  {},
	"cdn-staging.signal.org":      {},
	"cdn2-staging.signal.org":     {},
	"cdn3-staging.signal.org":     {},
	"cdsi.staging.signal.org":     {},
	"sfu.staging.voip.signal.org": {},
	"svr2.staging.signal.org":     {},
}

// Checks if a domain is in the predefined set
func isSignalHostname(domain string) bool {
	_, exists := signalHostnames[domain]
	return exists
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the inner ClientHello
	data := make([]byte, 4096)

	data_length, err := conn.Read(data)
	if err != nil {
		log.Printf("Error: %s", err)
	}

	hostname, err := parser.GetHostname(data[:])

	if err != nil {
		log.Println("Error reading inner TLS handshake:", err)
		return
	}

	log.Printf("SNI Hostname: %s", hostname)
	if !isSignalHostname(hostname) {
		log.Printf("Not a signal hostname")
		return
	}
	// Connect to the real server
	target := net.JoinHostPort(hostname, "443")
	backend, err := net.Dial("tcp", target)
	if err != nil {
		log.Println("Error connecting to real server:", err)
		return
	}
	defer backend.Close()

	// Forward the ClientHello we already read
	_, err = backend.Write(data[:data_length])
	if err != nil {
		log.Println("Error forwarding ClientHello:", err)
		return
	}

	// Copy the rest of the traffic in both directions
	go io.Copy(backend, conn)
	io.Copy(conn, backend)
}

func main() {
	// Since Fly.io is already terminating the outer TLS, we just do a plain TCP listen
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Error starting TCP listener:", err)
	}
	defer ln.Close()

	log.Println("Proxy listening on :8080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}
