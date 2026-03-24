// Command server runs the SGTP relay server.
//
// Usage:
//
//	sgtp-server [--addr :7777]
package main

import (
	"flag"
	"log"
	"os"

	"github.com/SecureGroupTP/sgtp-go/server"
)

func main() {
	addr := flag.String("addr", ":7777", "TCP address to listen on")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	srv := server.New(*addr, logger)

	log.Fatal(srv.ListenAndServe())
}
