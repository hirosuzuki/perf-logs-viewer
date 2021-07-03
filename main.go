package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	version  string
	revision string
	build    string
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "perf-logs-viewer (%s)", revision)
}

func getenv(key string, defaultValue string) string {
	ret := os.Getenv(key)
	if ret == "" {
		return defaultValue
	}
	return ret
}

func main() {
	// Load Settings
	perflogs_port := getenv("PERFLOGS_PORT", ":8080")
	perflogs_dir := getenv("PERFLOGS_DIRN", "logs")
	// Log Start Message
	log.Printf("Start Perf-Logs-Viewer (port=%s, dir=%s)\n", perflogs_port, perflogs_dir)
	// Routing Settings
	http.HandleFunc("/", handler)
	// Start Web App Server
	log.Fatal(http.ListenAndServe(perflogs_port, nil))
}
