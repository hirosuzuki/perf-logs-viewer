package main

import (
	"fmt"
	"log"
	"net/http"
)

var (
	version  string
	revision string
	build    string
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "perf-logs-viewer (%s)", revision)
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
