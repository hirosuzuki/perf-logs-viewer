package main

import (
	"log"
	"net/http"
	"os"
	"text/template"
)

var (
	version  string
	revision string
	build    string
)

func getenv(key string, defaultValue string) string {
	ret := os.Getenv(key)
	if ret == "" {
		return defaultValue
	}
	return ret
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/home.html")
	if err != nil {
		log.Printf("%s\n", err.Error())
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{}) != nil {
		log.Printf("%s\n", err.Error())
	}
}

func main() {
	// Load Settings
	perflogs_port := getenv("PERFLOGS_PORT", ":8080")
	perflogs_dir := getenv("PERFLOGS_DIRN", "logs")
	// Log Start Message
	log.Printf("Start Perf-Logs-Viewer (port=%s, dir=%s)\n", perflogs_port, perflogs_dir)
	// Routing Settings
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/favicon.ico", fs)
	http.HandleFunc("/", homeHandler)
	// Start Web App Server
	log.Fatal(http.ListenAndServe(perflogs_port, nil))
}
