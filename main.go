package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"text/template"
	"time"
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

type Trace struct {
	ID     string `json:"id"`
	ExecAt time.Time
}

func checkTraceID(v string) bool {
	rep := regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)
	return rep.MatchString(v)
}

func getTraces() []Trace {
	files, err := ioutil.ReadDir("./logs")
	if err != nil {
		panic(err)
	}
	traceList := []Trace{}
	jst := time.FixedZone("Asia/Tokyo", 9*60*60)
	for _, file := range files {
		if checkTraceID(file.Name()) {
			traceID := file.Name()
			t, _ := time.Parse("20060102-150405", traceID)
			jt := t.In(jst)
			trace := Trace{ID: traceID, ExecAt: jt}
			traceList = append(traceList, trace)
		}
	}
	sort.Slice(traceList, func(i int, j int) bool { return traceList[i].ID > traceList[j].ID })
	return traceList
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/home.html")
	if err != nil {
		log.Printf("%s\n", err.Error())
		return
	}
	traces := getTraces()
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{"traces": traces}) != nil {
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
