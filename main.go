package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	ID            string `json:"id"`
	ExecAt        time.Time
	AccessLogSize int64
	SQLLogSize    int64
}

func checkTraceID(v string) bool {
	rep := regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)
	return rep.MatchString(v)
}

func getFileSize(filename string) int64 {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return 0
	}
	return stat.Size()
}

func getTraces() []Trace {
	files, err := ioutil.ReadDir(perflogs_dir)
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
			trace := Trace{
				ID:            traceID,
				ExecAt:        jt,
				AccessLogSize: getFileSize(filepath.Join(perflogs_dir, traceID, "access.log")),
				SQLLogSize:    getFileSize(filepath.Join(perflogs_dir, traceID, "sql.log")),
			}
			traceList = append(traceList, trace)
		}
	}
	sort.Slice(traceList, func(i int, j int) bool { return traceList[i].ID > traceList[j].ID })
	return traceList
}

func numFormat(value int64) string {
	if value < 1000 {
		return strconv.FormatInt(value%1000, 10)
	}
	return numFormat(value/1000) + "," + fmt.Sprintf("%03d", value%1000)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	funcmap := template.FuncMap{
		"num": numFormat,
	}
	t, err := template.New("home.html").Funcs(funcmap).ParseFiles("templates/home.html")
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

var (
	perflogs_port string
	perflogs_dir  string
)

func main() {
	// Load Settings
	perflogs_port = getenv("PERFLOGS_PORT", ":8080")
	perflogs_dir = getenv("PERFLOGS_DIRN", "logs")
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
