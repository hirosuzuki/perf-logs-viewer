package main

import (
	"fmt"
	"html/template"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
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

type LogFile struct {
	Code     string
	Filename string
	Size     int64
}

type Trace struct {
	ID             string `json:"id"`
	ExecAt         time.Time
	AccessLogs     []LogFile
	AccessLogTotal int64
	SQLLogs        []LogFile
	SQLLogTolal    int64
}

func checkTraceID(v string) bool {
	rep := regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)
	return rep.MatchString(v)
}

func makeLogFile(logfile fs.FileInfo, prefix string) (LogFile, bool) {
	logfileName := logfile.Name()
	if strings.HasPrefix(logfileName, prefix) && strings.HasSuffix(logfileName, ".log") {
		filesize := logfile.Size()
		var code string = logfileName[len(prefix) : len(logfileName)-len(".log")]
		return LogFile{Code: code, Filename: logfile.Name(), Size: filesize}, true
	}
	return LogFile{}, false
}

func getTrace(file fs.FileInfo) (Trace, bool) {
	if !checkTraceID(file.Name()) {
		return Trace{}, false
	}

	traceID := file.Name()
	t, _ := time.Parse("20060102-150405", traceID)
	jst := time.FixedZone("Asia/Tokyo", 9*60*60)
	jt := t.In(jst)
	accessLogs := []LogFile{}
	var accessLogTotal int64
	sqlLogs := []LogFile{}
	var sqlLogTotal int64
	logfiles, err := ioutil.ReadDir(filepath.Join(perflogs_dir, traceID))
	if err != nil {
		panic(err)
	}
	for _, logfile := range logfiles {
		if accessLog, ok := makeLogFile(logfile, "access"); ok {
			accessLogs = append(accessLogs, accessLog)
			accessLogTotal += accessLog.Size
		}
		if sqlLog, ok := makeLogFile(logfile, "sql"); ok {
			sqlLogs = append(sqlLogs, sqlLog)
			sqlLogTotal += sqlLog.Size
		}
	}

	trace := Trace{
		ID:             traceID,
		ExecAt:         jt,
		AccessLogTotal: accessLogTotal,
		AccessLogs:     accessLogs,
		SQLLogTolal:    sqlLogTotal,
		SQLLogs:        sqlLogs,
	}

	return trace, true
}

func getTraces() []Trace {
	files, err := ioutil.ReadDir(perflogs_dir)
	if err != nil {
		panic(err)
	}
	traceList := []Trace{}
	for _, file := range files {
		if trace, ok := getTrace(file); ok {
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

func detailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tradeID := vars["code"]
	filename := filepath.Join(perflogs_dir, tradeID)
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {

	}
	if fs, err := f.Stat(); err == nil {
		trace, ok := getTrace(fs)
		log.Printf("%v %v\n", ok, trace)
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	fmt.Fprintf(w, "OK %s", tradeID)
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
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	router.HandleFunc("/detail/{code}", detailHandler)
	router.HandleFunc("/", homeHandler)

	// Start Web App Server
	log.Fatal(http.ListenAndServe(perflogs_port, router))
}
