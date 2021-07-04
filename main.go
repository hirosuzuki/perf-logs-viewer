package main

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
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

func makeLogFile(logfile fs.FileInfo, traceID string, prefix string) (LogFile, bool) {
	logfileName := logfile.Name()
	if strings.HasPrefix(logfileName, prefix) && strings.HasSuffix(logfileName, ".log") {
		filesize := logfile.Size()
		var code string = logfileName[len(prefix) : len(logfileName)-len(".log")]
		return LogFile{Code: code, Filename: filepath.Join(perflogs_path, traceID, logfile.Name()), Size: filesize}, true
	}
	return LogFile{}, false
}

func getTrace(file fs.FileInfo) (Trace, error) {
	if !checkTraceID(file.Name()) {
		return Trace{}, errors.New("No Trace ID")
	}

	traceID := file.Name()
	t, _ := time.Parse("20060102-150405", traceID)
	jst := time.FixedZone("Asia/Tokyo", 9*60*60)
	jt := t.In(jst)
	accessLogs := []LogFile{}
	var accessLogTotal int64
	sqlLogs := []LogFile{}
	var sqlLogTotal int64
	logfiles, err := ioutil.ReadDir(filepath.Join(perflogs_path, traceID))
	if err != nil {
		return Trace{}, err
	}
	for _, logfile := range logfiles {
		if accessLog, ok := makeLogFile(logfile, traceID, "access"); ok {
			accessLogs = append(accessLogs, accessLog)
			accessLogTotal += accessLog.Size
		}
		if sqlLog, ok := makeLogFile(logfile, traceID, "sql"); ok {
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

	return trace, nil
}

func getTraces() []Trace {
	files, err := ioutil.ReadDir(perflogs_path)
	if err != nil {
		panic(err)
	}
	traceList := []Trace{}
	for _, file := range files {
		if trace, err := getTrace(file); err == nil {
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

func getTraceFromID(traceID string) (Trace, error) {
	filename := filepath.Join(perflogs_path, traceID)
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return Trace{}, err
	}
	if fs, err := f.Stat(); err != nil {
		return Trace{}, err
	} else {
		return getTrace(fs)
	}
}

func detailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	traceID := vars["code"]
	trace, err := getTraceFromID(traceID)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	log.Printf("%v\n", trace)
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	fmt.Fprintf(w, "OK %s", trace.ID)
}

func outputLogs(w io.Writer, logs []LogFile) {
	for _, log := range logs {
		fp, err := os.Open(log.Filename)
		defer fp.Close()
		if err == nil {
			buf, err := ioutil.ReadAll(fp)
			if err == nil {
				w.Write(buf)
			}
		}
	}
}

func rawAccessHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	traceID := vars["code"]
	trace, err := getTraceFromID(traceID)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	outputLogs(w, trace.AccessLogs)
}

func rawSqlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	traceID := vars["code"]
	trace, err := getTraceFromID(traceID)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	outputLogs(w, trace.SQLLogs)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func getKataribePath() string {
	kataribePath := os.Getenv("KATARIBE_PATH")
	if kataribePath != "" {
		return kataribePath
	}
	homePath := os.Getenv("HOME")
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(homePath, "go")
	}
	kataribePath = filepath.Join(goPath, "bin", "kataribe")
	return kataribePath
}

func kataribeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	traceID := vars["code"]
	trace, err := getTraceFromID(traceID)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	cmd := exec.Command(getKataribePath())
	pipe, err := cmd.StdinPipe()
	if err == nil {
		cmd.Stdout = w
		cmd.Start()
		outputLogs(pipe, trace.AccessLogs)
		pipe.Close()
		cmd.Wait()
	}
}

var (
	perflogs_port string
	perflogs_path string
)

func main() {

	// Load Settings
	perflogs_port = getenv("PERFLOGS_PORT", ":8080")
	perflogs_path = getenv("PERFLOGS_PATH", "logs")

	// Log Start Message
	log.Printf("Start Perf-Logs-Viewer (port=%s, dir=%s)\n", perflogs_port, perflogs_path)

	// Routing Settings
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	router.HandleFunc("/detail/{code}", detailHandler)
	router.HandleFunc("/raw/access/{code}", rawAccessHandler)
	router.HandleFunc("/raw/sql/{code}", rawSqlHandler)
	router.HandleFunc("/kataribe/{code}", kataribeHandler)
	router.HandleFunc("/", homeHandler)

	// Start Web App Server
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)
	log.Fatal(http.ListenAndServe(perflogs_port, loggedRouter))
}
