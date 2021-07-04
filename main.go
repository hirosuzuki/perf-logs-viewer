package main

import (
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

type LogSet struct {
	ID             string `json:"id"`
	ExecAt         time.Time
	AccessLogs     []LogFile
	AccessLogTotal int64
	SQLLogs        []LogFile
	SQLLogTolal    int64
}

func makeLogFile(logfile fs.FileInfo, logSetID string, prefix string) (LogFile, bool) {
	name := logfile.Name()
	if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".log") {
		code := name[len(prefix) : len(name)-len(".log")]
		if strings.HasPrefix(code, "-") {
			code = code[1:]
		}
		return LogFile{Code: code, Filename: filepath.Join(perflogs_path, logSetID, name), Size: logfile.Size()}, true
	}
	return LogFile{}, false
}

func fetchLogSet(file fs.FileInfo) (LogSet, error) {
	// ファイル名のチェック
	logSetID := file.Name()
	if !regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`).MatchString(logSetID) {
		return LogSet{}, fmt.Errorf("Invalid LogSet name %s", logSetID)
	}

	// ファイル名から実行時間を算出
	execAt, err := time.Parse("20060102-150405", logSetID)
	if err != nil {
		return LogSet{}, fmt.Errorf("Invalid LogSet name %s", logSetID)
	}
	execAt = execAt.In(time.FixedZone("Asia/Tokyo", 9*60*60))

	accessLogs := []LogFile{}
	sqlLogs := []LogFile{}

	// ログファイルの収集
	logfiles, err := ioutil.ReadDir(filepath.Join(perflogs_path, logSetID))
	if err != nil {
		return LogSet{}, err
	}
	for _, logfile := range logfiles {
		if accessLog, ok := makeLogFile(logfile, logSetID, "access"); ok {
			accessLogs = append(accessLogs, accessLog)
		}
		if sqlLog, ok := makeLogFile(logfile, logSetID, "sql"); ok {
			sqlLogs = append(sqlLogs, sqlLog)
		}
	}

	// ファイルサイズの合計計算関数
	calcTotalFileSize := func(logs []LogFile) int64 {
		var result int64
		for _, log := range logs {
			result += log.Size
		}
		return result
	}

	return LogSet{
		ID:             logSetID,
		ExecAt:         execAt,
		AccessLogTotal: calcTotalFileSize(accessLogs),
		AccessLogs:     accessLogs,
		SQLLogTolal:    calcTotalFileSize(sqlLogs),
		SQLLogs:        sqlLogs,
	}, nil
}

func fetchLogSetList() ([]LogSet, error) {
	files, err := ioutil.ReadDir(perflogs_path)
	if err != nil {
		return []LogSet{}, err
	}
	logSetList := []LogSet{}
	for _, file := range files {
		if logSet, err := fetchLogSet(file); err == nil {
			logSetList = append(logSetList, logSet)
		}
	}
	sort.Slice(logSetList, func(i int, j int) bool { return logSetList[i].ID > logSetList[j].ID })
	return logSetList, nil
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
	logSetList, err := fetchLogSetList()
	if err != nil {
		log.Printf("%v", err.Error())
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{"logSetList": logSetList}) != nil {
		log.Printf("%s", err.Error())
	}
}

func getLogSetFromID(logSetID string) (LogSet, error) {
	filename := filepath.Join(perflogs_path, logSetID)
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		return LogSet{}, err
	}
	if fs, err := f.Stat(); err != nil {
		return LogSet{}, err
	} else {
		return fetchLogSet(fs)
	}
}

func detailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		log.Printf("%s", err.Error())
		w.WriteHeader(404)
		return
	}
	log.Printf("%v\n", logSet)
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	fmt.Fprintf(w, "OK %s", logSet.ID)
}

func outputLogs(w io.Writer, logs []LogFile) {
	for _, log := range logs {
		buf, err := ioutil.ReadFile(log.Filename)
		if err == nil {
			w.Write(buf)
		}
	}
}

func rawAccessHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		log.Printf("%s", err.Error())
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	outputLogs(w, logSet.AccessLogs)
}

func rawSqlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		log.Printf("%s", err.Error())
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	outputLogs(w, logSet.SQLLogs)
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

func execCommandFromLogsToWriter(w io.Writer, logs []LogFile, name string, arg ...string) error {
	command := exec.Command(name, arg...)
	stdinPipe, err := command.StdinPipe()
	if err != nil {
		return err
	}
	command.Stdout = w
	if err = command.Start(); err != nil {
		return err
	}
	outputLogs(stdinPipe, logs)
	if err = stdinPipe.Close(); err != nil {
		return err
	}
	if err = command.Wait(); err != nil {
		return err
	}
	return nil
}

func kataribeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		log.Printf("%s", err.Error())
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	err = execCommandFromLogsToWriter(w, logSet.AccessLogs, getKataribePath())
	if err != nil {
		log.Printf("%v", err.Error())
	}
}

func sqlAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		log.Printf("%s", err.Error())
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	err = execCommandFromLogsToWriter(w, logSet.SQLLogs, "python3", "parse_log.py")
	if err != nil {
		log.Printf("%v", err.Error())
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
	router.HandleFunc("/detail/{id}", detailHandler)
	router.HandleFunc("/raw/access/{id}", rawAccessHandler)
	router.HandleFunc("/raw/sql/{id}", rawSqlHandler)
	router.HandleFunc("/kataribe/{id}", kataribeHandler)
	router.HandleFunc("/sqlanalyze/{id}", sqlAnalyzeHandler)
	router.HandleFunc("/", homeHandler)

	// Start Web App Server
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)
	log.Fatal(http.ListenAndServe(perflogs_port, loggedRouter))
}
