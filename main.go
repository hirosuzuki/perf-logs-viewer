package main

import (
	"bufio"
	"embed"
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

//go:embed templates
var templateFs embed.FS

//go:embed static
var staticFs embed.FS

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
		code = strings.TrimPrefix(code, "-")
		return LogFile{Code: code, Filename: filepath.Join(perflogs_path, logSetID, name), Size: logfile.Size()}, true
	}
	return LogFile{}, false
}

func isValidLogSetID(id string) bool {
	return regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`).MatchString(id)
}

func fetchLogSet(file fs.FileInfo) (LogSet, error) {
	// ファイル名のチェック
	logSetID := file.Name()
	if !isValidLogSetID(logSetID) {
		return LogSet{}, fmt.Errorf("invalid logSet ID %s", logSetID)
	}

	// ファイル名から実行時間を算出
	execAt, err := time.Parse("20060102-150405", logSetID)
	if err != nil {
		return LogSet{}, fmt.Errorf("invalid logSet ID %s", logSetID)
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

func outputError(err error) {
	log.Print(err)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	funcmap := template.FuncMap{
		"num": numFormat,
	}
	t, err := template.New("home.html").Funcs(funcmap).ParseFS(templateFs, "templates/home.html")
	if err != nil {
		outputError(err)
		return
	}
	logSetList, err := fetchLogSetList()
	if err != nil {
		outputError(err)
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{"logSetList": logSetList}) != nil {
		outputError(err)
	}
}

func getLogSetFromID(logSetID string) (LogSet, error) {
	if !isValidLogSetID(logSetID) {
		return LogSet{}, fmt.Errorf("invalid logSet ID %s", logSetID)
	}
	filename := filepath.Join(perflogs_path, logSetID)
	f, err := os.Open(filename)
	if err != nil {
		return LogSet{}, err
	}
	defer f.Close()
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
		outputError(err)
		w.WriteHeader(404)
		return
	}
	funcmap := template.FuncMap{
		"num": numFormat,
	}
	t, err := template.New("detail.html").Funcs(funcmap).ParseFS(templateFs, "templates/detail.html")
	if err != nil {
		outputError(err)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{"logSet": logSet}) != nil {
		outputError(err)
	}
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
		outputError(err)
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	outputLogs(w, logSet.AccessLogs)
}

type UID struct {
	ID      string
	Times   int
	Request string
}

func uidListHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		outputError(err)
		w.WriteHeader(404)
		return
	}

	uidSet := make(map[string]*UID)
	uidList := make([]*UID, 0)

	for _, log := range logSet.AccessLogs {
		fp, err := os.Open(log.Filename)
		if err != nil {
			continue
		}
		defer fp.Close()
		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := scanner.Text()
			vs := strings.SplitN(line, " ", 4)
			if len(vs) < 4 {
				continue
			}
			uid := vs[1]
			if uid == "-" {
				continue
			}
			u := uidSet[uid]
			if u == nil {
				u = &UID{
					ID:      uid,
					Times:   0,
					Request: vs[3],
				}
				uidList = append(uidList, u)
				uidSet[uid] = u
			}
			u.Times++
		}
		if err := scanner.Err(); err != nil {
			continue
		}
	}

	funcmap := template.FuncMap{
		"num": numFormat,
		"safe": func(s string) template.HTML {
			return template.HTML(s)
		},
		"attr": func(s string) template.HTMLAttr {
			return template.HTMLAttr(s)
		},
	}
	t, err := template.New("uidlist.html").Funcs(funcmap).ParseFS(templateFs, "templates/uidlist.html")
	if err != nil {
		outputError(err)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if t.Execute(w, map[string]interface{}{"LogSet": logSet, "UIDList": uidList}) != nil {
		outputError(err)
	}
}

func uidHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	uid := vars["uid"]
	if err != nil {
		outputError(err)
		w.WriteHeader(404)
		return
	}

	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")

	for _, log := range logSet.AccessLogs {
		fp, err := os.Open(log.Filename)
		if err != nil {
			continue
		}
		defer fp.Close()
		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := scanner.Text()
			vs := strings.SplitN(line, " ", 4)
			if len(vs) < 4 {
				continue
			}
			if vs[1] == uid {
				fmt.Fprintln(w, line)
			}
		}
		if err := scanner.Err(); err != nil {
			continue
		}
	}
}

func rawSqlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		outputError(err)
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
		outputError(err)
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	err = execCommandFromLogsToWriter(w, logSet.AccessLogs, getKataribePath())
	if err != nil {
		outputError(err)
	}
}

type QueryRec struct {
	totalTime   int
	count       int
	averageTime int
	p50         int
	p90         int
	p99         int
	max         int
	content     string
}

func analyzeSQLLogs(w io.Writer, logFiles []LogFile) error {
	query_count := make(map[string]int)
	query_time := make(map[string]int)
	query_times := make(map[string][]int)
	for _, log := range logFiles {
		fp, err := os.Open(log.Filename)
		if err != nil {
			return err
		}
		defer fp.Close()
		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := scanner.Text()
			vs := strings.Split(line, "\t")
			deltatime, _ := strconv.Atoi(vs[1])
			query := vs[2]
			if len(vs) >= 4 {
				query = vs[3]
			}
			query_count[query] += 1
			query_time[query] += deltatime
			_, ok := query_times[query]
			if !ok {
				query_times[query] = make([]int, 0)
			}
			query_times[query] = append(query_times[query], deltatime)
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	for query := range query_times {
		sort.Slice(query_times[query], func(i int, j int) bool {
			return query_times[query][i] < query_times[query][j]
		})
	}

	queryRecList := make([]QueryRec, 0)
	for k := range query_count {
		times := query_times[k]
		queryRecList = append(queryRecList, QueryRec{
			content:     k,
			count:       query_count[k],
			totalTime:   query_time[k],
			p50:         times[(len(times)-1)*50/100],
			p90:         times[(len(times)-1)*90/100],
			p99:         times[(len(times)-1)*99/100],
			max:         times[(len(times)-1)*100/100],
			averageTime: query_time[k] / query_count[k],
		})
	}

	convertValues := func(q QueryRec) []string {
		return []string{
			fmt.Sprintf("%.3f", float64(q.totalTime)/1000000),
			fmt.Sprintf("%d", q.count),
			fmt.Sprintf("%.3f", float64(q.averageTime)/1000000),
			fmt.Sprintf("%.3f", float64(q.p50)/1000000),
			fmt.Sprintf("%.3f", float64(q.p90)/1000000),
			fmt.Sprintf("%.3f", float64(q.p99)/1000000),
			fmt.Sprintf("%.3f", float64(q.max)/1000000),
			q.content,
		}
	}

	titles := []string{"total(ms)", "count", "avg(ms)", "P50", "P90", "P99", "MAX", "content"}
	fmts := []string{"%*s", "%*s", "%*s", "%*s", "%*s", "%*s", "%*s", "%-*s"}
	widths := make([]int, len(titles))
	for i, t := range titles {
		widths[i] = len(t)
	}
	for _, q := range queryRecList {
		for i, v := range convertValues(q) {
			if widths[i] < len(v) {
				widths[i] = len(v)
			}
		}
	}

	outputValues := func(w io.Writer, values []string, splitter string, widths []int, formats []string) {
		for i := 0; i < len(values)-1; i++ {
			fmt.Fprintf(w, fmts[i], widths[i], values[i])
			fmt.Fprint(w, splitter)
		}
		fmt.Fprintln(w, values[len(values)-1])
	}

	outputSection := func(sectionTitle string, sortFunc func(i int, j int) bool) {
		sort.Slice(queryRecList, sortFunc)
		fmt.Fprint(w, sectionTitle, "\n\n")
		outputValues(w, titles, " | ", widths, fmts)
		lines := make([]string, 0)
		for _, v := range widths {
			lines = append(lines, strings.Repeat("-", v))
		}
		outputValues(w, lines, "-+-", widths, fmts)

		for _, q := range queryRecList {
			outputValues(w, convertValues(q), " | ", widths, fmts)
		}
		fmt.Fprint(w, "\n")
	}

	outputSection("# Top Query (総時間順)", func(i int, j int) bool {
		return queryRecList[i].totalTime > queryRecList[j].totalTime
	})

	outputSection("# Top Query (回数順)", func(i int, j int) bool {
		return queryRecList[i].count > queryRecList[j].count
	})

	outputSection("# Top Query (平均時間順)", func(i int, j int) bool {
		return queryRecList[i].averageTime > queryRecList[j].averageTime
	})

	return nil
}

func sqlAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		outputError(err)
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/plain")
	//err = execCommandFromLogsToWriter(w, logSet.SQLLogs, "python3", "parse_log.py")
	err = analyzeSQLLogs(w, logSet.SQLLogs)
	if err != nil {
		outputError(err)
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
	log.Printf("Start Perf-Logs-Viewer (port=%s, dir=%s)", perflogs_port, perflogs_path)

	// Routing Settings
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticFs)))
	router.HandleFunc("/detail/{id}", detailHandler)
	router.HandleFunc("/raw/access/{id}", rawAccessHandler)
	router.HandleFunc("/raw/sql/{id}", rawSqlHandler)
	router.HandleFunc("/kataribe/{id}", kataribeHandler)
	router.HandleFunc("/uid/{id}", uidListHandler)
	router.HandleFunc("/uid/{id}/{uid}", uidHandler)
	router.HandleFunc("/sqlanalyze/{id}", sqlAnalyzeHandler)
	router.HandleFunc("/", homeHandler)

	// Open Browser
	browser, ok := os.LookupEnv("BROWSER")
	if ok && browser != "" {
		exec.Command(browser, "http://localhost"+perflogs_port).Start()
	}

	// Start Web App Server
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)
	log.Fatal(http.ListenAndServe(perflogs_port, loggedRouter))
}
