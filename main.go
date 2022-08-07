package main

import (
	"bufio"
	"compress/gzip"
	"embed"
	"encoding/json"
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

var LogMap map[string]string = map[string]string{
	"web":  "access-",
	"app":  "app-",
	"sql":  "sql-",
	"slow": "mysql-slow-",
}

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
	FileSize int64
}

const LOGSET_JSON_VERSION = "1.0"

type LogSet struct {
	Version  string `json:"ver"`
	ID       string `json:"id"`
	ExecAt   time.Time
	LogSet   map[string]([]LogFile)
	LogTotal map[string]int64
}

func makeLogFile(logfile fs.FileInfo, logSetID string, prefix string) (LogFile, bool) {
	name := logfile.Name()
	if strings.HasPrefix(name, prefix) && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz")) {
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

	// UTC -> JST 変換
	execAt = execAt.In(time.FixedZone("Asia/Tokyo", 9*60*60))

	// ログフォルダ情報設定
	logfiles_dir := filepath.Join(perflogs_path, logSetID)
	logfiles_json := filepath.Join(logfiles_dir, "info.json")

	// ログ一覧情報の初期化
	result := LogSet{
		Version:  LOGSET_JSON_VERSION,
		ID:       logSetID,
		ExecAt:   execAt,
		LogSet:   map[string][]LogFile{},
		LogTotal: map[string]int64{},
	}

	for key := range LogMap {
		result.LogSet[key] = make([]LogFile, 0)
		result.LogTotal[key] = 0
	}

	// フォルダ内を検索してログ一覧情報を更新
	if logfiles, err := ioutil.ReadDir(logfiles_dir); err == nil {
		for _, logfile := range logfiles {
			for key, prefix := range LogMap {
				if log, ok := makeLogFile(logfile, logSetID, prefix); ok {
					result.LogSet[key] = append(result.LogSet[key], log)
					result.LogTotal[key] += log.Size
					break
				}
			}
		}
	}

	// ログファイル一覧の情報をJSON形式で保存
	result_json, err := json.Marshal(result)
	if err == nil {
		fp, _ := os.Create(logfiles_json)
		fp.Write(result_json)
	}

	return result, nil
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
	logSetList, err := fetchLogSetList()
	if err != nil {
		outputError(err)
	}
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if HTMLTemplate["home.html"].Execute(w, map[string]interface{}{"logSetList": logSetList}) != nil {
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
	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if HTMLTemplate["detail.html"].Execute(w, map[string]interface{}{"logSet": logSet}) != nil {
		outputError(err)
	}
}

func iterateLogs(logs []LogFile, handler func(io.Reader) error) error {
	for _, logfile := range logs {
		var src io.Reader
		fp, err := os.Open(logfile.Filename)
		if err != nil {
			log.Printf("error open file: %v", err)
			continue
		}
		defer fp.Close()
		src = fp
		if strings.HasSuffix(logfile.Filename, ".gz") {
			ze, err := gzip.NewReader(fp)
			if err != nil {
				log.Printf("error read gzip file: %v", err)
				continue
			}
			defer ze.Close()
			src = ze
		}
		err = handler(src)
		if err != nil {
			return err
		}
	}
	return nil
}

func outputLogs(w io.Writer, logs []LogFile) {
	err := iterateLogs(logs, func(src io.Reader) error {
		_, err := io.Copy(w, src)
		return err
	})
	if err != nil {
		log.Printf("error io copy: %v", err)
	}
}

func createRawHandler(logType string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		logSet, err := getLogSetFromID(vars["id"])
		if err != nil {
			outputError(err)
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		w.Header().Set("Content-type", "text/plain")
		outputLogs(w, logSet.LogSet[logType])
	}
}

type UID struct {
	ID      string
	Times   int
	Request string
}

func createUidListHandler(logtype string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		logSet, err := getLogSetFromID(vars["id"])
		if err != nil {
			outputError(err)
			w.WriteHeader(404)
			return
		}

		uidSet := make(map[string]*UID)
		uidList := make([]*UID, 0)

		err = iterateLogs(logSet.LogSet[logtype], func(src io.Reader) error {
			scanner := bufio.NewScanner(src)
			for scanner.Scan() {
				line := scanner.Text()
				vs := strings.SplitN(line, " ", 4)
				if len(vs) < 4 {
					continue
				}
				uid := vs[2]
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
			return scanner.Err()
		})
		if err != nil {
			log.Printf("error log processing: %v", err)
		}

		w.WriteHeader(200)
		w.Header().Set("Content-type", "text/html")
		if HTMLTemplate["uidlist.html"].Execute(w, map[string]interface{}{"LogType": logtype, "LogSet": logSet, "UIDList": uidList}) != nil {
			outputError(err)
		}
	}
}

func createUidQueryHandler(logType string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		logSet, err := getLogSetFromID(vars["id"])
		query := vars["query"]
		if err != nil {
			outputError(err)
			w.WriteHeader(404)
			return
		}

		w.WriteHeader(200)
		w.Header().Set("Content-type", "text/plain")

		err = iterateLogs(logSet.LogSet[logType], func(src io.Reader) error {
			scanner := bufio.NewScanner(src)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, query) {
					fmt.Fprintln(w, line)
				}
			}
			return scanner.Err()
		})
		if err != nil {
			log.Printf("error log processing: %v", err)
		}
	}
}

func getCommandPath(cmdName string, pathEnvName string) string {
	path := os.Getenv(pathEnvName)
	if path != "" {
		return path
	}
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	path = filepath.Join(goPath, "bin", cmdName)
	if f, err := os.Stat(path); !os.IsNotExist(err) && !f.IsDir() {
		return path
	}
	return cmdName
}

func getKataribePath() string {
	return getCommandPath("kataribe", "KATARIBE_PATH")
}

func getQueryDigestPath() string {
	return getCommandPath("go-mysql-query-digest", "QUERY_DIGEST_PATH")
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

func createCommandHandler(logType string, cmdPath string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		logSet, err := getLogSetFromID(vars["id"])
		if err != nil {
			outputError(err)
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		w.Header().Set("Content-type", "text/plain")
		err = execCommandFromLogsToWriter(w, logSet.LogSet[logType], cmdPath)
		if err != nil {
			outputError(err)
		}
	}
}

type QueryRec struct {
	TotalTime   int
	Count       int
	AverageTime int
	P50         int
	P90         int
	P99         int
	Max         int
	Content     string
}

func analyzeSQLLog(logFiles []LogFile) []QueryRec {
	query_count := make(map[string]int)
	query_time := make(map[string]int)
	query_times := make(map[string][]int)

	err := iterateLogs(logFiles, func(src io.Reader) error {
		scanner := bufio.NewScanner(src)
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
		return scanner.Err()
	})
	if err != nil {
		log.Printf("error log processing: %v", err)
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
			Content:     k,
			Count:       query_count[k],
			TotalTime:   query_time[k],
			P50:         times[(len(times)-1)*50/100],
			P90:         times[(len(times)-1)*90/100],
			P99:         times[(len(times)-1)*99/100],
			Max:         times[(len(times)-1)*100/100],
			AverageTime: query_time[k] / query_count[k],
		})
	}

	return queryRecList
}

func analyzeSQLLogs(w io.Writer, logFiles []LogFile) error {
	queryRecList := analyzeSQLLog(logFiles)

	convertValues := func(q QueryRec) []string {
		return []string{
			fmt.Sprintf("%.3f", float64(q.TotalTime)/1000000),
			fmt.Sprintf("%d", q.Count),
			fmt.Sprintf("%.3f", float64(q.AverageTime)/1000000),
			fmt.Sprintf("%.3f", float64(q.P50)/1000000),
			fmt.Sprintf("%.3f", float64(q.P90)/1000000),
			fmt.Sprintf("%.3f", float64(q.P99)/1000000),
			fmt.Sprintf("%.3f", float64(q.Max)/1000000),
			q.Content,
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
		return queryRecList[i].TotalTime > queryRecList[j].TotalTime
	})

	outputSection("# Top Query (回数順)", func(i int, j int) bool {
		return queryRecList[i].Count > queryRecList[j].Count
	})

	outputSection("# Top Query (平均時間順)", func(i int, j int) bool {
		return queryRecList[i].AverageTime > queryRecList[j].AverageTime
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
	err = analyzeSQLLogs(w, logSet.LogSet["sql"])
	if err != nil {
		outputError(err)
	}
}

func sqlAnalyzeHtmlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logSet, err := getLogSetFromID(vars["id"])
	if err != nil {
		outputError(err)
		w.WriteHeader(404)
		return
	}

	queryRecList := analyzeSQLLog(logSet.LogSet["sql"])

	sort.SliceStable(queryRecList, func(i int, j int) bool {
		return queryRecList[i].TotalTime > queryRecList[j].TotalTime
	})

	w.WriteHeader(200)
	w.Header().Set("Content-type", "text/html")
	if HTMLTemplate["sqlanalyze.html"].Execute(w, map[string]interface{}{"QueryList": queryRecList}) != nil {
		outputError(err)
	}
}

var (
	perflogs_port string
	perflogs_path string
)

var HTMLTemplateNames = []string{"detail.html", "home.html", "sqlanalyze.html", "uidlist.html"}
var HTMLTemplate map[string]*template.Template = map[string]*template.Template{}

func loadHTMLTemplate() {
	funcmap := template.FuncMap{
		"num": numFormat,
		"float3": func(v int) string {
			return fmt.Sprintf("%.3f", float64(v)/1000000)
		},
		"safe": func(s string) template.HTML {
			return template.HTML(s)
		},
		"attr": func(s string) template.HTMLAttr {
			return template.HTMLAttr(s)
		},
	}
	for _, k := range HTMLTemplateNames {
		t, err := template.New(k).Funcs(funcmap).ParseFS(templateFs, "templates/"+k)
		if err != nil {
			log.Fatalf("error Load Template: %v", err)
		}
		HTMLTemplate[k] = t
	}
}

func main() {
	loadHTMLTemplate()

	// Load Settings
	perflogs_port = getenv("PERFLOGS_PORT", ":8080")
	perflogs_path = getenv("PERFLOGS_PATH", "logs")

	// Log Start Message
	log.Printf("Start Perf-Logs-Viewer (port=%s, dir=%s, url=http://localhost%s)", perflogs_port, perflogs_path, perflogs_port)

	// Routing Settings
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticFs)))
	router.HandleFunc("/detail/{id}", detailHandler)

	router.HandleFunc("/web/raw/{id}", createRawHandler("web"))
	router.HandleFunc("/web/kataribe/{id}", createCommandHandler("web", getKataribePath()))
	router.HandleFunc("/web/uid/{id}", createUidListHandler("web"))
	router.HandleFunc("/web/uid/{id}/{query}", createUidQueryHandler("web"))

	router.HandleFunc("/app/raw/{id}", createRawHandler("app"))
	router.HandleFunc("/app/kataribe/{id}", createCommandHandler("app", getKataribePath()))
	router.HandleFunc("/app/uid/{id}", createUidListHandler("app"))
	router.HandleFunc("/app/uid/{id}/{query}", createUidQueryHandler("app"))

	router.HandleFunc("/sql/raw/{id}", createRawHandler("sql"))
	router.HandleFunc("/sql/analyze/{id}", sqlAnalyzeHandler)
	router.HandleFunc("/sql/analyzehtml/{id}", sqlAnalyzeHtmlHandler)

	router.HandleFunc("/slow/raw/{id}", createRawHandler("slow"))
	router.HandleFunc("/slow/digest/{id}", createCommandHandler("slow", getQueryDigestPath()))

	router.HandleFunc("/", homeHandler)

	// Open Browser
	if len(os.Args) >= 2 && os.Args[1] == "browser" {
		browser := os.Getenv("BROWSER")
		if browser != "" {
			exec.Command(browser, "http://localhost"+perflogs_port).Start()
		}
	}

	// Start Web App Server
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)
	log.Fatal(http.ListenAndServe(perflogs_port, loggedRouter))
}
