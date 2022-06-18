build: perf-logs-viewer

clean:
	rm -f perf-logs-viewer

start:
	./perf-logs-viewer

perf-logs-viewer: main.go
	go build -o perf-logs-viewer
