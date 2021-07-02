build: perf-logs-viewer

clean:
	rm -f perf-logs-viewer

start:
	./perf-logs-viewer

perf-logs-viewer: main.go
	# see: https://devlights.hatenablog.com/entry/2021/03/02/110912
	go build -o perf-logs-viewer \
	-ldflags "-X main.version=$(shell git describe --tag --abbrev=0 2>/dev/null) -X main.revision=$(shell git rev-parse HEAD) -X main.build=$(shell git describe --tags 2>/dev/null)"
