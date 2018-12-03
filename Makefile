BUILD_DATE = $(shell date +"%d %B %Y, %H:%M:%S" | sed -e 's/^0//')
BUILD_HASH = $(shell git rev-parse HEAD)
VERSION    = $(shell git describe --abbrev=0 --tags)
LDFLAGS    = '-s -w -X "main.BuildDate=$(BUILD_DATE)" -X main.BuildHash=$(BUILD_HASH) -X main.Version=$(VERSION)'

all: build-darwin build-linux build-windows

build:
	mkdir -p build/sortpem-$(VERSION)

build-darwin: build
	GOOS=darwin GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem && \
	(cd build; tar -czvf sortpem-$(VERSION)-macos.tar.gz sortpem-$(VERSION)/) && \
	rm build/sortpem-$(VERSION)/sortpem

build-linux: build
	GOOS=linux GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem && \
	(cd build; tar -czvf sortpem-$(VERSION)-linux-amd64.tar.gz sortpem-$(VERSION)/) && \
	rm build/sortpem-$(VERSION)/sortpem
	GOOS=linux GOARCH=386 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem && \
	(cd build; tar -czvf sortpem-$(VERSION)-linux-386.tar.gz sortpem-$(VERSION)/) && \
	rm build/sortpem-$(VERSION)/sortpem

build-windows: build
	GOOS=windows GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem.exe && \
	(cd build; tar -czvf sortpem-$(VERSION)-windows-amd64.tar.gz sortpem-$(VERSION)/) && \
	rm build/sortpem-$(VERSION)/sortpem.exe

	GOOS=windows GOARCH=386 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem.exe && \
	(cd build; tar -czvf sortpem-$(VERSION)-windows-386.tar.gz sortpem-$(VERSION)/) && \
	rm build/sortpem-$(VERSION)/sortpem.exe
