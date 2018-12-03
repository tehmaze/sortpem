BUILD_DATE = $(shell date)
BUILD_HASH = $(shell git rev-parse HEAD)
VERSION    = $(shell git describe --abbrev=0 --tags)
LDFLAGS    = '-s -w -X "main.BuildDate=$(BUILD_DATE)" -X main.BuildHash=$(BUILD_HASH) -X main.Version=$(VERSION)'

all: build-macos build-linux build-windows

build-macos:
	rm -rf build/macos/sortpem-$(VERSION)
	mkdir -p build/macos/sortpem-$(VERSION)
	
	GOOS=darwin GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/macos/sortpem-$(VERSION)/sortpem ./cmd/sortpem && \
	(cd build/macos; tar -czvf ../sortpem-$(VERSION)-macos.tar.gz sortpem-$(VERSION)/)

build-linux: build
	rm -rf build/linux/sortpem-$(VERSION)
	mkdir -p build/linux/sortpem-$(VERSION)
	
	GOOS=linux GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem ./cmd/sortpem && \
	(cd build/linux; tar -czvf ../sortpem-$(VERSION)-linux-amd64.tar.gz sortpem-$(VERSION)/)

	GOOS=linux GOARCH=386 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem ./cmd/sortpem && \
	(cd build/linux; tar -czvf ../sortpem-$(VERSION)-linux-386.tar.gz sortpem-$(VERSION)/)

build-windows: build
	rm -rf build/windows/sortpem-$(VERSION)
	mkdir -p build/windows/sortpem-$(VERSION)

	GOOS=windows GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem.exe ./cmd/sortpem && \
	(cd build/windows; tar -czvf ../sortpem-$(VERSION)-windows-amd64.tar.gz sortpem-$(VERSION)/) 

	GOOS=windows GOARCH=386 go build -ldflags=$(LDFLAGS) -o build/sortpem-$(VERSION)/sortpem.exe ./cmd/sortpem && \
	(cd build/windows; tar -czvf ../sortpem-$(VERSION)-windows-386.tar.gz sortpem-$(VERSION)/) 
