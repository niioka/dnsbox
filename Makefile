EXECUTABLES = bin/dnsbox
GO ?= go

.PHONY: build test clean

build: $(EXECUTABLES)
test:
	$(GO) test ./...
clean:
	rm -f $(EXECUTABLES)
bin/dnsbox:
	$(GO) build -o bin/dnsbox
