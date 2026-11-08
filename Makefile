.PHONY: build build-alt install-browsers vet test clean

BINARY := xsshunts
ALT_BINARY := xsshunts-chromedp

build:
	go build -o $(BINARY) .

build-alt:
	go build -o $(ALT_BINARY) ./cmd/xsshunts-chromedp

install-browsers: build
	./$(BINARY) --install-browsers

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -f $(BINARY) $(ALT_BINARY)
