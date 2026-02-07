.PHONY: build generate clean

CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

build: generate
	go build -o bin/ebpf-threat-detector ./cmd/detector

generate:
	go generate ./...

clean:
	rm -rf bin/
	rm -f internal/loader/*_bpfel.go internal/loader/*_bpfeb.go

deps:
	go mod tidy
	go install github.com/cilium/ebpf/cmd/bpf2go@latest
