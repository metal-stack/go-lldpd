GO111MODULE := on

.PHONY: all
all:
	go build -tags netgo -o bin/lldpd main.go
	strip bin/lldpd

.PHONY: release
release: all
	tar -cvzf go-lldpd.tgz bin/lldpd lldpd.service README.md