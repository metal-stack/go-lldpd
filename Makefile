.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

GO111MODULE := on

.PHONY: all
all:
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "-X 'github.com/metal-stack/v.Version=$(VERSION)' \
				  -X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				  -X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				  -X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
		-o bin/lldpd main.go
	strip bin/lldpd

.PHONY: release
release: all
	rm -rf rel
	mkdir -p rel/usr/local/bin rel/etc/systemd/system
	cp bin/lldpd rel/usr/local/bin
	cp lldpd.service rel/etc/systemd/system
	cd rel \
	&& tar -cvzf go-lldpd.tgz usr/local/bin/lldpd etc/systemd/system/lldpd.service \
	&& mv go-lldpd.tgz .. \
	&& cd -
