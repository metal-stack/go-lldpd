GO111MODULE := on

.PHONY: all
all:
	go build -trimpath -tags netgo -o bin/lldpd main.go
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