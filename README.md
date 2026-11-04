# go-lldpd

go-lldpd is a lldpd server written in go which sends machineUUID and installation timestamp of a bare metal server to connected switches.
It is configured from a yaml file `/etc/metal/install.yaml`:

```yaml
---
machineuuid: 3be6c846-57de-432a-b50e-61c6c559b6bb
timestamp: 2006-01-02T15:04:05Z07:00
```

The config file location cannot be modified.
By default go-lldpd expects at least 2 ethernet interfaces to be up (one per leaf switch), otherwise it exits.
The minimum can be lowered for setups with a single leaf switch, e.g. a hardware lab:

```bash
lldpd -min-interfaces 1
# or, e.g. in a systemd drop-in /etc/systemd/system/lldpd.service.d/min-interfaces.conf:
# [Service]
# Environment=LLDPD_MIN_INTERFACES=1
```

The flag takes precedence over the environment variable. Production machines should keep the default.

Example systemd service is also bundled.
