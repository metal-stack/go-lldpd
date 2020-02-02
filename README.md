# go-lldpd

go-lldpd is a lldpd server written in go which sends machineUUID and installation timestamp of a bare metal server to connected switches.
It is configured from a yaml file `/etc/metal/install.yaml`:

```yaml
---
machineuuid: 3be6c846-57de-432a-b50e-61c6c559b6bb
timestamp: 2006-01-02T15:04:05Z07:00
```

The config file location cannot be modified.
go-lldpd also expects 2 distinct uplinks to the switch, otherwise it will die.

Example systemd service is also bundled.