# SSLE_Project1

Threat detection, monitoring and prevention on a pure-Incus lab (SSLE, Universidade de Aveiro).

## Layout

| Path | What |
|---|---|
| `docs/` | Design decisions: `architecture.md` (instances, flows, DNS test), `naming.md` (naming scheme) |
| `scripts/build.sh` | Builds the lab: `./scripts/build.sh core`, then `./scripts/build.sh site avr` |
| `config/sites.conf` | The sites (name, region, subnet); adding a site = one line here + one `build.sh site` run |
| `Projeto.pdf` | Teacher guidelines |

## Build

```bash
./scripts/build.sh core        # once: ssle-mgmt + inet
./scripts/build.sh site avr    # per site
```

The script is idempotent: running it again leaves existing networks and instances as they are.
