The format I want to follow is the DNS-style:

```
<service>-<instance>.<site>.<region>.<org>
api-02.avr.pt.ssle      
```

## When an alert fires, who has to deal with it?
- Hybrid: every zone has a default owner, and everything under the zone belongs to that owner.
- An instance sets `user.owner` **only when it differs** from its zone's owner (the exception overrides the default).
- Owners are teams/roles, never people (people leave, teams stay).
- Lookup order: `user.owner` on the instance → owner of its zone → owner of the parent zone → ... → `ssle`.

| Zone | Default owner |
|---|---|
| `ssle` | secops |
| `pt.ssle` | ops-pt |
| `avr.pt.ssle` | ops-avr |
| `lis.pt.ssle` | ops-lis |
| exception: `db-01.avr.pt.ssle` | team-data |
| exception: `api-01.avr.pt.ssle` | team-web |

## Why hybrid?

setting the owner on every instance means editing every instance when a team changes (drift).
Only the zone default means you can't express exceptions (e.g. the `db` belongs to a data team).
Limitation: the owner is now spread across two places (this table + Incus metadata), so they can disagree.

`inet` is the outside world: not owned by `ssle`, so it has no owner on purpose. It exists only so the lab's
outside actors (`client-01.inet`, `attacker-01.inet`) have readable names.
Limitation: in reality an attacker's IP has no useful name, so detection rules must work on IPs, never on the
`attacker-01.inet` label. Otherwise the demo cheats.

## What if a container moves to another host?
Suppose api-02 moves from host h01 to h02: 
- its name still says h01, which is now wrong; The alert would be sent to the wrong machine
- if i rename it to h02, every log, alert and dashboard referring to the old name stops matching

Solution: two layers, a stable logical name and the physical location as metadata, but the host label now comes from the exporter

## How does the metadata reach Prometheus? One info metric per instance, joined at query time:

```
container_info{instance="api-02.avr.pt.ssle",host="h01",site="avr",owner="..."} 1
container_cpu_seconds_total{instance="api-02.avr.pt.ssle"} 12.3

rate(container_cpu_seconds_total[1m]) * on(instance) group_left(host, site, owner) container_info
```

- Why: a series is identified by its name + all of its labels. If every metric carried `host`, a move would
  restart every series of that container. With the info metric, only `container_info` changes.
- Limitation: queries and alert rules need the join; during a move, two `container_info` series exist for a short
  time and the join fails ("duplicate series") until the old one goes stale.
- Limitation: metadata is self-declared, and root on the VM (or anyone in `incus-admin`) can change it to
  misdirect responders. Mitigations: alert on metadata changes, compare against the build script in git.

## Where does a host come from?

From where the exporter actually runs.
- Why: a fact you measure is harder to fake than one you declare. One incus config set can no longer change it.
   - Consequence: you need one exporter per physical host. That scales naturally, and it fits the "monitor by location, optimise bandwidth" bonus.
   - Limitation: root on that host can still tamper with the exporter itself. It's harder to fake, not impossible.

## How are physical hosts named?

Physical hosts are an org-level asset owned by `secops`, so they live directly under the org: `h01.ssle`.
Not `h01.pt.ssle`: a region in the name would suggest the host belongs to that region, but `h01` runs
both `avr` and `lis`. Logical sites are *placed onto* physical hosts; the name keeps the two layers apart.