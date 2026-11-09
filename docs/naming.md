The format I want to follow is the DNS-style:

```
<service>-<instance>.<site>.<region>.<org>
api-02.avr.pt.ssle      + metadata: user.host=h01
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
| exception: `bd-01` | team-data |
| exception: `api-01` | team-web |

## Why hybrid: setting the owner on every instance means editing every instance when a team changes (drift).
Only the zone default means you can't express exceptions (e.g. the `db` belongs to a data team).
Limitation: the owner is now spread across two places (this table + Incus metadata), so they can disagree.

## What if a container moves to another host?
Suppose api-02 moves from host h01 to h02: 
- its name still says h01, which is now wrong; The alert would be sent to the wrong machine
- if i rename it to h02, every log, alert and dashboard referring to the old name stops matching

Solution: two layers, a stable logical name and the physical location as metadata user.host=h01, which also becomes a Prometheus label

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