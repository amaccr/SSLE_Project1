# Naming scheme

Identifying elements in a way that scales is an explicit requirement of the project. The
scheme uses a **DNS-style hierarchical name**, so that one name answers three questions
at once: *where* is the element (logically and physically), *who* is responsible for it,
and how quickly an incident can be traced to its source.

## Format

```
<service>-<instance>.<site>.<region>.<org>     e.g.  api-02.avr.pt.ssle
```

| Part | Meaning | Example |
|---|---|---|
| `service` | the role the instance plays | `api`, `db`, `lb`, `prom`, `siem` |
| `instance` | which one, unique per site | `01`, `02` |
| `site` | logical site (a failure/scaling unit) | `avr`, `lis` |
| `region` | geographic region | `pt` |
| `org` | the organisation (the root zone) | `ssle` |

**Constraint.** Incus instance names cannot contain dots (they must be valid
hostnames), so the short name (`api-02`) is the Incus instance and the fully-qualified
name is assembled from the network's `dns.domain`. Anything that is not part of the
identity lives in `user.*` config keys as metadata.

## In the name vs. in metadata

The guiding principle is that the name carries only the **stable logical identity**,
while facts that can change are kept as **metadata** and never baked into the name:

- **In the name (stable):** service, instance, site, region, org.
- **Metadata (can change without renaming):** the physical host (observed, see below)
  and the owner (`user.owner`, see below).

This separation is what lets a container move between physical hosts, or change teams,
without invalidating every log, alert and dashboard that refers to it: the logical name
is the key, and the volatile facts are labels joined to it at query time.

## Responsibility: who handles an alert?

Ownership is **hybrid** — a zone default with per-instance exceptions:

- Every zone has a default owner, and everything under the zone inherits it.
- An instance sets `user.owner` **only when it differs** from its zone's owner (the
  exception overrides the default).
- Owners are teams or roles, never individuals (people leave, teams stay).
- Lookup order: `user.owner` on the instance → owner of its zone → owner of the parent
  zone → … → `ssle`.

| Zone | Default owner |
|---|---|
| `ssle` | secops |
| `pt.ssle` | ops-pt |
| `avr.pt.ssle` | ops-avr |
| `lis.pt.ssle` | ops-lis |
| exception: `db-01.avr.pt.ssle` | team-data |
| exception: `api-01.avr.pt.ssle` | team-web |

**Why hybrid?** Setting the owner on *every* instance means editing every instance when
a team changes (drift); using *only* the zone default cannot express exceptions (e.g. the
database belonging to a data team). The hybrid keeps the common case in one place and
still allows exceptions.

*Limitation.* The owner is now expressed in two places (this table and Incus metadata),
so they can disagree; the metadata should be checked against this document (and the build
script) in review.

**`inet` has no owner on purpose.** It models the outside world, which `ssle` does not
own; it exists only so the lab's external actors (`client-01.inet`, `attacker-01.inet`)
have readable names. *Limitation:* a real attacker's IP has no useful name, so detection
rules must key on IPs, never on the `attacker-01.inet` label — otherwise the demonstration
would be cheating.

## Physical location: observed, not declared

**Where does a host come from? From where the exporter actually runs.** A fact that is
*measured* is harder to fake than one that is *declared*: a single `incus config set` can
no longer move a container to a different host in the monitoring data.

- *Consequence:* one exporter per physical host. This scales naturally and fits the
  "monitor by location, optimise bandwidth" bonus.
- *Limitation:* root on a host can still tamper with the exporter itself — harder to fake,
  not impossible.

**What if a container moves to another host?** Suppose `api-02` moves from `h01` to `h02`.
If the host were part of the name, the name would now be wrong and alerts would be routed
to the wrong machine; renaming it to `h02` would instead break every log, alert and
dashboard that referenced the old name. The two-layer design avoids both: the logical
name is stable, and the host is a metadata label that the exporter reports.

**How the metadata reaches Prometheus.** One `info` metric per instance, joined at query
time:

```
container_info{instance="api-02.avr.pt.ssle",host="h01",site="avr",owner="..."} 1
container_cpu_seconds_total{instance="api-02.avr.pt.ssle"} 12.3

rate(container_cpu_seconds_total[1m]) * on(instance) group_left(host, site, owner) container_info
```

- *Why:* a time series is identified by its name plus all of its labels. If every metric
  carried `host`, a move would restart every series of that container; with the info
  metric, only `container_info` changes.
- *Limitation:* queries and alert rules must perform the join; during a move two
  `container_info` series coexist briefly and the join fails ("duplicate series") until
  the old one goes stale.
- *Limitation:* metadata is self-declared — root on the VM (or anyone in `incus-admin`)
  can change it to misdirect responders. Mitigations: alert on metadata changes, and
  compare the live metadata against the build script in git.

## Naming physical hosts

Physical hosts are an org-level asset owned by `secops`, so they live directly under the
org: `h01.ssle` — **not** `h01.pt.ssle`. A region in the name would imply the host belongs
to that region, but `h01` runs both `avr` and `lis`. Logical sites are *placed onto*
physical hosts; keeping the host under the org keeps the logical and physical layers apart.
