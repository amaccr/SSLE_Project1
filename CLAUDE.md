# SSLE Project 1: Threat detection, monitoring and prevention

Master's course "Security in Large Scale Systems" (Universidade de Aveiro). Due **22 Nov 2026**.
Teacher guidelines: `Projeto.pdf`. Grading: report 50% and demo/repository 50%.

## Stack
- **Pure Incus** (as used in the practical classes), with no Docker: each service is its own Incus instance,
  namely an nginx load balancer, 2× Python/Flask API, analytics and postgres (option B: the Guide 1
  pipeline concept placed behind nginx). Instances are built with a script, so the
  whole setup can be rebuilt with one command.
- **Prometheus** for monitoring (required). **Wazuh** as the SIEM (recommended).
- Incus instance names can't contain dots (hostname rules). Full DNS-style names come from the
  network's `dns.domain`, and extra metadata goes in `user.*` config keys.

## Naming scheme
See `docs/naming.md` (a named grading aspect). DNS-style format: `<service>-<instance>.<site>.<region>.<org>`.
Decided: host and owner are metadata, not part of the name. `user.host` is set on every instance. Owner is
hybrid: each zone has a default owner (table in naming.md) and `user.owner` is set only where it differs.
Instance numbers are unique per site. There will be a second site to show scalability, and outside actors
(client, attacker) get their own separate zone.

## Planned threats (3 required, from the syllabus)
DoS, botnet/credential stuffing, APT. Each one needs detection plus an action-response in Wazuh, and
its own report section: description, relevance, exploitation, metrics, response, PoC post-mortem.

## Working with the user
The user wants to **learn**. Prefer explanations, small steps and exercises over finished code.
Ask them to make the design decisions. Explain trade-offs, and remember that the report rewards
discussing limitations.
