# SSLE Project 1: Threat detection, monitoring and prevention

Master's course "Security in Large Scale Systems" (Universidade de Aveiro). Due **22 Nov 2026**.
Teacher guidelines: `Projeto.pdf`. Grading: report 50% and demo/repository 50%.

## Stack
- **Pure Incus** (as used in the practical classes), with no Docker: each service is its own Incus instance,
  namely an nginx load balancer, 2× Python/Flask API and postgres. Instances are built with a script, so the
  whole setup can be rebuilt with one command.
- **Prometheus** for monitoring (required). **Wazuh** as the SIEM (recommended).
- Incus instance names can't contain dots (hostname rules). Full DNS-style names come from the
  network's `dns.domain`, and extra metadata goes in `user.*` config keys.

## Naming scheme
See `docs/naming.md` (a named grading aspect). DNS-style format: `<service>-<instance>.<host>.<site>.<region>.<org>`.
Still open: whether the owner and the host go in the name or in metadata/labels.

## Planned threats (3 required, from the syllabus)
DoS, botnet/credential stuffing, APT. Each one needs detection plus an action-response in Wazuh, and
its own report section: description, relevance, exploitation, metrics, response, PoC post-mortem.

## Working with the user
The user wants to **learn**. Prefer explanations, small steps and exercises over finished code.
Ask them to make the design decisions. Explain trade-offs, and remember that the report rewards
discussing limitations.
