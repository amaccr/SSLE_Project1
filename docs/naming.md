The format I want to follow is the DNS-style:

```
<service>-<instance>.<site>.<region>.<org>
api-02.avr.pt.ssle      + metadata: usar.host=h01
```

When an alert fires, who has to deal with it?
- Infer it from hierarchy: the zone has an owner, and everything under the zone belongs to that owner.

What if a container moves to another host?
Suppose api-02 moves from host h01 to h02: 
- its name still says h01, which is now wrong; The alert would be sent to the wrong machine
- if i rename it to h02, every log, alert and dashboard referring to the old name stops matching

Solution: two layers, a stable logical name and the physical location as metadata user.host=h01, which also becomes a Prometheus label