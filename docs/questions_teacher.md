# Questions for the teacher

## 1. Can the APT demo start with the attacker already holding valid credentials?

The weak endpoint (`/report`, command injection) needs a logged-in operator, which is realistic
(post-authentication vulnerabilities are common). The threats don't need to depend on each other, so the plan is:

- **APT demo:** starts from "the attacker already has valid operator credentials" (phished, bought or reused,
  which is common in real APTs), logs in as `bob`, then exploits `/report`.
- **Bonus, if time allows:** show the full chain: credential stuffing (threat 2) finds `bob`'s weak password,
  then the APT continues from there. This shows correlation across threats.

Is assuming valid credentials at the start of the APT acceptable, or should the APT entry be unauthenticated?
