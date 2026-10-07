# Deployment modes and network exposure

Lab #07 runs Elasticsearch and Kibana with **xpack security disabled**. That is
a deliberate choice for a single-machine teaching lab, and it is the reason the
network binding matters so much.

This document exists because of security audit finding **H-2**: publishing
Elasticsearch and Kibana on `0.0.0.0` with no authentication means anything on
the network has unauthenticated cluster administration.

> **Where this sits now.** The Compose stack has been given explicit isolation
> names for the shared server (project `bcssl-siem-lab07`, containers
> `bcssl-siem07-es` / `bcssl-siem07-kibana`, network `bcssl-siem07-net`,
> volumes `bcssl-siem07-es-data` / `bcssl-siem07-kibana-config`), plus CPU,
> memory and log-rotation limits. None of that changes network exposure: the
> port bindings below are unchanged and still loopback-only. See
> [SERVER_DEPLOYMENT.md](SERVER_DEPLOYMENT.md).
>
> The Mode 2 decision below is **still open**. Isolation makes this lab safe to
> place on a shared host; it does not make it safe to hand to a class.

## What changed

`docker-compose.yml` now publishes:

```yaml
ports:
  - "127.0.0.1:9200:9200"   # was "9200:9200"
  - "127.0.0.1:5601:5601"   # was "5601:5601"
```

Loopback binding is the safe default. The documented single-machine lab
workflow is unchanged - everything in this project talks to `localhost`.

## Mode 1: Local development (default, safe)

```powershell
.\scripts\setup.ps1        # once
.\scripts\start_lab.ps1    # each session
```

- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`
- Training platform: `http://localhost:8080`

Nothing is reachable from another machine. This is correct for an instructor
demonstrating the lab from their own laptop, and it is the default.

If a host firewall or a corporate policy blocks loopback publishing, or you need
to reach the stack from a VM or WSL instance, bind explicitly to the interface
you need - and understand that you have re-opened the exposure:

```yaml
ports:
  - "192.168.1.50:9200:9200"   # a specific LAN address, not 0.0.0.0
```

## Mode 2: Classroom deployment - REQUIRES A DECISION

**This mode is not implemented, and it cannot be implemented safely by editing
a port number.** Enabling it needs a choice only the product owner can make.

The problem: students must use Kibana to investigate events in Discover. That is
the core training loop. With `xpack.security.enabled=true`, every student needs
a Kibana account. There is no configuration that gives an unauthenticated
browser read-only access to Kibana while denying it cluster administration -
Kibana's API will happily create, modify and delete saved objects, and a
student who can reach Elasticsearch directly can delete the shared dataset
that every other student is investigating.

### Option A - per-student Kibana accounts (most secure, most work)

Enable `docker-compose.prod.yml`, provision one account per student, and
add Kibana login to the training platform.

- Students cannot administer the cluster or each other's dashboards.
- Cost: a roster, a provisioning step, a login step for every student, and
  credential handling in a training environment.
- Needs a decision on whether accounts are pre-provisioned or self-registered
  through the training platform, and how an instructor resets a locked account.

### Option B - read-only reverse proxy (moderate work, moderate security)

Keep the stack on loopback and put a proxy in front of Kibana that forwards
only the read paths students need (Discover, Dashboard view) and rejects the
saved-objects and console APIs.

- Students get the investigation loop without accounts.
- Cost: a new component to build, configure and keep patched, and it must be
  right - a proxy rule that is too broad re-opens the hole.
- The training platform would need to point its Kibana links at the proxy.

### Option C - shared read-only credential (least work, weakest)

Give all students one read-only Elasticsearch role, and keep port 9200 off the
students' network entirely so only Kibana is reachable.

- Simpler than A or B, and students still cannot write to the cluster
  *through Kibana* if the credential is read-only.
- Weaknesses: the shared credential is a shared credential; Kibana's
  saved-objects API would still be writable unless the proxy in Option B also
  covers it; and any student who finds a route to 9200 regains full cluster
  access.
- This option is only defensible with Option B's proxy rules layered on top.

### What this project has done

Only Mode 1. Loopback binding plus documentation. No classroom mode has been
invented, because choosing between A, B and C trades off security against
classroom friction and that trade-off is an owner's decision, not a technical
one. Enabling the secure stack without a plan for student access would lock
instructors out of the investigation flow the lab exists to teach.

## Related: encryption keys (audit H-3)

`docker-compose.yml` used to fall back to fixed `SIEM_*_ENCRYPTION_KEY` values
that were published in this repository. A value everyone can read protects
nothing, so the fallbacks are gone and the variables are required:

```yaml
- XPACK_SECURITY_ENCRYPTIONKEY=${SIEM_ENCRYPTION_KEY:?...}
```

Compose now stops with an explicit message when one is missing.
`scripts/ensure_lab_env.ps1`, called by both `setup.ps1` and `start_lab.ps1`,
generates three random keys into a git-ignored `.env` on first run, so a fresh
clone still starts with no manual step. Existing values are never overwritten,
and key material is never printed.

Rotating the keys invalidates encrypted saved objects, so re-import the
dashboard afterwards:

```powershell
python -m src.main import-dashboard
```

## Checklist before exposing this lab to a network

- [ ] Elasticsearch port not published to students (`9200` unreachable from a
      student machine)
- [ ] `xpack.security.enabled=true`, or a proxy that enforces read-only paths
- [ ] Kibana reachable only through that proxy or an authenticated route
- [ ] `SIEM_ENCRYPTION_KEY`, `SIEM_ESO_ENCRYPTION_KEY` and
      `SIEM_REPORTING_ENCRYPTION_KEY` set to real generated values
- [ ] `.env` is git-ignored and never committed
- [ ] Training-platform port 8080 bound deliberately, with the auth endpoints
      in use
- [ ] Mode 2 access decision recorded in writing before the session
