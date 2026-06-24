# Scanner Architecture

`kubeops.dev/scanner` is an **aggregated Kubernetes API server** that exposes Docker image
vulnerability scans as **native Kubernetes resources**. It walks the images referenced by workloads
in the cluster, runs [trivy](https://github.com/aquasecurity/trivy) against them, and serves the
findings as API objects — so anything that can talk to the Kubernetes API can read vulnerability
data (`kubectl`, dashboards, policy engines, etc.).

The produced binary is `scanner`: a long-running aggregated apiserver **plus** scan controllers.

---

## 1. What you interact with — the API

Two API groups, served by this apiserver:

- `scanner.appscode.com/v1alpha1` — **requests**: you ask for an image to be scanned.
- `reports.appscode.com/v1alpha1` — **rolled-up reports**: the results.

| Resource | Short name | Meaning |
|----------|-----------|---------|
| `ImageScanRequest` | `isrq` | "Scan this image." You create it; the controller drives it. |
| `ImageScanReport` | `isrp` | The scan result for one image (created by the controller/job). |
| `Vulnerability` | `cve` | A single CVE, queryable on its own. |

All three are full `genericregistry.Store` resources with a `/status` subresource, so **every verb
is allowed** (subject to RBAC): `create, get, list, watch, update, patch, delete, deletecollection`.
In normal use you only *create* an `ImageScanRequest`; the controller fills its status and produces
the `ImageScanReport`. Reports are cluster-scoped and named by a hash of the image ref.

---

## 2. Runtime — the `scanner-0` pod (3 containers, 1 init)

The pod is a self-contained apiserver **plus its own datastore** — there is no external etcd.

```
 PVC (storage-scanner-0)  ──►  /var/data  (db.sqlite + /files trivy DB mirror)
        ▲                          ▲                    ▲
        │                          │                    │
  ┌─────┴──────┐            ┌──────┴──────┐      ┌──────┴───────────────────┐
  │ init-db    │  creates   │ kine        │ etcd │ app (this repo's binary) │
  │ (kine img) │ db.sqlite  │ etcd⇄sqlite │ API  │ aggregated apiserver     │
  │  one-shot  │            │ :2379 (TLS) │◄─────│ + scan controllers       │
  └────────────┘            └─────────────┘      │ + fileserver :8080       │
                                                 │ API :8443                │
                                                 └──────────────────────────┘
```

| Component | Image | Role |
|-----------|-------|------|
| `init-db` (init) | `rancher/kine` | `touch /var/data/db.sqlite` if missing — seeds the datastore. |
| `kine` (sidecar) | `rancher/kine` | Speaks the **etcd v3 API on :2379** but stores everything in SQLite — a lightweight, single-file etcd replacement. |
| `app` (main) | `ghcr.io/appscode/scanner` | The apiserver + controllers. Persists CRs by pointing `--etcd-servers=https://127.0.0.1:2379` at the kine sidecar. |

So the apiserver *thinks* it talks to etcd; really it's kine → one SQLite file on the PVC. Because
the file lives on the PVC, all scan data (and the cached trivy DB) survives pod restarts.

---

## 3. Code layout

- `cmd/scanner/`, `pkg/cmds/` — entry point + Cobra tree (`run`, `backend`, `upload-report`, `download`, `scan`).
- `apis/scanner/v1alpha1/`, `apis/reports/v1alpha1/` — CR types (hand-written + `zz_generated.*`).
- `pkg/apiserver/` — aggregated apiserver config; wires up the controllers (`apiserver.go:229`).
- `pkg/registry/` — `rest.Storage` per resource. **The only persistence path** — don't add another.
- `pkg/controllers/scanrequest/`, `scanreport/` — the reconcilers that drive scanning & GC.
- `pkg/backend/` — NATS + blob-store client/worker for the public-image scan path (AppsCode SaaS side).
- `pkg/fileserver/` — serves the cached trivy DB tar over `:8080` off the PVC.

> Generated code (`zz_generated.*`, `client/`, `crds/`) is off-limits — edit `apis/**/*_types.go`
> and run `make gen`.

---

## 4. End-to-end flow — from request to report

The `scanrequest` reconciler (`pkg/controllers/scanrequest/reconciler.go`) branches on **image
visibility**, which it learns via a NATS round-trip to the backend (`backend.GetResponseFromBackend`).
The key split: **only private images spawn an in-cluster trivy Job**; public images are scanned by
the (SaaS or self-hosted) backend and merely fetched.

```
ImageScanRequest created
        │
   Reconcile ──► GetResponseFromBackend (NATS) ──► visibility?
        │
        ├─ Unknown  ─► status = Failed
        │
        ├─ Public   ─► backend scans (online trivy), report stored in S3
        │              ─► EnsureScanReport ─► status = Current      (no in-cluster Job)
        │
        └─ Private  ─► copy SA + imagePullSecrets into workspace ns
                        │
                        └─► create batch.Job (GenerateName: scan-image) in workspace ns
                                  │
                          ┌───────┴──────── shared emptyDir at /root/.cache ─────────┐
                          │ init: trivy   →  cp trivy binary  ("tv")                 │
                          │ init: trivydb →  extract.sh, lay down trivy DB           │
                          │ init: scanner →  ./tv rootfs --offline-scan → report.json│
                          │ main: uploader→  scanner upload-report → ImageScanReport │
                          └──────────────────────────────────────────────────────────┘
                                  │
                       Job watch re-enqueues the request
                                  │
                       doStuffsForPrivateImage ─► resolve digest, link report
                                  ─► Succeeded → Current  |  Failed → Failed
```

Key files: visibility branch `reconciler.go:184` (`scan()`), Job spec `private.go:51`
(`ensureJob`), report write-back `pkg/cmds/upload-report.go:59`. Finished requests are garbage
collected after `--scan-request-ttl-after-finished` (`reconciler.go:101`).

### The private-image Job is a 3-init pipeline + 1 container

All four containers share an `emptyDir` mounted at `/root/.cache`, passing artifacts down the line:

1. **init `trivy`** — copies the trivy binary into the shared volume as `tv`.
2. **init `trivydb`** — runs `extract.sh` (from the cacher image) to lay the trivy DB into the volume.
3. **init `scanner`** — *the target image itself* is used as this container, so trivy scans its
   rootfs offline (`trivy rootfs --skip-db-update --offline-scan / > report.json`) with no extra
   pull or registry auth.
4. **main `uploader`** — runs `scanner upload-report`, which parses `report.json` + `trivy.json`
   and writes an `ImageScanReport` straight into the apiserver (→ kine → SQLite).

---

## 5. NATS — external (default) vs local

The in-cluster side is only a NATS **client**; the heavy lifting (scanning public images + the
shared report cache) lives behind NATS. Two subjects (`backend/stream.go:98`):

- `scanner.report` — request/reply: "give me the report for image X".
- `scanner.queue.scan` — JetStream work-queue: "scan image X" (durable, 30-day retention).

```
 scanner-0 (app = client)            NATS                 backend (`scanner backend` cmd)
   scan() ─ Request "scanner.report" ─►  ── QueueSubscribe ─► handler: private? S3 cached?
                                         ◄─ reply visibility+report ─
                                         ─ on miss: pub "scanner.queue.scan" ─►
                                                            workers: trivy image → S3 cache
```

- **External (default)** `this-is-nats.appscode.ninja:4222`, AppsCode-hosted — public images are
  scanned SaaS-side (that's *why* they need no in-cluster Job). When **licensed**, the client rides
  the licensed audit-NATS connection (`apiserver.go:210`), so `--nats-addr` can be left empty — this
  is the `scanner-0` setup.
- **Local / air-gapped** — run your own NATS + the `scanner backend` worker (`cmds/backend.go`) and
  point `--nats-addr` at it. `DeploymentMode=Production` (cross-account `scanner.report.*` subjects)
  kicks in only when the NATS host is a hosted appscode domain (`stream.go:177`).

---

## 6. Trivy DB — seeded by a CronJob, used by every job

Trivy runs **fully offline** (`--skip-db-update --offline-scan`); the DB is supplied locally:

1. **Baked into `--trivydb-cacher-image`** — not fetched from the internet at scan time. With
   `imagePullPolicy: IfNotPresent`, the node pulls that image (and its embedded DB) **once**.
2. **Seeded into the PVC fileserver by `CronJob/scanner-trivydb-cacher`** (in the scanner's namespace,
   from the installer/Helm chart — *not* this repo). It runs `update-trivydb.sh` from the
   `--trivydb-cacher-image` and **POSTs the DB tar + `metadata.json` to the fileserver**
   (`FILESERVER_ADDR=https://scanner.<ns>.svc`), which writes them to `/var/data/files/trivy/`
   (`fileserver.FileSave`). Schedule is `0 */6 * * *` (every 6h).
3. **Extracted per job** — the scan Job's `trivydb` init container also runs `extract.sh` (same cacher
   image, with `FILESERVER_ADDR`) to lay the DB into the job's shared volume so the `scanner` init
   container can read it offline.

> **The metadata file gates *all* reconciling.** Both reconcilers return early — silently, with a
> 1-minute requeue and **no log line** — until `/var/data/files/trivy/metadata.json` exists
> (`reconciler.go:78`, `scanreport/controller.go:42`); that file's `UpdatedAt` drives staleness checks.
> Because the file lives on the PVC it survives pod restarts, **but a fresh/empty PVC (or a wiped
> datastore) leaves it absent** — and scanning is then **dead-locked until the cacher CronJob next
> fires** (up to 6h away). The scan Job's own `extract.sh` upload can't bootstrap this, because no Job
> is ever created while the gate is closed (chicken-and-egg). Recovery: manually run the cacher —
> `kubectl create job -n <ns> --from=cronjob/scanner-trivydb-cacher trivydb-cacher-now`. See `plan.md`.

**When does the DB update / a report get re-scanned?** There is **no runtime DB auto-update
in-cluster** — the DB advances only when you bump the `--trivydb-cacher-image` tag and the new image
is pulled. (The SaaS backend runs `trivy image` online, so *its* DB follows trivy's own cadence.)
Reports are then re-evaluated by comparing timestamps:

- `ImageScanReportReconciler` (`scanreport/controller.go:62`) compares the live DB time to each
  report's stored DB time → newer DB ⇒ `Outdated`, else `Current`.
- `Outdated` reports older than `--scan-report-ttl-after-outdated` (168h) are deleted; a SaaS S3
  report older than `TrivyRefreshPeriod` (6h) with a stale DB is treated as missing → triggers a
  re-scan.

---

## 7. Key `run` flags (reference)

| Group | Flags | Notes |
|-------|-------|-------|
| apiserver plumbing | `--secure-port`, `--tls-*`, `--etcd-*`, `--audit-log-path` | required; `--etcd-servers` points at the kine sidecar |
| scan images | `--scanner-image`, `--trivydb-cacher-image`, `--trivy-image`, `--workspace-namespace` | required (except `--trivy-image`, defaults `aquasec/trivy`) |
| fileserver | `--file-server-addr`, `--file-server-files-dir` (`/var/data/files`) | source of the trivy DB tar fetched by jobs |
| backend / NATS | `--nats-addr` | default `this-is-nats.appscode.ninja:4222`; may be empty **only when licensed** (uses the audit NATS client) |
| GC TTLs | `--scan-request-ttl-after-finished` (def 12h), `--scan-report-ttl-after-outdated` (def 168h) | optional |
| dead flag | `--scan-public-image-incluster` | declared but **not wired anywhere** in current source — no effect |
