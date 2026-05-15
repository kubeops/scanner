# AGENTS.md

This file provides guidance to coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Repository purpose

Go module `kubeops.dev/scanner` — an aggregated Kubernetes API server that **exposes Docker image vulnerability scan results as native Kubernetes resources**. The scanner walks images referenced by workloads in the cluster, runs [trivy](https://github.com/aquasecurity/trivy) against them, and presents the findings as `scanner.appscode.com/v1alpha1` and `reports.appscode.com/v1alpha1` objects — so any tool that can query Kubernetes can read vulnerability data.

The produced binary is `scanner`. Long-running aggregated apiserver + scan workers.

## Architecture

- `cmd/scanner/` — entry point.
- `pkg/cmds/` — Cobra command tree.
- `apis/`:
  - `scanner/v1alpha1/` — image-scan request/result types.
  - `reports/v1alpha1/` — rolled-up scan-report types.
  - Each group has `register.go`, `install/`, `fuzzer/`, hand-written types, and generated `zz_generated.*.go`.
- `client/` — generated typed clientset.
- `crds/` — generated CRDs for both groups.
- `pkg/apiserver/` — aggregated apiserver config and lifecycle.
- `pkg/registry/`:
  - `scanner/` — `rest.Storage` for `scanner.appscode.com` resources.
  - `reports/` — `rest.Storage` for `reports.appscode.com` resources.
- `pkg/controllers/` — controllers that drive periodic image scanning (workload watcher → scan queue → trivy execution).
- `pkg/trivy/` — wraps the trivy binary/SDK.
- `pkg/backend/` — storage backends for scan results.
- `pkg/fileserver/` — exposes scan artifacts (raw trivy reports) via HTTP.
- `Dockerfile.in` (PROD, distroless), `Dockerfile.dbg` (debian), `Dockerfile.ubi` (Red Hat certified) — three image variants.
- `hack/`, `Makefile` — AppsCode build harness.
- `PROJECT` — Kubebuilder metadata.
- `DEVELOPMENT.md` — developer guide.
- `vendor/` — checked-in deps.

CRD API groups are `scanner.appscode.com` and `reports.appscode.com`.

## Common commands

All Make targets run inside `ghcr.io/appscode/golang-dev` — Docker must be running.

- `make ci` — CI pipeline.
- `make build` / `make all-build` — build host or all-platform binaries.
- `make gen` — regenerate clientset + manifests + openapi. Run after any change to `apis/**/*_types.go`.
- `make manifests` — regenerate CRDs only.
- `make clientset` — regenerate `client/` only.
- `make openapi` — regenerate OpenAPI definitions.
- `make fmt`, `make lint`, `make unit-tests` / `make test` — standard.
- `make verify` — `verify-gen verify-modules`; `go mod tidy && go mod vendor` must leave the tree clean.
- `make container` — build PROD, DBG, and UBI images.
- `make push` — push all three; `make docker-manifest` writes multi-arch manifests; `make release` is the full publish flow.
- `make push-to-kind` / `make deploy-to-kind` — load into Kind and Helm-install.
- `make install` / `make uninstall` / `make purge` — Helm install lifecycle.
- `make add-license` / `make check-license` — manage license headers.

Run a single Go test (requires a local Go toolchain):

```
go test ./pkg/controllers/... -run TestName -v
```

## Conventions

- Module path is `kubeops.dev/scanner` (vanity URL). Imports must use that.
- License: `LICENSE`. Sign off commits (`git commit -s`); contributions follow the DCO.
- Vendor directory is checked in — `go mod tidy && go mod vendor` must leave the tree clean (enforced by `verify-modules`).
- This is an **aggregated apiserver** — `pkg/registry/*` is the only persistence path. Don't add a parallel storage layer.
- Trivy is invoked via `pkg/trivy/`; isolate trivy version pinning there so upstream bumps are localized.
- Do not hand-edit `zz_generated.*.go`, anything under `client/`, or `crds/` — change `apis/<group>/v1alpha1/*_types.go` and re-run `make gen`.
- Two API groups: `scanner.appscode.com` (requests) and `reports.appscode.com` (rolled-up reports). Keep them in their own `apis/<group>/` directories.
- Three Dockerfiles, one binary — keep `Dockerfile.in`, `Dockerfile.dbg`, and `Dockerfile.ubi` in sync.
