[![Go Report Card](https://goreportcard.com/badge/kubeops.dev/scanner)](https://goreportcard.com/report/kubeops.dev/scanner)
[![Build Status](https://github.com/kubeops/scanner/workflows/CI/badge.svg)](https://github.com/kubeops/scanner/actions?workflow=CI)
[![Docker Pulls](https://img.shields.io/docker/pulls/appscode/scanner.svg)](https://hub.docker.com/r/appscode/scanner/)
[![Twitter](https://img.shields.io/twitter/follow/kubeops.svg?style=social&logo=twitter&label=Follow)](https://twitter.com/intent/follow?screen_name=Kubeops)

# scanner

Scanner is an [extended api server](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/) that reports Docker image scan results.

## Deploy into a Kubernetes Cluster

You can deploy `scanner` using Helm chart found [here](https://github.com/kubeops/installer/tree/master/charts/scanner).

```console
helm repo add appscode https://charts.appscode.com/stable/
helm repo update

helm install scanner appscode/scanner
```
