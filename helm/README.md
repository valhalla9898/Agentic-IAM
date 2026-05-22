This folder contains a starter Helm chart layout suggestion.

- `templates/` should include Deployment, Service, ConfigMap, Secret manifests.
- Use values.yaml to configure `image`, `replicaCount`, `resources`, and `env`.

This repo includes `k8s/` manifests as a minimal deployable example.
