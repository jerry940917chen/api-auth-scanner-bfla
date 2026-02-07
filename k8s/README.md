# Deploying to Kubernetes (k8s)

This directory contains standard Kubernetes manifests to deploy the API Auth Scanner environment.

## Prerequisites
*   A running Kubernetes cluster (Minikube, Kind, or remote).
*   `kubectl` installed and configured.
*   Container images built and available to the cluster.

## Deployment Steps

1.  **Build Images**:
    Ensure the local images are available (or push to a registry).
    ```bash
    docker build -t api-auth-scanner:latest .
    docker build -t api-auth-scanner-demo-api:latest ./demo_api
    ```
    *If using Minikube/Kind, verify how to load local images.*

2.  **Apply Manifests**:
    ```bash
    kubectl apply -f k8s/
    ```

3.  **Access Scanner**:
    The scanner service is exposed as a `NodePort` on port `30080`.
    *   **Minikube**: `minikube service scanner --url`
    *   **Localhost**: `http://localhost:30080` (if port forwarding or routed).

4.  **Run Scans**:
    You can port-forward the scanner to use the existing scripts:
    ```bash
    kubectl port-forward svc/scanner 8000:8000
    ```
    Then run:
    ```powershell
    ./scripts/demo_run.ps1
    ```
