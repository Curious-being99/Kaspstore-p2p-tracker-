# 🌐 Decentralized Release Configuration Guide

This repository is configured to automatically build and mirror itself across the decentralized web whenever you push to the `main` branch.

## 🛠️ GitHub Secrets Setup

To make the automation work, you must add the following **Secrets** to your GitHub repository settings (`Settings > Secrets and variables > Actions`):

### 1. IPFS (via Pinata)
*   **`PINATA_API_KEY`**: Your Pinata API Key.
*   **`PINATA_API_SECRET`**: Your Pinata API Secret.
*   *Purpose*: Pins your dashboard to IPFS so it stays online 24/7.

### 2. Radicle (P2P Git)
*   **`RAD_PASSPHRASE`**: Your Radicle identity passphrase.
*   **`RAD_PRIVATE_KEY`**: Your Radicle private key (formatted for the action).
*   **`RAD_PROJECT_ID`**: The Radicle Project ID (`rad:...`).
*   *Purpose*: Mirrors your code to the Radicle P2P network, ensuring it's uncensorable.

### 3. Application Security
*   **`TRACKER_API_KEY`**: The key required to interact with your tracker API.
*   *Purpose*: Injected into the built dashboard so it can talk to your server securely.

## 🚀 How it works

1.  **Push**: You push code to GitHub.
2.  **Build**: GitHub Actions builds the React Dashboard.
3.  **Pin**: The `ipshipyard/ipfs-deploy-action` uploads the build to IPFS and pins it on Pinata.
4.  **Mirror**: The `radicle-dev/github-action` pushes your latest commit to a Radicle seed node.
5.  **Result**: You get an immutable IPFS gateway link in your Action logs!

## 🔗 Accessing your Dashboard
Once the action completes, you can view your dashboard at:
`https://gateway.pinata.cloud/ipfs/<YOUR_CID>`
