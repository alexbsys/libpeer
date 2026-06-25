#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential cmake ninja-build git coturn
echo "Optional: install Docker Desktop with WSL integration for containerized coturn."
