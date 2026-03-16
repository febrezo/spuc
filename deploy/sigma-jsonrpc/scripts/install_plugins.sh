#!/usr/bin/env bash
# install_plugins.sh
#
# Installs sigma-cli and a curated set of pySigma backends/pipelines.
# Each package is installed individually so a single failure does not
# abort the entire build.
#
# After installation, `sigma plugin list` is run to confirm what is
# actually available.

set -euo pipefail

PIP="python3 -m pip install --no-cache-dir --break-system-packages"

echo "=== Installing sigma-cli ==="
$PIP sigma-cli

echo ""
echo "=== Installing pySigma backends ==="

# Confirmed real packages from the pySigma ecosystem (PyPI).
# In order of approximate popularity/usefulness.
BACKENDS=(
  pysigma-backend-splunk
  pysigma-backend-elasticsearch
  pysigma-backend-opensearch
  pysigma-backend-microsoft365defender
  pysigma-backend-crowdstrike
  pysigma-backend-loki
  pysigma-backend-secops
  pysigma-backend-chronicle
  pysigma-backend-insightidr
  pysigma-backend-qradar
  pysigma-backend-sentinelone
  pysigma-backend-carbonblack
)

for pkg in "${BACKENDS[@]}"; do
  if $PIP "$pkg" 2>/dev/null; then
    echo "  [ok] $pkg"
  else
    echo "  [skip] $pkg (not available or incompatible)"
  fi
done

echo ""
echo "=== Installing pySigma pipelines ==="

PIPELINES=(
  pysigma-pipeline-windows
  pysigma-pipeline-crowdstrike
  pysigma-pipeline-sysmon
  pysigma-pipeline-sentinelone
)

for pkg in "${PIPELINES[@]}"; do
  if $PIP "$pkg" 2>/dev/null; then
    echo "  [ok] $pkg"
  else
    echo "  [skip] $pkg (not available or incompatible)"
  fi
done

echo ""
echo "=== sigma plugin list ==="
sigma plugin list || echo "(sigma plugin list failed – check logs)"

echo ""
echo "=== Plugin installation complete ==="
