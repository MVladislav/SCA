#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# Install wazuh-regex + its shared libraries into the project.
# No root required: downloads the wazuh-manager package and extracts the
# binary/libs without installing them system-wide.
# =============================================================================
set -euo pipefail

# Configurable package version (the wazuh manager version the SCA files match)
WAZUH_MANAGER_VERSION="${WAZUH_MANAGER_VERSION:-4.9.1-1}"

# If a binary already exists, let the user force a reinstall
if [[ -x ./wazuh-regex ]] && [[ "${1:-}" != "-f" && "${1:-}" != "--force" ]]; then
  echo "wazuh-regex already present. Use \"$0 --force\" to reinstall."
  exit 0
fi

URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/wazuh-manager_${WAZUH_MANAGER_VERSION}_amd64.deb"

echo "Downloading ${URL} ..."
wget -q -O ./wazuh-manager.deb "$URL"

echo "Extracting wazuh-manager package..."
mkdir -p ./wazuh-manager
dpkg-deb -R ./wazuh-manager.deb ./wazuh-manager

echo "Copying wazuh-regex binary..."
cp ./wazuh-manager/var/ossec/bin/wazuh-regex .

echo "Copying shared libraries..."
mkdir -p ./wazuh-lib
cp -r ./wazuh-manager/var/ossec/lib/* ./wazuh-lib/

echo "Cleaning up..."
chmod -R u+rwX ./wazuh-manager
rm -rf ./wazuh-manager ./wazuh-manager.deb
chmod u+x wazuh-regex

echo
echo "Done. wazuh-regex + wazuh-lib are ready."
echo "Version: ${WAZUH_MANAGER_VERSION}"
