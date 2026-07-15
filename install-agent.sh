#!/usr/bin/env bash
# Install the Sigil EDR agent (sigil-agent) from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/maxyrrr-sh/sigil-siem/main/install-agent.sh | bash
#
# Supports Linux (.deb, via apt/dpkg) and macOS (tar.gz -> /usr/local/bin).
# Windows users: grab the .zip release asset manually (see docs/EDR.md).
#
# Env vars:
#   SIGIL_AGENT_TAG    pin to a specific release tag instead of the newest
#                      matching release (e.g. agent-nightly-abc1234)
#   GITHUB_TOKEN       optional, raises the GitHub API rate limit

set -euo pipefail

REPO="maxyrrr-sh/sigil-siem"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="sigil-agent"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

need curl

os="$(uname -s)"
arch="$(uname -m)"

if [ -n "${SIGIL_AGENT_TAG:-}" ]; then
  api_url="https://api.github.com/repos/${REPO}/releases/tags/${SIGIL_AGENT_TAG}"
else
  api_url="https://api.github.com/repos/${REPO}/releases"
fi

as_root() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  else
    need sudo
    sudo "$@"
  fi
}

curl_gh() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$@"
  else
    curl -fsSL "$@"
  fi
}

# First browser_download_url whose filename matches a grep -E pattern.
# Releases (and their assets) are returned newest-first by the GitHub API.
asset_url() {
  local pattern="$1"
  curl_gh "$api_url" \
    | grep -o '"browser_download_url": *"[^"]*"' \
    | cut -d'"' -f4 \
    | grep -E "$pattern" \
    | head -n1
}

install_linux_deb() {
  local url
  url="$(asset_url '/sigil-agent\.deb$')"
  [ -n "$url" ] || die "no sigil-agent .deb release asset found (check https://github.com/${REPO}/releases)"

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  log "downloading $(basename "$url")"
  curl -fsSL -o "$tmp/sigil-agent.deb" "$url"

  log "installing via apt/dpkg (may prompt for your sudo password)"
  if command -v apt-get >/dev/null 2>&1; then
    as_root apt-get install -y "$tmp/sigil-agent.deb"
  else
    as_root dpkg -i "$tmp/sigil-agent.deb"
  fi
}

install_macos() {
  local url
  url="$(asset_url "sigil-agent-macos-${arch}\\.tar\\.gz$")"
  if [ -z "$url" ]; then
    warn "no build for arch '${arch}'; falling back to whatever macOS build is published"
    url="$(asset_url 'sigil-agent-macos-.*\.tar\.gz$')"
  fi
  [ -n "$url" ] || die "no sigil-agent macOS release asset found (check https://github.com/${REPO}/releases)"

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  log "downloading $(basename "$url")"
  curl -fsSL -o "$tmp/sigil-agent.tar.gz" "$url"
  tar xzf "$tmp/sigil-agent.tar.gz" -C "$tmp"
  [ -f "$tmp/${BIN_NAME}" ] || die "archive did not contain a '${BIN_NAME}' binary"

  xattr -d com.apple.quarantine "$tmp/${BIN_NAME}" 2>/dev/null || true
  chmod +x "$tmp/${BIN_NAME}"

  log "installing to ${INSTALL_DIR}/${BIN_NAME} (may prompt for your sudo password)"
  if [ -w "$INSTALL_DIR" ]; then
    install -m 0755 "$tmp/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  else
    as_root install -m 0755 "$tmp/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  fi
}

case "$os" in
  Linux)
    command -v dpkg >/dev/null 2>&1 \
      || die "this installer only supports Debian/Ubuntu (dpkg) on Linux; see https://github.com/${REPO}/releases for other formats"
    install_linux_deb
    ;;
  Darwin)
    need tar
    install_macos
    ;;
  *)
    die "unsupported OS '${os}'; Windows users should download the .zip from https://github.com/${REPO}/releases"
    ;;
esac

log "installed: $(command -v ${BIN_NAME} || echo "${INSTALL_DIR}/${BIN_NAME}")"
log "run '${BIN_NAME} --help' to get started (see docs/EDR.md for enrollment)"
