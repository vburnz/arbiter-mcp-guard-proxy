#!/bin/sh
# Arbiter installer — downloads a pre-built binary from GitHub Releases.
# Usage: curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
#
# Environment variables:
#   ARBITER_VERSION      — version to install (default: latest)
#   ARBITER_INSTALL_DIR  — installation directory (default: ~/.arbiter/bin)
#   ARBITER_LIBC         — force libc variant: "musl" (default on Linux) or "gnu"

set -eu

REPO="cyrenei/arbiter-mcp-firewall"
INSTALL_DIR="${ARBITER_INSTALL_DIR:-$HOME/.arbiter/bin}"

# Minisign public key for signature verification.
MINISIGN_PUBKEY="RWSvUzuT3bMn1BIHBaqPJNRl7xogZUHrz+9zDymIZaewqWvZvJPI+3QR"

main() {
    need_cmd curl
    need_cmd tar
    need_cmd uname

    local _os _arch _libc _target _version _url _checksum_url

    _os="$(detect_os)"
    _arch="$(detect_arch)"

    if [ "$_os" = "linux" ]; then
        _libc="${ARBITER_LIBC:-$(detect_libc)}"
        if [ "$_libc" = "gnu" ]; then
            _target="linux-gnu-${_arch}"
        else
            _target="linux-${_arch}"
        fi
    else
        _target="${_os}-${_arch}"
    fi

    printf "Detected platform: %s\n" "$_target"

    _version="$(resolve_version)"
    printf "Installing Arbiter %s\n" "$_version"

    _url="https://github.com/${REPO}/releases/download/${_version}/arbiter-${_target}.tar.gz"
    _checksum_url="https://github.com/${REPO}/releases/download/${_version}/checksums-sha256.txt"

    _tmpdir="$(mktemp -d)"
    trap 'rm -rf "$_tmpdir"' EXIT

    printf "Downloading arbiter-%s.tar.gz...\n" "$_target"
    curl -sSfL "$_url" -o "$_tmpdir/arbiter.tar.gz" || {
        err "download failed — check that release ${_version} exists at https://github.com/${REPO}/releases"
    }

    printf "Downloading checksums...\n"
    curl -sSfL "$_checksum_url" -o "$_tmpdir/checksums-sha256.txt" || {
        err "checksum download failed"
    }

    printf "Verifying SHA256 checksum...\n"
    verify_checksum "$_tmpdir" "arbiter-${_target}.tar.gz"

    # Signature verification (opportunistic — requires minisign)
    verify_signature "$_tmpdir" "arbiter-${_target}.tar.gz" "$_version"

    printf "Extracting...\n"
    tar xzf "$_tmpdir/arbiter.tar.gz" -C "$_tmpdir"

    # Find binaries inside the extracted directory
    local _bin="" _ctl=""
    for _candidate in "$_tmpdir"/*/arbiter "$_tmpdir"/arbiter; do
        if [ -f "$_candidate" ]; then
            _bin="$_candidate"
            break
        fi
    done
    if [ -z "$_bin" ]; then
        err "could not find arbiter binary in archive"
    fi
    # Look for arbiter-ctl alongside the main binary
    _ctl="$(dirname "$_bin")/arbiter-ctl"

    mkdir -p "$INSTALL_DIR"
    cp "$_bin" "$INSTALL_DIR/arbiter"
    chmod +x "$INSTALL_DIR/arbiter"

    if [ -f "$_ctl" ]; then
        cp "$_ctl" "$INSTALL_DIR/arbiter-ctl"
        chmod +x "$INSTALL_DIR/arbiter-ctl"
        printf "\nArbiter %s installed to %s (arbiter + arbiter-ctl)\n" "$_version" "$INSTALL_DIR"
    else
        printf "\nArbiter %s installed to %s/arbiter\n" "$_version" "$INSTALL_DIR"
    fi

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        local _line="export PATH=\"${INSTALL_DIR}:\$PATH\""
        local _profile
        _profile="$(detect_profile)"

        if [ -n "$_profile" ] && [ -t 0 ]; then
            printf "\n%s is not in your PATH.\n" "$INSTALL_DIR"
            printf "Add it to %s? [y/N] " "$_profile"
            read -r _answer </dev/tty
            case "$_answer" in
                [yY]|[yY][eE][sS])
                    printf '\n# Added by Arbiter installer\n%s\n' "$_line" >> "$_profile"
                    printf "Added to %s — restart your shell or run:\n" "$_profile"
                    printf "  source %s\n" "$_profile"
                    ;;
                *)
                    printf "\nTo add manually:\n  %s\n" "$_line"
                    printf "Add that line to %s to persist across sessions.\n" "$_profile"
                    ;;
            esac
        else
            printf "\nAdd Arbiter to your PATH for this session:\n"
            printf "  %s\n" "$_line"
            printf "\nTo persist across sessions, add that line to your shell profile (~/.bashrc, ~/.zshrc, etc.)\n"
        fi
    fi

    printf "\nVerify: arbiter --version\n"

    # Offer to run the configuration wizard.
    offer_configure
}

offer_configure() {
    if [ ! -t 0 ]; then
        printf "\nTo generate a config file, run:\n"
        printf "  curl -sSf https://raw.githubusercontent.com/${REPO}/main/configure.sh | sh\n\n"
        return
    fi

    printf "\n"
    printf "Would you like to generate an arbiter.toml config file now? [y/N] "
    read -r _answer </dev/tty
    case "$_answer" in
        [yY]|[yY][eE][sS])
            local _configure_url="https://raw.githubusercontent.com/${REPO}/main/configure.sh"
            local _configure_tmp
            _configure_tmp="$(mktemp)"
            printf "Downloading configuration wizard...\n"
            if curl -sSfL "$_configure_url" -o "$_configure_tmp" 2>/dev/null; then
                sh "$_configure_tmp"
                rm -f "$_configure_tmp"
            else
                printf "Could not download configure.sh. You can run it manually:\n"
                printf "  curl -sSf %s | sh\n" "$_configure_url"
                rm -f "$_configure_tmp"
            fi
            ;;
        *)
            printf "\nTo configure later:\n"
            printf "  curl -sSf https://raw.githubusercontent.com/${REPO}/main/configure.sh | sh\n"
            printf "\nOr copy and edit the example config:\n"
            printf "  curl -sSfL https://raw.githubusercontent.com/${REPO}/main/arbiter.example.toml -o arbiter.toml\n"
            printf "\n"
            ;;
    esac
}

detect_os() {
    local _uname
    _uname="$(uname -s)"
    case "$_uname" in
        Linux)  echo "linux" ;;
        Darwin) echo "macos" ;;
        *)      err "unsupported OS: $_uname — Arbiter provides binaries for Linux and macOS" ;;
    esac
}

detect_arch() {
    local _uname
    _uname="$(uname -m)"
    case "$_uname" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              err "unsupported architecture: $_uname — Arbiter provides binaries for amd64 and arm64" ;;
    esac
}

detect_libc() {
    # Detect whether the system uses musl or glibc.
    # Default to musl (static binary works everywhere).
    if ldd --version 2>&1 | grep -qi musl; then
        echo "musl"
    elif [ -f /lib/ld-musl-x86_64.so.1 ] || [ -f /lib/ld-musl-aarch64.so.1 ]; then
        echo "musl"
    else
        # glibc system — still default to musl (static, more portable)
        echo "musl"
    fi
}

resolve_version() {
    if [ -n "${ARBITER_VERSION:-}" ]; then
        echo "$ARBITER_VERSION"
        return
    fi
    # Fetch latest release tag via GitHub API redirect
    local _location
    _location="$(curl -sSf -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest")" || {
        err "could not determine latest version — set ARBITER_VERSION explicitly or check https://github.com/${REPO}/releases"
    }
    # Extract tag from redirect URL: https://github.com/.../releases/tag/v0.5.0 → v0.5.0
    local _tag="${_location##*/}"
    if [ -z "$_tag" ]; then
        err "could not determine latest version — no releases found. Set ARBITER_VERSION explicitly or check https://github.com/${REPO}/releases"
    fi
    echo "$_tag"
}

verify_checksum() {
    local _dir="$1" _filename="$2"
    local _expected _actual

    _expected="$(grep "$_filename" "$_dir/checksums-sha256.txt" | awk '{print $1}')"
    if [ -z "$_expected" ]; then
        err "no checksum found for $_filename in checksums-sha256.txt"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        _actual="$(sha256sum "$_dir/arbiter.tar.gz" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        _actual="$(shasum -a 256 "$_dir/arbiter.tar.gz" | awk '{print $1}')"
    else
        err "no sha256sum or shasum found — cannot verify checksum"
    fi

    if [ "$_expected" != "$_actual" ]; then
        err "checksum mismatch!
  expected: $_expected
  actual:   $_actual
The downloaded file may be corrupted or tampered with. Aborting."
    fi

    printf "Checksum verified: %s\n" "$_actual"
}

verify_signature() {
    local _dir="$1" _filename="$2" _version="$3"
    local _sig_url="https://github.com/${REPO}/releases/download/${_version}/${_filename}.minisig"

    if command -v minisign >/dev/null 2>&1; then
        printf "Downloading signature...\n"
        if curl -sSfL "$_sig_url" -o "$_dir/arbiter.tar.gz.minisig" 2>/dev/null; then
            if minisign -Vm "$_dir/arbiter.tar.gz" -P "$MINISIGN_PUBKEY" -x "$_dir/arbiter.tar.gz.minisig" 2>/dev/null; then
                printf "Signature verified (minisign)\n"
            else
                err "signature verification failed! The binary may have been tampered with."
            fi
        else
            printf "WARNING: this release is unsigned — no signature file found. Verify provenance manually.\n" >&2
        fi
    else
        printf "WARNING: minisign not installed — cannot verify release signature.\n" >&2
        printf "  Install it: https://jedisct1.github.io/minisign/\n" >&2
    fi
}

detect_profile() {
    # Return the most likely shell profile for the current user
    local _shell
    _shell="$(basename "${SHELL:-/bin/sh}")"
    case "$_shell" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                echo "$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.profile"
            fi
            ;;
        *)    echo "$HOME/.profile" ;;
    esac
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "required command not found: $1"
    fi
}

err() {
    printf "error: %s\n" "$1" >&2
    exit 1
}

main "$@"
