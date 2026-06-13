#!/bin/zsh
# AUR Security Scanner - Zsh Integration
#
# Source this file in your ~/.zshrc:
#   source /usr/share/aur-scan/integration.zsh
#
# Or for manual installation:
#   source /path/to/integration.zsh

# Configuration (can be overridden before sourcing)
: "${AUR_SCAN_ENABLED:=1}"
: "${AUR_SCAN_SEVERITY:=high}"
: "${AUR_SCAN_INTERACTIVE:=1}"

# Check if aur-scan is available
if ! command -v aur-scan &> /dev/null; then
    print -P "%F{yellow}Warning: aur-scan not found in PATH. AUR security scanning disabled.%f" >&2
    return 0
fi

# Wrapper function for paru
paru() {
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command paru "$@"
        return
    fi

    # Check if this is an install operation
    local is_sync=0
    local -a packages

    for arg in "$@"; do
        case "$arg" in
            -S*|--sync) is_sync=1 ;;
            -Q*|--query) is_sync=0; break ;;
            -s*|--search) is_sync=0; break ;;
            -*) ;;
            *) packages+=("$arg") ;;
        esac
    done

    if [[ "$is_sync" == "1" ]] && [[ ${#packages[@]} -gt 0 ]]; then
        # Race-free mode: scan the exact bytes, then build them in dep order
        # (replaces the helper for the named AUR packages). Opt in with
        # AUR_SCAN_MODE=install.
        if [[ "${AUR_SCAN_MODE:-gate}" == "install" ]]; then
            aur-scan install "${packages[@]}"
            return $?
        fi

        print -P "%F{cyan}AUR Security Scanner:%f Pre-checking packages..."

        local -a scan_args
        scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")

        if ! aur-scan check "${scan_args[@]}" "${packages[@]}"; then
            print -P "%F{yellow}Scan failed or user aborted. Not proceeding with paru.%f"
            return 1
        fi
    fi

    command paru "$@"
}

# Wrapper function for yay
yay() {
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command yay "$@"
        return
    fi

    # Check if this is an install operation
    local is_sync=0
    local -a packages

    for arg in "$@"; do
        case "$arg" in
            -S*|--sync) is_sync=1 ;;
            -Q*|--query) is_sync=0; break ;;
            -s*|--search) is_sync=0; break ;;
            -*) ;;
            *) packages+=("$arg") ;;
        esac
    done

    if [[ "$is_sync" == "1" ]] && [[ ${#packages[@]} -gt 0 ]]; then
        # Race-free mode: scan the exact bytes, then build them in dep order
        # (replaces the helper for the named AUR packages). Opt in with
        # AUR_SCAN_MODE=install.
        if [[ "${AUR_SCAN_MODE:-gate}" == "install" ]]; then
            aur-scan install "${packages[@]}"
            return $?
        fi

        print -P "%F{cyan}AUR Security Scanner:%f Pre-checking packages..."

        local -a scan_args
        scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")

        if ! aur-scan check "${scan_args[@]}" "${packages[@]}"; then
            print -P "%F{yellow}Scan failed or user aborted. Not proceeding with yay.%f"
            return 1
        fi
    fi

    command yay "$@"
}

# Convenience alias to temporarily disable scanning
alias paru-unsafe='AUR_SCAN_ENABLED=0 paru'
alias yay-unsafe='AUR_SCAN_ENABLED=0 yay'

# Function to scan all installed AUR packages
aur-scan-system() {
    aur-scan system "$@"
}

print -P "%F{green}AUR Security Scanner:%f Shell integration loaded."
print -P "  - paru and yay auto-scan before installing AUR packages"
print -P "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)"
print -P "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper"
print -P "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
print -P "  - Set AUR_SCAN_ENABLED=0 to disable globally"
