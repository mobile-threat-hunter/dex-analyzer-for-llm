#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <output-path>" >&2
    exit 2
fi

output_path="$1"
ubuntu_mirror="${UBUNTU_MIRROR:-https://archive.ubuntu.com/ubuntu/}"
ubuntu_codename="${UBUNTU_CODENAME:-focal}"
ubuntu_arch="${UBUNTU_ARCH:-amd64}"
ubuntu_components="${UBUNTU_COMPONENTS:-main universe}"
package_name="${UBUNTU_LIBSTDCXX_DEV_PACKAGE:-libstdc++-10-dev}"

if [ -e "$output_path" ]; then
    echo "error: output path already exists: $output_path" >&2
    exit 1
fi

if ! command -v xz >/dev/null 2>&1; then
    echo "error: xz is required to read Ubuntu package indexes" >&2
    exit 1
fi

download() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$output" "$url"
    else
        echo "error: curl or wget is required" >&2
        exit 1
    fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

find_package_filename() {
    local suite="$1"
    local component="$2"
    local packages_xz="$3"
    local url="${ubuntu_mirror%/}/dists/$suite/$component/binary-$ubuntu_arch/Packages.xz"

    if ! download "$url" "$packages_xz" 2>/dev/null; then
        return 1
    fi

    xz -dc "$packages_xz" | awk -v package_name="$package_name" '
        BEGIN { RS = ""; FS = "\n" }
        {
            package = "";
            filename = "";
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^Package: /) {
                    package = substr($i, 10);
                } else if ($i ~ /^Filename: /) {
                    filename = substr($i, 11);
                }
            }
            if (package == package_name && filename != "") {
                print filename;
                exit;
            }
        }
    '
}

package_filename=""
for suite in "$ubuntu_codename-updates" "$ubuntu_codename-security" "$ubuntu_codename"; do
    for component in $ubuntu_components; do
        candidate="$(find_package_filename "$suite" "$component" "$tmpdir/Packages.xz" || true)"
        if [ -n "$candidate" ]; then
            package_filename="$candidate"
            break 2
        fi
    done
done

if [ -z "$package_filename" ]; then
    echo "error: cannot find $package_name in $ubuntu_codename repositories" >&2
    exit 1
fi

mkdir -p "$(dirname "$output_path")"
download "${ubuntu_mirror%/}/$package_filename" "$tmpdir/$package_name.deb"
mkdir -p "$output_path"
dpkg-deb -x "$tmpdir/$package_name.deb" "$output_path"

if [ ! -d "$output_path/usr/include/c++/10" ] || \
   [ ! -d "$output_path/usr/include/x86_64-linux-gnu/c++/10" ]; then
    echo "error: $package_name did not provide the expected GCC 10 headers" >&2
    exit 1
fi
