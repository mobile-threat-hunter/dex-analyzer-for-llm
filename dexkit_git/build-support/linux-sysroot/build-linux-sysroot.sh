#!/usr/bin/env bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <sysroot-path>" >&2
    exit 2
fi

__SysrootDir="$1"
__UbuntuRepo="${UBUNTU_MIRROR:-http://archive.ubuntu.com/ubuntu/}"
__CodeName="${UBUNTU_CODENAME:-focal}"
__Components="${UBUNTU_COMPONENTS:-main universe}"

if [ "${UBUNTU_EXTRA_PACKAGES+x}" ]; then
    __Packages="$UBUNTU_EXTRA_PACKAGES"
else
    __Packages=""
fi

if [ -e "$__SysrootDir" ]; then
    echo "error: sysroot path already exists: $__SysrootDir" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script must be run as root" >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y debootstrap ubuntu-keyring ca-certificates gnupg xz-utils
elif command -v debootstrap >/dev/null 2>&1; then
    :
else
    echo "error: debootstrap is required" >&2
    exit 1
fi

mkdir -p "$(dirname "$__SysrootDir")"

debootstrap \
    --variant=minbase \
    --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
    --force-check-gpg \
    --arch amd64 \
    "$__CodeName" \
    "$__SysrootDir" \
    "$__UbuntuRepo"

rm -f "$__SysrootDir/etc/apt/sources.list"
rm -rf "$__SysrootDir/etc/apt/sources.list.d"
mkdir -p "$__SysrootDir/etc/apt/sources.list.d"

cat <<EOF > "$__SysrootDir/etc/apt/sources.list.d/$__CodeName.list"
deb $__UbuntuRepo $__CodeName $__Components
deb $__UbuntuRepo $__CodeName-updates $__Components
deb $__UbuntuRepo $__CodeName-security $__Components
deb $__UbuntuRepo $__CodeName-backports $__Components
EOF

chroot "$__SysrootDir" apt-get update
chroot "$__SysrootDir" apt-get -f -y install
chroot "$__SysrootDir" apt-get -y install \
    build-essential \
    gcc \
    g++ \
    zlib1g-dev \
    symlinks \
    $__Packages

chroot "$__SysrootDir" symlinks -cr /usr
chroot "$__SysrootDir" apt-get clean
rm -rf "$__SysrootDir/var/lib/apt/lists"/* "$__SysrootDir/tmp"/* "$__SysrootDir/var/tmp"/*
