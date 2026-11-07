#!/bin/sh
# make_deb.sh DIST_DIR VERSION OUT.deb: the frozen app (DIST_DIR/x28-flasher) as a Debian package under /opt, with a menu entry.
set -e
dist=$1 version=$2 out=$3
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(mktemp -d)
mkdir -p "$root/DEBIAN" "$root/opt/x28-flasher" "$root/usr/bin" "$root/usr/share/applications" "$root/usr/share/icons/hicolor/512x512/apps"
cp -R "$dist/x28-flasher/." "$root/opt/x28-flasher/"
ln -s /opt/x28-flasher/x28-flasher "$root/usr/bin/x28-flasher"
cp "$here/assets/icon-512.png" "$root/usr/share/icons/hicolor/512x512/apps/x28-flasher.png"
cat > "$root/usr/share/applications/x28-flasher.desktop" <<D
[Desktop Entry]
Type=Application
Name=X28 Flasher
Comment=Back up and flash the ZLT X28 modem
Exec=/opt/x28-flasher/x28-flasher
Icon=x28-flasher
Categories=Utility;
Terminal=false
D
cat > "$root/DEBIAN/control" <<D
Package: x28-flasher
Version: $version
Architecture: amd64
Maintainer: mralinp
Depends: libusb-1.0-0, openssh-client
Description: Back up, build and flash the ZLT X28 5G modem over USB
D
dpkg-deb --root-owner-group --build "$root" "$out"
