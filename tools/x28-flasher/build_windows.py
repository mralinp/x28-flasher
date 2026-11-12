#!/usr/bin/env python3
"""Add a native WebView2 Windows launcher to build_binary.py's output (no extra Python runtime)."""
import argparse
import hashlib
import os
import subprocess
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK_VERSION = "1.0.4314.35"
SDK_SHA256 = "90778deb1b77e36292828b4b5833c9255c27533f40e0ddd55891ae718944edc4"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dist', type=Path, default=Path('dist'))
    args = ap.parse_args()
    out = args.dist.resolve() / 'x28-flasher'
    if os.name != 'nt' or not (out / 'x28-flasher.exe').is_file():
        raise SystemExit('Run on Windows after build_binary.py')
    work = args.dist.resolve().parent / 'build-x28-flasher' / 'windows-native'
    work.mkdir(parents=True, exist_ok=True)
    package = work / 'webview2.nupkg'
    urllib.request.urlretrieve(f'https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/{SDK_VERSION}/microsoft.web.webview2.{SDK_VERSION}.nupkg', package)
    if hashlib.sha256(package.read_bytes()).hexdigest() != SDK_SHA256:
        raise SystemExit('WebView2 SDK checksum mismatch')
    files = {
        'lib/net462/Microsoft.Web.WebView2.Core.dll': 'Microsoft.Web.WebView2.Core.dll',
        'lib/net462/Microsoft.Web.WebView2.WinForms.dll': 'Microsoft.Web.WebView2.WinForms.dll',
        'runtimes/win-x64/native/WebView2Loader.dll': 'WebView2Loader.dll',
        'LICENSE.txt': 'LICENSE-WebView2.txt',
    }
    with zipfile.ZipFile(package) as sdk:
        for src, dest in files.items():
            (out / dest).write_bytes(sdk.read(src))
    csc = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    subprocess.run([str(csc), '/nologo', '/target:winexe', '/platform:x64',
                    f'/out:{out / "X28 Flasher.exe"}', '/reference:System.Windows.Forms.dll',
                    '/reference:System.Drawing.dll', '/reference:System.Net.Http.dll', '/reference:System.Web.Extensions.dll',
                    f'/reference:{out / "Microsoft.Web.WebView2.Core.dll"}',
                    f'/reference:{out / "Microsoft.Web.WebView2.WinForms.dll"}', str(HERE / 'native/windows.cs')], check=True)
    bootstrapper = args.dist.resolve() / 'MicrosoftEdgeWebview2Setup.exe'
    urllib.request.urlretrieve('https://go.microsoft.com/fwlink/p/?LinkId=2124703', bootstrapper)
    # The Evergreen bootstrapper updates independently; verify Microsoft's signature rather than pinning stale bytes.
    subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                    "$s = Get-AuthenticodeSignature -LiteralPath $env:X28_WEBVIEW2_SETUP; "
                    "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Invalid WebView2 installer signature' }"],
                   env={**os.environ, 'X28_WEBVIEW2_SETUP': str(bootstrapper)}, check=True)
    # UsbDk gives libusb access to the modem's MediaTek boot-mode USB device (0e8d:0003); without it Windows shows nothing for the modem.
    usbdk = args.dist.resolve() / 'UsbDk.msi'
    urllib.request.urlretrieve('https://github.com/daynix/UsbDk/releases/download/v1.00-22/UsbDk_1.0.22_x64.msi', usbdk)
    got = hashlib.sha256(usbdk.read_bytes()).hexdigest()
    assert got == '91f6f695e1e13c656024e6d3b55620bf08d8835ef05ee0496935ba6bb62466a5', f'UsbDk installer hash mismatch: {got}'
    print(f'built {out / "X28 Flasher.exe"}')


if __name__ == '__main__':
    main()
