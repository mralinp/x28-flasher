; iscc /DSrc=<dist\x28-flasher> /DOut=<folder> /DVersion=<x.y.z> windows.iss
[Setup]
AppName=X28 Flasher
AppVersion={#Version}
AppPublisher=mralinp
DefaultDirName={autopf}\X28 Flasher
DefaultGroupName=X28 Flasher
OutputDir={#Out}
OutputBaseFilename=X28-Flasher-windows-x64-setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest

[Files]
Source: "{#Src}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "{#Src}\..\MicrosoftEdgeWebview2Setup.exe"; Flags: dontcopy
Source: "{#Src}\..\UsbDk.msi"; Flags: dontcopy

[Icons]
Name: "{group}\X28 Flasher"; Filename: "{app}\X28 Flasher.exe"
Name: "{autodesktop}\X28 Flasher"; Filename: "{app}\X28 Flasher.exe"

[Code]
function WebView2Installed: Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(HKLM32, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version)
    and (Version <> '') and (Version <> '0.0.0.0');
  if not Result then
    Result := RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version)
      and (Version <> '') and (Version <> '0.0.0.0');
end;

function UsbDkInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\UsbDk');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  // UsbDk is a kernel driver: it needs admin, so only this msiexec is elevated (one UAC prompt); setup itself stays per-user.
  if (CurStep = ssPostInstall) and not UsbDkInstalled then begin
    ExtractTemporaryFile('UsbDk.msi');
    if not ShellExec('runas', 'msiexec.exe', '/i "' + ExpandConstant('{tmp}\UsbDk.msi') + '" /qb /norestart', '', SW_SHOW, ewWaitUntilTerminated, Code)
      or ((Code <> 0) and (Code <> 3010)) then
      MsgBox('The USB driver (UsbDk) was not installed, so Windows cannot see the modem. Run UsbDk_1.0.22_x64.msi from github.com/daynix/UsbDk/releases, then reconnect the modem.', mbError, MB_OK);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  if not WebView2Installed then begin
    ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
    if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code)
      or not WebView2Installed then
      Result := 'Microsoft Edge WebView2 Runtime could not be installed. Connect to the internet, install WebView2 Runtime, and retry setup.';
  end;
end;
