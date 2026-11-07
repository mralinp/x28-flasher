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

[Icons]
Name: "{group}\X28 Flasher"; Filename: "{app}\x28-flasher.exe"
Name: "{autodesktop}\X28 Flasher"; Filename: "{app}\x28-flasher.exe"
