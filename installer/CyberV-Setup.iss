; ====================================================================
; CyberV-Setup.iss — Tier A installer (HYBRID_DISTRIBUTION_PLAN §2 Tier A)
; R1 skeleton: embed agent exe + UI + driver (nếu có). DriverUnsigned
; KHÔNG load trên máy người dùng — cần M1 attestation signing.
; Build: ISCC.exe installer\CyberV-Setup.iss (qua scripts/build-release.ps1)
; ====================================================================

#define AppName "CyberV"
#define AppVersion "1.0.0"
#define AppPublisher "CyberV Team"
#define AppExeName "CyberVUI.exe"

[Setup]
AppId={{7E3F2C1A-9B44-4D58-A1C2-53D9E7F0C6B1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\CyberV
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=CyberV-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern

[Files]
; Core Agent service (Rust, static CRT — không cần VCRUNTIME)
Source: "..\release\bin\cyberv-agent.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
; UI (PyInstaller — onefile exe + _internal dir nếu onedir)
Source: "..\release\ui\*"; DestDir: "{app}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; Kernel driver — CHỈ có hiệu lực khi đã attestation-signed (M1)
Source: "..\release\driver-bin\CyberVProbe.sys"; DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\release\driver-bin\CyberVProbe.cat"; DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\driver\CyberVProbe\CyberVProbe.inf"; DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
; DACL thư mục cài đặt: Users đọc+chạy, chỉ Admins ghi (mặc định {autopf})

[Run]
; Đăng ký + khởi động service agent (SYSTEM) — server sẽ tự publish
; agent_public_key.hex vào %PROGRAMDATA%\CyberV cho UI pinning (P1-1b).
Filename: "sc.exe"; Parameters: "create CyberV binPath= \""{app}\bin\cyberv-agent.exe\"" start= auto DisplayName= ""CyberV Core Agent"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "start CyberV"; Flags: runhidden
Filename: "sc.exe"; Parameters: "description CyberV device-trust agent"; Flags: runhidden
; UI shortcut + chạy sau cài
Filename: "{app}\ui\{#AppExeName}"; Description: "Khởi động {#AppName}"; Flags: nowait postinstall skipifsilent

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\ui\{#AppExeName}"

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop CyberV"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "sc.exe"; Parameters: "delete CyberV"; Flags: runhidden; RunOnceId: "DelSvc"

[Messages]
FinishedLabelNote=Có tác dụng phụ: agent sẽ publish khóa công khai để UI pin. Driver KHÔNG được cài qua installer này ở R1 (chưa signed) — dùng scripts/install-driver.ps1 trên máy dev sau khi ký.
