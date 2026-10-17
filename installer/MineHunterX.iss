; Установщик MineHunter X (Inno Setup 6).
; Сборка: powershell -ExecutionPolicy Bypass -File tools\make-installer.ps1
; Параметры командной строки ISCC:
;   /DAppVersion=0.1.0   версия (по умолчанию — из MH_CORE_VERSION, передаёт make-installer.ps1)
;   /DSourceDir=...      каталог с MineHunter.App.exe (Release)
;   /DRepoDir=...        корень репозитория (README, LICENSE, docs)
;   /DOutputDir=...      куда положить setup.exe

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef RepoDir
  #define RepoDir ".."
#endif
#ifndef SourceDir
  #define SourceDir RepoDir + "\build\Win64\Release"
#endif
#ifndef OutputDir
  #define OutputDir RepoDir + "\dist"
#endif

#define AppName "MineHunter X"
#define AppExe "MineHunter.App.exe"
#define AppPublisher "Байткрафт"
#define AppUrl "https://github.com/kazann116/MineHunterX"

[Setup]
AppId={{7E1C2B6A-58D4-4C1E-9F3A-5B2D8E6A4C10}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile={#RepoDir}\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=MineHunterX-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Установка для текущего пользователя без прав администратора; для всех — по выбору в диалоге.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
; Restart Manager закрывает запущенную программу перед обновлением (она завершается
; по WM_QUERYENDSESSION, а не прячется в трей).
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
; Подпись средствами Inno (включая деинсталлятор): ISCC /DUseSignTool "/SSignTool=signtool.exe sign /fd SHA256 ... $f".
; make-installer.ps1 -Sign подписывает exe и готовый установщик через tools\sign.ps1.
#ifdef UseSignTool
SignTool=SignTool
SignedUninstaller=yes
#endif

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.AutostartTask=Запускать MineHunter X вместе с Windows (свёрнутым в область уведомлений)
english.AutostartTask=Start MineHunter X with Windows (minimized to the notification area)
russian.LaunchNow=Запустить MineHunter X
english.LaunchNow=Launch MineHunter X
russian.DataKept=История наблюдений и настройки (%LOCALAPPDATA%\MineHunterX) сохранены. Удалите папку вручную, если они больше не нужны.
english.DataKept=Observation history and settings (%LOCALAPPDATA%\MineHunterX) were kept. Delete the folder manually if you no longer need them.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "{cm:AutostartTask}"; Flags: unchecked

[Files]
#ifdef UseSignTool
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion signonce
#else
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
#endif
Source: "{#RepoDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\docs\*.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Та же запись, что создаёт флажок в настройках программы (TMHSelfAutostart):
; ветка текущего пользователя, параметр --minimized.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "MineHunterX"; ValueData: """{app}\{#AppExe}"" --minimized"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchNow}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Автозапуск мог быть включён и из самой программы — убираем запись в любом случае.
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'MineHunterX');
    if not UninstallSilent then
      MsgBox(CustomMessage('DataKept'), mbInformation, MB_OK);
  end;
end;
