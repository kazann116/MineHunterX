unit MineHunter.Tests.Quarantine;

{
  Карантин и откат на поддельной файловой системе, реестре, службах и
  заданиях: полный цикл «в карантин → восстановить», защита системных
  объектов, отказы доступа, повреждённые записи, план исправления находки.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Actions, MineHunter.Core.Quarantine;

type
  TFakeFile = record
    Content: TBytes;
    Attributes: Cardinal;
  end;

  TFakeRegValue = record
    ValueType: Cardinal;
    Data: TBytes;
  end;

  TFakeQuarantineOps = class(TInterfacedObject, IMHQuarantineOps)
  public
    Files: TDictionary<string, TFakeFile>;
    Dirs: TList<string>;
    Registry: TDictionary<string, TFakeRegValue>;
    DeniedKeys: TList<string>;
    Services: TDictionary<string, Cardinal>;
    Tasks: TDictionary<string, Boolean>;
    LockedFiles: TList<string>;
    DeniedFiles: TList<string>;
    constructor Create;
    destructor Destroy; override;
    procedure AddFile(const APath, AText: string; AAttributes: Cardinal = 0);
    function WindowsDir: string;
    function SelfPath: string;
    function FileExists(const APath: string): Boolean;
    function GetAttributes(const APath: string; out AAttributes: Cardinal): Boolean;
    function SetAttributes(const APath: string; AAttributes: Cardinal): Boolean;
    function MoveFile(const ASource, ADest: string; out AError: string; out AAccessDenied: Boolean): Boolean;
    function DeleteFile(const APath: string; out AError: string): Boolean;
    function ForceDirectories(const APath: string): Boolean;
    function RemoveDirectory(const APath: string): Boolean;
    function ListDirectories(const APath: string): TArray<string>;
    function FileSha256(const APath: string; out ASha256: string; out ASize: Int64): Boolean;
    function ReadTextFile(const APath: string; out AText: string): Boolean;
    function WriteTextFile(const APath, AText: string): Boolean;
    function RegReadValue(const AKey, AName: string; out AType: Cardinal; out AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegWriteValue(const AKey, AName: string; AType: Cardinal; const AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegDeleteValue(const AKey, AName: string; out AError: string): TMHRegOpResult;
    function ServiceGetStartType(const AName: string; out AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function ServiceSetStartType(const AName: string; AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function TaskSetEnabled(const APath: string; AEnabled: Boolean; out AError: string): TMHRegOpResult;
  end;

  [TestFixture]
  [Category('Unit')]
  TQuarantineTests = class
  private
    FOps: TFakeQuarantineOps;
    FOpsIntf: IMHQuarantineOps;
    FLog: TObject;
    FLogIntf: IMHActionLog;
    FQuarantine: TMHQuarantine;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure File_QuarantineAndRestore_RoundTrip;
    [Test] procedure File_RefusesWindowsSelfInvalidAndMissing;
    [Test] procedure File_Locked_RollsBackAndExplains;
    [Test] procedure File_AccessDenied_SuggestsAdmin;
    [Test] procedure File_Restore_RefusesOverwriteAndTampered;
    [Test] procedure File_Purge_DeletesForever;
    [Test] procedure Registry_DisableAndRestore_KeepsTypeAndData;
    [Test] procedure Registry_RefusesUnknownKeyAndExistingValue;
    [Test] procedure Registry_AccessDenied_NoBackupLeft;
    [Test] procedure Service_DisableAndRestore;
    [Test] procedure Service_CriticalRefused_AlreadyDisabledOk;
    [Test] procedure Task_DisableAndRestore;
    [Test] procedure Items_NewestFirst_CorruptSkipped;
    [Test] procedure Journal_RecordsEveryAction;
    [Test] procedure RemediableKeys;
  end;

  [TestFixture]
  [Category('Unit')]
  TRemediationPlanTests = class
  public
    [Test] procedure ProcessFinding_StopAutostartAndQuarantine;
    [Test] procedure AutostartWithWindowsBinary_NoQuarantine;
    [Test] procedure DefenderExclusionGroup_RemovesValuesAndQuarantinesFiles;
    [Test] procedure IfeoGroup_RemovesDebuggerNeverTouchesWindows;
    [Test] procedure WmiAndHosts_AreManual;
    [Test] procedure DefenderPolicyGroup_RemovesAllValues;
  end;

implementation

uses
  System.Hash, System.StrUtils, System.Generics.Defaults,
  MineHunter.Core.Paths, MineHunter.Tests.Fakes, MineHunter.Tests.SettingsReports;

const
  RUN_KEY = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';

function K(const AText: string): string;
begin
  Result := AText.ToLower;
end;

{ TFakeQuarantineOps }

constructor TFakeQuarantineOps.Create;
begin
  inherited Create;
  Files := TDictionary<string, TFakeFile>.Create;
  Dirs := TList<string>.Create;
  Registry := TDictionary<string, TFakeRegValue>.Create;
  DeniedKeys := TList<string>.Create;
  Services := TDictionary<string, Cardinal>.Create;
  Tasks := TDictionary<string, Boolean>.Create;
  LockedFiles := TList<string>.Create;
  DeniedFiles := TList<string>.Create;
end;

destructor TFakeQuarantineOps.Destroy;
begin
  DeniedFiles.Free;
  LockedFiles.Free;
  Tasks.Free;
  Services.Free;
  DeniedKeys.Free;
  Registry.Free;
  Dirs.Free;
  Files.Free;
  inherited;
end;

procedure TFakeQuarantineOps.AddFile(const APath, AText: string; AAttributes: Cardinal);
var
  LFile: TFakeFile;
begin
  LFile.Content := TEncoding.UTF8.GetBytes(AText);
  LFile.Attributes := AAttributes;
  Files.AddOrSetValue(K(APath), LFile);
end;

function TFakeQuarantineOps.WindowsDir: string;
begin
  Result := 'C:\Windows';
end;

function TFakeQuarantineOps.SelfPath: string;
begin
  Result := 'C:\Tools\MineHunter\MineHunter.App.exe';
end;

function TFakeQuarantineOps.FileExists(const APath: string): Boolean;
begin
  Result := Files.ContainsKey(K(APath));
end;

function TFakeQuarantineOps.GetAttributes(const APath: string; out AAttributes: Cardinal): Boolean;
var
  LFile: TFakeFile;
begin
  Result := Files.TryGetValue(K(APath), LFile);
  if Result then
    AAttributes := LFile.Attributes
  else
    AAttributes := 0;
end;

function TFakeQuarantineOps.SetAttributes(const APath: string; AAttributes: Cardinal): Boolean;
var
  LFile: TFakeFile;
begin
  Result := Files.TryGetValue(K(APath), LFile);
  if Result then
  begin
    LFile.Attributes := AAttributes;
    Files[K(APath)] := LFile;
  end;
end;

function TFakeQuarantineOps.MoveFile(const ASource, ADest: string; out AError: string;
  out AAccessDenied: Boolean): Boolean;
var
  LFile: TFakeFile;
begin
  AError := '';
  AAccessDenied := DeniedFiles.Contains(K(ASource));
  if AAccessDenied then
  begin
    AError := 'Отказано в доступе';
    Exit(False);
  end;
  if LockedFiles.Contains(K(ASource)) then
  begin
    AError := 'Файл занят другим процессом';
    Exit(False);
  end;
  Result := Files.TryGetValue(K(ASource), LFile) and not Files.ContainsKey(K(ADest));
  if Result then
  begin
    Files.Remove(K(ASource));
    Files.Add(K(ADest), LFile);
  end
  else
    AError := 'не найден';
end;

function TFakeQuarantineOps.DeleteFile(const APath: string; out AError: string): Boolean;
begin
  AError := '';
  Result := Files.ContainsKey(K(APath));
  Files.Remove(K(APath));
end;

function TFakeQuarantineOps.ForceDirectories(const APath: string): Boolean;
begin
  if not Dirs.Contains(K(APath)) then
    Dirs.Add(K(APath));
  Result := True;
end;

function TFakeQuarantineOps.RemoveDirectory(const APath: string): Boolean;
begin
  Result := Dirs.Remove(K(APath)) >= 0;
end;

function TFakeQuarantineOps.ListDirectories(const APath: string): TArray<string>;
var
  LDir, LPrefix: string;
begin
  Result := nil;
  LPrefix := K(IncludeTrailingPathDelimiter(APath));
  for LDir in Dirs do
    if LDir.StartsWith(LPrefix) and not Copy(LDir, Length(LPrefix) + 1, MaxInt).Contains('\') then
      Result := Result + [LDir];
end;

function TFakeQuarantineOps.FileSha256(const APath: string; out ASha256: string; out ASize: Int64): Boolean;
var
  LFile: TFakeFile;
begin
  Result := Files.TryGetValue(K(APath), LFile);
  if Result then
  begin
    ASha256 := THashSHA2.GetHashString(TEncoding.UTF8.GetString(LFile.Content), SHA256).ToLower;
    ASize := Length(LFile.Content);
  end;
end;

function TFakeQuarantineOps.ReadTextFile(const APath: string; out AText: string): Boolean;
var
  LFile: TFakeFile;
begin
  Result := Files.TryGetValue(K(APath), LFile);
  if Result then
    AText := TEncoding.UTF8.GetString(LFile.Content);
end;

function TFakeQuarantineOps.WriteTextFile(const APath, AText: string): Boolean;
begin
  AddFile(APath, AText);
  Result := True;
end;

function TFakeQuarantineOps.RegReadValue(const AKey, AName: string; out AType: Cardinal;
  out AData: TBytes; out AError: string): TMHRegOpResult;
var
  LValue: TFakeRegValue;
begin
  AError := '';
  if DeniedKeys.Contains(K(AKey)) then
    Exit(rorAccessDenied);
  if not Registry.TryGetValue(K(AKey + '|' + AName), LValue) then
    Exit(rorNotFound);
  AType := LValue.ValueType;
  AData := LValue.Data;
  Result := rorOk;
end;

function TFakeQuarantineOps.RegWriteValue(const AKey, AName: string; AType: Cardinal;
  const AData: TBytes; out AError: string): TMHRegOpResult;
var
  LValue: TFakeRegValue;
begin
  AError := '';
  if DeniedKeys.Contains(K(AKey)) then
    Exit(rorAccessDenied);
  LValue.ValueType := AType;
  LValue.Data := AData;
  Registry.AddOrSetValue(K(AKey + '|' + AName), LValue);
  Result := rorOk;
end;

function TFakeQuarantineOps.RegDeleteValue(const AKey, AName: string; out AError: string): TMHRegOpResult;
begin
  AError := '';
  if DeniedKeys.Contains(K(AKey)) then
    Exit(rorAccessDenied);
  if not Registry.ContainsKey(K(AKey + '|' + AName)) then
    Exit(rorNotFound);
  Registry.Remove(K(AKey + '|' + AName));
  Result := rorOk;
end;

function TFakeQuarantineOps.ServiceGetStartType(const AName: string; out AStartType: Cardinal;
  out AError: string): TMHRegOpResult;
begin
  AError := '';
  if not Services.TryGetValue(K(AName), AStartType) then
    Exit(rorNotFound);
  Result := rorOk;
end;

function TFakeQuarantineOps.ServiceSetStartType(const AName: string; AStartType: Cardinal;
  out AError: string): TMHRegOpResult;
begin
  AError := '';
  if not Services.ContainsKey(K(AName)) then
    Exit(rorNotFound);
  Services[K(AName)] := AStartType;
  Result := rorOk;
end;

function TFakeQuarantineOps.TaskSetEnabled(const APath: string; AEnabled: Boolean;
  out AError: string): TMHRegOpResult;
begin
  AError := '';
  if not Tasks.ContainsKey(K(APath)) then
    Exit(rorNotFound);
  Tasks[K(APath)] := AEnabled;
  Result := rorOk;
end;

{ TQuarantineTests }

procedure TQuarantineTests.Setup;
var
  LLog: TRecordingActionLog;
begin
  FOps := TFakeQuarantineOps.Create;
  FOpsIntf := FOps;
  LLog := TRecordingActionLog.Create;
  FLog := LLog;
  FLogIntf := LLog;
  FQuarantine := TMHQuarantine.Create(FOpsIntf, FLogIntf, TFakeClock.Create(FAKE_NOW), 'C:\Q');
end;

procedure TQuarantineTests.TearDown;
begin
  FQuarantine.Free;
  FLogIntf := nil;
  FOpsIntf := nil;
end;

procedure TQuarantineTests.File_QuarantineAndRestore_RoundTrip;
var
  LResult: TMHActionResult;
  LItems: TArray<TMHQuarantineItem>;
  LAttr: Cardinal;
begin
  FOps.AddFile('C:\ProgramData\WindowsTask\AMD.exe', 'miner', $6);
  LResult := FQuarantine.QuarantineFile('C:\ProgramData\WindowsTask\AMD.exe', 'Майнер');
  Assert.IsTrue(LResult.Succeeded, LResult.Message);
  Assert.IsFalse(FOps.FileExists('C:\ProgramData\WindowsTask\AMD.exe'), 'Файл перенесён');
  LItems := FQuarantine.Items;
  Assert.AreEqual(1, Integer(Length(LItems)));
  Assert.AreEqual<TMHQuarantineKind>(qkFile, LItems[0].Kind);
  Assert.AreEqual(Cardinal($6), LItems[0].Attributes, 'Исходные атрибуты сохранены');
  Assert.IsTrue(LItems[0].StoredPath.EndsWith('.quarantine'), 'Файл нельзя запустить двойным щелчком');
  Assert.IsTrue(FOps.FileExists(LItems[0].StoredPath));
  Assert.AreEqual('Майнер', LItems[0].Reason);

  LResult := FQuarantine.Restore(LItems[0].Id);
  Assert.IsTrue(LResult.Succeeded, LResult.Message);
  Assert.IsTrue(FOps.FileExists('C:\ProgramData\WindowsTask\AMD.exe'));
  FOps.GetAttributes('C:\ProgramData\WindowsTask\AMD.exe', LAttr);
  Assert.AreEqual(Cardinal($6), LAttr, 'Атрибуты восстановлены');
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)), 'Запись удалена после восстановления');
end;

procedure TQuarantineTests.File_RefusesWindowsSelfInvalidAndMissing;
begin
  FOps.AddFile('C:\Windows\System32\systray.exe', 'x');
  FOps.AddFile('C:\Tools\MineHunter\MineHunter.App.exe', 'x');
  Assert.AreEqual<TMHActionResultKind>(arkProtected,
    FQuarantine.QuarantineFile('C:\Windows\System32\systray.exe', 'r').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkProtected,
    FQuarantine.QuarantineFile('C:\Tools\MineHunter\MineHunter.App.exe', 'r').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkFailed,
    FQuarantine.QuarantineFile('"C:\x.exe" -arg', 'r').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkNotFound,
    FQuarantine.QuarantineFile('C:\ProgramData\none.exe', 'r').Kind);
  Assert.IsTrue(FOps.FileExists('C:\Windows\System32\systray.exe'));
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)));
end;

procedure TQuarantineTests.File_Locked_RollsBackAndExplains;
var
  LResult: TMHActionResult;
  LAttr: Cardinal;
begin
  FOps.AddFile('C:\ProgramData\x\run.exe', 'x', $2);
  FOps.LockedFiles.Add(K('C:\ProgramData\x\run.exe'));
  LResult := FQuarantine.QuarantineFile('C:\ProgramData\x\run.exe', 'r');
  Assert.AreEqual<TMHActionResultKind>(arkFailed, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('остановите процесс'));
  Assert.IsTrue(FOps.FileExists('C:\ProgramData\x\run.exe'));
  FOps.GetAttributes('C:\ProgramData\x\run.exe', LAttr);
  Assert.AreEqual(Cardinal($2), LAttr, 'Атрибуты возвращены');
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)), 'Пустая запись не остаётся');
end;

procedure TQuarantineTests.File_AccessDenied_SuggestsAdmin;
var
  LResult: TMHActionResult;
begin
  FOps.AddFile('C:\Program Files\Bad\bad.exe', 'x');
  FOps.DeniedFiles.Add(K('C:\Program Files\Bad\bad.exe'));
  LResult := FQuarantine.QuarantineFile('C:\Program Files\Bad\bad.exe', 'r');
  Assert.AreEqual<TMHActionResultKind>(arkAccessDenied, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('администратора'));
end;

procedure TQuarantineTests.File_Restore_RefusesOverwriteAndTampered;
var
  LItem: TMHQuarantineItem;
  LFile: TFakeFile;
begin
  FOps.AddFile('C:\ProgramData\a.exe', 'one');
  FQuarantine.QuarantineFile('C:\ProgramData\a.exe', 'r');
  LItem := FQuarantine.Items[0];
  FOps.AddFile('C:\ProgramData\a.exe', 'new file');
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FQuarantine.Restore(LItem.Id).Kind,
    'Новый файл на прежнем месте не перезаписывается');
  FOps.Files.Remove(K('C:\ProgramData\a.exe'));
  LFile := FOps.Files[K(LItem.StoredPath)];
  LFile.Content := TEncoding.UTF8.GetBytes('changed');
  FOps.Files[K(LItem.StoredPath)] := LFile;
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FQuarantine.Restore(LItem.Id).Kind,
    'Изменённый файл в карантине не возвращается');
  Assert.AreEqual(1, Integer(Length(FQuarantine.Items)), 'Запись сохраняется при неудаче');
end;

procedure TQuarantineTests.File_Purge_DeletesForever;
var
  LItem: TMHQuarantineItem;
begin
  FOps.AddFile('C:\ProgramData\a.exe', 'one');
  FQuarantine.QuarantineFile('C:\ProgramData\a.exe', 'r');
  LItem := FQuarantine.Items[0];
  Assert.IsTrue(FQuarantine.Purge(LItem.Id).Succeeded);
  Assert.IsFalse(FOps.FileExists(LItem.StoredPath));
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)));
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FQuarantine.Restore(LItem.Id).Kind);
end;

procedure TQuarantineTests.Registry_DisableAndRestore_KeepsTypeAndData;
var
  LData: TBytes;
  LType: Cardinal;
  LError: string;
  LItems: TArray<TMHQuarantineItem>;
begin
  FOps.RegWriteValue(RUN_KEY, 'Updater', 2, TEncoding.Unicode.GetBytes('C:\x\u.exe'#0), LError);
  Assert.IsTrue(FQuarantine.DisableRegistryValue(RUN_KEY, 'Updater', 'Автозапуск').Succeeded);
  Assert.AreEqual<TMHRegOpResult>(rorNotFound, FOps.RegReadValue(RUN_KEY, 'Updater', LType, LData, LError));
  LItems := FQuarantine.Items;
  Assert.AreEqual<TMHQuarantineKind>(qkRegistryValue, LItems[0].Kind);
  Assert.IsTrue(FQuarantine.Restore(LItems[0].Id).Succeeded);
  Assert.AreEqual<TMHRegOpResult>(rorOk, FOps.RegReadValue(RUN_KEY, 'Updater', LType, LData, LError));
  Assert.AreEqual(Cardinal(2), LType, 'Тип значения (REG_EXPAND_SZ) сохранён');
  Assert.AreEqual('C:\x\u.exe'#0, TEncoding.Unicode.GetString(LData));
end;

procedure TQuarantineTests.Registry_RefusesUnknownKeyAndExistingValue;
var
  LError: string;
  LItem: TMHQuarantineItem;
begin
  FOps.RegWriteValue('HKLM\SYSTEM\CurrentControlSet\Services\X', 'Start', 4, [2, 0, 0, 0], LError);
  Assert.AreEqual<TMHActionResultKind>(arkProtected,
    FQuarantine.DisableRegistryValue('HKLM\SYSTEM\CurrentControlSet\Services\X', 'Start', 'r').Kind);
  FOps.RegWriteValue(RUN_KEY, 'A', 1, [65, 0, 0, 0], LError);
  FQuarantine.DisableRegistryValue(RUN_KEY, 'A', 'r');
  LItem := FQuarantine.Items[0];
  FOps.RegWriteValue(RUN_KEY, 'A', 1, [66, 0, 0, 0], LError);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FQuarantine.Restore(LItem.Id).Kind,
    'Существующее значение не перезаписывается');
end;

procedure TQuarantineTests.Registry_AccessDenied_NoBackupLeft;
var
  LError: string;
  LKey: string;
begin
  LKey := 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths';
  FOps.RegWriteValue(LKey, 'C:\ProgramData', 4, [0, 0, 0, 0], LError);
  FOps.DeniedKeys.Add(K(LKey));
  Assert.AreEqual<TMHActionResultKind>(arkAccessDenied,
    FQuarantine.DisableRegistryValue(LKey, 'C:\ProgramData', 'r').Kind);
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)));
end;

procedure TQuarantineTests.Service_DisableAndRestore;
var
  LItems: TArray<TMHQuarantineItem>;
begin
  FOps.Services.Add('wintasks', 2);
  Assert.IsTrue(FQuarantine.DisableService('WinTasks', 'r').Succeeded);
  Assert.AreEqual(Cardinal(4), FOps.Services['wintasks']);
  LItems := FQuarantine.Items;
  Assert.IsTrue(FQuarantine.Restore(LItems[0].Id).Succeeded);
  Assert.AreEqual(Cardinal(2), FOps.Services['wintasks'], 'Прежний тип запуска (автоматически)');
end;

procedure TQuarantineTests.Service_CriticalRefused_AlreadyDisabledOk;
begin
  FOps.Services.Add('windefend', 2);
  FOps.Services.Add('old', 4);
  Assert.AreEqual<TMHActionResultKind>(arkProtected, FQuarantine.DisableService('WinDefend', 'r').Kind);
  Assert.AreEqual(Cardinal(2), FOps.Services['windefend']);
  Assert.IsTrue(FQuarantine.DisableService('old', 'r').Succeeded);
  Assert.AreEqual(0, Integer(Length(FQuarantine.Items)), 'Уже отключённая служба — без записи');
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FQuarantine.DisableService('none', 'r').Kind);
end;

procedure TQuarantineTests.Task_DisableAndRestore;
begin
  FOps.Tasks.Add(K('\Microsoft\Windows\SysFilesL\RecoveryHosts'), True);
  Assert.IsTrue(FQuarantine.DisableTask('\Microsoft\Windows\SysFilesL\RecoveryHosts', 'r').Succeeded);
  Assert.IsFalse(FOps.Tasks[K('\Microsoft\Windows\SysFilesL\RecoveryHosts')]);
  Assert.IsTrue(FQuarantine.Restore(FQuarantine.Items[0].Id).Succeeded);
  Assert.IsTrue(FOps.Tasks[K('\Microsoft\Windows\SysFilesL\RecoveryHosts')]);
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FQuarantine.DisableTask('\none', 'r').Kind);
end;

procedure TQuarantineTests.Items_NewestFirst_CorruptSkipped;
var
  LItems: TArray<TMHQuarantineItem>;
  LClockIntf: IMHClock;
  LClock: TFakeClock;
  LQuarantine: TMHQuarantine;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  LClockIntf := LClock;
  LQuarantine := TMHQuarantine.Create(FOpsIntf, nil, LClockIntf, 'C:\Q');
  try
    FOps.AddFile('C:\ProgramData\a.exe', 'a');
    FOps.AddFile('C:\ProgramData\b.exe', 'b');
    LQuarantine.QuarantineFile('C:\ProgramData\a.exe', 'first');
    LClock.AdvanceMs(60000);
    LQuarantine.QuarantineFile('C:\ProgramData\b.exe', 'second');
    FOps.ForceDirectories('C:\Q\broken');
    FOps.WriteTextFile('C:\Q\broken\manifest.json', '{ not json');
    LItems := LQuarantine.Items;
    Assert.AreEqual(2, Integer(Length(LItems)), 'Повреждённая запись пропущена');
    Assert.AreEqual('second', LItems[0].Reason, 'Новые первыми');
  finally
    LQuarantine.Free;
  end;
end;

procedure TQuarantineTests.Journal_RecordsEveryAction;
var
  LRecords: TArray<TMHActionRecord>;
begin
  FOps.AddFile('C:\ProgramData\a.exe', 'a');
  FQuarantine.QuarantineFile('C:\ProgramData\a.exe', 'r');
  FQuarantine.QuarantineFile('C:\Windows\x.exe', 'r');
  FQuarantine.Restore(FQuarantine.Items[0].Id);
  LRecords := FLogIntf.LoadActions(10);
  Assert.AreEqual(3, Integer(Length(LRecords)), 'И удачные, и отказанные действия');
end;

procedure TQuarantineTests.RemediableKeys;
begin
  Assert.IsTrue(MHIsRemediableRegistryKey('HKCU\Software\Microsoft\Windows\CurrentVersion\Run'));
  Assert.IsTrue(MHIsRemediableRegistryKey('HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'));
  Assert.IsTrue(MHIsRemediableRegistryKey(
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe'));
  Assert.IsTrue(MHIsRemediableRegistryKey('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'));
  Assert.IsTrue(MHIsRemediableRegistryKey('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'));
  Assert.IsTrue(MHIsRemediableRegistryKey('HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System'));
  Assert.IsFalse(MHIsRemediableRegistryKey('HKLM\SYSTEM\CurrentControlSet\Services\WinDefend'));
  Assert.IsFalse(MHIsRemediableRegistryKey('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'));
  Assert.IsFalse(MHIsRemediableRegistryKey('HKCR\exefile\shell'));
  Assert.IsFalse(MHIsRemediableRegistryKey(''));
end;

{ TRemediationPlanTests }

function Kinds(const ASteps: TArray<TMHRemediationStep>): string;
var
  LStep: TMHRemediationStep;
begin
  Result := '';
  for LStep in ASteps do
    Result := Result + IntToStr(Ord(LStep.Kind));
end;

function Tamper(AKind: TMHTamperKind; const AName, AValue, ALocation, ADetails, AImage: string): TMHTamperEntry;
begin
  Result := TMHTamperEntry.Create(AKind, AName, AValue, ALocation);
  Result.Details := ADetails;
  Result.ImagePath := AImage;
end;

procedure TRemediationPlanTests.ProcessFinding_StopAutostartAndQuarantine;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LEntry: TMHAutostartEntry;
  LSteps: TArray<TMHRemediationStep>;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Processes := [TMHProcessInfo.Create(TMHProcessId.Create(77, 5), 'svc.exe', FAKE_NOW)];
  LEntry := Default(TMHAutostartEntry);
  LEntry.Kind := akRegistryRun;
  LEntry.Name := 'SvcUpdate';
  LEntry.Location := RUN_KEY;
  LEntry.ImagePath := MHNormalizePath('C:\Users\u\AppData\Local\Temp\svc.exe');
  LSnapshot.Autostart := [LEntry];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'process:x:майнинг';
  LFinding.Process := TMHProcessId.Create(77, 5);
  LFinding.ImagePath := 'C:\Users\u\AppData\Local\Temp\svc.exe';
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(IntToStr(Ord(rmStopProcess)) + IntToStr(Ord(rmRegistryValue)) + IntToStr(Ord(rmQuarantineFile)),
    Kinds(LSteps), 'Остановить, отключить автозапуск, в карантин');
  Assert.AreEqual(Cardinal(77), LSteps[0].Process.Pid);
  Assert.AreEqual('SvcUpdate', LSteps[1].ValueName);
end;

procedure TRemediationPlanTests.AutostartWithWindowsBinary_NoQuarantine;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LEntry: TMHAutostartEntry;
  LSteps: TArray<TMHRemediationStep>;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LEntry := Default(TMHAutostartEntry);
  LEntry.Kind := akScheduledTask;
  LEntry.Name := '\Updater';
  LEntry.Location := '\';
  LEntry.ImagePath := MHNormalizePath('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe');
  LSnapshot.Autostart := [LEntry];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'autostart:задание планировщика:\:\updater';
  LFinding.Key := Format('autostart:%s:%s:%s', [MHAutostartKindToString(akScheduledTask), '\', '\updater']);
  LFinding.ImagePath := LEntry.ImagePath;
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(IntToStr(Ord(rmTask)), Kinds(LSteps), 'powershell.exe не помещается в карантин');
end;

procedure TRemediationPlanTests.DefenderExclusionGroup_RemovesValuesAndQuarantinesFiles;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LSteps: TArray<TMHRemediationStep>;
  LKey: string;
begin
  LKey := 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths';
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [
    Tamper(tpDefenderExclusion, 'C:\ProgramData\WindowsTask\AMD.exe', 'x', LKey, 'путь',
      MHNormalizePath('C:\ProgramData\WindowsTask\AMD.exe')),
    Tamper(tpDefenderExclusion, 'C:\ProgramData\WindowsTask\gone.exe', 'x', LKey, 'путь; файла нет на диске',
      MHNormalizePath('C:\ProgramData\WindowsTask\gone.exe')),
    Tamper(tpDefenderExclusion, 'D:\Projects', 'x', LKey, 'путь', 'D:\Projects')];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'tamper:defender:files:' + MHNormalizePath('C:\ProgramData\WindowsTask').ToLower;
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(IntToStr(Ord(rmRegistryValue)) + IntToStr(Ord(rmQuarantineFile)) + IntToStr(Ord(rmRegistryValue)),
    Kinds(LSteps), 'Два исключения папки WindowsTask; карантин — только существующий файл');
  Assert.AreEqual('C:\ProgramData\WindowsTask\AMD.exe', LSteps[0].ValueName);
end;

procedure TRemediationPlanTests.IfeoGroup_RemovesDebuggerNeverTouchesWindows;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LSteps: TArray<TMHRemediationStep>;
  LStep: TMHRemediationStep;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [
    Tamper(tpIfeoDebugger, 'MsMpEng.exe', 'C:\Windows\System32\systray.exe', 'HKLM\…\MsMpEng.exe', '',
      'C:\Windows\System32\systray.exe'),
    Tamper(tpIfeoDebugger, 'mpcmdrun.exe', 'C:\Windows\System32\systray.exe', 'HKLM\…\mpcmdrun.exe', '',
      'C:\Windows\System32\systray.exe')];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'tamper:ifeo:c:\windows\system32\systray.exe';
  LFinding.ImagePath := 'C:\Windows\System32\systray.exe';
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(2, Integer(Length(LSteps)));
  for LStep in LSteps do
  begin
    Assert.AreEqual<TMHRemediationKind>(rmRegistryValue, LStep.Kind);
    Assert.AreEqual('Debugger', LStep.ValueName);
  end;
end;

procedure TRemediationPlanTests.WmiAndHosts_AreManual;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LSteps: TArray<TMHRemediationStep>;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [Tamper(tpWmiSubscription, 'Upd', 'C:\ProgramData\w.exe', 'root\subscription', '',
      MHNormalizePath('C:\ProgramData\w.exe')),
    Tamper(tpHostsRedirect, 'eset.com', '0.0.0.0', 'hosts', '', '')];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'tamper:wmi:upd';
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(IntToStr(Ord(rmManual)) + IntToStr(Ord(rmQuarantineFile)), Kinds(LSteps));
  LFinding.Key := 'tamper:hosts';
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(IntToStr(Ord(rmManual)), Kinds(LSteps));
end;

procedure TRemediationPlanTests.DefenderPolicyGroup_RemovesAllValues;
var
  LSnapshot: TMHSnapshot;
  LFinding: TMHFinding;
  LSteps: TArray<TMHRemediationStep>;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [
    Tamper(tpPolicyRestriction, 'DisableAntiSpyware', '1', 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM', ''),
    Tamper(tpPolicyRestriction, 'DisableRealtimeMonitoring', '1',
      'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection', 'HKLM', ''),
    Tamper(tpPolicyRestriction, 'EnableLUA', '0', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System',
      'HKLM', '')];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'tamper:policy:defender';
  LSteps := MHBuildRemediationPlan(LSnapshot, LFinding, 'C:\Windows');
  Assert.AreEqual(2, Integer(Length(LSteps)), 'UAC не входит в находку Defender');
end;

initialization
  TDUnitX.RegisterTestFixture(TQuarantineTests);
  TDUnitX.RegisterTestFixture(TRemediationPlanTests);

end.
