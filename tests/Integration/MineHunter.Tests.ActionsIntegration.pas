unit MineHunter.Tests.ActionsIntegration;

{
  Интеграционные тесты безопасных действий с реальными вызовами Windows.

  Используется только безвредный дочерний процесс «cmd.exe /c exit 0»,
  созданный приостановленным и без окна; он всегда завершается в finally.
  Microsoft Defender проверяет обычный текстовый файл (никаких тестовых
  сигнатур и вредоносных образцов). OpenFileLocation не выполняется
  (открыл бы окно Проводника) — проверяются только отказы валидации.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Actions;

type
  [TestFixture]
  [Category('Integration')]
  TActionsIntegrationTests = class
  private
    FDir: string;
    FOps: IMHSystemOps;
    FClock: IMHClock;
    FActions: TMHSafeActions;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Terminate_WrongIdentity_ChildStaysAlive_ThenCorrectIdentity_Terminates;
    [Test] procedure Terminate_OwnProcess_IsRefused;
    [Test] procedure Defender_HarmlessTextFile_IsCleanOrUnavailable;
    [Test] procedure OpenFileLocation_ValidationFailures;
    [Test] procedure FindDefenderCli_ReturnsExistingFileOrEmpty;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils, System.IOUtils,
  MineHunter.Core.Logging, MineHunter.Core.Calc, MineHunter.Core.Actions.WinApi;

procedure TActionsIntegrationTests.Setup;
begin
  FDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(FDir);
  FOps := TMHWinSystemOps.Create;
  FClock := TMHSystemClock.Create;
  FActions := TMHSafeActions.Create(FOps, nil, FClock);
end;

procedure TActionsIntegrationTests.TearDown;
begin
  FActions.Free;
  FActions := nil;
  FOps := nil;
  FClock := nil;
  if TDirectory.Exists(FDir) then
    TDirectory.Delete(FDir, True);
end;

procedure TActionsIntegrationTests.Terminate_WrongIdentity_ChildStaysAlive_ThenCorrectIdentity_Terminates;
var
  LSysDir: array[0..MAX_PATH] of Char;
  LExe, LCommandLine: string;
  LStartup: TStartupInfo;
  LProcess: TProcessInformation;
  LCreation, LExit, LKernel, LUser: TFileTime;
  LId: TMHProcessId;
  LResult: TMHActionResult;
begin
  GetSystemDirectory(@LSysDir[0], Length(LSysDir));
  LExe := IncludeTrailingPathDelimiter(string(PChar(@LSysDir[0]))) + 'cmd.exe';
  LCommandLine := '"' + LExe + '" /c exit 0';
  UniqueString(LCommandLine);
  FillChar(LStartup, SizeOf(LStartup), 0);
  LStartup.cb := SizeOf(LStartup);
  FillChar(LProcess, SizeOf(LProcess), 0);
  Assert.IsTrue(CreateProcess(PChar(LExe), PChar(LCommandLine), nil, nil, False,
    CREATE_SUSPENDED or CREATE_NO_WINDOW, nil, nil, LStartup, LProcess),
    'не удалось запустить дочерний процесс: ' + SysErrorMessage(GetLastError));
  try
    Assert.IsTrue(GetProcessTimes(LProcess.hProcess, LCreation, LExit, LKernel, LUser));
    LId := TMHProcessId.Create(LProcess.dwProcessId,
      MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime));

    // Неверное время создания — имитация переиспользованного PID.
    LResult := FActions.TerminateProcess(TMHProcessId.Create(LId.Pid, LId.CreateTime + 1), 'cmd.exe');
    Assert.AreEqual<TMHActionResultKind>(arkIdentityMismatch, LResult.Kind, LResult.Message);
    Assert.AreEqual<Cardinal>(WAIT_TIMEOUT, WaitForSingleObject(LProcess.hProcess, 0),
      'дочерний процесс должен остаться работающим');

    LResult := FActions.TerminateProcess(LId, 'cmd.exe');
    Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind, LResult.Message + ' ' + LResult.Details);
    Assert.AreEqual<Cardinal>(WAIT_OBJECT_0, WaitForSingleObject(LProcess.hProcess, 5000),
      'дочерний процесс должен завершиться');
  finally
    if WaitForSingleObject(LProcess.hProcess, 0) = WAIT_TIMEOUT then
    begin
      Winapi.Windows.TerminateProcess(LProcess.hProcess, 1);
      WaitForSingleObject(LProcess.hProcess, 5000);
    end;
    CloseHandle(LProcess.hThread);
    CloseHandle(LProcess.hProcess);
  end;
end;

procedure TActionsIntegrationTests.Terminate_OwnProcess_IsRefused;
var
  LCreation, LExit, LKernel, LUser: TFileTime;
  LId: TMHProcessId;
begin
  Assert.IsTrue(GetProcessTimes(GetCurrentProcess, LCreation, LExit, LKernel, LUser));
  LId := TMHProcessId.Create(GetCurrentProcessId,
    MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime));
  Assert.AreEqual<TMHActionResultKind>(arkProtected,
    FActions.TerminateProcess(LId, ExtractFileName(ParamStr(0))).Kind);
end;

procedure TActionsIntegrationTests.Defender_HarmlessTextFile_IsCleanOrUnavailable;
var
  LFile: string;
  LResult: TMHActionResult;
begin
  LFile := TPath.Combine(FDir, 'harmless.txt');
  TFile.WriteAllText(LFile, 'MineHunter X: обычный текстовый файл для проверки.');
  LResult := FActions.ScanWithDefender(LFile, nil);
  Assert.IsTrue(LResult.Kind in [arkDone, arkUnavailable],
    Format('%s: %s %s', [MHActionResultKindToString(LResult.Kind), LResult.Message, LResult.Details]));
  if LResult.Kind = arkDone then
    Assert.AreEqual('Угроз не обнаружено', LResult.Message);
  Assert.IsTrue(FileExists(LFile), 'Defender не должен изменять проверяемый файл');
end;

procedure TActionsIntegrationTests.OpenFileLocation_ValidationFailures;
begin
  Assert.AreEqual<TMHActionResultKind>(arkNotFound,
    FActions.OpenFileLocation(TPath.Combine(FDir, 'missing.exe')).Kind);
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FActions.OpenFileLocation(FDir).Kind,
    'каталог — не файл');
  Assert.AreEqual<TMHActionResultKind>(arkFailed,
    FActions.OpenFileLocation('"' + TPath.Combine(FDir, 'a.txt') + '"').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.OpenFileLocation('shell:startup').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.OpenFileLocation('notepad.exe').Kind);
end;

procedure TActionsIntegrationTests.FindDefenderCli_ReturnsExistingFileOrEmpty;
var
  LPath: string;
begin
  LPath := FOps.FindDefenderCli;
  if LPath <> '' then
  begin
    Assert.IsTrue(FileExists(LPath), LPath);
    Assert.IsTrue(SameText(ExtractFileName(LPath), 'MpCmdRun.exe'), LPath);
  end
  else
    Assert.Pass('Microsoft Defender не установлен в этой среде');
end;

initialization
  TDUnitX.RegisterTestFixture(TActionsIntegrationTests);

end.
