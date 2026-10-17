unit MineHunter.Tests.AutostartIntegration;

{
  Integration: коллектор автозапуска на реальной Windows.
  Все проверки только читают систему: реестр, службы и задания не изменяются.
  Единственная запись — временный ярлык в %TEMP%, который тест сам удаляет.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Integration')]
  TAutostartIntegrationTests = class
  public
    [Test] procedure Services_NotEmpty_WithExistingImage;
    [Test] procedure AllEntries_HaveNameAndLocation;
    [Test] procedure RegistryRun_IsReadable;
    [Test] procedure ScheduledTasks_PresentOrExplained;
    [Test] procedure CollectTwice_SecondFromCache;
    [Test] procedure Status_MatchesContract;
    [Test] procedure NoHandleLeak_AfterForcedRefreshes;
    [Test] procedure Shortcut_ReadDirectAndInStaThread;
  end;

implementation

{$WARN SYMBOL_PLATFORM OFF}

uses
  System.SysUtils, System.IOUtils, System.Diagnostics, System.Win.ComObj, Winapi.Windows,
  Winapi.ActiveX, Winapi.ShlObj,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Logging,
  MineHunter.Core.Paths,
  MineHunter.Collectors.Autostart, MineHunter.Collectors.Autostart.WinApi,
  MineHunter.Tests.Fakes;

function UtcNow: TDateTime;
var
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  Result := LClock.NowUtc;
end;

function NewCollector(const AClock: IMHClock; ARefreshSeconds: Integer): IMHCollector;
var
  LApi: IMHAutostartApi;
begin
  LApi := TMHWinAutostartApi.Create;
  Result := TMHAutostartCollector.Create(LApi, AClock, ARefreshSeconds);
end;

function CollectOnce: TMHCollectionResult;
var
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  Result := NewCollector(LClock, 60).Collect(TMHSnapshot.Create(1, UtcNow));
end;

function CountOf(const AResult: TMHCollectionResult; AKind: TMHAutostartKind): Integer;
var
  LEntry: TMHAutostartEntry;
begin
  Result := 0;
  for LEntry in AResult.Autostart do
    if LEntry.Kind = AKind then
      Inc(Result);
end;

{ TAutostartIntegrationTests }

procedure TAutostartIntegrationTests.Services_NotEmpty_WithExistingImage;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
  LExisting: Integer;
begin
  LResult := CollectOnce;
  Assert.IsTrue(CountOf(LResult, akService) > 0, 'Список служб автозапуска пуст: ' +
    LResult.Status.Message);
  LExisting := 0;
  for LEntry in LResult.Autostart do
    if (LEntry.Kind = akService) and (LEntry.ImagePath <> '') and FileExists(LEntry.ImagePath) then
      Inc(LExisting);
  Assert.IsTrue(LExisting > 0, 'Ни у одной службы путь к файлу не найден на диске');
end;

procedure TAutostartIntegrationTests.AllEntries_HaveNameAndLocation;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  LResult := CollectOnce;
  for LEntry in LResult.Autostart do
  begin
    Assert.IsNotEmpty(LEntry.Name, 'У элемента автозапуска должно быть имя');
    Assert.IsNotEmpty(LEntry.Location, 'У элемента автозапуска должно быть расположение: ' +
      LEntry.Name);
    if LEntry.ImagePath <> '' then
      Assert.AreEqual(MHNormalizePath(LEntry.ImagePath), LEntry.ImagePath,
        'ImagePath должен быть нормализован');
  end;
end;

procedure TAutostartIntegrationTests.RegistryRun_IsReadable;
var
  LApi: IMHAutostartApi;
  LEntries: TArray<TMHAutostartEntry>;
  LError: string;
begin
  LApi := TMHWinAutostartApi.Create;
  Assert.IsTrue(LApi.ReadRegistryRun(LEntries, LError), LError);
  Assert.IsTrue(LApi.ReadStartupFolders(LEntries, LError), LError);
  Assert.IsTrue(LApi.ReadServices(LEntries, LError), LError);
  Assert.IsTrue(DirectoryExists(LApi.WindowsDir), LApi.WindowsDir);
  Assert.IsTrue(LApi.FileExists(LApi.WindowsDir + '\System32\svchost.exe'));
  Assert.IsFalse(LApi.FileExists(LApi.WindowsDir), 'Каталог не является файлом');
  Assert.AreEqual(LApi.WindowsDir + '\x', LApi.ExpandEnvironment('%SystemRoot%\x'), True);
end;

procedure TAutostartIntegrationTests.ScheduledTasks_PresentOrExplained;
var
  LResult: TMHCollectionResult;
begin
  LResult := CollectOnce;
  if CountOf(LResult, akScheduledTask) = 0 then
    Assert.IsTrue(LResult.Status.Message.Contains('планировщик'),
      'Нет заданий и нет объяснения: ' + LResult.Status.Message)
  else
    Assert.Pass(Format('Заданий: %d', [CountOf(LResult, akScheduledTask)]));
end;

procedure TAutostartIntegrationTests.CollectTwice_SecondFromCache;
var
  LClock: IMHClock;
  LCollector: IMHCollector;
  LFirst, LSecond: TMHCollectionResult;
begin
  LClock := TMHSystemClock.Create;
  LCollector := NewCollector(LClock, 3600);
  LFirst := LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  LSecond := LCollector.Collect(TMHSnapshot.Create(2, UtcNow));
  Assert.AreEqual(1, (LCollector as TMHAutostartCollector).ReadCount);
  Assert.AreEqual(LFirst.Status.ItemCount, LSecond.Status.ItemCount);
  Assert.AreEqual<TMHSourceState>(LFirst.Status.State, LSecond.Status.State);
  Assert.IsTrue(LSecond.Status.ItemCount > 0);
end;

procedure TAutostartIntegrationTests.Status_MatchesContract;
var
  LClock: IMHClock;
  LCollector: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LClock := TMHSystemClock.Create;
  LCollector := NewCollector(LClock, 60);
  LResult := LCollector.Collect(Default(TMHSnapshot));
  Assert.AreEqual(LCollector.SourceId, LResult.Status.SourceId);
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial],
    'Состояние: ' + MHSourceStateToString(LResult.Status.State) + '. ' + LResult.Status.Message);
  if LResult.Status.State <> ssSuccess then
    Assert.IsNotEmpty(LResult.Status.Message);
  Assert.IsTrue(LResult.Status.TimestampUtc > 0);
  Assert.AreEqual(Integer(Length(LResult.Autostart)), LResult.Status.ItemCount);
end;

procedure TAutostartIntegrationTests.NoHandleLeak_AfterForcedRefreshes;
var
  LFake: TFakeClock;
  LClock: IMHClock;
  LCollector: IMHCollector;
  LBefore, LAfter: DWORD;
  I: Integer;
begin
  LFake := TFakeClock.Create(UtcNow);
  LClock := LFake;
  LCollector := NewCollector(LClock, 1);
  // Первый вызов прогревает однократные ресурсы (загрузка DLL, кэши COM).
  LCollector.Collect(TMHSnapshot.Create(1, LClock.NowUtc));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 2 to 11 do
  begin
    LFake.AdvanceMs(1000);
    LCollector.Collect(TMHSnapshot.Create(I, LClock.NowUtc));
  end;
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.AreEqual(11, (LCollector as TMHAutostartCollector).ReadCount,
    'Каждый вызов должен перечитывать источники');
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 30,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

procedure TAutostartIntegrationTests.Shortcut_ReadDirectAndInStaThread;
var
  LInit: HRESULT;
  LLinkPath, LTarget, LArgs, LError: string;
  LSysDir: array[0..MAX_PATH] of Char;
  LCmd: string;

  procedure CreateShortcut;
  var
    LLink: IShellLinkW;
  begin
    OleCheck(CoCreateInstance(CLSID_ShellLink, nil, CLSCTX_INPROC_SERVER, IShellLinkW, LLink));
    OleCheck(LLink.SetPath(PChar(LCmd)));
    OleCheck(LLink.SetArguments('/c exit 0'));
    OleCheck((LLink as IPersistFile).Save(PChar(LLinkPath), True));
  end;

begin
  GetSystemDirectory(LSysDir, Length(LSysDir));
  LCmd := string(LSysDir) + '\cmd.exe';
  LLinkPath := TPath.Combine(TPath.GetTempPath,
    'MineHunterTest_' + IntToStr(GetCurrentProcessId) + '.lnk');
  LInit := CoInitializeEx(nil, COINIT_MULTITHREADED);
  try
    CreateShortcut;
    try
      Assert.IsTrue(TMHWinAutostartApi.ReadShortcut(LLinkPath, LTarget, LArgs, LError), LError);
      Assert.IsTrue(MHSamePath(LCmd, LTarget), LTarget);
      Assert.AreEqual('/c exit 0', LArgs);

      Assert.IsTrue(TMHWinAutostartApi.ReadShortcut(LLinkPath, LTarget, LArgs, LError, True),
        'STA: ' + LError);
      Assert.IsTrue(MHSamePath(LCmd, LTarget), LTarget);
      Assert.AreEqual('/c exit 0', LArgs);

      Assert.IsFalse(TMHWinAutostartApi.ReadShortcut(LLinkPath + '.missing.lnk', LTarget, LArgs,
        LError), 'Отсутствующий ярлык');
      Assert.IsNotEmpty(LError);
    finally
      System.SysUtils.DeleteFile(LLinkPath);
    end;
  finally
    if (LInit = S_OK) or (LInit = S_FALSE) then
      CoUninitialize;
  end;
end;

end.
