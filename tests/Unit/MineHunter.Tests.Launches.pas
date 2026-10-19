unit MineHunter.Tests.Launches;

{
  Журнал запусков: записи из событий ETW и из опроса списка процессов (без прав
  администратора), объединение запуска и завершения в хранилище, фильтр,
  приватность путей, длительность.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types;

type
  [TestFixture]
  [Category('Unit')]
  TLaunchJournalTests = class
  public
    [Test] procedure FileTimeConversion;
    [Test] procedure Etw_StartAndStop_BecomeRecords;
    [Test] procedure Polling_WithoutAdmin;
    [Test] procedure DurationText;
    [Test] procedure CommandLine_ArgumentsAndPathText;
    [Test] procedure Etw_CommandLineKeptAndLimited;
    [Test] procedure Polling_ReadsCommandLineOnlyForNewLaunches;
  end;

  [TestFixture]
  [Category('Integration')]
  TLaunchCommandLineIntegrationTests = class
  public
    [Test] procedure OwnProcess_CommandLineRead_WrongInstanceEmpty;
  end;

  [TestFixture]
  [Category('Storage')]
  TLaunchStorageTests = class
  private
    FDir: string;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure StartAndExit_Merged_FilterAndPeriod;
    [Test] procedure Privacy_NoPaths;
    [Test] procedure CommandLine_StoredMergedAndSearchable;
  end;

implementation

uses
  System.IOUtils, System.DateUtils, System.StrUtils,
  MineHunter.Core.Interfaces, MineHunter.Core.Launches, MineHunter.Collectors.ProcessEvents,
  MineHunter.Storage.SQLite, MineHunter.Tests.Fakes, MineHunter.Tests.ProcessEvents,
  MineHunter.Collectors.ProcessEvents.WinApi, Winapi.Windows;

const
  // 2026-10-16 12:00 UTC в формате FILETIME.
  CT_BASE: UInt64 = 134366256000000000;

function Rec(APid: Cardinal; ACreate: UInt64; const AName: string; AExit: TDateTime = 0): TMHLaunchRecord;
begin
  Result := Default(TMHLaunchRecord);
  Result.Pid := APid;
  Result.CreateTime := ACreate;
  Result.StartUtc := MHFileTimeToUtc(ACreate);
  Result.ExitUtc := AExit;
  Result.Name := AName;
  if AName <> '' then
    Result.ImagePath := 'C:\Apps\' + AName;
  Result.ParentPid := 100;
  Result.ParentName := 'explorer.exe';
  Result.Source := 'etw';
end;

{ TLaunchJournalTests }

procedure TLaunchJournalTests.FileTimeConversion;
begin
  Assert.AreEqual(EncodeDateTime(2026, 10, 16, 12, 0, 0, 0), MHFileTimeToUtc(CT_BASE), 1 / SecsPerDay);
  Assert.AreEqual(0.0, MHFileTimeToUtc(0));
end;

procedure TLaunchJournalTests.Etw_StartAndStop_BecomeRecords;
var
  LSource: TFakeEventSource;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
begin
  LSource := TFakeEventSource.Create;
  LIntf := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(100, 1), 'explorer.exe', FAKE_NOW);
  LSnapshot.Processes := [LInfo];
  LSource.AddStart(500, 100, CT_BASE, FAKE_NOW, 'C:\Apps\tool.exe');
  LSource.AddStop(500, CT_BASE, IncSecond(FAKE_NOW, 3));
  LResult := LIntf.Collect(LSnapshot);
  Assert.AreEqual(2, Integer(Length(LResult.LaunchEvents)));
  Assert.AreEqual('tool.exe', LResult.LaunchEvents[0].Name);
  Assert.AreEqual('explorer.exe', LResult.LaunchEvents[0].ParentName, 'Кто запустил');
  Assert.AreEqual(0.0, LResult.LaunchEvents[0].ExitUtc);
  Assert.IsTrue(LResult.LaunchEvents[1].ExitUtc > 0, 'Завершение');
  Assert.AreEqual('etw', LResult.LaunchEvents[0].Source);
  Assert.AreEqual(0, Integer(Length(LIntf.Collect(LSnapshot).LaunchEvents)), 'Записи отдаются один раз');
end;

procedure TLaunchJournalTests.Polling_WithoutAdmin;
var
  LSource: TFakeEventSource;
  LIntf: IMHCollector;
  LSnapshot: TMHSnapshot;
  LResult: TMHCollectionResult;
  A, B, C: TMHProcessInfo;
  LNames: string;
  LRecord: TMHLaunchRecord;
begin
  LSource := TFakeEventSource.Create;
  LSource.StartResult := False;
  LSource.StartDenied := True;
  LIntf := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  A := TMHProcessInfo.Create(TMHProcessId.Create(100, CT_BASE), 'explorer.exe', FAKE_NOW);
  B := TMHProcessInfo.Create(TMHProcessId.Create(200, CT_BASE + 1), 'old.exe', FAKE_NOW);
  C := TMHProcessInfo.Create(TMHProcessId.Create(300, CT_BASE + 2), 'new.exe', FAKE_NOW);
  C.ParentPid := 100;
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Processes := [A, B];
  LResult := LIntf.Collect(LSnapshot);
  Assert.AreEqual(Ord(ssPartial), Ord(LResult.Status.State), 'Журнал работает и без прав');
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.AreEqual(0, Integer(Length(LResult.LaunchEvents)), 'Уже работавшие программы — не запуски');
  LSnapshot := TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 2));
  LSnapshot.Processes := [A, C];
  LResult := LIntf.Collect(LSnapshot);
  Assert.AreEqual(2, Integer(Length(LResult.LaunchEvents)));
  LNames := '';
  for LRecord in LResult.LaunchEvents do
  begin
    LNames := LNames + LRecord.Name + IfThen(LRecord.ExitUtc > 0, '-exit', '-start') + ' ';
    Assert.AreEqual('poll', LRecord.Source);
  end;
  Assert.IsTrue(LNames.Contains('new.exe-start'), LNames);
  Assert.IsTrue(LNames.Contains('old.exe-exit'), LNames);
  for LRecord in LResult.LaunchEvents do
    if LRecord.Name = 'new.exe' then
      Assert.AreEqual('explorer.exe', LRecord.ParentName);
end;

procedure TLaunchJournalTests.DurationText;
begin
  Assert.AreEqual('', MHLaunchDurationText(Rec(1, CT_BASE, 'a.exe')), 'Работает');
  Assert.IsTrue(MHLaunchDurationText(Rec(1, CT_BASE, 'a.exe', MHFileTimeToUtc(CT_BASE) + 0.4 / SecsPerDay))
    .Contains('0'));
  Assert.AreEqual('5 мин', MHLaunchDurationText(Rec(1, CT_BASE, 'a.exe', MHFileTimeToUtc(CT_BASE) + 5 / MinsPerDay)));
  Assert.AreEqual('2 ч 10 мин', MHLaunchDurationText(Rec(1, CT_BASE, 'a.exe',
    MHFileTimeToUtc(CT_BASE) + 130 / MinsPerDay)));
end;

procedure TLaunchJournalTests.CommandLine_ArgumentsAndPathText;
var
  LRecord: TMHLaunchRecord;
begin
  Assert.AreEqual('--type=renderer --lang=ru',
    MHCommandLineArguments('"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=ru'));
  Assert.AreEqual('-k netsvcs -p', MHCommandLineArguments('C:\Windows\system32\svchost.exe -k netsvcs -p'));
  Assert.AreEqual('', MHCommandLineArguments('"C:\Apps\tool.exe"'), 'Без параметров');
  Assert.AreEqual('', MHCommandLineArguments('tool.exe'));
  Assert.AreEqual('', MHCommandLineArguments(''));
  Assert.AreEqual('', MHCommandLineArguments('"C:\незакрытая кавычка'), 'Повреждённая строка — без параметров');
  LRecord := Rec(1, CT_BASE, 'xmrig.exe');
  LRecord.CommandLine := 'xmrig.exe -o pool.example:3333 -u wallet';
  Assert.AreEqual('C:\Apps\xmrig.exe -o pool.example:3333 -u wallet', MHLaunchPathText(LRecord),
    'Путь из события и параметры из командной строки');
  LRecord.ImagePath := '';
  Assert.AreEqual('xmrig.exe -o pool.example:3333 -u wallet', MHLaunchPathText(LRecord), 'Без пути — командная строка');
  LRecord.CommandLine := '';
  LRecord.ImagePath := 'C:\Apps\a.exe';
  Assert.AreEqual('C:\Apps\a.exe', MHLaunchPathText(LRecord), 'Параметры не прочитаны — только путь');
end;

procedure TLaunchJournalTests.Etw_CommandLineKeptAndLimited;
var
  LSource: TFakeEventSource;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LSource := TFakeEventSource.Create;
  LIntf := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LSource.AddStart(500, 100, CT_BASE, FAKE_NOW, 'C:\Apps\tool.exe', '"C:\Apps\tool.exe" --silent');
  LSource.AddStart(501, 100, CT_BASE + 1, FAKE_NOW, 'C:\Apps\big.exe', 'big.exe ' + StringOfChar('x', 5000));
  LResult := LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual('"C:\Apps\tool.exe" --silent', LResult.LaunchEvents[0].CommandLine);
  Assert.AreEqual(MH_LAUNCH_COMMAND_LINE_MAX, Length(LResult.LaunchEvents[1].CommandLine), 'Огромная строка обрезана');
end;

procedure TLaunchJournalTests.Polling_ReadsCommandLineOnlyForNewLaunches;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
  LSnapshot: TMHSnapshot;
  LResult: TMHCollectionResult;
  A, B: TMHProcessInfo;
  LReads: Integer;
  LRecord: TMHLaunchRecord;
begin
  LSource := TFakeEventSource.Create;
  LSource.StartResult := False;
  LSource.StartDenied := True;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  LReads := 0;
  LCollector.CommandLineReader :=
    function(APid: Cardinal; ACreateTime: UInt64): string
    begin
      Inc(LReads);
      Result := Format('app%d.exe --id %d', [APid, Int64(ACreateTime - CT_BASE)]);
    end;
  A := TMHProcessInfo.Create(TMHProcessId.Create(100, CT_BASE), 'explorer.exe', FAKE_NOW);
  B := TMHProcessInfo.Create(TMHProcessId.Create(300, CT_BASE + 7), 'new.exe', FAKE_NOW);
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Processes := [A];
  LIntf.Collect(LSnapshot);
  Assert.AreEqual(0, LReads, 'Уже работавшие программы не опрашиваются');
  LSnapshot := TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 2));
  LSnapshot.Processes := [A, B];
  LResult := LIntf.Collect(LSnapshot);
  Assert.AreEqual(1, LReads, 'Только новый запуск');
  Assert.AreEqual('app300.exe --id 7', LResult.LaunchEvents[0].CommandLine);
  LSnapshot := TMHSnapshot.Create(3, IncSecond(FAKE_NOW, 4));
  LSnapshot.Processes := [A, B];
  LIntf.Collect(LSnapshot);
  Assert.AreEqual(1, LReads, 'Повторно не читается');
  // Завершение несёт те же параметры.
  LSnapshot := TMHSnapshot.Create(4, IncSecond(FAKE_NOW, 6));
  LSnapshot.Processes := [A];
  LResult := LIntf.Collect(LSnapshot);
  Assert.AreEqual(1, Integer(Length(LResult.LaunchEvents)));
  LRecord := LResult.LaunchEvents[0];
  Assert.IsTrue(LRecord.ExitUtc > 0);
  Assert.AreEqual('app300.exe --id 7', LRecord.CommandLine);
end;

{ TLaunchCommandLineIntegrationTests }

procedure TLaunchCommandLineIntegrationTests.OwnProcess_CommandLineRead_WrongInstanceEmpty;
var
  LCreate, LExit, LKernel, LUser: TFileTime;
  LLine: string;
begin
  Assert.IsTrue(GetProcessTimes(GetCurrentProcess, LCreate, LExit, LKernel, LUser));
  LLine := MHReadProcessCommandLine(GetCurrentProcessId, UInt64(LCreate));
  Assert.IsTrue(LLine.ToLower.Contains('minehunter.tests'), 'Своя командная строка: ' + LLine);
  Assert.AreEqual('', MHReadProcessCommandLine(GetCurrentProcessId, UInt64(LCreate) + 1),
    'Другой экземпляр с тем же PID — пусто');
  Assert.AreEqual('', MHReadProcessCommandLine(4, 0), 'System — без командной строки');
  Assert.AreEqual('', MHReadProcessCommandLine($7FFFFFF0, 0), 'Нет такого процесса');
end;

{ TLaunchStorageTests }

procedure TLaunchStorageTests.Setup;
begin
  FDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\launch-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(FDir);
end;

procedure TLaunchStorageTests.TearDown;
begin
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог тестов.
  end;
end;

procedure TLaunchStorageTests.StartAndExit_Merged_FilterAndPeriod;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LSnapshot: TMHSnapshot;
  LRows: TArray<TMHLaunchRecord>;
  LExit: TDateTime;
begin
  LRepo := TMHSQLiteRepository.Create(TPath.Combine(FDir, 'h.db'), TMHStorageOptions.Default,
    TFakeClock.Create(FAKE_NOW), TRecordingLogger.Create);
  LIntf := LRepo;
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.LaunchEvents := [Rec(500, CT_BASE, 'tool.exe'), Rec(501, CT_BASE + 10, 'xmrig.exe')];
  LRepo.SaveSnapshot(LSnapshot);
  // Завершение приходит отдельной записью без имени и пути.
  LExit := IncSecond(MHFileTimeToUtc(CT_BASE), 3);
  LSnapshot := TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 5));
  LSnapshot.LaunchEvents := [Rec(500, CT_BASE, '', LExit)];
  LRepo.SaveSnapshot(LSnapshot);
  LRows := LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 100);
  Assert.AreEqual(2, Integer(Length(LRows)), 'Запуск и завершение — одна строка');
  Assert.AreEqual('xmrig.exe', LRows[0].Name, 'Новые первыми');
  Assert.AreEqual('tool.exe', LRows[1].Name, 'Имя не затёрто записью завершения');
  Assert.AreEqual('C:\Apps\tool.exe', LRows[1].ImagePath);
  Assert.AreEqual(LExit, LRows[1].ExitUtc, 1 / SecsPerDay);
  Assert.AreEqual('explorer.exe', LRows[1].ParentName);
  Assert.AreEqual(1, Integer(Length(LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, 'XMRIG', 100))),
    'Фильтр без учёта регистра');
  Assert.AreEqual(2, Integer(Length(LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, 'explorer', 100))),
    'Фильтр по тому, кто запустил');
  Assert.AreEqual(1, Integer(Length(LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 1))));
  Assert.AreEqual(0, Integer(Length(LRepo.LoadLaunches(FAKE_NOW + 1, FAKE_NOW + 2, '', 100))));
  LRepo.Clear;
  Assert.AreEqual(0, Integer(Length(LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 100))));
  LIntf := nil;
end;

procedure TLaunchStorageTests.Privacy_NoPaths;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
  LSnapshot: TMHSnapshot;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.StoreProcessPaths := False;
  LRepo := TMHSQLiteRepository.Create(TPath.Combine(FDir, 'p.db'), LOptions, TFakeClock.Create(FAKE_NOW),
    TRecordingLogger.Create);
  LIntf := LRepo;
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.LaunchEvents := [Rec(500, CT_BASE, 'tool.exe')];
  LRepo.SaveSnapshot(LSnapshot);
  Assert.AreEqual('', LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 10)[0].ImagePath);
  LIntf := nil;
end;

procedure TLaunchStorageTests.CommandLine_StoredMergedAndSearchable;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
  LSnapshot: TMHSnapshot;
  LRecord: TMHLaunchRecord;
  LRows: TArray<TMHLaunchRecord>;
begin
  LRepo := TMHSQLiteRepository.Create(TPath.Combine(FDir, 'c.db'), TMHStorageOptions.Default,
    TFakeClock.Create(FAKE_NOW), TRecordingLogger.Create);
  LIntf := LRepo;
  LRecord := Rec(500, CT_BASE, 'xmrig.exe');
  LRecord.CommandLine := 'xmrig.exe -o pool.minexmr.com:443';
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.LaunchEvents := [LRecord];
  LRepo.SaveSnapshot(LSnapshot);
  // Завершение без командной строки не стирает её.
  LSnapshot := TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 5));
  LSnapshot.LaunchEvents := [Rec(500, CT_BASE, '', IncSecond(MHFileTimeToUtc(CT_BASE), 3))];
  LRepo.SaveSnapshot(LSnapshot);
  LRows := LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 10);
  Assert.AreEqual('xmrig.exe -o pool.minexmr.com:443', LRows[0].CommandLine);
  Assert.AreEqual(1, Integer(Length(LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, 'MINEXMR', 10))),
    'Поиск по параметрам');
  LIntf := nil;
  // Без хранения путей параметры тоже не сохраняются.
  LOptions := TMHStorageOptions.Default;
  LOptions.StoreProcessPaths := False;
  LRepo := TMHSQLiteRepository.Create(TPath.Combine(FDir, 'c2.db'), LOptions, TFakeClock.Create(FAKE_NOW),
    TRecordingLogger.Create);
  LIntf := LRepo;
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.LaunchEvents := [LRecord];
  LRepo.SaveSnapshot(LSnapshot);
  Assert.AreEqual('', LRepo.LoadLaunches(FAKE_NOW - 1, FAKE_NOW + 1, '', 10)[0].CommandLine);
  LIntf := nil;
end;

initialization
  TDUnitX.RegisterTestFixture(TLaunchJournalTests);
  TDUnitX.RegisterTestFixture(TLaunchCommandLineIntegrationTests);
  TDUnitX.RegisterTestFixture(TLaunchStorageTests);

end.
