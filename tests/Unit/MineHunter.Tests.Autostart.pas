unit MineHunter.Tests.Autostart;

{
  Unit-тесты коллектора автозапуска (MH-04) на управляемом двойнике
  IMHAutostartApi: разбор командных строк, кэширование по часам,
  независимые отказы источников и контракт IMHCollector.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Autostart,
  MineHunter.Tests.Fakes;

type
  /// Часы, время которых можно установить произвольно (в том числе назад).
  TManualClock = class(TInterfacedObject, IMHClock)
  private
    FNow: TDateTime;
  public
    constructor Create(ANowUtc: TDateTime);
    function NowUtc: TDateTime;
    function TickMs: UInt64;
    property Value: TDateTime read FNow write FNow;
  end;

  TFakeSourceMode = (fsmOk, fsmFail, fsmRaise, fsmWarning);

  /// Двойник IMHAutostartApi: данные и поведение каждого источника задаются тестом.
  TFakeAutostartApi = class(TInterfacedObject, IMHAutostartApi)
  private type
    TSource = record
      Entries: TArray<TMHAutostartEntry>;
      Mode: TFakeSourceMode;
      Calls: Integer;
    end;
  private
    FSources: array[0..3] of TSource;
    FFiles: TList<string>;
    FFileChecks: Integer;
    function Read(AIndex: Integer; out AEntries: TArray<TMHAutostartEntry>;
      out AError: string): Boolean;
  public const
    SRC_REGISTRY = 0;
    SRC_STARTUP = 1;
    SRC_SERVICES = 2;
    SRC_TASKS = 3;
  public
    constructor Create;
    destructor Destroy; override;
    function ReadRegistryRun(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadStartupFolders(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadServices(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadScheduledTasks(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function WindowsDir: string;
    function FileExists(const APath: string): Boolean;
    function ExpandEnvironment(const AText: string): string;
    procedure AddFile(const APath: string);
    procedure SetEntries(ASource: Integer; const AEntries: TArray<TMHAutostartEntry>);
    procedure SetMode(ASource: Integer; AMode: TFakeSourceMode);
    procedure SetAllModes(AMode: TFakeSourceMode);
    function Calls(ASource: Integer): Integer;
    property FileChecks: Integer read FFileChecks;
  end;

  [TestFixture]
  [Category('Unit')]
  TExtractExecutableTests = class
  private
    FFiles: TArray<string>;
    function Exists(APath: string): Boolean;
  public
    [Setup] procedure Setup;
    [Test]
    [TestCase('quoted with args', '"C:\Program Files\My App\app.exe" --silent|C:\Program Files\My App\app.exe', '|')]
    [TestCase('quoted missing', '"C:\Missing Dir\x.exe" -a|C:\Missing Dir\x.exe', '|')]
    [TestCase('doubled quotes', '""C:\Tools\miner.exe"" --wake|C:\Tools\miner.exe', '|')]
    [TestCase('bare powershell', 'powershell.exe -WindowStyle Hidden -File C:\x\a.ps1|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '|')]
    [TestCase('bare in windows dir', 'regedit.exe /s x.reg|C:\Windows\regedit.exe', '|')]
    [TestCase('quoted unclosed', '"C:\Tools\miner.exe|C:\Tools\miner.exe', '|')]
    [TestCase('unquoted with spaces', 'C:\Program Files\My App\app.exe --silent|C:\Program Files\My App\app.exe', '|')]
    [TestCase('unquoted args', 'C:\Tools\miner.exe -o pool.example:3333 -t 4|C:\Tools\miner.exe', '|')]
    [TestCase('no extension appends exe', 'C:\Tools\miner -o x|C:\Tools\miner.exe', '|')]
    [TestCase('env expanded', 'C:\Windows\System32\svchost.exe -k netsvcs -p|C:\Windows\System32\svchost.exe', '|')]
    [TestCase('env SystemRoot left', '%SystemRoot%\System32\svchost.exe -k netsvcs|C:\Windows\System32\svchost.exe', '|')]
    [TestCase('env windir left', '%windir%\system32\rundll32.exe x.dll,Run|C:\Windows\system32\rundll32.exe', '|')]
    [TestCase('SystemRoot prefix', '\SystemRoot\System32\drivers\foo.sys|C:\Windows\System32\drivers\foo.sys', '|')]
    [TestCase('NT prefix', '\??\C:\Tools\miner.exe|C:\Tools\miner.exe', '|')]
    [TestCase('relative driver', 'System32\drivers\foo.sys|C:\Windows\System32\drivers\foo.sys', '|')]
    [TestCase('bare svchost', 'svchost.exe -k netsvcs|C:\Windows\System32\svchost.exe', '|')]
    [TestCase('bare svchost no ext', 'svchost -k LocalService|C:\Windows\System32\svchost.exe', '|')]
    [TestCase('rundll32 bare', 'rundll32.exe C:\Users\u\AppData\x.dll,Start|C:\Windows\System32\rundll32.exe', '|')]
    [TestCase('rundll32 full', 'C:\Windows\System32\rundll32.exe "C:\Program Files\X\y.dll",Run|C:\Windows\System32\rundll32.exe', '|')]
    [TestCase('missing unquoted', 'C:\Program Files\Missing App\tool.exe /x|C:\Program Files\Missing App\tool.exe', '|')]
    [TestCase('missing no extension', 'C:\Missing\tool -x|C:\Missing\tool', '|')]
    [TestCase('missing bare', 'unknown.exe /x|', '|')]
    [TestCase('arg path not glued', 'C:\Missing\run C:\Tools\miner.exe|C:\Missing\run', '|')]
    [TestCase('forward slashes', 'C:/Tools/miner.exe|C:\Tools\miner.exe', '|')]
    [TestCase('long path prefix', '\\?\C:\Tools\miner.exe|C:\Tools\miner.exe', '|')]
    [TestCase('script', 'C:\Users\u\AppData\Roaming\start.vbs|C:\Users\u\AppData\Roaming\start.vbs', '|')]
    procedure Extract(const ACommand, AExpected: string);
    [Test] procedure EmptyAndBlank_GiveEmpty;
    [Test] procedure UnquotedPath_PrefersShortestExisting_LikeCreateProcess;
    [Test] procedure NilFileExists_UsesTextualGuess;
    [Test] procedure WindowsDirWithTrailingSlash_IsAccepted;
  end;

  [TestFixture]
  [Category('Unit')]
  TAutostartCollectorTests = class
  private
    FApi: TFakeAutostartApi;
    FApiIntf: IMHAutostartApi;
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FCollector: TMHAutostartCollector;
    FCollectorIntf: IMHCollector;
    function Collect: TMHCollectionResult;
    procedure FillAllSources;
    procedure CreateWithNilApi;
    procedure CreateWithNilClock;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_NilArguments_Raise;
    [Test] procedure FirstCollect_ReadsAllSources;
    [Test] procedure ItemCount_EqualsEntries;
    [Test] procedure SecondCollect_WithinRefresh_UsesCache;
    [Test] procedure Collect_AfterRefreshInterval_Rereads;
    [Test] procedure ClockMovedBack_Rereads;
    [Test] procedure ZeroRefresh_ReadsEveryTime;
    [Test] procedure Invalidate_ForcesReread;
    [Test] procedure OneSourceFails_IsPartial_NamesSource;
    [Test] procedure SourceRaises_IsPartial_NotException;
    [Test] procedure SourceWarning_IsPartial;
    [Test] procedure AllSourcesFail_IsError_AndNotCached;
    [Test] procedure ImagePath_FilledFromCommand;
    [Test] procedure ImagePath_FromSource_IsKeptAndNormalized;
    [Test] procedure ImagePath_UsesEnvironmentExpansion;
    [Test] procedure FileChecks_AreCachedWithinRead;
    [Test] procedure Result_IsCopyOfCache;
    [Test] procedure Status_TimestampFromSnapshot;
    [Test] procedure EmptySnapshot_TimestampFromClock;
    [Test] procedure Contract_SourceIdAndDisplayName;
  end;

implementation

uses
  System.StrUtils;

const
  FAKE_WINDIR = 'C:\Windows';

function Entry(AKind: TMHAutostartKind; const AName, ACommand: string;
  const AImagePath: string = ''): TMHAutostartEntry;
begin
  Result := Default(TMHAutostartEntry);
  Result.Kind := AKind;
  Result.Scope := asMachine;
  Result.Name := AName;
  Result.Command := ACommand;
  Result.ImagePath := AImagePath;
  Result.Location := 'test';
  Result.Enabled := True;
end;

function FindEntry(const AResult: TMHCollectionResult; const AName: string;
  out AEntry: TMHAutostartEntry): Boolean;
var
  LItem: TMHAutostartEntry;
begin
  for LItem in AResult.Autostart do
    if LItem.Name = AName then
    begin
      AEntry := LItem;
      Exit(True);
    end;
  AEntry := Default(TMHAutostartEntry);
  Result := False;
end;

{ TManualClock }

constructor TManualClock.Create(ANowUtc: TDateTime);
begin
  inherited Create;
  FNow := ANowUtc;
end;

function TManualClock.NowUtc: TDateTime;
begin
  Result := FNow;
end;

function TManualClock.TickMs: UInt64;
begin
  Result := 0;
end;

{ TFakeAutostartApi }

constructor TFakeAutostartApi.Create;
begin
  inherited Create;
  FFiles := TList<string>.Create;
end;

destructor TFakeAutostartApi.Destroy;
begin
  FFiles.Free;
  inherited;
end;

function TFakeAutostartApi.Read(AIndex: Integer; out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
begin
  Inc(FSources[AIndex].Calls);
  AEntries := nil;
  AError := '';
  case FSources[AIndex].Mode of
    fsmFail:
      begin
        AError := Format('сбой источника %d', [AIndex]);
        Exit(False);
      end;
    fsmRaise:
      raise EMHError.CreateFmt('исключение источника %d', [AIndex]);
    fsmWarning:
      AError := Format('частично источник %d', [AIndex]);
  end;
  AEntries := Copy(FSources[AIndex].Entries);
  Result := True;
end;

function TFakeAutostartApi.ReadRegistryRun(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
begin
  Result := Read(SRC_REGISTRY, AEntries, AError);
end;

function TFakeAutostartApi.ReadStartupFolders(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
begin
  Result := Read(SRC_STARTUP, AEntries, AError);
end;

function TFakeAutostartApi.ReadServices(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
begin
  Result := Read(SRC_SERVICES, AEntries, AError);
end;

function TFakeAutostartApi.ReadScheduledTasks(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
begin
  Result := Read(SRC_TASKS, AEntries, AError);
end;

function TFakeAutostartApi.WindowsDir: string;
begin
  Result := FAKE_WINDIR;
end;

function TFakeAutostartApi.FileExists(const APath: string): Boolean;
var
  LFile: string;
begin
  Inc(FFileChecks);
  for LFile in FFiles do
    if SameText(LFile, APath) then
      Exit(True);
  Result := False;
end;

function TFakeAutostartApi.ExpandEnvironment(const AText: string): string;
begin
  Result := StringReplace(AText, '%ProgramFiles%', 'C:\Program Files', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '%SystemRoot%', FAKE_WINDIR, [rfReplaceAll, rfIgnoreCase]);
end;

procedure TFakeAutostartApi.AddFile(const APath: string);
begin
  FFiles.Add(APath);
end;

procedure TFakeAutostartApi.SetEntries(ASource: Integer; const AEntries: TArray<TMHAutostartEntry>);
begin
  FSources[ASource].Entries := AEntries;
end;

procedure TFakeAutostartApi.SetMode(ASource: Integer; AMode: TFakeSourceMode);
begin
  FSources[ASource].Mode := AMode;
end;

procedure TFakeAutostartApi.SetAllModes(AMode: TFakeSourceMode);
var
  I: Integer;
begin
  for I := Low(FSources) to High(FSources) do
    FSources[I].Mode := AMode;
end;

function TFakeAutostartApi.Calls(ASource: Integer): Integer;
begin
  Result := FSources[ASource].Calls;
end;

{ TExtractExecutableTests }

procedure TExtractExecutableTests.Setup;
begin
  FFiles := [
    'C:\Program Files\My App\app.exe',
    'C:\Windows\System32\svchost.exe',
    'C:\Windows\System32\rundll32.exe',
    'C:\Windows\System32\drivers\foo.sys',
    'C:\Tools\miner.exe',
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    'C:\Windows\regedit.exe'];
end;

function TExtractExecutableTests.Exists(APath: string): Boolean;
begin
  Result := MatchText(APath, FFiles);
end;

procedure TExtractExecutableTests.Extract(const ACommand, AExpected: string);
begin
  Assert.AreEqual(AExpected, MHExtractExecutable(ACommand, FAKE_WINDIR, Exists), True,
    'Команда: ' + ACommand);
end;

procedure TExtractExecutableTests.EmptyAndBlank_GiveEmpty;
begin
  Assert.AreEqual('', MHExtractExecutable('', FAKE_WINDIR, Exists));
  Assert.AreEqual('', MHExtractExecutable('   ', FAKE_WINDIR, Exists));
  Assert.AreEqual('', MHExtractExecutable('""', FAKE_WINDIR, Exists));
end;

procedure TExtractExecutableTests.UnquotedPath_PrefersShortestExisting_LikeCreateProcess;
begin
  // CreateProcess для пути без кавычек сначала пробует «C:\Program.exe» —
  // классическая подмена через незакавыченный путь. Коллектор показывает
  // файл, который реально будет запущен.
  FFiles := FFiles + ['C:\Program.exe'];
  Assert.AreEqual('C:\Program.exe',
    MHExtractExecutable('C:\Program Files\My App\app.exe --silent', FAKE_WINDIR, Exists));
  // В кавычках подмена невозможна.
  Assert.AreEqual('C:\Program Files\My App\app.exe',
    MHExtractExecutable('"C:\Program Files\My App\app.exe" --silent', FAKE_WINDIR, Exists));
end;

procedure TExtractExecutableTests.NilFileExists_UsesTextualGuess;
begin
  Assert.AreEqual('C:\Program Files\My App\app.exe',
    MHExtractExecutable('"C:\Program Files\My App\app.exe" -x', FAKE_WINDIR, nil));
  Assert.AreEqual('C:\Program Files\My App\app.exe',
    MHExtractExecutable('C:\Program Files\My App\app.exe -x', FAKE_WINDIR, nil));
  Assert.AreEqual('', MHExtractExecutable('svchost.exe -k netsvcs', FAKE_WINDIR, nil));
end;

procedure TExtractExecutableTests.WindowsDirWithTrailingSlash_IsAccepted;
begin
  Assert.AreEqual('C:\Windows\System32\svchost.exe',
    MHExtractExecutable('svchost.exe -k netsvcs', FAKE_WINDIR + '\', Exists));
  Assert.AreEqual('C:\Windows\System32\drivers\foo.sys',
    MHExtractExecutable('\SystemRoot\System32\drivers\foo.sys', FAKE_WINDIR + '\', Exists));
end;

{ TAutostartCollectorTests }

procedure TAutostartCollectorTests.Setup;
begin
  FApi := TFakeAutostartApi.Create;
  FApiIntf := FApi;
  FApi.AddFile('C:\Windows\System32\svchost.exe');
  FApi.AddFile('C:\Program Files\Vendor\agent.exe');
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FCollector := TMHAutostartCollector.Create(FApiIntf, FClockIntf, 60);
  FCollectorIntf := FCollector;
end;

procedure TAutostartCollectorTests.TearDown;
begin
  FCollectorIntf := nil;
  FCollector := nil;
  FClockIntf := nil;
  FClock := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TAutostartCollectorTests.Collect: TMHCollectionResult;
begin
  Result := FCollectorIntf.Collect(TMHSnapshot.Create(1, FClock.NowUtc));
end;

procedure TAutostartCollectorTests.FillAllSources;
begin
  FApi.SetEntries(TFakeAutostartApi.SRC_REGISTRY, [
    Entry(akRegistryRun, 'Agent', 'C:\Program Files\Vendor\agent.exe /background'),
    Entry(akRegistryRunOnce, 'Setup', '"C:\Temp\setup.exe" /finish')]);
  FApi.SetEntries(TFakeAutostartApi.SRC_STARTUP, [
    Entry(akStartupFolder, 'Tool.lnk', '"C:\Tools\tool.exe"', 'C:\Tools\tool.exe')]);
  FApi.SetEntries(TFakeAutostartApi.SRC_SERVICES, [
    Entry(akService, 'Svc1', '%SystemRoot%\System32\svchost.exe -k netsvcs -p'),
    Entry(akService, 'Svc2', 'svchost.exe -k LocalService')]);
  FApi.SetEntries(TFakeAutostartApi.SRC_TASKS, [
    Entry(akScheduledTask, '\Updater', '%ProgramFiles%\Vendor\agent.exe --update')]);
end;

procedure TAutostartCollectorTests.CreateWithNilApi;
var
  LCollector: IMHCollector;
begin
  LCollector := TMHAutostartCollector.Create(nil, FClockIntf);
end;

procedure TAutostartCollectorTests.CreateWithNilClock;
var
  LCollector: IMHCollector;
begin
  LCollector := TMHAutostartCollector.Create(FApiIntf, nil);
end;

procedure TAutostartCollectorTests.Create_NilArguments_Raise;
begin
  Assert.WillRaise(CreateWithNilApi, EArgumentNilException);
  Assert.WillRaise(CreateWithNilClock, EArgumentNilException);
end;

procedure TAutostartCollectorTests.FirstCollect_ReadsAllSources;
var
  LResult: TMHCollectionResult;
  I: Integer;
begin
  FillAllSources;
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual('', LResult.Status.Message);
  for I := TFakeAutostartApi.SRC_REGISTRY to TFakeAutostartApi.SRC_TASKS do
    Assert.AreEqual(1, FApi.Calls(I));
  Assert.AreEqual(1, FCollector.ReadCount);
  Assert.AreEqual(6, Integer(Length(LResult.Autostart)));
end;

procedure TAutostartCollectorTests.ItemCount_EqualsEntries;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  LResult := Collect;
  Assert.AreEqual(Integer(Length(LResult.Autostart)), LResult.Status.ItemCount);
  FApi.SetEntries(TFakeAutostartApi.SRC_TASKS, nil);
  FCollector.Invalidate;
  LResult := Collect;
  Assert.AreEqual(5, LResult.Status.ItemCount);
  Assert.AreEqual(Integer(Length(LResult.Autostart)), LResult.Status.ItemCount);
end;

procedure TAutostartCollectorTests.SecondCollect_WithinRefresh_UsesCache;
var
  LFirst, LSecond: TMHCollectionResult;
begin
  FillAllSources;
  LFirst := Collect;
  FClock.AdvanceMs(59 * 1000);
  LSecond := Collect;
  Assert.AreEqual(1, FApi.Calls(TFakeAutostartApi.SRC_SERVICES));
  Assert.AreEqual(1, FCollector.ReadCount);
  Assert.AreEqual(Integer(Length(LFirst.Autostart)), Integer(Length(LSecond.Autostart)));
  Assert.AreEqual<TMHSourceState>(LFirst.Status.State, LSecond.Status.State);
  Assert.AreEqual(LFirst.Status.ItemCount, LSecond.Status.ItemCount);
end;

procedure TAutostartCollectorTests.Collect_AfterRefreshInterval_Rereads;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  FillAllSources;
  Collect;
  // Новое значение в реестре появится только после истечения интервала.
  FApi.SetEntries(TFakeAutostartApi.SRC_REGISTRY, [
    Entry(akRegistryRun, 'NewMiner', 'C:\Users\u\AppData\Roaming\xmr.exe')]);
  FClock.AdvanceMs(30 * 1000);
  Assert.IsFalse(FindEntry(Collect, 'NewMiner', LEntry));
  FClock.AdvanceMs(30 * 1000);
  LResult := Collect;
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_REGISTRY));
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_TASKS));
  Assert.IsTrue(FindEntry(LResult, 'NewMiner', LEntry));
  Assert.AreEqual('C:\Users\u\AppData\Roaming\xmr.exe', LEntry.ImagePath);
end;

procedure TAutostartCollectorTests.ClockMovedBack_Rereads;
var
  LClock: TManualClock;
  LClockIntf: IMHClock;
  LCollector: IMHCollector;
begin
  FillAllSources;
  LClock := TManualClock.Create(FAKE_NOW);
  LClockIntf := LClock;
  LCollector := TMHAutostartCollector.Create(FApiIntf, LClockIntf, 60);
  LCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(1, FApi.Calls(TFakeAutostartApi.SRC_REGISTRY));
  // Часы перевели назад (синхронизация времени) — кэш считается устаревшим.
  LClock.Value := FAKE_NOW - 1 / HoursPerDay;
  LCollector.Collect(TMHSnapshot.Create(2, LClock.Value));
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_REGISTRY));
  // Время снимка на кэш не влияет — только часы коллектора.
  LCollector.Collect(TMHSnapshot.Create(3, FAKE_NOW + 1));
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_REGISTRY));
end;

procedure TAutostartCollectorTests.ZeroRefresh_ReadsEveryTime;
var
  LCollector: IMHCollector;
  I: Integer;
begin
  FillAllSources;
  LCollector := TMHAutostartCollector.Create(FApiIntf, FClockIntf, 0);
  for I := 1 to 3 do
    LCollector.Collect(TMHSnapshot.Create(I, FAKE_NOW));
  Assert.AreEqual(3, FApi.Calls(TFakeAutostartApi.SRC_STARTUP));
end;

procedure TAutostartCollectorTests.Invalidate_ForcesReread;
begin
  FillAllSources;
  Collect;
  Collect;
  Assert.AreEqual(1, FCollector.ReadCount);
  FCollector.Invalidate;
  Collect;
  Assert.AreEqual(2, FCollector.ReadCount);
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_SERVICES));
end;

procedure TAutostartCollectorTests.OneSourceFails_IsPartial_NamesSource;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  FillAllSources;
  FApi.SetMode(TFakeAutostartApi.SRC_TASKS, fsmFail);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('планировщик заданий'), LResult.Status.Message);
  Assert.IsTrue(LResult.Status.Message.Contains('сбой источника 3'), LResult.Status.Message);
  Assert.IsFalse(LResult.Status.Message.Contains('службы'), LResult.Status.Message);
  Assert.AreEqual(5, LResult.Status.ItemCount);
  Assert.IsTrue(FindEntry(LResult, 'Svc1', LEntry));
  Assert.IsFalse(FindEntry(LResult, '\Updater', LEntry));
  // Частичный результат кэшируется вместе со статусом.
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.AreEqual(1, FCollector.ReadCount);
end;

procedure TAutostartCollectorTests.SourceRaises_IsPartial_NotException;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  FApi.SetMode(TFakeAutostartApi.SRC_SERVICES, fsmRaise);
  FApi.SetMode(TFakeAutostartApi.SRC_STARTUP, fsmFail);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('службы'), LResult.Status.Message);
  Assert.IsTrue(LResult.Status.Message.Contains('исключение источника 2'), LResult.Status.Message);
  Assert.IsTrue(LResult.Status.Message.Contains('папки автозагрузки'), LResult.Status.Message);
  Assert.AreEqual(3, LResult.Status.ItemCount);
  Assert.AreEqual(1, FApi.Calls(TFakeAutostartApi.SRC_TASKS), 'Остальные источники читаются');
end;

procedure TAutostartCollectorTests.SourceWarning_IsPartial;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  FApi.SetMode(TFakeAutostartApi.SRC_SERVICES, fsmWarning);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('Неполные данные'), LResult.Status.Message);
  Assert.IsTrue(LResult.Status.Message.Contains('частично источник 2'), LResult.Status.Message);
  Assert.AreEqual(6, LResult.Status.ItemCount, 'Данные источника с предупреждением сохраняются');
end;

procedure TAutostartCollectorTests.AllSourcesFail_IsError_AndNotCached;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  FApi.SetAllModes(fsmFail);
  FApi.SetMode(TFakeAutostartApi.SRC_REGISTRY, fsmRaise);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssError, LResult.Status.State);
  Assert.IsNotEmpty(LResult.Status.Message);
  Assert.AreEqual(0, LResult.Status.ItemCount);
  Assert.AreEqual(0, Integer(Length(LResult.Autostart)));
  Assert.AreEqual(TMHAutostartCollector.SourceIdValue, LResult.Status.SourceId);
  // Ошибка не кэшируется: следующий вызов пробует снова и восстанавливается.
  FApi.SetAllModes(fsmOk);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(6, LResult.Status.ItemCount);
  Assert.AreEqual(2, FApi.Calls(TFakeAutostartApi.SRC_REGISTRY));
end;

procedure TAutostartCollectorTests.ImagePath_FilledFromCommand;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  FillAllSources;
  LResult := Collect;
  Assert.IsTrue(FindEntry(LResult, 'Agent', LEntry));
  Assert.AreEqual('C:\Program Files\Vendor\agent.exe', LEntry.ImagePath);
  Assert.AreEqual('C:\Program Files\Vendor\agent.exe /background', LEntry.Command,
    'Исходная команда не изменяется');
  Assert.IsTrue(FindEntry(LResult, 'Setup', LEntry));
  Assert.AreEqual('C:\Temp\setup.exe', LEntry.ImagePath, 'Отсутствующий файл в кавычках');
  Assert.IsTrue(FindEntry(LResult, 'Svc2', LEntry));
  Assert.AreEqual('C:\Windows\System32\svchost.exe', LEntry.ImagePath);
end;

procedure TAutostartCollectorTests.ImagePath_FromSource_IsKeptAndNormalized;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  FApi.SetEntries(TFakeAutostartApi.SRC_STARTUP, [
    Entry(akStartupFolder, 'A.lnk', 'ignored.exe', 'C:/Tools/./tool.exe'),
    Entry(akStartupFolder, 'B.lnk', '"C:\Other\b.exe"', '%SystemRoot%\b.exe')]);
  LResult := Collect;
  Assert.IsTrue(FindEntry(LResult, 'A.lnk', LEntry));
  Assert.AreEqual('C:\Tools\tool.exe', LEntry.ImagePath);
  Assert.IsTrue(FindEntry(LResult, 'B.lnk', LEntry));
  Assert.AreEqual('C:\Windows\b.exe', LEntry.ImagePath);
end;

procedure TAutostartCollectorTests.ImagePath_UsesEnvironmentExpansion;
var
  LResult: TMHCollectionResult;
  LEntry: TMHAutostartEntry;
begin
  FillAllSources;
  LResult := Collect;
  Assert.IsTrue(FindEntry(LResult, '\Updater', LEntry));
  Assert.AreEqual('C:\Program Files\Vendor\agent.exe', LEntry.ImagePath);
  Assert.AreEqual('%ProgramFiles%\Vendor\agent.exe --update', LEntry.Command);
  Assert.IsTrue(FindEntry(LResult, 'Svc1', LEntry));
  Assert.AreEqual('C:\Windows\System32\svchost.exe', LEntry.ImagePath);
end;

procedure TAutostartCollectorTests.FileChecks_AreCachedWithinRead;
var
  LEntries: TArray<TMHAutostartEntry>;
  I, LChecksAfterFirst: Integer;
begin
  LEntries := nil;
  for I := 1 to 50 do
    LEntries := LEntries + [Entry(akService, 'S' + IntToStr(I), 'svchost.exe -k group' + IntToStr(I))];
  FApi.SetEntries(TFakeAutostartApi.SRC_SERVICES, LEntries);
  Collect;
  LChecksAfterFirst := FApi.FileChecks;
  Assert.IsTrue(LChecksAfterFirst <= 2, Format('Проверок существования: %d', [LChecksAfterFirst]));
end;

procedure TAutostartCollectorTests.Result_IsCopyOfCache;
var
  LFirst, LSecond: TMHCollectionResult;
begin
  FillAllSources;
  LFirst := Collect;
  LFirst.Autostart[0].ImagePath := 'C:\tampered.exe';
  LSecond := Collect;
  Assert.AreNotEqual('C:\tampered.exe', LSecond.Autostart[0].ImagePath);
end;

procedure TAutostartCollectorTests.Status_TimestampFromSnapshot;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  LResult := FCollectorIntf.Collect(TMHSnapshot.Create(7, FAKE_NOW - 1));
  Assert.AreEqual(Double(FAKE_NOW - 1), Double(LResult.Status.TimestampUtc), 1e-9);
  // Из кэша — с временем нового снимка.
  LResult := FCollectorIntf.Collect(TMHSnapshot.Create(8, FAKE_NOW - 0.5));
  Assert.AreEqual(Double(FAKE_NOW - 0.5), Double(LResult.Status.TimestampUtc), 1e-9);
end;

procedure TAutostartCollectorTests.EmptySnapshot_TimestampFromClock;
var
  LResult: TMHCollectionResult;
begin
  FillAllSources;
  LResult := FCollectorIntf.Collect(Default(TMHSnapshot));
  Assert.AreEqual(Double(FClock.NowUtc), Double(LResult.Status.TimestampUtc), 1e-9);
  Assert.AreEqual(TMHAutostartCollector.SourceIdValue, LResult.Status.SourceId);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
end;

procedure TAutostartCollectorTests.Contract_SourceIdAndDisplayName;
var
  LResult: TMHCollectionResult;
begin
  Assert.AreEqual('autostart', FCollectorIntf.SourceId);
  Assert.IsNotEmpty(FCollectorIntf.DisplayName);
  // Пустые источники — успешный результат без элементов.
  LResult := Collect;
  Assert.AreEqual(FCollectorIntf.SourceId, LResult.Status.SourceId);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(0, LResult.Status.ItemCount);
  Assert.AreEqual(0, Integer(Length(LResult.Processes)));
end;

end.
