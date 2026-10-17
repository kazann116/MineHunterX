unit MineHunter.Tests.FileInspector;

{
  Unit-тесты инспектора файлов (TMHFileCollector) на поддельном IMHFileApi:
  бюджет времени и лимит проверок за цикл, кеш и его инвалидация, большие
  файлы, повтор неудачных проверок, вытеснение из кеша, сбор путей из снимка.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Files,
  MineHunter.Tests.Fakes;

type
  TFakeFile = record
    Size: Int64;
    LastWriteUtc: TDateTime;
    State: TMHSignatureState;
    Signer: string;
    Source: string;
    SignatureFails: Boolean;
    HashFails: Boolean;
    RaiseOnHash: Boolean;
  end;

  /// Управляемая файловая система в памяти. Каждая проверка подписи
  /// «занимает» CostMs миллисекунд собственного счётчика TickMs.
  TFakeFileApi = class(TInterfacedObject, IMHFileApi)
  private
    FFiles: TDictionary<string, TFakeFile>;
    FStampCalls: TDictionary<string, Integer>;
    FHashCalls: TDictionary<string, Integer>;
    FSignatureCalls: TDictionary<string, Integer>;
    FTick: UInt64;
    FCostMs: Cardinal;
    procedure Count(ADict: TDictionary<string, Integer>; const APath: string);
    function CountOf(ADict: TDictionary<string, Integer>; const APath: string): Integer;
    function Total(ADict: TDictionary<string, Integer>): Integer;
  public
    constructor Create;
    destructor Destroy; override;
    function GetFileStamp(const APath: string; out ASize: Int64;
      out ALastWriteUtc: TDateTime): Boolean;
    function ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
    function VerifySignature(const APath: string; out AState: TMHSignatureState;
      out ASigner, ASource, AError: string): Boolean;
    function TickMs: UInt64;

    procedure AddFile(const APath: string; ASize: Int64 = 1000;
      AState: TMHSignatureState = sgSignedTrusted);
    procedure SetFile(const APath: string; const AFile: TFakeFile);
    function GetFile(const APath: string): TFakeFile;
    procedure RemoveFile(const APath: string);
    function StampCalls(const APath: string): Integer;
    function HashCalls(const APath: string): Integer;
    function SignatureCalls(const APath: string): Integer;
    function TotalHashCalls: Integer;
    function TotalSignatureCalls: Integer;
    class function ExpectedHash(const APath: string; ASize: Int64): string; static;
    property CostMs: Cardinal read FCostMs write FCostMs;
  end;

  [TestFixture]
  [Category('Unit')]
  TFileInspectorTests = class
  private
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FApi: TFakeFileApi;
    FApiIntf: IMHFileApi;
    FCollector: TMHFileCollector;
    FCollectorIntf: IMHCollector;
    procedure NewCollector(ABudgetMs: Cardinal = 300; AMaxFilesPerCycle: Integer = 30;
      AMaxHashBytes: Int64 = 512 * 1024 * 1024; AMaxCacheEntries: Integer = 5000);
    function Snapshot(const AProcessPaths: array of string;
      const AAutostartPaths: array of string): TMHSnapshot;
    function CollectPaths(const APaths: array of string): TMHCollectionResult;
    function Find(const AResult: TMHCollectionResult; const APath: string;
      out AInfo: TMHFileInfo): Boolean;
    function CountPending(const AResult: TMHCollectionResult): Integer;
    procedure AddFiles(ACount: Integer; out APaths: TArray<string>);
    procedure CreateWithNilApi;
    procedure CreateWithNilClock;
    procedure CreateWithZeroCap;
    procedure CreateWithNegativeHashLimit;
    procedure CreateWithZeroCache;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_InvalidArguments_Raise;
    [Test] procedure Paths_FromProcessesAndAutostart_NormalizedAndDeduplicated;
    [Test] procedure Paths_EmptyAndRelative_AreSkipped;
    [Test] procedure Inspect_FillsAllFields_Success;
    [Test] procedure PerCycleCap_PartialThenCompleteOverCycles;
    [Test] procedure TimeBudget_PartialThenCompleteOverCycles;
    [Test] procedure SlowFile_AtLeastOneInspectionPerCycle;
    [Test] procedure SecondCycle_UsesCache_NoRecompute;
    [Test] procedure SizeChange_InvalidatesCache;
    [Test] procedure LastWriteChange_InvalidatesCache;
    [Test] procedure TooLargeFile_SignatureVerified_HashSkipped;
    [Test] procedure MissingFile_ErrorAndRetryAtMostOncePerMinute;
    [Test] procedure SignatureCheckFailure_IsRetriedAfterInterval;
    [Test] procedure HashFailure_KeepsSignature_IsRetried;
    [Test] procedure UnsignedAndUntrusted_AreCachedAsDefiniteResults;
    [Test] procedure UnexpectedApiException_BecomesFileError;
    [Test] procedure Cache_IsBounded_LeastRecentlyUsedEvicted;
    [Test] procedure EmptySnapshot_IsSuccessWithoutFiles;
    [Test] procedure ResultMatchesCollectorContract;
  end;

implementation

uses
  MineHunter.Core.Paths;

{ TFakeFileApi }

constructor TFakeFileApi.Create;
begin
  inherited Create;
  FFiles := TDictionary<string, TFakeFile>.Create;
  FStampCalls := TDictionary<string, Integer>.Create;
  FHashCalls := TDictionary<string, Integer>.Create;
  FSignatureCalls := TDictionary<string, Integer>.Create;
  FTick := 5000;
end;

destructor TFakeFileApi.Destroy;
begin
  FSignatureCalls.Free;
  FHashCalls.Free;
  FStampCalls.Free;
  FFiles.Free;
  inherited;
end;

procedure TFakeFileApi.Count(ADict: TDictionary<string, Integer>; const APath: string);
var
  LValue: Integer;
begin
  if not ADict.TryGetValue(APath.ToLower, LValue) then
    LValue := 0;
  ADict.AddOrSetValue(APath.ToLower, LValue + 1);
end;

function TFakeFileApi.CountOf(ADict: TDictionary<string, Integer>; const APath: string): Integer;
begin
  if not ADict.TryGetValue(APath.ToLower, Result) then
    Result := 0;
end;

function TFakeFileApi.Total(ADict: TDictionary<string, Integer>): Integer;
var
  LValue: Integer;
begin
  Result := 0;
  for LValue in ADict.Values do
    Inc(Result, LValue);
end;

class function TFakeFileApi.ExpectedHash(const APath: string; ASize: Int64): string;
begin
  Result := Format('hash:%s:%d', [APath.ToLower, ASize]);
end;

function TFakeFileApi.GetFileStamp(const APath: string; out ASize: Int64;
  out ALastWriteUtc: TDateTime): Boolean;
var
  LFile: TFakeFile;
begin
  Count(FStampCalls, APath);
  ASize := -1;
  ALastWriteUtc := 0;
  Result := FFiles.TryGetValue(APath.ToLower, LFile);
  if Result then
  begin
    ASize := LFile.Size;
    ALastWriteUtc := LFile.LastWriteUtc;
  end;
end;

function TFakeFileApi.ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
var
  LFile: TFakeFile;
begin
  Count(FHashCalls, APath);
  AHash := '';
  AError := '';
  if not FFiles.TryGetValue(APath.ToLower, LFile) then
  begin
    AError := 'simulated not found';
    Exit(False);
  end;
  if LFile.RaiseOnHash then
    raise EInOutError.Create('simulated unexpected failure');
  if LFile.HashFails then
  begin
    AError := 'simulated read failure';
    Exit(False);
  end;
  AHash := ExpectedHash(APath, LFile.Size);
  Result := True;
end;

function TFakeFileApi.VerifySignature(const APath: string; out AState: TMHSignatureState;
  out ASigner, ASource, AError: string): Boolean;
var
  LFile: TFakeFile;
begin
  Count(FSignatureCalls, APath);
  Inc(FTick, FCostMs);
  AState := sgCheckFailed;
  ASigner := '';
  ASource := '';
  AError := '';
  if not FFiles.TryGetValue(APath.ToLower, LFile) then
  begin
    AError := 'simulated not found';
    Exit(False);
  end;
  if LFile.SignatureFails then
  begin
    AError := 'simulated WinVerifyTrust failure';
    Exit(False);
  end;
  AState := LFile.State;
  case LFile.State of
    sgSignedTrusted:
      begin
        ASigner := LFile.Signer;
        ASource := LFile.Source;
      end;
    sgSignedUntrusted:
      begin
        ASource := LFile.Source;
        AError := 'файл изменён после подписания';
      end;
  end;
  Result := True;
end;

function TFakeFileApi.TickMs: UInt64;
begin
  Result := FTick;
end;

procedure TFakeFileApi.AddFile(const APath: string; ASize: Int64; AState: TMHSignatureState);
var
  LFile: TFakeFile;
begin
  LFile := Default(TFakeFile);
  LFile.Size := ASize;
  LFile.LastWriteUtc := FAKE_NOW - 1;
  LFile.State := AState;
  if AState in [sgSignedTrusted, sgSignedUntrusted] then
  begin
    LFile.Signer := 'Test Publisher';
    LFile.Source := 'embedded';
  end;
  FFiles.AddOrSetValue(APath.ToLower, LFile);
end;

procedure TFakeFileApi.SetFile(const APath: string; const AFile: TFakeFile);
begin
  FFiles.AddOrSetValue(APath.ToLower, AFile);
end;

function TFakeFileApi.GetFile(const APath: string): TFakeFile;
begin
  Result := FFiles[APath.ToLower];
end;

procedure TFakeFileApi.RemoveFile(const APath: string);
begin
  FFiles.Remove(APath.ToLower);
end;

function TFakeFileApi.StampCalls(const APath: string): Integer;
begin
  Result := CountOf(FStampCalls, APath);
end;

function TFakeFileApi.HashCalls(const APath: string): Integer;
begin
  Result := CountOf(FHashCalls, APath);
end;

function TFakeFileApi.SignatureCalls(const APath: string): Integer;
begin
  Result := CountOf(FSignatureCalls, APath);
end;

function TFakeFileApi.TotalHashCalls: Integer;
begin
  Result := Total(FHashCalls);
end;

function TFakeFileApi.TotalSignatureCalls: Integer;
begin
  Result := Total(FSignatureCalls);
end;

{ TFileInspectorTests }

procedure TFileInspectorTests.Setup;
begin
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FApi := TFakeFileApi.Create;
  FApiIntf := FApi;
  NewCollector;
end;

procedure TFileInspectorTests.TearDown;
begin
  FCollectorIntf := nil;
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
  FClockIntf := nil;
  FClock := nil;
end;

procedure TFileInspectorTests.NewCollector(ABudgetMs: Cardinal; AMaxFilesPerCycle: Integer;
  AMaxHashBytes: Int64; AMaxCacheEntries: Integer);
begin
  FCollectorIntf := nil;
  FCollector := TMHFileCollector.Create(FApiIntf, FClockIntf, ABudgetMs, AMaxFilesPerCycle,
    AMaxHashBytes, AMaxCacheEntries);
  FCollectorIntf := FCollector;
end;

function TFileInspectorTests.Snapshot(const AProcessPaths: array of string;
  const AAutostartPaths: array of string): TMHSnapshot;
var
  I: Integer;
  LProcess: TMHProcessInfo;
  LEntry: TMHAutostartEntry;
begin
  Result := TMHSnapshot.Create(1, FAKE_NOW);
  for I := 0 to High(AProcessPaths) do
  begin
    LProcess := TMHProcessInfo.Create(TMHProcessId.Create(100 + Cardinal(I), 1), 'p.exe', FAKE_NOW);
    LProcess.ImagePath := AProcessPaths[I];
    Result.Processes := Result.Processes + [LProcess];
  end;
  for I := 0 to High(AAutostartPaths) do
  begin
    LEntry := Default(TMHAutostartEntry);
    LEntry.Name := Format('entry%d', [I]);
    LEntry.ImagePath := AAutostartPaths[I];
    Result.Autostart := Result.Autostart + [LEntry];
  end;
end;

function TFileInspectorTests.CollectPaths(const APaths: array of string): TMHCollectionResult;
begin
  Result := FCollectorIntf.Collect(Snapshot(APaths, []));
end;

function TFileInspectorTests.Find(const AResult: TMHCollectionResult; const APath: string;
  out AInfo: TMHFileInfo): Boolean;
var
  LInfo: TMHFileInfo;
begin
  for LInfo in AResult.Files do
    if SameText(LInfo.Path, APath) then
    begin
      AInfo := LInfo;
      Exit(True);
    end;
  AInfo := Default(TMHFileInfo);
  Result := False;
end;

function TFileInspectorTests.CountPending(const AResult: TMHCollectionResult): Integer;
var
  LInfo: TMHFileInfo;
begin
  Result := 0;
  for LInfo in AResult.Files do
    if (LInfo.Signature = sgNotChecked) and (LInfo.Error = TMHFileCollector.PendingText) then
      Inc(Result);
end;

procedure TFileInspectorTests.AddFiles(ACount: Integer; out APaths: TArray<string>);
var
  I: Integer;
begin
  SetLength(APaths, ACount);
  for I := 0 to ACount - 1 do
  begin
    APaths[I] := Format('C:\Apps\app%d.exe', [I]);
    FApi.AddFile(APaths[I]);
  end;
end;

procedure TFileInspectorTests.CreateWithNilApi;
begin
  TMHFileCollector.Create(nil, FClockIntf).Free;
end;

procedure TFileInspectorTests.CreateWithNilClock;
begin
  TMHFileCollector.Create(FApiIntf, nil).Free;
end;

procedure TFileInspectorTests.CreateWithZeroCap;
begin
  TMHFileCollector.Create(FApiIntf, FClockIntf, 300, 0).Free;
end;

procedure TFileInspectorTests.CreateWithNegativeHashLimit;
begin
  TMHFileCollector.Create(FApiIntf, FClockIntf, 300, 30, -1).Free;
end;

procedure TFileInspectorTests.CreateWithZeroCache;
begin
  TMHFileCollector.Create(FApiIntf, FClockIntf, 300, 30, 1024, 0).Free;
end;

procedure TFileInspectorTests.Create_InvalidArguments_Raise;
begin
  Assert.WillRaise(CreateWithNilApi, EArgumentNilException);
  Assert.WillRaise(CreateWithNilClock, EArgumentNilException);
  Assert.WillRaise(CreateWithZeroCap, EArgumentOutOfRangeException);
  Assert.WillRaise(CreateWithNegativeHashLimit, EArgumentOutOfRangeException);
  Assert.WillRaise(CreateWithZeroCache, EArgumentOutOfRangeException);
end;

procedure TFileInspectorTests.Paths_FromProcessesAndAutostart_NormalizedAndDeduplicated;
var
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\Tool.exe');
  FApi.AddFile('C:\Apps\Agent.exe');
  FApi.AddFile('D:\Svc\svc.exe');
  LResult := FCollectorIntf.Collect(Snapshot(
    ['C:\Apps\Tool.exe', 'c:/apps/TOOL.EXE', '\\?\C:\Apps\.\Tool.exe', 'C:\Apps\Agent.exe'],
    ['"C:\Apps\Sub\..\Agent.exe"', 'D:\Svc\\svc.exe', 'c:\apps\tool.exe']));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual(3, Integer(Length(LResult.Files)), 'Пути без учёта регистра — один файл');
  Assert.AreEqual(3, LResult.Status.ItemCount);
  // Первое написание пути сохраняется; путь нормализован.
  Assert.AreEqual('C:\Apps\Tool.exe', LResult.Files[0].Path);
  Assert.AreEqual('C:\Apps\Agent.exe', LResult.Files[1].Path);
  Assert.AreEqual('D:\Svc\svc.exe', LResult.Files[2].Path);
  Assert.IsTrue(Find(LResult, 'D:\Svc\svc.exe', LInfo), 'Путь из автозапуска');
  Assert.AreEqual(1, FApi.HashCalls('C:\Apps\Tool.exe'), 'Дубликаты не проверяются повторно');
  Assert.AreEqual(1, FApi.SignatureCalls('C:\Apps\Agent.exe'));
end;

procedure TFileInspectorTests.Paths_EmptyAndRelative_AreSkipped;
var
  LResult: TMHCollectionResult;
begin
  FApi.AddFile('C:\Apps\a.exe');
  LResult := FCollectorIntf.Collect(Snapshot(['', '   ', 'a.exe', 'C:\Apps\a.exe'],
    ['', 'Apps\a.exe']));
  Assert.AreEqual(1, Integer(Length(LResult.Files)),
    'Относительные пути не проверяются: результат зависел бы от текущего каталога');
  Assert.AreEqual('C:\Apps\a.exe', LResult.Files[0].Path);
end;

procedure TFileInspectorTests.Inspect_FillsAllFields_Success;
var
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\a.exe', 4096);
  LResult := CollectPaths(['C:\Apps\a.exe']);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual('', LResult.Status.Message);
  Assert.IsTrue(Find(LResult, 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual<Int64>(4096, LInfo.SizeBytes);
  Assert.AreEqual(FAKE_NOW - 1, LInfo.LastWriteUtc, 1 / MSecsPerDay);
  Assert.AreEqual(TFakeFileApi.ExpectedHash('C:\Apps\a.exe', 4096), LInfo.Sha256);
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature);
  Assert.AreEqual('Test Publisher', LInfo.Signer);
  Assert.AreEqual('embedded', LInfo.SignatureSource);
  Assert.AreEqual('', LInfo.Error);
  Assert.AreEqual(1, FCollector.CacheCount);
end;

procedure TFileInspectorTests.PerCycleCap_PartialThenCompleteOverCycles;
var
  LPaths: TArray<string>;
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  NewCollector(10000, 2);
  AddFiles(5, LPaths);

  LResult := CollectPaths(LPaths);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.AreEqual(5, Integer(Length(LResult.Files)), 'Возвращаются все пути снимка');
  Assert.AreEqual(3, CountPending(LResult));
  Assert.IsTrue(LResult.Status.Message.Contains('Проверено 2 из 5 файлов'), LResult.Status.Message);
  Assert.IsTrue(LResult.Status.Message.Contains('в следующих циклах'), LResult.Status.Message);
  Assert.IsTrue(Find(LResult, LPaths[4], LInfo));
  Assert.AreEqual<TMHSignatureState>(sgNotChecked, LInfo.Signature);
  Assert.AreEqual(TMHFileCollector.PendingText, LInfo.Error);
  Assert.AreEqual('', LInfo.Sha256);

  LResult := CollectPaths(LPaths);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.AreEqual(1, CountPending(LResult));
  Assert.IsTrue(LResult.Status.Message.Contains('Проверено 4 из 5 файлов'), LResult.Status.Message);

  LResult := CollectPaths(LPaths);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual(0, CountPending(LResult));
  Assert.AreEqual(5, FApi.TotalHashCalls, 'Каждый файл хеширован ровно один раз');
  Assert.AreEqual(5, FApi.TotalSignatureCalls);
end;

procedure TFileInspectorTests.TimeBudget_PartialThenCompleteOverCycles;
var
  LPaths: TArray<string>;
  LResult: TMHCollectionResult;
  LCycles: Integer;
begin
  // Бюджет 300 мс, проверка подписи — 200 мс: за цикл успевают два файла
  // (после второго затрачено 400 мс, бюджет исчерпан).
  NewCollector(300, 100);
  FApi.CostMs := 200;
  AddFiles(6, LPaths);

  LResult := CollectPaths(LPaths);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.AreEqual(4, CountPending(LResult));
  Assert.AreEqual(2, FApi.TotalSignatureCalls);

  LCycles := 1;
  while (LResult.Status.State = ssPartial) and (LCycles < 10) do
  begin
    LResult := CollectPaths(LPaths);
    Inc(LCycles);
  end;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(3, LCycles);
  Assert.AreEqual(6, FApi.TotalSignatureCalls);
end;

procedure TFileInspectorTests.SlowFile_AtLeastOneInspectionPerCycle;
var
  LPaths: TArray<string>;
  LResult: TMHCollectionResult;
begin
  NewCollector(0, 30);
  FApi.CostMs := 5000;
  AddFiles(2, LPaths);
  LResult := CollectPaths(LPaths);
  Assert.AreEqual(1, CountPending(LResult), 'Даже при исчерпанном бюджете очередь продвигается');
  LResult := CollectPaths(LPaths);
  Assert.AreEqual(0, CountPending(LResult));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
end;

procedure TFileInspectorTests.SecondCycle_UsesCache_NoRecompute;
var
  LPaths: TArray<string>;
  LFirst, LSecond: TMHCollectionResult;
  I: Integer;
begin
  AddFiles(3, LPaths);
  LFirst := CollectPaths(LPaths);
  LSecond := CollectPaths(LPaths);
  Assert.AreEqual(3, FApi.TotalHashCalls, 'Повторный цикл не пересчитывает хеш');
  Assert.AreEqual(3, FApi.TotalSignatureCalls, 'Повторный цикл не проверяет подпись заново');
  Assert.AreEqual(2, FApi.StampCalls(LPaths[0]), 'Актуальность кеша проверяется по метке файла');
  for I := 0 to High(LPaths) do
  begin
    Assert.AreEqual(LFirst.Files[I].Sha256, LSecond.Files[I].Sha256);
    Assert.AreEqual<TMHSignatureState>(LFirst.Files[I].Signature, LSecond.Files[I].Signature);
  end;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LSecond.Status.State);
end;

procedure TFileInspectorTests.SizeChange_InvalidatesCache;
var
  LFile: TFakeFile;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\a.exe', 1000);
  CollectPaths(['C:\Apps\a.exe']);
  LFile := FApi.GetFile('C:\Apps\a.exe');
  LFile.Size := 2000;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  Assert.IsTrue(Find(CollectPaths(['C:\Apps\a.exe']), 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual(2, FApi.HashCalls('C:\Apps\a.exe'), 'Изменённый файл проверяется заново');
  Assert.AreEqual<Int64>(2000, LInfo.SizeBytes);
  Assert.AreEqual(TFakeFileApi.ExpectedHash('C:\Apps\a.exe', 2000), LInfo.Sha256);
end;

procedure TFileInspectorTests.LastWriteChange_InvalidatesCache;
var
  LFile: TFakeFile;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\a.exe', 1000, sgSignedTrusted);
  CollectPaths(['C:\Apps\a.exe']);
  // Подмена файла того же размера: подпись теперь недействительна.
  LFile := FApi.GetFile('C:\Apps\a.exe');
  LFile.LastWriteUtc := LFile.LastWriteUtc + 1 / SecsPerDay;
  LFile.State := sgSignedUntrusted;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  Assert.IsTrue(Find(CollectPaths(['C:\Apps\a.exe']), 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual(2, FApi.SignatureCalls('C:\Apps\a.exe'));
  Assert.AreEqual<TMHSignatureState>(sgSignedUntrusted, LInfo.Signature);
  Assert.AreEqual(LFile.LastWriteUtc, LInfo.LastWriteUtc, 1 / MSecsPerDay);
end;

procedure TFileInspectorTests.TooLargeFile_SignatureVerified_HashSkipped;
var
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  NewCollector(300, 30, 1024);
  FApi.AddFile('C:\Big\huge.exe', 1025);
  FApi.AddFile('C:\Big\edge.exe', 1024);
  LResult := CollectPaths(['C:\Big\huge.exe', 'C:\Big\edge.exe']);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State,
    'Пропуск хеша большого файла — штатное ограничение, а не сбой');
  Assert.IsTrue(Find(LResult, 'C:\Big\huge.exe', LInfo));
  Assert.AreEqual('', LInfo.Sha256);
  Assert.AreEqual(TMHFileCollector.TooLargeText, LInfo.Error);
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature, 'Подпись проверяется всегда');
  Assert.AreEqual(0, FApi.HashCalls('C:\Big\huge.exe'));
  Assert.IsTrue(Find(LResult, 'C:\Big\edge.exe', LInfo));
  Assert.IsNotEmpty(LInfo.Sha256, 'Файл ровно на пределе хешируется');

  CollectPaths(['C:\Big\huge.exe']);
  Assert.AreEqual(1, FApi.SignatureCalls('C:\Big\huge.exe'), 'Результат кешируется');
end;

procedure TFileInspectorTests.MissingFile_ErrorAndRetryAtMostOncePerMinute;
var
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  LResult := CollectPaths(['C:\Gone\x.exe']);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsNotEmpty(LResult.Status.Message);
  Assert.IsTrue(Find(LResult, 'C:\Gone\x.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LInfo.Signature);
  Assert.AreEqual(TMHFileCollector.UnavailableText, LInfo.Error);
  Assert.AreEqual<Int64>(-1, LInfo.SizeBytes);
  Assert.AreEqual(1, FApi.StampCalls('C:\Gone\x.exe'));

  // В течение минуты файл не проверяется снова — используется сохранённая ошибка.
  CollectPaths(['C:\Gone\x.exe']);
  FClock.AdvanceMs(59 * 1000);
  LResult := CollectPaths(['C:\Gone\x.exe']);
  Assert.AreEqual(1, FApi.StampCalls('C:\Gone\x.exe'));
  Assert.IsTrue(Find(LResult, 'C:\Gone\x.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LInfo.Signature);

  // Через минуту — повтор; файл появился.
  FApi.AddFile('C:\Gone\x.exe');
  FClock.AdvanceMs(1000);
  LResult := CollectPaths(['C:\Gone\x.exe']);
  Assert.AreEqual(2, FApi.StampCalls('C:\Gone\x.exe'));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.IsTrue(Find(LResult, 'C:\Gone\x.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature);
end;

procedure TFileInspectorTests.SignatureCheckFailure_IsRetriedAfterInterval;
var
  LFile: TFakeFile;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\a.exe');
  LFile := FApi.GetFile('C:\Apps\a.exe');
  LFile.SignatureFails := True;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  Assert.IsTrue(Find(CollectPaths(['C:\Apps\a.exe']), 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LInfo.Signature);
  Assert.IsTrue(LInfo.Error.Contains('simulated WinVerifyTrust failure'), LInfo.Error);

  CollectPaths(['C:\Apps\a.exe']);
  Assert.AreEqual(1, FApi.SignatureCalls('C:\Apps\a.exe'));

  LFile.SignatureFails := False;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  FClock.AdvanceMs(TMHFileCollector.RetryIntervalMs);
  Assert.IsTrue(Find(CollectPaths(['C:\Apps\a.exe']), 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual(2, FApi.SignatureCalls('C:\Apps\a.exe'));
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature);
  Assert.AreEqual('', LInfo.Error);
end;

procedure TFileInspectorTests.HashFailure_KeepsSignature_IsRetried;
var
  LFile: TFakeFile;
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\a.exe');
  LFile := FApi.GetFile('C:\Apps\a.exe');
  LFile.HashFails := True;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  LResult := CollectPaths(['C:\Apps\a.exe']);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(Find(LResult, 'C:\Apps\a.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature);
  Assert.AreEqual('', LInfo.Sha256);
  Assert.IsTrue(LInfo.Error.Contains('simulated read failure'), LInfo.Error);

  LResult := CollectPaths(['C:\Apps\a.exe']);
  Assert.AreEqual(1, FApi.HashCalls('C:\Apps\a.exe'), 'Повтор не чаще раза в минуту');
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State,
    'Сохранённая неудача по-прежнему делает данные неполными');

  LFile.HashFails := False;
  FApi.SetFile('C:\Apps\a.exe', LFile);
  FClock.AdvanceMs(TMHFileCollector.RetryIntervalMs);
  LResult := CollectPaths(['C:\Apps\a.exe']);
  Assert.AreEqual(2, FApi.HashCalls('C:\Apps\a.exe'));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
end;

procedure TFileInspectorTests.UnsignedAndUntrusted_AreCachedAsDefiniteResults;
var
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\plain.exe', 10, sgUnsigned);
  FApi.AddFile('C:\Apps\tampered.exe', 10, sgSignedUntrusted);
  LResult := CollectPaths(['C:\Apps\plain.exe', 'C:\Apps\tampered.exe']);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State,
    'Отсутствие подписи — результат проверки, а не сбой источника');
  Assert.IsTrue(Find(LResult, 'C:\Apps\plain.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgUnsigned, LInfo.Signature);
  Assert.AreEqual('', LInfo.Error);
  Assert.IsTrue(Find(LResult, 'C:\Apps\tampered.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgSignedUntrusted, LInfo.Signature);
  Assert.IsTrue(LInfo.Error.Contains('изменён'), LInfo.Error);

  CollectPaths(['C:\Apps\plain.exe', 'C:\Apps\tampered.exe']);
  Assert.AreEqual(2, FApi.TotalSignatureCalls);
end;

procedure TFileInspectorTests.UnexpectedApiException_BecomesFileError;
var
  LFile: TFakeFile;
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
begin
  FApi.AddFile('C:\Apps\bad.exe');
  FApi.AddFile('C:\Apps\good.exe');
  LFile := FApi.GetFile('C:\Apps\bad.exe');
  LFile.RaiseOnHash := True;
  FApi.SetFile('C:\Apps\bad.exe', LFile);
  LResult := CollectPaths(['C:\Apps\bad.exe', 'C:\Apps\good.exe']);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(Find(LResult, 'C:\Apps\bad.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LInfo.Signature);
  Assert.IsTrue(LInfo.Error.Contains('simulated unexpected failure'), LInfo.Error);
  Assert.IsTrue(Find(LResult, 'C:\Apps\good.exe', LInfo));
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature,
    'Сбой одного файла не мешает проверке остальных');
end;

procedure TFileInspectorTests.Cache_IsBounded_LeastRecentlyUsedEvicted;
var
  LPaths: TArray<string>;
  I: Integer;
begin
  NewCollector(300, 30, 1024 * 1024, 3);
  AddFiles(5, LPaths);
  CollectPaths([LPaths[0], LPaths[1], LPaths[2]]);
  Assert.AreEqual(3, FCollector.CacheCount);
  // Обращение к app0 делает его «свежим»; вытесняться должны app1 и app2.
  CollectPaths([LPaths[0]]);
  CollectPaths([LPaths[3], LPaths[4]]);
  Assert.AreEqual(3, FCollector.CacheCount, 'Кеш не превышает предела');

  CollectPaths([LPaths[0]]);
  Assert.AreEqual(1, FApi.HashCalls(LPaths[0]), 'Недавно использованная запись сохранена');
  CollectPaths([LPaths[1]]);
  Assert.AreEqual(2, FApi.HashCalls(LPaths[1]), 'Давно не использованная запись вытеснена');

  for I := 1 to 20 do
    CollectPaths(LPaths);
  Assert.IsTrue(FCollector.CacheCount <= 3);
end;

procedure TFileInspectorTests.EmptySnapshot_IsSuccessWithoutFiles;
var
  LResult: TMHCollectionResult;
begin
  LResult := FCollectorIntf.Collect(Default(TMHSnapshot));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(0, Integer(Length(LResult.Files)));
  Assert.AreEqual(0, LResult.Status.ItemCount);
  Assert.AreEqual(FAKE_NOW, LResult.Status.TimestampUtc, 1 / MSecsPerDay,
    'Без времени снимка используется IMHClock');
end;

procedure TFileInspectorTests.ResultMatchesCollectorContract;
var
  LSnapshot: TMHSnapshot;
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
  LProcess: TMHProcessInfo;
  LFound: Boolean;
begin
  NewCollector(300, 1);
  FApi.AddFile('C:\Apps\a.exe');
  FApi.AddFile('C:\Apps\b.exe');
  LSnapshot := Snapshot(['C:\Apps\a.exe', 'C:\Apps\b.exe', 'C:\Gone\c.exe'], []);
  LResult := FCollectorIntf.Collect(LSnapshot);
  Assert.AreEqual(TMHFileCollector.SourceIdValue, FCollectorIntf.SourceId);
  Assert.IsNotEmpty(FCollectorIntf.DisplayName);
  Assert.AreEqual(FCollectorIntf.SourceId, LResult.Status.SourceId);
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial, ssUnavailable, ssError]);
  if LResult.Status.State <> ssSuccess then
    Assert.IsNotEmpty(LResult.Status.Message);
  Assert.AreEqual(Integer(Length(LResult.Files)), LResult.Status.ItemCount);
  Assert.AreEqual(FAKE_NOW, LResult.Status.TimestampUtc, 1 / MSecsPerDay);
  Assert.AreEqual(0, Integer(Length(LResult.Processes)), 'Коллектор файлов не создаёт процессы');
  for LInfo in LResult.Files do
  begin
    Assert.AreEqual(MHNormalizePath(LInfo.Path), LInfo.Path);
    LFound := False;
    for LProcess in LSnapshot.Processes do
      LFound := LFound or SameText(LProcess.ImagePath, LInfo.Path);
    Assert.IsTrue(LFound, 'Файл должен относиться к пути из снимка: ' + LInfo.Path);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TFileInspectorTests);

end.
