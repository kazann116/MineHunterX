unit MineHunter.Tests.BinaryLab.Integration;

{
  BinaryLab: полный анализ (синтетические и настоящие файлы, отмена, лимиты,
  неизменность файла), BinaryDiff, отчёты JSON/HTML (экранирование данных
  файла), вердикты и их передача в анализатор угроз.
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Files,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source, MineHunter.Tests.PeBuilder;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabAnalyzerTests = class
  private
    FDir: string;
    function Analyze(const AData: TBytes; const AName: string): TMHBinaryReport; overload;
    function Analyze(const AData: TBytes; const AName: string; const AOptions: TMHBinaryLabOptions): TMHBinaryReport; overload;
    function SuspiciousPe: TBytes;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure SuspiciousPe_FullPipeline;
    [Test] procedure CleanPe_LowScore;
    [Test] procedure TextEmptyAndUnknown;
    [Test] procedure Partial_WhenLargerThanScanLimit;
    [Test] procedure Progress_AndCancel;
    [Test] procedure File_AnalysedWithoutModification;
    [Test] procedure File_Missing_Raises;
    [Test] procedure Signature_FromFileApi_AndApiFailure;
    [Test] procedure RealSystemFiles_SignedAndParsed;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabDiffTests = class
  private
    function Report(const AData: TBytes; const AName: string): TMHBinaryReport;
  public
    [Test] procedure Identical_Files;
    [Test] procedure Modified_Pe_SectionsImportsExportsResourcesBlocks;
    [Test] procedure DifferentSizes_TailIsChanged;
    [Test] procedure NonPe_StringsCompared;
    [Test] procedure Limits_Truncated;
    [Test] procedure NilAndCancel;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabReportTests = class
  private
    FDir: string;
    function HostileReport: TMHBinaryReport;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Json_RoundTripStructure;
    [Test] procedure Html_EscapesFileData;
    [Test] procedure Save_ByExtension;
    [Test] procedure Diff_JsonAndHtml;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabVerdictTests = class
  public
    [Test] procedure FromReport_WeightsSignalsAndCap;
    [Test] procedure Store_MatchByPathAndHash;
    [Test] procedure Store_EvictsOldest;
    [Test] procedure Store_ConcurrentAccess;
    [Test] procedure Engine_AddsBinaryLabEvidenceToProcessFinding;
    [Test] procedure Engine_IgnoresVerdictForChangedFile;
  end;

implementation

uses
  System.IOUtils, System.Classes, System.Hash, System.JSON, System.Generics.Collections, System.SyncObjs, System.DateUtils,
  MineHunter.BinaryLab.Analyzer, MineHunter.BinaryLab.Anomalies, MineHunter.BinaryLab.Diff,
  MineHunter.BinaryLab.Report, MineHunter.BinaryLab.Verdicts, MineHunter.Collectors.Files.WinApi,
  MineHunter.Analysis.Engine, MineHunter.Tests.Scenarios;

const
  NOW_UTC = 46314.5; // 2026-10-19 12:00

type
  TFakeFileApi = class(TInterfacedObject, IMHFileApi)
  public
    State: TMHSignatureState;
    Fail: Boolean;
    Calls: Integer;
    function GetFileStamp(const APath: string; out ASize: Int64; out ALastWriteUtc: TDateTime): Boolean;
    function ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
    function VerifySignature(const APath: string; out AState: TMHSignatureState;
      out ASigner, ASource, AError: string): Boolean;
    function TickMs: UInt64;
  end;

function TFakeFileApi.GetFileStamp(const APath: string; out ASize: Int64; out ALastWriteUtc: TDateTime): Boolean;
begin
  ASize := 0;
  ALastWriteUtc := 0;
  Result := False;
end;

function TFakeFileApi.ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
begin
  AHash := '';
  AError := 'нет';
  Result := False;
end;

function TFakeFileApi.VerifySignature(const APath: string; out AState: TMHSignatureState;
  out ASigner, ASource, AError: string): Boolean;
begin
  Inc(Calls);
  if Fail then
    raise Exception.Create('сбой проверки подписи');
  AState := State;
  ASigner := 'Test Publisher';
  ASource := 'embedded';
  AError := '';
  Result := True;
end;

function TFakeFileApi.TickMs: UInt64;
begin
  Result := 0;
end;

function NewTempDir: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\BLI-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(Result);
end;

function ManyImports(ACount: Integer): TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
    Result[I] := 'Function' + IntToStr(I);
end;

function HasCode(const AReport: TMHBinaryReport; const ACode: string): Boolean;
begin
  Result := AReport.HasAnomaly(ACode);
end;

{ TBinaryLabAnalyzerTests }

procedure TBinaryLabAnalyzerTests.Setup;
begin
  FDir := NewTempDir;
end;

procedure TBinaryLabAnalyzerTests.TearDown;
begin
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог; ошибка удаления не влияет на результат.
  end;
end;

function TBinaryLabAnalyzerTests.Analyze(const AData: TBytes; const AName: string): TMHBinaryReport;
begin
  Result := Analyze(AData, AName, TMHBinaryLabOptions.Default);
end;

function TBinaryLabAnalyzerTests.Analyze(const AData: TBytes; const AName: string;
  const AOptions: TMHBinaryLabOptions): TMHBinaryReport;
begin
  Result := MHAnalyzeBinarySource(TMHBytesSource.Create(AData), AName, AOptions, nil, NOW_UTC,
    TMHRiskThresholds.Default);
end;

function TBinaryLabAnalyzerTests.SuspiciousPe: TBytes;
var
  LBuilder: TTestPeBuilder;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('UPX0', nil, SCN_CODE or SCN_EXEC or SCN_READ or SCN_WRITE, $40000);
    LBuilder.AddSection('UPX1', TestRandomBytes(32768), SCN_CODE or SCN_EXEC or SCN_READ or SCN_WRITE);
    LBuilder.AddSection('.data', TestConcat([TestAscii('stratum+tcp://pool.supportxmr.com:3333'), TestBytes([0]),
      TestAscii('--donate-level=1'), TestBytes([0]),
      TestAscii('48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD'),
      TestBytes([0, 0, 0, 0])]), SCN_DATA);
    LBuilder.AddImport('KERNEL32.dll', ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'ExitProcess']);
    LBuilder.Overlay := TestMinimalPe;
    LBuilder.Build;
    LBuilder.EntryPointRva := LBuilder.SectionRva('UPX1') + 32;
    Result := LBuilder.Build;
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabAnalyzerTests.SuspiciousPe_FullPipeline;
var
  LData: TBytes;
  LReport: TMHBinaryReport;
  LSection: TMHPeSection;
  LFoundPe: Boolean;
  LObject: TMHEmbeddedObject;
begin
  LData := SuspiciousPe;
  LReport := Analyze(LData, 'C:\Users\Test\Pictures\holiday.jpg');
  Assert.AreEqual(0, Integer(Length(LReport.Errors)), string.Join('; ', LReport.Errors));
  Assert.AreEqual('holiday.jpg', LReport.FileName);
  Assert.AreEqual<Int64>(Length(LData), LReport.Size);
  Assert.AreEqual(THashSHA2.GetHashString(TBytesStream.Create(LData)).ToLower, LReport.Sha256);
  Assert.AreEqual(MH_BINARYLAB_VERSION, LReport.RulesVersion);
  Assert.AreEqual(Ord(bkPE), Ord(LReport.FileType.Kind));
  Assert.IsTrue(LReport.FileType.ExtensionMismatch);
  Assert.IsTrue(LReport.Pe.Valid);
  // Энтропия и хеши секций заполнены.
  Assert.IsTrue(LReport.Pe.FindSection('UPX1', LSection));
  Assert.IsTrue(LSection.Entropy > 7.5, FloatToStr(LSection.Entropy));
  Assert.AreEqual(64, Length(LSection.Sha256));
  Assert.IsTrue(LReport.Pe.FindSection('UPX0', LSection));
  Assert.AreEqual(-1.0, LSection.Entropy, 'Секция без данных в файле');
  Assert.IsTrue(LReport.Pe.ComputedCheckSum <> 0);
  // Строки, вложения, энтропия.
  Assert.IsTrue(LReport.Strings.CountByCategory[scMining] >= 1);
  Assert.IsTrue(LReport.Strings.CountByCategory[scWallet] >= 1);
  LFoundPe := False;
  for LObject in LReport.Embedded do
    if (LObject.Kind = bkPE) and (LObject.Offset = LReport.Pe.OverlayOffset) then
    begin
      LFoundPe := True;
      Assert.IsTrue(LObject.Location <> '', 'Где найден объект');
    end;
  Assert.IsTrue(LFoundPe, 'Программа в оверлее');
  Assert.IsTrue(Length(LReport.Entropy.Blocks) > 0);
  Assert.IsTrue(Length(LReport.Entropy.HighRegions) > 0);
  // Аномалии и оценка.
  Assert.IsTrue(HasCode(LReport, BL_EXTENSION_MISMATCH));
  Assert.IsTrue(HasCode(LReport, BL_PACKER_SECTIONS));
  Assert.IsTrue(HasCode(LReport, BL_PACKED_CODE));
  Assert.IsTrue(HasCode(LReport, BL_MINING_STRINGS));
  Assert.IsTrue(HasCode(LReport, BL_EMBEDDED_EXECUTABLE));
  Assert.AreEqual(100, LReport.Score);
  Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LReport.Level));
  Assert.AreEqual(Ord(sgNotChecked), Ord(LReport.Signature.State), 'Без API подпись не проверяется');
  Assert.AreEqual(NOW_UTC, LReport.AnalyzedAtUtc, 1e-9);
end;

procedure TBinaryLabAnalyzerTests.CleanPe_LowScore;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(20000), SCN_TEXT);
    LBuilder.AddSection('.rdata', TestAscii('Copyright (c) Example Company. All rights reserved.'), SCN_RDATA);
    LBuilder.AddImport('KERNEL32.dll', ManyImports(40));
    LBuilder.AddResource(RT_VERSION_ID, 1, $0409, TestAscii('version info block'));
    LReport := Analyze(LBuilder.Build, 'C:\Program Files\Example\example.exe');
  finally
    LBuilder.Free;
  end;
  Assert.AreEqual(0, Integer(Length(LReport.Errors)), string.Join('; ', LReport.Errors));
  Assert.IsTrue(LReport.Score < TMHRiskThresholds.Default.Low, IntToStr(LReport.Score));
  Assert.IsFalse(HasCode(LReport, BL_PACKED_CODE));
  Assert.IsTrue(LReport.Pe.Resources[0].Entropy >= 0, 'Энтропия ресурса посчитана');
end;

procedure TBinaryLabAnalyzerTests.TextEmptyAndUnknown;
var
  LReport: TMHBinaryReport;
begin
  LReport := Analyze(TestAscii('powershell -enc SQBFAFgA; schtasks /create /tn x /tr evil.exe'), 'run.ps1');
  Assert.AreEqual(Ord(bkScript), Ord(LReport.FileType.Kind));
  Assert.IsFalse(LReport.Pe.Valid);
  Assert.IsTrue(LReport.Strings.CountByCategory[TMHStringCategory.scCommand] >= 1);
  LReport := Analyze(nil, 'empty.bin');
  Assert.AreEqual(Ord(bkEmpty), Ord(LReport.FileType.Kind));
  Assert.AreEqual(0, LReport.Score);
  Assert.AreEqual(0, Integer(Length(LReport.Errors)), string.Join('; ', LReport.Errors));
  Assert.IsTrue(LReport.Verdict <> '');
  LReport := Analyze(TestRandomBytes(100000), 'blob.dat');
  Assert.AreEqual(Ord(bkUnknown), Ord(LReport.FileType.Kind));
  Assert.IsTrue(LReport.Entropy.Overall > 7.9);
  Assert.AreEqual(0, LReport.Score, 'Случайные данные — не угроза');
end;

procedure TBinaryLabAnalyzerTests.Partial_WhenLargerThanScanLimit;
var
  LOptions: TMHBinaryLabOptions;
  LReport: TMHBinaryReport;
begin
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.MaxScanBytes := 64 * 1024;
  LReport := Analyze(TestConcat([TestMinimalPe, TestRandomBytes(300000)]), 'big.exe', LOptions);
  Assert.IsTrue(LReport.Partial);
  Assert.IsTrue(Length(LReport.Notes) > 0);
  Assert.IsTrue(LReport.Entropy.BytesScanned <= 64 * 1024);
  Assert.IsTrue(HasCode(LReport, BL_PARTIAL_ANALYSIS));
  Assert.AreEqual(64, Length(LReport.Sha256), 'Хеш — по всему файлу');
end;

procedure TBinaryLabAnalyzerTests.Progress_AndCancel;
var
  LPercents: TArray<Integer>;
  LStages: Integer;
  I: Integer;
begin
  LStages := 0;
  MHAnalyzeBinarySource(TMHBytesSource.Create(SuspiciousPe), 'x.exe', TMHBinaryLabOptions.Default, nil, NOW_UTC,
    TMHRiskThresholds.Default, nil,
    procedure(const AStage: string; APercent: Integer)
    begin
      Inc(LStages);
      Assert.IsTrue(AStage <> '');
      LPercents := LPercents + [APercent];
    end);
  Assert.IsTrue(LStages >= 6);
  for I := 1 to High(LPercents) do
    Assert.IsTrue(LPercents[I] >= LPercents[I - 1], 'Ход только растёт');
  Assert.AreEqual(100, LPercents[High(LPercents)]);
  // Отмена на этапе энтропии.
  LStages := 0;
  Assert.WillRaise(
    procedure
    begin
      MHAnalyzeBinarySource(TMHBytesSource.Create(SuspiciousPe), 'x.exe', TMHBinaryLabOptions.Default, nil, NOW_UTC,
        TMHRiskThresholds.Default,
        function: Boolean
        begin
          Result := LStages >= 4;
        end,
        procedure(const AStage: string; APercent: Integer)
        begin
          Inc(LStages);
        end);
    end, EMHBinaryLabCancelled);
end;

procedure TBinaryLabAnalyzerTests.File_AnalysedWithoutModification;
var
  LPath: string;
  LData: TBytes;
  LBefore: TDateTime;
  LReport: TMHBinaryReport;
begin
  LData := SuspiciousPe;
  LPath := TPath.Combine(FDir, 'sample.exe');
  TFile.WriteAllBytes(LPath, LData);
  LBefore := TFile.GetLastWriteTime(LPath);
  LReport := MHAnalyzeBinaryFile(LPath, TMHBinaryLabOptions.Default, nil, NOW_UTC, TMHRiskThresholds.Default);
  Assert.AreEqual(LPath, LReport.Path);
  Assert.IsTrue(LReport.LastWriteUtc > 0);
  Assert.AreEqual(LBefore, TFile.GetLastWriteTime(LPath));
  Assert.IsTrue(CompareMem(@LData[0], @TFile.ReadAllBytes(LPath)[0], Length(LData)), 'Файл не изменён');
  // Файл можно удалить сразу после анализа: дескриптор закрыт.
  TFile.Delete(LPath);
  Assert.IsFalse(TFile.Exists(LPath));
end;

procedure TBinaryLabAnalyzerTests.File_Missing_Raises;
var
  LDir: string;
begin
  LDir := FDir;
  Assert.WillRaise(
    procedure
    begin
      MHAnalyzeBinaryFile(TPath.Combine(LDir, 'missing.exe'), TMHBinaryLabOptions.Default, nil, NOW_UTC,
        TMHRiskThresholds.Default);
    end, EMHBinaryLabError);
  Assert.WillRaise(
    procedure
    begin
      MHAnalyzeBinarySource(nil, 'x', TMHBinaryLabOptions.Default, nil, NOW_UTC, TMHRiskThresholds.Default);
    end, EArgumentNilException);
end;

procedure TBinaryLabAnalyzerTests.Signature_FromFileApi_AndApiFailure;
var
  LPath: string;
  LApi: TFakeFileApi;
  LApiIntf: IMHFileApi;
  LReport: TMHBinaryReport;
  LOptions: TMHBinaryLabOptions;
begin
  LPath := TPath.Combine(FDir, 'signed.exe');
  TFile.WriteAllBytes(LPath, SuspiciousPe);
  LApi := TFakeFileApi.Create;
  LApiIntf := LApi;
  LApi.State := sgSignedTrusted;
  LReport := MHAnalyzeBinaryFile(LPath, TMHBinaryLabOptions.Default, LApiIntf, NOW_UTC, TMHRiskThresholds.Default);
  Assert.AreEqual(Ord(sgSignedTrusted), Ord(LReport.Signature.State));
  Assert.AreEqual('Test Publisher', LReport.Signature.Signer);
  Assert.IsTrue(LReport.Verdict.Contains('доверенным') or LReport.Verdict.Contains('trusted'), LReport.Verdict);
  // Сбой проверки — состояние «не удалось проверить», анализ продолжается.
  LApi.Fail := True;
  LReport := MHAnalyzeBinaryFile(LPath, TMHBinaryLabOptions.Default, LApiIntf, NOW_UTC, TMHRiskThresholds.Default);
  Assert.AreEqual(Ord(sgCheckFailed), Ord(LReport.Signature.State));
  Assert.IsTrue(LReport.Signature.Error.Contains('сбой'));
  Assert.IsTrue(LReport.Score > 0);
  // Проверка подписи отключена в параметрах.
  LApi.Calls := 0;
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.VerifySignature := False;
  LReport := MHAnalyzeBinaryFile(LPath, LOptions, LApiIntf, NOW_UTC, TMHRiskThresholds.Default);
  Assert.AreEqual(0, LApi.Calls);
  Assert.AreEqual(Ord(sgNotChecked), Ord(LReport.Signature.State));
end;

procedure TBinaryLabAnalyzerTests.RealSystemFiles_SignedAndParsed;
var
  LPath: string;
  LReport: TMHBinaryReport;
begin
  LPath := TPath.Combine(TPath.GetDirectoryName(GetEnvironmentVariable('ComSpec')), 'kernel32.dll');
  if not TFile.Exists(LPath) then
    Assert.Pass('Системный файл недоступен');
  LReport := MHAnalyzeBinaryFile(LPath, TMHBinaryLabOptions.Default, TMHWinFileApi.Create, NOW_UTC,
    TMHRiskThresholds.Default);
  Assert.AreEqual(0, Integer(Length(LReport.Errors)), string.Join('; ', LReport.Errors));
  Assert.IsTrue(LReport.Pe.Valid);
  Assert.IsTrue(Length(LReport.Pe.ExportedFunctions) > 500);
  Assert.AreEqual(Ord(sgSignedTrusted), Ord(LReport.Signature.State), LReport.Signature.Error);
  Assert.AreEqual<Cardinal>(LReport.Pe.CheckSum, LReport.Pe.ComputedCheckSum, 'Контрольная сумма Windows');
  Assert.IsTrue(LReport.Score < TMHRiskThresholds.Default.NeedsReview,
    Format('Системная библиотека: %d — %s', [LReport.Score, LReport.Verdict]));
end;

{ TBinaryLabDiffTests }

function TBinaryLabDiffTests.Report(const AData: TBytes; const AName: string): TMHBinaryReport;
begin
  Result := MHAnalyzeBinarySource(TMHBytesSource.Create(AData), AName, TMHBinaryLabOptions.Default, nil, NOW_UTC,
    TMHRiskThresholds.Default);
end;

procedure TBinaryLabDiffTests.Identical_Files;
var
  LData: TBytes;
  LDiff: TMHBinaryDiff;
begin
  LData := TestMinimalPe;
  LDiff := MHCompareBinaries(Report(LData, 'a.dll'), Report(LData, 'b.dll'), TMHBytesSource.Create(LData),
    TMHBytesSource.Create(Copy(LData)), TMHBinaryLabOptions.Default);
  Assert.IsTrue(LDiff.Identical);
  Assert.AreEqual(100.0, LDiff.SimilarityPercent, 0.001);
  Assert.AreEqual<Int64>(0, LDiff.ChangedBytes);
  Assert.AreEqual(0, Integer(Length(LDiff.Items)));
  Assert.AreEqual(0, Integer(Length(LDiff.ChangedRanges)));
end;

procedure TBinaryLabDiffTests.Modified_Pe_SectionsImportsExportsResourcesBlocks;
var
  LLeftBuilder, LRightBuilder: TTestPeBuilder;
  LLeft, LRight: TBytes;
  LDiff: TMHBinaryDiff;
  LItem: TMHDiffItem;
  LImportAdded, LTextChanged: Boolean;
  LCode: TBytes;
  LTextOffset: Cardinal;
  LRange: TMHByteRange;
  LCovered: Boolean;
begin
  LCode := TestCodeBytes(4000);
  LLeftBuilder := TTestPeBuilder.Create;
  LRightBuilder := TTestPeBuilder.Create;
  try
    LLeftBuilder.AddSection('.text', LCode, SCN_TEXT);
    LLeftBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW']);
    LLeftBuilder.AddExport('Original');
    LLeft := LLeftBuilder.Build;
    // Справа: изменён код, добавлены импорт, экспорт и ресурс.
    LCode := Copy(LCode);
    LCode[100] := $90;
    LCode[101] := $90;
    LRightBuilder.AddSection('.text', LCode, SCN_TEXT);
    LRightBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW', 'WriteProcessMemory']);
    LRightBuilder.AddExport('Original');
    LRightBuilder.AddExport('Injected');
    LRightBuilder.AddResource(RT_RCDATA_ID, 7, 0, TestRandomBytes(500));
    LRight := LRightBuilder.Build;
    LTextOffset := LLeftBuilder.SectionRawOffset('.text');
  finally
    LRightBuilder.Free;
    LLeftBuilder.Free;
  end;
  LDiff := MHCompareBinaries(Report(LLeft, 'orig.dll'), Report(LRight, 'patched.dll'), TMHBytesSource.Create(LLeft),
    TMHBytesSource.Create(LRight), TMHBinaryLabOptions.Default, nil, 512);
  Assert.IsFalse(LDiff.Identical);
  Assert.IsTrue(LDiff.SimilarityPercent < 100);
  Assert.IsTrue(LDiff.ChangedBytes > 0);
  Assert.AreEqual(512, LDiff.BlockSize);
  LImportAdded := False;
  LTextChanged := False;
  for LItem in LDiff.Items do
  begin
    if (LItem.Area = MH_DIFF_AREA_IMPORT) and (LItem.Change = dcAdded) and
       (LItem.Name = 'kernel32.dll!WriteProcessMemory') then
      LImportAdded := True;
    if (LItem.Area = MH_DIFF_AREA_SECTION) and (LItem.Change = dcChanged) and (LItem.Name = '.text') then
      LTextChanged := True;
  end;
  Assert.IsTrue(LImportAdded, 'Новый импорт');
  Assert.IsTrue(LTextChanged, 'Изменённая секция кода');
  Assert.AreEqual(1, LDiff.CountOf(MH_DIFF_AREA_EXPORT), 'Новый экспорт');
  Assert.IsTrue(LDiff.CountOf(MH_DIFF_AREA_RESOURCE) >= 1, 'Новый ресурс');
  Assert.IsTrue(LDiff.CountOf(MH_DIFF_AREA_BLOCK) >= 1);
  // Изменённые байты кода попали в диапазон изменений.
  LCovered := False;
  for LRange in LDiff.ChangedRanges do
    if (LTextOffset + 100 >= LRange.Offset) and (LTextOffset + 100 < LRange.Offset + LRange.Size) then
      LCovered := True;
  Assert.IsTrue(LCovered);
end;

procedure TBinaryLabDiffTests.DifferentSizes_TailIsChanged;
var
  LLeft, LRight: TBytes;
  LDiff: TMHBinaryDiff;
begin
  LLeft := TestMinimalPe;
  LRight := TestConcat([LLeft, TestRandomBytes(5000)]);
  LDiff := MHCompareBinaries(Report(LLeft, 'a.dll'), Report(LRight, 'b.dll'), TMHBytesSource.Create(LLeft),
    TMHBytesSource.Create(LRight), TMHBinaryLabOptions.Default, nil, 1024);
  Assert.IsFalse(LDiff.Identical);
  Assert.AreEqual(1, Integer(Length(LDiff.ChangedRanges)), 'Один непрерывный хвост');
  Assert.AreEqual<Int64>(Length(LLeft) div 1024 * 1024, LDiff.ChangedRanges[0].Offset);
  Assert.AreEqual<Int64>(Length(LRight), LDiff.ChangedRanges[0].Offset + LDiff.ChangedRanges[0].Size);
  Assert.IsTrue(LDiff.CountOf(MH_DIFF_AREA_HEADER) >= 1, 'Оверлей изменился');
end;

procedure TBinaryLabDiffTests.NonPe_StringsCompared;
var
  LLeft, LRight: TBytes;
  LDiff: TMHBinaryDiff;
  LItem: TMHDiffItem;
  LAdded, LRemoved: Boolean;
begin
  LLeft := TestAscii('first line of text'#10'connect http://example.com/update'#10);
  LRight := TestAscii('first line of text'#10'connect http://evil.example.net/payload'#10);
  LDiff := MHCompareBinaries(Report(LLeft, 'a.txt'), Report(LRight, 'b.txt'), TMHBytesSource.Create(LLeft),
    TMHBytesSource.Create(LRight), TMHBinaryLabOptions.Default);
  LAdded := False;
  LRemoved := False;
  for LItem in LDiff.Items do
    if LItem.Area = MH_DIFF_AREA_STRING then
    begin
      if (LItem.Change = dcAdded) and LItem.Name.Contains('evil.example.net') then
        LAdded := True;
      if (LItem.Change = dcRemoved) and LItem.Name.Contains('example.com/update') then
        LRemoved := True;
    end;
  Assert.IsTrue(LAdded and LRemoved);
  Assert.AreEqual(0, LDiff.CountOf(MH_DIFF_AREA_SECTION));
end;

procedure TBinaryLabDiffTests.Limits_Truncated;
var
  LLeft, LRight: TMHBinaryReport;
  LLeftData, LRightData: TBytes;
  LOptions: TMHBinaryLabOptions;
  LDiff: TMHBinaryDiff;
  I: Integer;
  LString: TMHBinaryString;
begin
  LLeftData := TestRandomBytes(100000, 1);
  LRightData := TestRandomBytes(100000, 2);
  LLeft := Default(TMHBinaryReport);
  LRight := Default(TMHBinaryReport);
  // Строк больше лимита области.
  for I := 0 to MH_DIFF_MAX_ITEMS_PER_AREA + 100 do
  begin
    LString := Default(TMHBinaryString);
    LString.Text := 'only right ' + IntToStr(I);
    LRight.Strings.Items := LRight.Strings.Items + [LString];
  end;
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.MaxScanBytes := 16384;
  LDiff := MHCompareBinaries(LLeft, LRight, TMHBytesSource.Create(LLeftData), TMHBytesSource.Create(LRightData), LOptions);
  Assert.IsTrue(LDiff.Truncated);
  Assert.AreEqual(MH_DIFF_MAX_ITEMS_PER_AREA, LDiff.CountOf(MH_DIFF_AREA_STRING));
  Assert.IsFalse(LDiff.Identical);
end;

procedure TBinaryLabDiffTests.NilAndCancel;
var
  LReport: TMHBinaryReport;
  LData: TBytes;
begin
  LReport := Default(TMHBinaryReport);
  LData := TestRandomBytes(5000000);
  Assert.WillRaise(
    procedure
    begin
      MHCompareBinaries(LReport, LReport, nil, TMHBytesSource.Create(nil), TMHBinaryLabOptions.Default);
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      MHCompareBinaries(LReport, LReport, TMHBytesSource.Create(LData), TMHBytesSource.Create(LData),
        TMHBinaryLabOptions.Default,
        function: Boolean
        begin
          Result := True;
        end);
    end, EMHBinaryLabCancelled);
end;

{ TBinaryLabReportTests }

procedure TBinaryLabReportTests.Setup;
begin
  FDir := NewTempDir;
end;

procedure TBinaryLabReportTests.TearDown;
begin
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог; ошибка удаления не влияет на результат.
  end;
end;

function TBinaryLabReportTests.HostileReport: TMHBinaryReport;
var
  LBuilder: TTestPeBuilder;
  LString: TMHBinaryString;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('<b>x', TestCodeBytes(2000), SCN_TEXT);
    LBuilder.AddImport('evil"<dll>.dll', ['<img src=x onerror=alert(1)>']);
    LBuilder.AddExport('Exp');
    LBuilder.AddResource(RT_RCDATA_ID, 1, 0, TestRandomBytes(64));
    Result := MHAnalyzeBinarySource(TMHBytesSource.Create(TestConcat([LBuilder.Build,
      TestAscii('<script>alert(1)</script> stratum+tcp://pool.example.org:3333')])),
      'C:\Temp\<evil>&"file".exe', TMHBinaryLabOptions.Default, nil, NOW_UTC, TMHRiskThresholds.Default);
  finally
    LBuilder.Free;
  end;
  LString := Default(TMHBinaryString);
  LString.Text := '<script>alert("x")</script>';
  LString.Category := TMHStringCategory.scCommand;
  Result.Strings.Items := Result.Strings.Items + [LString];
end;

procedure TBinaryLabReportTests.Json_RoundTripStructure;
var
  LReport: TMHBinaryReport;
  LJson: TJSONValue;
  LRoot: TJSONObject;
begin
  LReport := HostileReport;
  LJson := TJSONObject.ParseJSONValue(MHBinaryReportToJson(LReport));
  try
    Assert.IsNotNull(LJson, 'Корректный JSON');
    LRoot := LJson as TJSONObject;
    Assert.AreEqual(LReport.Score, LRoot.GetValue<Integer>('score'));
    Assert.AreEqual(LReport.Sha256, LRoot.GetValue<string>('file.sha256'));
    Assert.AreEqual(LReport.Path, LRoot.GetValue<string>('file.path'));
    Assert.IsTrue(LRoot.GetValue<Boolean>('pe.valid'));
    Assert.AreEqual(Integer(Length(LReport.Pe.Sections)), LRoot.GetValue<TJSONArray>('pe.sections').Count);
    Assert.AreEqual(Integer(Length(LReport.Anomalies)), LRoot.GetValue<TJSONArray>('anomalies').Count);
    Assert.AreEqual(256, LRoot.GetValue<TJSONArray>('entropy.histogram').Count);
    Assert.AreEqual(Integer(Length(LReport.Entropy.Blocks)), LRoot.GetValue<TJSONArray>('entropy.blocks').Count);
    Assert.AreEqual(Integer(Length(LReport.Strings.Items)), LRoot.GetValue<TJSONArray>('strings.items').Count);
    Assert.AreEqual('<img src=x onerror=alert(1)>',
      ((LRoot.GetValue<TJSONArray>('pe.imports').Items[0] as TJSONObject).GetValue<TJSONArray>('functions').Items[0]).Value);
  finally
    LJson.Free;
  end;
  // Отчёт о не-PE файле — тоже корректный JSON.
  LReport := Default(TMHBinaryReport);
  LJson := TJSONObject.ParseJSONValue(MHBinaryReportToJson(LReport));
  try
    Assert.IsNotNull(LJson);
  finally
    LJson.Free;
  end;
end;

procedure TBinaryLabReportTests.Html_EscapesFileData;
var
  LHtml: string;
begin
  LHtml := MHBinaryReportToHtml(HostileReport);
  Assert.IsTrue(LHtml.StartsWith('<!DOCTYPE html>'));
  Assert.IsTrue(LHtml.Contains('<svg'), 'Карта энтропии');
  Assert.IsFalse(LHtml.Contains('<script'), 'Строки файла не становятся разметкой');
  Assert.IsFalse(LHtml.Contains('<img'), 'Имена функций экранированы');
  Assert.IsFalse(LHtml.Contains('<b>x'), 'Имена секций экранированы');
  Assert.IsFalse(LHtml.Contains('<evil>'), 'Путь экранирован');
  Assert.IsTrue(LHtml.Contains('&lt;script&gt;'));
  Assert.IsTrue(LHtml.Contains('stratum+tcp://pool.example.org'));
  Assert.IsTrue(LHtml.Contains('</html>'));
end;

procedure TBinaryLabReportTests.Save_ByExtension;
var
  LReport: TMHBinaryReport;
  LJsonPath, LHtmlPath: string;
  LJson: TJSONValue;
begin
  LReport := HostileReport;
  LJsonPath := TPath.Combine(FDir, 'report.json');
  LHtmlPath := TPath.Combine(FDir, 'отчёт.html');
  MHSaveBinaryReport(LReport, LJsonPath);
  MHSaveBinaryReport(LReport, LHtmlPath);
  LJson := TJSONObject.ParseJSONValue(TFile.ReadAllText(LJsonPath, TEncoding.UTF8));
  try
    Assert.IsNotNull(LJson);
  finally
    LJson.Free;
  end;
  Assert.IsTrue(TFile.ReadAllText(LHtmlPath, TEncoding.UTF8).Contains('BinaryLab'));
end;

procedure TBinaryLabReportTests.Diff_JsonAndHtml;
var
  LDiff: TMHBinaryDiff;
  LItem: TMHDiffItem;
  LRange: TMHByteRange;
  LJson: TJSONValue;
  LHtml: string;
begin
  LDiff := Default(TMHBinaryDiff);
  LDiff.LeftPath := 'a<1>.exe';
  LDiff.RightPath := 'b.exe';
  LDiff.LeftSize := 1000;
  LDiff.RightSize := 1200;
  LItem.Area := MH_DIFF_AREA_IMPORT;
  LItem.Change := dcAdded;
  LItem.Name := 'kernel32.dll!<CreateRemoteThread>';
  LItem.OldValue := '';
  LItem.NewValue := LItem.Name;
  LDiff.Items := [LItem];
  LRange.Offset := 512;
  LRange.Size := 100;
  LDiff.ChangedRanges := [LRange];
  LDiff.SimilarityPercent := 87.5;
  LJson := TJSONObject.ParseJSONValue(MHBinaryDiffToJson(LDiff));
  try
    Assert.IsNotNull(LJson);
    Assert.AreEqual(1, (LJson as TJSONObject).GetValue<TJSONArray>('items').Count);
    Assert.AreEqual<Int64>(512, ((LJson as TJSONObject).GetValue<TJSONArray>('changedRanges').Items[0] as TJSONArray)
      .Items[0].AsType<Int64>);
  finally
    LJson.Free;
  end;
  LHtml := MHBinaryDiffToHtml(LDiff);
  Assert.IsFalse(LHtml.Contains('<CreateRemoteThread>'));
  Assert.IsFalse(LHtml.Contains('a<1>'));
  Assert.IsTrue(LHtml.Contains('87.5'));
end;

{ TBinaryLabVerdictTests }

function AnomalyReport(const AAnomalies: array of TMHBinaryAnomaly; ASignature: TMHSignatureState): TMHBinaryReport;
var
  I: Integer;
begin
  Result := Default(TMHBinaryReport);
  Result.Path := 'C:\Program Files\App\..\App\app.exe';
  Result.Sha256 := 'ABCDEF';
  Result.Signature.State := ASignature;
  Result.Score := 70;
  for I := 0 to High(AAnomalies) do
    Result.Anomalies := Result.Anomalies + [AAnomalies[I]];
end;

procedure TBinaryLabVerdictTests.FromReport_WeightsSignalsAndCap;
var
  LVerdict: TMHBinaryVerdict;
  LTotal: Integer;
  LItem: TMHEvidence;
begin
  LVerdict := MHVerdictFromReport(AnomalyReport([
    TMHBinaryAnomaly.Create(BL_UNSIGNED, asLow, 'Без подписи', 'd', 5),
    TMHBinaryAnomaly.Create(BL_OVERLAY, asInfo, 'Оверлей', 'd', 0),
    TMHBinaryAnomaly.Create(BL_RWX_SECTION, asMedium, 'RWX', 'd', 12)], sgUnsigned));
  Assert.AreEqual(1, Integer(Length(LVerdict.Evidence)), 'Только средние и высокие');
  Assert.AreEqual('BINARYLAB:' + BL_RWX_SECTION, LVerdict.Evidence[0].Code);
  Assert.AreEqual(7, LVerdict.Evidence[0].Weight, '60% от 12');
  Assert.IsFalse(LVerdict.ThreatSignal);
  Assert.IsFalse(LVerdict.MiningSignal);
  Assert.AreEqual('C:\Program Files\App\app.exe', LVerdict.Path, 'Путь нормализован');
  Assert.AreEqual('abcdef', LVerdict.Sha256);
  // Майнинг и высокие признаки, предел суммы 40.
  LVerdict := MHVerdictFromReport(AnomalyReport([
    TMHBinaryAnomaly.Create(BL_MINING_STRINGS, asHigh, 'Майнинг', 'd', 30),
    TMHBinaryAnomaly.Create(BL_PACKED_CODE, asHigh, 'Упаковка', 'd', 20),
    TMHBinaryAnomaly.Create(BL_INJECTION_API, asHigh, 'Внедрение', 'd', 20),
    TMHBinaryAnomaly.Create(BL_RWX_SECTION, asMedium, 'RWX', 'd', 12)], sgUnsigned));
  Assert.IsTrue(LVerdict.MiningSignal);
  Assert.IsTrue(LVerdict.ThreatSignal);
  LTotal := 0;
  for LItem in LVerdict.Evidence do
    Inc(LTotal, LItem.Weight);
  Assert.AreEqual(MH_BINARYLAB_MAX_EVIDENCE_WEIGHT, LTotal);
  Assert.AreEqual('BINARYLAB:' + BL_MINING_STRINGS, LVerdict.Evidence[0].Code, 'Самый весомый первым');
  Assert.IsTrue(LVerdict.Evidence[0].Description.Contains('BinaryLab'));
  // Доверенная подпись — вес вдвое меньше.
  LVerdict := MHVerdictFromReport(AnomalyReport([TMHBinaryAnomaly.Create(BL_PACKED_CODE, asHigh, 'Упаковка', 'd', 20)],
    sgSignedTrusted));
  Assert.AreEqual(6, LVerdict.Evidence[0].Weight);
  // Нет признаков — пустой вердикт, но с путём и оценкой.
  LVerdict := MHVerdictFromReport(AnomalyReport([], sgUnsigned));
  Assert.AreEqual(0, Integer(Length(LVerdict.Evidence)));
  Assert.AreEqual(70, LVerdict.Score);
end;

procedure TBinaryLabVerdictTests.Store_MatchByPathAndHash;
var
  LStore: IMHBinaryVerdicts;
  LVerdict, LFound: TMHBinaryVerdict;
begin
  LStore := TMHBinaryVerdictStore.Create;
  LVerdict := Default(TMHBinaryVerdict);
  LVerdict.Path := 'C:\Tools\Miner.exe';
  LVerdict.Sha256 := 'AA11';
  LVerdict.Score := 80;
  LStore.Put(LVerdict);
  Assert.AreEqual(1, LStore.Count);
  Assert.IsTrue(LStore.TryGet('c:\tools\MINER.EXE', 'aa11', LFound), 'Без учёта регистра');
  Assert.AreEqual(80, LFound.Score);
  Assert.IsTrue(LStore.TryGet('C:\Tools\Miner.exe', '', LFound), 'Хеш процесса неизвестен — по пути');
  Assert.IsFalse(LStore.TryGet('C:\Tools\Miner.exe', 'bb22', LFound), 'Файл изменился');
  Assert.IsFalse(LStore.TryGet('C:\Tools\Other.exe', 'aa11', LFound));
  Assert.IsFalse(LStore.TryGet('', '', LFound));
  // Повторный анализ заменяет вердикт.
  LVerdict.Score := 10;
  LStore.Put(LVerdict);
  Assert.AreEqual(1, LStore.Count);
  Assert.IsTrue(LStore.TryGet('C:\Tools\Miner.exe', 'aa11', LFound));
  Assert.AreEqual(10, LFound.Score);
  // Пустой путь не сохраняется.
  LVerdict.Path := '';
  LStore.Put(LVerdict);
  Assert.AreEqual(1, LStore.Count);
  LStore.Clear;
  Assert.AreEqual(0, LStore.Count);
end;

procedure TBinaryLabVerdictTests.Store_EvictsOldest;
var
  LStore: IMHBinaryVerdicts;
  LVerdict, LFound: TMHBinaryVerdict;
  I: Integer;
begin
  LStore := TMHBinaryVerdictStore.Create;
  for I := 1 to TMHBinaryVerdictStore.MaxVerdicts + 5 do
  begin
    LVerdict := Default(TMHBinaryVerdict);
    LVerdict.Path := Format('C:\Files\f%d.exe', [I]);
    LStore.Put(LVerdict);
  end;
  Assert.AreEqual(TMHBinaryVerdictStore.MaxVerdicts, LStore.Count);
  Assert.IsFalse(LStore.TryGet('C:\Files\f1.exe', '', LFound), 'Самый старый вытеснен');
  Assert.IsTrue(LStore.TryGet(Format('C:\Files\f%d.exe', [TMHBinaryVerdictStore.MaxVerdicts + 5]), '', LFound));
end;

procedure TBinaryLabVerdictTests.Store_ConcurrentAccess;
var
  LStore: IMHBinaryVerdicts;
  LThreads: array[0..3] of TThread;
  I: Integer;
begin
  LStore := TMHBinaryVerdictStore.Create;
  for I := 0 to High(LThreads) do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      var
        J: Integer;
        LVerdict, LFound: TMHBinaryVerdict;
      begin
        for J := 0 to 1999 do
        begin
          LVerdict := Default(TMHBinaryVerdict);
          LVerdict.Path := Format('C:\T\%d.exe', [J mod 300]);
          LStore.Put(LVerdict);
          LStore.TryGet(Format('C:\T\%d.exe', [(J * 7) mod 300]), '', LFound);
        end;
      end);
    LThreads[I].FreeOnTerminate := False;
    LThreads[I].Start;
  end;
  for I := 0 to High(LThreads) do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;
  Assert.AreEqual(300, LStore.Count);
end;

function IdleProcessSnapshots(const APath: string; ASignature: TMHSignatureState): TArray<TMHSnapshot>;
begin
  Result := BuildSnapshots([Proc(4242, ExtractFileName(APath), APath, ASignature, '', [0, 1])], 900, False, nil,
    SCENARIO_MINUTES, SCENARIO_STEP_SECONDS);
end;

function FindingFor(const AFindings: TMHFindings; const AName: string; out AFinding: TMHFinding): Boolean;
var
  LFinding: TMHFinding;
begin
  for LFinding in AFindings do
    if SameText(LFinding.ProcessName, AName) then
    begin
      AFinding := LFinding;
      Exit(True);
    end;
  AFinding := Default(TMHFinding);
  Result := False;
end;

function RunAnalyzer(const AVerdicts: IMHBinaryVerdicts; const ASnapshots: TArray<TMHSnapshot>): TMHFindings;
var
  LAnalyzer: TMHThreatAnalyzer;
  LIntf: IMHAnalyzer;
  LSnapshot: TMHSnapshot;
begin
  LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
  LIntf := LAnalyzer;
  LAnalyzer.BinaryVerdicts := AVerdicts;
  Assert.IsTrue(LAnalyzer.BinaryVerdicts = AVerdicts);
  Result := nil;
  for LSnapshot in ASnapshots do
    Result := LAnalyzer.Analyze(LSnapshot, Default(TMHBaseline));
end;

procedure TBinaryLabVerdictTests.Engine_AddsBinaryLabEvidenceToProcessFinding;
const
  PATH = 'C:\Users\Test\AppData\Local\Updater\svc.exe';
var
  LStore: IMHBinaryVerdicts;
  LVerdict: TMHBinaryVerdict;
  LFinding: TMHFinding;
  LSnapshots: TArray<TMHSnapshot>;
  LEvidence: TMHEvidence;
  LHasBinaryEvidence: Boolean;
  LRecommendation: string;
  LMentionsBinaryLab: Boolean;
begin
  LStore := TMHBinaryVerdictStore.Create;
  LSnapshots := IdleProcessSnapshots('C:\Program Files\Vendor\svc.exe', sgSignedTrusted);
  // Без вердикта подписанная программа с низкой нагрузкой — без находки.
  Assert.IsFalse(FindingFor(RunAnalyzer(LStore, LSnapshots), 'svc.exe', LFinding));

  LSnapshots := IdleProcessSnapshots(PATH, sgUnsigned);
  LVerdict := Default(TMHBinaryVerdict);
  LVerdict.Path := PATH;
  LVerdict.Evidence := [TMHEvidence.Create('BINARYLAB:' + BL_MINING_STRINGS,
    'Строки, связанные с майнингом (разбор файла в BinaryLab)', 18, 'stratum+tcp://pool')];
  LVerdict.MiningSignal := True;
  LVerdict.ThreatSignal := True;
  LStore.Put(LVerdict);
  Assert.IsTrue(FindingFor(RunAnalyzer(LStore, LSnapshots), 'svc.exe', LFinding), 'Находка по вердикту BinaryLab');
  Assert.AreEqual(Ord(fcMining), Ord(LFinding.Category));
  LHasBinaryEvidence := False;
  for LEvidence in LFinding.Evidence do
    if LEvidence.Code.StartsWith(EV_BINARYLAB_PREFIX) then
      LHasBinaryEvidence := True;
  Assert.IsTrue(LHasBinaryEvidence);
  LMentionsBinaryLab := False;
  for LRecommendation in LFinding.Recommendations do
    if LRecommendation.Contains('BinaryLab') then
      LMentionsBinaryLab := True;
  Assert.IsTrue(LMentionsBinaryLab);
  // Без хранилища вердиктов анализатор работает как раньше.
  Assert.IsFalse(FindingFor(RunAnalyzer(nil, IdleProcessSnapshots('C:\Program Files\Vendor\svc.exe',
    sgSignedTrusted)), 'svc.exe', LFinding));
end;

procedure TBinaryLabVerdictTests.Engine_IgnoresVerdictForChangedFile;
const
  PATH = 'C:\Program Files\Vendor\tool.exe';
var
  LStore: IMHBinaryVerdicts;
  LVerdict: TMHBinaryVerdict;
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
  I, J: Integer;
begin
  LStore := TMHBinaryVerdictStore.Create;
  LVerdict := Default(TMHBinaryVerdict);
  LVerdict.Path := PATH;
  LVerdict.Sha256 := '1111';
  LVerdict.Evidence := [TMHEvidence.Create('BINARYLAB:' + BL_PACKED_CODE, 'Упаковка', 30)];
  LVerdict.ThreatSignal := True;
  LStore.Put(LVerdict);
  LSnapshots := IdleProcessSnapshots(PATH, sgSignedTrusted);
  // Файл процесса уже другой: SHA-256 не совпадает.
  for I := 0 to High(LSnapshots) do
    for J := 0 to High(LSnapshots[I].Files) do
      LSnapshots[I].Files[J].Sha256 := '2222';
  Assert.IsFalse(FindingFor(RunAnalyzer(LStore, LSnapshots), 'tool.exe', LFinding), 'Старый вердикт не применяется');
end;

end.
