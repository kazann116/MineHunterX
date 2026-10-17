unit MineHunter.Tests.SettingsReports;

{
  Тесты настроек (MH-07), экспорта отчётов (MH-08/MH-09) и безопасных
  действий (MH-10). Обращения к ОС в действиях заменены поддельной
  реализацией IMHSystemOps: ни один процесс не завершается, ни одна
  внешняя программа не запускается. Временные файлы создаются
  в %TEMP%\MineHunterTests\<guid> и удаляются в TearDown.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Settings,
  MineHunter.Core.Reports, MineHunter.Core.Actions,
  MineHunter.Tests.Fakes;

type
  [TestFixture]
  [Category('Unit')]
  TSettingsTests = class
  private
    FDir: string;
    FPath: string;
    FLogger: TRecordingLogger;
    FLoggerIntf: IMHLogger;
    procedure SaveToInvalidLocation;
    procedure WriteRaw(const AText: string);
    function FilesMatching(const APattern: string): TArray<string>;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Defaults_AreDocumentedValues;
    [Test] procedure Normalized_ClampsRanges;
    [Test] procedure Normalized_DropsInvalidAndDuplicateExclusions;
    [Test] procedure Load_MissingFile_ReturnsDefaults;
    [Test] procedure SaveLoad_RoundTrip;
    [Test] procedure Save_IsAtomic_NoTmpAndNoBom;
    [Test] procedure Load_UnknownFieldsIgnored_MissingAndWrongTypesUseDefaults;
    [Test] procedure Load_CorruptFile_DefaultsAndBadCopy;
    [Test] procedure Load_NotAnObject_IsCorrupt;
    [Test] procedure Save_InvalidLocation_RaisesSettingsError;
    [Test] procedure Exclusions_AddRemoveDuplicates;
    [Test] procedure Exclusions_HashSpecificMatching;
    [Test] procedure DefaultPath_IsUnderLocalAppData;
  end;

  [TestFixture]
  [Category('Unit')]
  TReportTests = class
  private
    FDir: string;
    function Options: TMHReportOptions;
    function SampleSnapshot: TMHSnapshot;
    function SampleFinding: TMHFinding;
    function ProfilePath(const ARelative: string): string;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Json_ParsesAndContainsFindingsAndEvidence;
    [Test] procedure Json_TopProcessesLimitedAndSorted;
    [Test] procedure Html_EscapesScriptProcessName;
    [Test] procedure Html_IsSelfContained;
    [Test] procedure Html_HasSectionsAndTextStatuses;
    [Test] procedure HtmlEscape_AllSpecialChars;
    [Test] procedure Redact_CurrentProfileAndUserName;
    [Test] procedure RedactWith_OtherProfilesUserAndComputer;
    [Test] procedure Reports_DoNotContainProfilePathWhenRedacted;
    [Test] procedure Reports_KeepPathsWhenRedactionDisabled;
    [Test] procedure CommandLines_ExcludedByDefault;
    [Test] procedure FindingCard_SvgHasGapsForNoData;
    [Test] procedure FindingCard_JsonHasNullForNoData;
    [Test] procedure Output_IsDeterministic;
    [Test] procedure SaveTextFile_Utf8WithoutBomAndNoTmp;
  end;

  /// Поддельные обращения к ОС с управляемыми ответами.
  TFakeSystemOps = class(TInterfacedObject, IMHSystemOps)
  public
    OwnPid: Cardinal;
    OpenSucceeds: Boolean;
    OpenError: Cardinal;
    ProcessCreateTime: UInt64;
    CreateTimeAvailable: Boolean;
    ImagePath: string;
    Critical: Boolean;
    AlreadyExited: Boolean;
    TerminateSucceeds: Boolean;
    TerminateError: Cardinal;
    ExitsAfterTerminate: Boolean;
    ExistingFiles: TArray<string>;
    ShellSucceeds: Boolean;
    DefenderPath: string;
    RunOutcome: TMHRunOutcome;
    RunExitCode: Cardinal;
    RunOutput: string;
    // Наблюдения
    OpenCalls: Integer;
    CloseCalls: Integer;
    TerminateCalls: Integer;
    ShellCalls: Integer;
    LastShellPath: string;
    RunCalls: Integer;
    LastRunExe: string;
    LastRunArgs: string;
    LastRunTimeout: Cardinal;
    constructor Create;
    function CurrentPid: Cardinal;
    function OpenProcessForTerminate(APid: Cardinal; out AHandle: THandle;
      out AError: Cardinal): Boolean;
    procedure CloseProcess(AHandle: THandle);
    function GetCreateTime(AHandle: THandle; out ACreateTime: UInt64): Boolean;
    function GetImagePath(AHandle: THandle; out APath: string): Boolean;
    function IsCritical(AHandle: THandle; out ACritical: Boolean): Boolean;
    function Terminate(AHandle: THandle; AExitCode: Cardinal; out AError: Cardinal): Boolean;
    function WaitExit(AHandle: THandle; ATimeoutMs: Cardinal): Boolean;
    function FileExists(const APath: string): Boolean;
    function ShellOpenSelect(const APath: string; out AError: string): Boolean;
    function FindDefenderCli: string;
    function RunHidden(const AExe, AArgs: string; ATimeoutMs: Cardinal;
      const ACancel: TMHCancelFunc; out AExitCode: Cardinal; out AOutput: string): TMHRunOutcome;
  end;

  /// Журнал действий в памяти; может имитировать сбой записи.
  TRecordingActionLog = class(TInterfacedObject, IMHActionLog)
  public
    Records: TArray<TMHActionRecord>;
    Fail: Boolean;
    procedure LogAction(const ARecord: TMHActionRecord);
    function LoadActions(AMaxCount: Integer): TArray<TMHActionRecord>;
  end;

  [TestFixture]
  [Category('Unit')]
  TSafeActionsTests = class
  private
    FOps: TFakeSystemOps;
    FOpsIntf: IMHSystemOps;
    FLog: TRecordingActionLog;
    FLogIntf: IMHActionLog;
    FClockIntf: IMHClock;
    FActions: TMHSafeActions;
    function Id: TMHProcessId;
    procedure CreateWithoutOps;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Constructor_RequiresOpsAndClock;
    [Test] procedure ProtectedNames_AreRefused;
    [Test] procedure SystemPids_AreRefused;
    [Test] procedure OwnPid_IsRefused;
    [Test] procedure MissingCreateTime_IsRefused;
    [Test] procedure IdentityMismatch_IsRefusedAndNotTerminated;
    [Test] procedure AccessDeniedOnOpen_SuggestsAdministrator;
    [Test] procedure AccessDeniedOnTerminate_IsReported;
    [Test] procedure ProcessGone_IsNotFound;
    [Test] procedure ProtectedImagePath_IsRefused;
    [Test] procedure CriticalProcess_IsRefused;
    [Test] procedure Success_TerminatesAndLogs;
    [Test] procedure NotExitedInTime_IsFailed;
    [Test] procedure ActionLogFailure_DoesNotRaise;
    [Test] procedure Defender_Unavailable;
    [Test] procedure Defender_Clean_UsesReportOnlyArguments;
    [Test] procedure Defender_Threat_ParsesNames;
    [Test] procedure Defender_Timeout_IsFailed;
    [Test] procedure Defender_Cancelled;
    [Test] procedure Defender_CancelledBeforeStart_DoesNotRun;
    [Test] procedure Defender_OtherExitCode_IsFailed;
    [Test] procedure Defender_ServiceNotRunning_IsUnavailable;
    [Test] procedure Defender_InvalidOrMissingPath_IsRefused;
    [Test] procedure OpenFileLocation_RefusesMissingFile;
    [Test] procedure OpenFileLocation_RefusesQuotesArgumentsAndUris;
    [Test] procedure OpenFileLocation_NormalizesAndOpens;
    [Test] procedure DefenderPlatforms_SortedNewestFirst;
    [Test] procedure DefenderThreats_ParsedWithoutDuplicates;
  end;

implementation

uses
  System.Classes, System.IOUtils, System.JSON, System.StrUtils, System.DateUtils,
  System.Generics.Collections,
  MineHunter.Core.Scanner;

const
  FAKE_HANDLE = THandle($BEEF);
  TEST_PID = 4242;
  TEST_CREATE_TIME = UInt64(133000000000000000);
  SAMPLE_SHA = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  OTHER_SHA = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
  SCRIPT_NAME = '<script>alert(1)</script>.exe';

function NewTempDir: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(Result);
end;

procedure RemoveTempDir(const ADir: string);
begin
  if (ADir <> '') and TDirectory.Exists(ADir) then
    TDirectory.Delete(ADir, True);
end;

function CountOf(const AText, AWhat: string): Integer;
var
  LPos: Integer;
begin
  Result := 0;
  LPos := PosEx(AWhat, AText, 1);
  while LPos > 0 do
  begin
    Inc(Result);
    LPos := PosEx(AWhat, AText, LPos + Length(AWhat));
  end;
end;

function Exclusion(const AKey, ASha: string): TMHExclusion;
begin
  Result := Default(TMHExclusion);
  Result.Key := AKey;
  Result.Sha256 := ASha;
  Result.Name := ExtractFileName(AKey);
end;

{ TSettingsTests }

procedure TSettingsTests.Setup;
begin
  FDir := NewTempDir;
  FPath := TPath.Combine(FDir, 'settings.json');
  FLogger := TRecordingLogger.Create;
  FLoggerIntf := FLogger;
end;

procedure TSettingsTests.TearDown;
begin
  FLoggerIntf := nil;
  RemoveTempDir(FDir);
end;

procedure TSettingsTests.WriteRaw(const AText: string);
begin
  TFile.WriteAllBytes(FPath, TEncoding.UTF8.GetBytes(AText));
end;

function TSettingsTests.FilesMatching(const APattern: string): TArray<string>;
begin
  Result := TDirectory.GetFiles(FDir, APattern);
end;

procedure TSettingsTests.Defaults_AreDocumentedValues;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  Assert.AreEqual<Cardinal>(2000, LSettings.IntervalMs);
  Assert.IsTrue(LSettings.StartScanOnLaunch);
  Assert.AreEqual(7, LSettings.RetentionDays);
  Assert.AreEqual(256, LSettings.MaxDatabaseMB);
  Assert.IsTrue(LSettings.StoreProcessPaths);
  Assert.AreEqual(3, LSettings.LearningDays);
  Assert.IsTrue(LSettings.RedactPathsInReports);
  Assert.AreEqual(0, Integer(Length(LSettings.Exclusions)));
  Assert.AreEqual(TMHRiskThresholds.Default.Suspicious, LSettings.Analyzer.Thresholds.Suspicious);
end;

procedure TSettingsTests.Normalized_ClampsRanges;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  LSettings.IntervalMs := 10;
  LSettings.RetentionDays := 0;
  LSettings.MaxDatabaseMB := -5;
  LSettings.LearningDays := 0;
  LSettings.Analyzer.Thresholds.Low := 90;
  LSettings.Analyzer.HighCpuPercent := 500;
  LSettings := LSettings.Normalized;
  Assert.AreEqual<Cardinal>(TMHScannerOptions.MinIntervalMs, LSettings.IntervalMs);
  Assert.AreEqual(1, LSettings.RetentionDays);
  Assert.AreEqual(TMHAppSettings.MinDatabaseSizeMB, LSettings.MaxDatabaseMB);
  Assert.AreEqual(1, LSettings.LearningDays);
  Assert.IsTrue(LSettings.Analyzer.Thresholds.IsValid);
  Assert.AreEqual(100.0, LSettings.Analyzer.HighCpuPercent, 1e-9);

  LSettings.IntervalMs := 100000000;
  LSettings.RetentionDays := 100000;
  LSettings.MaxDatabaseMB := MaxInt;
  LSettings.LearningDays := 1000;
  LSettings := LSettings.Normalized;
  Assert.AreEqual<Cardinal>(TMHScannerOptions.MaxIntervalMs, LSettings.IntervalMs);
  Assert.AreEqual(3650, LSettings.RetentionDays);
  Assert.AreEqual(TMHAppSettings.MaxDatabaseSizeMB, LSettings.MaxDatabaseMB);
  Assert.AreEqual(TMHAppSettings.MaxLearningDays, LSettings.LearningDays);
end;

procedure TSettingsTests.Normalized_DropsInvalidAndDuplicateExclusions;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  LSettings.Exclusions := [
    Exclusion('C:\Tools\App.exe', ''),
    Exclusion('c:\tools\app.exe', ''),            // повтор с другим регистром
    Exclusion('   ', ''),                         // пустой ключ
    Exclusion('c:\tools\app.exe', SAMPLE_SHA),     // другой хеш — отдельное исключение
    Exclusion('c:\tools\app.exe', SAMPLE_SHA.ToUpper), // повтор хеша в верхнем регистре
    Exclusion('c:\tools\bad.exe', 'xyz')];        // некорректный SHA-256
  LSettings := LSettings.Normalized;
  Assert.AreEqual(2, Integer(Length(LSettings.Exclusions)));
  Assert.AreEqual('c:\tools\app.exe', LSettings.Exclusions[0].Key);
  Assert.AreEqual('', LSettings.Exclusions[0].Sha256);
  Assert.AreEqual(SAMPLE_SHA, LSettings.Exclusions[1].Sha256);
end;

procedure TSettingsTests.Load_MissingFile_ReturnsDefaults;
var
  LStore: TMHSettingsStore;
  LSettings: TMHAppSettings;
begin
  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    Assert.IsTrue(LStore.Load(LSettings));
    Assert.AreEqual<Cardinal>(TMHAppSettings.Default.IntervalMs, LSettings.IntervalMs);
    Assert.IsFalse(FileExists(FPath), 'Load не должен создавать файл');
  finally
    LStore.Free;
  end;
end;

procedure TSettingsTests.SaveLoad_RoundTrip;
var
  LStore: TMHSettingsStore;
  LSaved, LLoaded: TMHAppSettings;
  LExclusion: TMHExclusion;
begin
  LSaved := TMHAppSettings.Default;
  LSaved.IntervalMs := 5000;
  LSaved.StartScanOnLaunch := False;
  LSaved.RetentionDays := 30;
  LSaved.MaxDatabaseMB := 512;
  LSaved.StoreProcessPaths := False;
  LSaved.LearningDays := 7;
  LSaved.RedactPathsInReports := False;
  LSaved.Analyzer.Thresholds.Low := 10;
  LSaved.Analyzer.Thresholds.NeedsReview := 30;
  LSaved.Analyzer.Thresholds.Suspicious := 55;
  LSaved.Analyzer.Thresholds.HighlySuspicious := 90;
  LSaved.Analyzer.HighCpuPercent := 33.5;
  LSaved.Analyzer.HighCoreCpuPercent := 75;
  LSaved.Analyzer.SustainedMinutes := 15;
  LSaved.Analyzer.BaselineMinSamples := 600;
  LExclusion := Exclusion('c:\games\launcher.exe', SAMPLE_SHA);
  LExclusion.Comment := 'Игра «Тест» — разрешено';
  LExclusion.CreatedUtc := EncodeDateTime(2026, 10, 1, 12, 30, 0, 0);
  LSaved.Exclusions := [LExclusion];

  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    LStore.Save(LSaved);
    Assert.IsTrue(LStore.Load(LLoaded));
  finally
    LStore.Free;
  end;
  Assert.AreEqual<Cardinal>(5000, LLoaded.IntervalMs);
  Assert.IsFalse(LLoaded.StartScanOnLaunch);
  Assert.AreEqual(30, LLoaded.RetentionDays);
  Assert.AreEqual(512, LLoaded.MaxDatabaseMB);
  Assert.IsFalse(LLoaded.StoreProcessPaths);
  Assert.AreEqual(7, LLoaded.LearningDays);
  Assert.IsFalse(LLoaded.RedactPathsInReports);
  Assert.AreEqual(10, LLoaded.Analyzer.Thresholds.Low);
  Assert.AreEqual(30, LLoaded.Analyzer.Thresholds.NeedsReview);
  Assert.AreEqual(55, LLoaded.Analyzer.Thresholds.Suspicious);
  Assert.AreEqual(90, LLoaded.Analyzer.Thresholds.HighlySuspicious);
  Assert.AreEqual(33.5, LLoaded.Analyzer.HighCpuPercent, 1e-9);
  Assert.AreEqual(75.0, LLoaded.Analyzer.HighCoreCpuPercent, 1e-9);
  Assert.AreEqual(15, LLoaded.Analyzer.SustainedMinutes);
  Assert.AreEqual(600, LLoaded.Analyzer.BaselineMinSamples);
  Assert.AreEqual(1, Integer(Length(LLoaded.Exclusions)));
  Assert.AreEqual('c:\games\launcher.exe', LLoaded.Exclusions[0].Key);
  Assert.AreEqual(SAMPLE_SHA, LLoaded.Exclusions[0].Sha256);
  Assert.AreEqual('Игра «Тест» — разрешено', LLoaded.Exclusions[0].Comment);
  Assert.AreEqual(LExclusion.CreatedUtc, LLoaded.Exclusions[0].CreatedUtc, 1 / SecsPerDay);
end;

procedure TSettingsTests.Save_IsAtomic_NoTmpAndNoBom;
var
  LStore: TMHSettingsStore;
  LBytes: TBytes;
  LJson: TJSONValue;
begin
  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    LStore.Save(TMHAppSettings.Default);
    LStore.Save(TMHAppSettings.Default); // замена существующего файла
  finally
    LStore.Free;
  end;
  Assert.IsTrue(FileExists(FPath));
  Assert.IsFalse(FileExists(FPath + '.tmp'), 'временный файл должен быть переименован');
  LBytes := TFile.ReadAllBytes(FPath);
  Assert.IsTrue(Length(LBytes) > 0);
  Assert.AreEqual(Ord('{'), Integer(LBytes[0]), 'файл должен начинаться без BOM');
  LJson := TJSONObject.ParseJSONValue(TEncoding.UTF8.GetString(LBytes));
  try
    Assert.IsNotNull(LJson);
    Assert.AreEqual(MH_SETTINGS_VERSION, (LJson as TJSONObject).GetValue<Integer>('version'));
  finally
    LJson.Free;
  end;
end;

procedure TSettingsTests.Load_UnknownFieldsIgnored_MissingAndWrongTypesUseDefaults;
var
  LStore: TMHSettingsStore;
  LSettings: TMHAppSettings;
begin
  WriteRaw('{"version":1,"futureOption":{"a":[1,2,3]},"intervalMs":3000,' +
    '"retentionDays":"тридцать","learningDays":5,' +
    '"analyzer":{"sustainedMinutes":20,"unknown":true},' +
    '"exclusions":[{"key":"C:\\Apps\\Tool.exe","extra":1},42,{"key":""}]}');
  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    Assert.IsTrue(LStore.Load(LSettings));
  finally
    LStore.Free;
  end;
  Assert.AreEqual<Cardinal>(3000, LSettings.IntervalMs);
  Assert.AreEqual(TMHAppSettings.Default.RetentionDays, LSettings.RetentionDays, 'неверный тип');
  Assert.AreEqual(5, LSettings.LearningDays);
  Assert.AreEqual(20, LSettings.Analyzer.SustainedMinutes);
  Assert.AreEqual(TMHAnalyzerSettings.Default.BaselineMinSamples,
    LSettings.Analyzer.BaselineMinSamples, 'отсутствующее поле');
  Assert.IsTrue(LSettings.RedactPathsInReports, 'отсутствующее поле');
  Assert.AreEqual(1, Integer(Length(LSettings.Exclusions)));
  Assert.AreEqual('c:\apps\tool.exe', LSettings.Exclusions[0].Key);
end;

procedure TSettingsTests.Load_CorruptFile_DefaultsAndBadCopy;
var
  LStore: TMHSettingsStore;
  LSettings: TMHAppSettings;
  LBad: TArray<string>;
begin
  WriteRaw('{"version":1, "intervalMs": 5000, oops');
  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    Assert.IsFalse(LStore.Load(LSettings));
  finally
    LStore.Free;
  end;
  Assert.AreEqual<Cardinal>(TMHAppSettings.Default.IntervalMs, LSettings.IntervalMs);
  Assert.IsFalse(FileExists(FPath), 'повреждённый файл должен быть переименован');
  LBad := FilesMatching('settings.json.bad-*');
  Assert.AreEqual(1, Integer(Length(LBad)));
  Assert.AreEqual('{"version":1, "intervalMs": 5000, oops',
    TEncoding.UTF8.GetString(TFile.ReadAllBytes(LBad[0])));
  Assert.IsTrue(FLogger.CountOf(llWarning) >= 1);
  Assert.IsTrue(FLogger.ContainsText('повреждён'));
end;

procedure TSettingsTests.Load_NotAnObject_IsCorrupt;
var
  LStore: TMHSettingsStore;
  LSettings: TMHAppSettings;
begin
  WriteRaw('[1,2,3]');
  LStore := TMHSettingsStore.Create(FPath, FLoggerIntf);
  try
    Assert.IsFalse(LStore.Load(LSettings));
    // Без поля version файл тоже считается повреждённым.
    WriteRaw('{"intervalMs":3000}');
    Assert.IsFalse(LStore.Load(LSettings));
  finally
    LStore.Free;
  end;
  Assert.AreEqual<Cardinal>(TMHAppSettings.Default.IntervalMs, LSettings.IntervalMs);
  Assert.AreEqual(2, Integer(Length(FilesMatching('settings.json.bad-*'))));
end;

procedure TSettingsTests.SaveToInvalidLocation;
var
  LStore: TMHSettingsStore;
  LBlocker: string;
begin
  // Каталог назначения не может быть создан: на его месте — обычный файл.
  LBlocker := TPath.Combine(FDir, 'blocker');
  TFile.WriteAllText(LBlocker, 'x');
  LStore := TMHSettingsStore.Create(TPath.Combine(LBlocker, 'settings.json'), FLoggerIntf);
  try
    LStore.Save(TMHAppSettings.Default);
  finally
    LStore.Free;
  end;
end;

procedure TSettingsTests.Save_InvalidLocation_RaisesSettingsError;
begin
  Assert.WillRaise(SaveToInvalidLocation, EMHSettingsError);
end;

procedure TSettingsTests.Exclusions_AddRemoveDuplicates;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  Assert.IsTrue(MHAddExclusion(LSettings, Exclusion('C:\Tools\App.exe', '')));
  Assert.IsFalse(MHAddExclusion(LSettings, Exclusion('c:\tools\app.exe', '')), 'повтор');
  Assert.IsFalse(MHAddExclusion(LSettings, Exclusion('  ', '')), 'пустой ключ');
  Assert.IsFalse(MHAddExclusion(LSettings, Exclusion('c:\x.exe', 'not-a-hash')), 'плохой хеш');
  Assert.IsTrue(MHAddExclusion(LSettings, Exclusion('c:\tools\app.exe', SAMPLE_SHA)));
  Assert.AreEqual(2, Integer(Length(LSettings.Exclusions)));

  Assert.IsTrue(MHRemoveExclusion(LSettings, 'C:\TOOLS\APP.EXE', ''));
  Assert.IsFalse(MHRemoveExclusion(LSettings, 'c:\tools\app.exe', ''), 'уже удалено');
  Assert.IsFalse(MHRemoveExclusion(LSettings, 'c:\tools\app.exe', OTHER_SHA), 'другой хеш');
  Assert.AreEqual(1, Integer(Length(LSettings.Exclusions)));
  Assert.AreEqual(SAMPLE_SHA, LSettings.Exclusions[0].Sha256);
end;

procedure TSettingsTests.Exclusions_HashSpecificMatching;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  MHAddExclusion(LSettings, Exclusion('c:\tools\pinned.exe', SAMPLE_SHA));
  MHAddExclusion(LSettings, Exclusion('c:\tools\any.exe', ''));
  Assert.IsTrue(MHIsExcluded(LSettings, 'c:\tools\pinned.exe', SAMPLE_SHA));
  Assert.IsTrue(MHIsExcluded(LSettings, 'C:\Tools\Pinned.exe', SAMPLE_SHA.ToUpper));
  Assert.IsFalse(MHIsExcluded(LSettings, 'c:\tools\pinned.exe', OTHER_SHA), 'файл подменён');
  Assert.IsFalse(MHIsExcluded(LSettings, 'c:\tools\pinned.exe', ''), 'хеш неизвестен');
  Assert.IsTrue(MHIsExcluded(LSettings, 'c:\tools\any.exe', OTHER_SHA));
  Assert.IsTrue(MHIsExcluded(LSettings, 'c:\tools\any.exe', ''));
  Assert.IsFalse(MHIsExcluded(LSettings, 'c:\tools\other.exe', ''));
end;

procedure TSettingsTests.DefaultPath_IsUnderLocalAppData;
var
  LPath: string;
begin
  LPath := MHDefaultSettingsPath;
  Assert.IsTrue(LPath.EndsWith('\MineHunterX\settings.json', True), LPath);
  Assert.IsTrue(TPath.IsPathRooted(LPath));
end;

{ TReportTests }

procedure TReportTests.Setup;
begin
  FDir := NewTempDir;
end;

procedure TReportTests.TearDown;
begin
  RemoveTempDir(FDir);
end;

function TReportTests.Options: TMHReportOptions;
begin
  Result := TMHReportOptions.Default;
  Result.AppVersion := '1.2.3-test';
  Result.RulesetVersion := 'rules-7';
  Result.GeneratedUtc := FAKE_NOW;
end;

function TReportTests.ProfilePath(const ARelative: string): string;
begin
  Result := IncludeTrailingPathDelimiter(TMHRedactionContext.Current.ProfileDir) + ARelative;
end;

function TReportTests.SampleFinding: TMHFinding;
begin
  Result := Default(TMHFinding);
  Result.Id := TGUID.Create('{11111111-2222-3333-4444-555555555555}');
  Result.Process := TMHProcessId.Create(1001, 777);
  Result.ParentPid := 900;
  Result.ProcessName := SCRIPT_NAME;
  Result.ImagePath := ProfilePath('AppData\Roaming\x\' + SCRIPT_NAME);
  Result.Title := 'Признаки скрытого майнинга: ' + SCRIPT_NAME;
  Result.Summary := 'Длительная нагрузка в фоне';
  Result.Score := 72;
  Result.RawScore := 80;
  Result.Level := rlSuspicious;
  Result.Confidence := 0.8;
  Result.Category := fcMining;
  Result.Key := 'mining:' + Result.ImagePath.ToLower;
  Result.Evidence := [
    TMHEvidence.Create('CPU_SUSTAINED', 'Высокая загрузка CPU без окна', 35, '87% в течение 40 мин'),
    TMHEvidence.Create('UNSIGNED', 'Файл без цифровой подписи', 20),
    TMHEvidence.Create('KNOWN_BASELINE', 'Процесс встречался в профиле нормы', -10)];
  Result.MissingData := ['Нет данных о сетевых соединениях'];
  Result.Recommendations := ['Проверьте файл Microsoft Defender'];
  Result.RulesetVersion := 'rules-7';
  Result.DetectedAtUtc := FAKE_NOW;
end;

function TReportTests.SampleSnapshot: TMHSnapshot;
var
  LInfo: TMHProcessInfo;
  LStatus: TMHSourceStatus;
begin
  Result := TMHSnapshot.Create(42, FAKE_NOW);
  Result.Metrics := [TMHMetric.Available(mkCpuPercent, 55.5, FAKE_NOW),
    TMHMetric.NoData(mkGpuPercent, FAKE_NOW)];
  LStatus := TMHSourceStatus.Create('processes', ssPartial, 'Нет доступа к 3 процессам', FAKE_NOW);
  LStatus.RequiresElevation := True;
  Result.Sources := [LStatus,
    TMHSourceStatus.Create('system', ssSuccess, '', FAKE_NOW),
    TMHSourceStatus.Create('gpu', ssUnavailable, 'Счётчики GPU недоступны', FAKE_NOW)];

  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(1001, 777), SCRIPT_NAME, FAKE_NOW);
  LInfo.ParentPid := 900;
  LInfo.ImagePath := ProfilePath('AppData\Roaming\x\' + SCRIPT_NAME);
  LInfo.CommandLine := '"' + LInfo.ImagePath + '" --pool stratum --pass secret-token-123';
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, 87, FAKE_NOW);
  LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 50 * 1024 * 1024, FAKE_NOW);
  LInfo.Signature := sgUnsigned;
  Result.Processes := [LInfo];

  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(2002, 888), 'explorer.exe', FAKE_NOW);
  LInfo.ImagePath := 'C:\Windows\explorer.exe';
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, 3.25, FAKE_NOW);
  LInfo.Signature := sgSignedTrusted;
  Result.Processes := Result.Processes + [LInfo];

  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(3003, 999), 'hidden.exe', FAKE_NOW);
  Result.Processes := Result.Processes + [LInfo]; // CPU — нет данных
end;

procedure TReportTests.Json_ParsesAndContainsFindingsAndEvidence;
var
  LText: string;
  LJson: TJSONValue;
  LRoot, LFinding: TJSONObject;
begin
  LText := TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], Options);
  LJson := TJSONObject.ParseJSONValue(LText);
  try
    Assert.IsNotNull(LJson, 'отчёт должен быть корректным JSON');
    LRoot := LJson as TJSONObject;
    Assert.AreEqual('rules-7', LRoot.GetValue<string>('rulesetVersion'));
    Assert.AreEqual('1.2.3-test', LRoot.GetValue<string>('generator.appVersion'));
    Assert.IsNotNull(LRoot.GetValue('generatedAt'));
    Assert.AreEqual(3, LRoot.GetValue<TJSONArray>('sources').Count);
    Assert.AreEqual('partial', LRoot.GetValue<string>('sources[0].state'));
    Assert.AreEqual(2, LRoot.GetValue<TJSONArray>('systemMetrics').Count);
    Assert.AreEqual(1, LRoot.GetValue<TJSONArray>('findings').Count);
    LFinding := LRoot.GetValue<TJSONArray>('findings').Items[0] as TJSONObject;
    Assert.AreEqual(72, LFinding.GetValue<Integer>('score'));
    Assert.AreEqual(3, LFinding.GetValue<TJSONArray>('evidence').Count);
    Assert.AreEqual('CPU_SUSTAINED', LFinding.GetValue<string>('evidence[0].code'));
    Assert.AreEqual(3, LRoot.GetValue<TJSONArray>('topProcesses').Count);
    Assert.IsTrue(LRoot.GetValue<TJSONArray>('missingData').Count >= 3,
      'частичный и недоступный источники + недостающие данные находки');
    Assert.IsTrue(LRoot.GetValue<string>('disclaimer').Contains('не гарантирует'));
  finally
    LJson.Free;
  end;
end;

procedure TReportTests.Json_TopProcessesLimitedAndSorted;
var
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
  LJson: TJSONValue;
  LTop: TJSONArray;
  I: Integer;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  for I := 1 to 25 do
  begin
    LInfo := TMHProcessInfo.Create(TMHProcessId.Create(I, I), Format('p%d.exe', [I]), FAKE_NOW);
    LInfo.Cpu := TMHMetric.Available(mkCpuPercent, (I * 7) mod 25, FAKE_NOW);
    LSnapshot.Processes := LSnapshot.Processes + [LInfo];
  end;
  LJson := TJSONObject.ParseJSONValue(TMHReportBuilder.BuildJson(LSnapshot, nil, Options));
  try
    LTop := (LJson as TJSONObject).GetValue<TJSONArray>('topProcesses');
    Assert.AreEqual(MH_REPORT_TOP_PROCESSES, LTop.Count);
    Assert.AreEqual(24.0, LTop.Items[0].GetValue<Double>('cpu.value'), 1e-9);
    for I := 1 to LTop.Count - 1 do
      Assert.IsTrue(LTop.Items[I - 1].GetValue<Double>('cpu.value') >=
        LTop.Items[I].GetValue<Double>('cpu.value'));
  finally
    LJson.Free;
  end;
end;

procedure TReportTests.Html_EscapesScriptProcessName;
var
  LHtml, LCard: string;
begin
  LHtml := TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options);
  Assert.IsTrue(LHtml.Contains('&lt;script&gt;alert(1)&lt;/script&gt;.exe'));
  Assert.IsFalse(ContainsText(LHtml, '<script'), 'тег script недопустим');
  LCard := TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0],
    nil, Options);
  Assert.IsTrue(LCard.Contains('&lt;script&gt;alert(1)&lt;/script&gt;.exe'));
  Assert.IsFalse(ContainsText(LCard, '<script'));
end;

procedure TReportTests.Html_IsSelfContained;
var
  LHtml: string;
  LLoad: TArray<TMHMetric>;
begin
  LLoad := [TMHMetric.Available(mkCpuPercent, 50, FAKE_NOW)];
  for LHtml in TArray<string>.Create(
    TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options),
    TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], LLoad, Options)) do
  begin
    Assert.IsTrue(LHtml.StartsWith('<!DOCTYPE html>'));
    Assert.IsTrue(LHtml.Contains('<meta charset="utf-8">'));
    Assert.IsFalse(ContainsText(LHtml, 'http://'), 'внешние ресурсы недопустимы');
    Assert.IsFalse(ContainsText(LHtml, 'https://'), 'внешние ресурсы недопустимы');
    Assert.IsFalse(ContainsText(LHtml, '<link'), 'внешние стили недопустимы');
    Assert.IsFalse(ContainsText(LHtml, ' src='), 'внешние ресурсы недопустимы');
    Assert.IsFalse(ContainsText(LHtml, '<script'), 'скрипты недопустимы');
    Assert.IsTrue(LHtml.Contains('<style>'));
    Assert.IsTrue(LHtml.Contains('Отсутствие находок не гарантирует отсутствие угроз'));
  end;
end;

procedure TReportTests.Html_HasSectionsAndTextStatuses;
var
  LHtml: string;
begin
  LHtml := TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options);
  Assert.IsTrue(LHtml.Contains('<h2>Сводка</h2>'));
  Assert.IsTrue(LHtml.Contains('<h2>Состояние источников</h2>'));
  Assert.IsTrue(LHtml.Contains('<h2>Находки</h2>'));
  Assert.IsTrue(LHtml.Contains('<h2>Самые нагруженные процессы</h2>'));
  Assert.IsTrue(LHtml.Contains('[ЧАСТИЧНО] частично'), 'статус текстом, а не только цветом');
  Assert.IsTrue(LHtml.Contains('[НЕДОСТУПНО] недоступно'));
  Assert.IsTrue(LHtml.Contains('подозрительно'), 'уровень находки текстом');
  Assert.IsTrue(LHtml.Contains('<strong>+35</strong>'));
  Assert.IsTrue(LHtml.Contains('<strong>−10</strong>'));
  Assert.IsTrue(LHtml.Contains('Проверьте файл Microsoft Defender'));
  Assert.IsTrue(LHtml.Contains('rules-7'));
  Assert.IsTrue(LHtml.Contains('нет данных'), 'CPU без данных — «нет данных», а не 0');
end;

procedure TReportTests.HtmlEscape_AllSpecialChars;
begin
  Assert.AreEqual('&amp;&lt;&gt;&quot;&#39;Текст', MHHtmlEscape('&<>"''Текст'));
end;

procedure TReportTests.Redact_CurrentProfileAndUserName;
var
  LContext: TMHRedactionContext;
  LText: string;
begin
  LContext := TMHRedactionContext.Current;
  Assert.IsTrue(LContext.ProfileDir <> '', 'профиль текущего пользователя должен определяться');
  Assert.AreEqual('%USERPROFILE%\AppData\x.exe', MHRedact(ProfilePath('AppData\x.exe')));
  Assert.AreEqual('%USERPROFILE%\appdata\x.exe', MHRedact(ProfilePath('AppData\x.exe').ToLower));
  if LContext.UserName <> '' then
  begin
    LText := MHRedact('Владелец: ' + LContext.UserName + '.');
    Assert.AreEqual('Владелец: <user>.', LText);
  end;
end;

procedure TReportTests.RedactWith_OtherProfilesUserAndComputer;
var
  LContext: TMHRedactionContext;
begin
  LContext.ProfileDir := 'C:\Users\Ivan';
  LContext.UserName := 'Ivan';
  LContext.ComputerNames := ['DESKTOP-42'];
  Assert.AreEqual('%USERPROFILE%\Desktop\a.exe', MHRedactWith('C:\Users\Ivan\Desktop\a.exe', LContext));
  Assert.AreEqual('C:\Users\<user>\x.exe', MHRedactWith('c:\users\Ivan2\x.exe', LContext).Replace('c:\users', 'C:\Users'));
  Assert.AreEqual('D:\Users\<user>\x.exe', MHRedactWith('D:\Users\Petr Petrov\x.exe', LContext));
  Assert.AreEqual('C:\Users\Public\x.exe', MHRedactWith('C:\Users\Public\x.exe', LContext));
  Assert.AreEqual('<user> на <computer>', MHRedactWith('Ivan на DESKTOP-42', LContext));
  Assert.AreEqual('Ivanov', MHRedactWith('Ivanov', LContext), 'только целые слова');
  Assert.AreEqual('"%USERPROFILE%"', MHRedactWith('"C:\Users\Ivan"', LContext));
end;

procedure TReportTests.Reports_DoNotContainProfilePathWhenRedacted;
var
  LProfile, LText: string;
begin
  LProfile := TMHRedactionContext.Current.ProfileDir;
  for LText in TArray<string>.Create(
    TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options),
    TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], Options).Replace('\\', '\').Replace('\/', '/'),
    TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], nil, Options)) do
  begin
    Assert.IsFalse(ContainsText(LText, LProfile), 'путь профиля должен быть скрыт');
    Assert.IsTrue(LText.Contains('%USERPROFILE%'));
  end;
end;

procedure TReportTests.Reports_KeepPathsWhenRedactionDisabled;
var
  LOptions: TMHReportOptions;
  LHtml: string;
begin
  LOptions := Options;
  LOptions.RedactPaths := False;
  LHtml := TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], LOptions);
  Assert.IsTrue(ContainsText(LHtml, MHHtmlEscape(TMHRedactionContext.Current.ProfileDir)));
  Assert.IsFalse(LHtml.Contains('%USERPROFILE%'));
end;

procedure TReportTests.CommandLines_ExcludedByDefault;
var
  LOptions: TMHReportOptions;
begin
  LOptions := Options;
  Assert.IsFalse(LOptions.IncludeCommandLines);
  Assert.IsFalse(TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], LOptions).Contains('secret-token'));
  Assert.IsFalse(TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], LOptions).Contains('secret-token'));
  Assert.IsFalse(TMHReportBuilder.FindingCardJson(SampleFinding, SampleSnapshot.Processes[0], nil,
    LOptions).Contains('secret-token'));
  Assert.IsFalse(TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], nil,
    LOptions).Contains('secret-token'));

  LOptions.IncludeCommandLines := True;
  Assert.IsTrue(TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], LOptions).Contains('secret-token'));
  Assert.IsTrue(TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], LOptions).Contains('secret-token'));
end;

procedure TReportTests.FindingCard_SvgHasGapsForNoData;
var
  LLoad: TArray<TMHMetric>;
  LHtml: string;
begin
  LLoad := [TMHMetric.Available(mkCpuPercent, 10, FAKE_NOW),
    TMHMetric.Available(mkCpuPercent, 20, FAKE_NOW + 1 / 1440),
    TMHMetric.NoData(mkCpuPercent, FAKE_NOW + 2 / 1440),
    TMHMetric.Available(mkCpuPercent, 30, FAKE_NOW + 3 / 1440),
    TMHMetric.Available(mkCpuPercent, 40, FAKE_NOW + 4 / 1440),
    TMHMetric.NoData(mkCpuPercent, FAKE_NOW + 5 / 1440),
    TMHMetric.Available(mkCpuPercent, 100, FAKE_NOW + 6 / 1440)];
  LHtml := TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], LLoad, Options);
  Assert.AreEqual(1, CountOf(LHtml, '<svg'));
  Assert.AreEqual(2, CountOf(LHtml, '<polyline'), 'разрыв на «нет данных» — отдельные линии');
  Assert.AreEqual(1, CountOf(LHtml, '<circle'), 'одиночная точка после разрыва');
  Assert.IsTrue(LHtml.Contains('points="0,144 100,128"'), 'координаты в инвариантном формате');
  Assert.IsTrue(LHtml.Contains('cx="600" cy="0"'));
  Assert.IsTrue(LHtml.Contains('без данных: 2'), 'пропуски поясняются текстом');
  Assert.IsTrue(LHtml.Contains('Родительский PID'));
  Assert.IsTrue(LHtml.Contains('без цифровой подписи'));
  Assert.IsTrue(LHtml.Contains('Экспортировано'));
end;

procedure TReportTests.FindingCard_JsonHasNullForNoData;
var
  LJson: TJSONValue;
  LRoot: TJSONObject;
  LLoad: TArray<TMHMetric>;
begin
  LLoad := [TMHMetric.Available(mkCpuPercent, 10, FAKE_NOW), TMHMetric.NoData(mkCpuPercent, FAKE_NOW)];
  LJson := TJSONObject.ParseJSONValue(TMHReportBuilder.FindingCardJson(SampleFinding,
    SampleSnapshot.Processes[0], LLoad, Options));
  try
    Assert.IsNotNull(LJson);
    LRoot := LJson as TJSONObject;
    Assert.AreEqual(2, LRoot.GetValue<TJSONArray>('cpuLoad').Count);
    Assert.IsTrue((LRoot.GetValue<TJSONArray>('cpuLoad').Items[1] as TJSONObject).GetValue('value')
      is TJSONNull);
    Assert.AreEqual(900, LRoot.GetValue<Integer>('process.parentPid'));
    Assert.AreEqual('unsigned', LRoot.GetValue<string>('process.signature'));
    Assert.AreEqual(3, LRoot.GetValue<TJSONArray>('finding.evidence').Count);
    Assert.IsNotNull(LRoot.GetValue('exportedAt'));
  finally
    LJson.Free;
  end;
end;

procedure TReportTests.Output_IsDeterministic;
begin
  Assert.AreEqual(TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], Options),
    TMHReportBuilder.BuildJson(SampleSnapshot, [SampleFinding], Options));
  Assert.AreEqual(TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options),
    TMHReportBuilder.BuildHtml(SampleSnapshot, [SampleFinding], Options));
  Assert.AreEqual(
    TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], nil, Options),
    TMHReportBuilder.FindingCardHtml(SampleFinding, SampleSnapshot.Processes[0], nil, Options));
end;

procedure TReportTests.SaveTextFile_Utf8WithoutBomAndNoTmp;
var
  LPath: string;
  LBytes: TBytes;
begin
  LPath := TPath.Combine(FDir, 'sub\report.html');
  MHSaveTextFile(LPath, '<p>Отчёт</p>');
  MHSaveTextFile(LPath, '<p>Отчёт 2</p>');
  LBytes := TFile.ReadAllBytes(LPath);
  Assert.AreEqual(Ord('<'), Integer(LBytes[0]), 'без BOM');
  Assert.AreEqual('<p>Отчёт 2</p>', TEncoding.UTF8.GetString(LBytes));
  Assert.IsFalse(FileExists(LPath + '.tmp'));
end;

{ TFakeSystemOps }

constructor TFakeSystemOps.Create;
begin
  inherited Create;
  OwnPid := 1;
  OpenSucceeds := True;
  ProcessCreateTime := TEST_CREATE_TIME;
  CreateTimeAvailable := True;
  ImagePath := 'C:\Users\Test\AppData\Local\Temp\miner.exe';
  TerminateSucceeds := True;
  ExitsAfterTerminate := True;
  ShellSucceeds := True;
  RunOutcome := roCompleted;
end;

function TFakeSystemOps.CurrentPid: Cardinal;
begin
  Result := OwnPid;
end;

function TFakeSystemOps.OpenProcessForTerminate(APid: Cardinal; out AHandle: THandle;
  out AError: Cardinal): Boolean;
begin
  Inc(OpenCalls);
  Result := OpenSucceeds;
  if Result then
  begin
    AHandle := FAKE_HANDLE;
    AError := 0;
  end
  else
  begin
    AHandle := 0;
    AError := OpenError;
  end;
end;

procedure TFakeSystemOps.CloseProcess(AHandle: THandle);
begin
  if AHandle = FAKE_HANDLE then
    Inc(CloseCalls);
end;

function TFakeSystemOps.GetCreateTime(AHandle: THandle; out ACreateTime: UInt64): Boolean;
begin
  Result := CreateTimeAvailable;
  ACreateTime := ProcessCreateTime;
end;

function TFakeSystemOps.GetImagePath(AHandle: THandle; out APath: string): Boolean;
begin
  APath := ImagePath;
  Result := APath <> '';
end;

function TFakeSystemOps.IsCritical(AHandle: THandle; out ACritical: Boolean): Boolean;
begin
  ACritical := Critical;
  Result := True;
end;

function TFakeSystemOps.Terminate(AHandle: THandle; AExitCode: Cardinal;
  out AError: Cardinal): Boolean;
begin
  Inc(TerminateCalls);
  Result := TerminateSucceeds;
  if Result then
    AError := 0
  else
    AError := TerminateError;
end;

function TFakeSystemOps.WaitExit(AHandle: THandle; ATimeoutMs: Cardinal): Boolean;
begin
  if TerminateCalls > 0 then
    Result := ExitsAfterTerminate
  else
    Result := AlreadyExited;
end;

function TFakeSystemOps.FileExists(const APath: string): Boolean;
var
  LItem: string;
begin
  for LItem in ExistingFiles do
    if SameText(LItem, APath) then
      Exit(True);
  Result := False;
end;

function TFakeSystemOps.ShellOpenSelect(const APath: string; out AError: string): Boolean;
begin
  Inc(ShellCalls);
  LastShellPath := APath;
  Result := ShellSucceeds;
  if Result then
    AError := ''
  else
    AError := 'simulated shell failure';
end;

function TFakeSystemOps.FindDefenderCli: string;
begin
  Result := DefenderPath;
end;

function TFakeSystemOps.RunHidden(const AExe, AArgs: string; ATimeoutMs: Cardinal;
  const ACancel: TMHCancelFunc; out AExitCode: Cardinal; out AOutput: string): TMHRunOutcome;
begin
  Inc(RunCalls);
  LastRunExe := AExe;
  LastRunArgs := AArgs;
  LastRunTimeout := ATimeoutMs;
  AExitCode := RunExitCode;
  AOutput := RunOutput;
  Result := RunOutcome;
end;

{ TRecordingActionLog }

procedure TRecordingActionLog.LogAction(const ARecord: TMHActionRecord);
begin
  if Fail then
    raise EMHError.Create('simulated journal failure');
  Records := Records + [ARecord];
end;

function TRecordingActionLog.LoadActions(AMaxCount: Integer): TArray<TMHActionRecord>;
var
  I: Integer;
begin
  Result := nil;
  for I := High(Records) downto 0 do
    if Length(Result) < AMaxCount then
      Result := Result + [Records[I]];
end;

{ TSafeActionsTests }

procedure TSafeActionsTests.Setup;
begin
  FOps := TFakeSystemOps.Create;
  FOpsIntf := FOps;
  FLog := TRecordingActionLog.Create;
  FLogIntf := FLog;
  FClockIntf := TFakeClock.Create(FAKE_NOW);
  FActions := TMHSafeActions.Create(FOpsIntf, FLogIntf, FClockIntf);
end;

procedure TSafeActionsTests.TearDown;
begin
  FActions.Free;
  FActions := nil;
  FOpsIntf := nil;
  FLogIntf := nil;
  FClockIntf := nil;
end;

function TSafeActionsTests.Id: TMHProcessId;
begin
  Result := TMHProcessId.Create(TEST_PID, TEST_CREATE_TIME);
end;

procedure TSafeActionsTests.CreateWithoutOps;
begin
  TMHSafeActions.Create(nil, FLogIntf, FClockIntf).Free;
end;

procedure TSafeActionsTests.Constructor_RequiresOpsAndClock;
begin
  Assert.WillRaise(CreateWithoutOps, EArgumentNilException);
  // Журнал необязателен.
  TMHSafeActions.Create(FOpsIntf, nil, FClockIntf).Free;
end;

procedure TSafeActionsTests.ProtectedNames_AreRefused;
var
  LName: string;
  LResult: TMHActionResult;
begin
  for LName in TArray<string>.Create('svchost.exe', 'LSASS.EXE', 'System', 'Memory Compression',
    'Registry', 'csrss.exe', 'MsMpEng.exe', 'dwm.exe', 'C:\Windows\System32\winlogon.exe') do
  begin
    LResult := FActions.TerminateProcess(Id, LName);
    Assert.AreEqual<TMHActionResultKind>(arkProtected, LResult.Kind, LName);
    Assert.IsTrue(LResult.Message <> '', LName);
  end;
  Assert.AreEqual(0, FOps.OpenCalls, 'защищённые процессы даже не открываются');
  Assert.AreEqual(9, Integer(Length(FLog.Records)), 'каждая попытка журналируется');
  Assert.AreEqual('terminate', FLog.Records[0].Action);
  Assert.IsFalse(FLog.Records[0].Success);
end;

procedure TSafeActionsTests.SystemPids_AreRefused;
begin
  Assert.AreEqual<TMHActionResultKind>(arkProtected, FActions.TerminateProcess(TMHProcessId.Create(0, 0), 'idle').Kind);
  Assert.AreEqual<TMHActionResultKind>(arkProtected, FActions.TerminateProcess(TMHProcessId.Create(4, 1), 'x.exe').Kind);
  Assert.AreEqual(0, FOps.OpenCalls);
end;

procedure TSafeActionsTests.OwnPid_IsRefused;
var
  LResult: TMHActionResult;
begin
  FOps.OwnPid := TEST_PID;
  LResult := FActions.TerminateProcess(Id, 'MineHunter.App.exe');
  Assert.AreEqual<TMHActionResultKind>(arkProtected, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('собственный'));
  Assert.AreEqual(0, FOps.OpenCalls);
end;

procedure TSafeActionsTests.MissingCreateTime_IsRefused;
begin
  Assert.AreEqual<TMHActionResultKind>(arkIdentityMismatch,
    FActions.TerminateProcess(TMHProcessId.Create(TEST_PID, 0), 'miner.exe').Kind);
  Assert.AreEqual(0, FOps.TerminateCalls);
end;

procedure TSafeActionsTests.IdentityMismatch_IsRefusedAndNotTerminated;
var
  LResult: TMHActionResult;
begin
  FOps.ProcessCreateTime := TEST_CREATE_TIME + 1;
  LResult := FActions.TerminateProcess(Id, 'miner.exe');
  Assert.AreEqual<TMHActionResultKind>(arkIdentityMismatch, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('PID уже принадлежит другому процессу'));
  Assert.AreEqual(0, FOps.TerminateCalls);
  Assert.AreEqual(1, FOps.CloseCalls, 'дескриптор закрыт');
  Assert.AreEqual(1, Integer(Length(FLog.Records)));
end;

procedure TSafeActionsTests.AccessDeniedOnOpen_SuggestsAdministrator;
var
  LResult: TMHActionResult;
begin
  FOps.OpenSucceeds := False;
  FOps.OpenError := 5;
  LResult := FActions.TerminateProcess(Id, 'miner.exe');
  Assert.AreEqual<TMHActionResultKind>(arkAccessDenied, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('администратора'));
  Assert.IsTrue(LResult.Message.Contains('не повышаются'));
end;

procedure TSafeActionsTests.AccessDeniedOnTerminate_IsReported;
begin
  FOps.TerminateSucceeds := False;
  FOps.TerminateError := 5;
  Assert.AreEqual<TMHActionResultKind>(arkAccessDenied, FActions.TerminateProcess(Id, 'miner.exe').Kind);
  Assert.AreEqual(1, FOps.CloseCalls);
end;

procedure TSafeActionsTests.ProcessGone_IsNotFound;
begin
  FOps.OpenSucceeds := False;
  FOps.OpenError := 87;
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FActions.TerminateProcess(Id, 'miner.exe').Kind);
  FOps.OpenSucceeds := True;
  FOps.AlreadyExited := True;
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FActions.TerminateProcess(Id, 'miner.exe').Kind);
  Assert.AreEqual(0, FOps.TerminateCalls);
end;

procedure TSafeActionsTests.ProtectedImagePath_IsRefused;
begin
  FOps.ImagePath := 'C:\Windows\System32\lsass.exe';
  Assert.AreEqual<TMHActionResultKind>(arkProtected, FActions.TerminateProcess(Id, 'renamed.exe').Kind);
  Assert.AreEqual(0, FOps.TerminateCalls);
end;

procedure TSafeActionsTests.CriticalProcess_IsRefused;
begin
  FOps.Critical := True;
  Assert.AreEqual<TMHActionResultKind>(arkProtected, FActions.TerminateProcess(Id, 'miner.exe').Kind);
  Assert.AreEqual(0, FOps.TerminateCalls);
end;

procedure TSafeActionsTests.Success_TerminatesAndLogs;
var
  LResult: TMHActionResult;
begin
  LResult := FActions.TerminateProcess(Id, 'miner.exe');
  Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind);
  Assert.IsTrue(LResult.Succeeded);
  Assert.AreEqual(1, FOps.TerminateCalls);
  Assert.AreEqual(1, FOps.CloseCalls);
  Assert.AreEqual(1, Integer(Length(FLog.Records)));
  Assert.AreEqual('terminate', FLog.Records[0].Action);
  Assert.AreEqual('miner.exe (PID 4242)', FLog.Records[0].Target);
  Assert.IsTrue(FLog.Records[0].Success);
  Assert.IsTrue(FLog.Records[0].Result.Contains('Процесс остановлен'));
  Assert.AreEqual(FAKE_NOW, FLog.Records[0].TimestampUtc, 1e-9);
end;

procedure TSafeActionsTests.NotExitedInTime_IsFailed;
begin
  FOps.ExitsAfterTerminate := False;
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.TerminateProcess(Id, 'miner.exe').Kind);
  Assert.IsFalse(FLog.Records[0].Success);
end;

procedure TSafeActionsTests.ActionLogFailure_DoesNotRaise;
var
  LResult: TMHActionResult;
begin
  FLog.Fail := True;
  LResult := FActions.TerminateProcess(Id, 'miner.exe');
  Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind);
  Assert.IsTrue(LResult.Details.Contains('журнал'));
end;

procedure TSafeActionsTests.Defender_Unavailable;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := '';
  LResult := FActions.ScanWithDefender('C:\Data\file.exe', nil);
  Assert.AreEqual<TMHActionResultKind>(arkUnavailable, LResult.Kind);
  Assert.AreEqual('Microsoft Defender недоступен', LResult.Message);
  Assert.AreEqual(0, FOps.RunCalls);
  Assert.AreEqual('defender-scan', FLog.Records[0].Action);
  Assert.AreEqual('C:\Data\file.exe', FLog.Records[0].Target);
end;

procedure TSafeActionsTests.Defender_Clean_UsesReportOnlyArguments;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Program Files\Some App\file.exe'];
  FOps.DefenderPath := 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MpCmdRun.exe';
  FOps.RunExitCode := 0;
  LResult := FActions.ScanWithDefender('C:/Program Files/Some App/file.exe', nil);
  Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind);
  Assert.AreEqual('Угроз не обнаружено', LResult.Message);
  Assert.AreEqual(FOps.DefenderPath, FOps.LastRunExe);
  Assert.AreEqual('-Scan -ScanType 3 -File "C:\Program Files\Some App\file.exe" -DisableRemediation',
    FOps.LastRunArgs);
  Assert.AreEqual<Cardinal>(10 * 60 * 1000, FOps.LastRunTimeout);
  Assert.IsTrue(FLog.Records[0].Success);
end;

procedure TSafeActionsTests.Defender_Threat_ParsesNames;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  FOps.RunExitCode := 2;
  FOps.RunOutput := 'Scan starting...'#13#10'Scan finished.'#13#10 +
    'Scanning C:\Data\file.exe found 1 threats.'#13#10#13#10 +
    '<===========================LIST OF DETECTED THREATS==========================>'#13#10 +
    '----------------------------- Threat information ------------------------------'#13#10 +
    'Threat                  : Trojan:Win32/CoinMiner.Test'#13#10 +
    'Resources               : 1 total'#13#10 +
    '    file                : C:\Data\file.exe'#13#10;
  LResult := FActions.ScanWithDefender('C:\Data\file.exe', nil);
  Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind);
  Assert.AreEqual('Defender обнаружил угрозу: Trojan:Win32/CoinMiner.Test', LResult.Details);
end;

procedure TSafeActionsTests.Defender_Timeout_IsFailed;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  FOps.RunOutcome := roTimeout;
  LResult := FActions.ScanWithDefender('C:\Data\file.exe', nil);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('10 мин'));
  Assert.IsFalse(FLog.Records[0].Success);
end;

procedure TSafeActionsTests.Defender_Cancelled;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  FOps.RunOutcome := roCancelled;
  Assert.AreEqual<TMHActionResultKind>(arkCancelled, FActions.ScanWithDefender('C:\Data\file.exe', nil).Kind);
  Assert.AreEqual(1, Integer(Length(FLog.Records)));
end;

procedure TSafeActionsTests.Defender_CancelledBeforeStart_DoesNotRun;
var
  LCancel: TMHCancelFunc;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  LCancel :=
    function: Boolean
    begin
      Result := True;
    end;
  Assert.AreEqual<TMHActionResultKind>(arkCancelled, FActions.ScanWithDefender('C:\Data\file.exe', LCancel).Kind);
  Assert.AreEqual(0, FOps.RunCalls);
end;

procedure TSafeActionsTests.Defender_OtherExitCode_IsFailed;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  FOps.RunExitCode := Cardinal($80508023);
  FOps.RunOutput := 'line 1'#13#10'CmdTool: Failed with hr = 0x80508023.';
  LResult := FActions.ScanWithDefender('C:\Data\file.exe', nil);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, LResult.Kind);
  Assert.IsTrue(LResult.Message.Contains('0x80508023'), LResult.Message);
  Assert.IsTrue(LResult.Details.Contains('Failed with hr'));
end;

procedure TSafeActionsTests.Defender_ServiceNotRunning_IsUnavailable;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  FOps.RunExitCode := Cardinal($800106BA);
  Assert.AreEqual<TMHActionResultKind>(arkUnavailable, FActions.ScanWithDefender('C:\Data\file.exe', nil).Kind);
end;

procedure TSafeActionsTests.Defender_InvalidOrMissingPath_IsRefused;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  FOps.DefenderPath := 'C:\Defender\MpCmdRun.exe';
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.ScanWithDefender('C:\Data\file.exe" -Restore "x', nil).Kind);
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FActions.ScanWithDefender('C:\Data\missing.exe', nil).Kind);
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.ScanWithDefender('', nil).Kind);
  Assert.AreEqual(0, FOps.RunCalls);
  Assert.AreEqual(3, Integer(Length(FLog.Records)), 'каждая попытка журналируется');
end;

procedure TSafeActionsTests.OpenFileLocation_RefusesMissingFile;
var
  LResult: TMHActionResult;
begin
  LResult := FActions.OpenFileLocation('C:\Data\missing.exe');
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, LResult.Kind);
  Assert.AreEqual(0, FOps.ShellCalls);
end;

procedure TSafeActionsTests.OpenFileLocation_RefusesQuotesArgumentsAndUris;
var
  LPath: string;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe'];
  for LPath in TArray<string>.Create('C:\Data\file.exe" /root,"C:\Windows', '"C:\Data\file.exe"',
    'shell:startup', 'file:///C:/Data/file.exe', 'C:\Data\file.exe:hidden', 'Data\file.exe',
    '\Data\file.exe', 'C:\Data\*.exe', '\\server', '\\?\GLOBALROOT\Device\x') do
    Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.OpenFileLocation(LPath).Kind, LPath);
  // Аргументы после пути: такой «файл» не существует.
  Assert.AreEqual<TMHActionResultKind>(arkNotFound, FActions.OpenFileLocation('C:\Data\file.exe /c calc').Kind);
  Assert.AreEqual(0, FOps.ShellCalls);
end;

procedure TSafeActionsTests.OpenFileLocation_NormalizesAndOpens;
var
  LResult: TMHActionResult;
begin
  FOps.ExistingFiles := ['C:\Data\file.exe', '\\server\share\dir\a.txt'];
  LResult := FActions.OpenFileLocation('  C:/Data/sub/../file.exe ');
  Assert.AreEqual<TMHActionResultKind>(arkDone, LResult.Kind);
  Assert.AreEqual('C:\Data\file.exe', FOps.LastShellPath);
  Assert.AreEqual<TMHActionResultKind>(arkDone, FActions.OpenFileLocation('\\server\share\dir\a.txt').Kind);
  FOps.ShellSucceeds := False;
  Assert.AreEqual<TMHActionResultKind>(arkFailed, FActions.OpenFileLocation('C:\Data\file.exe').Kind);
end;

procedure TSafeActionsTests.DefenderPlatforms_SortedNewestFirst;
var
  LSorted: TArray<string>;
  LCompare: Integer;
begin
  LSorted := MHSortDefenderPlatforms(['4.18.2001.10', '4.18.24090.11-0', 'junk',
    '4.18.23110.3-0', '4.18.24090.11-1', '']);
  Assert.AreEqual(4, Integer(Length(LSorted)));
  Assert.AreEqual('4.18.24090.11-1', LSorted[0]);
  Assert.AreEqual('4.18.24090.11-0', LSorted[1]);
  Assert.AreEqual('4.18.23110.3-0', LSorted[2]);
  Assert.AreEqual('4.18.2001.10', LSorted[3]);
  Assert.IsTrue(MHTryCompareVersions('4.10', '4.9', LCompare));
  Assert.AreEqual(1, LCompare, 'числовое, а не строковое сравнение');
  Assert.IsFalse(MHTryCompareVersions('abc', '4.9', LCompare));
end;

procedure TSafeActionsTests.DefenderThreats_ParsedWithoutDuplicates;
var
  LThreats: TArray<string>;
begin
  LThreats := MHParseDefenderThreats('Threat : A'#10'threat: A'#13#10 +
    '---- Threat information ----'#13#10'Threat                  : B'#13#10'Resources : 1');
  Assert.AreEqual(2, Integer(Length(LThreats)));
  Assert.AreEqual('A', LThreats[0]);
  Assert.AreEqual('B', LThreats[1]);
  Assert.AreEqual(0, Integer(Length(MHParseDefenderThreats(''))));
end;

initialization
  TDUnitX.RegisterTestFixture(TSettingsTests);
  TDUnitX.RegisterTestFixture(TReportTests);
  TDUnitX.RegisterTestFixture(TSafeActionsTests);

end.
