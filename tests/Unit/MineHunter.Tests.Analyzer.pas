unit MineHunter.Tests.Analyzer;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Analysis.Engine, MineHunter.Tests.Scenarios;

type
  [TestFixture]
  [Category('Unit')]
  TIndicatorTests = class
  public
    [Test] procedure MinerNames;
    [Test] procedure MinerCommandTokens;
    [Test] procedure PoolPorts;
    [Test] procedure MonitoringTools;
    [Test] procedure Workloads;
    [Test] procedure SystemNamesAndLookalikes;
    [Test] procedure SuspiciousLocations;
    [Test] procedure ScriptsRandomFoldersObfuscation;
  end;

  [TestFixture]
  [Category('Unit')]
  TAnalyzerTests = class
  private
    function Run(const ASnapshots: TArray<TMHSnapshot>; AAnalyzer: TMHThreatAnalyzer = nil): TMHFindings;
  public
    [Test] procedure LightLoad_NoFinding;
    [Test] procedure ShortHistory_NoLoadEvidence_ButMissingDataNoted;
    [Test] procedure Deterministic_SameInputSameOutput;
    [Test] procedure FindingId_IsStableAndRfc4122;
    [Test] procedure EveryFinding_HasExplanationAndRuleset;
    [Test] procedure PoolPortAlone_IsNotEvidence;
    [Test] procedure SelfProcess_IsIgnored;
    [Test] procedure ExitedProcesses_AreForgotten;
    [Test] procedure Exclusion_HashMismatch_StillAnalyzed;
    [Test] procedure AccessDenied_LowersConfidence;
    [Test] procedure Baseline_TypicalLoad_IsNegativeFactor;
    [Test] procedure Baseline_AboveNormal_IsEvidence;
    [Test] procedure SystemOverload_PerformanceFinding;
    [Test] procedure ExplainLoad_NamesTopConsumersAndCategories;
    [Test] procedure Settings_ThresholdsAreApplied;
  end;

  [TestFixture]
  [Category('Regression')]
  TScenarioTests = class
  public
    [Test] procedure AllScenarios_MatchExpectations_AndWriteFalsePositiveReport;
    [Test] procedure StoredRegressionFixtures_MatchExpectations;
  end;

  [TestFixture]
  [Category('Performance')]
  TAnalyzerPerformanceTests = class
  public
    [Test] procedure ThousandsOfProcesses_AnalyzedQuickly;
    [Test] procedure LongRun_StateIsBounded;
    [Test] procedure FastPolling_HistoryIsCapped;
  end;

function ScenarioLevelText(ALevel: TMHRiskLevel): string;

implementation

uses
  System.SysUtils, System.Classes, System.IOUtils, System.Diagnostics, System.Generics.Collections,
  System.StrUtils, MineHunter.Analysis.Indicators, MineHunter.Core.Serialization, MineHunter.Core.Paths,
  MineHunter.Tests.Fakes;

function ScenarioLevelText(ALevel: TMHRiskLevel): string;
begin
  Result := MHRiskLevelToString(ALevel);
end;

function NewAnalyzer: TMHThreatAnalyzer;
begin
  Result := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
end;

function RunAll(AAnalyzer: TMHThreatAnalyzer; const ASnapshots: TArray<TMHSnapshot>;
  const ABaseline: TMHBaseline): TMHFindings;
var
  LSnapshot: TMHSnapshot;
begin
  Result := nil;
  for LSnapshot in ASnapshots do
    Result := AAnalyzer.Analyze(LSnapshot, ABaseline);
end;

function Codes(const AFinding: TMHFinding): string;
var
  LEvidence: TMHEvidence;
begin
  Result := '';
  for LEvidence in AFinding.Evidence do
  begin
    if Result <> '' then
      Result := Result + ', ';
    Result := Result + LEvidence.Code + '(' + IfThen(LEvidence.Weight > 0, '+', '') +
      IntToStr(LEvidence.Weight) + ')';
  end;
end;

{ TIndicatorTests }

procedure TIndicatorTests.MinerNames;
begin
  Assert.IsTrue(MHIsKnownMinerName('XMRig.exe'));
  Assert.IsTrue(MHIsKnownMinerName('C:\x\t-rex.exe'));
  Assert.IsFalse(MHIsKnownMinerName('chrome.exe'));
  Assert.IsFalse(MHIsKnownMinerName(''));
end;

procedure TIndicatorTests.MinerCommandTokens;
begin
  Assert.AreEqual('stratum+tcp://', MHFindMinerCommandToken('x.exe -o STRATUM+TCP://a:3333'));
  Assert.AreEqual('--donate-level', MHFindMinerCommandToken('a --donate-level 1'));
  Assert.AreEqual('', MHFindMinerCommandToken('notepad.exe readme.txt'));
end;

procedure TIndicatorTests.PoolPorts;
begin
  Assert.IsTrue(MHIsMiningPoolPort(3333));
  Assert.IsTrue(MHIsMiningPoolPort(14444));
  Assert.IsFalse(MHIsMiningPoolPort(443));
  Assert.IsFalse(MHIsMiningPoolPort(80));
end;

procedure TIndicatorTests.MonitoringTools;
begin
  Assert.IsTrue(MHIsMonitoringTool('Taskmgr.exe'));
  Assert.IsTrue(MHIsMonitoringTool('ProcessHacker.exe'));
  Assert.IsFalse(MHIsMonitoringTool('notepad.exe'));
end;

procedure TIndicatorTests.Workloads;
begin
  Assert.AreEqual<TMHWorkloadCategory>(wlBuild, MHWorkloadCategoryOf('MSBuild.exe', ''));
  Assert.AreEqual<TMHWorkloadCategory>(wlRender, MHWorkloadCategoryOf('blender.exe', ''));
  Assert.AreEqual<TMHWorkloadCategory>(wlUpdate, MHWorkloadCategoryOf('TiWorker.exe', ''));
  Assert.AreEqual<TMHWorkloadCategory>(wlSecurity, MHWorkloadCategoryOf('MsMpEng.exe', ''));
  Assert.AreEqual<TMHWorkloadCategory>(wlGame,
    MHWorkloadCategoryOf('x.exe', 'D:\SteamLibrary\steamapps\common\Game\x.exe'));
  Assert.AreEqual<TMHWorkloadCategory>(wlBrowser, MHWorkloadCategoryOf('msedge.exe', ''));
  Assert.AreEqual<TMHWorkloadCategory>(wlNone, MHWorkloadCategoryOf('unknown.exe', 'C:\a\unknown.exe'));
end;

procedure TIndicatorTests.SystemNamesAndLookalikes;
var
  LDirs: TArray<string>;
  LName: string;
begin
  Assert.IsTrue(MHIsSystemProcessName('SVCHOST.EXE', LDirs));
  Assert.AreEqual('\windows\system32\', LDirs[0]);
  Assert.IsFalse(MHIsSystemProcessName('chrome.exe', LDirs));
  Assert.IsTrue(MHLooksLikeSystemName('svch0st.exe', LName));
  Assert.AreEqual('svchost.exe', LName);
  Assert.IsTrue(MHLooksLikeSystemName('scvhost.exe', LName) or MHLooksLikeSystemName('csrsss.exe', LName));
  Assert.IsTrue(MHLooksLikeSystemName('csrsss.exe', LName), 'Лишний символ');
  Assert.IsFalse(MHLooksLikeSystemName('svchost.exe', LName), 'Точное совпадение — не двойник');
  Assert.IsFalse(MHLooksLikeSystemName('notepad.exe', LName));
end;

procedure TIndicatorTests.SuspiciousLocations;
var
  LReason: string;
begin
  Assert.IsTrue(MHIsSuspiciousLocation('C:\Users\u\AppData\Local\Temp\a.exe', LReason));
  Assert.IsTrue(MHIsSuspiciousLocation('C:\Users\u\Downloads\a.exe', LReason));
  Assert.IsTrue(MHIsSuspiciousLocation('C:\Users\Public\a.exe', LReason));
  Assert.IsTrue(MHIsSuspiciousLocation('C:\ProgramData\a.exe', LReason));
  Assert.IsFalse(MHIsSuspiciousLocation('C:\ProgramData\Microsoft\Windows Defender\Platform\1\MsMpEng.exe', LReason),
    'Папка производителя в ProgramData — обычное место');
  Assert.IsFalse(MHIsSuspiciousLocation('C:\Program Files\App\a.exe', LReason));
  Assert.IsFalse(MHIsSuspiciousLocation('', LReason));
  Assert.IsTrue(MHIsStandardInstallLocation('C:\Program Files (x86)\a\b.exe'));
  Assert.IsFalse(MHIsStandardInstallLocation('D:\Games\b.exe'));
end;

procedure TIndicatorTests.ScriptsRandomFoldersObfuscation;
var
  LFolder: string;
begin
  Assert.IsTrue(MHIsScriptFile('C:\a\b.BAT'));
  Assert.IsTrue(MHIsScriptFile('x.ps1'));
  Assert.IsFalse(MHIsScriptFile('x.exe'));
  Assert.IsTrue(MHFindRandomLookingFolder('C:\ProgramData\Microsoft\MapData\YfBZXN4ndJYr5fK\a.bat', LFolder));
  Assert.AreEqual('YfBZXN4ndJYr5fK', LFolder);
  Assert.IsFalse(MHFindRandomLookingFolder('C:\Program Files\Microsoft Office\root\Office16\a.exe', LFolder));
  Assert.IsFalse(MHFindRandomLookingFolder('C:\Users\u\AppData\Local\Package Cache\{0F8B6E5A-1234}\a.exe', LFolder));
  Assert.IsFalse(MHFindRandomLookingFolder('C:\Cache\0123456789abcdef0123\a.exe', LFolder),
    'Шестнадцатеричные имена (хеши) не считаются случайными');
  Assert.IsFalse(MHFindRandomLookingFolder('C:\Program Files\WindowsApps\a.exe', LFolder));
  Assert.AreEqual('закодированная команда PowerShell',
    MHFindObfuscatedCommand('powershell.exe -NoProfile -EncodedCommand SQBFAFgA'));
  Assert.AreEqual('', MHFindObfuscatedCommand('"C:\Program Files\App\app.exe" --minimized'));
  Assert.AreEqual('', MHFindObfuscatedCommand('powershell -WindowStyle Hidden -File a.ps1'),
    'Скрытое окно — не обфускация');
  Assert.AreEqual('скрытое окно и обход политики выполнения PowerShell',
    MHFindHiddenScriptLaunch('powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File E:\a.ps1'));
  Assert.AreEqual('', MHFindHiddenScriptLaunch('powershell.exe -File E:\a.ps1'));
end;

{ TAnalyzerTests }

function TAnalyzerTests.Run(const ASnapshots: TArray<TMHSnapshot>; AAnalyzer: TMHThreatAnalyzer): TMHFindings;
var
  LAnalyzer: TMHThreatAnalyzer;
begin
  if AAnalyzer = nil then
  begin
    LAnalyzer := NewAnalyzer;
    try
      Result := RunAll(LAnalyzer, ASnapshots, TMHBaseline.Empty);
    finally
      LAnalyzer.Free;
    end;
  end
  else
    Result := RunAll(AAnalyzer, ASnapshots, TMHBaseline.Empty);
end;

procedure TAnalyzerTests.LightLoad_NoFinding;
var
  LFindings: TMHFindings;
begin
  LFindings := Run(BuildSnapshots([Proc(10, 'app.exe', 'C:\Program Files\App\app.exe', sgUnsigned, '', [0, 2])],
    10, False, nil));
  Assert.AreEqual(0, Integer(Length(LFindings)));
end;

procedure TAnalyzerTests.ShortHistory_NoLoadEvidence_ButMissingDataNoted;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  // 3 минуты истории при пороге длительности 10 минут.
  LFindings := Run(BuildSnapshots([Proc(10, 'svchost.exe', 'C:\Users\Public\svchost.exe', sgUnsigned, '', [0, 60])],
    10, False, nil, 3));
  Assert.IsTrue(MaxLevelFor(LFindings, 'svchost.exe', LFinding) >= rlSuspicious, 'Маскировка видна сразу');
  Assert.IsFalse(Codes(LFinding).Contains(EV_LOAD_SUSTAINED), 'Длительность ещё не подтверждена');
  Assert.IsTrue(string.Join(';', LFinding.MissingData).Contains('История нагрузки короче'));
  Assert.IsTrue(LFinding.Confidence < 1);
end;

procedure TAnalyzerTests.Deterministic_SameInputSameOutput;
var
  LScenario: TScenario;
  A, B: TMHFindings;
  I: Integer;
begin
  for LScenario in BuildScenarios do
  begin
    A := Run(LScenario.Snapshots);
    B := Run(LScenario.Snapshots);
    Assert.AreEqual(Integer(Length(A)), Integer(Length(B)), LScenario.Name);
    for I := 0 to High(A) do
      Assert.AreEqual(TMHJson.FindingToString(A[I]), TMHJson.FindingToString(B[I]), LScenario.Name);
  end;
end;

procedure TAnalyzerTests.FindingId_IsStableAndRfc4122;
var
  LId: TGUID;
begin
  LId := MHFindingIdFromKey('process:x');
  Assert.AreEqual(LId, MHFindingIdFromKey('process:x'));
  Assert.AreNotEqual(LId, MHFindingIdFromKey('process:y'));
  Assert.AreEqual(3, Integer(LId.D3 shr 12), 'Версия 3');
  Assert.AreEqual($80, Integer(LId.D4[0] and $C0), 'Вариант RFC 4122');
end;

procedure TAnalyzerTests.EveryFinding_HasExplanationAndRuleset;
var
  LScenario: TScenario;
  LFinding: TMHFinding;
begin
  for LScenario in BuildScenarios do
    for LFinding in Run(LScenario.Snapshots) do
    begin
      Assert.IsTrue(Length(LFinding.PositiveEvidence) > 0, 'Без признаков находки не бывает: ' + LFinding.Title);
      Assert.IsNotEmpty(LFinding.Title);
      Assert.IsNotEmpty(LFinding.Summary);
      Assert.IsNotEmpty(LFinding.Key);
      Assert.IsTrue(Length(LFinding.Recommendations) > 0);
      Assert.AreEqual(MH_RULESET_VERSION, Copy(LFinding.RulesetVersion, 1, Length(MH_RULESET_VERSION)));
      Assert.IsTrue((LFinding.Score >= 0) and (LFinding.Score <= 100));
      Assert.IsTrue((LFinding.Confidence > 0) and (LFinding.Confidence <= 1));
      Assert.IsTrue(LFinding.Summary.Contains('не диагноз'), 'Формулировка без категоричного диагноза');
    end;
end;

procedure TAnalyzerTests.PoolPortAlone_IsNotEvidence;
var
  P: TScenarioProcess;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  // Обычная программа без нагрузки с соединением на порт 3333 — выводов не делаем.
  P := Proc(10, 'client.exe', 'C:\Program Files\Vendor\client.exe', sgSignedTrusted, 'Vendor', [0, 1]);
  P.RemotePort := 3333;
  LFindings := Run(BuildSnapshots([P], 10, False, nil));
  Assert.AreEqual<TMHRiskLevel>(rlNone, MaxLevelFor(LFindings, 'client.exe', LFinding));
end;

procedure TAnalyzerTests.SelfProcess_IsIgnored;
var
  LAnalyzer: TMHThreatAnalyzer;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 10);
  try
    LFindings := RunAll(LAnalyzer, BuildSnapshots([Proc(10, 'xmrig.exe', 'C:\Users\Public\xmrig.exe',
      sgUnsigned, '', [0, 90])], 900, False, nil), TMHBaseline.Empty);
    Assert.AreEqual<TMHRiskLevel>(rlNone, MaxLevelFor(LFindings, 'xmrig.exe', LFinding),
      'Собственный процесс не анализируется (системная находка о нагрузке допустима)');
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerTests.ExitedProcesses_AreForgotten;
var
  LAnalyzer: TMHThreatAnalyzer;
  LSnapshots: TArray<TMHSnapshot>;
  LEmpty: TMHSnapshot;
begin
  LAnalyzer := NewAnalyzer;
  try
    LSnapshots := BuildSnapshots([Proc(10, 'a.exe', 'C:\a.exe', sgUnsigned, '', [0, 5]),
      Proc(11, 'b.exe', 'C:\b.exe', sgUnsigned, '', [0, 5])], 10, False, nil, 1);
    RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty);
    Assert.AreEqual(2, LAnalyzer.TrackedCount);
    LEmpty := TMHSnapshot.Create(1000, SCENARIO_START + 1);
    LAnalyzer.Analyze(LEmpty, TMHBaseline.Empty);
    Assert.AreEqual(0, LAnalyzer.TrackedCount);
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerTests.Exclusion_HashMismatch_StillAnalyzed;
var
  LAnalyzer: TMHThreatAnalyzer;
  LExclusion: TMHExclusion;
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
  P: TScenarioProcess;
begin
  P := Proc(10, 'xmrig.exe', 'C:\Users\Public\xmrig.exe', sgUnsigned, '', [0, 90]);
  LSnapshots := BuildSnapshots([P], 900, False, nil);
  LAnalyzer := NewAnalyzer;
  try
    LExclusion := Default(TMHExclusion);
    LExclusion.Key := MHProgramKey(MHNormalizePath(P.Path), P.Name);
    LExclusion.Sha256 := 'ffff'; // исключён другой файл с тем же путём
    LAnalyzer.Exclusions := [LExclusion];
    Assert.IsTrue(MaxLevelFor(RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty), 'xmrig.exe', LFinding) >= rlSuspicious,
      'Подмена файла по разрешённому пути не должна скрывать находку');
    LExclusion.Sha256 := '';
    LAnalyzer.Exclusions := [LExclusion];
    Assert.AreEqual<TMHRiskLevel>(rlNone, MaxLevelFor(RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty),
      'xmrig.exe', LFinding));
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerTests.AccessDenied_LowersConfidence;
var
  LSnapshots: TArray<TMHSnapshot>;
  I, J: Integer;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LSnapshots := BuildSnapshots([Proc(10, 'xmrig.exe', '', sgNotChecked, '', [0, 90])], 900, False, nil);
  for I := 0 to High(LSnapshots) do
    for J := 0 to High(LSnapshots[I].Processes) do
      LSnapshots[I].Processes[J].Access := alDenied;
  LFindings := Run(LSnapshots);
  Assert.IsTrue(MaxLevelFor(LFindings, 'xmrig.exe', LFinding) >= rlNeedsReview);
  Assert.IsTrue(LFinding.Confidence <= 0.7);
  Assert.IsTrue(string.Join(';', LFinding.MissingData).Contains('Путь к файлу недоступен'));
end;

function BaselineFor(const AKey: string; AP95: Double): TMHBaseline;
var
  LValues: TArray<Double>;
  I: Integer;
begin
  Result := TMHBaseline.Empty;
  Result.Context := wcIdle;
  Result.SampleCount := 100000;
  SetLength(LValues, 100);
  for I := 0 to 99 do
    LValues[I] := AP95;
  Result.SystemCpu := TMHStat.FromValues(LValues);
  SetLength(Result.Processes, 1);
  Result.Processes[0].Key := AKey;
  Result.Processes[0].Cpu := TMHStat.FromValues(LValues);
  Result.Processes[0].PresenceRatio := 1;
end;

procedure TAnalyzerTests.Baseline_TypicalLoad_IsNegativeFactor;
var
  LAnalyzer: TMHThreatAnalyzer;
  P: TScenarioProcess;
  LFinding: TMHFinding;
  LKey: string;
begin
  P := Proc(10, 'boinc.exe', 'C:\Program Files\BOINC\boinc.exe', sgSignedTrusted, 'BOINC', [0, 40]);
  LKey := MHProgramKey(MHNormalizePath(P.Path), P.Name);
  LAnalyzer := NewAnalyzer;
  try
    MaxLevelFor(RunAll(LAnalyzer, BuildSnapshots([P], 900, False, nil), BaselineFor(LKey, 45)), 'boinc.exe', LFinding);
    Assert.IsTrue((LFinding.Key = '') or not Codes(LFinding).Contains(EV_ABOVE_BASELINE));
    Assert.IsTrue(LFinding.Level <= rlLow, 'Обычная для компьютера нагрузка');
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerTests.Baseline_AboveNormal_IsEvidence;
var
  LAnalyzer: TMHThreatAnalyzer;
  P: TScenarioProcess;
  LFinding: TMHFinding;
begin
  P := Proc(10, 'tool.exe', 'C:\Users\user\AppData\Local\Programs\tool\tool.exe', sgUnsigned, '', [0, 60]);
  LAnalyzer := NewAnalyzer;
  try
    MaxLevelFor(RunAll(LAnalyzer, BuildSnapshots([P], 900, False, nil),
      BaselineFor(MHProgramKey(MHNormalizePath(P.Path), P.Name), 5)), 'tool.exe', LFinding);
    Assert.IsTrue(Codes(LFinding).Contains(EV_ABOVE_BASELINE), Codes(LFinding));
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerTests.SystemOverload_PerformanceFinding;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  LFound: Boolean;
begin
  LFindings := Run(BuildSnapshots([Proc(10, 'blender.exe', 'C:\Program Files\Blender\blender.exe',
    sgSignedTrusted, 'Blender Foundation', [0, 95])], 10, False, nil));
  LFound := False;
  for LFinding in LFindings do
    if LFinding.Key = 'system:cpu' then
    begin
      LFound := True;
      Assert.AreEqual<TMHFindingCategory>(fcPerformance, LFinding.Category);
      Assert.IsTrue(LFinding.Summary.Contains('blender.exe'), LFinding.Summary);
      Assert.IsTrue(LFinding.Summary.Contains('рендеринг'), 'Указан вероятный характер нагрузки');
      Assert.IsTrue(LFinding.Level <= rlNeedsReview, 'Причина замедления, а не угроза');
    end;
  Assert.IsTrue(LFound, 'Перегрузка процессора объясняется находкой производительности');
end;

procedure TAnalyzerTests.ExplainLoad_NamesTopConsumersAndCategories;
var
  LSnapshots: TArray<TMHSnapshot>;
  LReasons: TArray<TMHLoadReason>;
begin
  LSnapshots := BuildSnapshots([
    Proc(10, 'MSBuild.exe', 'C:\Program Files\Microsoft Visual Studio\MSBuild.exe', sgSignedTrusted, 'Microsoft', [0, 40]),
    Proc(11, 'chrome.exe', 'C:\Program Files\Google\Chrome\Application\chrome.exe', sgSignedTrusted, 'Google', [0, 10])],
    10, False, nil, 1);
  LReasons := MHExplainLoad(LSnapshots[High(LSnapshots)], 8);
  Assert.AreEqual(4, Integer(Length(LReasons)), 'cpu, memory, disk, gpu');
  Assert.AreEqual('cpu', LReasons[0].Resource);
  Assert.IsTrue(LReasons[0].Text.Contains('MSBuild.exe 40%'), LReasons[0].Text);
  Assert.IsTrue(LReasons[0].Text.Contains('компиляция'));
  Assert.IsTrue(LReasons[0].Text.IndexOf('MSBuild') < LReasons[0].Text.IndexOf('chrome'));
end;

procedure TAnalyzerTests.Settings_ThresholdsAreApplied;
var
  LAnalyzer: TMHThreatAnalyzer;
  LSettings: TMHAnalyzerSettings;
  LFinding: TMHFinding;
  LSnapshots: TArray<TMHSnapshot>;
begin
  // 10% машины на 8 ядрах = 0,8 ядра: по умолчанию (80% ядра) это высокая нагрузка.
  LSnapshots := BuildSnapshots([Proc(10, 'job.exe', 'D:\Jobs\job.exe', sgUnsigned, '', [0, 10])],
    900, False, nil);
  LAnalyzer := NewAnalyzer;
  try
    Assert.IsTrue(MaxLevelFor(RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty), 'job.exe', LFinding) >= rlNeedsReview,
      'По умолчанию фоновая нагрузка в 0,8 ядра без подписи требует проверки');
  finally
    LAnalyzer.Free;
  end;
  LAnalyzer := NewAnalyzer;
  try
    LSettings := TMHAnalyzerSettings.Default;
    LSettings.HighCpuPercent := 50;
    LSettings.HighCoreCpuPercent := 100;
    LAnalyzer.Settings := LSettings;
    Assert.AreEqual<TMHRiskLevel>(rlNone,
      MaxLevelFor(RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty), 'job.exe', LFinding),
      'С порогами 50% машины и 100% ядра та же нагрузка не считается высокой');
    Assert.AreEqual(50.0, LAnalyzer.Settings.HighCpuPercent, 0.001);
  finally
    LAnalyzer.Free;
  end;
end;

{ TScenarioTests }

function CheckScenario(const AScenario: TScenario; out ALevel: TMHRiskLevel;
  out AFinding: TMHFinding): Boolean;
var
  LAnalyzer: TMHThreatAnalyzer;
  LFindings: TMHFindings;
begin
  LAnalyzer := NewAnalyzer;
  try
    LAnalyzer.Exclusions := AScenario.Exclusions;
    LFindings := RunAll(LAnalyzer, AScenario.Snapshots, TMHBaseline.Empty);
  finally
    LAnalyzer.Free;
  end;
  ALevel := MaxLevelFor(LFindings, AScenario.Target, AFinding);
  Result := (ALevel >= AScenario.MinLevel) and (ALevel <= AScenario.MaxLevel);
  if Result and AScenario.ExpectCategory then
    Result := AFinding.Category = AScenario.Category;
end;

procedure TScenarioTests.AllScenarios_MatchExpectations_AndWriteFalsePositiveReport;
var
  LScenario: TScenario;
  LLevel: TMHRiskLevel;
  LFinding: TMHFinding;
  LReport: TStringList;
  LFailures, LMalicious, LDetected, LLegit, LFalsePositives: Integer;
  LOk: Boolean;
  LDir: string;
begin
  LReport := TStringList.Create;
  try
    LReport.Add('# Отчёт о ложных срабатываниях MineHunter X');
    LReport.Add('');
    LReport.Add('Версия правил: ' + MH_RULESET_VERSION + '. Сценарии синтетические (без вредоносного кода), ' +
      Format('%d логических CPU, шаг %d с, длительность %d мин.', [SCENARIO_CPU_COUNT, SCENARIO_STEP_SECONDS,
      SCENARIO_MINUTES]));
    LReport.Add('Ложным срабатыванием считается уровень «требует проверки» и выше для легальной нагрузки.');
    LReport.Add('');
    LReport.Add('| Сценарий | Тип | Ожидание | Результат | Балл | Признаки | Итог |');
    LReport.Add('|---|---|---|---|---|---|---|');
    LFailures := 0;
    LMalicious := 0;
    LDetected := 0;
    LLegit := 0;
    LFalsePositives := 0;
    for LScenario in BuildScenarios do
    begin
      LOk := CheckScenario(LScenario, LLevel, LFinding);
      if not LOk then
        Inc(LFailures);
      if LScenario.Malicious then
      begin
        Inc(LMalicious);
        if LLevel >= rlNeedsReview then
          Inc(LDetected);
      end
      else
      begin
        Inc(LLegit);
        if LLevel >= rlNeedsReview then
          Inc(LFalsePositives);
      end;
      LReport.Add(Format('| %s — %s | %s | %s…%s | %s | %d | %s | %s |',
        [LScenario.Name, LScenario.Description, IfThen(LScenario.Malicious, 'имитация угрозы', 'легальная'),
         ScenarioLevelText(LScenario.MinLevel), ScenarioLevelText(LScenario.MaxLevel),
         ScenarioLevelText(LLevel), LFinding.Score, Codes(LFinding), IfThen(LOk, 'ОК', 'ОШИБКА')]));
    end;
    LReport.Add('');
    LReport.Add(Format('Обнаружено имитаций угроз: %d из %d. Ложных срабатываний: %d из %d легальных сценариев.',
      [LDetected, LMalicious, LFalsePositives, LLegit]));
    LDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'reports');
    ForceDirectories(LDir);
    LReport.SaveToFile(TPath.Combine(LDir, 'false-positive-report.md'), TEncoding.UTF8);
    Assert.AreEqual(0, LFailures, LReport.Text);
    Assert.AreEqual(LMalicious, LDetected);
    Assert.AreEqual(0, LFalsePositives);
  finally
    LReport.Free;
  end;
end;

function FindRegressionDir: string;
var
  LDir: string;
  I: Integer;
begin
  LDir := ExtractFilePath(ParamStr(0));
  for I := 1 to 6 do
  begin
    Result := TPath.Combine(LDir, 'tests\Fixtures\regression');
    if TDirectory.Exists(Result) then
      Exit;
    LDir := ExtractFilePath(ExcludeTrailingPathDelimiter(LDir));
  end;
  Result := '';
end;

procedure TScenarioTests.StoredRegressionFixtures_MatchExpectations;
var
  LDir, LFile, LText: string;
  LLines: TArray<string>;
  LScenario: TScenario;
  LExpected: TDictionary<string, TScenario>;
  LLevel: TMHRiskLevel;
  LFinding: TMHFinding;
  LSnapshots: TList<TMHSnapshot>;
  LLine: string;
  LChecked: Integer;
begin
  LDir := FindRegressionDir;
  Assert.IsNotEmpty(LDir, 'Каталог tests\Fixtures\regression не найден');
  LExpected := TDictionary<string, TScenario>.Create;
  LSnapshots := TList<TMHSnapshot>.Create;
  try
    for LScenario in BuildScenarios do
      LExpected.Add(LScenario.Name, LScenario);
    LChecked := 0;
    for LFile in TDirectory.GetFiles(LDir, '*.jsonl') do
    begin
      LText := TFile.ReadAllText(LFile, TEncoding.UTF8);
      LLines := LText.Split([#10], TStringSplitOptions.ExcludeEmpty);
      Assert.IsTrue(LExpected.TryGetValue(TPath.GetFileNameWithoutExtension(LFile), LScenario),
        'Неизвестный сценарий: ' + LFile);
      LSnapshots.Clear;
      for LLine in LLines do
        if Trim(LLine) <> '' then
          LSnapshots.Add(TMHJson.SnapshotFromString(Trim(LLine)));
      // Сохранённые (обезличенные) данные, а не построенные кодом, проверяются теми же ожиданиями.
      LScenario.Snapshots := LSnapshots.ToArray;
      Assert.IsTrue(CheckScenario(LScenario, LLevel, LFinding),
        Format('%s: получено «%s», признаки %s', [LScenario.Name, ScenarioLevelText(LLevel), Codes(LFinding)]));
      Inc(LChecked);
    end;
    Assert.AreEqual(Integer(LExpected.Count), LChecked, 'Для каждого сценария должна быть сохранённая фикстура');
  finally
    LSnapshots.Free;
    LExpected.Free;
  end;
end;

{ TAnalyzerPerformanceTests }

procedure TAnalyzerPerformanceTests.ThousandsOfProcesses_AnalyzedQuickly;
const
  COUNT = 1500;
  LIMIT_MS = 150;
var
  LProcesses: TArray<TScenarioProcess>;
  LSnapshots: TArray<TMHSnapshot>;
  LAnalyzer: TMHThreatAnalyzer;
  LWatch: TStopwatch;
  I: Integer;
  LWorst: Int64;
begin
  SetLength(LProcesses, COUNT);
  for I := 0 to COUNT - 1 do
    LProcesses[I] := Proc(100 + I, Format('p%d.exe', [I]), Format('C:\Program Files\V%d\p%d.exe', [I mod 50, I]),
      sgSignedTrusted, 'Vendor', [0, (I mod 7) * 0.5]);
  LSnapshots := BuildSnapshots(LProcesses, 10, False, nil, 2);
  LAnalyzer := NewAnalyzer;
  try
    LWorst := 0;
    for I := 0 to High(LSnapshots) do
    begin
      LWatch := TStopwatch.StartNew;
      LAnalyzer.Analyze(LSnapshots[I], TMHBaseline.Empty);
      if LWatch.ElapsedMilliseconds > LWorst then
        LWorst := LWatch.ElapsedMilliseconds;
    end;
    Assert.IsTrue(LWorst < LIMIT_MS, Format('Анализ %d процессов занял до %d мс', [COUNT, LWorst]));
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerPerformanceTests.LongRun_StateIsBounded;
var
  LAnalyzer: TMHThreatAnalyzer;
  LSnapshots: TArray<TMHSnapshot>;
  LBefore, LAfter: Int64;
  I, J: Integer;
begin
  // 3 часа работы с шагом 10 с: история не должна расти бесконечно.
  LSnapshots := BuildSnapshots([Proc(10, 'a.exe', 'C:\a.exe', sgUnsigned, '', [0, 5])], 10, False, nil, 60);
  LAnalyzer := NewAnalyzer;
  try
    RunAll(LAnalyzer, LSnapshots, TMHBaseline.Empty);
    LBefore := MHTestAllocatedBytes;
    for J := 1 to 2 do
      for I := 0 to High(LSnapshots) do
      begin
        LSnapshots[I].TimestampUtc := LSnapshots[I].TimestampUtc + 1 / 24;
        LAnalyzer.Analyze(LSnapshots[I], TMHBaseline.Empty);
      end;
    LAfter := MHTestAllocatedBytes;
    Assert.IsTrue(LAfter - LBefore < 256 * 1024, Format('Рост памяти %d байт', [LAfter - LBefore]));
    Assert.AreEqual(1, LAnalyzer.TrackedCount);
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAnalyzerPerformanceTests.FastPolling_HistoryIsCapped;
const
  PROCESSES = 50;
var
  LAnalyzer: TMHThreatAnalyzer;
  LProcesses: TArray<TScenarioProcess>;
  LSnapshots: TArray<TMHSnapshot>;
  I: Integer;
  LLimit: Integer;
begin
  // Регрессия soak-теста: при опросе каждые 250 мс окно истории за 30 минут
  // разрасталось в 8 раз. Теперь хранится не больше одной точки за ~2 с.
  SetLength(LProcesses, PROCESSES);
  for I := 0 to PROCESSES - 1 do
    LProcesses[I] := Proc(100 + I, Format('p%d.exe', [I]), Format('C:\Program Files\V\p%d.exe', [I]),
      sgSignedTrusted, 'Vendor', [0, 1]);
  LSnapshots := BuildSnapshots(LProcesses, 10, False, nil, 40, 1);
  LAnalyzer := NewAnalyzer;
  try
    for I := 0 to High(LSnapshots) do
      LAnalyzer.Analyze(LSnapshots[I], TMHBaseline.Empty);
    // Окно хранения — 30 мин; не больше одной точки за 2 с.
    LLimit := PROCESSES * (30 * 60 div 2 + 2);
    Assert.IsTrue(LAnalyzer.TotalSamples <= LLimit,
      Format('Точек истории: %d (предел %d)', [LAnalyzer.TotalSamples, LLimit]));
    Assert.IsTrue(LAnalyzer.TotalSamples >= PROCESSES * 30 * 60 div 3, 'История не должна теряться');
  finally
    LAnalyzer.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TIndicatorTests);
  TDUnitX.RegisterTestFixture(TAnalyzerTests);
  TDUnitX.RegisterTestFixture(TScenarioTests);
  TDUnitX.RegisterTestFixture(TAnalyzerPerformanceTests);

end.
