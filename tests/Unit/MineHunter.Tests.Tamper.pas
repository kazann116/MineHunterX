unit MineHunter.Tests.Tamper;

{
  Признаки вмешательства в защиту: коллектор (разбор hosts, кэш, частичные
  отказы, права администратора) и правила оценки с оправдывающими случаями.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Tamper;

type
  TFakeTamperApi = class(TInterfacedObject, IMHTamperApi)
  public
    Wmi, Defender, Hijacks, Policies: TArray<TMHTamperEntry>;
    HostsText, HostsPath, HostsDefaultPath: string;
    WmiError, DefenderError: string;
    WmiFails, DefenderFails, HijacksRaise, AllFail, Managed: Boolean;
    Reads: Integer;
    constructor Create;
    function ReadWmiSubscriptions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadDefenderExclusions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadExecutionHijacks(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadHostsFile(out AText, APath, ADefaultPath: string; out AError: string): Boolean;
    function ReadPolicies(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function IsManagedComputer: Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TTamperCollectorTests = class
  private
    FApi: TFakeTamperApi;
    FApiIntf: IMHTamperApi;
    FClock: TObject;
    FClockIntf: IMHClock;
    FCollector: IMHCollector;
    function Collect: TMHCollectionResult;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Hosts_OnlySecurityDomains;
    [Test] procedure Hosts_CommentsAndSeveralHostsPerLine;
    [Test] procedure Hosts_RelocatedDatabasePath_IsEntry;
    [Test] procedure Collect_MergesAllSources;
    [Test] procedure NoAdmin_IsPartialWithElevationHint;
    [Test] procedure SourceException_IsIsolated;
    [Test] procedure AllSourcesFail_IsErrorAndNotCached;
    [Test] procedure Cache_RefreshesAfterInterval;
    [Test] procedure NilArguments_Raise;
  end;

  [TestFixture]
  [Category('Unit')]
  TTamperRulesTests = class
  private
    function Analyze(const AEntries: TArray<TMHTamperEntry>; const AFiles: TArray<TMHFileInfo> = nil): TMHFindings;
    function Single(const AEntry: TMHTamperEntry; const AFiles: TArray<TMHFileInfo> = nil): TMHFinding;
  public
    [Test] procedure Wmi_CommandConsumer_IsPersistence;
    [Test] procedure Wmi_ObfuscatedMinerCommand_IsMiningHigh;
    [Test] procedure Wmi_SignedVendorAndUnbound_AreLowered;
    [Test] procedure Defender_BroadPath_IsSuspicious;
    [Test] procedure Defender_SuspiciousFolderAndMinerProcess;
    [Test] procedure Defender_ExecutableExtension_VsOther;
    [Test] procedure Defender_DeveloperFolder_IsLow;
    [Test] procedure Defender_Policy_IsLowered;
    [Test] procedure Defender_GroupedByFolder_WithMinerArtifacts;
    [Test] procedure Ifeo_SameCommand_OneFinding;
    [Test] procedure DefenderPolicies_OneFinding;
    [Test] procedure Ifeo_ProcessExplorerReplacement_NoFinding;
    [Test] procedure Ifeo_StickyKeysBackdoor_IsHigh;
    [Test] procedure Ifeo_TaskManagerHijackedByUnknown_IsHigh;
    [Test] procedure Ifeo_DeveloperDebugger_IsLow;
    [Test] procedure SilentExit_IsPersistence;
    [Test] procedure Hosts_AvDomains_OneFindingHigh;
    [Test] procedure Hosts_UpdatesOnly_IsWeaker;
    [Test] procedure Hosts_Relocated_IsSuspicious;
    [Test] procedure Policies_Each;
    [Test] procedure UserExclusion_SuppressesFinding;
    [Test] procedure Findings_HaveExplanationAndStableKeys;
    [Test] procedure EvidenceFor_ExcludedPathAndProcessName;
    [Test] procedure EvidenceFor_LaunchedByWmi;
    [Test] procedure Analyzer_LoadedProcessInExcludedFolder_GetsEvidence;
    [Test] procedure Analyzer_IdleProcessInExcludedFolder_NoFinding;
  end;

implementation

uses
  System.SysUtils, System.StrUtils,
  MineHunter.Analysis.Tamper, MineHunter.Analysis.Engine, MineHunter.Core.Paths,
  MineHunter.Tests.Fakes, MineHunter.Tests.Scenarios;

function Entry(AKind: TMHTamperKind; const AName, AValue: string; const ADetails: string = '';
  const AImagePath: string = ''): TMHTamperEntry;
begin
  Result := TMHTamperEntry.Create(AKind, AName, AValue, 'test-location');
  Result.Details := ADetails;
  Result.ImagePath := AImagePath;
end;

function HasCode(const AFinding: TMHFinding; const ACode: string): Boolean;
var
  LEvidence: TMHEvidence;
begin
  for LEvidence in AFinding.Evidence do
    if LEvidence.Code = ACode then
      Exit(True);
  Result := False;
end;

function SignedFile(const APath, ASigner: string): TMHFileInfo;
begin
  Result := TMHFileInfo.Create(MHNormalizePath(APath));
  Result.Signature := sgSignedTrusted;
  Result.Signer := ASigner;
  Result.Sha256 := StringOfChar('a', 64);
end;

function UnsignedFile(const APath: string): TMHFileInfo;
begin
  Result := TMHFileInfo.Create(MHNormalizePath(APath));
  Result.Signature := sgUnsigned;
  Result.Sha256 := StringOfChar('b', 64);
end;

{ TFakeTamperApi }

constructor TFakeTamperApi.Create;
begin
  inherited Create;
  HostsPath := 'C:\Windows\System32\drivers\etc\hosts';
  HostsDefaultPath := HostsPath;
end;

function TFakeTamperApi.ReadWmiSubscriptions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
begin
  Inc(Reads);
  AEntries := Wmi;
  AError := WmiError;
  Result := not (WmiFails or AllFail);
end;

function TFakeTamperApi.ReadDefenderExclusions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
begin
  AEntries := Defender;
  AError := DefenderError;
  Result := not (DefenderFails or AllFail);
end;

function TFakeTamperApi.ReadExecutionHijacks(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
begin
  if HijacksRaise then
    raise EMHError.Create('simulated registry exception');
  AEntries := Hijacks;
  AError := '';
  Result := not AllFail;
end;

function TFakeTamperApi.ReadHostsFile(out AText, APath, ADefaultPath: string; out AError: string): Boolean;
begin
  AText := HostsText;
  APath := HostsPath;
  ADefaultPath := HostsDefaultPath;
  AError := IfThen(AllFail, 'simulated', '');
  Result := not AllFail;
end;

function TFakeTamperApi.IsManagedComputer: Boolean;
begin
  Result := Managed;
end;

function TFakeTamperApi.ReadPolicies(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
begin
  AEntries := Policies;
  AError := IfThen(AllFail, 'simulated', '');
  Result := not AllFail;
end;

{ TTamperCollectorTests }

procedure TTamperCollectorTests.Setup;
var
  LClock: TFakeClock;
begin
  FApi := TFakeTamperApi.Create;
  FApiIntf := FApi;
  LClock := TFakeClock.Create(FAKE_NOW);
  FClock := LClock;
  FClockIntf := LClock;
  FCollector := TMHTamperCollector.Create(FApiIntf, FClockIntf, 120);
end;

procedure TTamperCollectorTests.TearDown;
begin
  FCollector := nil;
  FClockIntf := nil;
  FApiIntf := nil;
end;

function TTamperCollectorTests.Collect: TMHCollectionResult;
begin
  Result := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
end;

procedure TTamperCollectorTests.Hosts_OnlySecurityDomains;
var
  LEntries: TArray<TMHTamperEntry>;
begin
  LEntries := MHParseHostsRedirects(
    '127.0.0.1 localhost'#13#10 +
    '0.0.0.0 ads.example.com'#13#10 +
    '0.0.0.0 www.kaspersky.ru'#13#10 +
    '127.0.0.1 update.microsoft.com'#13#10 +
    '10.0.0.5 notkaspersky.ru.example', 'hosts');
  Assert.AreEqual(2, Integer(Length(LEntries)), 'Реклама и свои сайты не считаются');
  Assert.AreEqual('www.kaspersky.ru', LEntries[0].Name);
  Assert.AreEqual('0.0.0.0', LEntries[0].Value);
  Assert.AreEqual<TMHTamperKind>(tpHostsRedirect, LEntries[0].Kind);
end;

procedure TTamperCollectorTests.Hosts_CommentsAndSeveralHostsPerLine;
var
  LEntries: TArray<TMHTamperEntry>;
begin
  LEntries := MHParseHostsRedirects(
    '# 0.0.0.0 drweb.com — закомментировано'#10 +
    '0.0.0.0'#9'eset.com malwarebytes.com # блок'#10 +
    '   '#10, 'hosts');
  Assert.AreEqual(2, Integer(Length(LEntries)));
  Assert.AreEqual('eset.com', LEntries[0].Name);
  Assert.AreEqual('malwarebytes.com', LEntries[1].Name);
end;

procedure TTamperCollectorTests.Hosts_RelocatedDatabasePath_IsEntry;
var
  LResult: TMHCollectionResult;
  LEntry: TMHTamperEntry;
  LFound: Boolean;
begin
  FApi.HostsPath := 'C:\ProgramData\x\hosts';
  LResult := Collect;
  LFound := False;
  for LEntry in LResult.Tamper do
    if LEntry.Name = 'DataBasePath' then
      LFound := True;
  Assert.IsTrue(LFound);
end;

procedure TTamperCollectorTests.Collect_MergesAllSources;
var
  LResult: TMHCollectionResult;
begin
  FApi.Wmi := [Entry(tpWmiSubscription, 'w', 'cmd')];
  FApi.Defender := [Entry(tpDefenderExclusion, 'C:\x', 'C:\x', 'путь')];
  FApi.Hijacks := [Entry(tpIfeoDebugger, 'sethc.exe', 'cmd.exe')];
  FApi.Policies := [Entry(tpPolicyRestriction, 'DisableTaskMgr', '1')];
  FApi.HostsText := '0.0.0.0 avast.com';
  LResult := Collect;
  Assert.AreEqual(5, Integer(Length(LResult.Tamper)));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(TMHTamperCollector.SourceIdValue, LResult.Status.SourceId);
end;

procedure TTamperCollectorTests.NoAdmin_IsPartialWithElevationHint;
var
  LResult: TMHCollectionResult;
begin
  FApi.WmiFails := True;
  FApi.WmiError := 'видны только с правами администратора';
  FApi.DefenderError := 'видны только с правами администратора';
  FApi.Hijacks := [Entry(tpIfeoDebugger, 'sethc.exe', 'cmd.exe')];
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.IsTrue(LResult.Status.Message.Contains('подписки WMI'));
  Assert.AreEqual(1, Integer(Length(LResult.Tamper)), 'Остальные источники работают');
end;

procedure TTamperCollectorTests.SourceException_IsIsolated;
var
  LResult: TMHCollectionResult;
begin
  FApi.HijacksRaise := True;
  FApi.Policies := [Entry(tpPolicyRestriction, 'DisableTaskMgr', '1')];
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('simulated registry exception'));
  Assert.AreEqual(1, Integer(Length(LResult.Tamper)));
end;

procedure TTamperCollectorTests.AllSourcesFail_IsErrorAndNotCached;
begin
  FApi.AllFail := True;
  Assert.AreEqual<TMHSourceState>(ssError, Collect.Status.State);
  FApi.AllFail := False;
  Assert.AreEqual<TMHSourceState>(ssSuccess, Collect.Status.State, 'Полный отказ не кэшируется');
  Assert.AreEqual(2, FApi.Reads);
end;

procedure TTamperCollectorTests.Cache_RefreshesAfterInterval;
begin
  Collect;
  Collect;
  Assert.AreEqual(1, FApi.Reads, 'Повторное чтение — из кэша');
  TFakeClock(FClock).AdvanceMs(121 * 1000);
  Collect;
  Assert.AreEqual(2, FApi.Reads);
end;

procedure TTamperCollectorTests.NilArguments_Raise;
var
  LClock: IMHClock;
begin
  LClock := FClockIntf;
  Assert.WillRaise(
    procedure
    begin
      TMHTamperCollector.Create(nil, LClock).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHTamperCollector.Create(FApiIntf, nil).Free;
    end, EArgumentNilException);
end;

{ TTamperRulesTests }

function TTamperRulesTests.Analyze(const AEntries: TArray<TMHTamperEntry>;
  const AFiles: TArray<TMHFileInfo>): TMHFindings;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := AEntries;
  LSnapshot.Files := AFiles;
  Result := MHAnalyzeTamper(LSnapshot, TMHRiskThresholds.Default, nil, 'test');
end;

function TTamperRulesTests.Single(const AEntry: TMHTamperEntry; const AFiles: TArray<TMHFileInfo>): TMHFinding;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([AEntry], AFiles);
  Assert.AreEqual(1, Integer(Length(LFindings)), 'Ожидалась одна находка');
  Result := LFindings[0];
end;

procedure TTamperRulesTests.Wmi_CommandConsumer_IsPersistence;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpWmiSubscription, 'Updater', 'C:\ProgramData\upd\run.exe',
    'команда (CommandLineEventConsumer); срабатывает по запросу: SELECT * FROM __InstanceModificationEvent',
    'C:\ProgramData\upd\run.exe'), [UnsignedFile('C:\ProgramData\upd\run.exe')]);
  Assert.AreEqual<TMHFindingCategory>(fcPersistence, LFinding.Category);
  Assert.IsTrue(HasCode(LFinding, EV_WMI_PERSISTENCE));
  Assert.IsTrue(LFinding.Level >= rlSuspicious, IntToStr(LFinding.Score));
  Assert.AreEqual('tamper:wmi:updater', LFinding.Key);
end;

procedure TTamperRulesTests.Wmi_ObfuscatedMinerCommand_IsMiningHigh;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpWmiSubscription, 'Sys', 'powershell.exe -w hidden -enc SQBFAFgA; xmrig.exe -o stratum+tcp://p:3333',
    'команда (CommandLineEventConsumer)'));
  Assert.AreEqual<TMHFindingCategory>(fcMining, LFinding.Category);
  Assert.AreEqual<TMHRiskLevel>(rlHighlySuspicious, LFinding.Level);
end;

procedure TTamperRulesTests.Wmi_SignedVendorAndUnbound_AreLowered;
var
  LFindings: TMHFindings;
begin
  // Подписанная программа производителя и подписка без события — тревоги нет.
  LFindings := Analyze([Entry(tpWmiSubscription, 'VendorBackup', '"C:\Program Files\Vendor\agent.exe" /wmi',
    'команда (CommandLineEventConsumer); не привязана к событию', 'C:\Program Files\Vendor\agent.exe')],
    [SignedFile('C:\Program Files\Vendor\agent.exe', 'Vendor Inc')]);
  Assert.AreEqual(0, Integer(Length(LFindings)));
  // Только подпись (подписка привязана к событию) — ниже, чем без неё.
  Assert.IsTrue(HasCode(Single(Entry(tpWmiSubscription, 'VendorAgent', '"C:\Program Files\Vendor\agent.exe"',
    'команда (CommandLineEventConsumer)', 'C:\Program Files\Vendor\agent.exe'),
    [SignedFile('C:\Program Files\Vendor\agent.exe', 'Vendor Inc')]), 'SIGNED_TRUSTED'));
end;

procedure TTamperRulesTests.Defender_BroadPath_IsSuspicious;
begin
  Assert.IsTrue(Single(Entry(tpDefenderExclusion, 'C:\', 'C:\', 'путь', 'C:\')).Level >= rlNeedsReview);
  Assert.IsTrue(Single(Entry(tpDefenderExclusion, 'C:\Windows\System32', 'x', 'путь',
    'C:\Windows\System32')).Level >= rlNeedsReview);
  Assert.IsTrue(Single(Entry(tpDefenderExclusion, 'C:\Users\user\AppData\Roaming', 'x', 'путь',
    'C:\Users\user\AppData\Roaming')).Level >= rlNeedsReview);
end;

procedure TTamperRulesTests.Defender_SuspiciousFolderAndMinerProcess;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpDefenderExclusion, USER_DIR + 'AppData\Local\Temp\svc', 'x', 'путь',
    USER_DIR + 'AppData\Local\Temp\svc'));
  Assert.IsTrue(LFinding.Level >= rlNeedsReview);
  LFinding := Single(Entry(tpDefenderExclusion, 'xmrig.exe', 'xmrig.exe', 'процесс'));
  Assert.AreEqual<TMHFindingCategory>(fcMining, LFinding.Category);
  Assert.IsTrue(LFinding.Level >= rlNeedsReview);
end;

procedure TTamperRulesTests.Defender_ExecutableExtension_VsOther;
begin
  Assert.IsTrue(Single(Entry(tpDefenderExclusion, '.exe', '.exe', 'расширение')).Level >= rlNeedsReview);
  Assert.AreEqual(0, Integer(Length(Analyze([Entry(tpDefenderExclusion, '.log', '.log', 'расширение')]))),
    'Исключение журналов — не повод для находки');
end;

procedure TTamperRulesTests.Defender_DeveloperFolder_IsLow;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpDefenderExclusion, 'D:\Projects', 'D:\Projects', 'путь', 'D:\Projects'));
  Assert.AreEqual<TMHRiskLevel>(rlLow, LFinding.Level, 'Под наблюдением, не тревога');
end;

procedure TTamperRulesTests.Defender_Policy_IsLowered;
var
  LEntry: TMHTamperEntry;
  LManaged, LHome: TMHFinding;
begin
  LEntry := Entry(tpDefenderExclusion, 'C:\', 'C:\', 'путь, задано политикой', 'C:\');
  LEntry.ManagedComputer := True;
  LManaged := Single(LEntry);
  Assert.IsTrue(HasCode(LManaged, EV_CORPORATE_POLICY), 'Компьютер организации — политика администратора');
  LEntry.ManagedComputer := False;
  LHome := Single(LEntry);
  Assert.IsTrue(HasCode(LHome, EV_POLICY_NO_DOMAIN), 'Домашний компьютер — политику прописала программа');
  Assert.IsTrue(LHome.Score > LManaged.Score);
end;

procedure TTamperRulesTests.Defender_GroupedByFolder_WithMinerArtifacts;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  // Как на реальном заражённом компьютере: программы с системными именами в ProgramData,
  // скрытые файлы и драйвер WinRing0 рядом.
  LFindings := Analyze([
    Entry(tpDefenderExclusion, 'C:\ProgramData\WindowsTask\audiodg.exe', 'x',
      'путь, задано политикой; файл скрытый и системный; рядом: WinRing0x64.sys',
      'C:\ProgramData\WindowsTask\audiodg.exe'),
    Entry(tpDefenderExclusion, 'C:\ProgramData\WindowsTask\AMD.exe', 'x',
      'процесс, задано политикой; файл скрытый и системный; рядом: WinRing0x64.sys',
      'C:\ProgramData\WindowsTask\AMD.exe')]);
  Assert.AreEqual(1, Integer(Length(LFindings)), 'Одна находка на папку');
  LFinding := LFindings[0];
  Assert.AreEqual<TMHFindingCategory>(fcMining, LFinding.Category);
  Assert.AreEqual<TMHRiskLevel>(rlHighlySuspicious, LFinding.Level);
  Assert.IsTrue(HasCode(LFinding, EV_MINER_ARTIFACT));
  Assert.IsTrue(HasCode(LFinding, 'MASQUERADE'));
  Assert.IsTrue(HasCode(LFinding, EV_HIDDEN_FILE));
  Assert.IsTrue(HasCode(LFinding, EV_PROGRAMDATA_EXE));
  Assert.IsTrue(LFinding.Title.Contains('2 программ'));
end;

procedure TTamperRulesTests.Ifeo_SameCommand_OneFinding;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([Entry(tpIfeoDebugger, 'MsMpEng.exe', 'C:\Windows\System32\systray.exe'),
    Entry(tpIfeoDebugger, 'MpCmdRun.exe', 'C:\Windows\System32\systray.exe'),
    Entry(tpIfeoDebugger, 'CompatTelRunner.exe', 'C:\Windows\System32\systray.exe')]);
  Assert.AreEqual(1, Integer(Length(LFindings)));
  Assert.IsTrue(LFindings[0].Title.Contains('MsMpEng.exe'));
  Assert.IsTrue(LFindings[0].Level >= rlSuspicious, 'Запуск антивируса заблокирован');
end;

procedure TTamperRulesTests.DefenderPolicies_OneFinding;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([Entry(tpPolicyRestriction, 'DisableAntiSpyware', '1', 'HKLM'),
    Entry(tpPolicyRestriction, 'DisableRealtimeMonitoring', '1', 'HKLM'),
    Entry(tpPolicyRestriction, 'EnableLUA', '0', 'HKLM')]);
  Assert.AreEqual(2, Integer(Length(LFindings)), 'Политики Defender — одна находка, UAC — отдельная');
end;

procedure TTamperRulesTests.Ifeo_ProcessExplorerReplacement_NoFinding;
begin
  Assert.AreEqual(0, Integer(Length(Analyze([Entry(tpIfeoDebugger, 'taskmgr.exe',
    '"C:\Tools\procexp64.exe" /e', '', 'C:\Tools\procexp64.exe')]))));
end;

procedure TTamperRulesTests.Ifeo_StickyKeysBackdoor_IsHigh;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpIfeoDebugger, 'sethc.exe', 'C:\Windows\System32\cmd.exe', '',
    'C:\Windows\System32\cmd.exe'));
  Assert.IsTrue(HasCode(LFinding, EV_ACCESSIBILITY_HIJACK));
  Assert.IsTrue(LFinding.Level >= rlSuspicious);
end;

procedure TTamperRulesTests.Ifeo_TaskManagerHijackedByUnknown_IsHigh;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpIfeoDebugger, 'taskmgr.exe', 'C:\ProgramData\k\kill.exe', '',
    'C:\ProgramData\k\kill.exe'), [UnsignedFile('C:\ProgramData\k\kill.exe')]);
  Assert.IsTrue(HasCode(LFinding, EV_EXECUTION_HIJACK));
  Assert.IsTrue(LFinding.Level >= rlSuspicious, IntToStr(LFinding.Score));
end;

procedure TTamperRulesTests.Ifeo_DeveloperDebugger_IsLow;
begin
  Assert.AreEqual(0, Integer(Length(Analyze([Entry(tpIfeoDebugger, 'myapp.exe', 'vsjitdebugger.exe', '',
    'C:\Windows\System32\vsjitdebugger.exe')]))), 'Отладчик разработчика — не повод для находки');
end;

procedure TTamperRulesTests.SilentExit_IsPersistence;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpSilentExitMonitor, 'notepad.exe', 'C:\Users\Public\m.exe', '',
    'C:\Users\Public\m.exe'));
  Assert.AreEqual<TMHFindingCategory>(fcPersistence, LFinding.Category);
  Assert.IsTrue(LFinding.Level >= rlSuspicious);
end;

procedure TTamperRulesTests.Hosts_AvDomains_OneFindingHigh;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([Entry(tpHostsRedirect, 'kaspersky.com', '0.0.0.0'),
    Entry(tpHostsRedirect, 'eset.com', '0.0.0.0'), Entry(tpHostsRedirect, 'update.microsoft.com', '0.0.0.0')]);
  Assert.AreEqual(1, Integer(Length(LFindings)), 'Перенаправления hosts — одна находка');
  Assert.AreEqual('tamper:hosts', LFindings[0].Key);
  Assert.IsTrue(LFindings[0].Level >= rlNeedsReview);
  Assert.IsTrue(LFindings[0].Title.Contains('3'));
end;

procedure TTamperRulesTests.Hosts_UpdatesOnly_IsWeaker;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpHostsRedirect, 'update.microsoft.com', '0.0.0.0'));
  Assert.IsTrue(HasCode(LFinding, EV_UPDATES_ONLY));
  Assert.IsTrue(LFinding.Score < 35);
end;

procedure TTamperRulesTests.Hosts_Relocated_IsSuspicious;
var
  LFinding: TMHFinding;
begin
  LFinding := Single(Entry(tpHostsRedirect, 'DataBasePath', 'C:\ProgramData\x\hosts', 'перенесён'));
  Assert.IsTrue(HasCode(LFinding, EV_HOSTS_RELOCATED));
  Assert.IsTrue(LFinding.Level >= rlNeedsReview);
end;

procedure TTamperRulesTests.Policies_Each;
var
  LName: string;
  LFinding: TMHFinding;
begin
  for LName in ['DisableTaskMgr', 'DisableRegistryTools', 'DisableCMD', 'EnableLUA', 'DisableAntiSpyware',
    'DisableRealtimeMonitoring'] do
  begin
    LFinding := Single(Entry(tpPolicyRestriction, LName, '1', 'HKCU'));
    Assert.IsTrue(HasCode(LFinding, EV_POLICY_RESTRICTION), LName);
    Assert.IsTrue(LFinding.Level >= rlLow, LName);
  end;
  Assert.IsTrue(Single(Entry(tpPolicyRestriction, 'DisableTaskMgr', '1', 'HKCU')).Level >= rlNeedsReview);
end;

procedure TTamperRulesTests.UserExclusion_SuppressesFinding;
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [Entry(tpPolicyRestriction, 'DisableCMD', '1', 'HKCU'),
    Entry(tpPolicyRestriction, 'DisableTaskMgr', '1', 'HKCU')];
  LFindings := MHAnalyzeTamper(LSnapshot, TMHRiskThresholds.Default,
    function(const AKey, ASha256: string): Boolean
    begin
      Result := AKey = 'tamper:policy:hkcu:disablecmd';
    end, 'test');
  Assert.AreEqual(1, Integer(Length(LFindings)));
  Assert.AreEqual('tamper:policy:hkcu:disabletaskmgr', LFindings[0].Key);
end;

procedure TTamperRulesTests.Findings_HaveExplanationAndStableKeys;
var
  LFindings, LAgain: TMHFindings;
  LFinding: TMHFinding;
  I: Integer;
begin
  LFindings := Analyze([Entry(tpWmiSubscription, 'A', 'cmd /c x'), Entry(tpIfeoDebugger, 'osk.exe', 'cmd.exe'),
    Entry(tpPolicyRestriction, 'DisableTaskMgr', '1', 'HKLM')]);
  LAgain := Analyze([Entry(tpWmiSubscription, 'A', 'cmd /c x'), Entry(tpIfeoDebugger, 'osk.exe', 'cmd.exe'),
    Entry(tpPolicyRestriction, 'DisableTaskMgr', '1', 'HKLM')]);
  Assert.AreEqual(3, Integer(Length(LFindings)));
  for I := 0 to High(LFindings) do
  begin
    LFinding := LFindings[I];
    Assert.IsNotEmpty(LFinding.Title);
    Assert.IsNotEmpty(LFinding.Summary);
    Assert.IsTrue(Length(LFinding.Recommendations) > 0, LFinding.Title);
    Assert.IsTrue(Length(LFinding.Evidence) > 0);
    Assert.AreEqual('test', LFinding.RulesetVersion);
    Assert.AreEqual(GUIDToString(LFinding.Id), GUIDToString(LAgain[I].Id), 'Идентификатор стабилен');
  end;
end;

procedure TTamperRulesTests.EvidenceFor_ExcludedPathAndProcessName;
var
  LSnapshot: TMHSnapshot;
  LExcluded: Boolean;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [Entry(tpDefenderExclusion, 'C:\ProgramData\Svc', 'x', 'путь'),
    Entry(tpDefenderExclusion, 'miner.exe', 'x', 'процесс')];
  MHTamperEvidenceFor(LSnapshot, 'C:\ProgramData\Svc\bin\a.exe', 'a.exe', LExcluded);
  Assert.IsTrue(LExcluded, 'Вложенная папка исключённого пути');
  MHTamperEvidenceFor(LSnapshot, 'C:\ProgramData\SvcOther\a.exe', 'a.exe', LExcluded);
  Assert.IsFalse(LExcluded, 'Похожее имя папки — не исключение');
  MHTamperEvidenceFor(LSnapshot, 'D:\x\miner.exe', 'miner.exe', LExcluded);
  Assert.IsTrue(LExcluded, 'Исключение по имени процесса');
end;

procedure TTamperRulesTests.EvidenceFor_LaunchedByWmi;
var
  LSnapshot: TMHSnapshot;
  LExcluded: Boolean;
  LEvidence: TArray<TMHEvidence>;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Tamper := [Entry(tpWmiSubscription, 'W', 'C:\x\run.exe', '', MHNormalizePath('C:\x\run.exe'))];
  LEvidence := MHTamperEvidenceFor(LSnapshot, 'C:\x\run.exe', 'run.exe', LExcluded);
  Assert.AreEqual(1, Integer(Length(LEvidence)));
  Assert.AreEqual(EV_TAMPER_LINK, LEvidence[0].Code);
  Assert.IsFalse(LExcluded);
end;

procedure TTamperRulesTests.Analyzer_LoadedProcessInExcludedFolder_GetsEvidence;
var
  LSnapshots: TArray<TMHSnapshot>;
  LAnalyzer: TMHThreatAnalyzer;
  LIntf: IInterface;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  I: Integer;
begin
  LSnapshots := BuildSnapshots([Proc(5001, 'helper.exe', 'C:\ProgramData\Helper\helper.exe', sgUnsigned, '',
    [0, 50])], 900, False, nil);
  for I := 0 to High(LSnapshots) do
    LSnapshots[I].Tamper := [Entry(tpDefenderExclusion, 'C:\ProgramData\Helper', 'x', 'путь',
      'C:\ProgramData\Helper')];
  LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
  LIntf := LAnalyzer;
  LFindings := nil;
  for I := 0 to High(LSnapshots) do
    LFindings := LAnalyzer.Analyze(LSnapshots[I], TMHBaseline.Empty);
  Assert.IsTrue(MaxLevelFor(LFindings, 'helper.exe', LFinding) >= rlSuspicious);
  Assert.IsTrue(HasCode(LFinding, EV_AV_EXCLUDED), 'Исключение антивируса усиливает находку процесса');
end;

procedure TTamperRulesTests.Analyzer_IdleProcessInExcludedFolder_NoFinding;
var
  LSnapshots: TArray<TMHSnapshot>;
  LAnalyzer: TMHThreatAnalyzer;
  LIntf: IInterface;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  I: Integer;
begin
  LSnapshots := BuildSnapshots([Proc(5002, 'devtool.exe', 'D:\Projects\bin\devtool.exe', sgUnsigned, '',
    [0, 1])], 10, False, nil);
  for I := 0 to High(LSnapshots) do
    LSnapshots[I].Tamper := [Entry(tpDefenderExclusion, 'D:\Projects', 'x', 'путь', 'D:\Projects')];
  LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
  LIntf := LAnalyzer;
  LFindings := nil;
  for I := 0 to High(LSnapshots) do
    LFindings := LAnalyzer.Analyze(LSnapshots[I], TMHBaseline.Empty);
  Assert.AreEqual<TMHRiskLevel>(rlNone, MaxLevelFor(LFindings, 'devtool.exe', LFinding),
    'Программа без нагрузки в исключённой папке разработчика — не находка');
end;

initialization
  TDUnitX.RegisterTestFixture(TTamperCollectorTests);
  TDUnitX.RegisterTestFixture(TTamperRulesTests);

end.
