unit MineHunter.Tests.Acknowledge;

{
  «Проверено, не беспокоить»: отпечаток находки, возврат тревоги при новом
  содержимом или росте риска, фильтр анализатора, сохранение в настройках.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types;

type
  [TestFixture]
  [Category('Unit')]
  TAcknowledgeTests = class
  public
    [Test] procedure Fingerprint_LoadNumbersDoNotMatter;
    [Test] procedure Fingerprint_NewTamperValueChangesIt;
    [Test] procedure Acknowledged_UntilChangedOrRiskGrows;
    [Test] procedure Filter_And_Analyzer;
    [Test] procedure Settings_RoundTripAndRemove;
  end;

implementation

uses
  MineHunter.Analysis.Acknowledge, MineHunter.Core.Settings, MineHunter.Analysis.Engine,
  MineHunter.Tests.Fakes;

function Finding(const AKey: string; ALevel: TMHRiskLevel; const AEvidence: array of TMHEvidence): TMHFinding;
var
  I: Integer;
begin
  Result := Default(TMHFinding);
  Result.Key := AKey;
  Result.Title := 'Находка ' + AKey;
  Result.Level := ALevel;
  SetLength(Result.Evidence, Length(AEvidence));
  for I := 0 to High(AEvidence) do
    Result.Evidence[I] := AEvidence[I];
end;

procedure TAcknowledgeTests.Fingerprint_LoadNumbersDoNotMatter;
var
  A, B: TMHFinding;
begin
  A := Finding('process:c:\x.exe:mining', rlSuspicious, [TMHEvidence.Create('SUSTAINED_CPU', 'Нагрузка', 20, '87% 40 мин')]);
  B := Finding('process:c:\x.exe:mining', rlSuspicious, [TMHEvidence.Create('SUSTAINED_CPU', 'Нагрузка', 20, '91% 45 мин')]);
  Assert.AreEqual(MHFindingFingerprint(A), MHFindingFingerprint(B), 'Цифры нагрузки меняются каждый цикл');
  B.Evidence := B.Evidence + [TMHEvidence.Create('MINER_NAME', 'Имя майнера', 35, 'xmrig')];
  Assert.AreNotEqual(MHFindingFingerprint(A), MHFindingFingerprint(B), 'Новый признак — новое содержимое');
end;

procedure TAcknowledgeTests.Fingerprint_NewTamperValueChangesIt;
var
  A, B, C: TMHFinding;
begin
  A := Finding('tamper:defender:c:\programdata', rlSuspicious,
    [TMHEvidence.Create('AV_EXCLUSION', 'Исключение', 30, 'C:\ProgramData; C:\Tools')]);
  B := Finding('tamper:defender:c:\programdata', rlSuspicious,
    [TMHEvidence.Create('AV_EXCLUSION', 'Исключение', 30, 'C:\ProgramData; C:\Tools; C:\Users\Public')]);
  C := Finding('tamper:defender:c:\programdata', rlSuspicious,
    [TMHEvidence.Create('AV_EXCLUSION', 'Исключение', 30, 'c:\programdata; c:\tools')]);
  Assert.AreNotEqual(MHFindingFingerprint(A), MHFindingFingerprint(B), 'Новое исключение — тревога вернётся');
  Assert.AreEqual(MHFindingFingerprint(A), MHFindingFingerprint(C), 'Регистр букв не важен');
end;

procedure TAcknowledgeTests.Acknowledged_UntilChangedOrRiskGrows;
var
  LFinding, LChanged: TMHFinding;
  LAcks: TArray<TMHAcknowledgement>;
begin
  LFinding := Finding('tamper:policy:defender', rlNeedsReview,
    [TMHEvidence.Create('POLICY', 'Политика', 40, 'DisableAntiSpyware=1')]);
  LAcks := [MHAcknowledgementFor(LFinding, FAKE_NOW)];
  Assert.IsTrue(MHIsAcknowledged(LFinding, LAcks));
  LChanged := LFinding;
  LChanged.Level := rlSuspicious;
  Assert.IsFalse(MHIsAcknowledged(LChanged, LAcks), 'Риск вырос — снова тревога');
  LChanged := LFinding;
  LChanged.Level := rlLow;
  Assert.IsTrue(MHIsAcknowledged(LChanged, LAcks), 'Риск снизился — отметка действует');
  LChanged := LFinding;
  LChanged.Evidence[0].Observed := 'DisableAntiSpyware=1; DisableRealtimeMonitoring=1';
  Assert.IsFalse(MHIsAcknowledged(LChanged, LAcks), 'Новое значение политики — снова тревога');
  Assert.IsFalse(MHIsAcknowledged(LFinding, nil));
end;

procedure TAcknowledgeTests.Filter_And_Analyzer;
var
  A, B: TMHFinding;
  LFiltered: TMHFindings;
  LAnalyzer: TMHThreatAnalyzer;
begin
  A := Finding('tamper:a', rlSuspicious, [TMHEvidence.Create('X', 'x', 30, '1')]);
  B := Finding('tamper:b', rlSuspicious, [TMHEvidence.Create('X', 'x', 30, '2')]);
  LFiltered := MHFilterAcknowledged([A, B], [MHAcknowledgementFor(A, FAKE_NOW)]);
  Assert.AreEqual(1, Integer(Length(LFiltered)));
  Assert.AreEqual('tamper:b', LFiltered[0].Key);
  LAnalyzer := TMHThreatAnalyzer.Create(8, 0);
  try
    LAnalyzer.Acknowledged := [MHAcknowledgementFor(A, FAKE_NOW)];
    Assert.AreEqual(1, Integer(Length(LAnalyzer.Acknowledged)));
    Assert.AreEqual(A.Key, LAnalyzer.Acknowledged[0].Key);
  finally
    LAnalyzer.Free;
  end;
end;

procedure TAcknowledgeTests.Settings_RoundTripAndRemove;
var
  LSettings, LLoaded: TMHAppSettings;
  LAck: TMHAcknowledgement;
begin
  LSettings := TMHAppSettings.Default;
  LAck := MHAcknowledgementFor(Finding('tamper:a', rlSuspicious, [TMHEvidence.Create('X', 'x', 30, 'v')]), FAKE_NOW);
  MHSetAcknowledgement(LSettings, LAck);
  LAck.Level := rlHighlySuspicious;
  MHSetAcknowledgement(LSettings, LAck); // замена, а не дубль
  Assert.AreEqual(1, Integer(Length(LSettings.Acknowledged)));
  LLoaded := MHSettingsFromJson(MHSettingsToJson(LSettings));
  Assert.AreEqual(1, Integer(Length(LLoaded.Acknowledged)));
  Assert.AreEqual(LAck.Fingerprint, LLoaded.Acknowledged[0].Fingerprint);
  Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LLoaded.Acknowledged[0].Level));
  Assert.AreEqual(LAck.Title, LLoaded.Acknowledged[0].Title);
  Assert.IsTrue(MHRemoveAcknowledgement(LLoaded, 'TAMPER:A'), 'Без учёта регистра');
  Assert.IsFalse(MHRemoveAcknowledgement(LLoaded, 'tamper:a'));
  Assert.AreEqual(0, Integer(Length(MHSettingsFromJson('{"version":1,"acknowledged":[{"key":"","fingerprint":"x"}]}')
    .Acknowledged)), 'Записи без ключа отбрасываются');
end;

initialization
  TDUnitX.RegisterTestFixture(TAcknowledgeTests);

end.
