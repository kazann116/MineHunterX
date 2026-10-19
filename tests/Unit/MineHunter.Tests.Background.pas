unit MineHunter.Tests.Background;

{
  Работа в фоне: автозапуск MineHunter X (поддельная ветка Run), отбор
  уведомлений о тревогах, новые поля настроек и их сохранение.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.SelfAutostart, MineHunter.Core.Settings,
  MineHunter.App.Notifier;

type
  TFakeRunKeyOps = class(TInterfacedObject, IMHRunKeyOps)
  public
    Values: TDictionary<string, string>;
    WriteFails: Boolean;
    WriteCalls: Integer;
    constructor Create;
    destructor Destroy; override;
    function ReadRunValue(const AName: string; out AValue: string): Boolean;
    function WriteRunValue(const AName, AValue: string; out AError: string): Boolean;
    function DeleteRunValue(const AName: string; out AError: string): Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TSelfAutostartTests = class
  public
    [Test] procedure EnableDisable_RoundTrip;
    [Test] procedure StaleEntry_Detected_AndRewritten;
    [Test] procedure WriteFailure_Reported;
    [Test] procedure InvalidExePath_Refused;
    [Test] procedure CommandParsing;
    [Test] procedure MinimizedSwitch;
  end;

  [TestFixture]
  [Category('Unit')]
  TAlertNotifierTests = class
  private
    function Finding(const AKey: string; ALevel: TMHRiskLevel; AScore: Integer = 60): TMHFinding;
  public
    [Test] procedure LowLevels_NotNotified;
    [Test] procedure SameFinding_NotifiedOnce;
    [Test] procedure Escalation_NotifiedAgain;
    [Test] procedure Throttle_AggregatesNewFindings;
    [Test] procedure Forgotten_AfterAnHour;
    [Test] procedure Notice_PicksMostDangerous;
    [Test] procedure EmptyKey_Ignored;
  end;

  [TestFixture]
  [Category('Unit')]
  TBackgroundSettingsTests = class
  public
    [Test] procedure Defaults_AreSafe;
    [Test] procedure Json_RoundTrip;
    [Test] procedure Json_OldFile_UsesDefaults;
    [Test] procedure Normalize_BadPrice;
  end;

implementation

uses
  System.DateUtils;

const
  EXE = 'C:\Program Files\MineHunter X\MineHunter.App.exe';

{ TFakeRunKeyOps }

constructor TFakeRunKeyOps.Create;
begin
  inherited Create;
  Values := TDictionary<string, string>.Create;
end;

destructor TFakeRunKeyOps.Destroy;
begin
  Values.Free;
  inherited;
end;

function TFakeRunKeyOps.ReadRunValue(const AName: string; out AValue: string): Boolean;
begin
  Result := Values.TryGetValue(AName, AValue) and (AValue <> '');
end;

function TFakeRunKeyOps.WriteRunValue(const AName, AValue: string; out AError: string): Boolean;
begin
  Inc(WriteCalls);
  AError := '';
  if WriteFails then
  begin
    AError := 'Отказано в доступе';
    Exit(False);
  end;
  Values.AddOrSetValue(AName, AValue);
  Result := True;
end;

function TFakeRunKeyOps.DeleteRunValue(const AName: string; out AError: string): Boolean;
begin
  AError := '';
  Values.Remove(AName);
  Result := True;
end;

{ TSelfAutostartTests }

procedure TSelfAutostartTests.EnableDisable_RoundTrip;
var
  LOps: TFakeRunKeyOps;
  LOpsIntf: IMHRunKeyOps;
  LAuto: TMHSelfAutostart;
  LError: string;
begin
  LOps := TFakeRunKeyOps.Create;
  LOpsIntf := LOps;
  LAuto := TMHSelfAutostart.Create(LOpsIntf, EXE);
  try
    Assert.AreEqual(Ord(sasDisabled), Ord(LAuto.State));
    Assert.IsTrue(LAuto.SetEnabled(True, LError), LError);
    Assert.AreEqual(Ord(sasEnabled), Ord(LAuto.State));
    Assert.AreEqual('"' + EXE + '" --minimized', LOps.Values[TMHSelfAutostart.ValueName]);
    Assert.IsTrue(LAuto.SetEnabled(False, LError), LError);
    Assert.AreEqual(Ord(sasDisabled), Ord(LAuto.State));
    Assert.IsFalse(LOps.Values.ContainsKey(TMHSelfAutostart.ValueName));
    Assert.IsTrue(LAuto.SetEnabled(False, LError), 'Повторное выключение — не ошибка');
  finally
    LAuto.Free;
  end;
end;

procedure TSelfAutostartTests.StaleEntry_Detected_AndRewritten;
var
  LOps: TFakeRunKeyOps;
  LOpsIntf: IMHRunKeyOps;
  LAuto: TMHSelfAutostart;
  LError: string;
begin
  LOps := TFakeRunKeyOps.Create;
  LOpsIntf := LOps;
  LOps.Values.Add(TMHSelfAutostart.ValueName, '"D:\Old\MineHunter.App.exe" --minimized');
  LAuto := TMHSelfAutostart.Create(LOpsIntf, EXE);
  try
    Assert.AreEqual(Ord(sasStale), Ord(LAuto.State));
    Assert.IsFalse(LAuto.IsEnabled);
    Assert.IsTrue(LAuto.SetEnabled(True, LError));
    Assert.AreEqual(Ord(sasEnabled), Ord(LAuto.State));
    // Сравнение без учёта регистра.
    LOps.Values[TMHSelfAutostart.ValueName] := '"' + EXE.ToUpper + '" --minimized';
    Assert.AreEqual(Ord(sasEnabled), Ord(LAuto.State));
  finally
    LAuto.Free;
  end;
end;

procedure TSelfAutostartTests.WriteFailure_Reported;
var
  LOps: TFakeRunKeyOps;
  LOpsIntf: IMHRunKeyOps;
  LAuto: TMHSelfAutostart;
  LError: string;
begin
  LOps := TFakeRunKeyOps.Create;
  LOpsIntf := LOps;
  LOps.WriteFails := True;
  LAuto := TMHSelfAutostart.Create(LOpsIntf, EXE);
  try
    Assert.IsFalse(LAuto.SetEnabled(True, LError));
    Assert.IsNotEmpty(LError);
    Assert.AreEqual(Ord(sasDisabled), Ord(LAuto.State));
  finally
    LAuto.Free;
  end;
end;

procedure TSelfAutostartTests.InvalidExePath_Refused;
var
  LOps: TFakeRunKeyOps;
  LOpsIntf: IMHRunKeyOps;
  LAuto: TMHSelfAutostart;
  LError: string;
begin
  LOps := TFakeRunKeyOps.Create;
  LOpsIntf := LOps;
  LAuto := TMHSelfAutostart.Create(LOpsIntf, '');
  try
    Assert.IsFalse(LAuto.SetEnabled(True, LError));
    Assert.IsNotEmpty(LError);
    Assert.AreEqual(0, LOps.WriteCalls, 'В реестр ничего не записывается');
  finally
    LAuto.Free;
  end;
  Assert.WillRaise(
    procedure
    begin
      TMHSelfAutostart.Create(nil, EXE).Free;
    end, EArgumentNilException);
end;

procedure TSelfAutostartTests.CommandParsing;
begin
  Assert.AreEqual(EXE, MHRunCommandExecutable('"' + EXE + '" --minimized'));
  Assert.AreEqual('C:\Tools\mh.exe', MHRunCommandExecutable('C:\Tools\mh.exe --minimized'));
  Assert.AreEqual('C:\Tools\mh.exe', MHRunCommandExecutable('  C:\Tools\mh.exe  '));
  Assert.AreEqual('', MHRunCommandExecutable(''));
  Assert.AreEqual('', MHRunCommandExecutable('"C:\unterminated'));
end;

procedure TSelfAutostartTests.MinimizedSwitch;
begin
  Assert.IsTrue(MHHasMinimizedSwitch(['--minimized']));
  Assert.IsTrue(MHHasMinimizedSwitch(['x', '--MINIMIZED']));
  Assert.IsTrue(MHHasMinimizedSwitch(['/minimized']));
  Assert.IsFalse(MHHasMinimizedSwitch([]));
  Assert.IsFalse(MHHasMinimizedSwitch(['--minimize', '-m']));
end;

{ TAlertNotifierTests }

function TAlertNotifierTests.Finding(const AKey: string; ALevel: TMHRiskLevel; AScore: Integer): TMHFinding;
begin
  Result := Default(TMHFinding);
  Result.Key := AKey;
  Result.Level := ALevel;
  Result.Score := AScore;
  Result.Title := 'Находка ' + AKey;
  Result.ProcessName := AKey + '.exe';
end;

procedure TAlertNotifierTests.LowLevels_NotNotified;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
begin
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  try
    Assert.IsFalse(LNotifier.Process([Finding('a', rlLow), Finding('b', rlNeedsReview)], Now, LNotice));
    Assert.AreEqual(0, LNotifier.PendingCount);
    Assert.IsFalse(LNotifier.Process([], Now, LNotice), 'Пустой цикл');
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.SameFinding_NotifiedOnce;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
  LNow: TDateTime;
begin
  LNow := EncodeDateTime(2026, 10, 17, 12, 0, 0, 0);
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  try
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], LNow, LNotice));
    Assert.AreEqual(1, LNotice.Count);
    Assert.AreEqual('a', LNotice.FindingKey);
    Assert.IsTrue(LNotice.Text.Contains('a.exe'), LNotice.Text);
    Assert.IsFalse(LNotifier.Process([Finding('a', rlSuspicious)], IncMinute(LNow, 5), LNotice));
    Assert.IsFalse(LNotifier.Process([Finding('a', rlSuspicious)], IncMinute(LNow, 30), LNotice));
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.Escalation_NotifiedAgain;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
  LNow: TDateTime;
begin
  LNow := EncodeDateTime(2026, 10, 17, 12, 0, 0, 0);
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  try
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], LNow, LNotice));
    Assert.IsTrue(LNotifier.Process([Finding('a', rlHighlySuspicious, 95)], IncMinute(LNow, 2), LNotice));
    Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LNotice.Level));
    // Понижение и возврат к прежнему уровню не уведомляют.
    Assert.IsFalse(LNotifier.Process([Finding('a', rlSuspicious)], IncMinute(LNow, 4), LNotice));
    Assert.IsFalse(LNotifier.Process([Finding('a', rlHighlySuspicious)], IncMinute(LNow, 6), LNotice));
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.Throttle_AggregatesNewFindings;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
  LNow: TDateTime;
begin
  LNow := EncodeDateTime(2026, 10, 17, 12, 0, 0, 0);
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  try
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], LNow, LNotice));
    Assert.IsFalse(LNotifier.Process([Finding('b', rlSuspicious)], IncSecond(LNow, 10), LNotice),
      'Пауза между уведомлениями');
    Assert.IsFalse(LNotifier.Process([Finding('c', rlSuspicious)], IncSecond(LNow, 20), LNotice));
    Assert.AreEqual(2, LNotifier.PendingCount);
    Assert.IsTrue(LNotifier.Process([], IncSecond(LNow, 61), LNotice), 'Накопленные — одним уведомлением');
    Assert.AreEqual(2, LNotice.Count);
    Assert.IsTrue(LNotice.Title.Contains('2'), LNotice.Title);
    Assert.IsTrue(LNotice.Text.Contains('и ещё 1'), LNotice.Text);
    Assert.AreEqual(0, LNotifier.PendingCount);
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.Forgotten_AfterAnHour;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
  LNow: TDateTime;
begin
  LNow := EncodeDateTime(2026, 10, 17, 12, 0, 0, 0);
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  try
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], LNow, LNotice));
    Assert.IsFalse(LNotifier.Process([], IncMinute(LNow, 30), LNotice));
    // Находка исчезла больше чем на час и вернулась — о ней снова сообщается.
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], IncMinute(LNow, 61), LNotice));
    LNotifier.Reset;
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious)], IncMinute(LNow, 62), LNotice),
      'После сброса всё считается новым');
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.Notice_PicksMostDangerous;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
begin
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 0);
  try
    Assert.IsTrue(LNotifier.Process([Finding('a', rlSuspicious, 70), Finding('b', rlHighlySuspicious, 90),
      Finding('c', rlHighlySuspicious, 99)], Now, LNotice));
    Assert.AreEqual('c', LNotice.FindingKey);
    Assert.AreEqual(3, LNotice.Count);
    Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LNotice.Level));
  finally
    LNotifier.Free;
  end;
end;

procedure TAlertNotifierTests.EmptyKey_Ignored;
var
  LNotifier: TMHAlertNotifier;
  LNotice: TMHAlertNotice;
begin
  LNotifier := TMHAlertNotifier.Create(rlSuspicious, 0);
  try
    Assert.IsFalse(LNotifier.Process([Finding('', rlHighlySuspicious)], Now, LNotice));
  finally
    LNotifier.Free;
  end;
end;

{ TBackgroundSettingsTests }

procedure TBackgroundSettingsTests.Defaults_AreSafe;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  Assert.IsFalse(LSettings.CheckForUpdates, 'Без согласия — никаких запросов в интернет');
  Assert.IsTrue(LSettings.MinimizeToTray);
  Assert.IsTrue(LSettings.RemindInBackground);
  Assert.IsTrue(LSettings.NotifyAlerts);
  Assert.IsTrue(LSettings.EconomyWhenHidden);
  Assert.AreEqual(Ord(ulRussian), Ord(LSettings.Language));
  Assert.AreEqual(Ord(utLight), Ord(LSettings.Theme));
  Assert.AreEqual(Ord(chsStatic), Ord(LSettings.ChartScale), 'Шкала графиков по умолчанию — статичная');
  Assert.AreEqual(TMHAppSettings.DefaultElectricityPrice, LSettings.ElectricityPrice, 0.0001);
end;

procedure TBackgroundSettingsTests.Json_RoundTrip;
var
  LSettings, LLoaded: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  LSettings.MinimizeToTray := False;
  LSettings.RemindInBackground := False;
  LSettings.NotifyAlerts := False;
  LSettings.EconomyWhenHidden := False;
  LSettings.CheckForUpdates := True;
  LSettings.ElectricityPrice := 7.85;
  LSettings.Language := ulEnglish;
  LSettings.Theme := utDark;
  LSettings.ChartScale := chsDynamic;
  LLoaded := MHSettingsFromJson(MHSettingsToJson(LSettings));
  Assert.AreEqual(Ord(chsDynamic), Ord(LLoaded.ChartScale));
  Assert.IsFalse(LLoaded.MinimizeToTray);
  Assert.IsFalse(LLoaded.RemindInBackground);
  Assert.IsFalse(LLoaded.NotifyAlerts);
  Assert.IsFalse(LLoaded.EconomyWhenHidden);
  Assert.IsTrue(LLoaded.CheckForUpdates);
  Assert.AreEqual(7.85, LLoaded.ElectricityPrice, 0.0001);
  Assert.AreEqual(Ord(ulEnglish), Ord(LLoaded.Language));
  Assert.AreEqual(Ord(utDark), Ord(LLoaded.Theme));
end;

procedure TBackgroundSettingsTests.Json_OldFile_UsesDefaults;
var
  LLoaded: TMHAppSettings;
begin
  LLoaded := MHSettingsFromJson('{"version":1,"intervalMs":2000,"language":"de","theme":42}');
  Assert.IsTrue(LLoaded.MinimizeToTray);
  Assert.IsTrue(LLoaded.RemindInBackground, 'В старом файле нет ключа — напоминание включено');
  Assert.IsFalse(LLoaded.CheckForUpdates);
  Assert.AreEqual(Ord(ulRussian), Ord(LLoaded.Language), 'Неизвестный язык — русский');
  Assert.AreEqual(Ord(utLight), Ord(LLoaded.Theme));
  Assert.AreEqual(Ord(chsStatic), Ord(LLoaded.ChartScale), 'Старый файл — статичная шкала');
  Assert.AreEqual(Ord(chsStatic), Ord(MHSettingsFromJson('{"version":1,"chartScale":"zoom"}').ChartScale),
    'Неизвестное значение — статичная');
  Assert.AreEqual(TMHAppSettings.DefaultElectricityPrice, LLoaded.ElectricityPrice, 0.0001);
end;

procedure TBackgroundSettingsTests.Normalize_BadPrice;
var
  LSettings: TMHAppSettings;
begin
  LSettings := TMHAppSettings.Default;
  LSettings.ElectricityPrice := -5;
  Assert.AreEqual(TMHAppSettings.DefaultElectricityPrice, LSettings.Normalized.ElectricityPrice, 0.0001);
  LSettings.ElectricityPrice := 1E9;
  Assert.AreEqual(TMHAppSettings.MaxElectricityPrice, LSettings.Normalized.ElectricityPrice, 0.0001);
  LSettings.ElectricityPrice := 0;
  Assert.AreEqual(0.0, LSettings.Normalized.ElectricityPrice, 0.0001, 'Бесплатное электричество допустимо');
  Assert.AreEqual(TMHAppSettings.DefaultElectricityPrice,
    MHSettingsFromJson('{"version":1,"electricityPrice":-1}').ElectricityPrice, 0.0001);
end;

initialization
  TDUnitX.RegisterTestFixture(TSelfAutostartTests);
  TDUnitX.RegisterTestFixture(TAlertNotifierTests);
  TDUnitX.RegisterTestFixture(TBackgroundSettingsTests);

end.
