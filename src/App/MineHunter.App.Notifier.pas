unit MineHunter.App.Notifier;

{
  Отбор находок для всплывающих уведомлений.
  Правила: уведомляем только о находках уровня не ниже заданного; об одной
  находке — один раз, повторно — только если уровень вырос; находка, которой
  не было дольше часа, снова считается новой; уведомления не чаще одного за
  AMinGapSeconds (новые находки за это время объединяются в одно уведомление).
  Класс не зависит от VCL и проверяется тестами без окна.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types;

type
  TMHAlertNotice = record
    Title: string;
    Text: string;
    /// Число новых находок в уведомлении.
    Count: Integer;
    /// Наивысший уровень среди них.
    Level: TMHRiskLevel;
    /// Ключ первой (самой опасной) находки — для перехода к ней по щелчку.
    FindingKey: string;
  end;

  TMHAlertNotifier = class
  public const
    ForgetAfterMinutes = 60;
  private type
    TSeen = record
      Level: TMHRiskLevel;
      LastSeenUtc: TDateTime;
    end;
  private
    FMinLevel: TMHRiskLevel;
    FMinGapSeconds: Integer;
    FSeen: TDictionary<string, TSeen>;
    FPending: TList<TMHFinding>;
    FLastNoticeUtc: TDateTime;
    procedure Forget(ANowUtc: TDateTime);
    procedure AddPending(const AFinding: TMHFinding);
    function BuildNotice: TMHAlertNotice;
  public
    constructor Create(AMinLevel: TMHRiskLevel = rlSuspicious; AMinGapSeconds: Integer = 60);
    destructor Destroy; override;
    /// Учитывает находки очередного цикла. True — пора показать ANotice.
    function Process(const AFindings: TMHFindings; ANowUtc: TDateTime;
      out ANotice: TMHAlertNotice): Boolean;
    /// Число находок, ожидающих уведомления (накоплены во время паузы).
    function PendingCount: Integer;
    procedure Reset;
    property MinLevel: TMHRiskLevel read FMinLevel write FMinLevel;
  end;

implementation

uses
  System.DateUtils;

constructor TMHAlertNotifier.Create(AMinLevel: TMHRiskLevel; AMinGapSeconds: Integer);
begin
  inherited Create;
  FMinLevel := AMinLevel;
  if AMinGapSeconds < 0 then
    AMinGapSeconds := 0;
  FMinGapSeconds := AMinGapSeconds;
  FSeen := TDictionary<string, TSeen>.Create;
  FPending := TList<TMHFinding>.Create;
end;

destructor TMHAlertNotifier.Destroy;
begin
  FPending.Free;
  FSeen.Free;
  inherited;
end;

procedure TMHAlertNotifier.Reset;
begin
  FSeen.Clear;
  FPending.Clear;
  FLastNoticeUtc := 0;
end;

function TMHAlertNotifier.PendingCount: Integer;
begin
  Result := FPending.Count;
end;

procedure TMHAlertNotifier.Forget(ANowUtc: TDateTime);
var
  LKeys: TList<string>;
  LPair: TPair<string, TSeen>;
  LKey: string;
begin
  LKeys := TList<string>.Create;
  try
    for LPair in FSeen do
      if MinutesBetween(ANowUtc, LPair.Value.LastSeenUtc) >= ForgetAfterMinutes then
        LKeys.Add(LPair.Key);
    for LKey in LKeys do
      FSeen.Remove(LKey);
  finally
    LKeys.Free;
  end;
end;

procedure TMHAlertNotifier.AddPending(const AFinding: TMHFinding);
var
  I: Integer;
begin
  for I := 0 to FPending.Count - 1 do
    if FPending[I].Key = AFinding.Key then
    begin
      FPending[I] := AFinding;
      Exit;
    end;
  FPending.Add(AFinding);
end;

function TMHAlertNotifier.BuildNotice: TMHAlertNotice;
var
  LBest: TMHFinding;
  LFinding: TMHFinding;
begin
  LBest := FPending[0];
  for LFinding in FPending do
    if (LFinding.Level > LBest.Level) or ((LFinding.Level = LBest.Level) and (LFinding.Score > LBest.Score)) then
      LBest := LFinding;
  Result.Count := FPending.Count;
  Result.Level := LBest.Level;
  Result.FindingKey := LBest.Key;
  if Result.Count = 1 then
    Result.Title := 'MineHunter X: ' + MHRiskLevelToString(LBest.Level)
  else
    Result.Title := Format('MineHunter X: новых тревог — %d', [Result.Count]);
  Result.Text := LBest.Title;
  if LBest.ProcessName <> '' then
    Result.Text := Result.Text + ' (' + LBest.ProcessName + ')';
  if Result.Count > 1 then
    Result.Text := Result.Text + Format(' и ещё %d', [Result.Count - 1]);
  Result.Text := Result.Text + '. Нажмите, чтобы открыть объяснение.';
end;

function TMHAlertNotifier.Process(const AFindings: TMHFindings; ANowUtc: TDateTime;
  out ANotice: TMHAlertNotice): Boolean;
var
  LFinding: TMHFinding;
  LSeen: TSeen;
  LKnown: Boolean;
begin
  ANotice := Default(TMHAlertNotice);
  Forget(ANowUtc);
  for LFinding in AFindings do
  begin
    if (LFinding.Key = '') or (LFinding.Level < FMinLevel) then
      Continue;
    LKnown := FSeen.TryGetValue(LFinding.Key, LSeen);
    if not LKnown or (LFinding.Level > LSeen.Level) then
      AddPending(LFinding);
    if not LKnown or (LFinding.Level > LSeen.Level) then
      LSeen.Level := LFinding.Level;
    LSeen.LastSeenUtc := ANowUtc;
    FSeen.AddOrSetValue(LFinding.Key, LSeen);
  end;
  Result := (FPending.Count > 0) and
    ((FLastNoticeUtc = 0) or (SecondsBetween(ANowUtc, FLastNoticeUtc) >= FMinGapSeconds));
  if Result then
  begin
    ANotice := BuildNotice;
    FPending.Clear;
    FLastNoticeUtc := ANowUtc;
  end;
end;

end.
