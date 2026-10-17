unit MineHunter.App.FindingsView;

{
  Модель представления находок (MH-07, MH-08): активные тревоги с
  объединением повторов, история, риск процесса для таблицы и текст
  карточки находки. Не зависит от VCL и тестируется отдельно.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHFindingsMode = (fmActive, fmHistory);

  TMHFindingRow = record
    Finding: TMHFinding;
    FirstSeenUtc: TDateTime;
    LastSeenUtc: TDateTime;
    MaxScore: Integer;
    Occurrences: Integer;
    Active: Boolean;
  end;

  TMHFindingsModel = class
  private
    FActive: TDictionary<string, TMHFindingRow>;
    FHistory: TArray<TMHFindingRow>;
    FRows: TArray<TMHFindingRow>;
    FMode: TMHFindingsMode;
    FMinLevel: TMHRiskLevel;
    FStaleSeconds: Integer;
    procedure Rebuild;
    function GetCount: Integer;
    function GetRow(AIndex: Integer): TMHFindingRow;
    procedure SetMode(AValue: TMHFindingsMode);
    procedure SetMinLevel(AValue: TMHRiskLevel);
  public
    /// AStaleSeconds — через сколько секунд без подтверждения тревога перестаёт быть активной.
    constructor Create(AStaleSeconds: Integer = 60);
    destructor Destroy; override;
    /// Находки очередного снимка.
    procedure UpdateActive(const AFindings: TMHFindings; ANowUtc: TDateTime);
    procedure SetHistory(const AItems: TArray<TMHStoredFinding>);
    procedure ClearActive;
    /// Убирает активную находку (например, после добавления программы в исключения).
    procedure Remove(const AKey: string);
    function IndexOfKey(const AKey: string): Integer;
    /// Все активные находки независимо от режима и фильтра (для отчётов).
    function ActiveCount: Integer;
    function ActiveRows(AIndex: Integer): TMHFindingRow;
    /// Число активных тревог с уровнем не ниже AMinLevel.
    function ActiveAlertCount(AMinLevel: TMHRiskLevel = rlNeedsReview): Integer;
    /// Наивысший уровень активных находок по экземпляру процесса.
    function RiskOf(const AId: TMHProcessId): TMHRiskLevel;
    property Count: Integer read GetCount;
    property Rows[AIndex: Integer]: TMHFindingRow read GetRow; default;
    property Mode: TMHFindingsMode read FMode write SetMode;
    property MinLevel: TMHRiskLevel read FMinLevel write SetMinLevel;
  end;

/// Текст карточки находки (MH-08) построчно.
function MHFindingCardLines(const ARow: TMHFindingRow; const AProcess: TMHProcessInfo;
  AHasProcess: Boolean; const AParentName: string): TArray<string>;

implementation

uses
  System.Math, System.DateUtils, System.Generics.Defaults,
  MineHunter.App.Display, MineHunter.App.ProcessView;

{ TMHFindingsModel }

constructor TMHFindingsModel.Create(AStaleSeconds: Integer);
begin
  inherited Create;
  FActive := TDictionary<string, TMHFindingRow>.Create;
  FStaleSeconds := Max(1, AStaleSeconds);
  FMode := fmActive;
  FMinLevel := rlLow;
end;

destructor TMHFindingsModel.Destroy;
begin
  FActive.Free;
  inherited;
end;

procedure TMHFindingsModel.UpdateActive(const AFindings: TMHFindings; ANowUtc: TDateTime);
var
  LFinding: TMHFinding;
  LRow: TMHFindingRow;
  LKeys: TArray<string>;
  LKey: string;
begin
  for LFinding in AFindings do
  begin
    if FActive.TryGetValue(LFinding.Key, LRow) then
    begin
      LRow.Finding := LFinding;
      LRow.LastSeenUtc := LFinding.DetectedAtUtc;
      LRow.MaxScore := Max(LRow.MaxScore, LFinding.Score);
      Inc(LRow.Occurrences);
    end
    else
    begin
      LRow := Default(TMHFindingRow);
      LRow.Finding := LFinding;
      LRow.FirstSeenUtc := LFinding.DetectedAtUtc;
      LRow.LastSeenUtc := LFinding.DetectedAtUtc;
      LRow.MaxScore := LFinding.Score;
      LRow.Occurrences := 1;
    end;
    LRow.Active := True;
    FActive.AddOrSetValue(LFinding.Key, LRow);
  end;
  // Тревоги, которые давно не подтверждались (процесс завершился, нагрузка спала), снимаются.
  LKeys := FActive.Keys.ToArray;
  for LKey in LKeys do
    if (ANowUtc - FActive[LKey].LastSeenUtc) * SecsPerDay > FStaleSeconds then
      FActive.Remove(LKey);
  Rebuild;
end;

procedure TMHFindingsModel.SetHistory(const AItems: TArray<TMHStoredFinding>);
var
  I: Integer;
begin
  SetLength(FHistory, Length(AItems));
  for I := 0 to High(AItems) do
  begin
    FHistory[I].Finding := AItems[I].Finding;
    FHistory[I].FirstSeenUtc := AItems[I].FirstSeenUtc;
    FHistory[I].LastSeenUtc := AItems[I].LastSeenUtc;
    FHistory[I].MaxScore := AItems[I].MaxScore;
    FHistory[I].Occurrences := AItems[I].Occurrences;
    FHistory[I].Active := FActive.ContainsKey(AItems[I].Finding.Key);
  end;
  Rebuild;
end;

procedure TMHFindingsModel.ClearActive;
begin
  FActive.Clear;
  Rebuild;
end;

procedure TMHFindingsModel.Remove(const AKey: string);
begin
  FActive.Remove(AKey);
  Rebuild;
end;

function TMHFindingsModel.ActiveCount: Integer;
begin
  Result := FActive.Count;
end;

function TMHFindingsModel.ActiveRows(AIndex: Integer): TMHFindingRow;
var
  LRows: TArray<TMHFindingRow>;
begin
  LRows := FActive.Values.ToArray;
  TArray.Sort<TMHFindingRow>(LRows, TComparer<TMHFindingRow>.Construct(
    function(const A, B: TMHFindingRow): Integer
    begin
      Result := CompareValue(B.Finding.Score, A.Finding.Score);
      if Result = 0 then
        Result := CompareStr(A.Finding.Key, B.Finding.Key);
    end));
  Result := LRows[AIndex];
end;

procedure TMHFindingsModel.SetMode(AValue: TMHFindingsMode);
begin
  FMode := AValue;
  Rebuild;
end;

procedure TMHFindingsModel.SetMinLevel(AValue: TMHRiskLevel);
begin
  FMinLevel := AValue;
  Rebuild;
end;

procedure TMHFindingsModel.Rebuild;
var
  LList: TList<TMHFindingRow>;
  LRow: TMHFindingRow;
  LSource: TArray<TMHFindingRow>;
begin
  if FMode = fmActive then
    LSource := FActive.Values.ToArray
  else
    LSource := FHistory;
  LList := TList<TMHFindingRow>.Create;
  try
    for LRow in LSource do
      if LRow.Finding.Level >= FMinLevel then
        LList.Add(LRow);
    LList.Sort(TComparer<TMHFindingRow>.Construct(
      function(const A, B: TMHFindingRow): Integer
      begin
        Result := CompareValue(Ord(B.Finding.Level), Ord(A.Finding.Level));
        if Result = 0 then
          Result := CompareValue(B.Finding.Score, A.Finding.Score);
        if Result = 0 then
          Result := CompareValue(B.LastSeenUtc, A.LastSeenUtc);
        if Result = 0 then
          Result := CompareStr(A.Finding.Key, B.Finding.Key);
      end));
    FRows := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TMHFindingsModel.GetCount: Integer;
begin
  Result := Length(FRows);
end;

function TMHFindingsModel.GetRow(AIndex: Integer): TMHFindingRow;
begin
  Result := FRows[AIndex];
end;

function TMHFindingsModel.IndexOfKey(const AKey: string): Integer;
var
  I: Integer;
begin
  for I := 0 to High(FRows) do
    if FRows[I].Finding.Key = AKey then
      Exit(I);
  Result := -1;
end;

function TMHFindingsModel.ActiveAlertCount(AMinLevel: TMHRiskLevel): Integer;
var
  LRow: TMHFindingRow;
begin
  Result := 0;
  for LRow in FActive.Values do
    if LRow.Finding.Level >= AMinLevel then
      Inc(Result);
end;

function TMHFindingsModel.RiskOf(const AId: TMHProcessId): TMHRiskLevel;
var
  LRow: TMHFindingRow;
begin
  Result := rlNone;
  for LRow in FActive.Values do
    if (LRow.Finding.Process = AId) and not AId.IsEmpty and (LRow.Finding.Level > Result) then
      Result := LRow.Finding.Level;
end;

function MHFindingCardLines(const ARow: TMHFindingRow; const AProcess: TMHProcessInfo;
  AHasProcess: Boolean; const AParentName: string): TArray<string>;
var
  LLines: TList<string>;
  LEvidence: TMHEvidence;
  LText: string;
  F: TMHFinding;
begin
  F := ARow.Finding;
  LLines := TList<string>.Create;
  try
    LLines.Add(F.Title);
    LLines.Add(Format('Уровень: %s · оценка %d из 100 · уверенность %d%% · %s',
      [MHRiskLevelToString(F.Level), F.Score, Round(F.Confidence * 100),
       MHFindingCategoryToString(F.Category)]));
    LLines.Add(F.Summary);
    LLines.Add('');
    LLines.Add(Format('Впервые: %s · последний раз: %s · повторений: %d',
      [MHFormatUtcAsLocal(ARow.FirstSeenUtc), MHFormatUtcAsLocal(ARow.LastSeenUtc), ARow.Occurrences]));
    if not F.Process.IsEmpty or (F.Process.Pid <> 0) then
    begin
      LText := Format('Процесс: %s (PID %d, запущен %s)', [F.ProcessName, F.Process.Pid,
        MHFormatFileTimeLocal(F.Process.CreateTime)]);
      if not AHasProcess then
        LText := LText + ' — сейчас не выполняется';
      LLines.Add(LText);
      if AParentName <> '' then
        LLines.Add(Format('Родительский процесс: %s (PID %d)', [AParentName, F.ParentPid]))
      else if F.ParentPid <> 0 then
        LLines.Add(Format('Родительский процесс: PID %d (уже завершён или недоступен)', [F.ParentPid]));
    end;
    if F.ImagePath <> '' then
      LLines.Add('Файл: ' + F.ImagePath)
    else
      LLines.Add('Файл: ' + MH_NO_DATA);
    if AHasProcess then
    begin
      LLines.Add('Подпись: ' + MHSignatureToString(AProcess.Signature));
      if AProcess.Sha256 <> '' then
        LLines.Add('SHA-256: ' + AProcess.Sha256);
      LLines.Add(Format('Сейчас: CPU %s · память %s · GPU %s (вычисления %s)', [MHFormatMetric(AProcess.Cpu),
        MHFormatMetric(MHProcessMemory(AProcess)), MHFormatMetric(AProcess.Gpu),
        MHFormatMetric(AProcess.GpuCompute)]));
    end;
    LLines.Add('');
    LLines.Add('Почему это подозрительно:');
    for LEvidence in F.PositiveEvidence do
    begin
      LText := Format('  + %s (+%d)', [LEvidence.Description, LEvidence.Weight]);
      if LEvidence.Observed <> '' then
        LText := LText + ': ' + LEvidence.Observed;
      LLines.Add(LText);
    end;
    if Length(F.NegativeEvidence) > 0 then
    begin
      LLines.Add('Что говорит в пользу обычной работы:');
      for LEvidence in F.NegativeEvidence do
      begin
        LText := Format('  − %s (%d)', [LEvidence.Description, LEvidence.Weight]);
        if LEvidence.Observed <> '' then
          LText := LText + ': ' + LEvidence.Observed;
        LLines.Add(LText);
      end;
    end;
    if Length(F.MissingData) > 0 then
    begin
      LLines.Add('Недостающие данные (оценка может быть неточной):');
      for LText in F.MissingData do
        LLines.Add('  • ' + LText);
    end;
    LLines.Add('');
    LLines.Add('Рекомендации:');
    for LText in F.Recommendations do
      LLines.Add('  • ' + LText);
    LLines.Add('');
    LLines.Add('Версия правил: ' + F.RulesetVersion);
    Result := LLines.ToArray;
  finally
    LLines.Free;
  end;
end;

end.
