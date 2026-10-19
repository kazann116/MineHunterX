unit MineHunter.BinaryLab.Verdicts;

{
  Передача результатов BinaryLab в анализатор угроз.

  После разбора файла его аномалии превращаются в признаки (TMHEvidence)
  с кодами BINARYLAB:<код аномалии> и попадают в хранилище вердиктов.
  Анализатор при следующем цикле добавляет их в находку процесса этого
  файла — с объяснением и пометкой, что признак получен статическим разбором.

  Правила перевода:
  - в признаки идут аномалии средней и высокой серьёзности (сведения и
    слабые особенности не должны поднимать оценку процесса);
  - вес признака — 60% веса аномалии: в находке процесса статический разбор
    дополняет поведение (нагрузка, сеть, автозапуск), а не заменяет его;
    сумма признаков BinaryLab не больше 40;
  - вердикт привязан к SHA-256: изменённый файл не получает старых признаков.

  Хранилище — в памяти сеанса, не больше MaxVerdicts файлов (самые старые
  вытесняются). Потокобезопасно.
}

interface

uses
  System.SysUtils, System.SyncObjs, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.BinaryLab.Types;

const
  /// Предел суммы весов признаков BinaryLab в находке процесса.
  MH_BINARYLAB_MAX_EVIDENCE_WEIGHT = 40;

type
  TMHBinaryVerdictStore = class(TInterfacedObject, IMHBinaryVerdicts)
  public const
    MaxVerdicts = 1000;
  private
    FLock: TCriticalSection;
    FItems: TDictionary<string, TMHBinaryVerdict>;
    FOrder: TList<string>;
    class function KeyOf(const APath: string): string; static;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Put(const AVerdict: TMHBinaryVerdict);
    function TryGet(const APath, ASha256: string; out AVerdict: TMHBinaryVerdict): Boolean;
    function Count: Integer;
    procedure Clear;
  end;

/// Вердикт для анализатора угроз по отчёту BinaryLab.
function MHVerdictFromReport(const AReport: TMHBinaryReport): TMHBinaryVerdict;

implementation

uses
  System.Math,
  MineHunter.Core.Lang, MineHunter.Core.Paths, MineHunter.BinaryLab.Anomalies;

const
  /// Аномалии, означающие майнинг.
  MINING_CODES: array[0..1] of string = (BL_MINING_STRINGS, BL_WALLET_STRINGS);

function IsMiningCode(const ACode: string): Boolean;
var
  LCode: string;
begin
  for LCode in MINING_CODES do
    if LCode = ACode then
      Exit(True);
  Result := False;
end;

function MHVerdictFromReport(const AReport: TMHBinaryReport): TMHBinaryVerdict;
var
  LAnomaly: TMHBinaryAnomaly;
  LWeight, LTotal: Integer;
  LSorted: TArray<TMHBinaryAnomaly>;
  I, J: Integer;
  LSwap: TMHBinaryAnomaly;
begin
  Result := Default(TMHBinaryVerdict);
  Result.Path := MHNormalizePath(AReport.Path);
  Result.Sha256 := AReport.Sha256.ToLower;
  Result.Score := AReport.Score;
  Result.Level := AReport.Level;
  Result.AnalyzedAtUtc := AReport.AnalyzedAtUtc;
  Result.Summary := AReport.Verdict;
  // Самые весомые — первыми, чтобы предел суммы отсекал слабые признаки.
  LSorted := Copy(AReport.Anomalies);
  for I := 0 to High(LSorted) - 1 do
    for J := I + 1 to High(LSorted) do
      if LSorted[J].Weight > LSorted[I].Weight then
      begin
        LSwap := LSorted[I];
        LSorted[I] := LSorted[J];
        LSorted[J] := LSwap;
      end;
  LTotal := 0;
  for LAnomaly in LSorted do
  begin
    if (LAnomaly.Severity < asMedium) or (LAnomaly.Weight <= 0) then
      Continue;
    LWeight := Max(1, Round(LAnomaly.Weight * 0.6));
    // Доверенная подпись: как и в оценке BinaryLab, вес вдвое меньше.
    if AReport.Signature.State = sgSignedTrusted then
      LWeight := Max(1, LWeight div 2);
    LWeight := Min(LWeight, MH_BINARYLAB_MAX_EVIDENCE_WEIGHT - LTotal);
    if LWeight <= 0 then
      Break;
    Inc(LTotal, LWeight);
    Result.Evidence := Result.Evidence + [TMHEvidence.Create('BINARYLAB:' + LAnomaly.Code,
      LAnomaly.Title + MHL(' (разбор файла в BinaryLab)', ' (BinaryLab file analysis)'), LWeight, LAnomaly.Details)];
    if IsMiningCode(LAnomaly.Code) then
      Result.MiningSignal := True
    else if LAnomaly.Severity = asHigh then
      Result.ThreatSignal := True;
  end;
  if Result.MiningSignal then
    Result.ThreatSignal := True;
end;

{ TMHBinaryVerdictStore }

constructor TMHBinaryVerdictStore.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FItems := TDictionary<string, TMHBinaryVerdict>.Create;
  FOrder := TList<string>.Create;
end;

destructor TMHBinaryVerdictStore.Destroy;
begin
  FOrder.Free;
  FItems.Free;
  FLock.Free;
  inherited;
end;

class function TMHBinaryVerdictStore.KeyOf(const APath: string): string;
begin
  Result := AnsiLowerCase(MHNormalizePath(APath));
end;

procedure TMHBinaryVerdictStore.Put(const AVerdict: TMHBinaryVerdict);
var
  LKey: string;
  LItem: TMHBinaryVerdict;
begin
  LKey := KeyOf(AVerdict.Path);
  if LKey = '' then
    Exit;
  LItem := AVerdict;
  LItem.Path := MHNormalizePath(AVerdict.Path);
  LItem.Sha256 := AVerdict.Sha256.ToLower;
  FLock.Enter;
  try
    if FItems.ContainsKey(LKey) then
      FOrder.Remove(LKey);
    FItems.AddOrSetValue(LKey, LItem);
    FOrder.Add(LKey);
    while FOrder.Count > MaxVerdicts do
    begin
      FItems.Remove(FOrder[0]);
      FOrder.Delete(0);
    end;
  finally
    FLock.Leave;
  end;
end;

function TMHBinaryVerdictStore.TryGet(const APath, ASha256: string; out AVerdict: TMHBinaryVerdict): Boolean;
var
  LKey: string;
begin
  AVerdict := Default(TMHBinaryVerdict);
  LKey := KeyOf(APath);
  if LKey = '' then
    Exit(False);
  FLock.Enter;
  try
    Result := FItems.TryGetValue(LKey, AVerdict);
  finally
    FLock.Leave;
  end;
  // Файл изменился после анализа — старые признаки к нему не относятся.
  if Result and (AVerdict.Sha256 <> '') and (ASha256 <> '') and not SameText(AVerdict.Sha256, ASha256) then
  begin
    AVerdict := Default(TMHBinaryVerdict);
    Result := False;
  end;
end;

function TMHBinaryVerdictStore.Count: Integer;
begin
  FLock.Enter;
  try
    Result := FItems.Count;
  finally
    FLock.Leave;
  end;
end;

procedure TMHBinaryVerdictStore.Clear;
begin
  FLock.Enter;
  try
    FItems.Clear;
    FOrder.Clear;
  finally
    FLock.Leave;
  end;
end;

end.
