unit MineHunter.Analysis.Acknowledge;

{
  «Проверено, не беспокоить»: пользователь отмечает находку проверенной, и она
  перестаёт быть тревогой, пока не изменится.

  Отпечаток находки — SHA-1 от ключа, пути и признаков. У сведений, которые
  меняются только при изменении системы (признаки вмешательства в защиту,
  автозапуск, диски, запуски), в отпечаток входят и наблюдаемые значения:
  новое исключение Defender, новое значение политики или новая запись
  автозапуска дают новый отпечаток — находка снова становится тревогой.
  У находок о нагрузке значения (проценты, минуты) меняются каждый цикл,
  поэтому в отпечаток входят только коды признаков.
  Рост уровня риска выше отмеченного тоже возвращает тревогу.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

/// Отпечаток содержимого находки (hex SHA-1).
function MHFindingFingerprint(const AFinding: TMHFinding): string;

/// Отмечена ли находка проверенной в нынешнем виде.
function MHIsAcknowledged(const AFinding: TMHFinding; const AAcks: TArray<TMHAcknowledgement>): Boolean;

/// Отметка для находки на текущий момент.
function MHAcknowledgementFor(const AFinding: TMHFinding; ANowUtc: TDateTime): TMHAcknowledgement;

/// Убирает находки, отмеченные проверенными.
function MHFilterAcknowledged(const AFindings: TMHFindings; const AAcks: TArray<TMHAcknowledgement>): TMHFindings;

implementation

uses
  System.Hash, System.Generics.Collections, System.Generics.Defaults;

function StableContent(const AKey: string): Boolean;
begin
  Result := AKey.StartsWith('tamper:') or AKey.StartsWith('autostart:') or AKey.StartsWith('disk:') or
    AKey.StartsWith('launch:');
end;

function MHFindingFingerprint(const AFinding: TMHFinding): string;
var
  LParts: TList<string>;
  LEvidence: TMHEvidence;
  LText: string;
begin
  LParts := TList<string>.Create;
  try
    for LEvidence in AFinding.Evidence do
      if StableContent(AFinding.Key) then
        LParts.Add(LEvidence.Code + '=' + LEvidence.Observed.ToLower)
      else
        LParts.Add(LEvidence.Code);
    // Порядок признаков не влияет на отпечаток.
    LParts.Sort(TComparer<string>.Construct(
      function(const A, B: string): Integer
      begin
        Result := CompareStr(A, B);
      end));
    LText := AFinding.Key.ToLower + #10 + AFinding.ImagePath.ToLower + #10 + string.Join(#10, LParts.ToArray);
  finally
    LParts.Free;
  end;
  Result := THashSHA1.GetHashString(LText);
end;

function MHIsAcknowledged(const AFinding: TMHFinding; const AAcks: TArray<TMHAcknowledgement>): Boolean;
var
  LAck: TMHAcknowledgement;
  LPrint: string;
begin
  if Length(AAcks) = 0 then
    Exit(False);
  LPrint := MHFindingFingerprint(AFinding);
  for LAck in AAcks do
    if SameText(LAck.Key, AFinding.Key) and SameText(LAck.Fingerprint, LPrint) and
       (AFinding.Level <= LAck.Level) then
      Exit(True);
  Result := False;
end;

function MHAcknowledgementFor(const AFinding: TMHFinding; ANowUtc: TDateTime): TMHAcknowledgement;
begin
  Result := Default(TMHAcknowledgement);
  Result.Key := AFinding.Key;
  Result.Fingerprint := MHFindingFingerprint(AFinding);
  Result.Level := AFinding.Level;
  Result.Title := AFinding.Title;
  Result.CreatedUtc := ANowUtc;
end;

function MHFilterAcknowledged(const AFindings: TMHFindings; const AAcks: TArray<TMHAcknowledgement>): TMHFindings;
var
  LFinding: TMHFinding;
begin
  if Length(AAcks) = 0 then
    Exit(AFindings);
  Result := nil;
  for LFinding in AFindings do
    if not MHIsAcknowledged(LFinding, AAcks) then
      Result := Result + [LFinding];
end;

end.
