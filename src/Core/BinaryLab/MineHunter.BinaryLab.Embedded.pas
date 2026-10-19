unit MineHunter.BinaryLab.Embedded;

{
  Поиск вложенных объектов внутри файла: исполняемые файлы, архивы,
  документы, изображения и фрагменты сценариев.

  - Смещение 0 — сам файл, оно не проверяется: ищутся объекты внутри.
  - Каждая позиция сначала проверяется по таблице первых байтов и коротким
    префиксам сигнатур (дёшево), затем подтверждается MHIdentifyAt в строгом
    режиме: случайные «MZ», «PK» и текст объектами не считаются.
  - Внутри найденного объекта известного размера поиск не ведётся (части
    того же объекта не дублируются). Размер берётся из заголовка и потому
    недоверенный: если объект «выходит» за конец файла, пропуск не делается,
    чтобы поддельный заголовок не скрывал остальную часть файла.
  - Фрагменты сценариев — не чаще одного на окно 4 КБ.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

/// Вложенные объекты в позициях 1..AOptions.MaxScanBytes - 1, по возрастанию смещения,
/// не больше AOptions.MaxEmbedded. ALocate (если задана) — где находится объект.
/// ACancel — EMHBinaryLabCancelled при отмене.
function MHFindEmbedded(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ALocate: TMHLocateFunc; const ACancel: TMHCancelCheck): TArray<TMHEmbeddedObject>;

const
  /// Не больше одного фрагмента сценария в окне такого размера.
  MH_SCRIPT_WINDOW = 4096;
  /// Сколько символов строки сценария попадает в описание.
  MH_SCRIPT_SNIPPET = 60;

implementation

uses
  System.Math, System.Generics.Collections,
  MineHunter.Core.Lang, MineHunter.BinaryLab.FileType;

const
  READ_CHUNK = 1024 * 1024;
  /// Перекрытие блоков чтения и запас просмотра вперёд: самый длинный
  /// маркер сценария и префикс сигнатуры должны целиком лежать в блоке.
  LOOKAHEAD = 64;

  FIRST_BINARY = 1;
  FIRST_SCRIPT = 2;

  SCRIPT_MARKERS: TArray<string> = ['<script', '#!/bin/', '@echo off', 'powershell -', 'powershell.exe -',
    'iex(', 'invoke-expression', 'set-executionpolicy', 'wscript.shell', 'createobject("wscript'];

type
  TFirstByteTable = array[Byte] of Byte;

  TEmbeddedScanner = class
  private
    FReader: TMHBinaryReader;
    FLocate: TMHLocateFunc;
    FFirst: TFirstByteTable;
    FMarkers: TArray<TBytes>;
    FMaxObjects: Integer;
    FEnd: Int64;
    FFileSize: Int64;
    FNext: Int64;
    FLastScript: Int64;
    FJumped: Boolean;
    FFound: TList<TMHEmbeddedObject>;
    function QuickBinary(const AData: TBytes; AIndex, AAvailable: Integer): Boolean;
    function MatchScript(const AData: TBytes; AIndex, AAvailable: Integer): Boolean;
    function ScriptSnippet(AOffset: Int64): string;
    procedure AddObject(AOffset, ASize: Int64; AKind: TMHBinaryKind; const ADescription: string);
  public
    constructor Create(const ASource: IMHBinarySource; AEnd: Int64; AMaxObjects: Integer;
      const ALocate: TMHLocateFunc);
    destructor Destroy; override;
    /// False — прекратить чтение (лимит объектов или переход за пределы блока).
    function Process(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean;
    function Full: Boolean;
    property Next: Int64 read FNext;
    property Jumped: Boolean read FJumped write FJumped;
    property Found: TList<TMHEmbeddedObject> read FFound;
  end;

function LowerAscii(AByte: Byte): Byte; inline;
begin
  if (AByte >= Ord('A')) and (AByte <= Ord('Z')) then
    Result := AByte + 32
  else
    Result := AByte;
end;

{ TEmbeddedScanner }

constructor TEmbeddedScanner.Create(const ASource: IMHBinarySource; AEnd: Int64; AMaxObjects: Integer;
  const ALocate: TMHLocateFunc);
const
  BINARY_FIRST: array[0..13] of Byte = ($4D, $50, $52, $37, $1F, $D0, $25, $89, $FF, $47, $7F, $FE, $CE, $CF);
var
  I, J: Integer;
  LMarker: string;
begin
  inherited Create;
  FReader := TMHBinaryReader.Create(ASource);
  FFound := TList<TMHEmbeddedObject>.Create;
  FLocate := ALocate;
  FMaxObjects := AMaxObjects;
  FEnd := AEnd;
  FFileSize := ASource.Size;
  FNext := 1;
  FLastScript := -MH_SCRIPT_WINDOW;
  FillChar(FFirst, SizeOf(FFirst), 0);
  for I := Low(BINARY_FIRST) to High(BINARY_FIRST) do
    FFirst[BINARY_FIRST[I]] := FFirst[BINARY_FIRST[I]] or FIRST_BINARY;
  SetLength(FMarkers, Length(SCRIPT_MARKERS));
  for I := 0 to High(SCRIPT_MARKERS) do
  begin
    LMarker := SCRIPT_MARKERS[I];
    SetLength(FMarkers[I], Length(LMarker));
    for J := 1 to Length(LMarker) do
      FMarkers[I][J - 1] := Byte(Ord(LMarker[J]));
    // Маркеры в нижнем регистре; первый байт — в обоих регистрах.
    FFirst[FMarkers[I][0]] := FFirst[FMarkers[I][0]] or FIRST_SCRIPT;
    if (FMarkers[I][0] >= Ord('a')) and (FMarkers[I][0] <= Ord('z')) then
      FFirst[FMarkers[I][0] - 32] := FFirst[FMarkers[I][0] - 32] or FIRST_SCRIPT;
  end;
end;

destructor TEmbeddedScanner.Destroy;
begin
  FFound.Free;
  FReader.Free;
  inherited;
end;

function TEmbeddedScanner.Full: Boolean;
begin
  Result := FFound.Count >= FMaxObjects;
end;

function TEmbeddedScanner.QuickBinary(const AData: TBytes; AIndex, AAvailable: Integer): Boolean;

  function Has(const ABytes: array of Byte): Boolean;
  var
    K: Integer;
  begin
    if Length(ABytes) > AAvailable then
      Exit(False);
    for K := 0 to High(ABytes) do
      if AData[AIndex + K] <> ABytes[K] then
        Exit(False);
    Result := True;
  end;

begin
  // Короткие префиксы сигнатур из блока; полная проверка — MHIdentifyAt.
  case AData[AIndex] of
    $4D: Result := Has([$4D, $5A]) or Has([$4D, $53, $43, $46]);
    $50: Result := Has([$50, $4B, $03, $04]);
    $52: Result := Has([$52, $61, $72, $21]);
    $37: Result := Has([$37, $7A, $BC, $AF]);
    $1F: Result := Has([$1F, $8B, $08]);
    $D0: Result := Has([$D0, $CF, $11, $E0]);
    $25: Result := Has([$25, $50, $44, $46, $2D]);
    $89: Result := Has([$89, $50, $4E, $47]);
    $FF: Result := Has([$FF, $D8, $FF]);
    $47: Result := Has([$47, $49, $46, $38]);
    $7F: Result := Has([$7F, $45, $4C, $46]);
    $FE: Result := Has([$FE, $ED, $FA]);
    $CE, $CF: Result := Has([AData[AIndex], $FA, $ED, $FE]);
  else
    Result := False;
  end;
end;

function TEmbeddedScanner.MatchScript(const AData: TBytes; AIndex, AAvailable: Integer): Boolean;
var
  I, K: Integer;
  LFirst: Byte;
  LMatch: Boolean;
begin
  LFirst := LowerAscii(AData[AIndex]);
  for I := 0 to High(FMarkers) do
  begin
    if (FMarkers[I][0] <> LFirst) or (Length(FMarkers[I]) > AAvailable) then
      Continue;
    LMatch := True;
    for K := 1 to High(FMarkers[I]) do
      if LowerAscii(AData[AIndex + K]) <> FMarkers[I][K] then
      begin
        LMatch := False;
        Break;
      end;
    if LMatch then
      Exit(True);
  end;
  Result := False;
end;

function TEmbeddedScanner.ScriptSnippet(AOffset: Int64): string;
var
  LBytes: TBytes;
  LBuilder: TStringBuilder;
  I: Integer;
begin
  LBytes := FReader.ReadBytes(AOffset, MH_SCRIPT_SNIPPET);
  LBuilder := TStringBuilder.Create(MH_SCRIPT_SNIPPET);
  try
    for I := 0 to High(LBytes) do
    begin
      if LBytes[I] in [0, 10, 13] then
        Break;
      if (LBytes[I] >= $20) and (LBytes[I] < $7F) then
        LBuilder.Append(Char(LBytes[I]))
      else if LBytes[I] = 9 then
        LBuilder.Append(' ')
      else
        LBuilder.Append('?');
    end;
    Result := LBuilder.ToString.Trim;
  finally
    LBuilder.Free;
  end;
end;

procedure TEmbeddedScanner.AddObject(AOffset, ASize: Int64; AKind: TMHBinaryKind; const ADescription: string);
var
  LObject: TMHEmbeddedObject;
begin
  LObject.Offset := AOffset;
  LObject.Size := ASize;
  LObject.Kind := AKind;
  LObject.Description := ADescription;
  if Assigned(FLocate) then
    LObject.Location := FLocate(AOffset)
  else
    LObject.Location := '';
  FFound.Add(LObject);
end;

function TEmbeddedScanner.Process(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean;
var
  LFinal: Boolean;
  LIndex, LStop, LAvailable: Integer;
  LFlags: Byte;
  LOffset, LSize: Int64;
  LKind: TMHBinaryKind;
  LDescription: string;
begin
  Result := True;
  LFinal := ABase + ACount >= FEnd;
  // Последние LOOKAHEAD байт блока проверяются в следующем блоке (перекрытие),
  // кроме последнего блока — там данных дальше нет.
  if LFinal then
    LStop := Integer(Min(Int64(ACount), FEnd - ABase))
  else
    LStop := ACount - LOOKAHEAD;
  if FNext - ABase >= LStop then
    Exit;
  LIndex := Integer(Max(Int64(0), FNext - ABase));
  while LIndex < LStop do
  begin
    LFlags := FFirst[AData[LIndex]];
    if LFlags <> 0 then
    begin
      LOffset := ABase + LIndex;
      LAvailable := ACount - LIndex;
      if (LFlags and FIRST_BINARY <> 0) and QuickBinary(AData, LIndex, LAvailable) and
         MHIdentifyAt(FReader, LOffset, True, LKind, LDescription, LSize) then
      begin
        AddObject(LOffset, LSize, LKind, LDescription);
        if Full then
        begin
          FNext := FEnd;
          Exit(False);
        end;
        // Внутрь объекта известного размера не заглядываем — если размер правдоподобен.
        if (LSize > 0) and (LSize <= FFileSize - LOffset) then
        begin
          FNext := LOffset + LSize;
          if FNext >= ABase + LStop then
          begin
            // Переход за пределы блока: чтение продолжится с нового места.
            FJumped := FNext < FEnd;
            Exit(False);
          end;
          LIndex := Integer(FNext - ABase);
          Continue;
        end;
      end
      else if (LFlags and FIRST_SCRIPT <> 0) and (LOffset - FLastScript >= MH_SCRIPT_WINDOW) and
        MatchScript(AData, LIndex, LAvailable) then
      begin
        AddObject(LOffset, -1, bkScript, MHL('Фрагмент сценария: ', 'Script fragment: ') + ScriptSnippet(LOffset));
        FLastScript := LOffset;
        if Full then
        begin
          FNext := FEnd;
          Exit(False);
        end;
      end;
    end;
    Inc(LIndex);
  end;
  FNext := ABase + LStop;
end;

{ Функции }

function MHFindEmbedded(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ALocate: TMHLocateFunc; const ACancel: TMHCancelCheck): TArray<TMHEmbeddedObject>;
var
  LOptions: TMHBinaryLabOptions;
  LEnd: Int64;
  LScanner: TEmbeddedScanner;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := nil;
  if ASource = nil then
    Exit;
  LOptions := AOptions.Normalized;
  LEnd := Min(ASource.Size, LOptions.MaxScanBytes);
  if (LEnd <= 1) or (LOptions.MaxEmbedded <= 0) then
    Exit;
  LScanner := TEmbeddedScanner.Create(ASource, LEnd, LOptions.MaxEmbedded, ALocate);
  try
    // После пропуска объекта чтение начинается заново с его конца.
    repeat
      LScanner.Jumped := False;
      MHReadChunks(ASource, LScanner.Next, LEnd - LScanner.Next, READ_CHUNK, LOOKAHEAD,
        function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
        begin
          Result := LScanner.Process(ABase, AData, ACount);
        end, ACancel);
    until not LScanner.Jumped or LScanner.Full or (LScanner.Next >= LEnd);
    // Смещения возрастают по построению: позиции просматриваются по порядку.
    Result := LScanner.Found.ToArray;
  finally
    LScanner.Free;
  end;
end;

end.
