unit MineHunter.BinaryLab.Diff;

{
  BinaryDiff: сравнение двух файлов.

  Сравниваются уже разобранные отчёты BinaryLab (заголовок PE, секции,
  импорт, экспорт, ресурсы, строки, подпись) и сами байты: оба файла читаются
  параллельно блоками, совпадение блоков даёт процент сходства и диапазоны
  изменённых байтов. Память — два буфера чтения, независимо от размера.

  Типичный сценарий: сравнить подозрительный файл с оригиналом той же
  версии — заражение или «патч» видно как изменённые секции, новый импорт,
  новые строки и изменённые блоки.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

const
  /// Предел элементов в одной области (импорт, строки…); дальше — Truncated.
  MH_DIFF_MAX_ITEMS_PER_AREA = 500;
  MH_DIFF_AREA_HEADER = 'header';
  MH_DIFF_AREA_SECTION = 'section';
  MH_DIFF_AREA_IMPORT = 'import';
  MH_DIFF_AREA_EXPORT = 'export';
  MH_DIFF_AREA_RESOURCE = 'resource';
  MH_DIFF_AREA_STRING = 'string';
  MH_DIFF_AREA_BLOCK = 'block';

/// Сравнивает файлы ALeft и ARight (отчёты и байты). ABlockSize = 0 — размер
/// блока подбирается (не больше AOptions.MaxEntropyBlocks блоков).
function MHCompareBinaries(const ALeft, ARight: TMHBinaryReport; const ALeftSource, ARightSource: IMHBinarySource;
  const AOptions: TMHBinaryLabOptions; const ACancel: TMHCancelCheck = nil; ABlockSize: Integer = 0): TMHBinaryDiff;

function MHDiffAreaTitle(const AArea: string): string;

implementation

uses
  System.Math, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Types, MineHunter.Core.Lang;

function MHDiffAreaTitle(const AArea: string): string;
begin
  if AArea = MH_DIFF_AREA_HEADER then
    Result := MHL('Заголовок', 'Header')
  else if AArea = MH_DIFF_AREA_SECTION then
    Result := MHL('Секция', 'Section')
  else if AArea = MH_DIFF_AREA_IMPORT then
    Result := MHL('Импорт', 'Import')
  else if AArea = MH_DIFF_AREA_EXPORT then
    Result := MHL('Экспорт', 'Export')
  else if AArea = MH_DIFF_AREA_RESOURCE then
    Result := MHL('Ресурс', 'Resource')
  else if AArea = MH_DIFF_AREA_STRING then
    Result := MHL('Строка', 'String')
  else if AArea = MH_DIFF_AREA_BLOCK then
    Result := MHL('Байты', 'Bytes')
  else
    Result := AArea;
end;

type
  TDiffBuilder = class
  private
    FItems: TList<TMHDiffItem>;
    FCounts: TDictionary<string, Integer>;
    FTruncated: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const AArea: string; AChange: TMHDiffChange; const AName, AOld, ANew: string);
    procedure Field(const AName, AOld, ANew: string);
    property Truncated: Boolean read FTruncated;
    property Items: TList<TMHDiffItem> read FItems;
  end;

constructor TDiffBuilder.Create;
begin
  inherited Create;
  FItems := TList<TMHDiffItem>.Create;
  FCounts := TDictionary<string, Integer>.Create;
end;

destructor TDiffBuilder.Destroy;
begin
  FCounts.Free;
  FItems.Free;
  inherited;
end;

procedure TDiffBuilder.Add(const AArea: string; AChange: TMHDiffChange; const AName, AOld, ANew: string);
var
  LCount: Integer;
  LItem: TMHDiffItem;
begin
  FCounts.TryGetValue(AArea, LCount);
  if LCount >= MH_DIFF_MAX_ITEMS_PER_AREA then
  begin
    FTruncated := True;
    Exit;
  end;
  FCounts.AddOrSetValue(AArea, LCount + 1);
  LItem.Area := AArea;
  LItem.Change := AChange;
  LItem.Name := AName;
  LItem.OldValue := AOld;
  LItem.NewValue := ANew;
  FItems.Add(LItem);
end;

procedure TDiffBuilder.Field(const AName, AOld, ANew: string);
begin
  if AOld <> ANew then
    Add(MH_DIFF_AREA_HEADER, dcChanged, AName, AOld, ANew);
end;

function SignatureText(const ASignature: TMHBinarySignature): string;
begin
  case ASignature.State of
    sgSignedTrusted:   Result := MHL('подписан: ', 'signed: ') + ASignature.Signer;
    sgSignedUntrusted: Result := MHL('подпись недействительна', 'invalid signature');
    sgUnsigned:        Result := MHL('без подписи', 'unsigned');
    sgCheckFailed:     Result := MHL('не удалось проверить', 'check failed');
  else
    Result := MHL('не проверялась', 'not checked');
  end;
end;

/// Ключи секций: имя, а для повторяющихся имён — «имя #2».
function SectionMap(const APe: TMHPeInfo): TDictionary<string, TMHPeSection>;
var
  LSection: TMHPeSection;
  LKey: string;
  LIndex: Integer;
begin
  Result := TDictionary<string, TMHPeSection>.Create;
  for LSection in APe.Sections do
  begin
    LKey := LSection.Name;
    LIndex := 1;
    while Result.ContainsKey(LKey) do
    begin
      Inc(LIndex);
      LKey := LSection.Name + ' #' + IntToStr(LIndex);
    end;
    Result.Add(LKey, LSection);
  end;
end;

function SectionText(const ASection: TMHPeSection): string;
begin
  Result := Format(MHL('%s, %s байт, %s, энтропия %.2f', '%s, %s bytes, %s, entropy %.2f'),
    [MHHexOffset(ASection.VirtualAddress), FormatFloat('#,##0', ASection.RawSize), ASection.AccessText,
     Max(0.0, ASection.Entropy)]);
end;

procedure CompareSets(ABuilder: TDiffBuilder; const AArea: string; const ALeft, ARight: TArray<string>);
var
  LLeft, LRight: TDictionary<string, Boolean>;
  LItem: string;
begin
  LLeft := TDictionary<string, Boolean>.Create;
  LRight := TDictionary<string, Boolean>.Create;
  try
    for LItem in ALeft do
      LLeft.AddOrSetValue(LItem, True);
    for LItem in ARight do
      LRight.AddOrSetValue(LItem, True);
    for LItem in ALeft do
      if not LRight.ContainsKey(LItem) then
      begin
        ABuilder.Add(AArea, dcRemoved, LItem, LItem, '');
        LRight.AddOrSetValue(LItem, True); // повторы не дублируются
      end;
    for LItem in ARight do
      if not LLeft.ContainsKey(LItem) then
      begin
        ABuilder.Add(AArea, dcAdded, LItem, '', LItem);
        LLeft.AddOrSetValue(LItem, True);
      end;
  finally
    LRight.Free;
    LLeft.Free;
  end;
end;

function ImportKeys(const APe: TMHPeInfo): TArray<string>;
var
  LImport: TMHPeImport;
  LFunction: string;
begin
  Result := nil;
  for LImport in APe.Imports do
    for LFunction in LImport.Functions do
      Result := Result + [LImport.Dll.ToLower + '!' + LFunction];
end;

function ExportKeys(const APe: TMHPeInfo): TArray<string>;
var
  LExport: TMHPeExport;
begin
  Result := nil;
  for LExport in APe.ExportedFunctions do
    if LExport.Name <> '' then
      Result := Result + [LExport.Name]
    else
      Result := Result + ['#' + IntToStr(LExport.Ordinal)];
end;

function StringKeys(const AReport: TMHBinaryReport): TArray<string>;
var
  LList: TList<string>;
  LItem: TMHBinaryString;
begin
  // Сначала строки-индикаторы: при пределе элементов важные изменения не теряются.
  LList := TList<string>.Create;
  try
    for LItem in AReport.Strings.Items do
      if LItem.Category <> scPlain then
        LList.Add(LItem.Text);
    for LItem in AReport.Strings.Items do
      if LItem.Category = scPlain then
        LList.Add(LItem.Text);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

procedure CompareResources(ABuilder: TDiffBuilder; const ALeft, ARight: TMHPeInfo);
var
  LLeft, LRight: TDictionary<string, TMHPeResource>;
  LResource, LOther: TMHPeResource;
  LKey: string;

  function KeyOf(const AResource: TMHPeResource): string;
  begin
    Result := Format('%s/%s/%d', [AResource.TypeName, AResource.Name, AResource.Language]);
  end;

  function TextOf(const AResource: TMHPeResource): string;
  begin
    Result := Format(MHL('%s байт, энтропия %.2f', '%s bytes, entropy %.2f'),
      [FormatFloat('#,##0', AResource.Size), Max(0.0, AResource.Entropy)]);
  end;

begin
  LLeft := TDictionary<string, TMHPeResource>.Create;
  LRight := TDictionary<string, TMHPeResource>.Create;
  try
    for LResource in ALeft.Resources do
      LLeft.AddOrSetValue(KeyOf(LResource), LResource);
    for LResource in ARight.Resources do
      LRight.AddOrSetValue(KeyOf(LResource), LResource);
    for LResource in ALeft.Resources do
    begin
      LKey := KeyOf(LResource);
      if not LRight.TryGetValue(LKey, LOther) then
        ABuilder.Add(MH_DIFF_AREA_RESOURCE, dcRemoved, LKey, TextOf(LResource), '')
      else if (LOther.Size <> LResource.Size) or (Abs(LOther.Entropy - LResource.Entropy) > 0.01) then
        ABuilder.Add(MH_DIFF_AREA_RESOURCE, dcChanged, LKey, TextOf(LResource), TextOf(LOther));
    end;
    for LResource in ARight.Resources do
    begin
      LKey := KeyOf(LResource);
      if not LLeft.ContainsKey(LKey) then
        ABuilder.Add(MH_DIFF_AREA_RESOURCE, dcAdded, LKey, '', TextOf(LResource));
    end;
  finally
    LRight.Free;
    LLeft.Free;
  end;
end;

procedure CompareSections(ABuilder: TDiffBuilder; const ALeft, ARight: TMHPeInfo);
var
  LLeft, LRight: TDictionary<string, TMHPeSection>;
  LKey: string;
  LSection, LOther: TMHPeSection;
  LKeys: TArray<string>;
begin
  LLeft := SectionMap(ALeft);
  LRight := SectionMap(ARight);
  try
    LKeys := LLeft.Keys.ToArray;
    TArray.Sort<string>(LKeys);
    for LKey in LKeys do
    begin
      LSection := LLeft[LKey];
      if not LRight.TryGetValue(LKey, LOther) then
        ABuilder.Add(MH_DIFF_AREA_SECTION, dcRemoved, LKey, SectionText(LSection), '')
      else if (LSection.RawSize <> LOther.RawSize) or (LSection.VirtualSize <> LOther.VirtualSize) or
        (LSection.Characteristics <> LOther.Characteristics) or (LSection.VirtualAddress <> LOther.VirtualAddress) or
        not SameText(LSection.Sha256, LOther.Sha256) then
        ABuilder.Add(MH_DIFF_AREA_SECTION, dcChanged, LKey, SectionText(LSection), SectionText(LOther));
    end;
    LKeys := LRight.Keys.ToArray;
    TArray.Sort<string>(LKeys);
    for LKey in LKeys do
      if not LLeft.ContainsKey(LKey) then
        ABuilder.Add(MH_DIFF_AREA_SECTION, dcAdded, LKey, '', SectionText(LRight[LKey]));
  finally
    LRight.Free;
    LLeft.Free;
  end;
end;

procedure CompareHeaders(ABuilder: TDiffBuilder; const ALeft, ARight: TMHBinaryReport);
var
  L, R: TMHPeInfo;
begin
  ABuilder.Field(MHL('Вид файла', 'File type'), ALeft.FileType.Description, ARight.FileType.Description);
  ABuilder.Field(MHL('Подпись', 'Signature'), SignatureText(ALeft.Signature), SignatureText(ARight.Signature));
  L := ALeft.Pe;
  R := ARight.Pe;
  if not (L.Valid and R.Valid) then
    Exit;
  ABuilder.Field(MHL('Архитектура', 'Architecture'), L.MachineName, R.MachineName);
  ABuilder.Field(MHL('Время сборки', 'Build time'), '0x' + IntToHex(L.TimeDateStamp, 8), '0x' + IntToHex(R.TimeDateStamp, 8));
  ABuilder.Field(MHL('Точка входа', 'Entry point'), MHHexOffset(L.EntryPointRva) + ' ' + L.EntryPointSection,
    MHHexOffset(R.EntryPointRva) + ' ' + R.EntryPointSection);
  ABuilder.Field(MHL('Базовый адрес', 'Image base'), '0x' + IntToHex(L.ImageBase, 8), '0x' + IntToHex(R.ImageBase, 8));
  ABuilder.Field(MHL('Размер образа', 'Image size'), MHHexOffset(L.SizeOfImage), MHHexOffset(R.SizeOfImage));
  ABuilder.Field(MHL('Подсистема', 'Subsystem'), L.SubsystemName, R.SubsystemName);
  ABuilder.Field(MHL('Характеристики', 'Characteristics'), '0x' + IntToHex(L.Characteristics, 4),
    '0x' + IntToHex(R.Characteristics, 4));
  ABuilder.Field('DllCharacteristics', '0x' + IntToHex(L.DllCharacteristics, 4), '0x' + IntToHex(R.DllCharacteristics, 4));
  ABuilder.Field(MHL('Контрольная сумма', 'Checksum'), '0x' + IntToHex(L.CheckSum, 8), '0x' + IntToHex(R.CheckSum, 8));
  ABuilder.Field(MHL('Число секций', 'Section count'), IntToStr(Length(L.Sections)), IntToStr(Length(R.Sections)));
  ABuilder.Field(MHL('Оверлей, байт', 'Overlay, bytes'), IntToStr(L.OverlaySize), IntToStr(R.OverlaySize));
  ABuilder.Field(MHL('Функций TLS', 'TLS callbacks'), IntToStr(L.TlsCallbackCount), IntToStr(R.TlsCallbackCount));
end;

procedure CompareBlocks(var ADiff: TMHBinaryDiff; ABuilder: TDiffBuilder; const ALeftSource, ARightSource: IMHBinarySource;
  const AOptions: TMHBinaryLabOptions; const ACancel: TMHCancelCheck; ABlockSize: Integer);
const
  CHUNK = 1024 * 1024;
var
  LMax, LLimit, LPos, LBlockStart, LRangeStart, LTotalBlocks, LEqualBlocks: Int64;
  LLeftBuf, LRightBuf: TBytes;
  LLeftCount, LRightCount, LInChunk, LBlockLen, I: Integer;
  LRanges: TList<TMHByteRange>;
  LRange: TMHByteRange;
  LChanged, LInRange: Boolean;

  procedure CloseRange(AEnd: Int64);
  begin
    LRange.Offset := LRangeStart;
    LRange.Size := AEnd - LRangeStart;
    LRanges.Add(LRange);
    Inc(ADiff.ChangedBytes, LRange.Size);
    LInRange := False;
  end;

begin
  LMax := Max(ALeftSource.Size, ARightSource.Size);
  LLimit := Min(LMax, AOptions.MaxScanBytes);
  if LLimit < LMax then
    ADiff.Truncated := True;
  if ABlockSize <= 0 then
  begin
    ABlockSize := 512;
    while (LLimit div ABlockSize > AOptions.MaxEntropyBlocks) and (ABlockSize < 16 * 1024 * 1024) do
      ABlockSize := ABlockSize * 2;
  end;
  // Блок целиком помещается в буфер чтения.
  ABlockSize := Min(ABlockSize, CHUNK);
  ADiff.BlockSize := ABlockSize;
  SetLength(LLeftBuf, CHUNK);
  SetLength(LRightBuf, CHUNK);
  LRanges := TList<TMHByteRange>.Create;
  try
    LTotalBlocks := 0;
    LEqualBlocks := 0;
    LInRange := False;
    LRangeStart := 0;
    LPos := 0;
    while LPos < LLimit do
    begin
      MHCheckCancel(ACancel);
      LInChunk := Integer(Min(Int64(CHUNK div ABlockSize * ABlockSize), LLimit - LPos));
      LLeftCount := ALeftSource.ReadAt(LPos, LLeftBuf[0], LInChunk);
      LRightCount := ARightSource.ReadAt(LPos, LRightBuf[0], LInChunk);
      I := 0;
      while I < LInChunk do
      begin
        LBlockStart := LPos + I;
        LBlockLen := Min(ABlockSize, LInChunk - I);
        // Блок изменён, если байты различаются или он есть только в одном файле.
        if (I + LBlockLen > LLeftCount) or (I + LBlockLen > LRightCount) then
          LChanged := True
        else
          LChanged := not CompareMem(@LLeftBuf[I], @LRightBuf[I], LBlockLen);
        Inc(LTotalBlocks);
        if LChanged then
        begin
          if not LInRange then
          begin
            LRangeStart := LBlockStart;
            LInRange := True;
          end;
        end
        else
        begin
          Inc(LEqualBlocks);
          if LInRange then
            CloseRange(LBlockStart);
        end;
        Inc(I, LBlockLen);
      end;
      Inc(LPos, LInChunk);
    end;
    if LInRange then
      CloseRange(LLimit);
    ADiff.ChangedRanges := LRanges.ToArray;
    if LTotalBlocks > 0 then
      ADiff.SimilarityPercent := LEqualBlocks * 100 / LTotalBlocks
    else
      ADiff.SimilarityPercent := 100;
    for LRange in LRanges do
      ABuilder.Add(MH_DIFF_AREA_BLOCK, dcChanged, MHHexOffset(LRange.Offset) + ' – ' +
        MHHexOffset(LRange.Offset + LRange.Size - 1), '', Format(MHL('%s байт', '%s bytes'),
        [FormatFloat('#,##0', LRange.Size)]));
  finally
    LRanges.Free;
  end;
end;

function MHCompareBinaries(const ALeft, ARight: TMHBinaryReport; const ALeftSource, ARightSource: IMHBinarySource;
  const AOptions: TMHBinaryLabOptions; const ACancel: TMHCancelCheck; ABlockSize: Integer): TMHBinaryDiff;
var
  LBuilder: TDiffBuilder;
  LOptions: TMHBinaryLabOptions;
var
  LHoldLeft, LHoldRight: IMHBinarySource;
begin
  // Ссылки на источники на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldLeft := ALeftSource;
  LHoldRight := ARightSource;
  if (ALeftSource = nil) or (ARightSource = nil) then
    raise EArgumentNilException.Create(MHL('Не заданы файлы для сравнения', 'Files to compare are not specified'));
  LOptions := AOptions.Normalized;
  Result := Default(TMHBinaryDiff);
  Result.LeftPath := ALeft.Path;
  Result.RightPath := ARight.Path;
  Result.LeftSize := ALeftSource.Size;
  Result.RightSize := ARightSource.Size;
  Result.LeftSha256 := ALeft.Sha256;
  Result.RightSha256 := ARight.Sha256;
  LBuilder := TDiffBuilder.Create;
  try
    CompareHeaders(LBuilder, ALeft, ARight);
    if ALeft.Pe.Valid and ARight.Pe.Valid then
    begin
      CompareSections(LBuilder, ALeft.Pe, ARight.Pe);
      CompareSets(LBuilder, MH_DIFF_AREA_IMPORT, ImportKeys(ALeft.Pe), ImportKeys(ARight.Pe));
      CompareSets(LBuilder, MH_DIFF_AREA_EXPORT, ExportKeys(ALeft.Pe), ExportKeys(ARight.Pe));
      CompareResources(LBuilder, ALeft.Pe, ARight.Pe);
    end;
    MHCheckCancel(ACancel);
    CompareSets(LBuilder, MH_DIFF_AREA_STRING, StringKeys(ALeft), StringKeys(ARight));
    CompareBlocks(Result, LBuilder, ALeftSource, ARightSource, LOptions, ACancel, ABlockSize);
    Result.Items := LBuilder.Items.ToArray;
    Result.Truncated := Result.Truncated or LBuilder.Truncated or ALeft.Strings.Truncated or ARight.Strings.Truncated;
    // Совпадение хешей доказывает идентичность и для файлов больше лимита сравнения.
    if (Result.LeftSha256 <> '') and (Result.RightSha256 <> '') then
      Result.Identical := (Result.LeftSize = Result.RightSize) and SameText(Result.LeftSha256, Result.RightSha256)
    else
      Result.Identical := (Result.LeftSize = Result.RightSize) and (Result.ChangedBytes = 0) and not Result.Truncated;
  finally
    LBuilder.Free;
  end;
end;

end.
