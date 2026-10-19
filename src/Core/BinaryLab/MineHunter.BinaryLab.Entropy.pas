unit MineHunter.BinaryLab.Entropy;

{
  Энтропия содержимого файла: по блокам, общая и гистограмма байтов.

  - Файл читается потоком (MHReadChunks), в памяти — один блок чтения и
    массив результатов по блокам энтропии; размер файла на память не влияет.
  - Размер блока подбирается так, чтобы блоков было не больше
    MaxEntropyBlocks (степень двойки, не меньше 256 байт).
  - Подряд идущие блоки высокой энтропии (сжатые или шифрованные данные)
    объединяются в области; короткие области (меньше 512 байт) не
    показываются — на таком объёме оценка энтропии ненадёжна.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

const
  /// Порог энтропии блока для областей высокой энтропии (сжатые данные и выше).
  MH_HIGH_ENTROPY_THRESHOLD = 6.8;
  /// Области высокой энтропии меньше этого размера не показываются.
  MH_MIN_HIGH_REGION_SIZE = 512;
  /// Наименьший подбираемый размер блока энтропии.
  MH_MIN_AUTO_ENTROPY_BLOCK = 256;

/// Энтропия первых AOptions.MaxScanBytes байт источника: блоки, гистограмма,
/// общая энтропия и области высокой энтропии. ALocate (если задана) — где
/// находится начало области. ACancel — EMHBinaryLabCancelled при отмене.
function MHAnalyzeEntropy(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ALocate: TMHLocateFunc; const ACancel: TMHCancelCheck): TMHEntropyInfo;

/// Энтропия диапазона [AOffset, AOffset + Min(ASize, AMaxBytes)), обрезанного
/// по концу файла. -1 — диапазон пуст или вне файла.
function MHRangeEntropy(const ASource: IMHBinarySource; AOffset, ASize: Int64;
  AMaxBytes: Int64 = 64 * 1024 * 1024): Double;

implementation

uses
  System.Math;

const
  READ_CHUNK = 1024 * 1024;
  /// Предел числа блоков при явно заданном размере блока: память под результат
  /// не должна зависеть от размера файла сверх разумного (16 байт на блок).
  MAX_EXPLICIT_BLOCKS = 1024 * 1024;

type
  TByteCounts = array[Byte] of Int64;

  /// Накопитель энтропии по блокам. Блок может начинаться в одном блоке
  /// чтения и заканчиваться в другом.
  TEntropyAccumulator = class
  private
    FBlockSize: Integer;
    FBlocks: TArray<TMHEntropyBlock>;
    FBlockCount: Integer;
    FCounts: TByteCounts;
    FFill: Integer;
    FBlockStart: Int64;
    FTotal: TByteCounts;
    FScanned: Int64;
    procedure CloseBlock;
  public
    constructor Create(ABlockSize: Integer; AExpectedBlocks: Int64);
    procedure Feed(ABase: Int64; const AData: TBytes; ACount: Integer);
    procedure Finish;
    property Blocks: TArray<TMHEntropyBlock> read FBlocks;
    property Scanned: Int64 read FScanned;
    /// Частоты байтов всех закрытых блоков.
    property Total: TByteCounts read FTotal;
  end;

{ TEntropyAccumulator }

constructor TEntropyAccumulator.Create(ABlockSize: Integer; AExpectedBlocks: Int64);
begin
  inherited Create;
  FBlockSize := ABlockSize;
  SetLength(FBlocks, Integer(EnsureRange(AExpectedBlocks, 0, MAX_EXPLICIT_BLOCKS)));
  FBlockCount := 0;
  FillChar(FCounts, SizeOf(FCounts), 0);
  FillChar(FTotal, SizeOf(FTotal), 0);
  FFill := 0;
  FBlockStart := 0;
  FScanned := 0;
end;

procedure TEntropyAccumulator.CloseBlock;
var
  I: Integer;
  LBlock: TMHEntropyBlock;
begin
  if FFill = 0 then
    Exit;
  LBlock.Offset := FBlockStart;
  LBlock.Size := FFill;
  LBlock.Entropy := MHShannonEntropy(FCounts, FFill);
  // Число блоков рассчитано заранее; запас — если источник отдал больше ожидаемого.
  if FBlockCount >= Length(FBlocks) then
    SetLength(FBlocks, Max(16, Length(FBlocks) * 2));
  FBlocks[FBlockCount] := LBlock;
  Inc(FBlockCount);
  for I := Low(FCounts) to High(FCounts) do
    Inc(FTotal[I], FCounts[I]);
  FillChar(FCounts, SizeOf(FCounts), 0);
  FBlockStart := FBlockStart + FFill;
  FFill := 0;
end;

procedure TEntropyAccumulator.Feed(ABase: Int64; const AData: TBytes; ACount: Integer);
var
  LPos, LTake, I: Integer;
begin
  if FScanned = 0 then
    FBlockStart := ABase;
  LPos := 0;
  while LPos < ACount do
  begin
    LTake := Min(ACount - LPos, FBlockSize - FFill);
    for I := LPos to LPos + LTake - 1 do
      Inc(FCounts[AData[I]]);
    Inc(FFill, LTake);
    Inc(LPos, LTake);
    if FFill >= FBlockSize then
      CloseBlock;
  end;
  Inc(FScanned, ACount);
end;

procedure TEntropyAccumulator.Finish;
begin
  CloseBlock;
  SetLength(FBlocks, FBlockCount);
end;

{ Функции }

function ChooseBlockSize(const AOptions: TMHBinaryLabOptions; ALimit: Int64): Integer;
var
  LMaxBlocks: Int64;
begin
  if AOptions.EntropyBlockSize > 0 then
  begin
    Result := AOptions.EntropyBlockSize;
    LMaxBlocks := MAX_EXPLICIT_BLOCKS;
  end
  else
  begin
    Result := MH_MIN_AUTO_ENTROPY_BLOCK;
    LMaxBlocks := AOptions.MaxEntropyBlocks;
  end;
  // Удваиваем, пока блоков больше допустимого (размер блока не больше 1 ГБ).
  while ((ALimit + Result - 1) div Result > LMaxBlocks) and (Result < 1024 * 1024 * 1024) do
    Result := Result * 2;
end;

function BuildHighRegions(const ABlocks: TArray<TMHEntropyBlock>;
  const ALocate: TMHLocateFunc): TArray<TMHEntropyRegion>;
var
  LCount, I: Integer;
  LInRegion: Boolean;
  LRegion: TMHEntropyRegion;
  LWeighted: Double;

  procedure CloseRegion;
  begin
    if LInRegion and (LRegion.Size >= MH_MIN_HIGH_REGION_SIZE) then
    begin
      LRegion.AverageEntropy := LWeighted / LRegion.Size;
      LRegion.EntropyClass := MHEntropyClassOf(LRegion.AverageEntropy);
      if Assigned(ALocate) then
        LRegion.Location := ALocate(LRegion.Offset)
      else
        LRegion.Location := '';
      if LCount >= Length(Result) then
        SetLength(Result, Max(8, Length(Result) * 2));
      Result[LCount] := LRegion;
      Inc(LCount);
    end;
    LInRegion := False;
  end;

begin
  Result := nil;
  LCount := 0;
  LInRegion := False;
  LRegion := Default(TMHEntropyRegion);
  LWeighted := 0;
  for I := 0 to High(ABlocks) do
  begin
    if ABlocks[I].Entropy >= MH_HIGH_ENTROPY_THRESHOLD then
    begin
      // Блоки идут подряд по смещениям; разрыв (короткое чтение) закрывает область.
      if LInRegion and (LRegion.Offset + LRegion.Size <> ABlocks[I].Offset) then
        CloseRegion;
      if not LInRegion then
      begin
        LInRegion := True;
        LRegion := Default(TMHEntropyRegion);
        LRegion.Offset := ABlocks[I].Offset;
        LWeighted := 0;
      end;
      Inc(LRegion.Size, ABlocks[I].Size);
      LWeighted := LWeighted + Double(ABlocks[I].Entropy) * ABlocks[I].Size;
    end
    else
      CloseRegion;
  end;
  CloseRegion;
  SetLength(Result, LCount);
end;

function MHAnalyzeEntropy(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ALocate: TMHLocateFunc; const ACancel: TMHCancelCheck): TMHEntropyInfo;
var
  LOptions: TMHBinaryLabOptions;
  LLimit: Int64;
  LAccumulator: TEntropyAccumulator;
  LTotal: TByteCounts;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := Default(TMHEntropyInfo);
  LOptions := AOptions.Normalized;
  if ASource = nil then
    LLimit := 0
  else
    LLimit := Min(Max(Int64(0), ASource.Size), LOptions.MaxScanBytes);
  Result.BlockSize := ChooseBlockSize(LOptions, LLimit);
  if LLimit = 0 then
    Exit;
  LAccumulator := TEntropyAccumulator.Create(Result.BlockSize, (LLimit + Result.BlockSize - 1) div Result.BlockSize);
  try
    MHReadChunks(ASource, 0, LLimit, READ_CHUNK, 0,
      function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
      begin
        LAccumulator.Feed(ABase, AData, ACount);
        Result := True;
      end, ACancel);
    LAccumulator.Finish;
    Result.Blocks := LAccumulator.Blocks;
    Result.BytesScanned := LAccumulator.Scanned;
    LTotal := LAccumulator.Total;
    Move(LTotal, Result.Histogram, SizeOf(Result.Histogram));
  finally
    LAccumulator.Free;
  end;
  Result.Overall := MHShannonEntropy(Result.Histogram, Result.BytesScanned);
  Result.HighRegions := BuildHighRegions(Result.Blocks, ALocate);
end;

function MHRangeEntropy(const ASource: IMHBinarySource; AOffset, ASize: Int64; AMaxBytes: Int64): Double;
var
  LCount: Int64;
  LCounts: TByteCounts;
  LTotal: Int64;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := -1;
  if (ASource = nil) or (AOffset < 0) or (ASize <= 0) or (AMaxBytes <= 0) or (AOffset >= ASource.Size) then
    Exit;
  LCount := Min(Min(ASize, AMaxBytes), ASource.Size - AOffset);
  if LCount <= 0 then
    Exit;
  FillChar(LCounts, SizeOf(LCounts), 0);
  LTotal := 0;
  MHReadChunks(ASource, AOffset, LCount, READ_CHUNK, 0,
    function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
    var
      I: Integer;
    begin
      for I := 0 to ACount - 1 do
        Inc(LCounts[AData[I]]);
      Inc(LTotal, ACount);
      Result := True;
    end);
  if LTotal > 0 then
    Result := MHShannonEntropy(LCounts, LTotal);
end;

end.
