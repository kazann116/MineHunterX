unit MineHunter.Tests.BinaryLab.Api;

{
  BinaryLab: вспомогательные функции публичного API — поиск байтов и разбор
  шаблонов, проверка отмены, чтение структур, названия и имена перечислений,
  расширения, архитектуры, подсистемы, флаги и поиск секций, сохранение
  сравнения. Каждая функция — с граничными и ошибочными случаями.
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabApiTests = class
  public
    [Test] procedure FindBytes_FoundCaseLimitAndBoundary;
    [Test] procedure FindBytes_EdgeAndErrorCases;
    [Test] procedure ParseHexPattern_ValidAndInvalid;
    [Test] procedure TextPattern_AsciiAndUtf16;
    [Test] procedure CheckCancel_NilFalseTrue;
    [Test] procedure Reader_TryReadCacheAndLargeReads;
    [Test] procedure EnumTitlesAndNames_AllValuesDistinct;
    [Test] procedure MachineSubsystemAndPeKindNames;
    [Test] procedure Extensions_ExpectedAndInList;
    [Test] procedure Sections_FlagsFindAndRva;
    [Test] procedure DiffTitles_AndSaveDiff;
    [Test] procedure Report_HasAnomalyAndDiffCountOf;
    [Test] procedure Checksum_EmptyTinyFieldOutsideAndCancel;
    [Test] procedure Options_NormalizedLimitsBothSides;
    [Test] procedure Histogram_BarFractionEdges;
    [Test] procedure HexView_OffsetDigitsAtFourGigabytes;
    [Test] procedure EntropyMap_BlockCountEmptyAndData;
  end;

implementation

uses
  System.IOUtils, System.Generics.Collections, System.JSON, System.Math,
  MineHunter.BinaryLab.FileType, MineHunter.BinaryLab.Pe, MineHunter.BinaryLab.Diff,
  MineHunter.BinaryLab.Report, MineHunter.App.BinaryLab.Controls, MineHunter.Tests.PeBuilder;

type
  /// Источник заданного размера из нулевых байтов (файлы больше 4 ГБ без диска).
  TSizedSource = class(TInterfacedObject, IMHBinarySource)
  private
    FSize: Int64;
  public
    constructor Create(ASize: Int64);
    function GetSize: Int64;
    function GetName: string;
    function ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
  end;

constructor TSizedSource.Create(ASize: Int64);
begin
  inherited Create;
  FSize := ASize;
end;

function TSizedSource.GetSize: Int64;
begin
  Result := FSize;
end;

function TSizedSource.GetName: string;
begin
  Result := 'sized';
end;

function TSizedSource.ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
begin
  Result := 0;
  if (ACount <= 0) or (AOffset < 0) or (AOffset >= FSize) then
    Exit;
  Result := Integer(Min(Int64(ACount), FSize - AOffset));
  FillChar(ABuffer, Result, 0);
end;

{ TBinaryLabApiTests }

procedure TBinaryLabApiTests.FindBytes_FoundCaseLimitAndBoundary;
var
  LData: TBytes;
  LSource: IMHBinarySource;
begin
  // Шаблон ровно на границе блока чтения (1 МБ) и ещё один дальше.
  LData := TestRandomBytes(3 * 1024 * 1024);
  FillChar(LData[1024 * 1024 - 3], 8, 0);
  Move(TestAscii('NeedleXY')[0], LData[1024 * 1024 - 3], 8);
  Move(TestAscii('needlexy')[0], LData[2 * 1024 * 1024 + 100], 8);
  LSource := TMHBytesSource.Create(LData);
  Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('NeedleXY'), 0), 'На границе блока');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 1024 * 1024),
    'С учётом регистра «needlexy» не совпадает');
  Assert.AreEqual<Int64>(2 * 1024 * 1024 + 100, MHFindBytes(LSource, TestAscii('NeedleXY'), 1024 * 1024, True),
    'Без учёта регистра — второе вхождение');
  Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('nEEDLExy'), 0, True), 'Без учёта регистра');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1000), 'Лимит просмотра');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1024 * 1024 + 4),
    'Шаблон не помещается в лимит');
  Assert.AreEqual<Int64>(1024 * 1024 - 3, MHFindBytes(LSource, TestAscii('NeedleXY'), 0, False, nil, 1024 * 1024 + 5));
end;

procedure TBinaryLabApiTests.FindBytes_EdgeAndErrorCases;
var
  LSource: IMHBinarySource;
begin
  LSource := TMHBytesSource.Create(TestAscii('abcabc'));
  Assert.AreEqual<Int64>(0, MHFindBytes(LSource, TestAscii('abc'), 0));
  Assert.AreEqual<Int64>(3, MHFindBytes(LSource, TestAscii('abc'), 1));
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('abc'), 4), 'Хвост короче шаблона');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('abcabcx'), 0), 'Шаблон длиннее данных');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, nil, 0), 'Пустой шаблон');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('a'), 6), 'Начало за концом');
  Assert.AreEqual<Int64>(-1, MHFindBytes(LSource, TestAscii('a'), -1), 'Отрицательное начало');
  Assert.AreEqual<Int64>(-1, MHFindBytes(nil, TestAscii('a'), 0), 'Нет источника');
  Assert.AreEqual<Int64>(-1, MHFindBytes(TMHBytesSource.Create(nil), TestAscii('a'), 0), 'Пустой источник');
  Assert.AreEqual<Int64>(5, MHFindBytes(LSource, TestAscii('c'), 5), 'Последний байт');
  Assert.WillRaise(
    procedure
    begin
      MHFindBytes(TMHBytesSource.Create(TestRandomBytes(100000)), TestAscii('zzzzzz'), 0, False,
        function: Boolean
        begin
          Result := True;
        end);
    end, EMHBinaryLabCancelled);
end;

procedure TBinaryLabApiTests.ParseHexPattern_ValidAndInvalid;
var
  LPattern: TBytes;
begin
  Assert.IsTrue(MHParseHexPattern('4D 5A 90', LPattern));
  Assert.AreEqual(3, Integer(Length(LPattern)));
  Assert.AreEqual<Byte>($90, LPattern[2]);
  Assert.IsTrue(MHParseHexPattern('4d5a', LPattern));
  Assert.AreEqual<Byte>($5A, LPattern[1]);
  Assert.IsTrue(MHParseHexPattern('0x4D,0x5A', LPattern));
  Assert.AreEqual(2, Integer(Length(LPattern)));
  Assert.IsTrue(MHParseHexPattern('de-ad:be'#9'ef', LPattern), 'Разделители');
  Assert.AreEqual(4, Integer(Length(LPattern)));
  Assert.IsFalse(MHParseHexPattern('', LPattern), 'Пусто');
  Assert.AreEqual(0, Integer(Length(LPattern)));
  Assert.IsFalse(MHParseHexPattern('   ', LPattern), 'Только пробелы');
  Assert.IsFalse(MHParseHexPattern('4D 5', LPattern), 'Нечётное число цифр');
  Assert.IsFalse(MHParseHexPattern('4G', LPattern), 'Не шестнадцатеричная цифра');
  Assert.IsFalse(MHParseHexPattern('MZ', LPattern), 'Текст вместо байтов');
end;

procedure TBinaryLabApiTests.TextPattern_AsciiAndUtf16;
var
  LPattern: TBytes;
begin
  LPattern := MHTextPattern('Ab', False);
  Assert.AreEqual(2, Integer(Length(LPattern)));
  Assert.AreEqual<Byte>(Ord('A'), LPattern[0]);
  LPattern := MHTextPattern('Яb', False);
  Assert.AreEqual<Byte>(Ord('?'), LPattern[0], 'Не ASCII — «?»');
  LPattern := MHTextPattern('Яb', True);
  Assert.AreEqual(4, Integer(Length(LPattern)));
  Assert.AreEqual<Byte>($2F, LPattern[0]);
  Assert.AreEqual<Byte>($04, LPattern[1]);
  Assert.AreEqual(0, Integer(Length(MHTextPattern('', False))));
  Assert.AreEqual(0, Integer(Length(MHTextPattern('', True))));
end;

procedure TBinaryLabApiTests.CheckCancel_NilFalseTrue;
begin
  MHCheckCancel(nil);
  MHCheckCancel(
    function: Boolean
    begin
      Result := False;
    end);
  Assert.WillRaise(
    procedure
    begin
      MHCheckCancel(
        function: Boolean
        begin
          Result := True;
        end);
    end, EMHBinaryLabCancelled);
  Assert.IsTrue(EMHBinaryLabCancelled.InheritsFrom(EMHBinaryLabError), 'Отмена — разновидность ошибки BinaryLab');
end;

procedure TBinaryLabApiTests.Reader_TryReadCacheAndLargeReads;
var
  LData, LBuffer: TBytes;
  LReader: TMHBinaryReader;
begin
  LData := TestRandomBytes(200000);
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(LData));
  try
    // Мелкие чтения из кэша, крупное — мимо кэша, чтение через границу окна кэша.
    SetLength(LBuffer, 16);
    Assert.IsTrue(LReader.TryRead(10, LBuffer[0], 16));
    Assert.IsTrue(CompareMem(@LData[10], @LBuffer[0], 16));
    Assert.IsTrue(LReader.TryRead(65536 - 8, LBuffer[0], 16), 'Через границу окна кэша');
    Assert.IsTrue(CompareMem(@LData[65536 - 8], @LBuffer[0], 16));
    SetLength(LBuffer, 100000);
    Assert.IsTrue(LReader.TryRead(50000, LBuffer[0], 100000), 'Крупное чтение');
    Assert.IsTrue(CompareMem(@LData[50000], @LBuffer[0], 100000));
    Assert.IsFalse(LReader.TryRead(150000, LBuffer[0], 100000), 'Частично за концом');
    Assert.IsTrue(LReader.TryRead(200000, LBuffer[0], 0), 'Нулевая длина у конца');
    Assert.IsFalse(LReader.TryRead(200001, LBuffer[0], 0), 'Нулевая длина за концом');
    Assert.IsFalse(LReader.TryRead(0, LBuffer[0], -1), 'Отрицательная длина');
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabApiTests.EnumTitlesAndNames_AllValuesDistinct;
var
  LNames: TDictionary<string, Boolean>;
  LKind: TMHBinaryKind;
  LCategory: TMHStringCategory;
  LSeverity: TMHAnomalySeverity;
  LClass: TMHEntropyClass;
  LChange: TMHDiffChange;
  LName: string;
begin
  LNames := TDictionary<string, Boolean>.Create;
  try
    for LKind := Low(TMHBinaryKind) to High(TMHBinaryKind) do
    begin
      Assert.IsTrue(MHBinaryKindTitle(LKind) <> '');
      LName := MHBinaryKindToName(LKind);
      Assert.IsFalse(LNames.ContainsKey(LName), 'Имена вида различаются: ' + LName);
      LNames.Add(LName, True);
    end;
    LNames.Clear;
    for LCategory := Low(TMHStringCategory) to High(TMHStringCategory) do
    begin
      Assert.IsTrue(MHStringCategoryTitle(LCategory) <> '');
      LName := MHStringCategoryToName(LCategory);
      Assert.IsFalse(LNames.ContainsKey(LName), LName);
      LNames.Add(LName, True);
    end;
    LNames.Clear;
    for LSeverity := Low(TMHAnomalySeverity) to High(TMHAnomalySeverity) do
    begin
      Assert.IsTrue(MHAnomalySeverityTitle(LSeverity) <> '');
      LName := MHAnomalySeverityToName(LSeverity);
      Assert.IsFalse(LNames.ContainsKey(LName), LName);
      LNames.Add(LName, True);
    end;
    LNames.Clear;
    for LClass := Low(TMHEntropyClass) to High(TMHEntropyClass) do
    begin
      LName := MHEntropyClassTitle(LClass);
      Assert.IsFalse(LNames.ContainsKey(LName), LName);
      LNames.Add(LName, True);
    end;
    LNames.Clear;
    for LChange := Low(TMHDiffChange) to High(TMHDiffChange) do
    begin
      Assert.IsTrue(MHDiffChangeTitle(LChange) <> '');
      LName := MHDiffChangeToName(LChange);
      Assert.IsFalse(LNames.ContainsKey(LName), LName);
      LNames.Add(LName, True);
    end;
  finally
    LNames.Free;
  end;
  Assert.AreEqual('pe', MHBinaryKindToName(bkPE));
  Assert.AreEqual('suspicious_api', MHStringCategoryToName(scSuspiciousApi));
  Assert.AreEqual('high', MHAnomalySeverityToName(asHigh));
  Assert.AreEqual('added', MHDiffChangeToName(dcAdded));
end;

procedure TBinaryLabApiTests.MachineSubsystemAndPeKindNames;
begin
  Assert.AreEqual('x86', MHMachineName(IMAGE_FILE_MACHINE_I386));
  Assert.AreEqual('x64', MHMachineName(IMAGE_FILE_MACHINE_AMD64));
  Assert.AreEqual('ARM64', MHMachineName(IMAGE_FILE_MACHINE_ARM64));
  Assert.AreEqual('ARM', MHMachineName(IMAGE_FILE_MACHINE_ARMNT));
  Assert.AreEqual('0x1234', MHMachineName($1234), 'Неизвестная архитектура — код');
  Assert.IsTrue(MHSubsystemName(2) <> MHSubsystemName(3));
  Assert.IsTrue(MHSubsystemName(1).Contains('Native'));
  Assert.IsTrue(MHSubsystemName(999).Contains('999'), 'Неизвестная подсистема — с номером');
  Assert.AreEqual('', MHPeKindTitle(pkNone));
  Assert.IsTrue(MHPeKindTitle(pkDll).Contains('DLL'));
  Assert.IsTrue(MHPeKindTitle(pkDriver).Contains('SYS'));
  Assert.IsTrue(MHPeKindTitle(pkExe).Contains('EXE'));
end;

procedure TBinaryLabApiTests.Extensions_ExpectedAndInList;
begin
  Assert.IsTrue(MHExtensionInList('.dll', MHExpectedExtensions(bkPE)));
  Assert.IsTrue(MHExtensionInList('.SYS', MHExpectedExtensions(bkPE)), 'Без учёта регистра');
  Assert.IsFalse(MHExtensionInList('.dat', MHExpectedExtensions(bkPE)));
  Assert.IsFalse(MHExtensionInList('.bin', MHExpectedExtensions(bkPE)), '.bin — не расширение программ Windows');
  Assert.IsTrue(MHExtensionInList('.docx', MHExpectedExtensions(bkZip)));
  Assert.IsTrue(MHExtensionInList('.ps1', MHExpectedExtensions(bkScript)));
  Assert.IsFalse(MHExtensionInList('', MHExpectedExtensions(bkPE)), 'Пустое расширение');
  Assert.IsFalse(MHExtensionInList('.exe', ''), 'Пустой список');
  Assert.AreEqual('', MHExpectedExtensions(bkUnknown));
  Assert.AreEqual('', MHExpectedExtensions(bkEmpty));
end;

procedure TBinaryLabApiTests.Sections_FlagsFindAndRva;
var
  LSection: TMHPeSection;
  LPe: TMHPeInfo;
begin
  LSection := Default(TMHPeSection);
  Assert.AreEqual('---', LSection.AccessText);
  Assert.IsFalse(LSection.IsReadable or LSection.IsWritable or LSection.IsExecutable or LSection.ContainsCode);
  LSection.Characteristics := SCN_TEXT;
  Assert.IsTrue(LSection.IsReadable and LSection.IsExecutable and LSection.ContainsCode);
  Assert.IsFalse(LSection.IsWritable);
  Assert.AreEqual('R-X', LSection.AccessText);
  LSection.Characteristics := SCN_DATA or SCN_EXEC;
  Assert.AreEqual('RWX', LSection.AccessText);
  // Поиск секции по имени и адресу: заголовки, граница, вне секций, данные только в памяти.
  LSection := Default(TMHPeSection);
  LSection.Name := '.text';
  LSection.VirtualAddress := $1000;
  LSection.VirtualSize := $200;
  LSection.RawSize := $400;
  LPe := Default(TMHPeInfo);
  LPe.Sections := [LSection];
  LSection.Name := '.bss';
  LSection.VirtualAddress := $2000;
  LSection.VirtualSize := $1000;
  LSection.RawSize := 0;
  LPe.Sections := LPe.Sections + [LSection];
  Assert.IsTrue(LPe.FindSection('.TEXT', LSection), 'Без учёта регистра');
  Assert.IsFalse(LPe.FindSection('.rsrc', LSection));
  Assert.AreEqual('', LSection.Name, 'Не найдено — пустая запись');
  Assert.IsTrue(LPe.SectionOfRva($1000, LSection) and (LSection.Name = '.text'));
  Assert.IsTrue(LPe.SectionOfRva($13FF, LSection), 'Размер — максимум из размеров в памяти и в файле');
  Assert.IsFalse(LPe.SectionOfRva($1400, LSection), 'Сразу за секцией');
  Assert.IsTrue(LPe.SectionOfRva($2FFF, LSection) and (LSection.Name = '.bss'));
  Assert.IsFalse(LPe.SectionOfRva($500, LSection), 'Заголовки — вне секций');
  Assert.IsFalse(LPe.SectionOfRva($FFFFFFFF, LSection), 'Предельный адрес');
  Assert.IsFalse(Default(TMHPeInfo).SectionOfRva(0, LSection), 'Нет секций');
end;

procedure TBinaryLabApiTests.DiffTitles_AndSaveDiff;
const
  AREAS: array[0..6] of string = (MH_DIFF_AREA_HEADER, MH_DIFF_AREA_SECTION, MH_DIFF_AREA_IMPORT,
    MH_DIFF_AREA_EXPORT, MH_DIFF_AREA_RESOURCE, MH_DIFF_AREA_STRING, MH_DIFF_AREA_BLOCK);
var
  LDiff: TMHBinaryDiff;
  LDir, LJsonPath, LHtmlPath: string;
  LJson: TJSONValue;
  LArea: string;
begin
  for LArea in AREAS do
  begin
    Assert.IsTrue(MHDiffAreaTitle(LArea) <> '');
    Assert.AreNotEqual(LArea, MHDiffAreaTitle(LArea), 'Область переведена: ' + LArea);
  end;
  Assert.AreEqual('other', MHDiffAreaTitle('other'), 'Неизвестная область — как есть');
  LDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\BLD-' + TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(LDir);
  try
    LDiff := Default(TMHBinaryDiff);
    LDiff.LeftPath := 'a.exe';
    LDiff.RightPath := 'b.exe';
    LDiff.Identical := True;
    LDiff.SimilarityPercent := 100;
    LJsonPath := TPath.Combine(LDir, 'diff.JSON');
    LHtmlPath := TPath.Combine(LDir, 'diff.htm');
    MHSaveBinaryDiff(LDiff, LJsonPath);
    MHSaveBinaryDiff(LDiff, LHtmlPath);
    LJson := TJSONObject.ParseJSONValue(TFile.ReadAllText(LJsonPath, TEncoding.UTF8));
    try
      Assert.IsNotNull(LJson, 'Расширение .JSON — без учёта регистра');
      Assert.IsTrue((LJson as TJSONObject).GetValue<Boolean>('identical'));
    finally
      LJson.Free;
    end;
    Assert.IsTrue(TFile.ReadAllText(LHtmlPath, TEncoding.UTF8).StartsWith('<!DOCTYPE html>'), 'Иное расширение — HTML');
    // Недостающие папки создаются; недопустимое имя файла — ошибка.
    MHSaveBinaryDiff(LDiff, TPath.Combine(LDir, 'новая папка\x\diff.json'));
    Assert.IsTrue(TFile.Exists(TPath.Combine(LDir, 'новая папка\x\diff.json')));
    Assert.WillRaiseDescendant(
      procedure
      begin
        MHSaveBinaryDiff(LDiff, TPath.Combine(LDir, 'bad|name?.json'));
      end, Exception);
  finally
    TDirectory.Delete(LDir, True);
  end;
end;

procedure TBinaryLabApiTests.Checksum_EmptyTinyFieldOutsideAndCancel;
begin
  // Пустой файл: сумма слов 0 плюс длина 0.
  Assert.AreEqual<Cardinal>(0, MHComputePeChecksum(TMHBytesSource.Create(nil), 64));
  // Один байт (нечётная длина): байт как младшая половина слова плюс длина 1.
  Assert.AreEqual<Cardinal>($41 + 1, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([$41])), 64));
  // Поле CheckSum за концом файла — пропускать нечего: обычная сумма слов.
  Assert.AreEqual<Cardinal>($0201 + $0403 + 4, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([1, 2, 3, 4])), 1000));
  // Поле CheckSum на смещении 0 — его 4 байта не учитываются.
  Assert.AreEqual<Cardinal>(0 + 6, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([9, 9, 9, 9, 0, 0])), 0));
  // Перенос старшего разряда сворачивается: FFFF + 0001 = 0001 (+ длина 4).
  Assert.AreEqual<Cardinal>(1 + 4, MHComputePeChecksum(TMHBytesSource.Create(TestBytes([$FF, $FF, 1, 0])), 1000));
  Assert.WillRaise(
    procedure
    begin
      MHComputePeChecksum(TMHBytesSource.Create(TestRandomBytes(10000)), 64,
        function: Boolean
        begin
          Result := True;
        end);
    end, EMHBinaryLabCancelled);
end;

procedure TBinaryLabApiTests.Options_NormalizedLimitsBothSides;
var
  LOptions: TMHBinaryLabOptions;
begin
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.MaxScanBytes := High(Int64);
  LOptions.EntropyBlockSize := MaxInt;
  LOptions.MaxEntropyBlocks := MaxInt;
  LOptions.MinStringLength := 1000;
  LOptions.MaxStringLength := MaxInt;
  LOptions.MaxStrings := MaxInt;
  LOptions.MaxEmbedded := MaxInt;
  LOptions.MaxImportedFunctions := MaxInt;
  LOptions.MaxResources := MaxInt;
  LOptions.MaxExports := MaxInt;
  LOptions := LOptions.Normalized;
  Assert.AreEqual<Int64>(Int64(4) * 1024 * 1024 * 1024, LOptions.MaxScanBytes, 'Верхний предел сканирования — 4 ГБ');
  Assert.AreEqual(16 * 1024 * 1024, LOptions.EntropyBlockSize);
  Assert.AreEqual(65536, LOptions.MaxEntropyBlocks);
  Assert.AreEqual(64, LOptions.MinStringLength);
  Assert.AreEqual(65536, LOptions.MaxStringLength);
  Assert.AreEqual(1000000, LOptions.MaxStrings);
  Assert.AreEqual(100000, LOptions.MaxEmbedded);
  Assert.AreEqual(1000000, LOptions.MaxImportedFunctions);
  // Отрицательные значения — нижние пределы.
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.MaxScanBytes := -1;
  LOptions.EntropyBlockSize := -5;
  LOptions.MaxEntropyBlocks := -1;
  LOptions.MaxEmbedded := -1;
  LOptions.MaxImportedFunctions := -1;
  LOptions.MaxResources := -1;
  LOptions.MaxExports := -1;
  LOptions.MaxSectionHashBytes := -1;
  LOptions := LOptions.Normalized;
  Assert.AreEqual<Int64>(4096, LOptions.MaxScanBytes);
  Assert.AreEqual(64, LOptions.EntropyBlockSize, 'Явный размер блока — не меньше 64');
  Assert.AreEqual(16, LOptions.MaxEntropyBlocks);
  Assert.AreEqual(0, LOptions.MaxEmbedded);
  Assert.AreEqual(0, LOptions.MaxImportedFunctions);
  Assert.AreEqual(0, LOptions.MaxResources);
  Assert.AreEqual(0, LOptions.MaxExports);
  Assert.AreEqual<Int64>(0, LOptions.MaxSectionHashBytes);
  // Нормализация не меняет допустимые значения по умолчанию.
  Assert.AreEqual<Int64>(TMHBinaryLabOptions.Default.MaxScanBytes, TMHBinaryLabOptions.Default.Normalized.MaxScanBytes);
  Assert.AreEqual(TMHBinaryLabOptions.Default.MaxStrings, TMHBinaryLabOptions.Default.Normalized.MaxStrings);
end;

procedure TBinaryLabApiTests.Histogram_BarFractionEdges;
var
  LHistogram: TMHByteHistogram;
  LCounts: array[Byte] of Int64;
begin
  LHistogram := TMHByteHistogram.Create(nil);
  try
    // Пустая гистограмма: все доли нулевые, деления на ноль нет.
    Assert.AreEqual(0.0, LHistogram.BarFraction(0), 1e-12);
    Assert.AreEqual(0.0, LHistogram.BarFraction(255), 1e-12);
    LHistogram.SetHistogram([]);
    Assert.AreEqual(0.0, LHistogram.BarFraction(7), 1e-12);
    FillChar(LCounts, SizeOf(LCounts), 0);
    LCounts[0] := 1000;
    LCounts[1] := 10;
    LHistogram.SetHistogram(LCounts);
    Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12, 'Наибольший столбец — вся высота');
    Assert.AreEqual(0.0, LHistogram.BarFraction(2), 1e-12, 'Нулевой счётчик — нет столбца');
    LHistogram.Logarithmic := True;
    Assert.AreEqual(Ln(11) / Ln(1001), LHistogram.BarFraction(1), 1e-9, 'Логарифмическая шкала');
    LHistogram.Logarithmic := False;
    Assert.AreEqual(0.01, LHistogram.BarFraction(1), 1e-9, 'Линейная шкала');
    // Меньше 256 значений — остальные байты нулевые.
    LHistogram.SetHistogram([5]);
    Assert.AreEqual(1.0, LHistogram.BarFraction(0), 1e-12);
    Assert.AreEqual(0.0, LHistogram.BarFraction(1), 1e-12);
  finally
    LHistogram.Free;
  end;
end;

procedure TBinaryLabApiTests.HexView_OffsetDigitsAtFourGigabytes;
var
  LHex: TMHHexView;
begin
  LHex := TMHHexView.Create(nil);
  try
    Assert.AreEqual(8, LHex.OffsetDigits, 'Без источника');
    LHex.Source := TSizedSource.Create(0);
    Assert.AreEqual(8, LHex.OffsetDigits, 'Пустой файл');
    LHex.Source := TSizedSource.Create($100000000);
    Assert.AreEqual(8, LHex.OffsetDigits, 'Ровно 4 ГБ: последнее смещение FFFFFFFF');
    LHex.Source := TSizedSource.Create($100000001);
    Assert.AreEqual(12, LHex.OffsetDigits, 'На байт больше 4 ГБ');
    LHex.Source := nil;
    Assert.AreEqual(8, LHex.OffsetDigits, 'Источник снят');
  finally
    LHex.Free;
  end;
end;

procedure TBinaryLabApiTests.EntropyMap_BlockCountEmptyAndData;
var
  LMap: TMHEntropyMap;
  LBlocks: TArray<TMHEntropyBlock>;
  I: Integer;
begin
  LMap := TMHEntropyMap.Create(nil);
  try
    Assert.AreEqual(0, LMap.BlockCount, 'До данных');
    LMap.SetData(nil, 0);
    Assert.AreEqual(0, LMap.BlockCount, 'Пустые данные');
    SetLength(LBlocks, 3);
    for I := 0 to High(LBlocks) do
    begin
      LBlocks[I].Offset := I * 256;
      LBlocks[I].Size := 256;
      LBlocks[I].Entropy := I;
    end;
    LMap.SetData(LBlocks, 768);
    Assert.AreEqual(3, LMap.BlockCount);
    Assert.AreEqual<Int64>(768, LMap.FileSize);
    LMap.SetData(nil, 0);
    Assert.AreEqual(0, LMap.BlockCount, 'Данные сброшены');
  finally
    LMap.Free;
  end;
end;

procedure TBinaryLabApiTests.Report_HasAnomalyAndDiffCountOf;
var
  LReport: TMHBinaryReport;
  LDiff: TMHBinaryDiff;
  LItem: TMHDiffItem;
begin
  LReport := Default(TMHBinaryReport);
  Assert.IsFalse(LReport.HasAnomaly('X'));
  LReport.Anomalies := [TMHBinaryAnomaly.Create('X', asLow, 't', 'd', 1, 10, 20)];
  Assert.IsTrue(LReport.HasAnomaly('X'));
  Assert.IsFalse(LReport.HasAnomaly('x'), 'Коды сравниваются точно');
  Assert.AreEqual<Int64>(10, LReport.Anomalies[0].Offset);
  Assert.AreEqual<Int64>(20, LReport.Anomalies[0].Size);
  Assert.AreEqual<Int64>(MH_NO_OFFSET, TMHBinaryAnomaly.Create('Y', asInfo, 't', 'd', 0).Offset);
  LDiff := Default(TMHBinaryDiff);
  Assert.AreEqual(0, LDiff.CountOf(MH_DIFF_AREA_IMPORT));
  LItem := Default(TMHDiffItem);
  LItem.Area := MH_DIFF_AREA_IMPORT;
  LDiff.Items := [LItem, LItem];
  LItem.Area := MH_DIFF_AREA_STRING;
  LDiff.Items := LDiff.Items + [LItem];
  Assert.AreEqual(2, LDiff.CountOf(MH_DIFF_AREA_IMPORT));
  Assert.AreEqual(1, LDiff.CountOf(MH_DIFF_AREA_STRING));
end;

end.
