unit MineHunter.Tests.BinaryLab.Mutation;

{
  BinaryLab: тесты, закрывающие пробелы, найденные мутационным тестированием
  (tools/binarylab_mutation.py). Каждый тест ловит конкретного выжившего мутанта:
  граница размера блока BinaryDiff, непечатные байты в описании сценария,
  обрезанный каталог экспорта, порядок строк в HTML, смещение 0, ложный ICO,
  конец оверлея, сценарий UTF-16 с BOM, раздел замечаний, упакованный код без
  флага CODE, категории строк в JSON, строка UTF-16 на нечётном смещении через
  границу блока чтения.
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabMutationTests = class
  public
    [Test] procedure Diff_AutoBlockSizeExactlyAtLimit;
    [Test] procedure Embedded_ScriptDescriptionReplacesControlBytes;
    [Test] procedure Pe_ExportDirectoryCutByEndOfFile_Warns;
    [Test] procedure Html_IndicatorsBeforePlainStrings;
    [Test] procedure HexOffset_ZeroIsNotDash;
    [Test] procedure Detect_IconCountWithoutSignature_IsNotIcon;
    [Test] procedure Locate_EndOfOverlayIsOutside;
    [Test] procedure Detect_Utf16BomPowerShell_IsScript;
    [Test] procedure Html_NoNotesSectionWithoutNotes;
    [Test] procedure Anomalies_PackedExecuteOnlySection;
    [Test] procedure Json_OnlyNonZeroStringCategories;
    [Test] procedure Strings_Utf16OddOffsetAcrossChunk;
  end;

implementation

uses
  System.JSON, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.BinaryLab.FileType, MineHunter.BinaryLab.Pe, MineHunter.BinaryLab.Diff,
  MineHunter.BinaryLab.Embedded, MineHunter.BinaryLab.Strings, MineHunter.BinaryLab.Anomalies,
  MineHunter.BinaryLab.Report, MineHunter.Tests.PeBuilder;

function DetectKind(const AData: TBytes; const AName: string): TMHBinaryKind;
var
  LReader: TMHBinaryReader;
begin
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(AData));
  try
    Result := MHDetectBinaryType(LReader, AName).Kind;
  finally
    LReader.Free;
  end;
end;

{ TBinaryLabMutationTests }

procedure TBinaryLabMutationTests.Diff_AutoBlockSizeExactlyAtLimit;
var
  LData: TBytes;
  LReport: TMHBinaryReport;
  LDiff: TMHBinaryDiff;
  LOptions: TMHBinaryLabOptions;
begin
  // Ровно MaxEntropyBlocks блоков по 512 байт — блок не удваивается; на блок больше — удваивается.
  LOptions := TMHBinaryLabOptions.Default;
  LOptions.MaxEntropyBlocks := 64;
  LReport := Default(TMHBinaryReport);
  LData := TestRandomBytes(512 * 64);
  LDiff := MHCompareBinaries(LReport, LReport, TMHBytesSource.Create(LData), TMHBytesSource.Create(LData), LOptions);
  Assert.AreEqual(512, LDiff.BlockSize, 'Ровно на пределе');
  LData := TestRandomBytes(512 * 65);
  LDiff := MHCompareBinaries(LReport, LReport, TMHBytesSource.Create(LData), TMHBytesSource.Create(LData), LOptions);
  Assert.AreEqual(1024, LDiff.BlockSize, 'На блок больше предела');
end;

procedure TBinaryLabMutationTests.Embedded_ScriptDescriptionReplacesControlBytes;
var
  LObjects: TArray<TMHEmbeddedObject>;
  LObject: TMHEmbeddedObject;
  LFound: Boolean;
  C: Char;
begin
  LObjects := MHFindEmbedded(TMHBytesSource.Create(TestConcat([TestRandomBytes(300, 5),
    TestAscii('@echo off '), TestBytes([1, 2, $C8, $FF]), TestAscii(' tail'), TestBytes([0]),
    TestRandomBytes(300, 6)])), TMHBinaryLabOptions.Default, nil, nil);
  LFound := False;
  for LObject in LObjects do
    if LObject.Kind = bkScript then
    begin
      LFound := True;
      // Фрагмент — после подписи «Фрагмент сценария: ».
      for C in LObject.Description.Substring(LObject.Description.IndexOf(': ') + 2) do
        Assert.IsTrue((C >= ' ') and (C <> #$7F) and (Ord(C) < $C8), 'Непечатный байт в описании: ' + IntToStr(Ord(C)));
      Assert.IsTrue(LObject.Description.Contains('????'), LObject.Description);
    end;
  Assert.IsTrue(LFound, 'Фрагмент сценария найден');
end;

procedure TBinaryLabMutationTests.Pe_ExportDirectoryCutByEndOfFile_Warns;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LReader: TMHBinaryReader;
  LPe: TMHPeInfo;
  LWarning: string;
  LWarned: Boolean;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddExport('OnlyExport');
    LData := LBuilder.Build;
    // .edata — последняя секция: каталог экспорта за 20 байт до конца файла не помещается (40 байт).
    PokeDWord(LData, LBuilder.OptionalOffset + 112, LBuilder.SectionRva('.edata') + TEST_FILE_ALIGN - 20);
  finally
    LBuilder.Free;
  end;
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(LData));
  try
    LPe := MHParsePe(LReader, TMHBinaryLabOptions.Default);
  finally
    LReader.Free;
  end;
  Assert.IsTrue(LPe.Valid);
  Assert.AreEqual(0, Integer(Length(LPe.ExportedFunctions)));
  LWarned := False;
  for LWarning in LPe.Warnings do
    if LWarning.Contains('экспорта') then
      LWarned := True;
  Assert.IsTrue(LWarned, string.Join('; ', LPe.Warnings));
end;

procedure TBinaryLabMutationTests.Html_IndicatorsBeforePlainStrings;
var
  LReport: TMHBinaryReport;
  LPlain, LIndicator: TMHBinaryString;
  LHtml: string;
begin
  LReport := Default(TMHBinaryReport);
  LPlain := Default(TMHBinaryString);
  LPlain.Text := 'plain-first-in-file';
  LIndicator := Default(TMHBinaryString);
  LIndicator.Offset := 100;
  LIndicator.Text := 'http://indicator-second.example.com';
  LIndicator.Category := scUrl;
  LReport.Strings.Items := [LPlain, LIndicator];
  LReport.Strings.TotalFound := 2;
  LHtml := MHBinaryReportToHtml(LReport);
  Assert.IsTrue(LHtml.Contains('plain-first-in-file') and LHtml.Contains('indicator-second'));
  Assert.IsTrue(LHtml.IndexOf('indicator-second') < LHtml.IndexOf('plain-first-in-file'),
    'Индикаторы выводятся раньше обычных строк');
end;

procedure TBinaryLabMutationTests.HexOffset_ZeroIsNotDash;
begin
  Assert.AreEqual('0x00000000', MHHexOffset(0));
  Assert.AreEqual('—', MHHexOffset(-1));
  Assert.AreEqual('0xFFFFFFFF', MHHexOffset($FFFFFFFF));
  Assert.AreEqual('0x000100000000', MHHexOffset($100000000));
end;

procedure TBinaryLabMutationTests.Detect_IconCountWithoutSignature_IsNotIcon;
begin
  // Слово по смещению 4 похоже на число значков (5), но сигнатуры 00 00 01 00 нет.
  Assert.AreNotEqual(Ord(bkIco), Ord(DetectKind(TestConcat([TestBytes([1, 2, 3, 4, 5, 0]), TestRandomBytes(200, 9)]),
    'x.bin')));
  Assert.AreEqual(Ord(bkIco), Ord(DetectKind(TestConcat([TestBytes([0, 0, 1, 0, 5, 0]), TestRandomBytes(200, 9)]),
    'x.ico')));
end;

procedure TBinaryLabMutationTests.Locate_EndOfOverlayIsOutside;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LReader: TMHBinaryReader;
  LPe: TMHPeInfo;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.Overlay := TestRandomBytes(300);
    LData := LBuilder.Build;
  finally
    LBuilder.Free;
  end;
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(LData));
  try
    LPe := MHParsePe(LReader, TMHBinaryLabOptions.Default);
  finally
    LReader.Free;
  end;
  Assert.AreEqual<Int64>(Length(LData), LPe.OverlayOffset + LPe.OverlaySize, 'Оверлей до конца файла');
  Assert.IsTrue(MHPeLocate(LPe, Length(LData), LPe.OverlayOffset + LPe.OverlaySize - 1) <> '', 'Последний байт оверлея');
  Assert.AreEqual('', MHPeLocate(LPe, Length(LData), LPe.OverlayOffset + LPe.OverlaySize), 'Сразу за оверлеем');
end;

procedure TBinaryLabMutationTests.Detect_Utf16BomPowerShell_IsScript;
begin
  Assert.AreEqual(Ord(bkScript), Ord(DetectKind(TestConcat([TestBytes([$FF, $FE]),
    TestUtf16('powershell -enc SQBFAFgA')]), 'notes.txt')), 'Команды в UTF-16 с BOM');
  Assert.AreEqual(Ord(bkText), Ord(DetectKind(TestConcat([TestBytes([$FF, $FE]), TestUtf16('просто текст')]),
    'notes.txt')));
end;

procedure TBinaryLabMutationTests.Html_NoNotesSectionWithoutNotes;
var
  LReport: TMHBinaryReport;
begin
  LReport := Default(TMHBinaryReport);
  Assert.IsFalse(MHBinaryReportToHtml(LReport).Contains('<h2>Замечания</h2>'), 'Нет замечаний — нет раздела');
  LReport.Errors := ['ошибка чтения'];
  Assert.IsTrue(MHBinaryReportToHtml(LReport).Contains('<h2>Замечания</h2>'));
end;

procedure TBinaryLabMutationTests.Anomalies_PackedExecuteOnlySection;
var
  LReport: TMHBinaryReport;
  LSection: TMHPeSection;
  LAnomaly: TMHBinaryAnomaly;
  LFound: Boolean;
begin
  LReport := Default(TMHBinaryReport);
  LReport.FileType.Kind := bkPE;
  LReport.Pe.Valid := True;
  LReport.Signature.State := sgUnsigned;
  LSection := Default(TMHPeSection);
  LSection.Name := '.text';
  LSection.Characteristics := SCN_EXEC or SCN_READ; // без флага CODE
  LSection.RawSize := 8192;
  LSection.Entropy := 7.9;
  LReport.Pe.Sections := [LSection];
  LFound := False;
  for LAnomaly in MHDetectAnomalies(LReport, Now) do
    if LAnomaly.Code = BL_PACKED_CODE then
      LFound := True;
  Assert.IsTrue(LFound, 'Исполняемая секция без флага CODE тоже проверяется');
end;

procedure TBinaryLabMutationTests.Json_OnlyNonZeroStringCategories;
var
  LReport: TMHBinaryReport;
  LJson: TJSONValue;
  LCategories: TJSONArray;
begin
  LReport := Default(TMHBinaryReport);
  LReport.Strings.CountByCategory[scUrl] := 3;
  LJson := TJSONObject.ParseJSONValue(MHBinaryReportToJson(LReport));
  try
    LCategories := (LJson as TJSONObject).GetValue<TJSONArray>('strings.byCategory');
    Assert.AreEqual(1, LCategories.Count, 'Только категории с найденными строками');
    Assert.AreEqual('url', (LCategories.Items[0] as TJSONArray).Items[0].Value);
  finally
    LJson.Free;
  end;
end;

procedure TBinaryLabMutationTests.Strings_Utf16OddOffsetAcrossChunk;
var
  LData: TBytes;
  LText: TBytes;
  LStart: Integer;
  LInfo: TMHStringsInfo;
  LItem: TMHBinaryString;
  LCount: Integer;
begin
  // Строка UTF-16 с нечётного смещения, пересекающая границу блока чтения 1 МБ.
  SetLength(LData, 2 * 1024 * 1024 + 101);
  FillChar(LData[0], Length(LData), $FF);
  LText := TestUtf16('OddWideStringAcrossBoundary');
  LStart := 1024 * 1024 - 21; // нечётное
  Move(LText[0], LData[LStart], Length(LText));
  LInfo := MHScanStrings(TMHBytesSource.Create(LData), TMHBinaryLabOptions.Default, nil);
  LCount := 0;
  for LItem in LInfo.Items do
    if (LItem.Encoding = seUtf16) and (LItem.Text = 'OddWideStringAcrossBoundary') then
    begin
      Inc(LCount);
      Assert.AreEqual<Int64>(LStart, LItem.Offset);
    end;
  Assert.AreEqual(1, LCount, 'Найдена один раз с верным смещением');
end;

end.
