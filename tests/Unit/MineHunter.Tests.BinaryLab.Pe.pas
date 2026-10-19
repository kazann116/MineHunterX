unit MineHunter.Tests.BinaryLab.Pe;

{
  BinaryLab: PE Analyzer (разбор синтетических PE32/PE32+, повреждённых и
  намеренно искажённых файлов, лимиты, отмена, фаззинг заголовков) и
  Anomaly Detector (правила, веса, поправка на подпись, итог).
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.Core.Types,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source, MineHunter.BinaryLab.Pe,
  MineHunter.BinaryLab.Anomalies, MineHunter.Tests.PeBuilder;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabPeTests = class
  private
    function Parse(const AData: TBytes): TMHPeInfo; overload;
    function Parse(const AData: TBytes; const AOptions: TMHBinaryLabOptions): TMHPeInfo; overload;
    function HasWarning(const APe: TMHPeInfo; const AText: string): Boolean;
  public
    [Test] procedure Pe64_HeadersSectionsImportsExports;
    [Test] procedure Pe32_OrdinalImportsAndImageBase;
    [Test] procedure Resources_TreeTypesLanguagesAndContent;
    [Test] procedure TlsDotNetCertificateOverlay;
    [Test] procedure EntryPoint_OffsetSectionAndRvaMapping;
    [Test] procedure Checksum_MatchesBuilderIncludingOddLength;
    [Test] procedure Locate_DescribesOffsets;
    [Test] procedure NotPe_IsInvalidWithReason;
    [Test] procedure Truncated_AtEveryLength_NeverRaises;
    [Test] procedure HugeCounts_AreClampedWithWarnings;
    [Test] procedure ImportOutsideFile_AndUnterminatedThunks;
    [Test] procedure ResourceCycle_DoesNotHang;
    [Test] procedure Limits_ImportsAndExports;
    [Test] procedure Cancel_Raises;
    [Test] procedure Fuzz_RandomHeaderCorruption_NeverRaises;
    [Test] procedure RangeSha256_Bounds;
  end;

  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabAnomalyTests = class
  private
    function ReportOf(ABuilder: TTestPeBuilder; const AName: string = 'test.exe'): TMHBinaryReport;
    function Codes(const AReport: TMHBinaryReport): string;
  public
    [Test] procedure CleanProgram_NoThreatVerdict;
    [Test] procedure EntryOutsideSections;
    [Test] procedure UpxLikePacking;
    [Test] procedure PackedCodeAndEncryptedData;
    [Test] procedure Imports_NoneDynamicFewInjectionAntiDebug;
    [Test] procedure DotNet_NoImportsIsNormal;
    [Test] procedure Driver_UnsignedAndChecksum;
    [Test] procedure Signature_InvalidAndTrustedHalvesScore;
    [Test] procedure ExtensionMismatch_ExecutableVsData;
    [Test] procedure Strings_MiningWalletCommands;
    [Test] procedure Embedded_ExecutableArchiveScript;
    [Test] procedure Overlay_EncryptedVsInstaller;
    [Test] procedure TlsTimestampOddNames;
    [Test] procedure DamagedHeader_NonPeData;
    [Test] procedure Score_ClampedAndLevelFromThresholds;
  end;

implementation

uses
  System.Math, System.DateUtils;

function SectionByName(const APe: TMHPeInfo; const AName: string): TMHPeSection;
begin
  if not APe.FindSection(AName, Result) then
    raise Exception.Create('Нет секции ' + AName);
end;

{ TBinaryLabPeTests }

function TBinaryLabPeTests.Parse(const AData: TBytes): TMHPeInfo;
begin
  Result := Parse(AData, TMHBinaryLabOptions.Default);
end;

function TBinaryLabPeTests.Parse(const AData: TBytes; const AOptions: TMHBinaryLabOptions): TMHPeInfo;
var
  LReader: TMHBinaryReader;
begin
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(AData));
  try
    Result := MHParsePe(LReader, AOptions);
  finally
    LReader.Free;
  end;
end;

function TBinaryLabPeTests.HasWarning(const APe: TMHPeInfo; const AText: string): Boolean;
var
  LWarning: string;
begin
  for LWarning in APe.Warnings do
    if LWarning.Contains(AText) then
      Exit(True);
  Result := False;
end;

procedure TBinaryLabPeTests.Pe64_HeadersSectionsImportsExports;
var
  LBuilder: TTestPeBuilder;
  LPe: TMHPeInfo;
  LText: TMHPeSection;
  I: Integer;
  LForwarded: Boolean;
begin
  LBuilder := TTestPeBuilder.Create(True);
  try
    LBuilder.Dll := True;
    LBuilder.TimeDateStamp := $66000000;
    LBuilder.AddSection('.text', TestCodeBytes(3000), SCN_TEXT);
    LBuilder.AddSection('.data', TestAscii('data'), SCN_DATA, $2000);
    LBuilder.AddImport('KERNEL32.dll', ['CreateFileW', 'ReadFile', 'CloseHandle']);
    LBuilder.AddImport('ADVAPI32.dll', ['RegOpenKeyExW']);
    LBuilder.ExportDllName := 'sample.dll';
    LBuilder.AddExport('First');
    LBuilder.AddExport('Second');
    LBuilder.AddExport('Fwd', 'KERNEL32.Sleep');
    LPe := Parse(LBuilder.Build);
    Assert.IsTrue(LPe.Valid);
    Assert.IsTrue(LPe.Is64);
    Assert.AreEqual(Ord(pkDll), Ord(LPe.Kind));
    Assert.AreEqual<Word>($8664, LPe.Machine);
    Assert.AreEqual('x64', LPe.MachineName);
    Assert.AreEqual<Cardinal>($66000000, LPe.TimeDateStamp);
    Assert.AreEqual<UInt64>($180000000, LPe.ImageBase);
    Assert.AreEqual<Cardinal>(TEST_FILE_ALIGN, LPe.FileAlignment);
    Assert.AreEqual<Cardinal>(TEST_SECTION_ALIGN, LPe.SectionAlignment);
    Assert.AreEqual('14.38', LPe.LinkerVersion);
    Assert.AreEqual(16, Integer(Length(LPe.DataDirectories)));
    Assert.AreEqual(0, Integer(Length(LPe.Warnings)), string.Join('; ', LPe.Warnings));
    // Секции: две свои + созданные .idata и .edata.
    Assert.AreEqual(4, Integer(Length(LPe.Sections)));
    LText := SectionByName(LPe, '.text');
    Assert.AreEqual('R-X', LText.AccessText);
    Assert.IsTrue(LText.ContainsCode);
    Assert.AreEqual<Cardinal>(LBuilder.SectionRawOffset('.text'), LText.RawOffset);
    Assert.AreEqual<Cardinal>(3000, LText.VirtualSize);
    Assert.AreEqual('RW-', SectionByName(LPe, '.data').AccessText);
    Assert.AreEqual<Cardinal>($2000, SectionByName(LPe, '.data').VirtualSize);
    // Импорт.
    Assert.AreEqual(2, Integer(Length(LPe.Imports)));
    Assert.AreEqual('KERNEL32.dll', LPe.Imports[0].Dll);
    Assert.AreEqual(3, Integer(Length(LPe.Imports[0].Functions)));
    Assert.AreEqual('ReadFile', LPe.Imports[0].Functions[1]);
    Assert.AreEqual('RegOpenKeyExW', LPe.Imports[1].Functions[0]);
    Assert.AreEqual(4, LPe.ImportedFunctionCount);
    Assert.IsTrue(LPe.ImportsFunction('closehandle'), 'Без учёта регистра');
    Assert.IsFalse(LPe.ImportsFunction('WriteFile'));
    // Экспорт с переадресацией.
    Assert.AreEqual('sample.dll', LPe.ExportName);
    Assert.AreEqual(3, Integer(Length(LPe.ExportedFunctions)));
    Assert.AreEqual('First', LPe.ExportedFunctions[0].Name);
    Assert.AreEqual<Cardinal>(1, LPe.ExportedFunctions[0].Ordinal);
    LForwarded := False;
    for I := 0 to High(LPe.ExportedFunctions) do
      if LPe.ExportedFunctions[I].Name = 'Fwd' then
      begin
        Assert.AreEqual('KERNEL32.Sleep', LPe.ExportedFunctions[I].Forwarder);
        LForwarded := True;
      end
      else
        Assert.AreEqual('', LPe.ExportedFunctions[I].Forwarder);
    Assert.IsTrue(LForwarded);
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.Pe32_OrdinalImportsAndImageBase;
var
  LBuilder: TTestPeBuilder;
  LPe: TMHPeInfo;
begin
  LBuilder := TTestPeBuilder.Create(False);
  try
    LBuilder.Subsystem := 3;
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddImport('WS2_32.dll', ['#23', '#115', 'gethostbyname']);
    LPe := Parse(LBuilder.Build);
    Assert.IsTrue(LPe.Valid);
    Assert.IsFalse(LPe.Is64);
    Assert.AreEqual<Word>($10B, LPe.Magic);
    Assert.AreEqual('x86', LPe.MachineName);
    Assert.AreEqual(Ord(pkExe), Ord(LPe.Kind));
    Assert.AreEqual<UInt64>($400000, LPe.ImageBase);
    Assert.AreEqual<Word>(3, LPe.Subsystem);
    Assert.IsTrue(LPe.SubsystemName <> '');
    Assert.AreEqual('#23', LPe.Imports[0].Functions[0]);
    Assert.AreEqual('#115', LPe.Imports[0].Functions[1]);
    Assert.AreEqual('gethostbyname', LPe.Imports[0].Functions[2]);
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.Resources_TreeTypesLanguagesAndContent;
var
  LBuilder: TTestPeBuilder;
  LPe: TMHPeInfo;
  LResource: TMHPeResource;
  LFoundPe, LFoundIcon, LFoundCustom: Boolean;
  LData: TBytes;
  LPayload: TBytes;
begin
  LPayload := TestMinimalPe;
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddResource(RT_ICON_ID, 1, $0409, TestRandomBytes(300));
    LBuilder.AddResource(RT_RCDATA_ID, 101, $0419, LPayload);
    LBuilder.AddResource(777, 5, 0, TestAscii('custom resource'));
    LData := LBuilder.Build;
    LPe := Parse(LData);
    Assert.AreEqual(0, Integer(Length(LPe.Warnings)), string.Join('; ', LPe.Warnings));
    Assert.AreEqual(3, Integer(Length(LPe.Resources)));
    LFoundPe := False;
    LFoundIcon := False;
    LFoundCustom := False;
    for LResource in LPe.Resources do
    begin
      Assert.IsTrue(LResource.Offset > 0, 'Смещение данных в файле');
      if LResource.TypeName = 'RCDATA' then
      begin
        LFoundPe := True;
        Assert.AreEqual('101', LResource.Name);
        Assert.AreEqual<Cardinal>($0419, LResource.Language);
        Assert.AreEqual<Cardinal>(Length(LPayload), LResource.Size);
        Assert.AreEqual(Ord(bkPE), Ord(LResource.ContentKind), 'Программа внутри ресурса');
        Assert.AreEqual(LPayload[0], LData[LResource.Offset]);
        Assert.AreEqual(LPayload[High(LPayload)], LData[LResource.Offset + Length(LPayload) - 1]);
      end
      else if LResource.TypeName = 'ICON' then
      begin
        LFoundIcon := True;
        Assert.AreEqual<Cardinal>($0409, LResource.Language);
        Assert.AreEqual(Ord(bkUnknown), Ord(LResource.ContentKind));
      end
      else if LResource.TypeName = '#777' then
        LFoundCustom := True;
    end;
    Assert.IsTrue(LFoundPe and LFoundIcon and LFoundCustom);
    Assert.AreEqual('ICON', MHResourceTypeName(3));
    Assert.AreEqual('', MHResourceTypeName(999));
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.TlsDotNetCertificateOverlay;
var
  LBuilder: TTestPeBuilder;
  LPe: TMHPeInfo;
  LData: TBytes;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.TlsCallbackCount := 3;
    LBuilder.DotNet := True;
    LBuilder.Overlay := TestRandomBytes(5000);
    LBuilder.Certificate := TestRandomBytes(1000, 99);
    LData := LBuilder.Build;
    LPe := Parse(LData);
    Assert.AreEqual(3, LPe.TlsCallbackCount);
    Assert.IsTrue(LPe.IsDotNet);
    Assert.AreEqual<Int64>(LBuilder.CertificateOffset, LPe.CertificateOffset);
    Assert.AreEqual<Cardinal>(1008, LPe.CertificateSize);
    // Оверлей — данные между концом образа и подписью; подпись в него не входит.
    Assert.AreEqual<Int64>(LBuilder.ImageEnd, LPe.OverlayOffset);
    Assert.AreEqual<Int64>(LBuilder.CertificateOffset - LBuilder.ImageEnd, LPe.OverlaySize);
    Assert.IsTrue(LPe.OverlaySize >= 5000);
  finally
    LBuilder.Free;
  end;
  // Без оверлея и подписи.
  LPe := Parse(TestMinimalPe);
  Assert.AreEqual<Int64>(0, LPe.OverlaySize);
  Assert.AreEqual<Int64>(MH_NO_OFFSET, LPe.OverlayOffset);
  Assert.AreEqual<Int64>(MH_NO_OFFSET, LPe.CertificateOffset);
  Assert.AreEqual(0, LPe.TlsCallbackCount);
  Assert.IsFalse(LPe.IsDotNet);
end;

procedure TBinaryLabPeTests.EntryPoint_OffsetSectionAndRvaMapping;
var
  LBuilder: TTestPeBuilder;
  LPe: TMHPeInfo;
  LTextRva, LTextRaw: Cardinal;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(1000), SCN_TEXT, $3000);
    LBuilder.AddSection('.data', TestAscii('payload'), SCN_DATA);
    LBuilder.Build;
    LTextRva := LBuilder.SectionRva('.text');
    LTextRaw := LBuilder.SectionRawOffset('.text');
    LBuilder.EntryPointRva := LTextRva + $10;
    LPe := Parse(LBuilder.Build);
    Assert.AreEqual('.text', LPe.EntryPointSection);
    Assert.AreEqual<Int64>(LTextRaw + $10, LPe.EntryPointOffset);
    // RVA → смещение: заголовки, секция, хвост секции без данных в файле, вне секций.
    Assert.AreEqual<Int64>($40, MHPeRvaToOffset(LPe, $40));
    Assert.AreEqual<Int64>(LTextRaw + 5, MHPeRvaToOffset(LPe, LTextRva + 5));
    Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(LPe, LTextRva + $2000), 'Нули в памяти, нет данных в файле');
    Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(LPe, $7FFFFFF0));
    Assert.AreEqual<Int64>(MH_NO_OFFSET, MHPeRvaToOffset(Default(TMHPeInfo), $10), 'Не PE');
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.Checksum_MatchesBuilderIncludingOddLength;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LPe: TMHPeInfo;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(2000), SCN_TEXT);
    LBuilder.WriteChecksum := True;
    LBuilder.Overlay := TestRandomBytes(1001); // нечётная длина файла
    LData := LBuilder.Build;
    Assert.IsTrue(Odd(Length(LData)));
    LPe := Parse(LData);
    Assert.IsTrue(LPe.CheckSum <> 0);
    Assert.AreEqual<Cardinal>(LPe.CheckSum, MHComputePeChecksum(TMHBytesSource.Create(LData),
      LBuilder.OptionalOffset + 64));
    // Изменённый байт меняет сумму.
    LData[Length(LData) - 10] := LData[Length(LData) - 10] xor $FF;
    Assert.AreNotEqual<Cardinal>(LPe.CheckSum, MHComputePeChecksum(TMHBytesSource.Create(LData),
      LBuilder.OptionalOffset + 64));
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.Locate_DescribesOffsets;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LPe: TMHPeInfo;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.Overlay := TestRandomBytes(300);
    LBuilder.Certificate := TestRandomBytes(64);
    LData := LBuilder.Build;
    LPe := Parse(LData);
    Assert.IsTrue(MHPeLocate(LPe, Length(LData), 10).Contains('заголов') or
      MHPeLocate(LPe, Length(LData), 10).Contains('header'));
    Assert.IsTrue(MHPeLocate(LPe, Length(LData), LBuilder.SectionRawOffset('.text') + 3).Contains('.text'));
    Assert.IsTrue(MHPeLocate(LPe, Length(LData), LBuilder.ImageEnd + 5) <> '');
    Assert.AreNotEqual(MHPeLocate(LPe, Length(LData), LBuilder.ImageEnd + 5),
      MHPeLocate(LPe, Length(LData), LBuilder.CertificateOffset + 3), 'Оверлей и подпись различаются');
    Assert.AreEqual('', MHPeLocate(LPe, Length(LData), -1));
    Assert.AreEqual('', MHPeLocate(Default(TMHPeInfo), 100, 5));
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.NotPe_IsInvalidWithReason;
var
  LPe: TMHPeInfo;
  LData: TBytes;
begin
  LPe := Parse(TestAscii('just some text, not a program'));
  Assert.IsFalse(LPe.Valid);
  Assert.AreEqual(1, Integer(Length(LPe.Warnings)));
  LPe := Parse(nil);
  Assert.IsFalse(LPe.Valid);
  LData := TestMinimalPe;
  PokeWord(LData, $98, $107); // ROM-образ: неизвестный Magic
  LPe := Parse(LData);
  Assert.IsFalse(LPe.Valid);
  Assert.IsTrue(HasWarning(LPe, 'Magic'));
end;

procedure TBinaryLabPeTests.Truncated_AtEveryLength_NeverRaises;
var
  LFull, LCut: TBytes;
  LLength: Integer;
  LPe: TMHPeInfo;
  LBuilder: TTestPeBuilder;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(700), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'ExitProcess', 'GetTickCount']);
    LBuilder.AddExport('Exported');
    LBuilder.AddResource(RT_RCDATA_ID, 1, 0, TestRandomBytes(200));
    LBuilder.TlsCallbackCount := 1;
    LFull := LBuilder.Build;
  finally
    LBuilder.Free;
  end;
  LLength := 0;
  while LLength <= Length(LFull) do
  begin
    LCut := Copy(LFull, 0, LLength);
    LPe := Parse(LCut);
    if LPe.Valid and (LLength < Length(LFull)) and (LLength > $400) then
      Assert.IsTrue(Length(LPe.Warnings) > 0, Format('Обрезка до %d байт без предупреждений', [LLength]));
    Inc(LLength, 37);
  end;
  Assert.Pass('Разбор обрезанных файлов не вызывает исключений');
end;

procedure TBinaryLabPeTests.HugeCounts_AreClampedWithWarnings;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LPe: TMHPeInfo;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LData := LBuilder.Build;
    PokeWord(LData, LBuilder.PeOffset + 6, $FFFF);            // NumberOfSections
    PokeDWord(LData, LBuilder.OptionalOffset + 108, $7FFFFFFF); // NumberOfRvaAndSizes
  finally
    LBuilder.Free;
  end;
  LPe := Parse(LData);
  Assert.IsTrue(LPe.Valid);
  Assert.IsTrue(Length(LPe.Sections) <= PE_MAX_SECTIONS);
  Assert.IsTrue(Length(LPe.DataDirectories) <= 16);
  Assert.IsTrue(HasWarning(LPe, '96'), string.Join('; ', LPe.Warnings));
  Assert.IsTrue(HasWarning(LPe, '16'), string.Join('; ', LPe.Warnings));
end;

procedure TBinaryLabPeTests.ImportOutsideFile_AndUnterminatedThunks;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LPe: TMHPeInfo;
  LDirBase: Integer;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep']);
    LData := LBuilder.Build;
    LDirBase := LBuilder.OptionalOffset + 112;
  finally
    LBuilder.Free;
  end;
  // Каталог импорта указывает на несуществующий адрес.
  PokeDWord(LData, LDirBase + 8, $00F00000);
  LPe := Parse(LData);
  Assert.IsTrue(LPe.Valid);
  Assert.AreEqual(0, Integer(Length(LPe.Imports)));
  Assert.IsTrue(Length(LPe.Warnings) > 0);
  // Таблица функций без завершающего нуля до конца файла: чтение ограничено размером файла.
  LData := TestConcat([TestMinimalPe, TestRandomBytes(1000)]);
  LPe := Parse(LData);
  Assert.IsTrue(LPe.Valid);
end;

procedure TBinaryLabPeTests.ResourceCycle_DoesNotHang;
var
  LBuilder: TTestPeBuilder;
  LData: TBytes;
  LPe: TMHPeInfo;
  LRoot: Cardinal;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddResource(RT_RCDATA_ID, 1, 0, TestRandomBytes(64));
    LData := LBuilder.Build;
    LRoot := LBuilder.SectionRawOffset('.rsrc');
  finally
    LBuilder.Free;
  end;
  // Первая запись корня ссылается на сам корень (смещение 0 с флагом каталога).
  PokeDWord(LData, LRoot + 16 + 4, $80000000);
  LPe := Parse(LData);
  Assert.IsTrue(LPe.Valid);
  Assert.IsTrue(HasWarning(LPe, 'цикл'), string.Join('; ', LPe.Warnings));
end;

procedure TBinaryLabPeTests.Limits_ImportsAndExports;
var
  LBuilder: TTestPeBuilder;
  LOptions: TMHBinaryLabOptions;
  LPe: TMHPeInfo;
  LNames: TArray<string>;
  I: Integer;
begin
  SetLength(LNames, 50);
  for I := 0 to High(LNames) do
    LNames[I] := 'Func' + IntToStr(I);
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddImport('A.dll', LNames);
    LBuilder.AddImport('B.dll', LNames);
    for I := 0 to 29 do
      LBuilder.AddExport('Export' + IntToStr(I));
    LOptions := TMHBinaryLabOptions.Default;
    LOptions.MaxImportedFunctions := 70;
    LOptions.MaxExports := 10;
    LPe := Parse(LBuilder.Build, LOptions);
    Assert.AreEqual(70, LPe.ImportedFunctionCount);
    Assert.AreEqual(10, Integer(Length(LPe.ExportedFunctions)));
    Assert.IsTrue(Length(LPe.Warnings) >= 2, string.Join('; ', LPe.Warnings));
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabPeTests.Cancel_Raises;
var
  LReader: TMHBinaryReader;
begin
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(TestMinimalPe));
  try
    Assert.WillRaise(
      procedure
      begin
        MHParsePe(LReader, TMHBinaryLabOptions.Default,
          function: Boolean
          begin
            Result := True;
          end);
      end, EMHBinaryLabCancelled);
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabPeTests.Fuzz_RandomHeaderCorruption_NeverRaises;
var
  LBase, LData, LNoise: TBytes;
  LBuilder: TTestPeBuilder;
  I, J, LPos: Integer;
  LValid: Integer;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(600), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'ExitProcess']);
    LBuilder.AddExport('X');
    LBuilder.AddResource(RT_VERSION_ID, 1, 0, TestRandomBytes(100));
    LBuilder.TlsCallbackCount := 2;
    LBase := LBuilder.Build;
  finally
    LBuilder.Free;
  end;
  LValid := 0;
  for I := 1 to 400 do
  begin
    LData := Copy(LBase);
    LNoise := TestRandomBytes(16, Cardinal(I) * 7919);
    // Портим 8 случайных байтов в заголовках и таблицах (первые 0x2000 байт).
    for J := 0 to 7 do
    begin
      LPos := (LNoise[J * 2] or (LNoise[J * 2 + 1] shl 8)) mod Min($2000, Length(LData));
      LData[LPos] := LNoise[(J + 5) mod 16];
    end;
    if Parse(LData).Valid then
      Inc(LValid);
  end;
  Assert.IsTrue(LValid > 0, 'Часть испорченных файлов остаётся разбираемой');
end;

procedure TBinaryLabPeTests.RangeSha256_Bounds;
var
  LSource: IMHBinarySource;
begin
  LSource := TMHBytesSource.Create(TestAscii('abc'));
  Assert.AreEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', MHRangeSha256(LSource, 0, 3));
  Assert.AreEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', MHRangeSha256(LSource, 0, 100),
    'Обрезается у конца');
  Assert.AreEqual('', MHRangeSha256(LSource, 3, 10));
  Assert.AreEqual('', MHRangeSha256(LSource, -1, 10));
  Assert.AreEqual('', MHRangeSha256(LSource, 0, 0));
  Assert.AreEqual('', MHRangeSha256(nil, 0, 10));
end;

{ TBinaryLabAnomalyTests }

function TBinaryLabAnomalyTests.ReportOf(ABuilder: TTestPeBuilder; const AName: string): TMHBinaryReport;
var
  LData: TBytes;
  LReader: TMHBinaryReader;
  I: Integer;
begin
  LData := ABuilder.Build;
  Result := Default(TMHBinaryReport);
  Result.FileName := AName;
  Result.Size := Length(LData);
  Result.FileType.Kind := bkPE;
  Result.FileType.Extension := ExtractFileExt(AName).ToLower;
  Result.Signature.State := sgSignedTrusted;
  LReader := TMHBinaryReader.Create(TMHBytesSource.Create(LData));
  try
    Result.Pe := MHParsePe(LReader, TMHBinaryLabOptions.Default);
  finally
    LReader.Free;
  end;
  // Энтропия секций — как у обычного кода и данных (тесты меняют при необходимости).
  for I := 0 to High(Result.Pe.Sections) do
    Result.Pe.Sections[I].Entropy := 6.0;
end;

function TBinaryLabAnomalyTests.Codes(const AReport: TMHBinaryReport): string;
var
  LAnomaly: TMHBinaryAnomaly;
begin
  Result := '';
  for LAnomaly in MHDetectAnomalies(AReport, EncodeDateTime(2026, 10, 19, 12, 0, 0, 0)) do
    Result := Result + LAnomaly.Code + ' ';
end;

procedure TBinaryLabAnomalyTests.CleanProgram_NoThreatVerdict;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LNames: TArray<string>;
  I: Integer;
begin
  SetLength(LNames, 40);
  for I := 0 to High(LNames) do
    LNames[I] := 'Function' + IntToStr(I);
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(2000), SCN_TEXT);
    LBuilder.AddSection('.rdata', TestAscii('constants'), SCN_RDATA);
    LBuilder.AddSection('.data', TestAscii('variables'), SCN_DATA);
    LBuilder.AddImport('KERNEL32.dll', LNames);
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LReport.Anomalies := MHDetectAnomalies(LReport, Now);
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.AreEqual(0, LReport.Score, Codes(LReport));
  Assert.AreEqual(Ord(rlNone), Ord(LReport.Level));
  Assert.IsTrue(LReport.Verdict.Contains('не гарантия') or LReport.Verdict.Contains('not a guarantee'), LReport.Verdict);
end;

procedure TBinaryLabAnomalyTests.EntryOutsideSections;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW', 'ReadFile', 'WriteFile']);
    LBuilder.EntryPointRva := $80; // в заголовках
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  Assert.IsTrue(Codes(LReport).Contains(BL_ENTRY_OUTSIDE_SECTIONS), Codes(LReport));
end;

procedure TBinaryLabAnomalyTests.UpxLikePacking;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    // UPX: пустая секция UPX0 (память для распакованного кода), сжатая UPX1 с точкой входа, всё RWX.
    LBuilder.AddSection('UPX0', nil, SCN_CODE or SCN_EXEC or SCN_READ or SCN_WRITE, $20000);
    LBuilder.AddSection('UPX1', TestRandomBytes(8000), SCN_CODE or SCN_EXEC or SCN_READ or SCN_WRITE);
    LBuilder.AddImport('KERNEL32.dll', ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'ExitProcess']);
    LBuilder.Build;
    LBuilder.EntryPointRva := LBuilder.SectionRva('UPX1') + 16;
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LReport.Pe.Sections[1].Entropy := 7.9;
  LReport.Signature.State := sgUnsigned;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_PACKER_SECTIONS), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_VIRTUAL_CODE_SECTION), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_RWX_SECTION), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_ENTRY_IN_WRITABLE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_PACKED_CODE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_DYNAMIC_IMPORTS_ONLY), LCodes);
  Assert.AreEqual('UPX', MHPackerBySectionName('upx1'));
  Assert.AreEqual('', MHPackerBySectionName('.text'));
  LReport.Anomalies := MHDetectAnomalies(LReport, Now);
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.IsTrue(LReport.Score >= TMHRiskThresholds.Default.Suspicious, IntToStr(LReport.Score));
  Assert.IsTrue(LReport.Verdict.Contains(IntToStr(LReport.Score)), LReport.Verdict);
end;

procedure TBinaryLabAnomalyTests.PackedCodeAndEncryptedData;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(8000), SCN_TEXT);
    LBuilder.AddSection('.data', TestRandomBytes(8000), SCN_DATA);
    LBuilder.AddResource(RT_ICON_ID, 1, 0, TestRandomBytes(8000));
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW', 'ReadFile', 'WriteFile']);
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LReport.Pe.Sections[0].Entropy := 6.3; // обычный код
  LReport.Pe.Sections[1].Entropy := 7.95;
  LReport.Pe.Sections[High(LReport.Pe.Sections)].Entropy := 7.99; // .rsrc: картинки — норма
  LCodes := Codes(LReport);
  Assert.IsFalse(LCodes.Contains(BL_PACKED_CODE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_HIGH_ENTROPY_DATA), LCodes);
  Assert.IsTrue(MHDetectAnomalies(LReport, Now)[0].Details <> '');
end;

procedure TBinaryLabAnomalyTests.Imports_NoneDynamicFewInjectionAntiDebug;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LReport := ReportOf(LBuilder);
    Assert.IsTrue(Codes(LReport).Contains(BL_NO_IMPORTS), Codes(LReport));

    LBuilder.AddImport('USER32.dll', ['MessageBoxW', 'wsprintfW']);
    LReport := ReportOf(LBuilder);
    Assert.IsTrue(Codes(LReport).Contains(BL_FEW_IMPORTS), Codes(LReport));
  finally
    LBuilder.Free;
  end;
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
      'IsDebuggerPresent', 'CloseHandle']);
    LBuilder.AddImport('ntdll.dll', ['NtQueryInformationProcess']);
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_INJECTION_API), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_ANTI_DEBUG_API), LCodes);
  Assert.IsFalse(LCodes.Contains(BL_FEW_IMPORTS), LCodes);
end;

procedure TBinaryLabAnomalyTests.DotNet_NoImportsIsNormal;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddImport('mscoree.dll', ['_CorExeMain']);
    LBuilder.DotNet := True;
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_DOTNET), LCodes);
  Assert.IsFalse(LCodes.Contains(BL_FEW_IMPORTS), LCodes);
  Assert.IsFalse(LCodes.Contains(BL_NO_IMPORTS), LCodes);
end;

procedure TBinaryLabAnomalyTests.Driver_UnsignedAndChecksum;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.Subsystem := 1;
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LReport := ReportOf(LBuilder, 'evil.sys');
  finally
    LBuilder.Free;
  end;
  LReport.Signature.State := sgUnsigned;
  LReport.Pe.CheckSum := $1234;
  LReport.Pe.ComputedCheckSum := $5678;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_UNSIGNED_DRIVER), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_CHECKSUM_MISMATCH), LCodes);
  Assert.IsFalse(LCodes.Contains(BL_NO_IMPORTS), 'Драйверам импорт не проверяется: ' + LCodes);
  Assert.IsFalse(LCodes.Contains(BL_UNSIGNED + ' '), 'Для драйвера — отдельное правило: ' + LCodes);
end;

procedure TBinaryLabAnomalyTests.Signature_InvalidAndTrustedHalvesScore;
var
  LBuilder: TTestPeBuilder;
  LReport, LTrusted: TMHBinaryReport;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LReport.Signature.State := sgSignedUntrusted;
  LReport.Signature.Error := 'файл изменён';
  Assert.IsTrue(Codes(LReport).Contains(BL_SIGNATURE_INVALID), Codes(LReport));
  LReport.Anomalies := MHDetectAnomalies(LReport, Now);
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  // Те же признаки с доверенной подписью (без правила о подписи) — вдвое меньше.
  LTrusted := LReport;
  LTrusted.Signature.State := sgSignedTrusted;
  LTrusted.Anomalies := MHDetectAnomalies(LTrusted, Now);
  LReport.Signature.State := sgNotChecked;
  LReport.Anomalies := MHDetectAnomalies(LReport, Now);
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  MHScoreBinaryReport(LTrusted, TMHRiskThresholds.Default);
  Assert.IsTrue(LReport.Score > 0);
  Assert.AreEqual(LReport.Score div 2, LTrusted.Score);
end;

procedure TBinaryLabAnomalyTests.ExtensionMismatch_ExecutableVsData;
var
  LReport: TMHBinaryReport;
  LAnomalies: TArray<TMHBinaryAnomaly>;
begin
  LReport := Default(TMHBinaryReport);
  LReport.FileType.Kind := bkPE;
  LReport.FileType.Extension := '.jpg';
  LReport.FileType.ExtensionMismatch := True;
  LAnomalies := MHDetectAnomalies(LReport, Now);
  Assert.AreEqual(BL_EXTENSION_MISMATCH, LAnomalies[0].Code);
  Assert.AreEqual(Ord(asHigh), Ord(LAnomalies[0].Severity));
  LReport.FileType.Kind := bkZip;
  LReport.FileType.Extension := '.pdf';
  LAnomalies := MHDetectAnomalies(LReport, Now);
  Assert.AreEqual(Ord(asLow), Ord(LAnomalies[0].Severity));
end;

procedure TBinaryLabAnomalyTests.Strings_MiningWalletCommands;
var
  LReport: TMHBinaryReport;
  LAnomalies: TArray<TMHBinaryAnomaly>;
  LItem: TMHBinaryString;
  LAnomaly: TMHBinaryAnomaly;
  LMiningFound: Boolean;
begin
  LReport := Default(TMHBinaryReport);
  LReport.FileType.Kind := bkUnknown;
  LItem.Offset := 100;
  LItem.Encoding := seAscii;
  LItem.Text := 'stratum+tcp://pool.minexmr.com:4444';
  LItem.Category := scMining;
  LReport.Strings.Items := [LItem];
  LReport.Strings.CountByCategory[scMining] := 1;
  LReport.Strings.CountByCategory[scWallet] := 1;
  LReport.Strings.CountByCategory[scCommand] := 4;
  LAnomalies := MHDetectAnomalies(LReport, Now);
  LMiningFound := False;
  for LAnomaly in LAnomalies do
    if LAnomaly.Code = BL_MINING_STRINGS then
    begin
      LMiningFound := True;
      Assert.IsTrue(LAnomaly.Details.Contains('stratum+tcp://pool.minexmr.com'), LAnomaly.Details);
      Assert.AreEqual(30, LAnomaly.Weight);
    end
    else if LAnomaly.Code = BL_COMMAND_STRINGS then
      Assert.AreEqual(Ord(asMedium), Ord(LAnomaly.Severity), 'Три и больше команд — средняя');
  Assert.IsTrue(LMiningFound);
  LReport.Anomalies := LAnomalies;
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.AreEqual(30 + 15 + 8, LReport.Score);
  // Без строк майнинга «кошелёк» — сведения без веса (так выглядят хеши).
  LReport.Strings.CountByCategory[scMining] := 0;
  LReport.Strings.Items := nil;
  LAnomalies := MHDetectAnomalies(LReport, Now);
  for LAnomaly in LAnomalies do
    if LAnomaly.Code = BL_WALLET_STRINGS then
    begin
      Assert.AreEqual(Ord(asInfo), Ord(LAnomaly.Severity));
      Assert.AreEqual(0, LAnomaly.Weight);
    end;
end;

procedure TBinaryLabAnomalyTests.Embedded_ExecutableArchiveScript;
var
  LReport: TMHBinaryReport;
  LObject: TMHEmbeddedObject;
  LCodes: string;
  LString: TMHBinaryString;
begin
  LReport := Default(TMHBinaryReport);
  LReport.FileType.Kind := bkPE;
  LObject := Default(TMHEmbeddedObject);
  LObject.Offset := 5000;
  LObject.Kind := bkPE;
  LReport.Embedded := [LObject];
  LObject.Offset := 9000;
  LObject.Kind := bkZip;
  LReport.Embedded := LReport.Embedded + [LObject];
  LObject.Offset := 12000;
  LObject.Kind := bkScript;
  LReport.Embedded := LReport.Embedded + [LObject];
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_EMBEDDED_EXECUTABLE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_EMBEDDED_ARCHIVE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_EMBEDDED_SCRIPT), LCodes);
  Assert.AreEqual<Int64>(5000, MHDetectAnomalies(LReport, Now)[0].Offset, 'Смещение первой вложенной программы');
  Assert.AreEqual(15, MHDetectAnomalies(LReport, Now)[0].Weight);
  // Внутри установщика программы — норма.
  LString := Default(TMHBinaryString);
  LString.Text := 'Nullsoft Install System v3.09';
  LReport.Strings.Items := [LString];
  Assert.AreEqual(BL_EMBEDDED_EXECUTABLE, MHDetectAnomalies(LReport, Now)[0].Code);
  Assert.AreEqual(0, MHDetectAnomalies(LReport, Now)[0].Weight);
end;

procedure TBinaryLabAnomalyTests.Overlay_EncryptedVsInstaller;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LBlock: TMHEntropyBlock;
  LCodes: string;
  I: Integer;
  LObject: TMHEmbeddedObject;
  LString: TMHBinaryString;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW', 'ReadFile', 'WriteFile']);
    LBuilder.Overlay := TestRandomBytes(200000);
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LReport.Signature.State := sgUnsigned;
  // Блоки энтропии оверлея — почти случайные.
  for I := 0 to 40 do
  begin
    LBlock.Offset := LReport.Pe.OverlayOffset + I * 4096;
    LBlock.Size := 4096;
    LBlock.Entropy := 7.98;
    LReport.Entropy.Blocks := LReport.Entropy.Blocks + [LBlock];
  end;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_ENCRYPTED_OVERLAY), LCodes);
  // Архив в оверлее — установщик: только сведения.
  LObject := Default(TMHEmbeddedObject);
  LObject.Offset := LReport.Pe.OverlayOffset;
  LObject.Kind := bk7z;
  LReport.Embedded := [LObject];
  LCodes := Codes(LReport);
  Assert.IsFalse(LCodes.Contains(BL_ENCRYPTED_OVERLAY), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_OVERLAY), LCodes);
  // Установщик Inno Setup: сжатый оверлей без сигнатуры архива — норма.
  LReport.Embedded := nil;
  Assert.IsTrue(Codes(LReport).Contains(BL_ENCRYPTED_OVERLAY));
  LString := Default(TMHBinaryString);
  LString.Text := 'This installation was built with Inno Setup.';
  LReport.Strings.Items := [LString];
  Assert.AreEqual('Inno Setup', MHDetectInstaller(LReport));
  LCodes := Codes(LReport);
  Assert.IsFalse(LCodes.Contains(BL_ENCRYPTED_OVERLAY), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_OVERLAY), LCodes);
  LReport.Strings.Items := nil;
  Assert.AreEqual('', MHDetectInstaller(LReport));
end;

procedure TBinaryLabAnomalyTests.TlsTimestampOddNames;
var
  LBuilder: TTestPeBuilder;
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(800), SCN_TEXT);
    LBuilder.AddSection(#1#2'x', TestAscii('odd'), SCN_DATA);
    LBuilder.AddImport('KERNEL32.dll', ['Sleep', 'CreateFileW', 'ReadFile', 'WriteFile']);
    LBuilder.TlsCallbackCount := 2;
    LBuilder.TimeDateStamp := Cardinal(DateTimeToUnix(EncodeDate(2031, 1, 1)));
    LReport := ReportOf(LBuilder);
  finally
    LBuilder.Free;
  end;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_TLS_CALLBACKS), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_TIMESTAMP_FUTURE), LCodes);
  Assert.IsTrue(LCodes.Contains(BL_ODD_SECTION_NAMES), LCodes);
end;

procedure TBinaryLabAnomalyTests.DamagedHeader_NonPeData;
var
  LReport: TMHBinaryReport;
  LCodes: string;
begin
  LReport := Default(TMHBinaryReport);
  LReport.FileType.Kind := bkMsDos;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_PE_DAMAGED), LCodes);
  LReport.FileType.Kind := bkZip;
  LReport.Size := 100000;
  LReport.Entropy.Overall := 7.99;
  LCodes := Codes(LReport);
  Assert.IsTrue(LCodes.Contains(BL_HIGH_ENTROPY_FILE), LCodes);
  LReport.Anomalies := MHDetectAnomalies(LReport, Now);
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.AreEqual(0, LReport.Score, 'Сжатый архив — не угроза');
end;

procedure TBinaryLabAnomalyTests.Score_ClampedAndLevelFromThresholds;
var
  LReport: TMHBinaryReport;
  I: Integer;
begin
  LReport := Default(TMHBinaryReport);
  for I := 1 to 10 do
    LReport.Anomalies := LReport.Anomalies + [TMHBinaryAnomaly.Create('X' + IntToStr(I), asHigh, 'T' + IntToStr(I),
      'D', 25)];
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.AreEqual(100, LReport.Score);
  Assert.AreEqual(Ord(rlHighlySuspicious), Ord(LReport.Level));
  Assert.IsTrue(LReport.Verdict.Contains('T1'), LReport.Verdict);
  LReport.Anomalies := [TMHBinaryAnomaly.Create('INFO', asInfo, 'info', 'D', 0)];
  MHScoreBinaryReport(LReport, TMHRiskThresholds.Default);
  Assert.AreEqual(0, LReport.Score);
  Assert.AreEqual(Ord(rlNone), Ord(LReport.Level));
end;

end.
