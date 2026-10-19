unit MineHunter.Tests.BinaryLab.Basics;

{
  BinaryLab: источник байтов (границы, файлы, блоки с перекрытием, отмена)
  и определение вида файла по содержимому.
}

interface

uses
  DUnitX.TestFramework,
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source, MineHunter.BinaryLab.FileType;

type
  [TestFixture]
  [Category('BinaryLab')]
  TBinaryLabBasicsTests = class
  private
    FDir: string;
    function Reader(const AData: TBytes): TMHBinaryReader;
    function Detect(const AData: TBytes; const AName: string): TMHBinaryTypeInfo;
    function TempFile(const AName: string; const AData: TBytes): string;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Reader_BoundsAreChecked;
    [Test] procedure Reader_StringsAndSignatures;
    [Test] procedure Reader_EmptySource;
    [Test] procedure FileSource_ReadsAndKeepsFileUnchanged;
    [Test] procedure FileSource_MissingOrFolder_Raises;
    [Test] procedure FileSource_OpenWhileFileIsLockedForWrite;
    [Test] procedure Chunks_OverlapCoversBoundaries;
    [Test] procedure Chunks_LimitAndCancel;
    [Test] procedure Detect_PeKinds;
    [Test] procedure Detect_ArchivesImagesDocuments;
    [Test] procedure Detect_TextAndScripts;
    [Test] procedure Detect_EmptyAndUnknown;
    [Test] procedure Detect_ExtensionMismatch;
    [Test] procedure Detect_DamagedPe_IsMsDos;
    [Test] procedure IdentifyAt_StrictRejectsWeakSignatures;
    [Test] procedure ProbePe_ImageEndAndHugeLfanew;
    [Test] procedure Entropy_ShannonBounds;
    [Test] procedure Options_Normalized;
  end;

implementation

uses
  System.IOUtils, System.Classes, Winapi.Windows,
  MineHunter.Tests.PeBuilder;

{ TBinaryLabBasicsTests }

procedure TBinaryLabBasicsTests.Setup;
begin
  FDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\BL-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(FDir);
end;

procedure TBinaryLabBasicsTests.TearDown;
begin
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог; ошибка удаления не влияет на результат.
  end;
end;

function TBinaryLabBasicsTests.Reader(const AData: TBytes): TMHBinaryReader;
begin
  Result := TMHBinaryReader.Create(TMHBytesSource.Create(AData));
end;

function TBinaryLabBasicsTests.Detect(const AData: TBytes; const AName: string): TMHBinaryTypeInfo;
var
  LReader: TMHBinaryReader;
begin
  LReader := Reader(AData);
  try
    Result := MHDetectBinaryType(LReader, AName);
  finally
    LReader.Free;
  end;
end;

function TBinaryLabBasicsTests.TempFile(const AName: string; const AData: TBytes): string;
begin
  Result := TPath.Combine(FDir, AName);
  TFile.WriteAllBytes(Result, AData);
end;

procedure TBinaryLabBasicsTests.Reader_BoundsAreChecked;
var
  LReader: TMHBinaryReader;
  LWord: Word;
  LDWord: Cardinal;
  LQWord: UInt64;
begin
  LReader := Reader([1, 2, 3, 4, 5, 6]);
  try
    Assert.AreEqual<Int64>(6, LReader.Size);
    Assert.IsTrue(LReader.TryReadWord(0, LWord));
    Assert.AreEqual<Word>($0201, LWord);
    Assert.IsTrue(LReader.TryReadDWord(2, LDWord));
    Assert.AreEqual<Cardinal>($06050403, LDWord);
    // Чтение за границей и частичное — отказ, а не исключение.
    Assert.IsFalse(LReader.TryReadDWord(3, LDWord), 'Частично за концом');
    Assert.IsFalse(LReader.TryReadQWord(0, LQWord), 'Больше файла');
    Assert.IsFalse(LReader.TryReadWord(-1, LWord), 'Отрицательное смещение');
    Assert.IsFalse(LReader.TryReadWord(High(Int64) - 1, LWord), 'Переполнение смещения');
    Assert.AreEqual(0, Integer(Length(LReader.ReadBytes(6, 10))));
    Assert.AreEqual(2, Integer(Length(LReader.ReadBytes(4, 10))), 'Обрезается у конца');
    Assert.AreEqual(0, Integer(Length(LReader.ReadBytes(0, -5))));
    Assert.IsTrue(LReader.InRange(0, 6));
    Assert.IsFalse(LReader.InRange(1, 6));
    Assert.IsFalse(LReader.InRange(0, -1));
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabBasicsTests.Reader_StringsAndSignatures;
var
  LReader: TMHBinaryReader;
begin
  LReader := Reader(TestConcat([TestAscii('abc'), TestBytes([0, 1]), TestAscii('d'), TestBytes([$C3, 0]), TestUtf16('Привет')]));
  try
    Assert.AreEqual('abc', LReader.ReadAnsiZ(0, 100));
    Assert.AreEqual('ab', LReader.ReadAnsiZ(0, 2), 'Ограничение длины');
    Assert.AreEqual('?d?', LReader.ReadAnsiZ(4, 100), 'Непечатаемые символы заменены');
    Assert.AreEqual('', LReader.ReadAnsiZ(1000, 10));
    Assert.AreEqual('Привет', LReader.ReadUtf16(8, 6));
    Assert.AreEqual('Привет', LReader.ReadUtf16(8, 100), 'Обрезается у конца');
    Assert.IsTrue(LReader.MatchesAt(0, TestBytes([$61, $62])));
    Assert.IsFalse(LReader.MatchesAt(0, TestBytes([$61, $63])));
    Assert.IsFalse(LReader.MatchesAt(19, TestBytes([0, 0, 0])), 'Сигнатура за концом');
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabBasicsTests.Reader_EmptySource;
var
  LReader: TMHBinaryReader;
  LByte: Byte;
begin
  LReader := Reader(nil);
  try
    Assert.AreEqual<Int64>(0, LReader.Size);
    Assert.IsFalse(LReader.TryReadByte(0, LByte));
    Assert.AreEqual('', LReader.ReadAnsiZ(0, 10));
    Assert.IsTrue(LReader.MatchesAt(0, []), 'Пустая сигнатура совпадает всегда');
  finally
    LReader.Free;
  end;
  Assert.WillRaise(
    procedure
    begin
      TMHBinaryReader.Create(nil).Free;
    end, EArgumentNilException);
end;

procedure TBinaryLabBasicsTests.FileSource_ReadsAndKeepsFileUnchanged;
var
  LPath: string;
  LData, LBuf: TBytes;
  LSource: IMHBinarySource;
  LBefore: TDateTime;
begin
  LData := TestRandomBytes(200000);
  LPath := TempFile('sample.bin', LData);
  LBefore := TFile.GetLastWriteTime(LPath);
  LSource := TMHFileSource.Create(LPath);
  Assert.AreEqual<Int64>(200000, LSource.Size);
  Assert.AreEqual(LPath, LSource.Name);
  SetLength(LBuf, 16);
  Assert.AreEqual(16, LSource.ReadAt(150000, LBuf[0], 16));
  Assert.AreEqual(LData[150000], LBuf[0]);
  Assert.AreEqual(LData[150015], LBuf[15]);
  Assert.AreEqual(5, LSource.ReadAt(199995, LBuf[0], 16), 'Обрезается у конца');
  Assert.AreEqual(0, LSource.ReadAt(200000, LBuf[0], 16));
  Assert.AreEqual(0, LSource.ReadAt(-1, LBuf[0], 16));
  Assert.IsTrue((LSource as TMHFileSource).LastWriteUtc > 0);
  LSource := nil;
  // Файл не изменён: содержимое и время записи прежние.
  Assert.AreEqual(LBefore, TFile.GetLastWriteTime(LPath));
  Assert.IsTrue(CompareMem(@LData[0], @TFile.ReadAllBytes(LPath)[0], Length(LData)));
end;

procedure TBinaryLabBasicsTests.FileSource_MissingOrFolder_Raises;
var
  LDir: string;
begin
  LDir := FDir;
  Assert.WillRaise(
    procedure
    begin
      TMHFileSource.Create(TPath.Combine(LDir, 'нет такого файла.exe')).Free;
    end, EMHBinaryLabError);
  Assert.WillRaise(
    procedure
    begin
      TMHFileSource.Create(LDir).Free;
    end, EMHBinaryLabError);
  Assert.WillRaise(
    procedure
    begin
      TMHFileSource.Create('').Free;
    end, EMHBinaryLabError);
end;

procedure TBinaryLabBasicsTests.FileSource_OpenWhileFileIsLockedForWrite;
var
  LPath: string;
  LStream: TFileStream;
  LSource: IMHBinarySource;
begin
  // Как у запущенной программы или открытого журнала: другой процесс держит файл на запись.
  LPath := TempFile('locked.dat', TestAscii('locked data'));
  LStream := TFileStream.Create(LPath, fmOpenReadWrite or fmShareDenyNone);
  try
    LSource := TMHFileSource.Create(LPath);
    Assert.AreEqual<Int64>(11, LSource.Size);
    LSource := nil;
  finally
    LStream.Free;
  end;
end;

procedure TBinaryLabBasicsTests.Chunks_OverlapCoversBoundaries;
var
  LData: TBytes;
  LFound: TArray<Int64>;
  LCalls: Integer;
  LCovered: Int64;
begin
  // Сигнатура «MZ» ровно на границе блоков 4096.
  SetLength(LData, 10000);
  FillChar(LData[0], Length(LData), $11);
  LData[4095] := $4D;
  LData[4096] := $5A;
  LCalls := 0;
  LCovered := 0;
  MHReadChunks(TMHBytesSource.Create(LData), 0, MaxInt, 4096, 16,
    function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
    var
      I: Integer;
    begin
      Inc(LCalls);
      if ABase + ACount > LCovered then
        LCovered := ABase + ACount;
      for I := 0 to ACount - 2 do
        if (AChunk[I] = $4D) and (AChunk[I + 1] = $5A) and
           ((Length(LFound) = 0) or (LFound[High(LFound)] <> ABase + I)) then
          LFound := LFound + [ABase + I];
      Result := True;
    end);
  Assert.AreEqual(1, Integer(Length(LFound)), 'Найдена один раз, несмотря на перекрытие');
  Assert.AreEqual<Int64>(4095, LFound[0]);
  Assert.AreEqual<Int64>(10000, LCovered, 'Прочитан весь файл');
  Assert.AreEqual(3, LCalls);
end;

procedure TBinaryLabBasicsTests.Chunks_LimitAndCancel;
var
  LData: TBytes;
  LCovered: Int64;
  LCalls: Integer;
begin
  LData := TestRandomBytes(50000);
  LCovered := 0;
  MHReadChunks(TMHBytesSource.Create(LData), 1000, 10000, 4096, 0,
    function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
    begin
      Assert.IsTrue(ABase >= 1000);
      LCovered := ABase + ACount;
      Result := True;
    end);
  Assert.AreEqual<Int64>(11000, LCovered, 'Лимит соблюдён');
  // Обработчик может остановить обход.
  LCalls := 0;
  MHReadChunks(TMHBytesSource.Create(LData), 0, MaxInt, 4096, 0,
    function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
    begin
      Inc(LCalls);
      Result := False;
    end);
  Assert.AreEqual(1, LCalls);
  // Отмена — исключение EMHBinaryLabCancelled.
  LCalls := 0;
  Assert.WillRaise(
    procedure
    begin
      MHReadChunks(TMHBytesSource.Create(LData), 0, MaxInt, 4096, 0,
        function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
        begin
          Inc(LCalls);
          Result := True;
        end,
        function: Boolean
        begin
          Result := LCalls >= 2;
        end);
    end, EMHBinaryLabCancelled);
  Assert.AreEqual(2, LCalls);
  // Начало за концом и пустой источник — без вызовов.
  LCalls := 0;
  MHReadChunks(TMHBytesSource.Create(LData), 60000, 100, 4096, 0,
    function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
    begin
      Inc(LCalls);
      Result := True;
    end);
  MHReadChunks(TMHBytesSource.Create(nil), 0, 100, 4096, 0,
    function(ABase: Int64; const AChunk: TBytes; ACount: Integer): Boolean
    begin
      Inc(LCalls);
      Result := True;
    end);
  Assert.AreEqual(0, LCalls);
end;

procedure TBinaryLabBasicsTests.Detect_PeKinds;
var
  LBuilder: TTestPeBuilder;
  LInfo: TMHBinaryTypeInfo;
begin
  LInfo := Detect(TestMinimalPe(True), 'test.dll');
  Assert.AreEqual(Ord(bkPE), Ord(LInfo.Kind));
  Assert.AreEqual(Ord(pkDll), Ord(LInfo.PeKind));
  Assert.IsTrue(LInfo.Description.Contains('x64'), LInfo.Description);
  Assert.IsFalse(LInfo.ExtensionMismatch);

  LBuilder := TTestPeBuilder.Create(False);
  try
    LBuilder.AddSection('.text', TestCodeBytes(512), SCN_TEXT);
    LInfo := Detect(LBuilder.Build, 'app.exe');
    Assert.AreEqual(Ord(pkExe), Ord(LInfo.PeKind));
    Assert.IsTrue(LInfo.Description.Contains('x86'), LInfo.Description);
    LBuilder.Subsystem := 1; // NATIVE — драйвер
    LInfo := Detect(LBuilder.Build, 'driver.sys');
    Assert.AreEqual(Ord(pkDriver), Ord(LInfo.PeKind));
    Assert.IsFalse(LInfo.ExtensionMismatch);
  finally
    LBuilder.Free;
  end;
end;

procedure TBinaryLabBasicsTests.Detect_ArchivesImagesDocuments;

  procedure Check(const AData: TBytes; const AName: string; AKind: TMHBinaryKind);
  begin
    Assert.AreEqual(MHBinaryKindToName(AKind), MHBinaryKindToName(Detect(AData, AName).Kind), AName);
  end;

begin
  Check(TestConcat([TestBytes([$50, $4B, $03, $04, $14, 0, 0, 0, 8, 0]), TestRandomBytes(100)]), 'a.zip', bkZip);
  Check(TestConcat([TestBytes([$52, $61, $72, $21, $1A, $07, 0]), TestRandomBytes(50)]), 'a.rar', bkRar);
  Check(TestConcat([TestBytes([$37, $7A, $BC, $AF, $27, $1C]), TestRandomBytes(50)]), 'a.7z', bk7z);
  Check(TestConcat([TestBytes([$1F, $8B, $08, 0]), TestRandomBytes(50)]), 'a.gz', bkGzip);
  Check(TestConcat([TestAscii('MSCF'), TestBytes([0, 0, 0, 0, 200, 0, 0, 0]), TestRandomBytes(50)]), 'a.cab', bkCab);
  Check(TestConcat([TestBytes([$D0, $CF, $11, $E0, $A1, $B1, $1A, $E1]), TestRandomBytes(50)]), 'a.msi', bkOle);
  Check(TestConcat([TestAscii('%PDF-1.7'), TestRandomBytes(50)]), 'a.pdf', bkPdf);
  Check(TestConcat([TestBytes([$89, $50, $4E, $47, $0D, $0A, $1A, $0A]), TestRandomBytes(50)]), 'a.png', bkPng);
  Check(TestConcat([TestBytes([$FF, $D8, $FF, $E0]), TestRandomBytes(50)]), 'a.jpg', bkJpeg);
  Check(TestConcat([TestAscii('GIF89a'), TestRandomBytes(50)]), 'a.gif', bkGif);
  Check(TestConcat([TestBytes([$7F, $45, $4C, $46, 2, 1]), TestRandomBytes(50)]), 'a.so', bkElf);
  Check(TestConcat([TestBytes([$CF, $FA, $ED, $FE]), TestRandomBytes(50)]), 'a.dylib', bkMachO);
  Check(TestConcat([TestBytes([$42, $4D, 60, 0, 0, 0, 0, 0, 0, 0]), TestRandomBytes(50)]), 'a.bmp', bkBmp);
  Check(TestConcat([TestBytes([0, 0, 1, 0, 1, 0]), TestRandomBytes(50)]), 'a.ico', bkIco);
end;

procedure TBinaryLabBasicsTests.Detect_TextAndScripts;
begin
  Assert.AreEqual(Ord(bkText), Ord(Detect(TestAscii('Обычный текст: hello world.' + #13#10 + 'line 2'), 'a.txt').Kind));
  Assert.AreEqual(Ord(bkScript), Ord(Detect(TestAscii('@echo off'#13#10'start x.exe'), 'run.bat').Kind));
  Assert.AreEqual(Ord(bkScript), Ord(Detect(TestAscii('#!/bin/sh'#10'echo hi'), 'run').Kind));
  Assert.AreEqual(Ord(bkScript), Ord(Detect(TestAscii('IEX (New-Object Net.WebClient).DownloadString(''x'')'),
    'readme.txt').Kind), 'Команды PowerShell — сценарий при любом расширении');
  Assert.AreEqual(Ord(bkScript), Ord(Detect(TestAscii('Write-Host 1'), 'a.ps1').Kind), 'Расширение сценария');
  Assert.AreEqual(Ord(bkText), Ord(Detect(TestConcat([TestBytes([$FF, $FE]), TestUtf16('Юникод')]), 'u.txt').Kind), 'UTF-16 с BOM');
  Assert.AreEqual(Ord(bkText), Ord(Detect(TestConcat([TestBytes([$EF, $BB, $BF]), TestAscii('utf8')]), 'u.txt').Kind), 'UTF-8 с BOM');
end;

procedure TBinaryLabBasicsTests.Detect_EmptyAndUnknown;
var
  LInfo: TMHBinaryTypeInfo;
begin
  LInfo := Detect(nil, 'empty.exe');
  Assert.AreEqual(Ord(bkEmpty), Ord(LInfo.Kind));
  Assert.IsFalse(LInfo.ExtensionMismatch);
  LInfo := Detect(TestRandomBytes(5000), 'blob.dat');
  Assert.AreEqual(Ord(bkUnknown), Ord(LInfo.Kind));
  Assert.IsFalse(LInfo.ExtensionMismatch, 'Неизвестные данные не сравниваются с расширением');
  Assert.AreEqual(Ord(bkUnknown), Ord(Detect([0], 'x').Kind), 'Один нулевой байт');
  Assert.AreEqual(Ord(bkText), Ord(Detect([$4D], 'x').Kind), 'Один печатный символ — текст');
end;

procedure TBinaryLabBasicsTests.Detect_ExtensionMismatch;
var
  LInfo: TMHBinaryTypeInfo;
begin
  LInfo := Detect(TestMinimalPe, 'photo.jpg');
  Assert.IsTrue(LInfo.ExtensionMismatch, 'Программа под видом картинки');
  Assert.AreEqual('.jpg', LInfo.Extension);
  Assert.IsTrue(Detect(TestMinimalPe, 'update.dat').ExtensionMismatch, 'Программа с расширением .dat');
  Assert.IsTrue(Detect(TestMinimalPe, 'Driver.BIN').ExtensionMismatch);
  Assert.IsFalse(Detect(TestMinimalPe, 'module').ExtensionMismatch, 'Без расширения — не сравнивается');
  Assert.IsFalse(Detect(TestMinimalPe, 'PLUGIN.DLL').ExtensionMismatch, 'Регистр не важен');
  Assert.IsTrue(Detect(TestConcat([TestBytes([$50, $4B, $03, $04, $14, 0, 0, 0, 8, 0]), TestRandomBytes(10)]),
    'doc.pdf').ExtensionMismatch, 'Архив под видом PDF');
  Assert.IsFalse(Detect(TestConcat([TestBytes([$50, $4B, $03, $04, $14, 0, 0, 0, 8, 0]), TestRandomBytes(10)]),
    'report.docx').ExtensionMismatch, 'DOCX — это ZIP');
end;

procedure TBinaryLabBasicsTests.Detect_DamagedPe_IsMsDos;
var
  LData: TBytes;
  LBuilder: TTestPeBuilder;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(512), SCN_TEXT);
    LData := LBuilder.Build;
    PokeDWord(LData, LBuilder.PeOffset, $12345678); // испорченная сигнатура PE
  finally
    LBuilder.Free;
  end;
  Assert.AreEqual(Ord(bkMsDos), Ord(Detect(LData, 'x.exe').Kind));
  // e_lfanew за концом файла.
  LData := TestMinimalPe;
  PokeDWord(LData, $3C, Cardinal(Length(LData) + 100));
  Assert.AreEqual(Ord(bkMsDos), Ord(Detect(LData, 'x.exe').Kind));
  // Обрезанный файл: только заголовок MZ.
  Assert.AreEqual(Ord(bkMsDos), Ord(Detect(Copy(TestMinimalPe, 0, 64), 'x.exe').Kind));
end;

procedure TBinaryLabBasicsTests.IdentifyAt_StrictRejectsWeakSignatures;
var
  LReader: TMHBinaryReader;
  LKind: TMHBinaryKind;
  LDescription: string;
  LSize: Int64;
  LData: TBytes;
begin
  // Внутри данных: случайные «MZ», «BM», текст и FF D8 FF без маркера — не объекты.
  LData := TestConcat([TestRandomBytes(100), TestAscii('MZ junk'), TestAscii('BM....'),
    TestAscii('plain text here'), TestBytes([$FF, $D8, $FF, $00]), TestRandomBytes(100)]);
  LReader := Reader(LData);
  try
    Assert.IsFalse(MHIdentifyAt(LReader, 100, True, LKind, LDescription, LSize), 'MZ без PE');
    Assert.IsTrue(MHIdentifyAt(LReader, 100, False, LKind, LDescription, LSize), 'Нестрого — MS-DOS');
    Assert.AreEqual(Ord(bkMsDos), Ord(LKind));
    Assert.IsFalse(MHIdentifyAt(LReader, 107, True, LKind, LDescription, LSize), 'BM');
    Assert.IsFalse(MHIdentifyAt(LReader, 113, True, LKind, LDescription, LSize), 'Текст');
    Assert.IsFalse(MHIdentifyAt(LReader, 128, True, LKind, LDescription, LSize), 'JPEG без маркера');
    Assert.IsFalse(MHIdentifyAt(LReader, Length(LData) + 10, False, LKind, LDescription, LSize), 'За концом');
  finally
    LReader.Free;
  end;
  // Настоящий PE внутри данных — найден, размер по секциям.
  LData := TestConcat([TestRandomBytes(1000), TestMinimalPe, TestRandomBytes(500)]);
  LReader := Reader(LData);
  try
    Assert.IsTrue(MHIdentifyAt(LReader, 1000, True, LKind, LDescription, LSize));
    Assert.AreEqual(Ord(bkPE), Ord(LKind));
    Assert.AreEqual<Int64>(Length(TestMinimalPe), LSize);
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabBasicsTests.ProbePe_ImageEndAndHugeLfanew;
var
  LReader: TMHBinaryReader;
  LInfo: TMHPeQuickInfo;
  LBuilder: TTestPeBuilder;
  LData: TBytes;
begin
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', TestCodeBytes(3000), SCN_TEXT);
    LBuilder.Overlay := TestRandomBytes(777);
    LData := LBuilder.Build;
    LReader := Reader(LData);
    try
      Assert.IsTrue(MHProbePe(LReader, 0, LInfo));
      Assert.IsTrue(LInfo.Is64);
      Assert.AreEqual<Word>($8664, LInfo.Machine);
      Assert.AreEqual<Int64>(LBuilder.ImageEnd, LInfo.ImageEnd, 'Оверлей не входит в образ');
    finally
      LReader.Free;
    end;
  finally
    LBuilder.Free;
  end;
  PokeDWord(LData, $3C, $7FFFFFFF);
  LReader := Reader(LData);
  try
    Assert.IsFalse(MHProbePe(LReader, 0, LInfo), 'Огромный e_lfanew');
  finally
    LReader.Free;
  end;
end;

procedure TBinaryLabBasicsTests.Entropy_ShannonBounds;
var
  LCounts: array[Byte] of Int64;
  I: Integer;
begin
  FillChar(LCounts, SizeOf(LCounts), 0);
  Assert.AreEqual(0.0, MHShannonEntropy(LCounts, 0), 'Нет данных');
  LCounts[7] := 1000;
  Assert.AreEqual(0.0, MHShannonEntropy(LCounts, 1000), 1e-9, 'Один байт');
  LCounts[8] := 1000;
  Assert.AreEqual(1.0, MHShannonEntropy(LCounts, 2000), 1e-9, 'Два равновероятных');
  for I := 0 to 255 do
    LCounts[I] := 10;
  Assert.AreEqual(8.0, MHShannonEntropy(LCounts, 2560), 1e-9, 'Равномерное распределение');
  Assert.AreEqual(Ord(ecEmpty), Ord(MHEntropyClassOf(0.2)));
  Assert.AreEqual(Ord(ecText), Ord(MHEntropyClassOf(4.5)));
  Assert.AreEqual(Ord(ecCode), Ord(MHEntropyClassOf(6.0)));
  Assert.AreEqual(Ord(ecCompressed), Ord(MHEntropyClassOf(7.2)));
  Assert.AreEqual(Ord(ecEncrypted), Ord(MHEntropyClassOf(7.95)));
  Assert.AreEqual('0x0001F400', MHHexOffset($1F400));
  Assert.AreEqual('—', MHHexOffset(-1));
end;

procedure TBinaryLabBasicsTests.Options_Normalized;
var
  LOptions: TMHBinaryLabOptions;
begin
  LOptions := TMHBinaryLabOptions.Default;
  Assert.IsTrue(LOptions.VerifySignature);
  LOptions.MaxScanBytes := 1;
  LOptions.MinStringLength := 0;
  LOptions.MaxStringLength := 1;
  LOptions.MaxStrings := -1;
  LOptions.EntropyBlockSize := 3;
  LOptions := LOptions.Normalized;
  Assert.AreEqual<Int64>(4096, LOptions.MaxScanBytes);
  Assert.AreEqual(3, LOptions.MinStringLength);
  Assert.AreEqual(3, LOptions.MaxStringLength, 'Не меньше минимальной');
  Assert.AreEqual(0, LOptions.MaxStrings);
  Assert.AreEqual(64, LOptions.EntropyBlockSize);
  LOptions.EntropyBlockSize := 0;
  Assert.AreEqual(0, LOptions.Normalized.EntropyBlockSize, '0 — подбирается автоматически');
end;

end.
