unit MineHunter.Tests.FileScan;

{
  Проверка файлов на дисках: правила классификации и обход папок на
  виртуальной файловой системе (майнер, конфигурация пула, сценарий,
  WinRing0, маскировка, скрытый exe, папка Windows, ссылки-петли,
  исключения, отмена) и интеграционная проверка на временной папке.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.FileScan;

type
  TFakeScanFs = class(TInterfacedObject, IMHFileScanFs)
  private
    FFiles: TDictionary<string, TBytes>;
    FAttrs: TDictionary<string, Cardinal>;
    FDirs: TList<string>;
    FReparse: TList<string>;
    FDenied: TList<string>;
  public
    Reads: Integer;
    Lists: Integer;
    constructor Create;
    destructor Destroy; override;
    procedure AddFile(const APath, AContent: string; AAttributes: Cardinal = 0);
    procedure AddDir(const APath: string);
    procedure AddJunction(const APath: string);
    procedure Deny(const APath: string);
    function ListDirectory(const APath: string; out AEntries: TArray<TMHFsEntry>): Boolean;
    function ReadHead(const APath: string; AMaxBytes: Integer; out AData: TBytes): Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TFileScanRuleTests = class
  public
    [Test] procedure MinerMarkers;
    [Test] procedure ReadLimits;
    [Test] procedure Classify_MinerName;
    [Test] procedure Classify_ConfigScriptAndStrings;
    [Test] procedure Classify_Masquerade_HiddenExe_Artifact;
    [Test] procedure Classify_Clean;
    [Test] procedure Classify_HiddenAndNearMiner;
    [Test] procedure Hidden_AttributesText;
    [Test] procedure Hidden_NoteExplainsFileAndFolders;
    [Test] procedure Hidden_NothingHiddenOrNoData_Empty;
    [Test] procedure Classify_KeepsAttributesInHit;
    [Test] procedure AntivirusBlock_PolicyDetected;
    [Test] procedure AntivirusBlock_OrdinaryPoliciesIgnored;
    [Test] procedure Classify_AntivirusPolicyAndScript;
    [Test] procedure ReadLimits_XmlOnlyHiddenOrSuspicious;
  end;

  [TestFixture]
  [Category('Unit')]
  TFileScannerTests = class
  public
    [Test] procedure Run_FindsMinerKit_SortedByScore;
    [Test] procedure Run_SkipsWindowsJunctionsDeniedAndExcluded;
    [Test] procedure Run_Cancel;
  end;

  [TestFixture]
  [Category('Integration')]
  TFileScanIntegrationTests = class
  public
    [Test] procedure RealFolder_FindsPlantedFiles;
    [Test] procedure RealHiddenSystemFile_AttributesAndNote;
  end;

implementation

uses
  System.IOUtils, Winapi.Windows, MineHunter.Core.FileScan.WinApi;

const
  WINDIR = 'C:\Windows';
  XMRIG_CONFIG = '{"donate-level": 1, "pools": [{"url": "stratum+tcp://pool.example:3333"}]}';

function Bytes(const AText: string): TBytes;
begin
  Result := TEncoding.UTF8.GetBytes(AText);
end;

{ TFakeScanFs }

constructor TFakeScanFs.Create;
begin
  inherited Create;
  FFiles := TDictionary<string, TBytes>.Create;
  FAttrs := TDictionary<string, Cardinal>.Create;
  FDirs := TList<string>.Create;
  FReparse := TList<string>.Create;
  FDenied := TList<string>.Create;
end;

destructor TFakeScanFs.Destroy;
begin
  FDenied.Free;
  FReparse.Free;
  FDirs.Free;
  FAttrs.Free;
  FFiles.Free;
  inherited;
end;

procedure TFakeScanFs.AddDir(const APath: string);
var
  LPath: string;
begin
  LPath := ExcludeTrailingPathDelimiter(APath).ToLower;
  while (LPath <> '') and not FDirs.Contains(LPath) do
  begin
    FDirs.Add(LPath);
    LPath := ExcludeTrailingPathDelimiter(ExtractFilePath(LPath));
    if Length(LPath) <= 2 then
      Break;
  end;
end;

procedure TFakeScanFs.AddFile(const APath, AContent: string; AAttributes: Cardinal);
begin
  AddDir(ExtractFilePath(APath));
  FFiles.AddOrSetValue(APath.ToLower, Bytes(AContent));
  FAttrs.AddOrSetValue(APath.ToLower, AAttributes);
end;

procedure TFakeScanFs.AddJunction(const APath: string);
begin
  AddDir(APath);
  FReparse.Add(ExcludeTrailingPathDelimiter(APath).ToLower);
end;

procedure TFakeScanFs.Deny(const APath: string);
begin
  AddDir(APath);
  FDenied.Add(ExcludeTrailingPathDelimiter(APath).ToLower);
end;

function TFakeScanFs.ListDirectory(const APath: string; out AEntries: TArray<TMHFsEntry>): Boolean;
var
  LParent, LKey: string;
  LEntry: TMHFsEntry;
begin
  Inc(Lists);
  AEntries := nil;
  LParent := ExcludeTrailingPathDelimiter(APath).ToLower;
  if FDenied.Contains(LParent) then
    Exit(False);
  for LKey in FDirs do
    if SameText(ExcludeTrailingPathDelimiter(ExtractFilePath(LKey)), LParent) then
    begin
      LEntry.Name := ExtractFileName(LKey);
      LEntry.Attributes := FILE_ATTRIBUTE_DIRECTORY_MH;
      if FReparse.Contains(LKey) then
        LEntry.Attributes := LEntry.Attributes or FILE_ATTRIBUTE_REPARSE_MH;
      LEntry.SizeBytes := 0;
      AEntries := AEntries + [LEntry];
    end;
  for LKey in FFiles.Keys do
    if SameText(ExcludeTrailingPathDelimiter(ExtractFilePath(LKey)), LParent) then
    begin
      LEntry.Name := ExtractFileName(LKey);
      LEntry.Attributes := FAttrs[LKey];
      LEntry.SizeBytes := Length(FFiles[LKey]);
      AEntries := AEntries + [LEntry];
    end;
  Result := True;
end;

function TFakeScanFs.ReadHead(const APath: string; AMaxBytes: Integer; out AData: TBytes): Boolean;
begin
  Inc(Reads);
  Result := FFiles.TryGetValue(APath.ToLower, AData);
  if Result and (Length(AData) > AMaxBytes) then
    SetLength(AData, AMaxBytes);
end;

function Classify(const APath, AContent: string; AAttributes: Cardinal; out AHit: TMHScanHit): Boolean;
var
  LData: TBytes;
begin
  LData := Bytes(AContent);
  if MHScanReadLimit(APath, AAttributes, Length(LData)) = 0 then
    LData := nil;
  Result := MHClassifyFile(APath, AAttributes, Length(Bytes(AContent)), LData, WINDIR,
    TMHRiskThresholds.Default, AHit);
end;

function HasCode(const AHit: TMHScanHit; const ACode: string): Boolean;
var
  LEvidence: TMHEvidence;
begin
  for LEvidence in AHit.Evidence do
    if LEvidence.Code = ACode then
      Exit(True);
  Result := False;
end;

{ TFileScanRuleTests }

procedure TFileScanRuleTests.MinerMarkers;
begin
  Assert.AreEqual('stratum+tcp://', MHFindMinerMarker(Bytes('url=STRATUM+TCP://pool:3333')));
  Assert.AreEqual('"donate-level"', MHFindMinerMarker(Bytes('{"donate-level":1}')));
  Assert.AreEqual('stratum+ssl://', MHFindMinerMarker(TEncoding.Unicode.GetBytes('pool stratum+ssl://x')),
    'Строки UTF-16');
  Assert.AreEqual('cryptonight', MHFindMinerMarker(TBytes.Create(0, 1, 2, Ord('c'), Ord('r'), Ord('y'),
    Ord('p'), Ord('t'), Ord('o'), Ord('n'), Ord('i'), Ord('g'), Ord('h'), Ord('t'), 0)), 'Внутри бинарных данных');
  Assert.AreEqual('', MHFindMinerMarker(Bytes('обычный текстовый файл, ничего особенного')));
  Assert.AreEqual('', MHFindMinerMarker(nil));
end;

procedure TFileScanRuleTests.ReadLimits;
begin
  Assert.AreEqual(100, MHScanReadLimit('D:\cfg\config.json', 0, 100));
  Assert.AreEqual(0, MHScanReadLimit('D:\cfg\big.json', 0, MH_SCAN_TEXT_LIMIT + 1), 'Большие тексты не читаются');
  Assert.AreEqual(50, MHScanReadLimit('D:\run.bat', 0, 50));
  Assert.AreEqual(0, MHScanReadLimit('D:\Games\game.exe', 0, 1000), 'Программы в обычных местах не читаются');
  Assert.AreEqual(1000, MHScanReadLimit('C:\Users\u\AppData\Local\Temp\x.exe', 0, 1000));
  Assert.AreEqual(1000, MHScanReadLimit('D:\Tools\x.exe', FILE_ATTRIBUTE_HIDDEN_MH, 1000), 'Скрытые — читаются');
  Assert.AreEqual(0, MHScanReadLimit('C:\Users\u\AppData\Local\Temp\x.exe', 0, MH_SCAN_BINARY_LIMIT + 1));
  Assert.AreEqual(0, MHScanReadLimit('D:\photo.jpg', 0, 100));
  Assert.AreEqual(0, MHScanReadLimit('D:\empty.txt', 0, 0));
end;

procedure TFileScanRuleTests.Classify_MinerName;
var
  LHit: TMHScanHit;
begin
  Assert.IsTrue(Classify('D:\Downloads\xmrig-6.21\xmrig.exe', 'MZ', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MINER_NAME));
  Assert.IsTrue(LHit.Level >= rlSuspicious, 'Майнер в «Загрузках»');
  Assert.IsTrue(HasCode(LHit, EV_FILE_LOCATION));
  Assert.IsFalse(HasCode(LHit, EV_FILE_MINER_ARTIFACT), 'xmrig.exe — не «спутник», а сам майнер');
  Assert.IsFalse(Classify('D:\Docs\xmrig.txt', 'notes about mining', 0, LHit), 'Только исполняемые файлы');
end;

procedure TFileScanRuleTests.Classify_ConfigScriptAndStrings;
var
  LHit: TMHScanHit;
begin
  Assert.IsTrue(Classify('C:\ProgramData\WindowsTask\config.json', XMRIG_CONFIG, 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_POOL_CONFIG));
  Assert.IsTrue(Classify('C:\ProgramData\WindowsTask\winlogon.bat', 'start AMD.exe -o stratum+tcp://p:3333', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MINER_SCRIPT));
  Assert.IsTrue(Classify('D:\scripts\run.cmd', 'xmrig.exe --donate-level 1 -o pool:3333', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MINER_SCRIPT));
  Assert.IsTrue(Classify('C:\Users\u\AppData\Local\Temp\AMD.exe', 'MZ....stratum+tcp://...', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MINER_STRINGS), 'Строки майнера в программе из Temp');
  Assert.IsTrue(LHit.Level >= rlSuspicious);
  Assert.IsFalse(Classify('D:\Games\Game\game.exe', 'MZ....stratum+tcp://...', 0, LHit),
    'Программы из обычных мест не читаются — нет и ложных совпадений');
end;

procedure TFileScanRuleTests.Classify_Masquerade_HiddenExe_Artifact;
var
  LHit: TMHScanHit;
begin
  Assert.IsTrue(Classify('C:\ProgramData\svchost.exe', 'MZ', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MASQUERADE));
  Assert.IsFalse(Classify(WINDIR + '\System32\svchost.exe', 'MZ', 0, LHit), 'Настоящий svchost');
  Assert.IsTrue(Classify('C:\ProgramData\WindowsTask\WinRing0x64.sys', 'MZ', 0, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_MINER_ARTIFACT));
  Assert.IsTrue(Classify('C:\ProgramData\AMD.exe', 'MZ',
    FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH, LHit));
  Assert.IsTrue(HasCode(LHit, EV_FILE_HIDDEN_EXE));
end;

procedure TFileScanRuleTests.Classify_Clean;
var
  LHit: TMHScanHit;
begin
  Assert.IsFalse(Classify('D:\Programs\app\app.exe', 'MZ', 0, LHit));
  Assert.IsFalse(Classify('D:\Docs\settings.json', '{"theme":"dark"}', 0, LHit));
  Assert.IsFalse(Classify('C:\Users\u\AppData\Local\Temp\setup.exe', 'MZ installer', 0, LHit),
    'Программа во временной папке без других признаков — не находка');
  Assert.IsFalse(Classify('D:\backup.bat', 'robocopy C:\ D:\backup /MIR', 0, LHit));
end;

procedure TFileScanRuleTests.Classify_HiddenAndNearMiner;
var
  LHit: TMHScanHit;
begin
  // Набор с машины пользователя: скрытый системный AMD.exe рядом с WinRing0x64.sys.
  Assert.IsTrue(MHClassifyFile('C:\ProgramData\WindowsTask\AMD.exe',
    FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH, 74 * 1024 * 1024, nil, WINDIR,
    TMHRiskThresholds.Default, LHit, True));
  Assert.IsTrue(HasCode(LHit, EV_FILE_HIDDEN_EXE));
  Assert.IsTrue(HasCode(LHit, EV_FILE_NEAR_MINER));
  Assert.IsTrue(LHit.Level >= rlSuspicious, MHRiskLevelToString(LHit.Level));
  // Скрытый exe в Program Files — обычная установка, не признак.
  Assert.IsFalse(MHClassifyFile('C:\Program Files\Vendor\helper.exe',
    FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH, 1000, nil, WINDIR, TMHRiskThresholds.Default, LHit));
  // Файлы подкачки и гибернации Windows — скрытые и системные, но не программы.
  Assert.IsFalse(MHClassifyFile('C:\pagefile.sys', FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH,
    8 * 1024 * 1024, nil, WINDIR, TMHRiskThresholds.Default, LHit));
  Assert.IsFalse(MHClassifyFile('C:\hiberfil.sys', FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH,
    8 * 1024 * 1024, nil, WINDIR, TMHRiskThresholds.Default, LHit));
  // Только скрытый (без «системный») — не признак.
  Assert.IsFalse(MHClassifyFile('D:\Tools\tool.exe', FILE_ATTRIBUTE_HIDDEN_MH, 1000, nil, WINDIR,
    TMHRiskThresholds.Default, LHit));
  // Соседство с майнером не делает подозрительными документы.
  Assert.IsFalse(MHClassifyFile('D:\Downloads\readme.txt', 0, 10, nil, WINDIR, TMHRiskThresholds.Default,
    LHit, True));
  Assert.IsTrue(MHScanReadLimit('C:\ProgramData\WindowsTask\AMD.exe', FILE_ATTRIBUTE_HIDDEN_MH,
    74 * 1024 * 1024) > 0, 'Файлы до 128 МБ читаются');
end;

{ TFileScannerTests }

function MinerKitFs: TFakeScanFs;
begin
  Result := TFakeScanFs.Create;
  Result.AddFile('C:\ProgramData\WindowsTask\AMD.exe', 'MZ stratum+tcp://pool',
    FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH);
  Result.AddFile('C:\ProgramData\WindowsTask\WinRing0x64.sys', 'MZ', FILE_ATTRIBUTE_HIDDEN_MH);
  Result.AddFile('C:\ProgramData\WindowsTask\new.xml', '<task/>');
  Result.AddFile('D:\Downloads\config.json', XMRIG_CONFIG);
  Result.AddFile('D:\Photos\cat.jpg', 'jpeg');
  Result.AddFile('D:\Docs\readme.txt', 'hello');
  Result.AddFile(WINDIR + '\System32\xmrig.exe', 'MZ'); // в System32 не проверяется (кроме Temp/Fonts/Debug)
  Result.AddFile(WINDIR + '\Temp\xmrig.exe', 'MZ');
end;

procedure TFileScannerTests.Run_FindsMinerKit_SortedByScore;
var
  LFs: TFakeScanFs;
  LScanner: TMHFileScanner;
  LHits: TArray<TMHScanHit>;
  LPaths: string;
  LHit: TMHScanHit;
  I, LProgressCalls: Integer;
begin
  LFs := MinerKitFs;
  LScanner := TMHFileScanner.Create(LFs, WINDIR, [], TMHRiskThresholds.Default);
  try
    LProgressCalls := 0;
    LHits := LScanner.Run(['C:\', 'D:\'], nil,
      procedure(const AProgress: TMHScanProgress)
      begin
        Inc(LProgressCalls);
      end);
    LPaths := '';
    for LHit in LHits do
      LPaths := LPaths + LHit.Path + '; ';
    Assert.AreEqual(4, Integer(Length(LHits)), LPaths);
    for I := 1 to High(LHits) do
      Assert.IsTrue(LHits[I - 1].Score >= LHits[I].Score, 'Опасные — первыми');
    LPaths := LPaths.ToLower; // виртуальная ФС хранит пути в нижнем регистре
    Assert.IsTrue(LPaths.Contains('amd.exe'), LPaths);
    Assert.IsTrue(LPaths.Contains('winring0x64.sys'), LPaths);
    Assert.IsTrue(LPaths.Contains('config.json'), LPaths);
    Assert.IsTrue(LPaths.Contains('windows\temp\xmrig.exe'), LPaths);
    Assert.IsFalse(LPaths.Contains('system32'), LPaths);
    Assert.IsTrue(LScanner.Progress.Done);
    Assert.AreEqual<Int64>(7, LScanner.Progress.FilesSeen, 'Все файлы, кроме System32, просмотрены');
    Assert.AreEqual(4, LScanner.Progress.Hits);
    Assert.IsTrue(LProgressCalls > 2);
    Assert.AreEqual(5, LFs.Reads, 'Содержимое читается только у кандидатов (тексты, скрытые, из Temp)');
  finally
    LScanner.Free;
  end;
end;

procedure TFileScannerTests.Run_SkipsWindowsJunctionsDeniedAndExcluded;
var
  LFs: TFakeScanFs;
  LScanner: TMHFileScanner;
  LHits: TArray<TMHScanHit>;
begin
  LFs := MinerKitFs;
  LFs.AddJunction('C:\Users\u\Application Data');      // ссылка-петля
  LFs.AddFile('C:\Users\u\Application Data\xmrig.exe', 'MZ');
  LFs.Deny('C:\System Volume Information');
  LFs.AddFile('C:\Tools\MineHunter\Quarantine\abc\xmrig.exe', 'MZ');
  LScanner := TMHFileScanner.Create(LFs, WINDIR, ['C:\Tools\MineHunter\Quarantine'], TMHRiskThresholds.Default,
    function(const APath: string): Boolean
    begin
      Result := APath.EndsWith('config.json');
    end);
  try
    LHits := LScanner.Run(['C:\', 'D:\'], nil, nil);
    Assert.AreEqual(3, Integer(Length(LHits)), 'Исключение, карантин и ссылка пропущены');
    Assert.IsTrue(LScanner.Progress.FoldersSkipped >= 2);
  finally
    LScanner.Free;
  end;
  Assert.WillRaise(
    procedure
    begin
      TMHFileScanner.Create(nil, WINDIR, [], TMHRiskThresholds.Default).Free;
    end, EArgumentNilException);
end;

procedure TFileScannerTests.Run_Cancel;
var
  LScanner: TMHFileScanner;
  LCalls: Integer;
begin
  LScanner := TMHFileScanner.Create(MinerKitFs, WINDIR, [], TMHRiskThresholds.Default);
  try
    LCalls := 0;
    LScanner.Run(['C:\', 'D:\'],
      function: Boolean
      begin
        Inc(LCalls);
        Result := LCalls > 2;
      end, nil);
    Assert.IsTrue(LScanner.Progress.Cancelled);
    Assert.IsTrue(LScanner.Progress.Done);
    Assert.IsTrue(LScanner.Progress.FilesSeen <= 3);
  finally
    LScanner.Free;
  end;
end;

{ TFileScanIntegrationTests }

/// Атрибуты по таблице: 'C:\ProgramData' и т. п. (нет в таблице — MH_NO_ATTRIBUTES).
function AttributesFrom(const APairs: array of string): TMHGetAttributes;
var
  LMap: TArray<string>;
  I: Integer;
begin
  SetLength(LMap, Length(APairs));
  for I := 0 to High(APairs) do
    LMap[I] := APairs[I];
  Result :=
    function(const APath: string): Cardinal
    var
      J: Integer;
    begin
      J := 0;
      while J < High(LMap) do
      begin
        if SameText(LMap[J], APath) then
          Exit(StrToInt(LMap[J + 1]));
        Inc(J, 2);
      end;
      Result := MH_NO_ATTRIBUTES;
    end;
end;

procedure TFileScanRuleTests.Hidden_AttributesText;
begin
  Assert.AreEqual('скрытый', MHHiddenAttributesText($2));
  Assert.AreEqual('системный', MHHiddenAttributesText($4));
  Assert.AreEqual('скрытый, системный', MHHiddenAttributesText($26));
  Assert.AreEqual('', MHHiddenAttributesText($20), 'Только «архивный» — не скрыт');
  Assert.AreEqual('', MHHiddenAttributesText(0));
  Assert.AreEqual('', MHHiddenAttributesText(MH_NO_ATTRIBUTES), 'Не прочитаны — не «скрытый»');
end;

procedure TFileScanRuleTests.Hidden_NoteExplainsFileAndFolders;
var
  LGet: TMHGetAttributes;
  LNote: string;
begin
  // Как на компьютере пользователя: win.exe скрытый и системный, ProgramData — скрытая папка,
  // у корня диска свои атрибуты (скрытый, системный) — он не считается.
  LGet := AttributesFrom(['C:\ProgramData\Microsoft\win.exe', '38', 'C:\ProgramData\Microsoft', '16',
    'C:\ProgramData', '18', 'C:', '22', 'C:\ProgramData\Microsoft\temp', '16',
    'C:\ProgramData\Microsoft\temp\H.bat', '32']);
  Assert.AreEqual('файл скрытый, системный; в скрытой папке',
    MHHiddenShortText('C:\ProgramData\Microsoft\win.exe', LGet));
  LNote := MHHiddenLocationNote('C:\ProgramData\Microsoft\win.exe', LGet);
  Assert.Contains(LNote, '«win.exe» помечен как скрытый, системный');
  Assert.Contains(LNote, 'Скрытая папка на пути: C:\ProgramData.');
  Assert.Contains(LNote, 'может выглядеть пустой');
  Assert.Contains(LNote, 'Скрытые элементы');
  Assert.Contains(LNote, 'Скрывать защищённые системные файлы', 'Для системного файла — и этот флажок');
  Assert.DoesNotContain(LNote, 'C:,', 'Корень диска не перечисляется');
  // Обычный файл в скрытой папке: только папка, без совета про системные файлы.
  Assert.AreEqual('в скрытой папке', MHHiddenShortText('C:\ProgramData\Microsoft\temp\H.bat', LGet));
  LNote := MHHiddenLocationNote('C:\ProgramData\Microsoft\temp\H.bat', LGet);
  Assert.Contains(LNote, 'C:\ProgramData');
  Assert.DoesNotContain(LNote, 'помечен как');
  Assert.DoesNotContain(LNote, 'защищённые системные');
  // Несколько скрытых папок — все, от ближней к дальней.
  LGet := AttributesFrom(['D:\a\b\c.exe', '32', 'D:\a\b', '18', 'D:\a', '18']);
  Assert.Contains(MHHiddenLocationNote('D:\a\b\c.exe', LGet), 'D:\a\b, D:\a');
  // Сетевой путь: корень ресурса не считается.
  LGet := AttributesFrom(['\\srv\share\x\m.exe', '2', '\\srv\share\x', '16', '\\srv\share', '18']);
  Assert.AreEqual('файл скрытый', MHHiddenShortText('\\srv\share\x\m.exe', LGet));
end;

procedure TFileScanRuleTests.Hidden_NothingHiddenOrNoData_Empty;
var
  LGet: TMHGetAttributes;
begin
  LGet := AttributesFrom(['C:\Tools\app.exe', '32', 'C:\Tools', '16', 'C:', '22']);
  Assert.AreEqual('', MHHiddenShortText('C:\Tools\app.exe', LGet));
  Assert.AreEqual('', MHHiddenLocationNote('C:\Tools\app.exe', LGet));
  // Файла нет и атрибуты папок не прочитать — ничего не утверждается.
  Assert.AreEqual('', MHHiddenLocationNote('E:\gone\x.exe', AttributesFrom([])));
  Assert.AreEqual('', MHHiddenLocationNote('', LGet));
  Assert.AreEqual('', MHHiddenLocationNote('C:\Tools\app.exe', nil));
  Assert.AreEqual('', MHHiddenShortText('C:\Tools\app.exe', nil));
  Assert.AreEqual('', MHHiddenShortText('x.exe', LGet), 'Без папки');
end;

procedure TFileScanRuleTests.Classify_KeepsAttributesInHit;
var
  LHit: TMHScanHit;
begin
  Assert.IsTrue(MHClassifyFile('C:\Users\u\AppData\Roaming\svc\xmrig.exe', $26, 1000, nil, 'C:\Windows',
    TMHRiskThresholds.Default, LHit));
  Assert.AreEqual<Cardinal>($26, LHit.Attributes);
end;

const
  // Фрагмент политики из набора C:\ProgramData\WindowsTask (сокращён).
  AV_POLICY =
    '<AppLockerPolicy Version="1">'#13#10 +
    '  <RuleCollection Type="Exe" EnforcementMode="NotConfigured">'#13#10 +
    '    <FilePublisherRule Id="1" Name="Подписано O=AO KASPERSKY LAB" UserOrGroupSid="S-1-1-0" Action="Deny">'#13#10 +
    '      <Conditions><FilePublisherCondition PublisherName="O=AO KASPERSKY LAB, L=MOSCOW, C=RU" ' +
    'ProductName="*" BinaryName="*" /></Conditions></FilePublisherRule>'#13#10 +
    '    <FilePublisherRule Id="2" Name="ESET" UserOrGroupSid="S-1-1-0" Action="Deny">'#13#10 +
    '      <Conditions><FilePublisherCondition PublisherName="O=ESET, SPOL. S R.O., L=BRATISLAVA, C=SK" ' +
    'ProductName="*" BinaryName="*" /></Conditions></FilePublisherRule>'#13#10 +
    '    <FilePublisherRule Id="3" Name="MBAM" UserOrGroupSid="S-1-1-0" Action="Deny">'#13#10 +
    '      <Conditions><FilePublisherCondition PublisherName="O=MALWAREBYTES INC., S=CALIFORNIA, C=US" ' +
    'ProductName="*" BinaryName="*" /></Conditions></FilePublisherRule>'#13#10 +
    '  </RuleCollection>'#13#10 +
    '</AppLockerPolicy>';

procedure TFileScanRuleTests.AntivirusBlock_PolicyDetected;
var
  LText: string;
begin
  LText := MHFindAntivirusBlock(TEncoding.UTF8.GetBytes(AV_POLICY));
  Assert.Contains(LText, 'запретов: 3');
  Assert.Contains(LText, 'антивирусов в списке: 3');
  Assert.Contains(LText, 'kaspersky, eset, malwarebytes');
  // Политика в UTF-16 (так сохраняет Get-AppLockerPolicy -Xml) — то же.
  Assert.AreEqual(LText, MHFindAntivirusBlock(TEncoding.Unicode.GetBytes(AV_POLICY)));
  // Сценарий, применяющий политику.
  Assert.AreEqual('Set-AppLockerPolicy', MHFindPolicyCommand(TEncoding.ANSI.GetBytes(
    '@echo off'#13#10'PowerShell.exe -command "Import-Module applocker" ; ' +
    '"Set-AppLockerPolicy -XMLPolicy C:\ProgramData\WindowsTask\new.xml"')));
  Assert.AreEqual('Set-AppLockerPolicy', MHFindPolicyCommand(TEncoding.Unicode.GetBytes('set-applockerpolicy -x a')));
end;

procedure TFileScanRuleTests.AntivirusBlock_OrdinaryPoliciesIgnored;
begin
  Assert.AreEqual('', MHFindAntivirusBlock(nil));
  Assert.AreEqual('', MHFindAntivirusBlock(TEncoding.UTF8.GetBytes('kaspersky eset action="deny"')),
    'Не политика AppLocker');
  // Корпоративная политика: разрешения и запрет одной программы — не находка.
  Assert.AreEqual('', MHFindAntivirusBlock(TEncoding.UTF8.GetBytes(
    '<AppLockerPolicy><FilePublisherRule Action="Allow" Name="KASPERSKY ESET" /></AppLockerPolicy>')),
    'Только разрешения');
  Assert.AreEqual('', MHFindAntivirusBlock(TEncoding.UTF8.GetBytes(
    '<AppLockerPolicy><FilePublisherRule Action="Deny" Name="O=AO KASPERSKY LAB" /></AppLockerPolicy>')),
    'Один издатель — может быть обычной политикой');
  Assert.AreEqual('', MHFindPolicyCommand(TEncoding.ANSI.GetBytes('Get-AppLockerPolicy -Effective')));
  Assert.AreEqual('', MHFindPolicyCommand(nil));
end;

procedure TFileScanRuleTests.Classify_AntivirusPolicyAndScript;
var
  LHit: TMHScanHit;
begin
  Assert.IsTrue(MHClassifyFile('C:\ProgramData\WindowsTask\new.xml', $26, Length(AV_POLICY),
    TEncoding.UTF8.GetBytes(AV_POLICY), 'C:\Windows', TMHRiskThresholds.Default, LHit));
  Assert.AreEqual(EV_FILE_AV_BLOCK, LHit.Evidence[0].Code);
  Assert.IsTrue(LHit.Score >= 85, IntToStr(LHit.Score));
  Assert.IsTrue(Ord(LHit.Level) >= Ord(rlHighlySuspicious), 'Высокая степень подозрения');
  Assert.IsTrue(MHClassifyFile('C:\ProgramData\WindowsTask\winlogon.bat', $26, 120, TEncoding.ANSI.GetBytes(
    'PowerShell.exe -command "Set-AppLockerPolicy -XMLPolicy C:\ProgramData\WindowsTask\new.xml"'),
    'C:\Windows', TMHRiskThresholds.Default, LHit));
  Assert.AreEqual(EV_FILE_POLICY_SCRIPT, LHit.Evidence[0].Code);
  // Тот же текст в документе (.txt) — не сценарий: только политика считается.
  Assert.IsFalse(MHClassifyFile('C:\Users\u\Documents\notes.txt', 0, 40, TEncoding.ANSI.GetBytes(
    'how to use Set-AppLockerPolicy'), 'C:\Windows', TMHRiskThresholds.Default, LHit));
end;

procedure TFileScanRuleTests.ReadLimits_XmlOnlyHiddenOrSuspicious;
begin
  Assert.AreEqual(31199, MHScanReadLimit('C:\ProgramData\WindowsTask\new.xml', $26, 31199), 'Скрытый системный');
  Assert.AreEqual(500, MHScanReadLimit('D:\Projects\app\settings.xml', $2, 500), 'Скрытый');
  Assert.AreEqual(0, MHScanReadLimit('D:\Projects\app\settings.xml', $20, 500), 'Обычный XML не читается');
  Assert.AreEqual(0, MHScanReadLimit('C:\ProgramData\WindowsTask\new.xml', $26, MH_SCAN_TEXT_LIMIT + 1),
    'Больше лимита текста');
  Assert.AreEqual(0, MHScanReadLimit('C:\ProgramData\WindowsTask\new.xml', $26, 0));
end;

procedure TFileScanIntegrationTests.RealHiddenSystemFile_AttributesAndNote;
var
  LDir, LPath: string;
  LAttr: Cardinal;
begin
  LDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\hidden-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(LDir);
  LPath := TPath.Combine(LDir, 'win.exe');
  try
    TFile.WriteAllText(LPath, 'MZ');
    Assert.IsTrue(SetFileAttributes(PChar(LPath), FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM));
    LAttr := MHWinFileAttributes(LPath);
    Assert.IsTrue(LAttr and FILE_ATTRIBUTE_HIDDEN <> 0);
    Assert.IsTrue(LAttr and FILE_ATTRIBUTE_SYSTEM <> 0);
    Assert.IsTrue(MHHiddenShortText(LPath, MHWinFileAttributes).StartsWith('файл скрытый, системный'));
    Assert.Contains(MHHiddenLocationNote(LPath, MHWinFileAttributes), 'Скрывать защищённые системные файлы');
    Assert.AreEqual(MH_NO_ATTRIBUTES, MHWinFileAttributes(TPath.Combine(LDir, 'нет.exe')));
    Assert.AreEqual(MH_NO_ATTRIBUTES, MHWinFileAttributes(''));
  finally
    SetFileAttributes(PChar(LPath), FILE_ATTRIBUTE_NORMAL);
    TDirectory.Delete(LDir, True);
  end;
end;

procedure TFileScanIntegrationTests.RealFolder_FindsPlantedFiles;
var
  LDir, LDeep: string;
  LScanner: TMHFileScanner;
  LHits: TArray<TMHScanHit>;
  LPaths: string;
  LHit: TMHScanHit;
  LWin: array[0..MAX_PATH] of Char;
  LWinDir: string;
begin
  LDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\scan-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  // Длинный путь (> 260 символов) — проверка префикса \\?\.
  LDeep := LDir;
  while Length(LDeep) < 300 do
    LDeep := TPath.Combine(LDeep, 'very_long_folder_name_for_path_test');
  ForceDirectories('\\?\' + LDeep);
  try
    TFile.WriteAllText(TPath.Combine(LDir, 'pool.json'), XMRIG_CONFIG);
    TFile.WriteAllText(TPath.Combine(LDir, 'notes.txt'), 'nothing here');
    TFile.WriteAllText('\\?\' + TPath.Combine(LDeep, 'start.bat'), 'xmrig.exe -o stratum+tcp://x:1');
    SetString(LWinDir, LWin, GetWindowsDirectory(LWin, MAX_PATH));
    LScanner := TMHFileScanner.Create(TMHWinFileScanFs.Create, LWinDir, [], TMHRiskThresholds.Default);
    try
      LHits := LScanner.Run([LDir], nil, nil);
    finally
      LScanner.Free;
    end;
    LPaths := '';
    for LHit in LHits do
      LPaths := LPaths + LHit.Path + '; ';
    Assert.AreEqual(2, Integer(Length(LHits)), LPaths);
    Assert.IsTrue(LPaths.Contains('pool.json'));
    Assert.IsTrue(LPaths.Contains('start.bat'), 'Файл по длинному пути найден');
    Assert.IsTrue(Length(MHLocalFixedRoots) >= 1);
  finally
    TDirectory.Delete('\\?\' + LDir, True);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TFileScanRuleTests);
  TDUnitX.RegisterTestFixture(TFileScannerTests);
  TDUnitX.RegisterTestFixture(TFileScanIntegrationTests);

end.
