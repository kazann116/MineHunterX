unit MineHunter.Core.FileScan;

{
  Проверка файлов на дисках: поиск майнеров и их следов там, где программа
  сейчас не запущена.

  Что ищется (каждое совпадение — признак с весом и объяснением):
    - исполняемый файл с именем известного майнера (xmrig, nbminer…);
    - спутники майнеров (WinRing0x64.sys — драйвер для доступа к процессору);
    - системное имя Windows вне системной папки (svchost.exe в ProgramData);
    - конфигурация с адресом пула (stratum+tcp://, "donate-level");
    - сценарий (bat, ps1, vbs…), запускающий майнер;
    - скрытый системный исполняемый файл в нетипичном месте;
    - строки майнера внутри исполняемого файла из нетипичного места
      (только для таких файлов: читать содержимое всех программ дорого).
  Обход: только локальные диски; точки повторного анализа (junction, симлинки)
  не раскрываются; папка Windows пропускается, кроме Temp, Fonts и Debug, где
  программ быть не должно; исключения пользователя и заданные папки (карантин,
  сама программа) пропускаются. Отмена проверяется на каждом файле.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

const
  EV_FILE_MINER_NAME = 'FILE_MINER_NAME';
  EV_FILE_MINER_ARTIFACT = 'FILE_MINER_ARTIFACT';
  EV_FILE_MASQUERADE = 'FILE_MASQUERADE';
  EV_FILE_POOL_CONFIG = 'FILE_POOL_CONFIG';
  EV_FILE_MINER_SCRIPT = 'FILE_MINER_SCRIPT';
  EV_FILE_HIDDEN_EXE = 'FILE_HIDDEN_EXECUTABLE';
  EV_FILE_MINER_STRINGS = 'FILE_MINER_STRINGS';
  EV_FILE_LOCATION = 'FILE_SUSPICIOUS_LOCATION';
  EV_FILE_NEAR_MINER = 'FILE_NEAR_MINER';
  EV_FILE_AV_BLOCK = 'FILE_ANTIVIRUS_BLOCK';
  EV_FILE_POLICY_SCRIPT = 'FILE_APPLOCKER_SCRIPT';

  FILE_ATTRIBUTE_HIDDEN_MH = $2;
  FILE_ATTRIBUTE_SYSTEM_MH = $4;
  FILE_ATTRIBUTE_DIRECTORY_MH = $10;
  FILE_ATTRIBUTE_REPARSE_MH = $400;

  /// Размер, до которого читаются конфигурации и сценарии.
  MH_SCAN_TEXT_LIMIT = 256 * 1024;
  /// Размер, до которого читаются исполняемые файлы из нетипичных мест.
  MH_SCAN_BINARY_LIMIT = 128 * 1024 * 1024;

type
  TMHFsEntry = record
    Name: string;
    Attributes: Cardinal;
    SizeBytes: Int64;
    function IsDirectory: Boolean;
    function IsReparsePoint: Boolean;
  end;

  /// Файловая система для проверки (подменяется в тестах).
  IMHFileScanFs = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1D20}']
    /// Содержимое папки без «.» и «..». False — папку прочитать нельзя.
    function ListDirectory(const APath: string; out AEntries: TArray<TMHFsEntry>): Boolean;
    /// Первые AMaxBytes байт файла.
    function ReadHead(const APath: string; AMaxBytes: Integer; out AData: TBytes): Boolean;
  end;

  TMHScanHit = record
  public
    Path: string;
    SizeBytes: Int64;
    /// Атрибуты файла при проверке (FILE_ATTRIBUTE_*).
    Attributes: Cardinal;
    Title: string;
    Evidence: TArray<TMHEvidence>;
    Score: Integer;
    Level: TMHRiskLevel;
  end;

  TMHScanProgress = record
  public
    FilesSeen: Int64;
    FilesInspected: Int64;
    FoldersSkipped: Int64;
    Hits: Integer;
    CurrentFolder: string;
    Done: Boolean;
    Cancelled: Boolean;
  end;

  TMHScanCancel = reference to function: Boolean;
  TMHScanProgressProc = reference to procedure(const AProgress: TMHScanProgress);
  TMHScanExcluded = reference to function(const APath: string): Boolean;

  TMHFileScanner = class
  private
    FFs: IMHFileScanFs;
    FWindowsDir: string;
    FSkipDirs: TArray<string>;
    FThresholds: TMHRiskThresholds;
    FIsExcluded: TMHScanExcluded;
    FProgress: TMHScanProgress;
    FHits: TArray<TMHScanHit>;
    function SkipFolder(const APath: string): Boolean;
    procedure ScanFolder(const APath: string; const ACancel: TMHScanCancel;
      const AOnProgress: TMHScanProgressProc; ADepth: Integer);
    procedure InspectFile(const APath: string; const AEntry: TMHFsEntry; ANearMiner: Boolean);
  public
    /// ASkipDirs — папки, которые не проверяются (карантин, папка самой программы).
    constructor Create(const AFs: IMHFileScanFs; const AWindowsDir: string;
      const ASkipDirs: TArray<string>; const AThresholds: TMHRiskThresholds;
      const AIsExcluded: TMHScanExcluded = nil);
    /// Проверяет папки ARoots (например, «C:\», «D:\»). Возвращает находки, опасные — первыми.
    function Run(const ARoots: TArray<string>; const ACancel: TMHScanCancel;
      const AOnProgress: TMHScanProgressProc): TArray<TMHScanHit>;
    property Progress: TMHScanProgress read FProgress;
  end;

/// Оценка одного файла по имени, месту, атрибутам и (если передано) началу содержимого.
/// False — признаков нет.
function MHClassifyFile(const APath: string; AAttributes: Cardinal; ASize: Int64; const AHead: TBytes;
  const AWindowsDir: string; const AThresholds: TMHRiskThresholds; out AHit: TMHScanHit;
  ANearMiner: Boolean = False): Boolean;

/// Нужно ли читать содержимое файла и сколько байт (0 — не нужно).
function MHScanReadLimit(const APath: string; AAttributes: Cardinal; ASize: Int64): Integer;

/// Признак майнера в содержимом ('' — нет): адрес пула, параметры, имя алгоритма.
function MHFindMinerMarker(const AData: TBytes): string;

/// Политика AppLocker, запрещающая запуск антивирусов (правила Deny с издателями
/// антивирусов): так майнеры не дают себя найти и удалить. '' — нет; иначе — краткое описание
/// («запретов: 47; Kaspersky, ESET, …»). Текст в ANSI/UTF-8 или UTF-16.
function MHFindAntivirusBlock(const AData: TBytes): string;

/// Сценарий применяет политику AppLocker (Set-AppLockerPolicy). '' — нет.
function MHFindPolicyCommand(const AData: TBytes): string;

const
  /// Атрибуты не прочитаны (INVALID_FILE_ATTRIBUTES).
  MH_NO_ATTRIBUTES = Cardinal($FFFFFFFF);

type
  /// Атрибуты файла или папки (MH_NO_ATTRIBUTES — нет или нельзя прочитать).
  TMHGetAttributes = reference to function(const APath: string): Cardinal;

/// «скрытый», «системный», «скрытый, системный» или ''.
function MHHiddenAttributesText(AAttributes: Cardinal): string;

/// Почему файл не виден в Проводнике: сам файл скрытый/системный или лежит в скрытой
/// папке (корень диска не учитывается). '' — ничего не скрыто. Текст объясняет, что папка
/// в Проводнике может выглядеть пустой, и как включить показ скрытых файлов.
function MHHiddenLocationNote(const APath: string; const AGetAttributes: TMHGetAttributes): string;

/// Короткая пометка для таблицы: «файл скрытый, системный», «в скрытой папке» или ''.
function MHHiddenShortText(const APath: string; const AGetAttributes: TMHGetAttributes): string;

implementation

uses
  System.Math, System.StrUtils, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Lang, MineHunter.Core.Paths, MineHunter.Analysis.Indicators;

const
  TEXT_EXTENSIONS: array[0..7] of string = ('.json', '.conf', '.cfg', '.txt', '.ini', '.yaml', '.yml', '.config');
  SCRIPT_EXTENSIONS: array[0..8] of string = ('.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta');
  BINARY_EXTENSIONS: array[0..4] of string = ('.exe', '.dll', '.scr', '.com', '.sys');
  /// Файлы политик и заданий: читаются только скрытые/системные и в подозрительных местах
  /// (XML на диске много — читать каждый было бы долго).
  POLICY_EXTENSIONS: array[0..0] of string = ('.xml');
  /// Издатели антивирусов и средств удаления вредоносных программ (по полю O= сертификата).
  ANTIVIRUS_PUBLISHERS: array[0..23] of string = ('kaspersky', 'eset', 'malwarebytes', 'doctor web', 'avast',
    'avg technologies', 'bitdefender', 'mcafee', 'nortonlifelock', 'symantec', 'sophos', 'trend micro',
    'panda security', 'avira', 'emsisoft', 'comodo', 'webroot', 'ahnlab', 'zemana', 'gridinsoft', 'adlice',
    'surfright', 'cezurity', 'microworld');
  /// Нет записи «Microsoft Windows» в этом списке: Защитник запрещают отдельно, а правило на
  /// подпись Microsoft встречается и в обычных корпоративных политиках.
  /// Признаки майнера в тексте и в бинарных файлах (в нижнем регистре).
  MINER_MARKERS: array[0..9] of string = ('stratum+tcp://', 'stratum+ssl://', 'stratum2+tcp://',
    'stratum1+tcp://', '"donate-level"', '--donate-level', 'xmrig.com', 'cryptonight', '"randomx"',
    'nicehash.com');
  /// Папки внутри Windows, где программ быть не должно (проверяются).
  WINDOWS_CHECKED_SUBDIRS: array[0..2] of string = ('temp', 'fonts', 'debug');

function InList(const AValue: string; const AList: array of string): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

{ TMHFsEntry }

function TMHFsEntry.IsDirectory: Boolean;
begin
  Result := (Attributes and FILE_ATTRIBUTE_DIRECTORY_MH) <> 0;
end;

function TMHFsEntry.IsReparsePoint: Boolean;
begin
  Result := (Attributes and FILE_ATTRIBUTE_REPARSE_MH) <> 0;
end;

function ContainsMarker(const AText: RawByteString): string;
var
  LMarker: string;
begin
  for LMarker in MINER_MARKERS do
    if Pos(RawByteString(AnsiString(LMarker)), AText) > 0 then
      Exit(LMarker);
  Result := '';
end;

function MHFindMinerMarker(const AData: TBytes): string;
var
  LText, LPacked: RawByteString;
  I, N: Integer;
  B: Byte;
begin
  Result := '';
  if Length(AData) = 0 then
    Exit;
  // Байтовое представление в нижнем регистре (без перевода в Unicode: файлы до 64 МБ);
  // непечатные байты заменяются пробелом.
  SetLength(LText, Length(AData));
  for I := 0 to High(AData) do
  begin
    B := AData[I];
    if (B >= Ord('A')) and (B <= Ord('Z')) then
      B := B + 32
    else if (B < 32) or (B >= 127) then
      B := 32;
    LText[I + 1] := AnsiChar(B);
  end;
  Result := ContainsMarker(LText);
  if (Result = '') and (Length(AData) <= MH_SCAN_TEXT_LIMIT) then
  begin
    // Текст в UTF-16: без нулевых байтов «s.t.r.a.t.u.m» превращается в «stratum».
    SetLength(LPacked, Length(AData));
    N := 0;
    for I := 0 to High(AData) do
      if AData[I] <> 0 then
      begin
        Inc(N);
        LPacked[N] := LText[I + 1];
      end;
    SetLength(LPacked, N);
    Result := ContainsMarker(LPacked);
  end;
end;

/// Текст в нижнем регистре: нулевые байты (UTF-16) убираются, непечатные — пробел.
/// Кириллица и прочие не-ASCII символы заменяются пробелом: ищутся ASCII-слова.
function LowerAsciiText(const AData: TBytes): string;
var
  I, N: Integer;
  B: Byte;
begin
  SetLength(Result, Length(AData));
  N := 0;
  for I := 0 to High(AData) do
  begin
    B := AData[I];
    if B = 0 then
      Continue;
    if (B >= Ord('A')) and (B <= Ord('Z')) then
      B := B + 32
    else if (B < 32) or (B >= 127) then
      B := 32;
    Inc(N);
    Result[N] := Char(B);
  end;
  SetLength(Result, N);
end;

function CountOccurrences(const AText, ASub: string): Integer;
var
  P: Integer;
begin
  Result := 0;
  P := Pos(ASub, AText);
  while P > 0 do
  begin
    Inc(Result);
    P := Pos(ASub, AText, P + Length(ASub));
  end;
end;

function MHFindAntivirusBlock(const AData: TBytes): string;
var
  LText, LVendor, LVendors: string;
  LDeny, LFound: Integer;
begin
  Result := '';
  if Length(AData) = 0 then
    Exit;
  LText := LowerAsciiText(AData);
  if Pos('<applockerpolicy', LText) = 0 then
    Exit;
  LDeny := CountOccurrences(LText, 'action="deny"');
  if LDeny = 0 then
    Exit;
  LFound := 0;
  LVendors := '';
  for LVendor in ANTIVIRUS_PUBLISHERS do
    if Pos(LVendor, LText) > 0 then
    begin
      Inc(LFound);
      if LFound <= 6 then
        LVendors := LVendors + IfThen(LVendors <> '', ', ', '') + LVendor;
    end;
  // Одно совпадение может быть случайным (обычная политика с одним правилом);
  // запрет нескольких антивирусов — нет.
  if LFound < 2 then
    Exit;
  if LFound > 6 then
    LVendors := LVendors + ', …';
  Result := Format(MHL('запретов: %d; антивирусов в списке: %d (%s)', 'deny rules: %d; antivirus vendors: %d (%s)'),
    [LDeny, LFound, LVendors]);
end;

function MHFindPolicyCommand(const AData: TBytes): string;
begin
  if (Length(AData) > 0) and (Pos('set-applockerpolicy', LowerAsciiText(AData)) > 0) then
    Result := 'Set-AppLockerPolicy'
  else
    Result := '';
end;

function IsInsideWindows(const APath, AWindowsDir: string): Boolean;
var
  LPath, LWin: string;
begin
  if AWindowsDir = '' then
    Exit(False);
  LPath := IncludeTrailingPathDelimiter(MHNormalizePath(ExtractFilePath(APath), AWindowsDir)).ToLower;
  LWin := IncludeTrailingPathDelimiter(MHNormalizePath(AWindowsDir, AWindowsDir)).ToLower;
  Result := LPath.StartsWith(LWin);
end;

function MHScanReadLimit(const APath: string; AAttributes: Cardinal; ASize: Int64): Integer;
var
  LExt, LReason: string;
begin
  Result := 0;
  if ASize <= 0 then
    Exit;
  LExt := ExtractFileExt(APath).ToLower;
  if InList(LExt, TEXT_EXTENSIONS) or InList(LExt, SCRIPT_EXTENSIONS) then
  begin
    if ASize <= MH_SCAN_TEXT_LIMIT then
      Result := ASize;
  end
  else if InList(LExt, POLICY_EXTENSIONS) then
  begin
    if (ASize <= MH_SCAN_TEXT_LIMIT) and (MHIsSuspiciousLocation(APath, LReason) or
       ((AAttributes and (FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH)) <> 0)) then
      Result := ASize;
  end
  else if InList(LExt, BINARY_EXTENSIONS) and (ASize <= MH_SCAN_BINARY_LIMIT) and
     (MHIsSuspiciousLocation(APath, LReason) or
      ((AAttributes and FILE_ATTRIBUTE_HIDDEN_MH) <> 0)) then
    Result := ASize;
end;

function MHClassifyFile(const APath: string; AAttributes: Cardinal; ASize: Int64; const AHead: TBytes;
  const AWindowsDir: string; const AThresholds: TMHRiskThresholds; out AHit: TMHScanHit;
  ANearMiner: Boolean): Boolean;
var
  LName, LExt, LReason, LMarker, LToken, LText: string;
  LEvidence: TArray<TMHEvidence>;
  LBinary, LScript, LConfig, LHidden, LSuspicious: Boolean;
  LItem: TMHEvidence;
  LRaw: Integer;
begin
  AHit := Default(TMHScanHit);
  Result := False;
  LName := ExtractFileName(APath);
  LExt := ExtractFileExt(LName).ToLower;
  LBinary := InList(LExt, BINARY_EXTENSIONS);
  LScript := InList(LExt, SCRIPT_EXTENSIONS);
  LConfig := InList(LExt, TEXT_EXTENSIONS);
  LHidden := (AAttributes and (FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH)) =
    (FILE_ATTRIBUTE_HIDDEN_MH or FILE_ATTRIBUTE_SYSTEM_MH);
  LSuspicious := MHIsSuspiciousLocation(APath, LReason);
  LEvidence := nil;

  if LBinary and MHIsKnownMinerName(LName) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MINER_NAME,
      MHL('Имя совпадает с известной программой для майнинга', 'The name matches a known mining program'),
      60, LName)];
  if MHIsMinerArtifact(LName) and not MHIsKnownMinerName(LName) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MINER_ARTIFACT,
      MHL('Файл, который майнеры приносят с собой (драйвер для прямого доступа к процессору)',
        'A file that miners bring with them (a driver for direct CPU access)'), 40, LName)];
  if LBinary and not IsInsideWindows(APath, AWindowsDir) and MHIsMasqueradedSystemFile(APath) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MASQUERADE,
      MHL('Системное имя Windows вне системной папки — частая маскировка',
        'A Windows system name outside the system folder — a common disguise'), 40, APath)];

  if Length(AHead) > 0 then
  begin
    // Защита от антивирусов: политика запрета и сценарий, который её применяет.
    LToken := MHFindAntivirusBlock(AHead);
    if LToken <> '' then
      LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_AV_BLOCK,
        MHL('Политика AppLocker запрещает запуск антивирусов', 'An AppLocker policy blocks antivirus programs'),
        85, LToken)];
    if LScript then
    begin
      LToken := MHFindPolicyCommand(AHead);
      if LToken <> '' then
        LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_POLICY_SCRIPT,
          MHL('Сценарий меняет политику запуска программ (AppLocker)',
            'The script changes the program launch policy (AppLocker)'), 45, LToken)];
    end;
    LMarker := MHFindMinerMarker(AHead);
    if LMarker <> '' then
    begin
      if LConfig then
        LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_POOL_CONFIG,
          MHL('Файл содержит настройки майнинга (адрес пула или параметры майнера)',
            'The file contains mining settings (a pool address or miner options)'), 45, LMarker)]
      else if LScript then
        LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MINER_SCRIPT,
          MHL('Сценарий запускает майнер или обращается к пулу', 'The script starts a miner or connects to a pool'),
          50, LMarker)]
      else if LBinary then
        LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MINER_STRINGS,
          MHL('Внутри программы найдены строки майнера', 'Miner strings were found inside the program'),
          55, LMarker)];
    end
    else if LScript then
    begin
      SetString(LText, PAnsiChar(@AHead[0]), Length(AHead));
      LToken := MHFindMinerCommandToken(LText);
      if LToken <> '' then
        LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_MINER_SCRIPT,
          MHL('Сценарий запускает майнер', 'The script starts a miner'), 50, LToken)];
    end;
  end;

  // Скрытый и системный одновременно исполняемый файл вне папок Windows и Program Files:
  // так прячут майнеры (обычные программы так не устанавливаются).
  // Драйверы (.sys) не учитываются: скрытые и системные pagefile.sys, hiberfil.sys,
  // swapfile.sys лежат в корне каждого системного диска.
  if LBinary and (LExt <> '.sys') and LHidden and (LSuspicious or not MHIsStandardInstallLocation(APath)) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_HIDDEN_EXE,
      MHL('Скрытый системный исполняемый файл вне папок программ', 'A hidden system executable outside program folders'),
      30, ExtractFileDir(APath))];
  // Рядом лежит майнер или его драйвер — соседние программы входят в тот же набор.
  if ANearMiner and (LBinary or LScript) and not MHIsMinerArtifact(LName) and not MHIsKnownMinerName(LName) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_NEAR_MINER,
      MHL('В той же папке лежит майнер или его драйвер', 'A miner or its driver is in the same folder'),
      30, ExtractFileDir(APath))];
  // Расположение усиливает другие признаки, но само по себе находкой не считается.
  if (Length(LEvidence) > 0) and LSuspicious then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_FILE_LOCATION,
      MHL('Файл лежит в нетипичном для программ месте', 'The file is in an unusual place for programs'), 15, LReason)];

  if Length(LEvidence) = 0 then
    Exit;
  LRaw := 0;
  for LItem in LEvidence do
    Inc(LRaw, LItem.Weight);
  AHit.Path := APath;
  AHit.SizeBytes := ASize;
  AHit.Attributes := AAttributes;
  AHit.Evidence := LEvidence;
  AHit.Score := MHClampScore(LRaw);
  AHit.Level := AThresholds.LevelOf(AHit.Score);
  AHit.Title := LEvidence[0].Description;
  Result := AHit.Score >= AThresholds.Low;
end;

{ TMHFileScanner }

constructor TMHFileScanner.Create(const AFs: IMHFileScanFs; const AWindowsDir: string;
  const ASkipDirs: TArray<string>; const AThresholds: TMHRiskThresholds; const AIsExcluded: TMHScanExcluded);
var
  LDir: string;
begin
  inherited Create;
  if AFs = nil then
    raise EArgumentNilException.Create('AFs');
  FFs := AFs;
  FWindowsDir := ExcludeTrailingPathDelimiter(AWindowsDir);
  for LDir in ASkipDirs do
    if LDir <> '' then
      FSkipDirs := FSkipDirs + [IncludeTrailingPathDelimiter(LDir).ToLower];
  FThresholds := AThresholds;
  FIsExcluded := AIsExcluded;
end;

function TMHFileScanner.SkipFolder(const APath: string): Boolean;
var
  LPath, LWin, LRest, LDir: string;
  LSub: string;
begin
  LPath := IncludeTrailingPathDelimiter(APath).ToLower;
  for LDir in FSkipDirs do
    if LPath.StartsWith(LDir) then
      Exit(True);
  // Папка Windows: проверяются только подпапки, где программ быть не должно.
  if FWindowsDir <> '' then
  begin
    LWin := IncludeTrailingPathDelimiter(FWindowsDir).ToLower;
    if LPath.StartsWith(LWin) and (LPath <> LWin) then
    begin
      LRest := Copy(LPath, Length(LWin) + 1, MaxInt);
      for LSub in WINDOWS_CHECKED_SUBDIRS do
        if LRest.StartsWith(LSub + '\') then
          Exit(False);
      Exit(True);
    end;
  end;
  Result := LPath.EndsWith('\system volume information\');
end;

procedure TMHFileScanner.InspectFile(const APath: string; const AEntry: TMHFsEntry; ANearMiner: Boolean);
var
  LLimit: Integer;
  LHead: TBytes;
  LHit: TMHScanHit;
begin
  LHead := nil;
  LLimit := MHScanReadLimit(APath, AEntry.Attributes, AEntry.SizeBytes);
  if LLimit > 0 then
  begin
    Inc(FProgress.FilesInspected);
    if not FFs.ReadHead(APath, LLimit, LHead) then
      LHead := nil;
  end;
  if MHClassifyFile(APath, AEntry.Attributes, AEntry.SizeBytes, LHead, FWindowsDir, FThresholds, LHit,
    ANearMiner) then
  begin
    if Assigned(FIsExcluded) and FIsExcluded(APath) then
      Exit;
    FHits := FHits + [LHit];
    FProgress.Hits := Length(FHits);
  end;
end;

procedure TMHFileScanner.ScanFolder(const APath: string; const ACancel: TMHScanCancel;
  const AOnProgress: TMHScanProgressProc; ADepth: Integer);
var
  LEntries: TArray<TMHFsEntry>;
  LEntry: TMHFsEntry;
  LPath: string;
  LNearMiner: Boolean;
begin
  if FProgress.Cancelled then
    Exit;
  // Ограничение глубины — защита от патологически вложенных папок.
  if (ADepth > 64) or SkipFolder(APath) or not FFs.ListDirectory(APath, LEntries) then
  begin
    Inc(FProgress.FoldersSkipped);
    Exit;
  end;
  FProgress.CurrentFolder := APath;
  if Assigned(AOnProgress) then
    AOnProgress(FProgress);
  // Есть ли в папке майнер или его драйвер (по именам — без чтения файлов).
  LNearMiner := False;
  for LEntry in LEntries do
    if not LEntry.IsDirectory and (MHIsMinerArtifact(LEntry.Name) or
       (MHIsKnownMinerName(LEntry.Name) and MHIsExecutableExtension(ExtractFileExt(LEntry.Name)))) then
    begin
      LNearMiner := True;
      Break;
    end;
  for LEntry in LEntries do
  begin
    if Assigned(ACancel) and ACancel() then
    begin
      FProgress.Cancelled := True;
      Exit;
    end;
    LPath := IncludeTrailingPathDelimiter(APath) + LEntry.Name;
    if LEntry.IsDirectory then
    begin
      // Junction и символические ссылки не раскрываются: иначе возможны циклы и двойной обход.
      if not LEntry.IsReparsePoint then
        ScanFolder(LPath, ACancel, AOnProgress, ADepth + 1);
    end
    else
    begin
      Inc(FProgress.FilesSeen);
      InspectFile(LPath, LEntry, LNearMiner);
    end;
    if FProgress.Cancelled then
      Exit;
  end;
end;

function TMHFileScanner.Run(const ARoots: TArray<string>; const ACancel: TMHScanCancel;
  const AOnProgress: TMHScanProgressProc): TArray<TMHScanHit>;
var
  LRoot: string;
  LList: TList<TMHScanHit>;
begin
  FProgress := Default(TMHScanProgress);
  FHits := nil;
  for LRoot in ARoots do
  begin
    ScanFolder(ExcludeTrailingPathDelimiter(LRoot) + '\', ACancel, AOnProgress, 0);
    if FProgress.Cancelled then
      Break;
  end;
  FProgress.Done := True;
  FProgress.CurrentFolder := '';
  LList := TList<TMHScanHit>.Create;
  try
    LList.AddRange(FHits);
    LList.Sort(TComparer<TMHScanHit>.Construct(
      function(const A, B: TMHScanHit): Integer
      begin
        Result := CompareValue(B.Score, A.Score);
        if Result = 0 then
          Result := CompareText(A.Path, B.Path);
      end));
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
  if Assigned(AOnProgress) then
    AOnProgress(FProgress);
end;

function MHHiddenAttributesText(AAttributes: Cardinal): string;
var
  LHidden, LSystem: Boolean;
begin
  if AAttributes = MH_NO_ATTRIBUTES then
    Exit('');
  LHidden := AAttributes and FILE_ATTRIBUTE_HIDDEN_MH <> 0;
  LSystem := AAttributes and FILE_ATTRIBUTE_SYSTEM_MH <> 0;
  if LHidden and LSystem then
    Result := MHL('скрытый, системный', 'hidden, system')
  else if LHidden then
    Result := MHL('скрытый', 'hidden')
  else if LSystem then
    Result := MHL('системный', 'system')
  else
    Result := '';
end;

/// Скрытые папки на пути к файлу (без корня диска), от ближней к дальней.
function HiddenFolders(const APath: string; const AGetAttributes: TMHGetAttributes): TArray<string>;
var
  LDir, LParent: string;
  LAttr: Cardinal;
  I: Integer;
begin
  Result := nil;
  LDir := ExcludeTrailingPathDelimiter(ExtractFileDir(APath));
  for I := 1 to 64 do
  begin
    if LDir = '' then
      Break;
    LParent := ExcludeTrailingPathDelimiter(ExtractFileDir(LDir));
    // Корень диска («C:» или «\\сервер\ресурс») — у него свои атрибуты, Проводник его показывает.
    if (LParent = LDir) or (LParent = '') or (ExtractFileDrive(LDir) = LDir) then
      Break;
    LAttr := AGetAttributes(LDir);
    if (LAttr <> MH_NO_ATTRIBUTES) and (LAttr and FILE_ATTRIBUTE_HIDDEN_MH <> 0) then
      Result := Result + [LDir];
    LDir := LParent;
  end;
end;

function MHHiddenShortText(const APath: string; const AGetAttributes: TMHGetAttributes): string;
var
  LText: string;
begin
  Result := '';
  if (APath = '') or not Assigned(AGetAttributes) then
    Exit;
  LText := MHHiddenAttributesText(AGetAttributes(APath));
  if LText <> '' then
    Result := MHL('файл ', 'file ') + LText;
  if Length(HiddenFolders(APath, AGetAttributes)) > 0 then
  begin
    if Result <> '' then
      Result := Result + '; ';
    Result := Result + MHL('в скрытой папке', 'in a hidden folder');
  end;
end;

function MHHiddenLocationNote(const APath: string; const AGetAttributes: TMHGetAttributes): string;
var
  LAttr: Cardinal;
  LFileText: string;
  LFolders: TArray<string>;
  LSystem: Boolean;
begin
  Result := '';
  if (APath = '') or not Assigned(AGetAttributes) then
    Exit;
  LAttr := AGetAttributes(APath);
  LFileText := MHHiddenAttributesText(LAttr);
  LFolders := HiddenFolders(APath, AGetAttributes);
  if (LFileText = '') and (Length(LFolders) = 0) then
    Exit;
  LSystem := (LAttr <> MH_NO_ATTRIBUTES) and (LAttr and FILE_ATTRIBUTE_SYSTEM_MH <> 0);
  if LFileText <> '' then
    Result := Format(MHL('Файл «%s» помечен как %s.', 'The file "%s" is marked as %s.'),
      [ExtractFileName(APath), LFileText]);
  if Length(LFolders) > 0 then
    Result := Trim(Result + ' ' + Format(MHL('Скрытая папка на пути: %s.', 'Hidden folder on the path: %s.'),
      [string.Join(', ', LFolders)]));
  Result := Result + ' ' + MHL('Проводник по умолчанию такие не показывает, поэтому папка может выглядеть ' +
    'пустой, хотя файл на месте.', 'Explorer does not show these by default, so the folder may look empty ' +
    'although the file is there.') + sLineBreak + sLineBreak +
    MHL('Как увидеть: в Проводнике «Вид» → «Показать» → «Скрытые элементы» (Windows 10: вкладка «Вид» → ' +
    'флажок «Скрытые элементы»).', 'To see them: in Explorer, View → Show → Hidden items (Windows 10: the View ' +
    'tab → the Hidden items box).');
  if LSystem then
    Result := Result + ' ' + MHL('Для системных файлов ещё: «Параметры папок» → «Вид» → снять флажок ' +
      '«Скрывать защищённые системные файлы».', 'For system files also: Folder Options → View → clear ' +
      '"Hide protected operating system files".');
  Result := Result + sLineBreak + sLineBreak + MHL('Скрытый исполняемый файл вне папок программ — частый ' +
    'приём маскировки майнеров. Путь можно скопировать, а файл — разобрать в BinaryLab без запуска.',
    'A hidden executable outside program folders is a common miner disguise. You can copy the path and ' +
    'analyse the file in BinaryLab without running it.');
end;

end.
