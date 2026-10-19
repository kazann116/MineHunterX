unit MineHunter.BinaryLab.Strings;

{
  Строки внутри файла (ASCII и UTF-16LE) и их категории-индикаторы:
  адреса, IP, пути, реестр, команды, майнинг, кошельки, подозрительные функции.

  - Файл читается потоком без перекрытия блоков: состояние незаконченной
    строки переносится в следующий блок, поэтому строка на границе блоков
    находится ровно один раз с правильным смещением.
  - UTF-16 ищется с обоих выравниваний (чётное и нечётное смещение):
    строка в ресурсах не обязана начинаться с чётного байта.
  - Память ограничена MaxStrings: при переполнении сохраняются в первую
    очередь строки с категорией, затем обычные (более ранние по файлу).
    Счётчики по категориям учитывают все найденные строки.
  - Классификация — простые проверки без регулярных выражений: на файле
    в сотни мегабайт строк миллионы. Текстовые маркеры ищутся за один
    проход по строке (таблица по первому символу).
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

/// Строки в первых AOptions.MaxScanBytes байтах источника, по возрастанию смещения.
/// ACancel — EMHBinaryLabCancelled при отмене.
function MHScanStrings(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ACancel: TMHCancelCheck): TMHStringsInfo;

/// Категория строки (по приоритету: майнинг, кошелёк, URL, почта, IP, реестр,
/// команда, функция API, путь, домен, Base64; иначе scPlain).
function MHClassifyString(const AText: string): TMHStringCategory;

implementation

uses
  System.Math, System.Generics.Collections, System.Generics.Defaults;

const
  READ_CHUNK = 1024 * 1024;

  // Маркеры — ASCII в нижнем регистре (сравнение без учёта регистра латиницы).
  MINING_MARKERS: TArray<string> = ['stratum+tcp://', 'stratum+ssl://', 'stratum2+', 'xmrig', 'nicehash',
    'minexmr', 'nanopool', '2miners', 'f2pool', 'ethermine', 'hashvault', 'supportxmr', 'moneroocean',
    'herominers', 'unmineable', '--donate-level', 'cryptonight', 'randomx', '--coin=', '-o pool',
    'nheqminer', 'ccminer', 'cpuminer', 'lolminer', 'gminer', 't-rex', 'phoenixminer'];

  URL_MARKERS: TArray<string> = ['http://', 'https://', 'ftp://', 'ws://', 'wss://', 'tcp://'];

  REGISTRY_MARKERS: TArray<string> = ['hkey_', 'hklm\', 'hkcu\', '\currentversion\run', 'software\microsoft\'];

  COMMAND_MARKERS: TArray<string> = ['cmd.exe /c', 'cmd /c', 'powershell', '-encodedcommand', ' -enc ',
    'schtasks', 'reg add', 'reg delete', 'vssadmin', 'bcdedit', 'wmic ', 'rundll32', 'regsvr32', 'certutil',
    'bitsadmin', 'mshta', 'invoke-expression', 'iex(', 'downloadstring', 'downloadfile', 'net user',
    'sc create', 'taskkill', 'attrib +h', 'netsh advfirewall', 'add-mppreference', 'set-mppreference'];

  PATH_MARKERS: TArray<string> = ['\device\', '\systemroot\', '\??\'];

  SUSPICIOUS_APIS: TArray<string> = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'CreateRemoteThreadEx', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'SetWindowsHookExA',
    'SetWindowsHookExW', 'QueueUserAPC', 'NtQueueApcThread', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'NtSetInformationThread', 'AdjustTokenPrivileges', 'MiniDumpWriteDump',
    'URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'WinExec',
    'SetThreadContext', 'RtlCreateUserThread', 'NtCreateThreadEx'];

  ENV_FOLDERS: TArray<string> = ['TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'USERPROFILE',
    'WINDIR', 'SYSTEMROOT', 'SYSTEMDRIVE', 'PUBLIC', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'COMSPEC',
    'ALLUSERSPROFILE', 'HOMEPATH'];

  DOMAIN_TLDS: TArray<string> = ['com', 'net', 'org', 'ru', 'io', 'xyz', 'top', 'info', 'biz', 'onion', 'su',
    'cc', 'me', 'tk', 'pw', 'co', 'uk', 'de', 'cn', 'club', 'online', 'site', 'in', 'us'];

type
  /// Группы текстовых маркеров (ищутся за один проход по строке).
  TMarkerGroup = (mgMining, mgUrl, mgRegistry, mgCommand, mgPath);
  TMarkerGroups = set of TMarkerGroup;

  TMarker = record
    Text: string;
    Group: TMarkerGroup;
  end;

var
  /// Маркеры по первому символу. Заполняется при инициализации модуля и
  /// дальше только читается (безопасно из любых потоков).
  GMarkers: array[0..127] of TArray<TMarker>;

{ Классификация }

function IsDigit(C: Char): Boolean; inline;
begin
  Result := (C >= '0') and (C <= '9');
end;

function IsLatinLetter(C: Char): Boolean; inline;
begin
  Result := ((C >= 'A') and (C <= 'Z')) or ((C >= 'a') and (C <= 'z'));
end;

function IsAlnum(C: Char): Boolean; inline;
begin
  Result := IsDigit(C) or IsLatinLetter(C);
end;

procedure RegisterMarkers(const AMarkers: TArray<string>; AGroup: TMarkerGroup);
var
  LText: string;
  LMarker: TMarker;
  LFirst: Integer;
begin
  for LText in AMarkers do
  begin
    LFirst := Ord(LText[1]);
    Assert(LFirst < Length(GMarkers), 'Маркеры — только ASCII');
    LMarker.Text := LText;
    LMarker.Group := AGroup;
    GMarkers[LFirst] := GMarkers[LFirst] + [LMarker];
  end;
end;

/// Нижний регистр только для латиницы: маркеры — ASCII, а преобразование
/// с учётом языка на миллионах строк заметно медленнее.
function LowerAscii(const AText: string): string;
var
  I: Integer;
  P: PChar;
begin
  Result := AText;
  if Result = '' then
    Exit;
  UniqueString(Result);
  P := PChar(Result);
  for I := 0 to Length(Result) - 1 do
    if (P[I] >= 'A') and (P[I] <= 'Z') then
      P[I] := Char(Ord(P[I]) + 32);
end;

function IsLowerAlnum(C: Char): Boolean; inline;
begin
  Result := ((C >= 'a') and (C <= 'z')) or ((C >= '0') and (C <= '9'));
end;

/// Маркер-слово не должен быть частью другого слова: «randomx» в
/// «RandomXorStartOffset» — не майнинг. Граница проверяется только для
/// концов маркера из букв и цифр («stratum+tcp://», «--coin=» — без проверки).
function AtWordBoundary(P: PChar; ALength, AStart, AMarkerLength: Integer; const AMarker: string): Boolean;
begin
  Result := True;
  if IsLowerAlnum(AMarker[1]) and (AStart > 0) and IsLowerAlnum(P[AStart - 1]) then
    Exit(False);
  if IsLowerAlnum(AMarker[AMarkerLength]) and (AStart + AMarkerLength < ALength) and
     IsLowerAlnum(P[AStart + AMarkerLength]) then
    Exit(False);
end;

/// Группы маркеров, встречающихся в строке (ALower — в нижнем регистре).
function FindMarkers(const ALower: string): TMarkerGroups;
var
  I, J, LCode, LLength, LMarkerLength: Integer;
  P: PChar;
begin
  Result := [];
  LLength := Length(ALower);
  P := PChar(ALower);
  for I := 0 to LLength - 1 do
  begin
    LCode := Ord(P[I]);
    if LCode >= Length(GMarkers) then
      Continue;
    for J := 0 to High(GMarkers[LCode]) do
    begin
      LMarkerLength := Length(GMarkers[LCode][J].Text);
      if not (GMarkers[LCode][J].Group in Result) and (I + LMarkerLength <= LLength) and
         CompareMem(@P[I], PChar(GMarkers[LCode][J].Text), LMarkerLength * SizeOf(Char)) and
         AtWordBoundary(P, LLength, I, LMarkerLength, GMarkers[LCode][J].Text) then
        Include(Result, GMarkers[LCode][J].Group);
    end;
  end;
end;

function InList(const AValue: string; const AList: TArray<string>): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

function IsBase58(C: Char): Boolean;
begin
  case C of
    '1'..'9', 'A'..'H', 'J'..'N', 'P'..'Z', 'a'..'k', 'm'..'z': Result := True;
  else
    Result := False;
  end;
end;

function IsBech32(C: Char): Boolean;
begin
  case C of
    'a', 'c'..'h', 'j'..'n', 'p'..'z', '0', '2'..'9': Result := True;
  else
    Result := False;
  end;
end;

function IsHexDigit(C: Char): Boolean;
begin
  case C of
    '0'..'9', 'a'..'f', 'A'..'F': Result := True;
  else
    Result := False;
  end;
end;

/// Слово из латинских букв и цифр — адрес кошелька Monero, Bitcoin или Ethereum.
function IsWalletToken(const AText: string; AStart, ALength: Integer): Boolean;
var
  I: Integer;
  LUpper, LLower, LDigit: Boolean;
  C: Char;
begin
  // Monero: 95 символов, «4» или «8», затем цифра или A/B, дальше base58.
  if (ALength = 95) and CharInSet(AText[AStart], ['4', '8']) and
     CharInSet(AText[AStart + 1], ['0'..'9', 'A', 'B']) then
  begin
    for I := AStart + 2 to AStart + ALength - 1 do
      if not IsBase58(AText[I]) then
        Exit(False);
    Exit(True);
  end;
  // Ethereum: 0x и 40 шестнадцатеричных цифр.
  if (ALength = 42) and (AText[AStart] = '0') and (AText[AStart + 1] = 'x') then
  begin
    for I := AStart + 2 to AStart + ALength - 1 do
      if not IsHexDigit(AText[I]) then
        Exit(False);
    Exit(True);
  end;
  // Bitcoin bech32: bc1 и 25..87 символов алфавита bech32 (только нижний регистр).
  if (ALength >= 28) and (ALength <= 90) and (AText[AStart] = 'b') and (AText[AStart + 1] = 'c') and
     (AText[AStart + 2] = '1') then
  begin
    for I := AStart + 3 to AStart + ALength - 1 do
      if not IsBech32(AText[I]) then
        Exit(False);
    Exit(True);
  end;
  // Bitcoin base58: «1» или «3» и 25..34 символа; смешанный регистр и цифра —
  // иначе под условие попадают обычные слова и идентификаторы.
  if (ALength >= 26) and (ALength <= 35) and CharInSet(AText[AStart], ['1', '3']) then
  begin
    LUpper := False;
    LLower := False;
    LDigit := False;
    for I := AStart + 1 to AStart + ALength - 1 do
    begin
      C := AText[I];
      if not IsBase58(C) then
        Exit(False);
      if (C >= 'A') and (C <= 'Z') then
        LUpper := True
      else if (C >= 'a') and (C <= 'z') then
        LLower := True
      else
        LDigit := True;
    end;
    Exit(LUpper and LLower and LDigit);
  end;
  Result := False;
end;

/// Адрес кошелька — отдельное слово внутри строки (например, «-u <адрес>.worker»).
function HasWallet(const AText: string): Boolean;
var
  I, LStart, LLength: Integer;
begin
  I := 1;
  while I <= Length(AText) do
  begin
    if not IsAlnum(AText[I]) then
    begin
      Inc(I);
      Continue;
    end;
    LStart := I;
    while (I <= Length(AText)) and IsAlnum(AText[I]) do
      Inc(I);
    LLength := I - LStart;
    if (LLength >= 26) and IsWalletToken(AText, LStart, LLength) then
      Exit(True);
  end;
  Result := False;
end;

/// Имя хоста с точкой и буквенным доменом верхнего уровня (2..24 буквы).
function IsHostWithTld(const AHost: string): Boolean;
var
  LLabels: TArray<string>;
  LLabel: string;
  C: Char;
begin
  if (AHost = '') or (Pos('.', AHost) = 0) then
    Exit(False);
  LLabels := AHost.Split(['.']);
  if Length(LLabels) < 2 then
    Exit(False);
  for LLabel in LLabels do
    if (LLabel = '') or (Length(LLabel) > 63) or (LLabel[1] = '-') or (LLabel[Length(LLabel)] = '-') then
      Exit(False);
  LLabel := LLabels[High(LLabels)];
  if (Length(LLabel) < 2) or (Length(LLabel) > 24) then
    Exit(False);
  for C in LLabel do
    if not IsLatinLetter(C) then
      Exit(False);
  Result := True;
end;

function HasEmail(const AText: string): Boolean;
var
  I, L, R: Integer;
  LHost: string;
begin
  for I := 2 to Length(AText) - 1 do
  begin
    if AText[I] <> '@' then
      Continue;
    L := I - 1;
    while (L >= 1) and (IsAlnum(AText[L]) or CharInSet(AText[L], ['.', '_', '%', '+', '-'])) do
      Dec(L);
    if L = I - 1 then
      Continue;
    R := I + 1;
    while (R <= Length(AText)) and (IsAlnum(AText[R]) or CharInSet(AText[R], ['.', '-'])) do
      Inc(R);
    LHost := Copy(AText, I + 1, R - I - 1);
    while (LHost <> '') and CharInSet(LHost[Length(LHost)], ['.', '-']) do
      SetLength(LHost, Length(LHost) - 1);
    if IsHostWithTld(LHost) then
      Exit(True);
  end;
  Result := False;
end;

/// Число из 1..AMaxDigits цифр с позиции AIndex (длиннее — отказ: «1234» — не октет).
function ReadNumber(const AText: string; var AIndex: Integer; AMaxDigits: Integer; out AValue: Integer): Boolean;
var
  LStart: Integer;
begin
  AValue := 0;
  LStart := AIndex;
  while (AIndex <= Length(AText)) and IsDigit(AText[AIndex]) do
  begin
    if AIndex - LStart >= AMaxDigits then
      Exit(False);
    AValue := AValue * 10 + Ord(AText[AIndex]) - Ord('0');
    Inc(AIndex);
  end;
  Result := AIndex > LStart;
end;

/// IPv4 «a.b.c.d» (необязательно «:порт») с позиции AStart. AEnd — позиция после адреса.
function ParseIpAt(const AText: string; AStart: Integer; out AFirst: Integer; out AAllSmall: Boolean;
  out AEnd: Integer): Boolean;
var
  I, K, LValue, LPortEnd: Integer;
begin
  AFirst := 0;
  AAllSmall := True;
  AEnd := AStart;
  I := AStart;
  for K := 0 to 3 do
  begin
    if not ReadNumber(AText, I, 3, LValue) or (LValue > 255) then
      Exit(False);
    if K = 0 then
      AFirst := LValue;
    if LValue >= 10 then
      AAllSmall := False;
    if K < 3 then
    begin
      if (I > Length(AText)) or (AText[I] <> '.') then
        Exit(False);
      Inc(I);
    end;
  end;
  // «1.2.3.4.5» и «1.2.3.4x» — не адрес (номер версии, идентификатор).
  if (I <= Length(AText)) and (IsAlnum(AText[I]) or
     ((AText[I] = '.') and (I < Length(AText)) and IsDigit(AText[I + 1]))) then
    Exit(False);
  if (I < Length(AText)) and (AText[I] = ':') and IsDigit(AText[I + 1]) then
  begin
    LPortEnd := I + 1;
    if ReadNumber(AText, LPortEnd, 5, LValue) and (LValue <= 65535) and
       ((LPortEnd > Length(AText)) or not IsAlnum(AText[LPortEnd])) then
      I := LPortEnd;
  end;
  AEnd := I;
  Result := True;
end;

function HasIp(const AText, ALower: string): Boolean;
var
  I, LFirst, LEnd: Integer;
  LAllSmall: Boolean;
  LTrimmed: string;
begin
  LTrimmed := Trim(AText);
  for I := 1 to Length(AText) do
  begin
    if not IsDigit(AText[I]) then
      Continue;
    // Начало числа, а не продолжение «10.0.19041.1» или «v1.2».
    if (I > 1) and (IsAlnum(AText[I - 1]) or (AText[I - 1] = '.')) then
      Continue;
    if not ParseIpAt(AText, I, LFirst, LAllSmall, LEnd) then
      Continue;
    // Все части меньше 10 — почти всегда номер версии (1.0.0.0, 2.5.1.3).
    if LAllSmall then
      Continue;
    if Copy(AText, I, LEnd - I) = LTrimmed then
      Exit(True);
    // Внутри текста — только правдоподобный адрес и не рядом со словом «version».
    if (LFirst >= 10) and (Pos('version', ALower) = 0) and (Pos('ver.', ALower) = 0) then
      Exit(True);
  end;
  Result := False;
end;

/// Путь с буквой диска, сетевой путь или переменная окружения (маркеры вида
/// «\Device\» проверяются отдельно, в FindMarkers).
function HasPath(const AText: string): Boolean;
var
  I, J: Integer;
  LName: string;
begin
  for I := 1 to Length(AText) - 2 do
  begin
    // Путь с буквой диска: «C:\…» (не часть слова).
    if IsLatinLetter(AText[I]) and (AText[I + 1] = ':') and (AText[I + 2] = '\') and
       ((I = 1) or CharInSet(AText[I - 1], [' ', #9, '"', '''', '=', '(', '[', ',', '>'])) and
       ((I + 3 > Length(AText)) or IsAlnum(AText[I + 3]) or CharInSet(AText[I + 3], ['%', '_', '.', '$', '~', ' '])) then
      // Только после разделителя и с именем после «:\»: служебные таблицы
      // вида «:@:D:H:L:P:T:X:\`:d:h:» путями не считаются.
      Exit(True);
    // Сетевой путь: «\\сервер\ресурс».
    if (AText[I] = '\') and (AText[I + 1] = '\') and ((I = 1) or (AText[I - 1] <> '\')) and
       IsAlnum(AText[I + 2]) then
    begin
      J := I + 2;
      while (J <= Length(AText)) and (IsAlnum(AText[J]) or CharInSet(AText[J], ['.', '-', '_', '$'])) do
        Inc(J);
      if (J < Length(AText)) and (AText[J] = '\') and (IsAlnum(AText[J + 1]) or CharInSet(AText[J + 1], ['$', '_'])) then
        Exit(True);
    end;
    // Переменная окружения: «%APPDATA%\…» или известная папка «%TEMP%».
    if (AText[I] = '%') and IsLatinLetter(AText[I + 1]) then
    begin
      J := I + 1;
      while (J <= Length(AText)) and (IsAlnum(AText[J]) or CharInSet(AText[J], ['_', '(', ')'])) do
        Inc(J);
      if (J <= Length(AText)) and (AText[J] = '%') and (J - I - 1 >= 2) then
      begin
        LName := Copy(AText, I + 1, J - I - 1);
        if ((J < Length(AText)) and (AText[J + 1] = '\')) or InList(LName, ENV_FOLDERS) then
          Exit(True);
      end;
    end;
  end;
  Result := False;
end;

function IsDomain(const AText: string): Boolean;
var
  LText, LTld: string;
  LHasLetter, LHasLower: Boolean;
  C: Char;
  I: Integer;
begin
  LText := Trim(AText);
  if (Length(LText) < 4) or (Length(LText) > 253) then
    Exit(False);
  LHasLetter := False;
  LHasLower := False;
  for C in LText do
    if IsLatinLetter(C) then
    begin
      LHasLetter := True;
      if (C >= 'a') and (C <= 'z') then
        LHasLower := True;
    end
    else if not (IsDigit(C) or (C = '.') or (C = '-')) then
      Exit(False);
  if not LHasLetter or not IsHostWithTld(LText) then
    Exit(False);
  I := LText.LastDelimiter('.');
  LTld := LText.Substring(I + 1);
  if not InList(LTld, DOMAIN_TLDS) then
    Exit(False);
  // «System.IO», «System.Net» — пространства имён, а не домены: домен верхнего
  // уровня пишется строчными буквами (или вся строка — прописными).
  Result := (LTld = LowerAscii(LTld)) or not LHasLower;
end;

function IsBase64(const AText: string): Boolean;
var
  I, LLength, LPad: Integer;
  LUpper, LLower, LDigit: Boolean;
  C: Char;
begin
  LLength := Length(AText);
  if (LLength < 40) or (LLength mod 4 <> 0) then
    Exit(False);
  LPad := 0;
  while (LPad < 2) and (AText[LLength - LPad] = '=') do
    Inc(LPad);
  LUpper := False;
  LLower := False;
  LDigit := False;
  for I := 1 to LLength - LPad do
  begin
    C := AText[I];
    if (C >= 'A') and (C <= 'Z') then
      LUpper := True
    else if (C >= 'a') and (C <= 'z') then
      LLower := True
    else if IsDigit(C) then
      LDigit := True
    else if (C <> '+') and (C <> '/') then
      Exit(False);
  end;
  Result := LUpper and LLower and LDigit;
end;

function IsSuspiciousApi(const AText: string): Boolean;
var
  LText: string;
begin
  LText := Trim(AText);
  Result := (Length(LText) >= 7) and (Length(LText) <= 32) and InList(LText, SUSPICIOUS_APIS);
end;

function MHClassifyString(const AText: string): TMHStringCategory;
var
  LLower: string;
  LGroups: TMarkerGroups;
  LHasAt, LHasDot, LHasPathChar: Boolean;
  C: Char;
begin
  if AText = '' then
    Exit(scPlain);
  LLower := LowerAscii(AText);
  LGroups := FindMarkers(LLower);
  // Символы, без которых часть проверок заведомо не пройдёт.
  LHasAt := False;
  LHasDot := False;
  LHasPathChar := False;
  for C in AText do
    case C of
      '@': LHasAt := True;
      '.': LHasDot := True;
      ':', '\', '%': LHasPathChar := True;
    end;
  if mgMining in LGroups then
    Result := scMining
  else if (Length(AText) >= 26) and HasWallet(AText) then
    Result := scWallet
  else if mgUrl in LGroups then
    Result := scUrl
  else if LHasAt and LHasDot and HasEmail(AText) then
    Result := scEmail
  else if LHasDot and HasIp(AText, LLower) then
    Result := scIp
  else if mgRegistry in LGroups then
    Result := scRegistry
  else if mgCommand in LGroups then
    Result := scCommand
  else if IsSuspiciousApi(AText) then
    Result := scSuspiciousApi
  else if (mgPath in LGroups) or (LHasPathChar and HasPath(AText)) then
    Result := scPath
  else if LHasDot and IsDomain(AText) then
    Result := scDomain
  else if IsBase64(AText) then
    Result := scBase64
  else
    Result := scPlain;
end;

{ Поиск строк }

type
  /// Незаконченная строка: начало, длина (не больше MaxInt) и первые символы.
  TStringRun = record
    Start: Int64;
    Length: Integer;
    Chars: TArray<Char>;
  end;

  TStringCollector = class
  private
    FMin: Integer;
    FMax: Integer;
    FMaxStrings: Integer;
    FAscii: TStringRun;
    /// UTF-16 с чётного [0] и нечётного [1] смещения.
    FWide: array[0..1] of TStringRun;
    /// Предыдущий байт (-1 — нет): кодовая единица UTF-16 может начинаться в прошлом блоке.
    FPrevByte: Integer;
    FNextPos: Int64;
    FCategorized: TList<TMHBinaryString>;
    FPlain: TList<TMHBinaryString>;
    FTotalFound: Integer;
    FTruncated: Boolean;
    FCountByCategory: array[TMHStringCategory] of Integer;
    procedure EndRun(var ARun: TStringRun; AEncoding: TMHStringEncoding);
    procedure Add(const AItem: TMHBinaryString);
    procedure FlushAll;
    procedure ScanAscii(ABase: Int64; const AData: TBytes; ACount: Integer);
    procedure ScanWide(AParity: Integer; ABase: Int64; const AData: TBytes; ACount: Integer);
  public
    constructor Create(const AOptions: TMHBinaryLabOptions);
    destructor Destroy; override;
    procedure Feed(ABase: Int64; const AData: TBytes; ACount: Integer);
    procedure Finish;
    function BuildResult: TMHStringsInfo;
  end;

var
  /// Печатаемые байты ASCII ($20..$7E и табуляция).
  GPrintable: array[Byte] of Boolean;

{ TStringCollector }

constructor TStringCollector.Create(const AOptions: TMHBinaryLabOptions);
var
  I: Integer;
begin
  inherited Create;
  FMin := AOptions.MinStringLength;
  FMax := AOptions.MaxStringLength;
  FMaxStrings := AOptions.MaxStrings;
  SetLength(FAscii.Chars, FMax);
  FAscii.Length := 0;
  for I := Low(FWide) to High(FWide) do
  begin
    SetLength(FWide[I].Chars, FMax);
    FWide[I].Length := 0;
  end;
  FPrevByte := -1;
  FNextPos := -1;
  FCategorized := TList<TMHBinaryString>.Create;
  FPlain := TList<TMHBinaryString>.Create;
end;

destructor TStringCollector.Destroy;
begin
  FPlain.Free;
  FCategorized.Free;
  inherited;
end;

procedure TStringCollector.Add(const AItem: TMHBinaryString);
begin
  if AItem.Category <> scPlain then
  begin
    if FCategorized.Count >= FMaxStrings then
    begin
      FTruncated := True;
      Exit;
    end;
    FCategorized.Add(AItem);
    // Место для строки с категорией освобождает самая поздняя обычная строка.
    if FCategorized.Count + FPlain.Count > FMaxStrings then
    begin
      FPlain.Delete(FPlain.Count - 1);
      FTruncated := True;
    end;
  end
  else if FCategorized.Count + FPlain.Count < FMaxStrings then
    FPlain.Add(AItem)
  else
    FTruncated := True;
end;

procedure TStringCollector.EndRun(var ARun: TStringRun; AEncoding: TMHStringEncoding);
var
  LItem: TMHBinaryString;
begin
  if ARun.Length >= FMin then
  begin
    LItem.Offset := ARun.Start;
    LItem.Encoding := AEncoding;
    SetString(LItem.Text, PChar(@ARun.Chars[0]), Min(ARun.Length, FMax));
    LItem.Category := MHClassifyString(LItem.Text);
    if FTotalFound < MaxInt then
      Inc(FTotalFound);
    Inc(FCountByCategory[LItem.Category]);
    Add(LItem);
  end;
  ARun.Length := 0;
end;

procedure TStringCollector.FlushAll;
begin
  EndRun(FAscii, seAscii);
  EndRun(FWide[0], seUtf16);
  EndRun(FWide[1], seUtf16);
  FPrevByte := -1;
end;

procedure TStringCollector.ScanAscii(ABase: Int64; const AData: TBytes; ACount: Integer);
var
  I, LLength, LMax: Integer;
  LStart: Int64;
  LChars: PChar;
  B: Byte;
begin
  // Состояние — в локальных переменных: цикл выполняется для каждого байта файла.
  LLength := FAscii.Length;
  LStart := FAscii.Start;
  LChars := PChar(@FAscii.Chars[0]);
  LMax := FMax;
  for I := 0 to ACount - 1 do
  begin
    B := AData[I];
    if GPrintable[B] then
    begin
      if LLength = 0 then
        LStart := ABase + I;
      if LLength < LMax then
        LChars[LLength] := Char(B);
      if LLength < MaxInt then
        Inc(LLength);
    end
    else if LLength > 0 then
    begin
      if LLength >= FMin then
      begin
        FAscii.Start := LStart;
        FAscii.Length := LLength;
        EndRun(FAscii, seAscii);
      end;
      LLength := 0;
    end;
  end;
  FAscii.Start := LStart;
  FAscii.Length := LLength;
end;

procedure TStringCollector.ScanWide(AParity: Integer; ABase: Int64; const AData: TBytes; ACount: Integer);
var
  LIndex, LLength, LMax: Integer;
  LStart, LFirst: Int64;
  LChars: PChar;
  LLow, LHigh: Byte;
  LChar: Char;
  LValid: Boolean;
begin
  // Кодовая единица — байты [U, U + 1]; первая может начинаться в прошлом блоке
  // (U = ABase - 1, младший байт — FPrevByte), последняя без старшего байта
  // переходит в следующий блок.
  if FPrevByte >= 0 then
    LFirst := ABase - 1
  else
    LFirst := ABase;
  if Integer(LFirst and 1) <> AParity then
    Inc(LFirst);
  LIndex := Integer(LFirst - ABase);
  LLength := FWide[AParity].Length;
  LStart := FWide[AParity].Start;
  LChars := PChar(@FWide[AParity].Chars[0]);
  LMax := FMax;
  while LIndex + 1 < ACount do
  begin
    if LIndex < 0 then
      LLow := Byte(FPrevByte)
    else
      LLow := AData[LIndex];
    LHigh := AData[LIndex + 1];
    if LHigh = 0 then
    begin
      LValid := GPrintable[LLow];
      LChar := Char(LLow);
    end
    else if LHigh = $04 then
    begin
      // Кириллица U+0400..U+04FF.
      LValid := True;
      LChar := Char($0400 or LLow);
    end
    else
    begin
      LValid := False;
      LChar := #0;
    end;
    if LValid then
    begin
      if LLength = 0 then
        LStart := ABase + LIndex;
      if LLength < LMax then
        LChars[LLength] := LChar;
      if LLength < MaxInt then
        Inc(LLength);
    end
    else if LLength > 0 then
    begin
      if LLength >= FMin then
      begin
        FWide[AParity].Start := LStart;
        FWide[AParity].Length := LLength;
        EndRun(FWide[AParity], seUtf16);
      end;
      LLength := 0;
    end;
    Inc(LIndex, 2);
  end;
  FWide[AParity].Start := LStart;
  FWide[AParity].Length := LLength;
end;

procedure TStringCollector.Feed(ABase: Int64; const AData: TBytes; ACount: Integer);
begin
  if ACount <= 0 then
    Exit;
  // Разрыв между блоками (короткое чтение) — незаконченные строки завершаются.
  if (FNextPos >= 0) and (ABase <> FNextPos) then
    FlushAll;
  // Отдельные проходы для ASCII и двух выравниваний UTF-16: порядок выдачи строк
  // внутри блока не важен, итог сортируется по смещению.
  ScanAscii(ABase, AData, ACount);
  ScanWide(0, ABase, AData, ACount);
  ScanWide(1, ABase, AData, ACount);
  FPrevByte := AData[ACount - 1];
  FNextPos := ABase + ACount;
end;

procedure TStringCollector.Finish;
begin
  FlushAll;
end;

function TStringCollector.BuildResult: TMHStringsInfo;
var
  LAll: TList<TMHBinaryString>;
  LCategory: TMHStringCategory;
begin
  Result := Default(TMHStringsInfo);
  LAll := TList<TMHBinaryString>.Create;
  try
    LAll.Capacity := FCategorized.Count + FPlain.Count;
    LAll.AddRange(FCategorized);
    LAll.AddRange(FPlain);
    LAll.Sort(TComparer<TMHBinaryString>.Construct(
      function(const ALeft, ARight: TMHBinaryString): Integer
      begin
        if ALeft.Offset < ARight.Offset then
          Result := -1
        else if ALeft.Offset > ARight.Offset then
          Result := 1
        else
          Result := Ord(ALeft.Encoding) - Ord(ARight.Encoding);
      end));
    Result.Items := LAll.ToArray;
  finally
    LAll.Free;
  end;
  Result.TotalFound := FTotalFound;
  Result.Truncated := FTruncated;
  for LCategory := Low(TMHStringCategory) to High(TMHStringCategory) do
    Result.CountByCategory[LCategory] := FCountByCategory[LCategory];
end;

function MHScanStrings(const ASource: IMHBinarySource; const AOptions: TMHBinaryLabOptions;
  const ACancel: TMHCancelCheck): TMHStringsInfo;
var
  LOptions: TMHBinaryLabOptions;
  LCollector: TStringCollector;
  LLimit: Int64;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := Default(TMHStringsInfo);
  if ASource = nil then
    Exit;
  LOptions := AOptions.Normalized;
  LLimit := Min(ASource.Size, LOptions.MaxScanBytes);
  if LLimit <= 0 then
    Exit;
  LCollector := TStringCollector.Create(LOptions);
  try
    MHReadChunks(ASource, 0, LLimit, READ_CHUNK, 0,
      function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
      begin
        LCollector.Feed(ABase, AData, ACount);
        Result := True;
      end, ACancel);
    LCollector.Finish;
    Result := LCollector.BuildResult;
  finally
    LCollector.Free;
  end;
end;

procedure InitPrintable;
var
  B: Byte;
begin
  for B := Low(Byte) to High(Byte) do
    GPrintable[B] := ((B >= $20) and (B <= $7E)) or (B = 9);
end;

initialization
  InitPrintable;
  RegisterMarkers(MINING_MARKERS, mgMining);
  RegisterMarkers(URL_MARKERS, mgUrl);
  RegisterMarkers(REGISTRY_MARKERS, mgRegistry);
  RegisterMarkers(COMMAND_MARKERS, mgCommand);
  RegisterMarkers(PATH_MARKERS, mgPath);

end.
