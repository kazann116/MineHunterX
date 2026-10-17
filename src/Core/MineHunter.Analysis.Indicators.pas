unit MineHunter.Analysis.Indicators;

{
  Локальная база индикаторов (MH-05: «локальные версии баз индикаторов»).

  Все списки встроены в программу и версионируются вместе с правилами;
  обращений к сети нет. Индикатор — это только признак: решение принимает
  анализатор с учётом других сигналов и оправдывающих факторов.
}

interface

type
  /// Категория известной ресурсоёмкой, но обычно легальной нагрузки.
  TMHWorkloadCategory = (
    wlNone,
    wlBuild,      // компиляция и сборка
    wlRender,     // рендеринг, кодирование видео
    wlUpdate,     // обновления и обслуживание Windows
    wlSecurity,   // антивирусная проверка
    wlGame,       // игры и игровые клиенты
    wlBrowser,    // браузеры
    wlCompute     // распределённые и научные вычисления (BOINC, Folding@home)
  );

const
  MH_INDICATORS_VERSION = '2026.10.2';

/// Имя (без учёта регистра) совпадает с известным майнером.
function MHIsKnownMinerName(const AName: string): Boolean;
/// Признак майнера в командной строке ('' — не найден).
function MHFindMinerCommandToken(const ACommandLine: string): string;
/// Порт часто используется пулами майнинга (сам по себе не доказательство).
function MHIsMiningPoolPort(APort: Word): Boolean;
/// Программа мониторинга процессов (диспетчер задач и аналоги).
function MHIsMonitoringTool(const AName: string): Boolean;
/// Категория известной нагрузки по имени и пути.
function MHWorkloadCategoryOf(const AName, AImagePath: string): TMHWorkloadCategory;
function MHWorkloadCategoryToString(ACategory: TMHWorkloadCategory): string;
/// Системное имя Windows: возвращает True и список допустимых каталогов.
function MHIsSystemProcessName(const AName: string; out AExpectedDirs: TArray<string>): Boolean;
/// Имя похоже на системное, но отличается одним символом (svch0st.exe).
function MHLooksLikeSystemName(const AName: string; out ASystemName: string): Boolean;
/// Необычное для программ расположение (Temp, Загрузки, Public и т.п.).
function MHIsSuspiciousLocation(const AImagePath: string; out AReason: string): Boolean;
/// Файл находится в каталоге Windows или Program Files.
function MHIsStandardInstallLocation(const AImagePath: string): Boolean;
/// Файл сценария (bat, cmd, vbs, js, ps1, wsf, hta).
function MHIsScriptFile(const APath: string): Boolean;
/// В пути есть папка со случайным именем («YfBZXN4ndJYr5fK»); возвращает её имя.
function MHFindRandomLookingFolder(const APath: string; out AFolder: string): Boolean;
/// Признак скрытой команды: закодированная команда PowerShell и т.п. ('' — нет).
function MHFindObfuscatedCommand(const ACommand: string): string;
/// Запуск сценария со скрытым окном или в обход политики выполнения ('' — нет).
/// Слабее, чем обфускация: путь к сценарию виден, так часто делает и обычная автоматизация.
function MHFindHiddenScriptLaunch(const ACommand: string): string;

implementation

uses
  System.SysUtils, System.StrUtils, System.Math;

const
  MINER_NAMES: array[0..30] of string = (
    'xmrig', 'xmrig-notls', 'xmrig-cuda', 'xmr-stak', 'xmr-stak-rx', 'xmr-stak-cpu',
    'cgminer', 'bfgminer', 'cpuminer', 'cpuminer-opt', 'cpuminer-multi', 'minerd',
    'nbminer', 't-rex', 'phoenixminer', 'lolminer', 'teamredminer', 'nanominer',
    'ethminer', 'ethdcrminer64', 'claymore', 'srbminer', 'srbminer-multi', 'wildrig',
    'wildrig-multi', 'kawpowminer', 'excavator', 'nicehashquickminer', 'nheqminer',
    'ccminer', 'gminer');

  MINER_TOKENS: array[0..22] of string = (
    'stratum+tcp://', 'stratum+ssl://', 'stratum2+tcp://', 'stratum1+tcp://',
    '--donate-level', '--cpu-max-threads-hint', '--randomx', '--coin=', '--algo=',
    '--nicehash', 'minexmr', 'nanopool.org', '2miners.com', 'f2pool', 'moneroocean',
    'herominers', 'unmineable', 'nicehash.com', 'hashvault', 'supportxmr', 'xmrpool',
    'c3pool', 'miningpoolhub');

  POOL_PORTS: array[0..17] of Word = (3333, 3334, 3335, 3336, 3357, 4444, 5555, 5556,
    5730, 6666, 7777, 9999, 10128, 10343, 14433, 14444, 45560, 45700);

  MONITOR_TOOLS: array[0..11] of string = ('taskmgr.exe', 'procexp.exe', 'procexp64.exe',
    'procexp64a.exe', 'processhacker.exe', 'systeminformer.exe', 'perfmon.exe', 'resmon.exe',
    'procmon.exe', 'procmon64.exe', 'anvir.exe', 'processlasso.exe');

  BUILD_NAMES: array[0..27] of string = ('dcc32.exe', 'dcc64.exe', 'dccaarm64.exe', 'bds.exe',
    'msbuild.exe', 'cl.exe', 'link.exe', 'clang.exe', 'clang++.exe', 'clang-cl.exe', 'lld-link.exe',
    'gcc.exe', 'g++.exe', 'cc1.exe', 'cc1plus.exe', 'ld.exe', 'make.exe', 'cmake.exe', 'ninja.exe',
    'javac.exe', 'rustc.exe', 'cargo.exe', 'go.exe', 'csc.exe', 'vbcscompiler.exe', 'devenv.exe',
    'dotnet.exe', 'gradle.exe');
  RENDER_NAMES: array[0..15] of string = ('blender.exe', 'ffmpeg.exe', 'handbrake.exe',
    'handbrakecli.exe', 'x264.exe', 'x265.exe', 'afterfx.exe', 'adobe premiere pro.exe',
    'resolve.exe', 'obs64.exe', '3dsmax.exe', 'maya.exe', 'cinema 4d.exe', 'houdini.exe',
    'vegas.exe', 'mediaencoder.exe');
  UPDATE_NAMES: array[0..17] of string = ('tiworker.exe', 'trustedinstaller.exe', 'wuauclt.exe',
    'mousocoreworker.exe', 'usoclient.exe', 'msiexec.exe', 'searchindexer.exe',
    'searchprotocolhost.exe', 'compattelrunner.exe', 'dismhost.exe', 'mrt.exe', 'ngen.exe',
    'ngentask.exe', 'mscorsvw.exe', 'sdiagnhost.exe', 'defrag.exe', 'wsappx.exe', 'setuphost.exe');
  SECURITY_NAMES: array[0..8] of string = ('msmpeng.exe', 'mpcmdrun.exe', 'nissrv.exe',
    'mbam.exe', 'avp.exe', 'ekrn.exe', 'bdservicehost.exe', 'mpdefendercoreservice.exe',
    'smartscreen.exe');
  GAME_NAMES: array[0..6] of string = ('steam.exe', 'steamwebhelper.exe', 'epicgameslauncher.exe',
    'battle.net.exe', 'eadesktop.exe', 'galaxyclient.exe', 'riotclientservices.exe');
  GAME_PATHS: array[0..5] of string = ('\steamapps\common\', '\epic games\', '\gog galaxy\games\',
    '\riot games\', '\battle.net\', '\ea games\');
  BROWSER_NAMES: array[0..7] of string = ('chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe',
    'browser.exe', 'brave.exe', 'vivaldi.exe', 'msedgewebview2.exe');
  /// Клиенты добровольных вычислений: легально нагружают CPU и GPU в фоне.
  COMPUTE_NAMES: array[0..3] of string = ('boinc.exe', 'boincmgr.exe', 'fahclient.exe',
    'foldingathome.exe');
  /// Вычислительные ядра Folding@home: FahCore_22.exe, FahCore_a8.exe…
  COMPUTE_PREFIX = 'fahcore_';

  SYSTEM_IN_SYSTEM32: array[0..16] of string = ('svchost.exe', 'csrss.exe', 'lsass.exe',
    'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe', 'dwm.exe', 'conhost.exe',
    'taskhostw.exe', 'runtimebroker.exe', 'spoolsv.exe', 'sihost.exe', 'ctfmon.exe',
    'dllhost.exe', 'rundll32.exe', 'lsaiso.exe');

function BaseName(const AName: string): string;
begin
  Result := AName.ToLower;
  if Result.EndsWith('.exe') then
    Result := Copy(Result, 1, Length(Result) - 4);
end;

function InList(const AValue: string; const AList: array of string): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

function MHIsKnownMinerName(const AName: string): Boolean;
begin
  Result := (AName <> '') and InList(BaseName(ExtractFileName(AName)), MINER_NAMES);
end;

function MHFindMinerCommandToken(const ACommandLine: string): string;
var
  LLower, LToken: string;
begin
  LLower := ACommandLine.ToLower;
  for LToken in MINER_TOKENS do
    if LLower.Contains(LToken) then
      Exit(LToken);
  Result := '';
end;

function MHIsMiningPoolPort(APort: Word): Boolean;
var
  LPort: Word;
begin
  for LPort in POOL_PORTS do
    if LPort = APort then
      Exit(True);
  Result := False;
end;

function MHIsMonitoringTool(const AName: string): Boolean;
begin
  Result := InList(ExtractFileName(AName), MONITOR_TOOLS);
end;

function MHWorkloadCategoryOf(const AName, AImagePath: string): TMHWorkloadCategory;
var
  LName, LPath, LGamePath: string;
begin
  LName := ExtractFileName(AName).ToLower;
  LPath := AImagePath.ToLower;
  if InList(LName, BUILD_NAMES) then
    Exit(wlBuild);
  if InList(LName, RENDER_NAMES) then
    Exit(wlRender);
  if InList(LName, UPDATE_NAMES) then
    Exit(wlUpdate);
  if InList(LName, SECURITY_NAMES) then
    Exit(wlSecurity);
  if InList(LName, GAME_NAMES) then
    Exit(wlGame);
  for LGamePath in GAME_PATHS do
    if LPath.Contains(LGamePath) then
      Exit(wlGame);
  if InList(LName, BROWSER_NAMES) then
    Exit(wlBrowser);
  if InList(LName, COMPUTE_NAMES) or LName.StartsWith(COMPUTE_PREFIX) then
    Exit(wlCompute);
  Result := wlNone;
end;

function MHWorkloadCategoryToString(ACategory: TMHWorkloadCategory): string;
begin
  case ACategory of
    wlBuild:    Result := 'компиляция и сборка программ';
    wlRender:   Result := 'рендеринг или кодирование видео';
    wlUpdate:   Result := 'обновление и обслуживание Windows';
    wlSecurity: Result := 'антивирусная проверка';
    wlGame:     Result := 'игра или игровой клиент';
    wlBrowser:  Result := 'браузер';
    wlCompute:  Result := 'добровольные научные вычисления (BOINC, Folding@home)';
  else
    Result := '';
  end;
end;

function MHIsSystemProcessName(const AName: string; out AExpectedDirs: TArray<string>): Boolean;
var
  LName: string;
begin
  LName := ExtractFileName(AName).ToLower;
  AExpectedDirs := nil;
  if LName = 'explorer.exe' then
    AExpectedDirs := ['\windows\', '\windows\syswow64\']
  else if InList(LName, SYSTEM_IN_SYSTEM32) then
    AExpectedDirs := ['\windows\system32\', '\windows\syswow64\'];
  Result := Length(AExpectedDirs) > 0;
end;

function Distance1(const A, B: string): Boolean;
var
  I, J, LDiff: Integer;
begin
  // Ровно одно изменение: замена, вставка или удаление символа.
  if Abs(Length(A) - Length(B)) > 1 then
    Exit(False);
  if A = B then
    Exit(False);
  // Перестановка соседних символов (scvhost <-> svchost) тоже считается одной правкой.
  if Length(A) = Length(B) then
  begin
    I := 1;
    while (I <= Length(A)) and (A[I] = B[I]) do
      Inc(I);
    if (I < Length(A)) and (A[I] = B[I + 1]) and (A[I + 1] = B[I]) and
       (Copy(A, I + 2, MaxInt) = Copy(B, I + 2, MaxInt)) then
      Exit(True);
  end;
  I := 1;
  J := 1;
  LDiff := 0;
  while (I <= Length(A)) and (J <= Length(B)) do
  begin
    if A[I] = B[J] then
    begin
      Inc(I);
      Inc(J);
      Continue;
    end;
    Inc(LDiff);
    if LDiff > 1 then
      Exit(False);
    if Length(A) > Length(B) then
      Inc(I)
    else if Length(A) < Length(B) then
      Inc(J)
    else
    begin
      Inc(I);
      Inc(J);
    end;
  end;
  Inc(LDiff, (Length(A) - I + 1) + (Length(B) - J + 1));
  Result := LDiff = 1;
end;

function MHLooksLikeSystemName(const AName: string; out ASystemName: string): Boolean;
var
  LName, LCandidate: string;
begin
  LName := ExtractFileName(AName).ToLower;
  ASystemName := '';
  if LName = '' then
    Exit(False);
  for LCandidate in SYSTEM_IN_SYSTEM32 do
    if Distance1(LName, LCandidate) then
    begin
      ASystemName := LCandidate;
      Exit(True);
    end;
  if Distance1(LName, 'explorer.exe') then
  begin
    ASystemName := 'explorer.exe';
    Exit(True);
  end;
  Result := False;
end;

function MHIsSuspiciousLocation(const AImagePath: string; out AReason: string): Boolean;
var
  LPath, LRest: string;
  LPos: Integer;
begin
  AReason := '';
  LPath := AImagePath.ToLower;
  if LPath = '' then
    Exit(False);
  if LPath.Contains('\appdata\local\temp\') or LPath.Contains('\windows\temp\') then
    AReason := 'временная папка'
  else if LPath.Contains('\downloads\') then
    AReason := 'папка «Загрузки»'
  else if LPath.Contains('\users\public\') then
    AReason := 'общая папка пользователей (Public)'
  else if LPath.Contains('\$recycle.bin\') then
    AReason := 'корзина'
  else if LPath.Contains('\perflogs\') then
    AReason := 'папка журналов производительности'
  else if LPath.Contains('\windows\fonts\') or LPath.Contains('\windows\debug\') then
    AReason := 'служебная папка Windows, где не бывает программ'
  else
  begin
    // Исполняемый файл прямо в ProgramData или в её подпапке первого уровня
    // без папки производителя — частое место для закрепления вредоносных программ.
    LPos := Pos('\programdata\', LPath);
    if LPos > 0 then
    begin
      LRest := Copy(LPath, LPos + Length('\programdata\'), MaxInt);
      if not LRest.Contains('\') then
        AReason := 'корень папки ProgramData';
    end;
  end;
  Result := AReason <> '';
end;

function MHIsScriptFile(const APath: string): Boolean;
var
  LExt: string;
begin
  LExt := ExtractFileExt(APath).ToLower;
  Result := (LExt = '.bat') or (LExt = '.cmd') or (LExt = '.vbs') or (LExt = '.vbe') or
    (LExt = '.js') or (LExt = '.jse') or (LExt = '.ps1') or (LExt = '.wsf') or (LExt = '.hta');
end;

function IsRandomLooking(const ASegment: string): Boolean;
var
  LCh: Char;
  LUpper, LLower, LDigits, LHexOnly: Integer;
begin
  // Длинное имя из букв в обоих регистрах и цифр, не похожее на GUID/хеш.
  Result := False;
  if Length(ASegment) < 12 then
    Exit;
  LUpper := 0;
  LLower := 0;
  LDigits := 0;
  LHexOnly := 0;
  for LCh in ASegment do
  begin
    if CharInSet(LCh, ['A'..'Z']) then
      Inc(LUpper)
    else if CharInSet(LCh, ['a'..'z']) then
      Inc(LLower)
    else if CharInSet(LCh, ['0'..'9']) then
      Inc(LDigits)
    else
      Exit; // пробелы, точки, дефисы — обычные имена папок
    if CharInSet(LCh, ['0'..'9', 'a'..'f', 'A'..'F']) then
      Inc(LHexOnly);
  end;
  if LHexOnly = Length(ASegment) then
    Exit; // шестнадцатеричные имена (хеши, кеши) обычны для программ
  Result := (LUpper >= 3) and (LLower >= 3) and (LDigits >= 1);
end;

function MHFindRandomLookingFolder(const APath: string; out AFolder: string): Boolean;
var
  LParts: TArray<string>;
  I: Integer;
begin
  AFolder := '';
  LParts := ExtractFilePath(APath).Split(['\'], TStringSplitOptions.ExcludeEmpty);
  for I := 0 to High(LParts) do
    if IsRandomLooking(LParts[I]) then
    begin
      AFolder := LParts[I];
      Exit(True);
    end;
  Result := False;
end;

function MHFindObfuscatedCommand(const ACommand: string): string;
var
  LLower: string;
begin
  LLower := ' ' + ACommand.ToLower + ' ';
  if LLower.Contains('powershell') and (LLower.Contains(' -enc ') or
     LLower.Contains(' -encodedcommand ') or LLower.Contains(' -e ') or LLower.Contains(' -ec ')) then
    Result := 'закодированная команда PowerShell'
  else if LLower.Contains('frombase64string') then
    Result := 'декодирование Base64 в команде'
  else if LLower.Contains('mshta ') and (LLower.Contains('http') or LLower.Contains('javascript:') or
          LLower.Contains('vbscript:')) then
    Result := 'mshta с внешним или встроенным сценарием'
  else
    Result := '';
end;

function MHFindHiddenScriptLaunch(const ACommand: string): string;
var
  LLower: string;
begin
  LLower := ' ' + ACommand.ToLower + ' ';
  if (LLower.Contains(' -windowstyle hidden') or LLower.Contains(' -w hidden')) and
     (LLower.Contains(' -executionpolicy bypass') or LLower.Contains(' -ep bypass')) then
    Result := 'скрытое окно и обход политики выполнения PowerShell'
  else if LLower.Contains(' -windowstyle hidden') or LLower.Contains(' -w hidden') then
    Result := 'скрытое окно PowerShell'
  else
    Result := '';
end;

function MHIsStandardInstallLocation(const AImagePath: string): Boolean;
var
  LPath: string;
begin
  LPath := AImagePath.ToLower;
  Result := LPath.Contains(':\windows\') or LPath.Contains(':\program files\') or
    LPath.Contains(':\program files (x86)\');
end;

end.
