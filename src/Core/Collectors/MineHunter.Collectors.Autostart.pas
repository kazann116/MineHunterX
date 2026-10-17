unit MineHunter.Collectors.Autostart;

{
  Коллектор элементов автозапуска (MH-04): разделы реестра Run/RunOnce,
  папки автозагрузки, службы и задания планировщика.

  Логика отделена от Windows API интерфейсом IMHAutostartApi, чтобы
  кэширование, частичные отказы источников и разбор командных строк
  проверялись детерминированными unit-тестами. Реальная реализация —
  MineHunter.Collectors.Autostart.WinApi.

  Чтение всех источников автозапуска дорогое (сотни служб и заданий,
  COM планировщика), а меняются они редко. Поэтому коллектор кэширует
  результат: первый вызов Collect читает всё, следующие возвращают
  кэш, пока по IMHClock.NowUtc не пройдёт ARefreshSeconds. Полный отказ
  (все источники недоступны) не кэшируется — следующий вызов повторит чтение.

  Каждый источник может отказать независимо: частичный отказ даёт ssPartial
  с перечнем недоступных источников, отказ всех — ssError. Исключения
  источников перехватываются и превращаются в статус.

  Путь исполняемого файла (ImagePath) извлекается из исходной команды чистой
  функцией MHExtractExecutable, если источник не определил его сам.
  Проверка подписи и хеша выполняется другими компонентами.

  Коллектор не потокобезопасен: сканер вызывает Collect последовательно.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Абстракция системных вызовов для коллектора автозапуска.
  /// Методы Read* независимы: отказ одного не влияет на остальные.
  /// Соглашение: False — источник прочитать не удалось (AError — причина);
  /// True с непустым AError — данные получены частично (AError — пояснение).
  /// Поле ImagePath записей может быть пустым: тогда коллектор извлечёт путь
  /// из Command функцией MHExtractExecutable.
  IMHAutostartApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C70}']
    /// Значения разделов Run/RunOnce (HKLM, HKCU, WOW6432Node).
    function ReadRegistryRun(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    /// Файлы и ярлыки папок автозагрузки пользователя и общей.
    function ReadStartupFolders(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    /// Службы Win32 с автоматическим запуском.
    function ReadServices(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    /// Задания планировщика (включая скрытые).
    function ReadScheduledTasks(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    /// Каталог Windows без завершающего «\» (например, C:\Windows).
    function WindowsDir: string;
    /// Существует ли файл (не каталог).
    function FileExists(const APath: string): Boolean;
    /// Подстановка переменных окружения вида %NAME% (неизвестные остаются как есть).
    function ExpandEnvironment(const AText: string): string;
  end;

  TMHAutostartCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'autostart';
    DefaultRefreshSeconds = 60;
  private type
    TSourceKind = (skRegistry, skStartupFolders, skServices, skTasks);
  private
    FApi: IMHAutostartApi;
    FClock: IMHClock;
    FRefreshSeconds: Integer;
    FHasCache: Boolean;
    FCacheUtc: TDateTime;
    FCached: TArray<TMHAutostartEntry>;
    FCachedState: TMHSourceState;
    FCachedMessage: string;
    FReadCount: Integer;
    function NeedsRefresh(ANowUtc: TDateTime): Boolean;
    function ReadSource(AKind: TSourceKind; out AEntries: TArray<TMHAutostartEntry>;
      out AError: string): Boolean;
    procedure FillImagePaths(var AEntries: TArray<TMHAutostartEntry>);
    procedure Refresh(ANowUtc: TDateTime);
    class function SourceName(AKind: TSourceKind): string; static;
  public
    /// ARefreshSeconds — время жизни кэша; 0 и меньше — читать при каждом вызове.
    constructor Create(const AApi: IMHAutostartApi; const AClock: IMHClock;
      ARefreshSeconds: Integer = DefaultRefreshSeconds);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Сбрасывает кэш: следующий Collect перечитает все источники
    /// (например, по кнопке «Обновить» в интерфейсе).
    procedure Invalidate;
    /// Сколько раз источники читались полностью (для диагностики и тестов).
    property ReadCount: Integer read FReadCount;
    property RefreshSeconds: Integer read FRefreshSeconds;
  end;

/// Извлекает нормализованный путь исполняемого файла из командной строки
/// автозапуска. Переменные окружения должны быть уже подставлены
/// (оставшиеся %SystemRoot% и %windir% заменяются на AWindowsDir).
/// Правила:
///  - пустая команда -> '';
///  - «"путь" аргументы» -> путь в кавычках;
///  - путь без кавычек с пробелами -> перебор префиксов по словам от
///    короткого к длинному, как это делает CreateProcess: первый
///    существующий файл (с указанным расширением или с добавленным «.exe»);
///    если ни один не существует — первый префикс с расширением исполняемого
///    файла (.exe, .com, .bat, .cmd, .dll, .scr, .sys, ...), иначе первое слово;
///  - «\SystemRoot\», «\??\», «\\?\» -> обычный путь Win32;
///  - относительный путь с каталогом («system32\drivers\x.sys») -> от AWindowsDir;
///  - голое имя («svchost.exe», «rundll32», «powershell») -> поиск в
///    AWindowsDir\System32, AWindowsDir, System32\WindowsPowerShell\v1.0 и
///    System32\wbem; не найдено -> '' (поиск по PATH не выполняется:
///    PATH процесса сканера не совпадает с окружением запуска элемента);
///  - повторные кавычки («""C:\a.exe""» из некоторых заданий) пропускаются;
///  - для rundll32 образом считается сам rundll32.exe.
/// AFileExists = nil — проверка существования недоступна (все файлы
/// считаются отсутствующими).
function MHExtractExecutable(const ACommand, AWindowsDir: string;
  const AFileExists: TFunc<string, Boolean>): string;

implementation

uses
  System.StrUtils, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Paths;

const
  /// Расширения, по которым префикс команды считается именем исполняемого файла.
  EXECUTABLE_EXTENSIONS: array[0..15] of string = ('.exe', '.com', '.bat', '.cmd', '.dll',
    '.scr', '.sys', '.cpl', '.ocx', '.msc', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.ps1');
  /// Защита от патологически длинных команд: дальше этого числа слов префиксы не перебираются.
  MAX_PREFIX_WORDS = 64;
  /// Каталоги (относительно каталога Windows) для поиска голого имени программы.
  BARE_NAME_DIRS: array[0..3] of string = ('System32', '', 'System32\WindowsPowerShell\v1.0',
    'System32\wbem');

function HasExecutableExtension(const APath: string): Boolean;
var
  LExt: string;
  LKnown: string;
begin
  LExt := ExtractFileExt(APath);
  if LExt = '' then
    Exit(False);
  for LKnown in EXECUTABLE_EXTENSIONS do
    if SameText(LExt, LKnown) then
      Exit(True);
  Result := False;
end;

/// Подставляет каталог Windows вместо оставшихся %SystemRoot% / %windir%.
function ReplaceWindowsVars(const AText, AWindowsDir: string): string;
begin
  Result := AText;
  if AWindowsDir = '' then
    Exit;
  Result := StringReplace(Result, '%SystemRoot%', AWindowsDir, [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '%windir%', AWindowsDir, [rfReplaceAll, rfIgnoreCase]);
end;

function IsBareName(const APath: string): Boolean;
begin
  Result := (APath <> '') and (Pos('\', APath) = 0) and (Pos('/', APath) = 0) and
    (Pos(':', APath) = 0);
end;

/// Путь кандидата без проверки существования. Для голого имени — ''.
function GuessPath(const ACandidate, AWindowsDir: string): string;
var
  S: string;
begin
  S := MHNormalizePath(ReplaceWindowsVars(ACandidate, AWindowsDir), AWindowsDir);
  if S = '' then
    Exit('');
  if IsBareName(S) then
    Exit('');
  if StartsStr('\\', S) or ((Length(S) >= 2) and (S[2] = ':')) then
    Exit(S);
  // Корень без диска («\Windows\x.exe») — диск каталога Windows.
  if StartsStr('\', S) then
  begin
    if (Length(AWindowsDir) >= 2) and (AWindowsDir[2] = ':') then
      Exit(MHNormalizePath(Copy(AWindowsDir, 1, 2) + S));
    Exit(S);
  end;
  // Относительный путь с каталогом: так SCM трактует пути драйверов
  // («system32\drivers\x.sys») — от каталога Windows.
  if AWindowsDir <> '' then
    Result := MHNormalizePath(IncludeTrailingPathDelimiter(AWindowsDir) + S)
  else
    Result := S;
end;

/// Ищет существующий файл для кандидата. Без расширения пробует добавить «.exe»
/// (как CreateProcess). Голое имя ищется в каталогах BARE_NAME_DIRS.
function TryResolveExisting(const ACandidate, AWindowsDir: string;
  const AFileExists: TFunc<string, Boolean>; out APath: string): Boolean;

  function Check(const APathToCheck: string): Boolean;
  begin
    Result := (APathToCheck <> '') and AFileExists(APathToCheck);
    if Result then
      APath := APathToCheck;
  end;

  function CheckWithExe(const APathToCheck: string): Boolean;
  begin
    Result := Check(APathToCheck);
    if not Result and (ExtractFileExt(APathToCheck) = '') then
      Result := Check(APathToCheck + '.exe');
  end;

var
  S, LWinDir, LSubDir: string;
begin
  APath := '';
  if not Assigned(AFileExists) then
    Exit(False);
  S := MHNormalizePath(ReplaceWindowsVars(ACandidate, AWindowsDir), AWindowsDir);
  if S = '' then
    Exit(False);
  if IsBareName(S) then
  begin
    if AWindowsDir = '' then
      Exit(False);
    LWinDir := ExcludeTrailingPathDelimiter(AWindowsDir);
    for LSubDir in BARE_NAME_DIRS do
      if LSubDir = '' then
      begin
        if CheckWithExe(LWinDir + '\' + S) then
          Exit(True);
      end
      else if CheckWithExe(LWinDir + '\' + LSubDir + '\' + S) then
        Exit(True);
    Result := False;
  end
  else
    Result := CheckWithExe(GuessPath(S, AWindowsDir));
end;

function ExtractQuoted(const ACommand, AWindowsDir: string;
  const AFileExists: TFunc<string, Boolean>): string;
var
  LStart, LClose: Integer;
  LInner: string;
begin
  // Повторные открывающие кавычки («""C:\a.exe""») пропускаются.
  LStart := 1;
  while (LStart <= Length(ACommand)) and (ACommand[LStart] = '"') do
    Inc(LStart);
  LClose := PosEx('"', ACommand, LStart);
  if LClose = 0 then
    LInner := Copy(ACommand, LStart, MaxInt)
  else
    LInner := Copy(ACommand, LStart, LClose - LStart);
  LInner := Trim(LInner);
  if LInner = '' then
    Exit('');
  if TryResolveExisting(LInner, AWindowsDir, AFileExists, Result) then
    Exit;
  Result := GuessPath(LInner, AWindowsDir);
end;

function ExtractUnquoted(const ACommand, AWindowsDir: string;
  const AFileExists: TFunc<string, Boolean>): string;
var
  LWords: TArray<string>;
  LCandidate, LFallback: string;
  I, LLast: Integer;
begin
  // Пустые элементы сохраняются, чтобы склейка восстанавливала исходные пробелы.
  LWords := ACommand.Split([' ']);
  LLast := High(LWords);
  if LLast >= MAX_PREFIX_WORDS then
    LLast := MAX_PREFIX_WORDS - 1;
  LFallback := '';
  LCandidate := '';
  for I := 0 to LLast do
  begin
    if I = 0 then
      LCandidate := LWords[0]
    else
      LCandidate := LCandidate + ' ' + LWords[I];
    if LWords[I] = '' then
      Continue;
    // Двоеточие после буквы диска — начало следующего пути в аргументах:
    // более длинные префиксы уже не могут быть путём к файлу.
    if PosEx(':', LCandidate, 3) > 0 then
      Break;
    if TryResolveExisting(LCandidate, AWindowsDir, AFileExists, Result) then
      Exit;
    if (LFallback = '') and HasExecutableExtension(LCandidate) then
    begin
      LFallback := GuessPath(LCandidate, AWindowsDir);
      // Голое имя с расширением не найдено в системных каталогах —
      // дальнейшие слова относятся к аргументам.
      if LFallback = '' then
        Exit('');
    end;
  end;
  if LFallback = '' then
    LFallback := GuessPath(LWords[0], AWindowsDir);
  Result := LFallback;
end;

function MHExtractExecutable(const ACommand, AWindowsDir: string;
  const AFileExists: TFunc<string, Boolean>): string;
var
  S, LWinDir: string;
begin
  S := Trim(ACommand);
  if S = '' then
    Exit('');
  LWinDir := ExcludeTrailingPathDelimiter(Trim(AWindowsDir));
  if S[1] = '"' then
    Result := ExtractQuoted(S, LWinDir, AFileExists)
  else
    Result := ExtractUnquoted(S, LWinDir, AFileExists);
end;

{ TMHAutostartCollector }

constructor TMHAutostartCollector.Create(const AApi: IMHAutostartApi; const AClock: IMHClock;
  ARefreshSeconds: Integer);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
  if ARefreshSeconds < 0 then
    ARefreshSeconds := 0;
  FRefreshSeconds := ARefreshSeconds;
  FCachedState := ssUnknown;
end;

function TMHAutostartCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHAutostartCollector.GetDisplayName: string;
begin
  Result := 'Автозапуск';
end;

procedure TMHAutostartCollector.Invalidate;
begin
  FHasCache := False;
end;

class function TMHAutostartCollector.SourceName(AKind: TSourceKind): string;
begin
  case AKind of
    skRegistry:       Result := 'реестр Run/RunOnce';
    skStartupFolders: Result := 'папки автозагрузки';
    skServices:       Result := 'службы';
  else
    Result := 'планировщик заданий';
  end;
end;

function TMHAutostartCollector.NeedsRefresh(ANowUtc: TDateTime): Boolean;
var
  LElapsedMs: Int64;
begin
  if not FHasCache or (FRefreshSeconds <= 0) then
    Exit(True);
  // Округление до миллисекунд убирает погрешность арифметики TDateTime
  // (ровно 60 с не должны превращаться в 59,999999 с).
  LElapsedMs := Round((ANowUtc - FCacheUtc) * MSecsPerDay);
  // Перевод часов назад тоже считается поводом перечитать данные.
  Result := (LElapsedMs < 0) or (LElapsedMs >= Int64(FRefreshSeconds) * MSecsPerSec);
end;

function TMHAutostartCollector.ReadSource(AKind: TSourceKind;
  out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
begin
  AEntries := nil;
  AError := '';
  try
    case AKind of
      skRegistry:       Result := FApi.ReadRegistryRun(AEntries, AError);
      skStartupFolders: Result := FApi.ReadStartupFolders(AEntries, AError);
      skServices:       Result := FApi.ReadServices(AEntries, AError);
    else
      Result := FApi.ReadScheduledTasks(AEntries, AError);
    end;
  except
    // Отказ одного источника не должен прерывать чтение остальных.
    on E: Exception do
    begin
      AEntries := nil;
      AError := E.Message;
      Result := False;
    end;
  end;
  if not Result then
  begin
    AEntries := nil;
    if Trim(AError) = '' then
      AError := 'причина не указана';
  end;
end;

procedure TMHAutostartCollector.FillImagePaths(var AEntries: TArray<TMHAutostartEntry>);
var
  LWinDir: string;
  LExistsCache: TDictionary<string, Boolean>;
  LExists: TFunc<string, Boolean>;
  LApi: IMHAutostartApi;
  I: Integer;
begin
  LApi := FApi;
  LWinDir := ExcludeTrailingPathDelimiter(FApi.WindowsDir);
  // Разные записи часто ссылаются на одни и те же файлы (svchost.exe,
  // rundll32.exe), а префиксы команд проверяются по нескольку раз —
  // результаты проверки существования кэшируются на время одного чтения.
  LExistsCache := TDictionary<string, Boolean>.Create(TIStringComparer.Ordinal);
  try
    LExists :=
      function(APath: string): Boolean
      begin
        if not LExistsCache.TryGetValue(APath, Result) then
        begin
          Result := LApi.FileExists(APath);
          LExistsCache.Add(APath, Result);
        end;
      end;
    for I := 0 to High(AEntries) do
      if Trim(AEntries[I].ImagePath) <> '' then
        AEntries[I].ImagePath := MHNormalizePath(
          ReplaceWindowsVars(FApi.ExpandEnvironment(AEntries[I].ImagePath), LWinDir), LWinDir)
      else
        AEntries[I].ImagePath := MHExtractExecutable(FApi.ExpandEnvironment(AEntries[I].Command),
          LWinDir, LExists);
  finally
    // Анонимный метод захватывает словарь: обнуляем ссылку до освобождения.
    LExists := nil;
    LExistsCache.Free;
  end;
end;

procedure TMHAutostartCollector.Refresh(ANowUtc: TDateTime);
var
  LKind: TSourceKind;
  LEntries, LAll: TArray<TMHAutostartEntry>;
  LError: string;
  LFailed, LWarnings: TArray<string>;
  LFailedCount: Integer;
begin
  LAll := nil;
  LFailed := nil;
  LWarnings := nil;
  LFailedCount := 0;
  for LKind := Low(TSourceKind) to High(TSourceKind) do
    if ReadSource(LKind, LEntries, LError) then
    begin
      LAll := LAll + LEntries;
      if Trim(LError) <> '' then
        LWarnings := LWarnings + [SourceName(LKind) + ': ' + Trim(LError)];
    end
    else
    begin
      Inc(LFailedCount);
      LFailed := LFailed + [SourceName(LKind) + ' (' + Trim(LError) + ')'];
    end;
  Inc(FReadCount);

  if LFailedCount = Ord(High(TSourceKind)) + 1 then
  begin
    // Полный отказ не кэшируется: следующий вызов повторит чтение.
    FHasCache := False;
    FCached := nil;
    FCachedState := ssError;
    FCachedMessage := 'Не удалось прочитать ни один источник автозапуска: ' +
      string.Join('; ', LFailed) + '.';
    Exit;
  end;

  FillImagePaths(LAll);
  FCached := LAll;
  FCacheUtc := ANowUtc;
  FHasCache := True;
  FCachedMessage := '';
  if LFailedCount > 0 then
    FCachedMessage := 'Не удалось прочитать: ' + string.Join('; ', LFailed) + '.';
  if Length(LWarnings) > 0 then
    FCachedMessage := Trim(FCachedMessage + ' Неполные данные: ' +
      string.Join('; ', LWarnings) + '.');
  if FCachedMessage <> '' then
    FCachedState := ssPartial
  else
    FCachedState := ssSuccess;
end;

function TMHAutostartCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LStamp: TDateTime;
begin
  LStamp := ASnapshot.TimestampUtc;
  if LStamp = 0 then
    LStamp := FClock.NowUtc;

  if NeedsRefresh(FClock.NowUtc) then
    Refresh(FClock.NowUtc);

  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, FCachedState,
    FCachedMessage, LStamp));
  // Копия: потребители не должны разделять массив с кэшем коллектора.
  Result.Autostart := Copy(FCached);
  Result.Status.ItemCount := Length(Result.Autostart);
end;

end.
