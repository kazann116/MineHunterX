unit MineHunter.Core.Actions;

{
  MineHunter X — безопасные действия пользователя (MH-10).

  Правила:
    - модуль ничего не делает сам: каждое действие вызывается из UI только
      после явного подтверждения пользователем; при этом API само по себе
      отказывает в опасных операциях (системные и критические процессы,
      собственный процесс, переиспользованный PID, подменённые пути);
    - права никогда не повышаются автоматически: при отказе в доступе
      возвращается подсказка о запуске от имени администратора;
    - карантин и удаление файлов не входят в MVP; проверка Microsoft Defender
      запускается с -DisableRemediation — только отчёт, без автоматических
      действий с файлом;
    - каждая попытка остановки процесса и проверки Defender (с любым исходом)
      записывается в журнал действий IMHActionLog;
    - обращения к ОС вынесены в IMHSystemOps, логика полностью покрыта
      unit-тестами с поддельной реализацией.

  Потоки: TerminateProcess и OpenFileLocation вызываются из главного потока;
  ScanWithDefender длится до 10 минут и должен выполняться в фоновом потоке
  (отмена — через ACancel). Реализация IMHActionLog должна быть потокобезопасной.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHActionResultKind = (
    arkDone,              // действие выполнено
    arkNotFound,          // процесс или файл не найден (уже завершён, удалён)
    arkAccessDenied,      // недостаточно прав
    arkIdentityMismatch,  // PID принадлежит другому процессу или личность не подтверждена
    arkProtected,         // системный или критический процесс — действие запрещено
    arkUnavailable,       // инструмент недоступен (например, Microsoft Defender)
    arkFailed,            // прочая ошибка, недопустимый путь, превышено время ожидания
    arkCancelled          // отменено пользователем
  );

  TMHActionResult = record
  public
    Kind: TMHActionResultKind;
    /// Краткое сообщение для пользователя.
    Message: string;
    /// Подробности (вывод инструмента, код ошибки); может быть пустым.
    Details: string;
    class function Create(AKind: TMHActionResultKind; const AMessage: string;
      const ADetails: string = ''): TMHActionResult; static;
    function Succeeded: Boolean;
  end;

  /// Проверка отмены длительной операции; True — прекратить.
  TMHCancelFunc = reference to function: Boolean;

  /// Исход запуска внешней программы.
  TMHRunOutcome = (
    roCompleted,    // программа завершилась сама, AExitCode заполнен
    roStartFailed,  // не удалось запустить (описание ошибки — в AOutput)
    roTimeout,      // превышено время ожидания, программа принудительно завершена
    roCancelled     // отменено, программа принудительно завершена
  );

  /// Обращения к ОС, необходимые безопасным действиям.
  IMHSystemOps = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C80}']
    function CurrentPid: Cardinal;
    /// Открывает процесс с правами PROCESS_TERMINATE, SYNCHRONIZE и
    /// PROCESS_QUERY_LIMITED_INFORMATION. AError — код ошибки Windows.
    function OpenProcessForTerminate(APid: Cardinal; out AHandle: THandle;
      out AError: Cardinal): Boolean;
    procedure CloseProcess(AHandle: THandle);
    /// Время создания процесса (FILETIME, UTC).
    function GetCreateTime(AHandle: THandle; out ACreateTime: UInt64): Boolean;
    /// Полный путь к образу процесса.
    function GetImagePath(AHandle: THandle; out APath: string): Boolean;
    /// Процесс помечен системой как критический (его завершение — BSOD).
    function IsCritical(AHandle: THandle; out ACritical: Boolean): Boolean;
    function Terminate(AHandle: THandle; AExitCode: Cardinal; out AError: Cardinal): Boolean;
    /// True — процесс завершился в течение ATimeoutMs (0 — проверка без ожидания).
    function WaitExit(AHandle: THandle; ATimeoutMs: Cardinal): Boolean;
    /// Существует ли файл (каталоги — False).
    function FileExists(const APath: string): Boolean;
    /// Открывает Проводник с выделенным файлом (explorer.exe /select,"<путь>").
    function ShellOpenSelect(const APath: string; out AError: string): Boolean;
    /// Полный путь к MpCmdRun.exe или '' — Microsoft Defender не найден.
    function FindDefenderCli: string;
    /// Запускает программу без окна, собирает stdout/stderr, ждёт завершения
    /// не дольше ATimeoutMs; ACancel (может быть nil) опрашивается периодически.
    function RunHidden(const AExe, AArgs: string; ATimeoutMs: Cardinal;
      const ACancel: TMHCancelFunc; out AExitCode: Cardinal; out AOutput: string): TMHRunOutcome;
  end;

  TMHSafeActions = class
  public const
    /// Сколько ждать завершения процесса после TerminateProcess.
    TerminateWaitMs = 5000;
    /// Предельная длительность проверки Microsoft Defender.
    DefenderTimeoutMs = 10 * 60 * 1000;
    ActionTerminate = 'terminate';
    ActionDefenderScan = 'defender-scan';
  private
    FOps: IMHSystemOps;
    FActionLog: IMHActionLog;
    FClock: IMHClock;
    procedure Journal(const AAction, ATarget: string; var AResult: TMHActionResult);
    function DoTerminate(const AId: TMHProcessId; const AName: string): TMHActionResult;
    function DoScan(const APath: string; const ACancel: TMHCancelFunc): TMHActionResult;
  public
    /// AOps и AClock обязательны; AActionLog может быть nil (журнал не ведётся).
    constructor Create(const AOps: IMHSystemOps; const AActionLog: IMHActionLog;
      const AClock: IMHClock);
    /// Показывает файл в Проводнике. Путь нормализуется; отклоняются
    /// несуществующие файлы и всё, что не является обычным локальным или
    /// UNC-путём (кавычки, аргументы, URI «shell:», альтернативные потоки).
    function OpenFileLocation(const APath: string): TMHActionResult;
    /// Останавливает процесс после проверки личности (PID + время создания).
    /// Отказывает для собственного процесса, PID 0/4, системных и критических
    /// процессов. Ждёт завершения до TerminateWaitMs. Журналируется всегда.
    function TerminateProcess(const AId: TMHProcessId; const AName: string): TMHActionResult;
    /// Проверка файла Microsoft Defender (MpCmdRun -Scan -ScanType 3
    /// -DisableRemediation): только отчёт, Defender ничего не удаляет.
    /// Длительная операция — вызывать из фонового потока. Журналируется всегда.
    function ScanWithDefender(const APath: string; const ACancel: TMHCancelFunc): TMHActionResult;

    /// Имя (или путь) относится к системным процессам, которые MineHunter не завершает.
    class function IsProtectedProcessName(const AName: string): Boolean; static;
    /// Проверяет, что путь — обычный абсолютный путь к файлу (X:\... или
    /// \\сервер\ресурс\...), без кавычек, подстановочных и управляющих
    /// символов, «:» после буквы диска. ANormalized — результат MHNormalizePath.
    class function ValidatePlainFilePath(const APath: string; out ANormalized: string;
      out AError: string): Boolean; static;
  end;

/// Сравнение версий вида «4.18.24090.11-0» по числовым компонентам.
/// Возвращает False, если строка не является версией.
function MHTryCompareVersions(const A, B: string; out AResult: Integer): Boolean;
/// Имена каталогов платформы Defender, отсортированные от новой версии
/// к старой; имена, не являющиеся версиями, отбрасываются.
function MHSortDefenderPlatforms(const ANames: TArray<string>): TArray<string>;
/// Имена угроз из вывода MpCmdRun (строки «Threat : <имя>»), без повторов.
function MHParseDefenderThreats(const AOutput: string): TArray<string>;
function MHActionResultKindToString(AKind: TMHActionResultKind): string;

implementation

uses
  System.Math, System.Character, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Paths, MineHunter.Core.Lang;

const
  // Коды ошибок Windows (winerror.h); модуль не зависит от Winapi.Windows.
  ERROR_ACCESS_DENIED_CODE = 5;
  ERROR_INVALID_PARAMETER_CODE = 87;
  /// HRESULT MpCmdRun: служба Microsoft Defender не запущена (отключена
  /// или заменена сторонним антивирусом).
  DEFENDER_SERVICE_NOT_RUNNING = Cardinal($800106BA);
  TERMINATE_EXIT_CODE = 1;
  MAX_PATH_LENGTH = 32767;
  OUTPUT_TAIL_LINES = 10;

  PROTECTED_PROCESS_NAMES: array[0..19] of string = (
    'system', 'system idle process', 'secure system', 'registry', 'memory compression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
    'lsaiso.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'msmpeng.exe',
    'securityhealthservice.exe', 'sgrmbroker.exe', 'nissrv.exe', 'mssense.exe');

{ TMHActionResult }

class function TMHActionResult.Create(AKind: TMHActionResultKind; const AMessage: string;
  const ADetails: string): TMHActionResult;
begin
  Result.Kind := AKind;
  Result.Message := AMessage;
  Result.Details := ADetails;
end;

function TMHActionResult.Succeeded: Boolean;
begin
  Result := Kind = arkDone;
end;

function MHActionResultKindToString(AKind: TMHActionResultKind): string;
begin
  case AKind of
    arkDone:             Result := MHL('выполнено', 'done');
    arkNotFound:         Result := MHL('не найдено', 'not found');
    arkAccessDenied:     Result := MHL('нет доступа', 'access denied');
    arkIdentityMismatch: Result := MHL('процесс не совпадает', 'process mismatch');
    arkProtected:        Result := MHL('защищённый объект', 'protected object');
    arkUnavailable:      Result := MHL('недоступно', 'unavailable');
    arkCancelled:        Result := MHL('отменено', 'cancelled');
  else
    Result := MHL('ошибка', 'error');
  end;
end;

{ Версии и вывод Defender }

function TryParseVersion(const AText: string; out AParts: TArray<Int64>): Boolean;
var
  LItems: TArray<string>;
  I: Integer;
begin
  AParts := nil;
  LItems := AText.Trim.Split(['.', '-']);
  if Length(LItems) < 2 then
    Exit(False);
  SetLength(AParts, Length(LItems));
  for I := 0 to High(LItems) do
    if (LItems[I] = '') or not TryStrToInt64(LItems[I], AParts[I]) or (AParts[I] < 0) then
      Exit(False);
  Result := True;
end;

function MHTryCompareVersions(const A, B: string; out AResult: Integer): Boolean;
var
  LA, LB: TArray<Int64>;
  I: Integer;
  LValueA, LValueB: Int64;
begin
  AResult := 0;
  if not TryParseVersion(A, LA) or not TryParseVersion(B, LB) then
    Exit(False);
  for I := 0 to Max(High(LA), High(LB)) do
  begin
    if I <= High(LA) then LValueA := LA[I] else LValueA := 0;
    if I <= High(LB) then LValueB := LB[I] else LValueB := 0;
    AResult := CompareValue(LValueA, LValueB);
    if AResult <> 0 then
      Break;
  end;
  Result := True;
end;

function CompareVersionsDesc(const A, B: string): Integer;
begin
  // Обе строки уже проверены как версии.
  MHTryCompareVersions(B, A, Result);
  if Result = 0 then
    Result := CompareStr(A, B);
end;

function MHSortDefenderPlatforms(const ANames: TArray<string>): TArray<string>;
var
  LName: string;
  LParts: TArray<Int64>;
begin
  Result := nil;
  for LName in ANames do
    if TryParseVersion(LName, LParts) then
      Result := Result + [LName.Trim];
  TArray.Sort<string>(Result, TComparer<string>.Construct(CompareVersionsDesc));
end;

function MHParseDefenderThreats(const AOutput: string): TArray<string>;
var
  LLine, LName, LExisting: string;
  LColon: Integer;
  LDuplicate: Boolean;
begin
  Result := nil;
  for LLine in AOutput.Split([#13#10, #10, #13]) do
  begin
    LColon := Pos(':', LLine);
    if (LColon = 0) or not SameText(Trim(Copy(LLine, 1, LColon - 1)), 'Threat') then
      Continue;
    LName := Trim(Copy(LLine, LColon + 1, MaxInt));
    if LName = '' then
      Continue;
    LDuplicate := False;
    for LExisting in Result do
      if SameText(LExisting, LName) then
        LDuplicate := True;
    if not LDuplicate then
      Result := Result + [LName];
  end;
end;

function OutputTail(const AOutput: string): string;
var
  LLines, LTail: TArray<string>;
  LLine: string;
begin
  LTail := nil;
  LLines := AOutput.Split([#13#10, #10, #13]);
  for LLine in LLines do
    if Trim(LLine) <> '' then
    begin
      LTail := LTail + [TrimRight(LLine)];
      if Length(LTail) > OUTPUT_TAIL_LINES then
        Delete(LTail, 0, 1);
    end;
  Result := string.Join(sLineBreak, LTail);
end;

{ TMHSafeActions }

constructor TMHSafeActions.Create(const AOps: IMHSystemOps; const AActionLog: IMHActionLog;
  const AClock: IMHClock);
begin
  inherited Create;
  if AOps = nil then
    raise EArgumentNilException.Create('AOps');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FOps := AOps;
  FActionLog := AActionLog;
  FClock := AClock;
end;

class function TMHSafeActions.IsProtectedProcessName(const AName: string): Boolean;
var
  LName, LItem: string;
begin
  LName := Trim(AName);
  // Передан путь — сравниваем только имя файла.
  if LName.Contains('\') or LName.Contains('/') then
    LName := ExtractFileName(StringReplace(LName, '/', '\', [rfReplaceAll]));
  for LItem in PROTECTED_PROCESS_NAMES do
    if SameText(LItem, LName) then
      Exit(True);
  Result := False;
end;

class function TMHSafeActions.ValidatePlainFilePath(const APath: string;
  out ANormalized: string; out AError: string): Boolean;
var
  C: Char;
  LRest: string;
  LParts: TArray<string>;
begin
  ANormalized := '';
  AError := '';
  if Trim(APath) = '' then
  begin
    AError := MHL('Путь к файлу не указан', 'File path is not specified');
    Exit(False);
  end;
  for C in APath do
    if CharInSet(C, ['"', '<', '>', '|', '*', '?', #0..#31]) then
    begin
      AError := MHL('Путь содержит недопустимые символы (кавычки, подстановочные или управляющие символы)',
        'The path contains invalid characters (quotes, wildcards or control characters)');
      Exit(False);
    end;
  if Length(APath) > MAX_PATH_LENGTH then
  begin
    AError := MHL('Путь слишком длинный', 'The path is too long');
    Exit(False);
  end;

  ANormalized := MHNormalizePath(APath);
  if (Length(ANormalized) >= 3) and ANormalized[1].IsLetter and (ANormalized[2] = ':') and
     (ANormalized[3] = '\') and CharInSet(ANormalized[1], ['A'..'Z', 'a'..'z']) then
    LRest := Copy(ANormalized, 4, MaxInt)
  else if (Length(ANormalized) > 2) and (Copy(ANormalized, 1, 2) = '\\') then
  begin
    LRest := Copy(ANormalized, 3, MaxInt);
    // UNC: сервер, общий ресурс и хотя бы одно имя внутри ресурса.
    LParts := LRest.Split(['\']);
    if Length(LParts) < 3 then
    begin
      AError := MHL('Неполный сетевой путь: требуется \\сервер\ресурс\файл',
        'Incomplete network path: \\server\share\file is required');
      Exit(False);
    end;
  end
  else
  begin
    AError := MHL('Ожидается полный путь к файлу (например, C:\Папка\файл.exe)',
      'A full file path is expected (for example, C:\Folder\file.exe)');
    Exit(False);
  end;

  if (LRest = '') or LRest.Contains(':') then
  begin
    // «:» после буквы диска — альтернативный поток NTFS или URI-подобная запись.
    AError := MHL('Путь не является обычным путём к файлу', 'The path is not a plain file path');
    Exit(False);
  end;
  Result := True;
end;

procedure TMHSafeActions.Journal(const AAction, ATarget: string; var AResult: TMHActionResult);
var
  LRecord: TMHActionRecord;
begin
  if FActionLog = nil then
    Exit;
  LRecord.TimestampUtc := FClock.NowUtc;
  LRecord.Action := AAction;
  LRecord.Target := ATarget;
  LRecord.Result := MHActionResultKindToString(AResult.Kind) + ': ' + AResult.Message;
  LRecord.Success := AResult.Succeeded;
  try
    FActionLog.LogAction(LRecord);
  except
    on E: Exception do
    begin
      // Действие уже выполнено (или отклонено); сбой журнала не должен скрыть его итог.
      if AResult.Details <> '' then
        AResult.Details := AResult.Details + sLineBreak;
      AResult.Details := AResult.Details + MHL('Не удалось записать действие в журнал: ',
        'Failed to write the action to the journal: ') + E.Message;
    end;
  end;
end;

function TMHSafeActions.OpenFileLocation(const APath: string): TMHActionResult;
var
  LPath, LError: string;
begin
  if not ValidatePlainFilePath(APath, LPath, LError) then
    Exit(TMHActionResult.Create(arkFailed, LError));
  if not FOps.FileExists(LPath) then
    Exit(TMHActionResult.Create(arkNotFound, MHL('Файл не найден: ', 'File not found: ') + LPath));
  if FOps.ShellOpenSelect(LPath, LError) then
    Result := TMHActionResult.Create(arkDone, MHL('Расположение файла открыто в Проводнике',
      'File location opened in Explorer'))
  else
    Result := TMHActionResult.Create(arkFailed, MHL('Не удалось открыть Проводник',
      'Failed to open Explorer'), LError);
end;

function TMHSafeActions.DoTerminate(const AId: TMHProcessId; const AName: string): TMHActionResult;
var
  LHandle: THandle;
  LError: Cardinal;
  LCreateTime: UInt64;
  LImagePath: string;
  LCritical: Boolean;
begin
  if (AId.Pid = 0) or (AId.Pid = 4) then
    Exit(TMHActionResult.Create(arkProtected,
      MHL('Это системный процесс Windows. MineHunter X не завершает системные процессы.',
        'This is a Windows system process. MineHunter X does not terminate system processes.')));
  if AId.Pid = FOps.CurrentPid then
    Exit(TMHActionResult.Create(arkProtected, MHL('MineHunter X не завершает собственный процесс.',
      'MineHunter X does not terminate its own process.')));
  if IsProtectedProcessName(AName) then
    Exit(TMHActionResult.Create(arkProtected, Format(MHL('«%s» — системный или защитный процесс ' +
      'Windows. Его остановка может нарушить работу системы, поэтому MineHunter X её не ' +
      'выполняет. Если файл находится не в системной папке, проверьте его Microsoft Defender.',
      '"%s" is a Windows system or security process. Stopping it may disrupt the system, ' +
      'so MineHunter X does not do it. If the file is not in a system folder, scan it with ' +
      'Microsoft Defender.'),
      [Trim(AName)])));
  if not AId.HasCreateTime then
    Exit(TMHActionResult.Create(arkIdentityMismatch, MHL('Не удалось подтвердить, что это тот же ' +
      'процесс: неизвестно время его создания. Обновите список процессов и повторите.',
      'Could not confirm that this is the same process: its creation time is unknown. ' +
      'Refresh the process list and try again.')));

  if not FOps.OpenProcessForTerminate(AId.Pid, LHandle, LError) then
  begin
    case LError of
      ERROR_INVALID_PARAMETER_CODE:
        Result := TMHActionResult.Create(arkNotFound, MHL('Процесс уже завершён.',
          'The process has already exited.'));
      ERROR_ACCESS_DENIED_CODE:
        Result := TMHActionResult.Create(arkAccessDenied, MHL('Недостаточно прав для остановки ' +
          'процесса. Если вы уверены в действии, перезапустите MineHunter X от имени ' +
          'администратора (права автоматически не повышаются).',
          'Insufficient rights to stop the process. If you are sure, restart MineHunter X ' +
          'as administrator (rights are not elevated automatically).'));
    else
      Result := TMHActionResult.Create(arkFailed, MHL('Не удалось открыть процесс.',
        'Failed to open the process.'),
        Format(MHL('Код ошибки Windows: %u', 'Windows error code: %u'), [LError]));
    end;
    Exit;
  end;
  try
    // Защита от переиспользования PID: процесс должен быть тем же экземпляром.
    if not FOps.GetCreateTime(LHandle, LCreateTime) then
      Exit(TMHActionResult.Create(arkFailed,
        MHL('Не удалось проверить время создания процесса; остановка не выполнена.',
          'Failed to verify the process creation time; the process was not stopped.')));
    if LCreateTime <> AId.CreateTime then
      Exit(TMHActionResult.Create(arkIdentityMismatch, MHL('PID уже принадлежит другому процессу: ' +
        'исходный процесс завершился, а номер занят новым. Остановка не выполнена.',
        'The PID now belongs to another process: the original process exited and its number ' +
        'was reused. The process was not stopped.')));
    if FOps.WaitExit(LHandle, 0) then
      Exit(TMHActionResult.Create(arkNotFound, MHL('Процесс уже завершён.',
        'The process has already exited.')));
    // Имя из снимка могло быть неполным — проверяем реальный образ процесса.
    if FOps.GetImagePath(LHandle, LImagePath) and IsProtectedProcessName(LImagePath) then
      Exit(TMHActionResult.Create(arkProtected, Format(MHL('Образ процесса — «%s», системный ' +
        'процесс Windows. MineHunter X его не завершает.',
        'The process image is "%s", a Windows system process. MineHunter X does not terminate it.'),
        [ExtractFileName(LImagePath)])));
    if FOps.IsCritical(LHandle, LCritical) and LCritical then
      Exit(TMHActionResult.Create(arkProtected, MHL('Процесс помечен Windows как критический: ' +
        'его остановка приведёт к аварийной перезагрузке. Действие запрещено.',
        'Windows marks this process as critical: stopping it would cause an emergency restart. ' +
        'The action is not allowed.')));

    if not FOps.Terminate(LHandle, TERMINATE_EXIT_CODE, LError) then
    begin
      if LError = ERROR_ACCESS_DENIED_CODE then
        Result := TMHActionResult.Create(arkAccessDenied, MHL('Windows отказала в остановке ' +
          'процесса. Возможно, нужен запуск MineHunter X от имени администратора или процесс ' +
          'защищён системой.',
          'Windows refused to stop the process. MineHunter X may need to run as administrator, ' +
          'or the process is protected by the system.'))
      else
        Result := TMHActionResult.Create(arkFailed, MHL('Не удалось остановить процесс.',
          'Failed to stop the process.'),
          Format(MHL('Код ошибки Windows: %u', 'Windows error code: %u'), [LError]));
      Exit;
    end;
    if FOps.WaitExit(LHandle, TerminateWaitMs) then
      Result := TMHActionResult.Create(arkDone, MHL('Процесс остановлен.', 'The process was stopped.'))
    else
      Result := TMHActionResult.Create(arkFailed, Format(MHL('Команда остановки отправлена, но ' +
        'процесс не завершился за %d с.',
        'The stop command was sent, but the process did not exit within %d s.'),
        [TerminateWaitMs div 1000]));
  finally
    FOps.CloseProcess(LHandle);
  end;
end;

function TMHSafeActions.TerminateProcess(const AId: TMHProcessId;
  const AName: string): TMHActionResult;
begin
  try
    Result := DoTerminate(AId, AName);
  except
    on E: Exception do
      Result := TMHActionResult.Create(arkFailed, MHL('Непредвиденная ошибка при остановке процесса.',
        'Unexpected error while stopping the process.'), E.Message);
  end;
  Journal(ActionTerminate, Format('%s (PID %u)', [Trim(AName), AId.Pid]), Result);
end;

function TMHSafeActions.DoScan(const APath: string; const ACancel: TMHCancelFunc): TMHActionResult;
var
  LPath, LError, LExe, LOutput, LThreatText: string;
  LExitCode: Cardinal;
  LThreats: TArray<string>;
begin
  if not ValidatePlainFilePath(APath, LPath, LError) then
    Exit(TMHActionResult.Create(arkFailed, LError));
  if not FOps.FileExists(LPath) then
    Exit(TMHActionResult.Create(arkNotFound, MHL('Файл не найден: ', 'File not found: ') + LPath));
  LExe := FOps.FindDefenderCli;
  if LExe = '' then
    Exit(TMHActionResult.Create(arkUnavailable, MHL('Microsoft Defender недоступен',
      'Microsoft Defender is unavailable')));
  if Assigned(ACancel) and ACancel() then
    Exit(TMHActionResult.Create(arkCancelled, MHL('Проверка отменена', 'Scan cancelled')));

  // -DisableRemediation: только отчёт, Defender не изменяет и не удаляет файл.
  case FOps.RunHidden(LExe, Format('-Scan -ScanType 3 -File "%s" -DisableRemediation', [LPath]),
    DefenderTimeoutMs, ACancel, LExitCode, LOutput) of
    roStartFailed:
      Result := TMHActionResult.Create(arkFailed, MHL('Не удалось запустить Microsoft Defender',
        'Failed to start Microsoft Defender'), LOutput);
    roTimeout:
      Result := TMHActionResult.Create(arkFailed, Format(MHL('Проверка Microsoft Defender не ' +
        'завершилась за %d мин и была прервана',
        'The Microsoft Defender scan did not finish within %d min and was aborted'),
        [DefenderTimeoutMs div 60000]), OutputTail(LOutput));
    roCancelled:
      Result := TMHActionResult.Create(arkCancelled, MHL('Проверка отменена', 'Scan cancelled'));
  else
    case LExitCode of
      0:
        Result := TMHActionResult.Create(arkDone, MHL('Угроз не обнаружено', 'No threats detected'),
          OutputTail(LOutput));
      2:
        begin
          LThreats := MHParseDefenderThreats(LOutput);
          if Length(LThreats) > 0 then
            LThreatText := string.Join('; ', LThreats)
          else
            LThreatText := MHL('название угрозы определить не удалось',
              'the threat name could not be determined');
          Result := TMHActionResult.Create(arkDone, MHL('Microsoft Defender обнаружил угрозу',
            'Microsoft Defender detected a threat'),
            MHL('Defender обнаружил угрозу: ', 'Defender detected a threat: ') + LThreatText);
        end;
      DEFENDER_SERVICE_NOT_RUNNING:
        Result := TMHActionResult.Create(arkUnavailable, MHL('Microsoft Defender недоступен: ' +
          'служба не запущена (возможно, используется другой антивирус)',
          'Microsoft Defender is unavailable: the service is not running (another antivirus ' +
          'may be in use)'), OutputTail(LOutput));
    else
      Result := TMHActionResult.Create(arkFailed, Format(MHL('Microsoft Defender завершился с ' +
        'кодом %u (0x%.8x)', 'Microsoft Defender exited with code %u (0x%.8x)'),
        [LExitCode, LExitCode]), OutputTail(LOutput));
    end;
  end;
end;

function TMHSafeActions.ScanWithDefender(const APath: string;
  const ACancel: TMHCancelFunc): TMHActionResult;
begin
  try
    Result := DoScan(APath, ACancel);
  except
    on E: Exception do
      Result := TMHActionResult.Create(arkFailed, MHL('Непредвиденная ошибка проверки Microsoft Defender',
        'Unexpected error during the Microsoft Defender scan'), E.Message);
  end;
  Journal(ActionDefenderScan, Trim(APath), Result);
end;

end.
