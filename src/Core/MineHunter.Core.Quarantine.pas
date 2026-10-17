unit MineHunter.Core.Quarantine;

{
  MineHunter X — карантин и откат (MH-10).

  Ничего не удаляется безвозвратно: перед каждым изменением сохраняется
  резервная копия, у каждого действия есть «Восстановить».
    - файл переносится в хранилище карантина под именем <SHA-256>.quarantine
      (его нельзя запустить двойным щелчком); исходный путь, атрибуты, размер
      и хеш записываются в манифест;
    - значение реестра удаляется после сохранения типа и данных (только в
      разделах, где живут автозапуск и признаки вмешательства);
    - у службы запоминается тип запуска и ставится «отключена»;
    - задание планировщика отключается.
  Системные файлы Windows, собственный файл программы и критические службы
  не трогаются никогда. Права не повышаются: при отказе в доступе — подсказка
  запустить программу от имени администратора.

  MHBuildRemediationPlan по находке и снимку составляет «план исправления»:
  что будет сделано (показывается пользователю до подтверждения). Подписки WMI
  и hosts — только инструкции: их безопасный откат требует ручной проверки.

  Обращения к ОС вынесены в IMHQuarantineOps (реализация — Quarantine.WinApi),
  логика проверяется unit-тестами на поддельной файловой системе и реестре.
  Каждое действие (с любым исходом) записывается в журнал IMHActionLog.
  Класс не потокобезопасен: вызывается из главного потока.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Actions;

type
  TMHQuarantineKind = (qkFile, qkRegistryValue, qkService, qkTask);

  /// Запись карантина (манифест).
  TMHQuarantineItem = record
  public
    Id: string;
    Kind: TMHQuarantineKind;
    CreatedUtc: TDateTime;
    /// Что исправлялось (заголовок находки).
    Reason: string;
    /// Файл: исходный путь; реестр: раздел «HKLM\…»; служба: имя; задание: путь.
    Target: string;
    /// Реестр: имя значения.
    ValueName: string;
    /// Файл: SHA-256 и размер; реестр: тип значения.
    Sha256: string;
    SizeBytes: Int64;
    ValueType: Cardinal;
    /// Реестр: данные значения (hex); служба: прежний тип запуска.
    Data: string;
    /// Файл: исходные атрибуты.
    Attributes: Cardinal;
    /// Путь к файлу в хранилище карантина.
    StoredPath: string;
    function Description: string;
  end;

  TMHRegOpResult = (rorOk, rorNotFound, rorAccessDenied, rorFailed);

  /// Обращения к ОС для карантина. Пути реестра — «HKLM\…» или «HKCU\…»
  /// (64-битное представление).
  IMHQuarantineOps = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CC0}']
    function WindowsDir: string;
    function SelfPath: string;
    function FileExists(const APath: string): Boolean;
    function GetAttributes(const APath: string; out AAttributes: Cardinal): Boolean;
    function SetAttributes(const APath: string; AAttributes: Cardinal): Boolean;
    /// Перемещение (между дисками — копирование и удаление). AAccessDenied — отказ в доступе.
    function MoveFile(const ASource, ADest: string; out AError: string; out AAccessDenied: Boolean): Boolean;
    function DeleteFile(const APath: string; out AError: string): Boolean;
    function ForceDirectories(const APath: string): Boolean;
    function RemoveDirectory(const APath: string): Boolean;
    function ListDirectories(const APath: string): TArray<string>;
    function FileSha256(const APath: string; out ASha256: string; out ASize: Int64): Boolean;
    function ReadTextFile(const APath: string; out AText: string): Boolean;
    function WriteTextFile(const APath, AText: string): Boolean;
    function RegReadValue(const AKey, AName: string; out AType: Cardinal; out AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegWriteValue(const AKey, AName: string; AType: Cardinal; const AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegDeleteValue(const AKey, AName: string; out AError: string): TMHRegOpResult;
    function ServiceGetStartType(const AName: string; out AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function ServiceSetStartType(const AName: string; AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function TaskSetEnabled(const APath: string; AEnabled: Boolean; out AError: string): TMHRegOpResult;
  end;

  TMHRemediationKind = (rmStopProcess, rmQuarantineFile, rmRegistryValue, rmService, rmTask, rmManual);

  /// Шаг плана исправления.
  TMHRemediationStep = record
  public
    Kind: TMHRemediationKind;
    /// Понятное описание шага для пользователя.
    Description: string;
    Process: TMHProcessId;
    ProcessName: string;
    /// Путь файла, раздел реестра, имя службы, путь задания.
    Target: string;
    ValueName: string;
  end;

  TMHQuarantine = class
  public const
    ActionQuarantine = 'quarantine';
    ActionRestore = 'restore';
    ActionPurge = 'purge-quarantine';
    ActionDisable = 'disable';
    SERVICE_DISABLED = 4;
  private
    FOps: IMHQuarantineOps;
    FActionLog: IMHActionLog;
    FClock: IMHClock;
    FStoreDir: string;
    function NewId: string;
    function ItemDir(const AId: string): string;
    function SaveManifest(const AItem: TMHQuarantineItem): Boolean;
    procedure DropManifest(const AId: string);
    procedure Journal(const AAction, ATarget: string; const AResult: TMHActionResult);
    function Finish(const AAction, ATarget: string; const AResult: TMHActionResult): TMHActionResult;
    function IsInsideWindows(const APath: string): Boolean;
    function RestoreFile(const AItem: TMHQuarantineItem): TMHActionResult;
    function RestoreRegistry(const AItem: TMHQuarantineItem): TMHActionResult;
    function RestoreService(const AItem: TMHQuarantineItem): TMHActionResult;
    function RestoreTask(const AItem: TMHQuarantineItem): TMHActionResult;
  public
    /// AStoreDir — каталог хранилища (создаётся при первом использовании).
    constructor Create(const AOps: IMHQuarantineOps; const AActionLog: IMHActionLog;
      const AClock: IMHClock; const AStoreDir: string);
    /// Переносит файл в карантин. Отказывает для файлов Windows, собственного
    /// файла MineHunter и путей с аргументами/кавычками. Занятый файл —
    /// подсказка сначала остановить процесс.
    function QuarantineFile(const APath, AReason: string): TMHActionResult;
    /// Удаляет значение реестра, сохранив его тип и данные. Только разделы
    /// автозапуска и признаков вмешательства (MHIsRemediableRegistryKey).
    function DisableRegistryValue(const AKey, AValueName, AReason: string): TMHActionResult;
    /// Ставит службе тип запуска «отключена» (критические службы Windows — отказ).
    function DisableService(const AName, AReason: string): TMHActionResult;
    /// Отключает задание планировщика.
    function DisableTask(const APath, AReason: string): TMHActionResult;
    /// Возвращает объект на место и удаляет запись карантина. Если на прежнем
    /// месте уже есть файл или значение — отказ (ничего не перезаписывается).
    function Restore(const AId: string): TMHActionResult;
    /// Окончательно удаляет запись карантина (файл — безвозвратно).
    function Purge(const AId: string): TMHActionResult;
    /// Записи карантина, новые первыми; повреждённые манифесты пропускаются.
    function Items: TArray<TMHQuarantineItem>;
    /// Папка Windows по данным операций (для MHBuildRemediationPlan).
    function WindowsDir: string;
    property StoreDir: string read FStoreDir;
  end;

/// Раздел реестра, в котором MineHunter может удалять значения с откатом:
/// Run/RunOnce, Image File Execution Options, SilentProcessExit, исключения и
/// политики Microsoft Defender, политики System и Windows\System.
function MHIsRemediableRegistryKey(const AKey: string): Boolean;

/// План исправления находки по данным снимка. AWindowsDir — каталог Windows:
/// системные файлы в карантин не попадают никогда.
function MHBuildRemediationPlan(const ASnapshot: TMHSnapshot; const AFinding: TMHFinding;
  const AWindowsDir: string): TArray<TMHRemediationStep>;

function MHQuarantineKindToString(AKind: TMHQuarantineKind): string;

implementation

uses
  System.JSON, System.DateUtils, System.StrUtils, System.Math, System.Generics.Collections,
  System.Generics.Defaults,
  MineHunter.Core.Paths;

const
  MANIFEST_NAME = 'manifest.json';
  KIND_NAMES: array[TMHQuarantineKind] of string = ('file', 'registry', 'service', 'task');
  /// Службы, которые нельзя отключать даже по находке (без них Windows не работает
  /// или остаётся без защиты).
  CRITICAL_SERVICES: array[0..17] of string = ('rpcss', 'dcomlaunch', 'lsm', 'samss', 'eventlog',
    'plugplay', 'power', 'profsvc', 'winmgmt', 'windefend', 'wscsvc', 'securityhealthservice',
    'mpssvc', 'bfe', 'cryptsvc', 'schedule', 'gpsvc', 'termservice');
  REMEDIABLE_KEYS: array[0..10] of string = (
    '\software\microsoft\windows\currentversion\run\',
    '\software\microsoft\windows\currentversion\runonce\',
    '\software\wow6432node\microsoft\windows\currentversion\run\',
    '\software\wow6432node\microsoft\windows\currentversion\runonce\',
    '\software\microsoft\windows\currentversion\policies\explorer\run\',
    '\software\microsoft\windows nt\currentversion\image file execution options\',
    '\software\microsoft\windows nt\currentversion\silentprocessexit\',
    '\software\microsoft\windows defender\exclusions\',
    '\software\policies\microsoft\windows defender\',
    '\software\microsoft\windows\currentversion\policies\system\',
    '\software\policies\microsoft\windows\system\');

function MHQuarantineKindToString(AKind: TMHQuarantineKind): string;
begin
  case AKind of
    qkFile: Result := 'файл';
    qkRegistryValue: Result := 'значение реестра';
    qkService: Result := 'служба';
  else
    Result := 'задание планировщика';
  end;
end;

function MHIsRemediableRegistryKey(const AKey: string): Boolean;
var
  LKey, LPrefix: string;
begin
  Result := False;
  LKey := AKey.Trim.ToLower;
  if not (LKey.StartsWith('hklm\') or LKey.StartsWith('hkcu\')) then
    Exit;
  // «hklm\software\…» -> «\software\…\» для сравнения с префиксами.
  LKey := Copy(LKey, 5, MaxInt);
  if not LKey.EndsWith('\') then
    LKey := LKey + '\';
  for LPrefix in REMEDIABLE_KEYS do
    if LKey.StartsWith(LPrefix) then
      Exit(True);
end;

function BytesToHex(const ABytes: TBytes): string;
var
  B: Byte;
begin
  Result := '';
  for B in ABytes do
    Result := Result + IntToHex(B, 2);
end;

function HexToBytes(const AText: string; out ABytes: TBytes): Boolean;
var
  I, LValue: Integer;
begin
  ABytes := nil;
  if Odd(Length(AText)) then
    Exit(False);
  SetLength(ABytes, Length(AText) div 2);
  for I := 0 to High(ABytes) do
  begin
    if not TryStrToInt('$' + Copy(AText, I * 2 + 1, 2), LValue) then
      Exit(False);
    ABytes[I] := Byte(LValue);
  end;
  Result := True;
end;

{ TMHQuarantineItem }

function TMHQuarantineItem.Description: string;
begin
  case Kind of
    qkFile: Result := 'Файл ' + Target;
    qkRegistryValue: Result := Format('Значение «%s» в %s', [ValueName, Target]);
    qkService: Result := 'Служба ' + Target + ' (тип запуска сохранён)';
  else
    Result := 'Задание планировщика ' + Target;
  end;
end;

function ItemToJson(const AItem: TMHQuarantineItem): string;
var
  LObj: TJSONObject;
begin
  LObj := TJSONObject.Create;
  try
    LObj.AddPair('version', TJSONNumber.Create(1));
    LObj.AddPair('id', AItem.Id);
    LObj.AddPair('kind', KIND_NAMES[AItem.Kind]);
    LObj.AddPair('createdUtc', DateToISO8601(AItem.CreatedUtc, True));
    LObj.AddPair('reason', AItem.Reason);
    LObj.AddPair('target', AItem.Target);
    LObj.AddPair('valueName', AItem.ValueName);
    LObj.AddPair('sha256', AItem.Sha256);
    LObj.AddPair('sizeBytes', TJSONNumber.Create(AItem.SizeBytes));
    LObj.AddPair('valueType', TJSONNumber.Create(AItem.ValueType));
    LObj.AddPair('data', AItem.Data);
    LObj.AddPair('attributes', TJSONNumber.Create(AItem.Attributes));
    LObj.AddPair('storedPath', AItem.StoredPath);
    Result := LObj.Format(2);
  finally
    LObj.Free;
  end;
end;

function ItemFromJson(const AText: string; out AItem: TMHQuarantineItem): Boolean;
var
  LValue: TJSONValue;
  LObj: TJSONObject;
  LKind: string;
  K: TMHQuarantineKind;
  LFound: Boolean;
begin
  Result := False;
  AItem := Default(TMHQuarantineItem);
  LValue := nil;
  try
    LValue := TJSONObject.ParseJSONValue(AText);
    if not (LValue is TJSONObject) then
      Exit;
    LObj := TJSONObject(LValue);
    LKind := LObj.GetValue<string>('kind', '');
    LFound := False;
    for K := Low(TMHQuarantineKind) to High(TMHQuarantineKind) do
      if KIND_NAMES[K] = LKind then
      begin
        AItem.Kind := K;
        LFound := True;
      end;
    if not LFound then
      Exit;
    AItem.Id := LObj.GetValue<string>('id', '');
    AItem.CreatedUtc := ISO8601ToDate(LObj.GetValue<string>('createdUtc', ''), True);
    AItem.Reason := LObj.GetValue<string>('reason', '');
    AItem.Target := LObj.GetValue<string>('target', '');
    AItem.ValueName := LObj.GetValue<string>('valueName', '');
    AItem.Sha256 := LObj.GetValue<string>('sha256', '');
    AItem.SizeBytes := LObj.GetValue<Int64>('sizeBytes', 0);
    AItem.ValueType := LObj.GetValue<Cardinal>('valueType', 0);
    AItem.Data := LObj.GetValue<string>('data', '');
    AItem.Attributes := LObj.GetValue<Cardinal>('attributes', 0);
    AItem.StoredPath := LObj.GetValue<string>('storedPath', '');
    Result := (AItem.Id <> '') and (AItem.Target <> '');
  except
    // Повреждённый манифест пропускается.
    Result := False;
  end;
  LValue.Free;
end;

{ TMHQuarantine }

constructor TMHQuarantine.Create(const AOps: IMHQuarantineOps; const AActionLog: IMHActionLog;
  const AClock: IMHClock; const AStoreDir: string);
begin
  inherited Create;
  if AOps = nil then
    raise EArgumentNilException.Create('AOps');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if AStoreDir = '' then
    raise EArgumentException.Create('AStoreDir');
  FOps := AOps;
  FActionLog := AActionLog;
  FClock := AClock;
  FStoreDir := ExcludeTrailingPathDelimiter(AStoreDir);
end;

function TMHQuarantine.NewId: string;
begin
  // Время + случайная часть: сортируется по времени и не повторяется.
  Result := FormatDateTime('yyyymmdd-hhnnss', FClock.NowUtc) + '-' +
    Copy(TGUID.NewGuid.ToString.Replace('{', '').Replace('-', ''), 1, 8).ToLower;
end;

function TMHQuarantine.ItemDir(const AId: string): string;
begin
  Result := FStoreDir + '\' + AId;
end;

function TMHQuarantine.SaveManifest(const AItem: TMHQuarantineItem): Boolean;
begin
  Result := FOps.ForceDirectories(ItemDir(AItem.Id)) and
    FOps.WriteTextFile(ItemDir(AItem.Id) + '\' + MANIFEST_NAME, ItemToJson(AItem));
end;

procedure TMHQuarantine.DropManifest(const AId: string);
var
  LError: string;
begin
  FOps.DeleteFile(ItemDir(AId) + '\' + MANIFEST_NAME, LError);
  FOps.RemoveDirectory(ItemDir(AId));
end;

procedure TMHQuarantine.Journal(const AAction, ATarget: string; const AResult: TMHActionResult);
var
  LRecord: TMHActionRecord;
begin
  if FActionLog = nil then
    Exit;
  LRecord.TimestampUtc := FClock.NowUtc;
  LRecord.Action := AAction;
  LRecord.Target := ATarget;
  LRecord.Result := AResult.Message;
  LRecord.Success := AResult.Succeeded;
  try
    FActionLog.LogAction(LRecord);
  except
    // Сбой журнала не отменяет выполненное действие.
  end;
end;

function TMHQuarantine.Finish(const AAction, ATarget: string; const AResult: TMHActionResult): TMHActionResult;
begin
  Result := AResult;
  Journal(AAction, ATarget, Result);
end;

function TMHQuarantine.IsInsideWindows(const APath: string): Boolean;
var
  LWindows: string;
begin
  LWindows := MHNormalizePath(FOps.WindowsDir);
  if LWindows = '' then
    Exit(False);
  LWindows := IncludeTrailingPathDelimiter(LWindows).ToLower;
  Result := MHNormalizePath(APath).ToLower.StartsWith(LWindows);
end;

function TMHQuarantine.QuarantineFile(const APath, AReason: string): TMHActionResult;
var
  LPath, LError: string;
  LItem: TMHQuarantineItem;
  LAccessDenied: Boolean;
begin
  if not TMHSafeActions.ValidatePlainFilePath(APath, LPath, LError) then
    Exit(Finish(ActionQuarantine, APath, TMHActionResult.Create(arkFailed, 'Недопустимый путь: ' + LError)));
  if IsInsideWindows(LPath) then
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkProtected,
      'Файлы Windows не помещаются в карантин: удаление системного файла может нарушить работу компьютера')));
  if SameText(LPath, MHNormalizePath(FOps.SelfPath)) then
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkProtected,
      'Собственный файл MineHunter не помещается в карантин')));
  if not FOps.FileExists(LPath) then
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkNotFound, 'Файл не найден: ' + LPath)));

  LItem := Default(TMHQuarantineItem);
  LItem.Id := NewId;
  LItem.Kind := qkFile;
  LItem.CreatedUtc := FClock.NowUtc;
  LItem.Reason := AReason;
  LItem.Target := LPath;
  if not FOps.FileSha256(LPath, LItem.Sha256, LItem.SizeBytes) then
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkFailed,
      'Не удалось прочитать файл — возможно, он занят. Сначала остановите процесс.')));
  FOps.GetAttributes(LPath, LItem.Attributes);
  LItem.StoredPath := ItemDir(LItem.Id) + '\' + LItem.Sha256 + '.quarantine';
  // Манифест — до переноса: если перенос прервётся, запись всё равно найдётся.
  if not SaveManifest(LItem) then
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkFailed,
      'Не удалось создать запись карантина в ' + FStoreDir)));
  // «Скрытый», «системный» и «только чтение» мешают переносу.
  FOps.SetAttributes(LPath, 0);
  if not FOps.MoveFile(LPath, LItem.StoredPath, LError, LAccessDenied) then
  begin
    FOps.SetAttributes(LPath, LItem.Attributes);
    DropManifest(LItem.Id);
    if LAccessDenied then
      Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к файлу. Остановите процесс и запустите MineHunter от имени администратора.', LError)));
    Exit(Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkFailed,
      'Файл занят или недоступен — сначала остановите процесс', LError)));
  end;
  Result := Finish(ActionQuarantine, LPath, TMHActionResult.Create(arkDone,
    'Файл перемещён в карантин; вернуть его можно в «Настройки → Карантин»', LItem.Id));
end;

function TMHQuarantine.DisableRegistryValue(const AKey, AValueName, AReason: string): TMHActionResult;
var
  LItem: TMHQuarantineItem;
  LData: TBytes;
  LError, LTarget: string;
begin
  LTarget := AKey + '\' + AValueName;
  if not MHIsRemediableRegistryKey(AKey) then
    Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkProtected,
      'Этот раздел реестра MineHunter не изменяет')));
  LItem := Default(TMHQuarantineItem);
  LItem.Id := NewId;
  LItem.Kind := qkRegistryValue;
  LItem.CreatedUtc := FClock.NowUtc;
  LItem.Reason := AReason;
  LItem.Target := AKey;
  LItem.ValueName := AValueName;
  case FOps.RegReadValue(AKey, AValueName, LItem.ValueType, LData, LError) of
    rorNotFound:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkNotFound, 'Значение уже отсутствует')));
    rorAccessDenied:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к разделу реестра — запустите MineHunter от имени администратора', LError)));
    rorFailed:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkFailed,
        'Не удалось прочитать значение', LError)));
  end;
  LItem.Data := BytesToHex(LData);
  if not SaveManifest(LItem) then
    Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkFailed,
      'Не удалось сохранить резервную копию — значение не изменено')));
  if FOps.RegDeleteValue(AKey, AValueName, LError) = rorOk then
    Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkDone,
      'Значение удалено; резервная копия — в «Настройки → Карантин»', LItem.Id))
  else
  begin
    DropManifest(LItem.Id);
    Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkAccessDenied,
      'Не удалось удалить значение — запустите MineHunter от имени администратора', LError));
  end;
end;

function TMHQuarantine.DisableService(const AName, AReason: string): TMHActionResult;
var
  LItem: TMHQuarantineItem;
  LStart: Cardinal;
  LError, LService, LTarget: string;
begin
  LTarget := 'служба ' + AName;
  for LService in CRITICAL_SERVICES do
    if SameText(LService, AName.Trim) then
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkProtected,
        'Эту службу Windows отключать нельзя')));
  case FOps.ServiceGetStartType(AName, LStart, LError) of
    rorNotFound:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkNotFound, 'Служба не найдена')));
    rorAccessDenied:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к службе — запустите MineHunter от имени администратора', LError)));
    rorFailed:
      Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkFailed, 'Ошибка службы', LError)));
  end;
  if LStart = SERVICE_DISABLED then
    Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkDone, 'Служба уже отключена')));
  LItem := Default(TMHQuarantineItem);
  LItem.Id := NewId;
  LItem.Kind := qkService;
  LItem.CreatedUtc := FClock.NowUtc;
  LItem.Reason := AReason;
  LItem.Target := AName;
  LItem.Data := IntToStr(LStart);
  if not SaveManifest(LItem) then
    Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkFailed,
      'Не удалось сохранить резервную копию — служба не изменена')));
  if FOps.ServiceSetStartType(AName, SERVICE_DISABLED, LError) = rorOk then
    Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkDone,
      'Служба отключена (не запустится при следующей загрузке); включить — в «Настройки → Карантин»', LItem.Id))
  else
  begin
    DropManifest(LItem.Id);
    Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkAccessDenied,
      'Не удалось изменить службу — запустите MineHunter от имени администратора', LError));
  end;
end;

function TMHQuarantine.DisableTask(const APath, AReason: string): TMHActionResult;
var
  LItem: TMHQuarantineItem;
  LError, LTarget: string;
begin
  LTarget := 'задание ' + APath;
  LItem := Default(TMHQuarantineItem);
  LItem.Id := NewId;
  LItem.Kind := qkTask;
  LItem.CreatedUtc := FClock.NowUtc;
  LItem.Reason := AReason;
  LItem.Target := APath;
  if not SaveManifest(LItem) then
    Exit(Finish(ActionDisable, LTarget, TMHActionResult.Create(arkFailed,
      'Не удалось сохранить запись — задание не изменено')));
  case FOps.TaskSetEnabled(APath, False, LError) of
    rorOk:
      Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkDone,
        'Задание отключено; включить — в «Настройки → Карантин»', LItem.Id));
    rorNotFound:
      begin
        DropManifest(LItem.Id);
        Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkNotFound, 'Задание не найдено'));
      end;
  else
    begin
      DropManifest(LItem.Id);
      Result := Finish(ActionDisable, LTarget, TMHActionResult.Create(arkAccessDenied,
        'Не удалось отключить задание — запустите MineHunter от имени администратора', LError));
    end;
  end;
end;

function TMHQuarantine.WindowsDir: string;
begin
  Result := FOps.WindowsDir;
end;

function TMHQuarantine.Items: TArray<TMHQuarantineItem>;
var
  LDir, LText: string;
  LItem: TMHQuarantineItem;
  LList: TList<TMHQuarantineItem>;
begin
  LList := TList<TMHQuarantineItem>.Create;
  try
    for LDir in FOps.ListDirectories(FStoreDir) do
      if FOps.ReadTextFile(IncludeTrailingPathDelimiter(LDir) + MANIFEST_NAME, LText) and
         ItemFromJson(LText, LItem) then
        LList.Add(LItem);
    LList.Sort(TComparer<TMHQuarantineItem>.Construct(
      function(const A, B: TMHQuarantineItem): Integer
      begin
        Result := CompareDateTime(B.CreatedUtc, A.CreatedUtc);
        if Result = 0 then
          Result := CompareStr(B.Id, A.Id);
      end));
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function FindItem(const AItems: TArray<TMHQuarantineItem>; const AId: string;
  out AItem: TMHQuarantineItem): Boolean;
var
  LItem: TMHQuarantineItem;
begin
  for LItem in AItems do
    if LItem.Id = AId then
    begin
      AItem := LItem;
      Exit(True);
    end;
  AItem := Default(TMHQuarantineItem);
  Result := False;
end;

function TMHQuarantine.RestoreFile(const AItem: TMHQuarantineItem): TMHActionResult;
var
  LError, LSha: string;
  LSize: Int64;
  LAccessDenied: Boolean;
begin
  if FOps.FileExists(AItem.Target) then
    Exit(TMHActionResult.Create(arkFailed,
      'На прежнем месте уже есть файл — восстановление отменено, чтобы ничего не перезаписать'));
  if not FOps.FileSha256(AItem.StoredPath, LSha, LSize) or not SameText(LSha, AItem.Sha256) then
    Exit(TMHActionResult.Create(arkFailed, 'Файл в карантине повреждён или изменён — восстановление отменено'));
  FOps.ForceDirectories(ExtractFileDir(AItem.Target));
  if not FOps.MoveFile(AItem.StoredPath, AItem.Target, LError, LAccessDenied) then
  begin
    if LAccessDenied then
      Exit(TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к папке — запустите MineHunter от имени администратора', LError));
    Exit(TMHActionResult.Create(arkFailed, 'Не удалось вернуть файл', LError));
  end;
  FOps.SetAttributes(AItem.Target, AItem.Attributes);
  Result := TMHActionResult.Create(arkDone, 'Файл возвращён на место: ' + AItem.Target);
end;

function TMHQuarantine.RestoreRegistry(const AItem: TMHQuarantineItem): TMHActionResult;
var
  LType: Cardinal;
  LData, LExisting: TBytes;
  LError: string;
begin
  if not HexToBytes(AItem.Data, LData) then
    Exit(TMHActionResult.Create(arkFailed, 'Резервная копия значения повреждена'));
  if FOps.RegReadValue(AItem.Target, AItem.ValueName, LType, LExisting, LError) = rorOk then
    Exit(TMHActionResult.Create(arkFailed,
      'Значение уже существует — восстановление отменено, чтобы ничего не перезаписать'));
  case FOps.RegWriteValue(AItem.Target, AItem.ValueName, AItem.ValueType, LData, LError) of
    rorOk:
      Result := TMHActionResult.Create(arkDone, Format('Значение «%s» восстановлено', [AItem.ValueName]));
    rorAccessDenied:
      Result := TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к разделу реестра — запустите MineHunter от имени администратора', LError);
  else
    Result := TMHActionResult.Create(arkFailed, 'Не удалось записать значение', LError);
  end;
end;

function TMHQuarantine.RestoreService(const AItem: TMHQuarantineItem): TMHActionResult;
var
  LStart: Integer;
  LError: string;
begin
  if not TryStrToInt(AItem.Data, LStart) then
    Exit(TMHActionResult.Create(arkFailed, 'Резервная копия службы повреждена'));
  case FOps.ServiceSetStartType(AItem.Target, Cardinal(LStart), LError) of
    rorOk:
      Result := TMHActionResult.Create(arkDone, 'Прежний тип запуска службы восстановлен');
    rorNotFound:
      Result := TMHActionResult.Create(arkNotFound, 'Служба больше не существует');
    rorAccessDenied:
      Result := TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к службе — запустите MineHunter от имени администратора', LError);
  else
    Result := TMHActionResult.Create(arkFailed, 'Не удалось изменить службу', LError);
  end;
end;

function TMHQuarantine.RestoreTask(const AItem: TMHQuarantineItem): TMHActionResult;
var
  LError: string;
begin
  case FOps.TaskSetEnabled(AItem.Target, True, LError) of
    rorOk:
      Result := TMHActionResult.Create(arkDone, 'Задание снова включено');
    rorNotFound:
      Result := TMHActionResult.Create(arkNotFound, 'Задание больше не существует');
    rorAccessDenied:
      Result := TMHActionResult.Create(arkAccessDenied,
        'Нет доступа к заданию — запустите MineHunter от имени администратора', LError);
  else
    Result := TMHActionResult.Create(arkFailed, 'Не удалось включить задание', LError);
  end;
end;

function TMHQuarantine.Restore(const AId: string): TMHActionResult;
var
  LItem: TMHQuarantineItem;
begin
  if not FindItem(Items, AId, LItem) then
    Exit(Finish(ActionRestore, AId, TMHActionResult.Create(arkNotFound, 'Запись карантина не найдена')));
  case LItem.Kind of
    qkFile: Result := RestoreFile(LItem);
    qkRegistryValue: Result := RestoreRegistry(LItem);
    qkService: Result := RestoreService(LItem);
  else
    Result := RestoreTask(LItem);
  end;
  // Запись удаляется только после успешного восстановления.
  if Result.Succeeded then
    DropManifest(LItem.Id);
  Result := Finish(ActionRestore, LItem.Description, Result);
end;

function TMHQuarantine.Purge(const AId: string): TMHActionResult;
var
  LItem: TMHQuarantineItem;
  LError: string;
begin
  if not FindItem(Items, AId, LItem) then
    Exit(Finish(ActionPurge, AId, TMHActionResult.Create(arkNotFound, 'Запись карантина не найдена')));
  if (LItem.Kind = qkFile) and FOps.FileExists(LItem.StoredPath) and
     not FOps.DeleteFile(LItem.StoredPath, LError) then
    Exit(Finish(ActionPurge, LItem.Description, TMHActionResult.Create(arkFailed,
      'Не удалось удалить файл из карантина', LError)));
  DropManifest(LItem.Id);
  if LItem.Kind = qkFile then
    Result := Finish(ActionPurge, LItem.Description, TMHActionResult.Create(arkDone,
      'Файл удалён из карантина навсегда'))
  else
    Result := Finish(ActionPurge, LItem.Description, TMHActionResult.Create(arkDone,
      'Резервная копия удалена — изменение останется навсегда'));
end;

{ План исправления }

function Step(AKind: TMHRemediationKind; const ADescription, ATarget: string;
  const AValueName: string = ''): TMHRemediationStep;
begin
  Result := Default(TMHRemediationStep);
  Result.Kind := AKind;
  Result.Description := ADescription;
  Result.Target := ATarget;
  Result.ValueName := AValueName;
end;

function HasStep(const ASteps: TArray<TMHRemediationStep>; AKind: TMHRemediationKind;
  const ATarget, AValueName: string): Boolean;
var
  LStep: TMHRemediationStep;
begin
  for LStep in ASteps do
    if (LStep.Kind = AKind) and SameText(LStep.Target, ATarget) and SameText(LStep.ValueName, AValueName) then
      Exit(True);
  Result := False;
end;

/// Ключ находки автозапуска — как в анализаторе (autostart:<вид>:<место>:<имя>).
function AutostartKey(const AEntry: TMHAutostartEntry): string;
begin
  Result := Format('autostart:%s:%s:%s', [MHAutostartKindToString(AEntry.Kind), AEntry.Location.ToLower,
    AEntry.Name.ToLower]);
end;

procedure AddAutostartSteps(const AEntry: TMHAutostartEntry; var ASteps: TArray<TMHRemediationStep>);
var
  LPath: string;
begin
  case AEntry.Kind of
    akRegistryRun, akRegistryRunOnce:
      if not HasStep(ASteps, rmRegistryValue, AEntry.Location, AEntry.Name) then
        ASteps := ASteps + [Step(rmRegistryValue, Format('Отключить автозапуск «%s» (%s)',
          [AEntry.Name, AEntry.Location]), AEntry.Location, AEntry.Name)];
    akStartupFolder:
      begin
        LPath := IncludeTrailingPathDelimiter(AEntry.Location) + AEntry.Name;
        if not HasStep(ASteps, rmQuarantineFile, LPath, '') then
          ASteps := ASteps + [Step(rmQuarantineFile, 'Убрать ярлык из папки автозагрузки в карантин: ' + LPath,
            LPath)];
      end;
    akService:
      if not HasStep(ASteps, rmService, AEntry.Name, '') then
        ASteps := ASteps + [Step(rmService, 'Отключить службу ' + AEntry.Name, AEntry.Name)];
    akScheduledTask:
      if not HasStep(ASteps, rmTask, AEntry.Name, '') then
        ASteps := ASteps + [Step(rmTask, 'Отключить задание планировщика ' + AEntry.Name, AEntry.Name)];
  end;
end;

function IsWindowsFile(const APath, AWindowsDir: string): Boolean;
var
  LWindows: string;
begin
  LWindows := MHNormalizePath(AWindowsDir);
  Result := (LWindows <> '') and
    MHNormalizePath(APath).ToLower.StartsWith(IncludeTrailingPathDelimiter(LWindows).ToLower);
end;

procedure AddQuarantine(const APath, AWindowsDir: string; var ASteps: TArray<TMHRemediationStep>);
var
  LPath: string;
begin
  LPath := MHNormalizePath(APath);
  if (LPath = '') or IsWindowsFile(LPath, AWindowsDir) or HasStep(ASteps, rmQuarantineFile, LPath, '') then
    Exit;
  ASteps := ASteps + [Step(rmQuarantineFile, 'Переместить файл в карантин: ' + LPath, LPath)];
end;

function MHBuildRemediationPlan(const ASnapshot: TMHSnapshot; const AFinding: TMHFinding;
  const AWindowsDir: string): TArray<TMHRemediationStep>;
var
  LInfo: TMHProcessInfo;
  LEntry: TMHAutostartEntry;
  LTamper: TMHTamperEntry;
  LStep: TMHRemediationStep;
  LImage, LKey: string;
begin
  Result := nil;
  LImage := MHNormalizePath(AFinding.ImagePath);
  LKey := AFinding.Key.ToLower;

  // 1. Остановить запущенный процесс находки (по личности PID + время создания).
  if not AFinding.Process.IsEmpty and ASnapshot.FindProcess(AFinding.Process, LInfo) then
  begin
    LStep := Step(rmStopProcess, Format('Остановить процесс %s (PID %d)', [LInfo.Name, LInfo.Id.Pid]), '');
    LStep.Process := LInfo.Id;
    LStep.ProcessName := LInfo.Name;
    Result := Result + [LStep];
  end;

  // 2. Признаки вмешательства: значения реестра (откат возможен), WMI и hosts — инструкции.
  if LKey.StartsWith('tamper:') then
  begin
    for LTamper in ASnapshot.Tamper do
      case LTamper.Kind of
        tpDefenderExclusion:
          if LKey.StartsWith('tamper:defender:') and
             (('tamper:defender:files:' + ExtractFileDir(LTamper.ImagePath).ToLower = LKey) or
              ('tamper:defender:item:' + LTamper.Name.ToLower = LKey)) then
          begin
            Result := Result + [Step(rmRegistryValue, 'Удалить исключение Microsoft Defender: ' + LTamper.Name,
              LTamper.Location, LTamper.Name)];
            // Исключённые программы (не папки) — в карантин, если файлы на месте.
            if (ExtractFileExt(LTamper.Name) <> '') and not LTamper.Details.Contains('файла нет') then
              AddQuarantine(LTamper.ImagePath, AWindowsDir, Result);
          end;
        tpIfeoDebugger:
          if LKey = 'tamper:ifeo:' + LTamper.Value.ToLower then
            Result := Result + [Step(rmRegistryValue, 'Снять перехват запуска ' + LTamper.Name,
              LTamper.Location, 'Debugger')];
        tpSilentExitMonitor:
          if LKey = 'tamper:silentexit:' + LTamper.Name.ToLower then
          begin
            Result := Result + [Step(rmRegistryValue, 'Убрать запуск при завершении ' + LTamper.Name,
              LTamper.Location, 'MonitorProcess')];
            AddQuarantine(LTamper.ImagePath, AWindowsDir, Result);
          end;
        tpPolicyRestriction:
          if (LKey = 'tamper:policy:defender') and
             (SameText(LTamper.Name, 'DisableAntiSpyware') or SameText(LTamper.Name, 'DisableAntiVirus') or
              LTamper.Name.StartsWith('Disable', True) and LTamper.Location.ToLower.Contains('windows defender')) or
             (LKey = 'tamper:policy:' + LTamper.Details.ToLower + ':' + LTamper.Name.ToLower) then
            Result := Result + [Step(rmRegistryValue, Format('Удалить политику %s = %s', [LTamper.Name,
              LTamper.Value]), LTamper.Location, LTamper.Name)];
        tpWmiSubscription:
          if LKey = 'tamper:wmi:' + LTamper.Name.ToLower then
          begin
            Result := Result + [Step(rmManual, 'Подписку WMI «' + LTamper.Name + '» удалите вручную в PowerShell ' +
              'от имени администратора (см. рекомендации) — автоматический откат подписок не поддерживается', '')];
            AddQuarantine(LTamper.ImagePath, AWindowsDir, Result);
          end;
        tpHostsRedirect:
          if LKey.StartsWith('tamper:hosts') and (Length(Result) = 0) then
            Result := Result + [Step(rmManual, 'Удалите строки из файла hosts вручную (Блокнот от имени ' +
              'администратора) — MineHunter не изменяет hosts автоматически', '')];
      end;
    Exit;
  end;

  // 3. Автозапуск находки и все записи автозапуска, ведущие к её файлу.
  for LEntry in ASnapshot.Autostart do
    if (AutostartKey(LEntry) = LKey) or ((LImage <> '') and SameText(LEntry.ImagePath, LImage)) then
      AddAutostartSteps(LEntry, Result);

  // 4. Сам файл — в карантин (кроме файлов Windows: powershell.exe и т.п. не трогаются).
  AddQuarantine(LImage, AWindowsDir, Result);
end;

end.
