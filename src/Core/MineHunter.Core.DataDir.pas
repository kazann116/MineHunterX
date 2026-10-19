unit MineHunter.Core.DataDir;

{
  Папка данных MineHunter X: история наблюдений (history.db), настройки
  (settings.json) и карантин (Quarantine).

  По умолчанию — %LOCALAPPDATA%\MineHunterX. Пользователь может выбрать другую
  папку: выбор записывается в файл-указатель datadir.json, который всегда лежит
  в стандартной папке (иначе его не найти при запуске).

  Перенос выполняется при следующем запуске, до открытия базы истории (база в
  режиме WAL — копировать её во время работы нельзя): копируются база с файлами
  журнала, настройки и карантин. Старая папка не удаляется — пользователь
  удаляет её сам, убедившись, что всё на месте. Если в новой папке уже есть
  история, она не перезаписывается: программа просто начинает работать с ней.
  При ошибке копирования программа остаётся на прежней папке.
}

interface

type
  TMHDataDirPointer = record
    /// Выбранная папка ('' — стандартная).
    DataDir: string;
    /// Папка, из которой при следующем запуске нужно перенести данные ('' — переноса нет).
    MoveFrom: string;
  end;

const
  MH_DATA_DIR_POINTER = 'datadir.json';

/// %LOCALAPPDATA%\MineHunterX (если недоступно — папка во временном каталоге).
function MHStandardDataDir: string;
/// Текущая папка данных.
function MHDataDir: string;

/// То же для явно заданной стандартной папки (тесты и встраивание).
function MHResolveDataDir(const AStandardDir: string): string;
function MHReadDataDirPointer(const AStandardDir: string; out APointer: TMHDataDirPointer): Boolean;
function MHWriteDataDirPointer(const AStandardDir: string; const APointer: TMHDataDirPointer;
  out AError: string): Boolean;

/// Запрос переноса данных в ANewDir ('' — вернуть стандартную папку). Проверяет, что
/// папка задана полным путём, доступна для записи и не вложена в текущую (и наоборот).
/// Сам перенос — при следующем запуске (MHApplyPendingDataMove).
function MHRequestDataDirChange(const AStandardDir, ANewDir: string; out AError: string): Boolean;

/// Выполняет отложенный перенос; вызывается при запуске до создания сервисов.
/// AMoved — данные скопированы в новую папку. False — ошибка (AError), программа
/// остаётся на прежней папке.
function MHApplyPendingDataMove(const AStandardDir: string; out AMoved: Boolean; out AError: string): Boolean;

implementation

uses
  Winapi.Windows, Winapi.SHFolder, System.SysUtils, System.IOUtils, System.JSON,
  MineHunter.Core.Paths, MineHunter.Core.Lang;

const
  HISTORY_FILES: array[0..2] of string = ('history.db', 'history.db-wal', 'history.db-shm');
  SETTINGS_FILE = 'settings.json';
  QUARANTINE_DIR = 'Quarantine';

function MHStandardDataDir: string;
var
  LPath: array[0..MAX_PATH] of Char;
begin
  if Succeeded(SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, @LPath[0])) then
    Result := TPath.Combine(string(LPath), 'MineHunterX')
  else
    Result := TPath.Combine(TPath.GetTempPath, 'MineHunterX');
end;

function MHDataDir: string;
begin
  Result := MHResolveDataDir(MHStandardDataDir);
end;

function PointerPath(const AStandardDir: string): string;
begin
  Result := TPath.Combine(AStandardDir, MH_DATA_DIR_POINTER);
end;

function MHReadDataDirPointer(const AStandardDir: string; out APointer: TMHDataDirPointer): Boolean;
var
  LValue: TJSONValue;
begin
  APointer := Default(TMHDataDirPointer);
  if not FileExists(PointerPath(AStandardDir)) then
    Exit(False);
  try
    LValue := TJSONObject.ParseJSONValue(TFile.ReadAllText(PointerPath(AStandardDir), TEncoding.UTF8));
  except
    Exit(False);
  end;
  try
    Result := LValue is TJSONObject;
    if Result then
    begin
      APointer.DataDir := TJSONObject(LValue).GetValue<string>('dataDir', '');
      APointer.MoveFrom := TJSONObject(LValue).GetValue<string>('moveFrom', '');
    end;
  finally
    LValue.Free;
  end;
end;

function MHWriteDataDirPointer(const AStandardDir: string; const APointer: TMHDataDirPointer;
  out AError: string): Boolean;
var
  LObject: TJSONObject;
  LTemp: string;
begin
  AError := '';
  try
    ForceDirectories(AStandardDir);
    if (APointer.DataDir = '') and (APointer.MoveFrom = '') then
    begin
      // Стандартная папка без переноса — указатель не нужен.
      if FileExists(PointerPath(AStandardDir)) then
        TFile.Delete(PointerPath(AStandardDir));
      Exit(True);
    end;
    LObject := TJSONObject.Create;
    try
      LObject.AddPair('dataDir', APointer.DataDir);
      LObject.AddPair('moveFrom', APointer.MoveFrom);
      // Атомарная замена: сбой при записи не оставит половину файла.
      LTemp := PointerPath(AStandardDir) + '.tmp';
      TFile.WriteAllText(LTemp, LObject.ToJSON, TEncoding.UTF8);
    finally
      LObject.Free;
    end;
    if not MoveFileEx(PChar(LTemp), PChar(PointerPath(AStandardDir)),
      MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) then
      RaiseLastOSError;
    Result := True;
  except
    on E: Exception do
    begin
      AError := E.Message;
      Result := False;
    end;
  end;
end;

function DirectoryUsable(const ADir: string): Boolean;
begin
  try
    Result := DirectoryExists(ADir) or ForceDirectories(ADir);
  except
    Result := False;
  end;
end;

function MHResolveDataDir(const AStandardDir: string): string;
var
  LPointer: TMHDataDirPointer;
begin
  Result := AStandardDir;
  // Выбранная папка недоступна (например, отключён диск) — работаем в стандартной.
  if MHReadDataDirPointer(AStandardDir, LPointer) and (LPointer.DataDir <> '') and
     DirectoryUsable(LPointer.DataDir) then
    Result := ExcludeTrailingPathDelimiter(LPointer.DataDir);
end;

function IsInside(const AInner, AOuter: string): Boolean;
var
  LInner, LOuter: string;
begin
  LInner := IncludeTrailingPathDelimiter(MHNormalizePath(AInner));
  LOuter := IncludeTrailingPathDelimiter(MHNormalizePath(AOuter));
  Result := (Length(LInner) > Length(LOuter)) and SameText(Copy(LInner, 1, Length(LOuter)), LOuter);
end;

function IsAbsolute(const APath: string): Boolean;
begin
  Result := ((Length(APath) >= 3) and (APath[2] = ':') and CharInSet(APath[3], ['\', '/'])) or
    APath.StartsWith('\\');
end;

function CheckWritable(const ADir: string; out AError: string): Boolean;
var
  LProbe: string;
begin
  AError := '';
  try
    if not ForceDirectories(ADir) then
      RaiseLastOSError;
    LProbe := TPath.Combine(ADir, '.minehunter-write-test');
    TFile.WriteAllText(LProbe, 'ok');
    TFile.Delete(LProbe);
    Result := True;
  except
    on E: Exception do
    begin
      AError := Format(MHL('В папку «%s» нельзя записывать: %s', 'Cannot write to the folder "%s": %s'),
        [ADir, E.Message]);
      Result := False;
    end;
  end;
end;

function MHRequestDataDirChange(const AStandardDir, ANewDir: string; out AError: string): Boolean;
var
  LCurrent, LTarget: string;
  LPointer: TMHDataDirPointer;
begin
  AError := '';
  LCurrent := MHResolveDataDir(AStandardDir);
  LTarget := ExcludeTrailingPathDelimiter(Trim(ANewDir));
  if LTarget = '' then
    LTarget := AStandardDir
  else if not IsAbsolute(LTarget) then
  begin
    AError := MHL('Укажите полный путь к папке (например, D:\MineHunterX).',
      'Specify the full folder path (for example, D:\MineHunterX).');
    Exit(False);
  end;
  LTarget := MHNormalizePath(LTarget);
  if MHSamePath(LTarget, LCurrent) then
  begin
    AError := MHL('Данные уже хранятся в этой папке.', 'The data is already stored in this folder.');
    Exit(False);
  end;
  if IsInside(LTarget, LCurrent) or IsInside(LCurrent, LTarget) then
  begin
    AError := MHL('Новая папка не может быть внутри текущей и наоборот.',
      'The new folder cannot be inside the current one or vice versa.');
    Exit(False);
  end;
  if not CheckWritable(LTarget, AError) then
    Exit(False);
  LPointer := Default(TMHDataDirPointer);
  if not MHSamePath(LTarget, AStandardDir) then
    LPointer.DataDir := LTarget;
  LPointer.MoveFrom := LCurrent;
  Result := MHWriteDataDirPointer(AStandardDir, LPointer, AError);
end;

procedure CopyTree(const AFrom, ATo: string);
var
  LFile, LDir: string;
begin
  ForceDirectories(ATo);
  for LFile in TDirectory.GetFiles(AFrom) do
    TFile.Copy(LFile, TPath.Combine(ATo, ExtractFileName(LFile)), False);
  for LDir in TDirectory.GetDirectories(AFrom) do
    CopyTree(LDir, TPath.Combine(ATo, ExtractFileName(LDir)));
end;

function MHApplyPendingDataMove(const AStandardDir: string; out AMoved: Boolean; out AError: string): Boolean;
var
  LPointer, LRevert: TMHDataDirPointer;
  LTarget, LName, LRevertError, LCopiedQuarantine: string;
  LCopied: TArray<string>;

  procedure CopyOne(const AName: string);
  begin
    TFile.Copy(TPath.Combine(LPointer.MoveFrom, AName), TPath.Combine(LTarget, AName), False);
    LCopied := LCopied + [TPath.Combine(LTarget, AName)];
  end;

begin
  AMoved := False;
  AError := '';
  LCopied := nil;
  LCopiedQuarantine := '';
  if not MHReadDataDirPointer(AStandardDir, LPointer) or (LPointer.MoveFrom = '') then
    Exit(True);
  LTarget := LPointer.DataDir;
  if LTarget = '' then
    LTarget := AStandardDir;
  try
    if not MHSamePath(LTarget, LPointer.MoveFrom) and DirectoryExists(LPointer.MoveFrom) then
    begin
      ForceDirectories(LTarget);
      // История в новой папке уже есть — не перезаписываем её.
      if not FileExists(TPath.Combine(LTarget, HISTORY_FILES[0])) then
      begin
        for LName in HISTORY_FILES do
          if FileExists(TPath.Combine(LPointer.MoveFrom, LName)) then
            CopyOne(LName);
        if FileExists(TPath.Combine(LPointer.MoveFrom, SETTINGS_FILE)) and
           not FileExists(TPath.Combine(LTarget, SETTINGS_FILE)) then
          CopyOne(SETTINGS_FILE);
        if DirectoryExists(TPath.Combine(LPointer.MoveFrom, QUARANTINE_DIR)) and
           not DirectoryExists(TPath.Combine(LTarget, QUARANTINE_DIR)) then
        begin
          LCopiedQuarantine := TPath.Combine(LTarget, QUARANTINE_DIR);
          CopyTree(TPath.Combine(LPointer.MoveFrom, QUARANTINE_DIR), LCopiedQuarantine);
        end;
        AMoved := True;
      end;
    end;
    LPointer.MoveFrom := '';
    Result := MHWriteDataDirPointer(AStandardDir, LPointer, AError);
  except
    on E: Exception do
    begin
      AError := E.Message;
      // Неполная копия не должна выглядеть как готовая история при следующей попытке:
      // удаляется только то, что скопировал этот перенос.
      for LName in LCopied do
        System.SysUtils.DeleteFile(LName);
      if LCopiedQuarantine <> '' then
        try
          TDirectory.Delete(LCopiedQuarantine, True);
        except
          // Остатки копии карантина не мешают: при повторе папка уже есть и не копируется.
        end;
      // Остаёмся на прежней папке: указатель возвращается к ней, перенос отменяется.
      LRevert := Default(TMHDataDirPointer);
      if not MHSamePath(LPointer.MoveFrom, AStandardDir) then
        LRevert.DataDir := LPointer.MoveFrom;
      MHWriteDataDirPointer(AStandardDir, LRevert, LRevertError);
      AMoved := False;
      Result := False;
    end;
  end;
end;

end.
