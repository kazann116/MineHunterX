unit MineHunter.Core.SelfAutostart;

{
  Необязательный автозапуск самого MineHunter X вместе с Windows.
  Используется только ветка текущего пользователя
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run: права администратора не
  нужны, другие учётные записи не затрагиваются. Запись создаётся и удаляется
  только по явному действию пользователя в настройках.
}

interface

uses
  System.SysUtils;

type
  /// Доступ к значениям ветки Run текущего пользователя.
  IMHRunKeyOps = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CD0}']
    /// False — значения нет (или ветку не удалось прочитать).
    function ReadRunValue(const AName: string; out AValue: string): Boolean;
    function WriteRunValue(const AName, AValue: string; out AError: string): Boolean;
    /// True, если значения нет после вызова (в том числе если его не было).
    function DeleteRunValue(const AName: string; out AError: string): Boolean;
  end;

  TMHSelfAutostartState = (
    sasDisabled,  // записи нет
    sasEnabled,   // запись указывает на текущий exe
    sasStale      // запись есть, но указывает на другой файл (программу переместили)
  );

  TMHSelfAutostart = class
  public const
    ValueName = 'MineHunterX';
    MinimizedSwitch = '--minimized';
  private
    FOps: IMHRunKeyOps;
    FExePath: string;
  public
    constructor Create(const AOps: IMHRunKeyOps; const AExePath: string);
    /// Командная строка записи: "<exe>" --minimized.
    function Command: string;
    function State: TMHSelfAutostartState;
    function IsEnabled: Boolean;
    /// Включает (перезаписывая устаревшую запись) или удаляет запись.
    function SetEnabled(AEnabled: Boolean; out AError: string): Boolean;
    property ExePath: string read FExePath;
  end;

/// Путь исполняемого файла из командной строки записи Run ('' — не удалось разобрать).
function MHRunCommandExecutable(const ACommand: string): string;

/// Есть ли среди параметров запуска ключ --minimized (без учёта регистра, также /minimized).
function MHHasMinimizedSwitch(const AParams: TArray<string>): Boolean;

implementation

function MHRunCommandExecutable(const ACommand: string): string;
var
  LText: string;
  LEnd: Integer;
begin
  LText := Trim(ACommand);
  if LText = '' then
    Exit('');
  if LText[1] = '"' then
  begin
    LEnd := Pos('"', LText, 2);
    if LEnd = 0 then
      Exit('');
    Result := Copy(LText, 2, LEnd - 2);
  end
  else
  begin
    LEnd := Pos(' ', LText);
    if LEnd = 0 then
      Result := LText
    else
      Result := Copy(LText, 1, LEnd - 1);
  end;
  Result := Trim(Result);
end;

function MHHasMinimizedSwitch(const AParams: TArray<string>): Boolean;
var
  LParam: string;
begin
  for LParam in AParams do
    if SameText(LParam, TMHSelfAutostart.MinimizedSwitch) or SameText(LParam, '/minimized') then
      Exit(True);
  Result := False;
end;

{ TMHSelfAutostart }

constructor TMHSelfAutostart.Create(const AOps: IMHRunKeyOps; const AExePath: string);
begin
  inherited Create;
  if AOps = nil then
    raise EArgumentNilException.Create('AOps');
  FOps := AOps;
  FExePath := AExePath;
end;

function TMHSelfAutostart.Command: string;
begin
  Result := '"' + FExePath + '" ' + MinimizedSwitch;
end;

function TMHSelfAutostart.State: TMHSelfAutostartState;
var
  LValue: string;
begin
  if not FOps.ReadRunValue(ValueName, LValue) then
    Exit(sasDisabled);
  if SameText(ExpandFileName(MHRunCommandExecutable(LValue)), ExpandFileName(FExePath)) then
    Result := sasEnabled
  else
    Result := sasStale;
end;

function TMHSelfAutostart.IsEnabled: Boolean;
begin
  Result := State = sasEnabled;
end;

function TMHSelfAutostart.SetEnabled(AEnabled: Boolean; out AError: string): Boolean;
begin
  AError := '';
  if AEnabled then
  begin
    if (FExePath = '') or not FExePath.EndsWith('.exe', True) then
    begin
      AError := 'Неизвестен путь программы';
      Exit(False);
    end;
    Result := FOps.WriteRunValue(ValueName, Command, AError);
  end
  else
    Result := FOps.DeleteRunValue(ValueName, AError);
end;

end.
