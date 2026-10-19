unit MineHunter.Core.Launches;

{
  Журнал запусков программ: какие программы, когда и кем запускались и
  сколько работали. Записи приходят из коллектора processevents (ETW или,
  без прав администратора, по опросу списка процессов) и хранятся в истории.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

type
  IMHLaunchHistory = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1D30}']
    /// Запуски за период, новые первыми. AFilter — часть имени, пути или родителя
    /// (без учёта регистра; '' — все).
    function LoadLaunches(AFromUtc, AToUtc: TDateTime; const AFilter: string;
      AMaxCount: Integer): TArray<TMHLaunchRecord>;
  end;

const
  /// Предел длины сохраняемой командной строки (защита истории от огромных строк).
  MH_LAUNCH_COMMAND_LINE_MAX = 2048;

/// Длительность работы в читаемом виде («0,4 с», «5 мин», «2 ч 10 мин»);
/// '' — процесс ещё работает или завершение не наблюдалось.
function MHLaunchDurationText(const ARecord: TMHLaunchRecord): string;
/// Параметры запуска — командная строка без программы (первого слова, возможно в кавычках).
function MHCommandLineArguments(const ACommandLine: string): string;
/// Путь и параметры для показа: «C:\...pp.exe --type=renderer»; без пути — командная строка.
function MHLaunchPathText(const ARecord: TMHLaunchRecord): string;
/// Командная строка, обрезанная до MH_LAUNCH_COMMAND_LINE_MAX.
function MHLimitCommandLine(const ACommandLine: string): string;

implementation

uses
  System.Math, MineHunter.Core.Lang;

function MHCommandLineArguments(const ACommandLine: string): string;
var
  LLine: string;
  LEnd: Integer;
begin
  LLine := TrimLeft(ACommandLine);
  if LLine = '' then
    Exit('');
  if LLine[1] = '"' then
  begin
    LEnd := Pos('"', LLine, 2);
    if LEnd = 0 then
      Exit('');
  end
  else
  begin
    LEnd := Pos(' ', LLine);
    if LEnd = 0 then
      Exit('');
  end;
  Result := Trim(Copy(LLine, LEnd + 1, MaxInt));
end;

function MHLaunchPathText(const ARecord: TMHLaunchRecord): string;
var
  LArguments: string;
begin
  if ARecord.ImagePath = '' then
    Exit(Trim(ARecord.CommandLine));
  Result := ARecord.ImagePath;
  LArguments := MHCommandLineArguments(ARecord.CommandLine);
  if LArguments <> '' then
    Result := Result + ' ' + LArguments;
end;

function MHLimitCommandLine(const ACommandLine: string): string;
begin
  Result := Copy(ACommandLine, 1, MH_LAUNCH_COMMAND_LINE_MAX);
end;

function MHLaunchDurationText(const ARecord: TMHLaunchRecord): string;
var
  LSeconds: Double;
  LMinutes: Int64;
begin
  if (ARecord.ExitUtc = 0) or (ARecord.StartUtc = 0) then
    Exit('');
  LSeconds := Max(0, (ARecord.ExitUtc - ARecord.StartUtc) * SecsPerDay);
  if LSeconds < 60 then
    Result := FormatFloat('0.0', LSeconds) + MHL(' с', ' s')
  else
  begin
    LMinutes := Round(LSeconds / 60);
    if LMinutes < 60 then
      Result := Format(MHL('%d мин', '%d min'), [LMinutes])
    else
      Result := Format(MHL('%d ч %d мин', '%d h %d min'), [LMinutes div 60, LMinutes mod 60]);
  end;
end;

end.
