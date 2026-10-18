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

/// Длительность работы в читаемом виде («0,4 с», «5 мин», «2 ч 10 мин»);
/// '' — процесс ещё работает или завершение не наблюдалось.
function MHLaunchDurationText(const ARecord: TMHLaunchRecord): string;

implementation

uses
  System.Math, MineHunter.Core.Lang;

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
