unit MineHunter.Core.Calc;

{
  Чистые функции расчёта метрик. Не обращаются к ОС и полностью покрываются
  unit-тестами.
}

interface

/// Загрузка CPU процессом в процентах от всей машины (0..100).
/// ACpuDelta100ns — прирост времени ядра+пользователя процесса между замерами;
/// AWallDelta100ns — прошедшее реальное время; ALogicalCpuCount — число логических CPU.
/// Возвращает False, если расчёт невозможен (нет интервала, некорректные данные).
function MHTryCalcCpuPercent(ACpuDelta100ns, AWallDelta100ns: UInt64;
  ALogicalCpuCount: Integer; out APercent: Double): Boolean;

/// Безопасная разность счётчиков: если текущее значение меньше предыдущего
/// (счётчик сброшен, PID переиспользован), возвращает False.
function MHTryCounterDelta(APrevious, ACurrent: UInt64; out ADelta: UInt64): Boolean;

/// Загрузка CPU всей системы (0..100) по дельтам GetSystemTimes.
/// В Windows время ядра (AKernelDelta) включает время простоя (AIdleDelta),
/// поэтому занятость = (kernel + user - idle) / (kernel + user).
function MHTryCalcSystemCpuPercent(AIdleDelta, AKernelDelta, AUserDelta: UInt64;
  out APercent: Double): Boolean;

/// Скорость по дельте счётчика байт за интервал в 100-нс единицах (байт/с).
function MHTryCalcRate(AValueDelta, AWallDelta100ns: UInt64; out ARate: Double): Boolean;

/// Объединяет старшую и младшую части FILETIME.
function MHFileTimeToUInt64(ALow, AHigh: Cardinal): UInt64;

implementation

function MHTryCalcCpuPercent(ACpuDelta100ns, AWallDelta100ns: UInt64;
  ALogicalCpuCount: Integer; out APercent: Double): Boolean;
begin
  APercent := 0;
  if (AWallDelta100ns = 0) or (ALogicalCpuCount <= 0) then
    Exit(False);
  APercent := (ACpuDelta100ns / AWallDelta100ns) * 100.0 / ALogicalCpuCount;
  // Из-за разной гранулярности таймеров результат может слегка превысить 100%.
  if APercent > 100.0 then
    APercent := 100.0;
  Result := True;
end;

function MHTryCounterDelta(APrevious, ACurrent: UInt64; out ADelta: UInt64): Boolean;
begin
  if ACurrent < APrevious then
  begin
    ADelta := 0;
    Exit(False);
  end;
  ADelta := ACurrent - APrevious;
  Result := True;
end;

function MHTryCalcSystemCpuPercent(AIdleDelta, AKernelDelta, AUserDelta: UInt64;
  out APercent: Double): Boolean;
var
  LTotal: UInt64;
begin
  APercent := 0;
  LTotal := AKernelDelta + AUserDelta;
  // Простой не может превышать общее время; иначе счётчики несогласованы.
  if (LTotal = 0) or (AIdleDelta > LTotal) then
    Exit(False);
  APercent := (LTotal - AIdleDelta) / LTotal * 100.0;
  Result := True;
end;

function MHTryCalcRate(AValueDelta, AWallDelta100ns: UInt64; out ARate: Double): Boolean;
begin
  ARate := 0;
  if AWallDelta100ns = 0 then
    Exit(False);
  ARate := AValueDelta / (AWallDelta100ns / 10000000.0);
  Result := True;
end;

function MHFileTimeToUInt64(ALow, AHigh: Cardinal): UInt64;
begin
  Result := (UInt64(AHigh) shl 32) or ALow;
end;

end.
