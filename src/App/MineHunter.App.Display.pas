unit MineHunter.App.Display;

{
  Форматирование моделей для отображения пользователю.
  Отсутствующие метрики всегда показываются как «нет данных», а не как 0.
}

interface

uses
  MineHunter.Core.Types;

const
  MH_NO_DATA = 'нет данных';

function MHFormatBytes(ABytes: Double): string;
function MHFormatMetric(const AMetric: TMHMetric): string;
/// Текстовое состояние источника с символом, чтобы статус не передавался только цветом.
function MHFormatSourceState(AState: TMHSourceState): string;
function MHFormatUtcAsLocal(AUtc: TDateTime): string;
/// Время в формате FILETIME (UTC) -> локальные дата и время; 0 — «нет данных».
function MHFormatFileTimeLocal(AFileTime: UInt64): string;

implementation

uses
  Winapi.Windows, System.SysUtils, System.DateUtils;

function MHFormatBytes(ABytes: Double): string;
const
  KB = 1024.0;
  MB = KB * 1024;
  GB = MB * 1024;
begin
  if ABytes < 0 then
    Result := MH_NO_DATA
  else if ABytes >= GB then
    Result := FormatFloat('0.00', ABytes / GB) + ' ГБ'
  else if ABytes >= MB then
    Result := FormatFloat('0.0', ABytes / MB) + ' МБ'
  else if ABytes >= KB then
    Result := FormatFloat('0.0', ABytes / KB) + ' КБ'
  else
    Result := FormatFloat('0', ABytes) + ' Б';
end;

function MHFormatMetric(const AMetric: TMHMetric): string;
begin
  if not AMetric.HasValue then
    Exit(MH_NO_DATA);
  case AMetric.Kind of
    mkCpuPercent, mkGpuPercent, mkMemoryLoadPercent, mkDiskActivePercent, mkCpuTimePercent,
    mkCpuFrequencyPercent, mkCpuPerformanceLimitPercent, mkGpuComputePercent:
      Result := FormatFloat('0.0', AMetric.Value) + ' %';
    mkWorkingSetBytes, mkPrivateBytes, mkMemoryUsedBytes, mkMemoryTotalBytes, mkGpuMemoryBytes,
    mkPrivateWorkingSetBytes:
      Result := MHFormatBytes(AMetric.Value);
    mkDiskBytesPerSec, mkNetworkBytesPerSec, mkDiskReadBytesPerSec, mkDiskWriteBytesPerSec:
      Result := MHFormatBytes(AMetric.Value) + '/с';
    mkTemperatureCelsius, mkGpuTemperatureCelsius, mkCpuTemperatureCelsius, mkDiskTemperatureCelsius:
      Result := FormatFloat('0', AMetric.Value) + ' °C';
  else
    Result := FormatFloat('0.##', AMetric.Value);
  end;
end;

function MHFormatSourceState(AState: TMHSourceState): string;
const
  Marks: array[TMHSourceState] of string = ('○', '✔', '◐', '—', '✖');
begin
  Result := Marks[AState] + ' ' + MHSourceStateToString(AState);
end;

function MHFormatUtcAsLocal(AUtc: TDateTime): string;
begin
  if AUtc = 0 then
    Exit(MH_NO_DATA);
  Result := FormatDateTime('hh:nn:ss', TTimeZone.Local.ToLocalTime(AUtc));
end;

function MHFormatFileTimeLocal(AFileTime: UInt64): string;
var
  LFt: TFileTime;
  LSt: TSystemTime;
begin
  if AFileTime = 0 then
    Exit(MH_NO_DATA);
  LFt.dwLowDateTime := Cardinal(AFileTime and $FFFFFFFF);
  LFt.dwHighDateTime := Cardinal(AFileTime shr 32);
  if not FileTimeToSystemTime(LFt, LSt) then
    Exit(MH_NO_DATA);
  Result := FormatDateTime('dd.mm.yyyy hh:nn:ss',
    TTimeZone.Local.ToLocalTime(SystemTimeToDateTime(LSt)));
end;

end.
