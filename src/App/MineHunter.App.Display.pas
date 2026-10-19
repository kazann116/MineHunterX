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
  MineHunter.App.Lang, MineHunter.Core.Lang, Winapi.Windows, System.SysUtils, System.DateUtils,
  MineHunter.Collectors.NetAdapters;

function MHFormatBytes(ABytes: Double): string;
const
  KB = 1024.0;
  MB = KB * 1024;
  GB = MB * 1024;
begin
  if ABytes < 0 then
    Result := MHL(MH_NO_DATA, 'no data')
  else if ABytes >= GB then
    Result := FormatFloat('0.00', ABytes / GB) + MHL(' ГБ', ' GB')
  else if ABytes >= MB then
    Result := FormatFloat('0.0', ABytes / MB) + MHL(' МБ', ' MB')
  else if ABytes >= KB then
    Result := FormatFloat('0.0', ABytes / KB) + MHL(' КБ', ' KB')
  else
    Result := FormatFloat('0', ABytes) + MHL(' Б', ' B');
end;

function MHFormatMetric(const AMetric: TMHMetric): string;
begin
  if not AMetric.HasValue then
    Exit(MHL(MH_NO_DATA, 'no data'));
  case AMetric.Kind of
    mkCpuPercent, mkGpuPercent, mkMemoryLoadPercent, mkDiskActivePercent, mkCpuTimePercent,
    mkCpuFrequencyPercent, mkCpuPerformanceLimitPercent, mkGpuComputePercent:
      Result := FormatFloat('0.0', AMetric.Value) + ' %';
    mkWorkingSetBytes, mkPrivateBytes, mkMemoryUsedBytes, mkMemoryTotalBytes, mkGpuMemoryBytes,
    mkPrivateWorkingSetBytes:
      Result := MHFormatBytes(AMetric.Value);
    mkDiskBytesPerSec, mkDiskReadBytesPerSec, mkDiskWriteBytesPerSec:
      Result := MHFormatBytes(AMetric.Value) + MHL('/с', '/s');
    mkNetworkBytesPerSec:
      Result := MHFormatBitRate(AMetric.Value);
    mkTemperatureCelsius, mkGpuTemperatureCelsius, mkCpuTemperatureCelsius, mkDiskTemperatureCelsius:
      Result := FormatFloat('0', AMetric.Value) + ' °C';
    mkGpuPowerWatts:
      Result := FormatFloat('0', AMetric.Value) + MHL(' Вт', ' W');
  else
    Result := FormatFloat('0.##', AMetric.Value);
  end;
end;

function MHFormatSourceState(AState: TMHSourceState): string;
const
  Marks: array[TMHSourceState] of string = ('○', '✔', '◐', '—', '✖');
begin
  Result := Marks[AState] + ' ' + MHTr(MHSourceStateToString(AState));
end;

function MHFormatUtcAsLocal(AUtc: TDateTime): string;
begin
  if AUtc = 0 then
    Exit(MHL(MH_NO_DATA, 'no data'));
  Result := FormatDateTime('hh:nn:ss', TTimeZone.Local.ToLocalTime(AUtc));
end;

function MHFormatFileTimeLocal(AFileTime: UInt64): string;
var
  LFt: TFileTime;
  LSt: TSystemTime;
begin
  if AFileTime = 0 then
    Exit(MHL(MH_NO_DATA, 'no data'));
  LFt.dwLowDateTime := Cardinal(AFileTime and $FFFFFFFF);
  LFt.dwHighDateTime := Cardinal(AFileTime shr 32);
  if not FileTimeToSystemTime(LFt, LSt) then
    Exit(MHL(MH_NO_DATA, 'no data'));
  Result := FormatDateTime('dd.mm.yyyy hh:nn:ss',
    TTimeZone.Local.ToLocalTime(SystemTimeToDateTime(LSt)));
end;

end.
