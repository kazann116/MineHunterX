unit MineHunter.Collectors.Sensors;

{
  Коллектор датчиков температуры: накопители и (необязательно) процессор.

  Источники (реализация — MineHunter.Collectors.Sensors.WinApi):
    - накопители: IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceTemperatureProperty
      (Windows 10+, NVMe и большинство SATA), без прав администратора;
    - процессор: LibreHardwareMonitor или OpenHardwareMonitor, если пользователь
      их запустил (WMI root\LibreHardwareMonitor). Своего драйвера ядра у
      MineHunter нет: точную температуру ядер Windows без драйвера не отдаёт,
      поэтому без этих программ CPU показывается как «нет данных» с пояснением.

  Метрики: mkDiskTemperatureCelsius (самый горячий накопитель),
  mkCpuTemperatureCelsius. Не потокобезопасен.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHTemperatureReading = record
    /// Модель накопителя или имя датчика («CPU Package»).
    Device: string;
    /// 'storage', 'LibreHardwareMonitor', 'OpenHardwareMonitor'.
    Source: string;
    Celsius: Double;
    /// Порог, выше которого производитель не гарантирует нормальную работу.
    HasWarning: Boolean;
    WarningCelsius: Double;
  end;

  IMHSensorApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CA0}']
    /// Температуры накопителей; пустой массив и AReason — данных нет.
    function ReadDiskTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
    /// Температуры процессора из LibreHardwareMonitor/OpenHardwareMonitor.
    function ReadCpuTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
  end;

  TMHSensorCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'sensors';
  private
    FApi: IMHSensorApi;
    FClock: IMHClock;
  public
    constructor Create(const AApi: IMHSensorApi; const AClock: IMHClock);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

/// Температура процессора из набора датчиков: «CPU Package» / «Core (Tctl/Tdie)»,
/// иначе самый горячий датчик. False — подходящих нет.
function MHPickCpuTemperature(const AReadings: TArray<TMHTemperatureReading>;
  out ACelsius: Double): Boolean;

implementation

uses
  System.Math, System.StrUtils,
  MineHunter.Core.Lang;

function IsPlausible(ACelsius: Double): Boolean;
begin
  // Датчики иногда отдают 0, отрицательные значения или «255» при ошибке.
  Result := (ACelsius > 0) and (ACelsius < 150);
end;

function MHPickCpuTemperature(const AReadings: TArray<TMHTemperatureReading>;
  out ACelsius: Double): Boolean;
var
  LReading: TMHTemperatureReading;
  LName: string;
begin
  ACelsius := 0;
  for LReading in AReadings do
  begin
    LName := LReading.Device.ToLower;
    if IsPlausible(LReading.Celsius) and
       (LName.Contains('package') or LName.Contains('tctl') or LName.Contains('tdie')) then
    begin
      ACelsius := LReading.Celsius;
      Exit(True);
    end;
  end;
  Result := False;
  for LReading in AReadings do
    if IsPlausible(LReading.Celsius) then
    begin
      ACelsius := IfThen(Result, Max(ACelsius, LReading.Celsius), LReading.Celsius);
      Result := True;
    end;
end;

{ TMHSensorCollector }

constructor TMHSensorCollector.Create(const AApi: IMHSensorApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
end;

function TMHSensorCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHSensorCollector.GetDisplayName: string;
begin
  Result := MHL('Датчики температуры: накопители, процессор', 'Temperature sensors: drives, CPU');
end;

function TMHSensorCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LDisks, LCpu: TArray<TMHTemperatureReading>;
  LDiskReason, LCpuReason, LNotes: string;
  LReading: TMHTemperatureReading;
  LDiskMax, LCpuValue: Double;
  LHasDisk, LHasCpu: Boolean;
  LState: TMHSourceState;
  LReadings: TArray<TMHSensorReading>;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  LDisks := FApi.ReadDiskTemperatures(LDiskReason);
  LCpu := FApi.ReadCpuTemperatures(LCpuReason);

  LHasDisk := False;
  LDiskMax := 0;
  LReadings := nil;
  for LReading in LDisks do
    if IsPlausible(LReading.Celsius) then
    begin
      LReadings := LReadings + [TMHSensorReading.Create(skDisk, LReading.Device, LReading.Source,
        LReading.Celsius, IfThen(LReading.HasWarning, LReading.WarningCelsius, 0))];
      LDiskMax := IfThen(LHasDisk, Max(LDiskMax, LReading.Celsius), LReading.Celsius);
      LHasDisk := True;
    end;
  LHasCpu := MHPickCpuTemperature(LCpu, LCpuValue);
  if LHasCpu then
    LReadings := LReadings + [TMHSensorReading.Create(skCpu, MHL('Процессор', 'CPU'),
      IfThen(Length(LCpu) > 0, LCpu[0].Source, ''), LCpuValue, 0)];

  LNotes := '';
  if not LHasDisk then
    LNotes := MHL('Температура накопителей: ', 'Drive temperature: ') + IfThen(LDiskReason <> '', LDiskReason, MHL('нет данных', 'no data')) + '.';
  if not LHasCpu then
    LNotes := Trim(LNotes + MHL(' Температура процессора: ', ' CPU temperature: ') +
      IfThen(LCpuReason <> '', LCpuReason, MHL('нет данных', 'no data')) + '.');

  if LHasDisk and LHasCpu then
    LState := ssSuccess
  else if LHasDisk or LHasCpu then
    LState := ssPartial
  else
    LState := ssUnavailable;

  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState, LNotes, LNow));
  Result.Status.ItemCount := Length(LDisks) + Length(LCpu);
  Result.Sensors := LReadings;
  if LHasDisk then
    Result.Metrics := Result.Metrics + [TMHMetric.Available(mkDiskTemperatureCelsius, LDiskMax, LNow)]
  else
    Result.Metrics := Result.Metrics + [TMHMetric.NoData(mkDiskTemperatureCelsius, LNow)];
  if LHasCpu then
    Result.Metrics := Result.Metrics + [TMHMetric.Available(mkCpuTemperatureCelsius, LCpuValue, LNow)]
  else
    Result.Metrics := Result.Metrics + [TMHMetric.NoData(mkCpuTemperatureCelsius, LNow)];
end;

end.
