unit MineHunter.Collectors.Gpu;

{
  Коллектор GPU: загрузка видеокарты по процессам и в целом, вычислительные
  движки (Compute, CUDA), видеопамять, температура.

  Источники (реализация — MineHunter.Collectors.Gpu.WinApi):
    - счётчики Windows «GPU Engine», «GPU Process Memory», «GPU Adapter Memory»
      (WDDM 2.0+, Windows 10 1709+) — то же, что показывает диспетчер задач;
    - температура: сначала D3DKMT (данные драйвера о производительности
      адаптера, WDDM 2.4+), затем NVML (драйвер NVIDIA), если D3DKMT её не дал.

  Расчёт как в диспетчере задач: загрузка процесса — его самый загруженный
  движок; загрузка GPU — самый загруженный движок адаптера (сумма по
  процессам). Вычисления — то же по движкам Compute_* и CUDA: майнеры
  нагружают именно их.

  Сведения о процессах передаются через TMHCollectionResult.ProcessDetails
  (сканер переносит их в процессы снимка), поэтому коллектор должен стоять
  после коллектора processes. Не потокобезопасен.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Значение экземпляра счётчика.
  TMHGpuCounterSample = record
    InstanceName: string;
    Value: Double;
  end;

  TMHGpuCounters = record
    /// False — счётчики недоступны или это первый замер (Reason — почему).
    Available: Boolean;
    Reason: string;
    /// Счётчики есть, но это первый замер (загрузка появится со следующего).
    Pending: Boolean;
    /// «GPU Engine(*)\Utilization Percentage».
    Engines: TArray<TMHGpuCounterSample>;
    /// «GPU Process Memory(*)\Dedicated Usage», байт.
    ProcessMemory: TArray<TMHGpuCounterSample>;
    /// «GPU Adapter Memory(*)\Dedicated Usage», байт.
    AdapterMemory: TArray<TMHGpuCounterSample>;
  end;

  /// Датчик видеокарты.
  TMHGpuSensor = record
    AdapterName: string;
    /// 'D3DKMT' или 'NVML'.
    Source: string;
    HasTemperature: Boolean;
    TemperatureCelsius: Double;
    /// Температура, с которой начинается снижение частоты (если известна).
    HasSlowdown: Boolean;
    SlowdownCelsius: Double;
    /// Текущая потребляемая мощность (NVML), Вт.
    HasPower: Boolean;
    PowerWatts: Double;
  end;

  IMHGpuApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C90}']
    /// Один замер счётчиков; загрузка доступна со второго вызова.
    function GetCounters: TMHGpuCounters;
    /// Датчики; реализация может обновлять их реже, чем каждый опрос.
    function GetSensors(out AReason: string): TArray<TMHGpuSensor>;
  end;

  /// Разобранное имя экземпляра «pid_972_luid_0x0_0x102c2_phys_0_eng_3_engtype_Compute_0».
  TMHGpuEngineInstance = record
    Pid: Cardinal;
    /// «luid_…_phys_N» — физический адаптер.
    Adapter: string;
    /// Адаптер + номер движка.
    Engine: string;
    /// Тип движка в нижнем регистре: 3d, compute_0, cuda, copy, videodecode…
    EngineType: string;
  end;

  TMHGpuCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'gpu';
  private
    FApi: IMHGpuApi;
    FClock: IMHClock;
  public
    constructor Create(const AApi: IMHGpuApi; const AClock: IMHClock);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

function MHParseGpuEngineInstance(const AName: string; out AInstance: TMHGpuEngineInstance): Boolean;
/// «pid_18164_luid_0x0_0x102c2_phys_0» -> PID и адаптер.
function MHParseGpuProcessMemoryInstance(const AName: string; out APid: Cardinal;
  out AAdapter: string): Boolean;
/// Движки, которые используют вычисления общего назначения (майнинг, CUDA, OpenCL).
function MHIsComputeEngineType(const AEngineType: string): Boolean;

implementation

uses
  System.Math,
  MineHunter.Core.Lang;

const
  ENGTYPE_MARK = '_engtype_';
  ENG_MARK = '_eng_';

function MHIsComputeEngineType(const AEngineType: string): Boolean;
var
  LType: string;
begin
  LType := AEngineType.ToLower;
  Result := LType.StartsWith('compute') or (LType = 'cuda');
end;

/// «pid_<число>_<остаток>»: PID и остаток имени.
function SplitPid(const AName: string; out APid: Cardinal; out ARest: string): Boolean;
var
  LName: string;
  LSep: Integer;
  LPid: Int64;
begin
  Result := False;
  LName := AName.ToLower;
  if not LName.StartsWith('pid_') then
    Exit;
  LSep := LName.IndexOf('_', 4);
  if LSep < 0 then
    Exit;
  if not TryStrToInt64(LName.Substring(4, LSep - 4), LPid) or (LPid < 0) or (LPid > High(Cardinal)) then
    Exit;
  APid := Cardinal(LPid);
  ARest := LName.Substring(LSep + 1);
  Result := ARest.StartsWith('luid_');
end;

function MHParseGpuEngineInstance(const AName: string; out AInstance: TMHGpuEngineInstance): Boolean;
var
  LRest: string;
  LTypePos, LEngPos: Integer;
begin
  AInstance := Default(TMHGpuEngineInstance);
  Result := False;
  if not SplitPid(AName, AInstance.Pid, LRest) then
    Exit;
  LTypePos := LRest.IndexOf(ENGTYPE_MARK);
  LEngPos := LRest.IndexOf(ENG_MARK);
  if (LTypePos < 0) or (LEngPos < 0) or (LEngPos > LTypePos) then
    Exit;
  AInstance.Adapter := LRest.Substring(0, LEngPos);
  AInstance.Engine := LRest.Substring(0, LTypePos);
  AInstance.EngineType := LRest.Substring(LTypePos + Length(ENGTYPE_MARK));
  Result := (AInstance.Adapter <> '') and (AInstance.EngineType <> '');
end;

function MHParseGpuProcessMemoryInstance(const AName: string; out APid: Cardinal;
  out AAdapter: string): Boolean;
begin
  APid := 0;
  Result := SplitPid(AName, APid, AAdapter) and (AAdapter <> '');
end;

{ TMHGpuCollector }

constructor TMHGpuCollector.Create(const AApi: IMHGpuApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
end;

function TMHGpuCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHGpuCollector.GetDisplayName: string;
begin
  Result := MHL('Видеокарта: загрузка, видеопамять, температура', 'Graphics card: load, video memory, temperature');
end;

type
  TPidGpu = record
    MaxEngine: Double;
    MaxCompute: Double;
    MemoryBytes: Double;
    HasMemory: Boolean;
  end;

function TMHGpuCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LCounters: TMHGpuCounters;
  LSensors: TArray<TMHGpuSensor>;
  LSensor: TMHGpuSensor;
  LSensorReason: string;
  LSample: TMHGpuCounterSample;
  LInstance: TMHGpuEngineInstance;
  LPerEngine: TDictionary<string, Double>;
  LComputeEngines: TDictionary<string, Boolean>;
  LPerPidEngine: TDictionary<string, Double>;
  LPids: TDictionary<Cardinal, TPidGpu>;
  LPidGpu: TPidGpu;
  LKey, LAdapter: string;
  LValue, LGpu, LCompute, LAdapterMemory, LTemperature, LPower: Double;
  LPid: Cardinal;
  LHasAdapterMemory, LHasTemperature, LHasPower: Boolean;
  LMetrics: TList<TMHMetric>;
  LDetails: TList<TMHProcessDetail>;
  LDetail: TMHProcessDetail;
  LInfo: TMHProcessInfo;
  LSeen: TDictionary<Cardinal, Boolean>;
  LPair: TPair<string, Double>;
  LState: TMHSourceState;
  LNotes: string;
  LReadings: TArray<TMHSensorReading>;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  LCounters := FApi.GetCounters;
  LSensors := FApi.GetSensors(LSensorReason);

  LMetrics := TList<TMHMetric>.Create;
  LDetails := TList<TMHProcessDetail>.Create;
  LPerEngine := TDictionary<string, Double>.Create;
  LComputeEngines := TDictionary<string, Boolean>.Create;
  LPerPidEngine := TDictionary<string, Double>.Create;
  LPids := TDictionary<Cardinal, TPidGpu>.Create;
  LSeen := TDictionary<Cardinal, Boolean>.Create;
  try
    LNotes := '';
    if LCounters.Available then
    begin
      // Значение «процесс + движок» (на случай повторов экземпляра — сумма).
      for LSample in LCounters.Engines do
        if MHParseGpuEngineInstance(LSample.InstanceName, LInstance) then
        begin
          LValue := EnsureRange(LSample.Value, 0.0, 100.0);
          LKey := IntToStr(LInstance.Pid) + '|' + LInstance.Engine;
          if LPerPidEngine.ContainsKey(LKey) then
            LPerPidEngine[LKey] := LPerPidEngine[LKey] + LValue
          else
            LPerPidEngine.Add(LKey, LValue);
          if LPerEngine.ContainsKey(LInstance.Engine) then
            LPerEngine[LInstance.Engine] := LPerEngine[LInstance.Engine] + LValue
          else
            LPerEngine.Add(LInstance.Engine, LValue);
          if MHIsComputeEngineType(LInstance.EngineType) then
            LComputeEngines.AddOrSetValue(LInstance.Engine, True);
        end;

      // По процессам: самый загруженный движок и самый загруженный вычислительный.
      for LPair in LPerPidEngine do
      begin
        LPid := StrToUIntDef(LPair.Key.Substring(0, LPair.Key.IndexOf('|')), 0);
        LKey := LPair.Key.Substring(LPair.Key.IndexOf('|') + 1);
        if not LPids.TryGetValue(LPid, LPidGpu) then
          LPidGpu := Default(TPidGpu);
        LValue := Min(100.0, LPair.Value);
        LPidGpu.MaxEngine := Max(LPidGpu.MaxEngine, LValue);
        if LComputeEngines.ContainsKey(LKey) then
          LPidGpu.MaxCompute := Max(LPidGpu.MaxCompute, LValue);
        LPids.AddOrSetValue(LPid, LPidGpu);
      end;
      for LSample in LCounters.ProcessMemory do
        if MHParseGpuProcessMemoryInstance(LSample.InstanceName, LPid, LAdapter) then
        begin
          if not LPids.TryGetValue(LPid, LPidGpu) then
            LPidGpu := Default(TPidGpu);
          LPidGpu.MemoryBytes := LPidGpu.MemoryBytes + Max(0.0, LSample.Value);
          LPidGpu.HasMemory := True;
          LPids.AddOrSetValue(LPid, LPidGpu);
        end;

      // Система: самый загруженный движок (сумма по процессам).
      LGpu := 0;
      LCompute := 0;
      for LPair in LPerEngine do
      begin
        LValue := Min(100.0, LPair.Value);
        LGpu := Max(LGpu, LValue);
        if LComputeEngines.ContainsKey(LPair.Key) then
          LCompute := Max(LCompute, LValue);
      end;
      LMetrics.Add(TMHMetric.Available(mkGpuPercent, LGpu, LNow));
      LMetrics.Add(TMHMetric.Available(mkGpuComputePercent, LCompute, LNow));

      LAdapterMemory := 0;
      LHasAdapterMemory := False;
      for LSample in LCounters.AdapterMemory do
      begin
        LAdapterMemory := LAdapterMemory + Max(0.0, LSample.Value);
        LHasAdapterMemory := True;
      end;
      if LHasAdapterMemory then
        LMetrics.Add(TMHMetric.Available(mkGpuMemoryBytes, LAdapterMemory, LNow))
      else
        LMetrics.Add(TMHMetric.NoData(mkGpuMemoryBytes, LNow));

      // Процессы снимка без экземпляров GPU не используют видеокарту: 0%, как в диспетчере задач.
      for LInfo in ASnapshot.Processes do
      begin
        if LSeen.ContainsKey(LInfo.Id.Pid) or SameText(LInfo.SourceId, MH_SELF_SOURCE_ID) then
          Continue;
        LSeen.Add(LInfo.Id.Pid, True);
        if not LPids.TryGetValue(LInfo.Id.Pid, LPidGpu) then
          LPidGpu := Default(TPidGpu);
        LDetail := TMHProcessDetail.Create(LInfo.Id);
        LDetail.Gpu := TMHMetric.Available(mkGpuPercent, LPidGpu.MaxEngine, LNow);
        LDetail.GpuCompute := TMHMetric.Available(mkGpuComputePercent, LPidGpu.MaxCompute, LNow);
        if LPidGpu.HasMemory then
          LDetail.GpuMemory := TMHMetric.Available(mkGpuMemoryBytes, LPidGpu.MemoryBytes, LNow)
        else if LHasAdapterMemory then
          LDetail.GpuMemory := TMHMetric.Available(mkGpuMemoryBytes, 0, LNow);
        LDetails.Add(LDetail);
      end;
    end
    else
    begin
      LMetrics.Add(TMHMetric.NoData(mkGpuPercent, LNow));
      LMetrics.Add(TMHMetric.NoData(mkGpuComputePercent, LNow));
      LMetrics.Add(TMHMetric.NoData(mkGpuMemoryBytes, LNow));
      LNotes := MHL('Загрузка GPU: ', 'GPU load: ') + LCounters.Reason + '.';
    end;

    // Температура: самый горячий адаптер.
    LHasTemperature := False;
    LTemperature := 0;
    LReadings := nil;
    for LSensor in LSensors do
      if LSensor.HasTemperature and (LSensor.TemperatureCelsius > 0) and
         (LSensor.TemperatureCelsius < 150) then
      begin
        LReadings := LReadings + [TMHSensorReading.Create(skGpu, LSensor.AdapterName, LSensor.Source,
          LSensor.TemperatureCelsius, IfThen(LSensor.HasSlowdown, LSensor.SlowdownCelsius, 0))];
        LTemperature := IfThen(LHasTemperature, Max(LTemperature, LSensor.TemperatureCelsius),
          LSensor.TemperatureCelsius);
        LHasTemperature := True;
      end;
    // Мощность: сумма по адаптерам, сообщившим её (обычно только NVIDIA через NVML).
    LHasPower := False;
    LPower := 0;
    for LSensor in LSensors do
      if LSensor.HasPower and (LSensor.PowerWatts >= 0) and (LSensor.PowerWatts < 2000) then
      begin
        LPower := LPower + LSensor.PowerWatts;
        LHasPower := True;
      end;
    if LHasPower then
      LMetrics.Add(TMHMetric.Available(mkGpuPowerWatts, LPower, LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkGpuPowerWatts, LNow));

    if LHasTemperature then
      LMetrics.Add(TMHMetric.Available(mkGpuTemperatureCelsius, LTemperature, LNow))
    else
    begin
      LMetrics.Add(TMHMetric.NoData(mkGpuTemperatureCelsius, LNow));
      if LSensorReason <> '' then
        LNotes := Trim(LNotes + MHL(' Температура GPU: ', ' GPU temperature: ') + LSensorReason + '.');
    end;

    if LCounters.Available then
      LState := ssSuccess
    else if LHasTemperature or LCounters.Pending then
      LState := ssPartial
    else
      LState := ssUnavailable;
    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState, LNotes, LNow));
    Result.Status.ItemCount := LDetails.Count;
    Result.Metrics := LMetrics.ToArray;
    Result.ProcessDetails := LDetails.ToArray;
    Result.Sensors := LReadings;
  finally
    LSeen.Free;
    LPids.Free;
    LPerPidEngine.Free;
    LComputeEngines.Free;
    LPerEngine.Free;
    LDetails.Free;
    LMetrics.Free;
  end;
end;

end.
