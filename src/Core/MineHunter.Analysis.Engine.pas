unit MineHunter.Analysis.Engine;

{
  Анализатор угроз MineHunter X (MH-03, MH-06, MH-07).

  Принципы:
  - Ни один признак сам по себе не является доказательством заражения.
    Оценка складывается из независимых сигналов (нагрузка, подпись,
    расположение, автозапуск, сеть, поведение при запуске диспетчера задач)
    и уменьшается оправдывающими факторами (доверенная подпись, активная
    работа пользователя, игра, компиляция, обновления, норма этого компьютера).
  - Результат — «требует проверки / подозрительно», а не диагноз.
  - Каждая находка содержит признаки с весами, недостающие данные,
    уверенность, версию правил и рекомендации.
  - Детерминированность: одинаковая последовательность снимков даёт
    одинаковые находки (время берётся из снимков, идентификаторы находок
    вычисляются из ключа).

  Анализатор хранит скользящее окно нагрузки по каждому экземпляру процесса,
  поэтому вызывается последовательно (сканер так и делает). Настройки и
  исключения можно менять из другого потока.
}

interface

uses
  System.SysUtils, System.SyncObjs, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Analysis.Indicators;

const
  MH_RULESET_VERSION = 'MH-2026.10.6';

  // Коды признаков (стабильны: используются в отчётах и регрессионных тестах).
  EV_LOAD_SUSTAINED = 'LOAD_SUSTAINED';
  EV_LOAD_BACKGROUND = 'LOAD_BACKGROUND';
  EV_LOAD_WHILE_IDLE = 'LOAD_WHILE_IDLE';
  EV_MINER_NAME = 'MINER_NAME';
  EV_MINER_CMDLINE = 'MINER_CMDLINE';
  EV_POOL_PORT = 'POOL_PORT';
  EV_UNSIGNED = 'UNSIGNED';
  EV_SIGNATURE_INVALID = 'SIGNATURE_INVALID';
  EV_LOCATION = 'SUSPICIOUS_LOCATION';
  EV_MASQUERADE = 'MASQUERADE';
  EV_NAME_LOOKALIKE = 'NAME_LOOKALIKE';
  EV_AUTOSTART = 'AUTOSTART';
  EV_HIDES_FROM_MONITOR = 'HIDES_FROM_MONITOR';
  EV_ABOVE_BASELINE = 'ABOVE_BASELINE';
  EV_WORKLOAD_MISMATCH = 'WORKLOAD_NAME_MISMATCH';
  EV_SIGNED_TRUSTED = 'SIGNED_TRUSTED';
  EV_USER_ACTIVE = 'USER_ACTIVE';
  EV_FULLSCREEN = 'FULLSCREEN_APP';
  EV_KNOWN_WORKLOAD = 'KNOWN_WORKLOAD';
  EV_TYPICAL = 'TYPICAL_FOR_PC';
  EV_FILE_MISSING = 'FILE_MISSING';
  EV_SYSTEM_LOAD = 'SYSTEM_LOAD';
  EV_SCRIPT_AUTOSTART = 'SCRIPT_AUTOSTART';
  EV_RANDOM_FOLDER = 'RANDOM_FOLDER';
  EV_TASK_MASQUERADE = 'TASK_MASQUERADE';
  EV_OBFUSCATED_COMMAND = 'OBFUSCATED_COMMAND';
  EV_HIDDEN_SCRIPT = 'HIDDEN_SCRIPT';
  EV_GPU_SUSTAINED = 'GPU_SUSTAINED';
  EV_GPU_COMPUTE_BACKGROUND = 'GPU_COMPUTE_BACKGROUND';
  EV_OVERHEAT = 'OVERHEAT';
  EV_THROTTLING = 'CPU_THROTTLING';
  /// Префикс признаков BinaryLab (BINARYLAB:BL_PACKED_CODE и т.п.).
  EV_BINARYLAB_PREFIX = 'BINARYLAB:';

  /// Порог длительной загрузки GPU процессом, % самого загруженного движка.
  MH_GPU_HIGH_PERCENT = 40;
  /// Порог длительной загрузки вычислительных движков GPU (Compute, CUDA), %.
  MH_GPU_COMPUTE_HIGH_PERCENT = 30;

type
  TMHThreatAnalyzer = class(TInterfacedObject, IMHAnalyzer)
  private type
    TSample = record
      TimeUtc: TDateTime;
      Cpu: Double;
      Gpu: Single;
      GpuCompute: Single;
      HasCpu: Boolean;
      HasGpu: Boolean;
    end;
    TProcessState = class
      Samples: TList<TSample>;
      /// Нагрузка до появления диспетчера задач (снимок, после которого ждём реакции).
      WatchSince: TDateTime;
      WatchCpuBefore: Double;
      /// Момент, когда процесс снизил нагрузку при появлении диспетчера задач.
      HidSince: TDateTime;
      HidCpuBefore: Double;
      HidCpuAfter: Double;
      constructor Create;
      destructor Destroy; override;
    end;
    /// Ресурсы системной истории (индексы для SustainedAbove).
    TSystemResource = (srCpu, srMemory, srDisk, srGpu, srGpuHeat, srDiskHeat, srCpuHeat, srThrottle);
    TSystemSample = record
      TimeUtc: TDateTime;
      /// Значение ресурса; для перегрева — превышение порога устройства, °C
      /// (отрицательное — запас); для троттлинга — 100 − предел производительности.
      Values: array[TSystemResource] of Single;
      Has: array[TSystemResource] of Boolean;
    end;
  private
    FLock: TCriticalSection;
    FSettings: TMHAnalyzerSettings;
    FExclusions: TArray<TMHExclusion>;
    FAcknowledged: TArray<TMHAcknowledgement>;
    FBinaryVerdicts: IMHBinaryVerdicts;
    FCpuCount: Integer;
    FSelfPid: Cardinal;
    FStates: TObjectDictionary<string, TProcessState>;
    FSystem: TList<TSystemSample>;
    FMonitorKeys: TDictionary<string, Boolean>;
    /// Число точек истории после последнего UpdateHistory (читается из любого потока).
    FSampleCount: Integer;
    function StateKey(const AInfo: TMHProcessInfo): string;
    procedure UpdateHistory(const ASnapshot: TMHSnapshot; const ASettings: TMHAnalyzerSettings;
      out AMonitorAppeared: Boolean);
    procedure UpdateMonitorReaction(const ASnapshot: TMHSnapshot; AMonitorAppeared: Boolean;
      const ASettings: TMHAnalyzerSettings);
    function AnalyzeProcess(const ASnapshot: TMHSnapshot; const AInfo: TMHProcessInfo;
      const ABaseline: TMHBaseline; const ASettings: TMHAnalyzerSettings;
      out AFinding: TMHFinding): Boolean;
    function AnalyzeAutostart(const ASnapshot: TMHSnapshot; const AEntry: TMHAutostartEntry;
      const ASettings: TMHAnalyzerSettings; out AFinding: TMHFinding): Boolean;
    procedure AnalyzeSystem(const ASnapshot: TMHSnapshot; const ABaseline: TMHBaseline;
      const ASettings: TMHAnalyzerSettings; AFindings: TList<TMHFinding>);
    function IsExcluded(const AKey, ASha256: string): Boolean;
    function GetSettings: TMHAnalyzerSettings;
    procedure SetSettings(const AValue: TMHAnalyzerSettings);
    function GetExclusions: TArray<TMHExclusion>;
    procedure SetExclusions(const AValue: TArray<TMHExclusion>);
    function GetAcknowledged: TArray<TMHAcknowledgement>;
    procedure SetAcknowledged(const AValue: TArray<TMHAcknowledgement>);
    function GetBinaryVerdicts: IMHBinaryVerdicts;
    procedure SetBinaryVerdicts(const AValue: IMHBinaryVerdicts);
  public
    /// ALogicalCpuCount — для пересчёта «% машины» в «% ядра»;
    /// ASelfPid — собственный процесс, который не анализируется.
    constructor Create(ALogicalCpuCount: Integer; ASelfPid: Cardinal);
    destructor Destroy; override;
    function GetRulesetVersion: string;
    function Analyze(const ASnapshot: TMHSnapshot; const ABaseline: TMHBaseline): TMHFindings;
    /// Число экземпляров процессов, для которых хранится история (для тестов).
    function TrackedCount: Integer;
    /// Всего точек истории нагрузки во всех отслеживаемых процессах на конец последнего
    /// анализа (диагностика памяти; потокобезопасно).
    function TotalSamples: Integer;
    property Settings: TMHAnalyzerSettings read GetSettings write SetSettings;
    property Exclusions: TArray<TMHExclusion> read GetExclusions write SetExclusions;
    /// Находки, отмеченные проверенными: не возвращаются, пока не изменятся.
    property Acknowledged: TArray<TMHAcknowledgement> read GetAcknowledged write SetAcknowledged;
    /// Результаты BinaryLab: признаки из разбора файла добавляются в находку
    /// процесса этого файла (nil — не используются).
    property BinaryVerdicts: IMHBinaryVerdicts read GetBinaryVerdicts write SetBinaryVerdicts;
  end;

  /// Причина замедления в понятном виде (для панели «Почему компьютер тормозит»).
  TMHLoadReason = record
    Resource: string;
    Text: string;
    IsHigh: Boolean;
  end;

/// Объясняет текущую нагрузку: основные потребители ресурсов и их вероятный характер.
function MHExplainLoad(const ASnapshot: TMHSnapshot; ACpuCount: Integer;
  ATop: Integer = 3): TArray<TMHLoadReason>;

/// Детерминированный идентификатор находки по её ключу.
function MHFindingIdFromKey(const AKey: string): TGUID;

/// Порог температуры устройства: порог производителя (начало снижения частоты
/// видеокарты, предупреждение накопителя), а если он неизвестен — значение по
/// виду устройства (GPU 87 °C, накопитель 65 °C, процессор 90 °C).
function MHTemperatureLimit(const AReading: TMHSensorReading): Double;
/// Имя ресурса причины или находки о перегреве: 'heat:gpu', 'heat:disk', 'heat:cpu'.
function MHHeatResourceName(AKind: TMHSensorKind): string;

implementation

uses
  System.Math, System.StrUtils, System.Hash, System.DateUtils, System.Generics.Defaults,
  MineHunter.Core.Paths, MineHunter.Core.Lang, MineHunter.Analysis.Tamper, MineHunter.Analysis.Launches,
  MineHunter.Analysis.Disks, MineHunter.Analysis.Acknowledge;

const
  MINUTE = 1 / MinsPerDay;
  HISTORY_MINUTES_MIN = 30;
  MONITOR_REACTION_SECONDS = 90;
  HIDE_MEMORY_MINUTES = 30;
  IDLE_SECONDS = 300;
  /// Минимальный шаг между точками истории нагрузки процесса.
  MIN_SAMPLE_SPACING_SEC = 2;

function FormatPercent(AValue: Double): string;
begin
  Result := FormatFloat('0', AValue) + '%';
end;

procedure SetSystemValue(var ASample: TMHThreatAnalyzer.TSystemSample;
  AResource: TMHThreatAnalyzer.TSystemResource; AValue: Double);
begin
  ASample.Values[AResource] := AValue;
  ASample.Has[AResource] := True;
end;

function MHTemperatureLimit(const AReading: TMHSensorReading): Double;
begin
  if AReading.LimitCelsius > 0 then
    Exit(AReading.LimitCelsius);
  // Порог производителя неизвестен — консервативные значения по виду устройства.
  case AReading.Kind of
    skGpu: Result := 87;
    skDisk: Result := 65;
  else
    Result := 90;
  end;
end;

function MHFindingIdFromKey(const AKey: string): TGUID;
var
  LBytes: TBytes;
begin
  LBytes := THashMD5.GetHashBytes(AKey);
  Move(LBytes[0], Result, SizeOf(TGUID));
  // Версия 3 (на основе имени) и вариант RFC 4122.
  Result.D3 := (Result.D3 and $0FFF) or $3000;
  Result.D4[0] := (Result.D4[0] and $3F) or $80;
end;

{ TMHThreatAnalyzer.TProcessState }

constructor TMHThreatAnalyzer.TProcessState.Create;
begin
  inherited Create;
  Samples := TList<TSample>.Create;
end;

destructor TMHThreatAnalyzer.TProcessState.Destroy;
begin
  Samples.Free;
  inherited;
end;

{ TMHThreatAnalyzer }

constructor TMHThreatAnalyzer.Create(ALogicalCpuCount: Integer; ASelfPid: Cardinal);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSettings := TMHAnalyzerSettings.Default;
  FCpuCount := Max(1, ALogicalCpuCount);
  FSelfPid := ASelfPid;
  FStates := TObjectDictionary<string, TProcessState>.Create([doOwnsValues]);
  FSystem := TList<TSystemSample>.Create;
  FMonitorKeys := TDictionary<string, Boolean>.Create;
end;

destructor TMHThreatAnalyzer.Destroy;
begin
  FMonitorKeys.Free;
  FSystem.Free;
  FStates.Free;
  FLock.Free;
  inherited;
end;

function TMHThreatAnalyzer.GetRulesetVersion: string;
begin
  // Не зависит от языка: версия правил сохраняется вместе с находками.
  Result := MH_RULESET_VERSION + ' / индикаторы ' + MH_INDICATORS_VERSION;
end;

function TMHThreatAnalyzer.GetSettings: TMHAnalyzerSettings;
begin
  FLock.Enter;
  try
    Result := FSettings;
  finally
    FLock.Leave;
  end;
end;

procedure TMHThreatAnalyzer.SetSettings(const AValue: TMHAnalyzerSettings);
begin
  FLock.Enter;
  try
    FSettings := AValue.Normalized;
  finally
    FLock.Leave;
  end;
end;

function TMHThreatAnalyzer.GetExclusions: TArray<TMHExclusion>;
begin
  FLock.Enter;
  try
    Result := Copy(FExclusions);
  finally
    FLock.Leave;
  end;
end;

function TMHThreatAnalyzer.GetAcknowledged: TArray<TMHAcknowledgement>;
begin
  FLock.Enter;
  try
    Result := Copy(FAcknowledged);
  finally
    FLock.Leave;
  end;
end;

procedure TMHThreatAnalyzer.SetAcknowledged(const AValue: TArray<TMHAcknowledgement>);
begin
  FLock.Enter;
  try
    FAcknowledged := Copy(AValue);
  finally
    FLock.Leave;
  end;
end;

function TMHThreatAnalyzer.GetBinaryVerdicts: IMHBinaryVerdicts;
begin
  FLock.Enter;
  try
    Result := FBinaryVerdicts;
  finally
    FLock.Leave;
  end;
end;

procedure TMHThreatAnalyzer.SetBinaryVerdicts(const AValue: IMHBinaryVerdicts);
begin
  FLock.Enter;
  try
    FBinaryVerdicts := AValue;
  finally
    FLock.Leave;
  end;
end;

procedure TMHThreatAnalyzer.SetExclusions(const AValue: TArray<TMHExclusion>);
begin
  FLock.Enter;
  try
    FExclusions := Copy(AValue);
  finally
    FLock.Leave;
  end;
end;

function TMHThreatAnalyzer.IsExcluded(const AKey, ASha256: string): Boolean;
var
  LExclusion: TMHExclusion;
begin
  FLock.Enter;
  try
    for LExclusion in FExclusions do
      if LExclusion.Matches(AKey, ASha256) then
        Exit(True);
  finally
    FLock.Leave;
  end;
  Result := False;
end;

function TMHThreatAnalyzer.TrackedCount: Integer;
begin
  Result := FStates.Count;
end;

function TMHThreatAnalyzer.TotalSamples: Integer;
begin
  Result := TInterlocked.CompareExchange(FSampleCount, 0, 0);
end;

function TMHThreatAnalyzer.StateKey(const AInfo: TMHProcessInfo): string;
begin
  Result := AInfo.Id.ToString;
end;

procedure TMHThreatAnalyzer.UpdateHistory(const ASnapshot: TMHSnapshot;
  const ASettings: TMHAnalyzerSettings; out AMonitorAppeared: Boolean);
var
  LAlive: TDictionary<string, Boolean>;
  LMonitors: TDictionary<string, Boolean>;
  LInfo: TMHProcessInfo;
  LKey: string;
  LState: TProcessState;
  LSample: TSample;
  LSystem: TSystemSample;
  LMetric: TMHMetric;
  LKeep: TDateTime;
  LKeys: TArray<string>;
  LTotal: Integer;
  LReading: TMHSensorReading;
  LResource: TSystemResource;
  LMargin: Double;
begin
  AMonitorAppeared := False;
  LKeep := ASnapshot.TimestampUtc - Max(HISTORY_MINUTES_MIN, ASettings.SustainedMinutes * 2) * MINUTE;
  LAlive := TDictionary<string, Boolean>.Create;
  LMonitors := TDictionary<string, Boolean>.Create;
  try
    for LInfo in ASnapshot.Processes do
    begin
      LKey := StateKey(LInfo);
      if LAlive.ContainsKey(LKey) then
        Continue; // один экземпляр может прийти от нескольких источников
      LAlive.Add(LKey, True);
      if MHIsMonitoringTool(LInfo.Name) then
      begin
        LMonitors.AddOrSetValue(LKey, True);
        if not FMonitorKeys.ContainsKey(LKey) then
          AMonitorAppeared := True;
      end;
      if not FStates.TryGetValue(LKey, LState) then
      begin
        LState := TProcessState.Create;
        FStates.Add(LKey, LState);
      end;
      LSample.TimeUtc := ASnapshot.TimestampUtc;
      LSample.HasCpu := LInfo.Cpu.HasValue;
      LSample.Cpu := IfThen(LInfo.Cpu.HasValue, LInfo.Cpu.Value, 0);
      LSample.HasGpu := LInfo.Gpu.HasValue;
      LSample.Gpu := IfThen(LInfo.Gpu.HasValue, LInfo.Gpu.Value, 0);
      LSample.GpuCompute := IfThen(LInfo.GpuCompute.HasValue, LInfo.GpuCompute.Value, 0);
      // Не чаще одной точки за MIN_SAMPLE_SPACING_SEC: размер окна ограничен
      // независимо от интервала опроса (при 250 мс иначе было бы в 8 раз больше точек).
      // Точки группируются по интервалам фиксированной длины: внутри интервала
      // последняя точка заменяется (сравнение с её временем не годится — оно сдвигается).
      if (LState.Samples.Count > 0) and
         (Trunc(LSample.TimeUtc * SecsPerDay / MIN_SAMPLE_SPACING_SEC) =
          Trunc(LState.Samples.Last.TimeUtc * SecsPerDay / MIN_SAMPLE_SPACING_SEC)) then
        LState.Samples[LState.Samples.Count - 1] := LSample
      else
        LState.Samples.Add(LSample);
      while (LState.Samples.Count > 0) and (LState.Samples[0].TimeUtc < LKeep) do
        LState.Samples.Delete(0);
    end;
    // Завершившиеся процессы больше не отслеживаются.
    LKeys := FStates.Keys.ToArray;
    for LKey in LKeys do
      if not LAlive.ContainsKey(LKey) then
        FStates.Remove(LKey);
    FMonitorKeys.Clear;
    for LKey in LMonitors.Keys do
      FMonitorKeys.Add(LKey, True);
    LTotal := 0;
    for LState in FStates.Values do
      Inc(LTotal, LState.Samples.Count);
    TInterlocked.Exchange(FSampleCount, LTotal);
  finally
    LMonitors.Free;
    LAlive.Free;
  end;

  LSystem := Default(TSystemSample);
  LSystem.TimeUtc := ASnapshot.TimestampUtc;
  if ASnapshot.FindMetric(mkCpuPercent, LMetric) and LMetric.HasValue then
    SetSystemValue(LSystem, srCpu, LMetric.Value);
  if ASnapshot.FindMetric(mkMemoryLoadPercent, LMetric) and LMetric.HasValue then
    SetSystemValue(LSystem, srMemory, LMetric.Value);
  if ASnapshot.FindMetric(mkDiskActivePercent, LMetric) and LMetric.HasValue then
    SetSystemValue(LSystem, srDisk, LMetric.Value);
  if ASnapshot.FindMetric(mkGpuPercent, LMetric) and LMetric.HasValue then
    SetSystemValue(LSystem, srGpu, LMetric.Value);
  if ASnapshot.FindMetric(mkCpuPerformanceLimitPercent, LMetric) and LMetric.HasValue then
    SetSystemValue(LSystem, srThrottle, 100 - LMetric.Value);
  // Перегрев: превышение порога самого «горячего» устройства каждого вида.
  for LReading in ASnapshot.Sensors do
  begin
    case LReading.Kind of
      skGpu: LResource := srGpuHeat;
      skDisk: LResource := srDiskHeat;
    else
      LResource := srCpuHeat;
    end;
    LMargin := LReading.Celsius - MHTemperatureLimit(LReading);
    if not LSystem.Has[LResource] or (LMargin > LSystem.Values[LResource]) then
      SetSystemValue(LSystem, LResource, LMargin);
  end;
  // Как и для процессов — не чаще одной точки за MIN_SAMPLE_SPACING_SEC.
  if (FSystem.Count > 0) and
     (Trunc(LSystem.TimeUtc * SecsPerDay / MIN_SAMPLE_SPACING_SEC) =
      Trunc(FSystem.Last.TimeUtc * SecsPerDay / MIN_SAMPLE_SPACING_SEC)) then
    FSystem[FSystem.Count - 1] := LSystem
  else
    FSystem.Add(LSystem);
  while (FSystem.Count > 0) and (FSystem[0].TimeUtc < LKeep) do
    FSystem.Delete(0);
end;

/// Средняя загрузка GPU (AByCompute — вычислительных движков) за интервал.
function AverageGpu(ASamples: TList<TMHThreatAnalyzer.TSample>; AFrom, ATo: TDateTime;
  AByCompute: Boolean; out ACount: Integer; out AFirstTime: TDateTime): Double;
var
  I: Integer;
  LSum: Double;
begin
  LSum := 0;
  ACount := 0;
  AFirstTime := 0;
  for I := 0 to ASamples.Count - 1 do
    if ASamples[I].HasGpu and (ASamples[I].TimeUtc >= AFrom) and (ASamples[I].TimeUtc <= ATo) then
    begin
      if ACount = 0 then
        AFirstTime := ASamples[I].TimeUtc;
      if AByCompute then
        LSum := LSum + ASamples[I].GpuCompute
      else
        LSum := LSum + ASamples[I].Gpu;
      Inc(ACount);
    end;
  if ACount = 0 then
    Result := 0
  else
    Result := LSum / ACount;
end;

/// Средняя нагрузка за интервал [AFrom; ATo] и покрытие интервала данными.
function AverageCpu(ASamples: TList<TMHThreatAnalyzer.TSample>; AFrom, ATo: TDateTime;
  out ACount: Integer; out AFirstTime: TDateTime): Double;
var
  I: Integer;
  LSum: Double;
begin
  LSum := 0;
  ACount := 0;
  AFirstTime := 0;
  for I := 0 to ASamples.Count - 1 do
    if ASamples[I].HasCpu and (ASamples[I].TimeUtc >= AFrom) and (ASamples[I].TimeUtc <= ATo) then
    begin
      if ACount = 0 then
        AFirstTime := ASamples[I].TimeUtc;
      LSum := LSum + ASamples[I].Cpu;
      Inc(ACount);
    end;
  if ACount = 0 then
    Result := 0
  else
    Result := LSum / ACount;
end;

procedure TMHThreatAnalyzer.UpdateMonitorReaction(const ASnapshot: TMHSnapshot;
  AMonitorAppeared: Boolean; const ASettings: TMHAnalyzerSettings);
var
  LPair: TPair<string, TProcessState>;
  LState: TProcessState;
  LBefore, LAfter: Double;
  LCount: Integer;
  LFirst, LNow: TDateTime;
begin
  LNow := ASnapshot.TimestampUtc;
  for LPair in FStates do
  begin
    LState := LPair.Value;
    if AMonitorAppeared and (LState.WatchSince = 0) then
    begin
      // Нагрузка за 2 минуты до появления диспетчера задач (без текущего снимка).
      LBefore := AverageCpu(LState.Samples, LNow - 2 * MINUTE, LNow - 1 / SecsPerDay, LCount, LFirst);
      if (LCount >= 2) and (LBefore >= ASettings.HighCpuPercent) then
      begin
        LState.WatchSince := LNow;
        LState.WatchCpuBefore := LBefore;
      end;
    end
    else if (LState.WatchSince > 0) and (LNow > LState.WatchSince) then
    begin
      LAfter := AverageCpu(LState.Samples, LState.WatchSince + 1 / SecsPerDay, LNow, LCount, LFirst);
      if (LCount >= 1) and (LAfter <= LState.WatchCpuBefore * 0.3) then
      begin
        LState.HidSince := LNow;
        LState.HidCpuBefore := LState.WatchCpuBefore;
        LState.HidCpuAfter := LAfter;
        LState.WatchSince := 0;
      end
      else if (LNow - LState.WatchSince) * SecsPerDay > MONITOR_REACTION_SECONDS then
        LState.WatchSince := 0;
    end;
    if (LState.HidSince > 0) and ((LNow - LState.HidSince) > HIDE_MEMORY_MINUTES * MINUTE) then
      LState.HidSince := 0;
  end;
end;

function TMHThreatAnalyzer.Analyze(const ASnapshot: TMHSnapshot;
  const ABaseline: TMHBaseline): TMHFindings;
var
  LSettings: TMHAnalyzerSettings;
  LMonitorAppeared: Boolean;
  LList: TList<TMHFinding>;
  LSeen: TDictionary<string, Boolean>;
  LInfo: TMHProcessInfo;
  LEntry: TMHAutostartEntry;
  LFinding: TMHFinding;
  LSelfImage: string;
begin
  LSettings := Settings;
  UpdateHistory(ASnapshot, LSettings, LMonitorAppeared);
  UpdateMonitorReaction(ASnapshot, LMonitorAppeared, LSettings);
  LList := TList<TMHFinding>.Create;
  LSeen := TDictionary<string, Boolean>.Create;
  try
    LSelfImage := '';
    for LInfo in ASnapshot.Processes do
    begin
      if LInfo.Id.Pid = FSelfPid then
        LSelfImage := LInfo.ImagePath;
      if (LInfo.Id.Pid = FSelfPid) or LSeen.ContainsKey(StateKey(LInfo)) then
        Continue;
      LSeen.Add(StateKey(LInfo), True);
      if AnalyzeProcess(ASnapshot, LInfo, ABaseline, LSettings, LFinding) then
        LList.Add(LFinding);
    end;
    LSeen.Clear;
    for LEntry in ASnapshot.Autostart do
      // Собственный автозапуск MineHunter X (включается пользователем в настройках).
      if (LSelfImage <> '') and SameText(LEntry.ImagePath, LSelfImage) then
        Continue
      else if AnalyzeAutostart(ASnapshot, LEntry, LSettings, LFinding) and
         not LSeen.ContainsKey(LFinding.Key) then
      begin
        LSeen.Add(LFinding.Key, True);
        LList.Add(LFinding);
      end;
    for LFinding in MHAnalyzeTamper(ASnapshot, LSettings.Thresholds,
      function(const AKey, ASha256: string): Boolean
      begin
        Result := IsExcluded(AKey, ASha256);
      end, GetRulesetVersion) do
      LList.Add(LFinding);
    for LFinding in MHAnalyzeLaunches(ASnapshot, LSettings.Thresholds,
      function(const AKey, ASha256: string): Boolean
      begin
        Result := IsExcluded(AKey, ASha256);
      end, GetRulesetVersion) do
      LList.Add(LFinding);
    for LFinding in MHAnalyzeDisks(ASnapshot, LSettings.Thresholds, GetRulesetVersion) do
      LList.Add(LFinding);
    AnalyzeSystem(ASnapshot, ABaseline, LSettings, LList);
    // Сначала самые серьёзные; при равенстве — по ключу (детерминированно).
    LList.Sort(TComparer<TMHFinding>.Construct(
      function(const A, B: TMHFinding): Integer
      begin
        Result := CompareValue(B.Score, A.Score);
        if Result = 0 then
          Result := CompareStr(A.Key, B.Key);
      end));
    Result := MHFilterAcknowledged(LList.ToArray, GetAcknowledged);
  finally
    LSeen.Free;
    LList.Free;
  end;
end;

procedure AddEvidence(var AItems: TArray<TMHEvidence>; const ACode, ADescription: string;
  AWeight: Integer; const AObserved: string = '');
begin
  AItems := AItems + [TMHEvidence.Create(ACode, ADescription, AWeight, AObserved)];
end;

function HasCode(const AItems: TArray<TMHEvidence>; const ACode: string): Boolean;
var
  LItem: TMHEvidence;
begin
  for LItem in AItems do
    if LItem.Code = ACode then
      Exit(True);
  Result := False;
end;

procedure AddUnique(var AItems: TArray<string>; const AText: string);
var
  LItem: string;
begin
  for LItem in AItems do
    if LItem = AText then
      Exit;
  AItems := AItems + [AText];
end;

function TMHThreatAnalyzer.AnalyzeProcess(const ASnapshot: TMHSnapshot;
  const AInfo: TMHProcessInfo; const ABaseline: TMHBaseline;
  const ASettings: TMHAnalyzerSettings; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LMissing, LRecommend: TArray<string>;
  LState: TProcessState;
  LNow, LFirst: TDateTime;
  LAvg, LConfidence, LCoreShare: Double;
  LCount, LTotal, LRaw: Integer;
  LSustained, LLoadHigh, LMinerSignal, LThreatSignal: Boolean;
  LPath, LReason, LToken, LSystemName, LKey: string;
  LDirs: TArray<string>;
  LDir: string;
  LInExpectedDir: Boolean;
  LFile: TMHFileInfo;
  LHasFile: Boolean;
  LWorkload: TMHWorkloadCategory;
  LConnection: TMHNetConnection;
  LPoolPorts: string;
  LAutostart: TMHAutostartEntry;
  LBaseProcess: TMHProcessBaseline;
  LMinutes: Double;
  LIsForeground: Boolean;
  LGpuAvg, LComputeAvg: Double;
  LGpuCount: Integer;
  LGpuFirst: TDateTime;
  LGpuCovered, LGpuSustained, LComputeBackground: Boolean;
  LGpuMetric: TMHMetric;
  LTamperEvidence: TArray<TMHEvidence>;
  LTamperItem: TMHEvidence;
  LAvExcluded: Boolean;
  LVerdicts: IMHBinaryVerdicts;
  LVerdict: TMHBinaryVerdict;
  LBinaryItem: TMHEvidence;
  LSha256: string;
  LHasBinaryVerdict: Boolean;
begin
  Result := False;
  AFinding := Default(TMHFinding);
  LEvidence := nil;
  LMissing := nil;
  LRecommend := nil;
  LNow := ASnapshot.TimestampUtc;
  LPath := MHNormalizePath(AInfo.ImagePath);
  LKey := MHProgramKey(LPath, AInfo.Name);
  if IsExcluded(LKey, AInfo.Sha256) then
    Exit;
  LConfidence := 1.0;
  LMinerSignal := False;
  LThreatSignal := False;

  // --- Нагрузка ---
  LState := nil;
  LSustained := False;
  LLoadHigh := False;
  LAvg := 0;
  if FStates.TryGetValue(StateKey(AInfo), LState) then
  begin
    LAvg := AverageCpu(LState.Samples, LNow - ASettings.SustainedMinutes * MINUTE, LNow, LCount, LFirst);
    LCoreShare := LAvg * FCpuCount;
    LLoadHigh := (LCount > 0) and ((LAvg >= ASettings.HighCpuPercent) or
      ((FCpuCount > 1) and (LCoreShare >= ASettings.HighCoreCpuPercent)));
    LMinutes := IfThen(LCount > 0, (LNow - LFirst) / MINUTE, 0);
    // Длительность: данные покрывают почти весь интервал (допуск — один интервал опроса).
    LSustained := LLoadHigh and (LMinutes >= ASettings.SustainedMinutes * 0.9);
    if LLoadHigh and not LSustained then
      AddUnique(LMissing, Format(MHL('История нагрузки короче %d мин — длительность ещё не подтверждена',
        'Load history is shorter than %d min — duration not yet confirmed'),
        [ASettings.SustainedMinutes]));
  end;
  if LSustained then
  begin
    if LAvg >= ASettings.HighCpuPercent * 2 then
      AddEvidence(LEvidence, EV_LOAD_SUSTAINED, MHL('Длительная высокая нагрузка на процессор',
        'Sustained high CPU load'), 30,
        Format(MHL('в среднем %s CPU (≈%s ядра) в течение %d мин', 'average %s CPU (≈%s cores) for %d min'),
          [FormatPercent(LAvg), FormatFloat('0.0', LAvg * FCpuCount / 100), ASettings.SustainedMinutes]))
    else
      AddEvidence(LEvidence, EV_LOAD_SUSTAINED, MHL('Длительная высокая нагрузка на процессор',
        'Sustained high CPU load'), 25,
        Format(MHL('в среднем %s CPU (≈%s ядра) в течение %d мин', 'average %s CPU (≈%s cores) for %d min'),
          [FormatPercent(LAvg), FormatFloat('0.0', LAvg * FCpuCount / 100), ASettings.SustainedMinutes]));
    LIsForeground := ASnapshot.Context.Available and (ASnapshot.Context.ForegroundPid = AInfo.Id.Pid);
    if ASnapshot.Context.Available and not AInfo.HasVisibleWindow and not LIsForeground then
      AddEvidence(LEvidence, EV_LOAD_BACKGROUND, MHL('Нагрузку создаёт фоновый процесс без окна',
        'The load comes from a background process without a window'), 10);
    if ASnapshot.Context.Available and (ASnapshot.Context.UserIdleSeconds >= IDLE_SECONDS) then
      AddEvidence(LEvidence, EV_LOAD_WHILE_IDLE, MHL('Нагрузка сохраняется, пока пользователь не работает',
        'The load continues while the user is away'), 10,
        Format(MHL('бездействие %d мин', 'idle for %d min'), [ASnapshot.Context.UserIdleSeconds div 60]));
  end;

  // --- Видеокарта ---
  // Майнеры на GPU почти не нагружают процессор, поэтому проверяются отдельно:
  // длительная загрузка видеокарты и особенно её вычислительных блоков
  // (Compute, CUDA) фоновой программой без окна.
  LGpuSustained := False;
  LComputeBackground := False;
  if LState <> nil then
  begin
    LGpuAvg := AverageGpu(LState.Samples, LNow - ASettings.SustainedMinutes * MINUTE, LNow, False,
      LGpuCount, LGpuFirst);
    LComputeAvg := AverageGpu(LState.Samples, LNow - ASettings.SustainedMinutes * MINUTE, LNow, True,
      LGpuCount, LGpuFirst);
    LGpuCovered := (LGpuCount > 0) and ((LNow - LGpuFirst) / MINUTE >= ASettings.SustainedMinutes * 0.9);
    LIsForeground := ASnapshot.Context.Available and (ASnapshot.Context.ForegroundPid = AInfo.Id.Pid);
    if LGpuCovered and (LGpuAvg >= MH_GPU_HIGH_PERCENT) then
    begin
      LGpuSustained := True;
      AddEvidence(LEvidence, EV_GPU_SUSTAINED, MHL('Длительная высокая нагрузка на видеокарту',
        'Sustained high GPU load'), 20,
        Format(MHL('в среднем %s GPU в течение %d мин', 'average %s GPU for %d min'),
          [FormatPercent(LGpuAvg), ASettings.SustainedMinutes]));
    end;
    if LGpuCovered and (LComputeAvg >= MH_GPU_COMPUTE_HIGH_PERCENT) and ASnapshot.Context.Available and
       not AInfo.HasVisibleWindow and not LIsForeground then
    begin
      LComputeBackground := True;
      AddEvidence(LEvidence, EV_GPU_COMPUTE_BACKGROUND,
        MHL('Фоновая программа без окна загружает вычислительные блоки видеокарты (Compute, CUDA) — ',
          'A background program without a window is loading the GPU compute engines (Compute, CUDA) — ') +
        MHL('так работают майнеры на GPU', 'this is how GPU miners work'), 25,
        Format(MHL('в среднем %s вычислений GPU в течение %d мин', 'average %s GPU compute for %d min'),
          [FormatPercent(LComputeAvg),
          ASettings.SustainedMinutes]));
    end;
    if LGpuSustained or LComputeBackground then
    begin
      if ASnapshot.Context.Available and not AInfo.HasVisibleWindow and not LIsForeground and
         not HasCode(LEvidence, EV_LOAD_BACKGROUND) then
        AddEvidence(LEvidence, EV_LOAD_BACKGROUND, MHL('Нагрузку создаёт фоновый процесс без окна',
          'The load comes from a background process without a window'), 10);
      if ASnapshot.Context.Available and (ASnapshot.Context.UserIdleSeconds >= IDLE_SECONDS) and
         not HasCode(LEvidence, EV_LOAD_WHILE_IDLE) then
        AddEvidence(LEvidence, EV_LOAD_WHILE_IDLE, MHL('Нагрузка сохраняется, пока пользователь не работает',
          'The load continues while the user is away'), 10,
          Format(MHL('бездействие %d мин', 'idle for %d min'), [ASnapshot.Context.UserIdleSeconds div 60]));
    end;
  end;

  // --- Реакция на диспетчер задач ---
  if (LState <> nil) and (LState.HidSince > 0) then
  begin
    AddEvidence(LEvidence, EV_HIDES_FROM_MONITOR,
      MHL('Процесс резко снизил нагрузку после запуска диспетчера задач',
        'The process sharply reduced its load after Task Manager was started'), 30,
      Format(MHL('было %s, стало %s', 'was %s, now %s'), [FormatPercent(LState.HidCpuBefore), FormatPercent(LState.HidCpuAfter)]));
    LMinerSignal := True;
  end;

  // --- Признаки майнера ---
  if MHIsKnownMinerName(AInfo.Name) then
  begin
    AddEvidence(LEvidence, EV_MINER_NAME, MHL('Имя совпадает с известной программой для майнинга',
      'The name matches a known mining program'), 35, AInfo.Name);
    LMinerSignal := True;
  end;
  LToken := MHFindMinerCommandToken(AInfo.CommandLine);
  if LToken <> '' then
  begin
    AddEvidence(LEvidence, EV_MINER_CMDLINE, MHL('В командной строке есть параметры майнинга',
      'The command line contains mining parameters'), 40, LToken);
    LMinerSignal := True;
  end;
  LPoolPorts := '';
  for LConnection in ASnapshot.ConnectionsOf(AInfo.Id.Pid) do
    if LConnection.IsRemote and MHIsMiningPoolPort(LConnection.RemotePort) then
      LPoolPorts := LPoolPorts + Format('%s:%d ', [LConnection.RemoteAddress, LConnection.RemotePort]);
  // Сетевой индикатор учитывается только вместе с другими признаками:
  // по одному адресу или порту выводов не делаем (MH-05).
  if (LPoolPorts <> '') and (LSustained or LMinerSignal) then
  begin
    AddEvidence(LEvidence, EV_POOL_PORT,
      MHL('Соединение с портом, типичным для пулов майнинга (сам по себе не доказательство)',
        'Connection to a port typical for mining pools (not proof by itself)'), 15,
      Trim(LPoolPorts));
    LMinerSignal := True;
  end;

  // --- Файл: подпись и расположение ---
  LHasFile := ASnapshot.FindFile(LPath, LFile);
  if LPath = '' then
  begin
    AddUnique(LMissing, MHL('Путь к файлу недоступен (нет прав) — подпись и расположение не проверены',
      'File path is unavailable (no access) — signature and location not checked'));
    LConfidence := LConfidence - 0.3;
  end
  else if not LHasFile or (LFile.Signature = sgNotChecked) then
  begin
    AddUnique(LMissing, MHL('Цифровая подпись ещё не проверена', 'Digital signature not checked yet'));
    LConfidence := LConfidence - 0.15;
  end;
  if LHasFile then
    case LFile.Signature of
      sgUnsigned:
        AddEvidence(LEvidence, EV_UNSIGNED, MHL('Файл без цифровой подписи (это не доказательство угрозы)',
          'The file has no digital signature (this is not proof of a threat)'), 10);
      sgSignedUntrusted:
        begin
          AddEvidence(LEvidence, EV_SIGNATURE_INVALID, MHL('Подпись недействительна или файл изменён после подписания',
            'The signature is invalid or the file was modified after signing'),
            25, LFile.Error);
          LThreatSignal := True;
        end;
      sgCheckFailed:
        AddUnique(LMissing, MHL('Подпись не удалось проверить: ', 'Could not verify the signature: ') + LFile.Error);
    end;

  // --- BinaryLab: результаты статического разбора файла (если пользователь его проверял) ---
  LHasBinaryVerdict := False;
  LVerdicts := GetBinaryVerdicts;
  if (LPath <> '') and (LVerdicts <> nil) then
  begin
    LSha256 := AInfo.Sha256;
    if (LSha256 = '') and LHasFile then
      LSha256 := LFile.Sha256;
    if LVerdicts.TryGet(LPath, LSha256, LVerdict) then
    begin
      LHasBinaryVerdict := Length(LVerdict.Evidence) > 0;
      for LBinaryItem in LVerdict.Evidence do
        LEvidence := LEvidence + [LBinaryItem];
      if LVerdict.MiningSignal then
        LMinerSignal := True;
      if LVerdict.ThreatSignal then
        LThreatSignal := True;
    end;
  end;

  if (LPath <> '') and MHIsSuspiciousLocation(LPath, LReason) then
  begin
    AddEvidence(LEvidence, EV_LOCATION, MHL('Программа запущена из необычного места',
      'The program is running from an unusual location'), 15, LReason);
    LThreatSignal := True;
  end;

  // --- Маскировка под системные процессы ---
  if (LPath <> '') and MHIsSystemProcessName(AInfo.Name, LDirs) then
  begin
    // Каталог без буквы диска: «C:\Windows\System32\» -> «\Windows\System32\».
    LInExpectedDir := False;
    for LDir in LDirs do
      if SameText(Copy(ExtractFilePath(LPath), 3, MaxInt), LDir) then
        LInExpectedDir := True;
    if not LInExpectedDir then
    begin
      AddEvidence(LEvidence, EV_MASQUERADE, MHL('Системное имя Windows, но файл не в системной папке',
        'A Windows system name, but the file is not in a system folder'), 40,
        LPath);
      LThreatSignal := True;
    end;
  end
  else if MHLooksLikeSystemName(AInfo.Name, LSystemName) then
  begin
    AddEvidence(LEvidence, EV_NAME_LOOKALIKE, MHL('Имя похоже на системное, но отличается одним символом',
      'The name resembles a system name but differs by one character'), 25,
      Format('%s ≈ %s', [AInfo.Name, LSystemName]));
    LThreatSignal := True;
  end;

  // --- Автозапуск ---
  for LAutostart in ASnapshot.Autostart do
    if (LPath <> '') and SameText(LAutostart.ImagePath, LPath) then
    begin
      // Неподписанная программа из стандартной папки установки в автозапуске —
      // обычное дело (службы открытого ПО); само по себе не признак угрозы.
      if (LHasFile and (LFile.Signature = sgSignedUntrusted)) or
         (LHasFile and (LFile.Signature = sgUnsigned) and not MHIsStandardInstallLocation(LPath)) or
         MHIsSuspiciousLocation(LPath, LReason) or LMinerSignal then
      begin
        AddEvidence(LEvidence, EV_AUTOSTART, MHL('Программа закреплена в автозапуске',
          'The program is registered in autostart'), 15,
          MHAutostartKindTitle(LAutostart.Kind) + ': ' + LAutostart.Location);
        LThreatSignal := True;
      end;
      Break;
    end;

  // --- Признаки вмешательства, связанные с программой ---
  // Исключение антивируса учитывается только вместе с другими сигналами: иначе
  // каждая программа в папке проектов разработчика стала бы находкой.
  LTamperEvidence := MHTamperEvidenceFor(ASnapshot, LPath, AInfo.Name, LAvExcluded);
  for LTamperItem in LTamperEvidence do
    if (LTamperItem.Code <> EV_AV_EXCLUDED) or LSustained or LGpuSustained or LComputeBackground or
       LMinerSignal or LThreatSignal then
    begin
      LEvidence := LEvidence + [LTamperItem];
      LThreatSignal := True;
    end;

  // --- Отклонение от нормы этого компьютера ---
  if ABaseline.IsEstablished(ASettings.BaselineMinSamples) then
  begin
    if ABaseline.FindProcess(LKey, LBaseProcess) and LBaseProcess.Cpu.HasData then
    begin
      if LSustained and (LAvg > LBaseProcess.Cpu.P95 + 10) then
        AddEvidence(LEvidence, EV_ABOVE_BASELINE, MHL('Нагрузка выше обычной для этого компьютера',
          'The load is higher than usual for this computer'), 10,
          Format(MHL('сейчас %s, обычно до %s (%s)', 'now %s, usually up to %s (%s)'), [FormatPercent(LAvg), FormatPercent(LBaseProcess.Cpu.P95),
            MHWorkContextToString(ABaseline.Context)]))
      else if LSustained and (LAvg <= LBaseProcess.Cpu.P95 * 1.2) and not LMinerSignal and not LThreatSignal then
        AddEvidence(LEvidence, EV_TYPICAL, MHL('Такая нагрузка обычна для этого компьютера',
          'This load is typical for this computer'), -10,
          Format(MHL('обычно до %s', 'usually up to %s'), [FormatPercent(LBaseProcess.Cpu.P95)]));
    end
    else if LSustained then
      AddEvidence(LEvidence, EV_ABOVE_BASELINE, MHL('Новая программа, которой не было в профиле нормы',
        'A new program that was not in the baseline profile'), 10);
  end
  else if LSustained then
    AddUnique(LMissing, MHL('Профиль нормы ещё не сформирован — сравнение с обычной работой недоступно',
      'The baseline profile is not built yet — comparison with normal activity is unavailable'));

  // --- Оправдывающие факторы ---
  if LHasFile and (LFile.Signature = sgSignedTrusted) and not LThreatSignal then
  begin
    if MHIsStandardInstallLocation(LPath) and LFile.Signer.Contains('Microsoft') then
      AddEvidence(LEvidence, EV_SIGNED_TRUSTED, MHL('Подписан Microsoft, расположен в системной папке',
        'Signed by Microsoft, located in a system folder'), -25,
        LFile.Signer)
    else
      AddEvidence(LEvidence, EV_SIGNED_TRUSTED, MHL('Подписан доверенным издателем',
        'Signed by a trusted publisher'), -15, LFile.Signer);
  end;
  if ASnapshot.Context.Available then
  begin
    if ASnapshot.Context.FullscreenActive and (ASnapshot.Context.ForegroundPid = AInfo.Id.Pid) then
      AddEvidence(LEvidence, EV_FULLSCREEN, MHL('Это активное полноэкранное приложение (игра, видео, презентация)',
        'This is the active full-screen application (game, video, presentation)'), -20)
    else if (ASnapshot.Context.ForegroundPid = AInfo.Id.Pid) and
            (ASnapshot.Context.UserIdleSeconds < IDLE_SECONDS) then
      AddEvidence(LEvidence, EV_USER_ACTIVE, MHL('Пользователь сейчас работает с этой программой',
        'The user is currently working with this program'), -20)
    else if AInfo.HasVisibleWindow and (ASnapshot.Context.UserIdleSeconds < IDLE_SECONDS) then
      AddEvidence(LEvidence, EV_USER_ACTIVE, MHL('У программы есть открытое окно',
        'The program has an open window'), -10);
  end
  else
  begin
    AddUnique(LMissing, MHL('Нет данных о работе пользователя (активное окно, бездействие)',
      'No data on user activity (active window, idle time)'));
    LConfidence := LConfidence - 0.1;
  end;
  LWorkload := MHWorkloadCategoryOf(AInfo.Name, LPath);
  if LWorkload <> wlNone then
  begin
    if (LThreatSignal or LMinerSignal) or (LHasFile and (LFile.Signature in [sgUnsigned, sgSignedUntrusted]) and
       not MHIsStandardInstallLocation(LPath)) then
      AddEvidence(LEvidence, EV_WORKLOAD_MISMATCH,
        MHL('Имя совпадает с известной программой, но подпись или расположение необычны',
          'The name matches a known program, but its signature or location is unusual'), 10,
        MHWorkloadCategoryToString(LWorkload))
    else if LSustained or LGpuSustained or LComputeBackground then
      AddEvidence(LEvidence, EV_KNOWN_WORKLOAD, MHL('Похоже на обычную ресурсоёмкую задачу',
        'Looks like a normal resource-intensive task'), -20,
        MHWorkloadCategoryToString(LWorkload));
  end;

  // --- Итог ---
  LRaw := 0;
  for LTotal := 0 to High(LEvidence) do
    Inc(LRaw, LEvidence[LTotal].Weight);
  // Без единого положительного признака находки нет.
  if Length(LEvidence) = 0 then
    Exit;
  if (MHClampScore(LRaw) < ASettings.Thresholds.Low) then
    Exit;
  // Фоновые вычисления на GPU вместе с неподписанным файлом или другим признаком
  // угрозы — это уже признаки майнинга; сами по себе (BOINC, обучение нейросетей) — нет.
  if LComputeBackground and (LThreatSignal or HasCode(LEvidence, EV_UNSIGNED)) then
    LMinerSignal := True;
  if (LSustained or LLoadHigh) and
     not (ASnapshot.FindMetric(mkGpuPercent, LGpuMetric) and LGpuMetric.HasValue) then
    AddUnique(LMissing, MHL('Загрузка видеокарты недоступна — майнинг на GPU не проверен',
      'GPU load is unavailable — GPU mining not checked'));

  if HasCode(LEvidence, EV_LOCATION) or HasCode(LEvidence, EV_UNSIGNED) or LMinerSignal or
     HasCode(LEvidence, EV_MASQUERADE) or HasCode(LEvidence, EV_NAME_LOOKALIKE) then
    AddUnique(LRecommend, MHL('Проверьте файл через Microsoft Defender (кнопка «Проверить в Defender»).',
      'Scan the file with Microsoft Defender (the "Scan with Defender" button).'));
  AddUnique(LRecommend, MHL('Откройте расположение файла и убедитесь, что вы знаете эту программу.',
    'Open the file location and make sure you know this program.'));
  if HasCode(LEvidence, EV_MASQUERADE) or HasCode(LEvidence, EV_NAME_LOOKALIKE) then
    AddUnique(LRecommend, MHL('Системные файлы Windows находятся только в папке Windows — подделка имени является частым приёмом маскировки.',
      'Windows system files are located only in the Windows folder — faking the name is a common disguise technique.'));
  if LHasBinaryVerdict then
    AddUnique(LRecommend, MHL('Подробный разбор файла (структура, строки, вложения, аномалии) — в BinaryLab.',
      'A detailed file breakdown (structure, strings, embedded objects, anomalies) is available in BinaryLab.'));
  if HasCode(LEvidence, EV_HIDES_FROM_MONITOR) then
    AddUnique(LRecommend, MHL('Снижение нагрузки при открытии диспетчера задач характерно для скрытых майнеров — понаблюдайте за процессом с закрытым диспетчером.',
      'Reducing load when Task Manager opens is typical of hidden miners — observe the process with Task Manager closed.'));
  if HasCode(LEvidence, EV_AUTOSTART) then
    AddUnique(LRecommend, MHL('Проверьте запись автозапуска. Не удаляйте её, пока не убедились, что программа вам не нужна.',
      'Check the autostart entry. Do not delete it until you are sure you do not need the program.'));
  if (LSustained or LGpuSustained or LComputeBackground) and not LMinerSignal then
    AddUnique(LRecommend, MHL('Если это ваша программа (рендеринг, вычисления на процессоре или видеокарте, ',
      'If this is your program (rendering, CPU or GPU computing, ') +
      MHL('майнинг по вашему желанию) — добавьте её в исключения.',
        'mining by your choice) — add it to exclusions.'));
  if LMinerSignal or LThreatSignal then
    AddUnique(LRecommend, MHL('Чтобы остановить процесс, используйте «Остановить процесс» — действие потребует подтверждения.',
      'To stop the process, use "Stop process" — the action will require confirmation.'));

  if LState <> nil then
    LCount := LState.Samples.Count
  else
    LCount := 0;
  if (LCount > 0) and (LSustained or LLoadHigh) and
     ((LNow - LState.Samples[0].TimeUtc) < ASettings.SustainedMinutes * MINUTE * 0.9) then
    LConfidence := LConfidence - 0.2;
  if not ABaseline.IsEstablished(ASettings.BaselineMinSamples) and LSustained then
    LConfidence := LConfidence - 0.1;

  AFinding.Process := AInfo.Id;
  AFinding.ParentPid := AInfo.ParentPid;
  AFinding.ProcessName := AInfo.Name;
  AFinding.ImagePath := LPath;
  AFinding.Evidence := LEvidence;
  AFinding.MissingData := LMissing;
  AFinding.Recommendations := LRecommend;
  AFinding.RawScore := LRaw;
  AFinding.Score := MHClampScore(LRaw);
  AFinding.Level := ASettings.Thresholds.LevelOf(AFinding.Score);
  AFinding.Confidence := EnsureRange(LConfidence, 0.1, 1.0);
  AFinding.RulesetVersion := GetRulesetVersion;
  AFinding.DetectedAtUtc := LNow;
  if LMinerSignal then
  begin
    AFinding.Category := fcMining;
    AFinding.Title := MHL('Признаки скрытого майнинга: ', 'Signs of hidden mining: ') + AInfo.Name;
  end
  else if LThreatSignal then
  begin
    if HasCode(LEvidence, EV_AUTOSTART) and not HasCode(LEvidence, EV_MASQUERADE) then
      AFinding.Category := fcPersistence
    else
      AFinding.Category := fcSuspicious;
    AFinding.Title := MHL('Подозрительный процесс: ', 'Suspicious process: ') + AInfo.Name;
  end
  else
  begin
    AFinding.Category := fcPerformance;
    AFinding.Title := MHL('Необычная фоновая нагрузка: ', 'Unusual background load: ') + AInfo.Name;
  end;
  AFinding.Summary := Format(MHL('%s. Оценка %d из 100 (%s), уверенность %s. Это повод для проверки, а не диагноз.',
    '%s. Score %d of 100 (%s), confidence %s. This is a reason to check, not a diagnosis.'),
    [MHFindingCategoryTitle(AFinding.Category), AFinding.Score, MHRiskLevelToString(AFinding.Level),
     FormatPercent(AFinding.Confidence * 100)]);
  AFinding.Key := Format('process:%s:%s', [LKey, MHFindingCategoryToString(AFinding.Category)]);
  AFinding.Id := MHFindingIdFromKey(AFinding.Key + ':' + AInfo.Id.ToString);
  Result := True;
end;

function TMHThreatAnalyzer.AnalyzeAutostart(const ASnapshot: TMHSnapshot;
  const AEntry: TMHAutostartEntry; const ASettings: TMHAnalyzerSettings;
  out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LMissing, LRecommend: TArray<string>;
  LReason, LName, LSystemName, LKey, LFolder, LObfuscation: string;
  LFile: TMHFileInfo;
  LHasFile, LThreat, LStandard: Boolean;
  LDirs: TArray<string>;
  LRaw, I: Integer;
begin
  Result := False;
  AFinding := Default(TMHFinding);
  if (AEntry.ImagePath = '') or not AEntry.Enabled then
    Exit;
  LKey := MHProgramKey(AEntry.ImagePath, AEntry.Name);
  LHasFile := ASnapshot.FindFile(AEntry.ImagePath, LFile);
  if IsExcluded(LKey, IfThen(LHasFile, LFile.Sha256, '')) then
    Exit;
  LEvidence := nil;
  LMissing := nil;
  LRecommend := nil;
  LThreat := False;
  LName := ExtractFileName(AEntry.ImagePath);

  LStandard := MHIsStandardInstallLocation(AEntry.ImagePath);
  if MHIsSuspiciousLocation(AEntry.ImagePath, LReason) then
  begin
    AddEvidence(LEvidence, EV_LOCATION, MHL('Автозапуск программы из необычного места',
      'Autostart of a program from an unusual location'), 20, LReason);
    LThreat := True;
  end;
  if MHIsScriptFile(AEntry.ImagePath) and not LStandard then
  begin
    AddEvidence(LEvidence, EV_SCRIPT_AUTOSTART,
      MHL('Автозапуск сценария (bat, vbs, ps1…) вне системных папок',
        'Autostart of a script (bat, vbs, ps1…) outside system folders'), 20, LName);
    LThreat := True;
  end;
  if not LStandard and MHFindRandomLookingFolder(AEntry.ImagePath, LFolder) then
  begin
    AddEvidence(LEvidence, EV_RANDOM_FOLDER, MHL('Файл лежит в папке со случайным именем',
      'The file is in a folder with a random name'), 15, LFolder);
    LThreat := True;
  end;
  if (AEntry.Kind = akScheduledTask) and
     (AEntry.Location.ToLower.StartsWith('\microsoft\windows') or AEntry.Name.ToLower.StartsWith('\microsoft\windows')) and
     not LStandard then
  begin
    AddEvidence(LEvidence, EV_TASK_MASQUERADE,
      MHL('Задание размещено среди системных заданий Windows, но запускает файл вне папок Windows и Program Files',
        'The task is placed among Windows system tasks but runs a file outside the Windows and Program Files folders'),
      25, AEntry.Name);
    LThreat := True;
  end;
  LObfuscation := MHFindObfuscatedCommand(AEntry.Command);
  if LObfuscation <> '' then
  begin
    AddEvidence(LEvidence, EV_OBFUSCATED_COMMAND, MHL('Команда автозапуска скрывает своё содержимое',
      'The autostart command hides its content'), 35,
      LObfuscation);
    LThreat := True;
  end
  else
  begin
    LObfuscation := MHFindHiddenScriptLaunch(AEntry.Command);
    if LObfuscation <> '' then
    begin
      AddEvidence(LEvidence, EV_HIDDEN_SCRIPT,
        MHL('Сценарий запускается скрыто (так делает и обычная автоматизация — проверьте, ваш ли это сценарий)',
          'The script is launched hidden (normal automation does this too — check whether this script is yours)'),
        20, LObfuscation);
      LThreat := True;
    end;
  end;
  if MHIsKnownMinerName(LName) then
  begin
    AddEvidence(LEvidence, EV_MINER_NAME, MHL('В автозапуске программа с именем известного майнера',
      'A program with the name of a known miner is in autostart'), 35, LName);
    LThreat := True;
  end;
  if MHFindMinerCommandToken(AEntry.Command) <> '' then
  begin
    AddEvidence(LEvidence, EV_MINER_CMDLINE, MHL('В команде автозапуска есть параметры майнинга',
      'The autostart command contains mining parameters'), 40,
      MHFindMinerCommandToken(AEntry.Command));
    LThreat := True;
  end;
  if MHIsSystemProcessName(LName, LDirs) and not MHIsStandardInstallLocation(AEntry.ImagePath) then
  begin
    AddEvidence(LEvidence, EV_MASQUERADE, MHL('Системное имя Windows вне системной папки',
      'A Windows system name outside a system folder'), 40, AEntry.ImagePath);
    LThreat := True;
  end
  else if MHLooksLikeSystemName(LName, LSystemName) then
  begin
    AddEvidence(LEvidence, EV_NAME_LOOKALIKE, MHL('Имя похоже на системное', 'The name resembles a system name'),
      25, LName + ' ≈ ' + LSystemName);
    LThreat := True;
  end;
  // Подпись и отсутствие файла учитываются только вместе с другими признаками.
  if LThreat then
  begin
    if LHasFile and (LFile.Signature = sgUnsigned) then
      AddEvidence(LEvidence, EV_UNSIGNED, MHL('Файл без цифровой подписи', 'The file has no digital signature'), 10)
    else if LHasFile and (LFile.Signature = sgSignedUntrusted) then
      AddEvidence(LEvidence, EV_SIGNATURE_INVALID, MHL('Подпись недействительна', 'The signature is invalid'),
        25, LFile.Error)
    // Подпись не оправдывает угрозу в аргументах команды: подписанный powershell.exe
    // с закодированной командой остаётся подозрительным.
    else if LHasFile and (LFile.Signature = sgSignedTrusted) and
            not HasCode(LEvidence, EV_OBFUSCATED_COMMAND) and not HasCode(LEvidence, EV_MINER_CMDLINE) and
            not HasCode(LEvidence, EV_HIDDEN_SCRIPT) then
      AddEvidence(LEvidence, EV_SIGNED_TRUSTED, MHL('Подписан доверенным издателем',
        'Signed by a trusted publisher'), -15, LFile.Signer)
    else if not LHasFile or (LFile.Signature = sgNotChecked) then
      AddUnique(LMissing, MHL('Цифровая подпись ещё не проверена', 'Digital signature not checked yet'));
    // Только при реальной ошибке доступа: «проверка запланирована» — это ещё не проверенный файл.
    if LHasFile and (LFile.Signature = sgCheckFailed) and (LFile.SizeBytes < 0) then
      AddEvidence(LEvidence, EV_FILE_MISSING, MHL('Файл из автозапуска недоступен или отсутствует',
        'The autostart file is unavailable or missing'), 5, LFile.Error);
  end;
  if not LThreat then
    Exit;
  LRaw := 0;
  for I := 0 to High(LEvidence) do
    Inc(LRaw, LEvidence[I].Weight);
  if MHClampScore(LRaw) < ASettings.Thresholds.Low then
    Exit;

  AddUnique(LRecommend, MHL('Проверьте файл через Microsoft Defender.', 'Scan the file with Microsoft Defender.'));
  AddUnique(LRecommend, MHL('Проверьте запись автозапуска: ', 'Check the autostart entry: ') +
    MHAutostartKindTitle(AEntry.Kind) + ', ' + AEntry.Location +
    MHL('. Не удаляйте её, пока не убедились, что программа вам не нужна.',
      '. Do not delete it until you are sure you do not need the program.'));
  AFinding.Category := fcPersistence;
  AFinding.ProcessName := LName;
  AFinding.ImagePath := AEntry.ImagePath;
  AFinding.Title := MHL('Подозрительный автозапуск: ', 'Suspicious autostart: ') + AEntry.Name;
  AFinding.Evidence := LEvidence;
  AFinding.MissingData := LMissing;
  AFinding.Recommendations := LRecommend;
  AFinding.RawScore := LRaw;
  AFinding.Score := MHClampScore(LRaw);
  AFinding.Level := ASettings.Thresholds.LevelOf(AFinding.Score);
  AFinding.Confidence := IfThen(Length(LMissing) > 0, 0.85, 1.0);
  AFinding.RulesetVersion := GetRulesetVersion;
  AFinding.DetectedAtUtc := ASnapshot.TimestampUtc;
  AFinding.Summary := Format(MHL('Команда: %s. Оценка %d из 100 (%s). Это повод для проверки, а не диагноз.',
    'Command: %s. Score %d of 100 (%s). This is a reason to check, not a diagnosis.'),
    [AEntry.Command, AFinding.Score, MHRiskLevelToString(AFinding.Level)]);
  AFinding.Key := Format('autostart:%s:%s:%s', [MHAutostartKindToString(AEntry.Kind),
    AEntry.Location.ToLower, AEntry.Name.ToLower]);
  AFinding.Id := MHFindingIdFromKey(AFinding.Key);
  Result := True;
end;

procedure TMHThreatAnalyzer.AnalyzeSystem(const ASnapshot: TMHSnapshot;
  const ABaseline: TMHBaseline; const ASettings: TMHAnalyzerSettings; AFindings: TList<TMHFinding>);

  function SustainedAbove(AResource: TSystemResource; AThreshold: Double; out AAverage: Double): Boolean;
  var
    I, LCount, LAbove: Integer;
    LFirst: TDateTime;
    LValue: Double;
    LHas: Boolean;
  begin
    LCount := 0;
    LAbove := 0;
    AAverage := 0;
    LFirst := 0;
    for I := 0 to FSystem.Count - 1 do
    begin
      if FSystem[I].TimeUtc < ASnapshot.TimestampUtc - ASettings.SustainedMinutes * MINUTE then
        Continue;
      LHas := FSystem[I].Has[AResource];
      LValue := FSystem[I].Values[AResource];
      if not LHas then
        Continue;
      if LCount = 0 then
        LFirst := FSystem[I].TimeUtc;
      Inc(LCount);
      AAverage := AAverage + LValue;
      if LValue >= AThreshold then
        Inc(LAbove);
    end;
    if LCount > 0 then
      AAverage := AAverage / LCount;
    Result := (LCount >= 2) and (LAbove >= LCount * 0.8) and
      ((ASnapshot.TimestampUtc - LFirst) >= ASettings.SustainedMinutes * MINUTE * 0.9);
  end;

  procedure AddSystemFinding(const AResource, ATitle, AKey: string; AAverage: Double;
    const ABaselineStat: TMHStat; const AEvidenceCode: string = EV_SYSTEM_LOAD;
    const AObserved: string = ''; const ARecommendation: string = '');
  var
    LFinding: TMHFinding;
    LReasons: TArray<TMHLoadReason>;
    LReason: TMHLoadReason;
    LText: string;
  begin
    LFinding := Default(TMHFinding);
    LFinding.Category := fcPerformance;
    LFinding.Title := ATitle;
    LFinding.Key := AKey;
    LFinding.Id := MHFindingIdFromKey(AKey);
    if AObserved <> '' then
      LFinding.Evidence := [TMHEvidence.Create(AEvidenceCode, ATitle, 20, AObserved)]
    else
      LFinding.Evidence := [TMHEvidence.Create(AEvidenceCode, ATitle, 20,
        Format(MHL('в среднем %s за %d мин', 'average %s over %d min'),
          [FormatPercent(AAverage), ASettings.SustainedMinutes]))];
    if ABaselineStat.HasData then
      LFinding.Evidence := LFinding.Evidence + [TMHEvidence.Create(EV_ABOVE_BASELINE,
        MHL('Выше обычного для этого компьютера', 'Higher than usual for this computer'), 10,
        Format(MHL('обычно до %s', 'usually up to %s'), [FormatPercent(ABaselineStat.P95)]))];
    LText := '';
    LReasons := MHExplainLoad(ASnapshot, FCpuCount);
    for LReason in LReasons do
      if LReason.Resource = AResource then
        LText := LReason.Text;
    LFinding.Summary := MHL('Причина замедления, а не угроза и не диагноз. ',
      'A cause of slowdown, not a threat and not a diagnosis. ') + LText;
    LFinding.RawScore := 20 + IfThen(ABaselineStat.HasData, 10, 0);
    LFinding.Score := LFinding.RawScore;
    LFinding.Level := ASettings.Thresholds.LevelOf(LFinding.Score);
    LFinding.Confidence := 1.0;
    LFinding.RulesetVersion := GetRulesetVersion;
    LFinding.DetectedAtUtc := ASnapshot.TimestampUtc;
    if ARecommendation <> '' then
      LFinding.Recommendations := [ARecommendation]
    else
      LFinding.Recommendations := [MHL('Посмотрите на странице «Процессы», какие программы создают нагрузку, ',
        'Check on the "Processes" page which programs create the load, ') +
        MHL('и закройте ненужные.', 'and close the ones you do not need.')];
    AFindings.Add(LFinding);
  end;

  /// Самое горячее устройство вида AKind и его порог (для текста находки).
  function HottestOf(AKind: TMHSensorKind; out AReading: TMHSensorReading): Boolean;
  var
    LReading: TMHSensorReading;
  begin
    Result := False;
    for LReading in ASnapshot.Sensors do
      if (LReading.Kind = AKind) and (not Result or
         (LReading.Celsius - MHTemperatureLimit(LReading) > AReading.Celsius - MHTemperatureLimit(AReading))) then
      begin
        AReading := LReading;
        Result := True;
      end;
  end;

  procedure CheckHeat(AResource: TSystemResource; AKind: TMHSensorKind; const AKey, ATitle,
    ARecommendation: string);
  var
    LMargin: Double;
    LReading: TMHSensorReading;
  begin
    // Температура держится на пороге устройства или выше (запас <= 0) почти весь интервал.
    if SustainedAbove(AResource, 0, LMargin) and HottestOf(AKind, LReading) then
      AddSystemFinding(MHHeatResourceName(AKind), ATitle, AKey, 0, Default(TMHStat), EV_OVERHEAT,
        Format(MHL('%s: %.0f °C, порог %.0f °C, держится %d мин', '%s: %.0f °C, limit %.0f °C, for %d min'), [LReading.Device, LReading.Celsius,
          MHTemperatureLimit(LReading), ASettings.SustainedMinutes]), ARecommendation);
  end;

var
  LAverage: Double;
  LThreshold: Double;
begin
  // Процессор: выше 85% или выше нормы на 15 п.п.
  LThreshold := 85;
  if ABaseline.IsEstablished(ASettings.BaselineMinSamples) and ABaseline.SystemCpu.HasData then
    LThreshold := Min(LThreshold, Max(50, ABaseline.SystemCpu.P95 + 15));
  if SustainedAbove(srCpu, LThreshold, LAverage) then
    AddSystemFinding('cpu', MHL('Процессор долго загружен почти полностью',
      'The CPU has been almost fully loaded for a long time'), 'system:cpu', LAverage,
      ABaseline.SystemCpu);
  if SustainedAbove(srMemory, 90, LAverage) then
    AddSystemFinding('memory', MHL('Оперативная память почти заполнена', 'RAM is almost full'),
      'system:memory', LAverage, ABaseline.MemoryLoad);
  if SustainedAbove(srDisk, 90, LAverage) then
    AddSystemFinding('disk', MHL('Диск постоянно занят', 'The disk is constantly busy'), 'system:disk',
      LAverage, ABaseline.DiskActive);
  if SustainedAbove(srGpu, 90, LAverage) then
    AddSystemFinding('gpu', MHL('Видеокарта долго загружена почти полностью',
      'The GPU has been almost fully loaded for a long time'), 'system:gpu', LAverage,
      Default(TMHStat));
  // Троттлинг: прошивка ограничивает производительность процессора (перегрев или питание).
  if SustainedAbove(srThrottle, 10, LAverage) then
    AddSystemFinding('throttle', MHL('Процессор снижает производительность (троттлинг)',
      'The CPU is reducing performance (throttling)'), 'system:throttle',
      LAverage, Default(TMHStat), EV_THROTTLING,
      Format(MHL('производительность ограничена в среднем до %s', 'performance limited to %s on average'),
        [FormatPercent(100 - LAverage)]),
      MHL('Проверьте охлаждение (пыль, вентиляторы, термопасту) и режим электропитания. ',
        'Check the cooling (dust, fans, thermal paste) and the power plan. ') +
      MHL('Ограничение снижает скорость работы, пока не устранена причина.',
        'The limit slows the computer down until the cause is fixed.'));
  CheckHeat(srGpuHeat, skGpu, 'system:heat:gpu', MHL('Видеокарта работает на пределе температуры',
    'The GPU is running at its temperature limit'),
    MHL('Видеокарта при этой температуре снижает частоту. Проверьте, какая программа её нагружает ',
      'At this temperature the GPU lowers its clock speed. Check which program is loading it ') +
    MHL('(колонка «GPU» на странице «Процессы»), и состояние охлаждения.',
      '(the "GPU" column on the "Processes" page) and the state of the cooling.'));
  CheckHeat(srDiskHeat, skDisk, 'system:heat:disk', MHL('Накопитель перегревается', 'The drive is overheating'),
    MHL('Длительный перегрев сокращает срок службы накопителя и снижает скорость. ',
      'Prolonged overheating shortens the drive''s lifespan and reduces its speed. ') +
    MHL('Проверьте обдув корпуса; сделайте резервную копию важных данных.',
      'Check the case airflow; back up important data.'));
  CheckHeat(srCpuHeat, skCpu, 'system:heat:cpu', MHL('Процессор перегревается', 'The CPU is overheating'),
    MHL('Проверьте охлаждение процессора и программы, которые его нагружают.',
      'Check the CPU cooling and the programs that load it.'));
end;

/// Память процесса как в диспетчере задач: частный рабочий набор, иначе рабочий набор.
function MemoryOf(const AInfo: TMHProcessInfo): TMHMetric;
begin
  if AInfo.PrivateWorkingSet.HasValue then
    Result := AInfo.PrivateWorkingSet
  else
    Result := AInfo.WorkingSet;
end;

/// Ресурс процесса: 0 — CPU, 1 — память, 2 — GPU.
function ValueOf(const AInfo: TMHProcessInfo; AResource: Integer): TMHMetric;
begin
  case AResource of
    0: Result := AInfo.Cpu;
    1: Result := MemoryOf(AInfo);
  else
    Result := AInfo.Gpu;
  end;
end;

function MHExplainLoad(const ASnapshot: TMHSnapshot; ACpuCount: Integer;
  ATop: Integer): TArray<TMHLoadReason>;

  function Describe(const AInfo: TMHProcessInfo; AValue: string): string;
  var
    LCategory: TMHWorkloadCategory;
  begin
    Result := AInfo.Name + ' ' + AValue;
    LCategory := MHWorkloadCategoryOf(AInfo.Name, AInfo.ImagePath);
    if LCategory <> wlNone then
      Result := Result + ' (' + MHWorkloadCategoryToString(LCategory) + ')';
  end;

  /// Основные потребители: 0 — CPU, 1 — память, 2 — GPU.
  function TopBy(AResource: Integer): string;
  var
    LList: TList<TMHProcessInfo>;
    LInfo: TMHProcessInfo;
    LValue: TMHMetric;
    I: Integer;
  begin
    Result := '';
    LList := TList<TMHProcessInfo>.Create;
    try
      for LInfo in ASnapshot.Processes do
      begin
        LValue := ValueOf(LInfo, AResource);
        if LValue.HasValue and ((AResource = 1) or (LValue.Value >= 1)) and
           not SameText(LInfo.SourceId, MH_SELF_SOURCE_ID) then
          LList.Add(LInfo);
      end;
      LList.Sort(TComparer<TMHProcessInfo>.Construct(
        function(const A, B: TMHProcessInfo): Integer
        begin
          Result := CompareValue(ValueOf(B, AResource).Value, ValueOf(A, AResource).Value);
          if Result = 0 then
            Result := CompareText(A.Name, B.Name);
        end));
      for I := 0 to Min(ATop, LList.Count) - 1 do
      begin
        if Result <> '' then
          Result := Result + ', ';
        case AResource of
          0: Result := Result + Describe(LList[I], FormatPercent(LList[I].Cpu.Value));
          1: Result := Result + Describe(LList[I], FormatFloat('0', MemoryOf(LList[I]).Value / 1048576) +
            MHL(' МБ', ' MB'));
        else
          if LList[I].GpuCompute.HasValue and (LList[I].GpuCompute.Value >= 1) then
            Result := Result + Describe(LList[I], FormatPercent(LList[I].Gpu.Value) + MHL(', вычисления ', ', compute ') +
              FormatPercent(LList[I].GpuCompute.Value))
          else
            Result := Result + Describe(LList[I], FormatPercent(LList[I].Gpu.Value));
        end;
      end;
    finally
      LList.Free;
    end;
  end;

  procedure AddHeat(AKind: TMHSensorKind; const ADeviceTitle: string; var AResult: TArray<TMHLoadReason>);
  var
    LReading, LHottest: TMHSensorReading;
    LFound: Boolean;
    LReason: TMHLoadReason;
    LLimit: Double;
  begin
    LFound := False;
    for LReading in ASnapshot.Sensors do
      if (LReading.Kind = AKind) and (not LFound or
         (LReading.Celsius - MHTemperatureLimit(LReading) > LHottest.Celsius - MHTemperatureLimit(LHottest))) then
      begin
        LHottest := LReading;
        LFound := True;
      end;
    if not LFound then
      Exit;
    LLimit := MHTemperatureLimit(LHottest);
    LReason.Resource := MHHeatResourceName(AKind);
    // «Высокая» — ближе 5 °C к порогу устройства.
    LReason.IsHigh := LHottest.Celsius >= LLimit - 5;
    LReason.Text := Format('%s %s: %.0f °C', [ADeviceTitle, LHottest.Device, LHottest.Celsius]);
    if LHottest.LimitCelsius > 0 then
      LReason.Text := LReason.Text + Format(MHL(' (порог производителя %.0f °C)',
        ' (manufacturer limit %.0f °C)'), [LLimit]);
    if LReason.IsHigh then
      LReason.Text := LReason.Text + MHL(' — горячо: при такой температуре устройство снижает скорость',
        ' — hot: at this temperature the device slows down');
    AResult := AResult + [LReason];
  end;

var
  LMetric: TMHMetric;
  LReason: TMHLoadReason;
  LTop: string;
  LDisk: TMHDiskInfo;
  LVolume: TMHVolumeInfo;
begin
  Result := nil;
  if ASnapshot.FindMetric(mkCpuPercent, LMetric) and LMetric.HasValue then
  begin
    LReason.Resource := 'cpu';
    LReason.IsHigh := LMetric.Value >= 70;
    LTop := TopBy(0);
    LReason.Text := Format(MHL('Процессор загружен на %s', 'CPU load is %s'), [FormatPercent(LMetric.Value)]);
    if LTop <> '' then
      LReason.Text := LReason.Text + MHL('. Основная нагрузка: ', '. Main load: ') + LTop;
    Result := Result + [LReason];
  end;
  if ASnapshot.FindMetric(mkMemoryLoadPercent, LMetric) and LMetric.HasValue then
  begin
    LReason.Resource := 'memory';
    LReason.IsHigh := LMetric.Value >= 85;
    LTop := TopBy(1);
    LReason.Text := Format(MHL('Память занята на %s', 'Memory usage is %s'), [FormatPercent(LMetric.Value)]);
    if LTop <> '' then
      LReason.Text := LReason.Text + MHL('. Больше всего занимают: ', '. Largest consumers: ') + LTop;
    Result := Result + [LReason];
  end;
  if ASnapshot.FindMetric(mkDiskActivePercent, LMetric) and LMetric.HasValue then
  begin
    LReason.Resource := 'disk';
    LReason.IsHigh := LMetric.Value >= 80;
    LReason.Text := Format(MHL('Диск занят %s времени', 'The disk is busy %s of the time'),
      [FormatPercent(LMetric.Value)]);
    // Какой именно диск и кто его грузит (если известно).
    if (Length(ASnapshot.Disks) > 1) and MHBusiestDisk(ASnapshot, LDisk) then
      LReason.Text := LReason.Text + ' — ' + MHDiskLabel(LDisk);
    LTop := MHTopIoProcesses(ASnapshot, ATop);
    if LTop <> '' then
      LReason.Text := LReason.Text + MHL('. Больше всего читают и пишут: ', '. Most reading and writing: ') + LTop;
    Result := Result + [LReason];
  end;
  // Почти заполненные разделы — частая причина замедления.
  for LVolume in ASnapshot.Volumes do
    if MHVolumeSpaceLevel(LVolume) <> slOk then
    begin
      LReason.Resource := 'space';
      LReason.IsHigh := (MHVolumeSpaceLevel(LVolume) = slCritical) or LVolume.IsSystem;
      LReason.Text := Format(MHL('Мало места на разделе %s: свободно %s из %s',
        'Low space on volume %s: %s free of %s'),
        [LVolume.Name, MHFormatSize(LVolume.FreeBytes), MHFormatSize(LVolume.TotalBytes)]);
      Result := Result + [LReason];
    end;
  if ASnapshot.FindMetric(mkGpuPercent, LMetric) and LMetric.HasValue then
  begin
    LReason.Resource := 'gpu';
    LReason.IsHigh := LMetric.Value >= 80;
    LTop := TopBy(2);
    LReason.Text := Format(MHL('Видеокарта загружена на %s', 'GPU load is %s'), [FormatPercent(LMetric.Value)]);
    if LTop <> '' then
      LReason.Text := LReason.Text + MHL('. Основная нагрузка: ', '. Main load: ') + LTop;
    Result := Result + [LReason];
  end;
  // Троттлинг: прошивка ограничила производительность (перегрев или питание).
  if ASnapshot.FindMetric(mkCpuPerformanceLimitPercent, LMetric) and LMetric.HasValue then
  begin
    LReason.Resource := 'throttle';
    LReason.IsHigh := LMetric.Value < 90;
    if LReason.IsHigh then
      LReason.Text := Format(MHL('Процессор ограничен до %s производительности (перегрев или ограничение ',
        'The CPU is limited to %s of its performance (overheating or power ') +
        MHL('питания) — это замедляет работу', 'limit) — this slows the computer down'),
        [FormatPercent(LMetric.Value)])
    else
      LReason.Text := MHL('Процессор работает без ограничений производительности',
        'The CPU is running without performance limits');
    Result := Result + [LReason];
  end;
  AddHeat(skGpu, MHL('Видеокарта', 'GPU'), Result);
  AddHeat(skCpu, MHL('Процессор', 'CPU'), Result);
  AddHeat(skDisk, MHL('Накопитель', 'Drive'), Result);
end;

function MHHeatResourceName(AKind: TMHSensorKind): string;
begin
  case AKind of
    skGpu: Result := 'heat:gpu';
    skDisk: Result := 'heat:disk';
  else
    Result := 'heat:cpu';
  end;
end;

end.
