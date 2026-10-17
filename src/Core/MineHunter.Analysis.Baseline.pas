unit MineHunter.Analysis.Baseline;

{
  MineHunter X — профиль нормы компьютера (MH-06).

  - TMHBaselineBuilder: чистое детерминированное построение профиля по снимкам
    одного контекста работы (системные метрики и нагрузка отдельных программ).
  - TMHBaselineAccumulator: то же построение по снимкам, поступающим порциями
    (перестройка не держит в памяти всю выборку за период обучения).
  - TMHBaselineManager: хранит профили по контекстам в памяти, загружает их из
    хранилища при запуске и периодически перестраивает (Rebuild вызывается
    приложением из фонового потока). Чтение профиля потокобезопасно; блокировка
    не удерживается во время запросов к хранилищу и расчёта.
  - Сравнение с нормой: MHCompareStats / MHComparePeriods для системных метрик,
    MHCompareProcesses для программ. Вердикты — на русском языке для UI и отчётов.
}

interface

uses
  System.SysUtils, System.SyncObjs, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

const
  /// Отклонение медианы меньше этого значения (в процентах) — «в пределах нормы».
  MH_BASELINE_DEVIATION_PERCENT = 15.0;
  /// Минимум значений с каждой стороны, чтобы сравнение имело смысл.
  MH_BASELINE_MIN_COMPARE_SAMPLES = 10;
  /// Для метрик в процентах разница меньше этого числа процентных пунктов
  /// не считается отклонением (1% против 1,5% CPU — не «выше нормы на 50%»).
  MH_BASELINE_MIN_ABS_DELTA_POINTS = 2.0;

type
  /// Хранилище профилей и выборок истории для построения нормы.
  /// Реализуется TMHSQLiteRepository; в тестах подменяется двойником.
  IMHBaselineStore = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C61}']
    procedure SaveBaseline(const ABaseline: TMHBaseline);
    /// Сохранённые профили; повреждённые записи пропускаются.
    function LoadBaselines: TArray<TMHBaseline>;
    /// Не более AMaxCount снимков контекста AContext, равномерно прореженных
    /// по интервалу [AFromUtc; AToUtc], по возрастанию времени.
    function LoadSnapshotsSampled(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer;
      AContext: TMHWorkContext): TArray<TMHSnapshot>;
  end;

  /// Пошаговое построение профиля нормы: снимки добавляются в порядке времени
  /// (можно порциями), Finish возвращает профиль. Результат совпадает с
  /// TMHBaselineBuilder.Build по тем же снимкам. Не потокобезопасен.
  TMHBaselineAccumulator = class
  private type
    /// Накопитель значений одной программы.
    TProgramAccumulator = class
    public
      Name: string;
      Cpu: TList<Double>;
      WorkingSet: TList<Double>;
      Presence: Integer;
      constructor Create(const AName: string);
      destructor Destroy; override;
    end;
    /// Сумма нагрузки программы в одном снимке.
    TProgramSample = record
      Name: string;
      CpuSum: Double;
      HasCpu: Boolean;
      WorkingSetSum: Double;
      HasWorkingSet: Boolean;
    end;
  private
    FContext: TMHWorkContext;
    FNowUtc: TDateTime;
    FCount: Integer;
    FPeriodFromUtc, FPeriodToUtc: TDateTime;
    FCpu, FMemory, FDisk: TList<Double>;
    FPrograms: TObjectDictionary<string, TProgramAccumulator>;
    FInSnapshot: TDictionary<string, TProgramSample>;
  public
    constructor Create(AContext: TMHWorkContext; ANowUtc: TDateTime);
    destructor Destroy; override;
    procedure Add(const ASnapshot: TMHSnapshot); overload;
    procedure Add(const ASnapshots: TArray<TMHSnapshot>); overload;
    /// Профиль по добавленным снимкам; остаются AMaxProcesses программ
    /// с наибольшей долей присутствия.
    function Finish(AMaxProcesses: Integer = 300): TMHBaseline;
    /// Сколько снимков добавлено.
    property Count: Integer read FCount;
  end;

  /// Построение профиля нормы. Чистые функции без состояния.
  TMHBaselineBuilder = class
  public
    /// Профиль контекста AContext по снимкам ASnapshots.
    /// Системные метрики: mkCpuPercent, mkMemoryLoadPercent, mkDiskActivePercent
    /// (значения «нет данных» пропускаются). Программы группируются по
    /// MHProgramKey; нагрузка нескольких экземпляров одной программы в снимке
    /// суммируется. Остаются AMaxProcesses программ с наибольшей долей
    /// присутствия; результат упорядочен по ключу.
    class function Build(AContext: TMHWorkContext; const ASnapshots: TArray<TMHSnapshot>;
      ANowUtc: TDateTime; AMaxProcesses: Integer = 300): TMHBaseline; static;
  end;

  /// Профили нормы по контекстам работы (реализация IMHBaselineProvider).
  TMHBaselineManager = class(TInterfacedObject, IMHBaselineProvider)
  public const
    /// Контексты, для которых строится профиль.
    Contexts: array[0..2] of TMHWorkContext = (wcIdle, wcWork, wcGaming);
    /// На столько равных интервалов делится период обучения при перестройке:
    /// в памяти одновременно находится выборка только одного интервала.
    RebuildChunks = 10;
  private
    FLock: TCriticalSection;
    /// Исключает одновременную перестройку из нескольких потоков.
    FRebuildLock: TCriticalSection;
    FStore: IMHBaselineStore;
    FClock: IMHClock;
    FLogger: IMHLogger;
    FLearningDays: Integer;
    FSamplesPerContext: Integer;
    FProfiles: array[TMHWorkContext] of TMHBaseline;
    FLastRebuildUtc: TDateTime;
    procedure Log(ALevel: TMHLogLevel; const AMessage: string);
    function GetLastRebuildUtc: TDateTime;
    procedure SetLearningDays(AValue: Integer);
    /// Строит и сохраняет профиль одного контекста; False — профиль не изменён.
    function RebuildContext(AContext: TMHWorkContext; ANowUtc: TDateTime): Boolean;
  public
    constructor Create(const AStore: IMHBaselineStore; const AClock: IMHClock;
      const ALogger: IMHLogger; ALearningDays: Integer = 3; ASamplesPerContext: Integer = 5000);
    destructor Destroy; override;

    { IMHBaselineProvider }
    /// Профиль из памяти; TMHBaseline.Empty с заданным Context, если его ещё нет.
    function BaselineFor(AContext: TMHWorkContext): TMHBaseline;

    /// Загружает сохранённые профили (вызывается при запуске). Ошибки
    /// записываются в журнал, профили в памяти при этом не меняются.
    procedure LoadFromStore;
    /// Перестраивает профили всех контекстов по последним LearningDays дням.
    /// Для контекста без снимков и при ошибке сохраняется прежний профиль.
    /// Предназначен для вызова из фонового потока.
    procedure Rebuild;

    /// Период обучения в днях; изменение действует со следующей перестройки.
    /// Запись атомарна (выровненное Integer), поэтому безопасна из другого потока.
    property LearningDays: Integer read FLearningDays write SetLearningDays;
    property SamplesPerContext: Integer read FSamplesPerContext;
    /// Время последней перестройки без ошибок (0 — ещё не выполнялась).
    property LastRebuildUtc: TDateTime read GetLastRebuildUtc;
  end;

  /// Результат сравнения ряда значений с нормой.
  TMHMetricComparison = record
    Kind: TMHMetricKind;
    Current: TMHStat;
    Baseline: TMHStat;
    /// Относительное отклонение медианы, % (положительное — выше нормы).
    MedianDeltaPercent: Double;
    /// Относительное отклонение 95-го перцентиля, %.
    P95DeltaPercent: Double;
    HasBaseline: Boolean;
    Verdict: string;
  end;

  /// Программа, нагрузка которой превышает норму, или новая программа.
  TMHProcessDeviation = record
    Key: string;
    Name: string;
    CurrentCpuP95: Double;
    /// 0 для новой программы.
    BaselineCpuP95: Double;
    IsNewProgram: Boolean;
    Description: string;
  end;

/// Статистика ряда; точки «нет данных» пропускаются.
function MHStatsFromSeries(const ASeries: TArray<TMHMetric>): TMHStat;

/// Сравнение текущей статистики с нормой. Вердикт определяется отклонением
/// медианы: |delta| < 15% — «в пределах нормы»; иначе «выше/ниже нормы на N%».
/// Нет нормы — «нет данных о норме»; меньше 10 значений с любой стороны —
/// «мало данных для сравнения».
function MHCompareStats(AKind: TMHMetricKind; const ACurrent, ABaseline: TMHStat): TMHMetricComparison;

/// Сравнение системных метрик двух профилей (CPU, загрузка памяти, активность диска).
function MHComparePeriods(const ACurrent, ABaseline: TMHBaseline): TArray<TMHMetricComparison>;

/// Программы, у которых 95-й перцентиль CPU вырос не менее чем на
/// AMinCpuDeltaPercentPoints процентных пунктов, а также новые программы
/// (нет в норме) с p95 не ниже порога. Упорядочены по величине влияния.
function MHCompareProcesses(const ACurrent, ABaseline: TMHBaseline;
  AMinCpuDeltaPercentPoints: Double = 5): TArray<TMHProcessDeviation>;

implementation

uses
  System.Math, System.Generics.Defaults;

const
  BASELINE_SOURCE = 'baseline';

{ TMHBaselineAccumulator.TProgramAccumulator }

constructor TMHBaselineAccumulator.TProgramAccumulator.Create(const AName: string);
begin
  inherited Create;
  Name := AName;
  Cpu := TList<Double>.Create;
  WorkingSet := TList<Double>.Create;
end;

destructor TMHBaselineAccumulator.TProgramAccumulator.Destroy;
begin
  WorkingSet.Free;
  Cpu.Free;
  inherited;
end;

function StatOfList(AList: TList<Double>): TMHStat;
var
  LValues: TArray<Double>;
begin
  LValues := AList.ToArray;
  Result := TMHStat.FromValues(LValues);
end;

function IsPercentKind(AKind: TMHMetricKind): Boolean;
begin
  Result := AKind in [mkCpuPercent, mkGpuPercent, mkMemoryLoadPercent, mkDiskActivePercent];
end;

/// Относительное отклонение, %. Знаменатель не меньше 1, чтобы нулевая норма
/// не давала деления на ноль.
function RelativeDelta(ACurrent, ABaseline: Double): Double;
begin
  Result := (ACurrent - ABaseline) * 100 / Max(Abs(ABaseline), 1.0);
end;

{ TMHBaselineAccumulator }

constructor TMHBaselineAccumulator.Create(AContext: TMHWorkContext; ANowUtc: TDateTime);
begin
  inherited Create;
  FContext := AContext;
  FNowUtc := ANowUtc;
  FCpu := TList<Double>.Create;
  FMemory := TList<Double>.Create;
  FDisk := TList<Double>.Create;
  FPrograms := TObjectDictionary<string, TProgramAccumulator>.Create([doOwnsValues]);
  FInSnapshot := TDictionary<string, TProgramSample>.Create;
end;

destructor TMHBaselineAccumulator.Destroy;
begin
  FInSnapshot.Free;
  FPrograms.Free;
  FDisk.Free;
  FMemory.Free;
  FCpu.Free;
  inherited;
end;

procedure TMHBaselineAccumulator.Add(const ASnapshot: TMHSnapshot);
var
  LMetric: TMHMetric;
  LInfo: TMHProcessInfo;
  LKey: string;
  LSample: TProgramSample;
  LAcc: TProgramAccumulator;
begin
  if FCount = 0 then
  begin
    FPeriodFromUtc := ASnapshot.TimestampUtc;
    FPeriodToUtc := ASnapshot.TimestampUtc;
  end
  else
  begin
    FPeriodFromUtc := Min(FPeriodFromUtc, ASnapshot.TimestampUtc);
    FPeriodToUtc := Max(FPeriodToUtc, ASnapshot.TimestampUtc);
  end;
  Inc(FCount);

  if ASnapshot.FindMetric(mkCpuPercent, LMetric) and LMetric.HasValue then
    FCpu.Add(LMetric.Value);
  if ASnapshot.FindMetric(mkMemoryLoadPercent, LMetric) and LMetric.HasValue then
    FMemory.Add(LMetric.Value);
  if ASnapshot.FindMetric(mkDiskActivePercent, LMetric) and LMetric.HasValue then
    FDisk.Add(LMetric.Value);

  // Нагрузка всех экземпляров программы в снимке суммируется.
  FInSnapshot.Clear;
  for LInfo in ASnapshot.Processes do
  begin
    // Записи самодиагностики дублируют процесс MineHunter из коллектора процессов.
    if SameText(LInfo.SourceId, MH_SELF_SOURCE_ID) then
      Continue;
    LKey := MHProgramKey(LInfo.ImagePath, LInfo.Name);
    if LKey = '' then
      Continue;
    if not FInSnapshot.TryGetValue(LKey, LSample) then
    begin
      LSample := Default(TProgramSample);
      LSample.Name := LInfo.Name;
    end;
    if LInfo.Cpu.HasValue then
    begin
      LSample.CpuSum := LSample.CpuSum + LInfo.Cpu.Value;
      LSample.HasCpu := True;
    end;
    if LInfo.WorkingSet.HasValue then
    begin
      LSample.WorkingSetSum := LSample.WorkingSetSum + LInfo.WorkingSet.Value;
      LSample.HasWorkingSet := True;
    end;
    FInSnapshot.AddOrSetValue(LKey, LSample);
  end;

  for LKey in FInSnapshot.Keys do
  begin
    LSample := FInSnapshot[LKey];
    if not FPrograms.TryGetValue(LKey, LAcc) then
    begin
      LAcc := TProgramAccumulator.Create(LSample.Name);
      FPrograms.Add(LKey, LAcc);
    end;
    Inc(LAcc.Presence);
    if LSample.HasCpu then
      LAcc.Cpu.Add(LSample.CpuSum);
    if LSample.HasWorkingSet then
      LAcc.WorkingSet.Add(LSample.WorkingSetSum);
  end;
end;

procedure TMHBaselineAccumulator.Add(const ASnapshots: TArray<TMHSnapshot>);
var
  LSnapshot: TMHSnapshot;
begin
  for LSnapshot in ASnapshots do
    Add(LSnapshot);
end;

function TMHBaselineAccumulator.Finish(AMaxProcesses: Integer): TMHBaseline;
var
  LPrograms: TObjectDictionary<string, TProgramAccumulator>;
  LAcc: TProgramAccumulator;
  LKeys: TArray<string>;
  I: Integer;
begin
  Result := TMHBaseline.Empty;
  Result.Context := FContext;
  Result.CreatedUtc := FNowUtc;
  Result.UpdatedUtc := FNowUtc;
  Result.SampleCount := FCount;
  if FCount = 0 then
    Exit;
  Result.PeriodFromUtc := FPeriodFromUtc;
  Result.PeriodToUtc := FPeriodToUtc;
  Result.SystemCpu := StatOfList(FCpu);
  Result.MemoryLoad := StatOfList(FMemory);
  Result.DiskActive := StatOfList(FDisk);

  // Отбор: больше присутствие — важнее; при равенстве — по ключу (стабильно).
  LPrograms := FPrograms;
  LKeys := LPrograms.Keys.ToArray;
  TArray.Sort<string>(LKeys, TComparer<string>.Construct(
    function(const A, B: string): Integer
    begin
      Result := CompareValue(LPrograms[B].Presence, LPrograms[A].Presence);
      if Result = 0 then
        Result := CompareStr(A, B);
    end));
  if Length(LKeys) > Max(0, AMaxProcesses) then
    SetLength(LKeys, Max(0, AMaxProcesses));
  TArray.Sort<string>(LKeys, TStringComparer.Ordinal);

  SetLength(Result.Processes, Length(LKeys));
  for I := 0 to High(LKeys) do
  begin
    LAcc := LPrograms[LKeys[I]];
    Result.Processes[I].Key := LKeys[I];
    Result.Processes[I].Name := LAcc.Name;
    Result.Processes[I].Cpu := StatOfList(LAcc.Cpu);
    Result.Processes[I].WorkingSet := StatOfList(LAcc.WorkingSet);
    Result.Processes[I].PresenceRatio := LAcc.Presence / FCount;
  end;
end;

{ TMHBaselineBuilder }

class function TMHBaselineBuilder.Build(AContext: TMHWorkContext;
  const ASnapshots: TArray<TMHSnapshot>; ANowUtc: TDateTime;
  AMaxProcesses: Integer): TMHBaseline;
var
  LAccumulator: TMHBaselineAccumulator;
begin
  LAccumulator := TMHBaselineAccumulator.Create(AContext, ANowUtc);
  try
    LAccumulator.Add(ASnapshots);
    Result := LAccumulator.Finish(AMaxProcesses);
  finally
    LAccumulator.Free;
  end;
end;

{ TMHBaselineManager }

constructor TMHBaselineManager.Create(const AStore: IMHBaselineStore; const AClock: IMHClock;
  const ALogger: IMHLogger; ALearningDays, ASamplesPerContext: Integer);
var
  LContext: TMHWorkContext;
begin
  inherited Create;
  if AStore = nil then
    raise EArgumentNilException.Create('AStore');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if ALogger = nil then
    raise EArgumentNilException.Create('ALogger');
  FStore := AStore;
  FClock := AClock;
  FLogger := ALogger;
  FLearningDays := EnsureRange(ALearningDays, 1, 365);
  FSamplesPerContext := EnsureRange(ASamplesPerContext, 10, 1000000);
  for LContext := Low(TMHWorkContext) to High(TMHWorkContext) do
  begin
    FProfiles[LContext] := TMHBaseline.Empty;
    FProfiles[LContext].Context := LContext;
  end;
  FLock := TCriticalSection.Create;
  FRebuildLock := TCriticalSection.Create;
end;

destructor TMHBaselineManager.Destroy;
begin
  FRebuildLock.Free;
  FLock.Free;
  inherited;
end;

procedure TMHBaselineManager.Log(ALevel: TMHLogLevel; const AMessage: string);
begin
  try
    FLogger.Log(ALevel, BASELINE_SOURCE, AMessage);
  except
    // Сбой журнала не должен ломать работу с профилем нормы.
  end;
end;

procedure TMHBaselineManager.SetLearningDays(AValue: Integer);
begin
  FLearningDays := EnsureRange(AValue, 1, 365);
end;

function TMHBaselineManager.GetLastRebuildUtc: TDateTime;
begin
  FLock.Enter;
  try
    Result := FLastRebuildUtc;
  finally
    FLock.Leave;
  end;
end;

function TMHBaselineManager.BaselineFor(AContext: TMHWorkContext): TMHBaseline;
begin
  FLock.Enter;
  try
    Result := FProfiles[AContext];
  finally
    FLock.Leave;
  end;
end;

procedure TMHBaselineManager.LoadFromStore;
var
  LLoaded: TArray<TMHBaseline>;
  LBaseline: TMHBaseline;
begin
  try
    LLoaded := FStore.LoadBaselines;
  except
    on E: Exception do
    begin
      Log(llError, 'Не удалось загрузить профили нормы: ' + E.Message);
      Exit;
    end;
  end;
  FLock.Enter;
  try
    for LBaseline in LLoaded do
      FProfiles[LBaseline.Context] := LBaseline;
  finally
    FLock.Leave;
  end;
  Log(llInfo, Format('Загружено профилей нормы: %d', [Length(LLoaded)]));
end;

function TMHBaselineManager.RebuildContext(AContext: TMHWorkContext; ANowUtc: TDateTime): Boolean;
var
  LAccumulator: TMHBaselineAccumulator;
  LSnapshots: TArray<TMHSnapshot>;
  LBaseline, LOld: TMHBaseline;
  LFromUtc, LSpan, LChunkFrom, LChunkTo: TDateTime;
  LRemaining, LQuota, I: Integer;
begin
  Result := False;
  try
    // Запрос и расчёт выполняются без блокировки: BaselineFor не ждёт.
    // Период делится на RebuildChunks интервалов; квота интервала — поровну от
    // оставшегося лимита, поэтому неиспользованная часть переходит к следующим.
    LAccumulator := TMHBaselineAccumulator.Create(AContext, ANowUtc);
    try
      LFromUtc := ANowUtc - FLearningDays;
      LSpan := (ANowUtc - LFromUtc) / RebuildChunks;
      LRemaining := FSamplesPerContext;
      for I := 0 to RebuildChunks - 1 do
      begin
        if LRemaining <= 0 then
          Break;
        LChunkFrom := LFromUtc + I * LSpan;
        // Границы включительные: интервал заканчивается за 1 мс до начала следующего.
        if I = RebuildChunks - 1 then
          LChunkTo := ANowUtc
        else
          LChunkTo := LFromUtc + (I + 1) * LSpan - 1 / MSecsPerDay;
        LQuota := (LRemaining + (RebuildChunks - I) - 1) div (RebuildChunks - I);
        LSnapshots := FStore.LoadSnapshotsSampled(LChunkFrom, LChunkTo, LQuota, AContext);
        LAccumulator.Add(LSnapshots);
        Dec(LRemaining, Length(LSnapshots));
        LSnapshots := nil;
      end;
      if LAccumulator.Count = 0 then
      begin
        Log(llDebug, Format('Профиль нормы «%s»: нет наблюдений за %d дн., прежний профиль сохранён',
          [MHWorkContextToString(AContext), FLearningDays]));
        Exit(True);
      end;
      LBaseline := LAccumulator.Finish;
    finally
      LAccumulator.Free;
    end;
    LOld := BaselineFor(AContext);
    if LOld.SampleCount > 0 then
      LBaseline.CreatedUtc := LOld.CreatedUtc;
    FStore.SaveBaseline(LBaseline);
    FLock.Enter;
    try
      FProfiles[AContext] := LBaseline;
    finally
      FLock.Leave;
    end;
    Result := True;
  except
    on E: Exception do
      Log(llError, Format('Не удалось перестроить профиль нормы «%s»: %s; используется прежний',
        [MHWorkContextToString(AContext), E.Message]));
  end;
end;

procedure TMHBaselineManager.Rebuild;
var
  LNow: TDateTime;
  LContext: TMHWorkContext;
  LAllOk: Boolean;
begin
  FRebuildLock.Enter;
  try
    LNow := FClock.NowUtc;
    LAllOk := True;
    for LContext in Contexts do
      if not RebuildContext(LContext, LNow) then
        LAllOk := False;
    if LAllOk then
    begin
      FLock.Enter;
      try
        FLastRebuildUtc := LNow;
      finally
        FLock.Leave;
      end;
      Log(llInfo, 'Профили нормы перестроены');
    end;
  finally
    FRebuildLock.Leave;
  end;
end;

{ Сравнение }

function MHStatsFromSeries(const ASeries: TArray<TMHMetric>): TMHStat;
var
  LValues: TArray<Double>;
  LCount: Integer;
  LMetric: TMHMetric;
begin
  SetLength(LValues, Length(ASeries));
  LCount := 0;
  for LMetric in ASeries do
    if LMetric.HasValue then
    begin
      LValues[LCount] := LMetric.Value;
      Inc(LCount);
    end;
  SetLength(LValues, LCount);
  Result := TMHStat.FromValues(LValues);
end;

function MHCompareStats(AKind: TMHMetricKind; const ACurrent, ABaseline: TMHStat): TMHMetricComparison;
var
  LDelta: Double;
begin
  Result := Default(TMHMetricComparison);
  Result.Kind := AKind;
  Result.Current := ACurrent;
  Result.Baseline := ABaseline;
  Result.HasBaseline := ABaseline.HasData;
  if not Result.HasBaseline then
  begin
    Result.Verdict := 'нет данных о норме';
    Exit;
  end;
  if ACurrent.HasData then
  begin
    Result.MedianDeltaPercent := RelativeDelta(ACurrent.Median, ABaseline.Median);
    Result.P95DeltaPercent := RelativeDelta(ACurrent.P95, ABaseline.P95);
  end;
  if (ACurrent.SampleCount < MH_BASELINE_MIN_COMPARE_SAMPLES) or
     (ABaseline.SampleCount < MH_BASELINE_MIN_COMPARE_SAMPLES) then
  begin
    Result.Verdict := 'мало данных для сравнения';
    Exit;
  end;
  LDelta := Result.MedianDeltaPercent;
  if (Abs(LDelta) < MH_BASELINE_DEVIATION_PERCENT) or
     (IsPercentKind(AKind) and
      (Abs(ACurrent.Median - ABaseline.Median) < MH_BASELINE_MIN_ABS_DELTA_POINTS)) then
    Result.Verdict := 'в пределах нормы'
  else if LDelta > 0 then
    Result.Verdict := Format('выше нормы на %d%%', [Round(LDelta)])
  else
    Result.Verdict := Format('ниже нормы на %d%%', [Round(-LDelta)]);
end;

function MHComparePeriods(const ACurrent, ABaseline: TMHBaseline): TArray<TMHMetricComparison>;
begin
  Result := [
    MHCompareStats(mkCpuPercent, ACurrent.SystemCpu, ABaseline.SystemCpu),
    MHCompareStats(mkMemoryLoadPercent, ACurrent.MemoryLoad, ABaseline.MemoryLoad),
    MHCompareStats(mkDiskActivePercent, ACurrent.DiskActive, ABaseline.DiskActive)];
end;

function MHCompareProcesses(const ACurrent, ABaseline: TMHBaseline;
  AMinCpuDeltaPercentPoints: Double): TArray<TMHProcessDeviation>;
var
  LBaseIndex: TDictionary<string, Integer>;
  LList: TList<TMHProcessDeviation>;
  LProcess, LBase: TMHProcessBaseline;
  LItem: TMHProcessDeviation;
  LIndex, I: Integer;
begin
  LBaseIndex := TDictionary<string, Integer>.Create;
  LList := TList<TMHProcessDeviation>.Create;
  try
    for I := 0 to High(ABaseline.Processes) do
      LBaseIndex.AddOrSetValue(ABaseline.Processes[I].Key.ToLower, I);

    for LProcess in ACurrent.Processes do
    begin
      if not LProcess.Cpu.HasData then
        Continue;
      LItem := Default(TMHProcessDeviation);
      LItem.Key := LProcess.Key;
      LItem.Name := LProcess.Name;
      LItem.CurrentCpuP95 := LProcess.Cpu.P95;
      if LBaseIndex.TryGetValue(LProcess.Key.ToLower, LIndex) then
      begin
        LBase := ABaseline.Processes[LIndex];
        if not LBase.Cpu.HasData then
          Continue;
        LItem.BaselineCpuP95 := LBase.Cpu.P95;
        if LItem.CurrentCpuP95 - LItem.BaselineCpuP95 < AMinCpuDeltaPercentPoints then
          Continue;
        LItem.Description := Format('CPU (p95) %.1f%% при норме %.1f%% (+%.1f п.п.)',
          [LItem.CurrentCpuP95, LItem.BaselineCpuP95, LItem.CurrentCpuP95 - LItem.BaselineCpuP95]);
      end
      else
      begin
        if LItem.CurrentCpuP95 < AMinCpuDeltaPercentPoints then
          Continue;
        LItem.IsNewProgram := True;
        LItem.Description := Format('новая программа: CPU (p95) %.1f%%, в профиле нормы отсутствует',
          [LItem.CurrentCpuP95]);
      end;
      LList.Add(LItem);
    end;

    // Влияние: прирост p95 (для новой программы — весь p95).
    LList.Sort(TComparer<TMHProcessDeviation>.Construct(
      function(const A, B: TMHProcessDeviation): Integer
      begin
        Result := CompareValue(B.CurrentCpuP95 - B.BaselineCpuP95,
          A.CurrentCpuP95 - A.BaselineCpuP95);
        if Result = 0 then
          Result := CompareStr(A.Key, B.Key);
      end));
    Result := LList.ToArray;
  finally
    LList.Free;
    LBaseIndex.Free;
  end;
end;

end.
