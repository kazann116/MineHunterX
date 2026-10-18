unit MineHunter.Core.Scanner;

{
  TMHScanner — асинхронное управление сканированием.

  Цикл: опрос коллекторов -> сборка снимка -> анализ -> события.
  Отказоустойчивость:
    - исключение коллектора переводит его статус в ssError, остальные работают;
    - после MaxConsecutiveFailures подряд коллектор временно отключается
      с экспоненциальной задержкой (до MaxBackoffCycles циклов), затем опрос
      возобновляется автоматически;
    - исключения анализатора и обработчиков событий журналируются и не
      останавливают сканирование.

  Потоки: Start/Stop/Free вызываются из одного (обычно главного) потока.
  Обработчики событий вызываются:
    - edMainThread  — в главном потоке через TThread.Queue; после вызова
                      Stop ещё не доставленные события отменяются
                      (Start/Stop должны вызываться из главного потока);
    - edWorkerThread — прямо в потоке сканера.
  В обработчиках нельзя вызывать Stop и TThread.Synchronize (взаимоблокировка).
}

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHSnapshotEvent = reference to procedure(const ASnapshot: TMHSnapshot);
  TMHFindingEvent = reference to procedure(const AFinding: TMHFinding);
  /// Итог цикла: снимок и все находки этого цикла вместе.
  TMHCycleEvent = reference to procedure(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);

  TMHEventDispatch = (edMainThread, edWorkerThread);

  TMHScannerOptions = record
  public const
    MinIntervalMs = 250;
    MaxIntervalMs = 600000;
  public
    IntervalMs: Cardinal;
    MaxConsecutiveFailures: Integer;
    MaxBackoffCycles: Integer;
    EventDispatch: TMHEventDispatch;
    class function Default: TMHScannerOptions; static;
    /// Возвращает копию с значениями, приведёнными к допустимым диапазонам.
    function Normalized: TMHScannerOptions;
  end;

  TMHScanner = class
  private type
    TCollectorState = record
      Collector: IMHCollector;
      ConsecutiveFailures: Integer;
      SkipCycles: Integer;
      BackoffCycles: Integer;
      LastStatus: TMHSourceStatus;
    end;

    TWorker = class(TThread)
    private
      FOwner: TMHScanner;
      FWakeEvent: TEvent;
      FEpoch: Integer;
    protected
      procedure Execute; override;
    public
      constructor Create(AOwner: TMHScanner; AEpoch: Integer);
      destructor Destroy; override;
      procedure Wake;
    end;
  private
    FScanLock: TCriticalSection;   // сериализует циклы сканирования
    FStateLock: TCriticalSection;  // защищает настройки и базовый профиль
    FCollectors: TArray<TCollectorState>;
    FAnalyzer: IMHAnalyzer;
    FRepository: IMHRepository;
    FStorageFailing: Boolean;
    FDuplicateMetricLogged: Boolean;
    FLogger: IMHLogger;
    FClock: IMHClock;
    FOptions: TMHScannerOptions;
    FBaseline: TMHBaseline;
    FBaselineProvider: IMHBaselineProvider;
    FSequence: UInt64;
    FWorker: TWorker;
    /// Номер запуска. Меняется в Start и Stop (только в потоке-владельце);
    /// событие из очереди доставляется, только если его эпоха актуальна.
    FDispatchEpoch: Integer;
    FOnSnapshot: TMHSnapshotEvent;
    FOnFinding: TMHFindingEvent;
    FOnCycle: TMHCycleEvent;
    /// 1 — следующий цикл сбрасывает кэши коллекторов (RequestRefresh).
    FRefreshPending: Integer;
    /// Номер снимка последнего цикла со сбросом кэшей (0 — не было).
    FLastRefreshSequence: Int64;
    function GetLastRefreshSequence: UInt64;
    function GetOptions: TMHScannerOptions;
    procedure SetOptions(const AValue: TMHScannerOptions);
    function GetBaseline: TMHBaseline;
    function GetBaselineProvider: IMHBaselineProvider;
    procedure SetBaselineProvider(const AValue: IMHBaselineProvider);
    /// Переносит сведения вспомогательных источников (файлы, командные строки,
    /// окна) в записи процессов снимка.
    procedure EnrichProcesses(var ASnapshot: TMHSnapshot;
      const ADetails: TArray<TMHProcessDetail>);
    procedure SaveFindings(const AFindings: TMHFindings);
    procedure SetBaseline(const AValue: TMHBaseline);
    function GetIsRunning: Boolean;
    function RunCollector(var AState: TCollectorState;
      var ASnapshot: TMHSnapshot; var ADetails: TArray<TMHProcessDetail>): TMHSourceStatus;
    procedure MergeResult(var ASnapshot: TMHSnapshot; const AResult: TMHCollectionResult;
      var ADetails: TArray<TMHProcessDetail>);
    /// Опрашивает все коллекторы. Вызывать только под FScanLock.
    function CollectSnapshot: TMHSnapshot;
    function RunAnalyzer(const ASnapshot: TMHSnapshot): TMHFindings;
    /// Сохраняет снимок и добавляет в него статус источника «storage».
    /// Вызывать только под FScanLock.
    procedure PersistSnapshot(var ASnapshot: TMHSnapshot);
    function GetRepository: IMHRepository;
    procedure SetRepository(const AValue: IMHRepository);
    procedure DispatchResults(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings;
      AQueued: Boolean; AEpoch: Integer);
    procedure InvokeHandlers(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);
    procedure Log(ALevel: TMHLogLevel; const AMessage: string);
  public
    /// ACollectors — не пустые; AAnalyzer может быть nil (только сбор данных).
    constructor Create(const ACollectors: TArray<IMHCollector>;
      const AAnalyzer: IMHAnalyzer; const AClock: IMHClock; const ALogger: IMHLogger);
    destructor Destroy; override;

    procedure Start;
    /// Останавливает поток и ждёт завершения текущего цикла.
    procedure Stop;
    /// Синхронный цикл сканирования в вызывающем потоке.
    /// Обработчики событий вызываются в этом же потоке.
    function ScanOnce: TMHSnapshot;
    /// «Проверить сейчас»: следующий цикл перечитывает и кэшируемые источники
    /// (автозапуск, признаки вмешательства). Если сканирование запущено,
    /// цикл начинается сразу, не дожидаясь интервала.
    procedure RequestRefresh;
    /// Номер снимка, в котором выполнен последний запрошенный сброс кэшей.
    property LastRefreshSequence: UInt64 read GetLastRefreshSequence;

    property IsRunning: Boolean read GetIsRunning;
    property Options: TMHScannerOptions read GetOptions write SetOptions;
    property Baseline: TMHBaseline read GetBaseline write SetBaseline;
    /// Профили нормы по контекстам. Если задан, анализатор получает профиль
    /// для контекста текущего снимка, иначе — свойство Baseline.
    property BaselineProvider: IMHBaselineProvider read GetBaselineProvider
      write SetBaselineProvider;
    /// Назначать до Start.
    property OnSnapshot: TMHSnapshotEvent read FOnSnapshot write FOnSnapshot;
    property OnFinding: TMHFindingEvent read FOnFinding write FOnFinding;
    /// Вызывается после OnSnapshot/OnFinding с полным набором находок цикла.
    property OnCycle: TMHCycleEvent read FOnCycle write FOnCycle;
    /// Хранилище истории (необязательно). Сбой записи не останавливает
    /// сканирование: он отражается статусом источника StorageSourceId.
    property Repository: IMHRepository read GetRepository write SetRepository;
  public const
    StorageSourceId = 'storage';
  end;

implementation

uses
  System.Math, System.Generics.Collections,
  MineHunter.Core.Paths, MineHunter.Core.Lang;

const
  SOURCE_SCANNER = 'scanner';
  MIN_IDLE_MS = 100;

{ TMHScannerOptions }

class function TMHScannerOptions.Default: TMHScannerOptions;
begin
  Result.IntervalMs := 2000;
  Result.MaxConsecutiveFailures := 3;
  Result.MaxBackoffCycles := 32;
  Result.EventDispatch := edMainThread;
end;

function TMHScannerOptions.Normalized: TMHScannerOptions;
begin
  Result := Self;
  Result.IntervalMs := EnsureRange(IntervalMs, MinIntervalMs, MaxIntervalMs);
  Result.MaxConsecutiveFailures := Max(1, MaxConsecutiveFailures);
  Result.MaxBackoffCycles := Max(1, MaxBackoffCycles);
end;

{ TMHScanner.TWorker }

constructor TMHScanner.TWorker.Create(AOwner: TMHScanner; AEpoch: Integer);
begin
  FOwner := AOwner;
  FEpoch := AEpoch;
  FWakeEvent := TEvent.Create(nil, False, False, '');
  inherited Create(False);
  NameThreadForDebugging('MineHunter.Scanner');
end;

destructor TMHScanner.TWorker.Destroy;
begin
  // inherited Destroy дожидается завершения потока и удаляет события,
  // поставленные потоком в очередь главного потока.
  inherited;
  FWakeEvent.Free;
end;

procedure TMHScanner.TWorker.Wake;
begin
  FWakeEvent.SetEvent;
end;

procedure TMHScanner.TWorker.Execute;
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
  LOptions: TMHScannerOptions;
  LStarted, LElapsed: UInt64;
  LWait: Cardinal;
begin
  while not Terminated do
  begin
    LOptions := FOwner.Options;
    LStarted := FOwner.FClock.TickMs;
    try
      FOwner.FScanLock.Enter;
      try
        LSnapshot := FOwner.CollectSnapshot;
        FOwner.PersistSnapshot(LSnapshot);
      finally
        FOwner.FScanLock.Leave;
      end;
    except
      on E: Exception do
      begin
        // Сюда попадают только непредвиденные сбои самого сканера.
        FOwner.Log(llError, MHL('Сбой цикла сканирования: ', 'Scan cycle failure: ') + E.Message);
        LSnapshot := Default(TMHSnapshot);
      end;
    end;
    if Terminated then
      Break;
    if LSnapshot.Sequence <> 0 then
    begin
      LFindings := FOwner.RunAnalyzer(LSnapshot);
      FOwner.DispatchResults(LSnapshot, LFindings,
        LOptions.EventDispatch = edMainThread, FEpoch);
    end;
    LElapsed := FOwner.FClock.TickMs - LStarted;
    // Даже если цикл занял больше интервала, оставляем паузу, чтобы
    // медленный источник не превратил сканер в постоянную нагрузку на CPU.
    if LElapsed + MIN_IDLE_MS >= LOptions.IntervalMs then
      LWait := MIN_IDLE_MS
    else
      LWait := LOptions.IntervalMs - Cardinal(LElapsed);
    if not Terminated then
      FWakeEvent.WaitFor(LWait);
  end;
end;

{ TMHScanner }

constructor TMHScanner.Create(const ACollectors: TArray<IMHCollector>;
  const AAnalyzer: IMHAnalyzer; const AClock: IMHClock; const ALogger: IMHLogger);
var
  I: Integer;
begin
  inherited Create;
  if Length(ACollectors) = 0 then
    raise EArgumentException.Create(MHL('Нужен хотя бы один коллектор',
      'At least one collector is required'));
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if ALogger = nil then
    raise EArgumentNilException.Create('ALogger');
  SetLength(FCollectors, Length(ACollectors));
  for I := 0 to High(ACollectors) do
  begin
    if ACollectors[I] = nil then
      raise EArgumentNilException.CreateFmt('ACollectors[%d]', [I]);
    FCollectors[I] := Default(TCollectorState);
    FCollectors[I].Collector := ACollectors[I];
    FCollectors[I].LastStatus := TMHSourceStatus.Create(ACollectors[I].SourceId,
      ssUnknown, '', 0);
  end;
  FAnalyzer := AAnalyzer;
  FClock := AClock;
  FLogger := ALogger;
  FOptions := TMHScannerOptions.Default;
  FBaseline := TMHBaseline.Empty;
  FScanLock := TCriticalSection.Create;
  FStateLock := TCriticalSection.Create;
end;

destructor TMHScanner.Destroy;
begin
  Stop;
  FStateLock.Free;
  FScanLock.Free;
  inherited;
end;

function TMHScanner.GetOptions: TMHScannerOptions;
begin
  FStateLock.Enter;
  try
    Result := FOptions;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.SetOptions(const AValue: TMHScannerOptions);
begin
  FStateLock.Enter;
  try
    FOptions := AValue.Normalized;
  finally
    FStateLock.Leave;
  end;
  // Новый интервал применяется сразу, не дожидаясь окончания старого ожидания.
  if FWorker <> nil then
    FWorker.Wake;
end;

function TMHScanner.GetBaseline: TMHBaseline;
begin
  FStateLock.Enter;
  try
    Result := FBaseline;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.SetBaseline(const AValue: TMHBaseline);
begin
  FStateLock.Enter;
  try
    FBaseline := AValue;
  finally
    FStateLock.Leave;
  end;
end;

function TMHScanner.GetIsRunning: Boolean;
begin
  Result := FWorker <> nil;
end;

procedure TMHScanner.Log(ALevel: TMHLogLevel; const AMessage: string);
begin
  try
    FLogger.Log(ALevel, SOURCE_SCANNER, AMessage);
  except
    // Сбой журнала не должен останавливать сканирование.
  end;
end;

procedure TMHScanner.Start;
begin
  if FWorker <> nil then
    Exit;
  Inc(FDispatchEpoch);
  FWorker := TWorker.Create(Self, FDispatchEpoch);
  Log(llInfo, MHL('Сканирование запущено', 'Monitoring started'));
end;

procedure TMHScanner.Stop;
var
  LWorker: TWorker;
begin
  if FWorker = nil then
    Exit;
  // Смена эпохи до ожидания потока: TThread.WaitFor в главном потоке
  // обрабатывает очередь синхронизации, и уже поставленные события
  // не должны дойти до обработчиков.
  Inc(FDispatchEpoch);
  LWorker := FWorker;
  LWorker.Terminate;
  LWorker.Wake;
  // Destroy ждёт завершения потока и отменяет недоставленные события.
  LWorker.Free;
  FWorker := nil;
  Log(llInfo, MHL('Сканирование остановлено', 'Monitoring stopped'));
end;

procedure TMHScanner.MergeResult(var ASnapshot: TMHSnapshot;
  const AResult: TMHCollectionResult; var ADetails: TArray<TMHProcessDetail>);
var
  LMetric: TMHMetric;
  I: Integer;
  LDuplicate: Boolean;
begin
  if Length(AResult.Processes) > 0 then
    ASnapshot.Processes := ASnapshot.Processes + AResult.Processes;
  // Системная метрика каждого вида — одна на снимок: её читают UI и хранилище.
  // При конфликте источников побеждает первый по порядку регистрации.
  for LMetric in AResult.Metrics do
  begin
    LDuplicate := False;
    for I := 0 to High(ASnapshot.Metrics) do
      if ASnapshot.Metrics[I].Kind = LMetric.Kind then
      begin
        LDuplicate := True;
        Break;
      end;
    if LDuplicate then
    begin
      if not FDuplicateMetricLogged then
      begin
        FDuplicateMetricLogged := True;
        Log(llWarning, Format(MHL('Источник %s повторно передал системную метрику вида %d; ' +
          'используется значение первого источника',
          'Source %s sent a duplicate system metric of kind %d; the value from the first ' +
          'source is used'), [AResult.Status.SourceId, Ord(LMetric.Kind)]));
      end;
      Continue;
    end;
    ASnapshot.Metrics := ASnapshot.Metrics + [LMetric];
  end;
  if Length(AResult.Files) > 0 then
    ASnapshot.Files := ASnapshot.Files + AResult.Files;
  if Length(AResult.Autostart) > 0 then
    ASnapshot.Autostart := ASnapshot.Autostart + AResult.Autostart;
  if Length(AResult.Connections) > 0 then
    ASnapshot.Connections := ASnapshot.Connections + AResult.Connections;
  if Length(AResult.ProcessDetails) > 0 then
    ADetails := ADetails + AResult.ProcessDetails;
  if Length(AResult.Sensors) > 0 then
    ASnapshot.Sensors := ASnapshot.Sensors + AResult.Sensors;
  if Length(AResult.Tamper) > 0 then
    ASnapshot.Tamper := ASnapshot.Tamper + AResult.Tamper;
  if Length(AResult.Launches) > 0 then
    ASnapshot.Launches := ASnapshot.Launches + AResult.Launches;
  if Length(AResult.Disks) > 0 then
    ASnapshot.Disks := ASnapshot.Disks + AResult.Disks;
  if Length(AResult.Volumes) > 0 then
    ASnapshot.Volumes := ASnapshot.Volumes + AResult.Volumes;
  if Length(AResult.LaunchEvents) > 0 then
    ASnapshot.LaunchEvents := ASnapshot.LaunchEvents + AResult.LaunchEvents;
  if Length(AResult.GpuAdapters) > 0 then
    ASnapshot.GpuAdapters := ASnapshot.GpuAdapters + AResult.GpuAdapters;
  if Length(AResult.NetAdapters) > 0 then
    ASnapshot.NetAdapters := ASnapshot.NetAdapters + AResult.NetAdapters;
  // Контекст — от первого источника, который его передал.
  if AResult.HasContext and not ASnapshot.Context.Available then
  begin
    ASnapshot.Context := AResult.Context;
    ASnapshot.Context.Available := True;
  end;
end;

procedure TMHScanner.EnrichProcesses(var ASnapshot: TMHSnapshot;
  const ADetails: TArray<TMHProcessDetail>);
var
  I, J: Integer;
  LFile: TMHFileInfo;
  LFiles: TDictionary<string, Integer>;
begin
  if Length(ASnapshot.Processes) = 0 then
    Exit;
  LFiles := TDictionary<string, Integer>.Create;
  try
    for I := 0 to High(ASnapshot.Files) do
      LFiles.AddOrSetValue(ASnapshot.Files[I].Path.ToLower, I);
    for I := 0 to High(ASnapshot.Processes) do
    begin
      if (ASnapshot.Processes[I].ImagePath <> '') and
         LFiles.TryGetValue(MHNormalizePath(ASnapshot.Processes[I].ImagePath).ToLower, J) then
      begin
        LFile := ASnapshot.Files[J];
        ASnapshot.Processes[I].Signature := LFile.Signature;
        if LFile.Sha256 <> '' then
          ASnapshot.Processes[I].Sha256 := LFile.Sha256;
      end;
      if ASnapshot.Context.Available then
        ASnapshot.Processes[I].HasVisibleWindow :=
          ASnapshot.Context.HasVisibleWindow(ASnapshot.Processes[I].Id.Pid);
      // Сведения могут прийти от нескольких источников (командная строка — от
      // контекста, GPU — от коллектора gpu); переносятся только заполненные поля.
      for J := 0 to High(ADetails) do
        if ADetails[J].Id = ASnapshot.Processes[I].Id then
        begin
          if (ADetails[J].CommandLine <> '') and (ASnapshot.Processes[I].CommandLine = '') then
            ASnapshot.Processes[I].CommandLine := ADetails[J].CommandLine;
          if ADetails[J].Gpu.HasValue then
            ASnapshot.Processes[I].Gpu := ADetails[J].Gpu;
          if ADetails[J].GpuCompute.HasValue then
            ASnapshot.Processes[I].GpuCompute := ADetails[J].GpuCompute;
          if ADetails[J].GpuMemory.HasValue then
            ASnapshot.Processes[I].GpuMemory := ADetails[J].GpuMemory;
        end;
    end;
  finally
    LFiles.Free;
  end;
end;

function TMHScanner.RunCollector(var AState: TCollectorState;
  var ASnapshot: TMHSnapshot; var ADetails: TArray<TMHProcessDetail>): TMHSourceStatus;
var
  LSourceId: string;
  LResult: TMHCollectionResult;
  LStarted: UInt64;
  LOptions: TMHScannerOptions;
begin
  LSourceId := AState.Collector.SourceId;
  if AState.SkipCycles > 0 then
  begin
    Dec(AState.SkipCycles);
    Result := TMHSourceStatus.Create(LSourceId, ssUnavailable,
      Format(MHL('Источник временно отключён после %d ошибок подряд; повтор через %d цикл(ов)',
        'Source temporarily disabled after %d consecutive errors; retry in %d cycle(s)'),
        [AState.ConsecutiveFailures, AState.SkipCycles + 1]), ASnapshot.TimestampUtc);
    Exit;
  end;

  LOptions := Options;
  LStarted := FClock.TickMs;
  try
    LResult := AState.Collector.Collect(ASnapshot);
    Result := LResult.Status;
    if Result.SourceId = '' then
      Result.SourceId := LSourceId;
    if Result.State = ssUnknown then
      Result.State := ssSuccess;
    MergeResult(ASnapshot, LResult, ADetails);
    AState.ConsecutiveFailures := 0;
    AState.BackoffCycles := 0;
  except
    on E: Exception do
    begin
      Result := TMHSourceStatus.Create(LSourceId, ssError,
        E.ClassName + ': ' + E.Message, ASnapshot.TimestampUtc);
      Inc(AState.ConsecutiveFailures);
      Log(llWarning, Format(MHL('Источник %s: %s', 'Source %s: %s'), [LSourceId, Result.Message]));
      if AState.ConsecutiveFailures >= LOptions.MaxConsecutiveFailures then
      begin
        if AState.BackoffCycles = 0 then
          AState.BackoffCycles := 1
        else
          AState.BackoffCycles := Min(AState.BackoffCycles * 2, LOptions.MaxBackoffCycles);
        AState.SkipCycles := AState.BackoffCycles;
        Log(llWarning, Format(MHL('Источник %s временно отключён на %d цикл(ов)',
          'Source %s temporarily disabled for %d cycle(s)'), [LSourceId, AState.SkipCycles]));
      end;
    end;
  end;
  Result.DurationMs := Cardinal(Min(FClock.TickMs - LStarted, UInt64(High(Cardinal))));
  if Result.TimestampUtc = 0 then
    Result.TimestampUtc := ASnapshot.TimestampUtc;
end;

function TMHScanner.CollectSnapshot: TMHSnapshot;
var
  I: Integer;
  LRefresh: Boolean;
  LCache: IMHCacheInvalidation;
  LStatuses: TArray<TMHSourceStatus>;
  LDetails: TArray<TMHProcessDetail>;
begin
  Inc(FSequence);
  Result := TMHSnapshot.Create(FSequence, FClock.NowUtc);
  LRefresh := TInterlocked.Exchange(FRefreshPending, 0) = 1;
  if LRefresh then
    for I := 0 to High(FCollectors) do
      if Supports(FCollectors[I].Collector, IMHCacheInvalidation, LCache) then
        LCache.Invalidate;
  SetLength(LStatuses, Length(FCollectors));
  LDetails := nil;
  for I := 0 to High(FCollectors) do
  begin
    LStatuses[I] := RunCollector(FCollectors[I], Result, LDetails);
    FCollectors[I].LastStatus := LStatuses[I];
  end;
  Result.Sources := LStatuses;
  EnrichProcesses(Result, LDetails);
  if LRefresh then
    TInterlocked.Exchange(FLastRefreshSequence, Int64(Result.Sequence));
end;

procedure TMHScanner.RequestRefresh;
begin
  TInterlocked.Exchange(FRefreshPending, 1);
  if FWorker <> nil then
    FWorker.Wake;
end;

function TMHScanner.GetLastRefreshSequence: UInt64;
begin
  Result := UInt64(TInterlocked.Read(FLastRefreshSequence));
end;

function TMHScanner.GetRepository: IMHRepository;
begin
  FStateLock.Enter;
  try
    Result := FRepository;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.SetRepository(const AValue: IMHRepository);
begin
  FStateLock.Enter;
  try
    FRepository := AValue;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.PersistSnapshot(var ASnapshot: TMHSnapshot);
var
  LRepository: IMHRepository;
  LStatus: TMHSourceStatus;
  LStarted: UInt64;
begin
  LRepository := Repository;
  if LRepository = nil then
    Exit;
  LStarted := FClock.TickMs;
  try
    LRepository.SaveSnapshot(ASnapshot);
    LStatus := TMHSourceStatus.Create(StorageSourceId, ssSuccess, '', ASnapshot.TimestampUtc);
    if FStorageFailing then
    begin
      FStorageFailing := False;
      Log(llInfo, MHL('Запись истории восстановлена', 'History recording resumed'));
    end;
  except
    on E: Exception do
    begin
      LStatus := TMHSourceStatus.Create(StorageSourceId, ssError,
        MHL('История не сохраняется: ', 'History is not being saved: ') + E.Message, ASnapshot.TimestampUtc);
      // Журналируем только смену состояния, чтобы не засорять журнал каждые N секунд.
      if not FStorageFailing then
      begin
        FStorageFailing := True;
        Log(llError, LStatus.Message);
      end;
    end;
  end;
  LStatus.DurationMs := Cardinal(Min(FClock.TickMs - LStarted, UInt64(High(Cardinal))));
  LStatus.ItemCount := Ord(LStatus.State = ssSuccess);
  ASnapshot.Sources := ASnapshot.Sources + [LStatus];
end;

function TMHScanner.RunAnalyzer(const ASnapshot: TMHSnapshot): TMHFindings;
var
  LBaseline: TMHBaseline;
  LProvider: IMHBaselineProvider;
begin
  Result := nil;
  if FAnalyzer = nil then
    Exit;
  LBaseline := Baseline;
  LProvider := BaselineProvider;
  if LProvider <> nil then
    try
      LBaseline := LProvider.BaselineFor(ASnapshot.Context.WorkContext);
    except
      on E: Exception do
      begin
        Log(llWarning, MHL('Профиль нормы недоступен: ', 'Baseline unavailable: ') + E.Message);
        LBaseline := TMHBaseline.Empty;
      end;
    end;
  try
    Result := FAnalyzer.Analyze(ASnapshot, LBaseline);
  except
    on E: Exception do
    begin
      Log(llError, MHL('Сбой анализатора: ', 'Analyzer failure: ') + E.Message);
      Result := nil;
    end;
  end;
  SaveFindings(Result);
end;

procedure TMHScanner.SaveFindings(const AFindings: TMHFindings);
var
  LHistory: IMHFindingHistory;
begin
  if (Length(AFindings) = 0) or not Supports(Repository, IMHFindingHistory, LHistory) then
    Exit;
  try
    LHistory.SaveFindings(AFindings);
  except
    on E: Exception do
      if not FStorageFailing then
      begin
        FStorageFailing := True;
        Log(llError, MHL('Находки не сохранены: ', 'Findings were not saved: ') + E.Message);
      end;
  end;
end;

function TMHScanner.GetBaselineProvider: IMHBaselineProvider;
begin
  FStateLock.Enter;
  try
    Result := FBaselineProvider;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.SetBaselineProvider(const AValue: IMHBaselineProvider);
begin
  FStateLock.Enter;
  try
    FBaselineProvider := AValue;
  finally
    FStateLock.Leave;
  end;
end;

procedure TMHScanner.InvokeHandlers(const ASnapshot: TMHSnapshot;
  const AFindings: TMHFindings);
var
  I: Integer;
begin
  if Assigned(FOnSnapshot) then
    try
      FOnSnapshot(ASnapshot);
    except
      on E: Exception do
        Log(llError, MHL('Ошибка обработчика OnSnapshot: ', 'OnSnapshot handler error: ') + E.Message);
    end;
  if Assigned(FOnFinding) then
    for I := 0 to High(AFindings) do
      try
        FOnFinding(AFindings[I]);
      except
        on E: Exception do
          Log(llError, MHL('Ошибка обработчика OnFinding: ', 'OnFinding handler error: ') + E.Message);
      end;
  if Assigned(FOnCycle) then
    try
      FOnCycle(ASnapshot, AFindings);
    except
      on E: Exception do
        Log(llError, MHL('Ошибка обработчика OnCycle: ', 'OnCycle handler error: ') + E.Message);
    end;
end;

procedure TMHScanner.DispatchResults(const ASnapshot: TMHSnapshot;
  const AFindings: TMHFindings; AQueued: Boolean; AEpoch: Integer);
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
begin
  if not AQueued then
  begin
    InvokeHandlers(ASnapshot, AFindings);
    Exit;
  end;
  LSnapshot := ASnapshot;
  LFindings := AFindings;
  // Привязка к потоку сканера: при уничтожении потока недоставленные
  // события удаляются, поэтому обработчик не вызовется после Stop.
  TThread.Queue(TThread.Current,
    procedure
    begin
      if AEpoch = FDispatchEpoch then
        InvokeHandlers(LSnapshot, LFindings);
    end);
end;

function TMHScanner.ScanOnce: TMHSnapshot;
var
  LFindings: TMHFindings;
begin
  FScanLock.Enter;
  try
    Result := CollectSnapshot;
    PersistSnapshot(Result);
  finally
    FScanLock.Leave;
  end;
  LFindings := RunAnalyzer(Result);
  InvokeHandlers(Result, LFindings);
end;

end.
