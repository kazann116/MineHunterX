unit MineHunter.App.Bootstrap;

{
  Composition root приложения: регистрация сервисов в DI-контейнере,
  создание сканера и фоновых служб (перестроение профиля нормы).
  Форма получает готовые сервисы и не знает, какие именно коллекторы подключены.

  Порядок коллекторов важен: system идёт первым (по его загруженности CPU
  масштабируется загрузка процессов), процессы и автозапуск — раньше
  инспектора файлов (он проверяет их пути), GPU и контекста (они читают процессы).
}

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Container,
  MineHunter.Core.Scanner, MineHunter.Storage.SQLite, MineHunter.Analysis.Engine,
  MineHunter.Analysis.Baseline, MineHunter.Core.Settings, MineHunter.Core.Actions,
  MineHunter.Core.Quarantine;

type
  /// Периодически перестраивает профили нормы в фоновом потоке.
  TMHBaselineScheduler = class(TThread)
  private
    FManager: TMHBaselineManager;
    FManagerIntf: IMHBaselineProvider;
    FLogger: IMHLogger;
    FWake: TEvent;
    FFirstDelayMs: Cardinal;
    FIntervalMs: Cardinal;
    FRebuildRequested: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(AManager: TMHBaselineManager; const ALogger: IMHLogger;
      AFirstDelayMs, AIntervalMs: Cardinal);
    destructor Destroy; override;
    /// Перестроить профили как можно скорее (кнопка в интерфейсе).
    procedure RequestRebuild;
    procedure Stop;
  end;

  TMHAppServices = class
  private
    FContainer: TMHContainer;
    FScanner: TMHScanner;
    FLogger: IMHLogger;
    FLogReader: IMHLogReader;
    FClock: IMHClock;
    FRepository: IMHRepository;
    FHistory: IMHMetricHistory;
    FFindingHistory: IMHFindingHistory;
    FActionLog: IMHActionLog;
    FStorage: TMHSQLiteRepository;
    FStorageError: string;
    FAnalyzer: TMHThreatAnalyzer;
    FAnalyzerIntf: IMHAnalyzer;
    FBaselines: TMHBaselineManager;
    FBaselinesIntf: IMHBaselineProvider;
    FScheduler: TMHBaselineScheduler;
    FSettingsStore: TMHSettingsStore;
    FSettings: TMHAppSettings;
    FSettingsLoadedOk: Boolean;
    FActions: TMHSafeActions;
    FQuarantine: TMHQuarantine;
  public
    /// Путь базы истории для стандартной конфигурации ('' — MHDefaultHistoryPath).
    /// Позволяет тестам не трогать историю пользователя.
    class var DefaultHistoryPath: string;
    /// Путь файла настроек ('' — MHDefaultSettingsPath; '-' — не хранить настройки).
    class var DefaultSettingsPath: string;
    /// AContainer должен содержать IMHClock, IMHLogger, IMHLogReader и
    /// хотя бы один IMHCollector; IMHAnalyzer и IMHRepository необязательны.
    /// Если хранилище не открылось, приложение работает без истории
    /// (причина — в StorageError и в журнале).
    /// Объект становится владельцем контейнера.
    constructor Create(AContainer: TMHContainer);
    destructor Destroy; override;
    /// Стандартная конфигурация приложения.
    class function CreateDefault: TMHAppServices; static;
    /// Регистрирует стандартные сервисы в контейнере.
    class procedure RegisterDefaults(AContainer: TMHContainer); static;

    property Container: TMHContainer read FContainer;
    property Scanner: TMHScanner read FScanner;
    property Logger: IMHLogger read FLogger;
    property LogReader: IMHLogReader read FLogReader;
    property Clock: IMHClock read FClock;
    /// nil, если история недоступна.
    property MetricHistory: IMHMetricHistory read FHistory;
    property FindingHistory: IMHFindingHistory read FFindingHistory;
    property ActionLog: IMHActionLog read FActionLog;
    /// Хранилище SQLite стандартной конфигурации (nil — недоступно или другое хранилище).
    property Storage: TMHSQLiteRepository read FStorage;
    property StorageError: string read FStorageError;
    /// Анализатор угроз (nil, если в контейнере другой анализатор или его нет).
    property Analyzer: TMHThreatAnalyzer read FAnalyzer;
    /// Профили нормы (nil без хранилища).
    property Baselines: TMHBaselineManager read FBaselines;
    property BaselineScheduler: TMHBaselineScheduler read FScheduler;
    /// Применяет настройки ко всем службам (сканер, хранилище, анализатор, норма).
    procedure ApplySettings(const ASettings: TMHAppSettings);
    /// Сохраняет текущие настройки; False и причина в AError при сбое записи.
    function SaveSettings(out AError: string): Boolean;
    property Settings: TMHAppSettings read FSettings;
    /// False — файл настроек был повреждён и заменён значениями по умолчанию.
    property SettingsLoadedOk: Boolean read FSettingsLoadedOk;
    property SettingsStore: TMHSettingsStore read FSettingsStore;
    /// Безопасные действия (открыть расположение, Defender, остановка процесса).
    property Actions: TMHSafeActions read FActions;
    /// Карантин и откат исправлений (хранилище — рядом с базой истории).
    property Quarantine: TMHQuarantine read FQuarantine;
  end;

implementation

uses
  Winapi.Windows,
  MineHunter.Core.Logging, MineHunter.Collectors.SelfMonitor,
  MineHunter.Collectors.Processes, MineHunter.Collectors.Processes.WinApi,
  MineHunter.Collectors.System, MineHunter.Collectors.System.WinApi,
  MineHunter.Collectors.Autostart, MineHunter.Collectors.Autostart.WinApi,
  MineHunter.Collectors.Network, MineHunter.Collectors.Network.WinApi,
  MineHunter.Collectors.Files, MineHunter.Collectors.Files.WinApi,
  MineHunter.Collectors.Context, MineHunter.Collectors.Context.WinApi,
  MineHunter.Collectors.Gpu, MineHunter.Collectors.Gpu.WinApi,
  MineHunter.Collectors.Sensors, MineHunter.Collectors.Sensors.WinApi,
  MineHunter.Collectors.Tamper, MineHunter.Collectors.Tamper.WinApi,
  MineHunter.Core.Actions.WinApi, MineHunter.Core.Quarantine.WinApi, System.IOUtils;

const
  BASELINE_FIRST_DELAY_MS = 60 * 1000;
  BASELINE_INTERVAL_MS = 60 * 60 * 1000;
  BASELINE_SAMPLES_PER_CONTEXT = 1500;

{ TMHBaselineScheduler }

constructor TMHBaselineScheduler.Create(AManager: TMHBaselineManager; const ALogger: IMHLogger;
  AFirstDelayMs, AIntervalMs: Cardinal);
begin
  FManager := AManager;
  FManagerIntf := AManager;
  FLogger := ALogger;
  FFirstDelayMs := AFirstDelayMs;
  FIntervalMs := AIntervalMs;
  FWake := TEvent.Create(nil, False, False, '');
  inherited Create(False);
  NameThreadForDebugging('MineHunter.Baseline');
  Priority := tpLower;
end;

destructor TMHBaselineScheduler.Destroy;
begin
  Stop;
  inherited;
  FWake.Free;
end;

procedure TMHBaselineScheduler.RequestRebuild;
begin
  FRebuildRequested := True;
  FWake.SetEvent;
end;

procedure TMHBaselineScheduler.Stop;
begin
  Terminate;
  if FWake <> nil then
    FWake.SetEvent;
end;

procedure TMHBaselineScheduler.Execute;
var
  LWait: Cardinal;
begin
  LWait := FFirstDelayMs;
  while not Terminated do
  begin
    FWake.WaitFor(LWait);
    if Terminated then
      Break;
    FRebuildRequested := False;
    try
      FManager.Rebuild;
    except
      on E: Exception do
        FLogger.Log(llError, 'baseline', 'Профиль нормы не перестроен: ' + E.Message);
    end;
    LWait := FIntervalMs;
  end;
end;

{ TMHAppServices }

class procedure TMHAppServices.RegisterDefaults(AContainer: TMHContainer);
var
  LClock: IMHClock;
  LLogger: TMHMemoryLogger;
begin
  LClock := TMHSystemClock.Create;
  AContainer.RegisterInstance<IMHClock>(LClock);

  // Один экземпляр журнала под двумя интерфейсами: запись и чтение.
  LLogger := TMHMemoryLogger.Create(LClock);
  AContainer.RegisterInstance<IMHLogger>(LLogger);
  AContainer.RegisterInstance<IMHLogReader>(LLogger);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHSystemMetricsApi;
    begin
      LApi := TMHWinSystemMetricsApi.Create;
      Result := TMHSystemCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHProcessApi;
    begin
      LApi := TMHWinProcessApi.Create;
      Result := TMHProcessCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  // После процессов: сопоставляет счётчики GPU с процессами снимка по PID.
  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHGpuApi;
    begin
      LApi := TMHWinGpuApi.Create;
      Result := TMHGpuCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHSensorApi;
    begin
      LApi := TMHWinSensorApi.Create;
      Result := TMHSensorCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHAutostartApi;
    begin
      LApi := TMHWinAutostartApi.Create;
      Result := TMHAutostartCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  // Признаки вмешательства в защиту; до инспектора файлов (он проверяет их программы).
  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHTamperApi;
    begin
      LApi := TMHWinTamperApi.Create;
      Result := TMHTamperCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHNetworkApi;
    begin
      LApi := TMHWinNetworkApi.Create;
      Result := TMHNetworkCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  // После процессов и автозапуска: проверяет их файлы.
  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHFileApi;
    begin
      LApi := TMHWinFileApi.Create;
      // Бюджет 150 мс и 15 файлов за цикл: первичная проверка растягивается на ~1 мин,
      // но не создаёт заметной нагрузки даже на 4-ядерных компьютерах.
      Result := TMHFileCollector.Create(LApi, AContainer.Resolve<IMHClock>, 150, 15);
    end);

  // После процессов: читает их нагрузку для выбора командных строк.
  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    var
      LApi: IMHContextApi;
    begin
      LApi := TMHWinContextApi.Create;
      Result := TMHContextCollector.Create(LApi, AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHCollector>(
    function: IMHCollector
    begin
      Result := TMHSelfMonitorCollector.Create(AContainer.Resolve<IMHClock>);
    end);

  AContainer.RegisterSingleton<IMHAnalyzer>(
    function: IMHAnalyzer
    var
      LInfo: TSystemInfo;
    begin
      GetSystemInfo(LInfo);
      Result := TMHThreatAnalyzer.Create(Integer(LInfo.dwNumberOfProcessors), GetCurrentProcessId);
    end);

  AContainer.RegisterSingleton<IMHRepository>(
    function: IMHRepository
    var
      LPath: string;
    begin
      LPath := DefaultHistoryPath;
      if LPath = '' then
        LPath := MHDefaultHistoryPath;
      Result := TMHSQLiteRepository.Create(LPath, TMHStorageOptions.Default,
        AContainer.Resolve<IMHClock>, AContainer.Resolve<IMHLogger>);
    end);
end;

class function TMHAppServices.CreateDefault: TMHAppServices;
var
  LContainer: TMHContainer;
begin
  LContainer := TMHContainer.Create;
  try
    RegisterDefaults(LContainer);
  except
    LContainer.Free;
    raise;
  end;
  Result := TMHAppServices.Create(LContainer);
end;

constructor TMHAppServices.Create(AContainer: TMHContainer);
var
  LQuarantineDir: string;
  LQuarantineOps: IMHQuarantineOps;
  LSystemOps: IMHSystemOps;
begin
  inherited Create;
  if AContainer = nil then
    raise EArgumentNilException.Create('AContainer');
  FContainer := AContainer;
  FLogger := FContainer.Resolve<IMHLogger>;
  FLogReader := FContainer.Resolve<IMHLogReader>;
  FClock := FContainer.Resolve<IMHClock>;
  FContainer.TryResolve<IMHAnalyzer>(FAnalyzerIntf);
  if (FAnalyzerIntf <> nil) and ((FAnalyzerIntf as TObject) is TMHThreatAnalyzer) then
    FAnalyzer := TMHThreatAnalyzer(FAnalyzerIntf as TObject);
  FScanner := TMHScanner.Create(FContainer.ResolveAll<IMHCollector>, FAnalyzerIntf,
    FClock, FLogger);
  FLogger.Log(llInfo, 'app', 'MineHunter X ' + MH_CORE_VERSION + ' запущен');

  // Хранилище необязательно: без него работает мониторинг, но не история.
  try
    FContainer.TryResolve<IMHRepository>(FRepository);
  except
    on E: Exception do
    begin
      FRepository := nil;
      FStorageError := E.Message;
      FLogger.Log(llError, 'storage', 'История недоступна: ' + E.Message);
    end;
  end;
  if FRepository <> nil then
  begin
    Supports(FRepository, IMHMetricHistory, FHistory);
    Supports(FRepository, IMHFindingHistory, FFindingHistory);
    Supports(FRepository, IMHActionLog, FActionLog);
    if (FRepository as TObject) is TMHSQLiteRepository then
      FStorage := TMHSQLiteRepository(FRepository as TObject);
    FScanner.Repository := FRepository;
  end;

  // Профиль нормы: загружается из базы сразу, перестраивается в фоне.
  if FStorage <> nil then
  begin
    // 1 500 снимков на контекст (примерно один за 3 минуты обучения) достаточно для
    // медиан и p95 и ограничивает пиковую память ежечасного перестроения.
    FBaselines := TMHBaselineManager.Create(FStorage, FClock, FLogger, 3, BASELINE_SAMPLES_PER_CONTEXT);
    FBaselinesIntf := FBaselines;
    try
      FBaselines.LoadFromStore;
    except
      on E: Exception do
        FLogger.Log(llWarning, 'baseline', 'Профиль нормы не загружен: ' + E.Message);
    end;
    FScanner.BaselineProvider := FBaselinesIntf;
    FScheduler := TMHBaselineScheduler.Create(FBaselines, FLogger, BASELINE_FIRST_DELAY_MS,
      BASELINE_INTERVAL_MS);
  end;

  // Обращения к ОС для действий можно подменить через контейнер (тесты).
  if not FContainer.TryResolve<IMHSystemOps>(LSystemOps) then
    LSystemOps := TMHWinSystemOps.Create;
  FActions := TMHSafeActions.Create(LSystemOps, FActionLog, FClock);
  LQuarantineDir := DefaultHistoryPath;
  if LQuarantineDir = '' then
    LQuarantineDir := MHDefaultHistoryPath;
  // Операции карантина можно подменить через контейнер (тесты, встраивание).
  if not FContainer.TryResolve<IMHQuarantineOps>(LQuarantineOps) then
    LQuarantineOps := TMHWinQuarantineOps.Create;
  FQuarantine := TMHQuarantine.Create(LQuarantineOps, FActionLog, FClock,
    TPath.Combine(ExtractFileDir(LQuarantineDir), 'Quarantine'));

  // Настройки: повреждённый файл заменяется значениями по умолчанию (с копией .bad).
  FSettings := TMHAppSettings.Default;
  FSettingsLoadedOk := True;
  if DefaultSettingsPath <> '-' then
  begin
    if DefaultSettingsPath <> '' then
      FSettingsStore := TMHSettingsStore.Create(DefaultSettingsPath, FLogger)
    else
      FSettingsStore := TMHSettingsStore.Create(MHDefaultSettingsPath, FLogger);
    FSettingsLoadedOk := FSettingsStore.Load(FSettings);
  end;
  ApplySettings(FSettings);
end;

procedure TMHAppServices.ApplySettings(const ASettings: TMHAppSettings);
var
  LOptions: TMHScannerOptions;
  LStorage: TMHStorageOptions;
begin
  FSettings := ASettings.Normalized;
  LOptions := FScanner.Options;
  LOptions.IntervalMs := FSettings.IntervalMs;
  FScanner.Options := LOptions;
  if FStorage <> nil then
  begin
    LStorage := FStorage.Options;
    LStorage.RetentionDays := FSettings.RetentionDays;
    LStorage.MaxDatabaseBytes := Int64(FSettings.MaxDatabaseMB) * 1024 * 1024;
    LStorage.StoreProcessPaths := FSettings.StoreProcessPaths;
    FStorage.Options := LStorage;
  end;
  if FAnalyzer <> nil then
  begin
    FAnalyzer.Settings := FSettings.Analyzer;
    FAnalyzer.Exclusions := FSettings.Exclusions;
  end;
  if FBaselines <> nil then
    FBaselines.LearningDays := FSettings.LearningDays;
end;

function TMHAppServices.SaveSettings(out AError: string): Boolean;
begin
  AError := '';
  if FSettingsStore = nil then
    Exit(True);
  try
    FSettingsStore.Save(FSettings);
    Result := True;
  except
    on E: Exception do
    begin
      AError := E.Message;
      FLogger.Log(llError, 'settings', 'Настройки не сохранены: ' + E.Message);
      Result := False;
    end;
  end;
end;

destructor TMHAppServices.Destroy;
begin
  // Сначала фоновые потоки: они используют сервисы контейнера.
  FreeAndNil(FScheduler);
  FScanner.Free;
  FreeAndNil(FQuarantine);
  FreeAndNil(FActions);
  FreeAndNil(FSettingsStore);
  FBaselines := nil;
  FBaselinesIntf := nil;
  FAnalyzer := nil;
  FAnalyzerIntf := nil;
  FStorage := nil;
  FHistory := nil;
  FFindingHistory := nil;
  FActionLog := nil;
  FRepository := nil;
  FClock := nil;
  FLogReader := nil;
  FLogger := nil;
  FContainer.Free;
  inherited;
end;

end.
