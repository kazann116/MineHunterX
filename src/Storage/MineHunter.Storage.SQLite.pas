unit MineHunter.Storage.SQLite;

{
  История наблюдений в SQLite (MH-09): IMHRepository + IMHMetricHistory,
  история находок (IMHFindingHistory), журнал действий (IMHActionLog) и
  хранилище профилей нормы (IMHBaselineStore), учёт «что изменилось»
  (IMHInventoryHistory: впервые замеченные автозапуск, признаки вмешательства,
  программы; обновляется не чаще раза в MH_INVENTORY_REFRESH_SECONDS).

  - FireDAC со статически встроенным SQLite: внешняя sqlite3.dll не нужна.
  - Защита от повреждения: WAL + synchronous=NORMAL, транзакция на каждый
    пакет снимков, PRAGMA quick_check при открытии. Повреждённый файл не удаляется,
    а переименовывается в «*.corrupt-<время>» и создаётся новая база.
  - Миграции схемы версионируются (таблица schema_version). База более новой
    версии не изменяется — открытие завершается ошибкой.
  - Ограничение размера: удаление записей старше RetentionDays и, при
    превышении MaxDatabaseBytes, самых старых снимков; затем incremental_vacuum.
  - Объём: для каждого снимка сохраняются системные метрики и не более
    MaxProcessesPerSnapshot самых нагруженных процессов (по CPU, затем по памяти).
  - Пакетная запись: снимки и находки копятся в памяти и пишутся одной
    транзакцией раз в FlushIntervalSec. Отдельная транзакция на снимок каждые
    1–2 с переписывала десятки страниц по 4 КБ (индекс процессов по PID
    разбрасывает вставки по всему дереву) — ≈ 225 КБ записи на снимок против
    ≈ 16 КБ при пакете за минуту. Перед любым чтением истории и при закрытии
    очередь записывается, поэтому читатели видят все данные; при аварийном
    завершении теряется не больше FlushIntervalSec последних секунд.
  - Приватность: при StoreProcessPaths = False пути процессов не сохраняются.
  - Потокобезопасность: одно соединение, все операции под блокировкой.
    SaveSnapshot вызывается из потока сканера, чтение — из любого потока.
  - Схема 2: контекст работы снимка (snapshots.context, NULL — неизвестен),
    находки с объединением повторов по ключу (findings), профили нормы по
    контекстам (baselines), журнал действий (actions, не более
    MaxActionRecords последних записей). База версии 1 обновляется на месте.
  - Ловушки FireDAC/SQLite: колонки INTEGER читаются как 32-битные — для
    64-битных значений объявляется BIGINT; колонки-выражения с NULL в первой
    строке становятся строковыми — числа читаются через FieldAsDouble;
    PRAGMA, возвращающие строки, выполняются через RunPragma; ExecSQL не
    используется для операторов, возвращающих строки.
}

interface

uses
  System.SysUtils, System.SyncObjs,
  FireDAC.Comp.Client,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Analysis.Baseline,
  MineHunter.Core.Inventory, MineHunter.Core.Launches;

type
  EMHStorageError = class(EMHError);

  TMHStorageOptions = record
  public
    RetentionDays: Integer;
    MaxDatabaseBytes: Int64;
    MaxProcessesPerSnapshot: Integer;
    StoreProcessPaths: Boolean;
    /// Обслуживание (ротация) запускается раз в столько сохранений.
    MaintenanceEverySaves: Integer;
    /// Сколько последних записей журнала действий хранится.
    MaxActionRecords: Integer;
    /// Снимки и находки пишутся на диск пакетом раз в столько секунд
    /// (0 — сразу, каждый снимок отдельной транзакцией).
    FlushIntervalSec: Integer;
    class function Default: TMHStorageOptions; static;
    function Normalized: TMHStorageOptions;
  end;

  TMHSQLiteRepository = class(TInterfacedObject, IMHRepository, IMHMetricHistory,
    IMHFindingHistory, IMHActionLog, IMHBaselineStore, IMHInventoryHistory, IMHLaunchHistory)
  public const
    SchemaVersion = 5;
    /// Журнал запусков: срок хранения не меньше этого и не больше MaxLaunchRows строк.
    MinLaunchRetentionDays = 30;
    MaxLaunchRows = 300000;
    /// Учёт хранится не меньше этого срока (даже при короткой истории снимков).
    MinInventoryRetentionDays = 30;
    MaxInventoryRows = 20000;
    /// Предел кэша страниц SQLite на соединение (страниц по 4 КБ ≈ 8 МБ). Значение
    /// FireDAC по умолчанию — 10000 страниц (≈ 40 МБ), кэш растёт вместе с базой.
    CacheSizePages = 2000;
    /// Предел очереди записи: при достижении пакет пишется раньше срока.
    MaxPendingSnapshots = 600;
    MaxPendingFindings = 20000;
  private type
    /// Снимок в очереди записи: только сохраняемые поля (метрики, источники,
    /// отобранные процессы, запуски) и, если подошёл срок, учёт «что изменилось».
    TPendingSnapshot = record
      Snapshot: TMHSnapshot;
      HasInventory: Boolean;
      Inventory: TArray<TMHInventoryItem>;
    end;
  private
    FLock: TCriticalSection;
    FConnection: TFDConnection;
    FFileName: string;
    FOptions: TMHStorageOptions;
    FClock: IMHClock;
    FLogger: IMHLogger;
    FSavesSinceMaintenance: Integer;
    FRecoveredFrom: string;
    FInsertSnapshot, FInsertMetric, FInsertSource, FInsertProcess: TFDQuery;
    FUpsertFinding, FInsertAction: TFDQuery;
    FUpsertInventory: TFDQuery;
    FUpsertLaunch: TFDQuery;
    FLastInventoryUtc: TDateTime;
    FPending: TArray<TPendingSnapshot>;
    FPendingCount: Integer;
    FPendingFindings: TArray<TMHFinding>;
    FPendingFindingCount: Integer;
    /// Время постановки в очередь первой записи пакета (0 — очередь пуста).
    FPendingSinceUtc: TDateTime;
    procedure SaveLaunchesLocked(const ASnapshot: TMHSnapshot);
    /// Подошёл ли срок обновить учёт (не чаще MH_INVENTORY_REFRESH_SECONDS).
    function InventoryDueLocked(ATimestampUtc: TDateTime): Boolean;
    procedure WriteInventoryLocked(const AItems: TArray<TMHInventoryItem>; ASeenUtc: TDateTime);
    procedure WriteSnapshotLocked(const AItem: TPendingSnapshot);
    procedure WriteFindingLocked(const AFinding: TMHFinding);
    procedure MarkPendingLocked;
    function FlushDueLocked: Boolean;
    /// Пишет очередь одной транзакцией. При ошибке пакет отбрасывается
    /// (как раньше отдельный снимок), исключение передаётся вызывающему.
    procedure FlushLocked;
    /// Перед чтением: записать очередь, ошибку — только в журнал.
    procedure FlushBeforeReadLocked;
    procedure Log(ALevel: TMHLogLevel; const AMessage: string);
    procedure CheckOpen;
    procedure OpenConnection(AIsNew: Boolean);
    procedure CloseConnection;
    function CheckIntegrity: Boolean;
    procedure QuarantineCorruptFile;
    procedure Migrate;
    procedure PrepareStatements;
    function NewQuery(const ASql: string): TFDQuery;
    /// Выполняет PRAGMA, возвращающую строки, до конца (иначе оператор остаётся
    /// незавершённым и следующая фиксация транзакции завершается ошибкой).
    procedure RunPragma(const ASql: string);
    procedure MaintenanceLocked;
    /// Оставляет MaxActionRecords последних записей журнала действий.
    function TrimActionsLocked: Int64;
    function UsedBytesLocked: Int64;
    function SelectProcesses(const ASnapshot: TMHSnapshot): TArray<TMHProcessInfo>;
    /// Загружает снимки, выбранные запросом ASelect (колонки id, seq, ts, context
    /// в порядке выдачи), вместе с метриками, процессами и, при AWithSources,
    /// статусами источников. ABind задаёт параметры запроса.
    function LoadSnapshotsLocked(const ASelect: string; const ABind: TProc<TFDQuery>;
      AWithSources: Boolean): TArray<TMHSnapshot>;
    function LoadSeriesLocked(const ASql: string; const AParams: array of Variant;
      AFromMs, AToMs: Int64; AMaxPoints: Integer; AKind: TMHMetricKind): TArray<TMHMetric>;
    function GetOptions: TMHStorageOptions;
    procedure SetOptions(const AValue: TMHStorageOptions);
  public
    /// Открывает (или создаёт) базу. Повреждённая база переименовывается и
    /// пересоздаётся; при невозможности открыть файл — EMHStorageError.
    constructor Create(const AFileName: string; const AOptions: TMHStorageOptions;
      const AClock: IMHClock; const ALogger: IMHLogger);
    destructor Destroy; override;

    { IMHRepository }
    /// Ставит снимок в очередь записи (см. TMHStorageOptions.FlushIntervalSec).
    procedure SaveSnapshot(const ASnapshot: TMHSnapshot);
    /// Записывает очередь снимков и находок на диск сейчас.
    procedure Flush;
    function LoadHistory(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer): TArray<TMHSnapshot>;
    { IMHMetricHistory }
    function LoadMetricSeries(AKind: TMHMetricKind; AFromUtc, AToUtc: TDateTime;
      AMaxPoints: Integer): TArray<TMHMetric>;
    function LoadProcessSeries(const AId: TMHProcessId; AKind: TMHMetricKind;
      AFromUtc, AToUtc: TDateTime; AMaxPoints: Integer): TArray<TMHMetric>;
    function GetStats: TMHHistoryStats;
    /// Удаляет снимки и находки. Журнал действий и профили нормы сохраняются:
    /// журнал — для аудита (в том числе самой очистки), профили — агрегаты,
    /// которые перестраиваются менеджером нормы.
    procedure Clear;
    /// Действующий размер кэша страниц соединения (PRAGMA cache_size; диагностика).
    function CacheSizeSetting: Integer;

    { IMHFindingHistory }
    /// Объединяет повторы по TMHFinding.Key: last_seen — время обнаружения
    /// (DetectedAtUtc; 0 — текущее время), occurrences + 1, max_score — максимум,
    /// уровень и JSON — от самого позднего наблюдения. Пустой ключ заменяется
    /// на MHDefaultFindingKey (процесс + категория).
    procedure SaveFindings(const AFindings: TMHFindings);
    function LoadFindings(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer): TArray<TMHStoredFinding>;

    { IMHActionLog }
    procedure LogAction(const ARecord: TMHActionRecord);
    function LoadActions(AMaxCount: Integer): TArray<TMHActionRecord>;

    { IMHInventoryHistory }
    function LoadInventoryChanges(ASinceUtc: TDateTime; AMaxCount: Integer): TArray<TMHInventoryItem>;
    function InventoryStartUtc: TDateTime;

    { IMHLaunchHistory }
    function LoadLaunches(AFromUtc, AToUtc: TDateTime; const AFilter: string;
      AMaxCount: Integer): TArray<TMHLaunchRecord>;

    { IMHBaselineStore }
    /// Сохраняет (заменяет) профиль нормы контекста ABaseline.Context.
    procedure SaveBaseline(const ABaseline: TMHBaseline);
    /// Сохранённые профили по возрастанию контекста. Повреждённые записи
    /// пропускаются с предупреждением в журнале.
    function LoadBaselines: TArray<TMHBaseline>;
    /// Снимки контекста AContext из интервала, равномерно прореженные до
    /// AMaxCount (каждый k-й по времени), по возрастанию времени. Загружаются
    /// метрики и процессы, статусы источников — нет. Для wcUnknown выбираются
    /// снимки без контекста.
    /// Число снимков режима работы за период (для прогресса профиля нормы).
    function CountSnapshots(AFromUtc, AToUtc: TDateTime; AContext: TMHWorkContext): Int64;
    function LoadSnapshotsSampled(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer;
      AContext: TMHWorkContext): TArray<TMHSnapshot>;

    /// Ротация по сроку хранения и размеру (выполняется и автоматически).
    procedure RunMaintenance;

    property FileName: string read FFileName;
    property Options: TMHStorageOptions read GetOptions write SetOptions;
    /// Путь, куда был перемещён повреждённый файл при открытии ('' — не было).
    property RecoveredFrom: string read FRecoveredFrom;
  end;

/// Путь базы истории: <папка данных>\history.db (по умолчанию %LOCALAPPDATA%\MineHunterX).
function MHDefaultHistoryPath: string;

/// Время UTC <-> миллисекунды Unix (формат хранения в базе).
function MHUtcToUnixMs(AUtc: TDateTime): Int64;
function MHUnixMsToUtc(AMs: Int64): TDateTime;

/// Ключ находки по умолчанию (когда анализатор не задал Key):
/// «<PID>@<время создания hex>|<категория>», например «1234@1d9a…|mining».
function MHDefaultFindingKey(const AFinding: TMHFinding): string;

implementation

uses
  System.Classes, System.Variants, System.Math, System.DateUtils, System.IOUtils,
  System.Generics.Collections, System.Generics.Defaults,
  Winapi.Windows, Winapi.ShlObj, MineHunter.Core.DataDir,
  Data.DB,
  FireDAC.Stan.Intf, FireDAC.Stan.Option, FireDAC.Stan.Error, FireDAC.Stan.Def,
  FireDAC.Stan.Async, FireDAC.Stan.Param, FireDAC.Phys.Intf, FireDAC.Phys,
  FireDAC.Phys.SQLite, FireDAC.Phys.SQLiteDef, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.DApt, FireDAC.ConsoleUI.Wait,
  MineHunter.Core.Serialization, MineHunter.Core.Lang;

const
  STORAGE_SOURCE = 'storage';

  // Для 64-битных значений используется тип BIGINT: FireDAC читает колонки
  // SQLite типа INTEGER как 32-битные. id INTEGER PRIMARY KEY — псевдоним rowid.

  MIGRATIONS: array[1..5] of string = (
    'CREATE TABLE snapshots(' +
    '  id INTEGER PRIMARY KEY,' +
    '  seq BIGINT NOT NULL,' +
    '  ts BIGINT NOT NULL);' +
    'CREATE INDEX ix_snapshots_ts ON snapshots(ts);' +
    'CREATE TABLE metrics(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  kind TEXT NOT NULL,' +
    '  value REAL,' +
    '  PRIMARY KEY(snapshot_id, kind)) WITHOUT ROWID;' +
    'CREATE TABLE sources(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  source_id TEXT NOT NULL,' +
    '  state TEXT NOT NULL,' +
    '  message TEXT,' +
    '  requires_elevation INTEGER NOT NULL,' +
    '  duration_ms BIGINT NOT NULL,' +
    '  item_count INTEGER NOT NULL,' +
    '  PRIMARY KEY(snapshot_id, source_id)) WITHOUT ROWID;' +
    'CREATE TABLE process_samples(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  pid BIGINT NOT NULL,' +
    '  create_time BIGINT NOT NULL,' +
    '  parent_pid BIGINT NOT NULL,' +
    '  name TEXT NOT NULL,' +
    '  image_path TEXT,' +
    '  access TEXT NOT NULL,' +
    '  cpu REAL,' +
    '  working_set REAL,' +
    '  private_bytes REAL,' +
    '  thread_count INTEGER NOT NULL,' +
    '  source_id TEXT NOT NULL,' +
    '  PRIMARY KEY(snapshot_id, pid, create_time, source_id)) WITHOUT ROWID;' +
    'CREATE INDEX ix_process_samples_identity ON process_samples(pid, create_time);',

    // 2: контекст снимка, находки, профили нормы, журнал действий.
    'ALTER TABLE snapshots ADD COLUMN context TEXT;' +
    'CREATE INDEX ix_snapshots_context_ts ON snapshots(context, ts);' +
    'CREATE TABLE findings(' +
    '  key TEXT PRIMARY KEY,' +
    '  first_seen BIGINT NOT NULL,' +
    '  last_seen BIGINT NOT NULL,' +
    '  max_score INTEGER NOT NULL,' +
    '  occurrences BIGINT NOT NULL,' +
    '  level TEXT NOT NULL,' +
    '  json TEXT NOT NULL);' +
    'CREATE INDEX ix_findings_last_seen ON findings(last_seen);' +
    'CREATE TABLE baselines(' +
    '  context TEXT PRIMARY KEY,' +
    '  updated BIGINT NOT NULL,' +
    '  json TEXT NOT NULL);' +
    'CREATE TABLE actions(' +
    '  id INTEGER PRIMARY KEY,' +
    '  ts BIGINT NOT NULL,' +
    '  action TEXT NOT NULL,' +
    '  target TEXT NOT NULL,' +
    '  result TEXT NOT NULL,' +
    '  success INTEGER NOT NULL);',

    // 3: учёт «что изменилось».
    'CREATE TABLE inventory(' +
    '  kind TEXT NOT NULL,' +
    '  key TEXT NOT NULL,' +
    '  name TEXT NOT NULL,' +
    '  details TEXT,' +
    '  image_path TEXT,' +
    '  first_seen BIGINT NOT NULL,' +
    '  last_seen BIGINT NOT NULL,' +
    '  PRIMARY KEY(kind, key)) WITHOUT ROWID;' +
    'CREATE INDEX ix_inventory_first_seen ON inventory(first_seen);' +
    'CREATE INDEX ix_inventory_last_seen ON inventory(last_seen);',

    // 4: журнал запусков программ.
    'CREATE TABLE launches(' +
    '  pid BIGINT NOT NULL,' +
    '  create_time BIGINT NOT NULL,' +
    '  start_ts BIGINT NOT NULL,' +
    '  exit_ts BIGINT,' +
    '  name TEXT NOT NULL,' +
    '  image_path TEXT,' +
    '  parent_pid BIGINT NOT NULL,' +
    '  parent_name TEXT,' +
    '  source TEXT NOT NULL,' +
    '  PRIMARY KEY(pid, create_time)) WITHOUT ROWID;' +
    'CREATE INDEX ix_launches_start ON launches(start_ts);',

    // 5: параметры запуска (командная строка) в журнале запусков.
    'ALTER TABLE launches ADD COLUMN command_line TEXT;'
  );

  // Запуск и завершение одного экземпляра приходят разными записями: объединяем.
  UPSERT_LAUNCH_SQL =
    'INSERT INTO launches(pid, create_time, start_ts, exit_ts, name, image_path, parent_pid, parent_name, source, ' +
    '  command_line) ' +
    'VALUES (:pid, :ct, :start, :exit, :name, :path, :ppid, :pname, :source, :cmd) ' +
    'ON CONFLICT(pid, create_time) DO UPDATE SET ' +
    '  exit_ts = COALESCE(excluded.exit_ts, launches.exit_ts),' +
    '  name = CASE WHEN excluded.name <> '''' THEN excluded.name ELSE launches.name END,' +
    '  image_path = COALESCE(excluded.image_path, launches.image_path),' +
    '  parent_pid = CASE WHEN excluded.parent_pid <> 0 THEN excluded.parent_pid ELSE launches.parent_pid END,' +
    '  parent_name = COALESCE(excluded.parent_name, launches.parent_name),' +
    '  command_line = COALESCE(excluded.command_line, launches.command_line)';

  UPSERT_INVENTORY_SQL =
    'INSERT INTO inventory(kind, key, name, details, image_path, first_seen, last_seen) ' +
    'VALUES (:kind, :key, :name, :details, :path, :seen, :seen) ' +
    'ON CONFLICT(kind, key) DO UPDATE SET ' +
    '  last_seen = MAX(inventory.last_seen, excluded.last_seen),' +
    '  first_seen = MIN(inventory.first_seen, excluded.first_seen),' +
    '  name = excluded.name, details = excluded.details,' +
    '  image_path = COALESCE(excluded.image_path, inventory.image_path)';

  // Повтор находки: время первого/последнего наблюдения расширяется, счётчик
  // растёт, уровень и JSON берутся от самого позднего наблюдения.
  UPSERT_FINDING_SQL =
    'INSERT INTO findings(key, first_seen, last_seen, max_score, occurrences, level, json) ' +
    'VALUES (:key, :seen, :seen, :score, 1, :level, :json) ' +
    'ON CONFLICT(key) DO UPDATE SET ' +
    '  first_seen = MIN(findings.first_seen, excluded.first_seen),' +
    '  last_seen = MAX(findings.last_seen, excluded.last_seen),' +
    '  max_score = MAX(findings.max_score, excluded.max_score),' +
    '  occurrences = findings.occurrences + 1,' +
    '  level = CASE WHEN excluded.last_seen >= findings.last_seen ' +
    '    THEN excluded.level ELSE findings.level END,' +
    '  json = CASE WHEN excluded.last_seen >= findings.last_seen ' +
    '    THEN excluded.json ELSE findings.json END';

function MHDefaultHistoryPath: string;
begin
  Result := TPath.Combine(MHDataDir, 'history.db');
end;

function MHUtcToUnixMs(AUtc: TDateTime): Int64;
begin
  Result := Round((AUtc - UnixDateDelta) * MSecsPerDay);
end;

function MHUnixMsToUtc(AMs: Int64): TDateTime;
begin
  Result := AMs / MSecsPerDay + UnixDateDelta;
end;

function MHDefaultFindingKey(const AFinding: TMHFinding): string;
begin
  Result := AFinding.Process.ToString + '|' + MHFindingCategoryToName(AFinding.Category);
end;

function MetricValue(const AMetric: TMHMetric): Variant;
begin
  if AMetric.HasValue then
    Result := AMetric.Value
  else
    Result := Null;
end;

/// Число из поля без зависимости от локали. Тип колонок-выражений (AVG и т.п.)
/// FireDAC определяет по первой строке: если она NULL, колонка становится
/// строковой, и AsFloat разбирал бы «75.14» по региональным настройкам.
function FieldAsDouble(AField: TField): Double;
begin
  if AField.DataType in [ftString, ftWideString, ftMemo, ftWideMemo, ftFixedChar, ftFixedWideChar] then
    Result := StrToFloat(AField.AsString, TFormatSettings.Invariant)
  else
    Result := AField.AsFloat;
end;

function MetricFromField(AKind: TMHMetricKind; AField: TField; ATime: TDateTime): TMHMetric;
begin
  if AField.IsNull then
    Result := TMHMetric.NoData(AKind, ATime)
  else
    Result := TMHMetric.Available(AKind, FieldAsDouble(AField), ATime);
end;

procedure SetParam(AQuery: TFDQuery; const AName: string; const AValue: Variant;
  ADataType: TFieldType);
var
  LParam: TFDParam;
begin
  LParam := AQuery.ParamByName(AName);
  LParam.DataType := ADataType;
  if VarIsNull(AValue) then
    LParam.Clear
  else
    LParam.Value := AValue;
end;

{ TMHStorageOptions }

class function TMHStorageOptions.Default: TMHStorageOptions;
begin
  Result.RetentionDays := 7;
  Result.MaxDatabaseBytes := 256 * 1024 * 1024;
  Result.MaxProcessesPerSnapshot := 30;
  Result.StoreProcessPaths := True;
  Result.MaintenanceEverySaves := 300;
  Result.MaxActionRecords := 10000;
  Result.FlushIntervalSec := 60;
end;

function TMHStorageOptions.Normalized: TMHStorageOptions;
begin
  Result := Self;
  Result.RetentionDays := EnsureRange(RetentionDays, 1, 3650);
  Result.MaxDatabaseBytes := Max(Int64(4 * 1024 * 1024), MaxDatabaseBytes);
  Result.MaxProcessesPerSnapshot := EnsureRange(MaxProcessesPerSnapshot, 0, 10000);
  Result.MaintenanceEverySaves := Max(1, MaintenanceEverySaves);
  Result.MaxActionRecords := EnsureRange(MaxActionRecords, 10, 1000000);
  Result.FlushIntervalSec := EnsureRange(FlushIntervalSec, 0, 3600);
end;

{ TMHSQLiteRepository }

constructor TMHSQLiteRepository.Create(const AFileName: string;
  const AOptions: TMHStorageOptions; const AClock: IMHClock; const ALogger: IMHLogger);
var
  LIsNew, LHealthy: Boolean;
begin
  inherited Create;
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if ALogger = nil then
    raise EArgumentNilException.Create('ALogger');
  if Trim(AFileName) = '' then
    raise EArgumentException.Create(MHL('Не задан путь к базе истории',
      'The history database path is not specified'));
  FClock := AClock;
  FLogger := ALogger;
  FOptions := AOptions.Normalized;
  FFileName := TPath.GetFullPath(AFileName);
  FLock := TCriticalSection.Create;
  try
    ForceDirectories(ExtractFileDir(FFileName));
    LIsNew := not FileExists(FFileName);
    try
      OpenConnection(LIsNew);
      LHealthy := CheckIntegrity;
    except
      on E: Exception do
      begin
        Log(llWarning, MHL('Ошибка открытия базы истории: ', 'Error opening the history database: ') +
          E.Message);
        LHealthy := False;
      end;
    end;
    if not LHealthy then
    begin
      CloseConnection;
      QuarantineCorruptFile;
      OpenConnection(True);
      LIsNew := True;
    end;
    Migrate;
    PrepareStatements;
    if not LIsNew then
      MaintenanceLocked;
  except
    on E: Exception do
    begin
      CloseConnection;
      FreeAndNil(FLock);
      if E is EMHStorageError then
        raise;
      raise EMHStorageError.CreateFmt(MHL('Не удалось открыть базу истории «%s»: %s',
        'Failed to open the history database "%s": %s'), [FFileName, E.Message]);
    end;
  end;
end;

destructor TMHSQLiteRepository.Destroy;
begin
  if FLock <> nil then
  begin
    FLock.Enter;
    try
      if FConnection <> nil then
        try
          FlushLocked;
        except
          on E: Exception do
            Log(llWarning, MHL('Последние снимки не записаны при закрытии: ',
              'The latest snapshots were not written on close: ') + E.Message);
        end;
      CloseConnection;
    finally
      FLock.Leave;
    end;
  end;
  FLock.Free;
  inherited;
end;

procedure TMHSQLiteRepository.Log(ALevel: TMHLogLevel; const AMessage: string);
begin
  try
    FLogger.Log(ALevel, STORAGE_SOURCE, AMessage);
  except
    // Сбой журнала не должен ломать хранилище.
  end;
end;

procedure TMHSQLiteRepository.CheckOpen;
begin
  if FConnection = nil then
    raise EMHStorageError.Create(MHL('База истории закрыта', 'The history database is closed'));
end;

procedure TMHSQLiteRepository.OpenConnection(AIsNew: Boolean);
begin
  FConnection := TFDConnection.Create(nil);
  FConnection.DriverName := 'SQLite';
  FConnection.LoginPrompt := False;
  FConnection.ResourceOptions.SilentMode := True;
  FConnection.Params.Database := FFileName;
  FConnection.Params.Values['OpenMode'] := 'CreateUTF8';
  FConnection.Params.Values['LockingMode'] := 'Normal';
  FConnection.Params.Values['Synchronous'] := 'Normal';
  FConnection.Params.Values['JournalMode'] := 'WAL';
  FConnection.Params.Values['ForeignKeys'] := 'On';
  FConnection.Params.Values['BusyTimeout'] := '5000';
  FConnection.Params.Values['StringFormat'] := 'Unicode';
  FConnection.Params.Values['CacheSize'] := IntToStr(CacheSizePages);
  FConnection.Connected := True;
  if AIsNew then
    // Должно выполняться до создания таблиц, иначе не действует.
    FConnection.ExecSQL('PRAGMA auto_vacuum = INCREMENTAL');
end;

procedure TMHSQLiteRepository.CloseConnection;
begin
  FreeAndNil(FInsertSnapshot);
  FreeAndNil(FInsertMetric);
  FreeAndNil(FInsertSource);
  FreeAndNil(FInsertProcess);
  FreeAndNil(FUpsertFinding);
  FreeAndNil(FInsertAction);
  FreeAndNil(FUpsertInventory);
  FreeAndNil(FUpsertLaunch);
  if FConnection <> nil then
  begin
    try
      FConnection.Connected := False;
    except
      // Закрытие повреждённой базы может завершиться ошибкой — объект всё равно освобождаем.
    end;
    FreeAndNil(FConnection);
  end;
end;

function TMHSQLiteRepository.CheckIntegrity: Boolean;
var
  LResult: string;
begin
  LResult := VarToStr(FConnection.ExecSQLScalar('PRAGMA quick_check'));
  Result := SameText(LResult, 'ok');
  if not Result then
    Log(llWarning, MHL('Проверка целостности базы истории: ', 'History database integrity check: ') +
      LResult);
end;

procedure TMHSQLiteRepository.QuarantineCorruptFile;
var
  LTarget, LSuffix: string;
begin
  if not FileExists(FFileName) then
    Exit;
  LSuffix := '.corrupt-' + FormatDateTime('yyyymmdd-hhnnss', Now);
  LTarget := FFileName + LSuffix;
  if not RenameFile(FFileName, LTarget) then
    raise EMHStorageError.CreateFmt(
      MHL('База истории повреждена и не может быть перемещена (%s)',
        'The history database is corrupted and cannot be moved (%s)'), [SysErrorMessage(GetLastError)]);
  // Журналы WAL принадлежат повреждённой базе и переносятся вместе с ней.
  if FileExists(FFileName + '-wal') then
    RenameFile(FFileName + '-wal', LTarget + '-wal');
  if FileExists(FFileName + '-shm') then
    RenameFile(FFileName + '-shm', LTarget + '-shm');
  FRecoveredFrom := LTarget;
  Log(llWarning, MHL('База истории повреждена и сохранена как «',
    'The history database is corrupted and was saved as "') + LTarget +
    MHL('»; создана новая база', '"; a new database was created'));
end;

procedure TMHSQLiteRepository.Migrate;
var
  LVersion, I: Integer;
begin
  FConnection.ExecSQL('CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)');
  LVersion := FConnection.ExecSQLScalar('SELECT COALESCE(MAX(version), 0) FROM schema_version');
  if LVersion > SchemaVersion then
    raise EMHStorageError.CreateFmt(
      MHL('База истории создана более новой версией MineHunter X (схема %d, поддерживается %d)',
        'The history database was created by a newer version of MineHunter X (schema %d, ' +
        'supported %d)'), [LVersion, SchemaVersion]);
  for I := LVersion + 1 to SchemaVersion do
  begin
    FConnection.StartTransaction;
    try
      FConnection.ExecSQL(MIGRATIONS[I]);
      FConnection.ExecSQL('DELETE FROM schema_version');
      FConnection.ExecSQL('INSERT INTO schema_version(version) VALUES (' + IntToStr(I) + ')');
      FConnection.Commit;
    except
      FConnection.Rollback;
      raise;
    end;
    Log(llInfo, Format(MHL('Схема базы истории обновлена до версии %d',
      'History database schema upgraded to version %d'), [I]));
  end;
end;

function TMHSQLiteRepository.NewQuery(const ASql: string): TFDQuery;
begin
  Result := TFDQuery.Create(nil);
  Result.Connection := FConnection;
  Result.ResourceOptions.SilentMode := True;
  Result.FetchOptions.Unidirectional := True;
  Result.SQL.Text := ASql;
end;

procedure TMHSQLiteRepository.RunPragma(const ASql: string);
var
  LQuery: TFDQuery;
begin
  LQuery := NewQuery(ASql);
  try
    // Одни PRAGMA возвращают строки (wal_checkpoint), другие — нет (incremental_vacuum).
    if LQuery.OpenOrExecute then
    begin
      while not LQuery.Eof do
        LQuery.Next;
      LQuery.Close;
    end;
  finally
    LQuery.Free;
  end;
end;

procedure TMHSQLiteRepository.PrepareStatements;
begin
  FInsertSnapshot := NewQuery('INSERT INTO snapshots(seq, ts, context) VALUES (:seq, :ts, :ctx)');
  FInsertMetric := NewQuery(
    'INSERT OR REPLACE INTO metrics(snapshot_id, kind, value) VALUES (:sid, :kind, :value)');
  FInsertSource := NewQuery('INSERT OR REPLACE INTO sources(snapshot_id, source_id, state, ' +
    'message, requires_elevation, duration_ms, item_count) VALUES ' +
    '(:sid, :source, :state, :message, :elev, :duration, :items)');
  FInsertProcess := NewQuery('INSERT OR REPLACE INTO process_samples(snapshot_id, pid, ' +
    'create_time, parent_pid, name, image_path, access, cpu, working_set, private_bytes, ' +
    'thread_count, source_id) VALUES (:sid, :pid, :ct, :ppid, :name, :path, :access, :cpu, ' +
    ':ws, :priv, :threads, :source)');
  FUpsertFinding := NewQuery(UPSERT_FINDING_SQL);
  FInsertAction := NewQuery('INSERT INTO actions(ts, action, target, result, success) ' +
    'VALUES (:ts, :action, :target, :result, :success)');
  FUpsertInventory := NewQuery(UPSERT_INVENTORY_SQL);
  FUpsertLaunch := NewQuery(UPSERT_LAUNCH_SQL);
end;

function TMHSQLiteRepository.GetOptions: TMHStorageOptions;
begin
  FLock.Enter;
  try
    Result := FOptions;
  finally
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.SetOptions(const AValue: TMHStorageOptions);
begin
  FLock.Enter;
  try
    FOptions := AValue.Normalized;
    if (FPendingSinceUtc <> 0) and FlushDueLocked then
      FlushBeforeReadLocked;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.SelectProcesses(const ASnapshot: TMHSnapshot): TArray<TMHProcessInfo>;
var
  LList: TList<TMHProcessInfo>;
  LLimit, I: Integer;
begin
  LLimit := FOptions.MaxProcessesPerSnapshot;
  if (LLimit = 0) or (Length(ASnapshot.Processes) = 0) then
    Exit(nil);
  LList := TList<TMHProcessInfo>.Create;
  try
    // Записи самодиагностики дублируют данные коллектора процессов.
    for I := 0 to High(ASnapshot.Processes) do
      if not SameText(ASnapshot.Processes[I].SourceId, MH_SELF_SOURCE_ID) then
        LList.Add(ASnapshot.Processes[I]);
    // Самые нагруженные: по CPU (без данных — в конце), затем по рабочему набору.
    LList.Sort(TComparer<TMHProcessInfo>.Construct(
      function(const A, B: TMHProcessInfo): Integer
      begin
        if A.Cpu.HasValue <> B.Cpu.HasValue then
          Exit(IfThen(A.Cpu.HasValue, -1, 1));
        Result := CompareValue(B.Cpu.Value, A.Cpu.Value);
        if Result = 0 then
          Result := CompareValue(B.WorkingSet.Value, A.WorkingSet.Value);
      end));
    if LList.Count > LLimit then
      LList.Count := LLimit;
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

procedure TMHSQLiteRepository.SaveSnapshot(const ASnapshot: TMHSnapshot);
var
  LItem: TPendingSnapshot;
begin
  FLock.Enter;
  try
    CheckOpen;
    // В очереди — только то, что пишется в базу: полный снимок (файлы,
    // соединения, автозапуск) занимал бы мегабайты памяти за минуту. Массивы
    // копируются: снимок принадлежит сканеру и может меняться после вызова.
    LItem.Snapshot := TMHSnapshot.Create(ASnapshot.Sequence, ASnapshot.TimestampUtc);
    LItem.Snapshot.Context := ASnapshot.Context;
    LItem.Snapshot.Metrics := Copy(ASnapshot.Metrics);
    LItem.Snapshot.Sources := Copy(ASnapshot.Sources);
    LItem.Snapshot.Processes := SelectProcesses(ASnapshot);
    LItem.Snapshot.LaunchEvents := Copy(ASnapshot.LaunchEvents);
    LItem.HasInventory := InventoryDueLocked(ASnapshot.TimestampUtc);
    if LItem.HasInventory then
      LItem.Inventory := MHInventoryFromSnapshot(ASnapshot, FOptions.StoreProcessPaths)
    else
      LItem.Inventory := nil;
    if FPendingCount = Length(FPending) then
      SetLength(FPending, Max(16, FPendingCount * 2));
    FPending[FPendingCount] := LItem;
    Inc(FPendingCount);
    MarkPendingLocked;
    if FlushDueLocked then
      FlushLocked;
  finally
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.WriteSnapshotLocked(const AItem: TPendingSnapshot);
var
  LSnapshotId: Int64;
  LMetric: TMHMetric;
  LStatus: TMHSourceStatus;
  LInfo: TMHProcessInfo;
  LPath, LContext: Variant;
begin
  if AItem.Snapshot.Context.Available then
    LContext := MHWorkContextToName(AItem.Snapshot.Context.WorkContext)
  else
    LContext := Null;
  SetParam(FInsertSnapshot, 'seq', Int64(AItem.Snapshot.Sequence), ftLargeint);
  SetParam(FInsertSnapshot, 'ts', MHUtcToUnixMs(AItem.Snapshot.TimestampUtc), ftLargeint);
  SetParam(FInsertSnapshot, 'ctx', LContext, ftWideString);
  FInsertSnapshot.ExecSQL;
  LSnapshotId := FConnection.GetLastAutoGenValue('');

  for LMetric in AItem.Snapshot.Metrics do
  begin
    SetParam(FInsertMetric, 'sid', LSnapshotId, ftLargeint);
    SetParam(FInsertMetric, 'kind', MHMetricKindToName(LMetric.Kind), ftWideString);
    SetParam(FInsertMetric, 'value', MetricValue(LMetric), ftFloat);
    FInsertMetric.ExecSQL;
  end;

  for LStatus in AItem.Snapshot.Sources do
  begin
    SetParam(FInsertSource, 'sid', LSnapshotId, ftLargeint);
    SetParam(FInsertSource, 'source', LStatus.SourceId, ftWideString);
    SetParam(FInsertSource, 'state', MHSourceStateToName(LStatus.State), ftWideString);
    SetParam(FInsertSource, 'message', LStatus.Message, ftWideString);
    SetParam(FInsertSource, 'elev', Ord(LStatus.RequiresElevation), ftInteger);
    SetParam(FInsertSource, 'duration', Int64(LStatus.DurationMs), ftLargeint);
    SetParam(FInsertSource, 'items', LStatus.ItemCount, ftInteger);
    FInsertSource.ExecSQL;
  end;

  // Процессы уже отобраны при постановке в очередь (SelectProcesses).
  for LInfo in AItem.Snapshot.Processes do
  begin
    if FOptions.StoreProcessPaths and (LInfo.ImagePath <> '') then
      LPath := LInfo.ImagePath
    else
      LPath := Null;
    SetParam(FInsertProcess, 'sid', LSnapshotId, ftLargeint);
    SetParam(FInsertProcess, 'pid', Int64(LInfo.Id.Pid), ftLargeint);
    SetParam(FInsertProcess, 'ct', Int64(LInfo.Id.CreateTime), ftLargeint);
    SetParam(FInsertProcess, 'ppid', Int64(LInfo.ParentPid), ftLargeint);
    SetParam(FInsertProcess, 'name', LInfo.Name, ftWideString);
    SetParam(FInsertProcess, 'path', LPath, ftWideString);
    SetParam(FInsertProcess, 'access', MHAccessLevelToName(LInfo.Access), ftWideString);
    SetParam(FInsertProcess, 'cpu', MetricValue(LInfo.Cpu), ftFloat);
    SetParam(FInsertProcess, 'ws', MetricValue(LInfo.WorkingSet), ftFloat);
    SetParam(FInsertProcess, 'priv', MetricValue(LInfo.PrivateBytes), ftFloat);
    SetParam(FInsertProcess, 'threads', LInfo.ThreadCount, ftInteger);
    SetParam(FInsertProcess, 'source', LInfo.SourceId, ftWideString);
    FInsertProcess.ExecSQL;
  end;
  if AItem.HasInventory then
    WriteInventoryLocked(AItem.Inventory, AItem.Snapshot.TimestampUtc);
  SaveLaunchesLocked(AItem.Snapshot);
end;

procedure TMHSQLiteRepository.WriteFindingLocked(const AFinding: TMHFinding);
begin
  SetParam(FUpsertFinding, 'key', AFinding.Key, ftWideString);
  SetParam(FUpsertFinding, 'seen', MHUtcToUnixMs(AFinding.DetectedAtUtc), ftLargeint);
  SetParam(FUpsertFinding, 'score', AFinding.Score, ftInteger);
  SetParam(FUpsertFinding, 'level', MHRiskLevelToName(AFinding.Level), ftWideString);
  SetParam(FUpsertFinding, 'json', TMHJson.FindingToString(AFinding), ftWideMemo);
  FUpsertFinding.ExecSQL;
end;

procedure TMHSQLiteRepository.MarkPendingLocked;
begin
  if FPendingSinceUtc = 0 then
    FPendingSinceUtc := FClock.NowUtc;
end;

function TMHSQLiteRepository.FlushDueLocked: Boolean;
var
  LNow: TDateTime;
begin
  if (FOptions.FlushIntervalSec = 0) or (FPendingCount >= MaxPendingSnapshots) or
     (FPendingFindingCount >= MaxPendingFindings) then
    Exit(True);
  LNow := FClock.NowUtc;
  // Часы переведены назад — пакет пишется, а не копится до нового срока.
  // Разница — в целых миллисекундах: сумма шагов TDateTime теряет точность.
  Result := (LNow < FPendingSinceUtc) or
    (Round((LNow - FPendingSinceUtc) * MSecsPerDay) >= Int64(FOptions.FlushIntervalSec) * 1000);
end;

procedure TMHSQLiteRepository.FlushLocked;
var
  I, LWritten: Integer;
begin
  if (FPendingCount = 0) and (FPendingFindingCount = 0) then
    Exit;
  LWritten := FPendingCount;
  try
    FConnection.StartTransaction;
    try
      for I := 0 to FPendingCount - 1 do
        WriteSnapshotLocked(FPending[I]);
      for I := 0 to FPendingFindingCount - 1 do
        WriteFindingLocked(FPendingFindings[I]);
      FConnection.Commit;
    except
      FConnection.Rollback;
      raise;
    end;
  finally
    FPending := nil;
    FPendingCount := 0;
    FPendingFindings := nil;
    FPendingFindingCount := 0;
    FPendingSinceUtc := 0;
  end;

  Inc(FSavesSinceMaintenance, LWritten);
  if FSavesSinceMaintenance >= FOptions.MaintenanceEverySaves then
    MaintenanceLocked;
end;

procedure TMHSQLiteRepository.FlushBeforeReadLocked;
begin
  if FConnection = nil then
    Exit;
  try
    FlushLocked;
  except
    on E: Exception do
      Log(llWarning, MHL('Не удалось записать историю: ', 'Failed to write history: ') + E.Message);
  end;
end;

procedure TMHSQLiteRepository.Flush;
begin
  FLock.Enter;
  try
    CheckOpen;
    FlushLocked;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.UsedBytesLocked: Int64;
var
  LPageSize, LPages, LFree: Int64;
begin
  LPageSize := FConnection.ExecSQLScalar('PRAGMA page_size');
  LPages := FConnection.ExecSQLScalar('PRAGMA page_count');
  LFree := FConnection.ExecSQLScalar('PRAGMA freelist_count');
  Result := (LPages - LFree) * LPageSize;
end;

function TMHSQLiteRepository.TrimActionsLocked: Int64;
begin
  // Подзапрос даёт id самой новой из лишних записей (NULL, если лишних нет).
  Result := FConnection.ExecSQL('DELETE FROM actions WHERE id <= ' +
    '(SELECT id FROM actions ORDER BY id DESC LIMIT 1 OFFSET :keep)',
    [FOptions.MaxActionRecords]);
end;

procedure TMHSQLiteRepository.MaintenanceLocked;
var
  LCutoff, LDeleted, LCount, LChunk, LOther: Int64;
  LGuard: Integer;
begin
  FSavesSinceMaintenance := 0;
  LCutoff := MHUtcToUnixMs(FClock.NowUtc - FOptions.RetentionDays);
  LDeleted := FConnection.ExecSQL('DELETE FROM snapshots WHERE ts < :cutoff', [LCutoff]);
  LOther := FConnection.ExecSQL('DELETE FROM findings WHERE last_seen < :cutoff', [LCutoff]);
  // Учёт «что изменилось» мал и нужен за неделю и дольше — хранится не меньше месяца.
  Inc(LOther, FConnection.ExecSQL('DELETE FROM launches WHERE start_ts < :cutoff',
    [MHUtcToUnixMs(FClock.NowUtc - Max(FOptions.RetentionDays, MinLaunchRetentionDays))]));
  Inc(LOther, FConnection.ExecSQL('DELETE FROM launches WHERE (pid, create_time) IN (SELECT pid, create_time ' +
    'FROM launches ORDER BY start_ts DESC LIMIT -1 OFFSET :n)', [MaxLaunchRows]));
  Inc(LOther, FConnection.ExecSQL('DELETE FROM inventory WHERE last_seen < :cutoff',
    [MHUtcToUnixMs(FClock.NowUtc - Max(FOptions.RetentionDays, MinInventoryRetentionDays))]));
  Inc(LOther, FConnection.ExecSQL('DELETE FROM inventory WHERE (kind, key) IN (SELECT kind, key FROM inventory ' +
    'ORDER BY last_seen DESC LIMIT -1 OFFSET :n)', [MaxInventoryRows]));
  if LOther > 0 then
    Log(llInfo, Format(MHL('Ротация истории: удалено находок — %d',
      'History rotation: findings deleted — %d'), [LOther]));
  Inc(LOther, TrimActionsLocked);

  // Ограничение размера: удаляем самые старые снимки порциями по 10%.
  LGuard := 0;
  while (UsedBytesLocked > FOptions.MaxDatabaseBytes) and (LGuard < 20) do
  begin
    Inc(LGuard);
    LCount := FConnection.ExecSQLScalar('SELECT COUNT(*) FROM snapshots');
    if LCount = 0 then
      Break;
    LChunk := Max(Int64(1), LCount div 10);
    Inc(LDeleted, FConnection.ExecSQL('DELETE FROM snapshots WHERE id IN ' +
      '(SELECT id FROM snapshots ORDER BY ts LIMIT :n)', [LChunk]));
  end;

  if LDeleted + LOther > 0 then
    RunPragma('PRAGMA incremental_vacuum');
  if LDeleted > 0 then
    Log(llInfo, Format(MHL('Ротация истории: удалено снимков — %d',
      'History rotation: snapshots deleted — %d'), [LDeleted]));
  RunPragma('PRAGMA wal_checkpoint(TRUNCATE)');
end;

procedure TMHSQLiteRepository.RunMaintenance;
begin
  FLock.Enter;
  try
    FlushBeforeReadLocked;
    MaintenanceLocked;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadSnapshotsLocked(const ASelect: string;
  const ABind: TProc<TFDQuery>; AWithSources: Boolean): TArray<TMHSnapshot>;
var
  LQuery: TFDQuery;
  LIndexById: TDictionary<Int64, Integer>;
  LList: TList<TMHSnapshot>;
  LSnapshot: TMHSnapshot;
  LIndex: Integer;
  LKind: TMHMetricKind;
  LState: TMHSourceState;
  LAccess: TMHAccessLevel;
  LContext: TMHWorkContext;
  LStatus: TMHSourceStatus;
  LInfo: TMHProcessInfo;
  LSnaps: TArray<TMHSnapshot>;
begin
  LList := TList<TMHSnapshot>.Create;
  LIndexById := TDictionary<Int64, Integer>.Create;
  LQuery := nil;
  try
    // Дочерние записи связываются с тем же подзапросом по основной таблице.
    // (Временная таблица не годится: CREATE TABLE AS даёт колонкам тип INT,
    // который FireDAC читает как 32-битное целое и усекает время.)
    LQuery := NewQuery(ASelect);
    ABind(LQuery);
    LQuery.Open;
    while not LQuery.Eof do
    begin
      LSnapshot := TMHSnapshot.Create(UInt64(LQuery.Fields[1].AsLargeInt),
        MHUnixMsToUtc(LQuery.Fields[2].AsLargeInt));
      if not LQuery.Fields[3].IsNull and
         MHTryWorkContextFromName(LQuery.Fields[3].AsString, LContext) then
      begin
        LSnapshot.Context.Available := True;
        LSnapshot.Context.WorkContext := LContext;
      end;
      LIndexById.Add(LQuery.Fields[0].AsLargeInt, LList.Add(LSnapshot));
      LQuery.Next;
    end;
    LQuery.Close;
    LSnaps := LList.ToArray;
    if Length(LSnaps) = 0 then
      Exit(nil);

    LQuery.SQL.Text := 'SELECT m.snapshot_id, m.kind, m.value FROM metrics m ' +
      'JOIN (' + ASelect + ') s ON s.id = m.snapshot_id';
    ABind(LQuery);
    LQuery.Open;
    while not LQuery.Eof do
    begin
      if LIndexById.TryGetValue(LQuery.Fields[0].AsLargeInt, LIndex) and
         MHTryMetricKindFromName(LQuery.Fields[1].AsString, LKind) then
      begin
        LSnaps[LIndex].Metrics := LSnaps[LIndex].Metrics +
          [MetricFromField(LKind, LQuery.Fields[2], LSnaps[LIndex].TimestampUtc)];
      end;
      LQuery.Next;
    end;
    LQuery.Close;

    if AWithSources then
    begin
      LQuery.SQL.Text := 'SELECT r.snapshot_id, r.source_id, r.state, r.message, ' +
        'r.requires_elevation, r.duration_ms, r.item_count FROM sources r ' +
        'JOIN (' + ASelect + ') s ON s.id = r.snapshot_id';
      ABind(LQuery);
      LQuery.Open;
      while not LQuery.Eof do
      begin
        if LIndexById.TryGetValue(LQuery.Fields[0].AsLargeInt, LIndex) and
           MHTrySourceStateFromName(LQuery.Fields[2].AsString, LState) then
        begin
          LStatus := TMHSourceStatus.Create(LQuery.Fields[1].AsString, LState,
            LQuery.Fields[3].AsString, LSnaps[LIndex].TimestampUtc);
          LStatus.RequiresElevation := LQuery.Fields[4].AsInteger <> 0;
          LStatus.DurationMs := Cardinal(LQuery.Fields[5].AsLargeInt);
          LStatus.ItemCount := LQuery.Fields[6].AsInteger;
          LSnaps[LIndex].Sources := LSnaps[LIndex].Sources + [LStatus];
        end;
        LQuery.Next;
      end;
      LQuery.Close;
    end;

    LQuery.SQL.Text := 'SELECT p.snapshot_id, p.pid, p.create_time, p.parent_pid, p.name, ' +
      'p.image_path, p.access, p.cpu, p.working_set, p.private_bytes, p.thread_count, ' +
      'p.source_id FROM process_samples p ' +
      'JOIN (' + ASelect + ') s ON s.id = p.snapshot_id';
    ABind(LQuery);
    LQuery.Open;
    while not LQuery.Eof do
    begin
      if LIndexById.TryGetValue(LQuery.Fields[0].AsLargeInt, LIndex) then
      begin
        LInfo := TMHProcessInfo.Create(TMHProcessId.Create(Cardinal(LQuery.Fields[1].AsLargeInt),
          UInt64(LQuery.Fields[2].AsLargeInt)), LQuery.Fields[4].AsString,
          LSnaps[LIndex].TimestampUtc);
        LInfo.ParentPid := Cardinal(LQuery.Fields[3].AsLargeInt);
        LInfo.ImagePath := LQuery.Fields[5].AsString;
        if MHTryAccessLevelFromName(LQuery.Fields[6].AsString, LAccess) then
          LInfo.Access := LAccess;
        LInfo.Cpu := MetricFromField(mkCpuPercent, LQuery.Fields[7], LSnaps[LIndex].TimestampUtc);
        LInfo.WorkingSet := MetricFromField(mkWorkingSetBytes, LQuery.Fields[8],
          LSnaps[LIndex].TimestampUtc);
        LInfo.PrivateBytes := MetricFromField(mkPrivateBytes, LQuery.Fields[9],
          LSnaps[LIndex].TimestampUtc);
        LInfo.ThreadCount := LQuery.Fields[10].AsInteger;
        LInfo.SourceId := LQuery.Fields[11].AsString;
        LSnaps[LIndex].Processes := LSnaps[LIndex].Processes + [LInfo];
      end;
      LQuery.Next;
    end;
    LQuery.Close;
    Result := LSnaps;
  finally
    LQuery.Free;
    LIndexById.Free;
    LList.Free;
  end;
end;

function TMHSQLiteRepository.LoadHistory(AFromUtc, AToUtc: TDateTime;
  AMaxCount: Integer): TArray<TMHSnapshot>;
var
  LFrom, LTo: Int64;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  LFrom := MHUtcToUnixMs(AFromUtc);
  LTo := MHUtcToUnixMs(AToUtc);
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    Result := LoadSnapshotsLocked('SELECT id, seq, ts, context FROM snapshots ' +
      'WHERE ts >= :f AND ts <= :t ORDER BY ts LIMIT :n',
      procedure(AQuery: TFDQuery)
      begin
        AQuery.ParamByName('f').AsLargeInt := LFrom;
        AQuery.ParamByName('t').AsLargeInt := LTo;
        AQuery.ParamByName('n').AsInteger := AMaxCount;
      end, True);
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.CountSnapshots(AFromUtc, AToUtc: TDateTime; AContext: TMHWorkContext): Int64;
var
  LWhere: string;
  LQuery: TFDQuery;
begin
  if AContext = wcUnknown then
    LWhere := 'COALESCE(context, :c) = :c AND ts >= :f AND ts <= :t'
  else
    LWhere := 'context = :c AND ts >= :f AND ts <= :t';
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    LQuery := NewQuery('SELECT COUNT(*) FROM snapshots WHERE ' + LWhere);
    try
      LQuery.ParamByName('c').AsWideString := MHWorkContextToName(AContext);
      LQuery.ParamByName('f').AsLargeInt := MHUtcToUnixMs(AFromUtc);
      LQuery.ParamByName('t').AsLargeInt := MHUtcToUnixMs(AToUtc);
      LQuery.Open;
      Result := LQuery.Fields[0].AsLargeInt;
    finally
      LQuery.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadSnapshotsSampled(AFromUtc, AToUtc: TDateTime;
  AMaxCount: Integer; AContext: TMHWorkContext): TArray<TMHSnapshot>;
var
  LFrom, LTo, LCount, LStep: Int64;
  LWhere, LContextName: string;
  LQuery: TFDQuery;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  LFrom := MHUtcToUnixMs(AFromUtc);
  LTo := MHUtcToUnixMs(AToUtc);
  LContextName := MHWorkContextToName(AContext);
  // Известный контекст — точное совпадение (индекс по (context, ts));
  // wcUnknown — снимки без контекста или с контекстом «unknown».
  if AContext = wcUnknown then
    LWhere := 'COALESCE(context, :c) = :c AND ts >= :f AND ts <= :t'
  else
    LWhere := 'context = :c AND ts >= :f AND ts <= :t';
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    LQuery := NewQuery('SELECT COUNT(*) FROM snapshots WHERE ' + LWhere);
    try
      LQuery.ParamByName('c').AsWideString := LContextName;
      LQuery.ParamByName('f').AsLargeInt := LFrom;
      LQuery.ParamByName('t').AsLargeInt := LTo;
      LQuery.Open;
      LCount := LQuery.Fields[0].AsLargeInt;
      LQuery.Close;
    finally
      LQuery.Free;
    end;
    if LCount = 0 then
      Exit(nil);
    // Каждый k-й снимок по времени: k = ceil(count / max).
    LStep := Max(Int64(1), (LCount + AMaxCount - 1) div AMaxCount);
    Result := LoadSnapshotsLocked('SELECT id, seq, ts, context FROM (' +
      'SELECT id, seq, ts, context, ROW_NUMBER() OVER (ORDER BY ts, id) - 1 AS rn ' +
      'FROM snapshots WHERE ' + LWhere + ') WHERE rn % :k = 0 ORDER BY ts, id LIMIT :n',
      procedure(AQuery: TFDQuery)
      begin
        AQuery.ParamByName('c').AsWideString := LContextName;
        AQuery.ParamByName('f').AsLargeInt := LFrom;
        AQuery.ParamByName('t').AsLargeInt := LTo;
        AQuery.ParamByName('k').AsLargeInt := LStep;
        AQuery.ParamByName('n').AsInteger := AMaxCount;
      end, False);
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadSeriesLocked(const ASql: string;
  const AParams: array of Variant; AFromMs, AToMs: Int64; AMaxPoints: Integer;
  AKind: TMHMetricKind): TArray<TMHMetric>;
var
  LQuery: TFDQuery;
  LBucket: Int64;
  LList: TList<TMHMetric>;
  LTime: TDateTime;
  I: Integer;
begin
  Result := nil;
  if (AMaxPoints <= 0) or (AToMs <= AFromMs) then
    Exit;
  FlushBeforeReadLocked;
  LBucket := Max(Int64(1), (AToMs - AFromMs + AMaxPoints - 1) div AMaxPoints);
  LList := TList<TMHMetric>.Create;
  LQuery := NewQuery(ASql);
  try
    LQuery.ParamByName('f').AsLargeInt := AFromMs;
    LQuery.ParamByName('t').AsLargeInt := AToMs;
    LQuery.ParamByName('b').AsLargeInt := LBucket;
    for I := 0 to Length(AParams) div 2 - 1 do
      LQuery.ParamByName(string(AParams[I * 2])).Value := AParams[I * 2 + 1];
    LQuery.Open;
    while not LQuery.Eof do
    begin
      // Точка — середина интервала усреднения.
      LTime := MHUnixMsToUtc(AFromMs + LQuery.Fields[0].AsLargeInt * LBucket + LBucket div 2);
      if LQuery.Fields[2].AsLargeInt > 0 then
        LList.Add(TMHMetric.Available(AKind, FieldAsDouble(LQuery.Fields[1]), LTime))
      else
        LList.Add(TMHMetric.NoData(AKind, LTime));
      LQuery.Next;
    end;
    Result := LList.ToArray;
  finally
    LQuery.Free;
    LList.Free;
  end;
end;

function TMHSQLiteRepository.LoadMetricSeries(AKind: TMHMetricKind;
  AFromUtc, AToUtc: TDateTime; AMaxPoints: Integer): TArray<TMHMetric>;
begin
  FLock.Enter;
  try
    Result := LoadSeriesLocked(
      'SELECT (s.ts - :f) / :b AS bucket, AVG(m.value), COUNT(m.value) ' +
      'FROM snapshots s JOIN metrics m ON m.snapshot_id = s.id AND m.kind = :kind ' +
      'WHERE s.ts >= :f AND s.ts <= :t GROUP BY bucket ORDER BY bucket',
      ['kind', MHMetricKindToName(AKind)], MHUtcToUnixMs(AFromUtc), MHUtcToUnixMs(AToUtc),
      AMaxPoints, AKind);
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadProcessSeries(const AId: TMHProcessId;
  AKind: TMHMetricKind; AFromUtc, AToUtc: TDateTime; AMaxPoints: Integer): TArray<TMHMetric>;
var
  LColumn: string;
begin
  case AKind of
    mkCpuPercent:      LColumn := 'cpu';
    mkWorkingSetBytes: LColumn := 'working_set';
    mkPrivateBytes:    LColumn := 'private_bytes';
  else
    raise EArgumentException.Create(MHL('Для процессов хранятся только CPU, рабочий набор и частная память',
      'Only CPU, working set and private memory are stored for processes'));
  end;
  FLock.Enter;
  try
    Result := LoadSeriesLocked(
      'SELECT (s.ts - :f) / :b AS bucket, AVG(p.' + LColumn + '), COUNT(p.' + LColumn + ') ' +
      'FROM snapshots s JOIN process_samples p ON p.snapshot_id = s.id ' +
      'WHERE p.pid = :pid AND p.create_time = :ct AND s.ts >= :f AND s.ts <= :t ' +
      'GROUP BY bucket ORDER BY bucket',
      ['pid', Int64(AId.Pid), 'ct', Int64(AId.CreateTime)],
      MHUtcToUnixMs(AFromUtc), MHUtcToUnixMs(AToUtc), AMaxPoints, AKind);
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.GetStats: TMHHistoryStats;
var
  LQuery: TFDQuery;
begin
  Result := Default(TMHHistoryStats);
  FLock.Enter;
  try
    FlushBeforeReadLocked;
    LQuery := NewQuery('SELECT COUNT(*), MIN(ts), MAX(ts) FROM snapshots');
    try
      LQuery.Open;
      Result.SnapshotCount := LQuery.Fields[0].AsLargeInt;
      if Result.SnapshotCount > 0 then
      begin
        Result.OldestUtc := MHUnixMsToUtc(LQuery.Fields[1].AsLargeInt);
        Result.NewestUtc := MHUnixMsToUtc(LQuery.Fields[2].AsLargeInt);
      end;
    finally
      LQuery.Free;
    end;
    Result.FileSizeBytes := Int64(FConnection.ExecSQLScalar('PRAGMA page_count')) *
      Int64(FConnection.ExecSQLScalar('PRAGMA page_size'));
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.CacheSizeSetting: Integer;
begin
  FLock.Enter;
  try
    CheckOpen;
    Result := FConnection.ExecSQLScalar('PRAGMA cache_size');
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.InventoryDueLocked(ATimestampUtc: TDateTime): Boolean;
begin
  // Учёт обновляется не на каждом снимке: состав автозапуска и программ меняется
  // редко, а запись сотен строк каждые 2 секунды тратила бы диск.
  Result := (FLastInventoryUtc = 0) or (ATimestampUtc < FLastInventoryUtc) or
    ((ATimestampUtc - FLastInventoryUtc) * SecsPerDay >= MH_INVENTORY_REFRESH_SECONDS);
  if Result then
    FLastInventoryUtc := ATimestampUtc;
end;

procedure TMHSQLiteRepository.WriteInventoryLocked(const AItems: TArray<TMHInventoryItem>;
  ASeenUtc: TDateTime);
var
  LItem: TMHInventoryItem;
  LPath: Variant;
begin
  for LItem in AItems do
  begin
    if LItem.ImagePath <> '' then
      LPath := LItem.ImagePath
    else
      LPath := Null;
    SetParam(FUpsertInventory, 'kind', MHInventoryKindToName(LItem.Kind), ftWideString);
    SetParam(FUpsertInventory, 'key', LItem.Key, ftWideString);
    SetParam(FUpsertInventory, 'name', LItem.Name, ftWideString);
    SetParam(FUpsertInventory, 'details', LItem.Details, ftWideString);
    SetParam(FUpsertInventory, 'path', LPath, ftWideString);
    SetParam(FUpsertInventory, 'seen', MHUtcToUnixMs(ASeenUtc), ftLargeint);
    FUpsertInventory.ExecSQL;
  end;
end;

procedure TMHSQLiteRepository.SaveLaunchesLocked(const ASnapshot: TMHSnapshot);
var
  LRecord: TMHLaunchRecord;
  LExit, LPath, LParent, LCommand: Variant;
begin
  for LRecord in ASnapshot.LaunchEvents do
  begin
    if (LRecord.CreateTime = 0) or (LRecord.StartUtc = 0) then
      Continue;
    if LRecord.ExitUtc > 0 then
      LExit := MHUtcToUnixMs(LRecord.ExitUtc)
    else
      LExit := Null;
    if FOptions.StoreProcessPaths and (LRecord.ImagePath <> '') then
      LPath := LRecord.ImagePath
    else
      LPath := Null;
    if LRecord.ParentName <> '' then
      LParent := LRecord.ParentName
    else
      LParent := Null;
    // Параметры запуска раскрывают пути и аргументы — хранятся вместе с путями.
    if FOptions.StoreProcessPaths and (LRecord.CommandLine <> '') then
      LCommand := Copy(LRecord.CommandLine, 1, MH_LAUNCH_COMMAND_LINE_MAX)
    else
      LCommand := Null;
    SetParam(FUpsertLaunch, 'pid', Int64(LRecord.Pid), ftLargeint);
    SetParam(FUpsertLaunch, 'ct', Int64(LRecord.CreateTime), ftLargeint);
    SetParam(FUpsertLaunch, 'start', MHUtcToUnixMs(LRecord.StartUtc), ftLargeint);
    SetParam(FUpsertLaunch, 'exit', LExit, ftLargeint);
    SetParam(FUpsertLaunch, 'name', LRecord.Name, ftWideString);
    SetParam(FUpsertLaunch, 'path', LPath, ftWideString);
    SetParam(FUpsertLaunch, 'ppid', Int64(LRecord.ParentPid), ftLargeint);
    SetParam(FUpsertLaunch, 'pname', LParent, ftWideString);
    SetParam(FUpsertLaunch, 'source', LRecord.Source, ftWideString);
    SetParam(FUpsertLaunch, 'cmd', LCommand, ftWideString);
    FUpsertLaunch.ExecSQL;
  end;
end;

function TMHSQLiteRepository.LoadLaunches(AFromUtc, AToUtc: TDateTime; const AFilter: string;
  AMaxCount: Integer): TArray<TMHLaunchRecord>;
var
  LQuery: TFDQuery;
  LList: TList<TMHLaunchRecord>;
  LRecord: TMHLaunchRecord;
  LSql: string;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    LSql := 'SELECT pid, create_time, start_ts, exit_ts, name, image_path, parent_pid, parent_name, source, ' +
      'command_line FROM launches WHERE start_ts >= :f AND start_ts <= :t';
    if AFilter <> '' then
      LSql := LSql + ' AND (instr(lower(name), :q) > 0 OR instr(lower(COALESCE(image_path, '''')), :q) > 0 ' +
        'OR instr(lower(COALESCE(parent_name, '''')), :q) > 0 OR instr(lower(COALESCE(command_line, '''')), :q) > 0)';
    LSql := LSql + ' ORDER BY start_ts DESC LIMIT :n';
    LQuery := NewQuery(LSql);
    LList := TList<TMHLaunchRecord>.Create;
    try
      LQuery.ParamByName('f').AsLargeInt := MHUtcToUnixMs(AFromUtc);
      LQuery.ParamByName('t').AsLargeInt := MHUtcToUnixMs(AToUtc);
      if AFilter <> '' then
        LQuery.ParamByName('q').AsWideString := AFilter.ToLower;
      LQuery.ParamByName('n').AsInteger := AMaxCount;
      LQuery.Open;
      while not LQuery.Eof do
      begin
        LRecord := Default(TMHLaunchRecord);
        LRecord.Pid := Cardinal(LQuery.Fields[0].AsLargeInt);
        LRecord.CreateTime := UInt64(LQuery.Fields[1].AsLargeInt);
        LRecord.StartUtc := MHUnixMsToUtc(LQuery.Fields[2].AsLargeInt);
        if not LQuery.Fields[3].IsNull then
          LRecord.ExitUtc := MHUnixMsToUtc(LQuery.Fields[3].AsLargeInt);
        LRecord.Name := LQuery.Fields[4].AsString;
        LRecord.ImagePath := LQuery.Fields[5].AsString;
        LRecord.ParentPid := Cardinal(LQuery.Fields[6].AsLargeInt);
        LRecord.ParentName := LQuery.Fields[7].AsString;
        LRecord.Source := LQuery.Fields[8].AsString;
        LRecord.CommandLine := LQuery.Fields[9].AsString;
        LList.Add(LRecord);
        LQuery.Next;
      end;
      Result := LList.ToArray;
    finally
      LList.Free;
      LQuery.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.InventoryStartUtc: TDateTime;
var
  LValue: Variant;
begin
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    LValue := FConnection.ExecSQLScalar('SELECT MIN(first_seen) FROM inventory');
    if VarIsNull(LValue) or VarIsEmpty(LValue) then
      Result := 0
    else
      Result := MHUnixMsToUtc(LValue);
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadInventoryChanges(ASinceUtc: TDateTime;
  AMaxCount: Integer): TArray<TMHInventoryItem>;
var
  LQuery: TFDQuery;
  LList: TList<TMHInventoryItem>;
  LItem: TMHInventoryItem;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  FLock.Enter;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    // Исходное состояние каждого вида — всё, что замечено в первые
    // MH_INVENTORY_GRACE_MINUTES после начала его учёта.
    LQuery := NewQuery('SELECT i.kind, i.key, i.name, i.details, i.image_path, i.first_seen, i.last_seen ' +
      'FROM inventory i JOIN (SELECT kind, MIN(first_seen) AS start FROM inventory GROUP BY kind) k ' +
      '  ON k.kind = i.kind ' +
      'WHERE i.first_seen >= :since AND i.first_seen > k.start + :grace ' +
      'ORDER BY i.first_seen DESC LIMIT :n');
    LList := TList<TMHInventoryItem>.Create;
    try
      LQuery.ParamByName('since').AsLargeInt := MHUtcToUnixMs(ASinceUtc);
      LQuery.ParamByName('grace').AsLargeInt := Int64(MH_INVENTORY_GRACE_MINUTES) * 60 * 1000;
      LQuery.ParamByName('n').AsInteger := AMaxCount;
      LQuery.Open;
      while not LQuery.Eof do
      begin
        LItem := Default(TMHInventoryItem);
        if MHTryInventoryKindFromName(LQuery.Fields[0].AsString, LItem.Kind) then
        begin
          LItem.Key := LQuery.Fields[1].AsString;
          LItem.Name := LQuery.Fields[2].AsString;
          LItem.Details := LQuery.Fields[3].AsString;
          LItem.ImagePath := LQuery.Fields[4].AsString;
          LItem.FirstSeenUtc := MHUnixMsToUtc(LQuery.Fields[5].AsLargeInt);
          LItem.LastSeenUtc := MHUnixMsToUtc(LQuery.Fields[6].AsLargeInt);
          LList.Add(LItem);
        end;
        LQuery.Next;
      end;
      Result := LList.ToArray;
    finally
      LList.Free;
      LQuery.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.Clear;
begin
  FLock.Enter;
  try
    // Очередь тоже относится к удаляемой истории.
    FPending := nil;
    FPendingCount := 0;
    FPendingFindings := nil;
    FPendingFindingCount := 0;
    FPendingSinceUtc := 0;
    FConnection.ExecSQL('DELETE FROM snapshots');
    FConnection.ExecSQL('DELETE FROM findings');
    FConnection.ExecSQL('DELETE FROM inventory');
    FConnection.ExecSQL('DELETE FROM launches');
    FLastInventoryUtc := 0;
    RunPragma('PRAGMA incremental_vacuum');
    RunPragma('PRAGMA wal_checkpoint(TRUNCATE)');
    Log(llWarning, MHL('История наблюдений и находок очищена пользователем',
      'Observation and finding history was cleared by the user'));
  finally
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.SaveFindings(const AFindings: TMHFindings);
var
  LFinding, LItem: TMHFinding;
  LNow: TDateTime;
begin
  if Length(AFindings) = 0 then
    Exit;
  LNow := FClock.NowUtc;
  FLock.Enter;
  try
    CheckOpen;
    // Находки пишутся вместе с пакетом снимков: повтор той же находки каждые
    // 1–2 с переписывал бы её JSON отдельной транзакцией.
    for LFinding in AFindings do
    begin
      // Копия: ключ и время дополняются до сериализации, чтобы JSON совпадал с записью.
      LItem := LFinding;
      if LItem.Key = '' then
        LItem.Key := MHDefaultFindingKey(LItem);
      if LItem.DetectedAtUtc = 0 then
        LItem.DetectedAtUtc := LNow;
      if FPendingFindingCount = Length(FPendingFindings) then
        SetLength(FPendingFindings, Max(16, FPendingFindingCount * 2));
      FPendingFindings[FPendingFindingCount] := LItem;
      Inc(FPendingFindingCount);
    end;
    MarkPendingLocked;
    if FlushDueLocked then
      FlushLocked;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadFindings(AFromUtc, AToUtc: TDateTime;
  AMaxCount: Integer): TArray<TMHStoredFinding>;
var
  LQuery: TFDQuery;
  LList: TList<TMHStoredFinding>;
  LItem: TMHStoredFinding;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  FLock.Enter;
  LList := TList<TMHStoredFinding>.Create;
  LQuery := nil;
  try
    CheckOpen;
    FlushBeforeReadLocked;
    LQuery := NewQuery('SELECT key, first_seen, last_seen, max_score, occurrences, json ' +
      'FROM findings WHERE last_seen >= :f AND last_seen <= :t ' +
      'ORDER BY last_seen DESC, key LIMIT :n');
    LQuery.ParamByName('f').AsLargeInt := MHUtcToUnixMs(AFromUtc);
    LQuery.ParamByName('t').AsLargeInt := MHUtcToUnixMs(AToUtc);
    LQuery.ParamByName('n').AsInteger := AMaxCount;
    LQuery.Open;
    while not LQuery.Eof do
    begin
      try
        LItem := Default(TMHStoredFinding);
        LItem.Finding := TMHJson.FindingFromString(LQuery.Fields[5].AsString);
        LItem.FirstSeenUtc := MHUnixMsToUtc(LQuery.Fields[1].AsLargeInt);
        LItem.LastSeenUtc := MHUnixMsToUtc(LQuery.Fields[2].AsLargeInt);
        LItem.MaxScore := LQuery.Fields[3].AsInteger;
        LItem.Occurrences := Integer(Min(LQuery.Fields[4].AsLargeInt, Int64(MaxInt)));
        LList.Add(LItem);
      except
        on E: Exception do
          Log(llWarning, Format(MHL('Находка «%s» в истории повреждена и пропущена: %s',
            'Finding "%s" in history is corrupted and was skipped: %s'), [LQuery.Fields[0].AsString, E.Message]));
      end;
      LQuery.Next;
    end;
    LQuery.Close;
    Result := LList.ToArray;
  finally
    LQuery.Free;
    LList.Free;
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.LogAction(const ARecord: TMHActionRecord);
var
  LTime: TDateTime;
begin
  LTime := ARecord.TimestampUtc;
  if LTime = 0 then
    LTime := FClock.NowUtc;
  FLock.Enter;
  try
    CheckOpen;
    SetParam(FInsertAction, 'ts', MHUtcToUnixMs(LTime), ftLargeint);
    SetParam(FInsertAction, 'action', ARecord.Action, ftWideString);
    SetParam(FInsertAction, 'target', ARecord.Target, ftWideString);
    SetParam(FInsertAction, 'result', ARecord.Result, ftWideString);
    SetParam(FInsertAction, 'success', Ord(ARecord.Success), ftInteger);
    FInsertAction.ExecSQL;
    TrimActionsLocked;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadActions(AMaxCount: Integer): TArray<TMHActionRecord>;
var
  LQuery: TFDQuery;
  LList: TList<TMHActionRecord>;
  LItem: TMHActionRecord;
begin
  if AMaxCount <= 0 then
    Exit(nil);
  FLock.Enter;
  LList := TList<TMHActionRecord>.Create;
  LQuery := nil;
  try
    CheckOpen;
    LQuery := NewQuery('SELECT ts, action, target, result, success FROM actions ' +
      'ORDER BY ts DESC, id DESC LIMIT :n');
    LQuery.ParamByName('n').AsInteger := AMaxCount;
    LQuery.Open;
    while not LQuery.Eof do
    begin
      LItem.TimestampUtc := MHUnixMsToUtc(LQuery.Fields[0].AsLargeInt);
      LItem.Action := LQuery.Fields[1].AsString;
      LItem.Target := LQuery.Fields[2].AsString;
      LItem.Result := LQuery.Fields[3].AsString;
      LItem.Success := LQuery.Fields[4].AsInteger <> 0;
      LList.Add(LItem);
      LQuery.Next;
    end;
    LQuery.Close;
    Result := LList.ToArray;
  finally
    LQuery.Free;
    LList.Free;
    FLock.Leave;
  end;
end;

procedure TMHSQLiteRepository.SaveBaseline(const ABaseline: TMHBaseline);
var
  LJson: string;
  LQuery: TFDQuery;
begin
  LJson := TMHJson.BaselineToString(ABaseline);
  FLock.Enter;
  try
    CheckOpen;
    LQuery := NewQuery('INSERT OR REPLACE INTO baselines(context, updated, json) ' +
      'VALUES (:ctx, :updated, :json)');
    try
      SetParam(LQuery, 'ctx', MHWorkContextToName(ABaseline.Context), ftWideString);
      SetParam(LQuery, 'updated', MHUtcToUnixMs(ABaseline.UpdatedUtc), ftLargeint);
      SetParam(LQuery, 'json', LJson, ftWideMemo);
      LQuery.ExecSQL;
    finally
      LQuery.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

function TMHSQLiteRepository.LoadBaselines: TArray<TMHBaseline>;
var
  LQuery: TFDQuery;
  LList: TList<TMHBaseline>;
begin
  FLock.Enter;
  LList := TList<TMHBaseline>.Create;
  LQuery := nil;
  try
    CheckOpen;
    LQuery := NewQuery('SELECT context, json FROM baselines ORDER BY context');
    LQuery.Open;
    while not LQuery.Eof do
    begin
      try
        LList.Add(TMHJson.BaselineFromString(LQuery.Fields[1].AsString));
      except
        on E: Exception do
          Log(llWarning, Format(MHL('Профиль нормы «%s» повреждён и пропущен: %s',
            'Baseline "%s" is corrupted and was skipped: %s'), [LQuery.Fields[0].AsString, E.Message]));
      end;
      LQuery.Next;
    end;
    LQuery.Close;
    Result := LList.ToArray;
  finally
    LQuery.Free;
    LList.Free;
    FLock.Leave;
  end;
end;

end.
