unit MineHunter.Core.Types;

{
  MineHunter X — базовые модели данных публичного API.

  Все модели — записи (record) со значимой семантикой. Снимок после публикации
  сканером не изменяется, поэтому его можно безопасно читать из любого потока.
  Время во всех моделях хранится в UTC.
}

interface

uses
  System.SysUtils;

const
  MH_CORE_VERSION = '0.2.0';

  /// Значение ThreadCount, когда число потоков неизвестно.
  MH_UNKNOWN_COUNT = -1;

  /// Источник самодиагностики. Его записи о процессе MineHunter дублируют данные
  /// коллектора процессов, поэтому в историю и профиль нормы не попадают.
  MH_SELF_SOURCE_ID = 'self';

type
  EMHError = class(Exception);

  /// Унифицированный статус источника данных (контракт для всех коллекторов).
  TMHSourceState = (
    ssUnknown,      // источник ещё не опрашивался
    ssSuccess,      // данные получены полностью
    ssPartial,      // данные получены частично (нет прав, нет истории и т.п.)
    ssUnavailable,  // источник недоступен на этой системе или временно отключён
    ssError         // сбой при сборе
  );

  /// Вид метрики. Новые значения добавляются только в конец: имена
  /// сериализуются, но порядок используется в массивах-описаниях.
  /// В TMHSnapshot.Metrics хранятся метрики уровня системы, в
  /// TMHProcessInfo — метрики процесса.
  TMHMetricKind = (
    mkCpuPercent,
    mkWorkingSetBytes,
    mkPrivateBytes,
    mkDiskBytesPerSec,
    mkNetworkBytesPerSec,
    mkGpuPercent,
    mkTemperatureCelsius,
    mkMemoryUsedBytes,
    mkMemoryTotalBytes,
    mkMemoryLoadPercent,
    mkDiskReadBytesPerSec,
    mkDiskWriteBytesPerSec,
    mkDiskActivePercent,
    /// Доля времени работы процессоров без учёта частоты (GetSystemTimes).
    /// mkCpuPercent — «загруженность» с учётом частоты, как в диспетчере задач.
    mkCpuTimePercent,
    /// Производительность процессора относительно базовой частоты, % (выше 100 — турбо).
    mkCpuFrequencyPercent,
    /// Предел производительности, установленный прошивкой (100 — ограничений нет;
    /// меньше — троттлинг по температуре или питанию).
    mkCpuPerformanceLimitPercent,
    /// Загрузка вычислительных движков GPU (Compute, CUDA), %.
    mkGpuComputePercent,
    /// Выделенная видеопамять (у процесса — его доля).
    mkGpuMemoryBytes,
    mkGpuTemperatureCelsius,
    mkCpuTemperatureCelsius,
    mkDiskTemperatureCelsius,
    /// Частный рабочий набор процесса — колонка «Память» диспетчера задач.
    mkPrivateWorkingSetBytes,
    /// Потребляемая мощность видеокарт (сумма по адаптерам, датчик драйвера), Вт.
    mkGpuPowerWatts
  );

  /// Уровень доступа, с которым удалось открыть процесс.
  TMHAccessLevel = (alUnknown, alFull, alLimited, alDenied);

  TMHSignatureState = (
    sgNotChecked,
    sgSignedTrusted,
    sgSignedUntrusted,
    sgUnsigned,
    sgCheckFailed
  );

  /// Итог оценки. Это «степень подозрения», а не диагноз заражения.
  TMHRiskLevel = (
    rlNone,              // признаков нет
    rlLow,               // слабые признаки, наблюдение
    rlNeedsReview,       // требует проверки
    rlSuspicious,        // подозрительно
    rlHighlySuspicious   // высокая степень подозрения
  );

  /// Контекст работы компьютера для профиля нормы.
  TMHWorkContext = (wcUnknown, wcIdle, wcWork, wcGaming);

  TMHFindingCategory = (
    fcMining,       // признаки скрытого майнинга
    fcSuspicious,   // подозрительный процесс (маскировка, расположение, подпись)
    fcPersistence,  // подозрительное закрепление в автозапуске
    fcPerformance   // необычная нагрузка без признаков угрозы
  );

  /// Устройство, к которому относится датчик температуры.
  TMHSensorKind = (skCpu, skGpu, skDisk);

  /// Признак вмешательства в защиту системы (приёмы, которыми майнеры прячутся
  /// и защищают себя).
  TMHTamperKind = (
    tpWmiSubscription,    // подписка WMI, запускающая команду или сценарий
    tpDefenderExclusion,  // исключение Microsoft Defender (путь, процесс, расширение)
    tpIfeoDebugger,       // перехват запуска программы (IFEO Debugger)
    tpSilentExitMonitor,  // запуск программы при завершении другой (SilentProcessExit)
    tpHostsRedirect,      // hosts перенаправляет сайт антивируса или обновлений
    tpPolicyRestriction   // политика отключает диспетчер задач, реестр или защиту
  );

  TMHAutostartKind = (akRegistryRun, akRegistryRunOnce, akStartupFolder, akService,
    akScheduledTask);
  TMHAutostartScope = (asMachine, asUser);
  TMHTransport = (ntTcp, ntUdp);

  /// Идентичность экземпляра процесса: PID + время создания.
  /// PID в Windows переиспользуется, поэтому одного PID недостаточно.
  TMHProcessId = record
  public
    Pid: Cardinal;
    /// Время создания процесса в формате FILETIME (100-нс интервалы с 1601 г., UTC).
    /// 0 — время неизвестно.
    CreateTime: UInt64;
    class function Create(APid: Cardinal; ACreateTime: UInt64): TMHProcessId; static;
    class function Empty: TMHProcessId; static;
    function IsEmpty: Boolean;
    function HasCreateTime: Boolean;
    function ToString: string;
    function GetHashCode: Integer;
    class operator Equal(const A, B: TMHProcessId): Boolean;
    class operator NotEqual(const A, B: TMHProcessId): Boolean;
  end;

  /// Измерение. HasValue = False означает «нет данных» — это не ноль.
  TMHMetric = record
  public
    Kind: TMHMetricKind;
    Value: Double;
    HasValue: Boolean;
    TimestampUtc: TDateTime;
    class function Available(AKind: TMHMetricKind; AValue: Double;
      ATimestampUtc: TDateTime): TMHMetric; static;
    class function NoData(AKind: TMHMetricKind;
      ATimestampUtc: TDateTime): TMHMetric; static;
  end;

  TMHProcessInfo = record
  public
    Id: TMHProcessId;
    ParentPid: Cardinal;
    Name: string;
    /// Полный путь к образу; пустая строка — путь получить не удалось.
    ImagePath: string;
    /// SHA-256 в hex; пустая строка — хеш не вычислялся.
    Sha256: string;
    Signature: TMHSignatureState;
    Access: TMHAccessLevel;
    Cpu: TMHMetric;
    WorkingSet: TMHMetric;
    PrivateBytes: TMHMetric;
    /// MH_UNKNOWN_COUNT, если неизвестно.
    ThreadCount: Integer;
    /// Идентификатор источника, предоставившего данные.
    SourceId: string;
    /// Командная строка ('' — не получена). Не сохраняется в истории.
    CommandLine: string;
    /// У процесса есть видимое окно верхнего уровня (по данным контекста).
    HasVisibleWindow: Boolean;
    /// Частный рабочий набор (колонка «Память» диспетчера задач).
    PrivateWorkingSet: TMHMetric;
    /// Загрузка GPU — самый загруженный движок процесса, % (как в диспетчере задач).
    Gpu: TMHMetric;
    /// Загрузка вычислительных движков GPU (Compute, CUDA), %.
    GpuCompute: TMHMetric;
    /// Выделенная видеопамять процесса.
    GpuMemory: TMHMetric;
    /// Чтение и запись процесса, байт/с (GetProcessIoCounters: все операции
    /// ввода-вывода процесса — в основном диск, но также сеть и устройства).
    IoRead: TMHMetric;
    IoWrite: TMHMetric;
    class function Create(const AId: TMHProcessId; const AName: string;
      ATimestampUtc: TDateTime): TMHProcessInfo; static;
  end;

  /// Дополнительные сведения о процессе от вспомогательных источников.
  /// Сканер переносит в процесс только заполненные поля.
  TMHProcessDetail = record
    Id: TMHProcessId;
    CommandLine: string;
    /// Метрики GPU; HasValue = False — источник их не передавал.
    Gpu: TMHMetric;
    GpuCompute: TMHMetric;
    GpuMemory: TMHMetric;
    class function Create(const AId: TMHProcessId): TMHProcessDetail; static;
  end;

  /// Сведения об исполняемом файле: хеш и цифровая подпись.
  TMHFileInfo = record
  public
    /// Нормализованный путь (MHNormalizePath).
    Path: string;
    /// -1 — размер неизвестен.
    SizeBytes: Int64;
    LastWriteUtc: TDateTime;
    /// SHA-256 в нижнем регистре hex; '' — не вычислялся.
    Sha256: string;
    Signature: TMHSignatureState;
    /// Издатель из сертификата подписи ('' — нет данных).
    Signer: string;
    /// 'embedded' — подпись в файле, 'catalog' — подпись каталога Windows, '' — нет.
    SignatureSource: string;
    /// Причина отсутствия данных ('' — ошибок нет).
    Error: string;
    class function Create(const APath: string): TMHFileInfo; static;
  end;

  /// Элемент автозапуска (MH-04).
  TMHAutostartEntry = record
  public
    Kind: TMHAutostartKind;
    Scope: TMHAutostartScope;
    /// Имя значения реестра, файла ярлыка, службы или путь задания.
    Name: string;
    /// Команда в исходном виде.
    Command: string;
    /// Нормализованный путь исполняемого файла ('' — не удалось определить).
    ImagePath: string;
    /// Раздел реестра, папка, «services» или папка планировщика.
    Location: string;
    Enabled: Boolean;
    /// Тип запуска службы, триггер задания, учётная запись и т.п.
    Details: string;
  end;

  /// Сетевое соединение или прослушиваемый порт (MH-05).
  TMHNetConnection = record
  public
    Transport: TMHTransport;
    IPv6: Boolean;
    LocalAddress: string;
    LocalPort: Word;
    /// '' для UDP и прослушиваемых портов.
    RemoteAddress: string;
    RemotePort: Word;
    /// 'ESTABLISHED', 'LISTEN', ... ; '' для UDP.
    State: string;
    OwningPid: Cardinal;
    function IsRemote: Boolean;
  end;

  /// Найденный признак вмешательства. Сам по себе — не диагноз: оценку даёт анализатор.
  TMHTamperEntry = record
  public
    Kind: TMHTamperKind;
    /// Имя подписки, исключённый путь/процесс/расширение, программа-цель, домен, политика.
    Name: string;
    /// Команда, значение исключения, отладчик, IP-адрес, значение политики.
    Value: string;
    /// Раздел реестра, пространство имён WMI, путь к hosts.
    Location: string;
    /// Нормализованный путь исполняемого файла, на который указывает запись ('' — нет).
    ImagePath: string;
    /// Дополнительно: тип подписки, запрос фильтра, вид исключения и т.п.
    Details: string;
    /// Компьютер входит в домен организации: там политики и исключения задаёт администратор.
    ManagedComputer: Boolean;
    class function Create(AKind: TMHTamperKind; const AName, AValue, ALocation: string): TMHTamperEntry; static;
  end;

  /// Показание датчика температуры.
  TMHSensorReading = record
  public
    Kind: TMHSensorKind;
    /// Модель устройства или имя датчика.
    Device: string;
    /// Источник: 'D3DKMT', 'NVML', 'storage', 'LibreHardwareMonitor'…
    Source: string;
    Celsius: Double;
    /// Порог производителя (предупреждение или начало снижения частоты);
    /// 0 — неизвестен.
    LimitCelsius: Double;
    class function Create(AKind: TMHSensorKind; const ADevice, ASource: string;
      ACelsius, ALimitCelsius: Double): TMHSensorReading; static;
  end;

  /// Сводка запусков одной программы за окно наблюдения (события запуска и
  /// завершения процессов ETW). Позволяет увидеть программы, которые живут
  /// меньше интервала опроса и поэтому не попадают в список процессов.
  TMHLaunchStat = record
  public
    ImagePath: string;
    Name: string;
    /// Запусков за окно.
    Starts: Integer;
    /// Из них завершились быстрее ShortLivedSeconds.
    ShortLived: Integer;
    /// Завершившихся за окно (для средней продолжительности).
    Exited: Integer;
    AverageLifetimeSeconds: Double;
    LastParentPid: Cardinal;
    LastParentName: string;
    LastStartUtc: TDateTime;
    WindowMinutes: Integer;
    ShortLivedSeconds: Integer;
  end;

  /// Запись журнала запусков программ.
  TMHLaunchRecord = record
  public
    Pid: Cardinal;
    /// Время создания процесса (FILETIME) — вместе с PID задаёт экземпляр.
    CreateTime: UInt64;
    StartUtc: TDateTime;
    /// Время завершения (0 — работает или завершение не наблюдалось).
    ExitUtc: TDateTime;
    Name: string;
    ImagePath: string;
    ParentPid: Cardinal;
    ParentName: string;
    /// 'etw' — событие Windows (видны даже мгновенные процессы); 'poll' — по опросу списка процессов.
    Source: string;
  end;

  /// Видеокарта (физический адаптер).
  TMHGpuAdapterInfo = record
  public
    /// «luid_0x…_0x…_phys_N» — как в счётчиках GPU Engine.
    Key: string;
    Name: string;
    /// Загрузка — самый загруженный движок, как в диспетчере задач.
    HasLoad: Boolean;
    LoadPercent: Double;
    ComputePercent: Double;
    HasMemory: Boolean;
    MemoryBytes: Double;
    HasTemperature: Boolean;
    TemperatureCelsius: Double;
    HasPower: Boolean;
    PowerWatts: Double;
  end;

  TMHNetAdapterKind = (nkOther, nkEthernet, nkWifi, nkMobile, nkVirtual);

  /// Сетевой адаптер.
  TMHNetAdapterInfo = record
  public
    Index: Cardinal;
    /// Имя подключения («Ethernet», «Беспроводная сеть»).
    Name: string;
    /// Описание устройства («Realtek PCIe GbE Family Controller»).
    Description: string;
    Kind: TMHNetAdapterKind;
    /// Физическое устройство (не виртуальное и не туннель).
    Physical: Boolean;
    Connected: Boolean;
    /// Скорость подключения, бит/с (0 — неизвестна).
    LinkSpeedBps: UInt64;
    /// Скорость приёма и передачи, байт/с (появляется со второго опроса).
    HasRate: Boolean;
    ReceiveBytesPerSec: Double;
    SendBytesPerSec: Double;
  end;

  /// Тип физического диска.
  TMHDiskMedia = (dmUnknown, dmHdd, dmSsd);
  /// Состояние диска по оценке Windows (Storage Management, учитывает SMART).
  TMHDiskHealth = (dhUnknown, dhHealthy, dhWarning, dhUnhealthy);

  /// Физический диск.
  TMHDiskInfo = record
  public
    /// Номер диска (\\.\PhysicalDriveN, «Управление дисками»).
    Number: Integer;
    Model: string;
    Media: TMHDiskMedia;
    /// Шина: NVMe, SATA, USB, SAS, RAID…
    Bus: string;
    SizeBytes: Int64;
    /// Разделы на диске: «C: D:».
    Volumes: string;
    /// Нагрузка (счётчики PhysicalDisk): доля времени работы и скорость.
    HasActivity: Boolean;
    ActivePercent: Double;
    ReadBytesPerSec: Double;
    WriteBytesPerSec: Double;
    HasTemperature: Boolean;
    TemperatureCelsius: Double;
    /// Порог производителя (0 — неизвестен).
    TemperatureLimitCelsius: Double;
    Health: TMHDiskHealth;
    /// Пояснение Windows к состоянию (например, «прогнозируется отказ»).
    HealthDetails: string;
    /// Износ SSD, % ресурса (0 — новый, 100 — исчерпан).
    HasWear: Boolean;
    WearPercent: Double;
    /// Счётчики ошибок чтения и записи с момента выпуска диска.
    HasErrors: Boolean;
    ReadErrors: Int64;
    WriteErrors: Int64;
    /// Наработка, часов (-1 — неизвестна).
    PowerOnHours: Int64;
    class function Create(ANumber: Integer; const AModel: string): TMHDiskInfo; static;
  end;

  /// Раздел (том) с буквой диска.
  TMHVolumeInfo = record
  public
    /// «C:».
    Name: string;
    VolumeLabel: string;
    FileSystem: string;
    TotalBytes: Int64;
    FreeBytes: Int64;
    /// Номера физических дисков, на которых лежит раздел.
    DiskNumbers: TArray<Integer>;
    /// Раздел с Windows.
    IsSystem: Boolean;
    Removable: Boolean;
    function FreePercent: Double;
  end;

  /// Контекст работы пользователя на момент снимка.
  TMHContextInfo = record
  public
    Available: Boolean;
    UserIdleSeconds: Cardinal;
    ForegroundPid: Cardinal;
    /// Полноэкранное приложение (игра, презентация, видео).
    FullscreenActive: Boolean;
    WorkContext: TMHWorkContext;
    /// PID процессов с видимыми окнами верхнего уровня.
    VisibleWindowPids: TArray<Cardinal>;
    function HasVisibleWindow(APid: Cardinal): Boolean;
  end;

  TMHSourceStatus = record
  public
    SourceId: string;
    State: TMHSourceState;
    /// Пояснение для пользователя (причина частичных данных или ошибки).
    Message: string;
    /// Источник даст больше данных при запуске с повышенными правами.
    RequiresElevation: Boolean;
    TimestampUtc: TDateTime;
    DurationMs: Cardinal;
    ItemCount: Integer;
    class function Create(const ASourceId: string; AState: TMHSourceState;
      const AMessage: string; ATimestampUtc: TDateTime): TMHSourceStatus; static;
  end;

  /// Признак, повлиявший на оценку. Weight > 0 повышает риск,
  /// Weight < 0 — отрицательный (оправдывающий) фактор.
  TMHEvidence = record
  public
    Code: string;
    Description: string;
    Weight: Integer;
    /// Наблюдаемое значение в читаемом виде (например, «87% CPU в течение 40 мин»).
    Observed: string;
    class function Create(const ACode, ADescription: string; AWeight: Integer;
      const AObserved: string = ''): TMHEvidence; static;
    function IsNegativeFactor: Boolean;
  end;

  TMHFinding = record
  public
    Id: TGUID;
    Process: TMHProcessId;
    ProcessName: string;
    ImagePath: string;
    Title: string;
    Summary: string;
    /// 0..100
    Score: Integer;
    Level: TMHRiskLevel;
    /// Уверенность оценки 0..1 (снижается при отсутствии данных).
    Confidence: Double;
    Evidence: TArray<TMHEvidence>;
    MissingData: TArray<string>;
    Recommendations: TArray<string>;
    RulesetVersion: string;
    DetectedAtUtc: TDateTime;
    Category: TMHFindingCategory;
    /// Стабильный ключ находки (процесс + категория) для объединения повторов.
    Key: string;
    ParentPid: Cardinal;
    /// Сумма положительных и отрицательных весов до ограничения 0..100.
    RawScore: Integer;
    function PositiveEvidence: TArray<TMHEvidence>;
    function NegativeEvidence: TArray<TMHEvidence>;
  end;

  TMHFindings = TArray<TMHFinding>;

  /// Пороги перевода балла 0..100 в уровень риска. Настраиваются пользователем.
  TMHRiskThresholds = record
  public
    Low: Integer;
    NeedsReview: Integer;
    Suspicious: Integer;
    HighlySuspicious: Integer;
    class function Default: TMHRiskThresholds; static;
    /// Пороги должны строго возрастать в пределах 1..100.
    function IsValid: Boolean;
    function LevelOf(AScore: Integer): TMHRiskLevel;
  end;

  /// Параметры анализатора угроз (настраиваются пользователем, MH-07).
  TMHAnalyzerSettings = record
  public
    Thresholds: TMHRiskThresholds;
    /// Порог высокой нагрузки процесса, % всей машины.
    HighCpuPercent: Double;
    /// Порог высокой нагрузки, % одного ядра (для многоядерных систем).
    HighCoreCpuPercent: Double;
    /// Сколько минут нагрузка должна держаться, чтобы считаться длительной.
    SustainedMinutes: Integer;
    /// Минимум снимков, после которого профиль нормы используется.
    BaselineMinSamples: Integer;
    class function Default: TMHAnalyzerSettings; static;
    function Normalized: TMHAnalyzerSettings;
  end;

  /// Разрешённая пользователем программа: находки по ней не создаются.
  TMHExclusion = record
  public
    /// MHProgramKey: нормализованный путь в нижнем регистре.
    Key: string;
    /// Если задан — исключение действует только для файла с этим SHA-256
    /// (подмена файла по тому же пути снова вызовет проверку).
    Sha256: string;
    Name: string;
    Comment: string;
    CreatedUtc: TDateTime;
    function Matches(const AKey, ASha256: string): Boolean;
  end;

  /// Находка, отмеченная пользователем как проверенная («не беспокоить»).
  TMHAcknowledgement = record
  public
    Key: string;
    /// Отпечаток содержимого находки (MHFindingFingerprint).
    Fingerprint: string;
    /// Уровень на момент отметки: рост риска выше него снова даёт тревогу.
    Level: TMHRiskLevel;
    Title: string;
    CreatedUtc: TDateTime;
  end;

  /// Статистика ряда значений.
  TMHStat = record
  public
    SampleCount: Integer;
    Mean: Double;
    Median: Double;
    P95: Double;
    Max: Double;
    function HasData: Boolean;
    /// Вычисляет статистику; значения массива переупорядочиваются.
    class function FromValues(var AValues: TArray<Double>): TMHStat; static;
  end;

  /// Норма для отдельной программы (ключ — нормализованный путь в нижнем регистре
  /// или имя процесса, если путь неизвестен).
  TMHProcessBaseline = record
    Key: string;
    Name: string;
    Cpu: TMHStat;
    WorkingSet: TMHStat;
    /// Доля снимков контекста, в которых программа присутствовала (0..1).
    PresenceRatio: Double;
  end;

  /// Профиль нормы компьютера для одного контекста работы (MH-06).
  TMHBaseline = record
  public
    Context: TMHWorkContext;
    CreatedUtc: TDateTime;
    UpdatedUtc: TDateTime;
    /// Число снимков, по которым построен профиль.
    SampleCount: Integer;
    PeriodFromUtc: TDateTime;
    PeriodToUtc: TDateTime;
    SystemCpu: TMHStat;
    MemoryLoad: TMHStat;
    DiskActive: TMHStat;
    Processes: TArray<TMHProcessBaseline>;
    class function Empty: TMHBaseline; static;
    /// Профиль считается сформированным при достаточном числе наблюдений.
    function IsEstablished(AMinSamples: Integer): Boolean;
    function FindProcess(const AKey: string; out AStat: TMHProcessBaseline): Boolean;
  end;

  /// Состояние системы на момент опроса.
  TMHSnapshot = record
  public
    Sequence: UInt64;
    TimestampUtc: TDateTime;
    Processes: TArray<TMHProcessInfo>;
    Metrics: TArray<TMHMetric>;
    Sources: TArray<TMHSourceStatus>;
    Files: TArray<TMHFileInfo>;
    Autostart: TArray<TMHAutostartEntry>;
    Connections: TArray<TMHNetConnection>;
    Context: TMHContextInfo;
    /// Показания датчиков температуры (GPU, накопители, процессор).
    Sensors: TArray<TMHSensorReading>;
    /// Признаки вмешательства в защиту системы.
    Tamper: TArray<TMHTamperEntry>;
    /// Сводка запусков программ (ETW; пусто без прав администратора).
    Launches: TArray<TMHLaunchStat>;
    /// Физические диски и разделы.
    Disks: TArray<TMHDiskInfo>;
    Volumes: TArray<TMHVolumeInfo>;
    /// Запуски и завершения программ с прошлого снимка (для журнала запусков).
    LaunchEvents: TArray<TMHLaunchRecord>;
    /// Видеокарты и сетевые адаптеры по отдельности.
    GpuAdapters: TArray<TMHGpuAdapterInfo>;
    NetAdapters: TArray<TMHNetAdapterInfo>;
    class function Create(ASequence: UInt64;
      ATimestampUtc: TDateTime): TMHSnapshot; static;
    function FindProcess(const AId: TMHProcessId; out AInfo: TMHProcessInfo): Boolean;
    function FindSource(const ASourceId: string; out AStatus: TMHSourceStatus): Boolean;
    /// Поиск по нормализованному пути без учёта регистра.
    function FindFile(const APath: string; out AInfo: TMHFileInfo): Boolean;
    function ConnectionsOf(APid: Cardinal): TArray<TMHNetConnection>;
    function FindMetric(AKind: TMHMetricKind; out AMetric: TMHMetric): Boolean;
  end;

  /// Результат одного вызова коллектора: статус источника и собранные данные.
  /// Сканер объединяет результат со снимком только если коллектор не упал.
  TMHCollectionResult = record
  public
    Status: TMHSourceStatus;
    Processes: TArray<TMHProcessInfo>;
    Metrics: TArray<TMHMetric>;
    Files: TArray<TMHFileInfo>;
    Autostart: TArray<TMHAutostartEntry>;
    Connections: TArray<TMHNetConnection>;
    ProcessDetails: TArray<TMHProcessDetail>;
    Sensors: TArray<TMHSensorReading>;
    Tamper: TArray<TMHTamperEntry>;
    Launches: TArray<TMHLaunchStat>;
    Disks: TArray<TMHDiskInfo>;
    Volumes: TArray<TMHVolumeInfo>;
    LaunchEvents: TArray<TMHLaunchRecord>;
    GpuAdapters: TArray<TMHGpuAdapterInfo>;
    NetAdapters: TArray<TMHNetAdapterInfo>;
    /// Контекст передаётся, только если HasContext = True.
    HasContext: Boolean;
    Context: TMHContextInfo;
    class function Create(const AStatus: TMHSourceStatus): TMHCollectionResult; static;
  end;

function MHSourceStateToString(AState: TMHSourceState): string;
function MHRiskLevelToString(ALevel: TMHRiskLevel): string;
function MHSignatureToString(AState: TMHSignatureState): string;
function MHFindingCategoryToString(ACategory: TMHFindingCategory): string;
function MHAutostartKindToString(AKind: TMHAutostartKind): string;
function MHWorkContextToString(AContext: TMHWorkContext): string;
function MHTamperKindToString(AKind: TMHTamperKind): string;
/// Названия для показа пользователю на текущем языке (функции *ToString выше
/// входят в сохраняемые ключи и не зависят от языка).
function MHFindingCategoryTitle(ACategory: TMHFindingCategory): string;
function MHAutostartKindTitle(AKind: TMHAutostartKind): string;
function MHTamperKindTitle(AKind: TMHTamperKind): string;
/// Ключ программы для профиля нормы и исключений: путь в нижнем регистре
/// (или имя, если путь неизвестен).
function MHProgramKey(const AImagePath, AName: string): string;
/// FILETIME (UTC) в TDateTime; 0 — для нулевого значения.
function MHFileTimeToUtc(AFileTime: UInt64): TDateTime;
function MHClampScore(AScore: Integer): Integer;

implementation

uses
  System.Hash, System.Math, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Lang;

{ TMHProcessId }

class function TMHProcessId.Create(APid: Cardinal; ACreateTime: UInt64): TMHProcessId;
begin
  Result.Pid := APid;
  Result.CreateTime := ACreateTime;
end;

class function TMHProcessId.Empty: TMHProcessId;
begin
  Result.Pid := 0;
  Result.CreateTime := 0;
end;

function TMHProcessId.IsEmpty: Boolean;
begin
  Result := (Pid = 0) and (CreateTime = 0);
end;

function TMHProcessId.HasCreateTime: Boolean;
begin
  Result := CreateTime <> 0;
end;

function TMHProcessId.ToString: string;
begin
  Result := Format('%u@%x', [Pid, CreateTime]);
end;

function TMHProcessId.GetHashCode: Integer;
var
  LKey: array[0..1] of UInt64;
begin
  LKey[0] := Pid;
  LKey[1] := CreateTime;
  Result := THashBobJenkins.GetHashValue(LKey, SizeOf(LKey));
end;

class operator TMHProcessId.Equal(const A, B: TMHProcessId): Boolean;
begin
  Result := (A.Pid = B.Pid) and (A.CreateTime = B.CreateTime);
end;

class operator TMHProcessId.NotEqual(const A, B: TMHProcessId): Boolean;
begin
  Result := not (A = B);
end;

{ TMHMetric }

class function TMHMetric.Available(AKind: TMHMetricKind; AValue: Double;
  ATimestampUtc: TDateTime): TMHMetric;
begin
  Result.Kind := AKind;
  Result.Value := AValue;
  Result.HasValue := True;
  Result.TimestampUtc := ATimestampUtc;
end;

class function TMHMetric.NoData(AKind: TMHMetricKind;
  ATimestampUtc: TDateTime): TMHMetric;
begin
  Result.Kind := AKind;
  Result.Value := 0;
  Result.HasValue := False;
  Result.TimestampUtc := ATimestampUtc;
end;

{ TMHProcessInfo }

class function TMHProcessInfo.Create(const AId: TMHProcessId; const AName: string;
  ATimestampUtc: TDateTime): TMHProcessInfo;
begin
  Result := Default(TMHProcessInfo);
  Result.Id := AId;
  Result.Name := AName;
  Result.Signature := sgNotChecked;
  Result.Access := alUnknown;
  Result.Cpu := TMHMetric.NoData(mkCpuPercent, ATimestampUtc);
  Result.WorkingSet := TMHMetric.NoData(mkWorkingSetBytes, ATimestampUtc);
  Result.PrivateBytes := TMHMetric.NoData(mkPrivateBytes, ATimestampUtc);
  Result.PrivateWorkingSet := TMHMetric.NoData(mkPrivateWorkingSetBytes, ATimestampUtc);
  Result.Gpu := TMHMetric.NoData(mkGpuPercent, ATimestampUtc);
  Result.GpuCompute := TMHMetric.NoData(mkGpuComputePercent, ATimestampUtc);
  Result.GpuMemory := TMHMetric.NoData(mkGpuMemoryBytes, ATimestampUtc);
  Result.IoRead := TMHMetric.NoData(mkDiskReadBytesPerSec, ATimestampUtc);
  Result.IoWrite := TMHMetric.NoData(mkDiskWriteBytesPerSec, ATimestampUtc);
  Result.ThreadCount := MH_UNKNOWN_COUNT;
end;

{ TMHDiskInfo }

class function TMHDiskInfo.Create(ANumber: Integer; const AModel: string): TMHDiskInfo;
begin
  Result := Default(TMHDiskInfo);
  Result.Number := ANumber;
  Result.Model := AModel;
  Result.PowerOnHours := -1;
end;

{ TMHVolumeInfo }

function TMHVolumeInfo.FreePercent: Double;
begin
  if TotalBytes <= 0 then
    Exit(0);
  Result := FreeBytes / TotalBytes * 100;
end;

{ TMHProcessDetail }

class function TMHProcessDetail.Create(const AId: TMHProcessId): TMHProcessDetail;
begin
  Result := Default(TMHProcessDetail);
  Result.Id := AId;
  Result.Gpu := TMHMetric.NoData(mkGpuPercent, 0);
  Result.GpuCompute := TMHMetric.NoData(mkGpuComputePercent, 0);
  Result.GpuMemory := TMHMetric.NoData(mkGpuMemoryBytes, 0);
end;

{ TMHTamperEntry }

class function TMHTamperEntry.Create(AKind: TMHTamperKind; const AName, AValue,
  ALocation: string): TMHTamperEntry;
begin
  Result := Default(TMHTamperEntry);
  Result.Kind := AKind;
  Result.Name := AName;
  Result.Value := AValue;
  Result.Location := ALocation;
end;

{ TMHSensorReading }

class function TMHSensorReading.Create(AKind: TMHSensorKind; const ADevice, ASource: string;
  ACelsius, ALimitCelsius: Double): TMHSensorReading;
begin
  Result.Kind := AKind;
  Result.Device := ADevice;
  Result.Source := ASource;
  Result.Celsius := ACelsius;
  Result.LimitCelsius := ALimitCelsius;
end;

{ TMHFileInfo }

class function TMHFileInfo.Create(const APath: string): TMHFileInfo;
begin
  Result := Default(TMHFileInfo);
  Result.Path := APath;
  Result.SizeBytes := -1;
  Result.Signature := sgNotChecked;
end;

{ TMHNetConnection }

function TMHNetConnection.IsRemote: Boolean;
begin
  Result := (Transport = ntTcp) and (RemoteAddress <> '') and (RemotePort <> 0) and
    (RemoteAddress <> '0.0.0.0') and (RemoteAddress <> '::') and
    (RemoteAddress <> '127.0.0.1') and (RemoteAddress <> '::1');
end;

{ TMHContextInfo }

function TMHContextInfo.HasVisibleWindow(APid: Cardinal): Boolean;
var
  LPid: Cardinal;
begin
  for LPid in VisibleWindowPids do
    if LPid = APid then
      Exit(True);
  Result := False;
end;

{ TMHSourceStatus }

class function TMHSourceStatus.Create(const ASourceId: string; AState: TMHSourceState;
  const AMessage: string; ATimestampUtc: TDateTime): TMHSourceStatus;
begin
  Result := Default(TMHSourceStatus);
  Result.SourceId := ASourceId;
  Result.State := AState;
  Result.Message := AMessage;
  Result.TimestampUtc := ATimestampUtc;
end;

{ TMHEvidence }

class function TMHEvidence.Create(const ACode, ADescription: string; AWeight: Integer;
  const AObserved: string): TMHEvidence;
begin
  Result.Code := ACode;
  Result.Description := ADescription;
  Result.Weight := AWeight;
  Result.Observed := AObserved;
end;

function TMHEvidence.IsNegativeFactor: Boolean;
begin
  Result := Weight < 0;
end;

{ TMHFinding }

function TMHFinding.PositiveEvidence: TArray<TMHEvidence>;
var
  LItem: TMHEvidence;
begin
  Result := nil;
  for LItem in Evidence do
    if LItem.Weight > 0 then
      Result := Result + [LItem];
end;

function TMHFinding.NegativeEvidence: TArray<TMHEvidence>;
var
  LItem: TMHEvidence;
begin
  Result := nil;
  for LItem in Evidence do
    if LItem.Weight < 0 then
      Result := Result + [LItem];
end;

{ TMHAnalyzerSettings }

class function TMHAnalyzerSettings.Default: TMHAnalyzerSettings;
begin
  Result.Thresholds := TMHRiskThresholds.Default;
  Result.HighCpuPercent := 25;
  Result.HighCoreCpuPercent := 80;
  Result.SustainedMinutes := 10;
  Result.BaselineMinSamples := 1800;
end;

function TMHAnalyzerSettings.Normalized: TMHAnalyzerSettings;
begin
  Result := Self;
  if not Result.Thresholds.IsValid then
    Result.Thresholds := TMHRiskThresholds.Default;
  Result.HighCpuPercent := EnsureRange(HighCpuPercent, 1.0, 100.0);
  Result.HighCoreCpuPercent := EnsureRange(HighCoreCpuPercent, 10.0, 100.0);
  Result.SustainedMinutes := EnsureRange(SustainedMinutes, 1, 24 * 60);
  Result.BaselineMinSamples := EnsureRange(BaselineMinSamples, 10, 10000000);
end;

{ TMHExclusion }

function TMHExclusion.Matches(const AKey, ASha256: string): Boolean;
begin
  Result := (Key <> '') and SameText(Key, AKey) and
    ((Sha256 = '') or SameText(Sha256, ASha256));
end;

{ TMHStat }

function TMHStat.HasData: Boolean;
begin
  Result := SampleCount > 0;
end;

class function TMHStat.FromValues(var AValues: TArray<Double>): TMHStat;
var
  I: Integer;
  LSum: Double;

  function Percentile(AP: Double): Double;
  var
    LPos: Double;
    LLow: Integer;
  begin
    // Линейная интерполяция между соседними порядковыми статистиками.
    LPos := AP * (Length(AValues) - 1);
    LLow := Trunc(LPos);
    if LLow >= High(AValues) then
      Result := AValues[High(AValues)]
    else
      Result := AValues[LLow] + (AValues[LLow + 1] - AValues[LLow]) * (LPos - LLow);
  end;

begin
  Result := Default(TMHStat);
  Result.SampleCount := Length(AValues);
  if Result.SampleCount = 0 then
    Exit;
  TArray.Sort<Double>(AValues);
  LSum := 0;
  for I := 0 to High(AValues) do
    LSum := LSum + AValues[I];
  Result.Mean := LSum / Length(AValues);
  Result.Median := Percentile(0.5);
  Result.P95 := Percentile(0.95);
  Result.Max := AValues[High(AValues)];
end;

{ TMHRiskThresholds }

class function TMHRiskThresholds.Default: TMHRiskThresholds;
begin
  Result.Low := 15;
  Result.NeedsReview := 35;
  Result.Suspicious := 60;
  Result.HighlySuspicious := 85;
end;

function TMHRiskThresholds.IsValid: Boolean;
begin
  Result := (Low >= 1) and (Low < NeedsReview) and (NeedsReview < Suspicious) and
    (Suspicious < HighlySuspicious) and (HighlySuspicious <= 100);
end;

function TMHRiskThresholds.LevelOf(AScore: Integer): TMHRiskLevel;
begin
  if not IsValid then
    raise EMHError.Create('Некорректные пороги уровня риска');
  AScore := MHClampScore(AScore);
  if AScore >= HighlySuspicious then
    Result := rlHighlySuspicious
  else if AScore >= Suspicious then
    Result := rlSuspicious
  else if AScore >= NeedsReview then
    Result := rlNeedsReview
  else if AScore >= Low then
    Result := rlLow
  else
    Result := rlNone;
end;

{ TMHBaseline }

class function TMHBaseline.Empty: TMHBaseline;
begin
  Result := Default(TMHBaseline);
  Result.Context := wcUnknown;
end;

function TMHBaseline.IsEstablished(AMinSamples: Integer): Boolean;
begin
  Result := (AMinSamples > 0) and (SampleCount >= AMinSamples);
end;

function TMHBaseline.FindProcess(const AKey: string; out AStat: TMHProcessBaseline): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(Processes) do
    if SameText(Processes[I].Key, AKey) then
    begin
      AStat := Processes[I];
      Exit(True);
    end;
  AStat := Default(TMHProcessBaseline);
  Result := False;
end;

{ TMHSnapshot }

class function TMHSnapshot.Create(ASequence: UInt64; ATimestampUtc: TDateTime): TMHSnapshot;
begin
  Result := Default(TMHSnapshot);
  Result.Sequence := ASequence;
  Result.TimestampUtc := ATimestampUtc;
end;

function TMHSnapshot.FindProcess(const AId: TMHProcessId; out AInfo: TMHProcessInfo): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(Processes) do
    if Processes[I].Id = AId then
    begin
      AInfo := Processes[I];
      Exit(True);
    end;
  AInfo := Default(TMHProcessInfo);
  Result := False;
end;

function TMHSnapshot.FindSource(const ASourceId: string; out AStatus: TMHSourceStatus): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(Sources) do
    if SameText(Sources[I].SourceId, ASourceId) then
    begin
      AStatus := Sources[I];
      Exit(True);
    end;
  AStatus := Default(TMHSourceStatus);
  Result := False;
end;

function TMHSnapshot.FindFile(const APath: string; out AInfo: TMHFileInfo): Boolean;
var
  I: Integer;
begin
  if APath <> '' then
    for I := 0 to High(Files) do
      if SameText(Files[I].Path, APath) then
      begin
        AInfo := Files[I];
        Exit(True);
      end;
  AInfo := Default(TMHFileInfo);
  Result := False;
end;

function TMHSnapshot.ConnectionsOf(APid: Cardinal): TArray<TMHNetConnection>;
var
  LItem: TMHNetConnection;
begin
  Result := nil;
  for LItem in Connections do
    if LItem.OwningPid = APid then
      Result := Result + [LItem];
end;

function TMHSnapshot.FindMetric(AKind: TMHMetricKind; out AMetric: TMHMetric): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(Metrics) do
    if Metrics[I].Kind = AKind then
    begin
      AMetric := Metrics[I];
      Exit(True);
    end;
  AMetric := TMHMetric.NoData(AKind, TimestampUtc);
  Result := False;
end;

{ TMHCollectionResult }

class function TMHCollectionResult.Create(const AStatus: TMHSourceStatus): TMHCollectionResult;
begin
  Result := Default(TMHCollectionResult);
  Result.Status := AStatus;
end;

function MHSourceStateToString(AState: TMHSourceState): string;
begin
  case AState of
    ssSuccess:     Result := MHL('успех', 'success');
    ssPartial:     Result := MHL('частично', 'partial');
    ssUnavailable: Result := MHL('недоступно', 'unavailable');
    ssError:       Result := MHL('ошибка', 'error');
  else
    Result := MHL('не опрашивался', 'not polled');
  end;
end;

function MHRiskLevelToString(ALevel: TMHRiskLevel): string;
begin
  case ALevel of
    rlLow:              Result := MHL('низкий', 'low');
    rlNeedsReview:      Result := MHL('требует проверки', 'needs review');
    rlSuspicious:       Result := MHL('подозрительно', 'suspicious');
    rlHighlySuspicious: Result := MHL('высокая степень подозрения', 'highly suspicious');
  else
    Result := MHL('нет признаков', 'no signs');
  end;
end;

function MHSignatureToString(AState: TMHSignatureState): string;
begin
  case AState of
    sgSignedTrusted:   Result := MHL('подписан, доверенный издатель', 'signed, trusted publisher');
    sgSignedUntrusted: Result := MHL('подпись недействительна или не доверена', 'signature invalid or untrusted');
    sgUnsigned:        Result := MHL('без цифровой подписи', 'no digital signature');
    sgCheckFailed:     Result := MHL('проверить подпись не удалось', 'signature check failed');
  else
    Result := MHL('не проверялась', 'not checked');
  end;
end;

function MHFindingCategoryToString(ACategory: TMHFindingCategory): string;
begin
  case ACategory of
    fcMining:      Result := 'признаки скрытого майнинга';
    fcPersistence: Result := 'подозрительный автозапуск';
    fcPerformance: Result := 'необычная нагрузка';
  else
    Result := 'подозрительный процесс';
  end;
end;

function MHAutostartKindToString(AKind: TMHAutostartKind): string;
begin
  case AKind of
    akRegistryRun:     Result := 'реестр Run';
    akRegistryRunOnce: Result := 'реестр RunOnce';
    akStartupFolder:   Result := 'папка автозагрузки';
    akService:         Result := 'служба';
  else
    Result := 'планировщик заданий';
  end;
end;

function MHTamperKindToString(AKind: TMHTamperKind): string;
begin
  case AKind of
    tpWmiSubscription: Result := 'подписка WMI';
    tpDefenderExclusion: Result := 'исключение Microsoft Defender';
    tpIfeoDebugger: Result := 'перехват запуска программы (IFEO)';
    tpSilentExitMonitor: Result := 'запуск при завершении программы (SilentProcessExit)';
    tpHostsRedirect: Result := 'перенаправление в hosts';
  else
    Result := 'ограничивающая политика';
  end;
end;

function MHFindingCategoryTitle(ACategory: TMHFindingCategory): string;
begin
  case ACategory of
    fcMining:      Result := MHL(MHFindingCategoryToString(ACategory), 'signs of hidden mining');
    fcPersistence: Result := MHL(MHFindingCategoryToString(ACategory), 'suspicious autostart');
    fcPerformance: Result := MHL(MHFindingCategoryToString(ACategory), 'unusual load');
  else
    Result := MHL(MHFindingCategoryToString(ACategory), 'suspicious process');
  end;
end;

function MHAutostartKindTitle(AKind: TMHAutostartKind): string;
begin
  case AKind of
    akRegistryRun:     Result := MHL(MHAutostartKindToString(AKind), 'registry Run');
    akRegistryRunOnce: Result := MHL(MHAutostartKindToString(AKind), 'registry RunOnce');
    akStartupFolder:   Result := MHL(MHAutostartKindToString(AKind), 'startup folder');
    akService:         Result := MHL(MHAutostartKindToString(AKind), 'service');
  else
    Result := MHL(MHAutostartKindToString(AKind), 'task scheduler');
  end;
end;

function MHTamperKindTitle(AKind: TMHTamperKind): string;
begin
  case AKind of
    tpWmiSubscription:   Result := MHL(MHTamperKindToString(AKind), 'WMI subscription');
    tpDefenderExclusion: Result := MHL(MHTamperKindToString(AKind), 'Microsoft Defender exclusion');
    tpIfeoDebugger:      Result := MHL(MHTamperKindToString(AKind), 'program launch hijack (IFEO)');
    tpSilentExitMonitor: Result := MHL(MHTamperKindToString(AKind), 'launch on program exit (SilentProcessExit)');
    tpHostsRedirect:     Result := MHL(MHTamperKindToString(AKind), 'hosts redirect');
  else
    Result := MHL(MHTamperKindToString(AKind), 'restrictive policy');
  end;
end;

function MHWorkContextToString(AContext: TMHWorkContext): string;
begin
  case AContext of
    wcIdle:   Result := MHL('простой', 'idle');
    wcWork:   Result := MHL('работа', 'work');
    wcGaming: Result := MHL('игра / полноэкранный режим', 'gaming / full screen');
  else
    Result := MHL('не определён', 'undetermined');
  end;
end;

function MHProgramKey(const AImagePath, AName: string): string;
begin
  if AImagePath <> '' then
    Result := AImagePath.ToLower
  else
    Result := AName.ToLower;
end;

function MHFileTimeToUtc(AFileTime: UInt64): TDateTime;
begin
  if AFileTime = 0 then
    Exit(0);
  // FILETIME — сотни наносекунд с 1601-01-01; TDateTime 0 = 1899-12-30.
  Result := AFileTime / (10000000.0 * 86400) - 109205.0;
end;

function MHClampScore(AScore: Integer): Integer;
begin
  if AScore < 0 then
    Result := 0
  else if AScore > 100 then
    Result := 100
  else
    Result := AScore;
end;

end.
