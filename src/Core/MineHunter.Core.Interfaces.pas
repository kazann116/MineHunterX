unit MineHunter.Core.Interfaces;

{
  MineHunter X — контракты публичного API (MVP).

  Реализации не зависят от VCL. Все методы коллекторов и анализаторов
  вызываются из фонового потока сканера и не должны обращаться к GUI.
}

interface

uses
  MineHunter.Core.Types;

type
  TMHLogLevel = (llDebug, llInfo, llWarning, llError);

  TMHLogEntry = record
    TimestampUtc: TDateTime;
    Level: TMHLogLevel;
    Source: string;
    Message: string;
  end;

  /// Источник времени. Позволяет детерминированно тестировать расчёты по дельтам.
  IMHClock = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C01}']
    function NowUtc: TDateTime;
    /// Монотонный счётчик в миллисекундах для измерения длительностей.
    function TickMs: UInt64;
  end;

  /// Потокобезопасный журнал событий приложения.
  IMHLogger = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C02}']
    procedure Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
  end;

  /// Журнал, хранящий последние записи в памяти (для «Последних событий» в UI).
  IMHLogReader = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C03}']
    /// Растёт при каждой новой записи; позволяет UI обновляться только при изменениях.
    function Version: UInt64;
    function Entries: TArray<TMHLogEntry>;
  end;

  /// Единый контракт источника данных.
  /// Collect не должен выбрасывать исключения при штатных отказах (нет прав,
  /// источник недоступен) — такие ситуации описываются статусом результата.
  /// Если исключение всё же возникло, сканер переводит источник в ssError
  /// и продолжает работу с остальными коллекторами.
  IMHCollector = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C10}']
    function GetSourceId: string;
    function GetDisplayName: string;
    /// ASnapshot — снимок, собранный предыдущими коллекторами текущего цикла
    /// (только для чтения). Возвращает статус и новые данные источника.
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    property SourceId: string read GetSourceId;
    property DisplayName: string read GetDisplayName;
  end;

  /// Частота обновления редко меняющихся данных, секунды. 0 — «выкл.»: значение читается
  /// при запуске и по «Проверить сейчас» (Invalidate), но не обновляется само.
  TMHRefreshIntervals = record
    /// Температура и мощность видеокарт.
    GpuSensorsSec: Integer;
    /// Разделы и свободное место.
    VolumesSec: Integer;
    /// Журнал здоровья NVMe.
    NvmeHealthSec: Integer;
    /// Список дисков, износ и ошибки (счётчики Windows), SMART дисков SATA.
    DiskInfoSec: Integer;
    class function Default: TMHRefreshIntervals; static;
  end;

  /// Коллектор (или его источник), частоту обновления которого можно менять на ходу.
  /// Вызывается из главного потока; значения — целые, запись атомарна.
  IMHRefreshConfigurable = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C12}']
    procedure ApplyRefresh(const AIntervals: TMHRefreshIntervals);
  end;

  /// Коллектор с кэшем (автозапуск, признаки вмешательства): Invalidate
  /// заставляет следующий Collect перечитать источники («Проверить сейчас»).
  IMHCacheInvalidation = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C11}']
    procedure Invalidate;
  end;

  /// Детерминированный анализ: одинаковые входные данные дают одинаковый результат.
  IMHAnalyzer = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C20}']
    function GetRulesetVersion: string;
    function Analyze(const ASnapshot: TMHSnapshot;
      const ABaseline: TMHBaseline): TMHFindings;
    property RulesetVersion: string read GetRulesetVersion;
  end;

  /// Хранилище истории наблюдений без привязки к GUI.
  IMHRepository = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C30}']
    procedure SaveSnapshot(const ASnapshot: TMHSnapshot);
    /// Снимки в интервале [AFromUtc; AToUtc], не более AMaxCount, по возрастанию времени.
    function LoadHistory(AFromUtc, AToUtc: TDateTime;
      AMaxCount: Integer): TArray<TMHSnapshot>;
  end;

  TMHHistoryStats = record
    SnapshotCount: Int64;
    OldestUtc: TDateTime;   // 0 — история пуста
    NewestUtc: TDateTime;
    FileSizeBytes: Int64;
  end;

  /// Временные ряды для графиков и сравнения с историей.
  /// Ряды прореживаются до AMaxPoints точек усреднением по равным интервалам;
  /// интервал без измерений даёт точку «нет данных» (разрыв на графике).
  IMHMetricHistory = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C31}']
    function LoadMetricSeries(AKind: TMHMetricKind; AFromUtc, AToUtc: TDateTime;
      AMaxPoints: Integer): TArray<TMHMetric>;
    function LoadProcessSeries(const AId: TMHProcessId; AKind: TMHMetricKind;
      AFromUtc, AToUtc: TDateTime; AMaxPoints: Integer): TArray<TMHMetric>;
    function GetStats: TMHHistoryStats;
    /// Удаляет всю историю. Вызывающая сторона обязана получить подтверждение пользователя.
    procedure Clear;
  end;

  /// Профили нормы по контекстам работы (MH-06).
  IMHBaselineProvider = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C60}']
    /// Профиль для контекста; TMHBaseline.Empty, если он ещё не сформирован.
    function BaselineFor(AContext: TMHWorkContext): TMHBaseline;
  end;

  /// Находка из истории: последняя версия и сведения о повторениях.
  TMHStoredFinding = record
    Finding: TMHFinding;
    FirstSeenUtc: TDateTime;
    LastSeenUtc: TDateTime;
    MaxScore: Integer;
    Occurrences: Integer;
  end;

  /// История находок (MH-09). Повторы одной находки объединяются по TMHFinding.Key.
  IMHFindingHistory = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C32}']
    procedure SaveFindings(const AFindings: TMHFindings);
    /// Находки, наблюдавшиеся в интервале, — новые первыми.
    function LoadFindings(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer): TArray<TMHStoredFinding>;
  end;

  /// Запись журнала изменяющих действий (MH-10): остановка процесса,
  /// исключения, очистка истории и т.п.
  TMHActionRecord = record
    TimestampUtc: TDateTime;
    Action: string;
    Target: string;
    Result: string;
    Success: Boolean;
  end;

  IMHActionLog = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C33}']
    procedure LogAction(const ARecord: TMHActionRecord);
    /// Последние записи — новые первыми.
    function LoadActions(AMaxCount: Integer): TArray<TMHActionRecord>;
  end;

function MHLogLevelToString(ALevel: TMHLogLevel): string;

implementation

{ TMHRefreshIntervals }

class function TMHRefreshIntervals.Default: TMHRefreshIntervals;
begin
  Result.GpuSensorsSec := 5;
  Result.VolumesSec := 30;
  Result.NvmeHealthSec := 60;
  Result.DiskInfoSec := 600;
end;

function MHLogLevelToString(ALevel: TMHLogLevel): string;
begin
  case ALevel of
    llDebug:   Result := 'отладка';
    llInfo:    Result := 'инфо';
    llWarning: Result := 'внимание';
  else
    Result := 'ошибка';
  end;
end;

end.
