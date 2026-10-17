unit MineHunter.Collectors.Processes;

{
  Коллектор процессов (MH-01).

  Логика отделена от Windows API интерфейсом IMHProcessApi, чтобы сценарии
  «нет доступа», «процесс исчез», «PID переиспользован» и «1000+ процессов»
  проверялись детерминированными unit-тестами. Реальная реализация —
  MineHunter.Collectors.Processes.WinApi.

  Загрузка CPU считается по дельте времени процессора между двумя опросами
  для одного и того же экземпляра процесса (PID + время создания). Новый
  экземпляр, в том числе с переиспользованным PID, получает «нет данных»
  до следующего опроса.

  Как на вкладке «Процессы» диспетчера задач, загрузка процесса приводится к
  «загруженности» с учётом частоты: множитель — отношение системных метрик
  mkCpuPercent / mkCpuTimePercent текущего снимка (коллектор system идёт
  раньше). Нет этих метрик — множитель 1 (чистое время работы).
  «Память» — частный рабочий набор (как в диспетчере задач); рабочий набор
  и выделенная память остаются отдельными метриками.

  Коллектор не потокобезопасен: сканер вызывает Collect последовательно.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Запись перечня процессов (снимок Toolhelp32).
  TMHRawProcessEntry = record
    Pid: Cardinal;
    ParentPid: Cardinal;
    ExeName: string;
    ThreadCount: Integer;
  end;

  TMHProcessQueryStatus = (
    pqOk,            // процесс открыт (часть полей может отсутствовать)
    pqAccessDenied,  // открыть процесс не удалось из-за прав
    pqGone           // процесс завершился между перечислением и открытием
  );

  /// Сведения, полученные через дескриптор процесса.
  TMHRawProcessDetails = record
    Status: TMHProcessQueryStatus;
    HasTimes: Boolean;
    CreateTime: UInt64;      // FILETIME
    CpuTime100ns: UInt64;    // ядро + пользователь
    ImagePath: string;       // '' — путь получить не удалось
    HasMemory: Boolean;
    WorkingSetBytes: UInt64;
    PrivateBytes: UInt64;
  end;

  /// Частный рабочий набор процесса по PID.
  TMHPidBytes = record
    Pid: Cardinal;
    Bytes: UInt64;
  end;

  /// Абстракция системных вызовов для коллектора процессов.
  IMHProcessApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C40}']
    /// False и AError — если перечень процессов получить не удалось.
    function Enumerate(out AEntries: TArray<TMHRawProcessEntry>; out AError: string): Boolean;
    function Query(APid: Cardinal): TMHRawProcessDetails;
    /// Текущее время в формате FILETIME (100 нс) — для дельты CPU.
    function NowFileTime: UInt64;
    function LogicalCpuCount: Integer;
    function IsElevated: Boolean;
    /// Частный рабочий набор процессов; пустой массив — данные недоступны.
    /// Реализация может обновлять значения реже, чем каждый опрос.
    function PrivateWorkingSets: TArray<TMHPidBytes>;
  end;

  TMHProcessCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'processes';
  private type
    TCpuSample = record
      Cpu100ns: UInt64;
      Wall100ns: UInt64;
    end;
  private
    FApi: IMHProcessApi;
    FClock: IMHClock;
    FPrevious: TDictionary<TMHProcessId, TCpuSample>;
    FCpuCount: Integer;
    function BuildInfo(const AEntry: TMHRawProcessEntry; const ADetails: TMHRawProcessDetails;
      AWallNow: UInt64; ANow: TDateTime; ACpuFactor: Double;
      ACurrent: TDictionary<TMHProcessId, TCpuSample>): TMHProcessInfo;
  public
    constructor Create(const AApi: IMHProcessApi; const AClock: IMHClock);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Число экземпляров, для которых хранится предыдущий замер CPU.
    function TrackedCount: Integer;
  end;

/// Множитель «загруженность / время работы» по системным метрикам снимка
/// (1 — данных нет или загрузка слишком мала для надёжного отношения).
function MHCpuUtilityFactor(const ASnapshot: TMHSnapshot): Double;

implementation

uses
  System.Generics.Defaults, System.Math,
  MineHunter.Core.Calc, MineHunter.Core.Lang;

type
  TProcessIdComparer = class(TEqualityComparer<TMHProcessId>)
  public
    function Equals(const Left, Right: TMHProcessId): Boolean; override;
    function GetHashCode(const Value: TMHProcessId): Integer; override;
  end;

function TProcessIdComparer.Equals(const Left, Right: TMHProcessId): Boolean;
begin
  Result := Left = Right;
end;

function TProcessIdComparer.GetHashCode(const Value: TMHProcessId): Integer;
begin
  Result := Value.GetHashCode;
end;

{ TMHProcessCollector }

constructor TMHProcessCollector.Create(const AApi: IMHProcessApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
  FCpuCount := FApi.LogicalCpuCount;
  if FCpuCount <= 0 then
    FCpuCount := 1;
  FPrevious := TDictionary<TMHProcessId, TCpuSample>.Create(TProcessIdComparer.Create);
end;

destructor TMHProcessCollector.Destroy;
begin
  FPrevious.Free;
  inherited;
end;

function TMHProcessCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHProcessCollector.GetDisplayName: string;
begin
  Result := MHL('Процессы', 'Processes');
end;

function TMHProcessCollector.TrackedCount: Integer;
begin
  Result := FPrevious.Count;
end;

function MHCpuUtilityFactor(const ASnapshot: TMHSnapshot): Double;
var
  LUtility, LTime: TMHMetric;
begin
  Result := 1;
  if ASnapshot.FindMetric(mkCpuPercent, LUtility) and LUtility.HasValue and
     ASnapshot.FindMetric(mkCpuTimePercent, LTime) and LTime.HasValue and (LTime.Value >= 1) then
    // Ограничение защищает от выбросов счётчиков (турбочастота даёт до ~2 раз).
    Result := EnsureRange(LUtility.Value / LTime.Value, 0.25, 4.0);
end;

function TMHProcessCollector.BuildInfo(const AEntry: TMHRawProcessEntry;
  const ADetails: TMHRawProcessDetails; AWallNow: UInt64; ANow: TDateTime; ACpuFactor: Double;
  ACurrent: TDictionary<TMHProcessId, TCpuSample>): TMHProcessInfo;
var
  LId: TMHProcessId;
  LPrev, LSample: TCpuSample;
  LCpuDelta, LWallDelta: UInt64;
  LPercent: Double;
  LComplete: Boolean;
begin
  if ADetails.HasTimes then
    LId := TMHProcessId.Create(AEntry.Pid, ADetails.CreateTime)
  else
    LId := TMHProcessId.Create(AEntry.Pid, 0);

  Result := TMHProcessInfo.Create(LId, AEntry.ExeName, ANow);
  Result.ParentPid := AEntry.ParentPid;
  Result.ThreadCount := AEntry.ThreadCount;
  Result.SourceId := SourceIdValue;

  if ADetails.Status = pqAccessDenied then
  begin
    Result.Access := alDenied;
    Exit;
  end;

  Result.ImagePath := ADetails.ImagePath;
  LComplete := ADetails.HasTimes and ADetails.HasMemory and (ADetails.ImagePath <> '');

  if ADetails.HasMemory then
  begin
    Result.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, ADetails.WorkingSetBytes, ANow);
    Result.PrivateBytes := TMHMetric.Available(mkPrivateBytes, ADetails.PrivateBytes, ANow);
  end;

  // CPU считается только для экземпляров с известным временем создания:
  // без него нельзя отличить продолжение работы от переиспользованного PID.
  if ADetails.HasTimes and LId.HasCreateTime then
  begin
    LSample.Cpu100ns := ADetails.CpuTime100ns;
    LSample.Wall100ns := AWallNow;
    ACurrent.AddOrSetValue(LId, LSample);
    if FPrevious.TryGetValue(LId, LPrev) and
       MHTryCounterDelta(LPrev.Cpu100ns, LSample.Cpu100ns, LCpuDelta) and
       MHTryCounterDelta(LPrev.Wall100ns, LSample.Wall100ns, LWallDelta) and
       MHTryCalcCpuPercent(LCpuDelta, LWallDelta, FCpuCount, LPercent) then
      Result.Cpu := TMHMetric.Available(mkCpuPercent, Min(100.0, LPercent * ACpuFactor), ANow);
  end;

  if LComplete then
    Result.Access := alFull
  else
    Result.Access := alLimited;
end;

function TMHProcessCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LEntries: TArray<TMHRawProcessEntry>;
  LError: string;
  LDetails: TMHRawProcessDetails;
  LInfos: TList<TMHProcessInfo>;
  LCurrent: TDictionary<TMHProcessId, TCpuSample>;
  LWallNow: UInt64;
  LDenied, LLimited, LGone, LReused: Integer;
  LEntry: TMHRawProcessEntry;
  LInfo: TMHProcessInfo;
  LState: TMHSourceState;
  LMessage: string;
  LCpuFactor: Double;
  LPrivate: TDictionary<Cardinal, UInt64>;
  LPidBytes: TMHPidBytes;
  LPrivateBytes: UInt64;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;

  if not FApi.Enumerate(LEntries, LError) then
    Exit(TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, ssError,
      MHL('Не удалось получить список процессов: ', 'Failed to get the process list: ') + LError, LNow)));

  LWallNow := FApi.NowFileTime;
  LCpuFactor := MHCpuUtilityFactor(ASnapshot);
  LDenied := 0;
  LLimited := 0;
  LGone := 0;
  LReused := 0;
  LInfos := TList<TMHProcessInfo>.Create;
  LCurrent := TDictionary<TMHProcessId, TCpuSample>.Create(Length(LEntries),
    TProcessIdComparer.Create);
  LPrivate := TDictionary<Cardinal, UInt64>.Create;
  try
    for LPidBytes in FApi.PrivateWorkingSets do
      LPrivate.AddOrSetValue(LPidBytes.Pid, LPidBytes.Bytes);
    LInfos.Capacity := Length(LEntries);
    for LEntry in LEntries do
    begin
      LDetails := FApi.Query(LEntry.Pid);
      if LDetails.Status = pqGone then
      begin
        Inc(LGone);
        Continue;
      end;
      // Защита от гонки: между перечислением и открытием PID мог достаться
      // другому процессу. Тогда имя из перечня не совпадает с образом.
      if (LDetails.Status = pqOk) and (LDetails.ImagePath <> '') and (LEntry.ExeName <> '') and
         not SameText(ExtractFileName(LDetails.ImagePath), LEntry.ExeName) then
      begin
        Inc(LReused);
        Continue;
      end;
      LInfo := BuildInfo(LEntry, LDetails, LWallNow, LNow, LCpuFactor, LCurrent);
      if (LInfo.Access <> alDenied) and LPrivate.TryGetValue(LEntry.Pid, LPrivateBytes) then
        LInfo.PrivateWorkingSet := TMHMetric.Available(mkPrivateWorkingSetBytes, LPrivateBytes, LNow);
      case LInfo.Access of
        alDenied: Inc(LDenied);
        alLimited: Inc(LLimited);
      end;
      LInfos.Add(LInfo);
    end;

    // Храним замеры только живых экземпляров — словарь не растёт бесконечно.
    FPrevious.Free;
    FPrevious := LCurrent;
    LCurrent := nil;

    LState := ssSuccess;
    LMessage := '';
    if (LDenied > 0) or (LLimited > 0) then
    begin
      LState := ssPartial;
      if LDenied > 0 then
        LMessage := Format(MHL('Нет доступа к %d из %d процессов.', 'No access to %d of %d processes.'),
          [LDenied, LInfos.Count]);
      if LLimited > 0 then
        LMessage := Trim(LMessage + Format(MHL(' Неполные данные: %d из %d процессов.',
          ' Incomplete data: %d of %d processes.'), [LLimited, LInfos.Count]));
    end;
    if LGone + LReused > 0 then
      LMessage := Trim(LMessage + Format(MHL(' Завершились во время опроса: %d.',
        ' Exited during polling: %d.'), [LGone + LReused]));

    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState,
      LMessage, LNow));
    Result.Status.ItemCount := LInfos.Count;
    Result.Status.RequiresElevation := (LState = ssPartial) and not FApi.IsElevated;
    Result.Processes := LInfos.ToArray;
  finally
    LPrivate.Free;
    LCurrent.Free;
    LInfos.Free;
  end;
end;

end.
