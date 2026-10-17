unit MineHunter.Collectors.Context;

{
  Коллектор контекста работы пользователя.

  Поставляет данные для снижения ложных срабатываний и выбора профиля нормы:
  время бездействия пользователя, процесс активного окна, полноэкранный режим,
  процессы с видимыми окнами и итоговый контекст работы (простой / работа /
  игра). Дополнительно получает командные строки процессов с заметной
  нагрузкой CPU.

  Командные строки запрашиваются дорого (WMI), поэтому:
    - только для процессов из ASnapshot.Processes (их собирает коллектор
      процессов в этом же цикле — он должен быть зарегистрирован раньше),
      у которых CPU >= порога;
    - не более AMaxCommandLinesPerCycle процессов за цикл, по убыванию CPU;
    - результат кешируется по полной идентичности TMHProcessId (PID + время
      создания), поэтому переиспользованный PID получает новый запрос, а не
      чужую командную строку; записи завершившихся процессов удаляются.

  Логика отделена от Windows API интерфейсом IMHContextApi; реальная
  реализация — MineHunter.Collectors.Context.WinApi.
  Коллектор не потокобезопасен: сканер вызывает Collect последовательно.
}

interface

uses
  System.SysUtils, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Абстракция системных вызовов для коллектора контекста.
  IMHContextApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C72}']
    /// Секунды с момента последнего ввода пользователя; False — нет данных.
    function UserIdleSeconds(out ASeconds: Cardinal): Boolean;
    /// PID процесса активного окна; 0 — активного окна нет.
    function ForegroundPid: Cardinal;
    /// Работает ли полноэкранное приложение; False — состояние неизвестно.
    function FullscreenState(out AFullscreen: Boolean): Boolean;
    /// Уникальные PID процессов с видимыми окнами верхнего уровня.
    function VisibleWindowPids: TArray<Cardinal>;
    /// Командные строки процессов. В ALines заполнены Id.Pid и CommandLine
    /// (CreateTime может быть 0). Процессы, о которых нет сведений, могут
    /// отсутствовать в ALines. False и AError — если запрос не выполнен.
    function ReadCommandLines(const APids: TArray<Cardinal>;
      out ALines: TArray<TMHProcessDetail>; out AError: string): Boolean;
  end;

  TMHContextCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'context';
    DefaultIdleThresholdSeconds = 300;
    DefaultCommandLineCpuPercent = 3.0;
    DefaultMaxCommandLinesPerCycle = 20;
  private
    FApi: IMHContextApi;
    FClock: IMHClock;
    FIdleThresholdSeconds: Cardinal;
    FCommandLineCpuPercent: Double;
    FMaxCommandLinesPerCycle: Integer;
    /// Командные строки по идентичности экземпляра ('' — сведений нет).
    FCommandLines: TDictionary<TMHProcessId, string>;
    function ReadContext(out AMessages: TArray<string>): TMHContextInfo;
    function UpdateCommandLines(const ASnapshot: TMHSnapshot; out AError: string): Boolean;
    function CachedDetails(const ASnapshot: TMHSnapshot): TArray<TMHProcessDetail>;
  public
    /// AIdleThresholdSeconds — бездействие, после которого контекст считается
    /// простоем; ACommandLineCpuPercent — порог CPU для запроса командной строки;
    /// AMaxCommandLinesPerCycle — максимум запросов командных строк за цикл.
    constructor Create(const AApi: IMHContextApi; const AClock: IMHClock;
      AIdleThresholdSeconds: Integer = DefaultIdleThresholdSeconds;
      ACommandLineCpuPercent: Double = DefaultCommandLineCpuPercent;
      AMaxCommandLinesPerCycle: Integer = DefaultMaxCommandLinesPerCycle);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Число экземпляров процессов в кеше командных строк.
    function CachedCount: Integer;
  end;

implementation

uses
  System.Math;

type
  TProcessIdComparer = class(TEqualityComparer<TMHProcessId>)
  public
    function Equals(const Left, Right: TMHProcessId): Boolean; override;
    function GetHashCode(const Value: TMHProcessId): Integer; override;
  end;

  TCandidate = record
    Id: TMHProcessId;
    Cpu: Double;
  end;

function TProcessIdComparer.Equals(const Left, Right: TMHProcessId): Boolean;
begin
  Result := Left = Right;
end;

function TProcessIdComparer.GetHashCode(const Value: TMHProcessId): Integer;
begin
  Result := Value.GetHashCode;
end;

{ TMHContextCollector }

constructor TMHContextCollector.Create(const AApi: IMHContextApi; const AClock: IMHClock;
  AIdleThresholdSeconds: Integer; ACommandLineCpuPercent: Double;
  AMaxCommandLinesPerCycle: Integer);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if AIdleThresholdSeconds <= 0 then
    raise EArgumentOutOfRangeException.Create('AIdleThresholdSeconds');
  if AMaxCommandLinesPerCycle < 0 then
    raise EArgumentOutOfRangeException.Create('AMaxCommandLinesPerCycle');
  FApi := AApi;
  FClock := AClock;
  FIdleThresholdSeconds := Cardinal(AIdleThresholdSeconds);
  FCommandLineCpuPercent := Max(ACommandLineCpuPercent, 0.0);
  FMaxCommandLinesPerCycle := AMaxCommandLinesPerCycle;
  FCommandLines := TDictionary<TMHProcessId, string>.Create(TProcessIdComparer.Create);
end;

destructor TMHContextCollector.Destroy;
begin
  FCommandLines.Free;
  inherited;
end;

function TMHContextCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHContextCollector.GetDisplayName: string;
begin
  Result := 'Контекст работы';
end;

function TMHContextCollector.CachedCount: Integer;
begin
  Result := FCommandLines.Count;
end;

function TMHContextCollector.ReadContext(out AMessages: TArray<string>): TMHContextInfo;
var
  LIdle: Cardinal;
  LHasIdle, LFullscreen: Boolean;
begin
  AMessages := nil;
  Result := Default(TMHContextInfo);
  Result.Available := True;

  LHasIdle := FApi.UserIdleSeconds(LIdle);
  if LHasIdle then
    Result.UserIdleSeconds := LIdle
  else
    AMessages := AMessages + ['Время бездействия пользователя недоступно.'];

  if FApi.FullscreenState(LFullscreen) then
    Result.FullscreenActive := LFullscreen
  else
    AMessages := AMessages + ['Состояние полноэкранного режима недоступно.'];

  Result.ForegroundPid := FApi.ForegroundPid;
  Result.VisibleWindowPids := FApi.VisibleWindowPids;

  if Result.FullscreenActive then
    Result.WorkContext := wcGaming
  else if not LHasIdle then
    Result.WorkContext := wcUnknown
  else if Result.UserIdleSeconds >= FIdleThresholdSeconds then
    Result.WorkContext := wcIdle
  else
    Result.WorkContext := wcWork;
end;

function TMHContextCollector.UpdateCommandLines(const ASnapshot: TMHSnapshot;
  out AError: string): Boolean;
var
  LPresent: TDictionary<TMHProcessId, Boolean>;
  LCandidates: TList<TCandidate>;
  LStale: TList<TMHProcessId>;
  LCandidate: TCandidate;
  LInfo: TMHProcessInfo;
  LId: TMHProcessId;
  LPids: TArray<Cardinal>;
  LLines: TArray<TMHProcessDetail>;
  LLine: TMHProcessDetail;
  LByPid: TDictionary<Cardinal, string>;
  I, LCount: Integer;
  LText: string;
begin
  AError := '';
  LPresent := TDictionary<TMHProcessId, Boolean>.Create(Length(ASnapshot.Processes),
    TProcessIdComparer.Create);
  LCandidates := TList<TCandidate>.Create;
  LStale := TList<TMHProcessId>.Create;
  try
    for LInfo in ASnapshot.Processes do
    begin
      LPresent.AddOrSetValue(LInfo.Id, True);
      // Без времени создания нельзя отличить экземпляр от переиспользованного PID.
      if (LInfo.Id.Pid <> 0) and LInfo.Id.HasCreateTime and LInfo.Cpu.HasValue and
         (LInfo.Cpu.Value >= FCommandLineCpuPercent) and
         not FCommandLines.ContainsKey(LInfo.Id) then
      begin
        LCandidate.Id := LInfo.Id;
        LCandidate.Cpu := LInfo.Cpu.Value;
        LCandidates.Add(LCandidate);
      end;
    end;

    // Кеш хранит только живые экземпляры.
    for LId in FCommandLines.Keys do
      if not LPresent.ContainsKey(LId) then
        LStale.Add(LId);
    for LId in LStale do
      FCommandLines.Remove(LId);

    if (LCandidates.Count = 0) or (FMaxCommandLinesPerCycle = 0) then
      Exit(True);

    // В первую очередь — самые нагруженные процессы.
    LCandidates.Sort(TComparer<TCandidate>.Construct(
      function(const Left, Right: TCandidate): Integer
      begin
        Result := CompareValue(Right.Cpu, Left.Cpu);
        if Result = 0 then
          Result := CompareValue(Int64(Left.Id.Pid), Int64(Right.Id.Pid));
      end));
    LCount := Min(LCandidates.Count, FMaxCommandLinesPerCycle);
    SetLength(LPids, LCount);
    for I := 0 to LCount - 1 do
      LPids[I] := LCandidates[I].Id.Pid;

    if not FApi.ReadCommandLines(LPids, LLines, AError) then
    begin
      if AError = '' then
        AError := 'причина неизвестна';
      Exit(False);
    end;

    LByPid := TDictionary<Cardinal, string>.Create(Length(LLines));
    try
      for LLine in LLines do
        LByPid.AddOrSetValue(LLine.Id.Pid, LLine.CommandLine);
      // Запрошенные экземпляры кешируются даже без ответа (процесс другого
      // пользователя или уже завершился), чтобы не повторять дорогой запрос.
      for I := 0 to LCount - 1 do
      begin
        if not LByPid.TryGetValue(LCandidates[I].Id.Pid, LText) then
          LText := '';
        FCommandLines.AddOrSetValue(LCandidates[I].Id, LText);
      end;
    finally
      LByPid.Free;
    end;
    Result := True;
  finally
    LStale.Free;
    LCandidates.Free;
    LPresent.Free;
  end;
end;

function TMHContextCollector.CachedDetails(const ASnapshot: TMHSnapshot): TArray<TMHProcessDetail>;
var
  LInfo: TMHProcessInfo;
  LDetail: TMHProcessDetail;
  LText: string;
begin
  Result := nil;
  for LInfo in ASnapshot.Processes do
    if FCommandLines.TryGetValue(LInfo.Id, LText) and (LText <> '') then
    begin
      // Create обнуляет все поля: у локальной записи без него метрики GPU содержали бы мусор.
      LDetail := TMHProcessDetail.Create(LInfo.Id);
      LDetail.CommandLine := LText;
      Result := Result + [LDetail];
    end;
end;

function TMHContextCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LContext: TMHContextInfo;
  LMessages: TArray<string>;
  LError: string;
  LState: TMHSourceState;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;

  LContext := ReadContext(LMessages);
  try
    if not UpdateCommandLines(ASnapshot, LError) then
      LMessages := LMessages + ['Не удалось получить командные строки процессов: ' + LError + '.'];
  except
    // Сбой WMI не должен лишать сканер данных контекста.
    on E: Exception do
      LMessages := LMessages + ['Не удалось получить командные строки процессов: ' +
        E.Message + '.'];
  end;

  if Length(LMessages) = 0 then
    LState := ssSuccess
  else
    LState := ssPartial;
  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState,
    string.Join(' ', LMessages), LNow));
  Result.HasContext := True;
  Result.Context := LContext;
  Result.ProcessDetails := CachedDetails(ASnapshot);
  Result.Status.ItemCount := Length(Result.ProcessDetails);
end;

end.
