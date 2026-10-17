unit MineHunter.Collectors.ProcessEvents;

{
  События запуска и завершения процессов (MH-05, расширение).
  Опрос списка процессов раз в несколько секунд не видит программы, которые
  живут меньше интервала. Источник событий (ETW, провайдер
  Microsoft-Windows-Kernel-Process) сообщает о каждом запуске и завершении;
  коллектор сводит их в статистику по программам за скользящее окно
  (TMHLaunchStat): сколько раз запускалась, сколько раз завершилась быстрее
  ShortLivedSeconds, кто запускал.

  Сеанс ETW требует прав администратора (или группы «Пользователи журналов
  производительности»). Без них источник недоступен, остальной мониторинг
  работает как обычно, а статус источника подсказывает, что даст повышение прав.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHProcessEventKind = (pekStart, pekStop);

  TMHProcessEvent = record
  public
    Kind: TMHProcessEventKind;
    Pid: Cardinal;
    ParentPid: Cardinal;
    /// Время создания процесса (FILETIME) — вместе с PID однозначно задаёт экземпляр.
    CreateTime: UInt64;
    TimestampUtc: TDateTime;
    /// Путь в формате Windows (C:\...). Только у события запуска.
    ImagePath: string;
  end;

  IMHProcessEventSource = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CF0}']
    /// Запускает приём событий. False — недоступно (причина в AError;
    /// AAccessDenied — нужны права администратора).
    function Start(out AError: string; out AAccessDenied: Boolean): Boolean;
    procedure Stop;
    /// Забирает накопленные события (потокобезопасно). ALost — потерянные
    /// источником события (переполнение буферов) с прошлого вызова.
    function Drain(out ALost: Integer): TArray<TMHProcessEvent>;
    function IsRunning: Boolean;
  end;

  TMHProcessEventCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'processevents';
    DefaultWindowMinutes = 30;
    DefaultShortLivedSeconds = 15;
    /// Предел отслеживаемых запусков (защита памяти при «шторме» процессов).
    MaxTracked = 20000;
    /// Повторная попытка запуска источника после сбоя (кроме отказа в доступе), минуты.
    RetryMinutes = 10;
    /// Сколько программ передаётся в снимок (самые часто запускаемые).
    MaxStats = 50;
  private type
    TLaunch = record
      Key: string;
      ImagePath: string;
      Name: string;
      StartUtc: TDateTime;
      ParentPid: Cardinal;
      ParentName: string;
      /// < 0 — процесс ещё работает (или его завершение не наблюдалось).
      LifetimeSeconds: Double;
    end;
  private
    FSource: IMHProcessEventSource;
    FClock: IMHClock;
    FWindowMinutes: Integer;
    FShortLivedSeconds: Integer;
    FStarted: Boolean;
    FAccessDenied: Boolean;
    FError: string;
    FLastAttemptUtc: TDateTime;
    FLostTotal: Int64;
    FLaunches: TList<TLaunch>;
    /// Ключ экземпляра → индекс в FLaunches (для сопоставления завершения).
    FIndex: TDictionary<string, Integer>;
    FNames: TDictionary<Cardinal, string>;
    procedure EnsureStarted(ANowUtc: TDateTime);
    procedure Apply(const AEvent: TMHProcessEvent);
    procedure Prune(ANowUtc: TDateTime);
    procedure RebuildIndex;
    function BuildStats: TArray<TMHLaunchStat>;
    class function InstanceKey(APid: Cardinal; ACreateTime: UInt64): string; static;
  public
    constructor Create(const ASource: IMHProcessEventSource; const AClock: IMHClock;
      AWindowMinutes: Integer = DefaultWindowMinutes; AShortLivedSeconds: Integer = DefaultShortLivedSeconds);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Запусков в окне (для диагностики и тестов).
    function TrackedCount: Integer;
  end;

implementation

uses
  System.Math, System.DateUtils, System.Generics.Defaults;

constructor TMHProcessEventCollector.Create(const ASource: IMHProcessEventSource; const AClock: IMHClock;
  AWindowMinutes, AShortLivedSeconds: Integer);
begin
  inherited Create;
  if ASource = nil then
    raise EArgumentNilException.Create('ASource');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FSource := ASource;
  FClock := AClock;
  FWindowMinutes := Max(1, AWindowMinutes);
  FShortLivedSeconds := Max(1, AShortLivedSeconds);
  FLaunches := TList<TLaunch>.Create;
  FIndex := TDictionary<string, Integer>.Create;
  FNames := TDictionary<Cardinal, string>.Create;
end;

destructor TMHProcessEventCollector.Destroy;
begin
  if FStarted then
    try
      FSource.Stop;
    except
      // Остановка сеанса при завершении программы не должна мешать освобождению.
    end;
  FNames.Free;
  FIndex.Free;
  FLaunches.Free;
  inherited;
end;

function TMHProcessEventCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHProcessEventCollector.GetDisplayName: string;
begin
  Result := 'Запуски процессов (ETW)';
end;

function TMHProcessEventCollector.TrackedCount: Integer;
begin
  Result := FLaunches.Count;
end;

class function TMHProcessEventCollector.InstanceKey(APid: Cardinal; ACreateTime: UInt64): string;
begin
  Result := IntToStr(APid) + ':' + UIntToStr(ACreateTime);
end;

procedure TMHProcessEventCollector.EnsureStarted(ANowUtc: TDateTime);
var
  LError: string;
  LDenied: Boolean;
begin
  if FStarted or FAccessDenied then
    Exit;
  if (FLastAttemptUtc <> 0) and (MinutesBetween(ANowUtc, FLastAttemptUtc) < RetryMinutes) then
    Exit;
  FLastAttemptUtc := ANowUtc;
  try
    FStarted := FSource.Start(LError, LDenied);
  except
    on E: Exception do
    begin
      FStarted := False;
      LError := E.Message;
      LDenied := False;
    end;
  end;
  if FStarted then
    FError := ''
  else
  begin
    FError := LError;
    FAccessDenied := LDenied;
  end;
end;

procedure TMHProcessEventCollector.Apply(const AEvent: TMHProcessEvent);
var
  LLaunch: TMHProcessEventCollector.TLaunch;
  LIndex: Integer;
  LParentName: string;
begin
  case AEvent.Kind of
    pekStart:
      begin
        if AEvent.ImagePath = '' then
          Exit;
        LLaunch := Default(TMHProcessEventCollector.TLaunch);
        LLaunch.Key := InstanceKey(AEvent.Pid, AEvent.CreateTime);
        LLaunch.ImagePath := AEvent.ImagePath;
        LLaunch.Name := ExtractFileName(AEvent.ImagePath);
        LLaunch.StartUtc := AEvent.TimestampUtc;
        LLaunch.ParentPid := AEvent.ParentPid;
        if FNames.TryGetValue(AEvent.ParentPid, LParentName) then
          LLaunch.ParentName := LParentName;
        LLaunch.LifetimeSeconds := -1;
        FNames.AddOrSetValue(AEvent.Pid, LLaunch.Name);
        if FIndex.ContainsKey(LLaunch.Key) then
          Exit;
        FIndex.Add(LLaunch.Key, FLaunches.Add(LLaunch));
      end;
    pekStop:
      if FIndex.TryGetValue(InstanceKey(AEvent.Pid, AEvent.CreateTime), LIndex) then
      begin
        LLaunch := FLaunches[LIndex];
        if LLaunch.LifetimeSeconds < 0 then
        begin
          LLaunch.LifetimeSeconds := Max(0, (AEvent.TimestampUtc - LLaunch.StartUtc) * SecsPerDay);
          FLaunches[LIndex] := LLaunch;
        end;
      end;
  end;
end;

procedure TMHProcessEventCollector.RebuildIndex;
var
  I: Integer;
begin
  FIndex.Clear;
  for I := 0 to FLaunches.Count - 1 do
    FIndex.AddOrSetValue(FLaunches[I].Key, I);
end;

procedure TMHProcessEventCollector.Prune(ANowUtc: TDateTime);
var
  LCutoff: TDateTime;
  LKeep: TList<TMHProcessEventCollector.TLaunch>;
  LLaunch: TMHProcessEventCollector.TLaunch;
  LDrop: Integer;
begin
  LCutoff := ANowUtc - FWindowMinutes / MinsPerDay;
  LDrop := Max(0, FLaunches.Count - MaxTracked);
  if (FLaunches.Count = 0) or ((FLaunches[0].StartUtc >= LCutoff) and (LDrop = 0)) then
    Exit;
  LKeep := TList<TMHProcessEventCollector.TLaunch>.Create;
  try
    for LLaunch in FLaunches do
    begin
      if LDrop > 0 then
      begin
        Dec(LDrop);
        Continue;
      end;
      if LLaunch.StartUtc >= LCutoff then
        LKeep.Add(LLaunch);
    end;
    FLaunches.Clear;
    FLaunches.AddRange(LKeep);
  finally
    LKeep.Free;
  end;
  RebuildIndex;
  // Имена процессов нужны только для родителей недавних запусков.
  if FNames.Count > MaxTracked then
    FNames.Clear;
end;

function TMHProcessEventCollector.BuildStats: TArray<TMHLaunchStat>;
var
  LStats: TDictionary<string, TMHLaunchStat>;
  LLifetimeSum: TDictionary<string, Double>;
  LLaunch: TMHProcessEventCollector.TLaunch;
  LStat: TMHLaunchStat;
  LKey: string;
  LSum: Double;
  LList: TList<TMHLaunchStat>;
begin
  LStats := TDictionary<string, TMHLaunchStat>.Create;
  LLifetimeSum := TDictionary<string, Double>.Create;
  LList := TList<TMHLaunchStat>.Create;
  try
    for LLaunch in FLaunches do
    begin
      LKey := LLaunch.ImagePath.ToLower;
      if not LStats.TryGetValue(LKey, LStat) then
      begin
        LStat := Default(TMHLaunchStat);
        LStat.ImagePath := LLaunch.ImagePath;
        LStat.Name := LLaunch.Name;
        LStat.WindowMinutes := FWindowMinutes;
        LStat.ShortLivedSeconds := FShortLivedSeconds;
        LLifetimeSum.Add(LKey, 0);
      end;
      Inc(LStat.Starts);
      if LLaunch.LifetimeSeconds >= 0 then
      begin
        Inc(LStat.Exited);
        LLifetimeSum[LKey] := LLifetimeSum[LKey] + LLaunch.LifetimeSeconds;
        if LLaunch.LifetimeSeconds < FShortLivedSeconds then
          Inc(LStat.ShortLived);
      end;
      if LLaunch.StartUtc >= LStat.LastStartUtc then
      begin
        LStat.LastStartUtc := LLaunch.StartUtc;
        LStat.LastParentPid := LLaunch.ParentPid;
        LStat.LastParentName := LLaunch.ParentName;
      end;
      LStats.AddOrSetValue(LKey, LStat);
    end;
    for LKey in LStats.Keys do
    begin
      LStat := LStats[LKey];
      // Однократные запуски — обычная жизнь компьютера, в снимок не передаются.
      if LStat.Starts < 2 then
        Continue;
      LSum := LLifetimeSum[LKey];
      if LStat.Exited > 0 then
        LStat.AverageLifetimeSeconds := LSum / LStat.Exited;
      LList.Add(LStat);
    end;
    LList.Sort(TComparer<TMHLaunchStat>.Construct(
      function(const A, B: TMHLaunchStat): Integer
      begin
        Result := CompareValue(B.Starts, A.Starts);
        if Result = 0 then
          Result := CompareText(A.ImagePath, B.ImagePath);
      end));
    while LList.Count > MaxStats do
      LList.Delete(LList.Count - 1);
    Result := LList.ToArray;
  finally
    LList.Free;
    LLifetimeSum.Free;
    LStats.Free;
  end;
end;

function TMHProcessEventCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LEvents: TArray<TMHProcessEvent>;
  LEvent: TMHProcessEvent;
  LInfo: TMHProcessInfo;
  LLost: Integer;
  LMessage: string;
  LState: TMHSourceState;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  EnsureStarted(LNow);
  if not FStarted then
  begin
    if FAccessDenied then
      LMessage := 'Наблюдение за запусками процессов (ETW) доступно при запуске от имени администратора'
    else
      LMessage := 'Наблюдение за запусками процессов недоступно: ' + FError;
    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, ssUnavailable, LMessage, LNow));
    Result.Status.RequiresElevation := FAccessDenied;
    Exit;
  end;

  // Имена уже работающих процессов — для родителей новых запусков.
  for LInfo in ASnapshot.Processes do
    FNames.AddOrSetValue(LInfo.Id.Pid, LInfo.Name);
  LEvents := FSource.Drain(LLost);
  Inc(FLostTotal, Max(0, LLost));
  for LEvent in LEvents do
    Apply(LEvent);
  Prune(LNow);

  LState := ssSuccess;
  LMessage := Format('Запусков за %d мин: %d', [FWindowMinutes, FLaunches.Count]);
  if not FSource.IsRunning then
  begin
    // Сеанс остановлен извне (например, другой программой) — перезапуск при следующем сборе.
    LState := ssPartial;
    LMessage := LMessage + '; сеанс событий остановлен, будет запущен повторно';
    FStarted := False;
    FLastAttemptUtc := 0;
  end
  else if FLostTotal > 0 then
  begin
    LState := ssPartial;
    LMessage := LMessage + Format('; пропущено событий из-за нагрузки: %d', [FLostTotal]);
  end;
  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState, LMessage, LNow));
  Result.Status.ItemCount := FLaunches.Count;
  Result.Launches := BuildStats;
end;

end.
