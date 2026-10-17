unit MineHunter.Collectors.ProcessEvents.WinApi;

{
  Источник событий запуска/завершения процессов на ETW.

  - Сеанс реального времени «MineHunterX-ProcessEvents» (StartTraceW), в нём
    включается провайдер Microsoft-Windows-Kernel-Process
    (GUID 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716) с ключевым словом
    WINEVENT_KEYWORD_PROCESS (0x10): событие 1 — запуск, 2 — завершение.
  - Потребитель (OpenTraceW + ProcessTrace) работает в отдельном потоке;
    обратный вызов только складывает события в очередь под блокировкой
    (не более MAX_QUEUE — при переполнении события считаются потерянными).
  - Поля событий читаются через TDH (TdhGetProperty по имени свойства), а не
    по смещениям: состав полей меняется между версиями Windows.
  - Пути ядра (\Device\HarddiskVolume3\...) переводятся в C:\... по таблице
    QueryDosDevice.
  - Сеанс с тем же именем, оставшийся после аварийного завершения, сначала
    останавливается. Stop останавливает сеанс и дожидается потока.
  - Права: нужен администратор (или группа Performance Log Users); иначе
    StartTraceW возвращает ERROR_ACCESS_DENIED.
  Структуры объявлены по evntrace.h, evntcons.h и tdh.h (Windows SDK);
  их размеры для x64 проверяются тестом.
}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.SyncObjs, System.Generics.Collections,
  MineHunter.Collectors.ProcessEvents;

type
  TRACEHANDLE = UInt64;

  TWnodeHeader = record
    BufferSize: ULONG;
    ProviderId: ULONG;
    HistoricalContext: UInt64;
    TimeStamp: Int64;
    Guid: TGUID;
    ClientContext: ULONG;
    Flags: ULONG;
  end;

  TEventTraceProperties = record
    Wnode: TWnodeHeader;
    BufferSize: ULONG;
    MinimumBuffers: ULONG;
    MaximumBuffers: ULONG;
    MaximumFileSize: ULONG;
    LogFileMode: ULONG;
    FlushTimer: ULONG;
    EnableFlags: ULONG;
    AgeLimit: Integer;
    NumberOfBuffers: ULONG;
    FreeBuffers: ULONG;
    EventsLost: ULONG;
    BuffersWritten: ULONG;
    LogBuffersLost: ULONG;
    RealTimeBuffersLost: ULONG;
    LoggerThreadId: THandle;
    LogFileNameOffset: ULONG;
    LoggerNameOffset: ULONG;
  end;
  PEventTraceProperties = ^TEventTraceProperties;

  TEventTraceHeader = record
    Size: Word;
    FieldTypeFlags: Word;
    Version: ULONG;
    ThreadId: ULONG;
    ProcessId: ULONG;
    TimeStamp: Int64;
    Guid: TGUID;
    ProcessorTime: UInt64;
  end;

  TEventTrace = record
    Header: TEventTraceHeader;
    InstanceId: ULONG;
    ParentInstanceId: ULONG;
    ParentGuid: TGUID;
    MofData: Pointer;
    MofLength: ULONG;
    ClientContext: ULONG;
  end;

  TTraceLogfileHeader = record
    BufferSize: ULONG;
    Version: ULONG;
    ProviderVersion: ULONG;
    NumberOfProcessors: ULONG;
    EndTime: Int64;
    TimerResolution: ULONG;
    MaximumFileSize: ULONG;
    LogFileMode: ULONG;
    BuffersWritten: ULONG;
    LogInstanceGuid: TGUID;
    LoggerName: PWideChar;
    LogFileName: PWideChar;
    TimeZone: TTimeZoneInformation;
    BootTime: Int64;
    PerfFreq: Int64;
    StartTime: Int64;
    ReservedFlags: ULONG;
    BuffersLost: ULONG;
  end;

  TEventDescriptor = record
    Id: Word;
    Version: Byte;
    Channel: Byte;
    Level: Byte;
    Opcode: Byte;
    Task: Word;
    Keyword: UInt64;
  end;

  TEventHeader = record
    Size: Word;
    HeaderType: Word;
    Flags: Word;
    EventProperty: Word;
    ThreadId: ULONG;
    ProcessId: ULONG;
    TimeStamp: Int64;
    ProviderId: TGUID;
    EventDescriptor: TEventDescriptor;
    ProcessorTime: UInt64;
    ActivityId: TGUID;
  end;

  TEtwBufferContext = record
    ProcessorIndex: Word;
    LoggerId: Word;
  end;

  TEventRecord = record
    EventHeader: TEventHeader;
    BufferContext: TEtwBufferContext;
    ExtendedDataCount: Word;
    UserDataLength: Word;
    ExtendedData: Pointer;
    UserData: Pointer;
    UserContext: Pointer;
  end;
  PEventRecord = ^TEventRecord;

  TEventRecordCallback = procedure(AEvent: PEventRecord); stdcall;

  TEventTraceLogfileW = record
    LogFileName: PWideChar;
    LoggerName: PWideChar;
    CurrentTime: Int64;
    BuffersRead: ULONG;
    ProcessTraceMode: ULONG;
    CurrentEvent: TEventTrace;
    LogfileHeader: TTraceLogfileHeader;
    BufferCallback: Pointer;
    BufferSize: ULONG;
    Filled: ULONG;
    EventsLost: ULONG;
    EventRecordCallback: TEventRecordCallback;
    IsKernelTrace: ULONG;
    Context: Pointer;
  end;

  TPropertyDataDescriptor = record
    PropertyName: UInt64;
    ArrayIndex: ULONG;
    Reserved: ULONG;
  end;

  TMHEtwProcessSource = class(TInterfacedObject, IMHProcessEventSource)
  public const
    SessionName = 'MineHunterX-ProcessEvents';
    MAX_QUEUE = 20000;
  private
    FLock: TCriticalSection;
    FQueue: TList<TMHProcessEvent>;
    FLost: Integer;
    FSession: TRACEHANDLE;
    FConsumer: TRACEHANDLE;
    FThread: TThread;
    FRunning: Boolean;
    FProps: TBytes;
    FDevices: TArray<TPair<string, string>>;
    procedure BuildDeviceMap;
    function ToDosPath(const APath: string): string;
    procedure Enqueue(const AEvent: TMHProcessEvent);
    procedure HandleEvent(AEvent: PEventRecord);
    function NewProperties: PEventTraceProperties;
    procedure StopSession;
  public
    constructor Create;
    destructor Destroy; override;
    function Start(out AError: string; out AAccessDenied: Boolean): Boolean;
    procedure Stop;
    function Drain(out ALost: Integer): TArray<TMHProcessEvent>;
    function IsRunning: Boolean;
  end;

implementation

uses
  System.DateUtils;

const
  KERNEL_PROCESS_PROVIDER: TGUID = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}';
  WINEVENT_KEYWORD_PROCESS = $10;
  TRACE_LEVEL_INFORMATION = 4;
  EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
  EVENT_TRACE_CONTROL_STOP = 1;
  EVENT_TRACE_REAL_TIME_MODE = $00000100;
  WNODE_FLAG_TRACED_GUID = $00020000;
  PROCESS_TRACE_MODE_REAL_TIME = $00000100;
  PROCESS_TRACE_MODE_EVENT_RECORD = $10000000;
  INVALID_PROCESSTRACE_HANDLE = TRACEHANDLE(-1);
  EVENT_ID_PROCESS_START = 1;
  EVENT_ID_PROCESS_STOP = 2;

function StartTraceW(var ATraceHandle: TRACEHANDLE; AInstanceName: PWideChar;
  AProperties: PEventTraceProperties): ULONG; stdcall; external advapi32 name 'StartTraceW';
function ControlTraceW(ATraceHandle: TRACEHANDLE; AInstanceName: PWideChar;
  AProperties: PEventTraceProperties; AControlCode: ULONG): ULONG; stdcall; external advapi32 name 'ControlTraceW';
function EnableTraceEx2(ATraceHandle: TRACEHANDLE; const AProviderId: TGUID; AControlCode: ULONG;
  ALevel: Byte; AMatchAnyKeyword, AMatchAllKeyword: UInt64; ATimeout: ULONG;
  AEnableParameters: Pointer): ULONG; stdcall; external advapi32 name 'EnableTraceEx2';
function OpenTraceW(var ALogfile: TEventTraceLogfileW): TRACEHANDLE; stdcall; external advapi32 name 'OpenTraceW';
function ProcessTrace(AHandleArray: PUInt64; AHandleCount: ULONG; AStartTime, AEndTime: PFileTime): ULONG;
  stdcall; external advapi32 name 'ProcessTrace';
function CloseTrace(ATraceHandle: TRACEHANDLE): ULONG; stdcall; external advapi32 name 'CloseTrace';
function TdhGetPropertySize(AEvent: PEventRecord; ATdhContextCount: ULONG; ATdhContext: Pointer;
  APropertyDataCount: ULONG; var APropertyData: TPropertyDataDescriptor; out APropertySize: ULONG): ULONG;
  stdcall; external 'tdh.dll' name 'TdhGetPropertySize';
function TdhGetProperty(AEvent: PEventRecord; ATdhContextCount: ULONG; ATdhContext: Pointer;
  APropertyDataCount: ULONG; var APropertyData: TPropertyDataDescriptor; ABufferSize: ULONG;
  ABuffer: PByte): ULONG; stdcall; external 'tdh.dll' name 'TdhGetProperty';

function ReadProperty(AEvent: PEventRecord; const AName: string; out ABytes: TBytes): Boolean;
var
  LDescriptor: TPropertyDataDescriptor;
  LSize: ULONG;
begin
  ABytes := nil;
  LDescriptor := Default(TPropertyDataDescriptor);
  LDescriptor.PropertyName := UInt64(PWideChar(AName));
  LDescriptor.ArrayIndex := ULONG(-1);
  if (TdhGetPropertySize(AEvent, 0, nil, 1, LDescriptor, LSize) <> ERROR_SUCCESS) or (LSize = 0) or
     (LSize > 64 * 1024) then
    Exit(False);
  SetLength(ABytes, LSize);
  Result := TdhGetProperty(AEvent, 0, nil, 1, LDescriptor, LSize, @ABytes[0]) = ERROR_SUCCESS;
end;

function ReadUInt32(AEvent: PEventRecord; const AName: string; out AValue: Cardinal): Boolean;
var
  LBytes: TBytes;
begin
  Result := ReadProperty(AEvent, AName, LBytes) and (Length(LBytes) >= 4);
  if Result then
    Move(LBytes[0], AValue, 4)
  else
    AValue := 0;
end;

function ReadUInt64(AEvent: PEventRecord; const AName: string; out AValue: UInt64): Boolean;
var
  LBytes: TBytes;
begin
  Result := ReadProperty(AEvent, AName, LBytes) and (Length(LBytes) >= 8);
  if Result then
    Move(LBytes[0], AValue, 8)
  else
    AValue := 0;
end;

function ReadUnicode(AEvent: PEventRecord; const AName: string; out AValue: string): Boolean;
var
  LBytes: TBytes;
  LChars: Integer;
begin
  AValue := '';
  Result := ReadProperty(AEvent, AName, LBytes) and (Length(LBytes) >= 2);
  if not Result then
    Exit;
  LChars := Length(LBytes) div 2;
  SetString(AValue, PWideChar(@LBytes[0]), LChars);
  AValue := Trim(string(PWideChar(AValue)));
end;

function FileTimeToUtc(AValue: Int64): TDateTime;
begin
  // FILETIME: сотни наносекунд с 1601-01-01 UTC.
  Result := EncodeDate(1601, 1, 1) + AValue / (10000000.0 * SecsPerDay);
end;

procedure EventRecordCallback(AEvent: PEventRecord); stdcall;
begin
  if (AEvent <> nil) and (AEvent.UserContext <> nil) then
    try
      TMHEtwProcessSource(AEvent.UserContext).HandleEvent(AEvent);
    except
      // Исключение не должно выйти в код ETW.
    end;
end;

{ TMHEtwProcessSource }

constructor TMHEtwProcessSource.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FQueue := TList<TMHProcessEvent>.Create;
  FConsumer := INVALID_PROCESSTRACE_HANDLE;
end;

destructor TMHEtwProcessSource.Destroy;
begin
  Stop;
  FQueue.Free;
  FLock.Free;
  inherited;
end;

function TMHEtwProcessSource.NewProperties: PEventTraceProperties;
var
  LSize: Integer;
begin
  LSize := SizeOf(TEventTraceProperties) + (Length(SessionName) + 1) * SizeOf(WideChar) + 1024;
  SetLength(FProps, LSize);
  FillChar(FProps[0], LSize, 0);
  Result := PEventTraceProperties(@FProps[0]);
  Result.Wnode.BufferSize := LSize;
  Result.Wnode.Flags := WNODE_FLAG_TRACED_GUID;
  Result.Wnode.ClientContext := 1; // QueryPerformanceCounter
  Result.LogFileMode := EVENT_TRACE_REAL_TIME_MODE;
  Result.BufferSize := 64;         // КБ
  Result.MinimumBuffers := 4;
  Result.MaximumBuffers := 16;
  Result.FlushTimer := 1;          // с
  Result.LoggerNameOffset := SizeOf(TEventTraceProperties);
end;

procedure TMHEtwProcessSource.BuildDeviceMap;
var
  LDrive: Char;
  LBuffer: array[0..1023] of Char;
  LList: TList<TPair<string, string>>;
begin
  LList := TList<TPair<string, string>>.Create;
  try
    for LDrive := 'A' to 'Z' do
      if QueryDosDevice(PChar(LDrive + ':'), LBuffer, Length(LBuffer)) > 0 then
        LList.Add(TPair<string, string>.Create(string(PChar(@LBuffer[0])), LDrive + ':'));
    FDevices := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TMHEtwProcessSource.ToDosPath(const APath: string): string;
var
  LPair: TPair<string, string>;
begin
  Result := APath;
  if Result.StartsWith('\??\') then
    Exit(Copy(Result, 5, MaxInt));
  for LPair in FDevices do
    if Result.StartsWith(LPair.Key + '\', True) then
      Exit(LPair.Value + Copy(Result, Length(LPair.Key) + 1, MaxInt));
end;

procedure TMHEtwProcessSource.Enqueue(const AEvent: TMHProcessEvent);
begin
  FLock.Enter;
  try
    if FQueue.Count >= MAX_QUEUE then
      Inc(FLost)
    else
      FQueue.Add(AEvent);
  finally
    FLock.Leave;
  end;
end;

procedure TMHEtwProcessSource.HandleEvent(AEvent: PEventRecord);
var
  LEvent: TMHProcessEvent;
  LCreate: UInt64;
  LImage: string;
begin
  if AEvent.EventHeader.ProviderId <> KERNEL_PROCESS_PROVIDER then
    Exit;
  LEvent := Default(TMHProcessEvent);
  case AEvent.EventHeader.EventDescriptor.Id of
    EVENT_ID_PROCESS_START:
      begin
        LEvent.Kind := pekStart;
        if not ReadUInt32(AEvent, 'ProcessID', LEvent.Pid) then
          Exit;
        ReadUInt32(AEvent, 'ParentProcessID', LEvent.ParentPid);
        if ReadUnicode(AEvent, 'ImageName', LImage) then
          LEvent.ImagePath := ToDosPath(LImage);
      end;
    EVENT_ID_PROCESS_STOP:
      begin
        LEvent.Kind := pekStop;
        if not ReadUInt32(AEvent, 'ProcessID', LEvent.Pid) then
          Exit;
      end;
  else
    Exit;
  end;
  if ReadUInt64(AEvent, 'CreateTime', LCreate) then
    LEvent.CreateTime := LCreate;
  // ProcessTrace по умолчанию переводит метки времени в системное время (FILETIME UTC);
  // сырые значения QPC пришли бы только с PROCESS_TRACE_MODE_RAW_TIMESTAMP.
  LEvent.TimestampUtc := FileTimeToUtc(AEvent.EventHeader.TimeStamp);
  Enqueue(LEvent);
end;

function TMHEtwProcessSource.Start(out AError: string; out AAccessDenied: Boolean): Boolean;
var
  LStatus: ULONG;
  LLogfile: TEventTraceLogfileW;
  LSelf: TMHEtwProcessSource;
begin
  AError := '';
  AAccessDenied := False;
  if FRunning then
    Exit(True);
  Stop;
  BuildDeviceMap;

  LStatus := StartTraceW(FSession, SessionName, NewProperties);
  if LStatus = ERROR_ALREADY_EXISTS then
  begin
    // Сеанс остался от предыдущего запуска (аварийное завершение) — останавливаем и создаём заново.
    ControlTraceW(0, SessionName, NewProperties, EVENT_TRACE_CONTROL_STOP);
    LStatus := StartTraceW(FSession, SessionName, NewProperties);
  end;
  if LStatus <> ERROR_SUCCESS then
  begin
    FSession := 0;
    AAccessDenied := LStatus = ERROR_ACCESS_DENIED;
    AError := SysErrorMessage(LStatus);
    Exit(False);
  end;

  LStatus := EnableTraceEx2(FSession, KERNEL_PROCESS_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_INFORMATION, WINEVENT_KEYWORD_PROCESS, 0, 0, nil);
  if LStatus <> ERROR_SUCCESS then
  begin
    AAccessDenied := LStatus = ERROR_ACCESS_DENIED;
    AError := 'провайдер событий процессов не включён: ' + SysErrorMessage(LStatus);
    StopSession;
    Exit(False);
  end;

  LLogfile := Default(TEventTraceLogfileW);
  LLogfile.LoggerName := SessionName;
  LLogfile.ProcessTraceMode := PROCESS_TRACE_MODE_REAL_TIME or PROCESS_TRACE_MODE_EVENT_RECORD;
  LLogfile.EventRecordCallback := EventRecordCallback;
  LLogfile.Context := Self;
  FConsumer := OpenTraceW(LLogfile);
  if FConsumer = INVALID_PROCESSTRACE_HANDLE then
  begin
    AError := 'не удалось подключиться к сеансу событий: ' + SysErrorMessage(GetLastError);
    StopSession;
    Exit(False);
  end;

  FRunning := True;
  LSelf := Self;
  FThread := TThread.CreateAnonymousThread(
    procedure
    var
      LHandle: TRACEHANDLE;
    begin
      LHandle := LSelf.FConsumer;
      // Блокируется до остановки сеанса или CloseTrace.
      ProcessTrace(@LHandle, 1, nil, nil);
      LSelf.FRunning := False;
    end);
  FThread.FreeOnTerminate := False;
  FThread.Start;
  Result := True;
end;

procedure TMHEtwProcessSource.StopSession;
begin
  if FSession <> 0 then
  begin
    ControlTraceW(FSession, nil, NewProperties, EVENT_TRACE_CONTROL_STOP);
    FSession := 0;
  end;
end;

procedure TMHEtwProcessSource.Stop;
begin
  StopSession;
  if FConsumer <> INVALID_PROCESSTRACE_HANDLE then
  begin
    CloseTrace(FConsumer);
    FConsumer := INVALID_PROCESSTRACE_HANDLE;
  end;
  if FThread <> nil then
  begin
    FThread.WaitFor;
    FreeAndNil(FThread);
  end;
  FRunning := False;
end;

function TMHEtwProcessSource.Drain(out ALost: Integer): TArray<TMHProcessEvent>;
begin
  FLock.Enter;
  try
    Result := FQueue.ToArray;
    FQueue.Clear;
    ALost := FLost;
    FLost := 0;
  finally
    FLock.Leave;
  end;
end;

function TMHEtwProcessSource.IsRunning: Boolean;
begin
  Result := FRunning;
end;

end.
