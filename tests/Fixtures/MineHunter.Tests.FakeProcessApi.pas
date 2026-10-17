unit MineHunter.Tests.FakeProcessApi;

{
  Управляемая имитация IMHProcessApi: синтетические процессы, отказ в доступе,
  завершение процесса во время опроса, переиспользование PID. Никакой
  реальной системной активности.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Collectors.Processes;

type
  TFakeProcess = record
    Entry: TMHRawProcessEntry;
    Details: TMHRawProcessDetails;
  end;

  TFakeProcessApi = class(TInterfacedObject, IMHProcessApi)
  private
    FProcesses: TList<TFakeProcess>;
    FWall: UInt64;
    FCpuCount: Integer;
    FElevated: Boolean;
    FEnumerateFails: Boolean;
    FQueryCalls: Integer;
    function IndexOfPid(APid: Cardinal): Integer;
  public
    constructor Create(ACpuCount: Integer = 4);
    destructor Destroy; override;
    { IMHProcessApi }
    function Enumerate(out AEntries: TArray<TMHRawProcessEntry>; out AError: string): Boolean;
    function Query(APid: Cardinal): TMHRawProcessDetails;
    function NowFileTime: UInt64;
    function LogicalCpuCount: Integer;
    function IsElevated: Boolean;
    function PrivateWorkingSets: TArray<TMHPidBytes>;
    { Управление сценарием }
    /// Полностью доступный процесс; путь = C:\Fake\<name>.
    procedure Add(APid, AParentPid: Cardinal; const AName: string; ACreateTime: UInt64;
      ACpu100ns: UInt64 = 0; AWorkingSet: UInt64 = 1048576);
    procedure AddDenied(APid, AParentPid: Cardinal; const AName: string);
    /// Процесс есть в перечне, но к моменту открытия уже завершился.
    procedure AddGone(APid: Cardinal; const AName: string);
    procedure SetCpu(APid: Cardinal; ACpu100ns: UInt64);
    procedure SetDetails(APid: Cardinal; const ADetails: TMHRawProcessDetails);
    function GetDetails(APid: Cardinal): TMHRawProcessDetails;
    procedure Remove(APid: Cardinal);
    procedure AdvanceWall(A100ns: UInt64);
    property Elevated: Boolean read FElevated write FElevated;
    property EnumerateFails: Boolean read FEnumerateFails write FEnumerateFails;
    property QueryCalls: Integer read FQueryCalls;
  public
    /// Значения частного рабочего набора, которые вернёт PrivateWorkingSets.
    PrivateSets: TArray<TMHPidBytes>;
  end;

const
  FAKE_SECOND: UInt64 = 10000000; // 1 с в 100-нс интервалах (UInt64: без переполнения в выражениях)
  FAKE_BASE_TIME: UInt64 = 133000000000000000; // ~2022 г. в формате FILETIME

implementation

constructor TFakeProcessApi.Create(ACpuCount: Integer);
begin
  inherited Create;
  FProcesses := TList<TFakeProcess>.Create;
  FCpuCount := ACpuCount;
  FWall := FAKE_BASE_TIME + 1000 * FAKE_SECOND;
end;

destructor TFakeProcessApi.Destroy;
begin
  FProcesses.Free;
  inherited;
end;

function TFakeProcessApi.IndexOfPid(APid: Cardinal): Integer;
var
  I: Integer;
begin
  for I := 0 to FProcesses.Count - 1 do
    if FProcesses[I].Entry.Pid = APid then
      Exit(I);
  Result := -1;
end;

function TFakeProcessApi.Enumerate(out AEntries: TArray<TMHRawProcessEntry>;
  out AError: string): Boolean;
var
  I: Integer;
begin
  AError := '';
  AEntries := nil;
  if FEnumerateFails then
  begin
    AError := 'simulated enumeration failure';
    Exit(False);
  end;
  SetLength(AEntries, FProcesses.Count);
  for I := 0 to FProcesses.Count - 1 do
    AEntries[I] := FProcesses[I].Entry;
  Result := True;
end;

function TFakeProcessApi.Query(APid: Cardinal): TMHRawProcessDetails;
var
  LIndex: Integer;
begin
  Inc(FQueryCalls);
  LIndex := IndexOfPid(APid);
  if LIndex < 0 then
  begin
    Result := Default(TMHRawProcessDetails);
    Result.Status := pqGone;
  end
  else
    Result := FProcesses[LIndex].Details;
end;

function TFakeProcessApi.NowFileTime: UInt64;
begin
  Result := FWall;
end;

function TFakeProcessApi.LogicalCpuCount: Integer;
begin
  Result := FCpuCount;
end;

function TFakeProcessApi.IsElevated: Boolean;
begin
  Result := FElevated;
end;

function TFakeProcessApi.PrivateWorkingSets: TArray<TMHPidBytes>;
begin
  Result := PrivateSets;
end;

procedure TFakeProcessApi.Add(APid, AParentPid: Cardinal; const AName: string;
  ACreateTime, ACpu100ns, AWorkingSet: UInt64);
var
  LProcess: TFakeProcess;
begin
  Remove(APid);
  LProcess.Entry.Pid := APid;
  LProcess.Entry.ParentPid := AParentPid;
  LProcess.Entry.ExeName := AName;
  LProcess.Entry.ThreadCount := 3;
  LProcess.Details := Default(TMHRawProcessDetails);
  LProcess.Details.Status := pqOk;
  LProcess.Details.HasTimes := True;
  LProcess.Details.CreateTime := ACreateTime;
  LProcess.Details.CpuTime100ns := ACpu100ns;
  LProcess.Details.ImagePath := 'C:\Fake\' + AName;
  LProcess.Details.HasMemory := True;
  LProcess.Details.WorkingSetBytes := AWorkingSet;
  LProcess.Details.PrivateBytes := AWorkingSet div 2;
  FProcesses.Add(LProcess);
end;

procedure TFakeProcessApi.AddDenied(APid, AParentPid: Cardinal; const AName: string);
var
  LProcess: TFakeProcess;
begin
  Remove(APid);
  LProcess.Entry.Pid := APid;
  LProcess.Entry.ParentPid := AParentPid;
  LProcess.Entry.ExeName := AName;
  LProcess.Entry.ThreadCount := 10;
  LProcess.Details := Default(TMHRawProcessDetails);
  LProcess.Details.Status := pqAccessDenied;
  FProcesses.Add(LProcess);
end;

procedure TFakeProcessApi.AddGone(APid: Cardinal; const AName: string);
var
  LProcess: TFakeProcess;
begin
  Remove(APid);
  LProcess.Entry.Pid := APid;
  LProcess.Entry.ParentPid := 0;
  LProcess.Entry.ExeName := AName;
  LProcess.Entry.ThreadCount := 1;
  LProcess.Details := Default(TMHRawProcessDetails);
  LProcess.Details.Status := pqGone;
  FProcesses.Add(LProcess);
end;

procedure TFakeProcessApi.SetCpu(APid: Cardinal; ACpu100ns: UInt64);
var
  LIndex: Integer;
  LProcess: TFakeProcess;
begin
  LIndex := IndexOfPid(APid);
  if LIndex < 0 then
    raise EArgumentException.CreateFmt('PID %d не найден', [APid]);
  LProcess := FProcesses[LIndex];
  LProcess.Details.CpuTime100ns := ACpu100ns;
  FProcesses[LIndex] := LProcess;
end;

procedure TFakeProcessApi.SetDetails(APid: Cardinal; const ADetails: TMHRawProcessDetails);
var
  LIndex: Integer;
  LProcess: TFakeProcess;
begin
  LIndex := IndexOfPid(APid);
  if LIndex < 0 then
    raise EArgumentException.CreateFmt('PID %d не найден', [APid]);
  LProcess := FProcesses[LIndex];
  LProcess.Details := ADetails;
  FProcesses[LIndex] := LProcess;
end;

function TFakeProcessApi.GetDetails(APid: Cardinal): TMHRawProcessDetails;
var
  LIndex: Integer;
begin
  LIndex := IndexOfPid(APid);
  if LIndex < 0 then
    raise EArgumentException.CreateFmt('PID %d не найден', [APid]);
  Result := FProcesses[LIndex].Details;
end;

procedure TFakeProcessApi.Remove(APid: Cardinal);
var
  LIndex: Integer;
begin
  LIndex := IndexOfPid(APid);
  if LIndex >= 0 then
    FProcesses.Delete(LIndex);
end;

procedure TFakeProcessApi.AdvanceWall(A100ns: UInt64);
begin
  Inc(FWall, A100ns);
end;

end.
