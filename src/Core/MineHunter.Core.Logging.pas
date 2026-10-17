unit MineHunter.Core.Logging;

{
  Стандартные реализации IMHClock и IMHLogger.
}

interface

uses
  System.SysUtils, System.SyncObjs,
  MineHunter.Core.Interfaces;

type
  TMHSystemClock = class(TInterfacedObject, IMHClock)
  public
    function NowUtc: TDateTime;
    function TickMs: UInt64;
  end;

  /// Журнал, отбрасывающий все записи.
  TMHNullLogger = class(TInterfacedObject, IMHLogger)
  public
    procedure Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
  end;

  /// Потокобезопасный кольцевой буфер последних записей журнала.
  TMHMemoryLogger = class(TInterfacedObject, IMHLogger, IMHLogReader)
  public const
    DefaultCapacity = 500;
  private
    FLock: TCriticalSection;
    FClock: IMHClock;
    FBuffer: TArray<TMHLogEntry>;
    FStart: Integer;
    FCount: Integer;
    FVersion: UInt64;
    FMinLevel: TMHLogLevel;
  public
    constructor Create(const AClock: IMHClock; ACapacity: Integer = DefaultCapacity;
      AMinLevel: TMHLogLevel = llInfo);
    destructor Destroy; override;
    procedure Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
    function Version: UInt64;
    /// Записи в хронологическом порядке (старые первыми).
    function Entries: TArray<TMHLogEntry>;
    function Capacity: Integer;
  end;

implementation

uses
  Winapi.Windows;

{ TMHSystemClock }

function TMHSystemClock.NowUtc: TDateTime;
var
  LTime: TSystemTime;
begin
  GetSystemTime(LTime);
  Result := SystemTimeToDateTime(LTime);
end;

function TMHSystemClock.TickMs: UInt64;
begin
  Result := GetTickCount64;
end;

{ TMHNullLogger }

procedure TMHNullLogger.Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
begin
  // Намеренно ничего не делает.
end;

{ TMHMemoryLogger }

constructor TMHMemoryLogger.Create(const AClock: IMHClock; ACapacity: Integer;
  AMinLevel: TMHLogLevel);
begin
  inherited Create;
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if ACapacity <= 0 then
    raise EArgumentOutOfRangeException.Create('ACapacity должен быть больше нуля');
  FClock := AClock;
  FLock := TCriticalSection.Create;
  SetLength(FBuffer, ACapacity);
  FMinLevel := AMinLevel;
end;

destructor TMHMemoryLogger.Destroy;
begin
  FLock.Free;
  inherited;
end;

function TMHMemoryLogger.Capacity: Integer;
begin
  Result := Length(FBuffer);
end;

procedure TMHMemoryLogger.Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
var
  LEntry: TMHLogEntry;
  LIndex: Integer;
begin
  if ALevel < FMinLevel then
    Exit;
  LEntry.TimestampUtc := FClock.NowUtc;
  LEntry.Level := ALevel;
  LEntry.Source := ASource;
  LEntry.Message := AMessage;
  FLock.Enter;
  try
    if FCount < Length(FBuffer) then
    begin
      LIndex := (FStart + FCount) mod Length(FBuffer);
      Inc(FCount);
    end
    else
    begin
      // Буфер заполнен — перезаписываем самую старую запись.
      LIndex := FStart;
      FStart := (FStart + 1) mod Length(FBuffer);
    end;
    FBuffer[LIndex] := LEntry;
    Inc(FVersion);
  finally
    FLock.Leave;
  end;
end;

function TMHMemoryLogger.Version: UInt64;
begin
  FLock.Enter;
  try
    Result := FVersion;
  finally
    FLock.Leave;
  end;
end;

function TMHMemoryLogger.Entries: TArray<TMHLogEntry>;
var
  I: Integer;
begin
  FLock.Enter;
  try
    SetLength(Result, FCount);
    for I := 0 to FCount - 1 do
      Result[I] := FBuffer[(FStart + I) mod Length(FBuffer)];
  finally
    FLock.Leave;
  end;
end;

end.
