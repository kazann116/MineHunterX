unit MineHunter.Tests.Logging;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Unit')]
  TMemoryLoggerTests = class
  public
    [Test] procedure Empty_HasNoEntriesAndZeroVersion;
    [Test] procedure Log_AddsEntryAndBumpsVersion;
    [Test] procedure BelowMinLevel_IsIgnored;
    [Test] procedure Overflow_KeepsNewestInOrder;
    [Test] procedure InvalidArguments_Raise;
    [Test] procedure ConcurrentWriters_LoseNothingWithinCapacity;
    [Test] procedure SystemClock_IsCloseToNow;
  end;

implementation

uses
  System.SysUtils, System.Classes, System.DateUtils,
  MineHunter.Core.Interfaces, MineHunter.Core.Logging, MineHunter.Tests.Fakes;

procedure TMemoryLoggerTests.Empty_HasNoEntriesAndZeroVersion;
var
  LLogger: TMHMemoryLogger;
  LReader: IMHLogReader;
begin
  LLogger := TMHMemoryLogger.Create(TFakeClock.Create(FAKE_NOW), 3);
  LReader := LLogger;
  Assert.AreEqual<UInt64>(0, LReader.Version);
  Assert.AreEqual(0, Integer(Length(LReader.Entries)));
end;

procedure TMemoryLoggerTests.Log_AddsEntryAndBumpsVersion;
var
  LLogger: IMHLogger;
  LReader: IMHLogReader;
  LEntries: TArray<TMHLogEntry>;
begin
  LLogger := TMHMemoryLogger.Create(TFakeClock.Create(FAKE_NOW), 3);
  Supports(LLogger, IMHLogReader, LReader);
  LLogger.Log(llWarning, 'src', 'msg');
  LEntries := LReader.Entries;
  Assert.AreEqual<UInt64>(1, LReader.Version);
  Assert.AreEqual(1, Integer(Length(LEntries)));
  Assert.AreEqual('src', LEntries[0].Source);
  Assert.AreEqual('msg', LEntries[0].Message);
  Assert.AreEqual<TMHLogLevel>(llWarning, LEntries[0].Level);
  Assert.AreEqual(FAKE_NOW, LEntries[0].TimestampUtc, 1e-9);
end;

procedure TMemoryLoggerTests.BelowMinLevel_IsIgnored;
var
  LLogger: TMHMemoryLogger;
  LReader: IMHLogReader;
begin
  LLogger := TMHMemoryLogger.Create(TFakeClock.Create(FAKE_NOW), 3, llWarning);
  LReader := LLogger;
  LLogger.Log(llDebug, 's', 'd');
  LLogger.Log(llInfo, 's', 'i');
  Assert.AreEqual(0, Integer(Length(LReader.Entries)));
  Assert.AreEqual<UInt64>(0, LReader.Version);
end;

procedure TMemoryLoggerTests.Overflow_KeepsNewestInOrder;
var
  LLogger: TMHMemoryLogger;
  LReader: IMHLogReader;
  LEntries: TArray<TMHLogEntry>;
  I: Integer;
begin
  LLogger := TMHMemoryLogger.Create(TFakeClock.Create(FAKE_NOW), 3);
  LReader := LLogger;
  for I := 1 to 7 do
    LLogger.Log(llInfo, 's', IntToStr(I));
  LEntries := LReader.Entries;
  Assert.AreEqual(3, Integer(Length(LEntries)));
  Assert.AreEqual('5', LEntries[0].Message);
  Assert.AreEqual('6', LEntries[1].Message);
  Assert.AreEqual('7', LEntries[2].Message);
  Assert.AreEqual<UInt64>(7, LReader.Version);
end;

procedure TMemoryLoggerTests.InvalidArguments_Raise;
var
  LClock: IMHClock;
begin
  // Часы — в интерфейсной переменной: если конструктор упадёт до сохранения
  // ссылки, объект, переданный напрямую в const-параметр, не был бы освобождён.
  LClock := TMHSystemClock.Create;
  Assert.WillRaise(
    procedure
    begin
      TMHMemoryLogger.Create(nil).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHMemoryLogger.Create(LClock, 0).Free;
    end, EArgumentOutOfRangeException);
end;

procedure TMemoryLoggerTests.ConcurrentWriters_LoseNothingWithinCapacity;
const
  THREADS = 8;
  PER_THREAD = 500;
var
  LLogger: TMHMemoryLogger;
  LIntf: IMHLogger;
  LReader: IMHLogReader;
  LThreads: array[0..THREADS - 1] of TThread;
  I: Integer;
begin
  LLogger := TMHMemoryLogger.Create(TMHSystemClock.Create, THREADS * PER_THREAD);
  LIntf := LLogger;
  LReader := LLogger;
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      var
        J: Integer;
      begin
        for J := 1 to PER_THREAD do
          LIntf.Log(llInfo, 't', 'x');
      end);
    LThreads[I].FreeOnTerminate := False;
    LThreads[I].Start;
  end;
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;
  Assert.AreEqual(THREADS * PER_THREAD, Integer(Length(LReader.Entries)));
  Assert.AreEqual<UInt64>(THREADS * PER_THREAD, LReader.Version);
end;

procedure TMemoryLoggerTests.SystemClock_IsCloseToNow;
var
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  Assert.IsTrue(Abs(SecondsBetween(LClock.NowUtc, TTimeZone.Local.ToUniversalTime(Now))) <= 2);
  Assert.IsTrue(LClock.TickMs > 0);
end;

initialization
  TDUnitX.RegisterTestFixture(TMemoryLoggerTests);

end.
