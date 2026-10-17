unit MineHunter.Tests.Calc;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Unit')]
  TCpuCalcTests = class
  public
    [Test] procedure OneCoreFullyBusy_OnSingleCpu_Is100;
    [Test] procedure OneCoreFullyBusy_OnEightCpus_Is12_5;
    [Test] procedure Idle_IsZero;
    [Test] procedure ZeroWallInterval_IsNotCalculable;
    [Test] procedure ZeroOrNegativeCpuCount_IsNotCalculable;
    [Test] procedure TimerJitterAbove100_IsClampedTo100;
    [Test] procedure CounterDelta_Normal;
    [Test] procedure CounterDelta_Decreasing_IsRejected;
    [Test] procedure FileTime_Combine;
    [Test] procedure SystemCpu_ReferenceValues;
    [Test] procedure SystemCpu_InvalidInput;
    [Test] procedure Rate_ReferenceValues;
  end;

implementation

uses
  MineHunter.Core.Calc;

const
  SEC_100NS = 10000000; // 1 секунда в 100-нс интервалах

procedure TCpuCalcTests.OneCoreFullyBusy_OnSingleCpu_Is100;
var
  LPercent: Double;
begin
  Assert.IsTrue(MHTryCalcCpuPercent(SEC_100NS, SEC_100NS, 1, LPercent));
  Assert.AreEqual(100.0, LPercent, 0.0001);
end;

procedure TCpuCalcTests.OneCoreFullyBusy_OnEightCpus_Is12_5;
var
  LPercent: Double;
begin
  Assert.IsTrue(MHTryCalcCpuPercent(2 * SEC_100NS, 2 * SEC_100NS, 8, LPercent));
  Assert.AreEqual(12.5, LPercent, 0.0001);
end;

procedure TCpuCalcTests.Idle_IsZero;
var
  LPercent: Double;
begin
  Assert.IsTrue(MHTryCalcCpuPercent(0, SEC_100NS, 4, LPercent));
  Assert.AreEqual(0.0, LPercent, 0.0001);
end;

procedure TCpuCalcTests.ZeroWallInterval_IsNotCalculable;
var
  LPercent: Double;
begin
  Assert.IsFalse(MHTryCalcCpuPercent(SEC_100NS, 0, 4, LPercent));
  Assert.AreEqual(0.0, LPercent, 0.0001);
end;

procedure TCpuCalcTests.ZeroOrNegativeCpuCount_IsNotCalculable;
var
  LPercent: Double;
begin
  Assert.IsFalse(MHTryCalcCpuPercent(SEC_100NS, SEC_100NS, 0, LPercent));
  Assert.IsFalse(MHTryCalcCpuPercent(SEC_100NS, SEC_100NS, -2, LPercent));
end;

procedure TCpuCalcTests.TimerJitterAbove100_IsClampedTo100;
var
  LPercent: Double;
begin
  // 4 ядра заняты на 101% из-за разной гранулярности таймеров.
  Assert.IsTrue(MHTryCalcCpuPercent(4040000, 1000000, 4, LPercent));
  Assert.AreEqual(100.0, LPercent, 0.0001);
end;

procedure TCpuCalcTests.CounterDelta_Normal;
var
  LDelta: UInt64;
begin
  Assert.IsTrue(MHTryCounterDelta(100, 350, LDelta));
  Assert.AreEqual<UInt64>(250, LDelta);
  Assert.IsTrue(MHTryCounterDelta(5, 5, LDelta));
  Assert.AreEqual<UInt64>(0, LDelta);
end;

procedure TCpuCalcTests.CounterDelta_Decreasing_IsRejected;
var
  LDelta: UInt64;
begin
  // Типичный случай: PID переиспользован другим процессом с меньшим временем CPU.
  Assert.IsFalse(MHTryCounterDelta(1000, 10, LDelta));
  Assert.AreEqual<UInt64>(0, LDelta);
end;

procedure TCpuCalcTests.FileTime_Combine;
begin
  Assert.AreEqual<UInt64>(UInt64($0000000100000002), MHFileTimeToUInt64(2, 1));
  Assert.AreEqual<UInt64>(UInt64($FFFFFFFFFFFFFFFF), MHFileTimeToUInt64($FFFFFFFF, $FFFFFFFF));
end;

procedure TCpuCalcTests.SystemCpu_ReferenceValues;
var
  LPercent: Double;
begin
  // kernel = 600 (из них idle 500), user = 400 -> занято (1000 - 500) / 1000 = 50%.
  Assert.IsTrue(MHTryCalcSystemCpuPercent(500, 600, 400, LPercent));
  Assert.AreEqual(50.0, LPercent, 0.0001);
  Assert.IsTrue(MHTryCalcSystemCpuPercent(1000, 1000, 0, LPercent));
  Assert.AreEqual(0.0, LPercent, 0.0001, 'Полный простой');
  Assert.IsTrue(MHTryCalcSystemCpuPercent(0, 300, 700, LPercent));
  Assert.AreEqual(100.0, LPercent, 0.0001, 'Полная загрузка');
end;

procedure TCpuCalcTests.SystemCpu_InvalidInput;
var
  LPercent: Double;
begin
  Assert.IsFalse(MHTryCalcSystemCpuPercent(0, 0, 0, LPercent), 'Нулевой интервал');
  Assert.IsFalse(MHTryCalcSystemCpuPercent(2000, 500, 500, LPercent),
    'Простой больше общего времени — счётчики несогласованы');
end;

procedure TCpuCalcTests.Rate_ReferenceValues;
var
  LRate: Double;
begin
  Assert.IsTrue(MHTryCalcRate(1048576, SEC_100NS, LRate));
  Assert.AreEqual(1048576.0, LRate, 0.001);
  Assert.IsTrue(MHTryCalcRate(1000, SEC_100NS div 2, LRate));
  Assert.AreEqual(2000.0, LRate, 0.001);
  Assert.IsFalse(MHTryCalcRate(1000, 0, LRate));
end;

initialization
  TDUnitX.RegisterTestFixture(TCpuCalcTests);

end.
