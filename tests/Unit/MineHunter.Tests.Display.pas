unit MineHunter.Tests.Display;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Unit')]
  TDisplayTests = class
  public
    [Test] procedure MissingMetric_ShowsNoData;
    [Test] procedure ZeroMetric_IsNotNoData;
    [Test] procedure Percent_IsFormatted;
    [Test] procedure Bytes_UseBinaryUnits;
    [Test] procedure NegativeBytes_ShowNoData;
    [Test] procedure SourceState_HasTextNotOnlySymbol;
    [Test] procedure ZeroTimestamp_ShowsNoData;
  end;

implementation

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.App.Display;

procedure TDisplayTests.MissingMetric_ShowsNoData;
begin
  Assert.AreEqual(MH_NO_DATA, MHFormatMetric(TMHMetric.NoData(mkTemperatureCelsius, 1)));
  Assert.AreEqual(MH_NO_DATA, MHFormatMetric(TMHMetric.NoData(mkCpuPercent, 1)));
end;

procedure TDisplayTests.ZeroMetric_IsNotNoData;
begin
  Assert.AreNotEqual(MH_NO_DATA, MHFormatMetric(TMHMetric.Available(mkCpuPercent, 0, 1)));
end;

procedure TDisplayTests.Percent_IsFormatted;
begin
  Assert.AreEqual(FormatFloat('0.0', 12.5) + ' %',
    MHFormatMetric(TMHMetric.Available(mkCpuPercent, 12.5, 1)));
end;

procedure TDisplayTests.Bytes_UseBinaryUnits;
begin
  Assert.AreEqual('512 Б', MHFormatBytes(512));
  Assert.AreEqual(FormatFloat('0.0', 1.5) + ' КБ', MHFormatBytes(1536));
  Assert.AreEqual(FormatFloat('0.0', 200) + ' МБ', MHFormatBytes(200 * 1024 * 1024));
  Assert.AreEqual(FormatFloat('0.00', 2) + ' ГБ', MHFormatBytes(2.0 * 1024 * 1024 * 1024));
end;

procedure TDisplayTests.NegativeBytes_ShowNoData;
begin
  Assert.AreEqual(MH_NO_DATA, MHFormatBytes(-1));
end;

procedure TDisplayTests.SourceState_HasTextNotOnlySymbol;
var
  LState: TMHSourceState;
begin
  for LState := Low(TMHSourceState) to High(TMHSourceState) do
    Assert.IsTrue(MHFormatSourceState(LState).Contains(MHSourceStateToString(LState)),
      'Статус не должен передаваться только символом или цветом');
end;

procedure TDisplayTests.ZeroTimestamp_ShowsNoData;
begin
  Assert.AreEqual(MH_NO_DATA, MHFormatUtcAsLocal(0));
end;

initialization
  TDUnitX.RegisterTestFixture(TDisplayTests);

end.
