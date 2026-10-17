unit MineHunter.Tests.Chart;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types;

type
  [TestFixture]
  [Category('Unit')]
  TChartTests = class
  public
    [Test] procedure Buffer_KeepsNewestInOrder;
    [Test] procedure Buffer_InvalidCapacity_Raises;
    [Test] procedure Segments_BreakOnNoData;
    [Test] procedure Segments_BreakOnTimeGap;
    [Test] procedure Segments_EmptyAndAllNoData;
    [Test] procedure Range_AddsPadding;
    [Test] procedure Range_FlatSeriesIsExpanded;
    [Test] procedure Range_NoData_ReturnsFalse;
    [Test] procedure Summary_DescribesLastMinMax;
    [Test] procedure Summary_NoData;
    [Test] procedure Paint_DoesNotFail_OnEdgeCases;
  end;

implementation

uses
  System.SysUtils, Vcl.Forms, Vcl.Graphics,
  MineHunter.App.Chart;

const
  SEC = 1 / SecsPerDay;

function P(ASecond: Integer; AValue: Double; AHas: Boolean = True): TMHMetric;
begin
  if AHas then
    Result := TMHMetric.Available(mkCpuPercent, AValue, 46311 + ASecond * SEC)
  else
    Result := TMHMetric.NoData(mkCpuPercent, 46311 + ASecond * SEC);
end;

function SegmentsText(const ASegments: TArray<TArray<Integer>>): string;
var
  I, J: Integer;
begin
  Result := '';
  for I := 0 to High(ASegments) do
  begin
    if I > 0 then
      Result := Result + '|';
    for J := 0 to High(ASegments[I]) do
    begin
      if J > 0 then
        Result := Result + ',';
      Result := Result + IntToStr(ASegments[I][J]);
    end;
  end;
end;

procedure TChartTests.Buffer_KeepsNewestInOrder;
var
  LBuffer: TMHSeriesBuffer;
  LItems: TArray<TMHMetric>;
  I: Integer;
begin
  LBuffer := TMHSeriesBuffer.Create(3);
  try
    for I := 1 to 5 do
      LBuffer.Add(P(I, I));
    LItems := LBuffer.ToArray;
    Assert.AreEqual(3, LBuffer.Count);
    Assert.AreEqual(3.0, LItems[0].Value, 0);
    Assert.AreEqual(5.0, LItems[2].Value, 0);
    LBuffer.Clear;
    Assert.AreEqual(0, Integer(Length(LBuffer.ToArray)));
  finally
    LBuffer.Free;
  end;
end;

procedure TChartTests.Buffer_InvalidCapacity_Raises;
begin
  Assert.WillRaise(
    procedure
    begin
      TMHSeriesBuffer.Create(0).Free;
    end, EArgumentOutOfRangeException);
end;

procedure TChartTests.Segments_BreakOnNoData;
begin
  Assert.AreEqual('0,1|3,4', SegmentsText(MHSplitSegments(
    [P(0, 1), P(1, 2), P(2, 0, False), P(3, 4), P(4, 5)], 3)));
end;

procedure TChartTests.Segments_BreakOnTimeGap;
begin
  // Шаг 1 с, затем пауза 60 с (программа не работала) — линия не соединяет точки.
  Assert.AreEqual('0,1,2|3,4', SegmentsText(MHSplitSegments(
    [P(0, 1), P(1, 2), P(2, 3), P(62, 4), P(63, 5)], 3)));
  Assert.AreEqual('0,1,2,3,4', SegmentsText(MHSplitSegments(
    [P(0, 1), P(1, 2), P(2, 3), P(62, 4), P(63, 5)], 0)), 'GapFactor 0 отключает разрывы');
end;

procedure TChartTests.Segments_EmptyAndAllNoData;
begin
  Assert.AreEqual(0, Integer(Length(MHSplitSegments(nil, 3))));
  Assert.AreEqual(0, Integer(Length(MHSplitSegments([P(0, 0, False), P(1, 0, False)], 3))));
  Assert.AreEqual('0', SegmentsText(MHSplitSegments([P(0, 7)], 3)));
end;

procedure TChartTests.Range_AddsPadding;
var
  LRange: TMHValueRange;
begin
  Assert.IsTrue(MHComputeRange([P(0, 10), P(1, 0, False), P(2, 20)], LRange));
  Assert.AreEqual(9.0, LRange.Min, 0.0001);
  Assert.AreEqual(21.0, LRange.Max, 0.0001);
end;

procedure TChartTests.Range_FlatSeriesIsExpanded;
var
  LRange: TMHValueRange;
begin
  Assert.IsTrue(MHComputeRange([P(0, 0), P(1, 0)], LRange));
  Assert.IsTrue(LRange.Max > LRange.Min);
  Assert.AreEqual(0.0, LRange.Min, 0.0001, 'Неотрицательная метрика не уходит ниже нуля');
end;

procedure TChartTests.Range_NoData_ReturnsFalse;
var
  LRange: TMHValueRange;
begin
  Assert.IsFalse(MHComputeRange([P(0, 0, False)], LRange));
  Assert.IsFalse(MHComputeRange(nil, LRange));
end;

procedure TChartTests.Summary_DescribesLastMinMax;
var
  LChart: TMHLineChart;
begin
  LChart := TMHLineChart.Create(nil);
  try
    LChart.Title := 'CPU';
    LChart.SetPoints([P(0, 10), P(1, 50), P(2, 30), P(3, 0, False)]);
    Assert.AreEqual('CPU: сейчас 30, минимум 10, максимум 50', LChart.SummaryText);
    Assert.AreEqual(LChart.SummaryText, LChart.Hint, 'Подсказка дублирует график текстом');
  finally
    LChart.Free;
  end;
end;

procedure TChartTests.Summary_NoData;
var
  LChart: TMHLineChart;
begin
  LChart := TMHLineChart.Create(nil);
  try
    LChart.Title := 'GPU';
    LChart.SetPoints([P(0, 0, False)]);
    Assert.AreEqual('GPU: нет данных', LChart.SummaryText);
  finally
    LChart.Free;
  end;
end;

procedure TChartTests.Paint_DoesNotFail_OnEdgeCases;
var
  LForm: TForm;
  LChart: TMHLineChart;
  LBitmap: TBitmap;
  LCases: TArray<TArray<TMHMetric>>;
  LCase: TArray<TMHMetric>;
begin
  LCases := [nil, [P(0, 0, False)], [P(0, 5)], [P(0, 1), P(1, 1)], [P(0, -5), P(1, 1e12)],
    [P(0, 10), P(1, 0, False), P(500, 90)]];
  LForm := TForm.Create(nil);
  LBitmap := TBitmap.Create;
  try
    LChart := TMHLineChart.Create(LForm);
    LChart.Parent := LForm;
    LChart.SetBounds(0, 0, 400, 160);
    LBitmap.SetSize(400, 160);
    for LCase in LCases do
    begin
      LChart.SetPoints(LCase);
      LChart.PaintTo(LBitmap.Canvas, 0, 0);
    end;
    LChart.SetFixedRange(0, 100);
    LChart.SetTimeWindow(46311, 46311 + 1 / 24);
    LChart.PaintTo(LBitmap.Canvas, 0, 0);
    // Слишком маленький размер: рисование пропускается без ошибок.
    LChart.SetBounds(0, 0, 5, 5);
    LChart.PaintTo(LBitmap.Canvas, 0, 0);
    Assert.WillRaise(
      procedure
      begin
        LChart.SetFixedRange(10, 10);
      end, EArgumentException);
  finally
    LBitmap.Free;
    LForm.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TChartTests);

end.
