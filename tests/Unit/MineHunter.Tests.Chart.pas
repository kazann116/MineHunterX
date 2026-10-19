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
    [Test] procedure NiceStep_RoundValues;
    [Test] procedure Axis_Static_FixedRangeAsIs;
    [Test] procedure Axis_Static_FromZeroToRoundMax;
    [Test] procedure Axis_Static_NoDataAndNegative;
    [Test] procedure Axis_Dynamic_FitsDataWithRoundDivisions;
    [Test] procedure Axis_Dynamic_FlatAndZeroSeries;
    [Test] procedure Axis_Dynamic_StaysInsideFixedRange;
    [Test] procedure Axis_Dynamic_NoDataFallsBackToStatic;
    [Test] procedure DynamicScale_AppliesToAllCharts;
  end;

implementation

uses
  System.SysUtils, System.Math, Vcl.Forms, Vcl.Graphics,
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
var
  LSince: TArray<TMHMetric>;
begin
  // Последние N минут по времени, а не последние N точек.
  LSince := MHPointsSince([P(0, 1), P(10, 2), P(20, 3), P(30, 4)], P(15, 0).TimestampUtc);
  Assert.AreEqual(2, Integer(Length(LSince)));
  Assert.AreEqual(3.0, LSince[0].Value, 0.01);
  Assert.AreEqual(0, Integer(Length(MHPointsSince([P(0, 1)], P(5, 0).TimestampUtc))));
  Assert.AreEqual(0, Integer(Length(MHSplitSegments(nil, 3))));
  // Окно свёрнуто: опрос раз в 30 с среди шагов по 2 с — не разрыв; пауза 5 минут — разрыв.
  Assert.AreEqual('0,1,2,3,4,5', SegmentsText(MHSplitSegments([P(0, 1), P(2, 1), P(4, 1), P(34, 1), P(64, 1), P(66, 1)],
    3, 90)), 'Экономный опрос — сплошная линия');
  Assert.AreEqual('0,1,2|3,4', SegmentsText(MHSplitSegments([P(0, 1), P(2, 1), P(4, 1), P(304, 1), P(306, 1)],
    3, 90)), 'Программа не работала 5 минут — разрыв');
  Assert.AreEqual('0,1,2|3|4,5', SegmentsText(MHSplitSegments([P(0, 1), P(2, 1), P(4, 1), P(34, 1), P(64, 1),
    P(66, 1)], 3)), 'Без нижней границы шаг 30 с при медиане 2 с — разрыв (прежнее поведение)');
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

function Series(const AValues: array of Double): TArray<TMHMetric>;
var
  I: Integer;
begin
  SetLength(Result, Length(AValues));
  for I := 0 to High(AValues) do
    Result[I] := P(I, AValues[I]);
end;

/// Инварианты оси: ровно MH_CHART_DIVISIONS круглых шагов, данные внутри.
procedure CheckAxis(const AAxis: TMHChartAxis; ALo, AHi: Double; const AContext: string);
begin
  Assert.IsTrue(AAxis.Step > 0, AContext);
  Assert.AreEqual(AAxis.Min + AAxis.Step * MH_CHART_DIVISIONS, AAxis.Max, 1E-9 * Max(1, Abs(AAxis.Max)), AContext);
  Assert.IsTrue(AAxis.Min <= ALo + 1E-9, AContext + ': минимум внутри');
  Assert.IsTrue(AAxis.Max >= AHi - 1E-9, AContext + ': максимум внутри');
end;

procedure TChartTests.NiceStep_RoundValues;
begin
  Assert.AreEqual(1.0, MHNiceStep(1), 1E-12);
  Assert.AreEqual(2.0, MHNiceStep(1.01), 1E-12);
  Assert.AreEqual(5.0, MHNiceStep(2.5), 1E-12);
  Assert.AreEqual(10.0, MHNiceStep(5.1), 1E-12);
  Assert.AreEqual(0.2, MHNiceStep(0.2), 1E-12, 'Погрешность не поднимает шаг до 0,5');
  Assert.AreEqual(0.25 * 2, MHNiceStep(0.3), 1E-12);
  Assert.AreEqual(20000.0, MHNiceStep(11776), 1E-6);
  Assert.AreEqual(1.0, MHNiceStep(0), 1E-12, 'Не положительное — 1');
  Assert.AreEqual(1.0, MHNiceStep(-5), 1E-12);
  Assert.AreEqual(1.0, MHNiceStep(NaN), 1E-12);
  Assert.AreEqual(1.0, MHNiceStep(Infinity), 1E-12);
end;

procedure TChartTests.Axis_Static_FixedRangeAsIs;
var
  LAxis: TMHChartAxis;
begin
  Assert.IsTrue(MHComputeAxis(Series([3, 7, 5]), False, True, 0, 100, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-12);
  Assert.AreEqual(100.0, LAxis.Max, 1E-12);
  Assert.AreEqual(25.0, LAxis.Step, 1E-12);
  // Неверная фиксированная шкала (верх не больше низа) не используется.
  Assert.IsTrue(MHComputeAxis(Series([3, 7]), False, True, 10, 10, LAxis));
  CheckAxis(LAxis, 0, 7, 'неверная фиксированная');
end;

procedure TChartTests.Axis_Static_FromZeroToRoundMax;
var
  LAxis: TMHChartAxis;
begin
  Assert.IsTrue(MHComputeAxis(Series([12.3, 47, 31]), False, False, 0, 0, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-12, 'Статичная — от нуля');
  Assert.AreEqual(20.0, LAxis.Step, 1E-12);
  Assert.AreEqual(80.0, LAxis.Max, 1E-12);
  // Максимум ровно на делении — шкала не раздувается.
  Assert.IsTrue(MHComputeAxis(Series([10, 40]), False, False, 0, 0, LAxis));
  Assert.AreEqual(40.0, LAxis.Max, 1E-12);
  // Все нули — небольшая шкала от нуля.
  Assert.IsTrue(MHComputeAxis(Series([0, 0]), False, False, 0, 0, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-12);
  CheckAxis(LAxis, 0, 0, 'нули');
  // Скорости в байтах — шаг кратен 1, 2 или 5 × 10^n.
  Assert.IsTrue(MHComputeAxis(Series([47104]), False, False, 0, 0, LAxis));
  Assert.AreEqual(20000.0, LAxis.Step, 1E-6);
  CheckAxis(LAxis, 0, 47104, 'байты');
end;

procedure TChartTests.Axis_Static_NoDataAndNegative;
var
  LAxis: TMHChartAxis;
begin
  Assert.IsFalse(MHComputeAxis(nil, False, False, 0, 0, LAxis), 'Нет данных');
  CheckAxis(LAxis, 0, 0, 'без данных');
  Assert.IsFalse(MHComputeAxis([P(0, 0, False), P(1, 0, False)], False, True, 0, 100, LAxis));
  Assert.AreEqual(100.0, LAxis.Max, 1E-12, 'Без данных фиксированная шкала сохраняется');
  Assert.IsTrue(MHComputeAxis(Series([-3, 5]), False, False, 0, 0, LAxis));
  CheckAxis(LAxis, -3, 5, 'отрицательные');
  Assert.IsTrue(LAxis.Min < 0);
  // Значения NaN и бесконечность не ломают ось.
  Assert.IsTrue(MHComputeAxis(Series([NaN, 4, Infinity]), False, False, 0, 0, LAxis));
  CheckAxis(LAxis, 0, 4, 'NaN');
end;

procedure TChartTests.Axis_Dynamic_FitsDataWithRoundDivisions;
var
  LAxis: TMHChartAxis;
begin
  // Загрузка 12–14 % — шкала около данных, а не 0–100.
  Assert.IsTrue(MHComputeAxis(Series([12.3, 13.1, 14.08]), True, True, 0, 100, LAxis));
  CheckAxis(LAxis, 12.3, 14.08, 'проценты');
  Assert.IsTrue(LAxis.Max - LAxis.Min <= 4, Format('Узкая шкала: %g..%g', [LAxis.Min, LAxis.Max]));
  Assert.AreEqual(MHNiceStep(LAxis.Step), LAxis.Step, 1E-12, 'Шаг круглый');
  Assert.AreEqual(Round(LAxis.Min / LAxis.Step) * LAxis.Step, LAxis.Min, 1E-9, 'Минимум кратен шагу');
  // Большой разброс без фиксированной шкалы.
  Assert.IsTrue(MHComputeAxis(Series([1000, 98000, 51000]), True, False, 0, 0, LAxis));
  CheckAxis(LAxis, 1000, 98000, 'разброс');
  Assert.IsTrue(LAxis.Min >= 0, 'Неотрицательные данные — ось не ниже нуля');
end;

procedure TChartTests.Axis_Dynamic_FlatAndZeroSeries;
var
  LAxis: TMHChartAxis;
begin
  Assert.IsTrue(MHComputeAxis(Series([50, 50, 50]), True, False, 0, 0, LAxis));
  CheckAxis(LAxis, 50, 50, 'ровная');
  Assert.IsTrue((LAxis.Min < 50) and (LAxis.Max > 50), 'Ровная линия не на краю');
  // Диск простаивает: 0 % — шкала 0–1 %, а не 0–100.
  Assert.IsTrue(MHComputeAxis(Series([0, 0, 0]), True, True, 0, 100, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-12);
  Assert.IsTrue(LAxis.Max <= 1 + 1E-9, Format('%g', [LAxis.Max]));
  CheckAxis(LAxis, 0, 0, 'простой');
end;

procedure TChartTests.Axis_Dynamic_StaysInsideFixedRange;
var
  LAxis: TMHChartAxis;
begin
  // У верхнего края процентов — ось не выходит за 100.
  Assert.IsTrue(MHComputeAxis(Series([97, 99.5, 100]), True, True, 0, 100, LAxis));
  CheckAxis(LAxis, 97, 100, 'у края');
  Assert.IsTrue(LAxis.Max <= 100 + 1E-9);
  // Почти весь диапазон — сама фиксированная шкала.
  Assert.IsTrue(MHComputeAxis(Series([1, 99]), True, True, 0, 100, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-9);
  Assert.AreEqual(100.0, LAxis.Max, 1E-9);
end;

procedure TChartTests.Axis_Dynamic_NoDataFallsBackToStatic;
var
  LAxis: TMHChartAxis;
begin
  Assert.IsFalse(MHComputeAxis(nil, True, True, 0, 100, LAxis));
  Assert.AreEqual(0.0, LAxis.Min, 1E-12);
  Assert.AreEqual(100.0, LAxis.Max, 1E-12);
end;

procedure TChartTests.DynamicScale_AppliesToAllCharts;
var
  LForm: TForm;
  LFirst, LSecond: TMHLineChart;
  LOld: Boolean;
  LBitmap: Vcl.Graphics.TBitmap;
begin
  LOld := TMHLineChart.DynamicScale;
  LForm := TForm.CreateNew(nil);
  LBitmap := Vcl.Graphics.TBitmap.Create;
  try
    LFirst := TMHLineChart.Create(LForm);
    LFirst.Parent := LForm;
    LFirst.SetFixedRange(0, 100);
    LFirst.SetPoints(Series([12, 13, 14]));
    LSecond := TMHLineChart.Create(LForm);
    LSecond.Parent := LForm;
    LSecond.SetPoints(Series([12, 13, 14]));
    TMHLineChart.DynamicScale := False;
    Assert.AreEqual(100.0, LFirst.Axis.Max, 1E-9);
    Assert.AreEqual(0.0, LSecond.Axis.Min, 1E-9);
    TMHLineChart.DynamicScale := True;
    Assert.IsTrue(LFirst.Axis.Max < 100, 'Уже созданный график переключился');
    Assert.IsTrue(LSecond.Axis.Min > 0);
    // Рисование в обоих режимах.
    LBitmap.SetSize(LFirst.Width, LFirst.Height);
    LFirst.PaintTo(LBitmap.Canvas.Handle, 0, 0);
    TMHLineChart.DynamicScale := False;
    LFirst.PaintTo(LBitmap.Canvas.Handle, 0, 0);
    // Освобождённый график исключается из списка (переключение после — без ошибок).
    LSecond.Free;
    TMHLineChart.DynamicScale := True;
  finally
    TMHLineChart.DynamicScale := LOld;
    LBitmap.Free;
    LForm.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TChartTests);

end.
