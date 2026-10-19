unit MineHunter.App.Chart;

{
  Лёгкий линейный график для VCL без внешних зависимостей.

  - Точки «нет данных» и большие промежутки времени (программа не работала)
    рисуются как разрыв линии, а не как ноль.
  - Размеры масштабируются по текущему DPI монитора.
  - SummaryText дублирует содержимое графика текстом (последнее, минимум,
    максимум), чтобы информация не передавалась только изображением.
  - Необязательная вторая линия (например, приём и передача сети) — своим
    цветом, с подписями обеих линий в заголовке; шкала общая.
  - Шкала с «круглыми» делениями (1, 2, 5 × 10^n), подписано каждое деление.
    Статичная — от нуля (проценты 0–100); динамическая — по данным, чтобы были
    видны небольшие изменения. Режим общий для всех графиков (DynamicScale).
  Расчёты вынесены в чистые функции и покрыты тестами.
}

interface

uses
  System.SysUtils, System.Classes, System.Types, System.UITypes,
  Vcl.Controls, Vcl.Graphics,
  MineHunter.Core.Types;

type
  TMHValueFormatter = reference to function(AValue: Double): string;

  /// Кольцевой буфер последних измерений (ограниченная память для живых графиков).
  TMHSeriesBuffer = class
  private
    FItems: TArray<TMHMetric>;
    FStart: Integer;
    FCount: Integer;
  public
    constructor Create(ACapacity: Integer);
    procedure Add(const AMetric: TMHMetric);
    procedure Clear;
    /// Точки в хронологическом порядке.
    function ToArray: TArray<TMHMetric>;
    property Count: Integer read FCount;
    function Capacity: Integer;
  end;

  TMHValueRange = record
    Min: Double;
    Max: Double;
  end;

  /// Ось значений: от Min до Max ровно за MH_CHART_DIVISIONS шагов Step.
  TMHChartAxis = record
    Min: Double;
    Max: Double;
    Step: Double;
  end;

  TMHLineChart = class(TCustomControl)
  private
    FPoints: TArray<TMHMetric>;
    FTitle: string;
    FLineColor: TColor;
    FFixedMin, FFixedMax: Double;
    FUseFixedRange: Boolean;
    FFormatter: TMHValueFormatter;
    FGapFactor: Double;
    FFromUtc, FToUtc: TDateTime;
    FSecondPoints: TArray<TMHMetric>;
    FSecondColor: TColor;
    FFirstLegend, FSecondLegend: string;
    FMinGapSeconds: Double;
    class var FDynamicScale: Boolean;
    class var FInstances: TList;
    class destructor Destroy;
    class procedure SetDynamicScale(AValue: Boolean); static;
    procedure SetTitle(const AValue: string);
    procedure SetLineColor(AValue: TColor);
    function Fmt(AValue: Double): string;
    function LastValueText(const APoints: TArray<TMHMetric>): string;
    function S(AValue: Integer): Integer;
  protected
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SetPoints(const APoints: TArray<TMHMetric>);
    /// Ось, по которой рисуется график (с учётом фиксированной шкалы и режима).
    function Axis: TMHChartAxis;
    /// Режим шкалы всех графиков: False — статичная (от нуля, фиксированные
    /// шкалы как есть), True — динамическая (по данным). Меняет уже созданные графики.
    class property DynamicScale: Boolean read FDynamicScale write SetDynamicScale;
    /// Вторая линия со своим цветом; подписи обеих линий выводятся в заголовке.
    /// APoints = nil — только основная линия.
    procedure SetSecondSeries(const APoints: TArray<TMHMetric>; const AFirstLegend, ASecondLegend: string);
    /// Фиксированная шкала (например, 0..100 для процентов).
    procedure SetFixedRange(AMin, AMax: Double);
    /// Явный интервал оси времени; 0..0 — по данным.
    procedure SetTimeWindow(AFromUtc, AToUtc: TDateTime);
    function SummaryText: string;
    property Points: TArray<TMHMetric> read FPoints;
    property SecondPoints: TArray<TMHMetric> read FSecondPoints;
    property SecondColor: TColor read FSecondColor write FSecondColor;
    property Title: string read FTitle write SetTitle;
    property LineColor: TColor read FLineColor write SetLineColor;
    property Formatter: TMHValueFormatter read FFormatter write FFormatter;
    /// Разрыв линии, если шаг по времени больше GapFactor × медианного шага.
    property GapFactor: Double read FGapFactor write FGapFactor;
    /// Шаг короче этого — не разрыв (по умолчанию 90 с: опрос раз в 30 с, пока окно свёрнуто).
    property MinGapSeconds: Double read FMinGapSeconds write FMinGapSeconds;
  published
    property Align;
    property Anchors;
    property Font;
    property ParentFont;
    property TabStop;
    property Hint;
    property ShowHint;
  end;

/// Отрезки непрерывной линии: индексы точек с данными, без больших разрывов.
function MHSplitSegments(const APoints: TArray<TMHMetric>;
  AGapFactor: Double; AMinGapSeconds: Double = 0): TArray<TArray<Integer>>;

/// Точки не раньше AFromUtc (живые графики показывают последние N минут по времени,
/// а не последние N точек: когда Windows притормаживает свёрнутое окно, точки реже).
function MHPointsSince(const APoints: TArray<TMHMetric>; AFromUtc: TDateTime): TArray<TMHMetric>;

/// Диапазон оси Y по данным: с небольшим запасом; плоский ряд расширяется.
/// False — в ряду нет ни одного значения.
function MHComputeRange(const APoints: TArray<TMHMetric>; out ARange: TMHValueRange): Boolean;

const
  /// Делений на оси значений (линий сетки — на одну больше).
  MH_CHART_DIVISIONS = 4;

/// Наименьший «круглый» шаг (1, 2 или 5 × 10^n), не меньший ARaw; ARaw <= 0 — 1.
function MHNiceStep(ARaw: Double): Double;

/// Ось значений с круглыми делениями.
/// ADynamic = False — статичная: фиксированная шкала (AHasFixed) как есть, иначе от нуля
/// до круглого значения не ниже максимума. ADynamic = True — по данным (с запасом),
/// в пределах фиксированной шкалы, если она задана; без данных — как статичная.
/// False — в рядах нет ни одного значения.
function MHComputeAxis(const APoints: TArray<TMHMetric>; ADynamic, AHasFixed: Boolean;
  AFixedMin, AFixedMax: Double; out AAxis: TMHChartAxis): Boolean;

implementation

uses
  MineHunter.App.Theme, MineHunter.Core.Lang, System.Math, System.DateUtils, System.Generics.Collections,
  Winapi.Windows;

{ TMHSeriesBuffer }

constructor TMHSeriesBuffer.Create(ACapacity: Integer);
begin
  inherited Create;
  if ACapacity <= 0 then
    raise EArgumentOutOfRangeException.Create('ACapacity должен быть больше нуля');
  SetLength(FItems, ACapacity);
end;

function TMHSeriesBuffer.Capacity: Integer;
begin
  Result := Length(FItems);
end;

procedure TMHSeriesBuffer.Add(const AMetric: TMHMetric);
begin
  if FCount < Length(FItems) then
  begin
    FItems[(FStart + FCount) mod Length(FItems)] := AMetric;
    Inc(FCount);
  end
  else
  begin
    FItems[FStart] := AMetric;
    FStart := (FStart + 1) mod Length(FItems);
  end;
end;

procedure TMHSeriesBuffer.Clear;
begin
  FStart := 0;
  FCount := 0;
end;

function TMHSeriesBuffer.ToArray: TArray<TMHMetric>;
var
  I: Integer;
begin
  SetLength(Result, FCount);
  for I := 0 to FCount - 1 do
    Result[I] := FItems[(FStart + I) mod Length(FItems)];
end;

{ Чистые функции }

function MedianStep(const APoints: TArray<TMHMetric>): Double;
var
  LSteps: TList<Double>;
  I: Integer;
begin
  LSteps := TList<Double>.Create;
  try
    for I := 1 to High(APoints) do
      if APoints[I].TimestampUtc > APoints[I - 1].TimestampUtc then
        LSteps.Add(APoints[I].TimestampUtc - APoints[I - 1].TimestampUtc);
    if LSteps.Count = 0 then
      Exit(0);
    LSteps.Sort;
    Result := LSteps[LSteps.Count div 2];
  finally
    LSteps.Free;
  end;
end;

function MHSplitSegments(const APoints: TArray<TMHMetric>;
  AGapFactor: Double; AMinGapSeconds: Double): TArray<TArray<Integer>>;
var
  LResult: TList<TArray<Integer>>;
  LCurrent: TList<Integer>;
  LMaxStep: Double;
  I, LPrev: Integer;

  procedure Flush;
  begin
    if LCurrent.Count > 0 then
      LResult.Add(LCurrent.ToArray);
    LCurrent.Clear;
  end;

begin
  LResult := TList<TArray<Integer>>.Create;
  LCurrent := TList<Integer>.Create;
  try
    // Разрыв — шаг больше GapFactor медианных, но не короче AMinGapSeconds: редкий опрос,
    // пока окно свёрнуто (экономный режим), разрывом не считается.
    LMaxStep := Max(MedianStep(APoints) * AGapFactor, AMinGapSeconds / SecsPerDay);
    LPrev := -1;
    for I := 0 to High(APoints) do
    begin
      if not APoints[I].HasValue then
      begin
        Flush;
        LPrev := -1;
        Continue;
      end;
      if (LPrev >= 0) and (AGapFactor > 0) and (LMaxStep > 0) and
         (APoints[I].TimestampUtc - APoints[LPrev].TimestampUtc > LMaxStep) then
        Flush;
      LCurrent.Add(I);
      LPrev := I;
    end;
    Flush;
    Result := LResult.ToArray;
  finally
    LCurrent.Free;
    LResult.Free;
  end;
end;

function MHPointsSince(const APoints: TArray<TMHMetric>; AFromUtc: TDateTime): TArray<TMHMetric>;
var
  I: Integer;
begin
  for I := 0 to High(APoints) do
    if APoints[I].TimestampUtc >= AFromUtc then
      Exit(Copy(APoints, I, MaxInt));
  Result := nil;
end;

function MHComputeRange(const APoints: TArray<TMHMetric>; out ARange: TMHValueRange): Boolean;
var
  I: Integer;
  LPad: Double;
begin
  Result := False;
  ARange.Min := 0;
  ARange.Max := 1;
  for I := 0 to High(APoints) do
    if APoints[I].HasValue then
    begin
      if not Result then
      begin
        ARange.Min := APoints[I].Value;
        ARange.Max := APoints[I].Value;
        Result := True;
      end
      else
      begin
        ARange.Min := Min(ARange.Min, APoints[I].Value);
        ARange.Max := Max(ARange.Max, APoints[I].Value);
      end;
    end;
  if not Result then
    Exit;
  if SameValue(ARange.Min, ARange.Max) then
  begin
    LPad := Max(Abs(ARange.Max) * 0.1, 1);
    ARange.Min := ARange.Min - LPad;
    ARange.Max := ARange.Max + LPad;
  end
  else
  begin
    LPad := (ARange.Max - ARange.Min) * 0.1;
    ARange.Max := ARange.Max + LPad;
    ARange.Min := ARange.Min - LPad;
  end;
  // Метрики MineHunter неотрицательны: не уводим ось ниже нуля без необходимости.
  if (ARange.Min < 0) and (ARange.Min + LPad >= 0) then
    ARange.Min := 0;
end;

function MHNiceStep(ARaw: Double): Double;
var
  LPower, LFraction: Double;
begin
  if IsNan(ARaw) or IsInfinite(ARaw) or (ARaw <= 0) then
    Exit(1);
  // Основание — явно Double: с целым 10 выбирается перегрузка Single и теряется точность (0,2 → 0,2000000029).
  LPower := IntPower(Double(10), Floor(Log10(ARaw)));
  LFraction := ARaw / LPower;
  // Допуск на погрешность: 0,2 / 0,1 даёт 2,0000000000000004.
  if LFraction <= 1 + 1E-9 then
    Result := LPower
  else if LFraction <= 2 + 1E-9 then
    Result := 2 * LPower
  else if LFraction <= 5 + 1E-9 then
    Result := 5 * LPower
  else
    Result := 10 * LPower;
end;

function MHComputeAxis(const APoints: TArray<TMHMetric>; ADynamic, AHasFixed: Boolean;
  AFixedMin, AFixedMax: Double; out AAxis: TMHChartAxis): Boolean;
var
  LRaw: TMHValueRange;
  LLo, LHi, LSpan, LFloor: Double;
  I: Integer;
begin
  AHasFixed := AHasFixed and (AFixedMax > AFixedMin);
  // Данные без запаса MHComputeRange.
  Result := False;
  LLo := 0;
  LHi := 0;
  for I := 0 to High(APoints) do
    if APoints[I].HasValue and not IsNan(APoints[I].Value) and not IsInfinite(APoints[I].Value) then
    begin
      if not Result then
      begin
        LLo := APoints[I].Value;
        LHi := LLo;
        Result := True;
      end;
      LLo := Min(LLo, APoints[I].Value);
      LHi := Max(LHi, APoints[I].Value);
    end;
  LRaw.Min := LLo;
  LRaw.Max := LHi;

  if not ADynamic or not Result then
  begin
    if AHasFixed then
    begin
      AAxis.Min := AFixedMin;
      AAxis.Max := AFixedMax;
      AAxis.Step := (AFixedMax - AFixedMin) / MH_CHART_DIVISIONS;
      Exit;
    end;
    // От нуля (или ниже, если есть отрицательные значения) до круглого значения.
    AAxis.Min := 0;
    if Result and (LRaw.Min < 0) then
      AAxis.Min := -MHNiceStep(-LRaw.Min / MH_CHART_DIVISIONS) * MH_CHART_DIVISIONS;
    AAxis.Step := MHNiceStep((Max(LRaw.Max, 0) - AAxis.Min) / MH_CHART_DIVISIONS);
    if not Result or (LRaw.Max - AAxis.Min <= 0) then
      AAxis.Step := MHNiceStep(0.25);
    while AAxis.Min + AAxis.Step * MH_CHART_DIVISIONS < LRaw.Max do
      AAxis.Step := MHNiceStep(AAxis.Step * 1.01);
    AAxis.Max := AAxis.Min + AAxis.Step * MH_CHART_DIVISIONS;
    Exit;
  end;

  // Динамическая: по данным с запасом; ровная линия — посередине.
  LSpan := LRaw.Max - LRaw.Min;
  if LSpan <= 0 then
  begin
    LSpan := Max(Abs(LRaw.Max) * 0.1, 1);
    LLo := LRaw.Min - LSpan / 2;
    LHi := LRaw.Max + LSpan / 2;
  end
  else
  begin
    LLo := LRaw.Min - LSpan * 0.05;
    LHi := LRaw.Max + LSpan * 0.05;
  end;
  // Нижняя граница: метрики неотрицательны — ось не уходит ниже нуля (и ниже фиксированной шкалы).
  if AHasFixed then
    LFloor := AFixedMin
  else if LRaw.Min >= 0 then
    LFloor := 0
  else
    LFloor := -MaxDouble;
  LLo := Max(LLo, LFloor);
  if AHasFixed then
    LHi := Min(LHi, AFixedMax);
  AAxis.Step := MHNiceStep((LHi - LLo) / MH_CHART_DIVISIONS);
  for I := 1 to 64 do
  begin
    AAxis.Min := Floor(LLo / AAxis.Step + 1E-9) * AAxis.Step;
    if AAxis.Min < LFloor then
      AAxis.Min := LFloor;
    AAxis.Max := AAxis.Min + AAxis.Step * MH_CHART_DIVISIONS;
    if AHasFixed and (AAxis.Max > AFixedMax) then
    begin
      // Сдвиг вниз, чтобы не выйти за фиксированную шкалу.
      AAxis.Max := AFixedMax;
      AAxis.Min := Max(AFixedMin, AFixedMax - AAxis.Step * MH_CHART_DIVISIONS);
      AAxis.Max := AAxis.Min + AAxis.Step * MH_CHART_DIVISIONS;
    end;
    if AAxis.Max >= LHi - 1E-9 * Max(1, Abs(LHi)) then
      Break;
    AAxis.Step := MHNiceStep(AAxis.Step * 1.01);
  end;
  if AHasFixed and ((AAxis.Max > AFixedMax + 1E-9) or (AAxis.Min < AFixedMin - 1E-9)) then
  begin
    // Данные занимают почти всю фиксированную шкалу — она и есть ось.
    AAxis.Min := AFixedMin;
    AAxis.Max := AFixedMax;
    AAxis.Step := (AFixedMax - AFixedMin) / MH_CHART_DIVISIONS;
  end;
end;

{ TMHLineChart }

class destructor TMHLineChart.Destroy;
begin
  FreeAndNil(FInstances);
end;

class procedure TMHLineChart.SetDynamicScale(AValue: Boolean);
var
  I: Integer;
begin
  FDynamicScale := AValue;
  if FInstances <> nil then
    for I := 0 to FInstances.Count - 1 do
      TMHLineChart(FInstances[I]).Invalidate;
end;

destructor TMHLineChart.Destroy;
begin
  if FInstances <> nil then
    FInstances.Remove(Self);
  inherited Destroy;
end;

function TMHLineChart.Axis: TMHChartAxis;
begin
  MHComputeAxis(FPoints + FSecondPoints, FDynamicScale, FUseFixedRange, FFixedMin, FFixedMax, Result);
end;

constructor TMHLineChart.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  // Графики создаются и освобождаются в главном потоке.
  if FInstances = nil then
    FInstances := TList.Create;
  FInstances.Add(Self);
  ControlStyle := ControlStyle + [csOpaque];
  DoubleBuffered := True;
  ParentFont := True;
  FLineColor := TColor($00B06A1F); // синий, контрастный на светлом фоне
  FSecondColor := TColor($001E7FE8); // оранжевый — различим с синим и при нарушениях цветовосприятия
  FGapFactor := 3;
  FMinGapSeconds := 90;
  Width := 300;
  Height := 140;
end;

function TMHLineChart.S(AValue: Integer): Integer;
begin
  Result := MulDiv(AValue, CurrentPPI, 96);
end;

function TMHLineChart.Fmt(AValue: Double): string;
begin
  if Assigned(FFormatter) then
    Result := FFormatter(AValue)
  else
    Result := FormatFloat('0.#', AValue);
end;

procedure TMHLineChart.SetTitle(const AValue: string);
begin
  FTitle := AValue;
  Invalidate;
end;

procedure TMHLineChart.SetLineColor(AValue: TColor);
begin
  FLineColor := AValue;
  Invalidate;
end;

procedure TMHLineChart.SetPoints(const APoints: TArray<TMHMetric>);
begin
  FPoints := APoints;
  Hint := SummaryText;
  Invalidate;
end;

procedure TMHLineChart.SetSecondSeries(const APoints: TArray<TMHMetric>; const AFirstLegend,
  ASecondLegend: string);
begin
  FSecondPoints := APoints;
  FFirstLegend := AFirstLegend;
  FSecondLegend := ASecondLegend;
  Hint := SummaryText;
  Invalidate;
end;

function TMHLineChart.LastValueText(const APoints: TArray<TMHMetric>): string;
var
  I: Integer;
begin
  Result := MHL('нет данных', 'no data');
  for I := High(APoints) downto 0 do
    if APoints[I].HasValue then
      Exit(Fmt(APoints[I].Value));
end;

procedure TMHLineChart.SetFixedRange(AMin, AMax: Double);
begin
  if AMax <= AMin then
    raise EArgumentException.Create('Верхняя граница шкалы должна быть больше нижней');
  FFixedMin := AMin;
  FFixedMax := AMax;
  FUseFixedRange := True;
  Invalidate;
end;

procedure TMHLineChart.SetTimeWindow(AFromUtc, AToUtc: TDateTime);
begin
  FFromUtc := AFromUtc;
  FToUtc := AToUtc;
  Invalidate;
end;

function TMHLineChart.SummaryText: string;
var
  LLast: string;
  LRange: TMHValueRange;
  I: Integer;
  LMin, LMax: Double;
  LHas: Boolean;
begin
  LLast := MHL('нет данных', 'no data');
  for I := High(FPoints) downto 0 do
    if FPoints[I].HasValue then
    begin
      LLast := Fmt(FPoints[I].Value);
      Break;
    end;
  if not MHComputeRange(FPoints, LRange) then
    Exit(Format('%s: нет данных', [FTitle]));
  LHas := False;
  LMin := 0;
  LMax := 0;
  for I := 0 to High(FPoints) do
    if FPoints[I].HasValue then
    begin
      if not LHas then
      begin
        LMin := FPoints[I].Value;
        LMax := LMin;
        LHas := True;
      end;
      LMin := Min(LMin, FPoints[I].Value);
      LMax := Max(LMax, FPoints[I].Value);
    end;
  Result := Format('%s: сейчас %s, минимум %s, максимум %s',
    [FTitle, LLast, Fmt(LMin), Fmt(LMax)]);
  if Length(FSecondPoints) > 0 then
    Result := Result + Format(' (%s); %s: сейчас %s', [FFirstLegend, FSecondLegend,
      LastValueText(FSecondPoints)]);
end;

procedure TMHLineChart.Paint;
var
  LRect, LPlot: TRect;
  LRange: TMHValueRange;
  LAxis: TMHChartAxis;
  LHasData: Boolean;
  LFrom, LTo: TDateTime;
  LSegments: TArray<TArray<Integer>>;
  LSegment: TArray<Integer>;
  LPts: TArray<TPoint>;
  I, J, LTextH, LLabelW: Integer;
  LValue: Double;
  LText: string;
  LLegend: TArray<string>;

  function XOf(ATime: TDateTime): Integer;
  begin
    if LTo <= LFrom then
      Result := LPlot.Right
    else
      Result := LPlot.Left + Round((ATime - LFrom) / (LTo - LFrom) * LPlot.Width);
  end;

  function YOf(AValue: Double): Integer;
  begin
    Result := LPlot.Bottom - Round((EnsureRange(AValue, LRange.Min, LRange.Max) - LRange.Min) /
      (LRange.Max - LRange.Min) * LPlot.Height);
  end;

begin
  LRect := ClientRect;
  Canvas.Font := Font;
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(clWindow);
  Canvas.Pen.Color := MHThemeColor(clBtnShadow);
  Canvas.Pen.Width := 1;
  Canvas.Rectangle(LRect);
  LTextH := Canvas.TextHeight('Ag');

  // Заголовок и текущее значение — текстом.
  Canvas.Font.Color := MHThemeColor(clWindowText);
  Canvas.Font.Style := [fsBold];
  Canvas.TextOut(LRect.Left + S(6), LRect.Top + S(4), FTitle);
  Canvas.Font.Style := [];
  if Length(FSecondPoints) > 0 then
  begin
    // «■ Приём 152 кбит/с   ■ Передача 8 кбит/с» — справа, метки цветом линий.
    LLegend := [FFirstLegend + ' ' + LastValueText(FPoints), FSecondLegend + ' ' +
      LastValueText(FSecondPoints)];
    J := LRect.Right - S(6);
    for I := High(LLegend) downto 0 do
    begin
      J := J - Canvas.TextWidth(LLegend[I]);
      Canvas.TextOut(J, LRect.Top + S(4), LLegend[I]);
      J := J - S(16);
      if I = 0 then
        Canvas.Brush.Color := FLineColor
      else
        Canvas.Brush.Color := FSecondColor;
      Canvas.FillRect(Rect(J + S(2), LRect.Top + S(4) + LTextH div 2 - S(2), J + S(12),
        LRect.Top + S(4) + LTextH div 2 + S(2)));
      Canvas.Brush.Color := MHThemeColor(clWindow);
      J := J - S(12);
    end;
  end
  else
  begin
    LText := MHL('нет данных', 'no data');
    for I := High(FPoints) downto 0 do
      if FPoints[I].HasValue then
      begin
        LText := Fmt(FPoints[I].Value);
        Break;
      end;
    Canvas.TextOut(LRect.Right - S(6) - Canvas.TextWidth(LText), LRect.Top + S(4), LText);
  end;

  // Шкала — общая для обеих линий, с круглыми делениями.
  LHasData := MHComputeAxis(FPoints + FSecondPoints, FDynamicScale, FUseFixedRange, FFixedMin, FFixedMax, LAxis);
  LRange.Min := LAxis.Min;
  LRange.Max := LAxis.Max;

  LLabelW := 0;
  for I := 0 to MH_CHART_DIVISIONS do
    LLabelW := Max(LLabelW, Canvas.TextWidth(Fmt(LAxis.Min + LAxis.Step * I)));
  Inc(LLabelW, S(8));
  LPlot := Rect(LRect.Left + LLabelW, LRect.Top + LTextH + S(10),
    LRect.Right - S(8), LRect.Bottom - LTextH - S(8));
  if (LPlot.Width < S(20)) or (LPlot.Height < S(10)) then
    Exit;

  // Сетка и подписи оси Y — у каждого деления.
  Canvas.Pen.Color := MHThemeColor(clBtnFace);
  Canvas.Font.Color := MHThemeColor(clGrayText);
  for I := 0 to MH_CHART_DIVISIONS do
  begin
    J := LPlot.Bottom - Round(LPlot.Height * I / MH_CHART_DIVISIONS);
    Canvas.MoveTo(LPlot.Left, J);
    Canvas.LineTo(LPlot.Right, J);
    // Подписи не налезают друг на друга на низком графике.
    if (I in [0, MH_CHART_DIVISIONS]) or (LPlot.Height >= MH_CHART_DIVISIONS * (LTextH + S(2))) then
    begin
      LValue := LAxis.Min + LAxis.Step * I;
      LText := Fmt(LValue);
      Canvas.TextOut(LPlot.Left - S(4) - Canvas.TextWidth(LText), J - LTextH div 2, LText);
    end;
  end;

  if not LHasData then
  begin
    LText := MHL('нет данных', 'no data');
    Canvas.Font.Color := MHThemeColor(clGrayText);
    Canvas.TextOut(LPlot.Left + (LPlot.Width - Canvas.TextWidth(LText)) div 2,
      LPlot.Top + (LPlot.Height - LTextH) div 2, LText);
    Exit;
  end;

  // Ось времени.
  if FToUtc > FFromUtc then
  begin
    LFrom := FFromUtc;
    LTo := FToUtc;
  end
  else
  begin
    LFrom := FPoints[0].TimestampUtc;
    LTo := FPoints[High(FPoints)].TimestampUtc;
  end;
  Canvas.TextOut(LPlot.Left, LPlot.Bottom + S(4),
    FormatDateTime('dd.mm hh:nn', TTimeZone.Local.ToLocalTime(LFrom)));
  LText := FormatDateTime('dd.mm hh:nn', TTimeZone.Local.ToLocalTime(LTo));
  Canvas.TextOut(LPlot.Right - Canvas.TextWidth(LText), LPlot.Bottom + S(4), LText);
  // Середина оси времени — если помещается между крайними подписями.
  if (LTo > LFrom) and (LPlot.Width > 4 * Canvas.TextWidth(LText)) then
  begin
    LText := FormatDateTime('hh:nn', TTimeZone.Local.ToLocalTime(LFrom + (LTo - LFrom) / 2));
    Canvas.TextOut(LPlot.Left + (LPlot.Width - Canvas.TextWidth(LText)) div 2, LPlot.Bottom + S(4), LText);
  end;

  // Линии по непрерывным отрезкам; одиночная точка — маркер.
  Canvas.Pen.Color := FLineColor;
  Canvas.Pen.Width := Max(1, S(2));
  Canvas.Brush.Color := FLineColor;
  LSegments := MHSplitSegments(FPoints, FGapFactor, FMinGapSeconds);
  for LSegment in LSegments do
  begin
    SetLength(LPts, Length(LSegment));
    for I := 0 to High(LSegment) do
      LPts[I] := Point(XOf(FPoints[LSegment[I]].TimestampUtc), YOf(FPoints[LSegment[I]].Value));
    if Length(LPts) = 1 then
      Canvas.Ellipse(LPts[0].X - S(2), LPts[0].Y - S(2), LPts[0].X + S(3), LPts[0].Y + S(3))
    else
      Canvas.Polyline(LPts);
  end;
  if Length(FSecondPoints) = 0 then
    Exit;
  Canvas.Pen.Color := FSecondColor;
  Canvas.Brush.Color := FSecondColor;
  LSegments := MHSplitSegments(FSecondPoints, FGapFactor, FMinGapSeconds);
  for LSegment in LSegments do
  begin
    SetLength(LPts, Length(LSegment));
    for I := 0 to High(LSegment) do
      LPts[I] := Point(XOf(FSecondPoints[LSegment[I]].TimestampUtc), YOf(FSecondPoints[LSegment[I]].Value));
    if Length(LPts) = 1 then
      Canvas.Ellipse(LPts[0].X - S(2), LPts[0].Y - S(2), LPts[0].X + S(3), LPts[0].Y + S(3))
    else
      Canvas.Polyline(LPts);
  end;
end;

end.
