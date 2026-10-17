unit MineHunter.Core.Energy;

{
  Оценка потреблённой энергии и её стоимости по истории мощности.
  Источник мощности — датчик драйвера (NVML для видеокарт NVIDIA); для
  процессора и остальных компонентов Windows без сторонних драйверов
  мощность не сообщает, поэтому оценка честно ограничена тем, что измерено.
  Интегрирование — методом трапеций; промежутки длиннее AMaxGapMinutes
  (программа была закрыта, компьютер спал) не учитываются.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

type
  TMHEnergyEstimate = record
    HasData: Boolean;
    /// Энергия за охваченное время, кВт·ч.
    KWh: Double;
    /// Время, за которое есть измерения, часы.
    CoveredHours: Double;
    AverageWatts: Double;
    PeakWatts: Double;
    /// Стоимость KWh по цене APricePerKWh.
    Cost: Double;
    /// Стоимость при той же средней мощности за сутки и за месяц (30 дней).
    CostPerDay: Double;
    CostPerMonth: Double;
  end;

/// Стоимость работы с мощностью AWatts в течение AHours часов.
function MHEnergyCost(AWatts, AHours, APricePerKWh: Double): Double;

function MHEstimateEnergy(const ASeries: TArray<TMHMetric>; APricePerKWh: Double;
  AMaxGapMinutes: Double = 15): TMHEnergyEstimate;

/// «12,35 ₽» (два знака до 100 ₽, далее без копеек).
function MHFormatMoney(AValue: Double): string;

/// «0,42 кВт·ч» / «850 Вт·ч».
function MHFormatEnergy(AKWh: Double): string;

implementation

uses
  System.Math, System.Generics.Collections, System.Generics.Defaults, MineHunter.Core.Lang;

function MHEnergyCost(AWatts, AHours, APricePerKWh: Double): Double;
begin
  if IsNan(AWatts) or IsNan(AHours) or IsNan(APricePerKWh) or (AWatts <= 0) or (AHours <= 0) or
     (APricePerKWh <= 0) then
    Exit(0);
  Result := AWatts / 1000 * AHours * APricePerKWh;
end;

function MHEstimateEnergy(const ASeries: TArray<TMHMetric>; APricePerKWh: Double;
  AMaxGapMinutes: Double): TMHEnergyEstimate;
var
  LPoints: TList<TMHMetric>;
  LMetric: TMHMetric;
  I: Integer;
  LHours, LWattHours: Double;
begin
  Result := Default(TMHEnergyEstimate);
  LPoints := TList<TMHMetric>.Create;
  try
    for LMetric in ASeries do
      if LMetric.HasValue and not IsNan(LMetric.Value) and not IsInfinite(LMetric.Value) and
         (LMetric.Value >= 0) then
        LPoints.Add(LMetric);
    if LPoints.Count = 0 then
      Exit;
    LPoints.Sort(TComparer<TMHMetric>.Construct(
      function(const A, B: TMHMetric): Integer
      begin
        Result := CompareValue(A.TimestampUtc, B.TimestampUtc);
      end));
    Result.HasData := True;
    LWattHours := 0;
    for I := 0 to LPoints.Count - 1 do
      Result.PeakWatts := Max(Result.PeakWatts, LPoints[I].Value);
    for I := 1 to LPoints.Count - 1 do
    begin
      LHours := (LPoints[I].TimestampUtc - LPoints[I - 1].TimestampUtc) * HoursPerDay;
      if (LHours <= 0) or (LHours * 60 > AMaxGapMinutes) then
        Continue;
      LWattHours := LWattHours + (LPoints[I].Value + LPoints[I - 1].Value) / 2 * LHours;
      Result.CoveredHours := Result.CoveredHours + LHours;
    end;
    Result.KWh := LWattHours / 1000;
    if Result.CoveredHours > 0 then
      Result.AverageWatts := LWattHours / Result.CoveredHours
    else
    begin
      // Одно измерение: средняя мощность известна, энергия — нет.
      Result.AverageWatts := LPoints[0].Value;
      for I := 1 to LPoints.Count - 1 do
        Result.AverageWatts := Result.AverageWatts + LPoints[I].Value;
      Result.AverageWatts := Result.AverageWatts / LPoints.Count;
    end;
    Result.Cost := Max(0, Result.KWh * Max(0, APricePerKWh));
    Result.CostPerDay := MHEnergyCost(Result.AverageWatts, 24, APricePerKWh);
    Result.CostPerMonth := MHEnergyCost(Result.AverageWatts, 24 * 30, APricePerKWh);
  finally
    LPoints.Free;
  end;
end;

function MHFormatMoney(AValue: Double): string;
begin
  if IsNan(AValue) or IsInfinite(AValue) then
    AValue := 0;
  if Abs(AValue) < 100 then
    Result := FormatFloat('0.00', AValue) + ' ₽'
  else
    Result := FormatFloat('#,##0', AValue) + ' ₽';
end;

function MHFormatEnergy(AKWh: Double): string;
begin
  if IsNan(AKWh) or IsInfinite(AKWh) or (AKWh < 0) then
    AKWh := 0;
  if AKWh < 1 then
    Result := FormatFloat('0', AKWh * 1000) + MHL(' Вт·ч', ' Wh')
  else
    Result := FormatFloat('0.00', AKWh) + MHL(' кВт·ч', ' kWh');
end;

end.
