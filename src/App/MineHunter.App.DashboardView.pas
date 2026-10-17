unit MineHunter.App.DashboardView;

{
  Модель страницы «Обзор»: из снимка — карточки «Сейчас» (значение, пояснение,
  состояние) и упорядоченный список причин «почему тормозит или греется».

  Чистые функции без VCL, поэтому проверяются модульными тестами. Пороги
  состояний согласованы с MHExplainLoad (анализатор): «внимание» — там же, где
  причина считается высокой.
}

interface

uses
  MineHunter.Core.Types, MineHunter.Analysis.Engine;

type
  /// Состояние карточки или причины (цвет отметки в интерфейсе).
  TMHTileState = (tsNoData, tsOk, tsInfo, tsWarning, tsAlert);

  TMHTileKind = (tkCpu, tkMemory, tkDisk, tkNetwork, tkGpu, tkTemperature);

  TMHTileData = record
    Kind: TMHTileKind;
    Title: string;
    /// Крупное значение («21 %», «45 °C», «нет данных»).
    Value: string;
    /// Пояснение в одну-две строки.
    Detail: string;
    State: TMHTileState;
  end;

  TMHReasonItem = record
    Text: string;
    State: TMHTileState;
  end;

/// Карточки «Сейчас» в порядке tkCpu..tkTemperature.
function MHBuildDashboardTiles(const ASnapshot: TMHSnapshot): TArray<TMHTileData>;

/// Причины замедления и нагрева: сначала требующие внимания, затем остальные.
/// Пустой снимок — одна строка «данных ещё нет».
function MHBuildDashboardReasons(const ASnapshot: TMHSnapshot; ACpuCount: Integer): TArray<TMHReasonItem>;

/// Состояние по значению и порогам «внимание» / «тревога».
function MHStateByThresholds(AValue, AWarning, AAlert: Double): TMHTileState;

implementation

uses
  System.SysUtils, System.Math, System.StrUtils,
  MineHunter.App.Display, MineHunter.Core.Lang;

function MHStateByThresholds(AValue, AWarning, AAlert: Double): TMHTileState;
begin
  if AValue >= AAlert then
    Result := tsAlert
  else if AValue >= AWarning then
    Result := tsWarning
  else
    Result := tsOk;
end;

function Percent(AValue: Double): string;
begin
  Result := FormatFloat('0', AValue) + ' %';
end;

function Tile(AKind: TMHTileKind; const ATitle: string): TMHTileData;
begin
  Result.Kind := AKind;
  Result.Title := ATitle;
  Result.Value := MH_NO_DATA;
  Result.Detail := '';
  Result.State := tsNoData;
end;

function CpuTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LCpu, LFrequency, LLimit: TMHMetric;
  LParts: string;
begin
  Result := Tile(tkCpu, MHL('Процессор', 'CPU'));
  if not (ASnapshot.FindMetric(mkCpuPercent, LCpu) and LCpu.HasValue) then
    Exit;
  Result.Value := Percent(LCpu.Value);
  Result.State := MHStateByThresholds(LCpu.Value, 70, 90);
  LParts := '';
  if ASnapshot.FindMetric(mkCpuFrequencyPercent, LFrequency) and LFrequency.HasValue then
    LParts := Format(MHL('частота %s от базовой', 'frequency %s of base'), [Percent(LFrequency.Value)]);
  if ASnapshot.FindMetric(mkCpuPerformanceLimitPercent, LLimit) and LLimit.HasValue then
  begin
    if LLimit.Value < 90 then
    begin
      LParts := IfThen(LParts <> '', LParts + ' · ', '') +
        Format(MHL('троттлинг: ограничен до %s', 'throttling: limited to %s'), [Percent(LLimit.Value)]);
      if Result.State = tsOk then
        Result.State := tsWarning;
    end
    else
      LParts := IfThen(LParts <> '', LParts + ' · ', '') + MHL('без троттлинга', 'no throttling');
  end;
  Result.Detail := LParts;
end;

function MemoryTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LLoad, LUsed, LTotal: TMHMetric;
begin
  Result := Tile(tkMemory, MHL('Память', 'Memory'));
  if not (ASnapshot.FindMetric(mkMemoryLoadPercent, LLoad) and LLoad.HasValue) then
    Exit;
  Result.Value := Percent(LLoad.Value);
  Result.State := MHStateByThresholds(LLoad.Value, 85, 95);
  if ASnapshot.FindMetric(mkMemoryUsedBytes, LUsed) and LUsed.HasValue and
     ASnapshot.FindMetric(mkMemoryTotalBytes, LTotal) and LTotal.HasValue then
    Result.Detail := Format(MHL('занято %s из %s', '%s of %s used'), [MHFormatBytes(LUsed.Value), MHFormatBytes(LTotal.Value)]);
end;

function DiskTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LActive, LRead, LWrite: TMHMetric;
begin
  Result := Tile(tkDisk, MHL('Диск', 'Disk'));
  if not (ASnapshot.FindMetric(mkDiskActivePercent, LActive) and LActive.HasValue) then
    Exit;
  Result.Value := Percent(LActive.Value);
  // Занятый диск обычен при копировании и обновлениях — это «внимание», а не тревога.
  Result.State := MHStateByThresholds(LActive.Value, 80, 101);
  if ASnapshot.FindMetric(mkDiskReadBytesPerSec, LRead) and LRead.HasValue and
     ASnapshot.FindMetric(mkDiskWriteBytesPerSec, LWrite) and LWrite.HasValue then
    Result.Detail := Format(MHL('чтение %s/с · запись %s/с', 'read %s/s · write %s/s'), [MHFormatBytes(LRead.Value),
      MHFormatBytes(LWrite.Value)]);
end;

function NetworkTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LNetwork: TMHMetric;
begin
  Result := Tile(tkNetwork, MHL('Сеть', 'Network'));
  if not (ASnapshot.FindMetric(mkNetworkBytesPerSec, LNetwork) and LNetwork.HasValue) then
    Exit;
  Result.Value := MHFormatBytes(LNetwork.Value) + MHL('/с', '/s');
  Result.Detail := MHL('принято и отправлено', 'received and sent');
  Result.State := tsInfo;
end;

function GpuTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LGpu, LCompute, LMemory, LPower: TMHMetric;
  LParts: string;
begin
  Result := Tile(tkGpu, MHL('Видеокарта', 'GPU'));
  if not (ASnapshot.FindMetric(mkGpuPercent, LGpu) and LGpu.HasValue) then
    Exit;
  Result.Value := Percent(LGpu.Value);
  Result.State := MHStateByThresholds(LGpu.Value, 80, 95);
  LParts := '';
  if ASnapshot.FindMetric(mkGpuComputePercent, LCompute) and LCompute.HasValue then
    LParts := MHL('вычисления ', 'compute ') + Percent(LCompute.Value);
  if ASnapshot.FindMetric(mkGpuMemoryBytes, LMemory) and LMemory.HasValue then
    LParts := IfThen(LParts <> '', LParts + ' · ', '') + MHL('видеопамять ', 'video memory ') + MHFormatBytes(LMemory.Value);
  if ASnapshot.FindMetric(mkGpuPowerWatts, LPower) and LPower.HasValue then
    LParts := IfThen(LParts <> '', LParts + ' · ', '') + Format(MHL('%.0f Вт', '%.0f W'), [LPower.Value]);
  Result.Detail := LParts;
end;

function KindTitle(AKind: TMHSensorKind): string;
begin
  case AKind of
    skGpu: Result := MHL('видеокарта', 'GPU');
    skDisk: Result := MHL('накопители', 'drives');
  else
    Result := MHL('процессор', 'CPU');
  end;
end;

/// «у видеокарты», «у накопителя», «у процессора».
function KindGenitive(AKind: TMHSensorKind): string;
begin
  case AKind of
    skGpu: Result := MHL('у видеокарты', 'GPU');
    skDisk: Result := MHL('у накопителя', 'drive');
  else
    Result := MHL('у процессора', 'CPU');
  end;
end;

function TemperatureTile(const ASnapshot: TMHSnapshot): TMHTileData;
var
  LReading, LWorst: TMHSensorReading;
  LHasWorst: Boolean;
  LKind: TMHSensorKind;
  LMax, LLimit: Double;
  LCount: Integer;
  LParts, LTitle: string;
begin
  Result := Tile(tkTemperature, MHL('Температура', 'Temperature'));
  if Length(ASnapshot.Sensors) = 0 then
    Exit;
  // Главное значение — устройство, ближе всех подошедшее к своему порогу.
  LHasWorst := False;
  for LReading in ASnapshot.Sensors do
    if not LHasWorst or (LReading.Celsius - MHTemperatureLimit(LReading) >
       LWorst.Celsius - MHTemperatureLimit(LWorst)) then
    begin
      LWorst := LReading;
      LHasWorst := True;
    end;
  LLimit := MHTemperatureLimit(LWorst);
  Result.Value := Format('%.0f °C', [LWorst.Celsius]);
  if LWorst.Celsius >= LLimit then
    Result.State := tsAlert
  else if LWorst.Celsius >= LLimit - 5 then
    Result.State := tsWarning
  else
    Result.State := tsOk;
  // Пояснение: чьё значение показано и его порог, затем остальные устройства.
  LParts := Format(MHL('%s, порог %.0f °C', '%s, threshold %.0f °C'), [KindGenitive(LWorst.Kind), LLimit]);
  for LKind := Low(TMHSensorKind) to High(TMHSensorKind) do
  begin
    if LKind = LWorst.Kind then
      Continue;
    LMax := 0;
    LCount := 0;
    for LReading in ASnapshot.Sensors do
      if LReading.Kind = LKind then
      begin
        LMax := IfThen(LCount = 0, LReading.Celsius, Max(LMax, LReading.Celsius));
        Inc(LCount);
      end;
    LTitle := KindTitle(LKind);
    if LCount = 0 then
      Continue;
    if LCount > 1 then
      LParts := IfThen(LParts <> '', LParts + ' · ', '') + Format(MHL('%s до %.0f °C', '%s up to %.0f °C'), [LTitle, LMax])
    else
      LParts := IfThen(LParts <> '', LParts + ' · ', '') + Format('%s %.0f °C', [LTitle, LMax]);
  end;
  Result.Detail := LParts;
end;

function MHBuildDashboardTiles(const ASnapshot: TMHSnapshot): TArray<TMHTileData>;
begin
  Result := [CpuTile(ASnapshot), MemoryTile(ASnapshot), DiskTile(ASnapshot), NetworkTile(ASnapshot),
    GpuTile(ASnapshot), TemperatureTile(ASnapshot)];
end;

function MHBuildDashboardReasons(const ASnapshot: TMHSnapshot; ACpuCount: Integer): TArray<TMHReasonItem>;
var
  LReasons: TArray<TMHLoadReason>;
  LReason: TMHLoadReason;
  LItem: TMHReasonItem;
  LHigh, LNormal: TArray<TMHReasonItem>;
begin
  LReasons := MHExplainLoad(ASnapshot, ACpuCount);
  if Length(LReasons) = 0 then
  begin
    LItem.Text := MHL('Данных пока нет — первые значения появятся после второго опроса.',
      'No data yet — the first values will appear after the second poll.');
    LItem.State := tsNoData;
    Result := [LItem];
    Exit;
  end;
  LHigh := nil;
  LNormal := nil;
  for LReason in LReasons do
  begin
    LItem.Text := LReason.Text;
    if LReason.IsHigh then
    begin
      // Перегрев и троттлинг — тревога; высокая нагрузка — внимание.
      if LReason.Resource.StartsWith('heat') or (LReason.Resource = 'throttle') then
        LItem.State := tsAlert
      else
        LItem.State := tsWarning;
      LHigh := LHigh + [LItem];
    end
    else
    begin
      LItem.State := tsOk;
      LNormal := LNormal + [LItem];
    end;
  end;
  // Итог первой строкой: понятен без чтения всего списка.
  if Length(LHigh) = 0 then
  begin
    LItem.Text := MHL('Компьютер не перегружен: нагрузка и температуры в норме.',
      'The computer is not overloaded: load and temperatures are normal.');
    LItem.State := tsOk;
  end
  else
  begin
    LItem.Text := Format(MHL('Требует внимания: %d из %d показателей (отмечены ниже).',
      'Needs attention: %d of %d indicators (marked below).'),
      [Length(LHigh), Length(LHigh) + Length(LNormal)]);
    LItem.State := tsWarning;
  end;
  Result := [LItem] + LHigh + LNormal;
end;

end.
