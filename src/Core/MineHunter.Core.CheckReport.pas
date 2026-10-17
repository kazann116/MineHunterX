unit MineHunter.Core.CheckReport;

{
  Отчёт кнопки «Проверить сейчас»: понятный итог полной проверки —
  тревоги с объяснением, причины нагрузки и нагрева, что изменилось за
  неделю, оценка расхода электроэнергии и ограничения самой проверки.
  Чистая функция: одинаковые входные данные дают одинаковый текст.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Inventory, MineHunter.Core.Energy;

type
  TMHCheckVerdict = (cvClean, cvAttention, cvThreat);

  TMHCheckReportInput = record
    Snapshot: TMHSnapshot;
    Findings: TMHFindings;
    CpuCount: Integer;
    /// Учёт изменений доступен (есть история).
    ChangesAvailable: Boolean;
    Changes: TArray<TMHInventoryItem>;
    ChangesDays: Integer;
    InventoryStartUtc: TDateTime;
    /// Оценка энергии видеокарты за последние сутки (HasData = False — нет датчика).
    Energy: TMHEnergyEstimate;
    ElectricityPrice: Double;
    IsElevated: Boolean;
  end;

  TMHCheckReport = record
    Verdict: TMHCheckVerdict;
    Headline: string;
    Text: string;
    AlertCount: Integer;
  end;

function MHBuildCheckReport(const AInput: TMHCheckReportInput): TMHCheckReport;

implementation

uses
  System.Math, System.Generics.Collections, System.Generics.Defaults, System.DateUtils,
  MineHunter.Analysis.Engine;

function LocalTime(AUtc: TDateTime): string;
begin
  Result := FormatDateTime('dd.mm.yyyy hh:nn', TTimeZone.Local.ToLocalTime(AUtc));
end;

function MetricText(const ASnapshot: TMHSnapshot; AKind: TMHMetricKind; out AValue: Double): Boolean;
var
  LMetric: TMHMetric;
begin
  Result := ASnapshot.FindMetric(AKind, LMetric) and LMetric.HasValue;
  if Result then
    AValue := LMetric.Value
  else
    AValue := 0;
end;

function MHBuildCheckReport(const AInput: TMHCheckReportInput): TMHCheckReport;
var
  LText: TStringBuilder;
  LAlerts: TList<TMHFinding>;
  LFinding: TMHFinding;
  LEvidence: TMHEvidence;
  LReason: TMHLoadReason;
  LReading: TMHSensorReading;
  LItem: TMHInventoryItem;
  LStatus: TMHSourceStatus;
  LValue, LLimit: Double;
  LHigh, LShown, LKindCount: Integer;
  LKind: TMHInventoryKind;
  LLine: string;
  LAnyLimit: Boolean;
begin
  Result := Default(TMHCheckReport);
  LText := TStringBuilder.Create;
  LAlerts := TList<TMHFinding>.Create;
  try
    for LFinding in AInput.Findings do
      if LFinding.Level >= rlNeedsReview then
        LAlerts.Add(LFinding);
    LAlerts.Sort(TComparer<TMHFinding>.Construct(
      function(const A, B: TMHFinding): Integer
      begin
        Result := CompareValue(Ord(B.Level), Ord(A.Level));
        if Result = 0 then
          Result := CompareValue(B.Score, A.Score);
        if Result = 0 then
          Result := CompareText(A.Key, B.Key);
      end));
    LHigh := 0;
    for LFinding in LAlerts do
      if LFinding.Level >= rlSuspicious then
        Inc(LHigh);
    Result.AlertCount := LAlerts.Count;
    if LHigh > 0 then
    begin
      Result.Verdict := cvThreat;
      Result.Headline := Format('Найдены признаки угрозы: %d (всего требуют проверки — %d)', [LHigh, LAlerts.Count]);
    end
    else if LAlerts.Count > 0 then
    begin
      Result.Verdict := cvAttention;
      Result.Headline := Format('Угроз не найдено, но %d объект(а) стоит проверить', [LAlerts.Count]);
    end
    else
    begin
      Result.Verdict := cvClean;
      Result.Headline := 'Угроз не обнаружено';
    end;

    LText.AppendLine('ПРОВЕРКА MINEHUNTER X — ' + LocalTime(AInput.Snapshot.TimestampUtc));
    LText.AppendLine('ИТОГ: ' + Result.Headline + '.');
    LText.AppendLine('Высокая нагрузка или отсутствие подписи сами по себе не доказывают заражение: ' +
      'каждая оценка ниже объяснена признаками.');
    LText.AppendLine;

    // 1. Тревоги.
    LText.AppendLine('1. ТРЕВОГИ');
    if LAlerts.Count = 0 then
      LText.AppendLine('   Нет находок уровня «требует проверки» и выше.')
    else
      for LFinding in LAlerts do
      begin
        LLine := Format('   • [%s, %d/100] %s', [MHRiskLevelToString(LFinding.Level), LFinding.Score, LFinding.Title]);
        if LFinding.ProcessName <> '' then
          LLine := LLine + ' — ' + LFinding.ProcessName;
        LText.AppendLine(LLine);
        if LFinding.ImagePath <> '' then
          LText.AppendLine('     Файл: ' + LFinding.ImagePath);
        LShown := 0;
        for LEvidence in LFinding.PositiveEvidence do
        begin
          if LShown = 3 then
            Break;
          LLine := '     + ' + LEvidence.Description;
          if LEvidence.Observed <> '' then
            LLine := LLine + ' (' + LEvidence.Observed + ')';
          LText.AppendLine(LLine);
          Inc(LShown);
        end;
        for LEvidence in LFinding.NegativeEvidence do
        begin
          LText.AppendLine('     − ' + LEvidence.Description);
          Break;
        end;
        if Length(LFinding.Recommendations) > 0 then
          LText.AppendLine('     Что сделать: ' + LFinding.Recommendations[0]);
      end;
    LText.AppendLine;

    // 2. Нагрузка и нагрев.
    LText.AppendLine('2. ПОЧЕМУ КОМПЬЮТЕР МОЖЕТ ТОРМОЗИТЬ ИЛИ ГРЕТЬСЯ');
    LLine := '   Сейчас:';
    if MetricText(AInput.Snapshot, mkCpuPercent, LValue) then
      LLine := LLine + Format(' процессор %.0f%%;', [LValue]);
    if MetricText(AInput.Snapshot, mkMemoryLoadPercent, LValue) then
      LLine := LLine + Format(' память %.0f%%;', [LValue]);
    if MetricText(AInput.Snapshot, mkDiskActivePercent, LValue) then
      LLine := LLine + Format(' диск %.0f%%;', [LValue]);
    if MetricText(AInput.Snapshot, mkGpuPercent, LValue) then
      LLine := LLine + Format(' видеокарта %.0f%%;', [LValue]);
    LText.AppendLine(LLine);
    for LReason in MHExplainLoad(AInput.Snapshot, Max(1, AInput.CpuCount)) do
      if LReason.IsHigh then
        LText.AppendLine('   ⚠ ' + LReason.Text)
      else
        LText.AppendLine('   • ' + LReason.Text);
    if MetricText(AInput.Snapshot, mkCpuPerformanceLimitPercent, LValue) and (LValue < 95) then
      LText.AppendLine(Format('   ⚠ Процессор ограничивает производительность до %.0f%% — обычно из-за ' +
        'перегрева или режима питания.', [LValue]));
    LAnyLimit := False;
    for LReading in AInput.Snapshot.Sensors do
    begin
      LLimit := MHTemperatureLimit(LReading);
      LLine := Format('   Температура: %s — %.0f °C', [LReading.Device, LReading.Celsius]);
      if (LLimit > 0) and (LReading.Celsius >= LLimit) then
      begin
        LLine := LLine + Format(' (выше порога %.0f °C — устройство перегревается)', [LLimit]);
        LAnyLimit := True;
      end
      else if LLimit > 0 then
        LLine := LLine + Format(' (порог %.0f °C)', [LLimit]);
      LText.AppendLine(LLine);
    end;
    if Length(AInput.Snapshot.Sensors) = 0 then
      LText.AppendLine('   Температура: датчики недоступны без драйвера производителя ' +
        '(см. «Источники данных»).')
    else if not LAnyLimit then
      LText.AppendLine('   Перегрева не обнаружено.');
    LText.AppendLine;

    // 3. Что изменилось.
    LText.AppendLine(Format('3. ЧТО ИЗМЕНИЛОСЬ ЗА %d ДН.', [Max(1, AInput.ChangesDays)]));
    if not AInput.ChangesAvailable then
      LText.AppendLine('   История недоступна — изменения не отслеживаются.')
    else if Length(AInput.Changes) = 0 then
    begin
      LText.AppendLine('   Новых записей автозапуска, признаков вмешательства и программ не появилось.');
      if AInput.InventoryStartUtc > 0 then
        LText.AppendLine('   Наблюдение ведётся с ' + LocalTime(AInput.InventoryStartUtc) + '.');
    end
    else
      for LKind := Low(TMHInventoryKind) to High(TMHInventoryKind) do
      begin
        LKindCount := 0;
        for LItem in AInput.Changes do
          if LItem.Kind = LKind then
            Inc(LKindCount);
        if LKindCount = 0 then
          Continue;
        LText.AppendLine(Format('   %s: %d', [MHInventoryKindTitle(LKind), LKindCount]));
        LShown := 0;
        for LItem in AInput.Changes do
          if LItem.Kind = LKind then
          begin
            if LShown = 10 then
            begin
              LText.AppendLine(Format('     … и ещё %d (полный список — на странице «История»)', [LKindCount - LShown]));
              Break;
            end;
            LLine := '     ' + LocalTime(LItem.FirstSeenUtc) + '  ' + LItem.Name;
            if LItem.Details <> '' then
              LLine := LLine + ' — ' + LItem.Details
            else if LItem.ImagePath <> '' then
              LLine := LLine + ' — ' + LItem.ImagePath;
            LText.AppendLine(LLine);
            Inc(LShown);
          end;
      end;
    LText.AppendLine;

    // 4. Электроэнергия.
    LText.AppendLine('4. ЭЛЕКТРОЭНЕРГИЯ (ВИДЕОКАРТА)');
    if MetricText(AInput.Snapshot, mkGpuPowerWatts, LValue) then
      LText.AppendLine(Format('   Сейчас: %.0f Вт — %s в час, %s в сутки при такой нагрузке (цена %s за кВт·ч).',
        [LValue, MHFormatMoney(MHEnergyCost(LValue, 1, AInput.ElectricityPrice)),
         MHFormatMoney(MHEnergyCost(LValue, 24, AInput.ElectricityPrice)), MHFormatMoney(AInput.ElectricityPrice)]))
    else
      LText.AppendLine('   Видеокарта не сообщает мощность (датчик есть у видеокарт NVIDIA через драйвер).');
    if AInput.Energy.HasData and (AInput.Energy.CoveredHours > 0) then
      LText.AppendLine(Format('   За последние сутки (измерено %.1f ч): %s ≈ %s; в среднем %.0f Вт, пик %.0f Вт. ' +
        'Скрытый майнер на видеокарте обычно добавляет 100–300 Вт.',
        [AInput.Energy.CoveredHours, MHFormatEnergy(AInput.Energy.KWh), MHFormatMoney(AInput.Energy.Cost),
         AInput.Energy.AverageWatts, AInput.Energy.PeakWatts]));
    LText.AppendLine;

    // 5. Ограничения.
    LText.AppendLine('5. ОГРАНИЧЕНИЯ ПРОВЕРКИ');
    LShown := 0;
    for LStatus in AInput.Snapshot.Sources do
      if LStatus.State in [ssUnavailable, ssError, ssPartial] then
      begin
        LLine := Format('   • %s: %s', [LStatus.SourceId, MHSourceStateToString(LStatus.State)]);
        if LStatus.Message <> '' then
          LLine := LLine + ' — ' + LStatus.Message;
        LText.AppendLine(LLine);
        Inc(LShown);
      end;
    if LShown = 0 then
      LText.AppendLine('   Все источники данных работают.');
    if not AInput.IsElevated then
      LText.AppendLine('   Запуск от имени администратора даст полные данные о службах, ' +
        'защищённых процессах и сетевых соединениях.');
    LText.AppendLine;
    LText.AppendLine('MineHunter X ничего не удаляет и не останавливает без вашего подтверждения. ' +
      'Анализ выполнен локально, данные никуда не передавались.');
    Result.Text := LText.ToString;
  finally
    LAlerts.Free;
    LText.Free;
  end;
end;

end.
