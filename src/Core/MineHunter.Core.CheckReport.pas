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
  MineHunter.Analysis.Engine, MineHunter.Core.Lang;

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
      Result.Headline := Format(MHL('Найдены признаки угрозы: %d (всего требуют проверки — %d)',
        'Signs of a threat found: %d (total needing review — %d)'), [LHigh, LAlerts.Count]);
    end
    else if LAlerts.Count > 0 then
    begin
      Result.Verdict := cvAttention;
      Result.Headline := Format(MHL('Угроз не найдено, но %d объект(а) стоит проверить',
        'No threats found, but %d item(s) are worth reviewing'), [LAlerts.Count]);
    end
    else
    begin
      Result.Verdict := cvClean;
      Result.Headline := MHL('Угроз не обнаружено', 'No threats detected');
    end;

    LText.AppendLine(MHL('ПРОВЕРКА MINEHUNTER X — ', 'MINEHUNTER X CHECK — ') + LocalTime(AInput.Snapshot.TimestampUtc));
    LText.AppendLine(MHL('ИТОГ: ', 'RESULT: ') + Result.Headline + '.');
    LText.AppendLine(MHL('Высокая нагрузка или отсутствие подписи сами по себе не доказывают заражение: ',
      'High load or a missing signature alone do not prove an infection: ') +
      MHL('каждая оценка ниже объяснена признаками.', 'every assessment below is explained by evidence.'));
    LText.AppendLine;

    // 1. Тревоги.
    LText.AppendLine(MHL('1. ТРЕВОГИ', '1. ALERTS'));
    if LAlerts.Count = 0 then
      LText.AppendLine(MHL('   Нет находок уровня «требует проверки» и выше.',
        '   No findings at the "needs review" level or above.'))
    else
      for LFinding in LAlerts do
      begin
        LLine := Format('   • [%s, %d/100] %s', [MHRiskLevelToString(LFinding.Level), LFinding.Score, LFinding.Title]);
        if LFinding.ProcessName <> '' then
          LLine := LLine + ' — ' + LFinding.ProcessName;
        LText.AppendLine(LLine);
        if LFinding.ImagePath <> '' then
          LText.AppendLine(MHL('     Файл: ', '     File: ') + LFinding.ImagePath);
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
          LText.AppendLine(MHL('     Что сделать: ', '     What to do: ') + LFinding.Recommendations[0]);
      end;
    LText.AppendLine;

    // 2. Нагрузка и нагрев.
    LText.AppendLine(MHL('2. ПОЧЕМУ КОМПЬЮТЕР МОЖЕТ ТОРМОЗИТЬ ИЛИ ГРЕТЬСЯ', '2. WHY THE COMPUTER MAY BE SLOW OR HOT'));
    LLine := MHL('   Сейчас:', '   Now:');
    if MetricText(AInput.Snapshot, mkCpuPercent, LValue) then
      LLine := LLine + Format(MHL(' процессор %.0f%%;', ' CPU %.0f%%;'), [LValue]);
    if MetricText(AInput.Snapshot, mkMemoryLoadPercent, LValue) then
      LLine := LLine + Format(MHL(' память %.0f%%;', ' memory %.0f%%;'), [LValue]);
    if MetricText(AInput.Snapshot, mkDiskActivePercent, LValue) then
      LLine := LLine + Format(MHL(' диск %.0f%%;', ' disk %.0f%%;'), [LValue]);
    if MetricText(AInput.Snapshot, mkGpuPercent, LValue) then
      LLine := LLine + Format(MHL(' видеокарта %.0f%%;', ' GPU %.0f%%;'), [LValue]);
    LText.AppendLine(LLine);
    for LReason in MHExplainLoad(AInput.Snapshot, Max(1, AInput.CpuCount)) do
      if LReason.IsHigh then
        LText.AppendLine('   ⚠ ' + LReason.Text)
      else
        LText.AppendLine('   • ' + LReason.Text);
    if MetricText(AInput.Snapshot, mkCpuPerformanceLimitPercent, LValue) and (LValue < 95) then
      LText.AppendLine(Format(MHL('   ⚠ Процессор ограничивает производительность до %.0f%% — обычно из-за ',
        '   ⚠ The CPU limits its performance to %.0f%% — usually due to ') +
        MHL('перегрева или режима питания.', 'overheating or the power plan.'), [LValue]));
    LAnyLimit := False;
    for LReading in AInput.Snapshot.Sensors do
    begin
      LLimit := MHTemperatureLimit(LReading);
      LLine := Format(MHL('   Температура: %s — %.0f °C', '   Temperature: %s — %.0f °C'), [LReading.Device, LReading.Celsius]);
      if (LLimit > 0) and (LReading.Celsius >= LLimit) then
      begin
        LLine := LLine + Format(MHL(' (выше порога %.0f °C — устройство перегревается)',
          ' (above the %.0f °C threshold — the device is overheating)'), [LLimit]);
        LAnyLimit := True;
      end
      else if LLimit > 0 then
        LLine := LLine + Format(MHL(' (порог %.0f °C)', ' (threshold %.0f °C)'), [LLimit]);
      LText.AppendLine(LLine);
    end;
    if Length(AInput.Snapshot.Sensors) = 0 then
      LText.AppendLine(MHL('   Температура: датчики недоступны без драйвера производителя ',
        '   Temperature: sensors are unavailable without the vendor driver ') +
        MHL('(см. «Источники данных»).', '(see "Data sources").'))
    else if not LAnyLimit then
      LText.AppendLine(MHL('   Перегрева не обнаружено.', '   No overheating detected.'));
    LText.AppendLine;

    // 3. Что изменилось.
    LText.AppendLine(Format(MHL('3. ЧТО ИЗМЕНИЛОСЬ ЗА %d ДН.', '3. WHAT CHANGED IN %d DAY(S)'), [Max(1, AInput.ChangesDays)]));
    if not AInput.ChangesAvailable then
      LText.AppendLine(MHL('   История недоступна — изменения не отслеживаются.',
        '   History is unavailable — changes are not tracked.'))
    else if Length(AInput.Changes) = 0 then
    begin
      LText.AppendLine(MHL('   Новых записей автозапуска, признаков вмешательства и программ не появилось.',
        '   No new autostart entries, tampering signs or programs have appeared.'));
      if AInput.InventoryStartUtc > 0 then
        LText.AppendLine(MHL('   Наблюдение ведётся с ', '   Monitoring since ') + LocalTime(AInput.InventoryStartUtc) + '.');
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
              LText.AppendLine(Format(MHL('     … и ещё %d (полный список — на странице «История»)',
                '     … and %d more (full list on the "History" page)'), [LKindCount - LShown]));
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
    LText.AppendLine(MHL('4. ЭЛЕКТРОЭНЕРГИЯ (ВИДЕОКАРТА)', '4. ELECTRICITY (GPU)'));
    if MetricText(AInput.Snapshot, mkGpuPowerWatts, LValue) then
      LText.AppendLine(Format(MHL('   Сейчас: %.0f Вт — %s в час, %s в сутки при такой нагрузке (цена %s за кВт·ч).',
        '   Now: %.0f W — %s per hour, %s per day at this load (price %s per kWh).'),
        [LValue, MHFormatMoney(MHEnergyCost(LValue, 1, AInput.ElectricityPrice)),
         MHFormatMoney(MHEnergyCost(LValue, 24, AInput.ElectricityPrice)), MHFormatMoney(AInput.ElectricityPrice)]))
    else
      LText.AppendLine(MHL('   Видеокарта не сообщает мощность (датчик есть у видеокарт NVIDIA через драйвер).',
        '   The GPU does not report its power draw (NVIDIA GPUs provide this sensor via the driver).'));
    if AInput.Energy.HasData and (AInput.Energy.CoveredHours > 0) then
      LText.AppendLine(Format(MHL('   За последние сутки (измерено %.1f ч): %s ≈ %s; в среднем %.0f Вт, пик %.0f Вт. ',
        '   Over the last 24 hours (measured %.1f h): %s ≈ %s; average %.0f W, peak %.0f W. ') +
        MHL('Скрытый майнер на видеокарте обычно добавляет 100–300 Вт.',
        'A hidden GPU miner usually adds 100–300 W.'),
        [AInput.Energy.CoveredHours, MHFormatEnergy(AInput.Energy.KWh), MHFormatMoney(AInput.Energy.Cost),
         AInput.Energy.AverageWatts, AInput.Energy.PeakWatts]));
    LText.AppendLine;

    // 5. Ограничения.
    LText.AppendLine(MHL('5. ОГРАНИЧЕНИЯ ПРОВЕРКИ', '5. CHECK LIMITATIONS'));
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
      LText.AppendLine(MHL('   Все источники данных работают.', '   All data sources are working.'));
    if not AInput.IsElevated then
      LText.AppendLine(MHL('   Запуск от имени администратора даст полные данные о службах, ',
        '   Running as administrator gives complete data on services, ') +
        MHL('защищённых процессах и сетевых соединениях.', 'protected processes and network connections.'));
    LText.AppendLine;
    LText.AppendLine(MHL('MineHunter X ничего не удаляет и не останавливает без вашего подтверждения. ',
      'MineHunter X does not delete or stop anything without your confirmation. ') +
      MHL('Анализ выполнен локально, данные никуда не передавались.',
      'The analysis was performed locally; no data was sent anywhere.'));
    Result.Text := LText.ToString;
  finally
    LAlerts.Free;
    LText.Free;
  end;
end;

end.
