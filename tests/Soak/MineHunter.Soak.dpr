program MineHunter.Soak;

{
  Длительный (soak) тест MineHunter X: реальные коллекторы, хранилище SQLite,
  анализатор и профиль нормы работают с ускоренным интервалом опроса.
  Раз в минуту фиксируются память, дескрипторы, число циклов и ошибки.

  Параметры:
    --cycles=N         сколько циклов выполнить (по умолчанию 14400 — это 8 ч
                       работы с обычным интервалом 2 с, требование ТЗ)
    --max-minutes=N    предельная длительность (по умолчанию 120)
    --interval=MS      интервал опроса (по умолчанию 250 — в 8 раз чаще обычного)
    --report=PATH      файл отчёта Markdown (по умолчанию reports\soak-report.md рядом с exe)
    --rebuild-every=N  дополнительно перестраивать профиль нормы каждые N минут
                       (0 — только по расписанию приложения, раз в час)

  Критерии (ТЗ, раздел 9): выполнено заданное число циклов, ни одного сбоя
  цикла или обработчика, рост частной памяти после прогрева < 30 МБ, рост
  числа дескрипторов < 100. Код возврата 0 — пройдено, 1 — не пройдено.
  Прогрев — WARMUP_MINUTES: за это время заполняются ограниченные буферы
  (окно истории анализатора — 30 мин, кэш страниц SQLite), и рост после него
  указывает на утечку, а не на штатное заполнение. Короткий прогон — с 5-й минуты.
  История и настройки — во временном каталоге (данные пользователя не трогаются).
}

{$APPTYPE CONSOLE}

uses
  System.SysUtils, System.Classes, System.IOUtils, System.SyncObjs, System.Math,
  Winapi.Windows, Winapi.PsAPI,
  MineHunter.Core.Types in '..\..\src\Core\MineHunter.Core.Types.pas',
  MineHunter.Core.Interfaces in '..\..\src\Core\MineHunter.Core.Interfaces.pas',
  MineHunter.Core.Scanner in '..\..\src\Core\MineHunter.Core.Scanner.pas',
  MineHunter.App.Bootstrap in '..\..\src\App\MineHunter.App.Bootstrap.pas';

const
  WARMUP_MINUTES = 35;

type
  TSample = record
    Minute: Integer;
    Cycles: Integer;
    PrivateMB: Double;
    HeapMB: Double;
    Handles: Cardinal;
    Errors: Integer;
    Findings: Integer;
    HistoryPoints: Integer;
  end;

function ArgValue(const AName, ADefault: string): string;
var
  I: Integer;
begin
  for I := 1 to ParamCount do
    if ParamStr(I).StartsWith('--' + AName + '=', True) then
      Exit(Copy(ParamStr(I), Length(AName) + 4, MaxInt));
  Result := ADefault;
end;

function PrivateMB: Double;
var
  LCounters: TProcessMemoryCountersEx;
begin
  FillChar(LCounters, SizeOf(LCounters), 0);
  LCounters.cb := SizeOf(LCounters);
  if GetProcessMemoryInfo(GetCurrentProcess, PPROCESS_MEMORY_COUNTERS(@LCounters), SizeOf(LCounters)) then
    Result := LCounters.PrivateUsage / 1048576
  else
    Result := 0;
end;

/// Память, занятая объектами Delphi (без блоков, удерживаемых менеджером памяти).
function HeapMB: Double;
var
  LState: TMemoryManagerState;
  LBytes: Int64;
  I: Integer;
begin
  {$WARN SYMBOL_PLATFORM OFF}
  GetMemoryManagerState(LState);
  {$WARN SYMBOL_PLATFORM ON}
  LBytes := Int64(LState.TotalAllocatedMediumBlockSize) + Int64(LState.TotalAllocatedLargeBlockSize);
  for I := Low(LState.SmallBlockTypeStates) to High(LState.SmallBlockTypeStates) do
    Inc(LBytes, Int64(LState.SmallBlockTypeStates[I].AllocatedBlockCount) *
      LState.SmallBlockTypeStates[I].UseableBlockSize);
  Result := LBytes / 1048576;
end;

function HandleCount: Cardinal;
begin
  if not GetProcessHandleCount(GetCurrentProcess, Result) then
    Result := 0;
end;

/// Сбои цикла сканирования и обработчиков событий (журнал источника «scanner»).
function ErrorCount(const AServices: TMHAppServices): Integer;
var
  LEntry: TMHLogEntry;
begin
  Result := 0;
  for LEntry in AServices.LogReader.Entries do
    if (LEntry.Level = llError) and SameText(LEntry.Source, 'scanner') then
      Inc(Result);
end;

function FileTimeTo100ns(const ATime: TFileTime): UInt64;
begin
  Result := (UInt64(ATime.dwHighDateTime) shl 32) or ATime.dwLowDateTime;
end;

var
  LMaxMinutes, LTargetCycles, LIntervalMs, LMinute, LWarmupIndex, LRebuildEvery, LRebuilds: Integer;
  LReportPath, LTempDir: string;
  LServices: TMHAppServices;
  LOptions: TMHScannerOptions;
  LCycles, LFindingsTotal: Integer;
  LSamples: TArray<TSample>;
  LSample: TSample;
  LReport: TStringList;
  LMemGrowth, LCpuPercent: Double;
  LHandleGrowth: Integer;
  LPassed: Boolean;
  LStarted: TDateTime;
  LKernel, LUser, LCreation, LExit: TFileTime;
  LWallMs: UInt64;
  LInfo: TSystemInfo;
begin
  LTargetCycles := StrToIntDef(ArgValue('cycles', '14400'), 14400);
  LMaxMinutes := StrToIntDef(ArgValue('max-minutes', '120'), 120);
  LIntervalMs := StrToIntDef(ArgValue('interval', '250'), 250);
  LRebuildEvery := Max(0, StrToIntDef(ArgValue('rebuild-every', '0'), 0));
  LRebuilds := 0;
  LReportPath := TPath.GetFullPath(ArgValue('report',
    TPath.Combine(ExtractFilePath(ParamStr(0)), 'reports\soak-report.md')));
  LTempDir := TPath.Combine(TPath.GetTempPath, 'MineHunterSoak-' + FormatDateTime('yyyymmdd-hhnnss', Now));
  ForceDirectories(LTempDir);
  TMHAppServices.DefaultHistoryPath := TPath.Combine(LTempDir, 'history.db');
  TMHAppServices.DefaultSettingsPath := '-';
  LCycles := 0;
  LFindingsTotal := 0;
  ExitCode := 1;
  try
    LServices := TMHAppServices.CreateDefault;
    try
      LOptions := LServices.Scanner.Options;
      LOptions.IntervalMs := LIntervalMs;
      LOptions.EventDispatch := edWorkerThread;
      LServices.Scanner.Options := LOptions;
      LServices.Scanner.OnCycle :=
        procedure(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings)
        begin
          TInterlocked.Increment(LCycles);
          TInterlocked.Add(LFindingsTotal, Length(AFindings));
        end;
      LStarted := Now;
      LServices.Scanner.Start;
      Writeln(Format('Soak: цель %d циклов, интервал %d мс, база %s', [LTargetCycles, LIntervalMs, LTempDir]));
      LMinute := 0;
      while (LMinute < LMaxMinutes) and (TInterlocked.CompareExchange(LCycles, 0, 0) < LTargetCycles) do
      begin
        Sleep(60 * 1000);
        Inc(LMinute);
        if (LRebuildEvery > 0) and (LMinute mod LRebuildEvery = 0) and
           (LServices.BaselineScheduler <> nil) then
        begin
          LServices.BaselineScheduler.RequestRebuild;
          Inc(LRebuilds);
        end;
        LSample.Minute := LMinute;
        LSample.Cycles := TInterlocked.CompareExchange(LCycles, 0, 0);
        LSample.PrivateMB := PrivateMB;
        LSample.HeapMB := HeapMB;
        LSample.Handles := HandleCount;
        LSample.Errors := ErrorCount(LServices);
        LSample.Findings := TInterlocked.CompareExchange(LFindingsTotal, 0, 0);
        LSample.HistoryPoints := -1;
        if LServices.Analyzer <> nil then
          LSample.HistoryPoints := LServices.Analyzer.TotalSamples;
        LSamples := LSamples + [LSample];
        Writeln(Format('%3d мин: циклов %d, память %.1f МБ (куча %.1f МБ), дескрипторов %d, ошибок %d, точек истории %d',
          [LMinute, LSample.Cycles, LSample.PrivateMB, LSample.HeapMB, LSample.Handles, LSample.Errors,
           LSample.HistoryPoints]));
      end;
      LServices.Scanner.Stop;
      LWallMs := Round((Now - LStarted) * MSecsPerDay);
      GetProcessTimes(GetCurrentProcess, LCreation, LExit, LKernel, LUser);
      GetSystemInfo(LInfo);
      // Доля CPU всей машины за время теста (ядро + пользователь, с учётом запуска).
      LCpuPercent := 0;
      if LWallMs > 0 then
        LCpuPercent := (FileTimeTo100ns(LKernel) + FileTimeTo100ns(LUser)) / 10000 / LWallMs * 100 /
          Max(1, LInfo.dwNumberOfProcessors);

      // Прогрев — до WARMUP_MINUTES, если прогон длиннее; иначе до 5-й минуты.
      if Length(LSamples) > WARMUP_MINUTES + 5 then
        LWarmupIndex := WARMUP_MINUTES - 1
      else
        LWarmupIndex := Min(4, High(LSamples));
      LMemGrowth := LSamples[High(LSamples)].PrivateMB - LSamples[LWarmupIndex].PrivateMB;
      LHandleGrowth := Integer(LSamples[High(LSamples)].Handles) - Integer(LSamples[LWarmupIndex].Handles);
      LPassed := (LSamples[High(LSamples)].Errors = 0) and (LMemGrowth < 30) and (LHandleGrowth < 100) and
        (LSamples[High(LSamples)].Cycles >= LTargetCycles);

      LReport := TStringList.Create;
      try
        LReport.Add('# Soak-тест MineHunter X');
        LReport.Add('');
        LReport.Add(Format('Дата: %s. Длительность: %d мин, интервал опроса %d мс (обычный интервал — 2000 мс).',
          [FormatDateTime('dd.mm.yyyy hh:nn', LStarted), LMinute, LIntervalMs]));
        LReport.Add(Format('Циклов выполнено: %d из %d — эквивалент %.1f ч работы с обычным интервалом 2 с.',
          [LSamples[High(LSamples)].Cycles, LTargetCycles, LSamples[High(LSamples)].Cycles * 2 / 3600]));
        LReport.Add('Работали реальные коллекторы (процессы, система, автозапуск, сеть, файлы, контекст), ' +
          'хранилище SQLite и анализатор угроз.');
        LReport.Add(Format('Средняя нагрузка процесса теста: %.2f%% CPU машины (%d логических CPU) ' +
          'при ускоренном в %.0f раз опросе.', [LCpuPercent, LInfo.dwNumberOfProcessors, 2000 / LIntervalMs]));
        if LRebuildEvery > 0 then
          LReport.Add(Format('Дополнительные перестройки профиля нормы: каждые %d мин (запрошено %d) — ' +
            'проверка, что перестройка не наращивает память.', [LRebuildEvery, LRebuilds]));
        LReport.Add('');
        LReport.Add('| Минута | Циклов | Частная память, МБ | Куча Delphi, МБ | Дескрипторов | Ошибок цикла | Находок (сумма) | Точек истории анализатора |');
        LReport.Add('|---|---|---|---|---|---|---|---|');
        for LSample in LSamples do
          LReport.Add(Format('| %d | %d | %.1f | %.1f | %d | %d | %d | %d |', [LSample.Minute, LSample.Cycles,
            LSample.PrivateMB, LSample.HeapMB, LSample.Handles, LSample.Errors, LSample.Findings,
            LSample.HistoryPoints]));
        LReport.Add('');
        LReport.Add(Format('Рост памяти после прогрева (с %d-й минуты): %.1f МБ (порог 30). ' +
          'Рост дескрипторов: %d (порог 100). Ошибок цикла: %d.',
          [LSamples[LWarmupIndex].Minute, LMemGrowth, LHandleGrowth, LSamples[High(LSamples)].Errors]));
        if LPassed then
          LReport.Add('**Итог: пройдено.**')
        else
          LReport.Add('**Итог: НЕ пройдено.**');
        if ExtractFileDir(LReportPath) <> '' then
          ForceDirectories(ExtractFileDir(LReportPath));
        LReport.SaveToFile(LReportPath, TEncoding.UTF8);
        Writeln(LReport.Text);
      finally
        LReport.Free;
      end;
    finally
      LServices.Free;
    end;
    if LPassed then
      ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln('Сбой soak-теста: ', E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
  try
    TDirectory.Delete(LTempDir, True);
  except
    // Временный каталог теста; ошибка удаления не влияет на результат.
  end;
end.
