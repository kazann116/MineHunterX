# MineHunter X — публичный API библиотеки

Библиотека (`src/Core`, `src/Storage`) не зависит от VCL и может использоваться без интерфейса
(служба, консольная утилита, другое приложение). Все модели — записи (`record`), время — UTC.

## Быстрый старт

```pascal
uses
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Scanner,
  MineHunter.App.Bootstrap;

var
  LServices: TMHAppServices;
begin
  LServices := TMHAppServices.CreateDefault;   // все коллекторы, SQLite, анализатор, норма
  try
    LServices.Scanner.OnCycle :=
      procedure(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings)
      var
        LFinding: TMHFinding;
      begin
        for LFinding in AFindings do
          Writeln(LFinding.Title, ' — ', MHRiskLevelToString(LFinding.Level));
      end;
    LServices.Scanner.ScanOnce;                 // синхронный цикл
    // или LServices.Scanner.Start / Stop — фоновый опрос
  finally
    LServices.Free;
  end;
end;
```

## Контракты (`MineHunter.Core.Interfaces`)

| Интерфейс | Назначение |
|---|---|
| `IMHCollector.Collect(const ASnapshot): TMHCollectionResult` | Единый контракт источника данных. Не мутирует снимок; возвращает статус (`ssSuccess / ssPartial / ssUnavailable / ssError` + пояснение) и свои данные. Штатные отказы — через статус, без исключений. |
| `IMHAnalyzer.Analyze(const ASnapshot; const ABaseline): TMHFindings` | Детерминированный анализ: одинаковая последовательность снимков → одинаковые находки. |
| `IMHRepository.SaveSnapshot / LoadHistory` | Хранение истории без привязки к GUI. |
| `IMHMetricHistory` | Ряды для графиков (`LoadMetricSeries`, `LoadProcessSeries`), статистика, `Clear`. |
| `IMHFindingHistory` | История находок с объединением повторов по `TMHFinding.Key`. |
| `IMHActionLog` | Журнал изменяющих действий (MH-10). |
| `IMHBaselineProvider.BaselineFor(AContext)` | Профиль нормы для контекста работы (простой / работа / игра). |
| `IMHClock`, `IMHLogger`, `IMHLogReader` | Время (для детерминированных тестов) и журнал. |

## Модели (`MineHunter.Core.Types`)

| Тип | Содержание |
|---|---|
| `TMHProcessId` | PID + время создания (FILETIME) — идентичность экземпляра; защищает от повторного использования PID. |
| `TMHProcessInfo` | PPID, имя, путь, SHA-256, подпись, доступ, CPU/рабочий набор/частная память (`TMHMetric`), потоки, командная строка, наличие окна, источник. |
| `TMHMetric` | Измерение; `HasValue = False` — «нет данных» (не ноль). |
| `TMHFileInfo` | Путь, размер, время изменения, SHA-256, подпись (`sgSignedTrusted / sgSignedUntrusted / sgUnsigned / sgCheckFailed / sgNotChecked`), издатель, источник подписи (`embedded` / `catalog`). |
| `TMHAutostartEntry` | Вид (Run, RunOnce, папка автозагрузки, служба, задание), область, имя, команда, путь, расположение, включён ли. |
| `TMHNetConnection` | TCP/UDP, IPv4/IPv6, адреса и порты, состояние, PID владельца. |
| `TMHContextInfo` | Бездействие пользователя, активный процесс, полноэкранный режим, процессы с окнами, контекст работы. |
| `TMHSnapshot` | Всё перечисленное на момент опроса + статусы источников. |
| `TMHEvidence` | Код признака, описание, вес (> 0 — «за», < 0 — оправдывающий фактор), наблюдаемое значение. |
| `TMHFinding` | Категория, балл 0–100, уровень, уверенность, признаки, недостающие данные, рекомендации, версия правил, ключ. |
| `TMHBaseline`, `TMHStat`, `TMHProcessBaseline` | Профиль нормы: медиана, p95, среднее, максимум по системе и программам. |
| `TMHAnalyzerSettings`, `TMHRiskThresholds`, `TMHExclusion` | Настраиваемые пороги и разрешённые программы (с привязкой к SHA-256). |

## Сканер (`MineHunter.Core.Scanner.TMHScanner`)

- `Start / Stop / ScanOnce`, свойства `Options` (интервал, доставка событий), `Repository`,
  `Baseline`, `BaselineProvider`.
- События `OnSnapshot`, `OnFinding`, `OnCycle` (снимок + находки цикла). По умолчанию доставляются
  в главный поток через очередь; после `Stop` недоставленные события отменяются.
- Отказоустойчивость: сбой коллектора → `ssError` и экспоненциальная пауза для этого источника;
  остальные работают. Сбой анализатора, обработчика или хранилища не останавливает опрос.

## Коллекторы (`src/Core/Collectors`)

| SourceId | Класс | Абстракция ОС (для тестов) |
|---|---|---|
| `system` | `TMHSystemCollector` | `IMHSystemMetricsApi` |
| `processes` | `TMHProcessCollector` | `IMHProcessApi` |
| `autostart` | `TMHAutostartCollector` | `IMHAutostartApi` |
| `network` | `TMHNetworkCollector` | `IMHNetworkApi` |
| `files` | `TMHFileCollector` | `IMHFileApi` |
| `context` | `TMHContextCollector` | `IMHContextApi` |
| `processevents` | `TMHProcessEventCollector` | `IMHProcessEventSource` (ETW: `TMHEtwProcessSource`) |
| `gpu` | `TMHGpuCollector` | `IMHGpuApi` (мощность — NVML, `mkGpuPowerWatts`) |
| `sensors` | `TMHSensorCollector` | `IMHSensorApi` |
| `tamper` | `TMHTamperCollector` | `IMHTamperApi` |
| `netadapters` | `TMHNetAdapterCollector` | `IMHNetAdapterApi` (`GetIfTable2`; скорость — по разнице счётчиков) |
| `disks` | `TMHDiskCollector` | `IMHDiskApi` (WMI Storage, PDH PhysicalDisk, разделы; `ReadHealth` — журнал NVMe и SMART SATA) |
| `self` | `TMHSelfMonitorCollector` | — |

Порядок регистрации важен: `files` после `processes`, `autostart` и `tamper`, `context` и
`processevents` после `processes`. Коллекторы с кэшем (`autostart`, `tamper`) реализуют
`IMHCacheInvalidation`; `TMHScanner.RequestRefresh` сбрасывает их кэш в следующем цикле
(«Проверить сейчас»), номер этого цикла — `LastRefreshSequence`.

## Анализ (`MineHunter.Analysis.*`)

- `TMHThreatAnalyzer` — правила с весами (`MH_RULESET_VERSION`), свойства `Settings`, `Exclusions`.
- `MHExplainLoad` — «почему компьютер тормозит»: основные потребители и характер нагрузки.
- `MineHunter.Analysis.Indicators` — локальная версионируемая база индикаторов.
- `MHTemperatureLimit`, `MHHeatResourceName` — порог температуры устройства и имена причин перегрева.
- Коллекторы `TMHGpuCollector` (`IMHGpuApi`), `TMHSensorCollector` (`IMHSensorApi`), общий
  `TMHPdhQuery` (`MineHunter.Collectors.Pdh`); `MHCpuUtilityFactor` — множитель «загруженность /
  время» для процессов.
- `TMHBaselineBuilder`, `TMHBaselineAccumulator` (построение порциями), `TMHBaselineManager`,
  `MHComparePeriods`, `MHCompareProcesses` — профиль нормы и сравнение.
- `MHAnalyzeTamper` (`MineHunter.Analysis.Tamper`) — признаки вмешательства в защиту, группировка
  по папке/команде/политике, связь с файлами-артефактами.
- `MHAnalyzeLaunches` (`MineHunter.Analysis.Launches`) — частые короткие запуски по `TMHSnapshot.Launches`.
- `MHFindingFingerprint`, `MHIsAcknowledged`, `MHFilterAcknowledged` (`MineHunter.Analysis.Acknowledge`) —
  «Проверено, не беспокоить»: отпечаток содержимого находки (`TMHAcknowledgement`); анализатор
  (`TMHThreatAnalyzer.Acknowledged`) скрывает отмеченные, пока отпечаток совпадает и риск не вырос.
- По устройствам: `TMHSnapshot.GpuAdapters` (`TMHGpuAdapterInfo` — по адаптеру LUID) и
  `TMHSnapshot.NetAdapters` (`TMHNetAdapterInfo`); скорость сети для показа — `MHFormatBitRate`
  (биты в секунду, как в диспетчере задач).
- `MHParseNvmeHealthLog`, `MHParseAtaSmart` (`MineHunter.Collectors.DiskHealth`) — разбор журнала здоровья
  NVMe и SMART SATA в `TMHDiskAttribute` (`TMHDiskInfo.Attributes`, `AttributesSource`) и поля диска
  (включения, аварийные отключения, объём чтения и записи, переназначенные, нестабильные и неисправимые
  секторы, критическое предупреждение NVMe); названия и значения для показа — `MHDiskAttributeName`,
  `MHDiskAttributeText`, `MHDiskAttributeRawHex`.

## Хранилище, настройки, отчёты, действия

- `TMHSQLiteRepository` (`MineHunter.Storage.SQLite`) — все интерфейсы истории; `TMHStorageOptions`.
- `TMHFileActions` (`MineHunter.App.FileActions`) — меню и окно действий с файлом строки таблицы
  (подробности, папка с выделенным файлом, VirusTotal по SHA-256, копирование); `TMHLineChart.SetSecondSeries` —
  вторая линия графика (приём и передача сети).
- `MHDataDir`, `MHRequestDataDirChange`, `MHApplyPendingDataMove` (`MineHunter.Core.DataDir`) — папка данных
  (история, настройки, карантин) и её перенос при следующем запуске.
- `TMHSettingsStore`, `TMHAppSettings` (`MineHunter.Core.Settings`) — атомарное сохранение JSON.
- `TMHReportBuilder` (`MineHunter.Core.Reports`) — отчёт и карточка находки в JSON/HTML, обезличивание.
- `TMHSafeActions` (`MineHunter.Core.Actions`) — открыть расположение, проверка Microsoft Defender
  (только отчёт), остановка процесса с проверкой идентичности; всё журналируется.
- `TMHJson` (`MineHunter.Core.Serialization`) — JSON всех моделей (схема 2, читает схему 1).
- `TMHQuarantine` (`MineHunter.Core.Quarantine`, ОС — `IMHQuarantineOps`) — карантин файлов,
  отключение значений реестра, служб и заданий с откатом (`Restore`) и удалением (`Purge`);
  `MHBuildRemediationPlan` — план исправления находки.
- `TMHSelfAutostart` (`MineHunter.Core.SelfAutostart`, `IMHRunKeyOps`) — автозапуск самой программы.
- `MHEstimateEnergy`, `MHEnergyCost` (`MineHunter.Core.Energy`) — энергия и стоимость по ряду мощности.
- `IMHInventoryHistory`, `MHInventoryFromSnapshot` (`MineHunter.Core.Inventory`) — учёт «что изменилось»
  (хранилище схемы 3).
- `MHBuildCheckReport` (`MineHunter.Core.CheckReport`) — отчёт «Проверить сейчас».
- `MHCommandLineArguments`, `MHLaunchPathText` (`MineHunter.Core.Launches`) — параметры запуска из командной
  строки и «путь с параметрами» для показа; `MHReadProcessCommandLine` (`MineHunter.Collectors.ProcessEvents.WinApi`) —
  командная строка живого процесса с проверкой экземпляра (PID + время создания).
- `IMHLaunchHistory` (`MineHunter.Core.Launches`) — журнал запусков (`TMHLaunchRecord`, таблица `launches`
  схемы 4, параметры запуска — со схемы 5; хранится не меньше 30 дней и не больше 300 000 записей); `TMHSnapshot.LaunchEvents`.
- `MHAnalyzeDisks`, `MHVolumeSpaceLevel`, `MHTopIoProcesses` (`MineHunter.Analysis.Disks`) — правила по
  дискам и «кто грузит диск»; `TMHSnapshot.Disks` / `Volumes`, `TMHProcessInfo.IoRead` / `IoWrite`.
- `TMHFileScanner`, `MHClassifyFile` (`MineHunter.Core.FileScan`, ФС — `IMHFileScanFs`) — проверка файлов
  на дисках с прогрессом и отменой.
- `MHCheckForUpdate`, `MHCompareVersions` (`MineHunter.Core.Updates`, HTTP — `IMHHttpGet`) — проверка
  новых версий на GitHub (по согласию пользователя).

## BinaryLab (`src/Core/BinaryLab`)

Разбор файла без запуска и без изменения: файл открывается только на чтение с совместным доступом,
каждое значение из файла проверяется на границы, циклы и глубина обхода ограничены, память — лимитами
`TMHBinaryLabOptions` (по умолчанию 256 МБ сканирования, 20 000 строк, 4 096 блоков энтропии).

```pascal
uses MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Analyzer, MineHunter.BinaryLab.Report,
  MineHunter.Collectors.Files.WinApi;

var
  LReport: TMHBinaryReport;
begin
  LReport := MHAnalyzeBinaryFile('C:\Tools\sample.exe', TMHBinaryLabOptions.Default,
    TMHWinFileApi.Create {проверка подписи; nil — не проверять}, TTimeZone.Local.ToUniversalTime(Now),
    TMHRiskThresholds.Default,
    function: Boolean begin Result := False end {отмена},
    procedure(const AStage: string; APercent: Integer) begin {ход анализа} end);
  Writeln(LReport.Score, ' ', LReport.Verdict);
  MHSaveBinaryReport(LReport, 'C:\Reports\sample.html'); // .json — JSON
end;
```

- `MineHunter.BinaryLab.Types` — модель отчёта (`TMHBinaryReport`, `TMHPeInfo`, `TMHEntropyInfo`,
  `TMHStringsInfo`, `TMHEmbeddedObject`, `TMHBinaryAnomaly`, `TMHBinaryDiff`), параметры и лимиты.
- `MineHunter.BinaryLab.Source` — `IMHBinarySource` (`TMHFileSource`, `TMHBytesSource`), `TMHBinaryReader`
  (чтение с проверкой границ), `MHReadChunks` (потоковый обход с перекрытием и отменой), `MHFindBytes`,
  `MHParseHexPattern`, `MHTextPattern`.
- `MineHunter.BinaryLab.FileType` — `MHDetectBinaryType` (вид по содержимому, несоответствие расширения),
  `MHIdentifyAt` (объект по смещению, строгий режим для середины файла), `MHProbePe`.
- `MineHunter.BinaryLab.Pe` — `MHParsePe` (заголовки, секции, импорт и отложенный импорт, экспорт с
  переадресацией, ресурсы, TLS, CLR, подпись, оверлей), `MHPeRvaToOffset`, `MHComputePeChecksum`
  (алгоритм CheckSumMappedFile), `MHRangeSha256`, `MHPeLocate`.
- `MineHunter.BinaryLab.Entropy` — `MHAnalyzeEntropy` (блоки, области высокой энтропии, гистограмма байтов),
  `MHRangeEntropy`.
- `MineHunter.BinaryLab.Strings` — `MHScanStrings` (ASCII и UTF-16), `MHClassifyString` (URL, IP, домены,
  почта, пути, реестр, команды, майнинг, кошельки, подозрительные функции, Base64).
- `MineHunter.BinaryLab.Embedded` — `MHFindEmbedded` (программы, архивы, документы, фрагменты сценариев).
- `MineHunter.BinaryLab.Anomalies` — `MHDetectAnomalies` (коды `BL_*`, серьёзность, вес, объяснение),
  `MHScoreBinaryReport` (доверенная подпись снижает оценку вдвое), `MHDetectInstaller`, `MHPackerBySectionName`.
- `MineHunter.BinaryLab.Diff` — `MHCompareBinaries` (заголовок, секции, импорт, экспорт, ресурсы, строки,
  изменённые блоки байтов, процент сходства).
- `MineHunter.BinaryLab.Report` — `MHBinaryReportToJson/Html`, `MHBinaryDiffToJson/Html`, `MHSaveBinaryReport`,
  `MHSaveBinaryDiff` (HTML самодостаточный, данные файла экранируются).
- `MineHunter.BinaryLab.Verdicts` — `MHVerdictFromReport`, `TMHBinaryVerdictStore` (`IMHBinaryVerdicts` из
  `MineHunter.Core.Interfaces`): признаки `BINARYLAB:*` для `TMHThreatAnalyzer.BinaryVerdicts` — анализатор
  добавляет их в находку процесса файла (вердикт привязан к SHA-256, сумма весов не больше 40).
- Интерфейс: `TMHBinaryLabPage` (`MineHunter.App.BinaryLabPage`, анализ, сравнение и поиск в фоновом потоке
  с отменой), элементы `TMHHexView`, `TMHEntropyMap`, `TMHByteHistogram`, `TMHRangeStrip`
  (`MineHunter.App.BinaryLab.Controls`); `TMHFileActions.OnBinaryLab` — пункт «Открыть в BinaryLab».
