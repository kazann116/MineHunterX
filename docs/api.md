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

## Хранилище, настройки, отчёты, действия

- `TMHSQLiteRepository` (`MineHunter.Storage.SQLite`) — все интерфейсы истории; `TMHStorageOptions`.
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
- `MHCheckForUpdate`, `MHCompareVersions` (`MineHunter.Core.Updates`, HTTP — `IMHHttpGet`) — проверка
  новых версий на GitHub (по согласию пользователя).
