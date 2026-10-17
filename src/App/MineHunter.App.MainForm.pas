unit MineHunter.App.MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes, System.Actions,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ComCtrls, Vcl.ActnList, Vcl.Menus,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.App.Bootstrap,
  MineHunter.App.ProcessView, MineHunter.App.Chart, MineHunter.Storage.SQLite,
  MineHunter.App.FindingsView, MineHunter.Core.Reports, MineHunter.Core.Actions,
  MineHunter.Core.Settings, MineHunter.Analysis.Engine, MineHunter.Analysis.Baseline,
  MineHunter.App.DashboardView, MineHunter.App.Tiles, MineHunter.Core.Quarantine,
  MineHunter.App.Notifier;

type
  TMHPage = (pgDashboard, pgProcesses, pgFindings, pgHistory, pgSettings);

  /// Подтверждение опасного действия пользователем.
  TMHConfirmFunc = reference to function(const AQuestion: string): Boolean;

  TMainForm = class(TForm)
    alMain: TActionList;
    actStart: TAction;
    actStop: TAction;
    actNavDashboard: TAction;
    actNavProcesses: TAction;
    actNavFindings: TAction;
    actNavHistory: TAction;
    actNavSettings: TAction;
    pnlTop: TPanel;
    btnStart: TButton;
    btnStop: TButton;
    lblScanState: TLabel;
    lbNav: TListBox;
    pcMain: TPageControl;
    tsDashboard: TTabSheet;
    tsProcesses: TTabSheet;
    tsFindings: TTabSheet;
    tsHistory: TTabSheet;
    tsSettings: TTabSheet;
    sbDashboard: TScrollBox;
    pnlStatus: TPanel;
    lblNowCaption: TLabel;
    pnlTiles: TPanel;
    lblChartsCaption: TLabel;
    pnlReasons: TPanel;
    lblDetailsCaption: TLabel;
    pcDetails: TPageControl;
    tsDetailSources: TTabSheet;
    tsDetailEvents: TTabSheet;
    tsDetailSelf: TTabSheet;
    lblSelfCpuCaption: TLabel;
    lblSelfCpu: TLabel;
    lblSelfMemCaption: TLabel;
    lblSelfMem: TLabel;
    lblSelfUpdatedCaption: TLabel;
    lblSelfUpdated: TLabel;
    lvSources: TListView;
    lvEvents: TListView;
    pnlProcFilter: TPanel;
    lblProcFilter: TLabel;
    edProcFilter: TEdit;
    lblProcCount: TLabel;
    lvProcesses: TListView;
    splProcDetails: TSplitter;
    gbProcDetails: TGroupBox;
    mmProcDetails: TMemo;
    lblAlerts: TLabel;
    lblWhySlow: TLabel;
    lblRights: TLabel;
    btnGoFindings: TButton;
    chkOnlyFindings: TCheckBox;
    chkOnlyUnsigned: TCheckBox;
    pnlFindingsTop: TPanel;
    lblFindingsMode: TLabel;
    lblFindingsMinLevel: TLabel;
    lblFindingsCount: TLabel;
    cbFindingsMode: TComboBox;
    cbFindingsMinLevel: TComboBox;
    btnExportReport: TButton;
    lvFindings: TListView;
    splFindings: TSplitter;
    pnlCard: TPanel;
    pnlCardButtons: TPanel;
    lblCardStatus: TLabel;
    btnOpenLocation: TButton;
    btnDefender: TButton;
    btnStopProcess: TButton;
    btnAllow: TButton;
    btnExportCard: TButton;
    pnlCardChart: TPanel;
    mmCard: TMemo;
    pnlBaseline: TPanel;
    lblBaselineInfo: TLabel;
    btnRebuildBaseline: TButton;
    lvComparison: TListView;
    lvDeviations: TListView;
    sbSettings: TScrollBox;
    gbAnalysis: TGroupBox;
    lblHighCpu: TLabel;
    lblSustained: TLabel;
    lblLearning: TLabel;
    cbHighCpu: TComboBox;
    cbSustained: TComboBox;
    cbLearning: TComboBox;
    chkStartScan: TCheckBox;
    chkRedactReports: TCheckBox;
    gbExclusions: TGroupBox;
    lvExclusions: TListView;
    btnRemoveExclusion: TButton;
    gbActionLog: TGroupBox;
    lvActionLog: TListView;
    sdExport: TSaveDialog;
    pnlLiveCharts: TPanel;
    pnlHistoryTop: TPanel;
    lblHistoryPeriod: TLabel;
    lblHistoryStatus: TLabel;
    cbHistoryPeriod: TComboBox;
    btnHistoryRefresh: TButton;
    pnlHistoryCharts: TPanel;
    gbStorage: TGroupBox;
    lblStoragePathCaption: TLabel;
    lblStoragePath: TLabel;
    lblStorageStats: TLabel;
    lblRetention: TLabel;
    lblStorageNote: TLabel;
    cbRetention: TComboBox;
    chkStorePaths: TCheckBox;
    btnClearHistory: TButton;
    lblInterval: TLabel;
    cbInterval: TComboBox;
    lblPrivacy: TLabel;
    sbMain: TStatusBar;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure actStartExecute(Sender: TObject);
    procedure actStopExecute(Sender: TObject);
    procedure actNavExecute(Sender: TObject);
    procedure lbNavClick(Sender: TObject);
    procedure cbIntervalChange(Sender: TObject);
    procedure lvProcessesData(Sender: TObject; Item: TListItem);
    procedure lvProcessesColumnClick(Sender: TObject; Column: TListColumn);
    procedure lvProcessesSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure edProcFilterChange(Sender: TObject);
    procedure pnlLiveChartsResize(Sender: TObject);
    procedure pnlTilesResize(Sender: TObject);
    procedure pnlHistoryChartsResize(Sender: TObject);
    procedure cbHistoryPeriodChange(Sender: TObject);
    procedure btnHistoryRefreshClick(Sender: TObject);
    procedure cbRetentionChange(Sender: TObject);
    procedure chkStorePathsClick(Sender: TObject);
    procedure btnClearHistoryClick(Sender: TObject);
    procedure btnGoFindingsClick(Sender: TObject);
    procedure chkOnlyFindingsClick(Sender: TObject);
    procedure chkOnlyUnsignedClick(Sender: TObject);
    procedure cbFindingsModeChange(Sender: TObject);
    procedure cbFindingsMinLevelChange(Sender: TObject);
    procedure btnExportReportClick(Sender: TObject);
    procedure lvFindingsData(Sender: TObject; Item: TListItem);
    procedure lvFindingsSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure btnOpenLocationClick(Sender: TObject);
    procedure btnDefenderClick(Sender: TObject);
    procedure btnStopProcessClick(Sender: TObject);
    procedure btnAllowClick(Sender: TObject);
    procedure btnExportCardClick(Sender: TObject);
    procedure pnlCardChartResize(Sender: TObject);
    procedure btnRebuildBaselineClick(Sender: TObject);
    procedure cbHighCpuChange(Sender: TObject);
    procedure cbSustainedChange(Sender: TObject);
    procedure cbLearningChange(Sender: TObject);
    procedure chkStartScanClick(Sender: TObject);
    procedure chkRedactReportsClick(Sender: TObject);
    procedure btnRemoveExclusionClick(Sender: TObject);
  private const
    LIVE_POINTS = 300;
    HISTORY_POINTS = 600;
    HISTORY_HOURS: array[0..3] of Integer = (1, 6, 24, 168);
    RETENTION_DAYS: array[0..4] of Integer = (1, 3, 7, 14, 30);
    HISTORY_KINDS: array[0..6] of TMHMetricKind = (mkCpuPercent, mkMemoryLoadPercent,
      mkDiskActivePercent, mkDiskReadBytesPerSec, mkDiskWriteBytesPerSec, mkGpuPercent,
      mkGpuTemperatureCelsius);
    HISTORY_TITLES: array[0..6] of string = ('Процессор', 'Память', 'Активность диска',
      'Чтение с диска', 'Запись на диск', 'Видеокарта', 'Температура видеокарты');
    IntervalChoicesMs: array[0..4] of Cardinal = (1000, 2000, 3000, 5000, 10000);
    HIGH_CPU_CHOICES: array[0..4] of Integer = (10, 15, 25, 40, 60);
    SUSTAINED_CHOICES: array[0..3] of Integer = (5, 10, 15, 30);
    LEARNING_CHOICES: array[0..3] of Integer = (1, 3, 7, 14);
  private
    FServices: TMHAppServices;
    FOwnsServices: Boolean;
    FSnapshotCount: Integer;
    FLastLogVersion: UInt64;
    FProcessModel: TMHProcessListModel;
    FSelectedProcess: TMHProcessId;
    // Отдельный флаг: идентичность System Idle Process (PID 0, без времени
    // создания) совпадает с TMHProcessId.Empty, поэтому IsEmpty не означает «нет выбора».
    FHasSelectedProcess: Boolean;
    FUpdatingProcesses: Boolean;
    FLiveCpu, FLiveMem, FLiveDisk, FLiveGpu: TMHSeriesBuffer;
    FChartCpu, FChartMem, FChartDisk, FChartGpu: TMHLineChart;
    FTiles: array[TMHTileKind] of TMHMetricTile;
    FReasons: TMHReasonList;
    FHistoryCharts: array[0..6] of TMHLineChart;
    FHistoryLoader: TThread;
    FHistoryGeneration: Integer;
    FHistoryLoading: Boolean;
    FHistoryReloadPending: Boolean;
    FHistoryRequested: Boolean;
    FDestroying: Boolean;
    FInitializingSettings: Boolean;
    FConfirm: TMHConfirmFunc;
    // Результат фоновой загрузки. Пишется потоком-загрузчиком до постановки
    // HistoryLoaded в очередь и читается только в HistoryLoaded; одновременно
    // работает не более одного загрузчика (FHistoryLoading).
    FHistoryResultSeries: TArray<TArray<TMHMetric>>;
    FHistoryResultError: string;
    FHistoryResultFrom, FHistoryResultTo: TDateTime;
    FHistoryResultGeneration: Integer;
    FHistoryResultComparisons: TArray<TMHMetricComparison>;
    FHistoryResultDeviations: TArray<TMHProcessDeviation>;
    FHistoryResultBaselineInfo: string;
    FFindingsModel: TMHFindingsModel;
    FSelectedFindingKey: string;
    FUpdatingFindings: Boolean;
    FLastSnapshot: TMHSnapshot;
    FHasLastSnapshot: Boolean;
    FCardChart: TMHLineChart;
    FCardSeriesKey: string;
    FDefenderThread: TThread;
    FDefenderResult: TMHActionResult;
    FDefenderDone: Boolean;
    FRemediateButton: TButton;
    FQuarantineBox: TGroupBox;
    FQuarantineList: TListView;
    FQuarantineRestore: TButton;
    FQuarantinePurge: TButton;
    FQuarantineItems: TArray<TMHQuarantineItem>;
    FTray: TTrayIcon;
    FTrayMenu: TPopupMenu;
    FNotifier: TMHAlertNotifier;
    FLastNotice: TMHAlertNotice;
    FNoticeCount: Integer;
    FQuitting: Boolean;
    FHiddenToTray: Boolean;
    FTrayHintShown: Boolean;
    FBackgroundBox: TGroupBox;
    FChkTray: TCheckBox;
    FChkNotify: TCheckBox;
    FChkEconomy: TCheckBox;
    FChkAutostart: TCheckBox;
    FLblAutostart: TLabel;
    procedure CreateTray;
    procedure CreateBackgroundSettings;
    procedure UpdateTray;
    procedure UpdateAutostartState;
    procedure TrayClick(Sender: TObject);
    procedure TrayBalloonClick(Sender: TObject);
    procedure TrayOpenClick(Sender: TObject);
    procedure TrayExitClick(Sender: TObject);
    procedure BackgroundSettingClick(Sender: TObject);
    procedure AutostartClick(Sender: TObject);
    procedure WMSysCommand(var AMessage: TWMSysCommand); message WM_SYSCOMMAND;
    procedure CreateRemediationControls;
    procedure RemediateClick(Sender: TObject);
    function ExecuteRemediationStep(const AStep: TMHRemediationStep; const AReason: string): TMHActionResult;
    procedure QuarantineSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure QuarantineRestoreClick(Sender: TObject);
    procedure QuarantinePurgeClick(Sender: TObject);
    procedure HandleCycle(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);
    procedure UpdateProtection(const ASnapshot: TMHSnapshot);
    procedure RefreshFindingsList;
    function SelectedFinding(out ARow: TMHFindingRow): Boolean;
    function FindLiveProcess(const AId: TMHProcessId; out AInfo: TMHProcessInfo): Boolean;
    function ParentNameOf(APid: Cardinal): string;
    function LoadSeriesFor(const AFinding: TMHFinding): TArray<TMHMetric>;
    procedure UpdateFindingCard;
    procedure ShowActionResult(const AResult: TMHActionResult);
    procedure DefenderFinished;
    function ReportOptions: TMHReportOptions;
    function AskExportFile(const ADefaultName: string; out AFileName: string;
      out AHtml: Boolean): Boolean;
    procedure ApplyComparison;
    procedure ChangeSettings(const ASettings: TMHAppSettings);
    procedure InitAnalysisSettings;
    procedure RefreshExclusions;
    procedure RefreshActionLog;
    procedure CreateCharts;
    procedure CreateDashboard;
    procedure UpdateSystem(const ASnapshot: TMHSnapshot);
    procedure LoadHistory;
    procedure ApplyHistory(AGeneration: Integer; AFromUtc, AToUtc: TDateTime;
      const ASeries: TArray<TArray<TMHMetric>>; const AError: string);
    procedure InitStorageSettings;
    function DefaultConfirm(const AQuestion: string): Boolean;
    /// Вызывается в главном потоке после фоновой загрузки истории.
    procedure HistoryLoaded;
    procedure UpdateStorageInfo;
    procedure HandleSnapshot(const ASnapshot: TMHSnapshot);
    procedure UpdateSelf(const ASnapshot: TMHSnapshot);
    procedure UpdateSources(const ASnapshot: TMHSnapshot);
    procedure UpdateEvents;
    procedure UpdateScanState;
    procedure UpdateProcesses(const ASnapshot: TMHSnapshot);
    procedure RefreshProcessList;
    procedure UpdateProcessDetails;
    procedure UpdateSortIndicator;
    function GetActivePage: TMHPage;
  public
    /// Конструктор для тестов и встраивания: форма использует переданные
    /// сервисы и не освобождает их.
    constructor CreateWithServices(AOwner: TComponent; AServices: TMHAppServices);
    procedure NavigateTo(APage: TMHPage);
    procedure StartScan;
    procedure StopScan;
    property ActivePage: TMHPage read GetActivePage;
    property Services: TMHAppServices read FServices;
    /// Число снимков, полученных формой (для диагностики и smoke-тестов).
    property SnapshotCount: Integer read FSnapshotCount;
    property ProcessModel: TMHProcessListModel read FProcessModel;
    /// Выбранный в таблице экземпляр процесса (сохраняется между обновлениями).
    property SelectedProcess: TMHProcessId read FSelectedProcess;
    property HasSelectedProcess: Boolean read FHasSelectedProcess;
    property LiveCpuChart: TMHLineChart read FChartCpu;
    property LiveMemoryChart: TMHLineChart read FChartMem;
    property LiveDiskChart: TMHLineChart read FChartDisk;
    property LiveGpuChart: TMHLineChart read FChartGpu;
    /// Карточка «Сейчас» на странице «Обзор».
    function DashboardTile(AKind: TMHTileKind): TMHMetricTile;
    property DashboardReasons: TMHReasonList read FReasons;
    function HistoryChart(AIndex: Integer): TMHLineChart;
    /// Идёт фоновая загрузка истории.
    property HistoryLoading: Boolean read FHistoryLoading;
    /// Подтверждение опасных действий (по умолчанию — диалог). Тесты подменяют.
    property ConfirmAction: TMHConfirmFunc read FConfirm write FConfirm;
    /// Кнопка «Исправить…» карточки находки и список карантина (для тестов).
    property RemediateButton: TButton read FRemediateButton;
    property QuarantineList: TListView read FQuarantineList;
    /// Строит план исправления выбранной находки, спрашивает подтверждение и выполняет.
    procedure RemediateSelected;
    /// Перечитывает список карантина в настройках.
    procedure RefreshQuarantine;
    /// Восстановить / удалить навсегда выделенный в списке объект карантина.
    procedure RestoreSelectedQuarantine;
    procedure PurgeSelectedQuarantine;
    /// Убрать окно в область уведомлений (опрос замедляется, если включён экономный режим).
    procedure HideToTray;
    /// Показать окно из области уведомлений.
    procedure ShowFromTray;
    /// Учитывает находки цикла для уведомлений; True — показано уведомление (LastNotice).
    function NotifyAlerts(const AFindings: TMHFindings; ANowUtc: TDateTime): Boolean;
    property LastNotice: TMHAlertNotice read FLastNotice;
    property NoticeCount: Integer read FNoticeCount;
    property HiddenToTray: Boolean read FHiddenToTray;
    property TrayIcon: TTrayIcon read FTray;
    property TrayCheckBox: TCheckBox read FChkTray;
    property NotifyCheckBox: TCheckBox read FChkNotify;
    property EconomyCheckBox: TCheckBox read FChkEconomy;
    property AutostartCheckBox: TCheckBox read FChkAutostart;
    /// Выход из программы (а не сворачивание в трей) при закрытии окна.
    procedure Quit;
    property FindingsModel: TMHFindingsModel read FFindingsModel;
    /// Ключ выбранной находки ('' — не выбрана); запись выбирает находку в списке.
    property SelectedFindingKey: string read FSelectedFindingKey;
    procedure SelectFinding(const AKey: string);
    property CardChart: TMHLineChart read FCardChart;
    /// Экспорт отчёта и карточки без диалога (кнопки вызывают их после TSaveDialog).
    procedure ExportReport(const AFileName: string; AHtml: Boolean);
    procedure ExportFindingCard(const AFileName: string; AHtml: Boolean);
    /// Идёт проверка Microsoft Defender.
    function DefenderRunning: Boolean;
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  System.Math, System.DateUtils, System.UITypes, System.StrUtils,
  MineHunter.Core.Scanner, MineHunter.App.Display, MineHunter.Collectors.SelfMonitor,
  MineHunter.Collectors.Processes, MineHunter.Collectors.System, MineHunter.Core.Paths,
  MineHunter.Core.SelfAutostart;

function PercentText(AValue: Double): string; forward;

function CommandLineParams: TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, ParamCount);
  for I := 1 to ParamCount do
    Result[I - 1] := ParamStr(I);
end;

/// Меняет текст только при изменении: иначе обновление раз в цикл сбрасывало бы
/// прокрутку, пока пользователь читает объяснение.
procedure SetMemoText(AMemo: TMemo; const AText: string);
var
  LTopLine: NativeInt;
begin
  if TrimRight(AMemo.Text) = TrimRight(AText) then
    Exit;
  // Текущие значения (CPU и т.п.) меняются каждый цикл — сохраняем позицию прокрутки.
  LTopLine := 0;
  if AMemo.HandleAllocated then
    LTopLine := SendMessage(AMemo.Handle, EM_GETFIRSTVISIBLELINE, 0, 0);
  AMemo.Text := AText;
  if (LTopLine > 0) and AMemo.HandleAllocated then
    SendMessage(AMemo.Handle, EM_LINESCROLL, 0, LTopLine);
end;

const
  PAGE_TITLES: array[TMHPage] of string =
    ('Обзор', 'Процессы', 'Находки', 'История', 'Настройки');
  PROCESS_COLUMN_TITLES: array[TMHProcessColumn] of string =
    ('Имя', 'PID', 'CPU', 'Память', 'GPU', 'Рабочий набор', 'Частная память', 'Потоки', 'Доступ',
     'Путь', 'Риск', 'Подпись');

constructor TMainForm.CreateWithServices(AOwner: TComponent; AServices: TMHAppServices);
begin
  if AServices = nil then
    raise EArgumentNilException.Create('AServices');
  // FServices должен быть назначен до загрузки DFM: FormCreate его использует.
  FServices := AServices;
  FOwnsServices := False;
  inherited Create(AOwner);
end;

procedure TMainForm.FormCreate(Sender: TObject);
var
  LPage: TMHPage;
  I: Integer;
  LOptions: TMHScannerOptions;
begin
  if FServices = nil then
  begin
    FServices := TMHAppServices.CreateDefault;
    FOwnsServices := True;
  end;

  lbNav.Items.Clear;
  for LPage := Low(TMHPage) to High(TMHPage) do
    lbNav.Items.Add(PAGE_TITLES[LPage]);
  for I := 0 to pcMain.PageCount - 1 do
    pcMain.Pages[I].TabVisible := False;

  LOptions := FServices.Scanner.Options;
  cbInterval.Items.Clear;
  cbInterval.ItemIndex := -1;
  for I := Low(IntervalChoicesMs) to High(IntervalChoicesMs) do
  begin
    cbInterval.Items.Add(Format('%d с', [IntervalChoicesMs[I] div 1000]));
    if IntervalChoicesMs[I] = LOptions.IntervalMs then
      cbInterval.ItemIndex := I;
  end;

  FFindingsModel := TMHFindingsModel.Create;
  FProcessModel := TMHProcessListModel.Create(TMHProcessCollector.SourceIdValue);
  FProcessModel.RiskLookup :=
    function(const AId: TMHProcessId): TMHRiskLevel
    begin
      Result := FFindingsModel.RiskOf(AId);
    end;
  FSelectedProcess := TMHProcessId.Empty;
  FHasSelectedProcess := False;
  UpdateSortIndicator;
  UpdateProcessDetails;

  FConfirm := DefaultConfirm;
  CreateCharts;
  CreateRemediationControls;
  FNotifier := TMHAlertNotifier.Create(rlSuspicious, 60);
  CreateTray;
  CreateBackgroundSettings;
  cbHistoryPeriod.Items.Clear;
  cbHistoryPeriod.Items.Add('1 час');
  cbHistoryPeriod.Items.Add('6 часов');
  cbHistoryPeriod.Items.Add('24 часа');
  cbHistoryPeriod.Items.Add('7 дней');
  cbHistoryPeriod.ItemIndex := 0;
  InitStorageSettings;

  FCardChart := TMHLineChart.Create(Self);
  FCardChart.Parent := pnlCardChart;
  FCardChart.ShowHint := True;
  FCardChart.SetFixedRange(0, 100);
  FCardChart.Formatter := PercentText;
  FCardChart.Title := 'Нагрузка (последний час)';
  pnlCardChartResize(nil);
  cbFindingsMode.Items.Clear;
  cbFindingsMode.Items.Add('Активные тревоги');
  cbFindingsMode.Items.Add('История за 7 дней');
  cbFindingsMode.ItemIndex := 0;
  cbFindingsMinLevel.Items.Clear;
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlLow));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlNeedsReview));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlSuspicious));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlHighlySuspicious));
  cbFindingsMinLevel.ItemIndex := 0;
  lblStorageNote.Caption := 'История и настройки хранятся только на этом компьютере ' +
    '(%LOCALAPPDATA%\MineHunterX) и никуда не передаются.';
  InitAnalysisSettings;
  RefreshFindingsList;
  if not FServices.SettingsLoadedOk then
    FServices.Logger.Log(llWarning, 'settings',
      'Файл настроек был повреждён: восстановлены значения по умолчанию');

  FServices.Scanner.OnCycle :=
    procedure(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings)
    begin
      HandleCycle(ASnapshot, AFindings);
    end;

  NavigateTo(pgDashboard);
  UpdateScanState;
  UpdateEvents;
  // Автоматический запуск — только в обычной работе приложения (не во встраивании и тестах).
  if FOwnsServices and FServices.Settings.StartScanOnLaunch then
    StartScan;
end;

procedure TMainForm.SelectFinding(const AKey: string);
begin
  FSelectedFindingKey := AKey;
  RefreshFindingsList;
end;

function TMainForm.DefenderRunning: Boolean;
begin
  Result := (FDefenderThread <> nil) and not FDefenderDone;
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  // Ожидание потоков ниже обрабатывает очередь синхронизации: отложенные
  // обработчики не должны обращаться к разрушаемой форме.
  FDestroying := True;
  FreeAndNil(FHistoryLoader);
  // Проверка Defender отменяется (ACancel видит FDestroying) и дожидается завершения.
  FreeAndNil(FDefenderThread);
  if FServices <> nil then
  begin
    // Остановка потока отменяет недоставленные события до освобождения формы.
    FServices.Scanner.Stop;
    FServices.Scanner.OnSnapshot := nil;
    FServices.Scanner.OnCycle := nil;
    if FOwnsServices then
      FreeAndNil(FServices)
    else
      FServices := nil;
  end;
  // Виртуальный список больше не должен обращаться к модели.
  lvProcesses.OnData := nil;
  FreeAndNil(FProcessModel);
  lvFindings.OnData := nil;
  FreeAndNil(FFindingsModel);
  FreeAndNil(FLiveCpu);
  FreeAndNil(FLiveMem);
  FreeAndNil(FLiveDisk);
  FreeAndNil(FLiveGpu);
  if FTray <> nil then
    FTray.Visible := False;
  FreeAndNil(FNotifier);
end;

function TMainForm.HistoryChart(AIndex: Integer): TMHLineChart;
begin
  Result := FHistoryCharts[AIndex];
end;

function TMainForm.GetActivePage: TMHPage;
begin
  Result := TMHPage(pcMain.ActivePageIndex);
end;

procedure TMainForm.NavigateTo(APage: TMHPage);
begin
  pcMain.ActivePageIndex := Ord(APage);
  if lbNav.ItemIndex <> Ord(APage) then
    lbNav.ItemIndex := Ord(APage);
  Caption := 'MineHunter X — ' + PAGE_TITLES[APage];
  case APage of
    pgHistory:
      if not FHistoryRequested then
        LoadHistory;
    pgSettings:
      UpdateStorageInfo;
  end;
end;

procedure TMainForm.lbNavClick(Sender: TObject);
begin
  if lbNav.ItemIndex >= 0 then
    NavigateTo(TMHPage(lbNav.ItemIndex));
end;

procedure TMainForm.actNavExecute(Sender: TObject);
begin
  // Tag действия навигации = порядковый номер страницы (задан в DFM).
  NavigateTo(TMHPage((Sender as TAction).Tag));
end;

procedure TMainForm.StartScan;
begin
  FServices.Scanner.Start;
  UpdateScanState;
end;

procedure TMainForm.StopScan;
begin
  FServices.Scanner.Stop;
  UpdateScanState;
  UpdateEvents;
end;

procedure TMainForm.actStartExecute(Sender: TObject);
begin
  StartScan;
end;

procedure TMainForm.actStopExecute(Sender: TObject);
begin
  StopScan;
end;

procedure TMainForm.cbIntervalChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (cbInterval.ItemIndex < Low(IntervalChoicesMs)) or
     (cbInterval.ItemIndex > High(IntervalChoicesMs)) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.IntervalMs := IntervalChoicesMs[cbInterval.ItemIndex];
  FServices.Logger.Log(llInfo, 'app',
    Format('Интервал опроса изменён на %d мс', [LSettings.IntervalMs]));
  ChangeSettings(LSettings);
end;

procedure TMainForm.UpdateScanState;
var
  LRunning: Boolean;
begin
  LRunning := FServices.Scanner.IsRunning;
  actStart.Enabled := not LRunning;
  actStop.Enabled := LRunning;
  // Если фокус был на кнопке, которая стала недоступной, Windows оставляет окно
  // без фокуса ввода и сочетания клавиш (Ctrl+1…5, F5) перестают работать.
  if (ActiveControl <> nil) and not ActiveControl.Enabled then
  begin
    if LRunning and btnStop.CanFocus then
      btnStop.SetFocus
    else if not LRunning and btnStart.CanFocus then
      btnStart.SetFocus;
  end;
  if LRunning then
    lblScanState.Caption := '● Сканирование выполняется'
  else
    lblScanState.Caption := '■ Сканирование остановлено';
  sbMain.Panels[0].Text := lblScanState.Caption;
end;

procedure TMainForm.HandleSnapshot(const ASnapshot: TMHSnapshot);
begin
  Inc(FSnapshotCount);
  UpdateSelf(ASnapshot);
  UpdateSystem(ASnapshot);
  UpdateSources(ASnapshot);
  UpdateProcesses(ASnapshot);
  UpdateEvents;
  sbMain.Panels[1].Text := Format('Снимок №%d в %s · процессов: %d',
    [ASnapshot.Sequence, MHFormatUtcAsLocal(ASnapshot.TimestampUtc),
     FProcessModel.TotalCount]);
end;

procedure TMainForm.UpdateSelf(const ASnapshot: TMHSnapshot);
var
  I: Integer;
begin
  for I := 0 to High(ASnapshot.Processes) do
    if (ASnapshot.Processes[I].Id.Pid = GetCurrentProcessId) and
       SameText(ASnapshot.Processes[I].SourceId, TMHSelfMonitorCollector.SourceIdValue) then
    begin
      lblSelfCpu.Caption := MHFormatMetric(ASnapshot.Processes[I].Cpu);
      lblSelfMem.Caption := MHFormatMetric(ASnapshot.Processes[I].WorkingSet);
      lblSelfUpdated.Caption := MHFormatUtcAsLocal(ASnapshot.TimestampUtc);
      Exit;
    end;
  lblSelfCpu.Caption := MH_NO_DATA;
  lblSelfMem.Caption := MH_NO_DATA;
end;

procedure TMainForm.UpdateSources(const ASnapshot: TMHSnapshot);
var
  LItem: TListItem;
  LStatus: TMHSourceStatus;
  LMessage: string;
begin
  lvSources.Items.BeginUpdate;
  try
    lvSources.Items.Clear;
    for LStatus in ASnapshot.Sources do
    begin
      LItem := lvSources.Items.Add;
      LItem.Caption := LStatus.SourceId;
      LItem.SubItems.Add(MHFormatSourceState(LStatus.State));
      LItem.SubItems.Add(IntToStr(LStatus.DurationMs));
      LMessage := LStatus.Message;
      if LStatus.RequiresElevation then
        LMessage := Trim(LMessage + ' (нужны права администратора)');
      LItem.SubItems.Add(LMessage);
    end;
  finally
    lvSources.Items.EndUpdate;
  end;
end;

procedure TMainForm.UpdateEvents;
var
  LVersion: UInt64;
  LEntries: TArray<TMHLogEntry>;
  LItem: TListItem;
  I: Integer;
begin
  LVersion := FServices.LogReader.Version;
  if LVersion = FLastLogVersion then
    Exit;
  FLastLogVersion := LVersion;
  LEntries := FServices.LogReader.Entries;
  lvEvents.Items.BeginUpdate;
  try
    lvEvents.Items.Clear;
    // Новые события сверху.
    for I := High(LEntries) downto 0 do
    begin
      LItem := lvEvents.Items.Add;
      LItem.Caption := MHFormatUtcAsLocal(LEntries[I].TimestampUtc);
      LItem.SubItems.Add(MHLogLevelToString(LEntries[I].Level));
      LItem.SubItems.Add(LEntries[I].Source);
      LItem.SubItems.Add(LEntries[I].Message);
    end;
  finally
    lvEvents.Items.EndUpdate;
  end;
end;

procedure TMainForm.UpdateProcesses(const ASnapshot: TMHSnapshot);
var
  LStatus: TMHSourceStatus;
begin
  // Снимок без данных процессов (источник отключён или упал) не очищает таблицу:
  // пользователь продолжает видеть последние известные данные.
  if not ASnapshot.FindSource(TMHProcessCollector.SourceIdValue, LStatus) or
     not (LStatus.State in [ssSuccess, ssPartial]) then
    Exit;
  FProcessModel.SetSnapshot(ASnapshot);
  RefreshProcessList;
end;

procedure TMainForm.RefreshProcessList;
var
  LIndex: Integer;
begin
  FUpdatingProcesses := True;
  try
    lvProcesses.Items.Count := FProcessModel.Count;
    LIndex := -1;
    if FHasSelectedProcess then
      LIndex := FProcessModel.IndexOf(FSelectedProcess);
    lvProcesses.ItemIndex := LIndex;
    if LIndex >= 0 then
      lvProcesses.Items[LIndex].Focused := True;
    lvProcesses.Invalidate;
  finally
    FUpdatingProcesses := False;
  end;
  lblProcCount.Caption := Format('Показано %d из %d',
    [FProcessModel.Count, FProcessModel.TotalCount]);
  UpdateProcessDetails;
end;

procedure TMainForm.lvProcessesData(Sender: TObject; Item: TListItem);
var
  LInfo: TMHProcessInfo;
begin
  if (FProcessModel = nil) or (Item.Index >= FProcessModel.Count) then
    Exit;
  LInfo := FProcessModel[Item.Index];
  Item.Caption := LInfo.Name;
  Item.SubItems.Add(UIntToStr(LInfo.Id.Pid));
  Item.SubItems.Add(MHFormatMetric(LInfo.Cpu));
  Item.SubItems.Add(MHFormatMetric(MHProcessMemory(LInfo)));
  Item.SubItems.Add(MHFormatMetric(LInfo.Gpu));
  Item.SubItems.Add(MHFormatMetric(LInfo.WorkingSet));
  Item.SubItems.Add(MHFormatMetric(LInfo.PrivateBytes));
  if LInfo.ThreadCount = MH_UNKNOWN_COUNT then
    Item.SubItems.Add(MH_NO_DATA)
  else
    Item.SubItems.Add(IntToStr(LInfo.ThreadCount));
  Item.SubItems.Add(MHAccessLevelToString(LInfo.Access));
  if LInfo.ImagePath = '' then
    Item.SubItems.Add(MH_NO_DATA)
  else
    Item.SubItems.Add(LInfo.ImagePath);
  Item.SubItems.Add(MHRiskLevelToString(FProcessModel.RiskOf(LInfo)));
  Item.SubItems.Add(MHSignatureToString(LInfo.Signature));
end;

procedure TMainForm.lvProcessesColumnClick(Sender: TObject; Column: TListColumn);
begin
  if (Column.Index < Ord(Low(TMHProcessColumn))) or
     (Column.Index > Ord(High(TMHProcessColumn))) then
    Exit;
  FProcessModel.SortBy(TMHProcessColumn(Column.Index));
  UpdateSortIndicator;
  RefreshProcessList;
end;

procedure TMainForm.lvProcessesSelectItem(Sender: TObject; Item: TListItem;
  Selected: Boolean);
begin
  if FUpdatingProcesses then
    Exit;
  if Selected and (Item <> nil) and (Item.Index < FProcessModel.Count) then
  begin
    FSelectedProcess := FProcessModel[Item.Index].Id;
    FHasSelectedProcess := True;
  end
  else if lvProcesses.ItemIndex < 0 then
  begin
    FSelectedProcess := TMHProcessId.Empty;
    FHasSelectedProcess := False;
  end;
  UpdateProcessDetails;
end;

procedure TMainForm.edProcFilterChange(Sender: TObject);
begin
  FProcessModel.Filter := edProcFilter.Text;
  RefreshProcessList;
end;

procedure TMainForm.UpdateSortIndicator;
var
  LColumn: TMHProcessColumn;
  LCaption: string;
begin
  for LColumn := Low(TMHProcessColumn) to High(TMHProcessColumn) do
  begin
    LCaption := PROCESS_COLUMN_TITLES[LColumn];
    if LColumn = FProcessModel.SortColumn then
    begin
      if FProcessModel.Ascending then
        LCaption := LCaption + ' ▲'
      else
        LCaption := LCaption + ' ▼';
    end;
    lvProcesses.Columns[Ord(LColumn)].Caption := LCaption;
  end;
end;

procedure TMainForm.UpdateProcessDetails;
var
  LIndex, LRemote: Integer;
  LInfo, LParent: TMHProcessInfo;
  LLines: TStringList;
  LConnections: TArray<TMHNetConnection>;
  LConnection: TMHNetConnection;
  LAutostart: TMHAutostartEntry;
  LText: string;
begin
  LLines := TStringList.Create;
  try
    LIndex := -1;
    if FHasSelectedProcess then
      LIndex := FProcessModel.IndexOf(FSelectedProcess);
    if LIndex < 0 then
    begin
      if not FHasSelectedProcess then
        LLines.Add('Выберите процесс в таблице, чтобы увидеть подробности.')
      else
        LLines.Add(Format('Процесс PID %d больше не выполняется или скрыт фильтром.',
          [FSelectedProcess.Pid]));
    end
    else
    begin
      LInfo := FProcessModel[LIndex];
      LLines.Add('Имя: ' + LInfo.Name);
      LLines.Add(Format('PID: %d    Запущен: %s',
        [LInfo.Id.Pid, MHFormatFileTimeLocal(LInfo.Id.CreateTime)]));
      if FProcessModel.TryFindParent(LInfo, LParent) then
        LLines.Add(Format('Родитель: %s (PID %d)', [LParent.Name, LParent.Id.Pid]))
      else
        LLines.Add(Format('Родитель: PID %d (процесс уже завершён или недоступен)',
          [LInfo.ParentPid]));
      if LInfo.ImagePath = '' then
        LLines.Add('Путь: ' + MH_NO_DATA)
      else
        LLines.Add('Путь: ' + LInfo.ImagePath);
      LLines.Add(Format('CPU: %s    Память (как в диспетчере задач): %s    Рабочий набор: %s    ' +
        'Выделено: %s', [MHFormatMetric(LInfo.Cpu), MHFormatMetric(MHProcessMemory(LInfo)),
         MHFormatMetric(LInfo.WorkingSet), MHFormatMetric(LInfo.PrivateBytes)]));
      LLines.Add(Format('Видеокарта: %s    вычисления (Compute, CUDA): %s    видеопамять: %s',
        [MHFormatMetric(LInfo.Gpu), MHFormatMetric(LInfo.GpuCompute), MHFormatMetric(LInfo.GpuMemory)]));
      if LInfo.ThreadCount = MH_UNKNOWN_COUNT then
        LLines.Add('Потоков: ' + MH_NO_DATA)
      else
        LLines.Add('Потоков: ' + IntToStr(LInfo.ThreadCount));
      LLines.Add('Доступ: ' + MHAccessLevelToString(LInfo.Access) +
        '    Источник данных: ' + LInfo.SourceId);
      if LInfo.Access in [alDenied, alLimited] then
        LLines.Add('Часть сведений недоступна с текущими правами. Это ограничение ' +
          'Windows, а не признак угрозы.');
      LLines.Add('Подпись: ' + MHSignatureToString(LInfo.Signature));
      if LInfo.Sha256 <> '' then
        LLines.Add('SHA-256: ' + LInfo.Sha256);
      LLines.Add('Оценка риска: ' + MHRiskLevelToString(FProcessModel.RiskOf(LInfo)));
      if LInfo.CommandLine <> '' then
        LLines.Add('Командная строка: ' + Copy(LInfo.CommandLine, 1, 400));
      if FHasLastSnapshot then
      begin
        LConnections := FLastSnapshot.ConnectionsOf(LInfo.Id.Pid);
        LRemote := 0;
        LText := '';
        for LConnection in LConnections do
          if LConnection.IsRemote then
          begin
            Inc(LRemote);
            if LRemote <= 5 then
              LText := LText + Format('%s:%d ', [LConnection.RemoteAddress, LConnection.RemotePort]);
          end;
        LLines.Add(Format('Сеть: соединений %d, внешних %d %s', [Length(LConnections), LRemote, Trim(LText)]));
        for LAutostart in FLastSnapshot.Autostart do
          if (LInfo.ImagePath <> '') and SameText(LAutostart.ImagePath, MHNormalizePath(LInfo.ImagePath)) then
            LLines.Add('Автозапуск: ' + MHAutostartKindToString(LAutostart.Kind) + ' — ' + LAutostart.Name);
      end;
    end;
    SetMemoText(mmProcDetails, LLines.Text);
  finally
    LLines.Free;
  end;
end;


{ Системная нагрузка и живые графики }

function PercentText(AValue: Double): string;
begin
  Result := FormatFloat('0', AValue) + ' %';
end;

function RateText(AValue: Double): string;
begin
  Result := MHFormatBytes(AValue) + '/с';
end;

function TemperatureText(AValue: Double): string;
begin
  Result := FormatFloat('0', AValue) + ' °C';
end;

/// График для вида метрики: проценты и температура — шкала 0..100, скорости — автоматическая.
function NewChart(AOwner: TComponent; AParent: TWinControl; const ATitle: string;
  AKind: TMHMetricKind): TMHLineChart;
begin
  Result := TMHLineChart.Create(AOwner);
  Result.Parent := AParent;
  Result.Title := ATitle;
  Result.ShowHint := True;
  case AKind of
    mkCpuPercent, mkMemoryLoadPercent, mkDiskActivePercent, mkGpuPercent, mkGpuComputePercent:
      begin
        Result.SetFixedRange(0, 100);
        Result.Formatter := PercentText;
      end;
    mkGpuTemperatureCelsius, mkCpuTemperatureCelsius, mkDiskTemperatureCelsius:
      begin
        Result.SetFixedRange(0, 100);
        Result.Formatter := TemperatureText;
      end;
  else
    Result.Formatter := RateText;
  end;
end;

procedure TMainForm.CreateCharts;
var
  I: Integer;
begin
  FLiveCpu := TMHSeriesBuffer.Create(LIVE_POINTS);
  FLiveMem := TMHSeriesBuffer.Create(LIVE_POINTS);
  FLiveDisk := TMHSeriesBuffer.Create(LIVE_POINTS);
  FLiveGpu := TMHSeriesBuffer.Create(LIVE_POINTS);
  FChartCpu := NewChart(Self, pnlLiveCharts, 'Процессор', mkCpuPercent);
  FChartMem := NewChart(Self, pnlLiveCharts, 'Память', mkMemoryLoadPercent);
  FChartDisk := NewChart(Self, pnlLiveCharts, 'Активность диска', mkDiskActivePercent);
  FChartGpu := NewChart(Self, pnlLiveCharts, 'Видеокарта', mkGpuPercent);
  CreateDashboard;
  for I := Low(HISTORY_KINDS) to High(HISTORY_KINDS) do
    FHistoryCharts[I] := NewChart(Self, pnlHistoryCharts, HISTORY_TITLES[I], HISTORY_KINDS[I]);
  pnlLiveChartsResize(nil);
  pnlHistoryChartsResize(nil);
end;

procedure TMainForm.CreateDashboard;
var
  LKind: TMHTileKind;
  LData: TMHTileData;
const
  TITLES: array[TMHTileKind] of string = ('Процессор', 'Память', 'Диск', 'Сеть', 'Видеокарта',
    'Температура');
begin
  for LKind := Low(TMHTileKind) to High(TMHTileKind) do
  begin
    FTiles[LKind] := TMHMetricTile.Create(Self);
    FTiles[LKind].Parent := pnlTiles;
    LData := Default(TMHTileData);
    LData.Kind := LKind;
    LData.Title := TITLES[LKind];
    LData.Value := MH_NO_DATA;
    LData.State := tsNoData;
    FTiles[LKind].SetData(LData);
  end;
  FReasons := TMHReasonList.Create(Self);
  FReasons.Parent := pnlReasons;
  FReasons.Align := alTop;
  FReasons.SetItems(MHBuildDashboardReasons(TMHSnapshot.Create(0, 0), 1));
  pnlTilesResize(nil);
end;

function TMainForm.DashboardTile(AKind: TMHTileKind): TMHMetricTile;
begin
  Result := FTiles[AKind];
end;

procedure TMainForm.pnlTilesResize(Sender: TObject);
var
  LKind: TMHTileKind;
  LCount, LGap, LWidth, I: Integer;
begin
  if FTiles[tkCpu] = nil then
    Exit;
  LCount := Ord(High(TMHTileKind)) + 1;
  LGap := MulDiv(8, CurrentPPI, 96);
  LWidth := (pnlTiles.ClientWidth - LGap * (LCount - 1)) div LCount;
  I := 0;
  for LKind := Low(TMHTileKind) to High(TMHTileKind) do
  begin
    FTiles[LKind].SetBounds(I * (LWidth + LGap), 0, Max(10, LWidth), pnlTiles.ClientHeight);
    Inc(I);
  end;
end;

procedure TMainForm.pnlLiveChartsResize(Sender: TObject);
var
  LCharts: array[0..3] of TMHLineChart;
  LWidth, LGap, I: Integer;
begin
  if FChartCpu = nil then
    Exit;
  LCharts[0] := FChartCpu;
  LCharts[1] := FChartMem;
  LCharts[2] := FChartDisk;
  LCharts[3] := FChartGpu;
  LGap := MulDiv(6, CurrentPPI, 96);
  LWidth := (pnlLiveCharts.ClientWidth - LGap * (Length(LCharts) + 1)) div Length(LCharts);
  for I := 0 to High(LCharts) do
    LCharts[I].SetBounds(LGap + I * (LWidth + LGap), 0, Max(10, LWidth),
      Max(10, pnlLiveCharts.ClientHeight));
end;

procedure TMainForm.pnlHistoryChartsResize(Sender: TObject);
var
  LHeight, LGap, I: Integer;
begin
  if FHistoryCharts[0] = nil then
    Exit;
  LGap := MulDiv(4, CurrentPPI, 96);
  LHeight := (pnlHistoryCharts.ClientHeight - LGap) div Length(FHistoryCharts);
  for I := Low(FHistoryCharts) to High(FHistoryCharts) do
    FHistoryCharts[I].SetBounds(LGap, LGap + I * LHeight,
      Max(10, pnlHistoryCharts.ClientWidth - 2 * LGap), Max(10, LHeight - LGap));
end;

function FindMetric(const ASnapshot: TMHSnapshot; AKind: TMHMetricKind;
  out AMetric: TMHMetric): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(ASnapshot.Metrics) do
    if ASnapshot.Metrics[I].Kind = AKind then
    begin
      AMetric := ASnapshot.Metrics[I];
      Exit(True);
    end;
  AMetric := TMHMetric.NoData(AKind, ASnapshot.TimestampUtc);
  Result := False;
end;

procedure TMainForm.UpdateSystem(const ASnapshot: TMHSnapshot);
var
  LStatus: TMHSourceStatus;
  LCpu, LMemLoad, LActive, LGpu: TMHMetric;
  LTiles: TArray<TMHTileData>;
  LTile: TMHTileData;
begin
  // Нет источника «system» в снимке — значит, он не подключён; графики не трогаем.
  if not ASnapshot.FindSource(TMHSystemCollector.SourceIdValue, LStatus) then
    Exit;
  FindMetric(ASnapshot, mkCpuPercent, LCpu);
  FindMetric(ASnapshot, mkMemoryLoadPercent, LMemLoad);
  FindMetric(ASnapshot, mkDiskActivePercent, LActive);
  FindMetric(ASnapshot, mkGpuPercent, LGpu);

  // Точки «нет данных» тоже добавляются — на графике это разрыв.
  FLiveCpu.Add(LCpu);
  FLiveMem.Add(LMemLoad);
  FLiveDisk.Add(LActive);
  FLiveGpu.Add(LGpu);
  FChartCpu.SetPoints(FLiveCpu.ToArray);
  FChartMem.SetPoints(FLiveMem.ToArray);
  FChartDisk.SetPoints(FLiveDisk.ToArray);
  FChartGpu.SetPoints(FLiveGpu.ToArray);

  LTiles := MHBuildDashboardTiles(ASnapshot);
  for LTile in LTiles do
    FTiles[LTile.Kind].SetData(LTile);
end;

{ История }

procedure TMainForm.LoadHistory;
var
  LHistory: IMHMetricHistory;
  LFrom, LTo: TDateTime;
  LGeneration, I: Integer;
  LContext: TMHWorkContext;
  LBaselines: TMHBaselineManager;
  LStorage: TMHSQLiteRepository;
  LMinSamples: Integer;
begin
  FHistoryRequested := True;
  LHistory := FServices.MetricHistory;
  if LHistory = nil then
  begin
    lblHistoryStatus.Caption := 'История недоступна: ' + FServices.StorageError;
    for I := Low(FHistoryCharts) to High(FHistoryCharts) do
      FHistoryCharts[I].SetPoints(nil);
    Exit;
  end;
  if FHistoryLoading then
  begin
    // Повторим, когда завершится текущая загрузка.
    FHistoryReloadPending := True;
    Exit;
  end;
  FreeAndNil(FHistoryLoader); // предыдущий поток уже завершился
  FHistoryLoading := True;
  Inc(FHistoryGeneration);
  LGeneration := FHistoryGeneration;
  LTo := FServices.Clock.NowUtc;
  LFrom := LTo - HISTORY_HOURS[Max(0, cbHistoryPeriod.ItemIndex)] / HoursPerDay;
  lblHistoryStatus.Caption := 'Загрузка…';
  if FHasLastSnapshot and FLastSnapshot.Context.Available and
     (FLastSnapshot.Context.WorkContext <> wcUnknown) then
    LContext := FLastSnapshot.Context.WorkContext
  else
    LContext := wcWork;
  LBaselines := FServices.Baselines;
  LStorage := FServices.Storage;
  LMinSamples := FServices.Settings.Analyzer.BaselineMinSamples;

  FHistoryLoader := TThread.CreateAnonymousThread(
    procedure
    var
      LSeries: TArray<TArray<TMHMetric>>;
      LError, LInfo: string;
      K: Integer;
      LBase, LCurrent: TMHBaseline;
      LComparisons: TArray<TMHMetricComparison>;
      LDeviations: TArray<TMHProcessDeviation>;
    begin
      SetLength(LSeries, Length(HISTORY_KINDS));
      LComparisons := nil;
      LDeviations := nil;
      LInfo := '';
      try
        for K := Low(HISTORY_KINDS) to High(HISTORY_KINDS) do
          LSeries[K] := LHistory.LoadMetricSeries(HISTORY_KINDS[K], LFrom, LTo, HISTORY_POINTS);
        // Сравнение периода с профилем нормы того же контекста работы (MH-06).
        if (LBaselines <> nil) and (LStorage <> nil) then
        begin
          LBase := LBaselines.BaselineFor(LContext);
          LCurrent := TMHBaselineBuilder.Build(LContext,
            LStorage.LoadSnapshotsSampled(LFrom, LTo, 2000, LContext), LTo);
          LComparisons := MHComparePeriods(LCurrent, LBase);
          LDeviations := MHCompareProcesses(LCurrent, LBase);
          if LBase.IsEstablished(LMinSamples) then
            LInfo := Format('Норма для режима «%s»: %d снимков за %s — %s. Сравнивается выбранный период.',
              [MHWorkContextToString(LContext), LBase.SampleCount, MHFormatUtcAsLocal(LBase.PeriodFromUtc),
               MHFormatUtcAsLocal(LBase.PeriodToUtc)])
          else
            LInfo := Format('Профиль нормы для режима «%s» ещё формируется: %d из %d снимков. ' +
              'Сравнение станет точнее после периода обучения.',
              [MHWorkContextToString(LContext), LBase.SampleCount, LMinSamples]);
        end
        else
          LInfo := 'Профиль нормы недоступен без истории наблюдений.';
      except
        on E: Exception do
          LError := E.Message;
      end;
      FHistoryResultComparisons := LComparisons;
      FHistoryResultDeviations := LDeviations;
      FHistoryResultBaselineInfo := LInfo;
      FHistoryResultSeries := LSeries;
      FHistoryResultError := LError;
      FHistoryResultFrom := LFrom;
      FHistoryResultTo := LTo;
      FHistoryResultGeneration := LGeneration;
      // Привязка к потоку: при его уничтожении недоставленный вызов удаляется.
      TThread.Queue(TThread.Current, HistoryLoaded);
    end);
  FHistoryLoader.FreeOnTerminate := False;
  FHistoryLoader.Start;
end;

procedure TMainForm.ApplyHistory(AGeneration: Integer; AFromUtc, AToUtc: TDateTime;
  const ASeries: TArray<TArray<TMHMetric>>; const AError: string);
var
  I, J, LPoints: Integer;
begin
  if FDestroying then
    Exit;
  FHistoryLoading := False;
  if AGeneration = FHistoryGeneration then
  begin
    if AError <> '' then
      lblHistoryStatus.Caption := 'Не удалось загрузить историю: ' + AError
    else
    begin
      LPoints := 0;
      for I := Low(FHistoryCharts) to High(FHistoryCharts) do
      begin
        FHistoryCharts[I].SetTimeWindow(AFromUtc, AToUtc);
        FHistoryCharts[I].SetPoints(ASeries[I]);
        for J := 0 to High(ASeries[I]) do
          if ASeries[I][J].HasValue then
            Inc(LPoints);
      end;
      if LPoints = 0 then
        lblHistoryStatus.Caption := 'За выбранный период данных нет'
      else
        lblHistoryStatus.Caption := Format('%s — %s',
          [MHFormatUtcAsLocal(AFromUtc), MHFormatUtcAsLocal(AToUtc)]);
    end;
  end;
  if FHistoryReloadPending then
  begin
    FHistoryReloadPending := False;
    LoadHistory;
  end;
end;

procedure TMainForm.HistoryLoaded;
begin
  if not FDestroying and (FHistoryResultGeneration = FHistoryGeneration) then
    ApplyComparison;
  ApplyHistory(FHistoryResultGeneration, FHistoryResultFrom, FHistoryResultTo,
    FHistoryResultSeries, FHistoryResultError);
  FHistoryResultSeries := nil;
end;

function TMainForm.DefaultConfirm(const AQuestion: string): Boolean;
begin
  Result := MessageDlg(AQuestion, mtConfirmation, [mbYes, mbNo], 0, mbNo) = mrYes;
end;

procedure TMainForm.cbHistoryPeriodChange(Sender: TObject);
begin
  LoadHistory;
end;

procedure TMainForm.btnHistoryRefreshClick(Sender: TObject);
begin
  LoadHistory;
end;

{ Настройки хранения }

procedure TMainForm.UpdateStorageInfo;
var
  LStats: TMHHistoryStats;
  LStorage: TMHSQLiteRepository;
begin
  LStorage := FServices.Storage;
  cbRetention.Enabled := LStorage <> nil;
  chkStorePaths.Enabled := LStorage <> nil;
  btnClearHistory.Enabled := LStorage <> nil;
  if LStorage = nil then
  begin
    lblStoragePath.Caption := MH_NO_DATA;
    lblStorageStats.Caption := 'История недоступна: ' + FServices.StorageError;
    Exit;
  end;
  lblStoragePath.Caption := LStorage.FileName;
  try
    LStats := LStorage.GetStats;
    if LStats.SnapshotCount = 0 then
      lblStorageStats.Caption := Format('Записей нет · размер файла %s',
        [MHFormatBytes(LStats.FileSizeBytes)])
    else
      lblStorageStats.Caption := Format('Снимков: %d · размер файла %s · с %s',
        [LStats.SnapshotCount, MHFormatBytes(LStats.FileSizeBytes),
         FormatDateTime('dd.mm.yyyy hh:nn', TTimeZone.Local.ToLocalTime(LStats.OldestUtc))]);
  except
    on E: Exception do
      lblStorageStats.Caption := 'Не удалось прочитать сведения: ' + E.Message;
  end;
end;

procedure TMainForm.InitStorageSettings;
var
  I: Integer;
  LOptions: TMHStorageOptions;
begin
  cbRetention.Items.Clear;
  for I := Low(RETENTION_DAYS) to High(RETENTION_DAYS) do
    cbRetention.Items.Add(Format('%d дн.', [RETENTION_DAYS[I]]));
  cbRetention.ItemIndex := -1;
  if FServices.Storage <> nil then
  begin
    LOptions := FServices.Storage.Options;
    for I := Low(RETENTION_DAYS) to High(RETENTION_DAYS) do
      if RETENTION_DAYS[I] = LOptions.RetentionDays then
        cbRetention.ItemIndex := I;
    FInitializingSettings := True;
    try
      chkStorePaths.Checked := LOptions.StoreProcessPaths;
    finally
      FInitializingSettings := False;
    end;
  end;
  UpdateStorageInfo;
end;

procedure TMainForm.cbRetentionChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (FServices.Storage = nil) or (cbRetention.ItemIndex < 0) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.RetentionDays := RETENTION_DAYS[cbRetention.ItemIndex];
  FServices.Logger.Log(llInfo, 'app',
    Format('Срок хранения истории: %d дн.', [LSettings.RetentionDays]));
  ChangeSettings(LSettings);
end;

procedure TMainForm.chkStorePathsClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (FServices.Storage = nil) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.StoreProcessPaths := chkStorePaths.Checked;
  if LSettings.StoreProcessPaths then
    FServices.Logger.Log(llInfo, 'app', 'Пути процессов сохраняются в истории')
  else
    FServices.Logger.Log(llInfo, 'app', 'Пути процессов больше не сохраняются в истории');
  ChangeSettings(LSettings);
end;

procedure TMainForm.btnClearHistoryClick(Sender: TObject);
var
  LRecord: TMHActionRecord;
begin
  if FServices.Storage = nil then
    Exit;
  if not FConfirm('Удалить всю историю наблюдений? Это действие нельзя отменить.') then
    Exit;
  LRecord.TimestampUtc := FServices.Clock.NowUtc;
  LRecord.Action := 'history-clear';
  LRecord.Target := FServices.Storage.FileName;
  try
    FServices.Storage.Clear;
    LRecord.Result := 'История наблюдений очищена';
    LRecord.Success := True;
  except
    on E: Exception do
    begin
      FServices.Logger.Log(llError, 'app', 'Не удалось очистить историю: ' + E.Message);
      LRecord.Result := E.Message;
      LRecord.Success := False;
    end;
  end;
  if FServices.ActionLog <> nil then
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', 'Журнал действий недоступен: ' + E.Message);
    end;
  RefreshActionLog;
  UpdateStorageInfo;
  UpdateEvents;
  if FHistoryRequested then
    LoadHistory;
end;


{ Цикл сканирования, защита, находки }

procedure TMainForm.HandleCycle(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);
begin
  FLastSnapshot := ASnapshot;
  FHasLastSnapshot := True;
  FFindingsModel.UpdateActive(AFindings, ASnapshot.TimestampUtc);
  HandleSnapshot(ASnapshot);
  RefreshFindingsList;
  UpdateProtection(ASnapshot);
  NotifyAlerts(AFindings, ASnapshot.TimestampUtc);
  UpdateTray;
end;

procedure TMainForm.UpdateProtection(const ASnapshot: TMHSnapshot);
var
  LAlerts, LLow: Integer;
  LText, LUnavailable: string;
  LStatus: TMHSourceStatus;
  LInfo: TSystemInfo;
  LState: TMHTileState;
begin
  LAlerts := FFindingsModel.ActiveAlertCount(rlNeedsReview);
  LLow := FFindingsModel.ActiveAlertCount(rlLow) - LAlerts;
  if LAlerts > 0 then
  begin
    lblAlerts.Caption := Format('⚠ Требуют проверки: %d', [LAlerts]);
    LState := tsAlert;
  end
  else if LLow > 0 then
  begin
    lblAlerts.Caption := Format('✔ Угроз не обнаружено · под наблюдением: %d', [LLow]);
    LState := tsOk;
  end
  else
  begin
    lblAlerts.Caption := '✔ Признаков угроз не обнаружено';
    LState := tsOk;
  end;
  // Светлый фон цвета состояния, заголовок — насыщенным цветом (не только цвет: есть значок и текст).
  if LState = tsAlert then
    pnlStatus.Color := TColor($00EAEBFD)
  else
    pnlStatus.Color := TColor($00ECF6EA);
  lblAlerts.Font.Color := MHStateColor(LState);

  GetSystemInfo(LInfo);
  FReasons.SetItems(MHBuildDashboardReasons(ASnapshot, Integer(LInfo.dwNumberOfProcessors)));

  LUnavailable := '';
  for LStatus in ASnapshot.Sources do
    if LStatus.State in [ssUnavailable, ssError] then
      LUnavailable := LUnavailable + LStatus.SourceId + ' ';
  if LAlerts > 0 then
    LText := 'Объяснение и безопасные действия — в «Находках». '
  else
    LText := '';
  if ASnapshot.FindSource(TMHProcessCollector.SourceIdValue, LStatus) and LStatus.RequiresElevation then
    LText := LText + 'Без прав администратора часть процессов видна не полностью.'
  else
    LText := LText + 'Все доступные процессы анализируются.';
  if LUnavailable <> '' then
    LText := LText + ' Недоступно: ' + Trim(LUnavailable) + ' (подробности ниже).';
  lblRights.Caption := LText;
  lblRights.Hint := LText;
  lblRights.ShowHint := True;
end;

procedure TMainForm.btnGoFindingsClick(Sender: TObject);
begin
  NavigateTo(pgFindings);
end;

procedure TMainForm.RefreshFindingsList;
var
  LIndex: Integer;
begin
  FUpdatingFindings := True;
  try
    lvFindings.Items.Count := FFindingsModel.Count;
    LIndex := -1;
    if FSelectedFindingKey <> '' then
      LIndex := FFindingsModel.IndexOfKey(FSelectedFindingKey);
    lvFindings.ItemIndex := LIndex;
    lvFindings.Invalidate;
  finally
    FUpdatingFindings := False;
  end;
  if FFindingsModel.Mode = fmActive then
    lblFindingsCount.Caption := Format('Активных: %d', [FFindingsModel.Count])
  else
    lblFindingsCount.Caption := Format('В истории: %d', [FFindingsModel.Count]);
  UpdateFindingCard;
end;

procedure TMainForm.lvFindingsData(Sender: TObject; Item: TListItem);
var
  LRow: TMHFindingRow;
begin
  if (FFindingsModel = nil) or (Item.Index >= FFindingsModel.Count) then
    Exit;
  LRow := FFindingsModel[Item.Index];
  Item.Caption := MHRiskLevelToString(LRow.Finding.Level);
  Item.SubItems.Add(IntToStr(LRow.Finding.Score));
  Item.SubItems.Add(MHFindingCategoryToString(LRow.Finding.Category));
  if LRow.Finding.ProcessName <> '' then
    Item.SubItems.Add(LRow.Finding.ProcessName)
  else
    Item.SubItems.Add('система');
  Item.SubItems.Add(MHFormatUtcAsLocal(LRow.LastSeenUtc));
  Item.SubItems.Add(IntToStr(LRow.Occurrences));
end;

procedure TMainForm.lvFindingsSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
begin
  if FUpdatingFindings then
    Exit;
  if Selected and (Item <> nil) and (Item.Index < FFindingsModel.Count) then
    FSelectedFindingKey := FFindingsModel[Item.Index].Finding.Key
  else if lvFindings.ItemIndex < 0 then
    FSelectedFindingKey := '';
  lblCardStatus.Caption := '';
  UpdateFindingCard;
end;

procedure TMainForm.cbFindingsModeChange(Sender: TObject);
var
  LHistory: TArray<TMHStoredFinding>;
begin
  if cbFindingsMode.ItemIndex = 1 then
  begin
    LHistory := nil;
    if FServices.FindingHistory <> nil then
      try
        LHistory := FServices.FindingHistory.LoadFindings(FServices.Clock.NowUtc - 7,
          FServices.Clock.NowUtc + 1, 1000);
      except
        on E: Exception do
          FServices.Logger.Log(llWarning, 'app', 'История находок недоступна: ' + E.Message);
      end;
    FFindingsModel.SetHistory(LHistory);
    FFindingsModel.Mode := fmHistory;
  end
  else
    FFindingsModel.Mode := fmActive;
  RefreshFindingsList;
end;

procedure TMainForm.cbFindingsMinLevelChange(Sender: TObject);
begin
  if cbFindingsMinLevel.ItemIndex >= 0 then
    FFindingsModel.MinLevel := TMHRiskLevel(cbFindingsMinLevel.ItemIndex + 1);
  RefreshFindingsList;
end;

function TMainForm.SelectedFinding(out ARow: TMHFindingRow): Boolean;
var
  LIndex: Integer;
begin
  LIndex := -1;
  if FSelectedFindingKey <> '' then
    LIndex := FFindingsModel.IndexOfKey(FSelectedFindingKey);
  Result := LIndex >= 0;
  if Result then
    ARow := FFindingsModel[LIndex]
  else
    ARow := Default(TMHFindingRow);
end;

function TMainForm.FindLiveProcess(const AId: TMHProcessId; out AInfo: TMHProcessInfo): Boolean;
var
  LInfo: TMHProcessInfo;
begin
  AInfo := Default(TMHProcessInfo);
  if not FHasLastSnapshot or not AId.HasCreateTime then
    Exit(False);
  for LInfo in FLastSnapshot.Processes do
    if (LInfo.Id = AId) and SameText(LInfo.SourceId, TMHProcessCollector.SourceIdValue) then
    begin
      AInfo := LInfo;
      Exit(True);
    end;
  Result := False;
end;

function TMainForm.ParentNameOf(APid: Cardinal): string;
var
  LInfo: TMHProcessInfo;
begin
  Result := '';
  if not FHasLastSnapshot or (APid = 0) then
    Exit;
  for LInfo in FLastSnapshot.Processes do
    if (LInfo.Id.Pid = APid) and SameText(LInfo.SourceId, TMHProcessCollector.SourceIdValue) then
      Exit(LInfo.Name);
end;

function TMainForm.LoadSeriesFor(const AFinding: TMHFinding): TArray<TMHMetric>;
var
  LNow: TDateTime;
begin
  Result := nil;
  if FServices.MetricHistory = nil then
    Exit;
  LNow := FServices.Clock.NowUtc;
  try
    if AFinding.Process.HasCreateTime then
      Result := FServices.MetricHistory.LoadProcessSeries(AFinding.Process, mkCpuPercent,
        LNow - 1 / HoursPerDay, LNow, 120)
    else if AFinding.Category = fcPerformance then
      Result := FServices.MetricHistory.LoadMetricSeries(mkCpuPercent, LNow - 1 / HoursPerDay, LNow, 120);
  except
    on E: Exception do
    begin
      FServices.Logger.Log(llWarning, 'app', 'График нагрузки недоступен: ' + E.Message);
      Result := nil;
    end;
  end;
end;

procedure TMainForm.UpdateFindingCard;
var
  LRow: TMHFindingRow;
  LProcess: TMHProcessInfo;
  LHasProcess, LHasFinding: Boolean;
begin
  LHasFinding := SelectedFinding(LRow);
  LHasProcess := False;
  if not LHasFinding then
  begin
    if FFindingsModel.Count = 0 then
      SetMemoText(mmCard, 'Находок нет. Отсутствие находок не гарантирует отсутствие угроз: ' +
        'MineHunter X оценивает поведение программ, а не проверяет файлы по базе сигнатур.')
    else
      SetMemoText(mmCard, 'Выберите находку в списке, чтобы увидеть объяснение и доступные действия.');
    FCardSeriesKey := '';
    FCardChart.SetPoints(nil);
    FCardChart.Title := 'Нагрузка (последний час)';
  end
  else
  begin
    LHasProcess := FindLiveProcess(LRow.Finding.Process, LProcess);
    SetMemoText(mmCard, string.Join(sLineBreak,
      MHFindingCardLines(LRow, LProcess, LHasProcess, ParentNameOf(LRow.Finding.ParentPid))));
    if FCardSeriesKey <> LRow.Finding.Key then
    begin
      FCardSeriesKey := LRow.Finding.Key;
      FCardChart.SetPoints(LoadSeriesFor(LRow.Finding));
    end;
    if LRow.Finding.ProcessName <> '' then
      FCardChart.Title := 'CPU: ' + LRow.Finding.ProcessName + ' (час)'
    else
      FCardChart.Title := 'CPU системы (час)';
  end;
  btnOpenLocation.Enabled := LHasFinding and (LRow.Finding.ImagePath <> '');
  btnDefender.Enabled := LHasFinding and (LRow.Finding.ImagePath <> '') and not DefenderRunning;
  btnStopProcess.Enabled := LHasFinding and LHasProcess;
  btnAllow.Enabled := LHasFinding and (LRow.Finding.ImagePath <> '');
  btnExportCard.Enabled := LHasFinding;
  if FRemediateButton <> nil then
    FRemediateButton.Enabled := LHasFinding and FHasLastSnapshot and (FServices.Quarantine <> nil);
end;

procedure TMainForm.pnlCardChartResize(Sender: TObject);
begin
  if FCardChart <> nil then
    FCardChart.SetBounds(4, 4, Max(10, pnlCardChart.ClientWidth - 8),
      Max(10, pnlCardChart.ClientHeight - 8));
end;

procedure TMainForm.ShowActionResult(const AResult: TMHActionResult);
var
  LText: string;
begin
  LText := AResult.Message;
  if AResult.Details <> '' then
    LText := LText + ' ' + AResult.Details;
  lblCardStatus.Caption := LText;
  if AResult.Succeeded then
    FServices.Logger.Log(llInfo, 'actions', LText)
  else
    FServices.Logger.Log(llWarning, 'actions', LText);
  UpdateEvents;
  RefreshActionLog;
end;

procedure TMainForm.btnOpenLocationClick(Sender: TObject);
var
  LRow: TMHFindingRow;
begin
  if SelectedFinding(LRow) then
    ShowActionResult(FServices.Actions.OpenFileLocation(LRow.Finding.ImagePath));
end;

procedure TMainForm.btnDefenderClick(Sender: TObject);
var
  LRow: TMHFindingRow;
  LPath: string;
  LActions: TMHSafeActions;
begin
  if not SelectedFinding(LRow) or DefenderRunning then
    Exit;
  // Завершившийся поток предыдущей проверки освобождается здесь (или при закрытии окна):
  // отложенных вызовов без владельца, которые могли бы пережить форму, нет.
  FreeAndNil(FDefenderThread);
  FDefenderDone := False;
  LPath := LRow.Finding.ImagePath;
  LActions := FServices.Actions;
  lblCardStatus.Caption := 'Microsoft Defender проверяет файл… Это может занять несколько минут.';
  btnDefender.Enabled := False;
  // Проверка выполняется в фоне; результат передаётся через очередь потока,
  // при закрытии окна проверка отменяется.
  FDefenderThread := TThread.CreateAnonymousThread(
    procedure
    begin
      FDefenderResult := LActions.ScanWithDefender(LPath,
        function: Boolean
        begin
          Result := FDestroying;
        end);
      TThread.Queue(TThread.Current, DefenderFinished);
    end);
  FDefenderThread.FreeOnTerminate := False;
  FDefenderThread.Start;
end;

procedure TMainForm.DefenderFinished;
begin
  if FDestroying then
    Exit;
  // Поток уже завершает работу; объект освобождается при следующей проверке или закрытии окна.
  FDefenderDone := True;
  ShowActionResult(FDefenderResult);
  UpdateFindingCard;
end;

procedure TMainForm.btnStopProcessClick(Sender: TObject);
var
  LRow: TMHFindingRow;
  LProcess: TMHProcessInfo;
begin
  if not SelectedFinding(LRow) or not FindLiveProcess(LRow.Finding.Process, LProcess) then
    Exit;
  if not FConfirm(Format('Остановить процесс %s (PID %d)?' + sLineBreak + '%s' + sLineBreak + sLineBreak +
    'Несохранённые данные этой программы будут потеряны. Файл программы не удаляется.',
    [LProcess.Name, LProcess.Id.Pid, LProcess.ImagePath])) then
    Exit;
  ShowActionResult(FServices.Actions.TerminateProcess(LProcess.Id, LProcess.Name));
end;

procedure TMainForm.btnAllowClick(Sender: TObject);
var
  LRow: TMHFindingRow;
  LProcess: TMHProcessInfo;
  LExclusion: TMHExclusion;
  LSettings: TMHAppSettings;
  LFile: TMHFileInfo;
  LRecord: TMHActionRecord;
begin
  if not SelectedFinding(LRow) or (LRow.Finding.ImagePath = '') then
    Exit;
  if not FConfirm(Format('Добавить %s в разрешённые программы?' + sLineBreak + '%s' + sLineBreak + sLineBreak +
    'MineHunter X перестанет сообщать об этом файле. Если файл будет заменён другим, ' +
    'проверка возобновится (исключение привязано к SHA-256).',
    [LRow.Finding.ProcessName, LRow.Finding.ImagePath])) then
    Exit;
  LExclusion := Default(TMHExclusion);
  LExclusion.Key := MHProgramKey(LRow.Finding.ImagePath, LRow.Finding.ProcessName);
  LExclusion.Name := LRow.Finding.ProcessName;
  LExclusion.CreatedUtc := FServices.Clock.NowUtc;
  LExclusion.Comment := 'Добавлено из карточки находки: ' + LRow.Finding.Title;
  if FindLiveProcess(LRow.Finding.Process, LProcess) and (LProcess.Sha256 <> '') then
    LExclusion.Sha256 := LProcess.Sha256
  else if FHasLastSnapshot and FLastSnapshot.FindFile(LRow.Finding.ImagePath, LFile) then
    LExclusion.Sha256 := LFile.Sha256;
  LSettings := FServices.Settings;
  if MHAddExclusion(LSettings, LExclusion) then
  begin
    ChangeSettings(LSettings);
    if FServices.ActionLog <> nil then
    begin
      LRecord.TimestampUtc := FServices.Clock.NowUtc;
      LRecord.Action := 'exclusion-add';
      LRecord.Target := LRow.Finding.ImagePath;
      LRecord.Result := 'Программа добавлена в исключения';
      LRecord.Success := True;
      try
        FServices.ActionLog.LogAction(LRecord);
      except
        on E: Exception do
          FServices.Logger.Log(llWarning, 'actions', 'Журнал действий недоступен: ' + E.Message);
      end;
    end;
    FFindingsModel.Remove(LRow.Finding.Key);
    FSelectedFindingKey := '';
    lblCardStatus.Caption := LRow.Finding.ProcessName + ' добавлена в исключения.';
    RefreshFindingsList;
    RefreshExclusions;
    RefreshActionLog;
  end
  else
    lblCardStatus.Caption := 'Эта программа уже есть в исключениях.';
end;

function TMainForm.ReportOptions: TMHReportOptions;
begin
  Result := TMHReportOptions.Default;
  Result.RedactPaths := FServices.Settings.RedactPathsInReports;
  Result.AppVersion := MH_CORE_VERSION;
  if FServices.Analyzer <> nil then
    Result.RulesetVersion := FServices.Analyzer.GetRulesetVersion;
  Result.GeneratedUtc := FServices.Clock.NowUtc;
end;

procedure TMainForm.ExportReport(const AFileName: string; AHtml: Boolean);
var
  LFindings: TMHFindings;
  I: Integer;
  LSnapshot: TMHSnapshot;
begin
  SetLength(LFindings, FFindingsModel.ActiveCount);
  for I := 0 to High(LFindings) do
    LFindings[I] := FFindingsModel.ActiveRows(I).Finding;
  if FHasLastSnapshot then
    LSnapshot := FLastSnapshot
  else
    LSnapshot := TMHSnapshot.Create(0, FServices.Clock.NowUtc);
  if AHtml then
    MHSaveTextFile(AFileName, TMHReportBuilder.BuildHtml(LSnapshot, LFindings, ReportOptions))
  else
    MHSaveTextFile(AFileName, TMHReportBuilder.BuildJson(LSnapshot, LFindings, ReportOptions));
  FServices.Logger.Log(llInfo, 'app', 'Отчёт сохранён: ' + AFileName);
end;

procedure TMainForm.ExportFindingCard(const AFileName: string; AHtml: Boolean);
var
  LRow: TMHFindingRow;
  LProcess: TMHProcessInfo;
  LSeries: TArray<TMHMetric>;
begin
  if not SelectedFinding(LRow) then
    raise EMHError.Create('Находка не выбрана');
  if not FindLiveProcess(LRow.Finding.Process, LProcess) then
    LProcess := TMHProcessInfo.Create(LRow.Finding.Process, LRow.Finding.ProcessName, LRow.LastSeenUtc);
  LSeries := LoadSeriesFor(LRow.Finding);
  if AHtml then
    MHSaveTextFile(AFileName, TMHReportBuilder.FindingCardHtml(LRow.Finding, LProcess, LSeries, ReportOptions))
  else
    MHSaveTextFile(AFileName, TMHReportBuilder.FindingCardJson(LRow.Finding, LProcess, LSeries, ReportOptions));
  FServices.Logger.Log(llInfo, 'app', 'Карточка находки сохранена: ' + AFileName);
end;

function TMainForm.AskExportFile(const ADefaultName: string; out AFileName: string;
  out AHtml: Boolean): Boolean;
begin
  sdExport.FileName := ADefaultName;
  sdExport.FilterIndex := 1;
  Result := sdExport.Execute(Handle);
  if Result then
  begin
    AFileName := sdExport.FileName;
    AHtml := not SameText(ExtractFileExt(AFileName), '.json');
  end;
end;

procedure TMainForm.btnExportReportClick(Sender: TObject);
var
  LFile: string;
  LHtml: Boolean;
begin
  if not AskExportFile('MineHunterX-report-' + FormatDateTime('yyyymmdd-hhnn', Now) + '.html', LFile, LHtml) then
    Exit;
  try
    ExportReport(LFile, LHtml);
    lblCardStatus.Caption := 'Отчёт сохранён: ' + LFile;
  except
    on E: Exception do
      lblCardStatus.Caption := 'Не удалось сохранить отчёт: ' + E.Message;
  end;
end;

procedure TMainForm.btnExportCardClick(Sender: TObject);
var
  LFile: string;
  LHtml: Boolean;
begin
  if not AskExportFile('MineHunterX-finding-' + FormatDateTime('yyyymmdd-hhnn', Now) + '.html', LFile, LHtml) then
    Exit;
  try
    ExportFindingCard(LFile, LHtml);
    lblCardStatus.Caption := 'Карточка сохранена: ' + LFile;
  except
    on E: Exception do
      lblCardStatus.Caption := 'Не удалось сохранить карточку: ' + E.Message;
  end;
end;

{ Процессы: фильтры }

procedure TMainForm.chkOnlyFindingsClick(Sender: TObject);
begin
  FProcessModel.OnlyWithFindings := chkOnlyFindings.Checked;
  RefreshProcessList;
end;

procedure TMainForm.chkOnlyUnsignedClick(Sender: TObject);
begin
  FProcessModel.OnlyUnsigned := chkOnlyUnsigned.Checked;
  RefreshProcessList;
end;

{ Сравнение с нормой }

procedure TMainForm.ApplyComparison;
var
  LItem: TListItem;
  LComparison: TMHMetricComparison;
  LDeviation: TMHProcessDeviation;
  LFmt: TFunc<TMHStat, string>;
begin
  lblBaselineInfo.Caption := FHistoryResultBaselineInfo;
  LFmt :=
    function(AStat: TMHStat): string
    begin
      if not AStat.HasData then
        Result := MH_NO_DATA
      else
        Result := FormatFloat('0', AStat.Median) + '% / ' + FormatFloat('0', AStat.P95) + '%';
    end;
  lvComparison.Items.BeginUpdate;
  try
    lvComparison.Items.Clear;
    for LComparison in FHistoryResultComparisons do
    begin
      LItem := lvComparison.Items.Add;
      case LComparison.Kind of
        mkCpuPercent: LItem.Caption := 'Процессор';
        mkMemoryLoadPercent: LItem.Caption := 'Память';
        mkDiskActivePercent: LItem.Caption := 'Активность диска';
      else
        LItem.Caption := '';
      end;
      LItem.SubItems.Add(LFmt(LComparison.Current));
      LItem.SubItems.Add(LFmt(LComparison.Baseline));
      LItem.SubItems.Add(LComparison.Verdict);
    end;
  finally
    lvComparison.Items.EndUpdate;
  end;
  lvDeviations.Items.BeginUpdate;
  try
    lvDeviations.Items.Clear;
    for LDeviation in FHistoryResultDeviations do
    begin
      LItem := lvDeviations.Items.Add;
      LItem.Caption := LDeviation.Name;
      LItem.SubItems.Add(FormatFloat('0', LDeviation.CurrentCpuP95) + '%');
      if LDeviation.IsNewProgram then
        LItem.SubItems.Add('—')
      else
        LItem.SubItems.Add(FormatFloat('0', LDeviation.BaselineCpuP95) + '%');
      LItem.SubItems.Add(LDeviation.Description);
    end;
    if lvDeviations.Items.Count = 0 then
    begin
      LItem := lvDeviations.Items.Add;
      LItem.Caption := 'Программы работают в пределах нормы';
    end;
  finally
    lvDeviations.Items.EndUpdate;
  end;
end;

procedure TMainForm.btnRebuildBaselineClick(Sender: TObject);
begin
  if FServices.BaselineScheduler = nil then
  begin
    lblBaselineInfo.Caption := 'Профиль нормы недоступен без истории наблюдений.';
    Exit;
  end;
  FServices.BaselineScheduler.RequestRebuild;
  lblBaselineInfo.Caption := 'Профиль нормы перестраивается в фоне. Нажмите «Обновить» через минуту.';
end;

{ Настройки }

procedure TMainForm.ChangeSettings(const ASettings: TMHAppSettings);
var
  LError: string;
begin
  FServices.ApplySettings(ASettings);
  if not FServices.SaveSettings(LError) then
    lblStorageStats.Caption := 'Настройки применены, но не сохранены: ' + LError;
  UpdateEvents;
end;

procedure TMainForm.InitAnalysisSettings;
var
  LSettings: TMHAppSettings;
  I: Integer;
begin
  LSettings := FServices.Settings;
  FInitializingSettings := True;
  try
    cbHighCpu.Items.Clear;
    cbHighCpu.ItemIndex := -1;
    for I := Low(HIGH_CPU_CHOICES) to High(HIGH_CPU_CHOICES) do
    begin
      cbHighCpu.Items.Add(Format('%d%% всей машины', [HIGH_CPU_CHOICES[I]]));
      if Round(LSettings.Analyzer.HighCpuPercent) = HIGH_CPU_CHOICES[I] then
        cbHighCpu.ItemIndex := I;
    end;
    cbSustained.Items.Clear;
    cbSustained.ItemIndex := -1;
    for I := Low(SUSTAINED_CHOICES) to High(SUSTAINED_CHOICES) do
    begin
      cbSustained.Items.Add(Format('%d мин', [SUSTAINED_CHOICES[I]]));
      if LSettings.Analyzer.SustainedMinutes = SUSTAINED_CHOICES[I] then
        cbSustained.ItemIndex := I;
    end;
    cbLearning.Items.Clear;
    cbLearning.ItemIndex := -1;
    for I := Low(LEARNING_CHOICES) to High(LEARNING_CHOICES) do
    begin
      cbLearning.Items.Add(Format('%d дн.', [LEARNING_CHOICES[I]]));
      if LSettings.LearningDays = LEARNING_CHOICES[I] then
        cbLearning.ItemIndex := I;
    end;
    chkStartScan.Checked := LSettings.StartScanOnLaunch;
    chkRedactReports.Checked := LSettings.RedactPathsInReports;
    chkStorePaths.Checked := LSettings.StoreProcessPaths;
    cbInterval.ItemIndex := -1;
    for I := Low(IntervalChoicesMs) to High(IntervalChoicesMs) do
      if IntervalChoicesMs[I] = LSettings.IntervalMs then
        cbInterval.ItemIndex := I;
    cbRetention.ItemIndex := -1;
    for I := Low(RETENTION_DAYS) to High(RETENTION_DAYS) do
      if RETENTION_DAYS[I] = LSettings.RetentionDays then
        cbRetention.ItemIndex := I;
  finally
    FInitializingSettings := False;
  end;
  RefreshExclusions;
  RefreshActionLog;
end;

procedure TMainForm.cbHighCpuChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (cbHighCpu.ItemIndex < 0) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.Analyzer.HighCpuPercent := HIGH_CPU_CHOICES[cbHighCpu.ItemIndex];
  ChangeSettings(LSettings);
end;

procedure TMainForm.cbSustainedChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (cbSustained.ItemIndex < 0) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.Analyzer.SustainedMinutes := SUSTAINED_CHOICES[cbSustained.ItemIndex];
  ChangeSettings(LSettings);
end;

procedure TMainForm.cbLearningChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings or (cbLearning.ItemIndex < 0) then
    Exit;
  LSettings := FServices.Settings;
  LSettings.LearningDays := LEARNING_CHOICES[cbLearning.ItemIndex];
  ChangeSettings(LSettings);
end;

procedure TMainForm.chkStartScanClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings then
    Exit;
  LSettings := FServices.Settings;
  LSettings.StartScanOnLaunch := chkStartScan.Checked;
  ChangeSettings(LSettings);
end;

procedure TMainForm.chkRedactReportsClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings then
    Exit;
  LSettings := FServices.Settings;
  LSettings.RedactPathsInReports := chkRedactReports.Checked;
  ChangeSettings(LSettings);
end;

procedure TMainForm.RefreshExclusions;
var
  LExclusion: TMHExclusion;
  LItem: TListItem;
begin
  lvExclusions.Items.BeginUpdate;
  try
    lvExclusions.Items.Clear;
    for LExclusion in FServices.Settings.Exclusions do
    begin
      LItem := lvExclusions.Items.Add;
      LItem.Caption := LExclusion.Name;
      LItem.SubItems.Add(LExclusion.Key);
      if LExclusion.Sha256 = '' then
        LItem.SubItems.Add('любой файл по этому пути')
      else
        LItem.SubItems.Add(Copy(LExclusion.Sha256, 1, 16) + '…');
      LItem.SubItems.Add(MHFormatUtcAsLocal(LExclusion.CreatedUtc));
    end;
  finally
    lvExclusions.Items.EndUpdate;
  end;
  btnRemoveExclusion.Enabled := lvExclusions.Items.Count > 0;
end;

procedure TMainForm.btnRemoveExclusionClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
  LExclusion: TMHExclusion;
begin
  if (lvExclusions.ItemIndex < 0) or (lvExclusions.ItemIndex > High(FServices.Settings.Exclusions)) then
    Exit;
  LExclusion := FServices.Settings.Exclusions[lvExclusions.ItemIndex];
  if not FConfirm(Format('Удалить %s из разрешённых программ? MineHunter X снова будет анализировать её.',
    [LExclusion.Name])) then
    Exit;
  LSettings := FServices.Settings;
  if MHRemoveExclusion(LSettings, LExclusion.Key, LExclusion.Sha256) then
    ChangeSettings(LSettings);
  RefreshExclusions;
end;

procedure TMainForm.CreateRemediationControls;
begin
  // Вторая строка кнопок карточки: исправление с откатом.
  pnlCardButtons.Height := pnlCardButtons.Height + 36;
  FRemediateButton := TButton.Create(Self);
  FRemediateButton.Parent := pnlCardButtons;
  FRemediateButton.SetBounds(btnOpenLocation.Left, btnOpenLocation.Top + btnOpenLocation.Height + 6, 320, 30);
  FRemediateButton.Caption := 'Исправить (карантин с откатом)…';
  FRemediateButton.Hint := 'Показывает план: остановить процесс, отключить автозапуск и признаки ' +
    'вмешательства, переместить файлы в карантин. Каждый шаг можно отменить в «Настройки → Карантин».';
  FRemediateButton.ShowHint := True;
  FRemediateButton.Enabled := False;
  FRemediateButton.OnClick := RemediateClick;

  // Раздел «Карантин» в настройках — под журналом действий.
  FQuarantineBox := TGroupBox.Create(Self);
  FQuarantineBox.Parent := sbSettings;
  FQuarantineBox.SetBounds(gbActionLog.Left, gbActionLog.Top + gbActionLog.Height + 16, gbActionLog.Width, 230);
  FQuarantineBox.Caption := 'Карантин и откат исправлений';
  FQuarantineList := TListView.Create(Self);
  FQuarantineList.Parent := FQuarantineBox;
  FQuarantineList.SetBounds(12, 24, FQuarantineBox.Width - 24, 150);
  FQuarantineList.ViewStyle := vsReport;
  FQuarantineList.ReadOnly := True;
  FQuarantineList.RowSelect := True;
  FQuarantineList.HideSelection := False;
  with FQuarantineList.Columns.Add do
  begin
    Caption := 'Когда';
    Width := 95;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := 'Тип';
    Width := 110;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := 'Объект';
    Width := 270;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := 'Причина';
    Width := 160;
  end;
  FQuarantineList.OnSelectItem := QuarantineSelectItem;
  FQuarantineRestore := TButton.Create(Self);
  FQuarantineRestore.Parent := FQuarantineBox;
  FQuarantineRestore.SetBounds(12, 184, 160, 30);
  FQuarantineRestore.Caption := 'Восстановить';
  FQuarantineRestore.Enabled := False;
  FQuarantineRestore.OnClick := QuarantineRestoreClick;
  FQuarantinePurge := TButton.Create(Self);
  FQuarantinePurge.Parent := FQuarantineBox;
  FQuarantinePurge.SetBounds(180, 184, 180, 30);
  FQuarantinePurge.Caption := 'Удалить навсегда…';
  FQuarantinePurge.Enabled := False;
  FQuarantinePurge.OnClick := QuarantinePurgeClick;
  RefreshQuarantine;
end;

procedure TMainForm.RemediateClick(Sender: TObject);
begin
  RemediateSelected;
end;

function TMainForm.ExecuteRemediationStep(const AStep: TMHRemediationStep;
  const AReason: string): TMHActionResult;
var
  LProcess: TMHProcessInfo;
begin
  case AStep.Kind of
    rmStopProcess:
      // Процесс проверяется по текущему снимку: PID мог освободиться.
      if FindLiveProcess(AStep.Process, LProcess) then
        Result := FServices.Actions.TerminateProcess(LProcess.Id, LProcess.Name)
      else
        Result := TMHActionResult.Create(arkNotFound, 'Процесс ' + AStep.ProcessName + ' уже не запущен');
    rmQuarantineFile:
      Result := FServices.Quarantine.QuarantineFile(AStep.Target, AReason);
    rmRegistryValue:
      Result := FServices.Quarantine.DisableRegistryValue(AStep.Target, AStep.ValueName, AReason);
    rmService:
      Result := FServices.Quarantine.DisableService(AStep.Target, AReason);
    rmTask:
      Result := FServices.Quarantine.DisableTask(AStep.Target, AReason);
  else
    Result := TMHActionResult.Create(arkUnavailable, 'Вручную: ' + AStep.Description);
  end;
end;

procedure TMainForm.RemediateSelected;
var
  LRow: TMHFindingRow;
  LSteps: TArray<TMHRemediationStep>;
  LStep: TMHRemediationStep;
  LResult: TMHActionResult;
  LQuestion, LReport, LReason: string;
  LDone, LFailed, I: Integer;
begin
  if not SelectedFinding(LRow) or not FHasLastSnapshot or (FServices.Quarantine = nil) then
    Exit;
  LSteps := MHBuildRemediationPlan(FLastSnapshot, LRow.Finding, FServices.Quarantine.WindowsDir);
  if Length(LSteps) = 0 then
  begin
    lblCardStatus.Caption := 'Для этой находки нет автоматических шагов исправления — следуйте рекомендациям.';
    Exit;
  end;
  LQuestion := 'Исправить находку «' + LRow.Finding.Title + '»?' + sLineBreak + sLineBreak +
    'Будут выполнены шаги:' + sLineBreak;
  for I := 0 to High(LSteps) do
    LQuestion := LQuestion + Format('%d. %s', [I + 1, LSteps[I].Description]) + sLineBreak;
  LQuestion := LQuestion + sLineBreak +
    'Файлы не удаляются: они перемещаются в карантин, а значения реестра, службы и задания ' +
    'сохраняются. Всё можно вернуть в «Настройки → Карантин». Файлы Windows не затрагиваются.';
  if not FConfirm(LQuestion) then
    Exit;

  LReason := LRow.Finding.Title;
  LReport := '';
  LDone := 0;
  LFailed := 0;
  for LStep in LSteps do
  begin
    LResult := ExecuteRemediationStep(LStep, LReason);
    if LResult.Succeeded then
    begin
      Inc(LDone);
      LReport := LReport + '✔ ' + LResult.Message + sLineBreak;
    end
    else
    begin
      if LStep.Kind <> rmManual then
        Inc(LFailed);
      LReport := LReport + '✖ ' + LResult.Message;
      if LResult.Details <> '' then
        LReport := LReport + ' (' + LResult.Details + ')';
      LReport := LReport + sLineBreak;
    end;
  end;
  FServices.Logger.Log(llInfo, 'actions', 'Исправление «' + LRow.Finding.Title + '»:' + sLineBreak + LReport);
  if LFailed = 0 then
    lblCardStatus.Caption := Format('Исправление выполнено: %d из %d шагов. Отменить можно в «Настройки → Карантин».',
      [LDone, Length(LSteps)])
  else
    lblCardStatus.Caption := Format('Исправление выполнено частично: успешно %d, с ошибками %d — подробности в журнале.',
      [LDone, LFailed]);
  lblCardStatus.Hint := LReport;
  lblCardStatus.ShowHint := True;
  UpdateEvents;
  RefreshActionLog;
  RefreshQuarantine;
end;

procedure TMainForm.RefreshQuarantine;
var
  LItem: TMHQuarantineItem;
  LView: TListItem;
begin
  if (FQuarantineList = nil) or (FServices.Quarantine = nil) then
    Exit;
  try
    FQuarantineItems := FServices.Quarantine.Items;
  except
    on E: Exception do
    begin
      FQuarantineItems := nil;
      FServices.Logger.Log(llWarning, 'quarantine', 'Список карантина недоступен: ' + E.Message);
    end;
  end;
  FQuarantineList.Items.BeginUpdate;
  try
    FQuarantineList.Items.Clear;
    for LItem in FQuarantineItems do
    begin
      LView := FQuarantineList.Items.Add;
      LView.Caption := FormatDateTime('dd.mm hh:nn', TTimeZone.Local.ToLocalTime(LItem.CreatedUtc));
      LView.SubItems.Add(MHQuarantineKindToString(LItem.Kind));
      LView.SubItems.Add(LItem.Description);
      LView.SubItems.Add(LItem.Reason);
    end;
  finally
    FQuarantineList.Items.EndUpdate;
  end;
  FQuarantineRestore.Enabled := False;
  FQuarantinePurge.Enabled := False;
  if Length(FQuarantineItems) = 0 then
    FQuarantineBox.Caption := 'Карантин и откат исправлений — пусто'
  else
    FQuarantineBox.Caption := Format('Карантин и откат исправлений — %d', [Length(FQuarantineItems)]);
end;

procedure TMainForm.QuarantineSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
var
  LHas: Boolean;
begin
  LHas := (FQuarantineList.Selected <> nil) and (FQuarantineList.Selected.Index <= High(FQuarantineItems));
  FQuarantineRestore.Enabled := LHas;
  // Удалять навсегда можно только файлы: записи реестра, службы и задания лишь отключены.
  FQuarantinePurge.Enabled := LHas and (FQuarantineItems[FQuarantineList.Selected.Index].Kind = qkFile);
end;

procedure TMainForm.RestoreSelectedQuarantine;
var
  LItem: TMHQuarantineItem;
begin
  if (FQuarantineList.Selected = nil) or (FQuarantineList.Selected.Index > High(FQuarantineItems)) then
    Exit;
  LItem := FQuarantineItems[FQuarantineList.Selected.Index];
  if not FConfirm('Восстановить из карантина?' + sLineBreak + LItem.Description + sLineBreak + sLineBreak +
    'Объект вернётся на прежнее место и снова сможет запускаться.') then
    Exit;
  ShowActionResult(FServices.Quarantine.Restore(LItem.Id));
  RefreshQuarantine;
end;

procedure TMainForm.PurgeSelectedQuarantine;
var
  LItem: TMHQuarantineItem;
begin
  if (FQuarantineList.Selected = nil) or (FQuarantineList.Selected.Index > High(FQuarantineItems)) then
    Exit;
  LItem := FQuarantineItems[FQuarantineList.Selected.Index];
  if not FConfirm('Удалить навсегда файл из карантина?' + sLineBreak + LItem.Description + sLineBreak + sLineBreak +
    'Это действие нельзя отменить.') then
    Exit;
  ShowActionResult(FServices.Quarantine.Purge(LItem.Id));
  RefreshQuarantine;
end;

procedure TMainForm.QuarantineRestoreClick(Sender: TObject);
begin
  RestoreSelectedQuarantine;
end;

procedure TMainForm.QuarantinePurgeClick(Sender: TObject);
begin
  PurgeSelectedQuarantine;
end;

procedure TMainForm.CreateTray;
var
  LItem: TMenuItem;
begin
  FTrayMenu := TPopupMenu.Create(Self);
  LItem := TMenuItem.Create(FTrayMenu);
  LItem.Caption := 'Открыть MineHunter X';
  LItem.Default := True;
  LItem.OnClick := TrayOpenClick;
  FTrayMenu.Items.Add(LItem);
  LItem := TMenuItem.Create(FTrayMenu);
  LItem.Caption := '-';
  FTrayMenu.Items.Add(LItem);
  LItem := TMenuItem.Create(FTrayMenu);
  LItem.Caption := 'Выход';
  LItem.OnClick := TrayExitClick;
  FTrayMenu.Items.Add(LItem);

  FTray := TTrayIcon.Create(Self);
  FTray.Icon.Assign(Application.Icon);
  FTray.Hint := 'MineHunter X';
  FTray.PopupMenu := FTrayMenu;
  FTray.OnClick := TrayClick;
  FTray.OnDblClick := TrayClick;
  FTray.OnBalloonClick := TrayBalloonClick;
  // Значок показывается только в обычной работе приложения: тесты и встраивание
  // не добавляют значков в область уведомлений пользователя.
  if FOwnsServices then
  begin
    FTray.Visible := FServices.Settings.MinimizeToTray or FServices.Settings.NotifyAlerts;
    if MHHasMinimizedSwitch(CommandLineParams) then
    begin
      // Запуск вместе с Windows: окно не показывается (Application.ShowMainForm = False).
      FTray.Visible := True;
      FHiddenToTray := True;
      FTrayHintShown := True;
      FServices.EconomyMode := True;
    end;
  end;
end;

procedure TMainForm.CreateBackgroundSettings;
var
  LTop: Integer;

  function AddCheck(const ACaption, AHint: string; AChecked: Boolean): TCheckBox;
  begin
    Result := TCheckBox.Create(Self);
    Result.Parent := FBackgroundBox;
    Result.SetBounds(16, LTop, FBackgroundBox.Width - 32, 19);
    Result.Caption := ACaption;
    Result.Hint := AHint;
    Result.ShowHint := True;
    Result.Checked := AChecked;
    Inc(LTop, 26);
  end;

begin
  FBackgroundBox := TGroupBox.Create(Self);
  FBackgroundBox.Parent := sbSettings;
  FBackgroundBox.SetBounds(gbActionLog.Left, FQuarantineBox.Top + FQuarantineBox.Height + 16,
    gbActionLog.Width, 160);
  FBackgroundBox.Caption := 'Работа в фоне и уведомления';
  LTop := 26;
  FInitializingSettings := True;
  try
    FChkTray := AddCheck('Сворачивать и закрывать в область уведомлений (значок у часов)',
      'Наблюдение продолжается, пока окно скрыто. Полный выход — «Выход» в меню значка.',
      FServices.Settings.MinimizeToTray);
    FChkNotify := AddCheck('Уведомлять о новых тревогах (уровень «подозрительно» и выше)',
      'Не чаще одного уведомления в минуту; об одной находке — один раз, повторно — если риск вырос.',
      FServices.Settings.NotifyAlerts);
    FChkEconomy := AddCheck(Format('Экономный режим: пока окно скрыто, опрос раз в %d с',
      [TMHAppSettings.EconomyIntervalMs div 1000]),
      'Снижает нагрузку самого MineHunter X, когда вы не смотрите на окно.',
      FServices.Settings.EconomyWhenHidden);
    FChkAutostart := AddCheck('Запускать MineHunter X вместе с Windows (свёрнутым)',
      'Запись в HKCU\...\CurrentVersion\Run только для текущего пользователя; права администратора не нужны.',
      False);
  finally
    FInitializingSettings := False;
  end;
  FChkTray.OnClick := BackgroundSettingClick;
  FChkNotify.OnClick := BackgroundSettingClick;
  FChkEconomy.OnClick := BackgroundSettingClick;
  FChkAutostart.OnClick := AutostartClick;
  FLblAutostart := TLabel.Create(Self);
  FLblAutostart.Parent := FBackgroundBox;
  FLblAutostart.SetBounds(34, LTop - 4, FBackgroundBox.Width - 50, 15);
  FLblAutostart.AutoSize := False;
  FLblAutostart.ShowAccelChar := False;
  FLblAutostart.Font.Color := clGrayText;
  UpdateAutostartState;
end;

procedure TMainForm.UpdateAutostartState;
begin
  if (FChkAutostart = nil) or (FServices.SelfAutostart = nil) then
    Exit;
  FInitializingSettings := True;
  try
    case FServices.SelfAutostart.State of
      sasEnabled:
        begin
          FChkAutostart.Checked := True;
          FLblAutostart.Caption := 'Включено: ' + FServices.SelfAutostart.Command;
        end;
      sasStale:
        begin
          FChkAutostart.Checked := False;
          FLblAutostart.Caption := 'Запись автозапуска указывает на другой файл (программу переместили) — ' +
            'включите заново.';
        end;
    else
      FChkAutostart.Checked := False;
      FLblAutostart.Caption := 'Выключено.';
    end;
  finally
    FInitializingSettings := False;
  end;
end;

procedure TMainForm.BackgroundSettingClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings then
    Exit;
  LSettings := FServices.Settings;
  LSettings.MinimizeToTray := FChkTray.Checked;
  LSettings.NotifyAlerts := FChkNotify.Checked;
  LSettings.EconomyWhenHidden := FChkEconomy.Checked;
  ChangeSettings(LSettings);
  if FOwnsServices and (FTray <> nil) then
    FTray.Visible := FHiddenToTray or LSettings.MinimizeToTray or LSettings.NotifyAlerts;
end;

procedure TMainForm.AutostartClick(Sender: TObject);
var
  LError: string;
  LEnable: Boolean;
  LRecord: TMHActionRecord;
begin
  if FInitializingSettings or (FServices.SelfAutostart = nil) then
    Exit;
  LEnable := FChkAutostart.Checked;
  LRecord.TimestampUtc := FServices.Clock.NowUtc;
  if LEnable then
    LRecord.Action := 'self-autostart-on'
  else
    LRecord.Action := 'self-autostart-off';
  LRecord.Target := FServices.SelfAutostart.Command;
  LRecord.Success := FServices.SelfAutostart.SetEnabled(LEnable, LError);
  if LRecord.Success then
    LRecord.Result := 'Готово'
  else
    LRecord.Result := 'Не удалось изменить автозапуск: ' + LError;
  if FServices.ActionLog <> nil then
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', 'Журнал действий недоступен: ' + E.Message);
    end;
  if not LRecord.Success then
    FServices.Logger.Log(llWarning, 'app', LRecord.Result);
  UpdateAutostartState;
  if not LRecord.Success then
    FLblAutostart.Caption := LRecord.Result;
  RefreshActionLog;
end;

function TMainForm.NotifyAlerts(const AFindings: TMHFindings; ANowUtc: TDateTime): Boolean;
var
  LNotice: TMHAlertNotice;
begin
  Result := False;
  if (FNotifier = nil) or not FServices.Settings.NotifyAlerts then
    Exit;
  if not FNotifier.Process(AFindings, ANowUtc, LNotice) then
    Exit;
  FLastNotice := LNotice;
  Inc(FNoticeCount);
  Result := True;
  // Пока окно открыто и активно, тревога и так видна на «Обзоре».
  if (FTray <> nil) and FTray.Visible and (FHiddenToTray or not Application.Active) then
  begin
    FTray.BalloonTitle := LNotice.Title;
    FTray.BalloonHint := LNotice.Text;
    if LNotice.Level >= rlHighlySuspicious then
      FTray.BalloonFlags := bfError
    else
      FTray.BalloonFlags := bfWarning;
    FTray.ShowBalloonHint;
  end;
end;

procedure TMainForm.UpdateTray;
var
  LAlerts: Integer;
begin
  if FTray = nil then
    Exit;
  LAlerts := FFindingsModel.ActiveAlertCount(rlNeedsReview);
  if LAlerts > 0 then
    FTray.Hint := Format('MineHunter X — требуют проверки: %d', [LAlerts])
  else if FServices.Scanner.IsRunning then
    FTray.Hint := 'MineHunter X — угроз не обнаружено'
  else
    FTray.Hint := 'MineHunter X — наблюдение остановлено';
end;

procedure TMainForm.HideToTray;
begin
  FHiddenToTray := True;
  FServices.EconomyMode := True;
  if FOwnsServices then
  begin
    FTray.Visible := True;
    Hide;
    if not FTrayHintShown then
    begin
      FTrayHintShown := True;
      FTray.BalloonTitle := 'MineHunter X работает в фоне';
      FTray.BalloonHint := 'Наблюдение продолжается. Откройте окно щелчком по значку; выход — в меню значка.';
      FTray.BalloonFlags := bfInfo;
      FTray.ShowBalloonHint;
    end;
  end;
end;

procedure TMainForm.ShowFromTray;
begin
  FHiddenToTray := False;
  FServices.EconomyMode := False;
  if FOwnsServices then
  begin
    FTray.Visible := FServices.Settings.MinimizeToTray or FServices.Settings.NotifyAlerts;
    Show;
    if WindowState = wsMinimized then
      WindowState := wsNormal;
    Application.Restore;
    Application.BringToFront;
    SetForegroundWindow(Handle);
  end;
end;

procedure TMainForm.Quit;
begin
  FQuitting := True;
  Close;
end;

procedure TMainForm.TrayClick(Sender: TObject);
begin
  ShowFromTray;
end;

procedure TMainForm.TrayBalloonClick(Sender: TObject);
begin
  ShowFromTray;
  if FLastNotice.FindingKey <> '' then
  begin
    NavigateTo(pgFindings);
    SelectFinding(FLastNotice.FindingKey);
  end;
end;

procedure TMainForm.TrayOpenClick(Sender: TObject);
begin
  ShowFromTray;
end;

procedure TMainForm.TrayExitClick(Sender: TObject);
begin
  Quit;
end;

procedure TMainForm.WMSysCommand(var AMessage: TWMSysCommand);
begin
  if ((AMessage.CmdType and $FFF0) = SC_MINIMIZE) and FOwnsServices and FServices.Settings.MinimizeToTray then
  begin
    HideToTray;
    AMessage.Result := 0;
  end
  else
    inherited;
end;

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  // Крестик окна при включённой настройке убирает программу в трей; выход — из меню значка.
  if not FQuitting and FOwnsServices and FServices.Settings.MinimizeToTray and
     not Application.Terminated then
  begin
    CanClose := False;
    HideToTray;
  end;
end;

procedure TMainForm.RefreshActionLog;
var
  LRecord: TMHActionRecord;
  LItem: TListItem;
  LRecords: TArray<TMHActionRecord>;
begin
  if FServices.ActionLog = nil then
    Exit;
  try
    LRecords := FServices.ActionLog.LoadActions(200);
  except
    on E: Exception do
      Exit;
  end;
  lvActionLog.Items.BeginUpdate;
  try
    lvActionLog.Items.Clear;
    for LRecord in LRecords do
    begin
      LItem := lvActionLog.Items.Add;
      LItem.Caption := FormatDateTime('dd.mm hh:nn:ss', TTimeZone.Local.ToLocalTime(LRecord.TimestampUtc));
      LItem.SubItems.Add(LRecord.Action);
      LItem.SubItems.Add(LRecord.Target);
      if LRecord.Success then
        LItem.SubItems.Add('✔ ' + LRecord.Result)
      else
        LItem.SubItems.Add('✖ ' + LRecord.Result);
    end;
  finally
    lvActionLog.Items.EndUpdate;
  end;
end;

end.
