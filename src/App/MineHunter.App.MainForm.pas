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
  MineHunter.App.Notifier, MineHunter.Core.Inventory, MineHunter.Core.Energy, MineHunter.App.DisksPage,
  MineHunter.Core.CheckReport, MineHunter.Core.Updates;

type
  TMHPage = (pgDashboard, pgProcesses, pgFindings, pgDisks, pgHistory, pgSettings);

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
    /// За сколько дней показывать «Что изменилось».
    CHANGES_DAYS = 7;
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
    FLblPrice: TLabel;
    FEdPrice: TEdit;
    FBtnCheckNow: TButton;
    FCheckPending: Boolean;
    FCheckBaseline: UInt64;
    FLastCheckReport: TMHCheckReport;
    FCheckCount: Integer;
    FShowReport: TProc<TMHCheckReport>;
    FChangesPanel: TPanel;
    FLblEnergy: TLabel;
    FChangesList: TListView;
    FHistoryResultEnergy: TMHEnergyEstimate;
    FHistoryResultChanges: TArray<TMHInventoryItem>;
    FHistoryResultInventoryStart: TDateTime;
    FHistoryResultHours: Integer;
    FAppearanceBox: TGroupBox;
    FDisksSheet: TTabSheet;
    FDisksPage: TMHDisksPage;
    FCbLanguage: TComboBox;
    FCbTheme: TComboBox;
    FChkUpdates: TCheckBox;
    FBtnCheckUpdates: TButton;
    FBtnExportSettings: TButton;
    FBtnImportSettings: TButton;
    FLblUpdate: TLabel;
    FLblAppearanceNote: TLabel;
    FUpdateHttp: IMHHttpGet;
    FUpdateThread: TThread;
    FUpdateResult: TMHUpdateInfo;
    FUpdateRunning: Boolean;
    FUpdateCount: Integer;
    procedure CreateAppearanceControls;
    procedure CreateDisksPage;
    procedure AppearanceChange(Sender: TObject);
    procedure UpdatesClick(Sender: TObject);
    procedure CheckUpdatesClick(Sender: TObject);
    procedure UpdateFinished;
    procedure UpdateLinkClick(Sender: TObject);
    procedure ExportSettingsClick(Sender: TObject);
    procedure ImportSettingsClick(Sender: TObject);
    procedure ReloadSettingsControls;
    procedure CreateCheckAndChangesControls;
    procedure CheckNowClick(Sender: TObject);
    procedure CompleteCheck(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);
    procedure DefaultShowReport(AReport: TMHCheckReport);
    procedure ApplyChanges;
    procedure PriceExit(Sender: TObject);
    procedure PriceKeyPress(Sender: TObject; var Key: Char);
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
    procedure WMQueryEndSession(var AMessage: TWMQueryEndSession); message WM_QUERYENDSESSION;
  protected
    procedure WndProc(var AMessage: TMessage); override;
  private
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
    /// «Проверить сейчас»: внеочередной цикл со сбросом кэшей и отчёт по его итогам.
    procedure CheckNow;
    property CheckNowButton: TButton read FBtnCheckNow;
    property CheckPending: Boolean read FCheckPending;
    property LastCheckReport: TMHCheckReport read FLastCheckReport;
    property CheckCount: Integer read FCheckCount;
    /// Показ отчёта проверки (по умолчанию — окно с текстом). Тесты подменяют.
    property ShowCheckReport: TProc<TMHCheckReport> read FShowReport write FShowReport;
    property ChangesList: TListView read FChangesList;
    property EnergyLabel: TLabel read FLblEnergy;
    property PriceEdit: TEdit read FEdPrice;
    /// Применяет цену электроэнергии из поля ввода (False — некорректное значение).
    function ApplyPriceText: Boolean;
    /// Проверка новых версий на GitHub в фоне (только по согласию или по кнопке).
    procedure StartUpdateCheck;
    property UpdateRunning: Boolean read FUpdateRunning;
    property UpdateResult: TMHUpdateInfo read FUpdateResult;
    property UpdateCount: Integer read FUpdateCount;
    /// HTTP для проверки обновлений (по умолчанию — System.Net). Тесты подменяют.
    property UpdateHttp: IMHHttpGet read FUpdateHttp write FUpdateHttp;
    /// Страница «Диски» (диски, разделы, проверка файлов).
    property DisksPage: TMHDisksPage read FDisksPage;
    property LanguageCombo: TComboBox read FCbLanguage;
    property ThemeCombo: TComboBox read FCbTheme;
    property UpdatesCheckBox: TCheckBox read FChkUpdates;
    /// Экспорт настроек в файл JSON (False и причина в AError).
    function ExportSettingsTo(const AFileName: string; out AError: string): Boolean;
    /// Импорт настроек из файла JSON: проверка, подтверждение, применение.
    function ImportSettingsFrom(const AFileName: string; out AError: string): Boolean;
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
  MineHunter.Core.SelfAutostart, MineHunter.Collectors.Processes.WinApi,
  MineHunter.App.Lang, MineHunter.App.Theme, MineHunter.Core.Updates.WinApi, Winapi.ShellAPI,
  System.IOUtils, MineHunter.Core.Lang;

function PercentText(AValue: Double): string; forward;

var
  MH_QUIT_MESSAGE: Cardinal;

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
    ('Обзор', 'Процессы', 'Находки', 'Диски', 'История', 'Настройки');
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
  MHSetLanguage(FServices.Settings.Language);
  // Стиль оформления глобален для процесса — меняется только в обычной работе приложения.
  if FOwnsServices then
    MHApplyTheme(FServices.Settings.Theme);

  CreateDisksPage;
  lbNav.Items.Clear;
  for LPage := Low(TMHPage) to High(TMHPage) do
    lbNav.Items.Add(MHTr(PAGE_TITLES[LPage]));
  for I := 0 to pcMain.PageCount - 1 do
    pcMain.Pages[I].TabVisible := False;

  LOptions := FServices.Scanner.Options;
  cbInterval.Items.Clear;
  cbInterval.ItemIndex := -1;
  for I := Low(IntervalChoicesMs) to High(IntervalChoicesMs) do
  begin
    cbInterval.Items.Add(Format(MHL('%d с', '%d s'), [IntervalChoicesMs[I] div 1000]));
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
  CreateCheckAndChangesControls;
  CreateAppearanceControls;
  cbHistoryPeriod.Items.Clear;
  cbHistoryPeriod.Items.Add(MHTr('1 час'));
  cbHistoryPeriod.Items.Add(MHTr('6 часов'));
  cbHistoryPeriod.Items.Add(MHTr('24 часа'));
  cbHistoryPeriod.Items.Add(MHTr('7 дней'));
  cbHistoryPeriod.ItemIndex := 0;
  InitStorageSettings;

  FCardChart := TMHLineChart.Create(Self);
  FCardChart.Parent := pnlCardChart;
  FCardChart.ShowHint := True;
  FCardChart.SetFixedRange(0, 100);
  FCardChart.Formatter := PercentText;
  FCardChart.Title := MHTr('Нагрузка (последний час)');
  pnlCardChartResize(nil);
  cbFindingsMode.Items.Clear;
  cbFindingsMode.Items.Add(MHTr('Активные тревоги'));
  cbFindingsMode.Items.Add(MHTr('История за 7 дней'));
  cbFindingsMode.ItemIndex := 0;
  cbFindingsMinLevel.Items.Clear;
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlLow));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlNeedsReview));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlSuspicious));
  cbFindingsMinLevel.Items.Add(MHRiskLevelToString(rlHighlySuspicious));
  cbFindingsMinLevel.ItemIndex := 0;
  lblStorageNote.Caption := MHTr('История и настройки хранятся только на этом компьютере ') +
    MHL('(%LOCALAPPDATA%\MineHunterX) и никуда не передаются.',
      '(%LOCALAPPDATA%\MineHunterX) and are never sent anywhere.');
  InitAnalysisSettings;
  RefreshFindingsList;
  if not FServices.SettingsLoadedOk then
    FServices.Logger.Log(llWarning, 'settings',
      MHL('Файл настроек был повреждён: восстановлены значения по умолчанию',
        'The settings file was corrupted: default values were restored'));

  FServices.Scanner.OnCycle :=
    procedure(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings)
    begin
      HandleCycle(ASnapshot, AFindings);
    end;

  MHTranslateTree(Self);
  NavigateTo(pgDashboard);
  UpdateScanState;
  UpdateEvents;
  if FOwnsServices and FServices.Settings.CheckForUpdates then
    StartUpdateCheck;
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
  // Проверка обновлений ограничена тайм-аутом HTTP (TMHNetHttpGet.TimeoutMs).
  FreeAndNil(FUpdateThread);
  // Проверка файлов отменяется и дожидается завершения до освобождения сервисов.
  FreeAndNil(FDisksPage);
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
  Caption := 'MineHunter X — ' + MHTr(PAGE_TITLES[APage]);
  case APage of
    pgHistory:
      if not FHistoryRequested then
        LoadHistory;
    pgSettings:
      UpdateStorageInfo;
    pgDisks:
      if FHasLastSnapshot then
        FDisksPage.UpdateSnapshot(FLastSnapshot);
  end;
end;

procedure TMainForm.CreateDisksPage;
var
  LAction: TAction;
begin
  // Вкладка создаётся в коде и ставится на место, соответствующее pgDisks.
  FDisksSheet := TTabSheet.Create(Self);
  FDisksSheet.PageControl := pcMain;
  FDisksSheet.PageIndex := Ord(pgDisks);
  FDisksSheet.Caption := PAGE_TITLES[pgDisks];
  FDisksPage := TMHDisksPage.Create(Self, FDisksSheet, FServices,
    function(const AQuestion: string): Boolean
    begin
      Result := FConfirm(AQuestion);
    end,
    procedure(const ATitle, AText: string)
    begin
      if (FTray <> nil) and FTray.Visible then
      begin
        FTray.BalloonTitle := ATitle;
        FTray.BalloonHint := AText;
        FTray.BalloonFlags := bfWarning;
        FTray.ShowBalloonHint;
      end;
    end);
  // Навигация: Ctrl+4 — «Диски», Ctrl+5 — «История», Ctrl+6 — «Настройки».
  actNavHistory.Tag := Ord(pgHistory);
  actNavHistory.ShortCut := ShortCut(Ord('5'), [ssCtrl]);
  actNavSettings.Tag := Ord(pgSettings);
  actNavSettings.ShortCut := ShortCut(Ord('6'), [ssCtrl]);
  LAction := TAction.Create(Self);
  LAction.ActionList := alMain;
  LAction.Caption := PAGE_TITLES[pgDisks];
  LAction.Tag := Ord(pgDisks);
  LAction.ShortCut := ShortCut(Ord('4'), [ssCtrl]);
  LAction.OnExecute := actNavExecute;
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
    Format(MHL('Интервал опроса изменён на %d мс', 'Polling interval changed to %d ms'),
      [LSettings.IntervalMs]));
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
    lblScanState.Caption := MHTr('● Сканирование выполняется')
  else
    lblScanState.Caption := MHTr('■ Сканирование остановлено');
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
  sbMain.Panels[1].Text := Format(MHTr('Снимок №%d в %s · процессов: %d'),
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
  lblSelfCpu.Caption := MHL(MH_NO_DATA, 'no data');
  lblSelfMem.Caption := MHL(MH_NO_DATA, 'no data');
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
        LMessage := Trim(LMessage + MHL(' (нужны права администратора)', ' (administrator rights required)'));
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
  lblProcCount.Caption := Format(MHTr('Показано %d из %d'),
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
    Item.SubItems.Add(MHL(MH_NO_DATA, 'no data'))
  else
    Item.SubItems.Add(IntToStr(LInfo.ThreadCount));
  Item.SubItems.Add(MHAccessLevelToString(LInfo.Access));
  if LInfo.ImagePath = '' then
    Item.SubItems.Add(MHL(MH_NO_DATA, 'no data'))
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
    LCaption := MHTr(PROCESS_COLUMN_TITLES[LColumn]);
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
        LLines.Add(MHL('Выберите процесс в таблице, чтобы увидеть подробности.',
          'Select a process in the table to see its details.'))
      else
        LLines.Add(Format(MHL('Процесс PID %d больше не выполняется или скрыт фильтром.',
          'Process PID %d is no longer running or is hidden by the filter.'),
          [FSelectedProcess.Pid]));
    end
    else
    begin
      LInfo := FProcessModel[LIndex];
      LLines.Add(MHL('Имя: ', 'Name: ') + LInfo.Name);
      LLines.Add(Format(MHL('PID: %d    Запущен: %s', 'PID: %d    Started: %s'),
        [LInfo.Id.Pid, MHFormatFileTimeLocal(LInfo.Id.CreateTime)]));
      if FProcessModel.TryFindParent(LInfo, LParent) then
        LLines.Add(Format(MHL('Родитель: %s (PID %d)', 'Parent: %s (PID %d)'), [LParent.Name, LParent.Id.Pid]))
      else
        LLines.Add(Format(MHL('Родитель: PID %d (процесс уже завершён или недоступен)',
          'Parent: PID %d (the process has already exited or is inaccessible)'),
          [LInfo.ParentPid]));
      if LInfo.ImagePath = '' then
        LLines.Add(MHL('Путь: ', 'Path: ') + MHL(MH_NO_DATA, 'no data'))
      else
        LLines.Add(MHL('Путь: ', 'Path: ') + LInfo.ImagePath);
      LLines.Add(Format(MHL('CPU: %s    Память (как в диспетчере задач): %s    Рабочий набор: %s    ' +
        'Выделено: %s', 'CPU: %s    Memory (as in Task Manager): %s    Working set: %s    ' +
        'Committed: %s'), [MHFormatMetric(LInfo.Cpu), MHFormatMetric(MHProcessMemory(LInfo)),
         MHFormatMetric(LInfo.WorkingSet), MHFormatMetric(LInfo.PrivateBytes)]));
      LLines.Add(Format(MHL('Видеокарта: %s    вычисления (Compute, CUDA): %s    видеопамять: %s',
        'Graphics card: %s    compute (Compute, CUDA): %s    video memory: %s'),
        [MHFormatMetric(LInfo.Gpu), MHFormatMetric(LInfo.GpuCompute), MHFormatMetric(LInfo.GpuMemory)]));
      if LInfo.ThreadCount = MH_UNKNOWN_COUNT then
        LLines.Add(MHL('Потоков: ', 'Threads: ') + MHL(MH_NO_DATA, 'no data'))
      else
        LLines.Add(MHL('Потоков: ', 'Threads: ') + IntToStr(LInfo.ThreadCount));
      LLines.Add(MHL('Доступ: ', 'Access: ') + MHAccessLevelToString(LInfo.Access) +
        MHL('    Источник данных: ', '    Data source: ') + LInfo.SourceId);
      if LInfo.Access in [alDenied, alLimited] then
        LLines.Add(MHL('Часть сведений недоступна с текущими правами. Это ограничение ' +
          'Windows, а не признак угрозы.', 'Some details are unavailable with the current rights. ' +
          'This is a Windows restriction, not a sign of a threat.'));
      LLines.Add(MHL('Подпись: ', 'Signature: ') + MHSignatureToString(LInfo.Signature));
      if LInfo.Sha256 <> '' then
        LLines.Add('SHA-256: ' + LInfo.Sha256);
      LLines.Add(MHL('Оценка риска: ', 'Risk assessment: ') + MHRiskLevelToString(FProcessModel.RiskOf(LInfo)));
      if LInfo.CommandLine <> '' then
        LLines.Add(MHL('Командная строка: ', 'Command line: ') + Copy(LInfo.CommandLine, 1, 400));
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
        LLines.Add(Format(MHL('Сеть: соединений %d, внешних %d %s', 'Network: %d connections, %d external %s'),
          [Length(LConnections), LRemote, Trim(LText)]));
        for LAutostart in FLastSnapshot.Autostart do
          if (LInfo.ImagePath <> '') and SameText(LAutostart.ImagePath, MHNormalizePath(LInfo.ImagePath)) then
            LLines.Add(MHL('Автозапуск: ', 'Autostart: ') + MHAutostartKindTitle(LAutostart.Kind) + ' — ' + LAutostart.Name);
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
  Result := MHFormatBytes(AValue) + MHL('/с', '/s');
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
    LData.Title := MHTr(TITLES[LKind]);
    LData.Value := MHL(MH_NO_DATA, 'no data');
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
  LPrice: Double;
  LHours, LEnergyPoints: Integer;
  LInventory: IMHInventoryHistory;
begin
  FHistoryRequested := True;
  LHistory := FServices.MetricHistory;
  if LHistory = nil then
  begin
    lblHistoryStatus.Caption := MHTr('История недоступна: ') + FServices.StorageError;
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
  lblHistoryStatus.Caption := MHTr('Загрузка…');
  if FHasLastSnapshot and FLastSnapshot.Context.Available and
     (FLastSnapshot.Context.WorkContext <> wcUnknown) then
    LContext := FLastSnapshot.Context.WorkContext
  else
    LContext := wcWork;
  LBaselines := FServices.Baselines;
  LStorage := FServices.Storage;
  LMinSamples := FServices.Settings.Analyzer.BaselineMinSamples;
  LPrice := FServices.Settings.ElectricityPrice;
  LHours := HISTORY_HOURS[Max(0, cbHistoryPeriod.ItemIndex)];
  LEnergyPoints := Max(HISTORY_POINTS, LHours * 12);
  if not Supports(FServices.MetricHistory, IMHInventoryHistory, LInventory) then
    LInventory := nil;

  FHistoryLoader := TThread.CreateAnonymousThread(
    procedure
    var
      LSeries: TArray<TArray<TMHMetric>>;
      LError, LInfo: string;
      K: Integer;
      LBase, LCurrent: TMHBaseline;
      LComparisons: TArray<TMHMetricComparison>;
      LDeviations: TArray<TMHProcessDeviation>;
      LEnergy: TMHEnergyEstimate;
      LChanges: TArray<TMHInventoryItem>;
      LInventoryStart: TDateTime;
    begin
      SetLength(LSeries, Length(HISTORY_KINDS));
      LEnergy := Default(TMHEnergyEstimate);
      LChanges := nil;
      LInventoryStart := 0;
      LComparisons := nil;
      LDeviations := nil;
      LInfo := '';
      try
        for K := Low(HISTORY_KINDS) to High(HISTORY_KINDS) do
          LSeries[K] := LHistory.LoadMetricSeries(HISTORY_KINDS[K], LFrom, LTo, HISTORY_POINTS);
        // Энергия видеокарты за период: точки не реже раза в 5 минут, промежутки длиннее
        // трёх интервалов (программа была закрыта) не учитываются.
        LEnergy := MHEstimateEnergy(LHistory.LoadMetricSeries(mkGpuPowerWatts, LFrom, LTo, LEnergyPoints),
          LPrice, Max(15.0, 3 * LHours * 60 / LEnergyPoints));
        if LInventory <> nil then
        begin
          LChanges := LInventory.LoadInventoryChanges(LTo - CHANGES_DAYS, 500);
          LInventoryStart := LInventory.InventoryStartUtc;
        end;
        // Сравнение периода с профилем нормы того же контекста работы (MH-06).
        if (LBaselines <> nil) and (LStorage <> nil) then
        begin
          LBase := LBaselines.BaselineFor(LContext);
          LCurrent := TMHBaselineBuilder.Build(LContext,
            LStorage.LoadSnapshotsSampled(LFrom, LTo, 2000, LContext), LTo);
          LComparisons := MHComparePeriods(LCurrent, LBase);
          LDeviations := MHCompareProcesses(LCurrent, LBase);
          if LBase.IsEstablished(LMinSamples) then
            LInfo := Format(MHL('Норма для режима «%s»: %d снимков за %s — %s. Сравнивается выбранный период.',
              'Baseline for the “%s” mode: %d snapshots from %s to %s. The selected period is compared.'),
              [MHWorkContextToString(LContext), LBase.SampleCount, MHFormatUtcAsLocal(LBase.PeriodFromUtc),
               MHFormatUtcAsLocal(LBase.PeriodToUtc)])
          else
            LInfo := Format(MHL('Профиль нормы для режима «%s» ещё формируется: %d из %d снимков. ' +
              'Сравнение станет точнее после периода обучения.',
              'The baseline for the “%s” mode is still being built: %d of %d snapshots. ' +
              'The comparison will become more accurate after the learning period.'),
              [MHWorkContextToString(LContext), LBase.SampleCount, LMinSamples]);
        end
        else
          LInfo := MHL('Профиль нормы недоступен без истории наблюдений.',
            'The baseline is unavailable without observation history.');
      except
        on E: Exception do
          LError := E.Message;
      end;
      FHistoryResultEnergy := LEnergy;
      FHistoryResultChanges := LChanges;
      FHistoryResultInventoryStart := LInventoryStart;
      FHistoryResultHours := LHours;
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
      lblHistoryStatus.Caption := MHTr('Не удалось загрузить историю: ') + AError
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
        lblHistoryStatus.Caption := MHTr('За выбранный период данных нет')
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
  begin
    ApplyComparison;
    ApplyChanges;
  end;
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
    lblStoragePath.Caption := MHL(MH_NO_DATA, 'no data');
    lblStorageStats.Caption := MHTr('История недоступна: ') + FServices.StorageError;
    Exit;
  end;
  lblStoragePath.Caption := LStorage.FileName;
  try
    LStats := LStorage.GetStats;
    if LStats.SnapshotCount = 0 then
      lblStorageStats.Caption := Format(MHTr('Записей нет · размер файла %s'),
        [MHFormatBytes(LStats.FileSizeBytes)])
    else
      lblStorageStats.Caption := Format(MHTr('Снимков: %d · размер файла %s · с %s'),
        [LStats.SnapshotCount, MHFormatBytes(LStats.FileSizeBytes),
         FormatDateTime('dd.mm.yyyy hh:nn', TTimeZone.Local.ToLocalTime(LStats.OldestUtc))]);
  except
    on E: Exception do
      lblStorageStats.Caption := MHTr('Не удалось прочитать сведения: ') + E.Message;
  end;
end;

procedure TMainForm.InitStorageSettings;
var
  I: Integer;
  LOptions: TMHStorageOptions;
begin
  cbRetention.Items.Clear;
  for I := Low(RETENTION_DAYS) to High(RETENTION_DAYS) do
    cbRetention.Items.Add(Format(MHL('%d дн.', '%d days'), [RETENTION_DAYS[I]]));
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
    Format(MHL('Срок хранения истории: %d дн.', 'History retention period: %d days'),
      [LSettings.RetentionDays]));
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
    FServices.Logger.Log(llInfo, 'app', MHL('Пути процессов сохраняются в истории',
      'Process paths are stored in the history'))
  else
    FServices.Logger.Log(llInfo, 'app', MHL('Пути процессов больше не сохраняются в истории',
      'Process paths are no longer stored in the history'));
  ChangeSettings(LSettings);
end;

procedure TMainForm.btnClearHistoryClick(Sender: TObject);
var
  LRecord: TMHActionRecord;
begin
  if FServices.Storage = nil then
    Exit;
  if not FConfirm(MHL('Удалить всю историю наблюдений? Это действие нельзя отменить.',
    'Delete the entire observation history? This cannot be undone.')) then
    Exit;
  LRecord.TimestampUtc := FServices.Clock.NowUtc;
  LRecord.Action := 'history-clear';
  LRecord.Target := FServices.Storage.FileName;
  try
    FServices.Storage.Clear;
    LRecord.Result := MHL('История наблюдений очищена', 'Observation history cleared');
    LRecord.Success := True;
  except
    on E: Exception do
    begin
      FServices.Logger.Log(llError, 'app', MHL('Не удалось очистить историю: ', 'Failed to clear the history: ') + E.Message);
      LRecord.Result := E.Message;
      LRecord.Success := False;
    end;
  end;
  if FServices.ActionLog <> nil then
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', MHL('Журнал действий недоступен: ', 'Action log is unavailable: ') + E.Message);
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
  if FDisksPage <> nil then
  begin
    if GetActivePage = pgDisks then
      FDisksPage.UpdateSnapshot(ASnapshot);
    FDisksPage.CheckSchedule(ASnapshot);
  end;
  // Отчёт «Проверить сейчас» — по первому снимку, собранному после сброса кэшей.
  if FCheckPending and (FServices.Scanner.LastRefreshSequence > FCheckBaseline) and
     (ASnapshot.Sequence >= FServices.Scanner.LastRefreshSequence) then
    CompleteCheck(ASnapshot, AFindings);
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
    lblAlerts.Caption := Format(MHTr('⚠ Требуют проверки: %d'), [LAlerts]);
    LState := tsAlert;
  end
  else if LLow > 0 then
  begin
    lblAlerts.Caption := Format(MHTr('✔ Угроз не обнаружено · под наблюдением: %d'), [LLow]);
    LState := tsOk;
  end
  else
  begin
    lblAlerts.Caption := MHTr('✔ Признаков угроз не обнаружено');
    LState := tsOk;
  end;
  // Светлый фон цвета состояния, заголовок — насыщенным цветом (не только цвет: есть значок и текст).
  if MHIsDarkTheme then
  begin
    if LState = tsAlert then
      pnlStatus.Color := TColor($00303050)
    else
      pnlStatus.Color := TColor($00303A30);
  end
  else if LState = tsAlert then
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
    LText := MHTr('Объяснение и безопасные действия — в «Находках». ')
  else
    LText := '';
  if ASnapshot.FindSource(TMHProcessCollector.SourceIdValue, LStatus) and LStatus.RequiresElevation then
    LText := LText + MHTr('Без прав администратора часть процессов видна не полностью.')
  else
    LText := LText + MHTr('Все доступные процессы анализируются.');
  if LUnavailable <> '' then
    LText := LText + MHTr(' Недоступно: ') + Trim(LUnavailable) + MHTr(' (подробности ниже).');
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
    lblFindingsCount.Caption := Format(MHTr('Активных: %d'), [FFindingsModel.Count])
  else
    lblFindingsCount.Caption := Format(MHTr('В истории: %d'), [FFindingsModel.Count]);
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
  Item.SubItems.Add(MHFindingCategoryTitle(LRow.Finding.Category));
  if LRow.Finding.ProcessName <> '' then
    Item.SubItems.Add(LRow.Finding.ProcessName)
  else
    Item.SubItems.Add(MHTr('система'));
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
          FServices.Logger.Log(llWarning, 'app', MHL('История находок недоступна: ', 'Findings history is unavailable: ') + E.Message);
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
      FServices.Logger.Log(llWarning, 'app', MHL('График нагрузки недоступен: ', 'Load chart is unavailable: ') + E.Message);
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
      SetMemoText(mmCard, MHL('Находок нет. Отсутствие находок не гарантирует отсутствие угроз: ' +
        'MineHunter X оценивает поведение программ, а не проверяет файлы по базе сигнатур.',
        'No findings. The absence of findings does not guarantee the absence of threats: ' +
        'MineHunter X assesses program behavior rather than checking files against a signature database.'))
    else
      SetMemoText(mmCard, MHL('Выберите находку в списке, чтобы увидеть объяснение и доступные действия.',
        'Select a finding in the list to see the explanation and available actions.'));
    FCardSeriesKey := '';
    FCardChart.SetPoints(nil);
    FCardChart.Title := MHTr('Нагрузка (последний час)');
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
      FCardChart.Title := 'CPU: ' + LRow.Finding.ProcessName + MHL(' (час)', ' (hour)')
    else
      FCardChart.Title := MHTr('CPU системы (час)');
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
  lblCardStatus.Caption := MHTr('Microsoft Defender проверяет файл… Это может занять несколько минут.');
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
  if not FConfirm(Format(MHL('Остановить процесс %s (PID %d)?', 'Stop process %s (PID %d)?') +
    sLineBreak + '%s' + sLineBreak + sLineBreak +
    MHL('Несохранённые данные этой программы будут потеряны. Файл программы не удаляется.',
    'Unsaved data of this program will be lost. The program file is not deleted.'),
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
  if not FConfirm(Format(MHL('Добавить %s в разрешённые программы?', 'Add %s to allowed programs?') +
    sLineBreak + '%s' + sLineBreak + sLineBreak +
    MHL('MineHunter X перестанет сообщать об этом файле. Если файл будет заменён другим, ' +
    'проверка возобновится (исключение привязано к SHA-256).',
    'MineHunter X will stop reporting this file. If the file is replaced with a different one, ' +
    'checking will resume (the exclusion is bound to SHA-256).'),
    [LRow.Finding.ProcessName, LRow.Finding.ImagePath])) then
    Exit;
  LExclusion := Default(TMHExclusion);
  LExclusion.Key := MHProgramKey(LRow.Finding.ImagePath, LRow.Finding.ProcessName);
  LExclusion.Name := LRow.Finding.ProcessName;
  LExclusion.CreatedUtc := FServices.Clock.NowUtc;
  LExclusion.Comment := MHL('Добавлено из карточки находки: ', 'Added from the finding card: ') + LRow.Finding.Title;
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
      LRecord.Result := MHL('Программа добавлена в исключения', 'Program added to exclusions');
      LRecord.Success := True;
      try
        FServices.ActionLog.LogAction(LRecord);
      except
        on E: Exception do
          FServices.Logger.Log(llWarning, 'actions', MHL('Журнал действий недоступен: ', 'Action log is unavailable: ') + E.Message);
      end;
    end;
    FFindingsModel.Remove(LRow.Finding.Key);
    FSelectedFindingKey := '';
    lblCardStatus.Caption := LRow.Finding.ProcessName + MHL(' добавлена в исключения.', ' added to exclusions.');
    RefreshFindingsList;
    RefreshExclusions;
    RefreshActionLog;
  end
  else
    lblCardStatus.Caption := MHTr('Эта программа уже есть в исключениях.');
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
  FServices.Logger.Log(llInfo, 'app', MHL('Отчёт сохранён: ', 'Report saved: ') + AFileName);
end;

procedure TMainForm.ExportFindingCard(const AFileName: string; AHtml: Boolean);
var
  LRow: TMHFindingRow;
  LProcess: TMHProcessInfo;
  LSeries: TArray<TMHMetric>;
begin
  if not SelectedFinding(LRow) then
    raise EMHError.Create(MHL('Находка не выбрана', 'No finding selected'));
  if not FindLiveProcess(LRow.Finding.Process, LProcess) then
    LProcess := TMHProcessInfo.Create(LRow.Finding.Process, LRow.Finding.ProcessName, LRow.LastSeenUtc);
  LSeries := LoadSeriesFor(LRow.Finding);
  if AHtml then
    MHSaveTextFile(AFileName, TMHReportBuilder.FindingCardHtml(LRow.Finding, LProcess, LSeries, ReportOptions))
  else
    MHSaveTextFile(AFileName, TMHReportBuilder.FindingCardJson(LRow.Finding, LProcess, LSeries, ReportOptions));
  FServices.Logger.Log(llInfo, 'app', MHL('Карточка находки сохранена: ', 'Finding card saved: ') + AFileName);
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
    lblCardStatus.Caption := MHTr('Отчёт сохранён: ') + LFile;
  except
    on E: Exception do
      lblCardStatus.Caption := MHTr('Не удалось сохранить отчёт: ') + E.Message;
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
    lblCardStatus.Caption := MHTr('Карточка сохранена: ') + LFile;
  except
    on E: Exception do
      lblCardStatus.Caption := MHTr('Не удалось сохранить карточку: ') + E.Message;
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
        Result := MHL(MH_NO_DATA, 'no data')
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
        mkCpuPercent: LItem.Caption := MHTr('Процессор');
        mkMemoryLoadPercent: LItem.Caption := MHTr('Память');
        mkDiskActivePercent: LItem.Caption := MHTr('Активность диска');
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
      LItem.Caption := MHTr('Программы работают в пределах нормы');
    end;
  finally
    lvDeviations.Items.EndUpdate;
  end;
end;

procedure TMainForm.btnRebuildBaselineClick(Sender: TObject);
begin
  if FServices.BaselineScheduler = nil then
  begin
    lblBaselineInfo.Caption := MHTr('Профиль нормы недоступен без истории наблюдений.');
    Exit;
  end;
  FServices.BaselineScheduler.RequestRebuild;
  lblBaselineInfo.Caption := MHTr('Профиль нормы перестраивается в фоне. Нажмите «Обновить» через минуту.');
end;

{ Настройки }

procedure TMainForm.ChangeSettings(const ASettings: TMHAppSettings);
var
  LError: string;
begin
  FServices.ApplySettings(ASettings);
  if not FServices.SaveSettings(LError) then
    lblStorageStats.Caption := MHTr('Настройки применены, но не сохранены: ') + LError;
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
      cbHighCpu.Items.Add(Format(MHL('%d%% всей машины', '%d%% of the whole machine'), [HIGH_CPU_CHOICES[I]]));
      if Round(LSettings.Analyzer.HighCpuPercent) = HIGH_CPU_CHOICES[I] then
        cbHighCpu.ItemIndex := I;
    end;
    cbSustained.Items.Clear;
    cbSustained.ItemIndex := -1;
    for I := Low(SUSTAINED_CHOICES) to High(SUSTAINED_CHOICES) do
    begin
      cbSustained.Items.Add(Format(MHL('%d мин', '%d min'), [SUSTAINED_CHOICES[I]]));
      if LSettings.Analyzer.SustainedMinutes = SUSTAINED_CHOICES[I] then
        cbSustained.ItemIndex := I;
    end;
    cbLearning.Items.Clear;
    cbLearning.ItemIndex := -1;
    for I := Low(LEARNING_CHOICES) to High(LEARNING_CHOICES) do
    begin
      cbLearning.Items.Add(Format(MHL('%d дн.', '%d days'), [LEARNING_CHOICES[I]]));
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
        LItem.SubItems.Add(MHTr('любой файл по этому пути'))
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
  if not FConfirm(Format(MHL('Удалить %s из разрешённых программ? MineHunter X снова будет анализировать её.',
    'Remove %s from allowed programs? MineHunter X will analyze it again.'),
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
  FRemediateButton.Caption := MHTr('Исправить (карантин с откатом)…');
  FRemediateButton.Hint := MHL('Показывает план: остановить процесс, отключить автозапуск и признаки ',
    'Shows the plan: stop the process, disable autostart and ') +
    MHL('вмешательства, переместить файлы в карантин. Каждый шаг можно отменить в «Настройки → Карантин».',
    'tampering signs, move files to quarantine. Each step can be undone in “Settings → Quarantine”.');
  FRemediateButton.ShowHint := True;
  FRemediateButton.Enabled := False;
  FRemediateButton.OnClick := RemediateClick;

  // Раздел «Карантин» в настройках — под журналом действий.
  FQuarantineBox := TGroupBox.Create(Self);
  FQuarantineBox.Parent := sbSettings;
  FQuarantineBox.SetBounds(gbActionLog.Left, gbActionLog.Top + gbActionLog.Height + 16, gbActionLog.Width, 230);
  FQuarantineBox.Caption := MHTr('Карантин и откат исправлений');
  FQuarantineList := TListView.Create(Self);
  FQuarantineList.Parent := FQuarantineBox;
  FQuarantineList.SetBounds(12, 24, FQuarantineBox.Width - 24, 150);
  FQuarantineList.ViewStyle := vsReport;
  FQuarantineList.ReadOnly := True;
  FQuarantineList.RowSelect := True;
  FQuarantineList.HideSelection := False;
  with FQuarantineList.Columns.Add do
  begin
    Caption := MHTr('Когда');
    Width := 95;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := MHTr('Тип');
    Width := 110;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := MHTr('Объект');
    Width := 270;
  end;
  with FQuarantineList.Columns.Add do
  begin
    Caption := MHTr('Причина');
    Width := 160;
  end;
  FQuarantineList.OnSelectItem := QuarantineSelectItem;
  FQuarantineRestore := TButton.Create(Self);
  FQuarantineRestore.Parent := FQuarantineBox;
  FQuarantineRestore.SetBounds(12, 184, 160, 30);
  FQuarantineRestore.Caption := MHTr('Восстановить');
  FQuarantineRestore.Enabled := False;
  FQuarantineRestore.OnClick := QuarantineRestoreClick;
  FQuarantinePurge := TButton.Create(Self);
  FQuarantinePurge.Parent := FQuarantineBox;
  FQuarantinePurge.SetBounds(180, 184, 180, 30);
  FQuarantinePurge.Caption := MHTr('Удалить навсегда…');
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
        Result := TMHActionResult.Create(arkNotFound, MHL('Процесс ', 'Process ') + AStep.ProcessName +
          MHL(' уже не запущен', ' is no longer running'));
    rmQuarantineFile:
      Result := FServices.Quarantine.QuarantineFile(AStep.Target, AReason);
    rmRegistryValue:
      Result := FServices.Quarantine.DisableRegistryValue(AStep.Target, AStep.ValueName, AReason);
    rmService:
      Result := FServices.Quarantine.DisableService(AStep.Target, AReason);
    rmTask:
      Result := FServices.Quarantine.DisableTask(AStep.Target, AReason);
  else
    Result := TMHActionResult.Create(arkUnavailable, MHL('Вручную: ', 'Manually: ') + AStep.Description);
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
    lblCardStatus.Caption := MHTr('Для этой находки нет автоматических шагов исправления — следуйте рекомендациям.');
    Exit;
  end;
  LQuestion := MHL('Исправить находку «', 'Remediate the finding “') + LRow.Finding.Title + MHL('»?', '”?') +
    sLineBreak + sLineBreak + MHL('Будут выполнены шаги:', 'The following steps will be performed:') + sLineBreak;
  for I := 0 to High(LSteps) do
    LQuestion := LQuestion + Format('%d. %s', [I + 1, LSteps[I].Description]) + sLineBreak;
  LQuestion := LQuestion + sLineBreak +
    MHL('Файлы не удаляются: они перемещаются в карантин, а значения реестра, службы и задания ' +
    'сохраняются. Всё можно вернуть в «Настройки → Карантин». Файлы Windows не затрагиваются.',
    'Files are not deleted: they are moved to quarantine, and registry values, services and tasks ' +
    'are preserved. Everything can be restored in “Settings → Quarantine”. Windows files are not affected.');
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
  FServices.Logger.Log(llInfo, 'actions', MHL('Исправление «', 'Remediation “') + LRow.Finding.Title +
    MHL('»:', '”:') + sLineBreak + LReport);
  if LFailed = 0 then
    lblCardStatus.Caption := Format(MHTr('Исправление выполнено: %d из %d шагов. Отменить можно в «Настройки → Карантин».'),
      [LDone, Length(LSteps)])
  else
    lblCardStatus.Caption := Format(MHTr('Исправление выполнено частично: успешно %d, с ошибками %d — подробности в журнале.'),
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
      FServices.Logger.Log(llWarning, 'quarantine', MHL('Список карантина недоступен: ', 'Quarantine list is unavailable: ') + E.Message);
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
    FQuarantineBox.Caption := MHTr('Карантин и откат исправлений — пусто')
  else
    FQuarantineBox.Caption := Format(MHTr('Карантин и откат исправлений — %d'), [Length(FQuarantineItems)]);
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
  if not FConfirm(MHL('Восстановить из карантина?', 'Restore from quarantine?') + sLineBreak +
    LItem.Description + sLineBreak + sLineBreak +
    MHL('Объект вернётся на прежнее место и снова сможет запускаться.',
    'The object will return to its original location and will be able to run again.')) then
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
  if not FConfirm(MHL('Удалить навсегда файл из карантина?', 'Permanently delete the file from quarantine?') +
    sLineBreak + LItem.Description + sLineBreak + sLineBreak +
    MHL('Это действие нельзя отменить.', 'This action cannot be undone.')) then
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
  LItem.Caption := MHTr('Открыть MineHunter X');
  LItem.Default := True;
  LItem.OnClick := TrayOpenClick;
  FTrayMenu.Items.Add(LItem);
  LItem := TMenuItem.Create(FTrayMenu);
  LItem.Caption := '-';
  FTrayMenu.Items.Add(LItem);
  LItem := TMenuItem.Create(FTrayMenu);
  LItem.Caption := MHTr('Выход');
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
  FBackgroundBox.Caption := MHTr('Работа в фоне и уведомления');
  LTop := 26;
  FInitializingSettings := True;
  try
    FChkTray := AddCheck(MHTr('Сворачивать и закрывать в область уведомлений (значок у часов)'),
      MHL('Наблюдение продолжается, пока окно скрыто. Полный выход — «Выход» в меню значка.',
      'Monitoring continues while the window is hidden. To quit completely, use “Exit” in the icon menu.'),
      FServices.Settings.MinimizeToTray);
    FChkNotify := AddCheck(MHTr('Уведомлять о новых тревогах (уровень «подозрительно» и выше)'),
      MHL('Не чаще одного уведомления в минуту; об одной находке — один раз, повторно — если риск вырос.',
      'At most one notification per minute; once per finding, again only if the risk has increased.'),
      FServices.Settings.NotifyAlerts);
    FChkEconomy := AddCheck(Format(MHTr('Экономный режим: пока окно скрыто, опрос раз в %d с'),
      [TMHAppSettings.EconomyIntervalMs div 1000]),
      MHL('Снижает нагрузку самого MineHunter X, когда вы не смотрите на окно.',
      'Reduces the load of MineHunter X itself while you are not looking at the window.'),
      FServices.Settings.EconomyWhenHidden);
    FChkAutostart := AddCheck(MHTr('Запускать MineHunter X вместе с Windows (свёрнутым)'),
      MHL('Запись в HKCU\...\CurrentVersion\Run только для текущего пользователя; права администратора не нужны.',
      'An entry in HKCU\...\CurrentVersion\Run for the current user only; administrator rights are not required.'),
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
          FLblAutostart.Caption := MHTr('Включено: ') + FServices.SelfAutostart.Command;
        end;
      sasStale:
        begin
          FChkAutostart.Checked := False;
          FLblAutostart.Caption := MHL('Запись автозапуска указывает на другой файл (программу переместили) — ',
            'The autostart entry points to another file (the program was moved) — ') +
            MHL('включите заново.', 'turn it on again.');
        end;
    else
      FChkAutostart.Checked := False;
      FLblAutostart.Caption := MHTr('Выключено.');
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
    LRecord.Result := MHL('Готово', 'Done')
  else
    LRecord.Result := MHL('Не удалось изменить автозапуск: ', 'Failed to change autostart: ') + LError;
  if FServices.ActionLog <> nil then
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', MHL('Журнал действий недоступен: ', 'Action log is unavailable: ') + E.Message);
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
    FTray.Hint := Format(MHTr('MineHunter X — требуют проверки: %d'), [LAlerts])
  else if FServices.Scanner.IsRunning then
    FTray.Hint := MHTr('MineHunter X — угроз не обнаружено')
  else
    FTray.Hint := MHTr('MineHunter X — наблюдение остановлено');
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
      FTray.BalloonTitle := MHTr('MineHunter X работает в фоне');
      FTray.BalloonHint := MHTr('Наблюдение продолжается. Откройте окно щелчком по значку; выход — в меню значка.');
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

procedure TMainForm.WMQueryEndSession(var AMessage: TWMQueryEndSession);
begin
  // Завершение сеанса Windows или Restart Manager (установщик): программа закрывается,
  // а не прячется в трей — иначе она мешала бы выключению компьютера.
  FQuitting := True;
  inherited;
end;

procedure TMainForm.WndProc(var AMessage: TMessage);
begin
  // Сообщение «MineHunterX.Quit» (RegisterWindowMessage) — штатный выход для
  // сценариев автоматизации: WM_CLOSE при включённом трее только скрывает окно.
  if (MH_QUIT_MESSAGE <> 0) and (AMessage.Msg = MH_QUIT_MESSAGE) then
  begin
    Quit;
    AMessage.Result := 1;
  end
  else
    inherited WndProc(AMessage);
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

procedure TMainForm.CreateCheckAndChangesControls;
begin
  FShowReport := DefaultShowReport;

  // «Проверить сейчас» — в верхней панели рядом с запуском и остановкой.
  FBtnCheckNow := TButton.Create(Self);
  FBtnCheckNow.Parent := pnlTop;
  FBtnCheckNow.SetBounds(lblScanState.Left + lblScanState.Width + 12, btnStart.Top, 170, btnStart.Height);
  FBtnCheckNow.Caption := MHTr('Проверить сейчас');
  FBtnCheckNow.Hint := MHTr('Внеочередная полная проверка (перечитываются автозапуск и признаки вмешательства) ') +
    'и понятный отчёт по её итогам.';
  FBtnCheckNow.ShowHint := True;
  FBtnCheckNow.OnClick := CheckNowClick;

  // «Что изменилось» и электроэнергия — колонка справа от графиков на странице «История»
  // (графики сохраняют высоту).
  FChangesPanel := TPanel.Create(Self);
  FChangesPanel.Parent := pnlBaseline.Parent;
  FChangesPanel.BevelOuter := bvNone;
  FChangesPanel.Width := 440;
  FChangesPanel.Align := alRight;
  FLblEnergy := TLabel.Create(Self);
  FLblEnergy.Parent := FChangesPanel;
  FLblEnergy.SetBounds(8, 4, FChangesPanel.Width - 16, 64);
  FLblEnergy.Anchors := [akLeft, akTop, akRight];
  FLblEnergy.AutoSize := False;
  FLblEnergy.WordWrap := True;
  FLblEnergy.ShowAccelChar := False;
  FLblEnergy.Caption := MHTr('Электроэнергия: загрузка…');
  with TLabel.Create(Self) do
  begin
    Parent := FChangesPanel;
    SetBounds(8, 74, FChangesPanel.Width - 16, 17);
    Caption := MHTr('Что изменилось за 7 дней');
    Font.Style := [fsBold];
    Hint := MHL('Впервые замеченные записи автозапуска, признаки вмешательства в защиту и программы. ' +
      'Всё, что было на компьютере в первые 30 минут наблюдения, считается исходным состоянием.',
      'First-seen autostart entries, security tampering signs and programs. Everything present ' +
      'during the first 30 minutes of monitoring is treated as the initial state.');
    ShowHint := True;
  end;
  FChangesList := TListView.Create(Self);
  FChangesList.Parent := FChangesPanel;
  FChangesList.SetBounds(8, 94, FChangesPanel.Width - 16, Max(60, FChangesPanel.Height - 100));
  FChangesList.Anchors := [akLeft, akTop, akRight, akBottom];
  FChangesList.ViewStyle := vsReport;
  FChangesList.ReadOnly := True;
  FChangesList.RowSelect := True;
  with FChangesList.Columns.Add do
  begin
    Caption := MHTr('Впервые замечено');
    Width := 85;
  end;
  with FChangesList.Columns.Add do
  begin
    Caption := MHTr('Что изменилось');
    Width := 150;
  end;
  with FChangesList.Columns.Add do
  begin
    Caption := MHTr('Объект');
    Width := 110;
  end;
  with FChangesList.Columns.Add do
  begin
    Caption := MHTr('Где');
    Width := 300;
  end;

  // Цена электроэнергии — в настройках работы в фоне.
  FBackgroundBox.Height := FBackgroundBox.Height + 36;
  FLblPrice := TLabel.Create(Self);
  FLblPrice.Parent := FBackgroundBox;
  FLblPrice.SetBounds(16, FBackgroundBox.Height - 44, 260, 15);
  FLblPrice.Caption := MHTr('Цена электроэнергии, ₽ за кВт·ч:');
  FEdPrice := TEdit.Create(Self);
  FEdPrice.Parent := FBackgroundBox;
  FEdPrice.SetBounds(280, FBackgroundBox.Height - 48, 90, 23);
  FEdPrice.Text := FormatFloat('0.00', FServices.Settings.ElectricityPrice);
  FEdPrice.Hint := MHTr('Используется для оценки стоимости работы видеокарты (и скрытого майнера на ней).');
  FEdPrice.ShowHint := True;
  FEdPrice.OnExit := PriceExit;
  FEdPrice.OnKeyPress := PriceKeyPress;
end;

function TMainForm.ApplyPriceText: Boolean;
var
  LText: string;
  LValue: Double;
  LSettings: TMHAppSettings;
  LFormat: TFormatSettings;
begin
  LText := Trim(FEdPrice.Text).Replace(',', '.').Replace('₽', '').Trim;
  LFormat := TFormatSettings.Invariant;
  Result := TryStrToFloat(LText, LValue, LFormat) and (LValue >= 0) and
    (LValue <= TMHAppSettings.MaxElectricityPrice);
  if Result then
  begin
    LSettings := FServices.Settings;
    LSettings.ElectricityPrice := LValue;
    ChangeSettings(LSettings);
  end;
  FEdPrice.Text := FormatFloat('0.00', FServices.Settings.ElectricityPrice);
end;

procedure TMainForm.PriceExit(Sender: TObject);
begin
  ApplyPriceText;
end;

procedure TMainForm.PriceKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    Key := #0;
    ApplyPriceText;
  end;
end;

procedure TMainForm.CheckNowClick(Sender: TObject);
begin
  CheckNow;
end;

procedure TMainForm.CheckNow;
begin
  if FCheckPending then
    Exit;
  FCheckPending := True;
  FCheckBaseline := FServices.Scanner.LastRefreshSequence;
  FBtnCheckNow.Enabled := False;
  FBtnCheckNow.Caption := MHTr('Проверка…');
  FServices.Scanner.RequestRefresh;
  // Без запущенного наблюдения цикл выполняется здесь же: обработчики вызываются
  // в этом потоке, и отчёт будет готов к выходу из процедуры.
  if not FServices.Scanner.IsRunning then
    FServices.Scanner.ScanOnce;
end;

procedure TMainForm.CompleteCheck(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings);
var
  LInput: TMHCheckReportInput;
  LInventory: IMHInventoryHistory;
  LInfo: TSystemInfo;
  LNow: TDateTime;
begin
  FCheckPending := False;
  FBtnCheckNow.Enabled := True;
  FBtnCheckNow.Caption := MHTr('Проверить сейчас');
  LInput := Default(TMHCheckReportInput);
  LInput.Snapshot := ASnapshot;
  LInput.Findings := AFindings;
  GetSystemInfo(LInfo);
  LInput.CpuCount := LInfo.dwNumberOfProcessors;
  LInput.ChangesDays := CHANGES_DAYS;
  LInput.ElectricityPrice := FServices.Settings.ElectricityPrice;
  LInput.IsElevated := TMHWinProcessApi.QueryElevation;
  LNow := ASnapshot.TimestampUtc;
  try
    if Supports(FServices.MetricHistory, IMHInventoryHistory, LInventory) then
    begin
      LInput.ChangesAvailable := True;
      LInput.Changes := LInventory.LoadInventoryChanges(LNow - CHANGES_DAYS, 200);
      LInput.InventoryStartUtc := LInventory.InventoryStartUtc;
    end;
    if FServices.MetricHistory <> nil then
      LInput.Energy := MHEstimateEnergy(FServices.MetricHistory.LoadMetricSeries(mkGpuPowerWatts,
        LNow - 1, LNow, 24 * 60), LInput.ElectricityPrice);
  except
    on E: Exception do
      FServices.Logger.Log(llWarning, 'check', MHL('История для отчёта недоступна: ', 'History for the report is unavailable: ') + E.Message);
  end;
  FLastCheckReport := MHBuildCheckReport(LInput);
  Inc(FCheckCount);
  FServices.Logger.Log(llInfo, 'check', MHL('Проверка выполнена: ', 'Check completed: ') + FLastCheckReport.Headline);
  UpdateEvents;
  if Assigned(FShowReport) then
    FShowReport(FLastCheckReport);
end;

procedure TMainForm.DefaultShowReport(AReport: TMHCheckReport);
var
  LForm: TForm;
  LMemo: TMemo;
  LPanel: TPanel;
  LHeadline: TLabel;
  LSave, LClose: TButton;
  LFileName: string;
  LHtml: Boolean;
begin
  if not Visible then
  begin
    // Окно скрыто в трей — итог показывается уведомлением.
    if (FTray <> nil) and FTray.Visible then
    begin
      FTray.BalloonTitle := MHTr('MineHunter X: проверка завершена');
      FTray.BalloonHint := AReport.Headline + '.';
      FTray.BalloonFlags := bfInfo;
      FTray.ShowBalloonHint;
    end;
    Exit;
  end;
  LForm := TForm.Create(nil);
  try
    LForm.Caption := MHTr('MineHunter X — результат проверки');
    LForm.Position := poOwnerFormCenter;
    LForm.Width := 860;
    LForm.Height := 640;
    LForm.Font.Assign(Font);
    LHeadline := TLabel.Create(LForm);
    LHeadline.Parent := LForm;
    LHeadline.Align := alTop;
    LHeadline.AlignWithMargins := True;
    LHeadline.Caption := AReport.Headline;
    LHeadline.Font.Size := 13;
    LHeadline.Font.Style := [fsBold];
    case AReport.Verdict of
      cvThreat: LHeadline.Font.Color := $002020C0;
      cvAttention: LHeadline.Font.Color := $000080C0;
    else
      LHeadline.Font.Color := $00208020;
    end;
    LPanel := TPanel.Create(LForm);
    LPanel.Parent := LForm;
    LPanel.Align := alBottom;
    LPanel.Height := 46;
    LPanel.BevelOuter := bvNone;
    LMemo := TMemo.Create(LForm);
    LMemo.Parent := LForm;
    LMemo.Align := alClient;
    LMemo.AlignWithMargins := True;
    LMemo.ReadOnly := True;
    LMemo.ScrollBars := ssVertical;
    LMemo.Font.Name := 'Consolas';
    LMemo.Text := AReport.Text;
    LSave := TButton.Create(LForm);
    LSave.Parent := LPanel;
    LSave.SetBounds(8, 8, 220, 30);
    LSave.Caption := MHTr('Сохранить подробный отчёт…');
    LSave.ModalResult := mrYes;
    LClose := TButton.Create(LForm);
    LClose.Parent := LPanel;
    LClose.SetBounds(236, 8, 120, 30);
    LClose.Caption := MHTr('Закрыть');
    LClose.ModalResult := mrCancel;
    LClose.Cancel := True;
    LClose.Default := True;
    if LForm.ShowModal = mrYes then
      if AskExportFile('minehunter-check-' + FormatDateTime('yyyymmdd-hhnn', Now), LFileName, LHtml) then
        ExportReport(LFileName, LHtml);
  finally
    LForm.Free;
  end;
end;

function MeasuredText(AHours: Double): string;
begin
  if AHours < 1 then
    Result := Format(MHL('%.0f мин', '%.0f min'), [AHours * 60])
  else
    Result := Format(MHL('%.1f ч', '%.1f h'), [AHours]);
end;

procedure TMainForm.ApplyChanges;
var
  LItem: TMHInventoryItem;
  LView: TListItem;
  LEnergy: TMHEnergyEstimate;
  LText: string;
begin
  if FChangesList = nil then
    Exit;
  LEnergy := FHistoryResultEnergy;
  if LEnergy.HasData and (LEnergy.CoveredHours > 0) then
    LText := Format(MHL('Электроэнергия видеокарты за %d ч (измерено %s): %s ≈ %s · в среднем %.0f Вт, ' +
      'пик %.0f Вт · при такой нагрузке ≈ %s в месяц (цена %s за кВт·ч).',
      'Graphics card electricity over %d h (measured %s): %s ≈ %s · average %.0f W, ' +
      'peak %.0f W · at this load ≈ %s per month (price %s per kWh).'),
      [FHistoryResultHours, MeasuredText(LEnergy.CoveredHours), MHFormatEnergy(LEnergy.KWh), MHFormatMoney(LEnergy.Cost),
       LEnergy.AverageWatts, LEnergy.PeakWatts, MHFormatMoney(LEnergy.CostPerMonth),
       MHFormatMoney(FServices.Settings.ElectricityPrice)])
  else
    LText := MHL('Электроэнергия: видеокарта не сообщает мощность (датчик есть у видеокарт NVIDIA) ' +
      'или за период нет измерений.', 'Electricity: the graphics card does not report power draw ' +
      '(NVIDIA cards have the sensor) or there are no measurements for the period.');
  FLblEnergy.Caption := LText;

  FChangesList.Items.BeginUpdate;
  try
    FChangesList.Items.Clear;
    for LItem in FHistoryResultChanges do
    begin
      LView := FChangesList.Items.Add;
      LView.Caption := FormatDateTime('dd.mm hh:nn', TTimeZone.Local.ToLocalTime(LItem.FirstSeenUtc));
      LView.SubItems.Add(MHInventoryKindTitle(LItem.Kind));
      LView.SubItems.Add(LItem.Name);
      if LItem.Details <> '' then
        LView.SubItems.Add(LItem.Details)
      else
        LView.SubItems.Add(LItem.ImagePath);
    end;
  finally
    FChangesList.Items.EndUpdate;
  end;
  if Length(FHistoryResultChanges) > 0 then
    FChangesList.Hint := ''
  else if FHistoryResultInventoryStart > 0 then
    FChangesList.Hint := MHTr('За 7 дней ничего нового не появилось. Наблюдение ведётся с ') +
      MHFormatUtcAsLocal(FHistoryResultInventoryStart) + '.';
  FChangesList.ShowHint := FChangesList.Hint <> '';
end;

procedure TMainForm.CreateAppearanceControls;
var
  LTop: Integer;
begin
  FUpdateHttp := TMHNetHttpGet.Create;
  FAppearanceBox := TGroupBox.Create(Self);
  FAppearanceBox.Parent := sbSettings;
  FAppearanceBox.SetBounds(gbActionLog.Left, FBackgroundBox.Top + FBackgroundBox.Height + 16,
    gbActionLog.Width, 196);
  FAppearanceBox.Caption := MHTr('Внешний вид и обновления');
  LTop := 26;
  FInitializingSettings := True;
  try
    with TLabel.Create(Self) do
    begin
      Parent := FAppearanceBox;
      SetBounds(16, LTop + 4, 150, 15);
      Caption := MHTr('Язык интерфейса:');
    end;
    FCbLanguage := TComboBox.Create(Self);
    FCbLanguage.Parent := FAppearanceBox;
    FCbLanguage.Style := csDropDownList;
    FCbLanguage.SetBounds(170, LTop, 150, 23);
    FCbLanguage.Items.Add('Русский');
    FCbLanguage.Items.Add('English');
    FCbLanguage.ItemIndex := Ord(FServices.Settings.Language);
    with TLabel.Create(Self) do
    begin
      Parent := FAppearanceBox;
      SetBounds(340, LTop + 4, 60, 15);
      Caption := MHTr('Тема:');
    end;
    FCbTheme := TComboBox.Create(Self);
    FCbTheme.Parent := FAppearanceBox;
    FCbTheme.Style := csDropDownList;
    FCbTheme.SetBounds(400, LTop, 150, 23);
    FCbTheme.Items.Add(MHTr('Светлая'));
    FCbTheme.Items.Add(MHTr('Тёмная'));
    FCbTheme.ItemIndex := Ord(FServices.Settings.Theme);
    Inc(LTop, 30);
    FLblAppearanceNote := TLabel.Create(Self);
    FLblAppearanceNote.Parent := FAppearanceBox;
    FLblAppearanceNote.SetBounds(16, LTop, FAppearanceBox.Width - 32, 15);
    FLblAppearanceNote.AutoSize := False;
    FLblAppearanceNote.ShowAccelChar := False;
    FLblAppearanceNote.Font.Color := clGrayText;
    FLblAppearanceNote.Caption := MHL('Язык интерфейса применяется после перезапуска программы.',
      'The interface language applies after the program restarts.');
    Inc(LTop, 24);
    FChkUpdates := TCheckBox.Create(Self);
    FChkUpdates.Parent := FAppearanceBox;
    FChkUpdates.SetBounds(16, LTop, FAppearanceBox.Width - 32, 19);
    FChkUpdates.Caption := MHTr('Проверять новые версии на GitHub (раз в сутки)');
    FChkUpdates.Hint := MHL('Запрос только к api.github.com (последний выпуск ',
      'Requests go only to api.github.com (latest release of ') + MH_UPDATE_REPOSITORY +
      MHL('); сведения о компьютере не передаются, ничего не скачивается автоматически.',
      '); no information about the computer is sent, nothing is downloaded automatically.');
    FChkUpdates.ShowHint := True;
    FChkUpdates.Checked := FServices.Settings.CheckForUpdates;
    Inc(LTop, 28);
    FBtnCheckUpdates := TButton.Create(Self);
    FBtnCheckUpdates.Parent := FAppearanceBox;
    FBtnCheckUpdates.SetBounds(16, LTop, 180, 28);
    FBtnCheckUpdates.Caption := MHTr('Проверить обновления');
    FBtnCheckUpdates.OnClick := CheckUpdatesClick;
    FLblUpdate := TLabel.Create(Self);
    FLblUpdate.Parent := FAppearanceBox;
    FLblUpdate.SetBounds(206, LTop + 6, FAppearanceBox.Width - 222, 15);
    FLblUpdate.AutoSize := False;
    FLblUpdate.ShowAccelChar := False;
    FLblUpdate.OnClick := UpdateLinkClick;
    if FServices.Settings.CheckForUpdates then
      FLblUpdate.Caption := ''
    else
      FLblUpdate.Caption := MHTr('Проверка обновлений выключена.');
    Inc(LTop, 40);
    FBtnExportSettings := TButton.Create(Self);
    FBtnExportSettings.Parent := FAppearanceBox;
    FBtnExportSettings.SetBounds(16, LTop, 180, 28);
    FBtnExportSettings.Caption := MHTr('Экспорт настроек…');
    FBtnExportSettings.Hint := MHL('Файл JSON с настройками и списком разрешённых программ (пути к файлам — внутри).',
      'A JSON file with the settings and the list of allowed programs (file paths are included).');
    FBtnExportSettings.ShowHint := True;
    FBtnExportSettings.OnClick := ExportSettingsClick;
    FBtnImportSettings := TButton.Create(Self);
    FBtnImportSettings.Parent := FAppearanceBox;
    FBtnImportSettings.SetBounds(204, LTop, 180, 28);
    FBtnImportSettings.Caption := MHTr('Импорт настроек…');
    FBtnImportSettings.OnClick := ImportSettingsClick;
  finally
    FInitializingSettings := False;
  end;
  FCbLanguage.OnChange := AppearanceChange;
  FCbTheme.OnChange := AppearanceChange;
  FChkUpdates.OnClick := UpdatesClick;
  if not MHDarkThemeAvailable then
  begin
    FCbTheme.Enabled := False;
    FCbTheme.Hint := MHL('Стиль тёмной темы не встроен в эту сборку.',
      'The dark theme style is not included in this build.');
    FCbTheme.ShowHint := True;
  end;
end;

procedure TMainForm.AppearanceChange(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings then
    Exit;
  LSettings := FServices.Settings;
  if FCbLanguage.ItemIndex >= 0 then
    LSettings.Language := TMHUiLanguage(FCbLanguage.ItemIndex);
  if FCbTheme.ItemIndex >= 0 then
    LSettings.Theme := TMHUiTheme(FCbTheme.ItemIndex);
  ChangeSettings(LSettings);
  if Sender = FCbLanguage then
    FLblAppearanceNote.Caption := 'Язык изменится после перезапуска MineHunter X. / ' +
      'The language will change after MineHunter X restarts.'
  else if (Sender = FCbTheme) and FOwnsServices then
    MHApplyTheme(LSettings.Theme);
end;

procedure TMainForm.UpdatesClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
begin
  if FInitializingSettings then
    Exit;
  LSettings := FServices.Settings;
  LSettings.CheckForUpdates := FChkUpdates.Checked;
  ChangeSettings(LSettings);
  if LSettings.CheckForUpdates then
    StartUpdateCheck
  else
    FLblUpdate.Caption := MHTr('Проверка обновлений выключена.');
end;

procedure TMainForm.CheckUpdatesClick(Sender: TObject);
begin
  StartUpdateCheck;
end;

procedure TMainForm.StartUpdateCheck;
var
  LHttp: IMHHttpGet;
begin
  if FUpdateRunning or (FUpdateHttp = nil) then
    Exit;
  FreeAndNil(FUpdateThread); // предыдущая проверка уже завершилась
  FUpdateRunning := True;
  FBtnCheckUpdates.Enabled := False;
  FLblUpdate.Caption := MHTr('Проверка…');
  LHttp := FUpdateHttp;
  FUpdateThread := TThread.CreateAnonymousThread(
    procedure
    begin
      FUpdateResult := MHCheckForUpdate(LHttp, MH_CORE_VERSION);
      TThread.Queue(TThread.Current, UpdateFinished);
    end);
  FUpdateThread.FreeOnTerminate := False;
  FUpdateThread.Start;
end;

procedure TMainForm.UpdateFinished;
begin
  if FDestroying then
    Exit;
  FUpdateRunning := False;
  Inc(FUpdateCount);
  FBtnCheckUpdates.Enabled := True;
  FLblUpdate.Caption := FUpdateResult.Message;
  if FUpdateResult.State = usAvailable then
  begin
    FLblUpdate.Font.Color := clHotLight;
    FLblUpdate.Font.Style := [fsUnderline];
    FLblUpdate.Cursor := crHandPoint;
    FLblUpdate.Hint := FUpdateResult.ReleaseUrl;
    FLblUpdate.ShowHint := True;
    if (FTray <> nil) and FTray.Visible and FHiddenToTray then
    begin
      FTray.BalloonTitle := 'MineHunter X ' + FUpdateResult.LatestVersion;
      FTray.BalloonHint := FUpdateResult.Message;
      FTray.BalloonFlags := bfInfo;
      FTray.ShowBalloonHint;
    end;
  end
  else
  begin
    FLblUpdate.Font.Color := clWindowText;
    FLblUpdate.Font.Style := [];
    FLblUpdate.Cursor := crDefault;
  end;
  FServices.Logger.Log(llInfo, 'updates', FUpdateResult.Message);
end;

procedure TMainForm.UpdateLinkClick(Sender: TObject);
begin
  // Открывается только страница выпусков проекта (адрес проверен при разборе ответа).
  if (FUpdateResult.State = usAvailable) and
     FUpdateResult.ReleaseUrl.StartsWith('https://github.com/' + MH_UPDATE_REPOSITORY + '/', True) then
    ShellExecute(Handle, 'open', PChar(FUpdateResult.ReleaseUrl), nil, nil, SW_SHOWNORMAL);
end;

function TMainForm.ExportSettingsTo(const AFileName: string; out AError: string): Boolean;
begin
  AError := '';
  try
    MHWriteTextFileAtomic(AFileName, MHSettingsToJson(FServices.Settings));
    Result := True;
  except
    on E: Exception do
    begin
      AError := E.Message;
      Result := False;
    end;
  end;
end;

function TMainForm.ImportSettingsFrom(const AFileName: string; out AError: string): Boolean;
var
  LText: string;
  LSettings: TMHAppSettings;
  LRecord: TMHActionRecord;
begin
  AError := '';
  Result := False;
  try
    if not FileExists(AFileName) then
      raise EMHSettingsError.Create(MHL('Файл не найден', 'File not found'));
    if TFile.GetSize(AFileName) > 4 * 1024 * 1024 then
      raise EMHSettingsError.Create(MHL('Файл слишком большой для файла настроек',
        'The file is too large to be a settings file'));
    LText := TFile.ReadAllText(AFileName, TEncoding.UTF8);
    LSettings := MHSettingsFromJson(LText);
  except
    on E: Exception do
    begin
      AError := E.Message;
      Exit;
    end;
  end;
  if not FConfirm(Format(MHL('Заменить текущие настройки настройками из файла?',
    'Replace the current settings with the settings from the file?') + sLineBreak + '%s' + sLineBreak +
    sLineBreak + MHL('Разрешённых программ в файле: %d. Текущие настройки будут заменены.',
    'Allowed programs in the file: %d. The current settings will be replaced.'),
    [AFileName, Length(LSettings.Exclusions)])) then
  begin
    AError := MHL('Отменено пользователем', 'Cancelled by the user');
    Exit;
  end;
  ChangeSettings(LSettings);
  ReloadSettingsControls;
  if FServices.ActionLog <> nil then
  begin
    LRecord.TimestampUtc := FServices.Clock.NowUtc;
    LRecord.Action := 'settings-import';
    LRecord.Target := AFileName;
    LRecord.Result := MHL('Настройки импортированы', 'Settings imported');
    LRecord.Success := True;
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', MHL('Журнал действий недоступен: ', 'Action log is unavailable: ') + E.Message);
    end;
    RefreshActionLog;
  end;
  Result := True;
end;

procedure TMainForm.ReloadSettingsControls;
var
  I: Integer;
begin
  FInitializingSettings := True;
  try
    for I := Low(IntervalChoicesMs) to High(IntervalChoicesMs) do
      if IntervalChoicesMs[I] = FServices.Settings.IntervalMs then
        cbInterval.ItemIndex := I;
    FChkTray.Checked := FServices.Settings.MinimizeToTray;
    FChkNotify.Checked := FServices.Settings.NotifyAlerts;
    FChkEconomy.Checked := FServices.Settings.EconomyWhenHidden;
    FChkUpdates.Checked := FServices.Settings.CheckForUpdates;
    FCbLanguage.ItemIndex := Ord(FServices.Settings.Language);
    FCbTheme.ItemIndex := Ord(FServices.Settings.Theme);
    FEdPrice.Text := FormatFloat('0.00', FServices.Settings.ElectricityPrice);
  finally
    FInitializingSettings := False;
  end;
  InitStorageSettings;
  InitAnalysisSettings;
  RefreshExclusions;
end;

procedure TMainForm.ExportSettingsClick(Sender: TObject);
var
  LDialog: TSaveDialog;
  LError: string;
begin
  LDialog := TSaveDialog.Create(nil);
  try
    LDialog.Filter := MHL('Настройки MineHunter X (*.json)|*.json', 'MineHunter X settings (*.json)|*.json');
    LDialog.DefaultExt := 'json';
    LDialog.FileName := 'minehunter-settings.json';
    LDialog.Options := [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing];
    if not LDialog.Execute(Handle) then
      Exit;
    if ExportSettingsTo(LDialog.FileName, LError) then
      lblStorageStats.Caption := MHL('Настройки сохранены: ', 'Settings saved: ') + LDialog.FileName
    else
      lblStorageStats.Caption := MHL('Не удалось сохранить настройки: ', 'Failed to save settings: ') + LError;
  finally
    LDialog.Free;
  end;
end;

procedure TMainForm.ImportSettingsClick(Sender: TObject);
var
  LDialog: TOpenDialog;
  LError: string;
begin
  LDialog := TOpenDialog.Create(nil);
  try
    LDialog.Filter := MHL('Настройки MineHunter X (*.json)|*.json', 'MineHunter X settings (*.json)|*.json');
    LDialog.Options := [ofFileMustExist, ofHideReadOnly, ofEnableSizing];
    if not LDialog.Execute(Handle) then
      Exit;
    if ImportSettingsFrom(LDialog.FileName, LError) then
      lblStorageStats.Caption := MHL('Настройки импортированы: ', 'Settings imported: ') + LDialog.FileName
    else if LError <> MHL('Отменено пользователем', 'Cancelled by the user') then
      MessageDlg(MHL('Настройки не импортированы: ', 'Settings were not imported: ') + LError, mtWarning, [mbOK], 0);
  finally
    LDialog.Free;
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

initialization
  MH_QUIT_MESSAGE := RegisterWindowMessage('MineHunterX.Quit');

end.
