unit MineHunter.App.DisksPage;

{
  Страница «Диски»: каждый физический диск (нагрузка, температура, состояние,
  износ, ошибки, наработка), атрибуты здоровья выбранного диска (журнал NVMe
  или SMART, как в CrystalDiskInfo), разделы со свободным местом, программы с
  наибольшим чтением и записью и проверка файлов на всех дисках (фоновый
  поток с низким приоритетом ввода-вывода, прогресс, отмена, действия:
  открыть расположение, в карантин, «это мой файл»).

  Элементы создаются в коде на переданной вкладке; страница не владеет
  сервисами. Каждая вкладка прокручивается целиком, как «Обзор»: таблицы
  показываются полностью (высота по числу строк, MHFitListHeight). Все обращения к интерфейсу — в главном потоке: поток проверки
  передаёт прогресс и итог через TThread.Queue и отменяется при закрытии.
}

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ComCtrls, Vcl.Forms,
  System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.FileScan, MineHunter.App.Bootstrap, MineHunter.App.Chart;

type
  TMHConfirmQuestion = reference to function(const AQuestion: string): Boolean;
  TMHNotice = reference to procedure(const ATitle, AText: string);

  TMHDisksPage = class(TComponent)
  private
    FServices: TMHAppServices;
    FConfirm: TMHConfirmQuestion;
    FNotice: TMHNotice;
    FSheet: TWinControl;
    FLblInfo: TLabel;
    FDisks: TListView;
    FVolumes: TListView;
    FIo: TListView;
    FBtnScan: TButton;
    FBtnCancel: TButton;
    FChkWeekly: TCheckBox;
    FLblScan: TLabel;
    FHitsView: TListView;
    FBtnOpen: TButton;
    FBtnQuarantine: TButton;
    FBtnAllow: TButton;
    FScanThread: TThread;
    FScanCancel: Boolean;
    FScanRunning: Boolean;
    FScanSilent: Boolean;
    FScanProgress: TMHScanProgress;
    FScanHits: TArray<TMHScanHit>;
    FScanCount: Integer;
    FScanFs: IMHFileScanFs;
    FScanRoots: TArray<string>;
    FLastProgressTick: UInt64;
    FInitializing: Boolean;
    FTabs: TPageControl;
    FDiskTab, FNetTab, FGpuTab: TTabSheet;
    FNet: TListView;
    FGpu: TListView;
    FDiskChart, FNetChart, FGpuChart: TMHLineChart;
    FHistory: TObjectDictionary<string, TMHSeriesBuffer>;
    FDiskKeys, FNetKeys, FGpuKeys: TArray<string>;
    FLastSnapshot: TMHSnapshot;
    FAttrs: TListView;
    FAttrCaption: TLabel;
    FDiskScroll, FNetScroll, FGpuScroll: TScrollBox;
    FDiskPanel, FVolRow: TPanel;
    procedure AddPoint(const AKey: string; AKind: TMHMetricKind; AValue: Double; ATime: TDateTime);
    procedure ShowChart(AChart: TMHLineChart; AList: TListView; const AKeys: TArray<string>;
      const ATitle: string);
    procedure DeviceSelect(Sender: TObject; Item: TListItem; Selected: Boolean);
    function DiskKey(AItem: TListItem): string;
    function NetKey(AItem: TListItem): string;
    function GpuKey(AItem: TListItem): string;
    procedure UpdateNetwork(const ASnapshot: TMHSnapshot);
    procedure UpdateGpus(const ASnapshot: TMHSnapshot);
    procedure UpdateAttributes;
    function NewScroll(AParent: TWinControl): TScrollBox;
    procedure ScrollResize(Sender: TObject);
    function NewList(AParent: TWinControl; AAlign: TAlign; AHeight: Integer;
      const AColumns: array of string; const AWidths: array of Integer): TListView;
    function NewCaption(AParent: TWinControl; const AText: string): TLabel;
    procedure ScanClick(Sender: TObject);
    procedure CancelClick(Sender: TObject);
    procedure WeeklyClick(Sender: TObject);
    procedure HitSelect(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure OpenClick(Sender: TObject);
    procedure QuarantineClick(Sender: TObject);
    procedure AllowClick(Sender: TObject);
    procedure QueueProgress(const AProgress: TMHScanProgress);
    procedure ApplyProgress(const AProgress: TMHScanProgress);
    procedure ScanFinished;
    procedure ShowHits;
    function SelectedHit(out AHit: TMHScanHit): Boolean;
    procedure RemoveHit(const APath: string);
    procedure UpdateButtons;
  public
    constructor Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices;
      const AConfirm: TMHConfirmQuestion; const ANotice: TMHNotice); reintroduce;
    destructor Destroy; override;
    /// Обновляет таблицы по снимку (вызывается на каждом цикле, когда страница видна).
    procedure UpdateSnapshot(const ASnapshot: TMHSnapshot);
    /// Накопление истории для графиков устройств (на каждом цикле, даже если страница скрыта).
    procedure RecordHistory(const ASnapshot: TMHSnapshot);
    /// Высота таблиц по числу строк (после каждого обновления содержимого).
    procedure LayoutLists;
    property DiskScroll: TScrollBox read FDiskScroll;
    property NetScroll: TScrollBox read FNetScroll;
    property NetView: TListView read FNet;
    property GpuView: TListView read FGpu;
    property Tabs: TPageControl read FTabs;
    property DiskChart: TMHLineChart read FDiskChart;
    property NetChart: TMHLineChart read FNetChart;
    property GpuChart: TMHLineChart read FGpuChart;
    /// Запускает проверку файлов (ASilent — плановая: итог уведомлением).
    procedure StartScan(ASilent: Boolean = False);
    procedure CancelScan;
    /// Плановая проверка раз в неделю, когда компьютер простаивает.
    procedure CheckSchedule(const ASnapshot: TMHSnapshot);
    property ScanRunning: Boolean read FScanRunning;
    property ScanHits: TArray<TMHScanHit> read FScanHits;
    property ScanCount: Integer read FScanCount;
    property ScanProgress: TMHScanProgress read FScanProgress;
    /// Файловая система и корни проверки (по умолчанию — Windows и все локальные диски). Тесты подменяют.
    property ScanFs: IMHFileScanFs read FScanFs write FScanFs;
    property ScanRoots: TArray<string> read FScanRoots write FScanRoots;
    property DisksView: TListView read FDisks;
    property AttributesView: TListView read FAttrs;
    property AttributesCaption: TLabel read FAttrCaption;
    property VolumesView: TListView read FVolumes;
    property IoView: TListView read FIo;
    property HitsView: TListView read FHitsView;
    property WeeklyCheckBox: TCheckBox read FChkWeekly;
    property ScanLabel: TLabel read FLblScan;
    procedure QuarantineSelected;
    procedure AllowSelected;
  end;

const
  MH_FILE_SCAN_INTERVAL_DAYS = 7;

implementation

uses
  Winapi.Windows, System.Math, System.DateUtils, System.Generics.Defaults,
  Vcl.Graphics,
  MineHunter.Core.Lang, MineHunter.Core.Settings, MineHunter.Core.Actions, MineHunter.Core.Interfaces,
  MineHunter.Core.FileScan.WinApi, MineHunter.Collectors.Disks, MineHunter.Analysis.Disks,
  MineHunter.App.Display, MineHunter.App.ListViews, MineHunter.Collectors.NetAdapters,
  MineHunter.Collectors.DiskHealth;

const
  /// Точек истории на устройство: 10 минут при опросе раз в 2 с.
  HISTORY_POINTS = 300;
  /// Высота графика сети и видеокарт под таблицей.
  CHART_HEIGHT = 320;
  /// Строк в «Кто больше всего читает и пишет».
  IO_ROWS = 10;
  TOTAL_KEY = 'total';
  /// Ряд передачи сетевого адаптера (приём — основной ряд).
  TX_SUFFIX = ':tx';

const
  THREAD_MODE_BACKGROUND_BEGIN = $00010000;
  THREAD_MODE_BACKGROUND_END = $00020000;

{ TMHDisksPage }

constructor TMHDisksPage.Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices;
  const AConfirm: TMHConfirmQuestion; const ANotice: TMHNotice);
var
  LTop, LScanPanel, LButtons, LDiskPanel, LNetPanel, LGpuPanel, LVolRow, LVolPanel, LAttrPanel: TPanel;
  LHost: TWinControl;
begin
  inherited Create(AOwner);
  FSheet := ASheet;
  FServices := AServices;
  FConfirm := AConfirm;
  FNotice := ANotice;
  FScanFs := TMHWinFileScanFs.Create;
  FHistory := TObjectDictionary<string, TMHSeriesBuffer>.Create([doOwnsValues]);

  // Вкладки: диски (с проверкой файлов), сеть, видеокарты.
  FTabs := TPageControl.Create(Self);
  FTabs.Parent := ASheet;
  FTabs.Align := alClient;
  FDiskTab := TTabSheet.Create(Self);
  FDiskTab.PageControl := FTabs;
  FDiskTab.Caption := MHL('Диски', 'Disks');
  FNetTab := TTabSheet.Create(Self);
  FNetTab.PageControl := FTabs;
  FNetTab.Caption := MHL('Сеть', 'Network');
  FGpuTab := TTabSheet.Create(Self);
  FGpuTab.PageControl := FTabs;
  FGpuTab.Caption := MHL('Видеокарты', 'Graphics cards');
  FDiskScroll := NewScroll(FDiskTab);
  FNetScroll := NewScroll(FNetTab);
  FGpuScroll := NewScroll(FGpuTab);
  LHost := FDiskScroll;

  LTop := TPanel.Create(Self);
  LTop.Parent := LHost;
  LTop.Align := alTop;
  LTop.Height := 28;
  LTop.BevelOuter := bvNone;
  FLblInfo := TLabel.Create(Self);
  FLblInfo.Parent := LTop;
  FLblInfo.SetBounds(8, 7, 900, 15);
  FLblInfo.ShowAccelChar := False;
  FLblInfo.Caption := MHL('Диски определяются автоматически. Износ, ошибки и наработка — по данным самих дисков ' +
    '(часть сведений доступна только с правами администратора).', 'Disks are detected automatically. Wear, ' +
    'errors and power-on hours come from the disks themselves (some data requires administrator rights).');

  NewCaption(LHost, MHL('Физические диски (строка «Всего» — все диски вместе; выберите диск, чтобы увидеть график)',
    'Physical disks ("Total" row is all disks together; select a disk to see its chart)'));
  LDiskPanel := TPanel.Create(Self);
  LDiskPanel.Parent := LHost;
  LDiskPanel.Top := 10000;
  LDiskPanel.Align := alTop;
  LDiskPanel.Height := 160;
  LDiskPanel.BevelOuter := bvNone;
  FDiskPanel := LDiskPanel;
  FDiskChart := TMHLineChart.Create(Self);
  FDiskChart.Parent := LDiskPanel;
  FDiskChart.Align := alRight;
  FDiskChart.Width := 340;
  FDiskChart.SetFixedRange(0, 100);
  FDiskChart.Formatter :=
    function(AValue: Double): string
    begin
      Result := FormatFloat('0', AValue) + ' %';
    end;
  FDisks := NewList(LDiskPanel, alClient, 0,
    [MHL('Диск', 'Disk'), MHL('Модель', 'Model'), MHL('Тип', 'Type'), MHL('Объём', 'Size'),
     MHL('Разделы', 'Volumes'), MHL('Занят', 'Busy'), MHL('Чтение', 'Read'), MHL('Запись', 'Write'),
     MHL('Температура', 'Temperature'), MHL('Состояние', 'Health'), MHL('Износ', 'Wear'),
     MHL('Ошибки', 'Errors'), MHL('Наработка', 'Power-on')],
    [55, 170, 175, 70, 70, 50, 75, 75, 135, 120, 55, 60, 75]);
  // Разделы слева, атрибуты здоровья выбранного диска справа — в одной строке.
  LVolRow := TPanel.Create(Self);
  LVolRow.Parent := LHost;
  LVolRow.Top := 10000;
  LVolRow.Align := alTop;
  LVolRow.Height := 210;
  LVolRow.BevelOuter := bvNone;
  FVolRow := LVolRow;
  LAttrPanel := TPanel.Create(Self);
  LAttrPanel.Parent := LVolRow;
  LAttrPanel.Align := alRight;
  LAttrPanel.Width := 640;
  LAttrPanel.BevelOuter := bvNone;
  FAttrCaption := NewCaption(LAttrPanel, MHL('Здоровье диска', 'Disk health'));
  FAttrs := NewList(LAttrPanel, alClient, 0,
    ['ID', MHL('Атрибут', 'Attribute'), MHL('Значение', 'Value'), MHL('Текущее', 'Current'),
     MHL('Худшее', 'Worst'), MHL('Порог', 'Threshold'), 'Raw'],
    [34, 205, 75, 58, 55, 48, 118]);
  FAttrs.Hint := MHL('Те же атрибуты, что показывает CrystalDiskInfo: журнал здоровья NVMe или SMART диска SATA.',
    'The same attributes CrystalDiskInfo shows: the NVMe health log or the SMART of a SATA disk.');
  FAttrs.ShowHint := True;
  LVolPanel := TPanel.Create(Self);
  LVolPanel.Parent := LVolRow;
  LVolPanel.Align := alClient;
  LVolPanel.BevelOuter := bvNone;
  NewCaption(LVolPanel, MHL('Разделы', 'Volumes'));
  FVolumes := NewList(LVolPanel, alClient, 0,
    [MHL('Раздел', 'Volume'), MHL('Метка', 'Label'), MHL('ФС', 'FS'), MHL('Всего', 'Total'),
     MHL('Свободно', 'Free'), MHL('Свободно, %', 'Free, %'), MHL('Диск', 'Disk'), MHL('Состояние', 'State')],
    [60, 160, 55, 80, 80, 80, 50, 260]);
  NewCaption(LHost, MHL('Кто больше всего читает и пишет (все операции ввода-вывода процесса)',
    'Top readers and writers (all process I/O)'));
  FIo := NewList(LHost, alTop, 110,
    [MHL('Программа', 'Program'), 'PID', MHL('Чтение', 'Read'), MHL('Запись', 'Write'), MHL('Путь', 'Path')],
    [170, 60, 90, 90, 480]);

  LScanPanel := TPanel.Create(Self);
  LScanPanel.Parent := LHost;
  LScanPanel.Top := 10000; // под таблицами дисков, над результатами проверки
  LScanPanel.Align := alTop;
  LScanPanel.Height := 104;
  LScanPanel.BevelOuter := bvNone;
  FBtnScan := TButton.Create(Self);
  FBtnScan.Parent := LScanPanel;
  FBtnScan.SetBounds(8, 6, 250, 28);
  FBtnScan.Caption := MHL('Проверить файлы на всех дисках', 'Scan files on all disks');
  FBtnScan.Hint := MHL('Ищет майнеры и их следы: известные программы, конфигурации пулов, сценарии запуска, ' +
    'драйвер WinRing0, маскировку под системные файлы. Работает в фоне с низким приоритетом.',
    'Looks for miners and their traces: known programs, pool configurations, launch scripts, the WinRing0 ' +
    'driver, files disguised as system files. Runs in the background at low priority.');
  FBtnScan.ShowHint := True;
  FBtnScan.OnClick := ScanClick;
  FBtnCancel := TButton.Create(Self);
  FBtnCancel.Parent := LScanPanel;
  FBtnCancel.SetBounds(266, 6, 120, 28);
  FBtnCancel.Caption := MHL('Остановить', 'Stop');
  FBtnCancel.Enabled := False;
  FBtnCancel.OnClick := CancelClick;
  FChkWeekly := TCheckBox.Create(Self);
  FChkWeekly.Parent := LScanPanel;
  FChkWeekly.SetBounds(400, 11, 520, 19);
  FChkWeekly.Caption := MHL('Проверять раз в неделю, когда компьютер простаивает',
    'Scan once a week while the computer is idle');
  FInitializing := True;
  FChkWeekly.Checked := FServices.Settings.FileScanWeekly;
  FInitializing := False;
  FChkWeekly.OnClick := WeeklyClick;
  with TLabel.Create(Self) do
  begin
    Parent := LScanPanel;
    SetBounds(8, 40, 1100, 34);
    AutoSize := False;
    WordWrap := True;
    ShowAccelChar := False;
    Caption := MHL('Проверка ищет на всех дисках следы майнеров, которые сейчас не запущены: известные майнеры ' +
      'и их настройки (адреса пулов, кошельки), сценарии их запуска, драйвер WinRing0 и программы рядом с ним, ' +
      'скрытые программы в системных папках, файлы под видом системных. Ничего не удаляется: найденное можно ' +
      'открыть, отправить в карантин или отметить как свой файл.',
      'The scan looks on all disks for traces of miners that are not running now: known miners and their ' +
      'settings (pool addresses, wallets), their launch scripts, the WinRing0 driver and programs next to it, ' +
      'hidden programs in system folders, files disguised as system files. Nothing is deleted: you can open ' +
      'what was found, quarantine it or mark it as your own file.');
  end;
  FLblScan := TLabel.Create(Self);
  FLblScan.Parent := LScanPanel;
  FLblScan.SetBounds(8, 80, 1100, 15);
  FLblScan.AutoSize := False;
  FLblScan.ShowAccelChar := False;
  if FServices.Settings.LastFileScanUtc > 0 then
    FLblScan.Caption := MHL('Последняя проверка: ', 'Last scan: ') +
      FormatDateTime('dd.mm.yyyy hh:nn', TTimeZone.Local.ToLocalTime(FServices.Settings.LastFileScanUtc))
  else
    FLblScan.Caption := MHL('Файлы ещё не проверялись.', 'Files have not been scanned yet.');

  LButtons := TPanel.Create(Self);
  LButtons.Parent := LHost;
  LButtons.Top := 10000;
  LButtons.Align := alTop;
  LButtons.Height := 40;
  LButtons.BevelOuter := bvNone;
  FBtnOpen := TButton.Create(Self);
  FBtnOpen.Parent := LButtons;
  FBtnOpen.SetBounds(8, 6, 180, 28);
  FBtnOpen.Caption := MHL('Открыть расположение', 'Open file location');
  FBtnOpen.OnClick := OpenClick;
  FBtnQuarantine := TButton.Create(Self);
  FBtnQuarantine.Parent := LButtons;
  FBtnQuarantine.SetBounds(196, 6, 180, 28);
  FBtnQuarantine.Caption := MHL('В карантин…', 'Quarantine…');
  FBtnQuarantine.OnClick := QuarantineClick;
  FBtnAllow := TButton.Create(Self);
  FBtnAllow.Parent := LButtons;
  FBtnAllow.SetBounds(384, 6, 180, 28);
  FBtnAllow.Caption := MHL('Это мой файл…', 'This is my file…');
  FBtnAllow.OnClick := AllowClick;
  FHitsView := NewList(LHost, alTop, 0,
    [MHL('Оценка', 'Score'), MHL('Уровень', 'Level'), MHL('Что найдено', 'What was found'), MHL('Файл', 'File'),
     MHL('Размер', 'Size')], [55, 140, 330, 480, 80]);
  // Кнопки действий — под результатами проверки.
  LButtons.Top := FHitsView.Top + FHitsView.Height + 1;
  FHitsView.OnSelectItem := HitSelect;
  FDisks.OnSelectItem := DeviceSelect;

  // Вкладка «Сеть».
  LNetPanel := TPanel.Create(Self);
  LNetPanel.Parent := FNetScroll;
  LNetPanel.Align := alTop;
  LNetPanel.Height := 30;
  LNetPanel.BevelOuter := bvNone;
  with TLabel.Create(Self) do
  begin
    Parent := LNetPanel;
    SetBounds(8, 8, 1000, 15);
    ShowAccelChar := False;
    Caption := MHL('Каждый сетевой адаптер отдельно и «Всего». Скорость — в битах в секунду, как в диспетчере задач. ' +
      'Выберите адаптер — график приёма (синяя линия) и передачи (оранжевая) за 10 минут.',
      'Each network adapter separately and "Total". Speed is in bits per second, as in Task Manager. ' +
      'Select an adapter to see receive (blue line) and send (orange) over 10 minutes.');
  end;
  FNet := NewList(FNetScroll, alTop, 0,
    [MHL('Адаптер', 'Adapter'), MHL('Тип', 'Type'), MHL('Состояние', 'State'), MHL('Скорость канала', 'Link speed'),
     MHL('Приём', 'Receive'), MHL('Передача', 'Send'), MHL('Устройство', 'Device')],
    [170, 140, 110, 110, 95, 95, 360]);
  FNet.OnSelectItem := DeviceSelect;
  FNetChart := TMHLineChart.Create(Self);
  FNetChart.Parent := FNetScroll;
  FNetChart.Height := CHART_HEIGHT;
  FNetChart.Top := 10000;
  FNetChart.Align := alTop;
  FNetChart.Formatter :=
    function(AValue: Double): string
    begin
      Result := MHFormatBitRate(AValue);
    end;

  // Вкладка «Видеокарты».
  LGpuPanel := TPanel.Create(Self);
  LGpuPanel.Parent := FGpuScroll;
  LGpuPanel.Align := alTop;
  LGpuPanel.Height := 30;
  LGpuPanel.BevelOuter := bvNone;
  with TLabel.Create(Self) do
  begin
    Parent := LGpuPanel;
    SetBounds(8, 8, 1000, 15);
    ShowAccelChar := False;
    Caption := MHL('Каждая видеокарта отдельно и «Всего». Выберите видеокарту — график загрузки за 10 минут.',
      'Each graphics card separately and "Total". Select a card to see its load over 10 minutes.');
  end;
  FGpu := NewList(FGpuScroll, alTop, 0,
    [MHL('Видеокарта', 'Graphics card'), MHL('Загрузка', 'Load'), MHL('Вычисления', 'Compute'),
     MHL('Видеопамять', 'Video memory'), MHL('Температура', 'Temperature'), MHL('Мощность', 'Power')],
    [300, 90, 100, 110, 110, 90]);
  FGpu.OnSelectItem := DeviceSelect;
  FGpu.Hint := MHL('Температуру видеокарты MineHunter X берёт из Windows (D3DKMT), мощность — у NVIDIA (NVML). ' +
    'Встроенная видеокарта Intel через эти интерфейсы температуру и мощность не сообщает: HWiNFO читает их ' +
    'своим драйвером. MineHunter X драйверы не устанавливает.', 'MineHunter X takes the graphics card temperature ' +
    'from Windows (D3DKMT) and power from NVIDIA (NVML). Intel integrated graphics do not report temperature and ' +
    'power through these interfaces: HWiNFO reads them with its own driver. MineHunter X does not install drivers.');
  FGpu.ShowHint := True;
  FGpuChart := TMHLineChart.Create(Self);
  FGpuChart.Parent := FGpuScroll;
  FGpuChart.Height := CHART_HEIGHT;
  FGpuChart.Top := 10000;
  FGpuChart.Align := alTop;
  FGpuChart.SetFixedRange(0, 100);
  FGpuChart.Formatter :=
    function(AValue: Double): string
    begin
      Result := FormatFloat('0', AValue) + ' %';
    end;
  FDiskScroll.OnResize := ScrollResize;
  FNetScroll.OnResize := ScrollResize;
  FGpuScroll.OnResize := ScrollResize;
  LayoutLists;
  UpdateButtons;
end;

function TMHDisksPage.NewScroll(AParent: TWinControl): TScrollBox;
begin
  Result := TScrollBox.Create(Self);
  Result.Parent := AParent;
  Result.Align := alClient;
  Result.BorderStyle := bsNone;
  Result.HorzScrollBar.Visible := False;
  Result.VertScrollBar.Tracking := True;
end;

procedure TMHDisksPage.ScrollResize(Sender: TObject);
begin
  // Ширина влияет на горизонтальную полосу таблиц, а значит, и на их высоту.
  LayoutLists;
end;

procedure TMHDisksPage.LayoutLists;
const
  CAPTION_HEIGHT = 24;
  MIN_DISK_PANEL = 160;
begin
  if FHitsView = nil then
    Exit;
  FDiskPanel.Height := Max(MIN_DISK_PANEL, MHListFitHeight(FDisks, 2));
  FVolRow.Height := CAPTION_HEIGHT + Max(MHListFitHeight(FVolumes, 2), MHListFitHeight(FAttrs, 2));
  // Число программ меняется каждый цикл — место всегда под IO_ROWS строк, иначе высота
  // вкладки скачет и полоса прокрутки страницы то появляется, то исчезает.
  MHFitListHeight(FIo, IO_ROWS);
  MHFitListHeight(FHitsView, 3);
  MHFitListHeight(FNet, 2);
  MHFitListHeight(FGpu, 2);
  // График под таблицей — до низа вкладки, но не ниже CHART_HEIGHT.
  // Top внутри прокрученной области отсчитывается от текущей позиции прокрутки.
  FNetChart.Height := Max(CHART_HEIGHT, FNetScroll.ClientHeight -
    (FNet.Top + FNetScroll.VertScrollBar.Position + FNet.Height) - 2);
  FGpuChart.Height := Max(CHART_HEIGHT, FGpuScroll.ClientHeight -
    (FGpu.Top + FGpuScroll.VertScrollBar.Position + FGpu.Height) - 2);
end;

destructor TMHDisksPage.Destroy;
begin
  // Проверка отменяется (отмена проверяется на каждом файле) и дожидается завершения.
  FScanCancel := True;
  FreeAndNil(FScanThread);
  FHistory.Free;
  inherited;
end;

function TMHDisksPage.NewCaption(AParent: TWinControl; const AText: string): TLabel;
var
  LPanel: TPanel;
begin
  LPanel := TPanel.Create(Self);
  LPanel.Parent := AParent;
  LPanel.Align := alTop;
  LPanel.Height := 24;
  LPanel.Top := 10000; // после уже выровненных сверху элементов
  LPanel.BevelOuter := bvNone;
  Result := TLabel.Create(Self);
  Result.Parent := LPanel;
  Result.SetBounds(8, 6, 900, 15);
  Result.Font.Style := [fsBold];
  Result.ShowAccelChar := False;
  Result.Caption := AText;
end;

function TMHDisksPage.NewList(AParent: TWinControl; AAlign: TAlign; AHeight: Integer;
  const AColumns: array of string; const AWidths: array of Integer): TListView;
var
  I: Integer;
begin
  Result := TListView.Create(Self);
  Result.Parent := AParent;
  if AHeight > 0 then
    Result.Height := AHeight;
  Result.Top := 10000;
  Result.Align := AAlign;
  Result.ViewStyle := vsReport;
  Result.ReadOnly := True;
  Result.RowSelect := True;
  Result.HideSelection := False;
  for I := 0 to High(AColumns) do
    with Result.Columns.Add do
    begin
      Caption := AColumns[I];
      Width := AWidths[I];
    end;
end;

function HoursText(AHours: Int64): string;
begin
  if AHours < 0 then
    Exit(MH_NO_DATA);
  if AHours >= 24 * 365 then
    Result := Format(MHL('%.1f г.', '%.1f yr'), [AHours / (24 * 365)])
  else
    Result := Format(MHL('%d ч', '%d h'), [AHours]);
end;

function KeyAt(const AKeys: TArray<string>; AIndex: Integer): string;
begin
  if (AIndex >= 0) and (AIndex <= High(AKeys)) then
    Result := AKeys[AIndex]
  else
    Result := '';
end;

function TMHDisksPage.DiskKey(AItem: TListItem): string;
begin
  Result := KeyAt(FDiskKeys, AItem.Index);
end;

function TMHDisksPage.NetKey(AItem: TListItem): string;
begin
  Result := KeyAt(FNetKeys, AItem.Index);
end;

function TMHDisksPage.GpuKey(AItem: TListItem): string;
begin
  Result := KeyAt(FGpuKeys, AItem.Index);
end;

procedure TMHDisksPage.UpdateSnapshot(const ASnapshot: TMHSnapshot);
var
  LDisk: TMHDiskInfo;
  LVolume: TMHVolumeInfo;
  LItem: TListItem;
  LText: string;
  LNumbers: string;
  LNumber: Integer;
  LList: TList<TMHProcessInfo>;
  LInfo: TMHProcessInfo;
  I: Integer;
  LState: TMHListState;
  LKeyOf: TMHListItemKey;
  LTotalSize: Int64;
  LTotalRead, LTotalWrite, LBusiest: Double;

  function IoTotal(const AInfo: TMHProcessInfo): Double;
  begin
    Result := 0;
    if AInfo.IoRead.HasValue then
      Result := Result + AInfo.IoRead.Value;
    if AInfo.IoWrite.HasValue then
      Result := Result + AInfo.IoWrite.Value;
  end;

begin
  FLastSnapshot := ASnapshot;
  LKeyOf := DiskKey;
  LState := MHSaveListState(FDisks, LKeyOf);
  FDiskKeys := nil;
  FDisks.Items.BeginUpdate;
  try
    FDisks.Items.Clear;
    for LDisk in ASnapshot.Disks do
    begin
      LItem := FDisks.Items.Add;
      LItem.Caption := IntToStr(LDisk.Number);
      LItem.SubItems.Add(LDisk.Model);
      LText := MHDiskMediaToString(LDisk.Media);
      if LDisk.Bus <> '' then
        LText := LText + ', ' + LDisk.Bus;
      LItem.SubItems.Add(LText);
      if LDisk.SizeBytes > 0 then
        LItem.SubItems.Add(MHFormatSize(LDisk.SizeBytes))
      else
        LItem.SubItems.Add(MH_NO_DATA);
      LItem.SubItems.Add(LDisk.Volumes);
      if LDisk.HasActivity then
      begin
        LItem.SubItems.Add(FormatFloat('0', LDisk.ActivePercent) + ' %');
        LItem.SubItems.Add(MHFormatRate(LDisk.ReadBytesPerSec));
        LItem.SubItems.Add(MHFormatRate(LDisk.WriteBytesPerSec));
      end
      else
      begin
        LItem.SubItems.Add(MH_NO_DATA);
        LItem.SubItems.Add(MH_NO_DATA);
        LItem.SubItems.Add(MH_NO_DATA);
      end;
      if LDisk.HasTemperature then
      begin
        LText := FormatFloat('0', LDisk.TemperatureCelsius) + ' °C';
        if LDisk.TemperatureLimitCelsius > 0 then
          LText := LText + Format(MHL(' (порог %.0f)', ' (limit %.0f)'), [LDisk.TemperatureLimitCelsius]);
        LItem.SubItems.Add(LText);
      end
      else
        LItem.SubItems.Add(MHL('не сообщает', 'not reported'));
      LText := MHDiskHealthToString(LDisk.Health);
      if LDisk.HealthDetails <> '' then
        LText := LText + ': ' + LDisk.HealthDetails;
      LItem.SubItems.Add(LText);
      // Износ ресурса записи имеет смысл только для SSD.
      if LDisk.HasWear and (LDisk.Media <> dmHdd) then
        LItem.SubItems.Add(FormatFloat('0', LDisk.WearPercent) + ' %')
      else if LDisk.Media = dmHdd then
        LItem.SubItems.Add('—')
      else
        LItem.SubItems.Add(MH_NO_DATA);
      if LDisk.HasErrors then
        LItem.SubItems.Add(IntToStr(LDisk.ReadErrors + LDisk.WriteErrors))
      else
        LItem.SubItems.Add(MH_NO_DATA);
      LItem.SubItems.Add(HoursText(LDisk.PowerOnHours));
      FDiskKeys := FDiskKeys + ['disk:' + IntToStr(LDisk.Number)];
    end;
    if Length(ASnapshot.Disks) > 1 then
    begin
      LItem := FDisks.Items.Add;
      LItem.Caption := MHL('Всего', 'Total');
      LItem.SubItems.Add(Format(MHL('дисков: %d', 'disks: %d'), [Length(ASnapshot.Disks)]));
      LItem.SubItems.Add('');
      LTotalSize := 0;
      LTotalRead := 0;
      LTotalWrite := 0;
      LBusiest := 0;
      for LDisk in ASnapshot.Disks do
      begin
        LTotalSize := LTotalSize + LDisk.SizeBytes;
        LTotalRead := LTotalRead + LDisk.ReadBytesPerSec;
        LTotalWrite := LTotalWrite + LDisk.WriteBytesPerSec;
        LBusiest := Max(LBusiest, LDisk.ActivePercent);
      end;
      LItem.SubItems.Add(MHFormatSize(LTotalSize));
      LItem.SubItems.Add('');
      LItem.SubItems.Add(FormatFloat('0', LBusiest) + ' %');
      LItem.SubItems.Add(MHFormatRate(LTotalRead));
      LItem.SubItems.Add(MHFormatRate(LTotalWrite));
      FDiskKeys := FDiskKeys + ['disk:' + TOTAL_KEY];
    end;
  finally
    FDisks.Items.EndUpdate;
  end;
  MHRestoreListState(FDisks, LState, LKeyOf);

  LKeyOf :=
    function(AItem: TListItem): string
    begin
      Result := AItem.Caption;
    end;
  LState := MHSaveListState(FVolumes, LKeyOf);
  FVolumes.Items.BeginUpdate;
  try
    FVolumes.Items.Clear;
    for LVolume in ASnapshot.Volumes do
    begin
      LItem := FVolumes.Items.Add;
      LItem.Caption := LVolume.Name;
      LText := LVolume.VolumeLabel;
      if LVolume.IsSystem then
        LText := Trim(LText + MHL(' (Windows)', ' (Windows)'));
      LItem.SubItems.Add(LText);
      LItem.SubItems.Add(LVolume.FileSystem);
      LItem.SubItems.Add(MHFormatSize(LVolume.TotalBytes));
      LItem.SubItems.Add(MHFormatSize(LVolume.FreeBytes));
      LItem.SubItems.Add(FormatFloat('0.0', LVolume.FreePercent) + ' %');
      LNumbers := '';
      for LNumber in LVolume.DiskNumbers do
        LNumbers := Trim(LNumbers + ' ' + IntToStr(LNumber));
      LItem.SubItems.Add(LNumbers);
      case MHVolumeSpaceLevel(LVolume) of
        slCritical: LItem.SubItems.Add(MHL('⚠ почти заполнен', '⚠ almost full'));
        slLow: LItem.SubItems.Add(MHL('мало места', 'low space'));
      else
        LItem.SubItems.Add(MHL('норма', 'normal'));
      end;
    end;
  finally
    FVolumes.Items.EndUpdate;
  end;
  MHRestoreListState(FVolumes, LState, LKeyOf);

  LList := TList<TMHProcessInfo>.Create;
  try
    for LInfo in ASnapshot.Processes do
      if IoTotal(LInfo) >= 1024 then
        LList.Add(LInfo);
    LList.Sort(TComparer<TMHProcessInfo>.Construct(
      function(const A, B: TMHProcessInfo): Integer
      var
        LA, LB: Double;
      begin
        LA := 0;
        LB := 0;
        if A.IoRead.HasValue then
          LA := LA + A.IoRead.Value;
        if A.IoWrite.HasValue then
          LA := LA + A.IoWrite.Value;
        if B.IoRead.HasValue then
          LB := LB + B.IoRead.Value;
        if B.IoWrite.HasValue then
          LB := LB + B.IoWrite.Value;
        Result := CompareValue(LB, LA);
      end));
    // Имя может повторяться (несколько msedge.exe) — ключ с PID.
    LKeyOf :=
      function(AItem: TListItem): string
      begin
        Result := MHItemTextKey(AItem, [0]);
      end;
    LState := MHSaveListState(FIo, LKeyOf);
    FIo.Items.BeginUpdate;
    try
      FIo.Items.Clear;
      for I := 0 to Min(LList.Count, IO_ROWS) - 1 do
      begin
        LItem := FIo.Items.Add;
        LItem.Caption := LList[I].Name;
        if LList[I].Id.Pid = GetCurrentProcessId then
          LItem.Caption := LItem.Caption + MHL(' (эта программа: проверка файлов запущенных программ)',
            ' (this program: checking files of running programs)');
        LItem.SubItems.Add(IntToStr(LList[I].Id.Pid));
        LItem.SubItems.Add(MHFormatRate(IfThen(LList[I].IoRead.HasValue, LList[I].IoRead.Value, 0)));
        LItem.SubItems.Add(MHFormatRate(IfThen(LList[I].IoWrite.HasValue, LList[I].IoWrite.Value, 0)));
        LItem.SubItems.Add(LList[I].ImagePath);
      end;
    finally
      FIo.Items.EndUpdate;
    end;
    MHRestoreListState(FIo, LState, LKeyOf);
  finally
    LList.Free;
  end;
  UpdateAttributes;
  UpdateNetwork(ASnapshot);
  UpdateGpus(ASnapshot);
  LayoutLists;
  ShowChart(FDiskChart, FDisks, FDiskKeys, MHL('Занятость диска (10 мин)', 'Disk busy (10 min)'));
  ShowChart(FNetChart, FNet, FNetKeys, MHL('Сеть (10 мин)', 'Network (10 min)'));
  ShowChart(FGpuChart, FGpu, FGpuKeys, MHL('Загрузка видеокарты (10 мин)', 'GPU load (10 min)'));
end;

procedure TMHDisksPage.AddPoint(const AKey: string; AKind: TMHMetricKind; AValue: Double; ATime: TDateTime);
var
  LBuffer: TMHSeriesBuffer;
begin
  if not FHistory.TryGetValue(AKey, LBuffer) then
  begin
    LBuffer := TMHSeriesBuffer.Create(HISTORY_POINTS);
    FHistory.Add(AKey, LBuffer);
  end;
  LBuffer.Add(TMHMetric.Available(AKind, AValue, ATime));
end;

procedure TMHDisksPage.RecordHistory(const ASnapshot: TMHSnapshot);
var
  LDisk: TMHDiskInfo;
  LNet: TMHNetAdapterInfo;
  LGpu: TMHGpuAdapterInfo;
  LTime: TDateTime;
  LMax, LSum, LSumTx: Double;
  LAny: Boolean;
begin
  LTime := ASnapshot.TimestampUtc;
  LMax := 0;
  LAny := False;
  for LDisk in ASnapshot.Disks do
    if LDisk.HasActivity then
    begin
      AddPoint('disk:' + IntToStr(LDisk.Number), mkDiskActivePercent, LDisk.ActivePercent, LTime);
      LMax := Max(LMax, LDisk.ActivePercent);
      LAny := True;
    end;
  if LAny then
    AddPoint('disk:' + TOTAL_KEY, mkDiskActivePercent, LMax, LTime);
  // Приём — основной ряд устройства, передача — ряд «…:tx» (две линии на графике).
  LSum := 0;
  LSumTx := 0;
  LAny := False;
  for LNet in ASnapshot.NetAdapters do
    if LNet.HasRate then
    begin
      AddPoint('net:' + IntToStr(LNet.Index), mkNetworkBytesPerSec, LNet.ReceiveBytesPerSec, LTime);
      AddPoint('net:' + IntToStr(LNet.Index) + TX_SUFFIX, mkNetworkBytesPerSec, LNet.SendBytesPerSec, LTime);
      LSum := LSum + LNet.ReceiveBytesPerSec;
      LSumTx := LSumTx + LNet.SendBytesPerSec;
      LAny := True;
    end;
  if LAny then
  begin
    AddPoint('net:' + TOTAL_KEY, mkNetworkBytesPerSec, LSum, LTime);
    AddPoint('net:' + TOTAL_KEY + TX_SUFFIX, mkNetworkBytesPerSec, LSumTx, LTime);
  end;
  LMax := 0;
  LAny := False;
  for LGpu in ASnapshot.GpuAdapters do
    if LGpu.HasLoad then
    begin
      AddPoint('gpu:' + LGpu.Key.ToLower, mkGpuPercent, LGpu.LoadPercent, LTime);
      LMax := Max(LMax, LGpu.LoadPercent);
      LAny := True;
    end;
  if LAny then
    AddPoint('gpu:' + TOTAL_KEY, mkGpuPercent, LMax, LTime);
end;

procedure TMHDisksPage.ShowChart(AChart: TMHLineChart; AList: TListView; const AKeys: TArray<string>;
  const ATitle: string);
var
  LKey, LName: string;
  LBuffer: TMHSeriesBuffer;
  LIndex: Integer;
begin
  // Выбранное устройство, иначе — «Всего» (последняя строка), иначе — единственное.
  LIndex := -1;
  if (AList.Selected <> nil) and (AList.Selected.Index <= High(AKeys)) then
    LIndex := AList.Selected.Index
  else if Length(AKeys) > 0 then
    LIndex := High(AKeys);
  if LIndex < 0 then
  begin
    AChart.SetPoints(nil);
    AChart.Title := ATitle;
    Exit;
  end;
  LKey := AKeys[LIndex];
  if FHistory.TryGetValue(LKey, LBuffer) then
    AChart.SetPoints(LBuffer.ToArray)
  else
    AChart.SetPoints(nil);
  if AChart = FNetChart then
  begin
    if FHistory.TryGetValue(LKey + TX_SUFFIX, LBuffer) then
      AChart.SetSecondSeries(LBuffer.ToArray, MHL('Приём', 'Receive'), MHL('Передача', 'Send'))
    else
      AChart.SetSecondSeries(nil, '', '');
  end;
  LName := AList.Items[LIndex].Caption;
  // У диска в первом столбце только номер — добавляем модель.
  if (AList = FDisks) and (LKey <> 'disk:' + TOTAL_KEY) and (AList.Items[LIndex].SubItems.Count > 0) then
    LName := Format(MHL('диск %s — %s', 'disk %s — %s'), [LName, AList.Items[LIndex].SubItems[0]]);
  AChart.Title := ATitle + ': ' + LName;
end;

procedure TMHDisksPage.DeviceSelect(Sender: TObject; Item: TListItem; Selected: Boolean);
begin
  // Только график своей таблицы: при пересборке других списков их ключи ещё не готовы.
  if not Selected then
    Exit;
  if Sender = FDisks then
  begin
    ShowChart(FDiskChart, FDisks, FDiskKeys, MHL('Занятость диска (10 мин)', 'Disk busy (10 min)'));
    UpdateAttributes;
    LayoutLists;
  end
  else if Sender = FNet then
    ShowChart(FNetChart, FNet, FNetKeys, MHL('Сеть (10 мин)', 'Network (10 min)'))
  else if Sender = FGpu then
    ShowChart(FGpuChart, FGpu, FGpuKeys, MHL('Загрузка видеокарты (10 мин)', 'GPU load (10 min)'));
end;

procedure TMHDisksPage.UpdateAttributes;
var
  LDisks: TArray<TMHDiskInfo>;
  LDisk: TMHDiskInfo;
  LAttribute: TMHDiskAttribute;
  LItem: TListItem;
  LIndex, LNumber, I: Integer;
  LKey, LReason: string;
  LState: TMHListState;
  LKeyOf: TMHListItemKey;

  function Number(AValue: Integer): string;
  begin
    if AValue < 0 then
      Result := ''
    else
      Result := IntToStr(AValue);
  end;

begin
  LDisks := FLastSnapshot.Disks;
  // Выбранный диск; без выбора или для строки «Всего» — первый диск с атрибутами.
  LIndex := -1;
  LKey := '';
  if FDisks.Selected <> nil then
    LKey := DiskKey(FDisks.Selected);
  if LKey.StartsWith('disk:') and TryStrToInt(LKey.Substring(5), LNumber) then
    for I := 0 to High(LDisks) do
      if LDisks[I].Number = LNumber then
        LIndex := I;
  if LIndex < 0 then
    for I := High(LDisks) downto 0 do
      if Length(LDisks[I].Attributes) > 0 then
        LIndex := I;
  if (LIndex < 0) and (Length(LDisks) > 0) then
    LIndex := 0;

  LKeyOf :=
    function(AItem: TListItem): string
    begin
      Result := AItem.Caption;
    end;
  LState := MHSaveListState(FAttrs, LKeyOf);
  FAttrs.Items.BeginUpdate;
  try
    FAttrs.Items.Clear;
    if LIndex < 0 then
      FAttrCaption.Caption := MHL('Здоровье диска', 'Disk health')
    else
    begin
      LDisk := LDisks[LIndex];
      FAttrCaption.Caption := Format(MHL('Здоровье диска %d — %s', 'Disk %d health — %s'), [LDisk.Number, LDisk.Model]);
      if LDisk.AttributesSource = MH_HEALTH_SOURCE_NVME then
        FAttrCaption.Caption := FAttrCaption.Caption + MHL(' (журнал NVMe)', ' (NVMe log)')
      else if LDisk.AttributesSource = MH_HEALTH_SOURCE_SMART then
        FAttrCaption.Caption := FAttrCaption.Caption + ' (SMART)';
      for LAttribute in LDisk.Attributes do
      begin
        LItem := FAttrs.Items.Add;
        LItem.Caption := IntToHex(LAttribute.Id, 2);
        LItem.SubItems.Add(MHDiskAttributeName(LDisk.AttributesSource, LAttribute.Id));
        LItem.SubItems.Add(MHDiskAttributeText(LDisk.AttributesSource, LAttribute));
        LItem.SubItems.Add(Number(LAttribute.Current));
        LItem.SubItems.Add(Number(LAttribute.Worst));
        LItem.SubItems.Add(Number(LAttribute.Threshold));
        LItem.SubItems.Add(MHDiskAttributeRawHex(LDisk.AttributesSource, LAttribute));
      end;
      if Length(LDisk.Attributes) = 0 then
      begin
        if SameText(LDisk.Bus, 'USB') then
          LReason := MHL('Диск подключён через USB: атрибуты через USB-мост не запрашиваются.',
            'The disk is connected via USB: attributes are not requested through the USB bridge.')
        else if SameText(LDisk.Bus, 'SATA') or SameText(LDisk.Bus, 'ATA') then
          LReason := MHL('SMART дисков SATA доступен с правами администратора.',
            'SMART of SATA disks is available with administrator rights.')
        else
          LReason := MHL('Диск не сообщает атрибуты здоровья.', 'The disk does not report health attributes.');
        LItem := FAttrs.Items.Add;
        LItem.Caption := '';
        LItem.SubItems.Add(LReason);
      end;
    end;
  finally
    FAttrs.Items.EndUpdate;
  end;
  MHRestoreListState(FAttrs, LState, LKeyOf);
end;

procedure TMHDisksPage.UpdateNetwork(const ASnapshot: TMHSnapshot);
var
  LNet: TMHNetAdapterInfo;
  LItem: TListItem;
  LState: TMHListState;
  LRx, LTx: Double;
  LConnected: Integer;
begin
  LState := MHSaveListState(FNet, NetKey);
  FNetKeys := nil;
  FNet.Items.BeginUpdate;
  try
    FNet.Items.Clear;
    LRx := 0;
    LTx := 0;
    LConnected := 0;
    for LNet in ASnapshot.NetAdapters do
    begin
      LItem := FNet.Items.Add;
      LItem.Caption := LNet.Name;
      LItem.SubItems.Add(MHNetAdapterKindToString(LNet.Kind));
      if LNet.Connected then
      begin
        LItem.SubItems.Add(MHL('подключён', 'connected'));
        Inc(LConnected);
      end
      else
        LItem.SubItems.Add(MHL('не подключён', 'disconnected'));
      LItem.SubItems.Add(MHFormatLinkSpeed(LNet.LinkSpeedBps));
      if LNet.HasRate then
      begin
        LItem.SubItems.Add(MHFormatBitRate(LNet.ReceiveBytesPerSec));
        LItem.SubItems.Add(MHFormatBitRate(LNet.SendBytesPerSec));
        LRx := LRx + LNet.ReceiveBytesPerSec;
        LTx := LTx + LNet.SendBytesPerSec;
      end
      else
      begin
        LItem.SubItems.Add(MH_NO_DATA);
        LItem.SubItems.Add(MH_NO_DATA);
      end;
      LItem.SubItems.Add(LNet.Description);
      FNetKeys := FNetKeys + ['net:' + IntToStr(LNet.Index)];
    end;
    if Length(ASnapshot.NetAdapters) > 0 then
    begin
      LItem := FNet.Items.Add;
      LItem.Caption := MHL('Всего', 'Total');
      LItem.SubItems.Add(Format(MHL('адаптеров: %d', 'adapters: %d'), [Length(ASnapshot.NetAdapters)]));
      LItem.SubItems.Add(Format(MHL('подключено: %d', 'connected: %d'), [LConnected]));
      LItem.SubItems.Add('');
      LItem.SubItems.Add(MHFormatBitRate(LRx));
      LItem.SubItems.Add(MHFormatBitRate(LTx));
      FNetKeys := FNetKeys + ['net:' + TOTAL_KEY];
    end;
  finally
    FNet.Items.EndUpdate;
  end;
  MHRestoreListState(FNet, LState, NetKey);
end;

procedure TMHDisksPage.UpdateGpus(const ASnapshot: TMHSnapshot);
var
  LGpu: TMHGpuAdapterInfo;
  LItem: TListItem;
  LMaxLoad, LMaxCompute, LMemory, LPower: Double;
  LHasPower: Boolean;
  LState: TMHListState;
begin
  LState := MHSaveListState(FGpu, GpuKey);
  FGpuKeys := nil;
  FGpu.Items.BeginUpdate;
  try
    FGpu.Items.Clear;
    LMaxLoad := 0;
    LMaxCompute := 0;
    LMemory := 0;
    LPower := 0;
    LHasPower := False;
    for LGpu in ASnapshot.GpuAdapters do
    begin
      LItem := FGpu.Items.Add;
      LItem.Caption := LGpu.Name;
      if LGpu.HasLoad then
      begin
        LItem.SubItems.Add(FormatFloat('0', LGpu.LoadPercent) + ' %');
        LItem.SubItems.Add(FormatFloat('0', LGpu.ComputePercent) + ' %');
      end
      else
      begin
        LItem.SubItems.Add(MH_NO_DATA);
        LItem.SubItems.Add(MH_NO_DATA);
      end;
      if LGpu.HasMemory then
        LItem.SubItems.Add(MHFormatSize(LGpu.MemoryBytes))
      else
        LItem.SubItems.Add(MH_NO_DATA);
      if LGpu.HasTemperature then
        LItem.SubItems.Add(FormatFloat('0', LGpu.TemperatureCelsius) + ' °C')
      else
        LItem.SubItems.Add(MHL('не сообщает', 'not reported'));
      if LGpu.HasPower then
        LItem.SubItems.Add(FormatFloat('0', LGpu.PowerWatts) + MHL(' Вт', ' W'))
      else
        LItem.SubItems.Add(MH_NO_DATA);
      LMaxLoad := Max(LMaxLoad, LGpu.LoadPercent);
      LMaxCompute := Max(LMaxCompute, LGpu.ComputePercent);
      LMemory := LMemory + LGpu.MemoryBytes;
      if LGpu.HasPower then
      begin
        LPower := LPower + LGpu.PowerWatts;
        LHasPower := True;
      end;
      FGpuKeys := FGpuKeys + ['gpu:' + LGpu.Key.ToLower];
    end;
    if Length(ASnapshot.GpuAdapters) > 1 then
    begin
      LItem := FGpu.Items.Add;
      LItem.Caption := MHL('Всего', 'Total');
      LItem.SubItems.Add(FormatFloat('0', LMaxLoad) + ' %');
      LItem.SubItems.Add(FormatFloat('0', LMaxCompute) + ' %');
      LItem.SubItems.Add(MHFormatSize(LMemory));
      LItem.SubItems.Add('');
      if LHasPower then
        LItem.SubItems.Add(FormatFloat('0', LPower) + MHL(' Вт', ' W'))
      else
        LItem.SubItems.Add('');
      FGpuKeys := FGpuKeys + ['gpu:' + TOTAL_KEY];
    end;
  finally
    FGpu.Items.EndUpdate;
  end;
  MHRestoreListState(FGpu, LState, GpuKey);
end;

procedure TMHDisksPage.UpdateButtons;
var
  LHit: TMHScanHit;
  LHas: Boolean;
begin
  FBtnScan.Enabled := not FScanRunning;
  FBtnCancel.Enabled := FScanRunning;
  LHas := SelectedHit(LHit);
  FBtnOpen.Enabled := LHas;
  FBtnQuarantine.Enabled := LHas and (FServices.Quarantine <> nil);
  FBtnAllow.Enabled := LHas;
end;

procedure TMHDisksPage.ScanClick(Sender: TObject);
begin
  StartScan(False);
end;

procedure TMHDisksPage.CancelClick(Sender: TObject);
begin
  CancelScan;
end;

procedure TMHDisksPage.CancelScan;
begin
  if FScanRunning then
    FScanCancel := True;
end;

procedure TMHDisksPage.WeeklyClick(Sender: TObject);
var
  LSettings: TMHAppSettings;
  LError: string;
begin
  if FInitializing then
    Exit;
  LSettings := FServices.Settings;
  LSettings.FileScanWeekly := FChkWeekly.Checked;
  FServices.ApplySettings(LSettings);
  FServices.SaveSettings(LError);
end;

procedure TMHDisksPage.QueueProgress(const AProgress: TMHScanProgress);
var
  LCopy: TMHScanProgress;
begin
  LCopy := AProgress;
  TThread.Queue(FScanThread,
    procedure
    begin
      ApplyProgress(LCopy);
    end);
end;

procedure TMHDisksPage.ApplyProgress(const AProgress: TMHScanProgress);
begin
  if not FScanRunning then
    Exit;
  FScanProgress := AProgress;
  FLblScan.Caption := Format(MHL('Проверка… файлов: %d, прочитано: %d, найдено: %d — %s',
    'Scanning… files: %d, read: %d, found: %d — %s'),
    [AProgress.FilesSeen, AProgress.FilesInspected, AProgress.Hits, AProgress.CurrentFolder]);
end;

procedure TMHDisksPage.StartScan(ASilent: Boolean);
var
  LFs: IMHFileScanFs;
  LRoots, LSkip: TArray<string>;
  LWindows: array[0..MAX_PATH] of Char;
  LWinDir: string;
  LSettings: TMHAppSettings;
  LThresholds: TMHRiskThresholds;
  LSelf: TMHDisksPage;
begin
  if FScanRunning then
    Exit;
  FreeAndNil(FScanThread); // предыдущая проверка уже завершилась
  FScanRunning := True;
  FScanSilent := ASilent;
  FScanCancel := False;
  FScanHits := nil;
  FScanProgress := Default(TMHScanProgress);
  FLastProgressTick := 0;
  ShowHits;
  FLblScan.Caption := MHL('Проверка начинается…', 'The scan is starting…');
  UpdateButtons;

  LFs := FScanFs;
  LRoots := FScanRoots;
  if Length(LRoots) = 0 then
    LRoots := MHLocalFixedRoots;
  SetString(LWinDir, LWindows, GetWindowsDirectory(LWindows, MAX_PATH));
  // Не проверяются: карантин (там намеренно лежат найденные файлы) и папка самой программы.
  LSkip := [ExtractFileDir(ParamStr(0))];
  if FServices.Quarantine <> nil then
    LSkip := LSkip + [FServices.Quarantine.StoreDir];
  LSettings := FServices.Settings;
  LThresholds := LSettings.Analyzer.Thresholds;
  LSelf := Self;
  FServices.Logger.Log(llInfo, 'filescan', MHL('Проверка файлов начата: ', 'File scan started: ') +
    string.Join(' ', LRoots));
  FScanThread := TThread.CreateAnonymousThread(
    procedure
    var
      LScanner: TMHFileScanner;
      LHits: TArray<TMHScanHit>;
    begin
      // Низкий приоритет процессора и ввода-вывода: проверка не мешает работе.
      SetThreadPriority(GetCurrentThread, THREAD_MODE_BACKGROUND_BEGIN);
      LHits := nil;
      LScanner := TMHFileScanner.Create(LFs, LWinDir, LSkip, LThresholds,
        function(const APath: string): Boolean
        begin
          Result := MHIsExcluded(LSettings, MHProgramKey(APath, ExtractFileName(APath)), '');
        end);
      try
        try
          LHits := LScanner.Run(LRoots,
            function: Boolean
            begin
              Result := LSelf.FScanCancel;
            end,
            procedure(const AProgress: TMHScanProgress)
            begin
              // Не чаще трёх раз в секунду — очередь главного потока не переполняется.
              if AProgress.Done or (GetTickCount64 - LSelf.FLastProgressTick >= 300) then
              begin
                LSelf.FLastProgressTick := GetTickCount64;
                LSelf.QueueProgress(AProgress);
              end;
            end);
        except
          on E: Exception do
            LSelf.FServices.Logger.Log(llError, 'filescan', MHL('Сбой проверки файлов: ', 'File scan failed: ') +
              E.Message);
        end;
        LSelf.FScanProgress := LScanner.Progress;
      finally
        LScanner.Free;
      end;
      SetThreadPriority(GetCurrentThread, THREAD_MODE_BACKGROUND_END);
      LSelf.FScanHits := LHits;
      TThread.Queue(TThread.Current, LSelf.ScanFinished);
    end);
  FScanThread.FreeOnTerminate := False;
  FScanThread.Start;
end;

procedure TMHDisksPage.ScanFinished;
var
  LSettings: TMHAppSettings;
  LError, LText: string;
  LRecord: TMHActionRecord;
begin
  if not FScanRunning then
    Exit;
  FScanRunning := False;
  Inc(FScanCount);
  if FScanProgress.Cancelled then
    LText := Format(MHL('Проверка остановлена: просмотрено файлов %d, найдено %d.',
      'Scan stopped: %d files checked, %d found.'), [FScanProgress.FilesSeen, Length(FScanHits)])
  else
  begin
    LText := Format(MHL('Проверка завершена: просмотрено файлов %d, прочитано %d, найдено %d.',
      'Scan finished: %d files checked, %d read, %d found.'),
      [FScanProgress.FilesSeen, FScanProgress.FilesInspected, Length(FScanHits)]);
    LSettings := FServices.Settings;
    LSettings.LastFileScanUtc := FServices.Clock.NowUtc;
    FServices.ApplySettings(LSettings);
    FServices.SaveSettings(LError);
  end;
  FLblScan.Caption := LText;
  FServices.Logger.Log(llInfo, 'filescan', LText);
  if FServices.ActionLog <> nil then
  begin
    LRecord.TimestampUtc := FServices.Clock.NowUtc;
    LRecord.Action := 'file-scan';
    LRecord.Target := MHL('все локальные диски', 'all local disks');
    LRecord.Result := LText;
    LRecord.Success := not FScanProgress.Cancelled;
    try
      FServices.ActionLog.LogAction(LRecord);
    except
      on E: Exception do
        FServices.Logger.Log(llWarning, 'actions', E.Message);
    end;
  end;
  ShowHits;
  UpdateButtons;
  if (Length(FScanHits) > 0) and Assigned(FNotice) and FScanSilent then
    FNotice(MHL('MineHunter X: найдены подозрительные файлы', 'MineHunter X: suspicious files found'),
      Format(MHL('Плановая проверка нашла файлов: %d. Подробности — на странице «Диски».',
        'The scheduled scan found %d file(s). Details are on the Disks page.'), [Length(FScanHits)]));
end;

procedure TMHDisksPage.ShowHits;
var
  LHit: TMHScanHit;
  LItem: TListItem;
begin
  FHitsView.Items.BeginUpdate;
  try
    FHitsView.Items.Clear;
    for LHit in FScanHits do
    begin
      LItem := FHitsView.Items.Add;
      LItem.Caption := IntToStr(LHit.Score);
      LItem.SubItems.Add(MHRiskLevelToString(LHit.Level));
      LItem.SubItems.Add(LHit.Title);
      LItem.SubItems.Add(LHit.Path);
      LItem.SubItems.Add(MHFormatSize(LHit.SizeBytes));
    end;
  finally
    FHitsView.Items.EndUpdate;
  end;
  LayoutLists;
  UpdateButtons;
end;

function TMHDisksPage.SelectedHit(out AHit: TMHScanHit): Boolean;
begin
  Result := (FHitsView <> nil) and (FHitsView.Selected <> nil) and
    (FHitsView.Selected.Index <= High(FScanHits));
  if Result then
    AHit := FScanHits[FHitsView.Selected.Index];
end;

procedure TMHDisksPage.HitSelect(Sender: TObject; Item: TListItem; Selected: Boolean);
var
  LHit: TMHScanHit;
  LText: string;
  LEvidence: TMHEvidence;
begin
  UpdateButtons;
  if not SelectedHit(LHit) then
    Exit;
  LText := '';
  for LEvidence in LHit.Evidence do
  begin
    LText := LText + '• ' + LEvidence.Description;
    if LEvidence.Observed <> '' then
      LText := LText + ' (' + LEvidence.Observed + ')';
    LText := LText + sLineBreak;
  end;
  FHitsView.Hint := LText;
  FHitsView.ShowHint := True;
end;

procedure TMHDisksPage.RemoveHit(const APath: string);
var
  I: Integer;
begin
  for I := High(FScanHits) downto 0 do
    if SameText(FScanHits[I].Path, APath) then
      Delete(FScanHits, I, 1);
  ShowHits;
end;

procedure TMHDisksPage.OpenClick(Sender: TObject);
var
  LHit: TMHScanHit;
begin
  if SelectedHit(LHit) then
    FServices.Actions.OpenFileLocation(LHit.Path);
end;

procedure TMHDisksPage.QuarantineClick(Sender: TObject);
begin
  QuarantineSelected;
end;

procedure TMHDisksPage.AllowClick(Sender: TObject);
begin
  AllowSelected;
end;

procedure TMHDisksPage.QuarantineSelected;
var
  LHit: TMHScanHit;
  LResult: TMHActionResult;
begin
  if not SelectedHit(LHit) or (FServices.Quarantine = nil) then
    Exit;
  if not FConfirm(Format(MHL('Переместить файл в карантин?' + sLineBreak + '%s' + sLineBreak + sLineBreak +
    'Файл не удаляется: его можно вернуть в «Настройки → Карантин».',
    'Move the file to quarantine?' + sLineBreak + '%s' + sLineBreak + sLineBreak +
    'The file is not deleted: you can restore it in Settings → Quarantine.'), [LHit.Path])) then
    Exit;
  LResult := FServices.Quarantine.QuarantineFile(LHit.Path, LHit.Title);
  FLblScan.Caption := LResult.Message;
  if LResult.Succeeded then
    RemoveHit(LHit.Path);
end;

procedure TMHDisksPage.AllowSelected;
var
  LHit: TMHScanHit;
  LSettings: TMHAppSettings;
  LExclusion: TMHExclusion;
  LError: string;
begin
  if not SelectedHit(LHit) then
    Exit;
  if not FConfirm(Format(MHL('Считать этот файл своим и больше не сообщать о нём?' + sLineBreak + '%s',
    'Treat this file as yours and stop reporting it?' + sLineBreak + '%s'), [LHit.Path])) then
    Exit;
  LExclusion := Default(TMHExclusion);
  LExclusion.Key := MHProgramKey(LHit.Path, ExtractFileName(LHit.Path));
  LExclusion.Name := ExtractFileName(LHit.Path);
  LExclusion.CreatedUtc := FServices.Clock.NowUtc;
  LExclusion.Comment := MHL('Добавлено из проверки файлов', 'Added from the file scan');
  LSettings := FServices.Settings;
  MHAddExclusion(LSettings, LExclusion);
  FServices.ApplySettings(LSettings);
  FServices.SaveSettings(LError);
  RemoveHit(LHit.Path);
end;

procedure TMHDisksPage.CheckSchedule(const ASnapshot: TMHSnapshot);
begin
  if FScanRunning or not FServices.Settings.FileScanWeekly then
    Exit;
  if (FServices.Settings.LastFileScanUtc > 0) and
     (DaysBetween(ASnapshot.TimestampUtc, FServices.Settings.LastFileScanUtc) < MH_FILE_SCAN_INTERVAL_DAYS) then
    Exit;
  // Только когда пользователь не работает за компьютером.
  if not ASnapshot.Context.Available or (ASnapshot.Context.WorkContext <> wcIdle) then
    Exit;
  StartScan(True);
end;

end.
