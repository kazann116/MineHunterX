unit MineHunter.App.BinaryLabPage;

{
  Страница «BinaryLab»: глубокий разбор файла без его запуска.

  Вкладки:
    - «Обзор» — итог, сведения о файле, аномалии с объяснениями;
    - «Структура» — дерево PE (заголовок, секции, каталоги, импорт, экспорт,
      ресурсы, TLS, подпись, оверлей) и подробности выбранного узла;
    - «Карта» — интерактивная карта энтропии с полосами секций, области
      высокой энтропии и распределение байтов; щелчок по карте открывает
      это место в Hex Viewer;
    - «Hex» — просмотр байтов с подсветкой структур, переход к смещению,
      поиск текста (ASCII, UTF-16) и байтов;
    - «Строки» — строки с фильтром и категориями индикаторов;
    - «Вложения» — найденные внутри файла программы, архивы, сценарии;
    - «Сравнение» — BinaryDiff с другим файлом.

  Анализ, сравнение и поиск выполняются в фоновом потоке: интерфейс не
  замирает, «Отмена» прерывает работу. Результаты из потока передаются через
  TThread.Queue, привязанный к потоку: при закрытии страницы поток
  останавливается, а невыполненные события удаляются (RemoveQueuedEvents).

  После анализа признаки передаются анализатору угроз (BinaryVerdicts):
  находка процесса этого файла получит их при следующем цикле проверки.
}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Graphics,
  MineHunter.Core.Types, MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source,
  MineHunter.App.Bootstrap, MineHunter.App.BinaryLab.Controls;

type
  /// Выбор файла: ASave — диалог сохранения. Тесты подменяют.
  TMHChooseFileFunc = reference to function(const ATitle, AFilter, ADefaultName: string; ASave: Boolean;
    out AFileName: string): Boolean;

  /// Файл папки для выбора: имя, размер, атрибуты (в том числе скрытые и системные).
  TMHFolderFile = record
    Name: string;
    SizeBytes: Int64;
    Attributes: Cardinal;
  end;

  /// Выбор файла из списка файлов папки (включая скрытые). Тесты подменяют.
  TMHChooseInFolderFunc = reference to function(const AFolder: string; const AFiles: TArray<TMHFolderFile>;
    out AFileName: string): Boolean;

  TMHBinaryLabPage = class(TComponent)
  public const
    TabOverview = 0;
    TabStructure = 1;
    TabMap = 2;
    TabHex = 3;
    TabStrings = 4;
    TabEmbedded = 5;
    TabDiff = 6;
  private type
    TJobKind = (jkAnalyze, jkCompare, jkFind);
    TNodeKind = (nkFile, nkHeader, nkSections, nkSection, nkDirectories, nkImports, nkImportDll, nkExports,
      nkResources, nkTls, nkSignature, nkOverlay);
    TNodeInfo = record
      Kind: TNodeKind;
      Index: Integer;
      Offset: Int64;
      Size: Int64;
    end;
    TFindMode = (fmAscii, fmUtf16, fmHex);
  private
    FServices: TMHAppServices;
    FOptions: TMHBinaryLabOptions;
    FChooseFile: TMHChooseFileFunc;
    FChooseInFolder: TMHChooseInFolderFunc;
    // Панель действий и итог.
    FOpenButton, FCompareButton, FCancelButton, FExportButton, FCheckButton: TButton;
    /// Путь проверяемого файла: виден целиком, копируется, в него можно вставить свой путь.
    FPathEdit: TEdit;
    FStageLabel, FVerdictLabel, FVerdictNote: TLabel;
    FLevelShape: TShape;
    FProgress: TProgressBar;
    FTabs: TPageControl;
    // Обзор.
    FInfoList, FAnomalyList: TListView;
    // Структура.
    FTree: TTreeView;
    FDetails: TListView;
    FNodes: TList<TNodeInfo>;
    FDetailOffsets: TList<TMHByteRange>;
    // Карта.
    FMap: TMHEntropyMap;
    FHistogram: TMHByteHistogram;
    FRegionList: TListView;
    // Hex.
    FHex: TMHHexView;
    FGotoEdit, FFindEdit: TEdit;
    FFindMode: TComboBox;
    FIgnoreCase: TCheckBox;
    FFindButton, FGotoButton: TButton;
    FHexStatus: TLabel;
    // Строки.
    FStringsFilter: TEdit;
    FStringsCategory: TComboBox;
    FStringsCount: TLabel;
    FStringsList: TListView;
    FStringRows: TArray<Integer>;
    // Вложения.
    FEmbeddedList: TListView;
    // Сравнение.
    FDiffButton, FDiffExportButton: TButton;
    FDiffSummary: TLabel;
    FDiffStrip: TMHRangeStrip;
    FDiffList: TListView;
    FDiffOffsets: TList<Int64>;
    // Состояние.
    FReport: TMHBinaryReport;
    FHasReport: Boolean;
    FDiff: TMHBinaryDiff;
    FHasDiff: Boolean;
    FSource: IMHBinarySource;
    FWorker: TThread;
    FBusy: Boolean;
    FCancelFlag: Integer;
    FLastError: string;
    FLastFindOffset: Int64;
    /// Страница уничтожается: отложенные события потока ничего не делают
    /// (окно и элементы в это время разрушаются).
    FDestroying: Boolean;
    function NewList(AParent: TWinControl; const ACaptions: array of string; const AWidths: array of Integer): TListView;
    function NewTab(const ACaption: string): TTabSheet;
    function NewPanel(AParent: TWinControl; AAlign: TAlign; AHeight: Integer): TPanel;
    function NewButton(AParent: TWinControl; const ACaption: string; ALeft, ATop, AWidth: Integer;
      AClick: TNotifyEvent): TButton;
    function NewLabel(AParent: TWinControl; ALeft, ATop, AWidth: Integer; const ACaption: string = ''): TLabel;
    procedure BuildToolbar(ASheet: TWinControl);
    procedure BuildOverview;
    procedure BuildStructure;
    procedure BuildMap;
    procedure BuildHex;
    procedure BuildStrings;
    procedure BuildEmbedded;
    procedure BuildDiff;
    procedure UpdateButtons;
    procedure SetStage(const AText: string; APercent: Integer);
    procedure StartWorker(AJob: TJobKind; const APath: string; const APattern: TBytes = nil);
    procedure ReleaseWorker;
    procedure JobFinished(AJob: TJobKind; const AReport: TMHBinaryReport; const ADiff: TMHBinaryDiff;
      AFound: Int64; APatternLength: Integer; const AError: string; ACancelled: Boolean);
    function CancelRequested: Boolean;
    procedure ShowReport;
    procedure FillOverview;
    procedure FillStructure;
    procedure FillMap;
    procedure FillHex;
    procedure FillStrings;
    procedure FillEmbedded;
    procedure ShowDiff;
    procedure ClearViews;
    procedure PassVerdict;
    procedure AddNode(AParent: TTreeNode; const ACaption: string; AKind: TNodeKind; AIndex: Integer;
      AOffset, ASize: Int64; out ANode: TTreeNode);
    procedure SetDetailColumns(const ACaptions: array of string; const AWidths: array of Integer);
    procedure AddDetail(const AValues: array of string; AOffset: Int64 = MH_NO_OFFSET; ASize: Int64 = 0);
    procedure OpenClick(Sender: TObject);
    procedure CheckClick(Sender: TObject);
    procedure PathEditKeyPress(Sender: TObject; var Key: Char);
    procedure CompareClick(Sender: TObject);
    procedure CancelClick(Sender: TObject);
    procedure ExportClick(Sender: TObject);
    procedure ExportDiffClick(Sender: TObject);
    procedure TreeChange(Sender: TObject; Node: TTreeNode);
    procedure DetailsDblClick(Sender: TObject);
    procedure AnomalyDblClick(Sender: TObject);
    procedure RegionDblClick(Sender: TObject);
    procedure EmbeddedDblClick(Sender: TObject);
    procedure StringsDblClick(Sender: TObject);
    procedure DiffDblClick(Sender: TObject);
    procedure MapBlockClick(Sender: TObject; AOffset: Int64);
    procedure StripClick(Sender: TObject; AOffset: Int64);
    procedure GotoClick(Sender: TObject);
    procedure FindClick(Sender: TObject);
    procedure HexSelectionChange(Sender: TObject);
    procedure StringsFilterChange(Sender: TObject);
    procedure StringsData(Sender: TObject; Item: TListItem);
    function DefaultChooseFile(const ATitle, AFilter, ADefaultName: string; ASave: Boolean;
      out AFileName: string): Boolean;
    function DefaultChooseInFolder(const AFolder: string; const AFiles: TArray<TMHFolderFile>;
      out AFileName: string): Boolean;
  public
    constructor Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices); reintroduce;
    destructor Destroy; override;
    /// Начинает анализ файла (в фоне). Идущая работа отменяется.
    procedure OpenFile(const APath: string);
    /// Сравнивает проанализированный файл с APath (в фоне).
    procedure CompareWith(const APath: string);
    /// Ищет шаблон в Hex Viewer после текущей позиции (в фоне, с переходом в начало).
    procedure FindPattern(const APattern: TBytes; AIgnoreCase: Boolean);
    procedure Cancel;
    function Busy: Boolean;
    procedure ExportReport(const AFileName: string);
    procedure ExportDiff(const AFileName: string);
    /// Открывает вкладку «Hex» на смещении AOffset и выделяет ALength байт.
    procedure ShowOffset(AOffset: Int64; ALength: Int64 = 1);
    /// Разбор смещения: «0x1F400», «1F400h», «128000».
    class function ParseOffset(const AText: string; out AOffset: Int64): Boolean; static;
    property Report: TMHBinaryReport read FReport;
    property HasReport: Boolean read FHasReport;
    property Diff: TMHBinaryDiff read FDiff;
    property HasDiff: Boolean read FHasDiff;
    property LastError: string read FLastError;
    property LastFindOffset: Int64 read FLastFindOffset;
    property Options: TMHBinaryLabOptions read FOptions write FOptions;
    property ChooseFile: TMHChooseFileFunc read FChooseFile write FChooseFile;
    property ChooseInFolder: TMHChooseInFolderFunc read FChooseInFolder write FChooseInFolder;
    /// Файлы папки (без вложенных папок), включая скрытые и системные, по имени.
    /// False — папку не прочитать.
    class function ListFolderFiles(const AFolder: string; out AFiles: TArray<TMHFolderFile>): Boolean; static;
    property Tabs: TPageControl read FTabs;
    property HexView: TMHHexView read FHex;
    property EntropyMap: TMHEntropyMap read FMap;
    property Histogram: TMHByteHistogram read FHistogram;
    property InfoList: TListView read FInfoList;
    property AnomalyList: TListView read FAnomalyList;
    property StructureTree: TTreeView read FTree;
    property DetailsList: TListView read FDetails;
    property RegionList: TListView read FRegionList;
    property StringsList: TListView read FStringsList;
    property StringsFilter: TEdit read FStringsFilter;
    property StringsCategory: TComboBox read FStringsCategory;
    property EmbeddedList: TListView read FEmbeddedList;
    property DiffList: TListView read FDiffList;
    property DiffStrip: TMHRangeStrip read FDiffStrip;
    property GotoEdit: TEdit read FGotoEdit;
    property FindEdit: TEdit read FFindEdit;
    property FindMode: TComboBox read FFindMode;
    property VerdictLabel: TLabel read FVerdictLabel;
    property VerdictNote: TLabel read FVerdictNote;
    property StageLabel: TLabel read FStageLabel;
    property OpenButton: TButton read FOpenButton;
    property CheckButton: TButton read FCheckButton;
    property PathEdit: TEdit read FPathEdit;
    /// Путь из поля: без пробелов по краям и кавычек («Копировать как путь» в Проводнике).
    class function CleanPath(const AText: string): string; static;
    property CompareButton: TButton read FCompareButton;
    property CancelButton: TButton read FCancelButton;
    property ExportButton: TButton read FExportButton;
    property GotoButton: TButton read FGotoButton;
    property FindButton: TButton read FFindButton;
    property DiffExportButton: TButton read FDiffExportButton;
    property HexStatus: TLabel read FHexStatus;
  end;

implementation

uses
  System.Math, System.SyncObjs, System.DateUtils, System.StrUtils, Vcl.Dialogs,
  MineHunter.Core.Interfaces, MineHunter.Core.Lang, MineHunter.Collectors.Files,
  MineHunter.BinaryLab.Analyzer, MineHunter.BinaryLab.Pe, MineHunter.BinaryLab.Diff,
  MineHunter.BinaryLab.Report, MineHunter.BinaryLab.Verdicts, System.IOUtils, System.Generics.Defaults,
  System.UITypes, Vcl.Forms, MineHunter.Core.FileScan, MineHunter.Core.FileScan.WinApi;

const
  SECTION_COLORS: array[0..5] of TColor = ($F0B060, $60C060, $4090F0, $C070C0, $40C0C0, $B0A040);
  COLOR_HEADERS = $A0A0A0;
  COLOR_OVERLAY = $5050E0;
  COLOR_CERTIFICATE = $40A040;
  COLOR_EMBEDDED = $0080FF;
  COLOR_ENTRY = $0000E0;
  LEVEL_COLORS: array[TMHRiskLevel] of TColor = ($909090, $D57B3A, $0091C7, $0F48D9, $2000B0);
  REPORT_FILTER = 'HTML (*.html)|*.html|JSON (*.json)|*.json';

function SizeText(ASize: Int64): string;
begin
  if ASize < 0 then
    Exit('?');
  Result := FormatFloat('#,##0', ASize);
end;

function EntropyText(AValue: Double): string;
begin
  if AValue < 0 then
    Result := '—'
  else
    Result := FormatFloat('0.00', AValue);
end;

function SignatureText(const ASignature: TMHBinarySignature): string;
begin
  case ASignature.State of
    sgSignedTrusted:   Result := MHL('подписан: ', 'signed: ') + ASignature.Signer;
    sgSignedUntrusted: Result := MHL('подпись недействительна', 'invalid signature') +
      IfThen(ASignature.Error <> '', ' (' + ASignature.Error + ')', '');
    sgUnsigned:        Result := MHL('без цифровой подписи', 'not digitally signed');
    sgCheckFailed:     Result := MHL('не удалось проверить: ', 'could not verify: ') + ASignature.Error;
  else
    Result := MHL('не проверялась', 'not checked');
  end;
end;

{ TMHBinaryLabPage }

constructor TMHBinaryLabPage.Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices);
begin
  inherited Create(AOwner);
  if AServices = nil then
    raise EArgumentNilException.Create('AServices');
  FServices := AServices;
  FOptions := TMHBinaryLabOptions.Default;
  FNodes := TList<TNodeInfo>.Create;
  FDetailOffsets := TList<TMHByteRange>.Create;
  FDiffOffsets := TList<Int64>.Create;
  FLastFindOffset := -1;
  FChooseFile := DefaultChooseFile;
  FChooseInFolder := DefaultChooseInFolder;
  BuildToolbar(ASheet);
  FTabs := TPageControl.Create(Self);
  FTabs.Parent := ASheet;
  FTabs.Align := alClient;
  BuildOverview;
  BuildStructure;
  BuildMap;
  BuildHex;
  BuildStrings;
  BuildEmbedded;
  BuildDiff;
  FTabs.ActivePageIndex := TabOverview;
  ClearViews;
  UpdateButtons;
end;

destructor TMHBinaryLabPage.Destroy;
begin
  // Поток останавливается до освобождения элементов, которые он обновляет. Во время
  // ожидания (WaitFor) главный поток выполняет его отложенные события — они пропускаются.
  FDestroying := True;
  Cancel;
  ReleaseWorker;
  // Элементы освобождаются позже (inherited) и при этом вызывают обработчики
  // (дерево — OnChange при удалении узлов): данные страницы к тому времени освобождены.
  if FTree <> nil then
    FTree.OnChange := nil;
  if FStringsList <> nil then
    FStringsList.OnData := nil;
  if FHex <> nil then
  begin
    FHex.OnSelectionChange := nil;
    FHex.Source := nil;
  end;
  FSource := nil;
  FDiffOffsets.Free;
  FDetailOffsets.Free;
  FNodes.Free;
  inherited;
end;

function TMHBinaryLabPage.NewPanel(AParent: TWinControl; AAlign: TAlign; AHeight: Integer): TPanel;
begin
  Result := TPanel.Create(Self);
  Result.Parent := AParent;
  Result.Align := AAlign;
  Result.BevelOuter := bvNone;
  Result.ShowCaption := False;
  if AAlign in [alTop, alBottom] then
    Result.Height := AHeight
  else
    Result.Width := AHeight;
end;

function TMHBinaryLabPage.NewButton(AParent: TWinControl; const ACaption: string; ALeft, ATop, AWidth: Integer;
  AClick: TNotifyEvent): TButton;
begin
  Result := TButton.Create(Self);
  Result.Parent := AParent;
  Result.SetBounds(ALeft, ATop, AWidth, 25);
  Result.Caption := ACaption;
  Result.OnClick := AClick;
end;

function TMHBinaryLabPage.NewLabel(AParent: TWinControl; ALeft, ATop, AWidth: Integer; const ACaption: string): TLabel;
begin
  Result := TLabel.Create(Self);
  Result.Parent := AParent;
  Result.AutoSize := False;
  Result.ShowAccelChar := False;
  Result.SetBounds(ALeft, ATop, AWidth, 17);
  Result.Caption := ACaption;
end;

function TMHBinaryLabPage.NewTab(const ACaption: string): TTabSheet;
begin
  Result := TTabSheet.Create(Self);
  Result.PageControl := FTabs;
  Result.Caption := ACaption;
end;

function TMHBinaryLabPage.NewList(AParent: TWinControl; const ACaptions: array of string;
  const AWidths: array of Integer): TListView;
var
  I: Integer;
begin
  Result := TListView.Create(Self);
  Result.Parent := AParent;
  Result.Align := alClient;
  Result.ViewStyle := vsReport;
  Result.ReadOnly := True;
  Result.RowSelect := True;
  Result.HideSelection := False;
  for I := 0 to High(ACaptions) do
    with Result.Columns.Add do
    begin
      Caption := ACaptions[I];
      Width := AWidths[I];
    end;
end;

procedure TMHBinaryLabPage.BuildToolbar(ASheet: TWinControl);
var
  LTop: TPanel;
begin
  LTop := NewPanel(ASheet, alTop, 100);
  FOpenButton := NewButton(LTop, MHL('Открыть файл…', 'Open file…'), 8, 8, 130, OpenClick);
  FCompareButton := NewButton(LTop, MHL('Сравнить с…', 'Compare with…'), 144, 8, 120, CompareClick);
  FCancelButton := NewButton(LTop, MHL('Отмена', 'Cancel'), 270, 8, 90, CancelClick);
  FExportButton := NewButton(LTop, MHL('Экспорт отчёта…', 'Export report…'), 366, 8, 130, ExportClick);
  FProgress := TProgressBar.Create(Self);
  FProgress.Parent := LTop;
  FProgress.SetBounds(508, 12, 180, 17);
  FProgress.Max := 100;
  FStageLabel := NewLabel(LTop, 698, 12, 600);
  FPathEdit := TEdit.Create(Self);
  FPathEdit.Parent := LTop;
  FPathEdit.SetBounds(8, 38, Max(200, LTop.Width - 8 - 130 - 16), 23);
  FPathEdit.Anchors := [akLeft, akTop, akRight];
  FPathEdit.TextHint := MHL('Путь к файлу или папке (можно вставить) — «Проверить». BinaryLab разбирает файл без ' +
    'запуска: структура, энтропия, строки, вложения, аномалии.', 'File or folder path (you can paste one) — “Check”. ' +
    'BinaryLab analyses a file without running it: structure, entropy, strings, embedded objects, anomalies.');
  FPathEdit.OnKeyPress := PathEditKeyPress;
  FCheckButton := NewButton(LTop, MHL('Проверить', 'Check'), FPathEdit.Left + FPathEdit.Width + 8, 36, 130,
    CheckClick);
  FCheckButton.Anchors := [akTop, akRight];
  FCheckButton.Hint := MHL('Проверить файл из поля (пустое поле — выбрать файл; папка — выбрать её файл, в том числе ' +
    'скрытый; тот же файл — проверить заново).', 'Check the file in the field (empty field — choose a file; a folder — ' +
    'choose one of its files, hidden ones included; the same file — check it again).');
  FCheckButton.ShowHint := True;
  FLevelShape := TShape.Create(Self);
  FLevelShape.Parent := LTop;
  FLevelShape.SetBounds(8, 68, 6, 22);
  FLevelShape.Pen.Style := psClear;
  FVerdictLabel := NewLabel(LTop, 20, 66, 1200);
  FVerdictLabel.Font.Style := [fsBold];
  FVerdictNote := NewLabel(LTop, 20, 82, 1200);
  FVerdictNote.Font.Color := clGrayText;
end;

procedure TMHBinaryLabPage.BuildOverview;
var
  LSheet: TTabSheet;
  LTop: TPanel;
  LSplitter: TSplitter;
begin
  LSheet := NewTab(MHL('Обзор', 'Overview'));
  LTop := NewPanel(LSheet, alTop, 230);
  FInfoList := NewList(LTop, [MHL('Свойство', 'Property'), MHL('Значение', 'Value')], [200, 900]);
  LSplitter := TSplitter.Create(Self);
  LSplitter.Parent := LSheet;
  LSplitter.Align := alTop;
  LSplitter.Top := LTop.Top + LTop.Height;
  FAnomalyList := NewList(LSheet, [MHL('Серьёзность', 'Severity'), MHL('Вес', 'Weight'), MHL('Признак', 'Sign'),
    MHL('Объяснение', 'Explanation')], [100, 50, 280, 800]);
  FAnomalyList.OnDblClick := AnomalyDblClick;
end;

procedure TMHBinaryLabPage.BuildStructure;
var
  LSheet: TTabSheet;
  LSplitter: TSplitter;
begin
  LSheet := NewTab(MHL('Структура', 'Structure'));
  FTree := TTreeView.Create(Self);
  FTree.Parent := LSheet;
  FTree.Align := alLeft;
  FTree.Width := 300;
  FTree.ReadOnly := True;
  FTree.HideSelection := False;
  FTree.OnChange := TreeChange;
  LSplitter := TSplitter.Create(Self);
  LSplitter.Parent := LSheet;
  LSplitter.Align := alLeft;
  LSplitter.Left := FTree.Width + 1;
  FDetails := NewList(LSheet, [MHL('Поле', 'Field'), MHL('Значение', 'Value')], [220, 700]);
  FDetails.OnDblClick := DetailsDblClick;
end;

procedure TMHBinaryLabPage.BuildMap;
var
  LSheet: TTabSheet;
  LRight, LBottom: TPanel;
  LCaption: TLabel;
begin
  LSheet := NewTab(MHL('Карта', 'Map'));
  LRight := NewPanel(LSheet, alRight, 380);
  LCaption := NewLabel(LRight, 4, 4, 370, MHL('Области высокой энтропии (двойной щелчок — в Hex):',
    'High-entropy regions (double-click — to Hex):'));
  LCaption.Align := alTop;
  FRegionList := NewList(LRight, [MHL('Смещение', 'Offset'), MHL('Размер', 'Size'), MHL('Энтропия', 'Entropy'),
    MHL('Где', 'Where')], [90, 80, 120, 80]);
  FRegionList.OnDblClick := RegionDblClick;
  LBottom := NewPanel(LSheet, alBottom, 150);
  FHistogram := TMHByteHistogram.Create(Self);
  FHistogram.Parent := LBottom;
  FHistogram.Align := alClient;
  FHistogram.ShowHint := True;
  FMap := TMHEntropyMap.Create(Self);
  FMap.Parent := LSheet;
  FMap.Align := alClient;
  FMap.ShowHint := True;
  FMap.OnBlockClick := MapBlockClick;
end;

procedure TMHBinaryLabPage.BuildHex;
var
  LSheet: TTabSheet;
  LTop: TPanel;
begin
  LSheet := NewTab('Hex');
  LTop := NewPanel(LSheet, alTop, 40);
  NewLabel(LTop, 8, 11, 70, MHL('Смещение:', 'Offset:'));
  FGotoEdit := TEdit.Create(Self);
  FGotoEdit.Parent := LTop;
  FGotoEdit.SetBounds(80, 8, 120, 23);
  FGotoEdit.TextHint := '0x1F400';
  FGotoButton := NewButton(LTop, MHL('Перейти', 'Go to'), 206, 7, 80, GotoClick);
  NewLabel(LTop, 304, 11, 50, MHL('Найти:', 'Find:'));
  FFindEdit := TEdit.Create(Self);
  FFindEdit.Parent := LTop;
  FFindEdit.SetBounds(356, 8, 220, 23);
  FFindEdit.TextHint := MHL('текст или байты 4D 5A 90', 'text or bytes 4D 5A 90');
  FFindMode := TComboBox.Create(Self);
  FFindMode.Parent := LTop;
  FFindMode.Style := csDropDownList;
  FFindMode.SetBounds(582, 8, 140, 23);
  FFindMode.Items.Add(MHL('Текст (ASCII)', 'Text (ASCII)'));
  FFindMode.Items.Add(MHL('Текст (UTF-16)', 'Text (UTF-16)'));
  FFindMode.Items.Add(MHL('Байты (hex)', 'Bytes (hex)'));
  FFindMode.ItemIndex := 0;
  FIgnoreCase := TCheckBox.Create(Self);
  FIgnoreCase.Parent := LTop;
  FIgnoreCase.SetBounds(730, 10, 150, 19);
  FIgnoreCase.Caption := MHL('без учёта регистра', 'ignore case');
  FIgnoreCase.Checked := True;
  FFindButton := NewButton(LTop, MHL('Найти далее', 'Find next'), 884, 7, 100, FindClick);
  FHexStatus := NewLabel(LSheet, 0, 0, 800);
  FHexStatus.Align := alBottom;
  FHex := TMHHexView.Create(Self);
  FHex.Parent := LSheet;
  FHex.Align := alClient;
  FHex.ShowHint := True;
  FHex.OnSelectionChange := HexSelectionChange;
end;

procedure TMHBinaryLabPage.BuildStrings;
var
  LSheet: TTabSheet;
  LTop: TPanel;
  LCategory: TMHStringCategory;
begin
  LSheet := NewTab(MHL('Строки', 'Strings'));
  LTop := NewPanel(LSheet, alTop, 40);
  NewLabel(LTop, 8, 11, 60, MHL('Фильтр:', 'Filter:'));
  FStringsFilter := TEdit.Create(Self);
  FStringsFilter.Parent := LTop;
  FStringsFilter.SetBounds(70, 8, 260, 23);
  FStringsFilter.TextHint := MHL('часть строки', 'part of a string');
  FStringsFilter.OnChange := StringsFilterChange;
  FStringsCategory := TComboBox.Create(Self);
  FStringsCategory.Parent := LTop;
  FStringsCategory.Style := csDropDownList;
  FStringsCategory.SetBounds(340, 8, 220, 23);
  FStringsCategory.Items.Add(MHL('Все строки', 'All strings'));
  FStringsCategory.Items.Add(MHL('Только индикаторы', 'Indicators only'));
  for LCategory := Succ(Low(TMHStringCategory)) to High(TMHStringCategory) do
    FStringsCategory.Items.Add(MHStringCategoryTitle(LCategory));
  FStringsCategory.ItemIndex := 1;
  FStringsCategory.OnChange := StringsFilterChange;
  FStringsCount := NewLabel(LTop, 572, 11, 600);
  FStringsList := NewList(LSheet, [MHL('Смещение', 'Offset'), MHL('Кодировка', 'Encoding'),
    MHL('Категория', 'Category'), MHL('Строка', 'String')], [100, 80, 150, 900]);
  FStringsList.OwnerData := True;
  FStringsList.OnData := StringsData;
  FStringsList.OnDblClick := StringsDblClick;
end;

procedure TMHBinaryLabPage.BuildEmbedded;
var
  LSheet: TTabSheet;
begin
  LSheet := NewTab(MHL('Вложения', 'Embedded'));
  FEmbeddedList := NewList(LSheet, [MHL('Смещение', 'Offset'), MHL('Размер', 'Size'), MHL('Что', 'What'),
    MHL('Где', 'Where')], [110, 110, 520, 200]);
  FEmbeddedList.OnDblClick := EmbeddedDblClick;
end;

procedure TMHBinaryLabPage.BuildDiff;
var
  LSheet: TTabSheet;
  LTop: TPanel;
begin
  LSheet := NewTab(MHL('Сравнение', 'Compare'));
  LTop := NewPanel(LSheet, alTop, 72);
  FDiffButton := NewButton(LTop, MHL('Сравнить с файлом…', 'Compare with file…'), 8, 8, 160, CompareClick);
  FDiffExportButton := NewButton(LTop, MHL('Экспорт сравнения…', 'Export comparison…'), 174, 8, 160,
    ExportDiffClick);
  FDiffSummary := NewLabel(LTop, 344, 12, 900);
  FDiffStrip := TMHRangeStrip.Create(Self);
  FDiffStrip.Parent := LTop;
  FDiffStrip.SetBounds(8, 40, 900, 26);
  FDiffStrip.Anchors := [akLeft, akTop, akRight];
  FDiffStrip.ShowHint := True;
  FDiffStrip.OnOffsetClick := StripClick;
  FDiffList := NewList(LSheet, [MHL('Область', 'Area'), MHL('Изменение', 'Change'), MHL('Элемент', 'Item'),
    'A', 'B'], [100, 100, 300, 260, 260]);
  FDiffList.OnDblClick := DiffDblClick;
end;

function TMHBinaryLabPage.Busy: Boolean;
begin
  Result := FBusy;
end;

procedure TMHBinaryLabPage.UpdateButtons;
begin
  FOpenButton.Enabled := not FBusy;
  FCheckButton.Enabled := not FBusy;
  FCompareButton.Enabled := not FBusy and FHasReport;
  FDiffButton.Enabled := FCompareButton.Enabled;
  FCancelButton.Enabled := FBusy;
  FExportButton.Enabled := not FBusy and FHasReport;
  FDiffExportButton.Enabled := not FBusy and FHasDiff;
  FFindButton.Enabled := not FBusy and (FSource <> nil);
end;

procedure TMHBinaryLabPage.SetStage(const AText: string; APercent: Integer);
begin
  if FDestroying then
    Exit;
  FStageLabel.Caption := AText;
  FProgress.Position := EnsureRange(APercent, 0, 100);
end;

function TMHBinaryLabPage.CancelRequested: Boolean;
begin
  Result := TInterlocked.CompareExchange(FCancelFlag, 0, 0) <> 0;
end;

procedure TMHBinaryLabPage.Cancel;
begin
  TInterlocked.Exchange(FCancelFlag, 1);
end;

procedure TMHBinaryLabPage.ReleaseWorker;
begin
  if FWorker = nil then
    Exit;
  // Поток не вызывает Synchronize, поэтому ожидание из главного потока не блокирует его.
  FWorker.WaitFor;
  TThread.RemoveQueuedEvents(FWorker);
  FreeAndNil(FWorker);
end;

procedure TMHBinaryLabPage.StartWorker(AJob: TJobKind; const APath: string; const APattern: TBytes);
var
  LOptions: TMHBinaryLabOptions;
  LApi: IMHFileApi;
  LThresholds: TMHRiskThresholds;
  LNow: TDateTime;
  LLeft: TMHBinaryReport;
  LSource: IMHBinarySource;
  LFrom: Int64;
  LIgnoreCase: Boolean;
  LCancel: TMHCancelCheck;
begin
  Cancel;
  ReleaseWorker;
  TInterlocked.Exchange(FCancelFlag, 0);
  FLastError := '';
  FBusy := True;
  UpdateButtons;
  LOptions := FOptions;
  LApi := FServices.FileApi;
  LThresholds := FServices.Settings.Analyzer.Thresholds;
  LNow := TTimeZone.Local.ToUniversalTime(Now);
  LLeft := FReport;
  LSource := FSource;
  LIgnoreCase := FIgnoreCase.Checked;
  LFrom := 0;
  if AJob = jkFind then
  begin
    LFrom := FHex.CaretOffset + 1;
    if FHex.SelLength > 0 then
      LFrom := FHex.SelStart + 1;
    SetStage(MHL('Поиск…', 'Searching…'), 0);
  end
  else
    SetStage(MHL('Подготовка…', 'Preparing…'), 0);
  LCancel :=
    function: Boolean
    begin
      Result := CancelRequested;
    end;
  FWorker := TThread.CreateAnonymousThread(
    procedure
    var
      LReport: TMHBinaryReport;
      LDiff: TMHBinaryDiff;
      LError: string;
      LCancelled: Boolean;
      LFound: Int64;
      LThread: TThread;
      LLastPercent: Integer;
    begin
      LThread := TThread.CurrentThread;
      LReport := Default(TMHBinaryReport);
      LDiff := Default(TMHBinaryDiff);
      LError := '';
      LCancelled := False;
      LFound := -1;
      LLastPercent := -1;
      try
        case AJob of
          jkFind:
            begin
              LFound := MHFindBytes(LSource, APattern, LFrom, LIgnoreCase, LCancel);
              // С начала файла до места, где начали.
              if (LFound < 0) and (LFrom > 0) then
                LFound := MHFindBytes(LSource, APattern, 0, LIgnoreCase, LCancel, LFrom + Length(APattern));
            end;
        else
          LReport := MHAnalyzeBinaryFile(APath, LOptions, LApi, LNow, LThresholds, LCancel,
            procedure(const AStage: string; APercent: Integer)
            var
              LStage: string;
              LPercent: Integer;
            begin
              if APercent = LLastPercent then
                Exit;
              LLastPercent := APercent;
              LStage := AStage;
              LPercent := APercent;
              if AJob = jkCompare then
                LPercent := APercent * 8 div 10;
              TThread.Queue(LThread,
                procedure
                begin
                  SetStage(LStage, LPercent);
                end);
            end);
          if AJob = jkCompare then
          begin
            TThread.Queue(LThread,
              procedure
              begin
                SetStage(MHL('Сравнение файлов…', 'Comparing files…'), 85);
              end);
            LDiff := MHCompareBinaries(LLeft, LReport, TMHFileSource.Create(LLeft.Path), TMHFileSource.Create(APath),
              LOptions, LCancel);
          end;
        end;
      except
        on E: EMHBinaryLabCancelled do
          LCancelled := True;
        on E: Exception do
          LError := E.Message;
      end;
      TThread.Queue(LThread,
        procedure
        begin
          JobFinished(AJob, LReport, LDiff, LFound, Length(APattern), LError, LCancelled);
        end);
    end);
  FWorker.FreeOnTerminate := False;
  FWorker.Start;
end;

procedure TMHBinaryLabPage.JobFinished(AJob: TJobKind; const AReport: TMHBinaryReport; const ADiff: TMHBinaryDiff;
  AFound: Int64; APatternLength: Integer; const AError: string; ACancelled: Boolean);
begin
  FBusy := False;
  if FDestroying then
    Exit;
  try
    if ACancelled then
    begin
      SetStage(MHL('Отменено.', 'Cancelled.'), 0);
      Exit;
    end;
    if AError <> '' then
    begin
      FLastError := AError;
      SetStage(MHL('Ошибка: ', 'Error: ') + AError, 0);
      Exit;
    end;
    case AJob of
      jkAnalyze:
        begin
          FReport := AReport;
          FHasReport := True;
          FHasDiff := False;
          ShowReport;
          SetStage(Format(MHL('Готово за %s с.', 'Done in %s s.'), [FormatFloat('0.0', AReport.DurationMs / 1000)]), 100);
        end;
      jkCompare:
        begin
          FDiff := ADiff;
          FHasDiff := True;
          ShowDiff;
          FTabs.ActivePageIndex := TabDiff;
          SetStage(MHL('Сравнение готово.', 'Comparison done.'), 100);
        end;
      jkFind:
        begin
          FLastFindOffset := AFound;
          if AFound >= 0 then
          begin
            FHex.GotoOffset(AFound, Max(1, APatternLength));
            SetStage(Format(MHL('Найдено по смещению %s.', 'Found at offset %s.'), [MHHexOffset(AFound)]), 100);
          end
          else
            SetStage(MHL('Не найдено.', 'Not found.'), 100);
        end;
    end;
  finally
    UpdateButtons;
  end;
end;

procedure TMHBinaryLabPage.OpenFile(const APath: string);
begin
  if Trim(APath) = '' then
    Exit;
  FPathEdit.Text := APath;
  StartWorker(jkAnalyze, APath);
end;

procedure TMHBinaryLabPage.CompareWith(const APath: string);
begin
  if not FHasReport or (Trim(APath) = '') then
    Exit;
  StartWorker(jkCompare, APath);
end;

procedure TMHBinaryLabPage.FindPattern(const APattern: TBytes; AIgnoreCase: Boolean);
begin
  if (FSource = nil) or (Length(APattern) = 0) then
    Exit;
  FIgnoreCase.Checked := AIgnoreCase;
  StartWorker(jkFind, '', APattern);
end;

procedure TMHBinaryLabPage.ClearViews;
begin
  FInfoList.Items.Clear;
  FAnomalyList.Items.Clear;
  FTree.Items.Clear;
  FNodes.Clear;
  FDetails.Items.Clear;
  FDetailOffsets.Clear;
  FRegionList.Items.Clear;
  FEmbeddedList.Items.Clear;
  FDiffList.Items.Clear;
  FDiffOffsets.Clear;
  FStringRows := nil;
  FStringsList.Items.Count := 0;
  FMap.SetData(nil, 0);
  FMap.SetBands(nil);
  FHistogram.SetHistogram([]);
  FDiffStrip.SetRanges(nil, 0, clRed);
  FDiffSummary.Caption := MHL('Откройте файл, затем выберите второй файл для сравнения.',
    'Open a file, then choose a second file to compare.');
  FVerdictLabel.Caption := '';
  FVerdictNote.Caption := '';
  FLevelShape.Visible := False;
end;

procedure TMHBinaryLabPage.ShowReport;
begin
  ClearViews;
  FHex.Source := nil;
  FSource := nil;
  try
    // Отдельный дескриптор только на чтение для просмотра байтов.
    FSource := TMHFileSource.Create(FReport.Path);
  except
    on E: Exception do
      FHexStatus.Caption := E.Message;
  end;
  FPathEdit.Text := FReport.Path;
  FLevelShape.Brush.Color := LEVEL_COLORS[FReport.Level];
  FLevelShape.Visible := True;
  FVerdictLabel.Caption := FReport.Verdict;
  FillOverview;
  FillStructure;
  FillMap;
  FillHex;
  FillStrings;
  FillEmbedded;
  PassVerdict;
  FTabs.ActivePageIndex := TabOverview;
end;

procedure TMHBinaryLabPage.PassVerdict;
var
  LVerdict: TMHBinaryVerdict;
begin
  if (FServices.BinaryVerdicts = nil) or (FReport.Path = '') then
    Exit;
  LVerdict := MHVerdictFromReport(FReport);
  FServices.BinaryVerdicts.Put(LVerdict);
  if Length(LVerdict.Evidence) > 0 then
    FVerdictNote.Caption := MHL('Признаки переданы анализатору угроз: если эта программа запущена, они появятся ' +
      'в её находке при следующей проверке.', 'The signs were passed to the threat analyser: if this program is ' +
      'running, they will appear in its finding at the next check.')
  else
    FVerdictNote.Caption := MHL('Признаков для анализатора угроз нет.', 'No signs for the threat analyser.');
end;

procedure TMHBinaryLabPage.FillOverview;

  procedure Info(const AName, AValue: string);
  begin
    with FInfoList.Items.Add do
    begin
      Caption := AName;
      SubItems.Add(AValue);
    end;
  end;

var
  LAnomaly: TMHBinaryAnomaly;
  LText: string;
  LPe: TMHPeInfo;
begin
  FInfoList.Items.BeginUpdate;
  try
    Info(MHL('Файл', 'File'), FReport.Path);
    Info(MHL('Размер', 'Size'), SizeText(FReport.Size) + MHL(' байт', ' bytes'));
    Info('SHA-256', FReport.Sha256);
    Info(MHL('Вид по содержимому', 'Type by content'), FReport.FileType.Description);
    if FReport.FileType.ExtensionMismatch then
      Info(MHL('Расширение', 'Extension'), FReport.FileType.Extension +
        MHL(' — не соответствует содержимому', ' — does not match the content'));
    Info(MHL('Цифровая подпись', 'Digital signature'), SignatureText(FReport.Signature));
    Info(MHL('Энтропия файла', 'File entropy'), EntropyText(FReport.Entropy.Overall) + MHL(' из 8', ' of 8'));
    LPe := FReport.Pe;
    if LPe.Valid then
    begin
      Info(MHL('Формат', 'Format'), IfThen(LPe.Is64, 'PE32+', 'PE32') + ', ' + LPe.MachineName + ', ' +
        MHPeKindTitle(LPe.Kind) + IfThen(LPe.IsDotNet, ', .NET', ''));
      Info(MHL('Секций / импорт / экспорт / ресурсов', 'Sections / imports / exports / resources'),
        Format('%d / %d / %d / %d', [Length(LPe.Sections), LPe.ImportedFunctionCount, Length(LPe.ExportedFunctions),
          Length(LPe.Resources)]));
      Info(MHL('Точка входа', 'Entry point'), MHHexOffset(LPe.EntryPointRva) + ' ' + LPe.EntryPointSection);
    end;
    Info(MHL('Строк / вложений', 'Strings / embedded'), Format('%d / %d', [FReport.Strings.TotalFound,
      Length(FReport.Embedded)]));
    Info(MHL('Анализ', 'Analysis'), Format(MHL('%s мс, правила %s', '%s ms, rules %s'),
      [IntToStr(FReport.DurationMs), FReport.RulesVersion]));
    for LText in FReport.Notes do
      Info(MHL('Замечание', 'Note'), LText);
    for LText in FReport.Errors do
      Info(MHL('Ошибка', 'Error'), LText);
  finally
    FInfoList.Items.EndUpdate;
  end;
  FAnomalyList.Items.BeginUpdate;
  try
    for LAnomaly in FReport.Anomalies do
      with FAnomalyList.Items.Add do
      begin
        Caption := MHAnomalySeverityTitle(LAnomaly.Severity);
        SubItems.Add(IntToStr(LAnomaly.Weight));
        SubItems.Add(LAnomaly.Title);
        SubItems.Add(LAnomaly.Details);
      end;
  finally
    FAnomalyList.Items.EndUpdate;
  end;
end;

procedure TMHBinaryLabPage.AddNode(AParent: TTreeNode; const ACaption: string; AKind: TNodeKind; AIndex: Integer;
  AOffset, ASize: Int64; out ANode: TTreeNode);
var
  LInfo: TNodeInfo;
begin
  LInfo.Kind := AKind;
  LInfo.Index := AIndex;
  LInfo.Offset := AOffset;
  LInfo.Size := ASize;
  FNodes.Add(LInfo);
  ANode := FTree.Items.AddChild(AParent, ACaption);
  // Номер записи в FNodes хранится в Data (не указатель на объект).
  ANode.Data := Pointer(NativeInt(FNodes.Count - 1));
end;

procedure TMHBinaryLabPage.FillStructure;
var
  LRoot, LNode, LChild: TTreeNode;
  LPe: TMHPeInfo;
  I: Integer;
begin
  FTree.Items.BeginUpdate;
  try
    AddNode(nil, MHL('Файл', 'File'), nkFile, -1, 0, FReport.Size, LRoot);
    LPe := FReport.Pe;
    if LPe.Valid then
    begin
      AddNode(LRoot, MHL('Заголовок PE', 'PE header'), nkHeader, -1, 0, LPe.SizeOfHeaders, LNode);
      AddNode(LRoot, Format(MHL('Секции (%d)', 'Sections (%d)'), [Length(LPe.Sections)]), nkSections, -1,
        MH_NO_OFFSET, 0, LNode);
      for I := 0 to High(LPe.Sections) do
        AddNode(LNode, LPe.Sections[I].Name, nkSection, I, IfThen(LPe.Sections[I].RawSize > 0,
          Int64(LPe.Sections[I].RawOffset), MH_NO_OFFSET), LPe.Sections[I].RawSize, LChild);
      AddNode(LRoot, MHL('Каталоги данных', 'Data directories'), nkDirectories, -1, MH_NO_OFFSET, 0, LNode);
      AddNode(LRoot, Format(MHL('Импорт (%d функций)', 'Imports (%d functions)'), [LPe.ImportedFunctionCount]),
        nkImports, -1, MH_NO_OFFSET, 0, LNode);
      for I := 0 to High(LPe.Imports) do
        AddNode(LNode, LPe.Imports[I].Dll, nkImportDll, I, MH_NO_OFFSET, 0, LChild);
      AddNode(LRoot, Format(MHL('Экспорт (%d)', 'Exports (%d)'), [Length(LPe.ExportedFunctions)]), nkExports, -1,
        MH_NO_OFFSET, 0, LNode);
      AddNode(LRoot, Format(MHL('Ресурсы (%d)', 'Resources (%d)'), [Length(LPe.Resources)]), nkResources, -1,
        MH_NO_OFFSET, 0, LNode);
      AddNode(LRoot, Format(MHL('TLS (%d функций)', 'TLS (%d callbacks)'), [LPe.TlsCallbackCount]), nkTls, -1,
        MH_NO_OFFSET, 0, LNode);
      AddNode(LRoot, MHL('Цифровая подпись', 'Digital signature'), nkSignature, -1, LPe.CertificateOffset,
        LPe.CertificateSize, LNode);
      AddNode(LRoot, Format(MHL('Оверлей (%s байт)', 'Overlay (%s bytes)'), [SizeText(LPe.OverlaySize)]), nkOverlay,
        -1, LPe.OverlayOffset, LPe.OverlaySize, LNode);
    end;
    LRoot.Expand(False);
  finally
    FTree.Items.EndUpdate;
  end;
  FTree.Selected := LRoot;
end;

procedure TMHBinaryLabPage.SetDetailColumns(const ACaptions: array of string; const AWidths: array of Integer);
var
  I: Integer;
begin
  FDetails.Items.BeginUpdate;
  try
    FDetails.Items.Clear;
    FDetails.Columns.Clear;
    for I := 0 to High(ACaptions) do
      with FDetails.Columns.Add do
      begin
        Caption := ACaptions[I];
        Width := AWidths[I];
      end;
  finally
    FDetails.Items.EndUpdate;
  end;
  FDetailOffsets.Clear;
end;

procedure TMHBinaryLabPage.AddDetail(const AValues: array of string; AOffset, ASize: Int64);
var
  LItem: TListItem;
  LRange: TMHByteRange;
  I: Integer;
begin
  LItem := FDetails.Items.Add;
  LItem.Caption := AValues[0];
  for I := 1 to High(AValues) do
    LItem.SubItems.Add(AValues[I]);
  LRange.Offset := AOffset;
  LRange.Size := ASize;
  FDetailOffsets.Add(LRange);
end;

procedure TMHBinaryLabPage.TreeChange(Sender: TObject; Node: TTreeNode);
var
  LInfo: TNodeInfo;
  LPe: TMHPeInfo;
  LSection: TMHPeSection;
  LResource: TMHPeResource;
  LExport: TMHPeExport;
  LDir: TMHPeDataDirectory;
  LFunction: string;
  I: Integer;

  procedure Field(const AName, AValue: string; AOffset: Int64 = MH_NO_OFFSET; ASize: Int64 = 0);
  begin
    AddDetail([AName, AValue], AOffset, ASize);
  end;

  procedure SectionRow(const ASection: TMHPeSection);
  begin
    AddDetail([ASection.Name, MHHexOffset(ASection.VirtualAddress), SizeText(ASection.VirtualSize),
      MHHexOffset(ASection.RawOffset), SizeText(ASection.RawSize), ASection.AccessText, EntropyText(ASection.Entropy),
      ASection.Sha256], IfThen(ASection.RawSize > 0, Int64(ASection.RawOffset), MH_NO_OFFSET), ASection.RawSize);
  end;

begin
  if (Node = nil) or not FHasReport or (csDestroying in ComponentState) or
     (Integer(NativeInt(Node.Data)) >= FNodes.Count) then
    Exit;
  LInfo := FNodes[Integer(NativeInt(Node.Data))];
  LPe := FReport.Pe;
  FDetails.Items.BeginUpdate;
  try
    case LInfo.Kind of
      nkSections, nkSection:
        begin
          SetDetailColumns([MHL('Имя', 'Name'), 'RVA', MHL('В памяти', 'Virtual'), MHL('Смещение', 'Offset'),
            MHL('В файле', 'Raw'), MHL('Доступ', 'Access'), MHL('Энтропия', 'Entropy'), 'SHA-256'],
            [90, 90, 90, 90, 90, 60, 70, 420]);
          if LInfo.Kind = nkSection then
            SectionRow(LPe.Sections[LInfo.Index])
          else
            for LSection in LPe.Sections do
              SectionRow(LSection);
        end;
      nkImports:
        begin
          SetDetailColumns([MHL('Библиотека', 'Library'), MHL('Функций', 'Functions'), MHL('Загрузка', 'Loading')],
            [300, 90, 150]);
          for I := 0 to High(LPe.Imports) do
            AddDetail([LPe.Imports[I].Dll, IntToStr(Length(LPe.Imports[I].Functions)),
              IfThen(LPe.Imports[I].Delayed, MHL('отложенная', 'delayed'), MHL('при запуске', 'at start'))]);
        end;
      nkImportDll:
        begin
          SetDetailColumns([MHL('Функция', 'Function')], [500]);
          for LFunction in LPe.Imports[LInfo.Index].Functions do
            AddDetail([LFunction]);
        end;
      nkExports:
        begin
          SetDetailColumns(['#', MHL('Имя', 'Name'), 'RVA', MHL('Переадресация', 'Forwarder')], [70, 320, 100, 300]);
          for LExport in LPe.ExportedFunctions do
            AddDetail([IntToStr(LExport.Ordinal), LExport.Name, MHHexOffset(LExport.Rva), LExport.Forwarder],
              MHPeRvaToOffset(LPe, LExport.Rva), 1);
        end;
      nkResources:
        begin
          SetDetailColumns([MHL('Тип', 'Type'), MHL('Имя', 'Name'), MHL('Язык', 'Language'), MHL('Смещение', 'Offset'),
            MHL('Размер', 'Size'), MHL('Энтропия', 'Entropy'), MHL('Содержимое', 'Content')],
            [110, 120, 60, 100, 90, 70, 260]);
          for LResource in LPe.Resources do
            AddDetail([LResource.TypeName, LResource.Name, IntToStr(LResource.Language), MHHexOffset(LResource.Offset),
              SizeText(LResource.Size), EntropyText(LResource.Entropy), IfThen(LResource.ContentKind <> bkUnknown,
              MHBinaryKindTitle(LResource.ContentKind), '')], LResource.Offset, LResource.Size);
        end;
      nkDirectories:
        begin
          SetDetailColumns([MHL('Каталог', 'Directory'), 'RVA', MHL('Размер', 'Size')], [160, 110, 110]);
          for LDir in LPe.DataDirectories do
            AddDetail([LDir.Name, MHHexOffset(LDir.Rva), SizeText(LDir.Size)]);
        end;
    else
      SetDetailColumns([MHL('Поле', 'Field'), MHL('Значение', 'Value')], [240, 700]);
      case LInfo.Kind of
        nkFile:
          begin
            Field(MHL('Путь', 'Path'), FReport.Path);
            Field(MHL('Размер', 'Size'), SizeText(FReport.Size));
            Field('SHA-256', FReport.Sha256);
            Field(MHL('Вид', 'Type'), FReport.FileType.Description);
            Field(MHL('Изменён (UTC)', 'Modified (UTC)'), IfThen(FReport.LastWriteUtc > 0,
              FormatDateTime('yyyy-mm-dd hh:nn:ss', FReport.LastWriteUtc), ''));
          end;
        nkHeader:
          begin
            Field('e_lfanew', MHHexOffset(LPe.HeaderOffset), LPe.HeaderOffset, 4);
            Field(MHL('Архитектура', 'Machine'), LPe.MachineName);
            Field(MHL('Формат', 'Format'), IfThen(LPe.Is64, 'PE32+', 'PE32'));
            Field(MHL('Вид', 'Kind'), MHPeKindTitle(LPe.Kind));
            Field(MHL('Подсистема', 'Subsystem'), LPe.SubsystemName);
            Field(MHL('Время сборки (UTC)', 'Build time (UTC)'),
              FormatDateTime('yyyy-mm-dd hh:nn:ss', UnixToDateTime(LPe.TimeDateStamp, True)));
            Field(MHL('Компоновщик', 'Linker'), LPe.LinkerVersion);
            Field(MHL('Версия ОС', 'OS version'), LPe.OsVersion);
            Field(MHL('Базовый адрес', 'Image base'), '0x' + IntToHex(LPe.ImageBase, 8));
            Field(MHL('Точка входа', 'Entry point'), MHHexOffset(LPe.EntryPointRva) + ' ' + LPe.EntryPointSection,
              LPe.EntryPointOffset, 16);
            Field(MHL('Размер образа', 'Image size'), SizeText(LPe.SizeOfImage));
            Field(MHL('Размер заголовков', 'Headers size'), SizeText(LPe.SizeOfHeaders), 0, LPe.SizeOfHeaders);
            Field(MHL('Выравнивание в файле / памяти', 'File / section alignment'),
              Format('0x%x / 0x%x', [LPe.FileAlignment, LPe.SectionAlignment]));
            Field(MHL('Характеристики', 'Characteristics'), '0x' + IntToHex(LPe.Characteristics, 4));
            Field('DllCharacteristics', '0x' + IntToHex(LPe.DllCharacteristics, 4));
            Field(MHL('Контрольная сумма (заголовок / факт)', 'Checksum (header / actual)'),
              Format('0x%.8x / 0x%.8x', [LPe.CheckSum, LPe.ComputedCheckSum]));
            Field('.NET', IfThen(LPe.IsDotNet, MHL('да', 'yes'), MHL('нет', 'no')));
            for I := 0 to High(LPe.Warnings) do
              Field(MHL('Проблема разбора', 'Parsing problem'), LPe.Warnings[I]);
          end;
        nkTls:
          Field(MHL('Функций обратного вызова', 'Callbacks'), IntToStr(LPe.TlsCallbackCount));
        nkSignature:
          begin
            Field(MHL('Состояние', 'State'), SignatureText(FReport.Signature));
            Field(MHL('Источник', 'Source'), FReport.Signature.Source);
            Field(MHL('Смещение данных подписи', 'Signature data offset'), MHHexOffset(LPe.CertificateOffset),
              LPe.CertificateOffset, LPe.CertificateSize);
            Field(MHL('Размер', 'Size'), SizeText(LPe.CertificateSize));
          end;
        nkOverlay:
          begin
            Field(MHL('Смещение', 'Offset'), MHHexOffset(LPe.OverlayOffset), LPe.OverlayOffset, LPe.OverlaySize);
            Field(MHL('Размер', 'Size'), SizeText(LPe.OverlaySize));
            Field(MHL('Энтропия', 'Entropy'), EntropyText(IfThen(LPe.OverlayEntropy > 0, LPe.OverlayEntropy, -1)));
          end;
      end;
    end;
  finally
    FDetails.Items.EndUpdate;
  end;
  if LInfo.Offset >= 0 then
    FHex.GotoOffset(LInfo.Offset, Max(Int64(1), Min(LInfo.Size, Int64(4096))));
end;

procedure TMHBinaryLabPage.FillMap;
var
  LBands: TArray<TMHMapBand>;
  LBand: TMHMapBand;
  LSection: TMHPeSection;
  LRegion: TMHEntropyRegion;
  I: Integer;
begin
  FMap.SetData(FReport.Entropy.Blocks, FReport.Size);
  LBands := nil;
  if FReport.Pe.Valid then
  begin
    I := 0;
    for LSection in FReport.Pe.Sections do
      if LSection.RawSize > 0 then
      begin
        LBand.Offset := LSection.RawOffset;
        LBand.Size := LSection.RawSize;
        LBand.Caption := LSection.Name;
        LBand.Color := SECTION_COLORS[I mod Length(SECTION_COLORS)];
        LBands := LBands + [LBand];
        Inc(I);
      end;
    if FReport.Pe.OverlaySize > 0 then
    begin
      LBand.Offset := FReport.Pe.OverlayOffset;
      LBand.Size := FReport.Pe.OverlaySize;
      LBand.Caption := MHL('оверлей', 'overlay');
      LBand.Color := COLOR_OVERLAY;
      LBands := LBands + [LBand];
    end;
    if FReport.Pe.CertificateSize > 0 then
    begin
      LBand.Offset := FReport.Pe.CertificateOffset;
      LBand.Size := FReport.Pe.CertificateSize;
      LBand.Caption := MHL('подпись', 'signature');
      LBand.Color := COLOR_CERTIFICATE;
      LBands := LBands + [LBand];
    end;
  end;
  FMap.SetBands(LBands);
  FHistogram.SetHistogram(FReport.Entropy.Histogram);
  FRegionList.Items.BeginUpdate;
  try
    for LRegion in FReport.Entropy.HighRegions do
      with FRegionList.Items.Add do
      begin
        Caption := MHHexOffset(LRegion.Offset);
        SubItems.Add(SizeText(LRegion.Size));
        SubItems.Add(EntropyText(LRegion.AverageEntropy) + ' — ' + MHEntropyClassTitle(LRegion.EntropyClass));
        SubItems.Add(LRegion.Location);
      end;
  finally
    FRegionList.Items.EndUpdate;
  end;
end;

procedure TMHBinaryLabPage.FillHex;
var
  LPe: TMHPeInfo;
  LObject: TMHEmbeddedObject;
  I, LCount: Integer;
begin
  FHex.ClearHighlights;
  FHex.Source := FSource;
  LPe := FReport.Pe;
  if LPe.Valid then
  begin
    FHex.AddHighlight(0, Min(Int64(LPe.SizeOfHeaders), FReport.Size), COLOR_HEADERS, MHL('Заголовки PE', 'PE headers'));
    for I := 0 to High(LPe.Sections) do
      if LPe.Sections[I].RawSize > 0 then
        FHex.AddHighlight(LPe.Sections[I].RawOffset, LPe.Sections[I].RawSize, SECTION_COLORS[I mod Length(SECTION_COLORS)],
          MHL('Секция ', 'Section ') + LPe.Sections[I].Name);
    if LPe.OverlaySize > 0 then
      FHex.AddHighlight(LPe.OverlayOffset, LPe.OverlaySize, COLOR_OVERLAY, MHL('Оверлей', 'Overlay'));
    if LPe.CertificateSize > 0 then
      FHex.AddHighlight(LPe.CertificateOffset, LPe.CertificateSize, COLOR_CERTIFICATE,
        MHL('Цифровая подпись', 'Digital signature'));
    if LPe.EntryPointOffset >= 0 then
      FHex.AddHighlight(LPe.EntryPointOffset, 16, COLOR_ENTRY, MHL('Точка входа', 'Entry point'));
  end;
  LCount := 0;
  for LObject in FReport.Embedded do
  begin
    if LCount >= 500 then
      Break;
    Inc(LCount);
    FHex.AddHighlight(LObject.Offset, IfThen(LObject.Size > 0, LObject.Size, 64), COLOR_EMBEDDED, LObject.Description);
  end;
  FHex.GotoOffset(0, 0);
end;

procedure TMHBinaryLabPage.FillStrings;
begin
  StringsFilterChange(nil);
end;

procedure TMHBinaryLabPage.StringsFilterChange(Sender: TObject);
var
  LFilter: string;
  LCategoryIndex, I, LCount: Integer;
  LItem: TMHBinaryString;
  LRows: TList<Integer>;
begin
  LFilter := Trim(FStringsFilter.Text).ToLower;
  LCategoryIndex := FStringsCategory.ItemIndex;
  LRows := TList<Integer>.Create;
  try
    if FHasReport then
      for I := 0 to High(FReport.Strings.Items) do
      begin
        LItem := FReport.Strings.Items[I];
        // 0 — все, 1 — только индикаторы, дальше — конкретная категория.
        if (LCategoryIndex = 1) and (LItem.Category = scPlain) then
          Continue;
        if (LCategoryIndex >= 2) and (Ord(LItem.Category) <> LCategoryIndex - 1) then
          Continue;
        if (LFilter <> '') and not LItem.Text.ToLower.Contains(LFilter) then
          Continue;
        LRows.Add(I);
      end;
    FStringRows := LRows.ToArray;
  finally
    LRows.Free;
  end;
  FStringsList.Items.Count := Length(FStringRows);
  FStringsList.Invalidate;
  LCount := 0;
  if FHasReport then
    LCount := FReport.Strings.TotalFound;
  FStringsCount.Caption := Format(MHL('Показано %d из %d найденных', 'Showing %d of %d found'),
    [Length(FStringRows), LCount]);
end;

procedure TMHBinaryLabPage.StringsData(Sender: TObject; Item: TListItem);
var
  LString: TMHBinaryString;
begin
  if (csDestroying in ComponentState) or (Item.Index < 0) or (Item.Index > High(FStringRows)) then
    Exit;
  LString := FReport.Strings.Items[FStringRows[Item.Index]];
  Item.Caption := MHHexOffset(LString.Offset);
  Item.SubItems.Add(IfThen(LString.Encoding = seUtf16, 'UTF-16', 'ASCII'));
  Item.SubItems.Add(MHStringCategoryTitle(LString.Category));
  Item.SubItems.Add(LString.Text);
end;

procedure TMHBinaryLabPage.FillEmbedded;
var
  LObject: TMHEmbeddedObject;
begin
  FEmbeddedList.Items.BeginUpdate;
  try
    for LObject in FReport.Embedded do
      with FEmbeddedList.Items.Add do
      begin
        Caption := MHHexOffset(LObject.Offset);
        SubItems.Add(SizeText(LObject.Size));
        SubItems.Add(LObject.Description);
        SubItems.Add(LObject.Location);
      end;
  finally
    FEmbeddedList.Items.EndUpdate;
  end;
end;

procedure TMHBinaryLabPage.ShowDiff;
var
  LItem: TMHDiffItem;
  LOffset: Int64;
  LText: string;
begin
  FDiffList.Items.BeginUpdate;
  try
    FDiffList.Items.Clear;
    FDiffOffsets.Clear;
    for LItem in FDiff.Items do
    begin
      with FDiffList.Items.Add do
      begin
        Caption := MHDiffAreaTitle(LItem.Area);
        SubItems.Add(MHDiffChangeTitle(LItem.Change));
        SubItems.Add(LItem.Name);
        SubItems.Add(LItem.OldValue);
        SubItems.Add(LItem.NewValue);
      end;
      LOffset := -1;
      if (LItem.Area = MH_DIFF_AREA_BLOCK) and LItem.Name.StartsWith('0x') then
        LOffset := StrToInt64Def('$' + Copy(LItem.Name, 3, Pos(' ', LItem.Name) - 3), -1);
      FDiffOffsets.Add(LOffset);
    end;
  finally
    FDiffList.Items.EndUpdate;
  end;
  FDiffStrip.SetRanges(FDiff.ChangedRanges, Max(FDiff.LeftSize, FDiff.RightSize), $0F48D9);
  if FDiff.Identical then
    LText := MHL('Файлы идентичны.', 'The files are identical.')
  else
    LText := Format(MHL('Сходство %s%%, изменено %s байт, различий: %d. B: %s', 'Similarity %s%%, %s bytes changed, ' +
      '%d differences. B: %s'), [FormatFloat('0.0', FDiff.SimilarityPercent), SizeText(FDiff.ChangedBytes),
      Length(FDiff.Items), FDiff.RightPath]);
  if FDiff.Truncated then
    LText := LText + MHL(' Сравнение неполное (лимит).', ' Incomplete comparison (limit).');
  FDiffSummary.Caption := LText;
end;

procedure TMHBinaryLabPage.ShowOffset(AOffset: Int64; ALength: Int64);
begin
  if (FSource = nil) or (AOffset < 0) then
    Exit;
  FTabs.ActivePageIndex := TabHex;
  FHex.GotoOffset(AOffset, Max(Int64(1), ALength));
end;

class function TMHBinaryLabPage.ParseOffset(const AText: string; out AOffset: Int64): Boolean;
var
  LText: string;
  LHex: Boolean;
  C: Char;
begin
  AOffset := -1;
  LText := Trim(AText).Replace(' ', '').Replace('_', '');
  LHex := False;
  if LText.StartsWith('0x', True) or LText.StartsWith('$') then
  begin
    LText := LText.Substring(IfThen(LText.StartsWith('$'), 1, 2));
    LHex := True;
  end
  else if LText.EndsWith('h', True) then
  begin
    LText := LText.Substring(0, LText.Length - 1);
    LHex := True;
  end;
  if LText = '' then
    Exit(False);
  for C in LText do
    if CharInSet(C, ['a'..'f', 'A'..'F']) then
      LHex := True
    else if not CharInSet(C, ['0'..'9']) then
      Exit(False);
  if LHex then
    Result := TryStrToInt64('$' + LText, AOffset)
  else
    Result := TryStrToInt64(LText, AOffset);
  Result := Result and (AOffset >= 0);
end;

procedure TMHBinaryLabPage.OpenClick(Sender: TObject);
var
  LFile: string;
begin
  if FChooseFile(MHL('Файл для анализа в BinaryLab', 'File to analyse in BinaryLab'),
    MHL('Все файлы (*.*)|*.*|Программы и библиотеки|*.exe;*.dll;*.sys;*.scr;*.ocx;*.cpl',
      'All files (*.*)|*.*|Programs and libraries|*.exe;*.dll;*.sys;*.scr;*.ocx;*.cpl'), '', False, LFile) then
    OpenFile(LFile);
end;

class function TMHBinaryLabPage.CleanPath(const AText: string): string;
begin
  Result := Trim(AText);
  if (Length(Result) >= 2) and (Result[1] = '"') and (Result[Length(Result)] = '"') then
    Result := Trim(Copy(Result, 2, Length(Result) - 2));
end;

procedure TMHBinaryLabPage.CheckClick(Sender: TObject);
var
  LPath, LFile: string;
  LFiles: TArray<TMHFolderFile>;
begin
  if FBusy then
    Exit;
  LPath := CleanPath(FPathEdit.Text);
  if LPath = '' then
  begin
    OpenClick(Sender);
    Exit;
  end;
  if DirectoryExists(LPath) then
  begin
    // Папка (в том числе скрытая): файлы показываются все — Проводник скрытые и системные не показывает.
    if not ListFolderFiles(LPath, LFiles) then
    begin
      FLastError := MHL('Папку не прочитать: ', 'Cannot read the folder: ') + LPath;
      SetStage(FLastError, 0);
      Exit;
    end;
    if Length(LFiles) = 0 then
    begin
      FLastError := MHL('В папке нет файлов (в том числе скрытых): ', 'The folder has no files (hidden ones included): ') +
        LPath;
      SetStage(FLastError, 0);
      Exit;
    end;
    if FChooseInFolder(LPath, LFiles, LFile) and (LFile <> '') then
      OpenFile(TPath.Combine(LPath, LFile));
    Exit;
  end;
  if not FileExists(LPath) then
  begin
    FLastError := MHL('Файл не найден: ', 'File not found: ') + LPath;
    SetStage(FLastError, 0);
    Exit;
  end;
  OpenFile(LPath);
end;

class function TMHBinaryLabPage.ListFolderFiles(const AFolder: string; out AFiles: TArray<TMHFolderFile>): Boolean;
var
  LEntries: TArray<TMHFsEntry>;
  LEntry: TMHFsEntry;
  LFile: TMHFolderFile;
  LFs: IMHFileScanFs;
begin
  AFiles := nil;
  LFs := TMHWinFileScanFs.Create;
  Result := LFs.ListDirectory(AFolder, LEntries);
  if not Result then
    Exit;
  for LEntry in LEntries do
    if not LEntry.IsDirectory then
    begin
      LFile.Name := LEntry.Name;
      LFile.SizeBytes := LEntry.SizeBytes;
      LFile.Attributes := LEntry.Attributes;
      AFiles := AFiles + [LFile];
    end;
  TArray.Sort<TMHFolderFile>(AFiles, TComparer<TMHFolderFile>.Construct(
    function(const A, B: TMHFolderFile): Integer
    begin
      Result := CompareText(A.Name, B.Name);
    end));
end;

function TMHBinaryLabPage.DefaultChooseInFolder(const AFolder: string; const AFiles: TArray<TMHFolderFile>;
  out AFileName: string): Boolean;
var
  LForm: TForm;
  LList: TListView;
  LNote: TLabel;
  LButtons: TPanel;
  LOk, LCancel: TButton;
  LFile: TMHFolderFile;
begin
  AFileName := '';
  LForm := TForm.CreateNew(nil);
  try
    LForm.Caption := MHL('Файлы папки — ', 'Folder files — ') + AFolder;
    LForm.Position := poMainFormCenter;
    LForm.BorderIcons := [biSystemMenu];
    LForm.SetBounds(0, 0, 720, 420);
    LNote := TLabel.Create(LForm);
    LNote.Parent := LForm;
    LNote.Align := alTop;
    LNote.WordWrap := True;
    LNote.AlignWithMargins := True;
    LNote.ShowAccelChar := False;
    LNote.Caption := MHL('Показаны все файлы, в том числе скрытые и системные — Проводник их по умолчанию не ' +
      'показывает. Выберите файл для разбора (он не запускается).', 'All files are shown, hidden and system ones ' +
      'included — Explorer does not show them by default. Choose a file to analyse (it is not run).');
    LButtons := TPanel.Create(LForm);
    LButtons.Parent := LForm;
    LButtons.Align := alBottom;
    LButtons.Height := 44;
    LButtons.BevelOuter := bvNone;
    LOk := TButton.Create(LForm);
    LOk.Parent := LButtons;
    LOk.SetBounds(8, 8, 140, 28);
    LOk.Caption := MHL('Проверить', 'Check');
    LOk.ModalResult := mrOk;
    LOk.Default := True;
    LCancel := TButton.Create(LForm);
    LCancel.Parent := LButtons;
    LCancel.SetBounds(156, 8, 100, 28);
    LCancel.Caption := MHL('Отмена', 'Cancel');
    LCancel.ModalResult := mrCancel;
    LCancel.Cancel := True;
    LList := TListView.Create(LForm);
    LList.Parent := LForm;
    LList.Align := alClient;
    LList.ViewStyle := vsReport;
    LList.ReadOnly := True;
    LList.RowSelect := True;
    LList.HideSelection := False;
    with LList.Columns.Add do
    begin
      Caption := MHL('Файл', 'File');
      Width := 300;
    end;
    with LList.Columns.Add do
    begin
      Caption := MHL('Размер, байт', 'Size, bytes');
      Width := 120;
      Alignment := taRightJustify;
    end;
    with LList.Columns.Add do
    begin
      Caption := MHL('Скрыт от Проводника', 'Hidden from Explorer');
      Width := 220;
    end;
    for LFile in AFiles do
      with LList.Items.Add do
      begin
        Caption := LFile.Name;
        SubItems.Add(SizeText(LFile.SizeBytes));
        SubItems.Add(MHHiddenAttributesText(LFile.Attributes));
      end;
    if LList.Items.Count > 0 then
      LList.Items[0].Selected := True;
    Result := (LForm.ShowModal = mrOk) and (LList.Selected <> nil);
    if Result then
      AFileName := LList.Selected.Caption;
  finally
    LForm.Free;
  end;
end;

procedure TMHBinaryLabPage.PathEditKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then
  begin
    Key := #0;
    CheckClick(Sender);
  end;
end;

procedure TMHBinaryLabPage.CompareClick(Sender: TObject);
var
  LFile: string;
begin
  if FHasReport and FChooseFile(MHL('Второй файл для сравнения', 'Second file to compare'),
    MHL('Все файлы (*.*)|*.*', 'All files (*.*)|*.*'), '', False, LFile) then
    CompareWith(LFile);
end;

procedure TMHBinaryLabPage.CancelClick(Sender: TObject);
begin
  Cancel;
  SetStage(MHL('Отмена…', 'Cancelling…'), FProgress.Position);
end;

procedure TMHBinaryLabPage.ExportReport(const AFileName: string);
begin
  if FHasReport then
    MHSaveBinaryReport(FReport, AFileName);
end;

procedure TMHBinaryLabPage.ExportDiff(const AFileName: string);
begin
  if FHasDiff then
    MHSaveBinaryDiff(FDiff, AFileName);
end;

procedure TMHBinaryLabPage.ExportClick(Sender: TObject);
var
  LFile: string;
begin
  if not FHasReport then
    Exit;
  if FChooseFile(MHL('Сохранить отчёт BinaryLab', 'Save the BinaryLab report'), REPORT_FILTER,
    ChangeFileExt(FReport.FileName, '') + '.binarylab.html', True, LFile) then
  begin
    try
      ExportReport(LFile);
      SetStage(MHL('Отчёт сохранён: ', 'Report saved: ') + LFile, 100);
    except
      on E: Exception do
        SetStage(MHL('Отчёт не сохранён: ', 'Report not saved: ') + E.Message, 0);
    end;
  end;
end;

procedure TMHBinaryLabPage.ExportDiffClick(Sender: TObject);
var
  LFile: string;
begin
  if not FHasDiff then
    Exit;
  if FChooseFile(MHL('Сохранить сравнение', 'Save the comparison'), REPORT_FILTER, 'binarydiff.html', True, LFile) then
  begin
    try
      ExportDiff(LFile);
      SetStage(MHL('Сравнение сохранено: ', 'Comparison saved: ') + LFile, 100);
    except
      on E: Exception do
        SetStage(MHL('Сравнение не сохранено: ', 'Comparison not saved: ') + E.Message, 0);
    end;
  end;
end;

procedure TMHBinaryLabPage.DetailsDblClick(Sender: TObject);
var
  LRange: TMHByteRange;
begin
  if (FDetails.Selected = nil) or (FDetails.Selected.Index >= FDetailOffsets.Count) then
    Exit;
  LRange := FDetailOffsets[FDetails.Selected.Index];
  if LRange.Offset >= 0 then
    ShowOffset(LRange.Offset, Min(Max(LRange.Size, Int64(1)), Int64(4096)));
end;

procedure TMHBinaryLabPage.AnomalyDblClick(Sender: TObject);
var
  LAnomaly: TMHBinaryAnomaly;
begin
  if (FAnomalyList.Selected = nil) or (FAnomalyList.Selected.Index > High(FReport.Anomalies)) then
    Exit;
  LAnomaly := FReport.Anomalies[FAnomalyList.Selected.Index];
  if LAnomaly.Offset >= 0 then
    ShowOffset(LAnomaly.Offset, Min(Max(LAnomaly.Size, Int64(1)), Int64(4096)));
end;

procedure TMHBinaryLabPage.RegionDblClick(Sender: TObject);
var
  LRegion: TMHEntropyRegion;
begin
  if (FRegionList.Selected = nil) or (FRegionList.Selected.Index > High(FReport.Entropy.HighRegions)) then
    Exit;
  LRegion := FReport.Entropy.HighRegions[FRegionList.Selected.Index];
  ShowOffset(LRegion.Offset, Min(LRegion.Size, Int64(4096)));
end;

procedure TMHBinaryLabPage.EmbeddedDblClick(Sender: TObject);
var
  LObject: TMHEmbeddedObject;
begin
  if (FEmbeddedList.Selected = nil) or (FEmbeddedList.Selected.Index > High(FReport.Embedded)) then
    Exit;
  LObject := FReport.Embedded[FEmbeddedList.Selected.Index];
  ShowOffset(LObject.Offset, IfThen(LObject.Size > 0, Min(LObject.Size, Int64(4096)), 2));
end;

procedure TMHBinaryLabPage.StringsDblClick(Sender: TObject);
var
  LString: TMHBinaryString;
begin
  if (FStringsList.Selected = nil) or (FStringsList.Selected.Index > High(FStringRows)) then
    Exit;
  LString := FReport.Strings.Items[FStringRows[FStringsList.Selected.Index]];
  ShowOffset(LString.Offset, Length(LString.Text) * IfThen(LString.Encoding = seUtf16, 2, 1));
end;

procedure TMHBinaryLabPage.DiffDblClick(Sender: TObject);
begin
  if (FDiffList.Selected <> nil) and (FDiffList.Selected.Index < FDiffOffsets.Count) and
     (FDiffOffsets[FDiffList.Selected.Index] >= 0) then
    ShowOffset(FDiffOffsets[FDiffList.Selected.Index], 16);
end;

procedure TMHBinaryLabPage.MapBlockClick(Sender: TObject; AOffset: Int64);
begin
  ShowOffset(AOffset, Max(1, FReport.Entropy.BlockSize));
end;

procedure TMHBinaryLabPage.StripClick(Sender: TObject; AOffset: Int64);
begin
  ShowOffset(AOffset, 16);
end;

procedure TMHBinaryLabPage.GotoClick(Sender: TObject);
var
  LOffset: Int64;
begin
  if ParseOffset(FGotoEdit.Text, LOffset) and (FSource <> nil) and (LOffset < FSource.Size) then
    FHex.GotoOffset(LOffset, 1)
  else
    SetStage(MHL('Смещение вне файла или записано неверно (пример: 0x1F400 или 128000).',
      'Offset is outside the file or invalid (example: 0x1F400 or 128000).'), FProgress.Position);
end;

procedure TMHBinaryLabPage.FindClick(Sender: TObject);
var
  LPattern: TBytes;
begin
  if Trim(FFindEdit.Text) = '' then
    Exit;
  case TFindMode(EnsureRange(FFindMode.ItemIndex, 0, Ord(High(TFindMode)))) of
    fmUtf16:
      LPattern := MHTextPattern(FFindEdit.Text, True);
    fmHex:
      if not MHParseHexPattern(FFindEdit.Text, LPattern) then
      begin
        SetStage(MHL('Байты записываются парами шестнадцатеричных цифр: 4D 5A 90.',
          'Bytes are written as pairs of hex digits: 4D 5A 90.'), FProgress.Position);
        Exit;
      end;
  else
    LPattern := MHTextPattern(FFindEdit.Text, False);
  end;
  FindPattern(LPattern, FIgnoreCase.Checked and (FFindMode.ItemIndex <> Ord(fmHex)));
end;

procedure TMHBinaryLabPage.HexSelectionChange(Sender: TObject);
var
  LCaption: string;
begin
  if FSource = nil then
    Exit;
  LCaption := '';
  FHex.HighlightAt(FHex.CaretOffset, LCaption);
  FHexStatus.Caption := Format(MHL('Смещение %s (%s), выделено %s байт. %s', 'Offset %s (%s), %s bytes selected. %s'),
    [MHHexOffset(FHex.CaretOffset), FormatFloat('#,##0', FHex.CaretOffset), FormatFloat('#,##0', FHex.SelLength),
     LCaption]);
end;

function TMHBinaryLabPage.DefaultChooseFile(const ATitle, AFilter, ADefaultName: string; ASave: Boolean;
  out AFileName: string): Boolean;
var
  LOpen: TOpenDialog;
  LSave: TSaveDialog;
begin
  AFileName := '';
  if ASave then
  begin
    LSave := TSaveDialog.Create(nil);
    try
      LSave.Title := ATitle;
      LSave.Filter := AFilter;
      LSave.FileName := ADefaultName;
      LSave.DefaultExt := 'html';
      LSave.Options := [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing];
      Result := LSave.Execute;
      if Result then
        AFileName := LSave.FileName;
    finally
      LSave.Free;
    end;
  end
  else
  begin
    LOpen := TOpenDialog.Create(nil);
    try
      LOpen.Title := ATitle;
      LOpen.Filter := AFilter;
      // Скрытые и системные файлы видны и при выключенном показе в Проводнике.
      LOpen.Options := [ofFileMustExist, ofHideReadOnly, ofEnableSizing, ofForceShowHidden];
      Result := LOpen.Execute;
      if Result then
        AFileName := LOpen.FileName;
    finally
      LOpen.Free;
    end;
  end;
end;

end.
