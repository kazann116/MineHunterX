unit MineHunter.App.BinaryLab.Controls;

{
  Визуальные элементы BinaryLab (рисуются сами, создаются в коде):

  - TMHHexView — виртуальный шестнадцатеричный просмотр. Читает из источника
    только видимые строки (весь файл в память не загружается), подсвечивает
    структуры файла, выделяет мышью и клавиатурой, ищет байты. Полоса
    прокрутки работает и для файлов больше 4 ГБ (позиция масштабируется).
  - TMHEntropyMap — карта энтропии: сетка блоков, цвет — от тёмно-синего
    (заполнение) до красного (шифрованные данные), полоса разделов сверху
    (секции PE, оверлей), шкала снизу. Если блоков больше, чем клеток,
    в клетку сводится несколько блоков (показывается максимум энтропии).
  - TMHByteHistogram — частоты 256 значений байта (логарифмическая шкала
    по умолчанию: редкие значения не теряются рядом с частыми).
  - TMHRangeStrip — полоса диапазонов по длине файла (изменённые области
    при сравнении файлов); диапазон не уже 1 пикселя.

  Общее: размеры масштабируются по DPI монитора, цвета берутся из активного
  стиля VCL (светлая и тёмная тема), двойная буферизация без мерцания,
  подсказка по точке под указателем. Все методы безопасны до создания окна
  и при нулевом размере.
}

interface

uses
  System.SysUtils, System.Classes, System.Types, System.UITypes,
  Winapi.Windows, Winapi.Messages,
  Vcl.Controls, Vcl.Graphics,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

type
  /// Событие со смещением в файле (щелчок по карте, полосе диапазонов).
  TMHOffsetEvent = procedure(Sender: TObject; AOffset: Int64) of object;

  /// Полоса над картой энтропии: секция PE, оверлей, ресурс.
  TMHMapBand = record
  public
    Offset: Int64;
    Size: Int64;
    Caption: string;
    Color: TColor;
  end;

  /// Основа элементов BinaryLab: масштаб по DPI, метрики шрифта без окна,
  /// подсказка по точке под указателем.
  TMHBinaryControl = class(TCustomControl)
  private
    FCharWidth: Integer;
    FTextHeight: Integer;
    FMetricsValid: Boolean;
    procedure CMFontChanged(var Message: TMessage); message CM_FONTCHANGED;
    procedure CMHintShow(var Message: TCMHintShow); message CM_HINTSHOW;
  protected
    function S(AValue: Integer): Integer;
    /// Клиентская область. До создания окна — по размерам элемента:
    /// TWinControl.ClientRect создал бы окно (и без родителя — исключение).
    function Area: TRect;
    function AreaWidth: Integer;
    function AreaHeight: Integer;
    function CharWidth: Integer;
    function TextHeight: Integer;
    /// Шрифт изменился (пересчёт раскладки).
    procedure MetricsChanged; virtual;
    procedure Resize; override;
    /// Текст подсказки в точке и область, внутри которой он не меняется ('' — нет подсказки).
    function GetHintAt(X, Y: Integer; out ARect: TRect): string; virtual;
    procedure PaintBackground;
    procedure PaintMessage(const AText: string);
  public
    constructor Create(AOwner: TComponent); override;
    /// Текст подсказки для точки (то же, что покажет всплывающая подсказка).
    function HintTextAt(X, Y: Integer): string;
  end;

  TMHHexHighlight = record
  public
    Offset: Int64;
    Size: Int64;
    Color: TColor;
    Caption: string;
  end;

  /// Виртуальный шестнадцатеричный просмотр.
  TMHHexView = class(TMHBinaryControl)
  public const
    ROW_BYTES = 16;
  private
    FSource: IMHBinarySource;
    FSize: Int64;
    FTopRow: Int64;
    FSelStart: Int64;
    FSelLength: Int64;
    FCaret: Int64;
    FAnchor: Int64;
    FPage: TBytes;
    FPageOffset: Int64;
    FPageRequested: Integer;
    FPageCount: Integer;
    FPageValid: Boolean;
    FHighlights: TArray<TMHHexHighlight>;
    FDragging: Boolean;
    FWheelAccum: Integer;
    FOnSelectionChange: TNotifyEvent;
    procedure SetSource(const AValue: IMHBinarySource);
    function GetBytesPerRow: Integer;
    function GetTopOffset: Int64;
    procedure SetTopOffset(AValue: Int64);
    procedure SetSelStart(AValue: Int64);
    procedure SetSelLength(AValue: Int64);
    procedure SetCaretOffset(AValue: Int64);
    procedure SetTopRow(AValue: Int64);
    function MaxTopRow: Int64;
    function RowHeight: Integer;
    function PaintRows: Integer;
    function Margin: Integer;
    function HexStart: Integer;
    function HexLeft(AColumn: Integer): Integer;
    function HexCellWidth(AColumn: Integer): Integer;
    function AsciiLeft: Integer;
    procedure UpdateScrollBar;
    function RowOfScrollPos(APos: Integer): Int64;
    procedure EnsurePage;
    function ByteAt(AOffset: Int64; out AValue: Byte): Boolean;
    function NearestOffset(X, Y: Integer; out AOffset: Int64): Boolean;
    procedure MoveCaret(ANew: Int64; AExtend: Boolean);
    procedure SetSelectionInternal(AStart, ALength: Int64);
    procedure ScrollToCaret;
    function HighlightIndexAt(AOffset: Int64): Integer;
    procedure WMVScroll(var Message: TWMVScroll); message WM_VSCROLL;
    procedure WMGetDlgCode(var Message: TWMGetDlgCode); message WM_GETDLGCODE;
  protected
    procedure CreateParams(var Params: TCreateParams); override;
    procedure CreateWnd; override;
    procedure Paint; override;
    procedure Resize; override;
    procedure MetricsChanged; override;
    procedure KeyDown(var Key: Word; Shift: TShiftState); override;
    procedure MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure MouseMove(Shift: TShiftState; X, Y: Integer); override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    function DoMouseWheel(Shift: TShiftState; WheelDelta: Integer; MousePos: TPoint): Boolean; override;
    procedure DoEnter; override;
    procedure DoExit; override;
    function GetHintAt(X, Y: Integer; out ARect: TRect): string; override;
  public
    constructor Create(AOwner: TComponent); override;
    /// Сбрасывает кэш страницы и перечитывает размер источника.
    procedure InvalidateData;
    procedure ClearHighlights;
    /// Подсветка структуры (фон байтов смешивается с фоном окна, текст читается в обеих темах).
    procedure AddHighlight(AOffset, ASize: Int64; AColor: TColor; const ACaption: string);
    /// Подсветка, содержащая смещение (при наложении — добавленная последней).
    function HighlightAt(AOffset: Int64; out ACaption: string): Boolean;
    function HighlightCount: Integer;
    /// Прокручивает к смещению (по центру, если оно было за экраном) и выделяет.
    procedure GotoOffset(AOffset: Int64; ASelectLength: Int64 = 1);
    /// Следующее вхождение после курсора (с переходом в начало один раз).
    function FindNext(const APattern: TBytes; AIgnoreCase: Boolean = False): Boolean;
    /// Прокрутка на ARows строк (отрицательное — вверх).
    procedure ScrollRows(ARows: Int64);
    function OffsetAtPoint(X, Y: Integer; out AOffset: Int64): Boolean;
    /// Точка внутри ячейки байта (шестнадцатеричной или символьной колонки);
    /// False — байт не виден.
    function PointOfOffset(AOffset: Int64; out APoint: TPoint; AAscii: Boolean = False): Boolean;
    /// Полностью видимых строк (не меньше 1).
    function VisibleRows: Integer;
    function RowCount: Int64;
    /// Цифр в колонке смещения: 8, для файлов больше 4 ГБ — 12.
    function OffsetDigits: Integer;
    /// Ширина содержимого строки в пикселях (без полосы прокрутки).
    function ContentWidth: Integer;
    property Source: IMHBinarySource read FSource write SetSource;
    property DataSize: Int64 read FSize;
    property BytesPerRow: Integer read GetBytesPerRow;
    property TopOffset: Int64 read GetTopOffset write SetTopOffset;
    property SelStart: Int64 read FSelStart write SetSelStart;
    property SelLength: Int64 read FSelLength write SetSelLength;
    property CaretOffset: Int64 read FCaret write SetCaretOffset;
    property OnSelectionChange: TNotifyEvent read FOnSelectionChange write FOnSelectionChange;
  end;

  /// Карта энтропии файла.
  TMHEntropyMap = class(TMHBinaryControl)
  private type
    TLayout = record
      Bands: TRect;
      Map: TRect;
      Legend: TRect;
      Cell: Integer;
      Cols: Integer;
      Rows: Integer;
      PerCell: Integer;
      CellCount: Integer;
    end;
  private
    FBlocks: TArray<TMHEntropyBlock>;
    FFileSize: Int64;
    FBands: TArray<TMHMapBand>;
    FSelectedOffset: Int64;
    FDownIndex: Integer;
    FOnBlockClick: TMHOffsetEvent;
    function GetLayout: TLayout;
    function CellRectOf(const ALayout: TLayout; ACell: Integer): TRect;
    function CellEntropy(const ALayout: TLayout; ACell: Integer): Double;
    function BandAt(AOffset: Int64): Integer;
    function BlockIndexOfOffset(AOffset: Int64): Integer;
    procedure SetSelectedOffset(AValue: Int64);
    procedure PaintBands(const ALayout: TLayout);
    procedure PaintLegend(const ALayout: TLayout);
  protected
    procedure Paint; override;
    procedure MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    function GetHintAt(X, Y: Integer; out ARect: TRect): string; override;
  public
    constructor Create(AOwner: TComponent); override;
    procedure SetData(const ABlocks: TArray<TMHEntropyBlock>; AFileSize: Int64);
    procedure SetBands(const ABands: TArray<TMHMapBand>);
    /// Цвет энтропии 0..8: тёмно-синий (0) → зелёный (4.5) → жёлтый (6.8) → красный (8).
    class function EntropyColor(AEntropy: Double): TColor; static;
    /// Блок под точкой (первый блок клетки, если в клетке их несколько).
    function BlockAtPoint(X, Y: Integer; out AIndex: Integer): Boolean;
    /// Клетка, в которой нарисован блок (пустой прямоугольник — не нарисован).
    function CellRect(AIndex: Integer): TRect;
    /// Блоков в одной клетке (больше 1 — блоки сведены).
    function BlocksPerCell: Integer;
    function CellCount: Integer;
    function BlockCount: Integer;
    property FileSize: Int64 read FFileSize;
    /// Выделенное смещение (-1 — нет); подсвечивается блок, содержащий его.
    property SelectedOffset: Int64 read FSelectedOffset write SetSelectedOffset;
    property OnBlockClick: TMHOffsetEvent read FOnBlockClick write FOnBlockClick;
  end;

  /// Гистограмма значений байтов.
  TMHByteHistogram = class(TMHBinaryControl)
  private
    FCounts: array[Byte] of Int64;
    FTotal: Int64;
    FMax: Int64;
    FLogarithmic: Boolean;
    procedure SetLogarithmic(AValue: Boolean);
    function PlotRect: TRect;
    function BarLeft(const APlot: TRect; AByte: Integer): Integer;
    function GetCount(AByte: Byte): Int64;
  protected
    procedure Paint; override;
    function GetHintAt(X, Y: Integer; out ARect: TRect): string; override;
  public
    constructor Create(AOwner: TComponent); override;
    /// Частоты значений 0..255 (лишние элементы игнорируются, недостающие — 0).
    procedure SetHistogram(const ACounts: array of Int64);
    function ByteAtPoint(X, Y: Integer; out AByte: Byte): Boolean;
    /// Столбец значения по всей высоте области графика.
    function BarRect(AByte: Byte): TRect;
    /// Высота столбца 0..1 относительно наибольшего.
    function BarFraction(AByte: Byte): Double;
    property Counts[AByte: Byte]: Int64 read GetCount;
    property Total: Int64 read FTotal;
    property Logarithmic: Boolean read FLogarithmic write SetLogarithmic;
  end;

  /// Полоса диапазонов по длине файла.
  TMHRangeStrip = class(TMHBinaryControl)
  private
    FRanges: TArray<TMHByteRange>;
    FFileSize: Int64;
    FRangeColor: TColor;
    FMouseDown: Boolean;
    FOnOffsetClick: TMHOffsetEvent;
    function TrackRect: TRect;
    function XOfOffset(const ATrack: TRect; AOffset: Int64): Integer;
    function RangeSpan(const ATrack: TRect; AIndex: Integer): TRect;
  protected
    procedure Paint; override;
    procedure MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    function GetHintAt(X, Y: Integer; out ARect: TRect): string; override;
  public
    constructor Create(AOwner: TComponent); override;
    procedure SetRanges(const ARanges: TArray<TMHByteRange>; AFileSize: Int64; AColor: TColor);
    /// Смещение файла под X (0 .. FileSize - 1; 0 — пустой файл).
    function OffsetAtX(X: Integer): Int64;
    /// Диапазон, нарисованный под X.
    function RangeAtX(X: Integer; out AIndex: Integer): Boolean;
    property FileSize: Int64 read FFileSize;
    property OnOffsetClick: TMHOffsetEvent read FOnOffsetClick write FOnOffsetClick;
  end;

/// Смешивает цвет с фоном: AAlpha = 1 — только цвет, 0 — только фон.
function MHBlendColor(AColor, ABack: TColor; AAlpha: Double): TColor;

implementation

uses
  System.Math, Vcl.Forms,
  MineHunter.Core.Lang, MineHunter.App.Theme;

const
  /// До этого числа строк позиция полосы прокрутки равна номеру строки,
  /// дальше — масштабируется в SCROLL_SCALED_RANGE.
  SCROLL_DIRECT_LIMIT = 1000000000;
  SCROLL_SCALED_RANGE = 1000000;
  WHEEL_ROWS = 3;

function MHBlendColor(AColor, ABack: TColor; AAlpha: Double): TColor;
var
  C1, C2: TColorRef;
  A: Double;
begin
  A := EnsureRange(AAlpha, 0, 1);
  C1 := ColorToRGB(AColor);
  C2 := ColorToRGB(ABack);
  Result := TColor(RGB(
    Round(GetRValue(C1) * A + GetRValue(C2) * (1 - A)),
    Round(GetGValue(C1) * A + GetGValue(C2) * (1 - A)),
    Round(GetBValue(C1) * A + GetBValue(C2) * (1 - A))));
end;

/// Чёрный или белый текст, читаемый на фоне AColor.
function ContrastText(AColor: TColor): TColor;
var
  C: TColorRef;
begin
  C := ColorToRGB(AColor);
  if GetRValue(C) * 299 + GetGValue(C) * 587 + GetBValue(C) * 114 > 140000 then
    Result := clBlack
  else
    Result := clWhite;
end;

function IsPrintable(AByte: Byte): Boolean; inline;
begin
  Result := (AByte >= 32) and (AByte <= 126);
end;

function RangeText(AFrom, ATo: Int64): string;
begin
  Result := MHHexOffset(AFrom) + ' – ' + MHHexOffset(ATo);
end;

{ TMHBinaryControl }

constructor TMHBinaryControl.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ControlStyle := ControlStyle + [csOpaque];
  DoubleBuffered := True;
  ShowHint := True;
end;

function TMHBinaryControl.S(AValue: Integer): Integer;
begin
  Result := MulDiv(AValue, CurrentPPI, 96);
end;

function TMHBinaryControl.Area: TRect;
begin
  if HandleAllocated then
    Result := ClientRect
  else
    Result := Rect(0, 0, Max(0, Width), Max(0, Height));
end;

function TMHBinaryControl.AreaWidth: Integer;
begin
  Result := Area.Width;
end;

function TMHBinaryControl.AreaHeight: Integer;
begin
  Result := Area.Height;
end;

procedure TMHBinaryControl.CMFontChanged(var Message: TMessage);
begin
  inherited;
  FMetricsValid := False;
  MetricsChanged;
  Invalidate;
end;

procedure TMHBinaryControl.CMHintShow(var Message: TCMHintShow);
var
  LRect: TRect;
  LText: string;
begin
  LText := GetHintAt(Message.HintInfo^.CursorPos.X, Message.HintInfo^.CursorPos.Y, LRect);
  if LText = '' then
  begin
    Message.Result := 1; // подсказки нет
    Exit;
  end;
  Message.HintInfo^.HintStr := LText;
  Message.HintInfo^.CursorRect := LRect;
  Message.Result := 0;
end;

function TMHBinaryControl.CharWidth: Integer;
var
  LBitmap: TBitmap;
  LMetric: TTextMetric;
begin
  if not FMetricsValid then
  begin
    // Метрики через растр: работает и до создания окна элемента.
    LBitmap := TBitmap.Create;
    try
      LBitmap.SetSize(1, 1);
      LBitmap.Canvas.Font.Assign(Font);
      if GetTextMetrics(LBitmap.Canvas.Handle, LMetric) then
        FTextHeight := Max(1, Integer(LMetric.tmHeight))
      else
        FTextHeight := Max(1, LBitmap.Canvas.TextHeight('0'));
      FCharWidth := Max(1, LBitmap.Canvas.TextWidth('0'));
    finally
      LBitmap.Free;
    end;
    FMetricsValid := True;
  end;
  Result := FCharWidth;
end;

function TMHBinaryControl.TextHeight: Integer;
begin
  CharWidth;
  Result := FTextHeight;
end;

procedure TMHBinaryControl.MetricsChanged;
begin
end;

procedure TMHBinaryControl.Resize;
begin
  inherited;
  Invalidate;
end;

function TMHBinaryControl.GetHintAt(X, Y: Integer; out ARect: TRect): string;
begin
  ARect := Rect(X, Y, X + 1, Y + 1);
  Result := '';
end;

function TMHBinaryControl.HintTextAt(X, Y: Integer): string;
var
  LRect: TRect;
begin
  Result := GetHintAt(X, Y, LRect);
end;

procedure TMHBinaryControl.PaintBackground;
begin
  Canvas.Font := Font;
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(clWindow);
  Canvas.FillRect(Area);
end;

procedure TMHBinaryControl.PaintMessage(const AText: string);
var
  LRect: TRect;
  LText: string;
begin
  LRect := Area;
  LText := AText;
  Canvas.Brush.Style := bsClear;
  Canvas.Font.Color := MHThemeColor(clGrayText);
  Canvas.TextRect(LRect, LText, [tfCenter, tfVerticalCenter, tfSingleLine, tfEndEllipsis]);
  Canvas.Brush.Style := bsSolid;
end;

{ TMHHexView }

constructor TMHHexView.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  TabStop := True;
  if Screen.Fonts.IndexOf('Consolas') >= 0 then
    Font.Name := 'Consolas'
  else
    Font.Name := 'Courier New';
  Font.Size := 10;
  FSelLength := 0;
  FPageOffset := -1;
  Width := 640;
  Height := 320;
end;

procedure TMHHexView.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  Params.Style := Params.Style or WS_VSCROLL;
end;

procedure TMHHexView.CreateWnd;
begin
  inherited CreateWnd;
  UpdateScrollBar;
end;

function TMHHexView.GetBytesPerRow: Integer;
begin
  Result := ROW_BYTES;
end;

function TMHHexView.RowCount: Int64;
begin
  Result := (FSize + ROW_BYTES - 1) div ROW_BYTES;
end;

function TMHHexView.RowHeight: Integer;
begin
  Result := TextHeight + S(2);
end;

function TMHHexView.VisibleRows: Integer;
begin
  Result := Max(1, AreaHeight div RowHeight);
end;

function TMHHexView.PaintRows: Integer;
begin
  Result := Max(0, (AreaHeight + RowHeight - 1) div RowHeight);
end;

function TMHHexView.MaxTopRow: Int64;
begin
  Result := Max(Int64(0), RowCount - VisibleRows);
end;

function TMHHexView.OffsetDigits: Integer;
begin
  if FSize - 1 > $FFFFFFFF then
    Result := 12
  else
    Result := 8;
end;

function TMHHexView.Margin: Integer;
begin
  Result := S(4);
end;

function TMHHexView.HexStart: Integer;
begin
  Result := Margin + (OffsetDigits + 2) * CharWidth;
end;

function TMHHexView.HexLeft(AColumn: Integer): Integer;
begin
  Result := HexStart + AColumn * 3 * CharWidth;
  if AColumn >= ROW_BYTES div 2 then
    Inc(Result, CharWidth); // промежуток после 8 байт
end;

function TMHHexView.HexCellWidth(AColumn: Integer): Integer;
begin
  Result := 3 * CharWidth;
  if AColumn = ROW_BYTES div 2 - 1 then
    Inc(Result, CharWidth);
end;

function TMHHexView.AsciiLeft: Integer;
begin
  Result := HexLeft(ROW_BYTES) + CharWidth;
end;

function TMHHexView.ContentWidth: Integer;
begin
  Result := AsciiLeft + ROW_BYTES * CharWidth + Margin;
end;

function TMHHexView.GetTopOffset: Int64;
begin
  Result := FTopRow * ROW_BYTES;
end;

procedure TMHHexView.SetTopOffset(AValue: Int64);
begin
  SetTopRow(AValue div ROW_BYTES);
end;

procedure TMHHexView.SetTopRow(AValue: Int64);
begin
  AValue := EnsureRange(AValue, Int64(0), MaxTopRow);
  if AValue = FTopRow then
    Exit;
  FTopRow := AValue;
  UpdateScrollBar;
  Invalidate;
end;

procedure TMHHexView.ScrollRows(ARows: Int64);
begin
  SetTopRow(FTopRow + ARows);
end;

procedure TMHHexView.UpdateScrollBar;
var
  LInfo: TScrollInfo;
  LMax: Int64;
begin
  if not HandleAllocated then
    Exit;
  LMax := MaxTopRow;
  FillChar(LInfo, SizeOf(LInfo), 0);
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.fMask := SIF_ALL;
  LInfo.nMin := 0;
  if LMax <= 0 then
  begin
    // Всё видно: полоса скрывается.
    LInfo.nMax := 0;
    LInfo.nPage := 1;
    LInfo.nPos := 0;
  end
  else if LMax <= SCROLL_DIRECT_LIMIT then
  begin
    LInfo.nPage := VisibleRows;
    LInfo.nMax := Integer(LMax) + VisibleRows - 1;
    LInfo.nPos := Integer(FTopRow);
  end
  else
  begin
    LInfo.nPage := 1;
    LInfo.nMax := SCROLL_SCALED_RANGE;
    LInfo.nPos := Round(FTopRow / LMax * SCROLL_SCALED_RANGE);
  end;
  SetScrollInfo(Handle, SB_VERT, LInfo, True);
end;

function TMHHexView.RowOfScrollPos(APos: Integer): Int64;
var
  LMax: Int64;
begin
  LMax := MaxTopRow;
  if LMax <= SCROLL_DIRECT_LIMIT then
    Result := APos
  else
    Result := Round(APos / SCROLL_SCALED_RANGE * LMax);
end;

procedure TMHHexView.WMVScroll(var Message: TWMVScroll);
var
  LInfo: TScrollInfo;
begin
  case Message.ScrollCode of
    SB_LINEUP: ScrollRows(-1);
    SB_LINEDOWN: ScrollRows(1);
    SB_PAGEUP: ScrollRows(-VisibleRows);
    SB_PAGEDOWN: ScrollRows(VisibleRows);
    SB_TOP: SetTopRow(0);
    SB_BOTTOM: SetTopRow(MaxTopRow);
    SB_THUMBTRACK, SB_THUMBPOSITION:
      if HandleAllocated then
      begin
        FillChar(LInfo, SizeOf(LInfo), 0);
        LInfo.cbSize := SizeOf(LInfo);
        LInfo.fMask := SIF_TRACKPOS;
        // Позиция 32-битная (в сообщении — только 16 бит).
        if GetScrollInfo(Handle, SB_VERT, LInfo) then
          SetTopRow(RowOfScrollPos(LInfo.nTrackPos));
      end;
  end;
  Message.Result := 0;
end;

procedure TMHHexView.WMGetDlgCode(var Message: TWMGetDlgCode);
begin
  inherited;
  Message.Result := Message.Result or DLGC_WANTARROWS or DLGC_WANTCHARS;
end;

procedure TMHHexView.Resize;
begin
  inherited;
  SetTopRow(FTopRow); // ограничение после изменения высоты
  UpdateScrollBar;
end;

procedure TMHHexView.MetricsChanged;
begin
  inherited;
  SetTopRow(FTopRow);
  UpdateScrollBar;
end;

procedure TMHHexView.SetSource(const AValue: IMHBinarySource);
begin
  FSource := AValue;
  FHighlights := nil;
  FTopRow := 0;
  FCaret := 0;
  FAnchor := 0;
  FDragging := False;
  InvalidateData;
  SetSelectionInternal(0, 0);
end;

procedure TMHHexView.InvalidateData;
begin
  FSize := 0;
  if FSource <> nil then
    try
      FSize := Max(Int64(0), FSource.Size);
    except
      FSize := 0; // источник недоступен — показываем «Нет данных»
    end;
  FPageValid := False;
  FPage := nil;
  FPageCount := 0;
  if FSize = 0 then
    FCaret := 0
  else
    FCaret := Min(FCaret, FSize - 1);
  FAnchor := FCaret;
  if FSelStart + FSelLength > FSize then
    SetSelectionInternal(Min(FSelStart, FSize), 0);
  SetTopRow(FTopRow);
  UpdateScrollBar;
  Invalidate;
end;

procedure TMHHexView.EnsurePage;
var
  LStart, LNeed: Int64;
  LRead, LGot: Integer;
begin
  if (FSource = nil) or (FSize <= 0) then
  begin
    FPageCount := 0;
    Exit;
  end;
  LStart := FTopRow * ROW_BYTES;
  LNeed := Min(Int64(PaintRows + 1) * ROW_BYTES, FSize - LStart);
  if LNeed <= 0 then
  begin
    FPageCount := 0;
    FPageValid := False;
    Exit;
  end;
  if FPageValid and (FPageOffset = LStart) and (FPageRequested >= LNeed) then
    Exit;
  SetLength(FPage, LNeed);
  LGot := 0;
  try
    while LGot < LNeed do
    begin
      LRead := FSource.ReadAt(LStart + LGot, FPage[LGot], Integer(LNeed) - LGot);
      if LRead <= 0 then
        Break;
      Inc(LGot, LRead);
    end;
  except
    // Сбой чтения: непрочитанные байты показываются как «??».
  end;
  FPageOffset := LStart;
  FPageRequested := Integer(LNeed);
  FPageCount := LGot;
  FPageValid := True;
end;

function TMHHexView.ByteAt(AOffset: Int64; out AValue: Byte): Boolean;
var
  LIndex: Int64;
begin
  AValue := 0;
  Result := False;
  if not FPageValid then
    Exit;
  LIndex := AOffset - FPageOffset;
  if (LIndex >= 0) and (LIndex < FPageCount) then
  begin
    AValue := FPage[LIndex];
    Result := True;
  end;
end;

procedure TMHHexView.ClearHighlights;
begin
  FHighlights := nil;
  Invalidate;
end;

procedure TMHHexView.AddHighlight(AOffset, ASize: Int64; AColor: TColor; const ACaption: string);
var
  LItem: TMHHexHighlight;
begin
  if (AOffset < 0) or (ASize <= 0) then
    Exit;
  LItem.Offset := AOffset;
  LItem.Size := ASize;
  LItem.Color := AColor;
  LItem.Caption := ACaption;
  FHighlights := FHighlights + [LItem];
  Invalidate;
end;

function TMHHexView.HighlightCount: Integer;
begin
  Result := Length(FHighlights);
end;

function TMHHexView.HighlightIndexAt(AOffset: Int64): Integer;
var
  I: Integer;
begin
  for I := High(FHighlights) downto 0 do
    if (AOffset >= FHighlights[I].Offset) and (AOffset - FHighlights[I].Offset < FHighlights[I].Size) then
      Exit(I);
  Result := -1;
end;

function TMHHexView.HighlightAt(AOffset: Int64; out ACaption: string): Boolean;
var
  LIndex: Integer;
begin
  LIndex := HighlightIndexAt(AOffset);
  Result := LIndex >= 0;
  if Result then
    ACaption := FHighlights[LIndex].Caption
  else
    ACaption := '';
end;

procedure TMHHexView.SetSelectionInternal(AStart, ALength: Int64);
begin
  if (AStart = FSelStart) and (ALength = FSelLength) then
    Exit;
  FSelStart := AStart;
  FSelLength := ALength;
  Invalidate;
  if Assigned(FOnSelectionChange) then
    FOnSelectionChange(Self);
end;

procedure TMHHexView.SetSelStart(AValue: Int64);
begin
  if FSize <= 0 then
    Exit;
  AValue := EnsureRange(AValue, Int64(0), FSize - 1);
  FCaret := AValue;
  FAnchor := AValue;
  SetSelectionInternal(AValue, Min(FSelLength, FSize - AValue));
  ScrollToCaret;
end;

procedure TMHHexView.SetSelLength(AValue: Int64);
begin
  if FSize <= 0 then
    Exit;
  SetSelectionInternal(FSelStart, EnsureRange(AValue, Int64(0), FSize - FSelStart));
end;

procedure TMHHexView.SetCaretOffset(AValue: Int64);
begin
  if FSize <= 0 then
    Exit;
  MoveCaret(EnsureRange(AValue, Int64(0), FSize - 1), False);
end;

procedure TMHHexView.ScrollToCaret;
var
  LRow: Int64;
begin
  LRow := FCaret div ROW_BYTES;
  if LRow < FTopRow then
    SetTopRow(LRow)
  else if LRow >= FTopRow + VisibleRows then
    SetTopRow(LRow - VisibleRows + 1);
end;

procedure TMHHexView.MoveCaret(ANew: Int64; AExtend: Boolean);
begin
  if FSize <= 0 then
    Exit;
  FCaret := EnsureRange(ANew, Int64(0), FSize - 1);
  if not AExtend then
    FAnchor := FCaret;
  SetSelectionInternal(Min(FAnchor, FCaret), Abs(FCaret - FAnchor) + 1);
  ScrollToCaret;
  Invalidate;
end;

procedure TMHHexView.GotoOffset(AOffset: Int64; ASelectLength: Int64);
var
  LRow: Int64;
begin
  if FSize <= 0 then
    Exit;
  AOffset := EnsureRange(AOffset, Int64(0), FSize - 1);
  FCaret := AOffset;
  FAnchor := AOffset;
  LRow := AOffset div ROW_BYTES;
  if (LRow < FTopRow) or (LRow >= FTopRow + VisibleRows) then
    SetTopRow(LRow - VisibleRows div 2);
  SetSelectionInternal(AOffset, EnsureRange(ASelectLength, Int64(0), FSize - AOffset));
  Invalidate;
end;

function TMHHexView.FindNext(const APattern: TBytes; AIgnoreCase: Boolean): Boolean;
var
  LFrom, LFound: Int64;
begin
  Result := False;
  if (FSource = nil) or (FSize <= 0) or (Length(APattern) = 0) then
    Exit;
  LFrom := FCaret + 1;
  LFound := -1;
  if LFrom < FSize then
    LFound := MHFindBytes(FSource, APattern, LFrom, AIgnoreCase);
  if LFound < 0 then
    // С начала файла до места, где начинался поиск (включая текущее вхождение).
    LFound := MHFindBytes(FSource, APattern, 0, AIgnoreCase, nil,
      Min(FSize, LFrom + Length(APattern) - 1));
  if LFound < 0 then
    Exit;
  GotoOffset(LFound, Length(APattern));
  Result := True;
end;

function TMHHexView.OffsetAtPoint(X, Y: Integer; out AOffset: Int64): Boolean;
var
  LRow: Int64;
  LCol, I: Integer;
begin
  Result := False;
  AOffset := -1;
  if (FSize <= 0) or (X < 0) or (Y < 0) or (Y >= AreaHeight) then
    Exit;
  LCol := -1;
  for I := 0 to ROW_BYTES - 1 do
    if (X >= HexLeft(I)) and (X < HexLeft(I) + HexCellWidth(I)) then
    begin
      LCol := I;
      Break;
    end;
  if (LCol < 0) and (X >= AsciiLeft) and (X < AsciiLeft + ROW_BYTES * CharWidth) then
    LCol := (X - AsciiLeft) div CharWidth;
  if LCol < 0 then
    Exit;
  LRow := FTopRow + Y div RowHeight;
  AOffset := LRow * ROW_BYTES + LCol;
  if AOffset >= FSize then
  begin
    AOffset := -1;
    Exit;
  end;
  Result := True;
end;

function TMHHexView.NearestOffset(X, Y: Integer; out AOffset: Int64): Boolean;
var
  LRow: Int64;
  LCol, I: Integer;
begin
  Result := FSize > 0;
  AOffset := 0;
  if not Result then
    Exit;
  Y := EnsureRange(Y, 0, VisibleRows * RowHeight - 1);
  if X >= AsciiLeft - CharWidth then
    LCol := EnsureRange((X - AsciiLeft) div CharWidth, 0, ROW_BYTES - 1)
  else
  begin
    LCol := ROW_BYTES - 1;
    for I := 0 to ROW_BYTES - 1 do
      if X < HexLeft(I) + HexCellWidth(I) then
      begin
        LCol := I;
        Break;
      end;
  end;
  LRow := FTopRow + Y div RowHeight;
  AOffset := EnsureRange(LRow * ROW_BYTES + LCol, Int64(0), FSize - 1);
end;

function TMHHexView.PointOfOffset(AOffset: Int64; out APoint: TPoint; AAscii: Boolean): Boolean;
var
  LRow: Int64;
  LCol: Integer;
begin
  APoint := Point(-1, -1);
  Result := False;
  if (AOffset < 0) or (AOffset >= FSize) then
    Exit;
  LRow := AOffset div ROW_BYTES - FTopRow;
  if (LRow < 0) or (LRow >= VisibleRows) then
    Exit;
  LCol := AOffset mod ROW_BYTES;
  if AAscii then
    APoint.X := AsciiLeft + LCol * CharWidth + CharWidth div 2
  else
    APoint.X := HexLeft(LCol) + CharWidth;
  APoint.Y := Integer(LRow) * RowHeight + RowHeight div 2;
  Result := True;
end;

procedure TMHHexView.KeyDown(var Key: Word; Shift: TShiftState);
var
  LNew: Int64;
begin
  inherited KeyDown(Key, Shift);
  if FSize <= 0 then
    Exit;
  case Key of
    VK_LEFT: LNew := FCaret - 1;
    VK_RIGHT: LNew := FCaret + 1;
    VK_UP: LNew := FCaret - ROW_BYTES;
    VK_DOWN: LNew := FCaret + ROW_BYTES;
    VK_PRIOR:
      begin
        LNew := FCaret - Int64(VisibleRows) * ROW_BYTES;
        ScrollRows(-VisibleRows);
      end;
    VK_NEXT:
      begin
        LNew := FCaret + Int64(VisibleRows) * ROW_BYTES;
        ScrollRows(VisibleRows);
      end;
    VK_HOME:
      if ssCtrl in Shift then
        LNew := 0
      else
        LNew := FCaret - FCaret mod ROW_BYTES;
    VK_END:
      if ssCtrl in Shift then
        LNew := FSize - 1
      else
        LNew := FCaret - FCaret mod ROW_BYTES + ROW_BYTES - 1;
  else
    Exit;
  end;
  Key := 0;
  MoveCaret(LNew, ssShift in Shift);
end;

procedure TMHHexView.MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var
  LOffset: Int64;
begin
  inherited MouseDown(Button, Shift, X, Y);
  if Button <> mbLeft then
    Exit;
  // CanFocus не проверяет видимость самой формы: окно должно быть видно на экране.
  if HandleAllocated and IsWindowVisible(Handle) and CanFocus and not Focused then
    SetFocus;
  if FSize <= 0 then
    Exit;
  if OffsetAtPoint(X, Y, LOffset) then
  begin
    MoveCaret(LOffset, ssShift in Shift);
    FDragging := True;
  end;
end;

procedure TMHHexView.MouseMove(Shift: TShiftState; X, Y: Integer);
var
  LOffset: Int64;
begin
  inherited MouseMove(Shift, X, Y);
  if not FDragging or not (ssLeft in Shift) or (FSize <= 0) then
    Exit;
  // За краем окна — прокрутка во время протягивания.
  if Y < 0 then
    ScrollRows(-1)
  else if Y >= VisibleRows * RowHeight then
    ScrollRows(1);
  if NearestOffset(X, Y, LOffset) then
    MoveCaret(LOffset, True);
end;

procedure TMHHexView.MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  inherited MouseUp(Button, Shift, X, Y);
  if Button = mbLeft then
    FDragging := False;
end;

function TMHHexView.DoMouseWheel(Shift: TShiftState; WheelDelta: Integer; MousePos: TPoint): Boolean;
var
  LNotches: Integer;
begin
  Result := inherited DoMouseWheel(Shift, WheelDelta, MousePos);
  if Result then
    Exit;
  // Накопление: сенсорные панели присылают доли щелчка колеса.
  Inc(FWheelAccum, WheelDelta);
  LNotches := FWheelAccum div WHEEL_DELTA;
  Dec(FWheelAccum, LNotches * WHEEL_DELTA);
  if LNotches <> 0 then
    ScrollRows(-Int64(LNotches) * WHEEL_ROWS);
  Result := True;
end;

procedure TMHHexView.DoEnter;
begin
  inherited;
  Invalidate;
end;

procedure TMHHexView.DoExit;
begin
  inherited;
  FDragging := False;
  Invalidate;
end;

function TMHHexView.GetHintAt(X, Y: Integer; out ARect: TRect): string;
var
  LOffset: Int64;
  LCol, LRowTop: Integer;
  LValue: Byte;
  LCaption: string;
begin
  Result := inherited GetHintAt(X, Y, ARect);
  if not OffsetAtPoint(X, Y, LOffset) then
    Exit;
  LCol := LOffset mod ROW_BYTES;
  LRowTop := (Y div RowHeight) * RowHeight;
  if X >= AsciiLeft then
    ARect := Rect(AsciiLeft + LCol * CharWidth, LRowTop, AsciiLeft + (LCol + 1) * CharWidth, LRowTop + RowHeight)
  else
    ARect := Rect(HexLeft(LCol), LRowTop, HexLeft(LCol) + HexCellWidth(LCol), LRowTop + RowHeight);
  Result := MHHexOffset(LOffset);
  EnsurePage;
  if ByteAt(LOffset, LValue) then
  begin
    Result := Result + Format(': %.2X', [LValue]);
    if IsPrintable(LValue) then
      Result := Result + Format(' (''%s'')', [Char(LValue)]);
  end;
  if HighlightAt(LOffset, LCaption) and (LCaption <> '') then
    Result := Result + sLineBreak + LCaption;
end;

procedure TMHHexView.Paint;
var
  LBack, LText, LGray, LSelBack, LSelText, LLine: TColor;
  LBacks: array[0..ROW_BYTES - 1] of TColor;
  LSel: array[0..ROW_BYTES - 1] of Boolean;
  LVisible: TArray<TMHHexHighlight>;
  LFirst, LLast, LRowOffset, LOffset: Int64;
  LRow, LCol, LCount, I, Y, LCw, LRh, LRight: Integer;
  LValue: Byte;
  LHas: Boolean;
  LRect: TRect;
  LCellText: string;
begin
  PaintBackground;
  if FSize <= 0 then
  begin
    PaintMessage(MHL('Нет данных', 'No data'));
    Exit;
  end;
  EnsurePage;
  LBack := MHThemeColor(clWindow);
  LText := MHThemeColor(clWindowText);
  LGray := MHThemeColor(clGrayText);
  LSelBack := MHThemeColor(clHighlight);
  LSelText := MHThemeColor(clHighlightText);
  LLine := MHThemeColor(clBtnFace);
  LCw := CharWidth;
  LRh := RowHeight;

  // Подсветки, задевающие видимую часть (порядок сохраняется: последняя — сверху).
  LFirst := FTopRow * ROW_BYTES;
  LLast := LFirst + Int64(PaintRows) * ROW_BYTES;
  LVisible := nil;
  for I := 0 to High(FHighlights) do
    if (FHighlights[I].Offset < LLast) and (FHighlights[I].Offset + FHighlights[I].Size > LFirst) then
      LVisible := LVisible + [FHighlights[I]];

  // Разделители колонок.
  Canvas.Pen.Color := LLine;
  Canvas.MoveTo(HexStart - LCw, 0);
  Canvas.LineTo(HexStart - LCw, AreaHeight);
  Canvas.MoveTo(AsciiLeft - LCw div 2, 0);
  Canvas.LineTo(AsciiLeft - LCw div 2, AreaHeight);

  for LRow := 0 to PaintRows - 1 do
  begin
    LRowOffset := (FTopRow + LRow) * ROW_BYTES;
    if LRowOffset >= FSize then
      Break;
    Y := LRow * LRh;
    LCount := Integer(Min(Int64(ROW_BYTES), FSize - LRowOffset));

    Canvas.Brush.Style := bsClear;
    Canvas.Font.Color := LGray;
    Canvas.TextOut(Margin, Y, IntToHex(LRowOffset, OffsetDigits));

    for LCol := 0 to LCount - 1 do
    begin
      LOffset := LRowOffset + LCol;
      LSel[LCol] := (FSelLength > 0) and (LOffset >= FSelStart) and (LOffset - FSelStart < FSelLength);
      LBacks[LCol] := LBack;
      if LSel[LCol] then
        LBacks[LCol] := LSelBack
      else
        for I := High(LVisible) downto 0 do
          if (LOffset >= LVisible[I].Offset) and (LOffset - LVisible[I].Offset < LVisible[I].Size) then
          begin
            LBacks[LCol] := MHBlendColor(LVisible[I].Color, LBack, 0.35);
            Break;
          end;
    end;

    for LCol := 0 to LCount - 1 do
    begin
      LOffset := LRowOffset + LCol;
      LHas := ByteAt(LOffset, LValue);
      // Фон ячейки продолжается до следующей, если у неё такой же фон (сплошное выделение).
      if (LCol < LCount - 1) and (LBacks[LCol + 1] = LBacks[LCol]) then
        LRight := HexLeft(LCol + 1)
      else
        LRight := HexLeft(LCol) + 2 * LCw;
      if LBacks[LCol] <> LBack then
      begin
        Canvas.Brush.Style := bsSolid;
        Canvas.Brush.Color := LBacks[LCol];
        Canvas.FillRect(Rect(HexLeft(LCol), Y, LRight, Y + LRh));
        Canvas.FillRect(Rect(AsciiLeft + LCol * LCw, Y, AsciiLeft + (LCol + 1) * LCw, Y + LRh));
      end;
      Canvas.Brush.Style := bsClear;
      if LSel[LCol] then
        Canvas.Font.Color := LSelText
      else
        Canvas.Font.Color := LText;
      if LHas then
        LCellText := IntToHex(LValue, 2)
      else
        LCellText := '??';
      Canvas.TextOut(HexLeft(LCol), Y, LCellText);
      if LHas and IsPrintable(LValue) then
        LCellText := Char(LValue)
      else
        LCellText := '.';
      Canvas.TextOut(AsciiLeft + LCol * LCw, Y, LCellText);
    end;

    // Курсор — рамка вокруг байта в обеих колонках (когда элемент в фокусе).
    if Focused and (FCaret >= LRowOffset) and (FCaret < LRowOffset + LCount) then
    begin
      LCol := FCaret - LRowOffset;
      Canvas.Brush.Style := bsSolid;
      Canvas.Brush.Color := LText;
      LRect := Rect(HexLeft(LCol) - 1, Y, HexLeft(LCol) + 2 * LCw + 1, Y + LRh);
      Canvas.FrameRect(LRect);
      LRect := Rect(AsciiLeft + LCol * LCw, Y, AsciiLeft + (LCol + 1) * LCw, Y + LRh);
      Canvas.FrameRect(LRect);
    end;
  end;
  Canvas.Brush.Style := bsSolid;
end;

{ TMHEntropyMap }

constructor TMHEntropyMap.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ParentFont := True;
  FSelectedOffset := -1;
  FDownIndex := -1;
  Width := 480;
  Height := 240;
end;

class function TMHEntropyMap.EntropyColor(AEntropy: Double): TColor;
type
  TStop = record
    E: Double;
    R, G, B: Integer;
  end;
const
  STOPS: array[0..3] of TStop = (
    (E: 0.0; R: 20;  G: 36;  B: 110), // заполнение — тёмно-синий
    (E: 4.5; R: 46;  G: 160; B: 72),  // текст, таблицы — зелёный
    (E: 6.8; R: 236; G: 200; B: 40),  // код, сжатие — жёлтый
    (E: 8.0; R: 240; G: 36;  B: 32)); // шифрованные — красный
var
  I: Integer;
  T: Double;
begin
  if IsNan(AEntropy) then
    AEntropy := 0;
  AEntropy := EnsureRange(AEntropy, 0, 8);
  I := 0;
  while (I < High(STOPS) - 1) and (AEntropy > STOPS[I + 1].E) do
    Inc(I);
  T := (AEntropy - STOPS[I].E) / (STOPS[I + 1].E - STOPS[I].E);
  T := EnsureRange(T, 0, 1);
  Result := TColor(RGB(
    Round(STOPS[I].R + (STOPS[I + 1].R - STOPS[I].R) * T),
    Round(STOPS[I].G + (STOPS[I + 1].G - STOPS[I].G) * T),
    Round(STOPS[I].B + (STOPS[I + 1].B - STOPS[I].B) * T)));
end;

procedure TMHEntropyMap.SetData(const ABlocks: TArray<TMHEntropyBlock>; AFileSize: Int64);
begin
  FBlocks := Copy(ABlocks);
  FFileSize := Max(Int64(0), AFileSize);
  FDownIndex := -1;
  Invalidate;
end;

procedure TMHEntropyMap.SetBands(const ABands: TArray<TMHMapBand>);
begin
  FBands := Copy(ABands);
  Invalidate;
end;

function TMHEntropyMap.BlockCount: Integer;
begin
  Result := Length(FBlocks);
end;

function TMHEntropyMap.GetLayout: TLayout;
var
  R: TRect;
  W, H, N, C, LMin, LMax: Integer;
  LCapacity: Int64;
begin
  Result := Default(TLayout);
  R := Area;
  InflateRect(R, -S(4), -S(4));
  if Length(FBands) > 0 then
  begin
    Result.Bands := Rect(R.Left, R.Top, R.Right, R.Top + TextHeight + S(4));
    R.Top := Result.Bands.Bottom + S(4);
  end;
  Result.Legend := Rect(R.Left, R.Bottom - (S(10) + S(2) + TextHeight), R.Right, R.Bottom);
  R.Bottom := Result.Legend.Top - S(4);
  Result.Map := R;
  W := R.Width;
  H := R.Height;
  N := Length(FBlocks);
  LMin := Max(2, S(2));
  LMax := Max(LMin, S(40));
  if (N = 0) or (W < LMin) or (H < LMin) then
    Exit;
  // Наибольшая клетка, при которой все блоки помещаются.
  C := Trunc(Sqrt(W / N * H));
  C := EnsureRange(C, LMin, Min(LMax, Min(W, H)));
  while (C > LMin) and (Int64(W div C) * (H div C) < N) do
    Dec(C);
  Result.Cell := C;
  Result.Cols := W div C;
  Result.Rows := H div C;
  LCapacity := Int64(Result.Cols) * Result.Rows;
  if LCapacity >= N then
    Result.PerCell := 1
  else
    Result.PerCell := Integer((N + LCapacity - 1) div LCapacity);
  Result.CellCount := (N + Result.PerCell - 1) div Result.PerCell;
end;

function TMHEntropyMap.BlocksPerCell: Integer;
begin
  Result := Max(1, GetLayout.PerCell);
end;

function TMHEntropyMap.CellCount: Integer;
begin
  Result := GetLayout.CellCount;
end;

function TMHEntropyMap.CellRectOf(const ALayout: TLayout; ACell: Integer): TRect;
var
  LGap: Integer;
begin
  if (ACell < 0) or (ACell >= ALayout.CellCount) or (ALayout.Cols <= 0) then
    Exit(Rect(0, 0, 0, 0));
  if ALayout.Cell >= 5 then
    LGap := 1
  else
    LGap := 0;
  Result.Left := ALayout.Map.Left + (ACell mod ALayout.Cols) * ALayout.Cell;
  Result.Top := ALayout.Map.Top + (ACell div ALayout.Cols) * ALayout.Cell;
  Result.Right := Result.Left + ALayout.Cell - LGap;
  Result.Bottom := Result.Top + ALayout.Cell - LGap;
end;

function TMHEntropyMap.CellEntropy(const ALayout: TLayout; ACell: Integer): Double;
var
  I: Integer;
begin
  Result := 0;
  for I := ACell * ALayout.PerCell to Min(High(FBlocks), (ACell + 1) * ALayout.PerCell - 1) do
    Result := Max(Result, Double(FBlocks[I].Entropy));
end;

function TMHEntropyMap.CellRect(AIndex: Integer): TRect;
var
  LLayout: TLayout;
begin
  LLayout := GetLayout;
  if (AIndex < 0) or (AIndex >= Length(FBlocks)) or (LLayout.PerCell <= 0) then
    Exit(Rect(0, 0, 0, 0));
  Result := CellRectOf(LLayout, AIndex div LLayout.PerCell);
end;

function TMHEntropyMap.BlockAtPoint(X, Y: Integer; out AIndex: Integer): Boolean;
var
  LLayout: TLayout;
  LCol, LRow, LCell: Integer;
begin
  AIndex := -1;
  Result := False;
  LLayout := GetLayout;
  if (LLayout.CellCount = 0) or not LLayout.Map.Contains(Point(X, Y)) then
    Exit;
  LCol := (X - LLayout.Map.Left) div LLayout.Cell;
  LRow := (Y - LLayout.Map.Top) div LLayout.Cell;
  if (LCol >= LLayout.Cols) or (LRow >= LLayout.Rows) then
    Exit;
  LCell := LRow * LLayout.Cols + LCol;
  if LCell >= LLayout.CellCount then
    Exit;
  AIndex := LCell * LLayout.PerCell;
  Result := True;
end;

function TMHEntropyMap.BandAt(AOffset: Int64): Integer;
var
  I: Integer;
begin
  for I := High(FBands) downto 0 do
    if (AOffset >= FBands[I].Offset) and (AOffset - FBands[I].Offset < FBands[I].Size) then
      Exit(I);
  Result := -1;
end;

function TMHEntropyMap.BlockIndexOfOffset(AOffset: Int64): Integer;
var
  I: Integer;
begin
  if AOffset >= 0 then
    for I := 0 to High(FBlocks) do
      if (AOffset >= FBlocks[I].Offset) and (AOffset - FBlocks[I].Offset < Max(1, FBlocks[I].Size)) then
        Exit(I);
  Result := -1;
end;

procedure TMHEntropyMap.SetSelectedOffset(AValue: Int64);
begin
  if AValue < 0 then
    AValue := -1;
  if AValue = FSelectedOffset then
    Exit;
  FSelectedOffset := AValue;
  Invalidate;
end;

procedure TMHEntropyMap.MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  inherited MouseDown(Button, Shift, X, Y);
  if (Button <> mbLeft) or not BlockAtPoint(X, Y, FDownIndex) then
    FDownIndex := -1;
end;

procedure TMHEntropyMap.MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var
  LIndex: Integer;
  LOffset: Int64;
begin
  inherited MouseUp(Button, Shift, X, Y);
  if Button <> mbLeft then
    Exit;
  if (FDownIndex >= 0) and BlockAtPoint(X, Y, LIndex) and (LIndex = FDownIndex) then
  begin
    FDownIndex := -1;
    LOffset := FBlocks[LIndex].Offset;
    SelectedOffset := LOffset;
    if Assigned(FOnBlockClick) then
      FOnBlockClick(Self, LOffset);
  end;
  FDownIndex := -1;
end;

function TMHEntropyMap.GetHintAt(X, Y: Integer; out ARect: TRect): string;
var
  LLayout: TLayout;
  LIndex, LLastIndex, LBand: Integer;
  LEntropy: Double;
  LOffset, LEnd: Int64;
begin
  Result := inherited GetHintAt(X, Y, ARect);
  LLayout := GetLayout;
  if (Length(FBands) > 0) and LLayout.Bands.Contains(Point(X, Y)) and (FFileSize > 0) and
    (LLayout.Bands.Width > 0) then
  begin
    LOffset := Trunc((X - LLayout.Bands.Left) / LLayout.Bands.Width * FFileSize);
    LBand := BandAt(LOffset);
    if LBand >= 0 then
    begin
      ARect := Rect(X, LLayout.Bands.Top, X + 1, LLayout.Bands.Bottom);
      Result := FBands[LBand].Caption + sLineBreak +
        RangeText(FBands[LBand].Offset, FBands[LBand].Offset + FBands[LBand].Size);
    end;
    Exit;
  end;
  if not BlockAtPoint(X, Y, LIndex) then
    Exit;
  ARect := CellRect(LIndex);
  LLastIndex := Min(High(FBlocks), LIndex + LLayout.PerCell - 1);
  LEntropy := CellEntropy(LLayout, LIndex div LLayout.PerCell);
  LOffset := FBlocks[LIndex].Offset;
  LEnd := FBlocks[LLastIndex].Offset + FBlocks[LLastIndex].Size;
  Result := RangeText(LOffset, LEnd) + sLineBreak +
    MHL('Энтропия: ', 'Entropy: ') + FormatFloat('0.00', LEntropy) +
    ' (' + MHEntropyClassTitle(MHEntropyClassOf(LEntropy)) + ')';
  if LLastIndex > LIndex then
    Result := Result + sLineBreak + Format(MHL('Наибольшая из %d блоков', 'Maximum of %d blocks'),
      [LLastIndex - LIndex + 1]);
  LBand := BandAt(LOffset);
  if LBand >= 0 then
    Result := Result + sLineBreak + FBands[LBand].Caption;
end;

procedure TMHEntropyMap.PaintBands(const ALayout: TLayout);
var
  I, X1, X2, W: Integer;
  LRect: TRect;
  LText: string;
begin
  W := ALayout.Bands.Width;
  if (W <= 0) or (FFileSize <= 0) then
    Exit;
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(clBtnFace);
  Canvas.FillRect(ALayout.Bands);
  for I := 0 to High(FBands) do
  begin
    if (FBands[I].Size <= 0) or (FBands[I].Offset >= FFileSize) then
      Continue;
    X1 := ALayout.Bands.Left + Trunc(FBands[I].Offset / FFileSize * W);
    X2 := ALayout.Bands.Left + Trunc(Min(FFileSize, FBands[I].Offset + FBands[I].Size) / FFileSize * W);
    X2 := Max(X2, X1 + 1);
    LRect := Rect(X1, ALayout.Bands.Top, X2, ALayout.Bands.Bottom);
    Canvas.Brush.Style := bsSolid;
    Canvas.Brush.Color := FBands[I].Color;
    Canvas.FillRect(LRect);
    LText := FBands[I].Caption;
    if (LText <> '') and (Canvas.TextWidth(LText) + S(4) <= LRect.Width) then
    begin
      Canvas.Brush.Style := bsClear;
      Canvas.Font.Color := ContrastText(FBands[I].Color);
      Canvas.TextRect(LRect, LText, [tfCenter, tfVerticalCenter, tfSingleLine]);
    end;
  end;
  Canvas.Brush.Style := bsSolid;
end;

procedure TMHEntropyMap.PaintLegend(const ALayout: TLayout);
var
  LBar: TRect;
  I, X, LW: Integer;
  LText: string;
begin
  LW := Min(ALayout.Legend.Width, S(320));
  if (LW <= 0) or (ALayout.Legend.Height <= 0) then
    Exit;
  LBar := Rect(ALayout.Legend.Left, ALayout.Legend.Top, ALayout.Legend.Left + LW, ALayout.Legend.Top + S(10));
  for X := 0 to LW - 1 do
  begin
    Canvas.Pen.Color := EntropyColor(8 * X / Max(1, LW - 1));
    Canvas.MoveTo(LBar.Left + X, LBar.Top);
    Canvas.LineTo(LBar.Left + X, LBar.Bottom);
  end;
  Canvas.Brush.Style := bsClear;
  Canvas.Font.Color := MHThemeColor(clGrayText);
  for I := 0 to 4 do
  begin
    LText := IntToStr(I * 2);
    X := LBar.Left + MulDiv(LW - 1, I, 4) - Canvas.TextWidth(LText) div 2;
    X := EnsureRange(X, LBar.Left, Max(LBar.Left, LBar.Right - Canvas.TextWidth(LText)));
    Canvas.TextOut(X, LBar.Bottom + S(2), LText);
  end;
  LText := MHL('энтропия, бит на байт', 'entropy, bits per byte');
  X := LBar.Right + S(8);
  if X + Canvas.TextWidth(LText) <= ALayout.Legend.Right then
    Canvas.TextOut(X, LBar.Top + (LBar.Height - Canvas.TextHeight(LText)) div 2, LText);
  Canvas.Brush.Style := bsSolid;
end;

procedure TMHEntropyMap.Paint;
var
  LLayout: TLayout;
  I, LSelected: Integer;
  LRect: TRect;
begin
  PaintBackground;
  if Length(FBlocks) = 0 then
  begin
    PaintMessage(MHL('Карта появится после анализа файла', 'The map will appear after the file is analysed'));
    Exit;
  end;
  LLayout := GetLayout;
  PaintBands(LLayout);
  Canvas.Brush.Style := bsSolid;
  for I := 0 to LLayout.CellCount - 1 do
  begin
    Canvas.Brush.Color := EntropyColor(CellEntropy(LLayout, I));
    Canvas.FillRect(CellRectOf(LLayout, I));
  end;
  LSelected := BlockIndexOfOffset(FSelectedOffset);
  if (LSelected >= 0) and (LLayout.PerCell > 0) then
  begin
    LRect := CellRectOf(LLayout, LSelected div LLayout.PerCell);
    if not LRect.IsEmpty then
    begin
      InflateRect(LRect, 1, 1);
      Canvas.Brush.Color := MHThemeColor(clWindowText);
      Canvas.FrameRect(LRect);
      InflateRect(LRect, 1, 1);
      Canvas.Brush.Color := MHThemeColor(clWindow);
      Canvas.FrameRect(LRect);
    end;
  end;
  PaintLegend(LLayout);
end;

{ TMHByteHistogram }

constructor TMHByteHistogram.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ParentFont := True;
  FLogarithmic := True;
  Width := 400;
  Height := 160;
end;

procedure TMHByteHistogram.SetHistogram(const ACounts: array of Int64);
var
  I: Integer;
begin
  FTotal := 0;
  FMax := 0;
  for I := 0 to 255 do
  begin
    if I <= High(ACounts) then
      FCounts[I] := Max(Int64(0), ACounts[I])
    else
      FCounts[I] := 0;
    Inc(FTotal, FCounts[I]);
    FMax := Max(FMax, FCounts[I]);
  end;
  Invalidate;
end;

function TMHByteHistogram.GetCount(AByte: Byte): Int64;
begin
  Result := FCounts[AByte];
end;

procedure TMHByteHistogram.SetLogarithmic(AValue: Boolean);
begin
  if AValue = FLogarithmic then
    Exit;
  FLogarithmic := AValue;
  Invalidate;
end;

function TMHByteHistogram.PlotRect: TRect;
begin
  Result := Area;
  InflateRect(Result, -S(4), -S(4));
  Dec(Result.Bottom, TextHeight + S(2));
end;

function TMHByteHistogram.BarLeft(const APlot: TRect; AByte: Integer): Integer;
begin
  Result := APlot.Left + MulDiv(APlot.Width, AByte, 256);
end;

function TMHByteHistogram.BarRect(AByte: Byte): TRect;
var
  LPlot: TRect;
begin
  LPlot := PlotRect;
  if (LPlot.Width <= 0) or (LPlot.Height <= 0) then
    Exit(Rect(0, 0, 0, 0));
  Result := Rect(BarLeft(LPlot, AByte), LPlot.Top, BarLeft(LPlot, AByte + 1), LPlot.Bottom);
end;

function TMHByteHistogram.BarFraction(AByte: Byte): Double;
begin
  if (FMax <= 0) or (FCounts[AByte] <= 0) then
    Exit(0);
  if FLogarithmic then
    Result := Ln(1 + FCounts[AByte]) / Ln(1 + FMax)
  else
    Result := FCounts[AByte] / FMax;
end;

function TMHByteHistogram.ByteAtPoint(X, Y: Integer; out AByte: Byte): Boolean;
var
  LPlot: TRect;
  B: Integer;
begin
  AByte := 0;
  LPlot := PlotRect;
  Result := (LPlot.Width > 0) and (X >= LPlot.Left) and (X < LPlot.Right) and (Y >= 0) and (Y < AreaHeight);
  if not Result then
    Exit;
  B := EnsureRange(MulDiv(X - LPlot.Left, 256, LPlot.Width), 0, 255);
  // Согласование с BarRect (округление MulDiv).
  while (B < 255) and (X >= BarLeft(LPlot, B + 1)) do
    Inc(B);
  while (B > 0) and (X < BarLeft(LPlot, B)) do
    Dec(B);
  AByte := Byte(B);
end;

function TMHByteHistogram.GetHintAt(X, Y: Integer; out ARect: TRect): string;
var
  B: Byte;
  LPercent: Double;
begin
  Result := inherited GetHintAt(X, Y, ARect);
  if (FTotal <= 0) or not ByteAtPoint(X, Y, B) then
    Exit;
  ARect := BarRect(B);
  ARect.Top := 0;
  ARect.Bottom := AreaHeight;
  LPercent := FCounts[B] / FTotal * 100;
  Result := Format('%s 0x%.2X', [MHL('Байт', 'Byte'), B]);
  if IsPrintable(B) then
    Result := Result + Format(' (''%s'')', [Char(B)]);
  Result := Result + Format(': %d (%s%%)', [FCounts[B], FormatFloat('0.0', LPercent)]);
end;

procedure TMHByteHistogram.Paint;
var
  LPlot, LBar: TRect;
  I, X, H: Integer;
  LZero, LText, LOther, LAxis: TColor;
  LLabels: array[0..2] of Integer;
  LCaption: string;
begin
  PaintBackground;
  if FTotal <= 0 then
  begin
    PaintMessage(MHL('Нет данных', 'No data'));
    Exit;
  end;
  LPlot := PlotRect;
  if (LPlot.Width <= 0) or (LPlot.Height <= 0) then
    Exit;
  LZero := TColor($00909090);  // 0x00 — заполнение
  LText := TColor($00C08030);  // печатные ASCII — синий
  LOther := TColor($002E86E0); // прочие значения — оранжевый
  LAxis := MHThemeColor(clGrayText);
  Canvas.Brush.Style := bsSolid;
  for I := 0 to 255 do
  begin
    H := Round(BarFraction(I) * LPlot.Height);
    if (H = 0) and (FCounts[I] > 0) then
      H := 1;
    if H = 0 then
      Continue;
    LBar := Rect(BarLeft(LPlot, I), LPlot.Bottom - H, Max(BarLeft(LPlot, I + 1), BarLeft(LPlot, I) + 1), LPlot.Bottom);
    if I = 0 then
      Canvas.Brush.Color := LZero
    else if IsPrintable(I) then
      Canvas.Brush.Color := LText
    else
      Canvas.Brush.Color := LOther;
    Canvas.FillRect(LBar);
  end;
  Canvas.Pen.Color := LAxis;
  Canvas.MoveTo(LPlot.Left, LPlot.Bottom);
  Canvas.LineTo(LPlot.Right, LPlot.Bottom);
  Canvas.Brush.Style := bsClear;
  Canvas.Font.Color := LAxis;
  LLabels[0] := $00;
  LLabels[1] := $7F;
  LLabels[2] := $FF;
  for I := 0 to High(LLabels) do
  begin
    LCaption := IntToHex(LLabels[I], 2);
    X := (BarLeft(LPlot, LLabels[I]) + BarLeft(LPlot, LLabels[I] + 1)) div 2 - Canvas.TextWidth(LCaption) div 2;
    X := EnsureRange(X, LPlot.Left, Max(LPlot.Left, LPlot.Right - Canvas.TextWidth(LCaption)));
    Canvas.TextOut(X, LPlot.Bottom + S(2), LCaption);
  end;
  Canvas.Brush.Style := bsSolid;
end;

{ TMHRangeStrip }

constructor TMHRangeStrip.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ParentFont := True;
  FRangeColor := TColor($002E86E0);
  Width := 400;
  Height := 24;
end;

procedure TMHRangeStrip.SetRanges(const ARanges: TArray<TMHByteRange>; AFileSize: Int64; AColor: TColor);
begin
  FRanges := Copy(ARanges);
  FFileSize := Max(Int64(0), AFileSize);
  FRangeColor := AColor;
  Invalidate;
end;

function TMHRangeStrip.TrackRect: TRect;
begin
  Result := Area;
  InflateRect(Result, -1, -1);
end;

function TMHRangeStrip.XOfOffset(const ATrack: TRect; AOffset: Int64): Integer;
begin
  if FFileSize <= 0 then
    Exit(ATrack.Left);
  Result := ATrack.Left + Trunc(EnsureRange(AOffset, Int64(0), FFileSize) / FFileSize * ATrack.Width);
end;

function TMHRangeStrip.RangeSpan(const ATrack: TRect; AIndex: Integer): TRect;
var
  X1, X2: Integer;
begin
  X1 := XOfOffset(ATrack, FRanges[AIndex].Offset);
  X2 := XOfOffset(ATrack, FRanges[AIndex].Offset + Max(Int64(0), FRanges[AIndex].Size));
  X2 := Max(X2, X1 + 1); // не уже 1 пикселя
  Result := Rect(X1, ATrack.Top, X2, ATrack.Bottom);
end;

function TMHRangeStrip.OffsetAtX(X: Integer): Int64;
var
  LTrack: TRect;
  LRel, W: Integer;
begin
  LTrack := TrackRect;
  W := LTrack.Width;
  if (FFileSize <= 0) or (W <= 0) then
    Exit(0);
  LRel := X - LTrack.Left;
  if LRel <= 0 then
    Exit(0);
  if LRel >= W - 1 then
    Exit(FFileSize - 1);
  Result := EnsureRange(Trunc(LRel / W * FFileSize), Int64(0), FFileSize - 1);
end;

function TMHRangeStrip.RangeAtX(X: Integer; out AIndex: Integer): Boolean;
var
  LTrack, LSpan: TRect;
  I: Integer;
begin
  AIndex := -1;
  LTrack := TrackRect;
  if (FFileSize <= 0) or (LTrack.Width <= 0) then
    Exit(False);
  for I := 0 to High(FRanges) do
  begin
    if FRanges[I].Offset >= FFileSize then
      Continue;
    LSpan := RangeSpan(LTrack, I);
    if (X >= LSpan.Left) and (X < LSpan.Right) then
    begin
      AIndex := I;
      Exit(True);
    end;
  end;
  Result := False;
end;

procedure TMHRangeStrip.MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  inherited MouseDown(Button, Shift, X, Y);
  FMouseDown := Button = mbLeft;
end;

procedure TMHRangeStrip.MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var
  LIndex: Integer;
  LOffset: Int64;
begin
  inherited MouseUp(Button, Shift, X, Y);
  if (Button <> mbLeft) or not FMouseDown then
    Exit;
  FMouseDown := False;
  if (FFileSize <= 0) or (X < 0) or (X >= AreaWidth) or (Y < 0) or (Y >= AreaHeight) then
    Exit;
  if RangeAtX(X, LIndex) then
    LOffset := FRanges[LIndex].Offset
  else
    LOffset := OffsetAtX(X);
  if Assigned(FOnOffsetClick) then
    FOnOffsetClick(Self, LOffset);
end;

function TMHRangeStrip.GetHintAt(X, Y: Integer; out ARect: TRect): string;
var
  LIndex: Integer;
begin
  Result := inherited GetHintAt(X, Y, ARect);
  if FFileSize <= 0 then
    Exit;
  ARect := Rect(X, 0, X + 1, AreaHeight);
  Result := MHHexOffset(OffsetAtX(X));
  if RangeAtX(X, LIndex) then
    Result := Result + sLineBreak + MHL('Изменено: ', 'Changed: ') +
      RangeText(FRanges[LIndex].Offset, FRanges[LIndex].Offset + FRanges[LIndex].Size) +
      Format(MHL(' (%d байт)', ' (%d bytes)'), [FRanges[LIndex].Size]);
end;

procedure TMHRangeStrip.Paint;
var
  LTrack: TRect;
  I: Integer;
begin
  PaintBackground;
  LTrack := TrackRect;
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(clBtnShadow);
  Canvas.FrameRect(Area);
  if (LTrack.Width <= 0) or (LTrack.Height <= 0) then
    Exit;
  Canvas.Brush.Color := MHBlendColor(MHThemeColor(clBtnFace), MHThemeColor(clWindow), 0.6);
  Canvas.FillRect(LTrack);
  if FFileSize <= 0 then
    Exit;
  Canvas.Brush.Color := FRangeColor;
  for I := 0 to High(FRanges) do
    if FRanges[I].Offset < FFileSize then
      Canvas.FillRect(RangeSpan(LTrack, I));
end;

end.
