unit MineHunter.Tests.UI.BinaryLabControls;

{
  Элементы BinaryLab: шестнадцатеричный просмотр (виртуальное чтение,
  навигация, выделение, подсветка, поиск, файлы больше 4 ГБ), карта
  энтропии, гистограмма байтов и полоса диапазонов. Формы не показываются:
  элементы создаются на скрытой форме, ввод — сообщениями самим элементам,
  рисование — в растр через PaintTo.
}

interface

uses
  System.SysUtils, System.Classes, System.Types, System.UITypes,
  DUnitX.TestFramework,
  Vcl.Forms, Vcl.Controls, Vcl.Graphics,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source,
  MineHunter.App.BinaryLab.Controls;

type
  /// Доступ к защищённым обработчикам клавиатуры и колеса.
  TTestHexView = class(TMHHexView)
  public
    procedure PressKey(AKey: Word; AShift: TShiftState = []);
    function Wheel(ADelta: Integer): Boolean;
  end;

  /// Виртуальный источник заданного размера (байты вычисляются по смещению);
  /// запоминает самое большое чтение.
  TVirtualSource = class(TInterfacedObject, IMHBinarySource)
  private
    FSize: Int64;
    FMaxRead: Integer;
    FReads: Integer;
  public
    constructor Create(ASize: Int64);
    function GetSize: Int64;
    function GetName: string;
    function ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
    property MaxRead: Integer read FMaxRead;
    property Reads: Integer read FReads;
  end;

  [TestFixture]
  [Category('UI,BinaryLab')]
  THexViewTests = class
  private
    FForm: TForm;
    FView: TTestHexView;
    FChanges: Integer;
    procedure SelectionChanged(Sender: TObject);
    procedure SetData(ASize: Integer);
    procedure AssertOffsetVisible(AOffset: Int64);
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Rows_CountAndVisible;
    [Test] procedure Goto_ScrollsIntoViewAndSelects;
    [Test] procedure Goto_VisibleOffset_DoesNotScroll;
    [Test] procedure TopOffset_RowAlignedAndClamped;
    [Test] procedure Keys_MoveCaret;
    [Test] procedure Keys_PageDownAndCtrlEnd;
    [Test] procedure ShiftKeys_ExtendSelection;
    [Test] procedure SelectionProperties_Clamped;
    [Test] procedure OffsetAtPoint_InverseOfPointOfOffset;
    [Test] procedure OffsetAtPoint_OutsideColumns_False;
    [Test] procedure Mouse_ClickSelectsAndDragExtends;
    [Test] procedure Wheel_ScrollsThreeRowsPerNotch;
    [Test] procedure ScrollBarMessages_Scroll;
    [Test] procedure Highlights_LookupAndHint;
    [Test] procedure FindNext_FindsWrapsAndKeepsPositionWhenMissing;
    [Test] procedure FindNext_IgnoreCase;
    [Test] procedure NilSource_Safe;
    [Test] procedure BigVirtualSource_ScrollsToEndAndReadsOnlyPage;
    [Test] procedure HugeSource_ScrollBarScaled;
    [Test] procedure Paint_NormalAndTiny;
    [Test] procedure BeforeHandle_Safe;
  end;

  [TestFixture]
  [Category('UI,BinaryLab')]
  TEntropyMapTests = class
  private
    FForm: TForm;
    FMap: TMHEntropyMap;
    FClicked: Int64;
    FClicks: Integer;
    procedure BlockClicked(Sender: TObject; AOffset: Int64);
    procedure SetBlocks(ACount: Integer);
    procedure Click(const APoint: TPoint);
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Cells_ConsistentWithBlockAtPoint;
    [Test] procedure ManyBlocks_Aggregated;
    [Test] procedure ManyBlocks_PerCellIsMinimal;
    [Test] procedure Click_RaisesBlockOffset;
    [Test] procedure SelectedOffset_Highlights;
    [Test] procedure EntropyColor_ScaleMonotonicAndDistinctEnds;
    [Test] procedure Hint_RangeEntropyAndBand;
    [Test] procedure Paint_CellColourAndEmptyAndTiny;
  end;

  [TestFixture]
  [Category('UI,BinaryLab')]
  THistogramTests = class
  private
    FForm: TForm;
    FHistogram: TMHByteHistogram;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure ByteAtPoint_MatchesBars;
    [Test] procedure ByteAtPoint_UnevenWidth_EveryByteReachable;
    [Test] procedure Scale_LogarithmicAndLinear;
    [Test] procedure Hint_ByteCountPercent;
    [Test] procedure Hint_SpaceIsPrintable;
    [Test] procedure BarRect_PlotWithoutWidthOrHeight_Empty;
    [Test] procedure Paint_NormalEmptyTiny;
  end;

  [TestFixture]
  [Category('UI,BinaryLab')]
  TRangeStripTests = class
  private
    FForm: TForm;
    FStrip: TMHRangeStrip;
    FClicked: Int64;
    FClicks: Integer;
    procedure OffsetClicked(Sender: TObject; AOffset: Int64);
    procedure ClickAt(X: Integer);
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure OffsetAtX_Endpoints;
    [Test] procedure Click_OnRangeGivesStart_ElsewhereComputed;
    [Test] procedure NarrowRange_AtLeastOnePixel;
    [Test] procedure ZeroFileSize_Safe;
  end;

  [TestFixture]
  [Category('UI,BinaryLab')]
  TBinaryLabDarkThemeTests = class
  public
    [Test] procedure AllControls_PaintInDarkTheme;
  end;

implementation

uses
  System.Math, Winapi.Windows, Winapi.Messages,
  MineHunter.Core.Lang, MineHunter.Core.Settings, MineHunter.App.Theme;

function MakeForm: TForm;
begin
  Result := TForm.CreateNew(nil);
  Result.SetBounds(0, 0, 900, 700);
end;

/// Рисует элемент в растр (без показа окна) и возвращает растр.
function Render(AControl: TWinControl): Vcl.Graphics.TBitmap;
begin
  Result := Vcl.Graphics.TBitmap.Create;
  try
    Result.PixelFormat := pf24bit;
    Result.SetSize(Max(1, AControl.Width), Max(1, AControl.Height));
    AControl.PaintTo(Result.Canvas.Handle, 0, 0);
  except
    Result.Free;
    raise;
  end;
end;

procedure RenderAndFree(AControl: TWinControl);
begin
  Render(AControl).Free;
end;

function Center(const ARect: TRect): TPoint;
begin
  Result := Point((ARect.Left + ARect.Right) div 2, (ARect.Top + ARect.Bottom) div 2);
end;

function MouseParam(X, Y: Integer): LPARAM;
begin
  Result := MakeLParam(Word(X), Word(Y));
end;

{ TTestHexView }

procedure TTestHexView.PressKey(AKey: Word; AShift: TShiftState);
begin
  KeyDown(AKey, AShift);
end;

function TTestHexView.Wheel(ADelta: Integer): Boolean;
begin
  Result := DoMouseWheel([], ADelta, Point(10, 10));
end;

{ TVirtualSource }

constructor TVirtualSource.Create(ASize: Int64);
begin
  inherited Create;
  FSize := ASize;
end;

function TVirtualSource.GetName: string;
begin
  Result := 'virtual';
end;

function TVirtualSource.GetSize: Int64;
begin
  Result := FSize;
end;

function TVirtualSource.ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
var
  P: PByte;
  I: Integer;
begin
  Inc(FReads);
  FMaxRead := Max(FMaxRead, ACount);
  if (AOffset < 0) or (AOffset >= FSize) or (ACount <= 0) then
    Exit(0);
  Result := Integer(Min(Int64(ACount), FSize - AOffset));
  P := @ABuffer;
  for I := 0 to Result - 1 do
    P[I] := Byte((AOffset + I) mod 251);
end;

{ THexViewTests }

procedure THexViewTests.Setup;
begin
  FForm := MakeForm;
  FView := TTestHexView.Create(FForm);
  FView.Parent := FForm;
  FView.SetBounds(0, 0, 700, 320);
  FView.OnSelectionChange := SelectionChanged;
  FView.HandleNeeded;
  FChanges := 0;
end;

procedure THexViewTests.TearDown;
begin
  FForm.Free;
end;

procedure THexViewTests.SelectionChanged(Sender: TObject);
begin
  Inc(FChanges);
end;

procedure THexViewTests.SetData(ASize: Integer);
var
  LData: TBytes;
  I: Integer;
begin
  SetLength(LData, ASize);
  for I := 0 to ASize - 1 do
    LData[I] := Byte(I mod 251);
  FView.Source := TMHBytesSource.Create(LData);
end;

procedure THexViewTests.AssertOffsetVisible(AOffset: Int64);
var
  LRow, LTopRow: Int64;
begin
  LRow := AOffset div 16;
  LTopRow := FView.TopOffset div 16;
  Assert.IsTrue((LRow >= LTopRow) and (LRow < LTopRow + FView.VisibleRows),
    Format('Смещение %d видно (первая строка %d, видно строк %d)', [AOffset, LTopRow, FView.VisibleRows]));
end;

procedure THexViewTests.Rows_CountAndVisible;
begin
  SetData(100 * 1024);
  Assert.AreEqual<Int64>(6400, FView.RowCount);
  Assert.AreEqual(16, FView.BytesPerRow);
  Assert.IsTrue(FView.VisibleRows > 0);
  Assert.IsTrue(FView.VisibleRows < 100, 'Видна только часть файла');
  Assert.AreEqual(8, FView.OffsetDigits);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  Assert.AreEqual<Int64>(0, FView.SelLength, 'После смены источника ничего не выделено');
  Assert.IsTrue(FView.ContentWidth > 0);
end;

procedure THexViewTests.Goto_ScrollsIntoViewAndSelects;
var
  P: TPoint;
  LRow: Int64;
begin
  SetData(100 * 1024);
  FChanges := 0;
  FView.GotoOffset(50000, 4);
  Assert.AreEqual<Int64>(50000, FView.SelStart);
  Assert.AreEqual<Int64>(4, FView.SelLength);
  Assert.AreEqual<Int64>(50000, FView.CaretOffset);
  Assert.IsTrue(FChanges > 0, 'OnSelectionChange');
  AssertOffsetVisible(50000);
  Assert.IsTrue(FView.PointOfOffset(50000, P));
  // Примерно по центру: не у самого края.
  LRow := 50000 div 16 - FView.TopOffset div 16;
  Assert.IsTrue((LRow > 0) and (LRow < FView.VisibleRows - 1), 'Строка не у края');
  // Длина выделения обрезается у конца файла, смещение — в пределах файла.
  FView.GotoOffset(100 * 1024 - 2, 100);
  Assert.AreEqual<Int64>(100 * 1024 - 2, FView.SelStart);
  Assert.AreEqual<Int64>(2, FView.SelLength);
  FView.GotoOffset(10 * 1024 * 1024);
  Assert.AreEqual<Int64>(100 * 1024 - 1, FView.SelStart);
  FView.GotoOffset(-5);
  Assert.AreEqual<Int64>(0, FView.SelStart);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
end;

procedure THexViewTests.Goto_VisibleOffset_DoesNotScroll;
var
  LTop: Int64;
begin
  SetData(100 * 1024);
  FView.TopOffset := 16 * 100;
  LTop := FView.TopOffset;
  FView.GotoOffset(LTop + 16 * 2 + 5);
  Assert.AreEqual<Int64>(LTop, FView.TopOffset, 'Видимое смещение — без прокрутки');
  Assert.AreEqual<Int64>(LTop + 37, FView.SelStart);
end;

procedure THexViewTests.TopOffset_RowAlignedAndClamped;
var
  LMaxTop: Int64;
begin
  SetData(100 * 1024);
  FView.TopOffset := 1000 + 5;
  Assert.AreEqual<Int64>(0, FView.TopOffset mod 16, 'Выравнивание по строке');
  Assert.AreEqual<Int64>(992, FView.TopOffset);
  FView.TopOffset := -100;
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  FView.TopOffset := High(Int64) div 2;
  LMaxTop := (FView.RowCount - FView.VisibleRows) * 16;
  Assert.AreEqual<Int64>(LMaxTop, FView.TopOffset, 'Ограничение у конца: последняя строка внизу');
  // Файл меньше окна — прокрутки нет.
  SetData(100);
  FView.TopOffset := 64;
  Assert.AreEqual<Int64>(0, FView.TopOffset);
end;

procedure THexViewTests.Keys_MoveCaret;
begin
  SetData(100 * 1024);
  FView.PressKey(VK_RIGHT);
  Assert.AreEqual<Int64>(1, FView.CaretOffset);
  Assert.AreEqual<Int64>(1, FView.SelStart);
  Assert.AreEqual<Int64>(1, FView.SelLength);
  FView.PressKey(VK_DOWN);
  Assert.AreEqual<Int64>(17, FView.CaretOffset);
  FView.PressKey(VK_END);
  Assert.AreEqual<Int64>(31, FView.CaretOffset, 'End — конец строки');
  FView.PressKey(VK_HOME);
  Assert.AreEqual<Int64>(16, FView.CaretOffset, 'Home — начало строки');
  FView.PressKey(VK_UP);
  Assert.AreEqual<Int64>(0, FView.CaretOffset);
  FView.PressKey(VK_LEFT);
  Assert.AreEqual<Int64>(0, FView.CaretOffset, 'Не уходит за начало');
  FView.PressKey(VK_UP);
  Assert.AreEqual<Int64>(0, FView.CaretOffset);
end;

procedure THexViewTests.Keys_PageDownAndCtrlEnd;
var
  LSize: Int64;
begin
  SetData(100 * 1024);
  LSize := 100 * 1024;
  FView.PressKey(VK_NEXT);
  Assert.AreEqual<Int64>(Int64(FView.VisibleRows) * 16, FView.CaretOffset);
  Assert.AreEqual<Int64>(Int64(FView.VisibleRows) * 16, FView.TopOffset, 'Страница прокручена');
  AssertOffsetVisible(FView.CaretOffset);
  FView.PressKey(VK_PRIOR);
  Assert.AreEqual<Int64>(0, FView.CaretOffset);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  FView.PressKey(VK_END, [ssCtrl]);
  Assert.AreEqual<Int64>(LSize - 1, FView.CaretOffset, 'Ctrl+End — конец файла');
  AssertOffsetVisible(LSize - 1);
  FView.PressKey(VK_RIGHT);
  Assert.AreEqual<Int64>(LSize - 1, FView.CaretOffset, 'Не уходит за конец');
  FView.PressKey(VK_NEXT);
  Assert.AreEqual<Int64>(LSize - 1, FView.CaretOffset);
  FView.PressKey(VK_HOME, [ssCtrl]);
  Assert.AreEqual<Int64>(0, FView.CaretOffset, 'Ctrl+Home — начало файла');
  Assert.AreEqual<Int64>(0, FView.TopOffset);
end;

procedure THexViewTests.ShiftKeys_ExtendSelection;
begin
  SetData(100 * 1024);
  FView.CaretOffset := 10;
  FView.PressKey(VK_RIGHT, [ssShift]);
  FView.PressKey(VK_RIGHT, [ssShift]);
  FView.PressKey(VK_RIGHT, [ssShift]);
  Assert.AreEqual<Int64>(10, FView.SelStart);
  Assert.AreEqual<Int64>(4, FView.SelLength);
  Assert.AreEqual<Int64>(13, FView.CaretOffset);
  // Через опорную точку в обратную сторону.
  FView.PressKey(VK_LEFT, [ssShift]);
  FView.PressKey(VK_LEFT, [ssShift]);
  FView.PressKey(VK_LEFT, [ssShift]);
  FView.PressKey(VK_LEFT, [ssShift]);
  FView.PressKey(VK_LEFT, [ssShift]);
  Assert.AreEqual<Int64>(8, FView.SelStart);
  Assert.AreEqual<Int64>(3, FView.SelLength);
  FView.PressKey(VK_DOWN, [ssShift]);
  FView.PressKey(VK_DOWN, [ssShift]);
  Assert.AreEqual<Int64>(10, FView.SelStart);
  Assert.AreEqual<Int64>(40, FView.CaretOffset);
  Assert.AreEqual<Int64>(31, FView.SelLength, '10..40');
  // Без Shift выделение сбрасывается на байт под курсором.
  FView.PressKey(VK_RIGHT);
  Assert.AreEqual<Int64>(41, FView.SelStart);
  Assert.AreEqual<Int64>(1, FView.SelLength);
end;

procedure THexViewTests.SelectionProperties_Clamped;
begin
  SetData(1000);
  FView.SelStart := 990;
  FView.SelLength := 100;
  Assert.AreEqual<Int64>(990, FView.SelStart);
  Assert.AreEqual<Int64>(10, FView.SelLength, 'Обрезано у конца');
  FView.SelStart := 5000;
  Assert.AreEqual<Int64>(999, FView.SelStart);
  Assert.AreEqual<Int64>(1, FView.SelLength);
  FView.SelLength := -3;
  Assert.AreEqual<Int64>(0, FView.SelLength);
  FView.CaretOffset := -10;
  Assert.AreEqual<Int64>(0, FView.CaretOffset);
end;

procedure THexViewTests.OffsetAtPoint_InverseOfPointOfOffset;
const
  COLS: array[0..6] of Integer = (0, 1, 7, 8, 9, 14, 15);
var
  LTop, LOffset, LFound: Int64;
  LRow, I: Integer;
  P: TPoint;
  LAscii: Boolean;
begin
  SetData(100 * 1024);
  FView.TopOffset := 16 * 500;
  LTop := FView.TopOffset;
  // Цикл ниже проверяет каждую видимую строку — их должно быть несколько.
  Assert.IsTrue(FView.VisibleRows >= 2, Format('Видимых строк: %d', [FView.VisibleRows]));
  for LAscii := False to True do
    for LRow := 0 to FView.VisibleRows - 1 do
      for I := 0 to High(COLS) do
      begin
        LOffset := LTop + LRow * 16 + COLS[I];
        Assert.IsTrue(FView.PointOfOffset(LOffset, P, LAscii), Format('Точка для %d', [LOffset]));
        Assert.IsTrue(FView.OffsetAtPoint(P.X, P.Y, LFound), Format('Байт в точке %d,%d', [P.X, P.Y]));
        Assert.AreEqual<Int64>(LOffset, LFound);
      end;
  // Невидимые байты точки не имеют.
  Assert.IsFalse(FView.PointOfOffset(LTop - 1, P));
  Assert.IsFalse(FView.PointOfOffset(LTop + Int64(FView.VisibleRows) * 16, P));
  Assert.IsFalse(FView.PointOfOffset(-1, P));
end;

procedure THexViewTests.OffsetAtPoint_OutsideColumns_False;
var
  LOffset: Int64;
  P: TPoint;
begin
  SetData(100);
  // Колонка смещений.
  Assert.IsFalse(FView.OffsetAtPoint(2, 2, LOffset));
  Assert.IsFalse(FView.OffsetAtPoint(-1, 2, LOffset));
  Assert.IsFalse(FView.OffsetAtPoint(FView.ContentWidth + 50, 2, LOffset));
  // За последним байтом короткой последней строки (100 = 6 строк + 4 байта).
  Assert.IsTrue(FView.PointOfOffset(99, P));
  Assert.IsTrue(FView.OffsetAtPoint(P.X, P.Y, LOffset));
  Assert.AreEqual<Int64>(99, LOffset);
  Assert.IsTrue(FView.PointOfOffset(96, P));
  Assert.IsFalse(FView.OffsetAtPoint(P.X, P.Y + 20 * FView.Height div FView.VisibleRows, LOffset),
    'Ниже последней строки байтов нет');
end;

procedure THexViewTests.Mouse_ClickSelectsAndDragExtends;
var
  P, P2: TPoint;
begin
  SetData(100 * 1024);
  Assert.IsTrue(FView.PointOfOffset(37, P));
  FChanges := 0;
  FView.Perform(WM_LBUTTONDOWN, MK_LBUTTON, MouseParam(P.X, P.Y));
  Assert.AreEqual<Int64>(37, FView.SelStart);
  Assert.AreEqual<Int64>(1, FView.SelLength);
  Assert.IsTrue(FChanges > 0);
  Assert.IsTrue(FView.PointOfOffset(70, P2, True));
  FView.Perform(WM_MOUSEMOVE, MK_LBUTTON, MouseParam(P2.X, P2.Y));
  FView.Perform(WM_LBUTTONUP, 0, MouseParam(P2.X, P2.Y));
  Assert.AreEqual<Int64>(37, FView.SelStart);
  Assert.AreEqual<Int64>(34, FView.SelLength, '37..70, протягивание в символьную колонку');
  // После отпускания движение мыши выделение не меняет.
  FView.Perform(WM_MOUSEMOVE, 0, MouseParam(P.X, P.Y));
  Assert.AreEqual<Int64>(34, FView.SelLength);
  // Shift+щелчок расширяет от опорной точки.
  Assert.IsTrue(FView.PointOfOffset(5, P));
  FView.Perform(WM_LBUTTONDOWN, MK_LBUTTON or MK_SHIFT, MouseParam(P.X, P.Y));
  FView.Perform(WM_LBUTTONUP, MK_SHIFT, MouseParam(P.X, P.Y));
  Assert.AreEqual<Int64>(5, FView.SelStart);
  Assert.AreEqual<Int64>(33, FView.SelLength, '5..37');
end;

procedure THexViewTests.Wheel_ScrollsThreeRowsPerNotch;
begin
  SetData(100 * 1024);
  Assert.IsTrue(FView.Wheel(-WHEEL_DELTA));
  Assert.AreEqual<Int64>(48, FView.TopOffset);
  FView.Wheel(-2 * WHEEL_DELTA);
  Assert.AreEqual<Int64>(144, FView.TopOffset);
  FView.Wheel(WHEEL_DELTA);
  Assert.AreEqual<Int64>(96, FView.TopOffset);
  // Доли щелчка накапливаются.
  FView.Wheel(-WHEEL_DELTA div 2);
  Assert.AreEqual<Int64>(96, FView.TopOffset);
  FView.Wheel(-WHEEL_DELTA div 2);
  Assert.AreEqual<Int64>(144, FView.TopOffset);
  FView.Wheel(100 * WHEEL_DELTA);
  Assert.AreEqual<Int64>(0, FView.TopOffset, 'Не выше начала');
end;

procedure THexViewTests.ScrollBarMessages_Scroll;
var
  LInfo: TScrollInfo;
begin
  SetData(100 * 1024);
  FView.Perform(WM_VSCROLL, SB_LINEDOWN, 0);
  Assert.AreEqual<Int64>(16, FView.TopOffset);
  FView.Perform(WM_VSCROLL, SB_PAGEDOWN, 0);
  Assert.AreEqual<Int64>(16 + Int64(FView.VisibleRows) * 16, FView.TopOffset);
  FView.Perform(WM_VSCROLL, SB_BOTTOM, 0);
  Assert.AreEqual<Int64>((FView.RowCount - FView.VisibleRows) * 16, FView.TopOffset);
  FillChar(LInfo, SizeOf(LInfo), 0);
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.fMask := SIF_ALL;
  Assert.IsTrue(GetScrollInfo(FView.Handle, SB_VERT, LInfo));
  Assert.AreEqual<Int64>(FView.RowCount - FView.VisibleRows, LInfo.nPos, 'Позиция полосы — номер строки');
  Assert.AreEqual(FView.VisibleRows, Integer(LInfo.nPage));
  FView.Perform(WM_VSCROLL, SB_TOP, 0);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  FView.Perform(WM_VSCROLL, SB_LINEUP, 0);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
end;

procedure THexViewTests.Highlights_LookupAndHint;
var
  LCaption, LHint: string;
  P: TPoint;
begin
  SetData(100 * 1024);
  FView.AddHighlight(100, 20, clRed, 'Заголовок DOS');
  FView.AddHighlight(110, 5, clBlue, 'e_lfanew');
  FView.AddHighlight(-1, 5, clBlue, 'неверная');
  FView.AddHighlight(500, 0, clBlue, 'пустая');
  Assert.AreEqual(2, FView.HighlightCount, 'Неверные диапазоны не добавляются');
  Assert.IsTrue(FView.HighlightAt(100, LCaption));
  Assert.AreEqual('Заголовок DOS', LCaption);
  Assert.IsTrue(FView.HighlightAt(112, LCaption));
  Assert.AreEqual('e_lfanew', LCaption, 'Добавленная позже — сверху');
  Assert.IsTrue(FView.HighlightAt(119, LCaption));
  Assert.AreEqual('Заголовок DOS', LCaption);
  Assert.IsFalse(FView.HighlightAt(120, LCaption));
  Assert.IsFalse(FView.HighlightAt(99, LCaption));
  Assert.IsTrue(FView.PointOfOffset(112, P));
  LHint := FView.HintTextAt(P.X, P.Y);
  Assert.Contains(LHint, '0x00000070');
  Assert.Contains(LHint, 'e_lfanew');
  Assert.Contains(LHint, Format('%.2X', [112 mod 251]), 'Значение байта');
  Assert.AreEqual('', FView.HintTextAt(2, 2), 'Колонка смещений — без подсказки');
  RenderAndFree(FView);
  FView.ClearHighlights;
  Assert.IsFalse(FView.HighlightAt(112, LCaption));
  // Новый источник — подсветки прежнего файла не переносятся.
  FView.AddHighlight(0, 10, clRed, 'x');
  SetData(1000);
  Assert.AreEqual(0, FView.HighlightCount);
end;

procedure THexViewTests.FindNext_FindsWrapsAndKeepsPositionWhenMissing;
var
  LData: TBytes;
begin
  SetLength(LData, 100 * 1024);
  FillChar(LData[0], Length(LData), 0);
  LData[1000] := Ord('M');
  LData[1001] := Ord('Z');
  LData[70000] := Ord('M');
  LData[70001] := Ord('Z');
  FView.Source := TMHBytesSource.Create(LData);
  Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));
  Assert.AreEqual<Int64>(1000, FView.SelStart);
  Assert.AreEqual<Int64>(2, FView.SelLength);
  Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));
  Assert.AreEqual<Int64>(70000, FView.SelStart);
  AssertOffsetVisible(70000);
  Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')), 'Переход в начало');
  Assert.AreEqual<Int64>(1000, FView.SelStart);
  AssertOffsetVisible(1000);
  Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('QQQ')));
  Assert.AreEqual<Int64>(1000, FView.SelStart, 'Не найдено — позиция прежняя');
  Assert.AreEqual<Int64>(2, FView.SelLength);
  Assert.IsFalse(FView.FindNext(nil), 'Пустой шаблон');
  // Единственное вхождение под курсором находится снова.
  LData[70000] := 0;
  FView.Source := TMHBytesSource.Create(LData);
  FView.GotoOffset(1000);
  Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));
  Assert.AreEqual<Int64>(1000, FView.SelStart);
end;

procedure THexViewTests.FindNext_IgnoreCase;
var
  LData: TBytes;
begin
  LData := TEncoding.ASCII.GetBytes('....This Program cannot be run....');
  FView.Source := TMHBytesSource.Create(LData);
  Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('this program')));
  Assert.AreEqual<Int64>(0, FView.SelLength);
  Assert.IsTrue(FView.FindNext(TEncoding.ASCII.GetBytes('this program'), True));
  Assert.AreEqual<Int64>(4, FView.SelStart);
  Assert.AreEqual<Int64>(12, FView.SelLength);
end;

procedure THexViewTests.NilSource_Safe;
var
  LOffset: Int64;
  P: TPoint;
  LKey: Word;
begin
  FView.Source := nil;
  Assert.AreEqual<Int64>(0, FView.RowCount);
  Assert.AreEqual<Int64>(0, FView.DataSize);
  RenderAndFree(FView);
  for LKey in TArray<Word>.Create(VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN, VK_PRIOR, VK_NEXT, VK_HOME, VK_END) do
  begin
    FView.PressKey(LKey);
    FView.PressKey(LKey, [ssShift]);
    FView.PressKey(LKey, [ssCtrl]);
  end;
  FView.Wheel(-WHEEL_DELTA);
  FView.Wheel(WHEEL_DELTA);
  FView.Perform(WM_VSCROLL, SB_PAGEDOWN, 0);
  FView.Perform(WM_VSCROLL, SB_BOTTOM, 0);
  FView.Perform(WM_VSCROLL, SB_THUMBTRACK, 0);
  FView.Perform(WM_LBUTTONDOWN, MK_LBUTTON, MouseParam(200, 10));
  FView.Perform(WM_MOUSEMOVE, MK_LBUTTON, MouseParam(300, 50));
  FView.Perform(WM_LBUTTONUP, 0, MouseParam(300, 50));
  FView.GotoOffset(100);
  FView.SelStart := 5;
  FView.SelLength := 5;
  FView.CaretOffset := 5;
  FView.TopOffset := 1000;
  Assert.IsFalse(FView.FindNext(TEncoding.ASCII.GetBytes('MZ')));
  Assert.IsFalse(FView.OffsetAtPoint(200, 10, LOffset));
  Assert.IsFalse(FView.PointOfOffset(0, P));
  Assert.AreEqual('', FView.HintTextAt(200, 10));
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  Assert.AreEqual<Int64>(0, FView.SelLength);
  // Пустой файл — то же самое.
  FView.Source := TMHBytesSource.Create(nil);
  FView.PressKey(VK_END, [ssCtrl]);
  RenderAndFree(FView);
  Assert.AreEqual<Int64>(0, FView.CaretOffset);
end;

procedure THexViewTests.BigVirtualSource_ScrollsToEndAndReadsOnlyPage;
const
  SIZE_6GB = Int64(6) * 1024 * 1024 * 1024;
var
  LSource: TVirtualSource;
  LKeep: IMHBinarySource;
  P: TPoint;
  LOffset: Int64;
  LHint: string;
begin
  LSource := TVirtualSource.Create(SIZE_6GB + 5);
  LKeep := LSource;
  FView.Source := LKeep;
  Assert.AreEqual(12, FView.OffsetDigits, 'Больше 4 ГБ — 12 цифр смещения');
  Assert.AreEqual<Int64>((SIZE_6GB + 5 + 15) div 16, FView.RowCount);
  RenderAndFree(FView);
  FView.PressKey(VK_END, [ssCtrl]);
  Assert.AreEqual<Int64>(SIZE_6GB + 4, FView.CaretOffset);
  Assert.AreEqual<Int64>((FView.RowCount - FView.VisibleRows) * 16, FView.TopOffset);
  AssertOffsetVisible(SIZE_6GB + 4);
  RenderAndFree(FView);
  Assert.IsTrue(FView.PointOfOffset(SIZE_6GB + 4, P));
  Assert.IsTrue(FView.OffsetAtPoint(P.X, P.Y, LOffset));
  Assert.AreEqual<Int64>(SIZE_6GB + 4, LOffset);
  LHint := FView.HintTextAt(P.X, P.Y);
  Assert.Contains(LHint, MHHexOffset(SIZE_6GB + 4));
  FView.GotoOffset(SIZE_6GB div 2, 16);
  AssertOffsetVisible(SIZE_6GB div 2);
  RenderAndFree(FView);
  Assert.IsTrue(LSource.MaxRead <= 64 * 1024, Format('Читается только видимая страница (%d байт)', [LSource.MaxRead]));
  Assert.IsTrue(LSource.Reads > 0);
  FView.Perform(WM_VSCROLL, SB_TOP, 0);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
end;

procedure THexViewTests.HugeSource_ScrollBarScaled;
const
  SIZE_16TB = Int64(16) * 1024 * 1024 * 1024 * 1024;
var
  LInfo: TScrollInfo;
begin
  // Строк больше, чем вмещает 32-битная полоса прокрутки, — позиция масштабируется.
  FView.Source := TVirtualSource.Create(SIZE_16TB);
  FView.PressKey(VK_END, [ssCtrl]);
  Assert.AreEqual<Int64>(SIZE_16TB - 1, FView.CaretOffset);
  FillChar(LInfo, SizeOf(LInfo), 0);
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.fMask := SIF_ALL;
  Assert.IsTrue(GetScrollInfo(FView.Handle, SB_VERT, LInfo));
  Assert.AreEqual(LInfo.nMax, LInfo.nPos, 'В конце — бегунок внизу');
  Assert.IsTrue(LInfo.nMax > 0);
  FView.GotoOffset(SIZE_16TB div 2);
  Assert.IsTrue(GetScrollInfo(FView.Handle, SB_VERT, LInfo));
  Assert.IsTrue(Abs(LInfo.nPos - LInfo.nMax div 2) <= 1, 'Середина файла — середина полосы');
  RenderAndFree(FView);
  FView.Perform(WM_VSCROLL, SB_TOP, 0);
  Assert.AreEqual<Int64>(0, FView.TopOffset);
  FView.Perform(WM_VSCROLL, SB_PAGEDOWN, 0);
  Assert.AreEqual<Int64>(Int64(FView.VisibleRows) * 16, FView.TopOffset);
end;

procedure THexViewTests.Paint_NormalAndTiny;
begin
  SetData(100 * 1024);
  FView.GotoOffset(100, 40);
  FView.AddHighlight(90, 30, clGreen, 'поле');
  RenderAndFree(FView);
  FView.SetBounds(0, 0, 1, 1);
  RenderAndFree(FView);
  Assert.IsTrue(FView.VisibleRows >= 1);
  FView.PressKey(VK_NEXT);
  FView.Wheel(-WHEEL_DELTA);
  FView.SetBounds(0, 0, 0, 0);
  RenderAndFree(FView);
  FView.SetBounds(0, 0, 700, 320);
  RenderAndFree(FView);
end;

procedure THexViewTests.BeforeHandle_Safe;
var
  LView: TMHHexView;
  LOffset: Int64;
  P: TPoint;
begin
  // Без родителя и окна: все методы работают, окна не создаются.
  LView := TMHHexView.Create(nil);
  try
    LView.Source := TVirtualSource.Create(100000);
    LView.GotoOffset(50000, 3);
    LView.TopOffset := 1600;
    LView.AddHighlight(0, 10, clRed, 'x');
    Assert.IsTrue(LView.FindNext(TBytes.Create(0)));
    Assert.IsTrue(LView.PointOfOffset(LView.TopOffset, P));
    Assert.IsTrue(LView.OffsetAtPoint(P.X, P.Y, LOffset));
    Assert.AreEqual<Int64>(LView.TopOffset, LOffset);
    Assert.IsFalse(LView.HandleAllocated);
  finally
    LView.Free;
  end;
end;

{ TEntropyMapTests }

procedure TEntropyMapTests.Setup;
begin
  FForm := MakeForm;
  FMap := TMHEntropyMap.Create(FForm);
  FMap.Parent := FForm;
  FMap.SetBounds(0, 0, 480, 240);
  FMap.OnBlockClick := BlockClicked;
  FMap.HandleNeeded;
  FClicked := -1;
  FClicks := 0;
end;

procedure TEntropyMapTests.TearDown;
begin
  FForm.Free;
end;

procedure TEntropyMapTests.BlockClicked(Sender: TObject; AOffset: Int64);
begin
  FClicked := AOffset;
  Inc(FClicks);
end;

procedure TEntropyMapTests.SetBlocks(ACount: Integer);
var
  LBlocks: TArray<TMHEntropyBlock>;
  I: Integer;
begin
  SetLength(LBlocks, ACount);
  for I := 0 to ACount - 1 do
  begin
    LBlocks[I].Offset := Int64(I) * 4096;
    LBlocks[I].Size := 4096;
    if ACount > 1 then
      LBlocks[I].Entropy := 8 * I / (ACount - 1)
    else
      LBlocks[I].Entropy := 4;
  end;
  FMap.SetData(LBlocks, Int64(ACount) * 4096);
end;

procedure TEntropyMapTests.Click(const APoint: TPoint);
begin
  FMap.Perform(WM_LBUTTONDOWN, MK_LBUTTON, MouseParam(APoint.X, APoint.Y));
  FMap.Perform(WM_LBUTTONUP, 0, MouseParam(APoint.X, APoint.Y));
end;

procedure TEntropyMapTests.Cells_ConsistentWithBlockAtPoint;
const
  INDICES: array[0..6] of Integer = (0, 1, 9, 10, 50, 98, 99);
var
  I, LIndex: Integer;
  R: TRect;
begin
  SetBlocks(100);
  Assert.AreEqual(1, FMap.BlocksPerCell);
  Assert.AreEqual(100, FMap.CellCount);
  for I in INDICES do
  begin
    R := FMap.CellRect(I);
    Assert.IsFalse(R.IsEmpty, Format('Клетка %d', [I]));
    Assert.IsTrue(FMap.ClientRect.Contains(R.TopLeft));
    Assert.IsTrue(FMap.BlockAtPoint(Center(R).X, Center(R).Y, LIndex));
    Assert.AreEqual(I, LIndex);
    Assert.IsTrue(FMap.BlockAtPoint(R.Left, R.Top, LIndex));
    Assert.AreEqual(I, LIndex, 'Левый верхний угол клетки');
  end;
  Assert.IsFalse(FMap.CellRect(0).IntersectsWith(FMap.CellRect(1)));
  Assert.IsTrue(FMap.CellRect(1).Left > FMap.CellRect(0).Left, 'Слева направо');
  Assert.IsTrue(FMap.CellRect(99).Top > FMap.CellRect(0).Top, 'Сверху вниз');
  Assert.IsTrue(FMap.CellRect(100).IsEmpty);
  Assert.IsTrue(FMap.CellRect(-1).IsEmpty);
  Assert.IsFalse(FMap.BlockAtPoint(0, 0, LIndex), 'Поле вокруг карты');
  Assert.IsFalse(FMap.BlockAtPoint(FMap.Width - 1, FMap.Height - 1, LIndex), 'Легенда');
end;

procedure TEntropyMapTests.ManyBlocks_Aggregated;
const
  N = 100000;
var
  LPer, LIndex, I: Integer;
  R: TRect;
begin
  SetBlocks(N);
  LPer := FMap.BlocksPerCell;
  Assert.IsTrue(LPer > 1, 'Блоков больше, чем клеток — сведение');
  Assert.IsTrue(Int64(FMap.CellCount) * LPer >= N);
  Assert.IsTrue(Int64(FMap.CellCount - 1) * LPer < N);
  for I in TArray<Integer>.Create(0, 1, LPer, 12345, N - 1) do
  begin
    R := FMap.CellRect(I);
    Assert.IsFalse(R.IsEmpty);
    Assert.IsTrue(R.Width >= 1);
    Assert.IsTrue(FMap.BlockAtPoint(Center(R).X, Center(R).Y, LIndex));
    Assert.AreEqual((I div LPer) * LPer, LIndex, 'Первый блок клетки');
  end;
  Assert.IsTrue(FMap.CellRect(N - 1).Bottom <= FMap.Height, 'Все клетки внутри элемента');
  Assert.Contains(FMap.HintTextAt(Center(FMap.CellRect(0)).X, Center(FMap.CellRect(0)).Y),
    IntToStr(LPer));
  RenderAndFree(FMap);
end;

procedure TEntropyMapTests.ManyBlocks_PerCellIsMinimal;
var
  LLow, LHigh, LMid, LCapacity: Integer;
begin
  // Ёмкость сетки при самой мелкой клетке — наибольшее число блоков, которые ещё
  // не сводятся (до неё клетка только уменьшается, блоков в клетке — 1).
  LLow := 1;
  LHigh := 200000;
  SetBlocks(LHigh);
  Assert.IsTrue(FMap.BlocksPerCell > 1);
  while LHigh - LLow > 1 do
  begin
    LMid := (LLow + LHigh) div 2;
    SetBlocks(LMid);
    if FMap.BlocksPerCell = 1 then
      LLow := LMid
    else
      LHigh := LMid;
  end;
  LCapacity := LLow;
  SetBlocks(LCapacity);
  Assert.AreEqual(LCapacity, FMap.CellCount, 'Все клетки заняты');
  // Ровно вдвое больше блоков — по два в клетке, клеток столько же.
  SetBlocks(2 * LCapacity);
  Assert.AreEqual(2, FMap.BlocksPerCell, 'Наименьшее число блоков в клетке');
  Assert.AreEqual(LCapacity, FMap.CellCount);
  SetBlocks(2 * LCapacity + 1);
  Assert.AreEqual(3, FMap.BlocksPerCell);
  Assert.IsTrue(FMap.CellCount <= LCapacity);
end;

procedure TEntropyMapTests.Click_RaisesBlockOffset;
begin
  SetBlocks(100);
  Click(Center(FMap.CellRect(37)));
  Assert.AreEqual(1, FClicks);
  Assert.AreEqual<Int64>(37 * 4096, FClicked);
  Assert.AreEqual<Int64>(37 * 4096, FMap.SelectedOffset);
  Click(Point(0, 0));
  Assert.AreEqual(1, FClicks, 'Вне карты — без события');
  // Нажатие на одном блоке, отпускание на другом — не щелчок.
  FMap.Perform(WM_LBUTTONDOWN, MK_LBUTTON, MouseParam(Center(FMap.CellRect(1)).X, Center(FMap.CellRect(1)).Y));
  FMap.Perform(WM_LBUTTONUP, 0, MouseParam(Center(FMap.CellRect(2)).X, Center(FMap.CellRect(2)).Y));
  Assert.AreEqual(1, FClicks);
  // Правая кнопка — не щелчок.
  FMap.Perform(WM_RBUTTONDOWN, MK_RBUTTON, MouseParam(Center(FMap.CellRect(3)).X, Center(FMap.CellRect(3)).Y));
  FMap.Perform(WM_RBUTTONUP, 0, MouseParam(Center(FMap.CellRect(3)).X, Center(FMap.CellRect(3)).Y));
  Assert.AreEqual(1, FClicks);
end;

procedure TEntropyMapTests.SelectedOffset_Highlights;
begin
  SetBlocks(100);
  Assert.AreEqual<Int64>(-1, FMap.SelectedOffset);
  FMap.SelectedOffset := 5 * 4096 + 10;
  Assert.AreEqual<Int64>(5 * 4096 + 10, FMap.SelectedOffset);
  RenderAndFree(FMap);
  FMap.SelectedOffset := -7;
  Assert.AreEqual<Int64>(-1, FMap.SelectedOffset);
  FMap.SelectedOffset := Int64(1000) * 4096; // за концом — ничего не подсвечивается
  RenderAndFree(FMap);
end;

procedure TEntropyMapTests.EntropyColor_ScaleMonotonicAndDistinctEnds;
var
  E: Double;
  LPrev, LRed: Integer;
  C0, C8: TColor;
begin
  LPrev := -1;
  E := 4.5;
  while E <= 8.0001 do
  begin
    LRed := GetRValue(ColorToRGB(TMHEntropyMap.EntropyColor(E)));
    Assert.IsTrue(LRed >= LPrev, Format('Красный не убывает: %.2f', [E]));
    LPrev := LRed;
    E := E + 0.05;
  end;
  C0 := TMHEntropyMap.EntropyColor(0);
  C8 := TMHEntropyMap.EntropyColor(8);
  Assert.AreNotEqual(Integer(C0), Integer(C8));
  Assert.IsTrue(GetBValue(C0) > GetRValue(C0), '0 — синий');
  Assert.IsTrue(GetRValue(C8) > GetGValue(C8) + 100, '8 — красный');
  Assert.IsTrue(GetGValue(TMHEntropyMap.EntropyColor(4.5)) > GetRValue(TMHEntropyMap.EntropyColor(4.5)), '4.5 — зелёный');
  Assert.AreEqual(Integer(C0), Integer(TMHEntropyMap.EntropyColor(-3)));
  Assert.AreEqual(Integer(C8), Integer(TMHEntropyMap.EntropyColor(12)));
  Assert.AreEqual(Integer(C0), Integer(TMHEntropyMap.EntropyColor(NaN)));
end;

procedure TEntropyMapTests.Hint_RangeEntropyAndBand;
var
  LBands: TArray<TMHMapBand>;
  LHint: string;
  P: TPoint;
begin
  SetBlocks(100);
  SetLength(LBands, 2);
  LBands[0].Offset := 0;
  LBands[0].Size := 50 * 4096;
  LBands[0].Caption := '.text';
  LBands[0].Color := clSkyBlue;
  LBands[1].Offset := 90 * 4096;
  LBands[1].Size := 10 * 4096;
  LBands[1].Caption := MHL('оверлей', 'overlay');
  LBands[1].Color := clMaroon;
  FMap.SetBands(LBands);
  P := Center(FMap.CellRect(10));
  LHint := FMap.HintTextAt(P.X, P.Y);
  Assert.Contains(LHint, MHHexOffset(10 * 4096));
  Assert.Contains(LHint, MHHexOffset(11 * 4096));
  Assert.Contains(LHint, FormatFloat('0.00', Single(8 * 10 / 99)));
  Assert.Contains(LHint, MHEntropyClassTitle(MHEntropyClassOf(Single(8 * 10 / 99))));
  Assert.Contains(LHint, '.text');
  P := Center(FMap.CellRect(99));
  LHint := FMap.HintTextAt(P.X, P.Y);
  Assert.Contains(LHint, FormatFloat('0.00', 8));
  Assert.Contains(LHint, LBands[1].Caption);
  P := Center(FMap.CellRect(70));
  Assert.IsFalse(FMap.HintTextAt(P.X, P.Y).Contains('.text'), 'Вне раздела');
  Assert.AreEqual('', FMap.HintTextAt(0, 0));
  // Полоса разделов сверху: подсказка — название раздела.
  Assert.IsTrue(FMap.CellRect(0).Top > 20, 'Полоса разделов над картой');
  Assert.Contains(FMap.HintTextAt(10, 10), '.text');
  RenderAndFree(FMap);
end;

procedure TEntropyMapTests.Paint_CellColourAndEmptyAndTiny;
var
  LBitmap: Vcl.Graphics.TBitmap;
  P: TPoint;
  LIndex: Integer;
begin
  SetBlocks(100);
  LBitmap := Render(FMap);
  try
    P := Center(FMap.CellRect(0));
    Assert.AreEqual(Integer(ColorToRGB(TMHEntropyMap.EntropyColor(0))), Integer(LBitmap.Canvas.Pixels[P.X, P.Y]));
    P := Center(FMap.CellRect(99));
    Assert.AreEqual(Integer(ColorToRGB(TMHEntropyMap.EntropyColor(8))), Integer(LBitmap.Canvas.Pixels[P.X, P.Y]));
  finally
    LBitmap.Free;
  end;
  FMap.SetData(nil, 0);
  Assert.AreEqual(0, FMap.CellCount);
  Assert.IsTrue(FMap.CellRect(0).IsEmpty);
  Assert.IsFalse(FMap.BlockAtPoint(100, 100, LIndex));
  Assert.AreEqual('', FMap.HintTextAt(100, 100));
  Click(Point(100, 100));
  Assert.AreEqual(0, FClicks);
  RenderAndFree(FMap);
  SetBlocks(1);
  Assert.AreEqual(1, FMap.CellCount);
  RenderAndFree(FMap);
  SetBlocks(5000);
  FMap.SetBounds(0, 0, 1, 1);
  RenderAndFree(FMap);
  Assert.AreEqual(0, FMap.CellCount);
  Assert.IsFalse(FMap.BlockAtPoint(0, 0, LIndex));
  Click(Point(0, 0));
  FMap.SetBounds(0, 0, 0, 0);
  RenderAndFree(FMap);
  FMap.SetBounds(0, 0, 30, 30);
  RenderAndFree(FMap);
  FMap.SetBounds(0, 0, 480, 240);
  RenderAndFree(FMap);
end;

{ THistogramTests }

procedure THistogramTests.Setup;
begin
  FForm := MakeForm;
  FHistogram := TMHByteHistogram.Create(FForm);
  FHistogram.Parent := FForm;
  FHistogram.SetBounds(0, 0, 520, 160);
  FHistogram.HandleNeeded;
end;

procedure THistogramTests.TearDown;
begin
  FForm.Free;
end;

procedure THistogramTests.ByteAtPoint_MatchesBars;
var
  LCounts: array[0..255] of Int64;
  I: Integer;
  B: Byte;
  R: TRect;
begin
  for I := 0 to 255 do
    LCounts[I] := I + 1;
  FHistogram.SetHistogram(LCounts);
  for I in [0, 1, $41, $7F, $80, $FE, $FF] do
  begin
    R := FHistogram.BarRect(I);
    Assert.IsTrue(R.Width >= 1);
    Assert.IsTrue(FHistogram.ByteAtPoint(R.Left, Center(R).Y, B));
    Assert.AreEqual(I, Integer(B), 'Левый край столбца');
    Assert.IsTrue(FHistogram.ByteAtPoint(R.Right - 1, Center(R).Y, B));
    Assert.AreEqual(I, Integer(B), 'Правый край столбца');
  end;
  Assert.IsTrue(FHistogram.BarRect(1).Left >= FHistogram.BarRect(0).Right, 'Столбцы не перекрываются');
  Assert.IsFalse(FHistogram.ByteAtPoint(0, 50, B), 'Поле слева');
  Assert.IsFalse(FHistogram.ByteAtPoint(FHistogram.Width - 1, 50, B), 'Поле справа');
  Assert.IsFalse(FHistogram.ByteAtPoint(100, -1, B));
end;

procedure THistogramTests.ByteAtPoint_UnevenWidth_EveryByteReachable;
var
  I: Integer;
  B: Byte;
  R: TRect;
begin
  FHistogram.SetHistogram([1, 2, 3]);
  FHistogram.SetBounds(0, 0, 300, 120);
  for I := 0 to 255 do
  begin
    R := FHistogram.BarRect(I);
    Assert.IsTrue(R.Width >= 1, Format('Столбец %d виден', [I]));
    Assert.IsTrue(FHistogram.ByteAtPoint(Center(R).X, Center(R).Y, B));
    Assert.AreEqual(I, Integer(B));
  end;
  Assert.AreEqual<Int64>(3, FHistogram.Counts[2]);
  Assert.AreEqual<Int64>(0, FHistogram.Counts[3], 'Недостающие — ноль');
  Assert.AreEqual<Int64>(6, FHistogram.Total);
end;

procedure THistogramTests.Scale_LogarithmicAndLinear;
var
  LCounts: array[0..255] of Int64;
  LLog: Double;
begin
  FillChar(LCounts, SizeOf(LCounts), 0);
  LCounts[0] := 1000000;
  LCounts[1] := 10;
  FHistogram.SetHistogram(LCounts);
  Assert.IsTrue(FHistogram.Logarithmic, 'По умолчанию — логарифмическая шкала');
  Assert.AreEqual(1.0, FHistogram.BarFraction(0), 1e-9);
  LLog := FHistogram.BarFraction(1);
  Assert.IsTrue(LLog > 0.1, 'Редкое значение заметно');
  Assert.AreEqual(0.0, FHistogram.BarFraction(2), 1e-9);
  FHistogram.Logarithmic := False;
  Assert.AreEqual(1.0, FHistogram.BarFraction(0), 1e-9);
  Assert.AreEqual(10 / 1000000, FHistogram.BarFraction(1), 1e-12);
  Assert.IsTrue(FHistogram.BarFraction(1) < LLog);
  RenderAndFree(FHistogram);
end;

procedure THistogramTests.Hint_ByteCountPercent;
var
  LCounts: array[0..255] of Int64;
  LHint: string;
  R: TRect;
begin
  FillChar(LCounts, SizeOf(LCounts), 0);
  LCounts[$41] := 1234;
  LCounts[$00] := 8766;
  FHistogram.SetHistogram(LCounts);
  R := FHistogram.BarRect($41);
  LHint := FHistogram.HintTextAt(Center(R).X, Center(R).Y);
  Assert.Contains(LHint, '0x41');
  Assert.Contains(LHint, '(''A'')');
  Assert.Contains(LHint, '1234');
  Assert.Contains(LHint, FormatFloat('0.0', 12.34) + '%');
  R := FHistogram.BarRect(0);
  LHint := FHistogram.HintTextAt(Center(R).X, Center(R).Y);
  Assert.Contains(LHint, '0x00');
  Assert.IsFalse(LHint.Contains(''''), 'Непечатный байт — без символа');
  Assert.AreEqual('', FHistogram.HintTextAt(0, 0));
end;

procedure THistogramTests.Hint_SpaceIsPrintable;
var
  LCounts: array[0..255] of Int64;
  I: Integer;
  R: TRect;
begin
  for I := 0 to 255 do
    LCounts[I] := 10;
  FHistogram.SetHistogram(LCounts);
  R := FHistogram.BarRect($20);
  Assert.Contains(FHistogram.HintTextAt(Center(R).X, Center(R).Y), '0x20 ('' '')', 'Пробел — печатный символ');
  R := FHistogram.BarRect($1F);
  Assert.DoesNotContain(FHistogram.HintTextAt(Center(R).X, Center(R).Y), '(''', 'Управляющий символ не показывается');
  R := FHistogram.BarRect($7F);
  Assert.DoesNotContain(FHistogram.HintTextAt(Center(R).X, Center(R).Y), '(''');
end;

procedure THistogramTests.BarRect_PlotWithoutWidthOrHeight_Empty;
var
  LCounts: array[0..255] of Int64;
  I: Integer;
begin
  for I := 0 to 255 do
    LCounts[I] := I + 1;
  FHistogram.SetHistogram(LCounts);
  // Нет ширины при достаточной высоте и нет высоты при достаточной ширине — столбцов нет.
  FHistogram.SetBounds(0, 0, 2, 160);
  Assert.IsTrue(FHistogram.BarRect(10) = Rect(0, 0, 0, 0), 'Нет ширины');
  FHistogram.SetBounds(0, 0, 520, 2);
  Assert.IsTrue(FHistogram.BarRect(10) = Rect(0, 0, 0, 0), 'Нет высоты');
  FHistogram.SetBounds(0, 0, 520, 160);
  Assert.IsFalse(FHistogram.BarRect(10).IsEmpty);
end;

procedure THistogramTests.Paint_NormalEmptyTiny;
var
  LCounts: array[0..255] of Int64;
  I: Integer;
  B: Byte;
begin
  RenderAndFree(FHistogram); // ещё нет данных
  for I := 0 to 255 do
    LCounts[I] := I * I;
  FHistogram.SetHistogram(LCounts);
  RenderAndFree(FHistogram);
  FHistogram.Logarithmic := False;
  RenderAndFree(FHistogram);
  FHistogram.SetBounds(0, 0, 1, 1);
  RenderAndFree(FHistogram);
  Assert.IsFalse(FHistogram.ByteAtPoint(0, 0, B));
  Assert.IsTrue(FHistogram.BarRect(10).IsEmpty);
  Assert.AreEqual('', FHistogram.HintTextAt(0, 0));
  FHistogram.SetBounds(0, 0, 0, 0);
  RenderAndFree(FHistogram);
  FHistogram.SetBounds(0, 0, 100, 60);
  RenderAndFree(FHistogram);
  FHistogram.SetHistogram([]);
  Assert.AreEqual<Int64>(0, FHistogram.Total);
  RenderAndFree(FHistogram);
end;

{ TRangeStripTests }

procedure TRangeStripTests.Setup;
var
  LRanges: TArray<TMHByteRange>;
begin
  FForm := MakeForm;
  FStrip := TMHRangeStrip.Create(FForm);
  FStrip.Parent := FForm;
  FStrip.SetBounds(0, 0, 400, 24);
  FStrip.OnOffsetClick := OffsetClicked;
  FStrip.HandleNeeded;
  SetLength(LRanges, 2);
  LRanges[0].Offset := 1000;
  LRanges[0].Size := 10;
  LRanges[1].Offset := 50000;
  LRanges[1].Size := 5000;
  FStrip.SetRanges(LRanges, 100000, clRed);
  FClicked := -1;
  FClicks := 0;
end;

procedure TRangeStripTests.TearDown;
begin
  FForm.Free;
end;

procedure TRangeStripTests.OffsetClicked(Sender: TObject; AOffset: Int64);
begin
  FClicked := AOffset;
  Inc(FClicks);
end;

procedure TRangeStripTests.ClickAt(X: Integer);
begin
  FStrip.Perform(WM_LBUTTONDOWN, MK_LBUTTON, MouseParam(X, 10));
  FStrip.Perform(WM_LBUTTONUP, 0, MouseParam(X, 10));
end;

procedure TRangeStripTests.OffsetAtX_Endpoints;
var
  X: Integer;
  LPrev, LOffset: Int64;
begin
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0));
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(1));
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(-50));
  Assert.AreEqual<Int64>(99999, FStrip.OffsetAtX(FStrip.Width - 2));
  Assert.AreEqual<Int64>(99999, FStrip.OffsetAtX(FStrip.Width + 100));
  LOffset := FStrip.OffsetAtX(FStrip.Width div 2);
  Assert.IsTrue(Abs(LOffset - 50000) < 1000, 'Середина полосы — середина файла');
  LPrev := -1;
  for X := 0 to FStrip.Width do
  begin
    LOffset := FStrip.OffsetAtX(X);
    Assert.IsTrue(LOffset >= LPrev, 'Смещение растёт слева направо');
    LPrev := LOffset;
  end;
  Assert.Contains(FStrip.HintTextAt(FStrip.Width div 2, 10), '0x0000');
end;

procedure TRangeStripTests.Click_OnRangeGivesStart_ElsewhereComputed;
var
  LIndex, X: Integer;
begin
  // Диапазон 50000..55000: середина его пикселей.
  X := 0;
  while (X < FStrip.Width) and not (FStrip.RangeAtX(X, LIndex) and (LIndex = 1)) do
    Inc(X);
  Assert.IsTrue(X < FStrip.Width, 'Диапазон нарисован');
  ClickAt(X + 3);
  Assert.AreEqual(1, FClicks);
  Assert.AreEqual<Int64>(50000, FClicked, 'Щелчок по диапазону — его начало');
  Assert.Contains(FStrip.HintTextAt(X + 3, 10), MHHexOffset(50000));
  ClickAt(300);
  Assert.AreEqual(2, FClicks);
  Assert.AreEqual<Int64>(FStrip.OffsetAtX(300), FClicked, 'Вне диапазонов — смещение под указателем');
  Assert.IsFalse(FStrip.RangeAtX(300, LIndex));
  RenderAndFree(FStrip);
end;

procedure TRangeStripTests.NarrowRange_AtLeastOnePixel;
var
  LIndex, X, LHits: Integer;
begin
  // Диапазон 10 байт из 100000 — меньше пикселя, но рисуется и попадает под щелчок.
  LHits := 0;
  for X := 0 to FStrip.Width - 1 do
    if FStrip.RangeAtX(X, LIndex) and (LIndex = 0) then
    begin
      Inc(LHits);
      if LHits = 1 then
      begin
        ClickAt(X);
        Assert.AreEqual<Int64>(1000, FClicked);
      end;
    end;
  Assert.AreEqual(1, LHits, 'Ровно 1 пиксель');
end;

procedure TRangeStripTests.ZeroFileSize_Safe;
var
  LIndex: Integer;
begin
  FStrip.SetRanges(nil, 0, clRed);
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(100));
  Assert.IsFalse(FStrip.RangeAtX(100, LIndex));
  ClickAt(100);
  Assert.AreEqual(0, FClicks, 'Пустой файл — без события');
  Assert.AreEqual('', FStrip.HintTextAt(100, 10));
  RenderAndFree(FStrip);
  FStrip.SetBounds(0, 0, 1, 1);
  RenderAndFree(FStrip);
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0));
  FStrip.SetBounds(0, 0, 0, 0);
  RenderAndFree(FStrip);
  FStrip.SetRanges([], 100, clRed);
  Assert.AreEqual<Int64>(0, FStrip.OffsetAtX(0), 'Нулевая ширина');
  ClickAt(0);
  RenderAndFree(FStrip);
end;

{ TBinaryLabDarkThemeTests }

procedure TBinaryLabDarkThemeTests.AllControls_PaintInDarkTheme;
var
  LForm: TForm;
  LView: TMHHexView;
  LMap: TMHEntropyMap;
  LHistogram: TMHByteHistogram;
  LStrip: TMHRangeStrip;
  LBlocks: TArray<TMHEntropyBlock>;
  LRanges: TArray<TMHByteRange>;
  LCounts: array[0..255] of Int64;
  I: Integer;
begin
  if not MHDarkThemeAvailable then
    Exit;
  LForm := MakeForm;
  try
    LView := TMHHexView.Create(LForm);
    LView.Parent := LForm;
    LView.SetBounds(0, 0, 700, 300);
    LView.Source := TVirtualSource.Create(100000);
    LView.GotoOffset(100, 40);
    LView.AddHighlight(90, 30, clGreen, 'поле');
    LMap := TMHEntropyMap.Create(LForm);
    LMap.Parent := LForm;
    LMap.SetBounds(0, 300, 480, 200);
    SetLength(LBlocks, 64);
    for I := 0 to High(LBlocks) do
    begin
      LBlocks[I].Offset := I * 4096;
      LBlocks[I].Size := 4096;
      LBlocks[I].Entropy := I / 8;
    end;
    LMap.SetData(LBlocks, 64 * 4096);
    LMap.SelectedOffset := 4096 * 3;
    LHistogram := TMHByteHistogram.Create(LForm);
    LHistogram.Parent := LForm;
    LHistogram.SetBounds(0, 500, 400, 120);
    for I := 0 to 255 do
      LCounts[I] := I;
    LHistogram.SetHistogram(LCounts);
    LStrip := TMHRangeStrip.Create(LForm);
    LStrip.Parent := LForm;
    LStrip.SetBounds(0, 630, 400, 24);
    SetLength(LRanges, 1);
    LRanges[0].Offset := 100;
    LRanges[0].Size := 5000;
    LStrip.SetRanges(LRanges, 100000, clRed);
    LForm.HandleNeeded;
    Assert.IsTrue(MHApplyTheme(utDark));
    try
      Assert.IsTrue(MHIsDarkTheme);
      RenderAndFree(LView);
      RenderAndFree(LMap);
      RenderAndFree(LHistogram);
      RenderAndFree(LStrip);
      // Форма освобождается при активном стиле: VCL снимает обработчики стиля
      // (освобождение после возврата к системному стилю оставляет их висеть,
      // и следующее переключение темы обращается к удалённой форме).
      FreeAndNil(LForm);
    finally
      MHApplyTheme(utLight);
    end;
  finally
    LForm.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(THexViewTests);
  TDUnitX.RegisterTestFixture(TEntropyMapTests);
  TDUnitX.RegisterTestFixture(THistogramTests);
  TDUnitX.RegisterTestFixture(TRangeStripTests);
  TDUnitX.RegisterTestFixture(TBinaryLabDarkThemeTests);

end.
