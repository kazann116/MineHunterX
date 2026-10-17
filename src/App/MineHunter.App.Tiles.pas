unit MineHunter.App.Tiles;

{
  Элементы страницы «Обзор»:
    - TMHMetricTile — карточка показателя: заголовок, крупное значение,
      пояснение и цветная полоса состояния;
    - TMHReasonList — список причин с цветной отметкой у каждой строки,
      высота подстраивается под текст.
  Состояние передаётся не только цветом: у карточки есть подпись состояния,
  у причины — значок (●, ▲, ✖). Размеры масштабируются по DPI монитора.
}

interface

uses
  System.SysUtils, System.Classes, System.Types, System.UITypes,
  Vcl.Controls, Vcl.Graphics,
  MineHunter.App.DashboardView;

type
  TMHMetricTile = class(TCustomControl)
  private
    FData: TMHTileData;
    function S(AValue: Integer): Integer;
  protected
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    procedure SetData(const AData: TMHTileData);
    property Data: TMHTileData read FData;
  published
    property Align;
    property Anchors;
    property Font;
    property ParentFont;
  end;

  TMHReasonList = class(TCustomControl)
  private
    FItems: TArray<TMHReasonItem>;
    function S(AValue: Integer): Integer;
    function LayoutHeight(AWidth: Integer; ADraw: Boolean): Integer;
  protected
    procedure Paint; override;
    procedure Resize; override;
  public
    constructor Create(AOwner: TComponent); override;
    procedure SetItems(const AItems: TArray<TMHReasonItem>);
    /// Текст всех причин (для копирования и доступности).
    function Text: string;
    property Items: TArray<TMHReasonItem> read FItems;
  published
    property Align;
    property Anchors;
    property Font;
    property ParentFont;
  end;

/// Цвет состояния (одинаковый для карточек, причин и плашки защиты).
function MHStateColor(AState: TMHTileState): TColor;
/// Подпись состояния словом — чтобы смысл не передавался только цветом.
function MHStateText(AState: TMHTileState): string;

implementation

uses
  MineHunter.App.Theme, MineHunter.App.Lang, Winapi.Windows, System.Math;

function MHStateColor(AState: TMHTileState): TColor;
begin
  case AState of
    tsOk: Result := TColor($0032A02E);      // зелёный
    tsInfo: Result := TColor($00B07A1E);    // синий
    tsWarning: Result := TColor($00008CE0); // янтарный
    tsAlert: Result := TColor($002828C6);   // красный
  else
    Result := TColor($00B0B0B0);            // серый — нет данных
  end;
end;

function MHStateText(AState: TMHTileState): string;
begin
  case AState of
    tsOk: Result := 'норма';
    tsInfo: Result := '';
    tsWarning: Result := 'внимание';
    tsAlert: Result := 'высокая';
  else
    Result := '';
  end;
end;

function StateMark(AState: TMHTileState): string;
begin
  case AState of
    tsWarning: Result := '▲';
    tsAlert: Result := '✖';
  else
    Result := '●';
  end;
end;

{ TMHMetricTile }

constructor TMHMetricTile.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  DoubleBuffered := True;
  FData.Value := '';
  FData.State := tsNoData;
  Width := 180;
  Height := 96;
end;

function TMHMetricTile.S(AValue: Integer): Integer;
begin
  Result := MulDiv(AValue, CurrentPPI, 96);
end;

procedure TMHMetricTile.SetData(const AData: TMHTileData);
begin
  FData := AData;
  Hint := MHTr(FData.Title) + ': ' + MHTr(FData.Value);
  if FData.Detail <> '' then
    Hint := Hint + sLineBreak + FData.Detail;
  ShowHint := True;
  Invalidate;
end;

procedure TMHMetricTile.Paint;
var
  LRect, LText: TRect;
  LColor: TColor;
  LState: string;
  LY, LPad: Integer;
begin
  LRect := ClientRect;
  LColor := MHStateColor(FData.State);
  LPad := S(10);
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(clWindow);
  Canvas.Pen.Color := MHThemeColor(clBtnShadow);
  Canvas.Pen.Width := 1;
  Canvas.Rectangle(LRect);
  // Полоса состояния слева.
  Canvas.Brush.Color := LColor;
  Canvas.FillRect(Rect(LRect.Left + 1, LRect.Top + 1, LRect.Left + 1 + S(5), LRect.Bottom - 1));
  Canvas.Brush.Style := bsClear;

  // Заголовок и подпись состояния.
  Canvas.Font := Font;
  Canvas.Font.Color := MHThemeColor(clGrayText);
  LY := LRect.Top + S(7);
  Canvas.TextOut(LRect.Left + LPad + S(4), LY, MHTr(FData.Title));
  LState := MHTr(MHStateText(FData.State));
  if LState <> '' then
  begin
    Canvas.Font.Color := LColor;
    Canvas.Font.Style := [fsBold];
    Canvas.TextOut(LRect.Right - LPad - Canvas.TextWidth(LState), LY, LState);
  end;

  // Значение — крупно.
  Canvas.Font := Font;
  Canvas.Font.Size := Font.Size + 9;
  Canvas.Font.Style := [fsBold];
  if FData.State = tsNoData then
    Canvas.Font.Color := MHThemeColor(clGrayText)
  else
    Canvas.Font.Color := MHThemeColor(clWindowText);
  LY := LY + S(18);
  Canvas.TextOut(LRect.Left + LPad + S(4), LY, FData.Value);

  // Пояснение — до двух строк с переносом.
  Canvas.Font := Font;
  Canvas.Font.Color := MHThemeColor(clGrayText);
  LText := Rect(LRect.Left + LPad + S(4), LY + S(30), LRect.Right - LPad, LRect.Bottom - S(4));
  DrawText(Canvas.Handle, PChar(FData.Detail), Length(FData.Detail), LText,
    DT_LEFT or DT_WORDBREAK or DT_END_ELLIPSIS or DT_NOPREFIX);
end;

{ TMHReasonList }

constructor TMHReasonList.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  DoubleBuffered := True;
  Height := 60;
end;

function TMHReasonList.S(AValue: Integer): Integer;
begin
  Result := MulDiv(AValue, CurrentPPI, 96);
end;

procedure TMHReasonList.SetItems(const AItems: TArray<TMHReasonItem>);
var
  LHeight: Integer;
begin
  FItems := AItems;
  LHeight := LayoutHeight(ClientWidth, False);
  if (LHeight > 0) and (LHeight <> Height) then
    Height := LHeight;
  Invalidate;
end;

function TMHReasonList.Text: string;
var
  LItem: TMHReasonItem;
begin
  Result := '';
  for LItem in FItems do
    Result := Result + LItem.Text + sLineBreak;
  Result := Result.TrimRight;
end;

/// Раскладка строк: значок + текст с переносом. Возвращает нужную высоту.
function TMHReasonList.LayoutHeight(AWidth: Integer; ADraw: Boolean): Integer;
var
  LItem: TMHReasonItem;
  LRect: TRect;
  LY, LMarkW, LTextH: Integer;
  LMark: string;
begin
  if not HandleAllocated or (AWidth <= 0) then
    Exit(0);
  Canvas.Font := Font;
  LMarkW := S(22);
  LY := S(4);
  for LItem in FItems do
  begin
    LRect := Rect(LMarkW, LY, Max(LMarkW + 10, AWidth - S(6)), LY + 1000);
    DrawText(Canvas.Handle, PChar(LItem.Text), Length(LItem.Text), LRect,
      DT_LEFT or DT_WORDBREAK or DT_NOPREFIX or DT_CALCRECT);
    LTextH := Max(LRect.Height, Canvas.TextHeight('Ag'));
    if ADraw then
    begin
      LMark := StateMark(LItem.State);
      Canvas.Font.Color := MHStateColor(LItem.State);
      Canvas.Font.Style := [fsBold];
      Canvas.TextOut(S(6), LY, LMark);
      Canvas.Font := Font;
      if LItem.State in [tsWarning, tsAlert] then
        Canvas.Font.Style := [fsBold];
      Canvas.Font.Color := MHThemeColor(clWindowText);
      LRect := Rect(LMarkW, LY, Max(LMarkW + 10, AWidth - S(6)), LY + LTextH);
      DrawText(Canvas.Handle, PChar(LItem.Text), Length(LItem.Text), LRect,
        DT_LEFT or DT_WORDBREAK or DT_NOPREFIX);
      Canvas.Font := Font;
    end;
    LY := LY + LTextH + S(6);
  end;
  Result := LY + S(2);
end;

procedure TMHReasonList.Paint;
begin
  Canvas.Brush.Style := bsSolid;
  Canvas.Brush.Color := MHThemeColor(Color);
  Canvas.FillRect(ClientRect);
  Canvas.Brush.Style := bsClear;
  LayoutHeight(ClientWidth, True);
end;

procedure TMHReasonList.Resize;
var
  LHeight: Integer;
begin
  inherited;
  LHeight := LayoutHeight(ClientWidth, False);
  if (LHeight > 0) and (LHeight <> Height) then
    Height := LHeight;
end;

end.
