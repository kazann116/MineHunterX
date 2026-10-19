unit MineHunter.App.ListViews;

{
  Обновление списков без «прыжков»: при периодическом обновлении таблицы
  (смена числа строк виртуального списка, полная пересборка, повторный выбор
  строки) Windows прокручивает список к выделенной строке или в начало.
  MHUpdatePreservingScroll запоминает первую видимую строку до обновления и
  возвращает прокрутку после него, если пользователь смотрел другую часть
  таблицы.
  Таблицы, которые пересобираются целиком (Clear + Add), сохраняют состояние
  по ключам записей (MHSaveListState / MHRestoreListState): выделенная строка
  остаётся выделенной, а новые записи в начале не сдвигают просматриваемую часть.
  Небольшие таблицы на прокручиваемых страницах показываются целиком
  (MHFitListHeight): высота по числу строк, прокручивается вся страница.
}

interface

uses
  System.SysUtils, System.Classes, Winapi.Messages, Vcl.Controls, Vcl.ComCtrls, Vcl.Menus;

type
  /// Ключ строки: одна и та же запись до и после пересборки даёт один ключ.
  TMHListItemKey = reference to function(AItem: TListItem): string;

  /// Что видит пользователь: первая видимая строка и выделенная строка.
  TMHListState = record
    /// Номер первой видимой строки (-1 — не определён).
    Top: Integer;
    TopKey: string;
    SelectedKey: string;
    HasSelection: Boolean;
  end;

  /// Общие улучшения таблицы; принадлежит таблице и освобождается вместе с ней.
  ///  - Системная двойная буферизация (LVS_EX_DOUBLEBUFFER): строки рисуются в памяти и
  ///    выводятся разом — таблица не мерцает при обновлении. VCL перезаписывает расширенные
  ///    стили целиком (создание окна, смена RowSelect, GridLines, темы), поэтому флаг
  ///    добавляется к каждой их установке.
  ///  - Копирование: «Копировать строку» (Ctrl+C) и «Копировать всю таблицу» — в меню
  ///    таблицы (своё меню, если его не было).
  TMHListHook = class(TComponent)
  private
    FList: TCustomListView;
    FOldProc: TWndMethod;
    FMenu: TPopupMenu;
    FOldPopup: TNotifyEvent;
    FItemCopyRow, FItemCopyAll: TMenuItem;
    procedure WndProc(var Message: TMessage);
    procedure MenuPopup(Sender: TObject);
    procedure CopyRowClick(Sender: TObject);
    procedure CopyAllClick(Sender: TObject);
  public
    constructor Create(AList: TCustomListView); reintroduce;
    destructor Destroy; override;
    property CopyRowItem: TMenuItem read FItemCopyRow;
    property CopyAllItem: TMenuItem read FItemCopyAll;
  end;

  TMHSetClipboardText = reference to procedure(const AText: string);

var
  /// Запись в буфер обмена (тесты подменяют, чтобы не трогать буфер пользователя).
  GMHSetClipboardText: TMHSetClipboardText;

/// Двойная буферизация и копирование у всех таблиц в дереве компонентов ARoot
/// (повторный вызов безопасен).
procedure MHEnhanceLists(ARoot: TComponent);
/// Улучшения таблицы (nil — не подключены).
function MHListHook(AList: TCustomListView): TMHListHook;
/// True — у таблицы включена системная двойная буферизация.
function MHListIsBuffered(AList: TCustomListView): Boolean;
/// Текст строк таблицы: столбцы через табуляцию, строки через перевод строки.
/// ASelectedOnly — только выделенные строки (без заголовка), иначе заголовок и все строки.
function MHListRowsText(AList: TCustomListView; ASelectedOnly: Boolean): string;
/// Копирует строки в буфер обмена; False — копировать нечего.
function MHCopyListRows(AList: TCustomListView; ASelectedOnly: Boolean): Boolean;

/// Выполняет AUpdate и восстанавливает вертикальную прокрутку AList.
procedure MHUpdatePreservingScroll(AList: TListView; const AUpdate: TProc);

/// Пересобирает строки списка и восстанавливает прокрутку и выделенную строку
/// (по тексту первого столбца — строки пересоздаются).
procedure MHRebuildList(AList: TListView; const ABuild: TProc);

/// Запоминает прокрутку и выделение перед пересборкой строк (Clear + Add).
function MHSaveListState(AList: TListView; const AKeyOf: TMHListItemKey): TMHListState;
/// Возвращает выделение и прокрутку по ключам записей: первой видимой остаётся та же
/// запись, даже если перед ней появились новые. Исключение — список в самом начале без
/// выделения: он остаётся в начале, чтобы новые записи были видны.
procedure MHRestoreListState(AList: TListView; const AState: TMHListState; const AKeyOf: TMHListItemKey);
/// Ключ по тексту первого столбца и столбцов SubItems с указанными номерами.
function MHItemTextKey(AItem: TListItem; const ASubItems: array of Integer): string;

/// Первая видимая строка (-1 — не определена) и возврат к ней после обновления.
function MHListTopIndex(AList: TListView): Integer;
procedure MHRestoreListTop(AList: TListView; AOldTop: Integer);

/// Высота таблицы, при которой все строки (не меньше AMinRows) видны без собственной
/// вертикальной прокрутки: рамка, заголовок, строки и, если столбцы шире таблицы,
/// горизонтальная полоса.
function MHListFitHeight(AList: TListView; AMinRows: Integer = 1): Integer;
/// Задаёт таблице такую высоту (для таблиц, выровненных по верху или без выравнивания).
procedure MHFitListHeight(AList: TListView; AMinRows: Integer = 1);
/// Есть ли у таблицы что прокручивать по вертикали (видны не все строки).
function MHListCanScroll(AList: TWinControl): Boolean;

/// Выделяет строку AIndex, только если выделение действительно меняется:
/// повторная установка ItemIndex прокручивает список к строке.
procedure MHSetItemIndexQuiet(AList: TListView; AIndex: Integer);

implementation

uses
  Winapi.Windows, Winapi.CommCtrl, System.Math, Vcl.Graphics, Vcl.Clipbrd, MineHunter.Core.Lang;

/// Высота строки, если строк ещё нет: по шрифту, как у элемента Windows.
function DefaultRowHeight(AList: TListView): Integer;
begin
  Result := Abs(AList.Font.Height) + MulDiv(6, AList.CurrentPPI, 96);
end;

function MHListFitHeight(AList: TListView; AMinRows: Integer): Integer;
var
  LRect: TRect;
  LHeader: HWND;
  LRowHeight, LHeaderHeight, LColumns, LClientWidth, LBorder, I: Integer;
  LStyle: NativeInt;
begin
  // Настоящая высота строки, а не оценка по шрифту: иначе таблица меняла бы высоту,
  // когда в ней появляются или пропадают строки (и вместе с ней — прокрутка страницы).
  // Измеренное значение запоминается в Tag; пустую таблицу меряем временной строкой.
  LRowHeight := 0;
  if AList.HandleAllocated and (AList.Items.Count = 0) and (AList.Tag <= 0) and not AList.OwnerData then
  begin
    AList.Items.BeginUpdate;
    try
      AList.Items.Add;
      if ListView_GetItemRect(AList.Handle, 0, LRect, LVIR_BOUNDS) then
        AList.Tag := LRect.Bottom - LRect.Top;
      AList.Items.Delete(0);
    finally
      AList.Items.EndUpdate;
    end;
  end;
  if AList.HandleAllocated and (AList.Items.Count > 0) and
     ListView_GetItemRect(AList.Handle, 0, LRect, LVIR_BOUNDS) then
  begin
    LRowHeight := LRect.Bottom - LRect.Top;
    if LRowHeight > 0 then
      AList.Tag := LRowHeight;
  end;
  if (LRowHeight <= 0) and (AList.Tag > 0) then
    LRowHeight := AList.Tag;
  if LRowHeight <= 0 then
    LRowHeight := DefaultRowHeight(AList);
  LHeaderHeight := 0;
  if AList.ShowColumnHeaders then
  begin
    if AList.HandleAllocated then
    begin
      LHeader := ListView_GetHeader(AList.Handle);
      if (LHeader <> 0) and GetWindowRect(LHeader, LRect) then
        LHeaderHeight := LRect.Bottom - LRect.Top;
    end;
    if LHeaderHeight <= 0 then
      LHeaderHeight := LRowHeight + MulDiv(4, AList.CurrentPPI, 96);
  end;
  // Рамка — без полос прокрутки, которые есть сейчас: после подгонки вертикальной не будет.
  LBorder := AList.Height - AList.ClientHeight;
  LClientWidth := AList.ClientWidth;
  if AList.HandleAllocated then
  begin
    LStyle := GetWindowLong(AList.Handle, GWL_STYLE);
    if LStyle and WS_HSCROLL <> 0 then
      Dec(LBorder, GetSystemMetrics(SM_CYHSCROLL));
    if LStyle and WS_VSCROLL <> 0 then
      Inc(LClientWidth, GetSystemMetrics(SM_CXVSCROLL));
  end;
  LColumns := 0;
  for I := 0 to AList.Columns.Count - 1 do
    Inc(LColumns, Max(0, AList.Columns[I].Width));
  Result := LBorder + LHeaderHeight + Max(AList.Items.Count, AMinRows) * LRowHeight + 2;
  if LColumns > LClientWidth then
    Inc(Result, GetSystemMetrics(SM_CYHSCROLL));
end;

procedure MHFitListHeight(AList: TListView; AMinRows: Integer);
var
  LHeight: Integer;
begin
  LHeight := MHListFitHeight(AList, AMinRows);
  if AList.Height <> LHeight then
    AList.Height := LHeight;
end;

function MHListCanScroll(AList: TWinControl): Boolean;
begin
  Result := AList.HandleAllocated and (GetWindowLong(AList.Handle, GWL_STYLE) and WS_VSCROLL <> 0);
end;

function MHListTopIndex(AList: TListView): Integer;
begin
  if not AList.HandleAllocated or (AList.ViewStyle <> vsReport) then
    Exit(-1);
  Result := ListView_GetTopIndex(AList.Handle);
end;

procedure MHRestoreListTop(AList: TListView; AOldTop: Integer);
var
  LNewTop, LCount: Integer;
  LRect: TRect;
begin
  if (AOldTop < 0) or not AList.HandleAllocated then
    Exit;
  LCount := ListView_GetItemCount(AList.Handle);
  if LCount = 0 then
    Exit;
  if AOldTop >= LCount then
    AOldTop := LCount - 1;
  LNewTop := ListView_GetTopIndex(AList.Handle);
  if LNewTop = AOldTop then
    Exit;
  if not ListView_GetItemRect(AList.Handle, 0, LRect, LVIR_BOUNDS) or (LRect.Bottom <= LRect.Top) then
    Exit;
  ListView_Scroll(AList.Handle, 0, (AOldTop - LNewTop) * (LRect.Bottom - LRect.Top));
end;

procedure MHUpdatePreservingScroll(AList: TListView; const AUpdate: TProc);
var
  LTop: Integer;
begin
  LTop := MHListTopIndex(AList);
  AUpdate();
  MHRestoreListTop(AList, LTop);
end;

function MHItemTextKey(AItem: TListItem; const ASubItems: array of Integer): string;
var
  I: Integer;
begin
  Result := AItem.Caption;
  for I in ASubItems do
    if I < AItem.SubItems.Count then
      Result := Result + #9 + AItem.SubItems[I]
    else
      Result := Result + #9;
end;

function FindByKey(AList: TListView; const AKey: string; const AKeyOf: TMHListItemKey): Integer;
var
  I: Integer;
begin
  if AKey <> '' then
    for I := 0 to AList.Items.Count - 1 do
      if AKeyOf(AList.Items[I]) = AKey then
        Exit(I);
  Result := -1;
end;

function MHSaveListState(AList: TListView; const AKeyOf: TMHListItemKey): TMHListState;
begin
  Result := Default(TMHListState);
  Result.Top := MHListTopIndex(AList);
  if (Result.Top >= 0) and (Result.Top < AList.Items.Count) then
    Result.TopKey := AKeyOf(AList.Items[Result.Top]);
  Result.HasSelection := AList.Selected <> nil;
  if Result.HasSelection then
    Result.SelectedKey := AKeyOf(AList.Selected);
end;

procedure MHRestoreListState(AList: TListView; const AState: TMHListState; const AKeyOf: TMHListItemKey);
var
  LIndex, LTop: Integer;
begin
  if AState.HasSelection then
  begin
    LIndex := FindByKey(AList, AState.SelectedKey, AKeyOf);
    // Выделение и фокус строки не прокручивают список (в отличие от ItemIndex).
    if (LIndex >= 0) and not AList.Items[LIndex].Selected then
    begin
      AList.Items[LIndex].Selected := True;
      AList.Items[LIndex].Focused := True;
    end;
  end;
  if AState.Top < 0 then
    Exit;
  LTop := AState.Top;
  // Пользователь выделил запись или прокрутил список — всё остаётся на месте.
  if (LTop > 0) or AState.HasSelection then
  begin
    LIndex := FindByKey(AList, AState.TopKey, AKeyOf);
    if LIndex >= 0 then
      LTop := LIndex;
  end;
  MHRestoreListTop(AList, LTop);
end;

procedure MHRebuildList(AList: TListView; const ABuild: TProc);
var
  LState: TMHListState;
  LKeyOf: TMHListItemKey;
begin
  LKeyOf :=
    function(AItem: TListItem): string
    begin
      Result := AItem.Caption;
    end;
  LState := MHSaveListState(AList, LKeyOf);
  AList.Items.BeginUpdate;
  try
    ABuild();
  finally
    AList.Items.EndUpdate;
  end;
  MHRestoreListState(AList, LState, LKeyOf);
end;

type
  TListViewAccess = class(TCustomListView);

{ TMHListHook }

constructor TMHListHook.Create(AList: TCustomListView);
var
  LItem: TMenuItem;
begin
  inherited Create(AList);
  FList := AList;
  FOldProc := AList.WindowProc;
  AList.WindowProc := WndProc;
  if AList.HandleAllocated then
    ListView_SetExtendedListViewStyleEx(AList.Handle, LVS_EX_DOUBLEBUFFER, LVS_EX_DOUBLEBUFFER);

  FMenu := TListViewAccess(AList).PopupMenu;
  if FMenu = nil then
  begin
    FMenu := TPopupMenu.Create(Self);
    TListViewAccess(AList).PopupMenu := FMenu;
  end
  else
  begin
    LItem := TMenuItem.Create(Self);
    LItem.Caption := '-';
    FMenu.Items.Add(LItem);
  end;
  FOldPopup := FMenu.OnPopup;
  FMenu.OnPopup := MenuPopup;
  FItemCopyRow := TMenuItem.Create(Self);
  FItemCopyRow.Caption := MHL('Копировать строку', 'Copy row');
  // Сочетание обрабатывается меню таблицы, пока таблица в фокусе.
  FItemCopyRow.ShortCut := ShortCut(Ord('C'), [ssCtrl]);
  FItemCopyRow.OnClick := CopyRowClick;
  FMenu.Items.Add(FItemCopyRow);
  FItemCopyAll := TMenuItem.Create(Self);
  FItemCopyAll.Caption := MHL('Копировать всю таблицу', 'Copy the whole table');
  FItemCopyAll.OnClick := CopyAllClick;
  FMenu.Items.Add(FItemCopyAll);
end;

procedure TMHListHook.MenuPopup(Sender: TObject);
begin
  if Assigned(FOldPopup) then
    FOldPopup(Sender);
  FItemCopyRow.Enabled := FList.SelCount > 0;
  FItemCopyAll.Enabled := FList.Items.Count > 0;
end;

procedure TMHListHook.CopyRowClick(Sender: TObject);
begin
  MHCopyListRows(FList, True);
end;

procedure TMHListHook.CopyAllClick(Sender: TObject);
begin
  MHCopyListRows(FList, False);
end;

destructor TMHListHook.Destroy;
begin
  // Таблица освобождается раньше своих компонентов — обработчик возвращается, если она ещё жива.
  if (FList <> nil) and not (csDestroying in FList.ComponentState) and
     (TMethod(FList.WindowProc).Data = Self) then
    FList.WindowProc := FOldProc;
  inherited Destroy;
end;

procedure TMHListHook.WndProc(var Message: TMessage);
begin
  if Message.Msg = LVM_SETEXTENDEDLISTVIEWSTYLE then
  begin
    // WParam — маска изменяемых флагов (0 — все): двойная буферизация остаётся включённой.
    if (Message.WParam = 0) or (Message.WParam and LVS_EX_DOUBLEBUFFER <> 0) then
      Message.LParam := Message.LParam or LVS_EX_DOUBLEBUFFER;
  end;
  FOldProc(Message);
end;

function MHListHook(AList: TCustomListView): TMHListHook;
var
  I: Integer;
begin
  for I := 0 to AList.ComponentCount - 1 do
    if AList.Components[I] is TMHListHook then
      Exit(TMHListHook(AList.Components[I]));
  Result := nil;
end;

procedure MHEnhanceLists(ARoot: TComponent);
var
  I: Integer;
begin
  if ARoot = nil then
    Exit;
  if (ARoot is TCustomListView) and (MHListHook(TCustomListView(ARoot)) = nil) then
    TMHListHook.Create(TCustomListView(ARoot));
  for I := 0 to ARoot.ComponentCount - 1 do
    if not (ARoot.Components[I] is TMHListHook) then
      MHEnhanceLists(ARoot.Components[I]);
end;

function RowText(AItem: TListItem; AColumns: Integer): string;
var
  I: Integer;
begin
  Result := AItem.Caption;
  // Столько столбцов, сколько у таблицы (у строки подстрок может быть меньше).
  for I := 0 to AColumns - 2 do
    if I < AItem.SubItems.Count then
      Result := Result + #9 + AItem.SubItems[I]
    else
      Result := Result + #9;
end;

function MHListRowsText(AList: TCustomListView; ASelectedOnly: Boolean): string;
var
  LList: TListViewAccess;
  LLines: TStringList;
  LColumns, I: Integer;
  LHeader: string;
begin
  LList := TListViewAccess(AList);
  LColumns := Max(1, LList.Columns.Count);
  LLines := TStringList.Create;
  try
    if not ASelectedOnly and (LList.Columns.Count > 0) then
    begin
      LHeader := LList.Columns[0].Caption;
      for I := 1 to LList.Columns.Count - 1 do
        LHeader := LHeader + #9 + LList.Columns[I].Caption;
      LLines.Add(LHeader);
    end;
    for I := 0 to LList.Items.Count - 1 do
      // Виртуальные таблицы: строка заполняется по запросу (OnData).
      if not ASelectedOnly or LList.Items[I].Selected then
        LLines.Add(RowText(LList.Items[I], LColumns));
    if ASelectedOnly and (LLines.Count = 0) then
      Exit('');
    if not ASelectedOnly and (LList.Items.Count = 0) then
      Exit('');
    // Пустой последний столбец сохраняется (табуляция в конце), лишнего перевода строки нет.
    LLines.TrailingLineBreak := False;
    Result := LLines.Text;
  finally
    LLines.Free;
  end;
end;

function MHCopyListRows(AList: TCustomListView; ASelectedOnly: Boolean): Boolean;
var
  LText: string;
begin
  LText := MHListRowsText(AList, ASelectedOnly);
  Result := LText <> '';
  if Result and Assigned(GMHSetClipboardText) then
    GMHSetClipboardText(LText);
end;

function MHListIsBuffered(AList: TCustomListView): Boolean;
begin
  Result := AList.HandleAllocated and
    (ListView_GetExtendedListViewStyle(AList.Handle) and LVS_EX_DOUBLEBUFFER <> 0);
end;

procedure MHSetItemIndexQuiet(AList: TListView; AIndex: Integer);
begin
  if AList.ItemIndex <> AIndex then
    AList.ItemIndex := AIndex;
end;

initialization
  GMHSetClipboardText :=
    procedure(const AText: string)
    begin
      // Буфер может быть занят другой программой — копирование не роняет окно.
      try
        Clipboard.AsText := AText;
      except
        on E: Exception do
          ;
      end;
    end;

end.
