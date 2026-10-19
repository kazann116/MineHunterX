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
}

interface

uses
  System.SysUtils, Vcl.ComCtrls;

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

/// Выполняет AUpdate и восстанавливает вертикальную прокрутку AList.
procedure MHUpdatePreservingScroll(AList: TListView; const AUpdate: TProc);

/// Пересобирает строки списка и восстанавливает прокрутку и выделенную строку
/// (по тексту первого столбца — строки пересоздаются).
procedure MHRebuildList(AList: TListView; const ABuild: TProc);

/// Запоминает прокрутку и выделение перед пересборкой строк (Clear + Add).
function MHSaveListState(AList: TListView; const AKeyOf: TMHListItemKey): TMHListState;
/// Возвращает выделение и прокрутку по ключам записей. Список, прокрученный в самое
/// начало, остаётся в начале (новые записи видны); иначе первой видимой остаётся та же
/// запись, даже если перед ней появились новые.
procedure MHRestoreListState(AList: TListView; const AState: TMHListState; const AKeyOf: TMHListItemKey);
/// Ключ по тексту первого столбца и столбцов SubItems с указанными номерами.
function MHItemTextKey(AItem: TListItem; const ASubItems: array of Integer): string;

/// Первая видимая строка (-1 — не определена) и возврат к ней после обновления.
function MHListTopIndex(AList: TListView): Integer;
procedure MHRestoreListTop(AList: TListView; AOldTop: Integer);

/// Выделяет строку AIndex, только если выделение действительно меняется:
/// повторная установка ItemIndex прокручивает список к строке.
procedure MHSetItemIndexQuiet(AList: TListView; AIndex: Integer);

implementation

uses
  Winapi.Windows, Winapi.CommCtrl;

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
  if (Result.Top > 0) and (Result.Top < AList.Items.Count) then
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
  if LTop > 0 then
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

procedure MHSetItemIndexQuiet(AList: TListView; AIndex: Integer);
begin
  if AList.ItemIndex <> AIndex then
    AList.ItemIndex := AIndex;
end;

end.
