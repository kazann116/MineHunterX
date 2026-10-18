unit MineHunter.App.ListViews;

{
  Обновление списков без «прыжков»: при периодическом обновлении таблицы
  (смена числа строк виртуального списка, полная пересборка, повторный выбор
  строки) Windows прокручивает список к выделенной строке или в начало.
  MHUpdatePreservingScroll запоминает первую видимую строку до обновления и
  возвращает прокрутку после него, если пользователь смотрел другую часть
  таблицы.
}

interface

uses
  System.SysUtils, Vcl.ComCtrls;

/// Выполняет AUpdate и восстанавливает вертикальную прокрутку AList.
procedure MHUpdatePreservingScroll(AList: TListView; const AUpdate: TProc);

/// Пересобирает строки списка и восстанавливает прокрутку и выделенную строку
/// (по тексту первого столбца — строки пересоздаются).
procedure MHRebuildList(AList: TListView; const ABuild: TProc);

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

procedure MHRebuildList(AList: TListView; const ABuild: TProc);
var
  LTop, I: Integer;
  LSelected: string;
  LHadSelection: Boolean;
begin
  LTop := MHListTopIndex(AList);
  LHadSelection := AList.Selected <> nil;
  if LHadSelection then
    LSelected := AList.Selected.Caption;
  AList.Items.BeginUpdate;
  try
    ABuild();
    if LHadSelection then
      for I := 0 to AList.Items.Count - 1 do
        if AList.Items[I].Caption = LSelected then
        begin
          AList.Items[I].Selected := True;
          Break;
        end;
  finally
    AList.Items.EndUpdate;
  end;
  MHRestoreListTop(AList, LTop);
end;

procedure MHSetItemIndexQuiet(AList: TListView; AIndex: Integer);
begin
  if AList.ItemIndex <> AIndex then
    AList.ItemIndex := AIndex;
end;

end.
