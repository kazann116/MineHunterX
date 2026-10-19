unit MineHunter.Tests.UI.ListViews;

{
  Пересборка таблиц без «прыжков»: выделенная строка и просматриваемая часть
  сохраняются по ключам записей, даже если перед ними появились новые строки
  (журнал запусков, журнал событий) или строки поменялись местами.
}

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework,
  Vcl.Forms, Vcl.Controls, Vcl.ComCtrls;

type
  [TestFixture]
  [Category('UI')]
  TListStateTests = class
  private
    FForm: TForm;
    FList: TListView;
    procedure Fill(const ANames: TArray<string>);
    function Names(AFirst, ACount: Integer; const APrefix: string = 'r'): TArray<string>;
    procedure ScrollTo(ATop: Integer);
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure RowsInsertedAbove_SameRecordStaysOnTopAndSelected;
    [Test] procedure AtTop_StaysAtTopAndShowsNewRows;
    [Test] procedure AtTopWithSelection_EverythingStaysInPlace;
    [Test] procedure SelectedRecordGone_NoSelection;
    [Test] procedure ScrolledUpAfterSelectingBelow_StaysUp;
    [Test] procedure ItemTextKey_UsesCaptionAndColumns;
    [Test] procedure FitHeight_AllRowsVisibleWithoutOwnScroll;
  end;

implementation

uses
  Winapi.Windows, Winapi.CommCtrl,
  MineHunter.App.ListViews;

function CaptionKey(AItem: TListItem): string;
begin
  Result := AItem.Caption;
end;

procedure TListStateTests.Setup;
begin
  FForm := TForm.CreateNew(nil);
  FForm.SetBounds(0, 0, 500, 400);
  FList := TListView.Create(FForm);
  FList.Parent := FForm;
  FList.Align := alClient;
  FList.ViewStyle := vsReport;
  FList.ReadOnly := True;
  FList.RowSelect := True;
  FList.HideSelection := False;
  FList.Columns.Add.Width := 200;
  FList.Columns.Add.Width := 100;
  FForm.Show;
  Application.ProcessMessages;
end;

procedure TListStateTests.TearDown;
begin
  FForm.Free;
end;

function TListStateTests.Names(AFirst, ACount: Integer; const APrefix: string): TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
    Result[I] := Format('%s%.3d', [APrefix, AFirst + I]);
end;

procedure TListStateTests.Fill(const ANames: TArray<string>);
var
  LName: string;
begin
  FList.Items.BeginUpdate;
  try
    FList.Items.Clear;
    for LName in ANames do
      with FList.Items.Add do
      begin
        Caption := LName;
        SubItems.Add('x');
      end;
  finally
    FList.Items.EndUpdate;
  end;
end;

procedure TListStateTests.ScrollTo(ATop: Integer);
var
  LRect: TRect;
begin
  Assert.IsTrue(ListView_GetItemRect(FList.Handle, 0, LRect, LVIR_BOUNDS));
  ListView_Scroll(FList.Handle, 0, (ATop - MHListTopIndex(FList)) * (LRect.Bottom - LRect.Top));
  Assert.AreEqual(ATop, MHListTopIndex(FList));
end;

procedure TListStateTests.RowsInsertedAbove_SameRecordStaysOnTopAndSelected;
var
  LState: TMHListState;
begin
  Fill(Names(1, 200));
  ScrollTo(50);
  FList.Items[60].Selected := True;
  LState := MHSaveListState(FList, CaptionKey);
  // Новые записи сверху (как в журнале запусков).
  Fill(Names(1, 12, 'new') + Names(1, 200));
  MHRestoreListState(FList, LState, CaptionKey);
  Assert.AreEqual('r051', FList.Items[MHListTopIndex(FList)].Caption, 'Первая видимая — та же запись');
  Assert.IsNotNull(FList.Selected);
  Assert.AreEqual('r061', FList.Selected.Caption, 'Выделение — та же запись');
  Assert.AreEqual(1, FList.SelCount);
end;

procedure TListStateTests.AtTop_StaysAtTopAndShowsNewRows;
var
  LState: TMHListState;
begin
  Fill(Names(1, 200));
  LState := MHSaveListState(FList, CaptionKey);
  Fill(Names(1, 5, 'new') + Names(1, 200));
  MHRestoreListState(FList, LState, CaptionKey);
  Assert.AreEqual(0, MHListTopIndex(FList), 'В начале списка без выделения новые записи видны');
  Assert.AreEqual('new001', FList.Items[0].Caption);
end;

procedure TListStateTests.AtTopWithSelection_EverythingStaysInPlace;
var
  LState: TMHListState;
  LRect: TRect;
  LBefore: Integer;
begin
  // Отзыв: «Выделил — выделение осталось. Таблица обновилась, но всё осталось на том же месте».
  Fill(Names(1, 200));
  FList.Items[3].Selected := True;
  Assert.IsTrue(ListView_GetItemRect(FList.Handle, 3, LRect, LVIR_BOUNDS));
  LBefore := LRect.Top;
  LState := MHSaveListState(FList, CaptionKey);
  Fill(Names(1, 5, 'new') + Names(1, 200));
  MHRestoreListState(FList, LState, CaptionKey);
  Assert.AreEqual('r001', FList.Items[MHListTopIndex(FList)].Caption, 'Первая видимая — та же запись');
  Assert.AreEqual('r004', FList.Selected.Caption);
  Assert.IsTrue(ListView_GetItemRect(FList.Handle, FList.Selected.Index, LRect, LVIR_BOUNDS));
  Assert.AreEqual(LBefore, LRect.Top, 'Выделенная строка на том же месте экрана');
end;

procedure TListStateTests.SelectedRecordGone_NoSelection;
var
  LState: TMHListState;
begin
  Fill(Names(1, 100));
  ScrollTo(40);
  FList.Items[45].Selected := True;
  LState := MHSaveListState(FList, CaptionKey);
  // Запись r046 исчезла, первая видимая r041 тоже; номер верхней строки сохраняется.
  Fill(Names(1, 40) + Names(47, 60));
  MHRestoreListState(FList, LState, CaptionKey);
  Assert.IsNull(FList.Selected);
  Assert.AreEqual(40, MHListTopIndex(FList));
  // Пустой список — без ошибок.
  LState := MHSaveListState(FList, CaptionKey);
  Fill(nil);
  MHRestoreListState(FList, LState, CaptionKey);
  Assert.AreEqual(0, FList.Items.Count);
end;

procedure TListStateTests.ScrolledUpAfterSelectingBelow_StaysUp;
var
  LState: TMHListState;
  I: Integer;
begin
  // Сценарий из отзыва: прокрутил вниз, выделил, вернулся наверх — обновления
  // не уводят таблицу к выделенной строке.
  Fill(Names(1, 200));
  ScrollTo(120);
  FList.Items[125].Selected := True;
  FList.Items[125].Focused := True;
  ScrollTo(0);
  for I := 1 to 3 do
  begin
    LState := MHSaveListState(FList, CaptionKey);
    Fill(Names(1, I, 'new') + Names(1, 200));
    MHRestoreListState(FList, LState, CaptionKey);
    Application.ProcessMessages;
    Assert.AreEqual('r001', FList.Items[MHListTopIndex(FList)].Caption,
      'Обновление ' + IntToStr(I) + ': таблица не уходит к выделенной строке и не сдвигается');
    Assert.AreEqual('r126', FList.Selected.Caption);
  end;
end;

procedure TListStateTests.ItemTextKey_UsesCaptionAndColumns;
var
  LItem: TListItem;
begin
  Fill(['msedge.exe']);
  LItem := FList.Items[0];
  LItem.SubItems[0] := '1016';
  Assert.AreEqual('msedge.exe'#9'1016', MHItemTextKey(LItem, [0]));
  Assert.AreEqual('msedge.exe'#9'1016'#9, MHItemTextKey(LItem, [0, 5]), 'Нет столбца — пустая часть');
  Assert.AreEqual('msedge.exe', MHItemTextKey(LItem, []));
end;

procedure TListStateTests.FitHeight_AllRowsVisibleWithoutOwnScroll;
var
  LEmptyHeight: Integer;
begin
  FList.Align := alNone;
  FList.SetBounds(0, 0, 400, 60);
  Fill(Names(1, 25));
  Application.ProcessMessages;
  Assert.IsTrue(MHListCanScroll(FList), 'До подгонки строки не помещаются');
  MHFitListHeight(FList);
  Application.ProcessMessages;
  Assert.IsFalse(MHListCanScroll(FList), 'После подгонки своей прокрутки нет');
  Assert.IsTrue(ListView_GetCountPerPage(FList.Handle) >= 25, 'Видны все строки');
  // Столбцы шире таблицы — учитывается горизонтальная полоса.
  FList.Columns[1].Width := 600;
  MHFitListHeight(FList);
  Application.ProcessMessages;
  Assert.IsFalse(MHListCanScroll(FList), 'С горизонтальной полосой строки тоже видны все');
  // Пустая таблица — заголовок и место под AMinRows строк.
  Fill(nil);
  MHFitListHeight(FList, 1);
  LEmptyHeight := FList.Height;
  MHFitListHeight(FList, 3);
  Assert.IsTrue(FList.Height > LEmptyHeight);
end;

initialization
  TDUnitX.RegisterTestFixture(TListStateTests);

end.
