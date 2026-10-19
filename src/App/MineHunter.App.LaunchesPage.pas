unit MineHunter.App.LaunchesPage;

{
  Страница «Запуски»: журнал запусков программ (что, когда, кем запущено и
  сколько работало) за выбранный период с фильтром. Данные — из истории
  (IMHLaunchHistory); без хранилища — последние записи из памяти.
  С правами администратора журнал видит каждый запуск (ETW), без них — только
  процессы, прожившие дольше интервала опроса (это показано в подсказке).
}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ComCtrls,
  MineHunter.Core.Types, MineHunter.App.Bootstrap;

type
  TMHLaunchesPage = class(TComponent)
  public const
    MaxRows = 2000;
    MaxMemory = 5000;
    ReloadSeconds = 5;
  private
    FServices: TMHAppServices;
    FPeriod: TComboBox;
    FFilter: TEdit;
    FInfo: TLabel;
    FList: TListView;
    FRecent: TList<TMHLaunchRecord>;
    FRows: TArray<TMHLaunchRecord>;
    FLastReloadUtc: TDateTime;
    FEtw: Boolean;
    FHasSource: Boolean;
    procedure RefreshClick(Sender: TObject);
    procedure FilterChange(Sender: TObject);
    function PeriodHours: Integer;
    function LoadRows: TArray<TMHLaunchRecord>;
    procedure ShowRows;
  public
    constructor Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices); reintroduce;
    destructor Destroy; override;
    /// Учитывает записи снимка; если страница видна — обновляет таблицу не чаще ReloadSeconds.
    procedure UpdateSnapshot(const ASnapshot: TMHSnapshot; AVisible: Boolean);
    /// Перечитывает журнал сейчас.
    procedure Reload;
    property List: TListView read FList;
    property FilterEdit: TEdit read FFilter;
    property PeriodCombo: TComboBox read FPeriod;
    property Rows: TArray<TMHLaunchRecord> read FRows;
  end;

implementation

uses
  System.Math, System.DateUtils, System.Generics.Defaults,
  MineHunter.Core.Lang, MineHunter.Core.Launches, MineHunter.App.ListViews,
  MineHunter.Collectors.ProcessEvents;

const
  PERIOD_HOURS: array[0..3] of Integer = (1, 24, 24 * 7, 24 * 30);

constructor TMHLaunchesPage.Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices);
var
  LTop: TPanel;
  LLabel: TLabel;
  LButton: TButton;
  I: Integer;
  LCaptions: array[0..6] of string;
  LWidths: array[0..6] of Integer;
begin
  inherited Create(AOwner);
  FServices := AServices;
  FRecent := TList<TMHLaunchRecord>.Create;

  LTop := TPanel.Create(Self);
  LTop.Parent := ASheet;
  LTop.Align := alTop;
  LTop.Height := 64;
  LTop.BevelOuter := bvNone;
  LLabel := TLabel.Create(Self);
  LLabel.Parent := LTop;
  LLabel.SetBounds(8, 12, 60, 15);
  LLabel.Caption := MHL('Период:', 'Period:');
  FPeriod := TComboBox.Create(Self);
  FPeriod.Parent := LTop;
  FPeriod.Style := csDropDownList;
  FPeriod.SetBounds(70, 8, 130, 23);
  FPeriod.Items.Add(MHL('1 час', '1 hour'));
  FPeriod.Items.Add(MHL('24 часа', '24 hours'));
  FPeriod.Items.Add(MHL('7 дней', '7 days'));
  FPeriod.Items.Add(MHL('30 дней', '30 days'));
  FPeriod.ItemIndex := 1;
  FPeriod.OnChange := RefreshClick;
  LLabel := TLabel.Create(Self);
  LLabel.Parent := LTop;
  LLabel.SetBounds(216, 12, 60, 15);
  LLabel.Caption := MHL('Фильтр:', 'Filter:');
  FFilter := TEdit.Create(Self);
  FFilter.Parent := LTop;
  FFilter.SetBounds(280, 8, 260, 23);
  FFilter.TextHint := MHL('имя, путь или кто запустил', 'name, path or launcher');
  FFilter.OnChange := FilterChange;
  LButton := TButton.Create(Self);
  LButton.Parent := LTop;
  LButton.SetBounds(552, 7, 110, 25);
  LButton.Caption := MHL('Обновить', 'Refresh');
  LButton.OnClick := RefreshClick;
  FInfo := TLabel.Create(Self);
  FInfo.Parent := LTop;
  FInfo.SetBounds(8, 40, 1100, 15);
  FInfo.AutoSize := False;
  FInfo.ShowAccelChar := False;

  FList := TListView.Create(Self);
  FList.Parent := ASheet;
  FList.Align := alClient;
  FList.ViewStyle := vsReport;
  FList.ReadOnly := True;
  FList.RowSelect := True;
  FList.HideSelection := False;
  LCaptions[0] := MHL('Запуск', 'Started');
  LCaptions[1] := MHL('Программа', 'Program');
  LCaptions[2] := 'PID';
  LCaptions[3] := MHL('Кто запустил', 'Launched by');
  LCaptions[4] := MHL('Работала', 'Ran for');
  LCaptions[5] := MHL('Путь', 'Path');
  LCaptions[6] := MHL('Источник', 'Source');
  LWidths[0] := 120; LWidths[1] := 170; LWidths[2] := 60; LWidths[3] := 150; LWidths[4] := 95;
  LWidths[5] := 420; LWidths[6] := 70;
  for I := 0 to High(LCaptions) do
    with FList.Columns.Add do
    begin
      Caption := LCaptions[I];
      Width := LWidths[I];
    end;
end;

destructor TMHLaunchesPage.Destroy;
begin
  FRecent.Free;
  inherited;
end;

function TMHLaunchesPage.PeriodHours: Integer;
begin
  Result := PERIOD_HOURS[EnsureRange(FPeriod.ItemIndex, 0, High(PERIOD_HOURS))];
end;

procedure TMHLaunchesPage.UpdateSnapshot(const ASnapshot: TMHSnapshot; AVisible: Boolean);
var
  LRecord: TMHLaunchRecord;
  LStatus: TMHSourceStatus;
begin
  for LRecord in ASnapshot.LaunchEvents do
  begin
    FRecent.Add(LRecord);
    if LRecord.Source = 'etw' then
      FEtw := True;
  end;
  if FRecent.Count > MaxMemory then
    FRecent.DeleteRange(0, FRecent.Count - MaxMemory);
  FHasSource := ASnapshot.FindSource(TMHProcessEventCollector.SourceIdValue, LStatus);
  if FHasSource then
    FEtw := LStatus.State = ssSuccess;
  if AVisible and ((FLastReloadUtc = 0) or
     ((ASnapshot.TimestampUtc - FLastReloadUtc) * SecsPerDay >= ReloadSeconds)) then
    Reload;
end;

function TMHLaunchesPage.LoadRows: TArray<TMHLaunchRecord>;
var
  LHistory: IMHLaunchHistory;
  LNow: TDateTime;
  LMerged: TDictionary<string, TMHLaunchRecord>;
  LRecord, LOld: TMHLaunchRecord;
  LKey, LFilter: string;
  LList: TList<TMHLaunchRecord>;
begin
  LNow := FServices.Clock.NowUtc;
  LFilter := Trim(FFilter.Text);
  if Supports(FServices.MetricHistory, IMHLaunchHistory, LHistory) then
    Exit(LHistory.LoadLaunches(LNow - PeriodHours / HoursPerDay, LNow + 1 / HoursPerDay, LFilter, MaxRows));
  // Без хранилища: записи из памяти (запуск и завершение одного экземпляра объединяются).
  LMerged := TDictionary<string, TMHLaunchRecord>.Create;
  LList := TList<TMHLaunchRecord>.Create;
  try
    for LRecord in FRecent do
    begin
      LKey := IntToStr(LRecord.Pid) + ':' + UIntToStr(LRecord.CreateTime);
      if LMerged.TryGetValue(LKey, LOld) then
      begin
        if LRecord.ExitUtc > 0 then
          LOld.ExitUtc := LRecord.ExitUtc;
        if LOld.Name = '' then
          LOld.Name := LRecord.Name;
        LMerged[LKey] := LOld;
      end
      else
        LMerged.Add(LKey, LRecord);
    end;
    for LRecord in LMerged.Values do
      if (LRecord.StartUtc >= LNow - PeriodHours / HoursPerDay) and ((LFilter = '') or
         LRecord.Name.ToLower.Contains(LFilter.ToLower) or LRecord.ImagePath.ToLower.Contains(LFilter.ToLower) or
         LRecord.ParentName.ToLower.Contains(LFilter.ToLower)) then
        LList.Add(LRecord);
    LList.Sort(TComparer<TMHLaunchRecord>.Construct(
      function(const A, B: TMHLaunchRecord): Integer
      begin
        Result := CompareValue(B.StartUtc, A.StartUtc);
      end));
    if LList.Count > MaxRows then
      LList.DeleteRange(MaxRows, LList.Count - MaxRows);
    Result := LList.ToArray;
  finally
    LList.Free;
    LMerged.Free;
  end;
end;

procedure TMHLaunchesPage.Reload;
begin
  FLastReloadUtc := FServices.Clock.NowUtc;
  try
    FRows := LoadRows;
  except
    on E: Exception do
    begin
      FRows := nil;
      FInfo.Caption := MHL('Журнал недоступен: ', 'The journal is unavailable: ') + E.Message;
      Exit;
    end;
  end;
  ShowRows;
end;

procedure TMHLaunchesPage.ShowRows;
var
  LRecord: TMHLaunchRecord;
  LItem: TListItem;
  LDuration, LParent: string;
  LState: TMHListState;
  LKeyOf: TMHListItemKey;
begin
  // Запись — время запуска и PID: новые запуски сверху не сдвигают просматриваемую часть.
  LKeyOf :=
    function(AItem: TListItem): string
    begin
      Result := MHItemTextKey(AItem, [1]);
    end;
  LState := MHSaveListState(FList, LKeyOf);
  FList.Items.BeginUpdate;
  try
    FList.Items.Clear;
    for LRecord in FRows do
    begin
      LItem := FList.Items.Add;
      LItem.Caption := FormatDateTime('dd.mm hh:nn:ss', TTimeZone.Local.ToLocalTime(LRecord.StartUtc));
      LItem.SubItems.Add(LRecord.Name);
      LItem.SubItems.Add(IntToStr(LRecord.Pid));
      LParent := LRecord.ParentName;
      if (LParent = '') and (LRecord.ParentPid <> 0) then
        LParent := 'PID ' + IntToStr(LRecord.ParentPid);
      LItem.SubItems.Add(LParent);
      LDuration := MHLaunchDurationText(LRecord);
      if LDuration = '' then
        LDuration := MHL('работает', 'running');
      LItem.SubItems.Add(LDuration);
      LItem.SubItems.Add(LRecord.ImagePath);
      if LRecord.Source = 'etw' then
        LItem.SubItems.Add('ETW')
      else
        LItem.SubItems.Add(MHL('опрос', 'polling'));
    end;
  finally
    FList.Items.EndUpdate;
  end;
  MHRestoreListState(FList, LState, LKeyOf);
  if FEtw then
    FInfo.Caption := Format(MHL('Записей: %d. Журнал видит каждый запуск (события Windows).',
      'Records: %d. The journal sees every launch (Windows events).'), [Length(FRows)])
  else
    FInfo.Caption := Format(MHL('Записей: %d. Без прав администратора журнал ведётся по опросу: программы, ' +
      'работавшие меньше интервала опроса, в него не попадают.', 'Records: %d. Without administrator rights ' +
      'the journal uses polling: programs that ran shorter than the polling interval are not recorded.'),
      [Length(FRows)]);
end;

procedure TMHLaunchesPage.RefreshClick(Sender: TObject);
begin
  Reload;
end;

procedure TMHLaunchesPage.FilterChange(Sender: TObject);
begin
  Reload;
end;

end.
