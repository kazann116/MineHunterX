unit MineHunter.App.DisksPage;

{
  Страница «Диски»: каждый физический диск (нагрузка, температура, состояние,
  износ, ошибки, наработка), разделы со свободным местом, программы с
  наибольшим чтением и записью и проверка файлов на всех дисках (фоновый
  поток с низким приоритетом ввода-вывода, прогресс, отмена, действия:
  открыть расположение, в карантин, «это мой файл»).

  Элементы создаются в коде на переданной вкладке; страница не владеет
  сервисами. Все обращения к интерфейсу — в главном потоке: поток проверки
  передаёт прогресс и итог через TThread.Queue и отменяется при закрытии.
}

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ComCtrls,
  MineHunter.Core.Types, MineHunter.Core.FileScan, MineHunter.App.Bootstrap;

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
  Winapi.Windows, System.Math, System.DateUtils, System.Generics.Collections, System.Generics.Defaults,
  Vcl.Graphics,
  MineHunter.Core.Lang, MineHunter.Core.Settings, MineHunter.Core.Actions, MineHunter.Core.Interfaces,
  MineHunter.Core.FileScan.WinApi, MineHunter.Collectors.Disks, MineHunter.Analysis.Disks,
  MineHunter.App.Display;

const
  THREAD_MODE_BACKGROUND_BEGIN = $00010000;
  THREAD_MODE_BACKGROUND_END = $00020000;

{ TMHDisksPage }

constructor TMHDisksPage.Create(AOwner: TComponent; ASheet: TWinControl; AServices: TMHAppServices;
  const AConfirm: TMHConfirmQuestion; const ANotice: TMHNotice);
var
  LTop, LScanPanel, LButtons: TPanel;
begin
  inherited Create(AOwner);
  FSheet := ASheet;
  FServices := AServices;
  FConfirm := AConfirm;
  FNotice := ANotice;
  FScanFs := TMHWinFileScanFs.Create;

  LTop := TPanel.Create(Self);
  LTop.Parent := ASheet;
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

  NewCaption(ASheet, MHL('Физические диски', 'Physical disks'));
  FDisks := NewList(ASheet, alTop, 130,
    [MHL('Диск', 'Disk'), MHL('Модель', 'Model'), MHL('Тип', 'Type'), MHL('Объём', 'Size'),
     MHL('Разделы', 'Volumes'), MHL('Занят', 'Busy'), MHL('Чтение', 'Read'), MHL('Запись', 'Write'),
     MHL('Температура', 'Temperature'), MHL('Состояние', 'Health'), MHL('Износ', 'Wear'),
     MHL('Ошибки', 'Errors'), MHL('Наработка', 'Power-on')],
    [40, 170, 175, 70, 70, 50, 75, 75, 135, 120, 55, 60, 75]);
  NewCaption(ASheet, MHL('Разделы', 'Volumes'));
  FVolumes := NewList(ASheet, alTop, 160,
    [MHL('Раздел', 'Volume'), MHL('Метка', 'Label'), MHL('ФС', 'FS'), MHL('Всего', 'Total'),
     MHL('Свободно', 'Free'), MHL('Свободно, %', 'Free, %'), MHL('Диск', 'Disk'), MHL('Состояние', 'State')],
    [60, 160, 55, 80, 80, 80, 50, 260]);
  NewCaption(ASheet, MHL('Кто больше всего читает и пишет (все операции ввода-вывода процесса)',
    'Top readers and writers (all process I/O)'));
  FIo := NewList(ASheet, alTop, 110,
    [MHL('Программа', 'Program'), 'PID', MHL('Чтение', 'Read'), MHL('Запись', 'Write'), MHL('Путь', 'Path')],
    [170, 60, 90, 90, 480]);

  LScanPanel := TPanel.Create(Self);
  LScanPanel.Parent := ASheet;
  LScanPanel.Top := 10000; // под таблицами дисков, над результатами проверки
  LScanPanel.Align := alTop;
  LScanPanel.Height := 64;
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
  FLblScan := TLabel.Create(Self);
  FLblScan.Parent := LScanPanel;
  FLblScan.SetBounds(8, 42, 1100, 15);
  FLblScan.AutoSize := False;
  FLblScan.ShowAccelChar := False;
  if FServices.Settings.LastFileScanUtc > 0 then
    FLblScan.Caption := MHL('Последняя проверка: ', 'Last scan: ') +
      FormatDateTime('dd.mm.yyyy hh:nn', TTimeZone.Local.ToLocalTime(FServices.Settings.LastFileScanUtc))
  else
    FLblScan.Caption := MHL('Файлы ещё не проверялись.', 'Files have not been scanned yet.');

  LButtons := TPanel.Create(Self);
  LButtons.Parent := ASheet;
  LButtons.Align := alBottom;
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
  FHitsView := NewList(ASheet, alClient, 0,
    [MHL('Оценка', 'Score'), MHL('Уровень', 'Level'), MHL('Что найдено', 'What was found'), MHL('Файл', 'File'),
     MHL('Размер', 'Size')], [55, 140, 330, 480, 80]);
  FHitsView.OnSelectItem := HitSelect;
  UpdateButtons;
end;

destructor TMHDisksPage.Destroy;
begin
  // Проверка отменяется (отмена проверяется на каждом файле) и дожидается завершения.
  FScanCancel := True;
  FreeAndNil(FScanThread);
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

  function IoTotal(const AInfo: TMHProcessInfo): Double;
  begin
    Result := 0;
    if AInfo.IoRead.HasValue then
      Result := Result + AInfo.IoRead.Value;
    if AInfo.IoWrite.HasValue then
      Result := Result + AInfo.IoWrite.Value;
  end;

begin
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
    end;
  finally
    FDisks.Items.EndUpdate;
  end;

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
    FIo.Items.BeginUpdate;
    try
      FIo.Items.Clear;
      for I := 0 to Min(LList.Count, 10) - 1 do
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
  finally
    LList.Free;
  end;
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
