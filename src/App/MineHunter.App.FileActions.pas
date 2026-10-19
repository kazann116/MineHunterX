unit MineHunter.App.FileActions;

{
  Действия с файлом прямо из таблицы (запуски, процессы, «что изменилось»):
    - «Подробности…» (и двойной щелчок) — полный путь, параметры запуска и
      остальные сведения, которые не помещаются в столбцы;
    - «Открыть папку и выделить файл» — Проводник с выделенным файлом;
    - «Проверить на VirusTotal…» — в браузере открывается отчёт VirusTotal по
      SHA-256 файла. Хеш считается здесь же; сам файл никуда не отправляется.
      Перед первым переходом за сеанс — подтверждение: это обращение к сайту;
    - «Копировать путь и параметры»;
    - «Открыть в BinaryLab» — глубокий разбор файла (если задан OnBinaryLab).
  Подключается к таблице контекстным меню и двойным щелчком; данные строки
  отдаёт функция таблицы (TMHFileTargetFunc).
}

interface

uses
  System.SysUtils, System.Classes, Vcl.Controls, Vcl.ComCtrls, Vcl.Menus;

type
  TMHFileTarget = record
    Title: string;
    Path: string;
    CommandLine: string;
    Sha256: string;
    /// Дополнительные строки «Название: значение».
    Details: TArray<string>;
  end;

  TMHFileTargetFunc = reference to function(out ATarget: TMHFileTarget): Boolean;
  TMHFileConfirm = reference to function(const AQuestion: string): Boolean;
  /// Открытие файла, папки или адреса оболочкой Windows (тесты подменяют).
  TMHShellOpen = reference to procedure(const AFile, AParameters: string);
  /// Передача файла в BinaryLab (задаёт главное окно).
  TMHFileTargetProc = reference to procedure(const ATarget: TMHFileTarget);

  TMHFileActions = class(TComponent)
  private
    FList: TListView;
    FGetTarget: TMHFileTargetFunc;
    FConfirm: TMHFileConfirm;
    FShellOpen: TMHShellOpen;
    FMenu: TPopupMenu;
    FItemDetails, FItemOpen, FItemVirusTotal, FItemCopy, FItemBinaryLab: TMenuItem;
    FLastError: string;
    FOnBinaryLab: TMHFileTargetProc;
    function NewItem(const ACaption: string; AClick: TNotifyEvent): TMenuItem;
    procedure MenuPopup(Sender: TObject);
    procedure DetailsClick(Sender: TObject);
    procedure OpenClick(Sender: TObject);
    procedure VirusTotalClick(Sender: TObject);
    procedure CopyClick(Sender: TObject);
    procedure BinaryLabClick(Sender: TObject);
    procedure ListDblClick(Sender: TObject);
    procedure ReportError;
  public
    constructor Create(AOwner: TComponent; AList: TListView; const AGetTarget: TMHFileTargetFunc;
      const AConfirm: TMHFileConfirm); reintroduce;
    /// Проводник с выделенным файлом; нет файла — его папка. False — ни файла, ни папки.
    function ShowInFolder(const ATarget: TMHFileTarget): Boolean;
    /// Отчёт VirusTotal по SHA-256 (при необходимости хеш считается). False — отказ или ошибка.
    function CheckVirusTotal(var ATarget: TMHFileTarget): Boolean;
    procedure CopyToClipboard(const ATarget: TMHFileTarget);
    procedure ShowDetails(const ATarget: TMHFileTarget);
    property Menu: TPopupMenu read FMenu;
    property ShellOpen: TMHShellOpen read FShellOpen write FShellOpen;
    /// «Открыть в BinaryLab»: пункт меню виден, только если обработчик задан.
    property OnBinaryLab: TMHFileTargetProc read FOnBinaryLab write FOnBinaryLab;
    property BinaryLabItem: TMenuItem read FItemBinaryLab;
    property LastError: string read FLastError;
  end;

/// Адрес отчёта VirusTotal по SHA-256.
function MHVirusTotalUrl(const ASha256: string): string;
/// Полные сведения для окна «Подробности».
function MHFileDetailsText(const ATarget: TMHFileTarget): string;
/// Путь с параметрами запуска (для копирования).
function MHFileTargetText(const ATarget: TMHFileTarget): string;
/// SHA-256 файла (чтение с разрешением совместного доступа — работает и для запущенных программ).
function MHFileSha256(const APath: string; out ASha256: string; out AError: string): Boolean;
/// Согласие на переходы к VirusTotal в этом сеансе (тесты сбрасывают).
procedure MHResetVirusTotalConsent;

implementation

uses
  Winapi.Windows, Winapi.ShellAPI, System.Hash, System.UITypes,
  Vcl.Forms, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.Dialogs,
  MineHunter.Core.Lang, MineHunter.Core.Launches, MineHunter.App.ListViews;

var
  GVirusTotalAgreed: Boolean;

procedure MHResetVirusTotalConsent;
begin
  GVirusTotalAgreed := False;
end;

function MHVirusTotalUrl(const ASha256: string): string;
begin
  Result := 'https://www.virustotal.com/gui/file/' + LowerCase(Trim(ASha256));
end;

function MHFileTargetText(const ATarget: TMHFileTarget): string;
var
  LArguments: string;
begin
  if ATarget.Path = '' then
    Exit(Trim(ATarget.CommandLine));
  Result := ATarget.Path;
  LArguments := MHCommandLineArguments(ATarget.CommandLine);
  if LArguments <> '' then
    Result := Result + ' ' + LArguments;
end;

function MHFileDetailsText(const ATarget: TMHFileTarget): string;
var
  LLines: TStringList;
  LLine, LArguments: string;
begin
  LLines := TStringList.Create;
  try
    LLines.Add(ATarget.Title);
    LLines.Add('');
    if ATarget.Path <> '' then
      LLines.Add(MHL('Путь: ', 'Path: ') + ATarget.Path)
    else
      LLines.Add(MHL('Путь: не известен', 'Path: unknown'));
    if ATarget.CommandLine <> '' then
    begin
      LArguments := MHCommandLineArguments(ATarget.CommandLine);
      if LArguments <> '' then
        LLines.Add(MHL('Параметры запуска: ', 'Arguments: ') + LArguments)
      else
        LLines.Add(MHL('Параметры запуска: нет', 'Arguments: none'));
      LLines.Add(MHL('Командная строка: ', 'Command line: ') + ATarget.CommandLine);
    end
    else
      LLines.Add(MHL('Параметры запуска: не прочитаны (процесс завершился раньше или защищён)',
        'Arguments: not read (the process ended earlier or is protected)'));
    for LLine in ATarget.Details do
      LLines.Add(LLine);
    if ATarget.Sha256 <> '' then
      LLines.Add('SHA-256: ' + ATarget.Sha256);
    Result := LLines.Text.TrimRight;
  finally
    LLines.Free;
  end;
end;

function MHFileSha256(const APath: string; out ASha256: string; out AError: string): Boolean;
var
  LStream: TFileStream;
  LHash: THashSHA2;
  LBuffer: TBytes;
  LRead: Integer;
begin
  ASha256 := '';
  AError := '';
  try
    LStream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      LHash := THashSHA2.Create(SHA256);
      SetLength(LBuffer, 1024 * 1024);
      repeat
        LRead := LStream.Read(LBuffer[0], Length(LBuffer));
        if LRead > 0 then
          LHash.Update(LBuffer, LRead);
      until LRead <= 0;
      ASha256 := LHash.HashAsString.ToLower;
    finally
      LStream.Free;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      AError := E.Message;
      Result := False;
    end;
  end;
end;

{ TMHFileActions }

constructor TMHFileActions.Create(AOwner: TComponent; AList: TListView; const AGetTarget: TMHFileTargetFunc;
  const AConfirm: TMHFileConfirm);
begin
  inherited Create(AOwner);
  FList := AList;
  FGetTarget := AGetTarget;
  FConfirm := AConfirm;
  FShellOpen :=
    procedure(const AFile, AParameters: string)
    begin
      ShellExecute(0, 'open', PChar(AFile), PChar(AParameters), nil, SW_SHOWNORMAL);
    end;
  FMenu := TPopupMenu.Create(Self);
  FMenu.OnPopup := MenuPopup;
  FItemDetails := NewItem(MHL('Подробности…', 'Details…'), DetailsClick);
  FItemDetails.Default := True;
  FItemOpen := NewItem(MHL('Открыть папку и выделить файл', 'Open folder and select the file'), OpenClick);
  FItemVirusTotal := NewItem(MHL('Проверить на VirusTotal…', 'Check on VirusTotal…'), VirusTotalClick);
  FItemCopy := NewItem(MHL('Копировать путь и параметры', 'Copy path and arguments'), CopyClick);
  FItemBinaryLab := NewItem(MHL('Открыть в BinaryLab (разбор файла)', 'Open in BinaryLab (file analysis)'),
    BinaryLabClick);
  FItemBinaryLab.Visible := False;
  FList.PopupMenu := FMenu;
  FList.OnDblClick := ListDblClick;
end;

function TMHFileActions.NewItem(const ACaption: string; AClick: TNotifyEvent): TMenuItem;
begin
  Result := TMenuItem.Create(FMenu);
  Result.Caption := ACaption;
  Result.OnClick := AClick;
  FMenu.Items.Add(Result);
end;

procedure TMHFileActions.MenuPopup(Sender: TObject);
var
  LTarget: TMHFileTarget;
  LHas: Boolean;
begin
  LHas := FGetTarget(LTarget);
  FItemDetails.Enabled := LHas;
  FItemOpen.Enabled := LHas and (LTarget.Path <> '');
  FItemVirusTotal.Enabled := LHas and ((LTarget.Path <> '') or (LTarget.Sha256 <> ''));
  FItemCopy.Enabled := LHas and ((LTarget.Path <> '') or (LTarget.CommandLine <> ''));
  FItemBinaryLab.Visible := Assigned(FOnBinaryLab);
  FItemBinaryLab.Enabled := LHas and (LTarget.Path <> '') and FileExists(LTarget.Path);
end;

procedure TMHFileActions.BinaryLabClick(Sender: TObject);
var
  LTarget: TMHFileTarget;
begin
  if Assigned(FOnBinaryLab) and FGetTarget(LTarget) and (LTarget.Path <> '') then
    FOnBinaryLab(LTarget);
end;

procedure TMHFileActions.ReportError;
begin
  if (FLastError <> '') and (FLastError <> MHL('Отменено пользователем', 'Cancelled by the user')) then
    MessageDlg(FLastError, mtWarning, [mbOK], 0);
end;

function TMHFileActions.ShowInFolder(const ATarget: TMHFileTarget): Boolean;
var
  LDir: string;
begin
  FLastError := '';
  if (ATarget.Path <> '') and FileExists(ATarget.Path) then
  begin
    FShellOpen('explorer.exe', '/select,"' + ATarget.Path + '"');
    Exit(True);
  end;
  LDir := ExtractFileDir(ATarget.Path);
  if (LDir <> '') and DirectoryExists(LDir) then
  begin
    FShellOpen(LDir, '');
    Exit(True);
  end;
  FLastError := Format(MHL('Файл не найден: %s', 'File not found: %s'), [ATarget.Path]);
  Result := False;
end;

function TMHFileActions.CheckVirusTotal(var ATarget: TMHFileTarget): Boolean;
var
  LCursor: TCursor;
  LError: string;
begin
  FLastError := '';
  if ATarget.Sha256 = '' then
  begin
    if (ATarget.Path = '') or not FileExists(ATarget.Path) then
    begin
      FLastError := Format(MHL('Файл не найден — отпечаток для VirusTotal посчитать нельзя: %s',
        'File not found, so its fingerprint for VirusTotal cannot be calculated: %s'), [ATarget.Path]);
      Exit(False);
    end;
    LCursor := Screen.Cursor;
    Screen.Cursor := crHourGlass;
    try
      if not MHFileSha256(ATarget.Path, ATarget.Sha256, LError) then
      begin
        FLastError := Format(MHL('Не удалось прочитать файл: %s', 'Could not read the file: %s'), [LError]);
        Exit(False);
      end;
    finally
      Screen.Cursor := LCursor;
    end;
  end;
  if not GVirusTotalAgreed then
  begin
    if not FConfirm(Format(MHL('Открыть на сайте VirusTotal отчёт о файле «%s»?' + sLineBreak + sLineBreak +
      'В браузере откроется страница virustotal.com с отпечатком SHA-256 файла (%s). Сам файл не ' +
      'отправляется — VirusTotal узнает только отпечаток. Если отчёта нет, файл можно загрузить на сайте ' +
      'вручную.' + sLineBreak + sLineBreak + 'В этом сеансе программа больше не будет спрашивать.',
      'Open the VirusTotal report for the file "%s"?' + sLineBreak + sLineBreak + 'Your browser opens ' +
      'virustotal.com with the SHA-256 fingerprint of the file (%s). The file itself is not sent — VirusTotal ' +
      'only learns the fingerprint. If there is no report, you can upload the file on the site manually.' +
      sLineBreak + sLineBreak + 'The program will not ask again in this session.'),
      [ExtractFileName(ATarget.Path), ATarget.Sha256])) then
    begin
      FLastError := MHL('Отменено пользователем', 'Cancelled by the user');
      Exit(False);
    end;
    GVirusTotalAgreed := True;
  end;
  FShellOpen(MHVirusTotalUrl(ATarget.Sha256), '');
  Result := True;
end;

procedure TMHFileActions.CopyToClipboard(const ATarget: TMHFileTarget);
begin
  if Assigned(GMHSetClipboardText) then
    GMHSetClipboardText(MHFileTargetText(ATarget));
end;

procedure TMHFileActions.ShowDetails(const ATarget: TMHFileTarget);
var
  LForm: TForm;
  LMemo: TMemo;
  LButtons: TPanel;
  LTarget: TMHFileTarget;
  LLeft: Integer;

  function AddButton(const ACaption: string; AWidth: Integer): TButton;
  begin
    Result := TButton.Create(LForm);
    Result.Parent := LButtons;
    Result.SetBounds(LLeft, 8, AWidth, 28);
    Result.Caption := ACaption;
    LLeft := LLeft + AWidth + 8;
  end;

begin
  LTarget := ATarget;
  LForm := TForm.CreateNew(nil);
  try
    LForm.Caption := MHL('Подробности — ', 'Details — ') + ATarget.Title;
    LForm.Position := poMainFormCenter;
    LForm.BorderIcons := [biSystemMenu];
    LForm.SetBounds(0, 0, 820, 360);
    LButtons := TPanel.Create(LForm);
    LButtons.Parent := LForm;
    LButtons.Align := alBottom;
    LButtons.Height := 44;
    LButtons.BevelOuter := bvNone;
    LMemo := TMemo.Create(LForm);
    LMemo.Parent := LForm;
    LMemo.Align := alClient;
    LMemo.ReadOnly := True;
    LMemo.ScrollBars := ssVertical;
    LMemo.WordWrap := True;
    LMemo.Text := MHFileDetailsText(LTarget);
    LLeft := 8;
    with AddButton(MHL('Открыть папку и выделить файл', 'Open folder and select the file'), 230) do
    begin
      Enabled := LTarget.Path <> '';
      OnClick := OpenClick;
    end;
    with AddButton(MHL('Проверить на VirusTotal…', 'Check on VirusTotal…'), 200) do
    begin
      Enabled := (LTarget.Path <> '') or (LTarget.Sha256 <> '');
      OnClick := VirusTotalClick;
    end;
    with AddButton(MHL('Копировать путь и параметры', 'Copy path and arguments'), 220) do
      OnClick := CopyClick;
    with AddButton(MHL('Закрыть', 'Close'), 100) do
    begin
      ModalResult := mrCancel;
      Cancel := True;
    end;
    LForm.ShowModal;
  finally
    LForm.Free;
  end;
end;

procedure TMHFileActions.DetailsClick(Sender: TObject);
var
  LTarget: TMHFileTarget;
begin
  if FGetTarget(LTarget) then
    ShowDetails(LTarget);
end;

procedure TMHFileActions.OpenClick(Sender: TObject);
var
  LTarget: TMHFileTarget;
begin
  if FGetTarget(LTarget) and not ShowInFolder(LTarget) then
    ReportError;
end;

procedure TMHFileActions.VirusTotalClick(Sender: TObject);
var
  LTarget: TMHFileTarget;
begin
  if FGetTarget(LTarget) and not CheckVirusTotal(LTarget) then
    ReportError;
end;

procedure TMHFileActions.CopyClick(Sender: TObject);
var
  LTarget: TMHFileTarget;
begin
  if FGetTarget(LTarget) then
    CopyToClipboard(LTarget);
end;

procedure TMHFileActions.ListDblClick(Sender: TObject);
begin
  if FList.Selected <> nil then
    DetailsClick(Sender);
end;

end.
