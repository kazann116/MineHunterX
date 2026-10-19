unit MineHunter.Tests.UI.FileActions;

{
  Действия с файлом из таблиц: подробности (полный путь и параметры), папка с
  выделенным файлом, VirusTotal по SHA-256 (подтверждение один раз за сеанс,
  файл не отправляется), копирование. Оболочка Windows подменяется — тесты
  не открывают Проводник и браузер.
}

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework,
  Vcl.Forms, Vcl.Controls, Vcl.ComCtrls,
  MineHunter.App.FileActions;

type
  [TestFixture]
  [Category('UI')]
  TFileActionsTests = class
  private
    FForm: TForm;
    FList: TListView;
    FActions: TMHFileActions;
    FOpened: TStringList;
    FAsked: Integer;
    FAnswer: Boolean;
    FTarget: TMHFileTarget;
    FHasTarget: Boolean;
    FDir: string;
    FHiddenPath: string;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure DetailsText_FullPathArgumentsAndDetails;
    [Test] procedure Sha256_OfFile;
    [Test] procedure ShowInFolder_SelectsFileOrOpensFolder;
    [Test] procedure ShowInFolder_HiddenFile_ExplainsAndAsks;
    [Test] procedure VirusTotal_HashOnlyConsentOncePerSession;
    [Test] procedure Menu_ItemsFollowSelectedRow;
    [Test] procedure Menu_OpenInBinaryLab;
  end;

implementation

uses
  System.IOUtils, Winapi.Windows;

procedure TFileActionsTests.Setup;
begin
  FForm := TForm.CreateNew(nil);
  FList := TListView.Create(FForm);
  FList.Parent := FForm;
  FList.ViewStyle := vsReport;
  FOpened := TStringList.Create;
  FAsked := 0;
  FAnswer := True;
  FHasTarget := True;
  FTarget := Default(TMHFileTarget);
  MHResetVirusTotalConsent;
  FActions := TMHFileActions.Create(FForm, FList,
    function(out ATarget: TMHFileTarget): Boolean
    begin
      ATarget := FTarget;
      Result := FHasTarget;
    end,
    function(const AQuestion: string): Boolean
    begin
      Inc(FAsked);
      Result := FAnswer;
    end);
  FActions.ShellOpen :=
    procedure(const AFile, AParameters: string)
    begin
      FOpened.Add(AFile + '|' + AParameters);
    end;
  // Атрибуты не зависят от того, что временная папка лежит в скрытой AppData.
  FHiddenPath := '';
  FActions.GetAttributes :=
    function(const APath: string): Cardinal
    begin
      if SameText(APath, FHiddenPath) then
        Result := FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM
      else
        Result := FILE_ATTRIBUTE_NORMAL;
    end;
  FDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\fileactions-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(FDir);
end;

procedure TFileActionsTests.TearDown;
begin
  FForm.Free;
  FOpened.Free;
  MHResetVirusTotalConsent;
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог тестов.
  end;
end;

procedure TFileActionsTests.DetailsText_FullPathArgumentsAndDetails;
var
  LTarget: TMHFileTarget;
  LText: string;
begin
  LTarget := Default(TMHFileTarget);
  LTarget.Title := 'setup.exe';
  LTarget.Path := 'C:\Users\User\Downloads\setup.exe';
  LTarget.CommandLine := '"C:\Users\User\Downloads\setup.exe" /S /D=C:\Apps';
  LTarget.Details := ['PID: 4242'];
  LText := MHFileDetailsText(LTarget);
  Assert.IsTrue(LText.Contains('Путь: C:\Users\User\Downloads\setup.exe'), LText);
  Assert.IsTrue(LText.Contains('Параметры запуска: /S /D=C:\Apps'), LText);
  Assert.IsTrue(LText.Contains('Командная строка: "C:\Users\User\Downloads\setup.exe" /S /D=C:\Apps'), LText);
  Assert.IsTrue(LText.Contains('PID: 4242'), LText);
  Assert.AreEqual('C:\Users\User\Downloads\setup.exe /S /D=C:\Apps', MHFileTargetText(LTarget), 'Для копирования');
  LTarget.CommandLine := '';
  Assert.IsTrue(MHFileDetailsText(LTarget).Contains('не прочитаны'), 'Понятно, почему параметров нет');
  Assert.AreEqual('https://www.virustotal.com/gui/file/abcdef', MHVirusTotalUrl(' ABCDEF '));
end;

procedure TFileActionsTests.Sha256_OfFile;
var
  LPath, LSha, LError: string;
begin
  LPath := TPath.Combine(FDir, 'abc.txt');
  TFile.WriteAllText(LPath, 'abc', TEncoding.ASCII);
  Assert.IsTrue(MHFileSha256(LPath, LSha, LError), LError);
  Assert.AreEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', LSha);
  Assert.IsFalse(MHFileSha256(TPath.Combine(FDir, 'none.txt'), LSha, LError));
  Assert.IsNotEmpty(LError);
end;

procedure TFileActionsTests.ShowInFolder_SelectsFileOrOpensFolder;
var
  LTarget: TMHFileTarget;
begin
  LTarget := Default(TMHFileTarget);
  LTarget.Path := TPath.Combine(FDir, 'app.exe');
  TFile.WriteAllText(LTarget.Path, 'x');
  Assert.IsTrue(FActions.ShowInFolder(LTarget));
  Assert.AreEqual('explorer.exe|/select,"' + LTarget.Path + '"', FOpened[0], 'Проводник с выделенным файлом');
  Assert.AreEqual(0, FAsked, 'Обычный файл — без вопросов');
  // Файла уже нет, папка осталась — после вопроса открывается папка.
  LTarget.Path := TPath.Combine(FDir, 'gone.exe');
  Assert.IsTrue(FActions.ShowInFolder(LTarget));
  Assert.AreEqual(1, FAsked, 'Сказано, что файла больше нет');
  Assert.AreEqual(FDir + '|', FOpened[1]);
  FAnswer := False;
  Assert.IsFalse(FActions.ShowInFolder(LTarget));
  Assert.AreEqual(2, FOpened.Count, 'Отказ — папка не открывается');
  FAnswer := True;
  LTarget.Path := 'Q:\NoSuchFolder\x.exe';
  Assert.IsFalse(FActions.ShowInFolder(LTarget));
  Assert.IsTrue(FActions.LastError.Contains('не найден'), FActions.LastError);
  Assert.AreEqual(2, FOpened.Count);
end;

procedure TFileActionsTests.ShowInFolder_HiddenFile_ExplainsAndAsks;
var
  LTarget: TMHFileTarget;
  LQuestion: string;
begin
  LTarget := Default(TMHFileTarget);
  LTarget.Path := TPath.Combine(FDir, 'win.exe');
  TFile.WriteAllText(LTarget.Path, 'MZ');
  FHiddenPath := LTarget.Path;
  LQuestion := '';
  FActions.Free;
  FActions := TMHFileActions.Create(FForm, FList,
    function(out ATarget: TMHFileTarget): Boolean
    begin
      ATarget := FTarget;
      Result := FHasTarget;
    end,
    function(const AQuestion: string): Boolean
    begin
      Inc(FAsked);
      LQuestion := AQuestion;
      Result := FAnswer;
    end);
  FActions.ShellOpen :=
    procedure(const AFile, AParameters: string)
    begin
      FOpened.Add(AFile + '|' + AParameters);
    end;
  FActions.GetAttributes :=
    function(const APath: string): Cardinal
    begin
      if SameText(APath, FHiddenPath) then
        Result := FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM
      else
        Result := FILE_ATTRIBUTE_NORMAL;
    end;
  // Отказ: Проводник не открывается, ошибки не показываются.
  FAnswer := False;
  Assert.IsFalse(FActions.ShowInFolder(LTarget));
  Assert.AreEqual(1, FAsked);
  Assert.AreEqual(0, FOpened.Count);
  Assert.Contains(LQuestion, 'скрытый, системный');
  Assert.Contains(LQuestion, 'может выглядеть пустой');
  Assert.Contains(LQuestion, 'Открыть папку в Проводнике?');
  Assert.AreEqual('Отменено пользователем', FActions.LastError);
  // Согласие: Проводник с выделенным файлом.
  FAnswer := True;
  Assert.IsTrue(FActions.ShowInFolder(LTarget));
  Assert.AreEqual('explorer.exe|/select,"' + LTarget.Path + '"', FOpened[0]);
end;

procedure TFileActionsTests.VirusTotal_HashOnlyConsentOncePerSession;
var
  LTarget: TMHFileTarget;
begin
  LTarget := Default(TMHFileTarget);
  LTarget.Path := TPath.Combine(FDir, 'abc.exe');
  TFile.WriteAllText(LTarget.Path, 'abc', TEncoding.ASCII);
  // Отказ — ничего не открывается.
  FAnswer := False;
  Assert.IsFalse(FActions.CheckVirusTotal(LTarget));
  Assert.AreEqual(1, FAsked);
  Assert.AreEqual(0, FOpened.Count);
  // Согласие — страница отчёта по SHA-256 (хеш посчитан здесь же).
  FAnswer := True;
  Assert.IsTrue(FActions.CheckVirusTotal(LTarget));
  Assert.AreEqual(2, FAsked);
  Assert.AreEqual('https://www.virustotal.com/gui/file/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|',
    FOpened[0]);
  // В этом сеансе больше не спрашивает; известный хеш не пересчитывается.
  LTarget := Default(TMHFileTarget);
  LTarget.Sha256 := 'AABB';
  Assert.IsTrue(FActions.CheckVirusTotal(LTarget));
  Assert.AreEqual(2, FAsked);
  Assert.AreEqual('https://www.virustotal.com/gui/file/aabb|', FOpened[1]);
  // Нет ни файла, ни хеша — понятная ошибка.
  LTarget := Default(TMHFileTarget);
  LTarget.Path := TPath.Combine(FDir, 'none.exe');
  Assert.IsFalse(FActions.CheckVirusTotal(LTarget));
  Assert.IsTrue(FActions.LastError.Contains('не найден'), FActions.LastError);
end;

procedure TFileActionsTests.Menu_ItemsFollowSelectedRow;
begin
  Assert.AreEqual(5, FActions.Menu.Items.Count);
  Assert.IsTrue(FList.PopupMenu = FActions.Menu, 'Меню по правой кнопке');
  Assert.IsTrue(Assigned(FList.OnDblClick), 'Двойной щелчок — подробности');
  FTarget.Title := 'tool.exe';
  FTarget.Path := 'C:\Apps\tool.exe';
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsTrue(FActions.Menu.Items[0].Enabled and FActions.Menu.Items[1].Enabled and
    FActions.Menu.Items[2].Enabled and FActions.Menu.Items[3].Enabled);
  // Строка без пути (например, процесс без доступа) — нечего открывать и проверять.
  FTarget.Path := '';
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsTrue(FActions.Menu.Items[0].Enabled, 'Подробности есть всегда');
  Assert.IsFalse(FActions.Menu.Items[1].Enabled);
  Assert.IsFalse(FActions.Menu.Items[2].Enabled);
  FHasTarget := False;
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsFalse(FActions.Menu.Items[0].Enabled, 'Ничего не выбрано');
  // Без обработчика пункт BinaryLab скрыт.
  Assert.IsFalse(FActions.BinaryLabItem.Visible);
end;

procedure TFileActionsTests.Menu_OpenInBinaryLab;
var
  LOpened: string;
begin
  LOpened := '';
  FActions.OnBinaryLab :=
    procedure(const ATarget: TMHFileTarget)
    begin
      LOpened := ATarget.Path;
    end;
  // Существующий файл — пункт виден и доступен, щелчок передаёт путь.
  FTarget.Title := 'tests';
  FTarget.Path := ParamStr(0);
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsTrue(FActions.BinaryLabItem.Visible);
  Assert.IsTrue(FActions.BinaryLabItem.Enabled);
  FActions.BinaryLabItem.Click;
  Assert.AreEqual(ParamStr(0), LOpened);
  // Файла нет на диске или путь неизвестен — разбирать нечего.
  FTarget.Path := 'C:\Нет такой папки	ool.exe';
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsFalse(FActions.BinaryLabItem.Enabled);
  FTarget.Path := '';
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsFalse(FActions.BinaryLabItem.Enabled);
  FHasTarget := False;
  FActions.Menu.OnPopup(FActions.Menu);
  Assert.IsFalse(FActions.BinaryLabItem.Enabled);
end;

initialization
  TDUnitX.RegisterTestFixture(TFileActionsTests);

end.
