unit MineHunter.Tests.Appearance;

{
  Язык интерфейса (словарь и перевод компонентов), тёмная тема (встроенный
  стиль VCL) и проверка обновлений на GitHub (разбор ответа, сравнение версий,
  сбои сети — на поддельном HTTP).
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Updates;

type
  TFakeHttpGet = class(TInterfacedObject, IMHHttpGet)
  public
    Status: Integer;
    Body: string;
    Fails: Boolean;
    Raises: Boolean;
    Calls: Integer;
    LastUrl: string;
    function Get(const AUrl: string; out AStatus: Integer; out ABody: string; out AError: string): Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TLanguageTests = class
  public
    [TearDown] procedure TearDown;
    [Test] procedure Russian_IsIdentity;
    [Test] procedure English_TranslatesKnownAndKeepsUnknown;
    [Test] procedure TranslateTree_ComponentsListsAndColumns;
    [Test] procedure Dictionary_HasNoDuplicateKeys;
  end;

  [TestFixture]
  [Category('UI')]
  TThemeTests = class
  public
    [Test] procedure DarkStyle_IsEmbeddedAndSwitchable;
  end;

  [TestFixture]
  [Category('Unit')]
  TUpdateTests = class
  public
    [Test] procedure CompareVersions;
    [Test] procedure Parse_NewerSameOlder;
    [Test] procedure Parse_NoReleasesAndErrors;
    [Test] procedure Parse_ForeignUrl_ReplacedWithReleasesPage;
    [Test] procedure Check_NetworkFailureAndException;
  end;

implementation

uses
  System.Classes, Vcl.Forms, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.Graphics, Vcl.Themes,
  MineHunter.Core.Settings, MineHunter.App.Lang, MineHunter.App.Theme;

{ TFakeHttpGet }

function TFakeHttpGet.Get(const AUrl: string; out AStatus: Integer; out ABody: string;
  out AError: string): Boolean;
begin
  Inc(Calls);
  LastUrl := AUrl;
  if Raises then
    raise Exception.Create('сбой сокета');
  AStatus := Status;
  ABody := Body;
  if Fails then
  begin
    AError := 'нет соединения';
    Exit(False);
  end;
  AError := '';
  Result := True;
end;

{ TLanguageTests }

procedure TLanguageTests.TearDown;
begin
  MHSetLanguage(ulRussian);
end;

procedure TLanguageTests.Russian_IsIdentity;
begin
  MHSetLanguage(ulRussian);
  Assert.AreEqual('Обзор', MHTr('Обзор'));
  Assert.AreEqual('&Обновить', MHTr('&Обновить'));
  Assert.AreEqual('', MHTr(''));
end;

procedure TLanguageTests.English_TranslatesKnownAndKeepsUnknown;
begin
  MHSetLanguage(ulEnglish);
  Assert.AreEqual(Ord(ulEnglish), Ord(MHLanguage));
  Assert.AreEqual('Overview', MHTr('Обзор'));
  Assert.AreEqual('Refresh', MHTr('&Обновить'), 'Ускоритель отбрасывается');
  Assert.AreEqual('Shown 3 of 7', Format(MHTr('Показано %d из %d'), [3, 7]));
  Assert.AreEqual('Неизвестная строка', MHTr('Неизвестная строка'));
  Assert.AreEqual('Overview', MHTr('Overview'), 'Повторный перевод ничего не меняет');
end;

procedure TLanguageTests.TranslateTree_ComponentsListsAndColumns;
var
  LForm: TForm;
  LButton: TButton;
  LCombo: TComboBox;
  LList: TListView;
begin
  LForm := TForm.CreateNew(nil);
  try
    LForm.Caption := 'Настройки';
    LButton := TButton.Create(LForm);
    LButton.Parent := LForm;
    LButton.Caption := '&Обновить';
    LButton.Hint := 'Имя';
    LCombo := TComboBox.Create(LForm);
    LCombo.Parent := LForm;
    LCombo.Style := csDropDownList;
    LCombo.Items.Add('1 час');
    LCombo.Items.Add('7 дней');
    LCombo.ItemIndex := 1;
    LList := TListView.Create(LForm);
    LList.Parent := LForm;
    LList.ViewStyle := vsReport;
    LList.Columns.Add.Caption := 'Путь';
    MHSetLanguage(ulRussian);
    MHTranslateTree(LForm);
    Assert.AreEqual('&Обновить', LButton.Caption, 'Русский — без изменений');
    MHSetLanguage(ulEnglish);
    MHTranslateTree(LForm);
    Assert.AreEqual('Settings', LForm.Caption);
    Assert.AreEqual('Refresh', LButton.Caption);
    Assert.AreEqual('Name', LButton.Hint);
    Assert.AreEqual('7 days', LCombo.Items[1]);
    Assert.AreEqual(1, LCombo.ItemIndex, 'Выбор сохраняется');
    Assert.AreEqual('Path', LList.Columns[0].Caption);
  finally
    LForm.Free;
  end;
end;

procedure TLanguageTests.Dictionary_HasNoDuplicateKeys;
begin
  // Словарь строится при первом обращении; повторяющийся ключ дал бы молча другой перевод.
  MHSetLanguage(ulEnglish);
  Assert.AreEqual('Settings', MHTr('Настройки'));
  Assert.AreEqual('Findings', MHTr('Находки'));
  Assert.AreEqual('Exit', MHTr('Выход'));
end;

{ TThemeTests }

procedure TThemeTests.DarkStyle_IsEmbeddedAndSwitchable;
var
  LLightWindow, LDarkWindow: TColor;
begin
  Assert.IsTrue(MHDarkThemeAvailable, 'Стиль Windows10 Dark встроен ресурсом VCLSTYLE');
  LLightWindow := MHThemeColor(clWindow);
  try
    Assert.IsTrue(MHApplyTheme(utDark));
    Assert.IsTrue(MHIsDarkTheme);
    LDarkWindow := MHThemeColor(clWindow);
    Assert.AreNotEqual(Integer(ColorToRGB(LLightWindow)), Integer(ColorToRGB(LDarkWindow)),
      'Собственные элементы получают цвета стиля');
    Assert.IsTrue(MHApplyTheme(utDark), 'Повторное применение — не ошибка');
  finally
    Assert.IsTrue(MHApplyTheme(utLight));
  end;
  Assert.IsFalse(MHIsDarkTheme);
  Assert.IsTrue(TStyleManager.ActiveStyle.IsSystemStyle);
end;

{ TUpdateTests }

procedure TUpdateTests.CompareVersions;
begin
  Assert.AreEqual(0, MHCompareVersions('0.1.0', '0.1.0'));
  Assert.AreEqual(0, MHCompareVersions('v0.1', '0.1.0'));
  Assert.IsTrue(MHCompareVersions('0.2.0', '0.1.9') > 0);
  Assert.IsTrue(MHCompareVersions('0.10.0', '0.9.0') > 0, 'Числовое, а не строковое сравнение');
  Assert.IsTrue(MHCompareVersions('1.0.0-beta', '1.0.1') < 0);
  Assert.IsTrue(MHCompareVersions('v2', '1.99.99') > 0);
end;

function ReleaseJson(const ATag, AUrl: string): string;
begin
  Result := Format('{"tag_name":"%s","name":"MineHunter X %s","html_url":"%s","assets":[]}', [ATag, ATag, AUrl]);
end;

procedure TUpdateTests.Parse_NewerSameOlder;
var
  LInfo: TMHUpdateInfo;
begin
  LInfo := MHParseLatestRelease(200, ReleaseJson('v0.2.0',
    'https://github.com/kazann116/MineHunterX/releases/tag/v0.2.0'), '0.1.0');
  Assert.AreEqual(Ord(usAvailable), Ord(LInfo.State));
  Assert.AreEqual('0.2.0', LInfo.LatestVersion);
  Assert.AreEqual('https://github.com/kazann116/MineHunterX/releases/tag/v0.2.0', LInfo.ReleaseUrl);
  Assert.IsTrue(LInfo.Message.Contains('0.2.0'));
  Assert.AreEqual(Ord(usUpToDate), Ord(MHParseLatestRelease(200, ReleaseJson('v0.1.0',
    'https://github.com/kazann116/MineHunterX/releases/tag/v0.1.0'), '0.1.0').State));
  Assert.AreEqual(Ord(usUpToDate), Ord(MHParseLatestRelease(200, ReleaseJson('0.0.9',
    'https://github.com/kazann116/MineHunterX/releases/tag/0.0.9'), '0.1.0').State), 'Старее — не предлагается');
end;

procedure TUpdateTests.Parse_NoReleasesAndErrors;
begin
  Assert.AreEqual(Ord(usNoReleases), Ord(MHParseLatestRelease(404, '{"message":"Not Found"}', '0.1.0').State));
  Assert.AreEqual(Ord(usFailed), Ord(MHParseLatestRelease(403, '{"message":"rate limit"}', '0.1.0').State));
  Assert.AreEqual(Ord(usFailed), Ord(MHParseLatestRelease(200, 'не json', '0.1.0').State));
  Assert.AreEqual(Ord(usFailed), Ord(MHParseLatestRelease(200, '[]', '0.1.0').State));
  Assert.AreEqual(Ord(usFailed), Ord(MHParseLatestRelease(200, '{"tag_name":"latest"}', '0.1.0').State));
end;

procedure TUpdateTests.Parse_ForeignUrl_ReplacedWithReleasesPage;
var
  LInfo: TMHUpdateInfo;
begin
  // Ссылка из ответа открывается в браузере — разрешена только страница этого проекта.
  LInfo := MHParseLatestRelease(200, ReleaseJson('v9.0.0', 'https://evil.example/download.exe'), '0.1.0');
  Assert.AreEqual(Ord(usAvailable), Ord(LInfo.State));
  Assert.AreEqual(MH_RELEASES_PAGE, LInfo.ReleaseUrl);
end;

procedure TUpdateTests.Check_NetworkFailureAndException;
var
  LHttp: TFakeHttpGet;
  LIntf: IMHHttpGet;
  LInfo: TMHUpdateInfo;
begin
  LHttp := TFakeHttpGet.Create;
  LIntf := LHttp;
  LHttp.Fails := True;
  LInfo := MHCheckForUpdate(LIntf, '0.1.0');
  Assert.AreEqual(Ord(usFailed), Ord(LInfo.State));
  Assert.IsTrue(LInfo.Message.Contains('нет соединения'));
  Assert.AreEqual(MH_UPDATE_URL, LHttp.LastUrl, 'Запрашивается только API последнего выпуска');
  LHttp.Fails := False;
  LHttp.Raises := True;
  Assert.AreEqual(Ord(usFailed), Ord(MHCheckForUpdate(LIntf, '0.1.0').State));
  LHttp.Raises := False;
  LHttp.Status := 200;
  LHttp.Body := ReleaseJson('v1.0.0', 'https://github.com/kazann116/MineHunterX/releases/tag/v1.0.0');
  Assert.AreEqual(Ord(usAvailable), Ord(MHCheckForUpdate(LIntf, '0.1.0').State));
  Assert.WillRaise(
    procedure
    begin
      MHCheckForUpdate(nil, '0.1.0');
    end, EArgumentNilException);
end;

initialization
  TDUnitX.RegisterTestFixture(TLanguageTests);
  TDUnitX.RegisterTestFixture(TThemeTests);
  TDUnitX.RegisterTestFixture(TUpdateTests);

end.
