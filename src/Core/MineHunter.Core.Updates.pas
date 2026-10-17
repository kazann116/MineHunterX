unit MineHunter.Core.Updates;

{
  Проверка новых версий на GitHub (по согласию пользователя — настройка
  CheckForUpdates выключена по умолчанию). Запрашивается только
  https://api.github.com/repos/<репозиторий>/releases/latest; о компьютере
  ничего не передаётся, кроме обычного заголовка User-Agent с версией
  программы. Ничего не скачивается и не устанавливается автоматически —
  пользователю показывается ссылка на страницу выпуска.
}

interface

uses
  System.SysUtils;

const
  MH_UPDATE_REPOSITORY = 'kazann116/MineHunterX';
  MH_UPDATE_URL = 'https://api.github.com/repos/' + MH_UPDATE_REPOSITORY + '/releases/latest';
  MH_RELEASES_PAGE = 'https://github.com/' + MH_UPDATE_REPOSITORY + '/releases';

type
  TMHUpdateState = (usUpToDate, usAvailable, usNoReleases, usFailed);

  TMHUpdateInfo = record
  public
    State: TMHUpdateState;
    CurrentVersion: string;
    LatestVersion: string;
    ReleaseUrl: string;
    ReleaseName: string;
    /// Понятное описание результата для пользователя.
    Message: string;
  end;

  /// HTTP GET (подменяется в тестах). AStatus — код ответа HTTP (0 — сбой соединения).
  IMHHttpGet = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1D00}']
    function Get(const AUrl: string; out AStatus: Integer; out ABody: string; out AError: string): Boolean;
  end;

/// Сравнение версий «1.2.3» (префикс v и суффиксы -beta допускаются): <0, 0, >0.
function MHCompareVersions(const A, B: string): Integer;

/// Разбор ответа releases/latest.
function MHParseLatestRelease(AStatus: Integer; const ABody, ACurrentVersion: string): TMHUpdateInfo;

function MHCheckForUpdate(const AHttp: IMHHttpGet; const ACurrentVersion: string): TMHUpdateInfo;

implementation

uses
  System.JSON, System.Math;

function VersionParts(const AVersion: string): TArray<Integer>;
var
  LText, LPart: string;
  LValue, LEnd: Integer;
begin
  Result := nil;
  LText := Trim(AVersion);
  if LText.StartsWith('v', True) then
    Delete(LText, 1, 1);
  LEnd := LText.IndexOfAny(['-', '+', ' ']);
  if LEnd >= 0 then
    LText := LText.Substring(0, LEnd);
  for LPart in LText.Split(['.']) do
  begin
    if not TryStrToInt(LPart, LValue) or (LValue < 0) then
      Exit(nil);
    Result := Result + [LValue];
  end;
end;

function MHCompareVersions(const A, B: string): Integer;
var
  LA, LB: TArray<Integer>;
  I, LX, LY: Integer;
begin
  LA := VersionParts(A);
  LB := VersionParts(B);
  for I := 0 to Max(High(LA), High(LB)) do
  begin
    if I <= High(LA) then
      LX := LA[I]
    else
      LX := 0;
    if I <= High(LB) then
      LY := LB[I]
    else
      LY := 0;
    if LX <> LY then
      Exit(CompareValue(LX, LY));
  end;
  Result := 0;
end;

function MHParseLatestRelease(AStatus: Integer; const ABody, ACurrentVersion: string): TMHUpdateInfo;
var
  LJson: TJSONValue;
  LTag, LUrl, LName: string;
begin
  Result := Default(TMHUpdateInfo);
  Result.CurrentVersion := ACurrentVersion;
  Result.ReleaseUrl := MH_RELEASES_PAGE;
  if AStatus = 404 then
  begin
    Result.State := usNoReleases;
    Result.Message := 'Опубликованных выпусков пока нет — у вас актуальная версия ' + ACurrentVersion + '.';
    Exit;
  end;
  if AStatus <> 200 then
  begin
    Result.State := usFailed;
    Result.Message := Format('Сервер GitHub ответил кодом %d — попробуйте позже.', [AStatus]);
    Exit;
  end;
  LJson := TJSONObject.ParseJSONValue(ABody);
  try
    if not (LJson is TJSONObject) or not TJSONObject(LJson).TryGetValue<string>('tag_name', LTag) or
       (VersionParts(LTag) = nil) then
    begin
      Result.State := usFailed;
      Result.Message := 'Не удалось разобрать ответ GitHub.';
      Exit;
    end;
    if TJSONObject(LJson).TryGetValue<string>('html_url', LUrl) and
       LUrl.StartsWith('https://github.com/' + MH_UPDATE_REPOSITORY + '/', True) then
      Result.ReleaseUrl := LUrl;
    if TJSONObject(LJson).TryGetValue<string>('name', LName) then
      Result.ReleaseName := LName;
  finally
    LJson.Free;
  end;
  Result.LatestVersion := LTag;
  if LTag.StartsWith('v', True) then
    Result.LatestVersion := Copy(LTag, 2, MaxInt);
  if MHCompareVersions(Result.LatestVersion, ACurrentVersion) > 0 then
  begin
    Result.State := usAvailable;
    Result.Message := Format('Доступна новая версия %s (у вас %s). Скачайте её со страницы выпуска.',
      [Result.LatestVersion, ACurrentVersion]);
  end
  else
  begin
    Result.State := usUpToDate;
    Result.Message := 'У вас последняя версия ' + ACurrentVersion + '.';
  end;
end;

function MHCheckForUpdate(const AHttp: IMHHttpGet; const ACurrentVersion: string): TMHUpdateInfo;
var
  LStatus: Integer;
  LBody, LError: string;
begin
  if AHttp = nil then
    raise EArgumentNilException.Create('AHttp');
  try
    if not AHttp.Get(MH_UPDATE_URL, LStatus, LBody, LError) then
    begin
      Result := Default(TMHUpdateInfo);
      Result.State := usFailed;
      Result.CurrentVersion := ACurrentVersion;
      Result.ReleaseUrl := MH_RELEASES_PAGE;
      Result.Message := 'Не удалось связаться с GitHub: ' + LError;
      Exit;
    end;
  except
    on E: Exception do
    begin
      Result := Default(TMHUpdateInfo);
      Result.State := usFailed;
      Result.CurrentVersion := ACurrentVersion;
      Result.ReleaseUrl := MH_RELEASES_PAGE;
      Result.Message := 'Не удалось связаться с GitHub: ' + E.Message;
      Exit;
    end;
  end;
  Result := MHParseLatestRelease(LStatus, LBody, ACurrentVersion);
end;

end.
