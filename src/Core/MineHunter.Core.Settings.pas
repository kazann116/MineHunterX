unit MineHunter.Core.Settings;

{
  MineHunter X — настройки приложения и их хранение в JSON (MH-07).

  Файл: %LOCALAPPDATA%\MineHunterX\settings.json, UTF-8 без BOM.
  Формат: JSON-объект с полем "version": 1 и стабильными именами полей; неизвестные поля
  игнорируются, отсутствующие или неверного типа заменяются значениями по
  умолчанию. Повреждённый файл не удаляется: он переименовывается
  в <имя>.bad-<yyyymmdd-hhnnss> для разбора, а приложение стартует
  с настройками по умолчанию.

  Сохранение атомарное: запись во временный файл <имя>.tmp, FlushFileBuffers,
  затем MoveFileEx(MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH).
  При сбое питания на диске остаётся либо старый, либо новый файл целиком.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

const
  /// Версия формата файла настроек.
  MH_SETTINGS_VERSION = 1;

type
  EMHSettingsError = class(EMHError);
  /// Ошибка атомарной записи текстового файла (MHWriteTextFileAtomic).
  EMHFileWriteError = class(EMHError);

  /// Язык интерфейса.
  TMHUiLanguage = (ulRussian, ulEnglish);
  /// Цветовая тема интерфейса.
  TMHUiTheme = (utLight, utDark);

  TMHAppSettings = record
  public const
    MinRetentionDays = 1;
    MaxRetentionDays = 3650;
    MinDatabaseSizeMB = 4;
    MaxDatabaseSizeMB = 102400;
    MinLearningDays = 1;
    MaxLearningDays = 90;
    MaxElectricityPrice = 1000.0;
    DefaultElectricityPrice = 6.0;
    /// Интервал опроса, пока окно скрыто (экономный режим), мс.
    EconomyIntervalMs = 30000;
  public
    /// Интервал опроса, мс (TMHScannerOptions.MinIntervalMs..MaxIntervalMs).
    IntervalMs: Cardinal;
    StartScanOnLaunch: Boolean;
    /// Срок хранения истории, дни.
    RetentionDays: Integer;
    /// Предельный размер базы истории, МБ.
    MaxDatabaseMB: Integer;
    /// Сохранять ли пути исполняемых файлов в истории.
    StoreProcessPaths: Boolean;
    Analyzer: TMHAnalyzerSettings;
    /// Период обучения профиля нормы, дни.
    LearningDays: Integer;
    /// Разрешённые пользователем программы.
    Exclusions: TArray<TMHExclusion>;
    /// Скрывать в отчётах имя пользователя, компьютера и путь профиля.
    RedactPathsInReports: Boolean;
    /// Закрытие и сворачивание окна убирают MineHunter X в область уведомлений.
    MinimizeToTray: Boolean;
    /// Всплывающие уведомления о новых тревогах (уровень «подозрительно» и выше).
    NotifyAlerts: Boolean;
    /// Пока окно скрыто, опрос не чаще одного раза в TMHAppSettings.EconomyIntervalMs.
    EconomyWhenHidden: Boolean;
    /// Цена электроэнергии за кВт·ч (в рублях) для оценки стоимости нагрузки.
    ElectricityPrice: Double;
    /// Проверять новые версии на GitHub (по умолчанию выключено: без запросов в интернет).
    CheckForUpdates: Boolean;
    /// Проверять файлы на всех дисках раз в неделю, когда компьютер простаивает.
    FileScanWeekly: Boolean;
    /// Время завершения последней проверки файлов (UTC, 0 — не выполнялась).
    LastFileScanUtc: TDateTime;
    Language: TMHUiLanguage;
    Theme: TMHUiTheme;
    class function Default: TMHAppSettings; static;
    /// Копия с приведёнными к допустимым диапазонам значениями; исключения
    /// с пустым ключом или некорректным SHA-256 отбрасываются, повторы
    /// (ключ + SHA-256 без учёта регистра) объединяются.
    function Normalized: TMHAppSettings;
  end;

  /// Загрузка и атомарное сохранение настроек. Экземпляр не потокобезопасен:
  /// используйте его из одного потока (обычно главного).
  TMHSettingsStore = class
  private
    FFileName: string;
    FLogger: IMHLogger;
    procedure LogMessage(ALevel: TMHLogLevel; const AMessage: string);
    function QuarantineBadFile: string;
  public
    /// AFileName — полный путь к файлу настроек; ALogger может быть nil.
    constructor Create(const AFileName: string; const ALogger: IMHLogger);
    /// Нет файла — значения по умолчанию и True. Повреждённый файл —
    /// значения по умолчанию, файл переименовывается в .bad-<время>,
    /// предупреждение в журнал, результат False. Исключений не выбрасывает.
    function Load(out ASettings: TMHAppSettings): Boolean;
    /// Атомарно сохраняет нормализованную копию настроек.
    /// Ошибки ввода-вывода — EMHSettingsError с понятным сообщением.
    procedure Save(const ASettings: TMHAppSettings);
    property FileName: string read FFileName;
  end;

/// %LOCALAPPDATA%\MineHunterX\settings.json.
function MHDefaultSettingsPath: string;

/// Сериализация настроек в JSON (стабильные имена полей) и обратно.
/// MHSettingsFromJson выбрасывает EMHSettingsError, если текст не является
/// JSON-объектом с полем "version"; отдельные некорректные поля заменяются
/// значениями по умолчанию.
function MHSettingsToJson(const ASettings: TMHAppSettings): string;
function MHSettingsFromJson(const AText: string): TMHAppSettings;

/// Добавляет исключение; False — пустой ключ или такое исключение уже есть.
function MHAddExclusion(var ASettings: TMHAppSettings; const AExclusion: TMHExclusion): Boolean;
/// Удаляет исключение с точно таким ключом и SHA-256 (без учёта регистра).
function MHRemoveExclusion(var ASettings: TMHAppSettings; const AKey, ASha256: string): Boolean;
/// Есть ли исключение, действующее для программы (см. TMHExclusion.Matches).
function MHIsExcluded(const ASettings: TMHAppSettings; const AKey, ASha256: string): Boolean;

/// Атомарная запись текста в UTF-8 без BOM: <имя>.tmp -> FlushFileBuffers ->
/// MoveFileEx(REPLACE_EXISTING or WRITE_THROUGH). Каталог создаётся при
/// необходимости. Ошибки — EMHFileWriteError; временный файл удаляется.
procedure MHWriteTextFileAtomic(const AFileName, AText: string);

implementation

uses
  Winapi.Windows, Winapi.ShlObj, System.Classes, System.IOUtils, System.JSON,
  System.DateUtils, System.Math, System.Generics.Collections,
  MineHunter.Core.Scanner;

const
  LOG_SOURCE = 'settings';
  /// Файл настроек больше этого размера считается повреждённым.
  MAX_SETTINGS_FILE_BYTES = 4 * 1024 * 1024;

function MHDefaultSettingsPath: string;
var
  LPath: array[0..MAX_PATH] of Char;
begin
  if Succeeded(SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, @LPath[0])) then
    Result := TPath.Combine(TPath.Combine(string(LPath), 'MineHunterX'), 'settings.json')
  else
    Result := TPath.Combine(TPath.Combine(TPath.GetTempPath, 'MineHunterX'), 'settings.json');
end;

function IsHexSha256(const AValue: string): Boolean;
var
  C: Char;
begin
  if Length(AValue) <> 64 then
    Exit(False);
  for C in AValue do
    if not CharInSet(C, ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
  Result := True;
end;

function SameExclusion(const A: TMHExclusion; const AKey, ASha256: string): Boolean;
begin
  Result := SameText(A.Key, AKey) and SameText(A.Sha256, ASha256);
end;

function NormalizeExclusion(const AExclusion: TMHExclusion; out AResult: TMHExclusion): Boolean;
begin
  AResult := AExclusion;
  AResult.Key := Trim(AExclusion.Key).ToLower;
  AResult.Sha256 := Trim(AExclusion.Sha256).ToLower;
  AResult.Name := Trim(AExclusion.Name);
  AResult.Comment := Trim(AExclusion.Comment);
  Result := (AResult.Key <> '') and ((AResult.Sha256 = '') or IsHexSha256(AResult.Sha256));
end;

{ TMHAppSettings }

class function TMHAppSettings.Default: TMHAppSettings;
begin
  Result.IntervalMs := TMHScannerOptions.Default.IntervalMs;
  Result.StartScanOnLaunch := True;
  Result.RetentionDays := 7;
  Result.MaxDatabaseMB := 256;
  Result.StoreProcessPaths := True;
  Result.Analyzer := TMHAnalyzerSettings.Default;
  Result.LearningDays := 3;
  Result.Exclusions := nil;
  Result.RedactPathsInReports := True;
  Result.MinimizeToTray := True;
  Result.NotifyAlerts := True;
  Result.EconomyWhenHidden := True;
  Result.ElectricityPrice := DefaultElectricityPrice;
  Result.CheckForUpdates := False;
  Result.FileScanWeekly := False;
  Result.LastFileScanUtc := 0;
  Result.Language := ulRussian;
  Result.Theme := utLight;
end;

function TMHAppSettings.Normalized: TMHAppSettings;
var
  LItem, LNormalized: TMHExclusion;
  LList: TArray<TMHExclusion>;
  LDuplicate: Boolean;
  I: Integer;
begin
  Result := Self;
  Result.IntervalMs := EnsureRange(IntervalMs, Cardinal(TMHScannerOptions.MinIntervalMs),
    Cardinal(TMHScannerOptions.MaxIntervalMs));
  Result.RetentionDays := EnsureRange(RetentionDays, MinRetentionDays, MaxRetentionDays);
  Result.MaxDatabaseMB := EnsureRange(MaxDatabaseMB, MinDatabaseSizeMB, MaxDatabaseSizeMB);
  Result.Analyzer := Analyzer.Normalized;
  Result.LearningDays := EnsureRange(LearningDays, MinLearningDays, MaxLearningDays);
  if IsNan(ElectricityPrice) or IsInfinite(ElectricityPrice) or (ElectricityPrice < 0) then
    Result.ElectricityPrice := DefaultElectricityPrice
  else
    Result.ElectricityPrice := Min(ElectricityPrice, MaxElectricityPrice);
  if not (Language in [Low(TMHUiLanguage)..High(TMHUiLanguage)]) then
    Result.Language := ulRussian;
  if not (Theme in [Low(TMHUiTheme)..High(TMHUiTheme)]) then
    Result.Theme := utLight;

  LList := nil;
  for LItem in Exclusions do
  begin
    if not NormalizeExclusion(LItem, LNormalized) then
      Continue;
    LDuplicate := False;
    for I := 0 to High(LList) do
      if SameExclusion(LList[I], LNormalized.Key, LNormalized.Sha256) then
      begin
        LDuplicate := True;
        Break;
      end;
    if not LDuplicate then
      LList := LList + [LNormalized];
  end;
  Result.Exclusions := LList;
end;

{ Исключения }

function MHAddExclusion(var ASettings: TMHAppSettings; const AExclusion: TMHExclusion): Boolean;
var
  LNormalized: TMHExclusion;
  LItem: TMHExclusion;
begin
  if not NormalizeExclusion(AExclusion, LNormalized) then
    Exit(False);
  for LItem in ASettings.Exclusions do
    if SameExclusion(LItem, LNormalized.Key, LNormalized.Sha256) then
      Exit(False);
  ASettings.Exclusions := ASettings.Exclusions + [LNormalized];
  Result := True;
end;

function MHRemoveExclusion(var ASettings: TMHAppSettings; const AKey, ASha256: string): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(ASettings.Exclusions) do
    if SameExclusion(ASettings.Exclusions[I], Trim(AKey), Trim(ASha256)) then
    begin
      Delete(ASettings.Exclusions, I, 1);
      Exit(True);
    end;
  Result := False;
end;

function MHIsExcluded(const ASettings: TMHAppSettings; const AKey, ASha256: string): Boolean;
var
  LItem: TMHExclusion;
begin
  for LItem in ASettings.Exclusions do
    if LItem.Matches(AKey, ASha256) then
      Exit(True);
  Result := False;
end;

{ JSON }

function ReadInt(AObj: TJSONObject; const AName: string; ADefault: Integer): Integer;
var
  LValue: TJSONValue;
  LInt: Int64;
begin
  LValue := AObj.GetValue(AName);
  if not (LValue is TJSONNumber) then
    Exit(ADefault);
  LInt := Round(EnsureRange(TJSONNumber(LValue).AsDouble, Low(Integer), High(Integer)));
  Result := Integer(LInt);
end;

function ReadCardinal(AObj: TJSONObject; const AName: string; ADefault: Cardinal): Cardinal;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if not (LValue is TJSONNumber) then
    Exit(ADefault);
  Result := Cardinal(Round(EnsureRange(TJSONNumber(LValue).AsDouble, 0.0, High(Cardinal) * 1.0)));
end;

function ReadDouble(AObj: TJSONObject; const AName: string; ADefault: Double): Double;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if not (LValue is TJSONNumber) then
    Exit(ADefault);
  Result := TJSONNumber(LValue).AsDouble;
  if IsNan(Result) or IsInfinite(Result) then
    Result := ADefault;
end;

function ReadBool(AObj: TJSONObject; const AName: string; ADefault: Boolean): Boolean;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if LValue is TJSONBool then
    Result := TJSONBool(LValue).AsBoolean
  else
    Result := ADefault;
end;

function ReadString(AObj: TJSONObject; const AName: string): string;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if LValue is TJSONString then
    Result := LValue.Value
  else
    Result := '';
end;

function ReadDate(AObj: TJSONObject; const AName: string): TDateTime;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if not (LValue is TJSONString) or not TryISO8601ToDate(LValue.Value, Result, True) then
    Result := 0;
end;

function DateToJsonValue(AUtc: TDateTime): TJSONValue;
begin
  if AUtc = 0 then
    Result := TJSONNull.Create
  else
    Result := TJSONString.Create(DateToISO8601(AUtc, True));
end;

const
  LANGUAGE_CODES: array[TMHUiLanguage] of string = ('ru', 'en');
  THEME_CODES: array[TMHUiTheme] of string = ('light', 'dark');

function MHSettingsToJson(const ASettings: TMHAppSettings): string;
var
  LRoot, LAnalyzer, LThresholds, LItem: TJSONObject;
  LArray: TJSONArray;
  LExclusion: TMHExclusion;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.AddPair('version', TJSONNumber.Create(MH_SETTINGS_VERSION));
    LRoot.AddPair('intervalMs', TJSONNumber.Create(ASettings.IntervalMs));
    LRoot.AddPair('startScanOnLaunch', TJSONBool.Create(ASettings.StartScanOnLaunch));
    LRoot.AddPair('retentionDays', TJSONNumber.Create(ASettings.RetentionDays));
    LRoot.AddPair('maxDatabaseMB', TJSONNumber.Create(ASettings.MaxDatabaseMB));
    LRoot.AddPair('storeProcessPaths', TJSONBool.Create(ASettings.StoreProcessPaths));
    LRoot.AddPair('learningDays', TJSONNumber.Create(ASettings.LearningDays));
    LRoot.AddPair('redactPathsInReports', TJSONBool.Create(ASettings.RedactPathsInReports));
    LRoot.AddPair('minimizeToTray', TJSONBool.Create(ASettings.MinimizeToTray));
    LRoot.AddPair('notifyAlerts', TJSONBool.Create(ASettings.NotifyAlerts));
    LRoot.AddPair('economyWhenHidden', TJSONBool.Create(ASettings.EconomyWhenHidden));
    LRoot.AddPair('electricityPrice', TJSONNumber.Create(ASettings.ElectricityPrice));
    LRoot.AddPair('checkForUpdates', TJSONBool.Create(ASettings.CheckForUpdates));
    LRoot.AddPair('fileScanWeekly', TJSONBool.Create(ASettings.FileScanWeekly));
    LRoot.AddPair('lastFileScan', DateToJsonValue(ASettings.LastFileScanUtc));
    LRoot.AddPair('language', LANGUAGE_CODES[ASettings.Language]);
    LRoot.AddPair('theme', THEME_CODES[ASettings.Theme]);

    LAnalyzer := TJSONObject.Create;
    LRoot.AddPair('analyzer', LAnalyzer);
    LThresholds := TJSONObject.Create;
    LAnalyzer.AddPair('thresholds', LThresholds);
    LThresholds.AddPair('low', TJSONNumber.Create(ASettings.Analyzer.Thresholds.Low));
    LThresholds.AddPair('needsReview', TJSONNumber.Create(ASettings.Analyzer.Thresholds.NeedsReview));
    LThresholds.AddPair('suspicious', TJSONNumber.Create(ASettings.Analyzer.Thresholds.Suspicious));
    LThresholds.AddPair('highlySuspicious',
      TJSONNumber.Create(ASettings.Analyzer.Thresholds.HighlySuspicious));
    LAnalyzer.AddPair('highCpuPercent', TJSONNumber.Create(ASettings.Analyzer.HighCpuPercent));
    LAnalyzer.AddPair('highCoreCpuPercent', TJSONNumber.Create(ASettings.Analyzer.HighCoreCpuPercent));
    LAnalyzer.AddPair('sustainedMinutes', TJSONNumber.Create(ASettings.Analyzer.SustainedMinutes));
    LAnalyzer.AddPair('baselineMinSamples', TJSONNumber.Create(ASettings.Analyzer.BaselineMinSamples));

    LArray := TJSONArray.Create;
    LRoot.AddPair('exclusions', LArray);
    for LExclusion in ASettings.Exclusions do
    begin
      LItem := TJSONObject.Create;
      LArray.AddElement(LItem);
      LItem.AddPair('key', LExclusion.Key);
      LItem.AddPair('sha256', LExclusion.Sha256);
      LItem.AddPair('name', LExclusion.Name);
      LItem.AddPair('comment', LExclusion.Comment);
      LItem.AddPair('created', DateToJsonValue(LExclusion.CreatedUtc));
    end;
    // EncodeBelow32 обязателен: без него управляющие символы попадут в JSON как есть.
    Result := LRoot.ToJSON([TJSONAncestor.TJSONOutputOption.EncodeBelow32]);
  finally
    LRoot.Free;
  end;
end;

function MHSettingsFromJson(const AText: string): TMHAppSettings;
var
  LJson: TJSONValue;
  LRoot, LAnalyzer, LThresholds, LItemObj: TJSONObject;
  LValue: TJSONValue;
  LArray: TJSONArray;
  LExclusion: TMHExclusion;
  LDefaults: TMHAppSettings;
  I: Integer;
begin
  LJson := TJSONObject.ParseJSONValue(AText, True, False);
  if LJson = nil then
    raise EMHSettingsError.Create('Файл настроек не является корректным JSON');
  try
    if not (LJson is TJSONObject) then
      raise EMHSettingsError.Create('Файл настроек должен содержать JSON-объект');
    LRoot := TJSONObject(LJson);
    if not (LRoot.GetValue('version') is TJSONNumber) then
      raise EMHSettingsError.Create('В файле настроек отсутствует поле "version"');
    if TJSONNumber(LRoot.GetValue('version')).AsDouble < 1 then
      raise EMHSettingsError.Create('Некорректная версия формата настроек');

    LDefaults := TMHAppSettings.Default;
    Result := LDefaults;
    Result.IntervalMs := ReadCardinal(LRoot, 'intervalMs', LDefaults.IntervalMs);
    Result.StartScanOnLaunch := ReadBool(LRoot, 'startScanOnLaunch', LDefaults.StartScanOnLaunch);
    Result.RetentionDays := ReadInt(LRoot, 'retentionDays', LDefaults.RetentionDays);
    Result.MaxDatabaseMB := ReadInt(LRoot, 'maxDatabaseMB', LDefaults.MaxDatabaseMB);
    Result.StoreProcessPaths := ReadBool(LRoot, 'storeProcessPaths', LDefaults.StoreProcessPaths);
    Result.LearningDays := ReadInt(LRoot, 'learningDays', LDefaults.LearningDays);
    Result.RedactPathsInReports := ReadBool(LRoot, 'redactPathsInReports',
      LDefaults.RedactPathsInReports);
    Result.MinimizeToTray := ReadBool(LRoot, 'minimizeToTray', LDefaults.MinimizeToTray);
    Result.NotifyAlerts := ReadBool(LRoot, 'notifyAlerts', LDefaults.NotifyAlerts);
    Result.EconomyWhenHidden := ReadBool(LRoot, 'economyWhenHidden', LDefaults.EconomyWhenHidden);
    Result.ElectricityPrice := ReadDouble(LRoot, 'electricityPrice', LDefaults.ElectricityPrice);
    Result.CheckForUpdates := ReadBool(LRoot, 'checkForUpdates', LDefaults.CheckForUpdates);
    Result.FileScanWeekly := ReadBool(LRoot, 'fileScanWeekly', LDefaults.FileScanWeekly);
    Result.LastFileScanUtc := ReadDate(LRoot, 'lastFileScan');
    if SameText(ReadString(LRoot, 'language'), LANGUAGE_CODES[ulEnglish]) then
      Result.Language := ulEnglish;
    if SameText(ReadString(LRoot, 'theme'), THEME_CODES[utDark]) then
      Result.Theme := utDark;

    LValue := LRoot.GetValue('analyzer');
    if LValue is TJSONObject then
    begin
      LAnalyzer := TJSONObject(LValue);
      LValue := LAnalyzer.GetValue('thresholds');
      if LValue is TJSONObject then
      begin
        LThresholds := TJSONObject(LValue);
        Result.Analyzer.Thresholds.Low := ReadInt(LThresholds, 'low',
          LDefaults.Analyzer.Thresholds.Low);
        Result.Analyzer.Thresholds.NeedsReview := ReadInt(LThresholds, 'needsReview',
          LDefaults.Analyzer.Thresholds.NeedsReview);
        Result.Analyzer.Thresholds.Suspicious := ReadInt(LThresholds, 'suspicious',
          LDefaults.Analyzer.Thresholds.Suspicious);
        Result.Analyzer.Thresholds.HighlySuspicious := ReadInt(LThresholds, 'highlySuspicious',
          LDefaults.Analyzer.Thresholds.HighlySuspicious);
      end;
      Result.Analyzer.HighCpuPercent := ReadDouble(LAnalyzer, 'highCpuPercent',
        LDefaults.Analyzer.HighCpuPercent);
      Result.Analyzer.HighCoreCpuPercent := ReadDouble(LAnalyzer, 'highCoreCpuPercent',
        LDefaults.Analyzer.HighCoreCpuPercent);
      Result.Analyzer.SustainedMinutes := ReadInt(LAnalyzer, 'sustainedMinutes',
        LDefaults.Analyzer.SustainedMinutes);
      Result.Analyzer.BaselineMinSamples := ReadInt(LAnalyzer, 'baselineMinSamples',
        LDefaults.Analyzer.BaselineMinSamples);
    end;

    LValue := LRoot.GetValue('exclusions');
    if LValue is TJSONArray then
    begin
      LArray := TJSONArray(LValue);
      for I := 0 to LArray.Count - 1 do
      begin
        if not (LArray.Items[I] is TJSONObject) then
          Continue;
        LItemObj := TJSONObject(LArray.Items[I]);
        LExclusion := Default(TMHExclusion);
        LExclusion.Key := ReadString(LItemObj, 'key');
        LExclusion.Sha256 := ReadString(LItemObj, 'sha256');
        LExclusion.Name := ReadString(LItemObj, 'name');
        LExclusion.Comment := ReadString(LItemObj, 'comment');
        LExclusion.CreatedUtc := ReadDate(LItemObj, 'created');
        Result.Exclusions := Result.Exclusions + [LExclusion];
      end;
    end;
  finally
    LJson.Free;
  end;
  Result := Result.Normalized;
end;

{ Атомарная запись }

procedure MHWriteTextFileAtomic(const AFileName, AText: string);
var
  LTemp, LDir: string;
  LBytes: TBytes;
  LStream: TFileStream;
  LError: Cardinal;
begin
  if Trim(AFileName) = '' then
    raise EMHFileWriteError.Create('Не указано имя файла для сохранения');
  LTemp := AFileName + '.tmp';
  try
    LDir := ExtractFileDir(AFileName);
    if (LDir <> '') and not ForceDirectories(LDir) then
      raise EMHFileWriteError.CreateFmt('Не удалось создать каталог «%s»: %s',
        [LDir, SysErrorMessage(GetLastError)]);
    LBytes := TEncoding.UTF8.GetBytes(AText); // GetBytes не добавляет BOM
    LStream := TFileStream.Create(LTemp, fmCreate or fmShareExclusive);
    try
      if Length(LBytes) > 0 then
        LStream.WriteBuffer(LBytes[0], Length(LBytes));
      if not FlushFileBuffers(LStream.Handle) then
        raise EMHFileWriteError.CreateFmt('Не удалось записать данные на диск: %s',
          [SysErrorMessage(GetLastError)]);
    finally
      LStream.Free;
    end;
    if not MoveFileEx(PChar(LTemp), PChar(AFileName),
      MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) then
    begin
      LError := GetLastError;
      raise EMHFileWriteError.CreateFmt('Не удалось заменить файл «%s»: %s',
        [AFileName, SysErrorMessage(LError)]);
    end;
  except
    on E: Exception do
    begin
      if FileExists(LTemp) then
        System.SysUtils.DeleteFile(LTemp);
      if E is EMHFileWriteError then
        raise;
      raise EMHFileWriteError.CreateFmt('Не удалось сохранить файл «%s»: %s',
        [AFileName, E.Message]);
    end;
  end;
end;

{ TMHSettingsStore }

constructor TMHSettingsStore.Create(const AFileName: string; const ALogger: IMHLogger);
begin
  inherited Create;
  if Trim(AFileName) = '' then
    raise EArgumentException.Create('Не указан путь к файлу настроек');
  FFileName := AFileName;
  FLogger := ALogger;
end;

procedure TMHSettingsStore.LogMessage(ALevel: TMHLogLevel; const AMessage: string);
begin
  if FLogger <> nil then
    FLogger.Log(ALevel, LOG_SOURCE, AMessage);
end;

function TMHSettingsStore.QuarantineBadFile: string;
var
  LBase: string;
  LSuffix: Integer;
begin
  LBase := FFileName + '.bad-' + FormatDateTime('yyyymmdd-hhnnss', Now);
  Result := LBase;
  LSuffix := 1;
  while FileExists(Result) do
  begin
    Inc(LSuffix);
    Result := LBase + '-' + IntToStr(LSuffix);
  end;
  if not MoveFileEx(PChar(FFileName), PChar(Result), MOVEFILE_WRITE_THROUGH) then
    Result := '';
end;

function TMHSettingsStore.Load(out ASettings: TMHAppSettings): Boolean;
var
  LBytes: TBytes;
  LText, LBadName, LReason: string;
  LOffset: Integer;
begin
  ASettings := TMHAppSettings.Default;
  try
    if not FileExists(FFileName) then
    begin
      LogMessage(llInfo, 'Файл настроек не найден, используются значения по умолчанию');
      Exit(True);
    end;
    LBytes := TFile.ReadAllBytes(FFileName);
  except
    on E: Exception do
    begin
      LogMessage(llWarning, Format('Не удалось прочитать файл настроек «%s»: %s. ' +
        'Используются значения по умолчанию', [FFileName, E.Message]));
      Exit(False);
    end;
  end;

  try
    if Length(LBytes) > MAX_SETTINGS_FILE_BYTES then
      raise EMHSettingsError.Create('Файл настроек слишком велик');
    // Допускаем BOM, если файл правили вручную в редакторе.
    LOffset := 0;
    if (Length(LBytes) >= 3) and (LBytes[0] = $EF) and (LBytes[1] = $BB) and (LBytes[2] = $BF) then
      LOffset := 3;
    LText := TEncoding.UTF8.GetString(LBytes, LOffset, Length(LBytes) - LOffset);
    ASettings := MHSettingsFromJson(LText);
    LogMessage(llInfo, 'Настройки загружены');
    Result := True;
  except
    on E: Exception do
    begin
      LReason := E.Message;
      ASettings := TMHAppSettings.Default;
      try
        LBadName := QuarantineBadFile;
      except
        LBadName := '';
      end;
      if LBadName <> '' then
        LogMessage(llWarning, Format('Файл настроек повреждён (%s). Он сохранён как «%s», ' +
          'используются значения по умолчанию', [LReason, ExtractFileName(LBadName)]))
      else
        LogMessage(llWarning, Format('Файл настроек повреждён (%s) и не может быть ' +
          'переименован. Используются значения по умолчанию', [LReason]));
      Result := False;
    end;
  end;
end;

procedure TMHSettingsStore.Save(const ASettings: TMHAppSettings);
begin
  try
    MHWriteTextFileAtomic(FFileName, MHSettingsToJson(ASettings.Normalized));
  except
    on E: Exception do
      raise EMHSettingsError.CreateFmt('Не удалось сохранить настройки: %s', [E.Message]);
  end;
  LogMessage(llInfo, 'Настройки сохранены');
end;

end.
