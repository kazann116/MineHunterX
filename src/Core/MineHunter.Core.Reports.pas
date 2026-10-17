unit MineHunter.Core.Reports;

{
  MineHunter X — экспорт отчётов в JSON и HTML (MH-08, MH-09).

  Принципы:
    - отчёт формируется только локально и сохраняется туда, куда укажет
      пользователь; никакие данные не отправляются в сеть;
    - HTML — один самодостаточный документ: только встроенный CSS, без
      скриптов и внешних ресурсов (ни шрифтов, ни картинок, ни ссылок http);
    - все динамические строки экранируются (&, <, >, ", ');
    - состояние передаётся текстом, а не только цветом;
    - командные строки по умолчанию не включаются (могут содержать пароли,
      токены и адреса пулов с логинами);
    - при RedactPaths каталог профиля заменяется на %USERPROFILE%, имена
      чужих профилей C:\Users\<имя>\ — на C:\Users\<user>\, имя пользователя
      и имя компьютера — на <user> и <computer>;
    - одинаковые входные данные и параметры дают побайтно одинаковый отчёт
      (время формирования передаётся в параметрах, числа — в фиксированном
      формате, не зависящем от региональных настроек).
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types;

const
  /// Версия формата JSON-отчёта.
  MH_REPORT_VERSION = 1;
  /// Сколько процессов попадает в раздел «Самые нагруженные процессы».
  MH_REPORT_TOP_PROCESSES = 20;
  MH_REPORT_DISCLAIMER = 'Отсутствие находок не гарантирует отсутствие угроз. ' +
    'Оценка MineHunter X — степень подозрения, а не диагноз заражения.';

type
  TMHReportOptions = record
  public
    /// Скрывать имя пользователя, компьютера и путь профиля.
    RedactPaths: Boolean;
    /// Включать командные строки процессов (по умолчанию — нет).
    IncludeCommandLines: Boolean;
    AppVersion: string;
    RulesetVersion: string;
    /// Время формирования отчёта (UTC); 0 — «нет данных».
    GeneratedUtc: TDateTime;
    /// RedactPaths = True, IncludeCommandLines = False, AppVersion = MH_CORE_VERSION,
    /// GeneratedUtc — текущее время UTC.
    class function Default: TMHReportOptions; static;
  end;

  /// Значения, скрываемые при обезличивании.
  TMHRedactionContext = record
  public
    /// Каталог профиля текущего пользователя (например, C:\Users\Ivan).
    ProfileDir: string;
    UserName: string;
    /// NetBIOS- и DNS-имена компьютера (пустые значения игнорируются).
    ComputerNames: TArray<string>;
    /// Значения текущего сеанса Windows (вычисляются один раз при запуске).
    class function Current: TMHRedactionContext; static;
  end;

  TMHReportBuilder = class
  public
    /// Отчёт о сканировании в JSON (UTF-8 при сохранении через MHSaveTextFile).
    class function BuildJson(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings;
      const AOptions: TMHReportOptions): string; static;
    /// Тот же отчёт как самодостаточный документ HTML5.
    class function BuildHtml(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings;
      const AOptions: TMHReportOptions): string; static;
    /// Карточка находки в JSON: находка, процесс, ряд загрузки CPU.
    class function FindingCardJson(const AFinding: TMHFinding; const AProcess: TMHProcessInfo;
      const ALoad: TArray<TMHMetric>; const AOptions: TMHReportOptions): string; static;
    /// Карточка находки в HTML с графиком загрузки CPU (встроенный SVG,
    /// разрывы линии на участках «нет данных»).
    class function FindingCardHtml(const AFinding: TMHFinding; const AProcess: TMHProcessInfo;
      const ALoad: TArray<TMHMetric>; const AOptions: TMHReportOptions): string; static;
  end;

/// Сохраняет текст в UTF-8 без BOM атомарно (временный файл + MoveFileEx).
/// Ошибки — EMHFileWriteError (MineHunter.Core.Settings).
procedure MHSaveTextFile(const AFileName, AText: string);

/// Обезличивание строки с данными текущего сеанса Windows.
function MHRedact(const AText: string): string;
/// Обезличивание с явно заданным контекстом (для тестов и пакетной обработки).
function MHRedactWith(const AText: string; const AContext: TMHRedactionContext): string;

/// Экранирование для HTML: &, <, >, ", '.
function MHHtmlEscape(const AText: string): string;

implementation

uses
  Winapi.Windows, Winapi.ShlObj, System.Classes, System.JSON, System.DateUtils,
  System.Math, System.Character, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Serialization, MineHunter.Core.Settings, MineHunter.Core.Lang;

const
  MH_REPORT_DISCLAIMER_EN = 'The absence of findings does not guarantee the absence of threats. ' +
    'The MineHunter X score is a degree of suspicion, not a diagnosis of infection.';
  NO_DATA_EN = 'no data';
  PLACEHOLDER_PROFILE = '%USERPROFILE%';
  PLACEHOLDER_USER = '<user>';
  PLACEHOLDER_COMPUTER = '<computer>';
  NO_DATA = 'нет данных';
  /// Общие каталоги в C:\Users, не содержащие имени пользователя.
  SHARED_PROFILE_DIRS: array[0..3] of string = ('Public', 'Default', 'Default User', 'All Users');

  CHART_WIDTH = 600;
  CHART_HEIGHT = 160;

  HTML_STYLE =
    'body{font-family:"Segoe UI",Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fff;' +
    'line-height:1.45}' +
    'h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;margin:24px 0 8px;' +
    'border-bottom:1px solid #ccc;padding-bottom:4px}h3{font-size:16px;margin:0 0 6px}' +
    'table{border-collapse:collapse;margin:6px 0 12px}' +
    'th,td{border:1px solid #c8c8c8;padding:4px 8px;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f0}' +
    '.finding{border:1px solid #bbb;border-left:6px solid #888;padding:10px 14px;margin:12px 0}' +
    '.lvl-none{border-left-color:#8a8a8a}.lvl-low{border-left-color:#3a7bd5}' +
    '.lvl-needsReview{border-left-color:#c79100}.lvl-suspicious{border-left-color:#d9480f}' +
    '.lvl-highlySuspicious{border-left-color:#b00020}' +
    '.muted{color:#555}.mono{font-family:Consolas,monospace;word-break:break-all}' +
    '.disclaimer{margin-top:28px;padding:10px;border:1px solid #c79100;background:#fff8e1}' +
    'svg{border:1px solid #ccc;background:#fafafa}' +
    '@media print{body{margin:0}}';

var
  GInvariantFormat: TFormatSettings;
  GRuFormat: TFormatSettings;
  GCurrentContext: TMHRedactionContext;

{ Вспомогательные функции }

function FormatUtc(AUtc: TDateTime): string;
begin
  if AUtc = 0 then
    Result := MHL(NO_DATA, NO_DATA_EN)
  else
    Result := FormatDateTime('yyyy-mm-dd hh:nn:ss', AUtc, GInvariantFormat) + ' UTC';
end;

function IsoUtc(AUtc: TDateTime): TJSONValue;
begin
  if AUtc = 0 then
    Result := TJSONNull.Create
  else
    Result := TJSONString.Create(DateToISO8601(AUtc, True));
end;

function FormatNumber(AValue: Double; const AFormat: string): string;
begin
  Result := FormatFloat(AFormat, AValue, GRuFormat);
end;

function FormatBytes(ABytes: Double): string;
const
  KB = 1024.0;
  MB = KB * 1024;
  GB = MB * 1024;
begin
  if ABytes >= GB then
    Result := FormatNumber(ABytes / GB, '0.00') + MHL(' ГБ', ' GB')
  else if ABytes >= MB then
    Result := FormatNumber(ABytes / MB, '0.0') + MHL(' МБ', ' MB')
  else if ABytes >= KB then
    Result := FormatNumber(ABytes / KB, '0.0') + MHL(' КБ', ' KB')
  else
    Result := FormatNumber(ABytes, '0') + MHL(' Б', ' B');
end;

function FormatMetric(const AMetric: TMHMetric): string;
begin
  if not AMetric.HasValue then
    Exit(MHL(NO_DATA, NO_DATA_EN));
  case AMetric.Kind of
    mkCpuPercent, mkGpuPercent, mkMemoryLoadPercent, mkDiskActivePercent, mkCpuTimePercent,
    mkCpuFrequencyPercent, mkCpuPerformanceLimitPercent, mkGpuComputePercent:
      Result := FormatNumber(AMetric.Value, '0.0') + ' %';
    mkWorkingSetBytes, mkPrivateBytes, mkMemoryUsedBytes, mkMemoryTotalBytes, mkGpuMemoryBytes,
    mkPrivateWorkingSetBytes:
      Result := FormatBytes(AMetric.Value);
    mkDiskBytesPerSec, mkNetworkBytesPerSec, mkDiskReadBytesPerSec, mkDiskWriteBytesPerSec:
      Result := FormatBytes(AMetric.Value) + MHL('/с', '/s');
    mkTemperatureCelsius, mkGpuTemperatureCelsius, mkCpuTemperatureCelsius, mkDiskTemperatureCelsius:
      Result := FormatNumber(AMetric.Value, '0') + ' °C';
    mkGpuPowerWatts:
      Result := FormatNumber(AMetric.Value, '0') + MHL(' Вт', ' W');
  else
    Result := FormatNumber(AMetric.Value, '0.##');
  end;
end;

/// Память процесса как в диспетчере задач: частный рабочий набор, иначе рабочий набор.
function ProcessMemory(const AInfo: TMHProcessInfo): TMHMetric;
begin
  if AInfo.PrivateWorkingSet.HasValue then
    Result := AInfo.PrivateWorkingSet
  else
    Result := AInfo.WorkingSet;
end;

function SensorKindTitle(AKind: TMHSensorKind): string;
begin
  case AKind of
    skGpu: Result := MHL('Видеокарта', 'GPU');
    skDisk: Result := MHL('Накопитель', 'Drive');
  else
    Result := MHL('Процессор', 'CPU');
  end;
end;

function MetricTitle(AKind: TMHMetricKind): string;
begin
  case AKind of
    mkCpuPercent:          Result := MHL('Загрузка CPU', 'CPU load');
    mkWorkingSetBytes:     Result := MHL('Рабочий набор', 'Working set');
    mkPrivateBytes:        Result := MHL('Частная память', 'Private memory');
    mkDiskBytesPerSec:     Result := MHL('Диск, всего', 'Disk, total');
    mkNetworkBytesPerSec:  Result := MHL('Сеть', 'Network');
    mkGpuPercent:          Result := MHL('Загрузка GPU', 'GPU load');
    mkTemperatureCelsius:  Result := MHL('Температура', 'Temperature');
    mkMemoryUsedBytes:     Result := MHL('Память занята', 'Memory used');
    mkMemoryTotalBytes:    Result := MHL('Память всего', 'Memory total');
    mkMemoryLoadPercent:   Result := MHL('Загрузка памяти', 'Memory load');
    mkDiskReadBytesPerSec: Result := MHL('Чтение с диска', 'Disk read');
    mkDiskWriteBytesPerSec: Result := MHL('Запись на диск', 'Disk write');
    mkDiskActivePercent:   Result := MHL('Активность диска', 'Disk activity');
    mkCpuTimePercent:      Result := MHL('Время работы CPU', 'CPU time');
    mkCpuFrequencyPercent: Result := MHL('Частота CPU (от базовой)', 'CPU frequency (of base)');
    mkCpuPerformanceLimitPercent: Result := MHL('Предел производительности CPU', 'CPU performance limit');
    mkGpuComputePercent:   Result := MHL('Вычисления на GPU', 'GPU compute');
    mkGpuMemoryBytes:      Result := MHL('Видеопамять', 'Video memory');
    mkGpuTemperatureCelsius: Result := MHL('Температура GPU', 'GPU temperature');
    mkCpuTemperatureCelsius: Result := MHL('Температура CPU', 'CPU temperature');
    mkDiskTemperatureCelsius: Result := MHL('Температура диска', 'Disk temperature');
    mkGpuPowerWatts:       Result := MHL('Мощность видеокарты', 'GPU power');
  else
    Result := MHL('Память процесса', 'Process memory');
  end;
end;

function SourceStateText(AState: TMHSourceState): string;
const
  Marks: array[TMHSourceState] of string = ('[?]', '[OK]', '[ЧАСТИЧНО]', '[НЕДОСТУПНО]', '[ОШИБКА]');
  MarksEn: array[TMHSourceState] of string = ('[?]', '[OK]', '[PARTIAL]', '[UNAVAILABLE]', '[ERROR]');
begin
  Result := MHL(Marks[AState], MarksEn[AState]) + ' ' + MHSourceStateToString(AState);
end;

function SvgNumber(AValue: Double): string;
begin
  Result := FormatFloat('0.##', AValue, GInvariantFormat);
end;

function IsWordChar(C: Char): Boolean;
begin
  Result := C.IsLetterOrDigit or (C = '_');
end;

function MatchAt(const AText: string; APos: Integer; const AWhat: string): Boolean;
begin
  Result := (AWhat <> '') and (APos + Length(AWhat) - 1 <= Length(AText)) and
    (StrLIComp(PChar(AText) + APos - 1, PChar(AWhat), Length(AWhat)) = 0);
end;

function IsPathEnd(const AText: string; APos: Integer): Boolean;
begin
  // Граница пути: конец строки, разделитель или символ, недопустимый в имени файла.
  Result := (APos > Length(AText)) or
    CharInSet(AText[APos], ['\', '/', '"', '''', '<', '>', '|', ';', ',', ')', #0..#31]);
end;

function MatchWholeWord(const AText: string; APos: Integer; const AWord: string): Boolean;
begin
  Result := (Length(AWord) >= 2) and MatchAt(AText, APos, AWord) and
    ((APos = 1) or not IsWordChar(AText[APos - 1])) and
    ((APos + Length(AWord) > Length(AText)) or not IsWordChar(AText[APos + Length(AWord)]));
end;

function IsSharedProfileDir(const AName: string): Boolean;
var
  LName: string;
begin
  for LName in SHARED_PROFILE_DIRS do
    if SameText(LName, AName) then
      Exit(True);
  Result := False;
end;

/// Позиция «X:\Users\» (любой регистр, разделители \ или /), начинающаяся в APos.
/// AStart — индекс первого символа имени профиля.
function MatchUsersDir(const AText: string; APos: Integer; out AStart: Integer): Boolean;
begin
  Result := (APos + 8 <= Length(AText)) and AText[APos].IsLetter and (AText[APos + 1] = ':') and
    CharInSet(AText[APos + 2], ['\', '/']) and MatchAt(AText, APos + 3, 'users') and
    CharInSet(AText[APos + 8], ['\', '/']) and
    ((APos = 1) or not IsWordChar(AText[APos - 1]));
  AStart := APos + 9;
end;

{ Обезличивание }

function MHRedactWith(const AText: string; const AContext: TMHRedactionContext): string;
var
  LBuilder: TStringBuilder;
  LPos, LStart, LEnd: Integer;
  LProfile, LSegment, LComputer: string;
  LMatched: Boolean;
begin
  if AText = '' then
    Exit('');
  LProfile := ExcludeTrailingPathDelimiter(AContext.ProfileDir);
  LBuilder := TStringBuilder.Create(Length(AText) + 16);
  try
    LPos := 1;
    // Один проход слева направо: подставленные заполнители повторно не разбираются.
    while LPos <= Length(AText) do
    begin
      // 1. Каталог профиля текущего пользователя.
      if (Length(LProfile) >= 3) and MatchAt(AText, LPos, LProfile) and
         IsPathEnd(AText, LPos + Length(LProfile)) then
      begin
        LBuilder.Append(PLACEHOLDER_PROFILE);
        Inc(LPos, Length(LProfile));
        Continue;
      end;

      // 2. Любой другой профиль: X:\Users\<имя>.
      if MatchUsersDir(AText, LPos, LStart) then
      begin
        LEnd := LStart;
        while (LEnd <= Length(AText)) and not IsPathEnd(AText, LEnd) do
          Inc(LEnd);
        LSegment := Copy(AText, LStart, LEnd - LStart);
        if (LSegment <> '') and not IsSharedProfileDir(LSegment) then
        begin
          LBuilder.Append(AText, LPos - 1, LStart - LPos);
          LBuilder.Append(PLACEHOLDER_USER);
          LPos := LEnd;
          Continue;
        end;
      end;

      // 3. Имя пользователя и имя компьютера отдельными словами.
      if MatchWholeWord(AText, LPos, AContext.UserName) then
      begin
        LBuilder.Append(PLACEHOLDER_USER);
        Inc(LPos, Length(AContext.UserName));
        Continue;
      end;
      LMatched := False;
      for LComputer in AContext.ComputerNames do
        if MatchWholeWord(AText, LPos, LComputer) then
        begin
          LBuilder.Append(PLACEHOLDER_COMPUTER);
          Inc(LPos, Length(LComputer));
          LMatched := True;
          Break;
        end;
      if LMatched then
        Continue;

      LBuilder.Append(AText[LPos]);
      Inc(LPos);
    end;
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function MHRedact(const AText: string): string;
begin
  Result := MHRedactWith(AText, GCurrentContext);
end;

function MHHtmlEscape(const AText: string): string;
var
  LBuilder: TStringBuilder;
  C: Char;
begin
  LBuilder := TStringBuilder.Create(Length(AText) + 16);
  try
    for C in AText do
      case C of
        '&':  LBuilder.Append('&amp;');
        '<':  LBuilder.Append('&lt;');
        '>':  LBuilder.Append('&gt;');
        '"':  LBuilder.Append('&quot;');
        '''': LBuilder.Append('&#39;');
        #0..#8, #11, #12, #14..#31:
          LBuilder.Append('&#xFFFD;');
      else
        LBuilder.Append(C);
      end;
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

procedure MHSaveTextFile(const AFileName, AText: string);
begin
  MHWriteTextFileAtomic(AFileName, AText);
end;

{ TMHRedactionContext }

function QueryProfileDir: string;
var
  LPath: array[0..MAX_PATH] of Char;
begin
  if Succeeded(SHGetFolderPath(0, CSIDL_PROFILE, 0, 0, @LPath[0])) then
    Result := string(PChar(@LPath[0]))
  else
    Result := GetEnvironmentVariable('USERPROFILE');
end;

function QueryUserName: string;
var
  LBuffer: array[0..256] of Char;
  LSize: DWORD;
begin
  LSize := Length(LBuffer);
  if GetUserName(@LBuffer[0], LSize) and (LSize > 1) then
    Result := string(PChar(@LBuffer[0]))
  else
    Result := GetEnvironmentVariable('USERNAME');
end;

function QueryComputerNames: TArray<string>;
var
  LBuffer: array[0..MAX_COMPUTERNAME_LENGTH * 8] of Char;
  LSize: DWORD;
  LName: string;
  LFormat: TComputerNameFormat;
  LExists: Boolean;
  LItem: string;
begin
  Result := nil;
  for LFormat in [ComputerNameNetBIOS, ComputerNameDnsHostname] do
  begin
    LSize := Length(LBuffer);
    if not GetComputerNameEx(LFormat, @LBuffer[0], LSize) then
      Continue;
    SetString(LName, PChar(@LBuffer[0]), LSize);
    LName := Trim(LName);
    if LName = '' then
      Continue;
    LExists := False;
    for LItem in Result do
      if SameText(LItem, LName) then
        LExists := True;
    if not LExists then
      Result := Result + [LName];
  end;
end;

class function TMHRedactionContext.Current: TMHRedactionContext;
begin
  Result := GCurrentContext;
end;

{ TMHReportOptions }

class function TMHReportOptions.Default: TMHReportOptions;
begin
  Result.RedactPaths := True;
  Result.IncludeCommandLines := False;
  Result.AppVersion := MH_CORE_VERSION;
  Result.RulesetVersion := '';
  Result.GeneratedUtc := TTimeZone.Local.ToUniversalTime(Now);
end;

{ Подготовка данных }

function Clean(const AText: string; const AOptions: TMHReportOptions): string;
begin
  if AOptions.RedactPaths then
    Result := MHRedact(AText)
  else
    Result := AText;
end;

function CleanStrings(const AValues: TArray<string>; const AOptions: TMHReportOptions): TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, Length(AValues));
  for I := 0 to High(AValues) do
    Result[I] := Clean(AValues[I], AOptions);
end;

function PrepareFinding(const AFinding: TMHFinding; const AOptions: TMHReportOptions): TMHFinding;
var
  I: Integer;
begin
  Result := AFinding;
  Result.Key := Clean(AFinding.Key, AOptions);
  Result.ProcessName := Clean(AFinding.ProcessName, AOptions);
  Result.ImagePath := Clean(AFinding.ImagePath, AOptions);
  Result.Title := Clean(AFinding.Title, AOptions);
  Result.Summary := Clean(AFinding.Summary, AOptions);
  Result.Evidence := Copy(AFinding.Evidence);
  for I := 0 to High(Result.Evidence) do
  begin
    Result.Evidence[I].Description := Clean(Result.Evidence[I].Description, AOptions);
    Result.Evidence[I].Observed := Clean(Result.Evidence[I].Observed, AOptions);
  end;
  Result.MissingData := CleanStrings(AFinding.MissingData, AOptions);
  Result.Recommendations := CleanStrings(AFinding.Recommendations, AOptions);
end;

function PrepareProcess(const AInfo: TMHProcessInfo; const AOptions: TMHReportOptions): TMHProcessInfo;
begin
  Result := AInfo;
  Result.Name := Clean(AInfo.Name, AOptions);
  Result.ImagePath := Clean(AInfo.ImagePath, AOptions);
  if AOptions.IncludeCommandLines then
    Result.CommandLine := Clean(AInfo.CommandLine, AOptions)
  else
    Result.CommandLine := '';
end;

function CompareByCpu(const A, B: TMHProcessInfo): Integer;
begin
  // Процессы с данными — первыми, по убыванию загрузки; затем по PID и времени
  // создания, чтобы порядок не зависел от порядка во входном массиве.
  if A.Cpu.HasValue <> B.Cpu.HasValue then
    Exit(IfThen(A.Cpu.HasValue, -1, 1));
  if A.Cpu.HasValue then
  begin
    Result := CompareValue(B.Cpu.Value, A.Cpu.Value);
    if Result <> 0 then
      Exit;
  end;
  Result := CompareValue(Int64(A.Id.Pid), Int64(B.Id.Pid));
  if Result = 0 then
    if A.Id.CreateTime < B.Id.CreateTime then
      Result := -1
    else if A.Id.CreateTime > B.Id.CreateTime then
      Result := 1;
end;

function TopProcesses(const ASnapshot: TMHSnapshot; const AOptions: TMHReportOptions): TArray<TMHProcessInfo>;
var
  LAll: TArray<TMHProcessInfo>;
  I: Integer;
begin
  LAll := Copy(ASnapshot.Processes);
  TArray.Sort<TMHProcessInfo>(LAll, TComparer<TMHProcessInfo>.Construct(CompareByCpu));
  SetLength(Result, Min(Length(LAll), MH_REPORT_TOP_PROCESSES));
  for I := 0 to High(Result) do
    Result[I] := PrepareProcess(LAll[I], AOptions);
end;

/// Сводка отсутствующих данных: проблемные источники и данные, которых не
/// хватило для оценки находок (без повторов, в порядке появления).
function MissingDataSummary(const ASnapshot: TMHSnapshot; const AFindings: TMHFindings;
  const AOptions: TMHReportOptions): TArray<string>;
var
  LStatus: TMHSourceStatus;
  LFinding: TMHFinding;
  LItem, LText: string;
  LList: TArray<string>;

  procedure AddUnique(const AValue: string);
  var
    LExisting: string;
  begin
    for LExisting in LList do
      if SameText(LExisting, AValue) then
        Exit;
    LList := LList + [AValue];
  end;

begin
  LList := nil;
  for LStatus in ASnapshot.Sources do
    if LStatus.State <> ssSuccess then
    begin
      LText := Format(MHL('Источник «%s»: %s', 'Source "%s": %s'), [LStatus.SourceId, MHSourceStateToString(LStatus.State)]);
      if LStatus.Message <> '' then
        LText := LText + ' — ' + LStatus.Message;
      if LStatus.RequiresElevation then
        LText := LText + MHL(' (больше данных доступно при запуске от имени администратора)',
          ' (more data is available when running as administrator)');
      AddUnique(Clean(LText, AOptions));
    end;
  for LFinding in AFindings do
    for LItem in LFinding.MissingData do
      AddUnique(Clean(LItem, AOptions));
  Result := LList;
end;

function HighestLevel(const AFindings: TMHFindings): TMHRiskLevel;
var
  LFinding: TMHFinding;
begin
  Result := rlNone;
  for LFinding in AFindings do
    if LFinding.Level > Result then
      Result := LFinding.Level;
end;

function GeneratorJson(const AOptions: TMHReportOptions): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('name', 'MineHunter X');
  Result.AddPair('appVersion', AOptions.AppVersion);
  Result.AddPair('coreVersion', MH_CORE_VERSION);
  Result.AddPair('reportVersion', TJSONNumber.Create(MH_REPORT_VERSION));
end;

function StringsJson(const AValues: TArray<string>): TJSONArray;
var
  LValue: string;
begin
  Result := TJSONArray.Create;
  for LValue in AValues do
    Result.Add(LValue);
end;

function JsonText(AJson: TJSONValue): string;
begin
  // EncodeBelow32: управляющие символы экранируются, кириллица остаётся читаемой.
  Result := AJson.ToJSON([TJSONAncestor.TJSONOutputOption.EncodeBelow32]);
end;

{ HTML }

type
  THtml = class
  private
    FBuilder: TStringBuilder;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Raw(const AText: string);
    /// Экранированный текст.
    procedure Text(const AText: string);
    procedure Tag(const ATag, AText: string; const AClass: string = '');
    procedure Row(const AHeader, AValue: string; const AValueClass: string = '');
    procedure BeginDocument(const ATitle: string);
    procedure EndDocument;
    function ToString: string; override;
  end;

constructor THtml.Create;
begin
  inherited Create;
  FBuilder := TStringBuilder.Create(16 * 1024);
end;

destructor THtml.Destroy;
begin
  FBuilder.Free;
  inherited;
end;

procedure THtml.Raw(const AText: string);
begin
  FBuilder.Append(AText);
end;

procedure THtml.Text(const AText: string);
begin
  FBuilder.Append(MHHtmlEscape(AText));
end;

procedure THtml.Tag(const ATag, AText: string; const AClass: string);
begin
  if AClass <> '' then
    Raw('<' + ATag + ' class="' + AClass + '">')
  else
    Raw('<' + ATag + '>');
  Text(AText);
  Raw('</' + ATag + '>'#13#10);
end;

procedure THtml.Row(const AHeader, AValue: string; const AValueClass: string);
begin
  Raw('<tr><th scope="row">');
  Text(AHeader);
  if AValueClass <> '' then
    Raw('</th><td class="' + AValueClass + '">')
  else
    Raw('</th><td>');
  Text(AValue);
  Raw('</td></tr>'#13#10);
end;

procedure THtml.BeginDocument(const ATitle: string);
begin
  Raw('<!DOCTYPE html>'#13#10'<html lang="' + MHL('ru', 'en') + '">'#13#10'<head>'#13#10);
  Raw('<meta charset="utf-8">'#13#10);
  Raw('<meta name="viewport" content="width=device-width, initial-scale=1">'#13#10);
  Raw('<meta name="referrer" content="no-referrer">'#13#10);
  Tag('title', ATitle);
  Raw('<style>' + HTML_STYLE + '</style>'#13#10'</head>'#13#10'<body>'#13#10);
  Tag('h1', ATitle);
end;

procedure THtml.EndDocument;
begin
  Raw('<p class="disclaimer"><strong>');
  Text(MHL('Важно: ', 'Important: '));
  Raw('</strong>');
  Text(MHL(MH_REPORT_DISCLAIMER, MH_REPORT_DISCLAIMER_EN));
  Raw('</p>'#13#10'</body>'#13#10'</html>'#13#10);
end;

function THtml.ToString: string;
begin
  Result := FBuilder.ToString;
end;

function LevelClass(ALevel: TMHRiskLevel): string;
begin
  Result := 'lvl-' + MHRiskLevelToName(ALevel);
end;

function ConfidenceText(AConfidence: Double): string;
begin
  Result := FormatNumber(EnsureRange(AConfidence, 0.0, 1.0) * 100, '0') + ' %';
end;

function WeightText(AWeight: Integer): string;
begin
  if AWeight > 0 then
    Result := '+' + IntToStr(AWeight)
  else if AWeight < 0 then
    Result := '−' + IntToStr(-AWeight)  // U+2212 «минус»
  else
    Result := '0';
end;

procedure WriteEvidenceList(AHtml: THtml; const ATitle: string;
  const AItems: TArray<TMHEvidence>);
var
  LItem: TMHEvidence;
begin
  AHtml.Tag('p', ATitle);
  if Length(AItems) = 0 then
  begin
    AHtml.Tag('p', MHL('нет', 'none'), 'muted');
    Exit;
  end;
  AHtml.Raw('<ul>'#13#10);
  for LItem in AItems do
  begin
    AHtml.Raw('<li><strong>');
    AHtml.Text(WeightText(LItem.Weight));
    AHtml.Raw('</strong> ');
    AHtml.Text(LItem.Description);
    if LItem.Observed <> '' then
      AHtml.Text(' (' + LItem.Observed + ')');
    AHtml.Raw(' <span class="muted">[');
    AHtml.Text(LItem.Code);
    AHtml.Raw(']</span></li>'#13#10);
  end;
  AHtml.Raw('</ul>'#13#10);
end;

procedure WriteStringList(AHtml: THtml; const ATitle: string; const AItems: TArray<string>;
  const AEmptyText: string);
var
  LItem: string;
begin
  AHtml.Tag('p', ATitle);
  if Length(AItems) = 0 then
  begin
    AHtml.Tag('p', AEmptyText, 'muted');
    Exit;
  end;
  AHtml.Raw('<ul>'#13#10);
  for LItem in AItems do
    AHtml.Tag('li', LItem);
  AHtml.Raw('</ul>'#13#10);
end;

/// Карточка находки (AFinding уже обезличена).
procedure WriteFinding(AHtml: THtml; const AFinding: TMHFinding; const AHeadingTag: string);
begin
  AHtml.Raw('<section class="finding ' + LevelClass(AFinding.Level) + '">'#13#10);
  AHtml.Tag(AHeadingTag, AFinding.Title);
  AHtml.Raw('<table>'#13#10);
  AHtml.Row(MHL('Уровень', 'Level'), MHRiskLevelToString(AFinding.Level));
  AHtml.Row(MHL('Балл', 'Score'), IntToStr(AFinding.Score) + MHL(' из 100', ' of 100'));
  AHtml.Row(MHL('Уверенность оценки', 'Assessment confidence'), ConfidenceText(AFinding.Confidence));
  AHtml.Row(MHL('Категория', 'Category'), MHFindingCategoryTitle(AFinding.Category));
  AHtml.Row(MHL('Процесс', 'Process'), Format('%s (PID %u)', [AFinding.ProcessName, AFinding.Process.Pid]));
  AHtml.Row(MHL('Родительский PID', 'Parent PID'), UIntToStr(AFinding.ParentPid));
  if AFinding.ImagePath <> '' then
    AHtml.Row(MHL('Путь', 'Path'), AFinding.ImagePath, 'mono')
  else
    AHtml.Row(MHL('Путь', 'Path'), MHL(NO_DATA, NO_DATA_EN));
  AHtml.Row(MHL('Обнаружено', 'Detected'), FormatUtc(AFinding.DetectedAtUtc));
  AHtml.Row(MHL('Версия правил', 'Ruleset version'), AFinding.RulesetVersion);
  AHtml.Raw('</table>'#13#10);
  if AFinding.Summary <> '' then
    AHtml.Tag('p', AFinding.Summary);
  WriteEvidenceList(AHtml, MHL('Признаки, повышающие оценку (+):', 'Evidence raising the score (+):'), AFinding.PositiveEvidence);
  WriteEvidenceList(AHtml, MHL('Оправдывающие факторы (−):', 'Mitigating factors (−):'), AFinding.NegativeEvidence);
  WriteStringList(AHtml, MHL('Недостающие данные:', 'Missing data:'), AFinding.MissingData, MHL('нет', 'none'));
  WriteStringList(AHtml, MHL('Рекомендации:', 'Recommendations:'), AFinding.Recommendations, MHL('нет', 'none'));
  AHtml.Raw('</section>'#13#10);
end;

/// График загрузки CPU: отдельная polyline на каждый непрерывный участок
/// с данными, одиночные точки — кружками; «нет данных» даёт разрыв.
procedure WriteLoadChart(AHtml: THtml; const ALoad: TArray<TMHMetric>);
var
  I, LNoData, LSegmentStart: Integer;

  function PointX(AIndex: Integer): string;
  begin
    if Length(ALoad) > 1 then
      Result := SvgNumber(AIndex * CHART_WIDTH / (Length(ALoad) - 1))
    else
      Result := SvgNumber(CHART_WIDTH / 2);
  end;

  function PointY(AIndex: Integer): string;
  begin
    Result := SvgNumber(CHART_HEIGHT -
      EnsureRange(ALoad[AIndex].Value, 0.0, 100.0) * CHART_HEIGHT / 100);
  end;

  /// Выводит участок [LSegmentStart; AEnd) с данными и сбрасывает его.
  procedure FlushSegment(AEnd: Integer);
  var
    J: Integer;
    LPoints: TArray<string>;
  begin
    if LSegmentStart < 0 then
      Exit;
    if AEnd - LSegmentStart = 1 then
      AHtml.Raw('<circle cx="' + PointX(LSegmentStart) + '" cy="' + PointY(LSegmentStart) +
        '" r="2.5" fill="#1f5fbf"/>'#13#10)
    else
    begin
      SetLength(LPoints, AEnd - LSegmentStart);
      for J := LSegmentStart to AEnd - 1 do
        LPoints[J - LSegmentStart] := PointX(J) + ',' + PointY(J);
      AHtml.Raw('<polyline fill="none" stroke="#1f5fbf" stroke-width="2" points="' +
        string.Join(' ', LPoints) + '"/>'#13#10);
    end;
    LSegmentStart := -1;
  end;

begin
  AHtml.Tag('h3', MHL('Загрузка CPU процессом, % всей машины', 'Process CPU load, % of the whole machine'));
  if Length(ALoad) = 0 then
  begin
    AHtml.Tag('p', MHL('Нет данных о загрузке за выбранный период.', 'No load data for the selected period.'), 'muted');
    Exit;
  end;
  LNoData := 0;
  for I := 0 to High(ALoad) do
    if not ALoad[I].HasValue then
      Inc(LNoData);
  AHtml.Raw(Format('<svg role="img" width="%d" height="%d" viewBox="0 0 %d %d" ' +
    'aria-label="' + MHL('График загрузки CPU', 'CPU load chart') + '">'#13#10, [CHART_WIDTH, CHART_HEIGHT, CHART_WIDTH, CHART_HEIGHT]));
  AHtml.Tag('title', Format(MHL('Загрузка CPU: %d точек, без данных: %d', 'CPU load: %d points, without data: %d'), [Length(ALoad), LNoData]));
  AHtml.Raw(Format('<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#ddd"/>'#13#10,
    [CHART_HEIGHT div 2, CHART_WIDTH, CHART_HEIGHT div 2]));
  LSegmentStart := -1;
  for I := 0 to High(ALoad) do
    if ALoad[I].HasValue then
    begin
      if LSegmentStart < 0 then
        LSegmentStart := I;
    end
    else
      FlushSegment(I);
  FlushSegment(Length(ALoad));
  AHtml.Raw('</svg>'#13#10);
  AHtml.Tag('p', Format(MHL('Шкала 0–100 %%; период: %s — %s; точек: %d, из них без данных: %d ',
    'Scale 0–100 %%; period: %s — %s; points: %d, of them without data: %d ') +
    MHL('(разрывы линии).', '(gaps in the line).'), [FormatUtc(ALoad[0].TimestampUtc), FormatUtc(ALoad[High(ALoad)].TimestampUtc),
    Length(ALoad), LNoData]), 'muted');
end;

{ TMHReportBuilder }

class function TMHReportBuilder.BuildJson(const ASnapshot: TMHSnapshot;
  const AFindings: TMHFindings; const AOptions: TMHReportOptions): string;
var
  LRoot, LSnapshot, LItem: TJSONObject;
  LArray: TJSONArray;
  LStatus: TMHSourceStatus;
  LMetric: TMHMetric;
  LFinding: TMHFinding;
  LProcess: TMHProcessInfo;
  LSensor: TMHSensorReading;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.AddPair('generator', GeneratorJson(AOptions));
    LRoot.AddPair('generatedAt', IsoUtc(AOptions.GeneratedUtc));
    LRoot.AddPair('rulesetVersion', AOptions.RulesetVersion);
    LRoot.AddPair('redacted', TJSONBool.Create(AOptions.RedactPaths));
    LRoot.AddPair('includesCommandLines', TJSONBool.Create(AOptions.IncludeCommandLines));

    LSnapshot := TJSONObject.Create;
    LRoot.AddPair('snapshot', LSnapshot);
    LSnapshot.AddPair('sequence', UIntToStr(ASnapshot.Sequence));
    LSnapshot.AddPair('timestamp', IsoUtc(ASnapshot.TimestampUtc));
    LSnapshot.AddPair('processCount', TJSONNumber.Create(Length(ASnapshot.Processes)));

    LArray := TJSONArray.Create;
    LRoot.AddPair('sources', LArray);
    for LStatus in ASnapshot.Sources do
    begin
      LItem := TJSONObject.Create;
      LArray.AddElement(LItem);
      LItem.AddPair('sourceId', LStatus.SourceId);
      LItem.AddPair('state', MHSourceStateToName(LStatus.State));
      LItem.AddPair('stateText', MHSourceStateToString(LStatus.State));
      LItem.AddPair('message', Clean(LStatus.Message, AOptions));
      LItem.AddPair('requiresElevation', TJSONBool.Create(LStatus.RequiresElevation));
    end;

    LArray := TJSONArray.Create;
    LRoot.AddPair('systemMetrics', LArray);
    for LMetric in ASnapshot.Metrics do
      LArray.AddElement(TMHJson.MetricToJson(LMetric));

    LArray := TJSONArray.Create;
    LRoot.AddPair('sensors', LArray);
    for LSensor in ASnapshot.Sensors do
    begin
      LItem := TJSONObject.Create;
      LArray.AddElement(LItem);
      LItem.AddPair('device', SensorKindTitle(LSensor.Kind) + ': ' + LSensor.Device);
      LItem.AddPair('source', LSensor.Source);
      LItem.AddPair('celsius', TJSONNumber.Create(LSensor.Celsius));
      if LSensor.LimitCelsius > 0 then
        LItem.AddPair('limitCelsius', TJSONNumber.Create(LSensor.LimitCelsius));
    end;

    LArray := TJSONArray.Create;
    LRoot.AddPair('findings', LArray);
    for LFinding in AFindings do
      LArray.AddElement(TMHJson.FindingToJson(PrepareFinding(LFinding, AOptions)));

    LArray := TJSONArray.Create;
    LRoot.AddPair('topProcesses', LArray);
    for LProcess in TopProcesses(ASnapshot, AOptions) do
      LArray.AddElement(TMHJson.ProcessToJson(LProcess));

    LRoot.AddPair('missingData', StringsJson(MissingDataSummary(ASnapshot, AFindings, AOptions)));
    LRoot.AddPair('disclaimer', MHL(MH_REPORT_DISCLAIMER, MH_REPORT_DISCLAIMER_EN));
    Result := JsonText(LRoot);
  finally
    LRoot.Free;
  end;
end;

class function TMHReportBuilder.BuildHtml(const ASnapshot: TMHSnapshot;
  const AFindings: TMHFindings; const AOptions: TMHReportOptions): string;
var
  LHtml: THtml;
  LStatus: TMHSourceStatus;
  LMetric: TMHMetric;
  LFinding: TMHFinding;
  LProcess: TMHProcessInfo;
  LMissing: TArray<string>;
  LSensor: TMHSensorReading;
begin
  LHtml := THtml.Create;
  try
    LHtml.BeginDocument(MHL('Отчёт MineHunter X', 'MineHunter X report'));

    LHtml.Tag('h2', MHL('Сводка', 'Summary'));
    LHtml.Raw('<table>'#13#10);
    LHtml.Row(MHL('Отчёт сформирован', 'Report generated'), FormatUtc(AOptions.GeneratedUtc));
    LHtml.Row(MHL('Версия программы', 'Application version'), AOptions.AppVersion);
    LHtml.Row(MHL('Версия правил', 'Ruleset version'), AOptions.RulesetVersion);
    LHtml.Row(MHL('Время снимка', 'Snapshot time'), FormatUtc(ASnapshot.TimestampUtc));
    LHtml.Row(MHL('Процессов в снимке', 'Processes in snapshot'), IntToStr(Length(ASnapshot.Processes)));
    LHtml.Row(MHL('Находок', 'Findings'), IntToStr(Length(AFindings)));
    LHtml.Row(MHL('Наивысший уровень', 'Highest level'), MHRiskLevelToString(HighestLevel(AFindings)));
    for LMetric in ASnapshot.Metrics do
      LHtml.Row(MetricTitle(LMetric.Kind), FormatMetric(LMetric));
    for LSensor in ASnapshot.Sensors do
      if LSensor.LimitCelsius > 0 then
        LHtml.Row(SensorKindTitle(LSensor.Kind) + ' ' + LSensor.Device,
          Format(MHL('%s °C (порог %s °C)', '%s °C (threshold %s °C)'), [FormatNumber(LSensor.Celsius, '0'), FormatNumber(LSensor.LimitCelsius, '0')]))
      else
        LHtml.Row(SensorKindTitle(LSensor.Kind) + ' ' + LSensor.Device,
          FormatNumber(LSensor.Celsius, '0') + ' °C');
    if AOptions.RedactPaths then
      LHtml.Row(MHL('Обезличивание', 'Anonymization'), MHL('имя пользователя, имя компьютера и путь профиля скрыты',
        'user name, computer name and profile path are hidden'))
    else
      LHtml.Row(MHL('Обезличивание', 'Anonymization'), MHL('выключено', 'off'));
    if AOptions.IncludeCommandLines then
      LHtml.Row(MHL('Командные строки', 'Command lines'), MHL('включены', 'included'))
    else
      LHtml.Row(MHL('Командные строки', 'Command lines'), MHL('не включены', 'not included'));
    LHtml.Raw('</table>'#13#10);

    LHtml.Tag('h2', MHL('Состояние источников', 'Source status'));
    if Length(ASnapshot.Sources) = 0 then
      LHtml.Tag('p', MHL('Сведения об источниках отсутствуют.', 'No source information available.'), 'muted')
    else
    begin
      LHtml.Raw('<table>'#13#10'<tr><th>' + MHL('Источник', 'Source') + '</th><th>' + MHL('Состояние', 'State') +
        '</th><th>' + MHL('Пояснение', 'Details') + '</th></tr>'#13#10);
      for LStatus in ASnapshot.Sources do
      begin
        LHtml.Raw('<tr><td>');
        LHtml.Text(LStatus.SourceId);
        LHtml.Raw('</td><td>');
        LHtml.Text(SourceStateText(LStatus.State));
        LHtml.Raw('</td><td>');
        LHtml.Text(Clean(LStatus.Message, AOptions));
        if LStatus.RequiresElevation then
          LHtml.Text(MHL(' (больше данных при запуске от имени администратора)',
            ' (more data when running as administrator)'));
        LHtml.Raw('</td></tr>'#13#10);
      end;
      LHtml.Raw('</table>'#13#10);
    end;

    LHtml.Tag('h2', MHL('Находки', 'Findings'));
    if Length(AFindings) = 0 then
      LHtml.Tag('p', MHL('Находок нет.', 'No findings.'))
    else
      for LFinding in AFindings do
        WriteFinding(LHtml, PrepareFinding(LFinding, AOptions), 'h3');

    LMissing := MissingDataSummary(ASnapshot, AFindings, AOptions);
    WriteStringList(LHtml, MHL('Отсутствующие данные:', 'Missing data:'), LMissing,
      MHL('Все источники ответили полностью.', 'All sources responded fully.'));

    LHtml.Tag('h2', MHL('Самые нагруженные процессы', 'Top processes by load'));
    LHtml.Raw('<table>'#13#10'<tr><th>' + MHL('Процесс', 'Process') + '</th><th>PID</th><th>' +
      MHL('Родитель', 'Parent') + '</th><th>CPU</th>' +
      '<th>' + MHL('Память', 'Memory') + '</th><th>GPU</th><th>' + MHL('Подпись', 'Signature') +
      '</th><th>' + MHL('Путь', 'Path') + '</th>');
    if AOptions.IncludeCommandLines then
      LHtml.Raw('<th>' + MHL('Командная строка', 'Command line') + '</th>');
    LHtml.Raw('</tr>'#13#10);
    for LProcess in TopProcesses(ASnapshot, AOptions) do
    begin
      LHtml.Raw('<tr><td>');
      LHtml.Text(LProcess.Name);
      LHtml.Raw('</td><td>');
      LHtml.Text(UIntToStr(LProcess.Id.Pid));
      LHtml.Raw('</td><td>');
      LHtml.Text(UIntToStr(LProcess.ParentPid));
      LHtml.Raw('</td><td>');
      LHtml.Text(FormatMetric(LProcess.Cpu));
      LHtml.Raw('</td><td>');
      LHtml.Text(FormatMetric(ProcessMemory(LProcess)));
      LHtml.Raw('</td><td>');
      LHtml.Text(FormatMetric(LProcess.Gpu));
      LHtml.Raw('</td><td>');
      LHtml.Text(MHSignatureToString(LProcess.Signature));
      LHtml.Raw('</td><td class="mono">');
      if LProcess.ImagePath <> '' then
        LHtml.Text(LProcess.ImagePath)
      else
        LHtml.Text(MHL(NO_DATA, NO_DATA_EN));
      if AOptions.IncludeCommandLines then
      begin
        LHtml.Raw('</td><td class="mono">');
        LHtml.Text(LProcess.CommandLine);
      end;
      LHtml.Raw('</td></tr>'#13#10);
    end;
    LHtml.Raw('</table>'#13#10);

    LHtml.EndDocument;
    Result := LHtml.ToString;
  finally
    LHtml.Free;
  end;
end;

class function TMHReportBuilder.FindingCardJson(const AFinding: TMHFinding;
  const AProcess: TMHProcessInfo; const ALoad: TArray<TMHMetric>;
  const AOptions: TMHReportOptions): string;
var
  LRoot: TJSONObject;
  LArray: TJSONArray;
  LMetric: TMHMetric;
begin
  LRoot := TJSONObject.Create;
  try
    LRoot.AddPair('generator', GeneratorJson(AOptions));
    LRoot.AddPair('exportedAt', IsoUtc(AOptions.GeneratedUtc));
    LRoot.AddPair('rulesetVersion', AFinding.RulesetVersion);
    LRoot.AddPair('redacted', TJSONBool.Create(AOptions.RedactPaths));
    LRoot.AddPair('finding', TMHJson.FindingToJson(PrepareFinding(AFinding, AOptions)));
    LRoot.AddPair('process', TMHJson.ProcessToJson(PrepareProcess(AProcess, AOptions)));
    LRoot.AddPair('signatureText', MHSignatureToString(AProcess.Signature));
    LArray := TJSONArray.Create;
    LRoot.AddPair('cpuLoad', LArray);
    for LMetric in ALoad do
      LArray.AddElement(TMHJson.MetricToJson(LMetric));
    LRoot.AddPair('disclaimer', MHL(MH_REPORT_DISCLAIMER, MH_REPORT_DISCLAIMER_EN));
    Result := JsonText(LRoot);
  finally
    LRoot.Free;
  end;
end;

class function TMHReportBuilder.FindingCardHtml(const AFinding: TMHFinding;
  const AProcess: TMHProcessInfo; const ALoad: TArray<TMHMetric>;
  const AOptions: TMHReportOptions): string;
var
  LHtml: THtml;
  LProcess: TMHProcessInfo;
begin
  LProcess := PrepareProcess(AProcess, AOptions);
  LHtml := THtml.Create;
  try
    LHtml.BeginDocument(MHL('Карточка находки MineHunter X', 'MineHunter X finding card'));
    LHtml.Raw('<table>'#13#10);
    LHtml.Row(MHL('Экспортировано', 'Exported'), FormatUtc(AOptions.GeneratedUtc));
    LHtml.Row(MHL('Версия программы', 'Application version'), AOptions.AppVersion);
    LHtml.Raw('</table>'#13#10);

    WriteFinding(LHtml, PrepareFinding(AFinding, AOptions), 'h2');

    LHtml.Tag('h2', MHL('Процесс', 'Process'));
    LHtml.Raw('<table>'#13#10);
    LHtml.Row(MHL('Имя', 'Name'), LProcess.Name);
    LHtml.Row('PID', UIntToStr(LProcess.Id.Pid));
    LHtml.Row(MHL('Родительский PID', 'Parent PID'), UIntToStr(LProcess.ParentPid));
    if LProcess.ImagePath <> '' then
      LHtml.Row(MHL('Путь', 'Path'), LProcess.ImagePath, 'mono')
    else
      LHtml.Row(MHL('Путь', 'Path'), MHL(NO_DATA, NO_DATA_EN));
    LHtml.Row(MHL('Цифровая подпись', 'Digital signature'), MHSignatureToString(LProcess.Signature));
    if LProcess.Sha256 <> '' then
      LHtml.Row('SHA-256', LProcess.Sha256, 'mono')
    else
      LHtml.Row('SHA-256', MHL(NO_DATA, NO_DATA_EN));
    LHtml.Row(MHL('Загрузка CPU', 'CPU load'), FormatMetric(LProcess.Cpu));
    LHtml.Row(MHL('Память (как в диспетчере задач)', 'Memory (as in Task Manager)'), FormatMetric(ProcessMemory(LProcess)));
    LHtml.Row(MHL('Рабочий набор', 'Working set'), FormatMetric(LProcess.WorkingSet));
    LHtml.Row(MHL('Загрузка GPU', 'GPU load'), FormatMetric(LProcess.Gpu));
    LHtml.Row(MHL('Вычисления на GPU', 'GPU compute'), FormatMetric(LProcess.GpuCompute));
    LHtml.Row(MHL('Видеопамять', 'Video memory'), FormatMetric(LProcess.GpuMemory));
    if AOptions.IncludeCommandLines then
      LHtml.Row(MHL('Командная строка', 'Command line'), LProcess.CommandLine, 'mono');
    LHtml.Raw('</table>'#13#10);

    WriteLoadChart(LHtml, ALoad);

    LHtml.EndDocument;
    Result := LHtml.ToString;
  finally
    LHtml.Free;
  end;
end;

initialization
  GInvariantFormat := TFormatSettings.Invariant;
  GRuFormat := TFormatSettings.Invariant;
  GRuFormat.DecimalSeparator := ',';
  GRuFormat.ThousandSeparator := ' ';
  GCurrentContext.ProfileDir := QueryProfileDir;
  GCurrentContext.UserName := QueryUserName;
  GCurrentContext.ComputerNames := QueryComputerNames;

end.
