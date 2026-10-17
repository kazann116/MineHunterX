unit MineHunter.Core.Serialization;

{
  JSON-сериализация моделей (для отчётов, экспорта и регрессионных фикстур).

  Формат:
    - время — ISO 8601 UTC;
    - время создания процесса (FILETIME, > 2^53) и другие 64-битные счётчики — строкой,
      чтобы не терять точность в JavaScript и других потребителях JSON;
    - метрика без данных — null (а не 0);
    - поле "schema" содержит версию формата.
  Неизвестные поля при чтении игнорируются; отсутствующие обязательные поля,
  неверные типы и значения вне диапазона приводят к EMHSerializationError.
}

interface

uses
  System.SysUtils, System.JSON,
  MineHunter.Core.Types;

const
  /// Версия формата. Схема 2 добавила файлы, автозапуск, соединения,
  /// контекст и командную строку; документы схемы 1 читаются.
  MH_JSON_SCHEMA = 2;

type
  EMHSerializationError = class(EMHError);

  TMHJson = class
  public
    class function ProcessIdToJson(const AId: TMHProcessId): TJSONObject; static;
    class function ProcessIdFromJson(AJson: TJSONValue): TMHProcessId; static;
    class function MetricToJson(const AMetric: TMHMetric): TJSONObject; static;
    class function MetricFromJson(AJson: TJSONValue): TMHMetric; static;
    class function ProcessToJson(const AInfo: TMHProcessInfo): TJSONObject; static;
    class function ProcessFromJson(AJson: TJSONValue): TMHProcessInfo; static;
    class function SourceStatusToJson(const AStatus: TMHSourceStatus): TJSONObject; static;
    class function SourceStatusFromJson(AJson: TJSONValue): TMHSourceStatus; static;
    class function SnapshotToJson(const ASnapshot: TMHSnapshot): TJSONObject; static;
    class function SnapshotFromJson(AJson: TJSONValue): TMHSnapshot; static;

    class function EvidenceToJson(const AEvidence: TMHEvidence): TJSONObject; static;
    class function EvidenceFromJson(AJson: TJSONValue): TMHEvidence; static;
    class function FindingToJson(const AFinding: TMHFinding): TJSONObject; static;
    class function FindingFromJson(AJson: TJSONValue): TMHFinding; static;
    class function FileInfoToJson(const AInfo: TMHFileInfo): TJSONObject; static;
    class function FileInfoFromJson(AJson: TJSONValue): TMHFileInfo; static;
    class function AutostartToJson(const AEntry: TMHAutostartEntry): TJSONObject; static;
    class function AutostartFromJson(AJson: TJSONValue): TMHAutostartEntry; static;
    class function ConnectionToJson(const AConnection: TMHNetConnection): TJSONObject; static;
    class function ConnectionFromJson(AJson: TJSONValue): TMHNetConnection; static;
    class function ContextToJson(const AContext: TMHContextInfo): TJSONObject; static;
    class function ContextFromJson(AJson: TJSONValue): TMHContextInfo; static;
    class function StatToJson(const AStat: TMHStat): TJSONObject; static;
    class function StatFromJson(AJson: TJSONValue): TMHStat; static;
    class function BaselineToJson(const ABaseline: TMHBaseline): TJSONObject; static;
    class function BaselineFromJson(AJson: TJSONValue): TMHBaseline; static;

    class function FindingToString(const AFinding: TMHFinding; AIndent: Boolean = False): string; static;
    class function FindingFromString(const AText: string): TMHFinding; static;
    class function BaselineToString(const ABaseline: TMHBaseline): string; static;
    class function BaselineFromString(const AText: string): TMHBaseline; static;

    class function SnapshotToString(const ASnapshot: TMHSnapshot;
      AIndent: Boolean = False): string; static;
    class function SnapshotFromString(const AText: string): TMHSnapshot; static;
  end;

/// Стабильные имена перечислений (используются в JSON и в базе истории).
function MHMetricKindToName(AKind: TMHMetricKind): string;
function MHTryMetricKindFromName(const AName: string; out AKind: TMHMetricKind): Boolean;
function MHSourceStateToName(AState: TMHSourceState): string;
function MHTrySourceStateFromName(const AName: string; out AState: TMHSourceState): Boolean;
function MHAccessLevelToName(AAccess: TMHAccessLevel): string;
function MHTryAccessLevelFromName(const AName: string; out AAccess: TMHAccessLevel): Boolean;
function MHRiskLevelToName(ALevel: TMHRiskLevel): string;
function MHFindingCategoryToName(ACategory: TMHFindingCategory): string;
function MHWorkContextToName(AContext: TMHWorkContext): string;
function MHTryWorkContextFromName(const AName: string; out AContext: TMHWorkContext): Boolean;

implementation

uses
  System.DateUtils, System.Generics.Collections;

const
  METRIC_KIND_NAMES: array[TMHMetricKind] of string = ('cpuPercent', 'workingSetBytes',
    'privateBytes', 'diskBytesPerSec', 'networkBytesPerSec', 'gpuPercent', 'temperatureCelsius',
    'memoryUsedBytes', 'memoryTotalBytes', 'memoryLoadPercent', 'diskReadBytesPerSec',
    'diskWriteBytesPerSec', 'diskActivePercent', 'cpuTimePercent', 'cpuFrequencyPercent',
    'cpuPerformanceLimitPercent', 'gpuComputePercent', 'gpuMemoryBytes', 'gpuTemperatureCelsius',
    'cpuTemperatureCelsius', 'diskTemperatureCelsius', 'privateWorkingSetBytes');
  ACCESS_NAMES: array[TMHAccessLevel] of string = ('unknown', 'full', 'limited', 'denied');
  SENSOR_KIND_NAMES: array[TMHSensorKind] of string = ('cpu', 'gpu', 'disk');
  SIGNATURE_NAMES: array[TMHSignatureState] of string = ('notChecked', 'signedTrusted',
    'signedUntrusted', 'unsigned', 'checkFailed');
  RISK_NAMES: array[TMHRiskLevel] of string = ('none', 'low', 'needsReview', 'suspicious',
    'highlySuspicious');
  CATEGORY_NAMES: array[TMHFindingCategory] of string = ('mining', 'suspicious', 'persistence',
    'performance');
  AUTOSTART_KIND_NAMES: array[TMHAutostartKind] of string = ('registryRun', 'registryRunOnce',
    'startupFolder', 'service', 'scheduledTask');
  AUTOSTART_SCOPE_NAMES: array[TMHAutostartScope] of string = ('machine', 'user');
  TRANSPORT_NAMES: array[TMHTransport] of string = ('tcp', 'udp');
  CONTEXT_NAMES: array[TMHWorkContext] of string = ('unknown', 'idle', 'work', 'gaming');
  STATE_NAMES: array[TMHSourceState] of string = ('unknown', 'success', 'partial',
    'unavailable', 'error');

function TryIndexOfName(const ANames: array of string; const AValue: string;
  out AIndex: Integer): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(ANames) do
    if ANames[I] = AValue then
    begin
      AIndex := I;
      Exit(True);
    end;
  AIndex := -1;
  Result := False;
end;

function MHMetricKindToName(AKind: TMHMetricKind): string;
begin
  Result := METRIC_KIND_NAMES[AKind];
end;

function MHTryMetricKindFromName(const AName: string; out AKind: TMHMetricKind): Boolean;
var
  LIndex: Integer;
begin
  Result := TryIndexOfName(METRIC_KIND_NAMES, AName, LIndex);
  if Result then
    AKind := TMHMetricKind(LIndex)
  else
    AKind := Low(TMHMetricKind);
end;

function MHSourceStateToName(AState: TMHSourceState): string;
begin
  Result := STATE_NAMES[AState];
end;

function MHTrySourceStateFromName(const AName: string; out AState: TMHSourceState): Boolean;
var
  LIndex: Integer;
begin
  Result := TryIndexOfName(STATE_NAMES, AName, LIndex);
  if Result then
    AState := TMHSourceState(LIndex)
  else
    AState := ssUnknown;
end;

function MHRiskLevelToName(ALevel: TMHRiskLevel): string;
begin
  Result := RISK_NAMES[ALevel];
end;

function MHFindingCategoryToName(ACategory: TMHFindingCategory): string;
begin
  Result := CATEGORY_NAMES[ACategory];
end;

function MHWorkContextToName(AContext: TMHWorkContext): string;
begin
  Result := CONTEXT_NAMES[AContext];
end;

function MHTryWorkContextFromName(const AName: string; out AContext: TMHWorkContext): Boolean;
var
  LIndex: Integer;
begin
  Result := TryIndexOfName(CONTEXT_NAMES, AName, LIndex);
  if Result then
    AContext := TMHWorkContext(LIndex)
  else
    AContext := wcUnknown;
end;

function MHAccessLevelToName(AAccess: TMHAccessLevel): string;
begin
  Result := ACCESS_NAMES[AAccess];
end;

function MHTryAccessLevelFromName(const AName: string; out AAccess: TMHAccessLevel): Boolean;
var
  LIndex: Integer;
begin
  Result := TryIndexOfName(ACCESS_NAMES, AName, LIndex);
  if Result then
    AAccess := TMHAccessLevel(LIndex)
  else
    AAccess := alUnknown;
end;

{ Вспомогательные функции чтения }

function AsObject(AJson: TJSONValue; const AContext: string): TJSONObject;
begin
  if not (AJson is TJSONObject) then
    raise EMHSerializationError.CreateFmt('%s: ожидался JSON-объект', [AContext]);
  Result := TJSONObject(AJson);
end;

function GetValue(AObj: TJSONObject; const AName: string): TJSONValue;
begin
  Result := AObj.GetValue(AName);
  if Result = nil then
    raise EMHSerializationError.CreateFmt('Отсутствует поле "%s"', [AName]);
end;

function GetString(AObj: TJSONObject; const AName: string): string;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if not (LValue is TJSONString) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть строкой', [AName]);
  Result := LValue.Value;
end;

function GetOptString(AObj: TJSONObject; const AName: string): string;
begin
  if AObj.GetValue(AName) = nil then
    Result := ''
  else
    Result := GetString(AObj, AName);
end;

function GetInt64(AObj: TJSONObject; const AName: string): Int64;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if not (LValue is TJSONNumber) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть числом', [AName]);
  try
    Result := TJSONNumber(LValue).AsInt64;
  except
    on E: Exception do
      raise EMHSerializationError.CreateFmt('Поле "%s": некорректное целое', [AName]);
  end;
end;

function GetCardinal(AObj: TJSONObject; const AName: string): Cardinal;
var
  LValue: Int64;
begin
  LValue := GetInt64(AObj, AName);
  if (LValue < 0) or (LValue > High(Cardinal)) then
    raise EMHSerializationError.CreateFmt('Поле "%s" вне диапазона', [AName]);
  Result := Cardinal(LValue);
end;

function GetInteger(AObj: TJSONObject; const AName: string): Integer;
var
  LValue: Int64;
begin
  LValue := GetInt64(AObj, AName);
  if (LValue < Low(Integer)) or (LValue > High(Integer)) then
    raise EMHSerializationError.CreateFmt('Поле "%s" вне диапазона', [AName]);
  Result := Integer(LValue);
end;

function GetUInt64Str(AObj: TJSONObject; const AName: string): UInt64;
var
  LText: string;
begin
  LText := GetString(AObj, AName);
  if (LText = '') or (LText[1] = '-') or not TryStrToUInt64(LText, Result) then
    raise EMHSerializationError.CreateFmt('Поле "%s": некорректное 64-битное значение', [AName]);
end;

function GetOptBool(AObj: TJSONObject; const AName: string; ADefault: Boolean): Boolean; forward;
function GetOptArray(AObj: TJSONObject; const AName: string): TJSONArray; forward;
function GetDouble(AObj: TJSONObject; const AName: string): Double; forward;

function GetBool(AObj: TJSONObject; const AName: string): Boolean;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if not (LValue is TJSONBool) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть логическим', [AName]);
  Result := TJSONBool(LValue).AsBoolean;
end;

function GetArray(AObj: TJSONObject; const AName: string): TJSONArray;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if not (LValue is TJSONArray) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть массивом', [AName]);
  Result := TJSONArray(LValue);
end;

function GetOptBool(AObj: TJSONObject; const AName: string; ADefault: Boolean): Boolean;
begin
  if AObj.GetValue(AName) = nil then
    Result := ADefault
  else
    Result := GetBool(AObj, AName);
end;

function GetOptArray(AObj: TJSONObject; const AName: string): TJSONArray;
begin
  if AObj.GetValue(AName) = nil then
    Result := nil
  else
    Result := GetArray(AObj, AName);
end;

function GetDouble(AObj: TJSONObject; const AName: string): Double;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if not (LValue is TJSONNumber) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть числом', [AName]);
  Result := TJSONNumber(LValue).AsDouble;
end;

function StringsToJson(const AValues: TArray<string>): TJSONArray;
var
  LValue: string;
begin
  Result := TJSONArray.Create;
  for LValue in AValues do
    Result.Add(LValue);
end;

function StringsFromJson(AArray: TJSONArray): TArray<string>;
var
  I: Integer;
begin
  Result := nil;
  if AArray = nil then
    Exit;
  SetLength(Result, AArray.Count);
  for I := 0 to AArray.Count - 1 do
  begin
    if not (AArray.Items[I] is TJSONString) then
      raise EMHSerializationError.Create('Ожидался массив строк');
    Result[I] := AArray.Items[I].Value;
  end;
end;

function DateToJson(AUtc: TDateTime): TJSONValue;
begin
  if AUtc = 0 then
    Result := TJSONNull.Create
  else
    Result := TJSONString.Create(DateToISO8601(AUtc, True));
end;

function GetDate(AObj: TJSONObject; const AName: string): TDateTime;
var
  LValue: TJSONValue;
begin
  LValue := GetValue(AObj, AName);
  if LValue is TJSONNull then
    Exit(0);
  if not (LValue is TJSONString) then
    raise EMHSerializationError.CreateFmt('Поле "%s" должно быть датой ISO 8601', [AName]);
  if not TryISO8601ToDate(LValue.Value, Result, True) then
    raise EMHSerializationError.CreateFmt('Поле "%s": некорректная дата', [AName]);
end;

function NameToIndex(const ANames: array of string; const AValue, AField: string): Integer;
begin
  if TryIndexOfName(ANames, AValue, Result) then
    Exit;
  raise EMHSerializationError.CreateFmt('Поле "%s": неизвестное значение "%s"', [AField, AValue]);
end;

{ TMHJson }

class function TMHJson.ProcessIdToJson(const AId: TMHProcessId): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('pid', TJSONNumber.Create(AId.Pid));
  Result.AddPair('createTime', UIntToStr(AId.CreateTime));
end;

class function TMHJson.ProcessIdFromJson(AJson: TJSONValue): TMHProcessId;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'processId');
  Result := TMHProcessId.Create(GetCardinal(LObj, 'pid'), GetUInt64Str(LObj, 'createTime'));
end;

class function TMHJson.MetricToJson(const AMetric: TMHMetric): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('kind', METRIC_KIND_NAMES[AMetric.Kind]);
  if AMetric.HasValue then
    Result.AddPair('value', TJSONNumber.Create(AMetric.Value))
  else
    Result.AddPair('value', TJSONNull.Create);
  Result.AddPair('timestamp', DateToJson(AMetric.TimestampUtc));
end;

class function TMHJson.MetricFromJson(AJson: TJSONValue): TMHMetric;
var
  LObj: TJSONObject;
  LValue: TJSONValue;
begin
  LObj := AsObject(AJson, 'metric');
  Result.Kind := TMHMetricKind(NameToIndex(METRIC_KIND_NAMES, GetString(LObj, 'kind'), 'kind'));
  Result.TimestampUtc := GetDate(LObj, 'timestamp');
  LValue := GetValue(LObj, 'value');
  if LValue is TJSONNull then
  begin
    Result.HasValue := False;
    Result.Value := 0;
  end
  else if LValue is TJSONNumber then
  begin
    Result.HasValue := True;
    Result.Value := TJSONNumber(LValue).AsDouble;
  end
  else
    raise EMHSerializationError.Create('Поле "value" должно быть числом или null');
end;

/// Метрика из необязательного поля; поля нет — «нет данных» вида AKind.
function OptMetricFromJson(AObj: TJSONObject; const AName: string; AKind: TMHMetricKind): TMHMetric;
var
  LValue: TJSONValue;
begin
  LValue := AObj.GetValue(AName);
  if (LValue = nil) or (LValue is TJSONNull) then
    Result := TMHMetric.NoData(AKind, 0)
  else
    Result := TMHJson.MetricFromJson(LValue);
end;

class function TMHJson.ProcessToJson(const AInfo: TMHProcessInfo): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('id', ProcessIdToJson(AInfo.Id));
    Result.AddPair('parentPid', TJSONNumber.Create(AInfo.ParentPid));
    Result.AddPair('name', AInfo.Name);
    Result.AddPair('imagePath', AInfo.ImagePath);
    Result.AddPair('sha256', AInfo.Sha256);
    Result.AddPair('signature', SIGNATURE_NAMES[AInfo.Signature]);
    Result.AddPair('access', ACCESS_NAMES[AInfo.Access]);
    Result.AddPair('cpu', MetricToJson(AInfo.Cpu));
    Result.AddPair('workingSet', MetricToJson(AInfo.WorkingSet));
    Result.AddPair('privateBytes', MetricToJson(AInfo.PrivateBytes));
    Result.AddPair('threadCount', TJSONNumber.Create(AInfo.ThreadCount));
    Result.AddPair('sourceId', AInfo.SourceId);
    if AInfo.CommandLine <> '' then
      Result.AddPair('commandLine', AInfo.CommandLine);
    Result.AddPair('hasVisibleWindow', TJSONBool.Create(AInfo.HasVisibleWindow));
    // Необязательные метрики пишутся только при наличии значения (совместимость со старыми файлами).
    if AInfo.PrivateWorkingSet.HasValue then
      Result.AddPair('privateWorkingSet', MetricToJson(AInfo.PrivateWorkingSet));
    if AInfo.Gpu.HasValue then
      Result.AddPair('gpu', MetricToJson(AInfo.Gpu));
    if AInfo.GpuCompute.HasValue then
      Result.AddPair('gpuCompute', MetricToJson(AInfo.GpuCompute));
    if AInfo.GpuMemory.HasValue then
      Result.AddPair('gpuMemory', MetricToJson(AInfo.GpuMemory));
  except
    Result.Free;
    raise;
  end;
end;

class function TMHJson.ProcessFromJson(AJson: TJSONValue): TMHProcessInfo;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'process');
  Result := Default(TMHProcessInfo);
  Result.Id := ProcessIdFromJson(GetValue(LObj, 'id'));
  Result.ParentPid := GetCardinal(LObj, 'parentPid');
  Result.Name := GetString(LObj, 'name');
  Result.ImagePath := GetOptString(LObj, 'imagePath');
  Result.Sha256 := GetOptString(LObj, 'sha256');
  Result.Signature := TMHSignatureState(NameToIndex(SIGNATURE_NAMES,
    GetString(LObj, 'signature'), 'signature'));
  Result.Access := TMHAccessLevel(NameToIndex(ACCESS_NAMES, GetString(LObj, 'access'), 'access'));
  Result.Cpu := MetricFromJson(GetValue(LObj, 'cpu'));
  Result.WorkingSet := MetricFromJson(GetValue(LObj, 'workingSet'));
  Result.PrivateBytes := MetricFromJson(GetValue(LObj, 'privateBytes'));
  Result.ThreadCount := GetInteger(LObj, 'threadCount');
  Result.SourceId := GetOptString(LObj, 'sourceId');
  Result.CommandLine := GetOptString(LObj, 'commandLine');
  Result.HasVisibleWindow := GetOptBool(LObj, 'hasVisibleWindow', False);
  Result.PrivateWorkingSet := OptMetricFromJson(LObj, 'privateWorkingSet', mkPrivateWorkingSetBytes);
  Result.Gpu := OptMetricFromJson(LObj, 'gpu', mkGpuPercent);
  Result.GpuCompute := OptMetricFromJson(LObj, 'gpuCompute', mkGpuComputePercent);
  Result.GpuMemory := OptMetricFromJson(LObj, 'gpuMemory', mkGpuMemoryBytes);
end;

class function TMHJson.SourceStatusToJson(const AStatus: TMHSourceStatus): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('sourceId', AStatus.SourceId);
  Result.AddPair('state', STATE_NAMES[AStatus.State]);
  Result.AddPair('message', AStatus.Message);
  Result.AddPair('requiresElevation', TJSONBool.Create(AStatus.RequiresElevation));
  Result.AddPair('timestamp', DateToJson(AStatus.TimestampUtc));
  Result.AddPair('durationMs', TJSONNumber.Create(AStatus.DurationMs));
  Result.AddPair('itemCount', TJSONNumber.Create(AStatus.ItemCount));
end;

class function TMHJson.SourceStatusFromJson(AJson: TJSONValue): TMHSourceStatus;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'source');
  Result.SourceId := GetString(LObj, 'sourceId');
  Result.State := TMHSourceState(NameToIndex(STATE_NAMES, GetString(LObj, 'state'), 'state'));
  Result.Message := GetOptString(LObj, 'message');
  Result.RequiresElevation := GetBool(LObj, 'requiresElevation');
  Result.TimestampUtc := GetDate(LObj, 'timestamp');
  Result.DurationMs := GetCardinal(LObj, 'durationMs');
  Result.ItemCount := GetInteger(LObj, 'itemCount');
end;

function SensorToJson(const AReading: TMHSensorReading): TJSONObject; forward;
function SensorFromJson(AJson: TJSONValue): TMHSensorReading; forward;

class function TMHJson.SnapshotToJson(const ASnapshot: TMHSnapshot): TJSONObject;
var
  LArray: TJSONArray;
  I: Integer;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('schema', TJSONNumber.Create(MH_JSON_SCHEMA));
    Result.AddPair('sequence', UIntToStr(ASnapshot.Sequence));
    Result.AddPair('timestamp', DateToJson(ASnapshot.TimestampUtc));

    LArray := TJSONArray.Create;
    Result.AddPair('processes', LArray);
    for I := 0 to High(ASnapshot.Processes) do
      LArray.AddElement(ProcessToJson(ASnapshot.Processes[I]));

    LArray := TJSONArray.Create;
    Result.AddPair('metrics', LArray);
    for I := 0 to High(ASnapshot.Metrics) do
      LArray.AddElement(MetricToJson(ASnapshot.Metrics[I]));

    LArray := TJSONArray.Create;
    Result.AddPair('sources', LArray);
    for I := 0 to High(ASnapshot.Sources) do
      LArray.AddElement(SourceStatusToJson(ASnapshot.Sources[I]));

    LArray := TJSONArray.Create;
    Result.AddPair('files', LArray);
    for I := 0 to High(ASnapshot.Files) do
      LArray.AddElement(FileInfoToJson(ASnapshot.Files[I]));

    LArray := TJSONArray.Create;
    Result.AddPair('autostart', LArray);
    for I := 0 to High(ASnapshot.Autostart) do
      LArray.AddElement(AutostartToJson(ASnapshot.Autostart[I]));

    LArray := TJSONArray.Create;
    Result.AddPair('connections', LArray);
    for I := 0 to High(ASnapshot.Connections) do
      LArray.AddElement(ConnectionToJson(ASnapshot.Connections[I]));

    Result.AddPair('context', ContextToJson(ASnapshot.Context));

    // Датчики пишутся только при наличии (совместимость с ранее сохранёнными снимками).
    if Length(ASnapshot.Sensors) > 0 then
    begin
      LArray := TJSONArray.Create;
      Result.AddPair('sensors', LArray);
      for I := 0 to High(ASnapshot.Sensors) do
        LArray.AddElement(SensorToJson(ASnapshot.Sensors[I]));
    end;
  except
    Result.Free;
    raise;
  end;
end;

function SensorToJson(const AReading: TMHSensorReading): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('kind', SENSOR_KIND_NAMES[AReading.Kind]);
  Result.AddPair('device', AReading.Device);
  Result.AddPair('source', AReading.Source);
  Result.AddPair('celsius', TJSONNumber.Create(AReading.Celsius));
  Result.AddPair('limitCelsius', TJSONNumber.Create(AReading.LimitCelsius));
end;

function SensorFromJson(AJson: TJSONValue): TMHSensorReading;
var
  LObj: TJSONObject;
begin
  if not (AJson is TJSONObject) then
    raise EMHSerializationError.Create('Ожидается объект датчика');
  LObj := TJSONObject(AJson);
  Result := TMHSensorReading.Create(
    TMHSensorKind(NameToIndex(SENSOR_KIND_NAMES, GetString(LObj, 'kind'), 'kind')),
    GetOptString(LObj, 'device'), GetOptString(LObj, 'source'),
    GetDouble(LObj, 'celsius'), GetDouble(LObj, 'limitCelsius'));
end;

class function TMHJson.SnapshotFromJson(AJson: TJSONValue): TMHSnapshot;
var
  LObj: TJSONObject;
  LArray: TJSONArray;
  LSchema: Int64;
  I: Integer;
begin
  LObj := AsObject(AJson, 'snapshot');
  LSchema := GetInt64(LObj, 'schema');
  if (LSchema < 1) or (LSchema > MH_JSON_SCHEMA) then
    raise EMHSerializationError.CreateFmt('Неподдерживаемая версия формата: %d', [LSchema]);
  Result := TMHSnapshot.Create(GetUInt64Str(LObj, 'sequence'), GetDate(LObj, 'timestamp'));

  LArray := GetArray(LObj, 'processes');
  SetLength(Result.Processes, LArray.Count);
  for I := 0 to LArray.Count - 1 do
    Result.Processes[I] := ProcessFromJson(LArray.Items[I]);

  LArray := GetArray(LObj, 'metrics');
  SetLength(Result.Metrics, LArray.Count);
  for I := 0 to LArray.Count - 1 do
    Result.Metrics[I] := MetricFromJson(LArray.Items[I]);

  LArray := GetArray(LObj, 'sources');
  SetLength(Result.Sources, LArray.Count);
  for I := 0 to LArray.Count - 1 do
    Result.Sources[I] := SourceStatusFromJson(LArray.Items[I]);

  // Необязательные разделы (схема 2).
  LArray := GetOptArray(LObj, 'files');
  if LArray <> nil then
  begin
    SetLength(Result.Files, LArray.Count);
    for I := 0 to LArray.Count - 1 do
      Result.Files[I] := FileInfoFromJson(LArray.Items[I]);
  end;
  LArray := GetOptArray(LObj, 'autostart');
  if LArray <> nil then
  begin
    SetLength(Result.Autostart, LArray.Count);
    for I := 0 to LArray.Count - 1 do
      Result.Autostart[I] := AutostartFromJson(LArray.Items[I]);
  end;
  LArray := GetOptArray(LObj, 'connections');
  if LArray <> nil then
  begin
    SetLength(Result.Connections, LArray.Count);
    for I := 0 to LArray.Count - 1 do
      Result.Connections[I] := ConnectionFromJson(LArray.Items[I]);
  end;
  if LObj.GetValue('context') <> nil then
    Result.Context := ContextFromJson(LObj.GetValue('context'));
  LArray := GetOptArray(LObj, 'sensors');
  if LArray <> nil then
  begin
    SetLength(Result.Sensors, LArray.Count);
    for I := 0 to LArray.Count - 1 do
      Result.Sensors[I] := SensorFromJson(LArray.Items[I]);
  end;
end;

class function TMHJson.EvidenceToJson(const AEvidence: TMHEvidence): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('code', AEvidence.Code);
  Result.AddPair('description', AEvidence.Description);
  Result.AddPair('weight', TJSONNumber.Create(AEvidence.Weight));
  Result.AddPair('observed', AEvidence.Observed);
end;

class function TMHJson.EvidenceFromJson(AJson: TJSONValue): TMHEvidence;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'evidence');
  Result := TMHEvidence.Create(GetString(LObj, 'code'), GetString(LObj, 'description'),
    GetInteger(LObj, 'weight'), GetOptString(LObj, 'observed'));
end;

class function TMHJson.FindingToJson(const AFinding: TMHFinding): TJSONObject;
var
  LArray: TJSONArray;
  LEvidence: TMHEvidence;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('id', AFinding.Id.ToString);
    Result.AddPair('key', AFinding.Key);
    Result.AddPair('category', CATEGORY_NAMES[AFinding.Category]);
    Result.AddPair('process', ProcessIdToJson(AFinding.Process));
    Result.AddPair('parentPid', TJSONNumber.Create(AFinding.ParentPid));
    Result.AddPair('processName', AFinding.ProcessName);
    Result.AddPair('imagePath', AFinding.ImagePath);
    Result.AddPair('title', AFinding.Title);
    Result.AddPair('summary', AFinding.Summary);
    Result.AddPair('score', TJSONNumber.Create(AFinding.Score));
    Result.AddPair('rawScore', TJSONNumber.Create(AFinding.RawScore));
    Result.AddPair('level', RISK_NAMES[AFinding.Level]);
    Result.AddPair('confidence', TJSONNumber.Create(AFinding.Confidence));
    LArray := TJSONArray.Create;
    Result.AddPair('evidence', LArray);
    for LEvidence in AFinding.Evidence do
      LArray.AddElement(EvidenceToJson(LEvidence));
    Result.AddPair('missingData', StringsToJson(AFinding.MissingData));
    Result.AddPair('recommendations', StringsToJson(AFinding.Recommendations));
    Result.AddPair('rulesetVersion', AFinding.RulesetVersion);
    Result.AddPair('detectedAt', DateToJson(AFinding.DetectedAtUtc));
  except
    Result.Free;
    raise;
  end;
end;

class function TMHJson.FindingFromJson(AJson: TJSONValue): TMHFinding;
var
  LObj: TJSONObject;
  LArray: TJSONArray;
  I: Integer;
begin
  LObj := AsObject(AJson, 'finding');
  Result := Default(TMHFinding);
  try
    Result.Id := TGUID.Create(GetString(LObj, 'id'));
  except
    on E: Exception do
      raise EMHSerializationError.Create('Поле "id": некорректный GUID');
  end;
  Result.Key := GetOptString(LObj, 'key');
  Result.Category := TMHFindingCategory(NameToIndex(CATEGORY_NAMES, GetString(LObj, 'category'), 'category'));
  Result.Process := ProcessIdFromJson(GetValue(LObj, 'process'));
  Result.ParentPid := GetCardinal(LObj, 'parentPid');
  Result.ProcessName := GetOptString(LObj, 'processName');
  Result.ImagePath := GetOptString(LObj, 'imagePath');
  Result.Title := GetString(LObj, 'title');
  Result.Summary := GetOptString(LObj, 'summary');
  Result.Score := GetInteger(LObj, 'score');
  if (Result.Score < 0) or (Result.Score > 100) then
    raise EMHSerializationError.Create('Поле "score" вне диапазона 0..100');
  Result.RawScore := GetInteger(LObj, 'rawScore');
  Result.Level := TMHRiskLevel(NameToIndex(RISK_NAMES, GetString(LObj, 'level'), 'level'));
  Result.Confidence := GetDouble(LObj, 'confidence');
  LArray := GetArray(LObj, 'evidence');
  SetLength(Result.Evidence, LArray.Count);
  for I := 0 to LArray.Count - 1 do
    Result.Evidence[I] := EvidenceFromJson(LArray.Items[I]);
  Result.MissingData := StringsFromJson(GetOptArray(LObj, 'missingData'));
  Result.Recommendations := StringsFromJson(GetOptArray(LObj, 'recommendations'));
  Result.RulesetVersion := GetString(LObj, 'rulesetVersion');
  Result.DetectedAtUtc := GetDate(LObj, 'detectedAt');
end;

class function TMHJson.FileInfoToJson(const AInfo: TMHFileInfo): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('path', AInfo.Path);
  Result.AddPair('sizeBytes', TJSONNumber.Create(AInfo.SizeBytes));
  Result.AddPair('lastWrite', DateToJson(AInfo.LastWriteUtc));
  Result.AddPair('sha256', AInfo.Sha256);
  Result.AddPair('signature', SIGNATURE_NAMES[AInfo.Signature]);
  Result.AddPair('signer', AInfo.Signer);
  Result.AddPair('signatureSource', AInfo.SignatureSource);
  Result.AddPair('error', AInfo.Error);
end;

class function TMHJson.FileInfoFromJson(AJson: TJSONValue): TMHFileInfo;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'file');
  Result := TMHFileInfo.Create(GetString(LObj, 'path'));
  Result.SizeBytes := GetInt64(LObj, 'sizeBytes');
  Result.LastWriteUtc := GetDate(LObj, 'lastWrite');
  Result.Sha256 := GetOptString(LObj, 'sha256');
  Result.Signature := TMHSignatureState(NameToIndex(SIGNATURE_NAMES,
    GetString(LObj, 'signature'), 'signature'));
  Result.Signer := GetOptString(LObj, 'signer');
  Result.SignatureSource := GetOptString(LObj, 'signatureSource');
  Result.Error := GetOptString(LObj, 'error');
end;

class function TMHJson.AutostartToJson(const AEntry: TMHAutostartEntry): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('kind', AUTOSTART_KIND_NAMES[AEntry.Kind]);
  Result.AddPair('scope', AUTOSTART_SCOPE_NAMES[AEntry.Scope]);
  Result.AddPair('name', AEntry.Name);
  Result.AddPair('command', AEntry.Command);
  Result.AddPair('imagePath', AEntry.ImagePath);
  Result.AddPair('location', AEntry.Location);
  Result.AddPair('enabled', TJSONBool.Create(AEntry.Enabled));
  Result.AddPair('details', AEntry.Details);
end;

class function TMHJson.AutostartFromJson(AJson: TJSONValue): TMHAutostartEntry;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'autostart');
  Result := Default(TMHAutostartEntry);
  Result.Kind := TMHAutostartKind(NameToIndex(AUTOSTART_KIND_NAMES, GetString(LObj, 'kind'), 'kind'));
  Result.Scope := TMHAutostartScope(NameToIndex(AUTOSTART_SCOPE_NAMES, GetString(LObj, 'scope'), 'scope'));
  Result.Name := GetString(LObj, 'name');
  Result.Command := GetOptString(LObj, 'command');
  Result.ImagePath := GetOptString(LObj, 'imagePath');
  Result.Location := GetOptString(LObj, 'location');
  Result.Enabled := GetOptBool(LObj, 'enabled', True);
  Result.Details := GetOptString(LObj, 'details');
end;

class function TMHJson.ConnectionToJson(const AConnection: TMHNetConnection): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('transport', TRANSPORT_NAMES[AConnection.Transport]);
  Result.AddPair('ipv6', TJSONBool.Create(AConnection.IPv6));
  Result.AddPair('localAddress', AConnection.LocalAddress);
  Result.AddPair('localPort', TJSONNumber.Create(AConnection.LocalPort));
  Result.AddPair('remoteAddress', AConnection.RemoteAddress);
  Result.AddPair('remotePort', TJSONNumber.Create(AConnection.RemotePort));
  Result.AddPair('state', AConnection.State);
  Result.AddPair('owningPid', TJSONNumber.Create(AConnection.OwningPid));
end;

class function TMHJson.ConnectionFromJson(AJson: TJSONValue): TMHNetConnection;
var
  LObj: TJSONObject;
  LPort: Int64;
begin
  LObj := AsObject(AJson, 'connection');
  Result := Default(TMHNetConnection);
  Result.Transport := TMHTransport(NameToIndex(TRANSPORT_NAMES, GetString(LObj, 'transport'), 'transport'));
  Result.IPv6 := GetOptBool(LObj, 'ipv6', False);
  Result.LocalAddress := GetOptString(LObj, 'localAddress');
  LPort := GetInt64(LObj, 'localPort');
  if (LPort < 0) or (LPort > 65535) then
    raise EMHSerializationError.Create('Поле "localPort" вне диапазона');
  Result.LocalPort := Word(LPort);
  Result.RemoteAddress := GetOptString(LObj, 'remoteAddress');
  LPort := GetInt64(LObj, 'remotePort');
  if (LPort < 0) or (LPort > 65535) then
    raise EMHSerializationError.Create('Поле "remotePort" вне диапазона');
  Result.RemotePort := Word(LPort);
  Result.State := GetOptString(LObj, 'state');
  Result.OwningPid := GetCardinal(LObj, 'owningPid');
end;

class function TMHJson.ContextToJson(const AContext: TMHContextInfo): TJSONObject;
var
  LArray: TJSONArray;
  LPid: Cardinal;
begin
  Result := TJSONObject.Create;
  Result.AddPair('available', TJSONBool.Create(AContext.Available));
  Result.AddPair('userIdleSeconds', TJSONNumber.Create(AContext.UserIdleSeconds));
  Result.AddPair('foregroundPid', TJSONNumber.Create(AContext.ForegroundPid));
  Result.AddPair('fullscreenActive', TJSONBool.Create(AContext.FullscreenActive));
  Result.AddPair('workContext', CONTEXT_NAMES[AContext.WorkContext]);
  LArray := TJSONArray.Create;
  Result.AddPair('visibleWindowPids', LArray);
  for LPid in AContext.VisibleWindowPids do
    LArray.Add(Int64(LPid));
end;

class function TMHJson.ContextFromJson(AJson: TJSONValue): TMHContextInfo;
var
  LObj: TJSONObject;
  LArray: TJSONArray;
  I: Integer;
begin
  LObj := AsObject(AJson, 'context');
  Result := Default(TMHContextInfo);
  Result.Available := GetOptBool(LObj, 'available', False);
  Result.UserIdleSeconds := GetCardinal(LObj, 'userIdleSeconds');
  Result.ForegroundPid := GetCardinal(LObj, 'foregroundPid');
  Result.FullscreenActive := GetOptBool(LObj, 'fullscreenActive', False);
  Result.WorkContext := TMHWorkContext(NameToIndex(CONTEXT_NAMES, GetString(LObj, 'workContext'), 'workContext'));
  LArray := GetOptArray(LObj, 'visibleWindowPids');
  if LArray <> nil then
  begin
    SetLength(Result.VisibleWindowPids, LArray.Count);
    for I := 0 to LArray.Count - 1 do
    begin
      if not (LArray.Items[I] is TJSONNumber) then
        raise EMHSerializationError.Create('Поле "visibleWindowPids" должно содержать числа');
      Result.VisibleWindowPids[I] := Cardinal(TJSONNumber(LArray.Items[I]).AsInt64);
    end;
  end;
end;

class function TMHJson.StatToJson(const AStat: TMHStat): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('count', TJSONNumber.Create(AStat.SampleCount));
  Result.AddPair('mean', TJSONNumber.Create(AStat.Mean));
  Result.AddPair('median', TJSONNumber.Create(AStat.Median));
  Result.AddPair('p95', TJSONNumber.Create(AStat.P95));
  Result.AddPair('max', TJSONNumber.Create(AStat.Max));
end;

class function TMHJson.StatFromJson(AJson: TJSONValue): TMHStat;
var
  LObj: TJSONObject;
begin
  LObj := AsObject(AJson, 'stat');
  Result.SampleCount := GetInteger(LObj, 'count');
  Result.Mean := GetDouble(LObj, 'mean');
  Result.Median := GetDouble(LObj, 'median');
  Result.P95 := GetDouble(LObj, 'p95');
  Result.Max := GetDouble(LObj, 'max');
end;

class function TMHJson.BaselineToJson(const ABaseline: TMHBaseline): TJSONObject;
var
  LArray: TJSONArray;
  LItem: TJSONObject;
  LProcess: TMHProcessBaseline;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('schema', TJSONNumber.Create(MH_JSON_SCHEMA));
    Result.AddPair('context', CONTEXT_NAMES[ABaseline.Context]);
    Result.AddPair('created', DateToJson(ABaseline.CreatedUtc));
    Result.AddPair('updated', DateToJson(ABaseline.UpdatedUtc));
    Result.AddPair('sampleCount', TJSONNumber.Create(ABaseline.SampleCount));
    Result.AddPair('periodFrom', DateToJson(ABaseline.PeriodFromUtc));
    Result.AddPair('periodTo', DateToJson(ABaseline.PeriodToUtc));
    Result.AddPair('systemCpu', StatToJson(ABaseline.SystemCpu));
    Result.AddPair('memoryLoad', StatToJson(ABaseline.MemoryLoad));
    Result.AddPair('diskActive', StatToJson(ABaseline.DiskActive));
    LArray := TJSONArray.Create;
    Result.AddPair('processes', LArray);
    for LProcess in ABaseline.Processes do
    begin
      LItem := TJSONObject.Create;
      LArray.AddElement(LItem);
      LItem.AddPair('key', LProcess.Key);
      LItem.AddPair('name', LProcess.Name);
      LItem.AddPair('cpu', StatToJson(LProcess.Cpu));
      LItem.AddPair('workingSet', StatToJson(LProcess.WorkingSet));
      LItem.AddPair('presence', TJSONNumber.Create(LProcess.PresenceRatio));
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TMHJson.BaselineFromJson(AJson: TJSONValue): TMHBaseline;
var
  LObj, LItem: TJSONObject;
  LArray: TJSONArray;
  I: Integer;
begin
  LObj := AsObject(AJson, 'baseline');
  Result := TMHBaseline.Empty;
  Result.Context := TMHWorkContext(NameToIndex(CONTEXT_NAMES, GetString(LObj, 'context'), 'context'));
  Result.CreatedUtc := GetDate(LObj, 'created');
  Result.UpdatedUtc := GetDate(LObj, 'updated');
  Result.SampleCount := GetInteger(LObj, 'sampleCount');
  Result.PeriodFromUtc := GetDate(LObj, 'periodFrom');
  Result.PeriodToUtc := GetDate(LObj, 'periodTo');
  Result.SystemCpu := StatFromJson(GetValue(LObj, 'systemCpu'));
  Result.MemoryLoad := StatFromJson(GetValue(LObj, 'memoryLoad'));
  Result.DiskActive := StatFromJson(GetValue(LObj, 'diskActive'));
  LArray := GetArray(LObj, 'processes');
  SetLength(Result.Processes, LArray.Count);
  for I := 0 to LArray.Count - 1 do
  begin
    LItem := AsObject(LArray.Items[I], 'processBaseline');
    Result.Processes[I].Key := GetString(LItem, 'key');
    Result.Processes[I].Name := GetOptString(LItem, 'name');
    Result.Processes[I].Cpu := StatFromJson(GetValue(LItem, 'cpu'));
    Result.Processes[I].WorkingSet := StatFromJson(GetValue(LItem, 'workingSet'));
    Result.Processes[I].PresenceRatio := GetDouble(LItem, 'presence');
  end;
end;

function ParseObject(const AText: string): TJSONValue;
begin
  Result := TJSONObject.ParseJSONValue(AText, True, False);
  if Result = nil then
    raise EMHSerializationError.Create('Некорректный JSON');
end;

function JsonToText(AJson: TJSONValue; AIndent: Boolean): string;
begin
  try
    if AIndent then
      Result := AJson.Format(2)
    else
      Result := AJson.ToJSON;
  finally
    AJson.Free;
  end;
end;

class function TMHJson.FindingToString(const AFinding: TMHFinding; AIndent: Boolean): string;
begin
  Result := JsonToText(FindingToJson(AFinding), AIndent);
end;

class function TMHJson.FindingFromString(const AText: string): TMHFinding;
var
  LJson: TJSONValue;
begin
  LJson := ParseObject(AText);
  try
    Result := FindingFromJson(LJson);
  finally
    LJson.Free;
  end;
end;

class function TMHJson.BaselineToString(const ABaseline: TMHBaseline): string;
begin
  Result := JsonToText(BaselineToJson(ABaseline), False);
end;

class function TMHJson.BaselineFromString(const AText: string): TMHBaseline;
var
  LJson: TJSONValue;
begin
  LJson := ParseObject(AText);
  try
    Result := BaselineFromJson(LJson);
  finally
    LJson.Free;
  end;
end;

class function TMHJson.SnapshotToString(const ASnapshot: TMHSnapshot; AIndent: Boolean): string;
var
  LJson: TJSONObject;
begin
  LJson := SnapshotToJson(ASnapshot);
  try
    if AIndent then
      Result := LJson.Format(2)
    else
      Result := LJson.ToJSON;
  finally
    LJson.Free;
  end;
end;

class function TMHJson.SnapshotFromString(const AText: string): TMHSnapshot;
var
  LJson: TJSONValue;
begin
  LJson := TJSONObject.ParseJSONValue(AText, True, False);
  if LJson = nil then
    raise EMHSerializationError.Create('Некорректный JSON');
  try
    Result := SnapshotFromJson(LJson);
  finally
    LJson.Free;
  end;
end;

end.
