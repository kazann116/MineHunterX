unit MineHunter.Tests.Serialization;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types;

type
  [TestFixture]
  [Category('Unit')]
  TSerializationTests = class
  public
    [Test] procedure Snapshot_RoundTrip_PreservesAllFields;
    [Test] procedure EmptySnapshot_RoundTrip;
    [Test] procedure NoDataMetric_IsNullNotZero;
    [Test] procedure CreateTime_IsStringWithoutPrecisionLoss;
    [Test] procedure ZeroTimestamp_IsNull;
    [Test] procedure UnicodePaths_Survive;
    [Test] procedure UnknownFields_AreIgnored;
    [Test] procedure InvalidJson_Raises;
    [Test] procedure WrongSchema_Raises;
    [Test] procedure MissingField_Raises;
    [Test] procedure WrongType_Raises;
    [Test] procedure OutOfRangePid_Raises;
    [Test] procedure UnknownEnumValue_Raises;
    [Test] procedure NegativeCreateTime_Raises;
  end;

implementation

uses
  System.SysUtils, System.JSON, System.DateUtils,
  MineHunter.Core.Serialization;

function SampleSnapshot: TMHSnapshot;
var
  LInfo: TMHProcessInfo;
  LStatus: TMHSourceStatus;
  LTime: TDateTime;
begin
  LTime := EncodeDateTime(2026, 10, 16, 12, 30, 15, 250);
  Result := TMHSnapshot.Create(42, LTime);
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(1234, 134050000000000001), 'app.exe', LTime);
  LInfo.ParentPid := 4;
  LInfo.ImagePath := 'C:\Program Files\App\app.exe';
  LInfo.Sha256 := 'ab12';
  LInfo.Signature := sgSignedTrusted;
  LInfo.Access := alLimited;
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, 12.75, LTime);
  LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 123456789, LTime);
  LInfo.ThreadCount := 17;
  LInfo.SourceId := 'processes';
  Result.Processes := [LInfo];
  Result.Metrics := [TMHMetric.NoData(mkTemperatureCelsius, LTime)];
  LStatus := TMHSourceStatus.Create('processes', ssPartial, 'Нет доступа: 3', LTime);
  LStatus.RequiresElevation := True;
  LStatus.DurationMs := 15;
  LStatus.ItemCount := 250;
  Result.Sources := [LStatus];
end;

procedure TSerializationTests.Snapshot_RoundTrip_PreservesAllFields;
var
  LSource, LBack: TMHSnapshot;
  P, Q: TMHProcessInfo;
begin
  LSource := SampleSnapshot;
  LBack := TMHJson.SnapshotFromString(TMHJson.SnapshotToString(LSource));
  Assert.AreEqual<UInt64>(42, LBack.Sequence);
  Assert.AreEqual(LSource.TimestampUtc, LBack.TimestampUtc, 1 / MSecsPerDay);
  Assert.AreEqual(1, Integer(Length(LBack.Processes)));
  P := LSource.Processes[0];
  Q := LBack.Processes[0];
  Assert.IsTrue(P.Id = Q.Id);
  Assert.AreEqual(P.ParentPid, Q.ParentPid);
  Assert.AreEqual(P.Name, Q.Name);
  Assert.AreEqual(P.ImagePath, Q.ImagePath);
  Assert.AreEqual(P.Sha256, Q.Sha256);
  Assert.AreEqual<TMHSignatureState>(P.Signature, Q.Signature);
  Assert.AreEqual<TMHAccessLevel>(P.Access, Q.Access);
  Assert.AreEqual(P.Cpu.Value, Q.Cpu.Value, 1e-9);
  Assert.IsTrue(Q.Cpu.HasValue);
  Assert.AreEqual(P.WorkingSet.Value, Q.WorkingSet.Value, 0.5);
  Assert.IsFalse(Q.PrivateBytes.HasValue);
  Assert.AreEqual(P.ThreadCount, Q.ThreadCount);
  Assert.AreEqual(P.SourceId, Q.SourceId);
  Assert.AreEqual(1, Integer(Length(LBack.Metrics)));
  Assert.IsFalse(LBack.Metrics[0].HasValue);
  Assert.AreEqual<TMHMetricKind>(mkTemperatureCelsius, LBack.Metrics[0].Kind);
  Assert.AreEqual(1, Integer(Length(LBack.Sources)));
  Assert.AreEqual<TMHSourceState>(ssPartial, LBack.Sources[0].State);
  Assert.AreEqual('Нет доступа: 3', LBack.Sources[0].Message);
  Assert.IsTrue(LBack.Sources[0].RequiresElevation);
  Assert.AreEqual<Cardinal>(15, LBack.Sources[0].DurationMs);
  Assert.AreEqual(250, LBack.Sources[0].ItemCount);
end;

procedure TSerializationTests.EmptySnapshot_RoundTrip;
var
  LBack: TMHSnapshot;
begin
  LBack := TMHJson.SnapshotFromString(TMHJson.SnapshotToString(Default(TMHSnapshot)));
  Assert.AreEqual<UInt64>(0, LBack.Sequence);
  Assert.AreEqual(0.0, LBack.TimestampUtc, 0);
  Assert.AreEqual(0, Integer(Length(LBack.Processes)));
end;

procedure TSerializationTests.NoDataMetric_IsNullNotZero;
var
  LJson: TJSONObject;
begin
  LJson := TMHJson.MetricToJson(TMHMetric.NoData(mkGpuPercent, 0));
  try
    Assert.IsTrue(LJson.GetValue('value') is TJSONNull);
  finally
    LJson.Free;
  end;
end;

procedure TSerializationTests.CreateTime_IsStringWithoutPrecisionLoss;
var
  LJson: TJSONObject;
  LId: TMHProcessId;
begin
  // 2^53 + 1 не представимо в double без потерь.
  LId := TMHProcessId.Create(7, 9007199254740993);
  LJson := TMHJson.ProcessIdToJson(LId);
  try
    Assert.IsTrue(LJson.GetValue('createTime') is TJSONString);
    Assert.AreEqual('9007199254740993', LJson.GetValue('createTime').Value);
    Assert.IsTrue(TMHJson.ProcessIdFromJson(LJson) = LId);
  finally
    LJson.Free;
  end;
end;

procedure TSerializationTests.ZeroTimestamp_IsNull;
var
  LJson: TJSONObject;
begin
  LJson := TMHJson.SnapshotToJson(Default(TMHSnapshot));
  try
    Assert.IsTrue(LJson.GetValue('timestamp') is TJSONNull);
  finally
    LJson.Free;
  end;
end;

procedure TSerializationTests.UnicodePaths_Survive;
var
  LSnapshot, LBack: TMHSnapshot;
begin
  LSnapshot := SampleSnapshot;
  LSnapshot.Processes[0].ImagePath := 'C:\Пользователи\Иван\"кавычки"\файл.exe';
  LBack := TMHJson.SnapshotFromString(TMHJson.SnapshotToString(LSnapshot, True));
  Assert.AreEqual(LSnapshot.Processes[0].ImagePath, LBack.Processes[0].ImagePath);
end;

procedure TSerializationTests.UnknownFields_AreIgnored;
var
  LJson: TJSONObject;
  LBack: TMHSnapshot;
begin
  LJson := TMHJson.SnapshotToJson(SampleSnapshot);
  try
    LJson.AddPair('futureField', 'x');
    LBack := TMHJson.SnapshotFromJson(LJson);
    Assert.AreEqual<UInt64>(42, LBack.Sequence);
  finally
    LJson.Free;
  end;
end;

procedure TSerializationTests.InvalidJson_Raises;
begin
  Assert.WillRaise(
    procedure
    begin
      TMHJson.SnapshotFromString('{ not json');
    end, EMHSerializationError);
  Assert.WillRaise(
    procedure
    begin
      TMHJson.SnapshotFromString('[]');
    end, EMHSerializationError);
end;

procedure ExpectBroken(const AText: string);
begin
  Assert.WillRaise(
    procedure
    begin
      TMHJson.SnapshotFromString(AText);
    end, EMHSerializationError, AText);
end;

function Mutate(const ASearch, AReplace: string): string;
begin
  Result := TMHJson.SnapshotToString(SampleSnapshot);
  Assert.IsTrue(Result.Contains(ASearch), 'Шаблон не найден: ' + ASearch);
  Result := StringReplace(Result, ASearch, AReplace, []);
end;

procedure TSerializationTests.WrongSchema_Raises;
begin
  ExpectBroken(Mutate('"schema":2', '"schema":999'));
end;

procedure TSerializationTests.MissingField_Raises;
begin
  ExpectBroken(Mutate('"name":"app.exe",', ''));
end;

procedure TSerializationTests.WrongType_Raises;
begin
  ExpectBroken(Mutate('"threadCount":17', '"threadCount":"17"'));
end;

procedure TSerializationTests.OutOfRangePid_Raises;
begin
  ExpectBroken(Mutate('"pid":1234', '"pid":99999999999'));
end;

procedure TSerializationTests.UnknownEnumValue_Raises;
begin
  ExpectBroken(Mutate('"access":"limited"', '"access":"root"'));
end;

procedure TSerializationTests.NegativeCreateTime_Raises;
begin
  ExpectBroken(Mutate('"createTime":"134050000000000001"', '"createTime":"-5"'));
end;

initialization
  TDUnitX.RegisterTestFixture(TSerializationTests);

end.
