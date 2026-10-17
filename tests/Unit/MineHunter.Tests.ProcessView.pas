unit MineHunter.Tests.ProcessView;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.App.ProcessView;

type
  [TestFixture]
  [Category('Unit')]
  TProcessViewTests = class
  private
    FModel: TMHProcessListModel;
    function Names: string;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure OnlyConfiguredSourceIsShown;
    [Test] procedure DefaultSort_CpuDescending_NoDataLast;
    [Test] procedure CpuAscending_NoDataStillLast;
    [Test] procedure SortByName_ThenToggle;
    [Test] procedure Filter_ByNamePathOrExactPid;
    [Test] procedure Filter_NoMatches_IsEmpty;
    [Test] procedure IndexOf_UsesFullIdentity;
    [Test] procedure Parent_Found;
    [Test] procedure Parent_CreatedAfterChild_IsReusedPid;
    [Test] procedure Parent_Missing;
    [Test] procedure EmptySnapshot_IsEmptyModel;
    [Test] procedure AccessNames_AreDistinct;
    [Test] procedure RiskAndSignature_SortAndFilter;
  end;

implementation

uses
  System.SysUtils;

const
  SRC = 'processes';

function Proc(APid: Cardinal; ACreate: UInt64; const AName: string; ACpu: Double;
  AHasCpu: Boolean = True; APpid: Cardinal = 0; const ASource: string = SRC): TMHProcessInfo;
begin
  Result := TMHProcessInfo.Create(TMHProcessId.Create(APid, ACreate), AName, 1);
  if AHasCpu then
    Result.Cpu := TMHMetric.Available(mkCpuPercent, ACpu, 1);
  Result.ImagePath := 'C:\Apps\' + AName;
  Result.ParentPid := APpid;
  Result.SourceId := ASource;
end;

function Snap(const AItems: array of TMHProcessInfo): TMHSnapshot;
var
  I: Integer;
begin
  Result := TMHSnapshot.Create(1, 1);
  SetLength(Result.Processes, Length(AItems));
  for I := 0 to High(AItems) do
    Result.Processes[I] := AItems[I];
end;

procedure TProcessViewTests.Setup;
begin
  FModel := TMHProcessListModel.Create(SRC);
end;

procedure TProcessViewTests.TearDown;
begin
  FreeAndNil(FModel);
end;

function TProcessViewTests.Names: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to FModel.Count - 1 do
  begin
    if I > 0 then
      Result := Result + ',';
    Result := Result + FModel[I].Name;
  end;
end;

procedure TProcessViewTests.OnlyConfiguredSourceIsShown;
begin
  FModel.SetSnapshot(Snap([Proc(1, 1, 'a', 1), Proc(2, 2, 'self', 1, True, 0, 'self')]));
  Assert.AreEqual(1, FModel.TotalCount);
  Assert.AreEqual('a', Names);
end;

procedure TProcessViewTests.DefaultSort_CpuDescending_NoDataLast;
begin
  FModel.SetSnapshot(Snap([Proc(1, 1, 'low', 1), Proc(2, 2, 'nodata', 0, False),
    Proc(3, 3, 'high', 90), Proc(4, 4, 'mid', 30)]));
  Assert.AreEqual<TMHProcessColumn>(pcCpu, FModel.SortColumn);
  Assert.IsFalse(FModel.Ascending);
  Assert.AreEqual('high,mid,low,nodata', Names);
end;

procedure TProcessViewTests.CpuAscending_NoDataStillLast;
begin
  FModel.SetSnapshot(Snap([Proc(1, 1, 'low', 1), Proc(2, 2, 'nodata', 0, False),
    Proc(3, 3, 'high', 90)]));
  FModel.SortBy(pcCpu); // переключение направления
  Assert.IsTrue(FModel.Ascending);
  Assert.AreEqual('low,high,nodata', Names);
end;

procedure TProcessViewTests.SortByName_ThenToggle;
begin
  FModel.SetSnapshot(Snap([Proc(1, 1, 'Bravo', 1), Proc(2, 2, 'alpha', 2), Proc(3, 3, 'charlie', 3)]));
  FModel.SortBy(pcName);
  Assert.IsTrue(FModel.Ascending);
  Assert.AreEqual('alpha,Bravo,charlie', Names);
  FModel.SortBy(pcName);
  Assert.AreEqual('charlie,Bravo,alpha', Names);
end;

procedure TProcessViewTests.Filter_ByNamePathOrExactPid;
begin
  FModel.SetSnapshot(Snap([Proc(10, 1, 'chrome.exe', 1), Proc(20, 2, 'Code.exe', 2),
    Proc(102, 3, 'other.exe', 3)]));
  FModel.Filter := 'CHROME';
  Assert.AreEqual('chrome.exe', Names);
  FModel.Filter := 'c:\apps\code';
  Assert.AreEqual('Code.exe', Names);
  FModel.Filter := '10';
  Assert.AreEqual('chrome.exe', Names, 'PID сравнивается точно, а не как подстрока');
  FModel.Filter := '';
  Assert.AreEqual(3, FModel.Count);
end;

procedure TProcessViewTests.Filter_NoMatches_IsEmpty;
begin
  FModel.SetSnapshot(Snap([Proc(1, 1, 'a.exe', 1)]));
  FModel.Filter := 'zzz';
  Assert.AreEqual(0, FModel.Count);
  Assert.AreEqual(1, FModel.TotalCount);
end;

procedure TProcessViewTests.IndexOf_UsesFullIdentity;
begin
  FModel.SetSnapshot(Snap([Proc(100, 5, 'new.exe', 1)]));
  Assert.AreEqual(0, FModel.IndexOf(TMHProcessId.Create(100, 5)));
  Assert.AreEqual(-1, FModel.IndexOf(TMHProcessId.Create(100, 4)),
    'Старый экземпляр с тем же PID не должен совпадать');
end;

procedure TProcessViewTests.Parent_Found;
var
  LParent: TMHProcessInfo;
begin
  FModel.SetSnapshot(Snap([Proc(4, 10, 'explorer.exe', 0), Proc(50, 20, 'child.exe', 0, True, 4)]));
  Assert.IsTrue(FModel.TryFindParent(FModel[FModel.IndexOf(TMHProcessId.Create(50, 20))], LParent));
  Assert.AreEqual('explorer.exe', LParent.Name);
end;

procedure TProcessViewTests.Parent_CreatedAfterChild_IsReusedPid;
var
  LParent: TMHProcessInfo;
begin
  // Настоящий родитель завершился, его PID получил процесс, запущенный позже потомка.
  FModel.SetSnapshot(Snap([Proc(4, 30, 'impostor.exe', 0), Proc(50, 20, 'child.exe', 0, True, 4)]));
  Assert.IsFalse(FModel.TryFindParent(FModel[FModel.IndexOf(TMHProcessId.Create(50, 20))], LParent));
end;

procedure TProcessViewTests.Parent_Missing;
var
  LParent: TMHProcessInfo;
begin
  FModel.SetSnapshot(Snap([Proc(50, 20, 'orphan.exe', 0, True, 999), Proc(0, 0, 'idle', 0, True, 0)]));
  Assert.IsFalse(FModel.TryFindParent(FModel[FModel.IndexOf(TMHProcessId.Create(50, 20))], LParent));
  Assert.IsFalse(FModel.TryFindParent(FModel[FModel.IndexOf(TMHProcessId.Create(0, 0))], LParent),
    'Процесс не может быть собственным родителем');
end;

procedure TProcessViewTests.EmptySnapshot_IsEmptyModel;
begin
  FModel.SetSnapshot(Default(TMHSnapshot));
  Assert.AreEqual(0, FModel.Count);
  Assert.AreEqual(-1, FModel.IndexOf(TMHProcessId.Create(1, 1)));
end;

procedure TProcessViewTests.AccessNames_AreDistinct;
begin
  Assert.AreNotEqual(MHAccessLevelToString(alFull), MHAccessLevelToString(alLimited));
  Assert.AreNotEqual(MHAccessLevelToString(alLimited), MHAccessLevelToString(alDenied));
end;

procedure TProcessViewTests.RiskAndSignature_SortAndFilter;
var
  LSigned, LUnsigned, LBad: TMHProcessInfo;
begin
  LSigned := Proc(1, 1, 'signed.exe', 50);
  LSigned.Signature := sgSignedTrusted;
  LUnsigned := Proc(2, 2, 'unsigned.exe', 10);
  LUnsigned.Signature := sgUnsigned;
  LBad := Proc(3, 3, 'bad.exe', 5);
  LBad.Signature := sgSignedUntrusted;
  FModel.RiskLookup :=
    function(const AId: TMHProcessId): TMHRiskLevel
    begin
      if AId.Pid = 3 then
        Result := rlSuspicious
      else if AId.Pid = 2 then
        Result := rlLow
      else
        Result := rlNone;
    end;
  FModel.SetSnapshot(Snap([LSigned, LUnsigned, LBad]));
  FModel.SortBy(pcRisk);
  Assert.IsFalse(FModel.Ascending, 'Риск по умолчанию — по убыванию');
  Assert.AreEqual('bad.exe,unsigned.exe,signed.exe', Names);
  FModel.OnlyWithFindings := True;
  Assert.AreEqual('bad.exe,unsigned.exe', Names);
  FModel.OnlyWithFindings := False;
  FModel.OnlyUnsigned := True;
  Assert.AreEqual('bad.exe,unsigned.exe', Names, 'Без подписи и с недействительной подписью');
  FModel.OnlyUnsigned := False;
  Assert.AreEqual<TMHRiskLevel>(rlSuspicious, FModel.RiskOf(LBad));
end;

initialization
  TDUnitX.RegisterTestFixture(TProcessViewTests);

end.
