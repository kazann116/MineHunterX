unit MineHunter.App.ProcessView;

{
  Модель представления таблицы процессов: фильтрация, сортировка и поиск
  родителя. Не зависит от VCL и тестируется отдельно.

  Метрики без данных всегда сортируются в конец независимо от направления,
  чтобы «нет данных» не выглядело как «минимальная нагрузка».
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types;

type
  /// Порядок совпадает с колонками таблицы на форме; новые — в конец.
  /// «Память» — частный рабочий набор, как колонка «Память» диспетчера задач
  /// (если недоступен — рабочий набор); «GPU» — самый загруженный движок видеокарты.
  TMHProcessColumn = (pcName, pcPid, pcCpu, pcMemory, pcGpu, pcWorkingSet, pcPrivate, pcThreads,
    pcAccess, pcPath, pcRisk, pcSignature);

  /// Уровень риска процесса по активным находкам.
  TMHRiskLookup = reference to function(const AId: TMHProcessId): TMHRiskLevel;

  TMHProcessListModel = class
  private
    FAll: TArray<TMHProcessInfo>;
    FVisible: TList<Integer>;
    FFilter: string;
    FSortColumn: TMHProcessColumn;
    FAscending: Boolean;
    FSourceId: string;
    FRiskLookup: TMHRiskLookup;
    FOnlyWithFindings: Boolean;
    FOnlyUnsigned: Boolean;
    procedure SetOnlyWithFindings(AValue: Boolean);
    procedure SetOnlyUnsigned(AValue: Boolean);
    function Compare(const A, B: TMHProcessInfo): Integer;
    function GetCount: Integer;
    function GetTotalCount: Integer;
    function GetItem(AIndex: Integer): TMHProcessInfo;
    procedure SetFilter(const AValue: string);
  public
    procedure Rebuild;
    function RiskOf(const AInfo: TMHProcessInfo): TMHRiskLevel;
    /// ASourceId — источник, процессы которого показываются в таблице.
    constructor Create(const ASourceId: string);
    destructor Destroy; override;
    procedure SetSnapshot(const ASnapshot: TMHSnapshot);
    /// Повторный выбор той же колонки меняет направление сортировки.
    procedure SortBy(AColumn: TMHProcessColumn);
    function IndexOf(const AId: TMHProcessId): Integer;
    /// Ищет родителя по PID среди всех процессов источника.
    /// Родитель должен быть создан раньше потомка — иначе PID уже
    /// переиспользован другим процессом.
    function TryFindParent(const AChild: TMHProcessInfo; out AParent: TMHProcessInfo): Boolean;
    property Count: Integer read GetCount;
    property Items[AIndex: Integer]: TMHProcessInfo read GetItem; default;
    property TotalCount: Integer read GetTotalCount;
    property Filter: string read FFilter write SetFilter;
    property SortColumn: TMHProcessColumn read FSortColumn;
    property Ascending: Boolean read FAscending;
    /// Источник уровней риска (nil — риск не показывается).
    property RiskLookup: TMHRiskLookup read FRiskLookup write FRiskLookup;
    property OnlyWithFindings: Boolean read FOnlyWithFindings write SetOnlyWithFindings;
    property OnlyUnsigned: Boolean read FOnlyUnsigned write SetOnlyUnsigned;
  end;

function MHAccessLevelToString(AAccess: TMHAccessLevel): string;
/// Память процесса как в диспетчере задач: частный рабочий набор, иначе рабочий набор.
function MHProcessMemory(const AInfo: TMHProcessInfo): TMHMetric;

implementation

uses
  System.Generics.Defaults, System.Math;

function MHProcessMemory(const AInfo: TMHProcessInfo): TMHMetric;
begin
  if AInfo.PrivateWorkingSet.HasValue then
    Result := AInfo.PrivateWorkingSet
  else
    Result := AInfo.WorkingSet;
end;

function MHAccessLevelToString(AAccess: TMHAccessLevel): string;
begin
  case AAccess of
    alFull:    Result := 'полный';
    alLimited: Result := 'частичный';
    alDenied:  Result := 'нет доступа';
  else
    Result := 'неизвестно';
  end;
end;

function CompareMetric(const A, B: TMHMetric; AAscending: Boolean): Integer;
begin
  if A.HasValue <> B.HasValue then
  begin
    // «Нет данных» всегда в конце.
    if A.HasValue then
      Exit(-1)
    else
      Exit(1);
  end;
  if not A.HasValue then
    Exit(0);
  Result := CompareValue(A.Value, B.Value);
  if not AAscending then
    Result := -Result;
end;

{ TMHProcessListModel }

constructor TMHProcessListModel.Create(const ASourceId: string);
begin
  inherited Create;
  FSourceId := ASourceId;
  FVisible := TList<Integer>.Create;
  FSortColumn := pcCpu;
  FAscending := False;
end;

destructor TMHProcessListModel.Destroy;
begin
  FVisible.Free;
  inherited;
end;

function TMHProcessListModel.GetCount: Integer;
begin
  Result := FVisible.Count;
end;

function TMHProcessListModel.GetTotalCount: Integer;
begin
  Result := Length(FAll);
end;

function TMHProcessListModel.GetItem(AIndex: Integer): TMHProcessInfo;
begin
  Result := FAll[FVisible[AIndex]];
end;

procedure TMHProcessListModel.SetFilter(const AValue: string);
begin
  if FFilter = Trim(AValue) then
    Exit;
  FFilter := Trim(AValue);
  Rebuild;
end;

procedure TMHProcessListModel.SetSnapshot(const ASnapshot: TMHSnapshot);
var
  LList: TList<TMHProcessInfo>;
  LInfo: TMHProcessInfo;
begin
  LList := TList<TMHProcessInfo>.Create;
  try
    for LInfo in ASnapshot.Processes do
      if SameText(LInfo.SourceId, FSourceId) then
        LList.Add(LInfo);
    FAll := LList.ToArray;
  finally
    LList.Free;
  end;
  Rebuild;
end;

procedure TMHProcessListModel.SetOnlyWithFindings(AValue: Boolean);
begin
  if FOnlyWithFindings = AValue then
    Exit;
  FOnlyWithFindings := AValue;
  Rebuild;
end;

procedure TMHProcessListModel.SetOnlyUnsigned(AValue: Boolean);
begin
  if FOnlyUnsigned = AValue then
    Exit;
  FOnlyUnsigned := AValue;
  Rebuild;
end;

function TMHProcessListModel.RiskOf(const AInfo: TMHProcessInfo): TMHRiskLevel;
begin
  if Assigned(FRiskLookup) then
    Result := FRiskLookup(AInfo.Id)
  else
    Result := rlNone;
end;

procedure TMHProcessListModel.SortBy(AColumn: TMHProcessColumn);
begin
  if AColumn = FSortColumn then
    FAscending := not FAscending
  else
  begin
    FSortColumn := AColumn;
    // Для нагрузки естественный порядок — по убыванию, для текста — по возрастанию.
    FAscending := not (AColumn in [pcCpu, pcMemory, pcGpu, pcWorkingSet, pcPrivate, pcThreads, pcRisk]);
  end;
  Rebuild;
end;

function TMHProcessListModel.Compare(const A, B: TMHProcessInfo): Integer;
begin
  case FSortColumn of
    pcCpu:        Exit(CompareMetric(A.Cpu, B.Cpu, FAscending));
    pcMemory:     Exit(CompareMetric(MHProcessMemory(A), MHProcessMemory(B), FAscending));
    pcGpu:        Exit(CompareMetric(A.Gpu, B.Gpu, FAscending));
    pcWorkingSet: Exit(CompareMetric(A.WorkingSet, B.WorkingSet, FAscending));
    pcPrivate:    Exit(CompareMetric(A.PrivateBytes, B.PrivateBytes, FAscending));
    pcName:       Result := CompareText(A.Name, B.Name);
    pcPid:        Result := CompareValue(Int64(A.Id.Pid), Int64(B.Id.Pid));
    pcThreads:    Result := CompareValue(A.ThreadCount, B.ThreadCount);
    pcAccess:     Result := CompareValue(Ord(A.Access), Ord(B.Access));
    pcPath:       Result := CompareText(A.ImagePath, B.ImagePath);
    pcRisk:       Result := CompareValue(Ord(RiskOf(A)), Ord(RiskOf(B)));
    pcSignature:  Result := CompareValue(Ord(A.Signature), Ord(B.Signature));
  else
    Result := 0;
  end;
  if not FAscending then
    Result := -Result;
end;

procedure TMHProcessListModel.Rebuild;
var
  I: Integer;
  LFilter: string;
begin
  FVisible.Clear;
  LFilter := FFilter.ToLower;
  for I := 0 to High(FAll) do
  begin
    if (LFilter <> '') and not (FAll[I].Name.ToLower.Contains(LFilter) or
       FAll[I].ImagePath.ToLower.Contains(LFilter) or (UIntToStr(FAll[I].Id.Pid) = LFilter)) then
      Continue;
    if FOnlyWithFindings and (RiskOf(FAll[I]) = rlNone) then
      Continue;
    // «Без подписи» — неподписанные и с недействительной подписью.
    if FOnlyUnsigned and not (FAll[I].Signature in [sgUnsigned, sgSignedUntrusted]) then
      Continue;
    FVisible.Add(I);
  end;
  FVisible.Sort(TComparer<Integer>.Construct(
    function(const L, R: Integer): Integer
    begin
      Result := Compare(FAll[L], FAll[R]);
      // Стабильный порядок при равенстве — по PID.
      if Result = 0 then
        Result := CompareValue(Int64(FAll[L].Id.Pid), Int64(FAll[R].Id.Pid));
    end));
end;

function TMHProcessListModel.IndexOf(const AId: TMHProcessId): Integer;
var
  I: Integer;
begin
  for I := 0 to FVisible.Count - 1 do
    if FAll[FVisible[I]].Id = AId then
      Exit(I);
  Result := -1;
end;

function TMHProcessListModel.TryFindParent(const AChild: TMHProcessInfo;
  out AParent: TMHProcessInfo): Boolean;
var
  I: Integer;
begin
  AParent := Default(TMHProcessInfo);
  if AChild.ParentPid = AChild.Id.Pid then
    Exit(False);
  for I := 0 to High(FAll) do
    if FAll[I].Id.Pid = AChild.ParentPid then
    begin
      if FAll[I].Id.HasCreateTime and AChild.Id.HasCreateTime and
         (FAll[I].Id.CreateTime > AChild.Id.CreateTime) then
        Exit(False);
      AParent := FAll[I];
      Exit(True);
    end;
  Result := False;
end;

end.
