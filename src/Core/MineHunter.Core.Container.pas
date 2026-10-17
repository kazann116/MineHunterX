unit MineHunter.Core.Container;

{
  Минимальный потокобезопасный DI-контейнер для интерфейсов с GUID.

  - Singleton: фабрика вызывается один раз при первом разрешении.
  - Transient: фабрика вызывается при каждом разрешении.
  - Instance: заранее созданный экземпляр.
  Для одного интерфейса допустимо несколько регистраций (например, коллекторы):
  Resolve<T> возвращает последнюю, ResolveAll<T> — все в порядке регистрации.
  Циклические зависимости обнаруживаются и приводят к EMHContainerError.
}

interface

uses
  System.SysUtils, System.SyncObjs, System.Generics.Collections,
  MineHunter.Core.Types;

type
  EMHContainerError = class(EMHError);

  TMHLifetime = (ltSingleton, ltTransient);

  TMHContainer = class
  private type
    TRegistration = class
      Lifetime: TMHLifetime;
      Factory: TFunc<IInterface>;
      Instance: IInterface;
      Resolving: Boolean;
    end;
  private
    FLock: TCriticalSection;
    FRegistrations: TObjectDictionary<TGUID, TObjectList<TRegistration>>;
    class function GuidOf<T: IInterface>: TGUID; static;
    class function NameOf<T: IInterface>: string; static;
    procedure AddRegistration(const AGuid: TGUID; ALifetime: TMHLifetime;
      const AFactory: TFunc<IInterface>; const AInstance: IInterface);
    function Materialize(ARegistration: TRegistration; const AName: string): IInterface;
  public
    constructor Create;
    destructor Destroy; override;

    procedure RegisterSingleton<T: IInterface>(const AFactory: TFunc<T>);
    procedure RegisterTransient<T: IInterface>(const AFactory: TFunc<T>);
    procedure RegisterInstance<T: IInterface>(const AInstance: T);

    function IsRegistered<T: IInterface>: Boolean;
    /// Последняя регистрация. Исключение EMHContainerError, если её нет.
    function Resolve<T: IInterface>: T;
    function TryResolve<T: IInterface>(out AService: T): Boolean;
    /// Все регистрации в порядке добавления (пустой массив, если их нет).
    function ResolveAll<T: IInterface>: TArray<T>;

    /// Освобождает все регистрации и singleton-экземпляры.
    procedure Clear;
  end;

implementation

uses
  System.TypInfo;

{ TMHContainer }

constructor TMHContainer.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FRegistrations := TObjectDictionary<TGUID, TObjectList<TRegistration>>.Create([doOwnsValues]);
end;

destructor TMHContainer.Destroy;
begin
  Clear;
  FRegistrations.Free;
  FLock.Free;
  inherited;
end;

procedure TMHContainer.Clear;
var
  LOld: TObjectDictionary<TGUID, TObjectList<TRegistration>>;
begin
  // Экземпляры освобождаются вне блокировки: их деструкторы могут
  // обращаться к контейнеру.
  FLock.Enter;
  try
    LOld := FRegistrations;
    FRegistrations := TObjectDictionary<TGUID, TObjectList<TRegistration>>.Create([doOwnsValues]);
  finally
    FLock.Leave;
  end;
  LOld.Free;
end;

class function TMHContainer.GuidOf<T>: TGUID;
var
  LInfo: PTypeInfo;
begin
  LInfo := TypeInfo(T);
  if (LInfo = nil) or (LInfo^.Kind <> tkInterface) then
    raise EMHContainerError.Create('Тип не является интерфейсом');
  Result := GetTypeData(LInfo)^.GUID;
  if Result = TGUID.Empty then
    raise EMHContainerError.CreateFmt('Интерфейс %s не имеет GUID', [NameOf<T>]);
end;

class function TMHContainer.NameOf<T>: string;
var
  LInfo: PTypeInfo;
begin
  LInfo := TypeInfo(T);
  if LInfo = nil then
    Result := '?'
  else
    Result := string(LInfo^.Name);
end;

procedure TMHContainer.AddRegistration(const AGuid: TGUID; ALifetime: TMHLifetime;
  const AFactory: TFunc<IInterface>; const AInstance: IInterface);
var
  LList: TObjectList<TRegistration>;
  LReg: TRegistration;
begin
  LReg := TRegistration.Create;
  LReg.Lifetime := ALifetime;
  LReg.Factory := AFactory;
  LReg.Instance := AInstance;
  FLock.Enter;
  try
    if not FRegistrations.TryGetValue(AGuid, LList) then
    begin
      LList := TObjectList<TRegistration>.Create(True);
      FRegistrations.Add(AGuid, LList);
    end;
    LList.Add(LReg);
  finally
    FLock.Leave;
  end;
end;

procedure TMHContainer.RegisterSingleton<T>(const AFactory: TFunc<T>);
var
  LFactory: TFunc<T>;
begin
  if not Assigned(AFactory) then
    raise EArgumentNilException.Create('AFactory');
  LFactory := AFactory;
  AddRegistration(GuidOf<T>, ltSingleton,
    function: IInterface
    begin
      Result := LFactory();
    end, nil);
end;

procedure TMHContainer.RegisterTransient<T>(const AFactory: TFunc<T>);
var
  LFactory: TFunc<T>;
begin
  if not Assigned(AFactory) then
    raise EArgumentNilException.Create('AFactory');
  LFactory := AFactory;
  AddRegistration(GuidOf<T>, ltTransient,
    function: IInterface
    begin
      Result := LFactory();
    end, nil);
end;

procedure TMHContainer.RegisterInstance<T>(const AInstance: T);
begin
  if IInterface(AInstance) = nil then
    raise EArgumentNilException.Create('AInstance');
  AddRegistration(GuidOf<T>, ltSingleton, nil, AInstance);
end;

function TMHContainer.Materialize(ARegistration: TRegistration;
  const AName: string): IInterface;
begin
  // Вызывается под FLock (критическая секция реентерабельна в одном потоке,
  // поэтому фабрика может разрешать свои зависимости).
  if (ARegistration.Lifetime = ltSingleton) and (ARegistration.Instance <> nil) then
    Exit(ARegistration.Instance);
  if ARegistration.Resolving then
    raise EMHContainerError.CreateFmt('Циклическая зависимость при разрешении %s', [AName]);
  ARegistration.Resolving := True;
  try
    Result := ARegistration.Factory();
  finally
    ARegistration.Resolving := False;
  end;
  if Result = nil then
    raise EMHContainerError.CreateFmt('Фабрика %s вернула nil', [AName]);
  if ARegistration.Lifetime = ltSingleton then
    ARegistration.Instance := Result;
end;

function TMHContainer.IsRegistered<T>: Boolean;
var
  LList: TObjectList<TRegistration>;
begin
  FLock.Enter;
  try
    Result := FRegistrations.TryGetValue(GuidOf<T>, LList) and (LList.Count > 0);
  finally
    FLock.Leave;
  end;
end;

function TMHContainer.TryResolve<T>(out AService: T): Boolean;
var
  LGuid: TGUID;
  LList: TObjectList<TRegistration>;
  LIntf: IInterface;
begin
  LGuid := GuidOf<T>;
  AService := Default(T);
  FLock.Enter;
  try
    if not FRegistrations.TryGetValue(LGuid, LList) or (LList.Count = 0) then
      Exit(False);
    LIntf := Materialize(LList.Last, NameOf<T>);
  finally
    FLock.Leave;
  end;
  if not Supports(LIntf, LGuid, AService) then
    raise EMHContainerError.CreateFmt('Объект не реализует %s', [NameOf<T>]);
  Result := True;
end;

function TMHContainer.Resolve<T>: T;
begin
  if not TryResolve<T>(Result) then
    raise EMHContainerError.CreateFmt('Сервис %s не зарегистрирован', [NameOf<T>]);
end;

function TMHContainer.ResolveAll<T>: TArray<T>;
var
  LGuid: TGUID;
  LList: TObjectList<TRegistration>;
  LIntfs: TArray<IInterface>;
  I: Integer;
begin
  LGuid := GuidOf<T>;
  FLock.Enter;
  try
    if not FRegistrations.TryGetValue(LGuid, LList) then
      Exit(nil);
    SetLength(LIntfs, LList.Count);
    for I := 0 to LList.Count - 1 do
      LIntfs[I] := Materialize(LList[I], NameOf<T>);
  finally
    FLock.Leave;
  end;
  SetLength(Result, Length(LIntfs));
  for I := 0 to High(LIntfs) do
    if not Supports(LIntfs[I], LGuid, Result[I]) then
      raise EMHContainerError.CreateFmt('Объект не реализует %s', [NameOf<T>]);
end;

end.
