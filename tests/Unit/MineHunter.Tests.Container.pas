unit MineHunter.Tests.Container;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Container;

type
  ITestService = interface
    ['{A1B2C3D4-0000-4000-8000-000000000001}']
    function Value: Integer;
  end;

  ITestDependent = interface
    ['{A1B2C3D4-0000-4000-8000-000000000002}']
    function Inner: ITestService;
  end;

  ICycleA = interface
    ['{A1B2C3D4-0000-4000-8000-000000000003}']
  end;

  ICycleB = interface
    ['{A1B2C3D4-0000-4000-8000-000000000004}']
  end;

  INoGuid = interface
  end;

  [TestFixture]
  [Category('Unit')]
  TContainerTests = class
  private
    FContainer: TMHContainer;
    FService: ITestService;
    FCycleA: ICycleA;
    // Действия для Assert.WillRaise (перегрузка TTestMethod).
    procedure DoResolveService;
    procedure DoResolveCycleA;
    procedure DoIsRegisteredNoGuid;
    procedure DoRegisterNilFactory;
    procedure DoRegisterNilInstance;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Singleton_ReturnsSameInstance;
    [Test] procedure Singleton_FactoryCalledOnce;
    [Test] procedure Transient_ReturnsNewInstances;
    [Test] procedure Instance_IsReturned;
    [Test] procedure Resolve_Unregistered_Raises;
    [Test] procedure TryResolve_Unregistered_ReturnsFalse;
    [Test] procedure IsRegistered_ReflectsRegistrations;
    [Test] procedure Resolve_ReturnsLastRegistration;
    [Test] procedure ResolveAll_ReturnsAllInOrder;
    [Test] procedure ResolveAll_Unregistered_ReturnsEmpty;
    [Test] procedure Factory_CanResolveDependencies;
    [Test] procedure CyclicDependency_Raises;
    [Test] procedure FactoryReturningNil_Raises;
    [Test] procedure InterfaceWithoutGuid_Raises;
    [Test] procedure NilArguments_Raise;
    [Test] procedure Clear_ReleasesSingletons;
    [Test] procedure FailedSingletonFactory_CanBeRetried;
  end;

implementation

uses
  System.SysUtils,
  MineHunter.Tests.Fakes;

type
  TTestService = class(TInterfacedObject, ITestService)
  private
    FValue: Integer;
  public
    class var Alive: Integer;
    constructor Create(AValue: Integer);
    destructor Destroy; override;
    function Value: Integer;
  end;

  TTestDependent = class(TInterfacedObject, ITestDependent)
  private
    FInner: ITestService;
  public
    constructor Create(const AInner: ITestService);
    function Inner: ITestService;
  end;

  TCycle = class(TInterfacedObject, ICycleA, ICycleB);

constructor TTestService.Create(AValue: Integer);
begin
  inherited Create;
  FValue := AValue;
  Inc(Alive);
end;

destructor TTestService.Destroy;
begin
  Dec(Alive);
  inherited;
end;

function TTestService.Value: Integer;
begin
  Result := FValue;
end;

constructor TTestDependent.Create(const AInner: ITestService);
begin
  inherited Create;
  FInner := AInner;
end;

function TTestDependent.Inner: ITestService;
begin
  Result := FInner;
end;

{ TContainerTests }

procedure TContainerTests.DoResolveService;
begin
  FService := FContainer.Resolve<ITestService>();
end;

procedure TContainerTests.DoResolveCycleA;
begin
  FCycleA := FContainer.Resolve<ICycleA>();
end;

procedure TContainerTests.DoIsRegisteredNoGuid;
begin
  FContainer.IsRegistered<INoGuid>();
end;

procedure TContainerTests.DoRegisterNilFactory;
begin
  FContainer.RegisterSingleton<ITestService>(nil);
end;

procedure TContainerTests.DoRegisterNilInstance;
begin
  FContainer.RegisterInstance<ITestService>(nil);
end;

procedure TContainerTests.Setup;
begin
  FContainer := TMHContainer.Create;
  TTestService.Alive := 0;
end;

procedure TContainerTests.TearDown;
begin
  FService := nil;
  FCycleA := nil;
  FreeAndNil(FContainer);
end;

procedure TContainerTests.Singleton_ReturnsSameInstance;
begin
  FContainer.RegisterSingleton<ITestService>(
    function: ITestService
    begin
      Result := TTestService.Create(1);
    end);
  Assert.IsTrue(FContainer.Resolve<ITestService>() = FContainer.Resolve<ITestService>());
end;

procedure TContainerTests.Singleton_FactoryCalledOnce;
var
  LCalls: Integer;
begin
  LCalls := 0;
  FContainer.RegisterSingleton<ITestService>(
    function: ITestService
    begin
      Inc(LCalls);
      Result := TTestService.Create(1);
    end);
  FContainer.Resolve<ITestService>();
  FContainer.Resolve<ITestService>();
  FContainer.ResolveAll<ITestService>();
  Assert.AreEqual(1, LCalls);
end;

procedure TContainerTests.Transient_ReturnsNewInstances;
begin
  FContainer.RegisterTransient<ITestService>(
    function: ITestService
    begin
      Result := TTestService.Create(1);
    end);
  Assert.IsFalse(FContainer.Resolve<ITestService>() = FContainer.Resolve<ITestService>());
end;

procedure TContainerTests.Instance_IsReturned;
var
  LService: ITestService;
begin
  LService := TTestService.Create(77);
  FContainer.RegisterInstance<ITestService>(LService);
  Assert.IsTrue(LService = FContainer.Resolve<ITestService>());
end;

procedure TContainerTests.Resolve_Unregistered_Raises;
begin
  Assert.WillRaise(DoResolveService, EMHContainerError);
end;

procedure TContainerTests.TryResolve_Unregistered_ReturnsFalse;
var
  LService: ITestService;
begin
  Assert.IsFalse(FContainer.TryResolve<ITestService>(LService));
  Assert.IsNull(LService);
end;

procedure TContainerTests.IsRegistered_ReflectsRegistrations;
begin
  Assert.IsFalse(FContainer.IsRegistered<ITestService>());
  FContainer.RegisterInstance<ITestService>(TTestService.Create(1));
  Assert.IsTrue(FContainer.IsRegistered<ITestService>());
end;

procedure TContainerTests.Resolve_ReturnsLastRegistration;
begin
  FContainer.RegisterInstance<ITestService>(TTestService.Create(1));
  FContainer.RegisterInstance<ITestService>(TTestService.Create(2));
  Assert.AreEqual(2, FContainer.Resolve<ITestService>().Value);
end;

procedure TContainerTests.ResolveAll_ReturnsAllInOrder;
var
  LAll: TArray<ITestService>;
begin
  FContainer.RegisterInstance<ITestService>(TTestService.Create(1));
  FContainer.RegisterTransient<ITestService>(
    function: ITestService
    begin
      Result := TTestService.Create(2);
    end);
  FContainer.RegisterInstance<ITestService>(TTestService.Create(3));
  LAll := FContainer.ResolveAll<ITestService>();
  Assert.AreEqual(3, Integer(Length(LAll)));
  Assert.AreEqual(1, LAll[0].Value);
  Assert.AreEqual(2, LAll[1].Value);
  Assert.AreEqual(3, LAll[2].Value);
end;

procedure TContainerTests.ResolveAll_Unregistered_ReturnsEmpty;
begin
  Assert.AreEqual(0, Integer(Length(FContainer.ResolveAll<ITestService>())));
end;

procedure TContainerTests.Factory_CanResolveDependencies;
var
  LContainer: TMHContainer;
begin
  LContainer := FContainer;
  FContainer.RegisterSingleton<ITestService>(
    function: ITestService
    begin
      Result := TTestService.Create(5);
    end);
  FContainer.RegisterSingleton<ITestDependent>(
    function: ITestDependent
    begin
      Result := TTestDependent.Create(LContainer.Resolve<ITestService>());
    end);
  Assert.AreEqual(5, FContainer.Resolve<ITestDependent>().Inner.Value);
  Assert.IsTrue(FContainer.Resolve<ITestDependent>().Inner = FContainer.Resolve<ITestService>());
end;

procedure TContainerTests.CyclicDependency_Raises;
var
  LContainer: TMHContainer;
begin
  LContainer := FContainer;
  FContainer.RegisterSingleton<ICycleA>(
    function: ICycleA
    begin
      LContainer.Resolve<ICycleB>();
      Result := TCycle.Create;
    end);
  FContainer.RegisterSingleton<ICycleB>(
    function: ICycleB
    begin
      LContainer.Resolve<ICycleA>();
      Result := TCycle.Create;
    end);
  Assert.WillRaise(DoResolveCycleA, EMHContainerError);
end;

procedure TContainerTests.FactoryReturningNil_Raises;
begin
  FContainer.RegisterTransient<ITestService>(
    function: ITestService
    begin
      Result := nil;
    end);
  Assert.WillRaise(DoResolveService, EMHContainerError);
end;

procedure TContainerTests.InterfaceWithoutGuid_Raises;
begin
  Assert.WillRaise(DoIsRegisteredNoGuid, EMHContainerError);
end;

procedure TContainerTests.NilArguments_Raise;
begin
  Assert.WillRaise(DoRegisterNilFactory, EArgumentNilException);
  Assert.WillRaise(DoRegisterNilInstance, EArgumentNilException);
end;

procedure TContainerTests.Clear_ReleasesSingletons;
var
  LService: ITestService;
begin
  FContainer.RegisterSingleton<ITestService>(
    function: ITestService
    begin
      Result := TTestService.Create(1);
    end);
  // Явная переменная: неявный временный результат удерживал бы ссылку до конца метода.
  LService := FContainer.Resolve<ITestService>();
  Assert.AreEqual(1, TTestService.Alive);
  LService := nil;
  FContainer.Clear;
  Assert.AreEqual(0, TTestService.Alive, 'Singleton должен освобождаться вместе с контейнером');
  Assert.IsFalse(FContainer.IsRegistered<ITestService>());
end;

procedure TContainerTests.FailedSingletonFactory_CanBeRetried;
var
  LFail: Boolean;
begin
  LFail := True;
  FContainer.RegisterSingleton<ITestService>(
    function: ITestService
    begin
      if LFail then
        raise ETestCollectorFailure.Create('transient');
      Result := TTestService.Create(9);
    end);
  Assert.WillRaise(DoResolveService, ETestCollectorFailure);
  LFail := False;
  Assert.AreEqual(9, FContainer.Resolve<ITestService>().Value,
    'После сбоя фабрики регистрация не должна остаться в состоянии «разрешается»');
end;

initialization
  TDUnitX.RegisterTestFixture(TContainerTests);

end.
