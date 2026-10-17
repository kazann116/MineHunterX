unit MineHunter.Tests.Contracts;

{
  Проверки контрактов всего проекта через RTTI: у каждого интерфейса
  MineHunter свой GUID. Совпадение GUID ломает приведения «as» и Supports —
  запрос одного интерфейса молча вернул бы другой.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Contract')]
  TContractTests = class
  public
    [Test] procedure InterfaceGuids_AreUnique;
  end;

implementation

uses
  System.SysUtils, System.Rtti, System.TypInfo, System.Generics.Collections;

procedure TContractTests.InterfaceGuids_AreUnique;
var
  LContext: TRttiContext;
  LType: TRttiType;
  LInterface: TRttiInterfaceType;
  LSeen: TDictionary<TGUID, string>;
  LOther: string;
  LCount: Integer;
begin
  LContext := TRttiContext.Create;
  LSeen := TDictionary<TGUID, string>.Create;
  try
    LCount := 0;
    for LType in LContext.GetTypes do
    begin
      if not (LType is TRttiInterfaceType) then
        Continue;
      LInterface := TRttiInterfaceType(LType);
      if not LInterface.QualifiedName.StartsWith('MineHunter.') or
         not (ifHasGuid in LInterface.IntfFlags) then
        Continue;
      Inc(LCount);
      if LSeen.TryGetValue(LInterface.GUID, LOther) then
        Assert.Fail(Format('Одинаковый GUID у %s и %s', [LOther, LInterface.QualifiedName]));
      LSeen.Add(LInterface.GUID, LInterface.QualifiedName);
    end;
    Assert.IsTrue(LCount >= 10, Format('Найдено интерфейсов MineHunter: %d', [LCount]));
  finally
    LSeen.Free;
    LContext.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TContractTests);

end.
