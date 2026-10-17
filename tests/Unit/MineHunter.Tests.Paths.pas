unit MineHunter.Tests.Paths;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Unit')]
  TPathTests = class
  public
    [TestCase('plain', 'C:\Windows\notepad.exe|C:\Windows\notepad.exe', '|')]
    [TestCase('quotes', '"C:\Program Files\App\a.exe"|C:\Program Files\App\a.exe', '|')]
    [TestCase('spaces', '  C:\a.exe  |C:\a.exe', '|')]
    [TestCase('slashes', 'C:/Windows/System32/cmd.exe|C:\Windows\System32\cmd.exe', '|')]
    [TestCase('long prefix', '\\?\C:\Windows\a.exe|C:\Windows\a.exe', '|')]
    [TestCase('nt prefix', '\??\C:\Windows\a.exe|C:\Windows\a.exe', '|')]
    [TestCase('device prefix', '\\.\C:\a.exe|C:\a.exe', '|')]
    [TestCase('long unc', '\\?\UNC\server\share\a.exe|\\server\share\a.exe', '|')]
    [TestCase('unc', '\\server\share\dir\..\a.exe|\\server\share\a.exe', '|')]
    [TestCase('double slash', 'C:\Windows\\System32\\\cmd.exe|C:\Windows\System32\cmd.exe', '|')]
    [TestCase('dot segments', 'C:\Windows\.\System32\..\notepad.exe|C:\Windows\notepad.exe', '|')]
    [TestCase('dotdot above root', 'C:\..\..\a.exe|C:\a.exe', '|')]
    [TestCase('trailing slash', 'C:\Windows\|C:\Windows', '|')]
    [TestCase('drive root', 'C:\|C:\', '|')]
    [TestCase('unc root kept', '\\server\share\..\..\x|\\server\share\x', '|')]
    procedure Normalize(const AInput, AExpected: string);
    [Test] procedure Empty_StaysEmpty;
    [Test] procedure SystemRoot_IsExpandedOnlyWithWindowsDir;
    [Test] procedure SamePath_IgnoresCaseAndForm;
    [Test] procedure SamePath_DifferentFiles;
  end;

implementation

uses
  MineHunter.Core.Paths;

procedure TPathTests.Normalize(const AInput, AExpected: string);
begin
  Assert.AreEqual(AExpected, MHNormalizePath(AInput));
end;

procedure TPathTests.Empty_StaysEmpty;
begin
  Assert.AreEqual('', MHNormalizePath(''));
  Assert.AreEqual('', MHNormalizePath('   '));
  Assert.AreEqual('', MHNormalizePath('""'));
end;

procedure TPathTests.SystemRoot_IsExpandedOnlyWithWindowsDir;
begin
  Assert.AreEqual('C:\Windows\System32\svchost.exe',
    MHNormalizePath('\SystemRoot\System32\svchost.exe', 'C:\Windows\'));
  Assert.AreEqual('C:\Windows\System32\svchost.exe',
    MHNormalizePath('%SystemRoot%\System32\svchost.exe', 'C:\Windows'));
  Assert.AreEqual('\SystemRoot\System32\svchost.exe',
    MHNormalizePath('\SystemRoot\System32\svchost.exe'));
end;

procedure TPathTests.SamePath_IgnoresCaseAndForm;
begin
  Assert.IsTrue(MHSamePath('c:/windows/SYSTEM32/cmd.exe', '\\?\C:\Windows\System32\cmd.exe'));
end;

procedure TPathTests.SamePath_DifferentFiles;
begin
  Assert.IsFalse(MHSamePath('C:\Windows\System32\svchost.exe',
    'C:\Users\Public\svchost.exe'), 'Одинаковое имя в другой папке — другой файл');
end;

initialization
  TDUnitX.RegisterTestFixture(TPathTests);

end.
