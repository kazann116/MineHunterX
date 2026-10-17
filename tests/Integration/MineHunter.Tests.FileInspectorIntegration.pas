unit MineHunter.Tests.FileInspectorIntegration;

{
  Integration: инспектор файлов на реальной Windows (TMHWinFileApi).
    - системные файлы подписаны Microsoft (подпись каталога или встроенная);
    - SHA-256 совпадает с эталоном System.Hash;
    - временный файл без подписи — sgUnsigned;
    - копия подписанного файла с изменённым байтом — sgSignedUntrusted.
  Сеть не используется: проверка отзыва отключена, URL — только из кеша.
  Временные файлы создаются в %TEMP%\MineHunterTests\<GUID> и удаляются в TearDown.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Collectors.Files;

type
  [TestFixture]
  [Category('Integration')]
  TFileInspectorIntegrationTests = class
  private
    FApi: IMHFileApi;
    FTempDir: string;
    function SystemFile(const AName: string): string;
    function WriteTempFile(const AName: string; const AData: TArray<Byte>): string;
    function FindEmbeddedSignedFile(out APath: string): Boolean;
    procedure CheckMicrosoftTrusted(const APath: string);
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Notepad_IsTrustedMicrosoft;
    [Test] procedure Kernel32_IsTrustedMicrosoft;
    [Test] procedure Sha256_MatchesRtlReference;
    [Test] procedure RunningExecutable_IsReadable;
    [Test] procedure FileStamp_MatchesFileSystem;
    [Test] procedure UnsignedTempFile_IsUnsigned;
    [Test] procedure TamperedSignedFile_IsUntrusted;
    [Test] procedure MissingFile_ReportsFailureWithoutException;
    [Test] procedure Collector_EndToEnd_OnRealFiles;
    [Test] procedure NoHandleLeak_AfterManyChecks;
    [Test] procedure Timing_SignatureAndHashing;
  end;

implementation

{$WARN SYMBOL_PLATFORM OFF}

uses
  System.SysUtils, System.Classes, System.IOUtils, System.Hash, System.Diagnostics,
  Winapi.Windows,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Logging,
  MineHunter.Collectors.Files.WinApi;

const
  /// Файлы со встроенной подписью Authenticode (Embarcadero/Idera), проверенные
  /// на машине разработки: dcc64.exe — Valid, SignatureType = Authenticode.
  EMBEDDED_SIGNED_CANDIDATES: array[0..2] of string = (
    'C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\dcc64.exe',
    'C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\dcc32.exe',
    'C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\bds.exe');

procedure TFileInspectorIntegrationTests.Setup;
begin
  FApi := TMHWinFileApi.Create;
  FTempDir := TPath.Combine(TPath.Combine(TPath.GetTempPath, 'MineHunterTests'),
    TGUID.NewGuid.ToString);
  ForceDirectories(FTempDir);
end;

procedure TFileInspectorIntegrationTests.TearDown;
begin
  FApi := nil;
  if (FTempDir <> '') and TDirectory.Exists(FTempDir) then
    TDirectory.Delete(FTempDir, True);
  // Общая папка удаляется, только если она пуста (параллельные прогоны не мешают).
  RemoveDir(ExtractFileDir(FTempDir));
  FTempDir := '';
end;

function TFileInspectorIntegrationTests.SystemFile(const AName: string): string;
var
  LBuffer: array[0..MAX_PATH] of Char;
begin
  GetSystemDirectory(LBuffer, Length(LBuffer));
  Result := TPath.Combine(string(LBuffer), AName);
end;

function TFileInspectorIntegrationTests.WriteTempFile(const AName: string;
  const AData: TArray<Byte>): string;
begin
  Result := TPath.Combine(FTempDir, AName);
  TFile.WriteAllBytes(Result, AData);
end;

function TFileInspectorIntegrationTests.FindEmbeddedSignedFile(out APath: string): Boolean;
var
  LCandidate, LSigner, LSource, LError: string;
  LState: TMHSignatureState;
begin
  for LCandidate in EMBEDDED_SIGNED_CANDIDATES do
    if FileExists(LCandidate) and
       FApi.VerifySignature(LCandidate, LState, LSigner, LSource, LError) and
       (LState = sgSignedTrusted) and (LSource = 'embedded') then
    begin
      APath := LCandidate;
      Exit(True);
    end;
  APath := '';
  Result := False;
end;

procedure TFileInspectorIntegrationTests.CheckMicrosoftTrusted(const APath: string);
var
  LState: TMHSignatureState;
  LSigner, LSource, LError: string;
begin
  Assert.IsTrue(FApi.VerifySignature(APath, LState, LSigner, LSource, LError), LError);
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LState, LError);
  Assert.IsTrue(LSigner.Contains('Microsoft'), 'Издатель: ' + LSigner);
  Assert.IsTrue((LSource = 'catalog') or (LSource = 'embedded'), 'Источник: ' + LSource);
  Assert.AreEqual('', LError);
end;

procedure TFileInspectorIntegrationTests.Notepad_IsTrustedMicrosoft;
begin
  CheckMicrosoftTrusted(SystemFile('notepad.exe'));
end;

procedure TFileInspectorIntegrationTests.Kernel32_IsTrustedMicrosoft;
begin
  CheckMicrosoftTrusted(SystemFile('kernel32.dll'));
end;

procedure TFileInspectorIntegrationTests.Sha256_MatchesRtlReference;
var
  LPaths: TArray<string>;
  LPath, LHash, LError: string;
begin
  LPaths := [SystemFile('notepad.exe'), SystemFile('kernel32.dll')];
  for LPath in LPaths do
  begin
    Assert.IsTrue(FApi.ComputeSha256(LPath, LHash, LError), LError);
    Assert.AreEqual(64, Length(LHash));
    Assert.AreEqual(LHash.ToLower, LHash, 'Хеш в нижнем регистре');
    Assert.AreEqual(THashSHA2.GetHashStringFromFile(LPath), LHash, True, LPath);
  end;
  // Пустой файл — известный хеш SHA-256 пустой строки.
  LPath := WriteTempFile('empty.bin', nil);
  Assert.IsTrue(FApi.ComputeSha256(LPath, LHash, LError), LError);
  Assert.AreEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', LHash);
end;

procedure TFileInspectorIntegrationTests.RunningExecutable_IsReadable;
var
  LHash, LError, LSigner, LSource: string;
  LState: TMHSignatureState;
begin
  // Образ запущенного процесса (этот тест-раннер) должен читаться.
  Assert.IsTrue(FApi.ComputeSha256(ParamStr(0), LHash, LError), LError);
  Assert.AreEqual(THashSHA2.GetHashStringFromFile(ParamStr(0)), LHash, True);
  Assert.IsTrue(FApi.VerifySignature(ParamStr(0), LState, LSigner, LSource, LError), LError);
  Assert.AreEqual<TMHSignatureState>(sgUnsigned, LState, 'Тестовая сборка не подписана');
end;

procedure TFileInspectorIntegrationTests.FileStamp_MatchesFileSystem;
var
  LPath: string;
  LSize: Int64;
  LLastWrite: TDateTime;
begin
  LPath := SystemFile('notepad.exe');
  Assert.IsTrue(FApi.GetFileStamp(LPath, LSize, LLastWrite));
  Assert.AreEqual<Int64>(TFile.GetSize(LPath), LSize);
  Assert.AreEqual(TFile.GetLastWriteTimeUtc(LPath), LLastWrite, 1 / SecsPerDay);
  Assert.IsFalse(FApi.GetFileStamp(ExtractFileDir(LPath), LSize, LLastWrite),
    'Каталог не является файлом');
end;

procedure TFileInspectorIntegrationTests.UnsignedTempFile_IsUnsigned;
var
  LPath, LSigner, LSource, LError: string;
  LState: TMHSignatureState;
begin
  LPath := WriteTempFile('plain.exe', TEncoding.ASCII.GetBytes('MineHunter test file, not a program'));
  Assert.IsTrue(FApi.VerifySignature(LPath, LState, LSigner, LSource, LError), LError);
  Assert.AreEqual<TMHSignatureState>(sgUnsigned, LState);
  Assert.AreEqual('', LSigner);
  Assert.AreEqual('', LSource);
end;

procedure TFileInspectorIntegrationTests.TamperedSignedFile_IsUntrusted;
var
  LOriginal, LCopy, LSigner, LSource, LError: string;
  LState: TMHSignatureState;
  LStream: TFileStream;
  LByte: Byte;
begin
  Assert.IsTrue(FindEmbeddedSignedFile(LOriginal),
    'Не найден файл со встроенной подписью: ' + string.Join('; ', EMBEDDED_SIGNED_CANDIDATES));
  LCopy := TPath.Combine(FTempDir, 'signed-copy.exe');
  TFile.Copy(LOriginal, LCopy);

  Assert.IsTrue(FApi.VerifySignature(LCopy, LState, LSigner, LSource, LError), LError);
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LState, 'Неизменённая копия подписана');
  Assert.AreEqual('embedded', LSource);
  Assert.IsNotEmpty(LSigner);

  // Меняем один байт в середине файла (область кода, не таблица сертификатов).
  LStream := TFileStream.Create(LCopy, fmOpenReadWrite or fmShareExclusive);
  try
    LStream.Position := LStream.Size div 2;
    LStream.ReadBuffer(LByte, 1);
    LByte := LByte xor $FF;
    LStream.Position := LStream.Size div 2;
    LStream.WriteBuffer(LByte, 1);
  finally
    LStream.Free;
  end;

  Assert.IsTrue(FApi.VerifySignature(LCopy, LState, LSigner, LSource, LError), LError);
  Assert.AreEqual<TMHSignatureState>(sgSignedUntrusted, LState);
  Assert.AreEqual('embedded', LSource);
  Assert.IsTrue(LError.Contains('изменён после подписания'), LError);
end;

procedure TFileInspectorIntegrationTests.MissingFile_ReportsFailureWithoutException;
var
  LPath, LHash, LSigner, LSource, LError: string;
  LState: TMHSignatureState;
  LSize: Int64;
  LLastWrite: TDateTime;
begin
  LPath := TPath.Combine(FTempDir, 'missing.exe');
  Assert.IsFalse(FApi.GetFileStamp(LPath, LSize, LLastWrite));
  Assert.AreEqual<Int64>(-1, LSize);
  Assert.IsFalse(FApi.ComputeSha256(LPath, LHash, LError));
  Assert.IsNotEmpty(LError);
  Assert.IsFalse(FApi.VerifySignature(LPath, LState, LSigner, LSource, LError));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LState);
  Assert.IsNotEmpty(LError);
end;

procedure TFileInspectorIntegrationTests.Collector_EndToEnd_OnRealFiles;
var
  LCollector: IMHCollector;
  LSnapshot: TMHSnapshot;
  LProcess: TMHProcessInfo;
  LEntry: TMHAutostartEntry;
  LResult: TMHCollectionResult;
  LInfo: TMHFileInfo;
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  LCollector := TMHFileCollector.Create(FApi, LClock, 5000);
  LSnapshot := TMHSnapshot.Create(1, LClock.NowUtc);
  LProcess := TMHProcessInfo.Create(TMHProcessId.Create(4242, 1), 'notepad.exe', LSnapshot.TimestampUtc);
  LProcess.ImagePath := SystemFile('notepad.exe');
  LSnapshot.Processes := [LProcess];
  LEntry := Default(TMHAutostartEntry);
  LEntry.ImagePath := TPath.Combine(FTempDir, 'missing.exe');
  LSnapshot.Autostart := [LEntry];

  LResult := LCollector.Collect(LSnapshot);
  Assert.AreEqual(2, Integer(Length(LResult.Files)));
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State, 'Отсутствующий файл — неполные данные');
  Assert.IsNotEmpty(LResult.Status.Message);
  LSnapshot.Files := LResult.Files;
  Assert.IsTrue(LSnapshot.FindFile(SystemFile('notepad.exe'), LInfo));
  Assert.AreEqual<TMHSignatureState>(sgSignedTrusted, LInfo.Signature);
  Assert.AreEqual(THashSHA2.GetHashStringFromFile(SystemFile('notepad.exe')), LInfo.Sha256, True);
  Assert.IsTrue(LInfo.SizeBytes > 0);
  Assert.IsTrue(LSnapshot.FindFile(TPath.Combine(FTempDir, 'missing.exe'), LInfo));
  Assert.AreEqual<TMHSignatureState>(sgCheckFailed, LInfo.Signature);
end;

procedure TFileInspectorIntegrationTests.NoHandleLeak_AfterManyChecks;
var
  LPlain, LHash, LSigner, LSource, LError: string;
  LState: TMHSignatureState;
  LBefore, LAfter: DWORD;
  I: Integer;
begin
  LPlain := WriteTempFile('plain.exe', TEncoding.ASCII.GetBytes('plain'));
  // Прогрев: однократная загрузка провайдеров доверия и каталогов.
  FApi.VerifySignature(SystemFile('notepad.exe'), LState, LSigner, LSource, LError);
  FApi.VerifySignature(LPlain, LState, LSigner, LSource, LError);
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 1 to 20 do
  begin
    FApi.VerifySignature(SystemFile('notepad.exe'), LState, LSigner, LSource, LError);
    FApi.VerifySignature(LPlain, LState, LSigner, LSource, LError);
    FApi.ComputeSha256(LPlain, LHash, LError);
  end;
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 10,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

procedure TFileInspectorIntegrationTests.Timing_SignatureAndHashing;
const
  SIGNATURE_RUNS = 10;
  HASH_RUNS = 5;
var
  LPaths: TArray<string>;
  LPath, LEmbedded, LHash, LSigner, LSource, LError, LReport: string;
  LState: TMHSignatureState;
  LWatch: TStopwatch;
  LSize: Int64;
  LLastWrite: TDateTime;
  LMs, LMsPerMb: Double;
  I: Integer;
begin
  LPaths := [SystemFile('notepad.exe'), SystemFile('kernel32.dll')];
  if FindEmbeddedSignedFile(LEmbedded) then
    LPaths := LPaths + [LEmbedded];
  LReport := '';
  for LPath in LPaths do
  begin
    FApi.VerifySignature(LPath, LState, LSigner, LSource, LError); // прогрев
    LWatch := TStopwatch.StartNew;
    for I := 1 to SIGNATURE_RUNS do
      Assert.IsTrue(FApi.VerifySignature(LPath, LState, LSigner, LSource, LError), LError);
    LWatch.Stop;
    LMs := LWatch.Elapsed.TotalMilliseconds / SIGNATURE_RUNS;
    LReport := LReport + Format('  подпись %s (%s): %.2f мс%s',
      [ExtractFileName(LPath), LSource, LMs, sLineBreak]);
    Assert.IsTrue(LMs < 2000, Format('Проверка подписи %s: %.0f мс', [LPath, LMs]));
  end;

  LPath := LPaths[High(LPaths)];
  Assert.IsTrue(FApi.GetFileStamp(LPath, LSize, LLastWrite));
  LWatch := TStopwatch.StartNew;
  for I := 1 to HASH_RUNS do
    Assert.IsTrue(FApi.ComputeSha256(LPath, LHash, LError), LError);
  LWatch.Stop;
  LMsPerMb := LWatch.Elapsed.TotalMilliseconds / HASH_RUNS / (LSize / (1024 * 1024));
  LReport := LReport + Format('  SHA-256 %s (%.1f МБ): %.2f мс/МБ',
    [ExtractFileName(LPath), LSize / (1024 * 1024), LMsPerMb]);
  Log('[FileInspector timing]' + sLineBreak + LReport);
  Assert.IsTrue(LMsPerMb < 200, Format('Хеширование: %.1f мс/МБ', [LMsPerMb]));
end;

initialization
  TDUnitX.RegisterTestFixture(TFileInspectorIntegrationTests);

end.
