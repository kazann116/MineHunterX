unit MineHunter.Tests.DataDir;

{
  Папка данных: стандартная по умолчанию, проверки при выборе новой папки,
  перенос при следующем запуске (база с журналом WAL, настройки, карантин),
  отказ перезаписывать существующую историю, откат и уборка при сбое
  копирования, возврат в стандартную папку. Только временные каталоги —
  настоящий %LOCALAPPDATA% не затрагивается.
}

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Storage')]
  TDataDirTests = class
  private
    FRoot: string;
    FStandard: string;
    procedure Put(const APath, AText: string);
    function Read(const APath: string): string;
    procedure FillStandard;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure NoPointer_StandardFolder;
    [Test] procedure Request_RejectsBadFolders;
    [Test] procedure Move_CopiesHistoryWalSettingsAndQuarantine_KeepsOld;
    [Test] procedure Move_ExistingHistoryInTarget_NotOverwritten;
    [Test] procedure Move_CopyFails_StaysOnOldFolderAndCleansUp;
    [Test] procedure BackToDefault_RemovesPointer;
    [Test] procedure ChosenFolderUnavailable_FallsBackToStandard;
  end;

implementation

uses
  System.IOUtils, Winapi.Windows,
  MineHunter.Core.DataDir;

procedure TDataDirTests.Setup;
begin
  FRoot := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\datadir-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  FStandard := TPath.Combine(FRoot, 'Standard');
  ForceDirectories(FStandard);
end;

procedure TDataDirTests.TearDown;
begin
  try
    TDirectory.Delete(FRoot, True);
  except
    // Временный каталог тестов.
  end;
end;

procedure TDataDirTests.Put(const APath, AText: string);
begin
  ForceDirectories(ExtractFileDir(APath));
  TFile.WriteAllText(APath, AText);
end;

function TDataDirTests.Read(const APath: string): string;
begin
  Result := TFile.ReadAllText(APath);
end;

procedure TDataDirTests.FillStandard;
begin
  Put(TPath.Combine(FStandard, 'history.db'), 'db');
  Put(TPath.Combine(FStandard, 'history.db-wal'), 'wal');
  Put(TPath.Combine(FStandard, 'settings.json'), '{"version":1}');
  Put(TPath.Combine(FStandard, 'Quarantine\item1\manifest.json'), '{}');
  Put(TPath.Combine(FStandard, 'Quarantine\item1\abc.quarantine'), 'file');
end;

procedure TDataDirTests.NoPointer_StandardFolder;
var
  LPointer: TMHDataDirPointer;
  LMoved: Boolean;
  LError: string;
begin
  Assert.AreEqual(FStandard, MHResolveDataDir(FStandard));
  Assert.IsFalse(MHReadDataDirPointer(FStandard, LPointer));
  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError), 'Нечего переносить — не ошибка');
  Assert.IsFalse(LMoved);
end;

procedure TDataDirTests.Request_RejectsBadFolders;
var
  LError: string;
  LDrive: Char;
  LMissing: string;
begin
  Assert.IsFalse(MHRequestDataDirChange(FStandard, 'MineHunterData', LError), 'Относительный путь');
  Assert.IsTrue(LError.Contains('полный путь'), LError);
  Assert.IsFalse(MHRequestDataDirChange(FStandard, FStandard + '\', LError), 'Та же папка');
  Assert.IsFalse(MHRequestDataDirChange(FStandard, TPath.Combine(FStandard, 'Inner'), LError), 'Внутри текущей');
  Assert.IsTrue(LError.Contains('внутри'), LError);
  Assert.IsFalse(MHRequestDataDirChange(FStandard, FRoot, LError), 'Текущая внутри новой');
  // Несуществующий диск — запись невозможна.
  LMissing := '';
  for LDrive := 'Z' downto 'M' do
    if GetDriveType(PChar(LDrive + ':\')) = DRIVE_NO_ROOT_DIR then
    begin
      LMissing := LDrive + ':\MineHunterX';
      Break;
    end;
  if LMissing <> '' then
  begin
    Assert.IsFalse(MHRequestDataDirChange(FStandard, LMissing, LError), LMissing);
    Assert.IsTrue(LError.Contains('нельзя записывать'), LError);
  end;
  Assert.IsFalse(FileExists(TPath.Combine(FStandard, MH_DATA_DIR_POINTER)), 'Отказ ничего не меняет');
end;

procedure TDataDirTests.Move_CopiesHistoryWalSettingsAndQuarantine_KeepsOld;
var
  LTarget, LError: string;
  LPointer: TMHDataDirPointer;
  LMoved: Boolean;
begin
  FillStandard;
  LTarget := TPath.Combine(FRoot, 'D-Data');
  Assert.IsTrue(MHRequestDataDirChange(FStandard, LTarget, LError), LError);
  Assert.IsTrue(MHReadDataDirPointer(FStandard, LPointer));
  Assert.AreEqual(LTarget, LPointer.DataDir);
  Assert.AreEqual(FStandard, LPointer.MoveFrom, 'Перенос — при следующем запуске');
  Assert.IsFalse(FileExists(TPath.Combine(LTarget, 'history.db')), 'До перезапуска ничего не копируется');

  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError), LError);
  Assert.IsTrue(LMoved);
  Assert.AreEqual('db', Read(TPath.Combine(LTarget, 'history.db')));
  Assert.AreEqual('wal', Read(TPath.Combine(LTarget, 'history.db-wal')), 'Журнал WAL — вместе с базой');
  Assert.AreEqual('{"version":1}', Read(TPath.Combine(LTarget, 'settings.json')));
  Assert.AreEqual('file', Read(TPath.Combine(LTarget, 'Quarantine\item1\abc.quarantine')));
  Assert.IsTrue(FileExists(TPath.Combine(FStandard, 'history.db')), 'Старая папка не удаляется');
  Assert.AreEqual(LTarget, MHResolveDataDir(FStandard));
  Assert.IsTrue(MHReadDataDirPointer(FStandard, LPointer));
  Assert.AreEqual('', LPointer.MoveFrom, 'Перенос выполнен один раз');
  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError));
  Assert.IsFalse(LMoved, 'Повторный запуск ничего не копирует');
end;

procedure TDataDirTests.Move_ExistingHistoryInTarget_NotOverwritten;
var
  LTarget, LError: string;
  LMoved: Boolean;
begin
  FillStandard;
  LTarget := TPath.Combine(FRoot, 'Existing');
  Put(TPath.Combine(LTarget, 'history.db'), 'their history');
  Assert.IsTrue(MHRequestDataDirChange(FStandard, LTarget, LError), LError);
  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError), LError);
  Assert.IsFalse(LMoved);
  Assert.AreEqual('their history', Read(TPath.Combine(LTarget, 'history.db')), 'Существующая история не затирается');
  Assert.AreEqual(LTarget, MHResolveDataDir(FStandard), 'Программа работает с историей в выбранной папке');
end;

procedure TDataDirTests.Move_CopyFails_StaysOnOldFolderAndCleansUp;
var
  LTarget, LError: string;
  LMoved: Boolean;
  LLock: TFileStream;
begin
  FillStandard;
  LTarget := TPath.Combine(FRoot, 'Broken');
  Assert.IsTrue(MHRequestDataDirChange(FStandard, LTarget, LError), LError);
  // Журнал WAL занят без права чтения — копирование обрывается после самой базы.
  LLock := TFileStream.Create(TPath.Combine(FStandard, 'history.db-wal'), fmOpenReadWrite or fmShareExclusive);
  try
    Assert.IsFalse(MHApplyPendingDataMove(FStandard, LMoved, LError));
  finally
    LLock.Free;
  end;
  Assert.IsNotEmpty(LError);
  Assert.IsFalse(LMoved);
  Assert.IsFalse(FileExists(TPath.Combine(LTarget, 'history.db')),
    'Неполная копия удалена — при повторе она не выглядит готовой историей');
  Assert.AreEqual(FStandard, MHResolveDataDir(FStandard), 'Программа остаётся на прежней папке');
  Assert.IsFalse(FileExists(TPath.Combine(FStandard, MH_DATA_DIR_POINTER)), 'Перенос отменён');
end;

procedure TDataDirTests.BackToDefault_RemovesPointer;
var
  LTarget, LError: string;
  LMoved: Boolean;
begin
  FillStandard;
  LTarget := TPath.Combine(FRoot, 'Custom');
  Assert.IsTrue(MHRequestDataDirChange(FStandard, LTarget, LError), LError);
  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError), LError);
  // Возврат: в стандартной папке история уже есть (не удалялась) — она и используется.
  Assert.IsTrue(MHRequestDataDirChange(FStandard, '', LError), LError);
  Assert.IsTrue(MHApplyPendingDataMove(FStandard, LMoved, LError), LError);
  Assert.AreEqual(FStandard, MHResolveDataDir(FStandard));
  Assert.IsFalse(FileExists(TPath.Combine(FStandard, MH_DATA_DIR_POINTER)), 'Стандартной папке указатель не нужен');
end;

procedure TDataDirTests.ChosenFolderUnavailable_FallsBackToStandard;
var
  LPointer: TMHDataDirPointer;
  LError: string;
begin
  LPointer := Default(TMHDataDirPointer);
  LPointer.DataDir := '?:\NoSuchDrive\MineHunterX';
  Assert.IsTrue(MHWriteDataDirPointer(FStandard, LPointer, LError), LError);
  Assert.AreEqual(FStandard, MHResolveDataDir(FStandard), 'Диск с выбранной папкой отключён — стандартная папка');
  // Повреждённый указатель — тоже стандартная.
  TFile.WriteAllText(TPath.Combine(FStandard, MH_DATA_DIR_POINTER), 'не json');
  Assert.AreEqual(FStandard, MHResolveDataDir(FStandard));
end;

initialization
  TDUnitX.RegisterTestFixture(TDataDirTests);

end.
