unit MineHunter.Core.Inventory;

{
  «Что изменилось»: учёт объектов, впервые замеченных на компьютере, —
  записей автозапуска, признаков вмешательства в защиту и программ.
  Хранилище запоминает время первого и последнего наблюдения каждого объекта;
  объекты, найденные в первые MH_INVENTORY_GRACE_MINUTES наблюдения своего
  вида, считаются исходным состоянием, а не изменениями (иначе в первый день
  «новым» было бы всё).
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

const
  MH_INVENTORY_GRACE_MINUTES = 30;
  /// Как часто хранилище обновляет учёт (по времени снимков), секунды.
  MH_INVENTORY_REFRESH_SECONDS = 60;

type
  TMHInventoryKind = (
    ikAutostart,  // запись автозапуска (реестр, папка, служба, задание)
    ikTamper,     // признак вмешательства в защиту (исключение Defender, IFEO…)
    ikProgram     // исполняемый файл, впервые замеченный среди процессов
  );

  TMHInventoryItem = record
  public
    Kind: TMHInventoryKind;
    /// Стабильный ключ объекта внутри вида.
    Key: string;
    Name: string;
    /// Где находится: раздел реестра, папка, тип службы…
    Details: string;
    ImagePath: string;
    FirstSeenUtc: TDateTime;
    LastSeenUtc: TDateTime;
  end;

  /// Чтение учёта (реализуется хранилищем истории).
  IMHInventoryHistory = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CE0}']
    /// Объекты, впервые замеченные не раньше ASinceUtc, кроме исходного
    /// состояния; новые — первыми.
    function LoadInventoryChanges(ASinceUtc: TDateTime; AMaxCount: Integer): TArray<TMHInventoryItem>;
    /// Начало наблюдения (0 — учёт ещё пуст).
    function InventoryStartUtc: TDateTime;
  end;

/// Объекты снимка. Без AStorePaths пути не сохраняются, программы учитываются по имени.
function MHInventoryFromSnapshot(const ASnapshot: TMHSnapshot; AStorePaths: Boolean): TArray<TMHInventoryItem>;

function MHInventoryKindToName(AKind: TMHInventoryKind): string;
function MHTryInventoryKindFromName(const AName: string; out AKind: TMHInventoryKind): Boolean;
/// «Новая запись автозапуска» и т.п.
function MHInventoryKindTitle(AKind: TMHInventoryKind): string;

implementation

uses
  System.Generics.Collections;

const
  KIND_NAMES: array[TMHInventoryKind] of string = ('autostart', 'tamper', 'program');

function MHInventoryKindToName(AKind: TMHInventoryKind): string;
begin
  Result := KIND_NAMES[AKind];
end;

function MHTryInventoryKindFromName(const AName: string; out AKind: TMHInventoryKind): Boolean;
var
  LKind: TMHInventoryKind;
begin
  for LKind := Low(TMHInventoryKind) to High(TMHInventoryKind) do
    if SameText(KIND_NAMES[LKind], AName) then
    begin
      AKind := LKind;
      Exit(True);
    end;
  AKind := ikProgram;
  Result := False;
end;

function MHInventoryKindTitle(AKind: TMHInventoryKind): string;
begin
  case AKind of
    ikAutostart: Result := 'Новая запись автозапуска';
    ikTamper: Result := 'Новый признак вмешательства в защиту';
  else
    Result := 'Впервые запущена программа';
  end;
end;

function MHInventoryFromSnapshot(const ASnapshot: TMHSnapshot; AStorePaths: Boolean): TArray<TMHInventoryItem>;
var
  LList: TList<TMHInventoryItem>;
  LSeen: TDictionary<string, Boolean>;
  LItem: TMHInventoryItem;
  LEntry: TMHAutostartEntry;
  LTamper: TMHTamperEntry;
  LInfo: TMHProcessInfo;

  procedure Add(AKind: TMHInventoryKind; const AKey, AName, ADetails, AImage: string);
  var
    LFull: string;
  begin
    if AKey = '' then
      Exit;
    LFull := KIND_NAMES[AKind] + '|' + AKey.ToLower;
    if LSeen.ContainsKey(LFull) then
      Exit;
    LSeen.Add(LFull, True);
    LItem := Default(TMHInventoryItem);
    LItem.Kind := AKind;
    LItem.Key := AKey.ToLower;
    LItem.Name := AName;
    LItem.Details := ADetails;
    if AStorePaths then
      LItem.ImagePath := AImage;
    LItem.FirstSeenUtc := ASnapshot.TimestampUtc;
    LItem.LastSeenUtc := ASnapshot.TimestampUtc;
    LList.Add(LItem);
  end;

begin
  LList := TList<TMHInventoryItem>.Create;
  LSeen := TDictionary<string, Boolean>.Create;
  try
    for LEntry in ASnapshot.Autostart do
      Add(ikAutostart, MHAutostartKindToString(LEntry.Kind) + '|' + LEntry.Location + '|' + LEntry.Name,
        LEntry.Name, MHAutostartKindToString(LEntry.Kind) + ': ' + LEntry.Location, LEntry.ImagePath);
    for LTamper in ASnapshot.Tamper do
      Add(ikTamper, MHTamperKindToString(LTamper.Kind) + '|' + LTamper.Location + '|' + LTamper.Name + '|' +
        LTamper.Value, LTamper.Name, MHTamperKindToString(LTamper.Kind) + ': ' + LTamper.Value,
        LTamper.ImagePath);
    for LInfo in ASnapshot.Processes do
      // Процессы без пути (System, защищённые) не дают устойчивого ключа.
      if LInfo.ImagePath <> '' then
      begin
        if AStorePaths then
          Add(ikProgram, LInfo.ImagePath, LInfo.Name, '', LInfo.ImagePath)
        else
          Add(ikProgram, LInfo.Name, LInfo.Name, '', '');
      end;
    Result := LList.ToArray;
  finally
    LSeen.Free;
    LList.Free;
  end;
end;

end.
