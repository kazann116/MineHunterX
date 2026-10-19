unit MineHunter.Collectors.Disks;

{
  Физические диски и разделы.
  Сводит в TMHSnapshot.Disks / Volumes:
    - список дисков (модель, тип, шина, объём, состояние по оценке Windows) —
      редко меняется, перечитывается раз в DiskRefreshSeconds;
    - счётчики надёжности (износ SSD, ошибки, наработка, температура) — тоже
      редко; без прав администратора Windows их может не отдавать;
    - атрибуты здоровья, как в CrystalDiskInfo: журнал NVMe — раз в минуту и
      без прав администратора, SMART SATA — раз в DiskRefreshSeconds (не будит
      лишний раз спящие диски) и только с правами администратора; заполняют
      то, чего нет в счётчиках надёжности;
    - разделы со свободным местом — раз в VolumeRefreshSeconds;
    - нагрузку каждого диска (счётчики PhysicalDisk) — на каждом цикле.
  Температура берётся из счётчиков надёжности, а если их нет — из показаний
  коллектора датчиков (sensors) по модели диска.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.DiskHealth;

type
  TMHRawDisk = record
    Number: Integer;
    Model: string;
    Media: TMHDiskMedia;
    Bus: string;
    SizeBytes: Int64;
    Health: TMHDiskHealth;
    HealthDetails: string;
  end;

  TMHRawReliability = record
    Number: Integer;
    HasTemperature: Boolean;
    Temperature: Double;
    TemperatureMax: Double;
    HasWear: Boolean;
    Wear: Double;
    HasErrors: Boolean;
    ReadErrors: Int64;
    WriteErrors: Int64;
    PowerOnHours: Int64;
  end;

  TMHRawDiskCounter = record
    Number: Integer;
    /// Буквы разделов из имени экземпляра счётчика («1 f: h: i:» → «F: H: I:»).
    Letters: string;
    ActivePercent: Double;
    ReadBytesPerSec: Double;
    WriteBytesPerSec: Double;
  end;

  IMHDiskApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1D10}']
    function ReadDisks(out ADisks: TArray<TMHRawDisk>; out AError: string): Boolean;
    function ReadReliability(out AItems: TArray<TMHRawReliability>; out AError: string;
      out AAccessDenied: Boolean): Boolean;
    function ReadVolumes(out AVolumes: TArray<TMHVolumeInfo>; out AError: string): Boolean;
    /// Нагрузка по дискам; доступна со второго вызова (счётчики считают разницу).
    function ReadCounters(out ACounters: TArray<TMHRawDiskCounter>; out AError: string): Boolean;
    /// Атрибуты здоровья диска (журнал NVMe или SMART SATA). False с пустой AError —
    /// для этой шины сведения не запрашиваются (USB, RAID); AAccessDenied — нужны права администратора.
    function ReadHealth(ANumber: Integer; const ABus: string; out AData: TMHDiskHealthData;
      out AError: string; out AAccessDenied: Boolean): Boolean;
  end;

  TMHDiskCollector = class(TInterfacedObject, IMHCollector, IMHCacheInvalidation, IMHRefreshConfigurable)
  public const
    SourceIdValue = 'disks';
    DiskRefreshSeconds = 600;
    VolumeRefreshSeconds = 30;
    NvmeHealthRefreshSeconds = 60;
  private
    FApi: IMHDiskApi;
    FClock: IMHClock;
    FDisks: TArray<TMHRawDisk>;
    FDisksUtc: TDateTime;
    FDisksError: string;
    FReliability: TArray<TMHRawReliability>;
    FReliabilityUtc: TDateTime;
    FReliabilityError: string;
    FReliabilityDenied: Boolean;
    FVolumes: TArray<TMHVolumeInfo>;
    FVolumesUtc: TDateTime;
    FVolumesError: string;
    FReadCount: Integer;
    FHealth: TDictionary<Integer, TMHDiskHealthData>;
    FNvmeHealthUtc: TDateTime;
    FSmartUtc: TDateTime;
    FSmartDenied: Boolean;
    FDiskRefreshSec: Integer;
    FVolumeRefreshSec: Integer;
    FNvmeRefreshSec: Integer;
    function Expired(AUtc, ANow: TDateTime; ASeconds: Integer): Boolean;
    procedure RefreshCaches(ANow: TDateTime);
    procedure RefreshHealth(ANvme: Boolean);
  public
    constructor Create(const AApi: IMHDiskApi; const AClock: IMHClock);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    procedure Invalidate;
    /// Частота обновления из настроек (0 — только при запуске и по «Проверить сейчас»).
    procedure ApplyRefresh(const AIntervals: TMHRefreshIntervals);
    /// Сколько раз перечитывался список дисков (для тестов кэша).
    property ReadCount: Integer read FReadCount;
  end;

/// «1 f: h: i:» → номер 1 и «F: H: I:». False — имя не начинается с номера (_Total).
function MHParseDiskInstance(const AInstance: string; out ANumber: Integer; out ALetters: string): Boolean;

function MHDiskMediaToString(AMedia: TMHDiskMedia): string;
function MHDiskHealthToString(AHealth: TMHDiskHealth): string;

implementation

uses
  System.Math, System.DateUtils, System.Generics.Defaults, MineHunter.Core.Lang;

function MHParseDiskInstance(const AInstance: string; out ANumber: Integer; out ALetters: string): Boolean;
var
  LParts: TArray<string>;
  LPart: string;
begin
  ANumber := -1;
  ALetters := '';
  LParts := Trim(AInstance).Split([' '], TStringSplitOptions.ExcludeEmpty);
  if (Length(LParts) = 0) or not TryStrToInt(LParts[0], ANumber) or (ANumber < 0) then
  begin
    ANumber := -1;
    Exit(False);
  end;
  for LPart in Copy(LParts, 1, MaxInt) do
    if (Length(LPart) = 2) and (LPart[2] = ':') and CharInSet(UpCase(LPart[1]), ['A'..'Z']) then
      ALetters := Trim(ALetters + ' ' + UpperCase(LPart));
  Result := True;
end;

function MHDiskMediaToString(AMedia: TMHDiskMedia): string;
begin
  case AMedia of
    dmHdd: Result := MHL('жёсткий диск (HDD)', 'hard disk (HDD)');
    dmSsd: Result := MHL('твердотельный (SSD)', 'solid-state (SSD)');
  else
    Result := MHL('неизвестно', 'unknown');
  end;
end;

function MHDiskHealthToString(AHealth: TMHDiskHealth): string;
begin
  case AHealth of
    dhHealthy: Result := MHL('исправен', 'healthy');
    dhWarning: Result := MHL('есть предупреждения', 'warning');
    dhUnhealthy: Result := MHL('неисправен', 'unhealthy');
  else
    Result := MHL('неизвестно', 'unknown');
  end;
end;

/// Атрибуты здоровья диска: сохраняются целиком и заполняют то, чего нет в счётчиках
/// надёжности Windows (они — основной источник износа, ошибок и наработки).
procedure ApplyHealth(var AInfo: TMHDiskInfo; const AData: TMHDiskHealthData);
begin
  AInfo.AttributesSource := AData.Source;
  AInfo.Attributes := AData.Attributes;
  if not AInfo.HasTemperature and AData.HasTemperature then
  begin
    AInfo.HasTemperature := True;
    AInfo.TemperatureCelsius := AData.TemperatureCelsius;
  end;
  if not AInfo.HasWear and AData.HasWear then
  begin
    AInfo.HasWear := True;
    AInfo.WearPercent := AData.WearPercent;
  end;
  // NVMe: неисправленные ошибки целостности носителя — это ошибки чтения данных.
  if not AInfo.HasErrors and (AData.MediaErrors >= 0) then
  begin
    AInfo.HasErrors := True;
    AInfo.ReadErrors := AData.MediaErrors;
    AInfo.WriteErrors := 0;
  end;
  if (AInfo.PowerOnHours < 0) and (AData.PowerOnHours >= 0) then
    AInfo.PowerOnHours := AData.PowerOnHours;
  AInfo.PowerCycles := AData.PowerCycles;
  AInfo.UnsafeShutdowns := AData.UnsafeShutdowns;
  AInfo.TotalReadBytes := AData.TotalReadBytes;
  AInfo.TotalWrittenBytes := AData.TotalWrittenBytes;
  AInfo.ReallocatedSectors := AData.ReallocatedSectors;
  AInfo.PendingSectors := AData.PendingSectors;
  AInfo.UncorrectableSectors := AData.UncorrectableSectors;
  AInfo.CriticalWarning := AData.CriticalWarning;
  AInfo.AvailableSparePercent := AData.AvailableSparePercent;
  AInfo.SpareThresholdPercent := AData.SpareThresholdPercent;
end;

{ TMHDiskCollector }

constructor TMHDiskCollector.Create(const AApi: IMHDiskApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
  FHealth := TDictionary<Integer, TMHDiskHealthData>.Create;
  FDiskRefreshSec := DiskRefreshSeconds;
  FVolumeRefreshSec := VolumeRefreshSeconds;
  FNvmeRefreshSec := NvmeHealthRefreshSeconds;
end;

procedure TMHDiskCollector.ApplyRefresh(const AIntervals: TMHRefreshIntervals);
begin
  FDiskRefreshSec := Max(0, AIntervals.DiskInfoSec);
  FVolumeRefreshSec := Max(0, AIntervals.VolumesSec);
  FNvmeRefreshSec := Max(0, AIntervals.NvmeHealthSec);
end;

destructor TMHDiskCollector.Destroy;
begin
  FHealth.Free;
  inherited;
end;

function TMHDiskCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHDiskCollector.GetDisplayName: string;
begin
  Result := MHL('Диски', 'Disks');
end;

procedure TMHDiskCollector.Invalidate;
begin
  FDisksUtc := 0;
  FReliabilityUtc := 0;
  FVolumesUtc := 0;
  FNvmeHealthUtc := 0;
  FSmartUtc := 0;
end;

procedure TMHDiskCollector.RefreshHealth(ANvme: Boolean);
var
  LRaw: TMHRawDisk;
  LData: TMHDiskHealthData;
  LError: string;
  LDenied: Boolean;
begin
  if not ANvme then
    FSmartDenied := False;
  for LRaw in FDisks do
  begin
    if SameText(LRaw.Bus, 'NVMe') <> ANvme then
      Continue;
    if FApi.ReadHealth(LRaw.Number, LRaw.Bus, LData, LError, LDenied) then
      FHealth.AddOrSetValue(LRaw.Number, LData)
    else
    begin
      FHealth.Remove(LRaw.Number);
      if LDenied then
        FSmartDenied := True;
    end;
  end;
end;

function TMHDiskCollector.Expired(AUtc, ANow: TDateTime; ASeconds: Integer): Boolean;
begin
  // «Выкл.»: только первое чтение и после Invalidate («Проверить сейчас»).
  if ASeconds <= 0 then
    Exit(AUtc = 0);
  Result := (AUtc = 0) or (ANow < AUtc) or ((ANow - AUtc) * SecsPerDay >= ASeconds);
end;

procedure TMHDiskCollector.RefreshCaches(ANow: TDateTime);
var
  LDisks: TArray<TMHRawDisk>;
  LReliability: TArray<TMHRawReliability>;
  LVolumes: TArray<TMHVolumeInfo>;
  LError: string;
  LDenied: Boolean;
begin
  if Expired(FDisksUtc, ANow, FDiskRefreshSec) then
  begin
    Inc(FReadCount);
    FDisksUtc := ANow;
    if FApi.ReadDisks(LDisks, LError) then
    begin
      FDisks := LDisks;
      FDisksError := '';
    end
    else
      FDisksError := LError; // прежний список остаётся — диски редко меняются
  end;
  if Expired(FReliabilityUtc, ANow, FDiskRefreshSec) then
  begin
    FReliabilityUtc := ANow;
    if FApi.ReadReliability(LReliability, LError, LDenied) then
    begin
      FReliability := LReliability;
      FReliabilityError := '';
      FReliabilityDenied := False;
    end
    else
    begin
      FReliabilityError := LError;
      FReliabilityDenied := LDenied;
    end;
  end;
  if Expired(FNvmeHealthUtc, ANow, FNvmeRefreshSec) then
  begin
    FNvmeHealthUtc := ANow;
    RefreshHealth(True);
  end;
  if Expired(FSmartUtc, ANow, FDiskRefreshSec) then
  begin
    FSmartUtc := ANow;
    RefreshHealth(False);
  end;
  if Expired(FVolumesUtc, ANow, FVolumeRefreshSec) then
  begin
    FVolumesUtc := ANow;
    if FApi.ReadVolumes(LVolumes, LError) then
    begin
      FVolumes := LVolumes;
      FVolumesError := '';
    end
    else
      FVolumesError := LError;
  end;
end;

function TMHDiskCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LCounters: TArray<TMHRawDiskCounter>;
  LCounter: TMHRawDiskCounter;
  LCounterError, LNotes: string;
  LCountersOk: Boolean;
  LDisks: TList<TMHDiskInfo>;
  LRaw: TMHRawDisk;
  LInfo: TMHDiskInfo;
  LRel: TMHRawReliability;
  LReading: TMHSensorReading;
  LVolumes: TArray<TMHVolumeInfo>;
  LLetters: TDictionary<string, Integer>;
  LPart, LNames: string;
  LNumber, I, J: Integer;
  LKnown: TDictionary<Integer, Boolean>;
  LState: TMHSourceState;
  LHealth: TMHDiskHealthData;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  RefreshCaches(LNow);
  LCountersOk := FApi.ReadCounters(LCounters, LCounterError);
  if not LCountersOk then
    LCounters := nil;

  // Разделы: если сведения о расположении на дисках не получены, берём их из имён счётчиков.
  LVolumes := Copy(FVolumes);
  LLetters := TDictionary<string, Integer>.Create;
  LKnown := TDictionary<Integer, Boolean>.Create;
  LDisks := TList<TMHDiskInfo>.Create;
  try
    for LCounter in LCounters do
      for LPart in LCounter.Letters.Split([' '], TStringSplitOptions.ExcludeEmpty) do
        LLetters.AddOrSetValue(UpperCase(LPart), LCounter.Number);
    for I := 0 to High(LVolumes) do
      if (Length(LVolumes[I].DiskNumbers) = 0) and LLetters.TryGetValue(UpperCase(LVolumes[I].Name), LNumber) then
        LVolumes[I].DiskNumbers := [LNumber];

    for LRaw in FDisks do
    begin
      LInfo := TMHDiskInfo.Create(LRaw.Number, LRaw.Model);
      LInfo.Media := LRaw.Media;
      LInfo.Bus := LRaw.Bus;
      LInfo.SizeBytes := LRaw.SizeBytes;
      LInfo.Health := LRaw.Health;
      LInfo.HealthDetails := LRaw.HealthDetails;
      LDisks.Add(LInfo);
      LKnown.AddOrSetValue(LRaw.Number, True);
    end;
    // Диски, которых нет в списке Windows Storage (сбой WMI), — по счётчикам нагрузки.
    for LCounter in LCounters do
      if not LKnown.ContainsKey(LCounter.Number) then
      begin
        LDisks.Add(TMHDiskInfo.Create(LCounter.Number, Format(MHL('Диск %d', 'Disk %d'), [LCounter.Number])));
        LKnown.Add(LCounter.Number, True);
      end;

    for I := 0 to LDisks.Count - 1 do
    begin
      LInfo := LDisks[I];
      for LCounter in LCounters do
        if LCounter.Number = LInfo.Number then
        begin
          LInfo.HasActivity := True;
          LInfo.ActivePercent := EnsureRange(LCounter.ActivePercent, 0, 100);
          LInfo.ReadBytesPerSec := Max(0, LCounter.ReadBytesPerSec);
          LInfo.WriteBytesPerSec := Max(0, LCounter.WriteBytesPerSec);
        end;
      for LRel in FReliability do
        if LRel.Number = LInfo.Number then
        begin
          if LRel.HasTemperature and (LRel.Temperature > 0) and (LRel.Temperature < 150) then
          begin
            LInfo.HasTemperature := True;
            LInfo.TemperatureCelsius := LRel.Temperature;
            // Максимум из счётчиков — предел, указанный производителем (для NVMe — порог предупреждения).
            if (LRel.TemperatureMax > LRel.Temperature) and (LRel.TemperatureMax <= 120) then
              LInfo.TemperatureLimitCelsius := LRel.TemperatureMax;
          end;
          if LRel.HasWear and (LRel.Wear >= 0) and (LRel.Wear <= 255) then
          begin
            LInfo.HasWear := True;
            LInfo.WearPercent := Min(100, LRel.Wear);
          end;
          if LRel.HasErrors then
          begin
            LInfo.HasErrors := True;
            LInfo.ReadErrors := Max(0, LRel.ReadErrors);
            LInfo.WriteErrors := Max(0, LRel.WriteErrors);
          end;
          if LRel.PowerOnHours >= 0 then
            LInfo.PowerOnHours := LRel.PowerOnHours;
        end;
      if FHealth.TryGetValue(LInfo.Number, LHealth) then
        ApplyHealth(LInfo, LHealth);
      // Температура и порог из коллектора датчиков (по модели) — если счётчики надёжности молчат.
      for LReading in ASnapshot.Sensors do
        if (LReading.Kind = skDisk) and SameText(Trim(LReading.Device), Trim(LInfo.Model)) then
        begin
          if not LInfo.HasTemperature then
          begin
            LInfo.HasTemperature := True;
            LInfo.TemperatureCelsius := LReading.Celsius;
          end;
          if LReading.LimitCelsius > 0 then
            LInfo.TemperatureLimitCelsius := LReading.LimitCelsius;
        end;
      LNames := '';
      for J := 0 to High(LVolumes) do
        for LNumber in LVolumes[J].DiskNumbers do
          if LNumber = LInfo.Number then
            LNames := Trim(LNames + ' ' + LVolumes[J].Name);
      LInfo.Volumes := LNames;
      LDisks[I] := LInfo;
    end;
    LDisks.Sort(TComparer<TMHDiskInfo>.Construct(
      function(const A, B: TMHDiskInfo): Integer
      begin
        Result := CompareValue(A.Number, B.Number);
      end));

    LNotes := '';
    LState := ssSuccess;
    if FDisksError <> '' then
    begin
      LState := ssPartial;
      LNotes := LNotes + MHL('Список дисков: ', 'Disk list: ') + FDisksError + '. ';
    end;
    if FReliabilityError <> '' then
    begin
      LState := ssPartial;
      if FReliabilityDenied then
        LNotes := LNotes + MHL('Износ, ошибки и SMART дисков доступны с правами администратора ' +
          '(журнал здоровья NVMe читается и без них). ', 'Disk wear, errors and SMART are available with ' +
          'administrator rights (the NVMe health log is read without them). ')
      else
        LNotes := LNotes + MHL('Износ и ошибки дисков: ', 'Disk wear and errors: ') + FReliabilityError + '. ';
    end;
    if FSmartDenied and not FReliabilityDenied then
    begin
      LState := ssPartial;
      LNotes := LNotes + MHL('SMART дисков SATA доступен с правами администратора. ',
        'SMART of SATA disks is available with administrator rights. ');
    end;
    if FVolumesError <> '' then
    begin
      LState := ssPartial;
      LNotes := LNotes + MHL('Разделы: ', 'Volumes: ') + FVolumesError + '. ';
    end;
    if not LCountersOk then
    begin
      LState := ssPartial;
      LNotes := LNotes + MHL('Нагрузка дисков: ', 'Disk load: ') + LCounterError + '. ';
    end;
    if (LDisks.Count = 0) and (Length(LVolumes) = 0) then
      LState := ssUnavailable;
    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState, Trim(LNotes), LNow));
    Result.Status.RequiresElevation := FReliabilityDenied or FSmartDenied;
    Result.Status.ItemCount := LDisks.Count;
    Result.Disks := LDisks.ToArray;
    Result.Volumes := LVolumes;
  finally
    LDisks.Free;
    LKnown.Free;
    LLetters.Free;
  end;
end;

end.
