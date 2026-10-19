unit MineHunter.Collectors.Disks.WinApi;

{
  IMHDiskApi для Windows.
  - Диски: WMI root\Microsoft\Windows\Storage, класс MSFT_PhysicalDisk
    (DeviceId = номер диска, MediaType 3 — HDD, 4 — SSD, BusType, HealthStatus
    0/1/2 — исправен/предупреждение/неисправен, OperationalStatus). Состояние
    учитывает прогноз отказа SMART.
  - Надёжность: MSFT_StorageReliabilityCounter через связь с диском
    (Associators_ — без ручного экранирования ObjectId). Обычно требует прав
    администратора.
  - Нагрузка: счётчики PhysicalDisk(*) — % Idle Time (занятость = 100 − простой),
    Disk Read/Write Bytes/sec; имя экземпляра «N c: d:» даёт номер и буквы.
  - Разделы: GetLogicalDriveStrings, GetDriveType (локальные и съёмные),
    GetVolumeInformation, GetDiskFreeSpaceEx, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
    Диалоги «вставьте диск» подавляются (SEM_FAILCRITICALERRORS).
  - Здоровье: NVMe — журнал Log Page 02h через IOCTL_STORAGE_QUERY_PROPERTY
    (StorageDeviceProtocolSpecificProperty; диск открывается без доступа к данным,
    права администратора не нужны); SATA — SMART_RCV_DRIVE_DATA (READ DATA и READ
    THRESHOLDS; диск открывается на чтение и запись — только администратор).
  WMI-запросы выполняются в потоке сканера с CoInitializeEx на время вызова.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types, MineHunter.Collectors.Disks, MineHunter.Collectors.Pdh,
  MineHunter.Collectors.DiskHealth;

type
  TMHWinDiskApi = class(TInterfacedObject, IMHDiskApi)
  private
    FPdh: TMHPdhQuery;
    FIdle, FRead, FWrite: THandle;
    FCounterError: string;
  public
    constructor Create;
    destructor Destroy; override;
    function ReadDisks(out ADisks: TArray<TMHRawDisk>; out AError: string): Boolean;
    function ReadReliability(out AItems: TArray<TMHRawReliability>; out AError: string;
      out AAccessDenied: Boolean): Boolean;
    function ReadVolumes(out AVolumes: TArray<TMHVolumeInfo>; out AError: string): Boolean;
    function ReadCounters(out ACounters: TArray<TMHRawDiskCounter>; out AError: string): Boolean;
    function ReadHealth(ANumber: Integer; const ABus: string; out AData: TMHDiskHealthData;
      out AError: string; out AAccessDenied: Boolean): Boolean;
  end;

/// Шина по коду BusType из MSFT_PhysicalDisk.
function MHBusTypeName(ACode: Integer): string;

implementation

uses
  Winapi.Windows, Winapi.ActiveX, System.Variants, System.Win.ComObj, System.Generics.Collections,
  System.Math, System.StrUtils, MineHunter.Core.Lang;

const
  WBEM_E_ACCESS_DENIED = HRESULT($80041003);
  wbemFlagForwardOnly = $20;
  STORAGE_NAMESPACE = 'root\Microsoft\Windows\Storage';
  IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = $00560000;
  MAX_EXTENTS = 32;
  IOCTL_STORAGE_QUERY_PROPERTY = $002D1400;
  SMART_RCV_DRIVE_DATA = $0007C088;
  STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY = 50;
  PROTOCOL_TYPE_NVME = 3;
  NVME_DATA_TYPE_LOG_PAGE = 2;
  NVME_LOG_PAGE_HEALTH_INFO = 2;
  /// STORAGE_PROPERTY_QUERY до AdditionalParameters и размер STORAGE_PROTOCOL_SPECIFIC_DATA.
  PROPERTY_QUERY_HEADER = 8;
  PROTOCOL_SPECIFIC_DATA_SIZE = 40;
  SMART_READ_ATTRIBUTES = $D0;
  SMART_READ_THRESHOLDS = $D1;
  /// SENDCMDINPARAMS (упаковка 1 байт) и заголовок SENDCMDOUTPARAMS до bBuffer.
  SENDCMD_IN_SIZE = 33;
  SENDCMD_OUT_HEADER = 16;

type
  TDiskExtent = record
    DiskNumber: DWORD;
    StartingOffset: Int64;
    ExtentLength: Int64;
  end;

  TVolumeDiskExtents = record
    NumberOfDiskExtents: DWORD;
    Extents: array[0..MAX_EXTENTS - 1] of TDiskExtent;
  end;

function OpenPhysicalDrive(ANumber: Integer; AAccess: DWORD): THandle;
begin
  Result := CreateFile(PChar(Format('\\.\PhysicalDrive%d', [ANumber])), AAccess,
    FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
end;

/// Журнал здоровья NVMe: запрос — STORAGE_PROPERTY_QUERY с STORAGE_PROTOCOL_SPECIFIC_DATA,
/// ответ — STORAGE_PROTOCOL_DATA_DESCRIPTOR (Version, Size, та же структура и данные журнала).
function ReadNvmeHealthLog(AHandle: THandle; out ALog: TBytes; out AError: string): Boolean;
var
  LBuffer: TBytes;
  LReturned, LOffset, LLength: DWORD;
begin
  ALog := nil;
  SetLength(LBuffer, PROPERTY_QUERY_HEADER + PROTOCOL_SPECIFIC_DATA_SIZE + MH_HEALTH_LOG_SIZE);
  FillChar(LBuffer[0], Length(LBuffer), 0);
  PDWORD(@LBuffer[0])^ := STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY; // PropertyId
  PDWORD(@LBuffer[4])^ := 0;                                         // PropertyStandardQuery
  PDWORD(@LBuffer[8])^ := PROTOCOL_TYPE_NVME;                        // ProtocolType
  PDWORD(@LBuffer[12])^ := NVME_DATA_TYPE_LOG_PAGE;                  // DataType
  PDWORD(@LBuffer[16])^ := NVME_LOG_PAGE_HEALTH_INFO;                // ProtocolDataRequestValue
  PDWORD(@LBuffer[24])^ := PROTOCOL_SPECIFIC_DATA_SIZE;              // ProtocolDataOffset
  PDWORD(@LBuffer[28])^ := MH_HEALTH_LOG_SIZE;                       // ProtocolDataLength
  LReturned := 0;
  if not DeviceIoControl(AHandle, IOCTL_STORAGE_QUERY_PROPERTY, @LBuffer[0], Length(LBuffer),
    @LBuffer[0], Length(LBuffer), LReturned, nil) then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit(False);
  end;
  LOffset := PDWORD(@LBuffer[PROPERTY_QUERY_HEADER + 16])^;
  LLength := PDWORD(@LBuffer[PROPERTY_QUERY_HEADER + 20])^;
  if (LLength < MH_HEALTH_LOG_SIZE) or
     (UInt64(PROPERTY_QUERY_HEADER) + LOffset + MH_HEALTH_LOG_SIZE > UInt64(Length(LBuffer))) or
     (UInt64(LReturned) < UInt64(PROPERTY_QUERY_HEADER) + LOffset + MH_HEALTH_LOG_SIZE) then
  begin
    AError := MHL('диск вернул неполный журнал здоровья', 'the disk returned an incomplete health log');
    Exit(False);
  end;
  ALog := Copy(LBuffer, PROPERTY_QUERY_HEADER + Integer(LOffset), MH_HEALTH_LOG_SIZE);
  Result := True;
end;

/// Команда SMART (READ DATA или READ THRESHOLDS): 512 байт данных.
function SmartCommand(AHandle: THandle; AFeature: Byte; out AData: TBytes): Boolean;
var
  LIn: array[0..SENDCMD_IN_SIZE - 1] of Byte;
  LOut: TBytes;
  LReturned: DWORD;
begin
  AData := nil;
  FillChar(LIn, SizeOf(LIn), 0);
  PDWORD(@LIn[0])^ := MH_HEALTH_LOG_SIZE; // cBufferSize
  LIn[4] := AFeature;                     // bFeaturesReg
  LIn[5] := 1;                            // bSectorCountReg
  LIn[6] := 1;                            // bSectorNumberReg
  LIn[7] := $4F;                          // bCylLowReg — сигнатура SMART
  LIn[8] := $C2;                          // bCylHighReg
  LIn[9] := $A0;                          // bDriveHeadReg
  LIn[10] := $B0;                         // bCommandReg — SMART
  SetLength(LOut, SENDCMD_OUT_HEADER + MH_HEALTH_LOG_SIZE);
  FillChar(LOut[0], Length(LOut), 0);
  LReturned := 0;
  Result := DeviceIoControl(AHandle, SMART_RCV_DRIVE_DATA, @LIn[0], SizeOf(LIn), @LOut[0], Length(LOut),
    LReturned, nil) and (LReturned > SENDCMD_OUT_HEADER);
  if Result then
    AData := Copy(LOut, SENDCMD_OUT_HEADER, MH_HEALTH_LOG_SIZE);
end;

function MHBusTypeName(ACode: Integer): string;
begin
  case ACode of
    1: Result := 'SCSI';
    2: Result := 'ATAPI';
    3: Result := 'ATA';
    4: Result := 'IEEE 1394';
    5: Result := 'SSA';
    6: Result := 'Fibre Channel';
    7: Result := 'USB';
    8: Result := 'RAID';
    9: Result := 'iSCSI';
    10: Result := 'SAS';
    11: Result := 'SATA';
    12: Result := 'SD';
    13: Result := 'MMC';
    15: Result := 'File-backed';
    16: Result := 'Storage Spaces';
    17: Result := 'NVMe';
  else
    Result := '';
  end;
end;

function VarToInt64Def(const AValue: OleVariant; ADefault: Int64): Int64;
begin
  if VarIsNull(AValue) or VarIsEmpty(AValue) then
    Exit(ADefault);
  try
    Result := AValue;
  except
    Result := ADefault;
  end;
end;

function VarToStrSafe(const AValue: OleVariant): string;
begin
  if VarIsNull(AValue) or VarIsEmpty(AValue) then
    Result := ''
  else
    Result := Trim(VarToStr(AValue));
end;

/// Выполняет AProc с инициализированным COM; ошибки WMI — в AError.
function WithCom(const AProc: TProc; out AError: string; out AAccessDenied: Boolean): Boolean;
var
  LInit: HResult;
begin
  AError := '';
  AAccessDenied := False;
  LInit := CoInitializeEx(nil, COINIT_MULTITHREADED);
  if Failed(LInit) and (LInit <> RPC_E_CHANGED_MODE) then
  begin
    AError := Format(MHL('не удалось инициализировать COM (0x%.8x)', 'could not initialize COM (0x%.8x)'),
      [Cardinal(LInit)]);
    Exit(False);
  end;
  try
    try
      AProc();
      Result := True;
    except
      on E: EOleException do
      begin
        AAccessDenied := (E.ErrorCode = WBEM_E_ACCESS_DENIED) or (E.ErrorCode = E_ACCESSDENIED);
        if AAccessDenied then
          AError := MHL('нужны права администратора', 'administrator rights are required')
        else
          AError := 'WMI: ' + E.Message;
        Result := False;
      end;
      on E: Exception do
      begin
        AError := 'WMI: ' + E.Message;
        Result := False;
      end;
    end;
  finally
    if Succeeded(LInit) then
      CoUninitialize;
  end;
end;

function OperationalText(const AValue: OleVariant): string;
var
  I, LCode: Integer;
  LText: string;
begin
  // OperationalStatus — массив кодов; 2 (OK) не показываем.
  Result := '';
  if not VarIsArray(AValue) then
    Exit;
  for I := VarArrayLowBound(AValue, 1) to VarArrayHighBound(AValue, 1) do
  begin
    LCode := VarToInt64Def(AValue[I], 0);
    case LCode of
      3: LText := MHL('деградация', 'degraded');
      5: LText := MHL('прогнозируется отказ', 'predictive failure');
      6: LText := MHL('ошибка', 'error');
      10: LText := MHL('остановлен', 'stopped');
      13: LText := MHL('потеря связи', 'lost communication');
      $D00A: LText := MHL('ошибка передачи данных', 'transient error');
      $D00D: LText := MHL('удалён', 'removed');
    else
      LText := '';
    end;
    if LText <> '' then
      Result := Trim(Result + IfThen(Result <> '', ', ', '') + LText);
  end;
end;

{ TMHWinDiskApi }

function TMHWinDiskApi.ReadHealth(ANumber: Integer; const ABus: string; out AData: TMHDiskHealthData;
  out AError: string; out AAccessDenied: Boolean): Boolean;
var
  LHandle: THandle;
  LLog, LValues, LThresholds: TBytes;
  LCode: DWORD;
begin
  AError := '';
  AAccessDenied := False;
  AData := TMHDiskHealthData.Create('');
  if SameText(ABus, 'NVMe') then
  begin
    // Запрос свойства устройства: доступ к данным диска не нужен.
    LHandle := OpenPhysicalDrive(ANumber, 0);
    if LHandle = INVALID_HANDLE_VALUE then
    begin
      AError := SysErrorMessage(GetLastError);
      Exit(False);
    end;
    try
      Result := ReadNvmeHealthLog(LHandle, LLog, AError) and MHParseNvmeHealthLog(LLog, AData);
    finally
      CloseHandle(LHandle);
    end;
  end
  else if SameText(ABus, 'SATA') or SameText(ABus, 'ATA') then
  begin
    // Команды SMART требуют открыть диск на чтение и запись — только с правами администратора.
    LHandle := OpenPhysicalDrive(ANumber, GENERIC_READ or GENERIC_WRITE);
    if LHandle = INVALID_HANDLE_VALUE then
    begin
      LCode := GetLastError;
      AAccessDenied := LCode = ERROR_ACCESS_DENIED;
      AError := SysErrorMessage(LCode);
      Exit(False);
    end;
    try
      if not SmartCommand(LHandle, SMART_READ_ATTRIBUTES, LValues) then
      begin
        AError := SysErrorMessage(GetLastError);
        Exit(False);
      end;
      if not SmartCommand(LHandle, SMART_READ_THRESHOLDS, LThresholds) then
        LThresholds := nil;
      Result := MHParseAtaSmart(LValues, LThresholds, AData);
    finally
      CloseHandle(LHandle);
    end;
  end
  else
    // USB, RAID и другие шины: команды через мост не отправляются.
    Result := False;
end;

constructor TMHWinDiskApi.Create;
begin
  inherited Create;
  FPdh := TMHPdhQuery.Create;
  FIdle := FPdh.AddCounter('\PhysicalDisk(*)\% Idle Time');
  FRead := FPdh.AddCounter('\PhysicalDisk(*)\Disk Read Bytes/sec');
  FWrite := FPdh.AddCounter('\PhysicalDisk(*)\Disk Write Bytes/sec');
  if (FIdle = 0) or (FRead = 0) or (FWrite = 0) then
    FCounterError := FPdh.LastError;
  FPdh.Collect; // первый замер: значения появятся со следующего
end;

destructor TMHWinDiskApi.Destroy;
begin
  FPdh.Free;
  inherited;
end;

function TMHWinDiskApi.ReadDisks(out ADisks: TArray<TMHRawDisk>; out AError: string): Boolean;
var
  LList: TList<TMHRawDisk>;
  LDenied: Boolean;
begin
  ADisks := nil;
  LList := TList<TMHRawDisk>.Create;
  try
    Result := WithCom(
      procedure
      var
        LLocator, LService, LObjects, LItem: OleVariant;
        LEnum: IEnumVARIANT;
        LFetched: LongWord;
        LDisk: TMHRawDisk;
      begin
        LLocator := CreateOleObject('WbemScripting.SWbemLocator');
        LService := LLocator.ConnectServer('.', STORAGE_NAMESPACE);
        LObjects := LService.ExecQuery('SELECT DeviceId, FriendlyName, Model, MediaType, BusType, Size, ' +
          'HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk', 'WQL', wbemFlagForwardOnly);
        LEnum := IUnknown(LObjects._NewEnum) as IEnumVARIANT;
        while LEnum.Next(1, LItem, LFetched) = S_OK do
        begin
          LDisk := Default(TMHRawDisk);
          LDisk.Number := StrToIntDef(VarToStrSafe(LItem.DeviceId), -1);
          if LDisk.Number < 0 then
            Continue;
          LDisk.Model := VarToStrSafe(LItem.FriendlyName);
          if LDisk.Model = '' then
            LDisk.Model := VarToStrSafe(LItem.Model);
          case VarToInt64Def(LItem.MediaType, 0) of
            3: LDisk.Media := dmHdd;
            4: LDisk.Media := dmSsd;
          else
            LDisk.Media := dmUnknown;
          end;
          LDisk.Bus := MHBusTypeName(VarToInt64Def(LItem.BusType, 0));
          LDisk.SizeBytes := VarToInt64Def(LItem.Size, 0);
          case VarToInt64Def(LItem.HealthStatus, 5) of
            0: LDisk.Health := dhHealthy;
            1: LDisk.Health := dhWarning;
            2: LDisk.Health := dhUnhealthy;
          else
            LDisk.Health := dhUnknown;
          end;
          LDisk.HealthDetails := OperationalText(LItem.OperationalStatus);
          LList.Add(LDisk);
          LItem := Unassigned;
        end;
      end, AError, LDenied);
    if Result then
      ADisks := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TMHWinDiskApi.ReadReliability(out AItems: TArray<TMHRawReliability>; out AError: string;
  out AAccessDenied: Boolean): Boolean;
var
  LList: TList<TMHRawReliability>;
begin
  AItems := nil;
  LList := TList<TMHRawReliability>.Create;
  try
    Result := WithCom(
      procedure
      var
        LLocator, LService, LDisks, LDisk, LCounters, LCounter: OleVariant;
        LEnum, LInner: IEnumVARIANT;
        LFetched: LongWord;
        LItem: TMHRawReliability;
      begin
        LLocator := CreateOleObject('WbemScripting.SWbemLocator');
        LService := LLocator.ConnectServer('.', STORAGE_NAMESPACE);
        LDisks := LService.ExecQuery('SELECT * FROM MSFT_PhysicalDisk', 'WQL', wbemFlagForwardOnly);
        LEnum := IUnknown(LDisks._NewEnum) as IEnumVARIANT;
        while LEnum.Next(1, LDisk, LFetched) = S_OK do
        begin
          LItem := Default(TMHRawReliability);
          LItem.Number := StrToIntDef(VarToStrSafe(LDisk.DeviceId), -1);
          LItem.PowerOnHours := -1;
          if LItem.Number >= 0 then
          begin
            LCounters := LDisk.Associators_('MSFT_PhysicalDiskToStorageReliabilityCounter');
            LInner := IUnknown(LCounters._NewEnum) as IEnumVARIANT;
            if LInner.Next(1, LCounter, LFetched) = S_OK then
            begin
              // Нулевые значения у многих дисков означают «не поддерживается».
              LItem.Temperature := VarToInt64Def(LCounter.Temperature, 0);
              LItem.TemperatureMax := VarToInt64Def(LCounter.TemperatureMax, 0);
              LItem.HasTemperature := LItem.Temperature > 0;
              LItem.HasWear := not VarIsNull(LCounter.Wear);
              LItem.Wear := VarToInt64Def(LCounter.Wear, 0);
              LItem.HasErrors := not VarIsNull(LCounter.ReadErrorsTotal) or not VarIsNull(LCounter.WriteErrorsTotal);
              LItem.ReadErrors := VarToInt64Def(LCounter.ReadErrorsTotal, 0);
              LItem.WriteErrors := VarToInt64Def(LCounter.WriteErrorsTotal, 0);
              LItem.PowerOnHours := VarToInt64Def(LCounter.PowerOnHours, -1);
              LList.Add(LItem);
            end;
            LCounter := Unassigned;
            LCounters := Unassigned;
          end;
          LDisk := Unassigned;
        end;
      end, AError, AAccessDenied);
    if Result then
      AItems := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TMHWinDiskApi.ReadVolumes(out AVolumes: TArray<TMHVolumeInfo>; out AError: string): Boolean;
var
  LBuffer: array[0..1023] of Char;
  LLength: DWORD;
  LRoot: PChar;
  LList: TList<TMHVolumeInfo>;
  LVolume: TMHVolumeInfo;
  LType: UINT;
  LLabel, LFs: array[0..MAX_PATH] of Char;
  LSerial, LMaxLen, LFlags: DWORD;
  LFree, LTotal, LTotalFree: Int64;
  LOldMode: UINT;
  LHandle: THandle;
  LExtents: TVolumeDiskExtents;
  LReturned: DWORD;
  LWinDir: array[0..MAX_PATH] of Char;
  LSystemDrive: string;
  I: Integer;
begin
  AVolumes := nil;
  AError := '';
  LLength := GetLogicalDriveStrings(Length(LBuffer) - 1, LBuffer);
  if (LLength = 0) or (LLength > DWORD(Length(LBuffer))) then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit(False);
  end;
  SetString(LSystemDrive, LWinDir, GetWindowsDirectory(LWinDir, MAX_PATH));
  LSystemDrive := UpperCase(Copy(LSystemDrive, 1, 2));
  LList := TList<TMHVolumeInfo>.Create;
  LOldMode := SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOOPENFILEERRORBOX);
  try
    LRoot := @LBuffer[0];
    while LRoot^ <> #0 do
    begin
      LType := GetDriveType(LRoot);
      if (LType = DRIVE_FIXED) or (LType = DRIVE_REMOVABLE) then
      begin
        LVolume := Default(TMHVolumeInfo);
        LVolume.Name := UpperCase(Copy(string(LRoot), 1, 2));
        LVolume.Removable := LType = DRIVE_REMOVABLE;
        LVolume.IsSystem := SameText(LVolume.Name, LSystemDrive);
        // Носитель не вставлен (кардридер) — раздел пропускается.
        if GetDiskFreeSpaceEx(LRoot, LFree, LTotal, @LTotalFree) then
        begin
          LVolume.TotalBytes := LTotal;
          LVolume.FreeBytes := LTotalFree;
          FillChar(LLabel, SizeOf(LLabel), 0);
          FillChar(LFs, SizeOf(LFs), 0);
          if GetVolumeInformation(LRoot, LLabel, Length(LLabel), @LSerial, LMaxLen, LFlags, LFs, Length(LFs)) then
          begin
            LVolume.VolumeLabel := string(PChar(@LLabel[0]));
            LVolume.FileSystem := string(PChar(@LFs[0]));
          end;
          LHandle := CreateFile(PChar('\\.\' + LVolume.Name), 0, FILE_SHARE_READ or FILE_SHARE_WRITE, nil,
            OPEN_EXISTING, 0, 0);
          if LHandle <> INVALID_HANDLE_VALUE then
          try
            FillChar(LExtents, SizeOf(LExtents), 0);
            if DeviceIoControl(LHandle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nil, 0, @LExtents,
              SizeOf(LExtents), LReturned, nil) then
              for I := 0 to Min(Integer(LExtents.NumberOfDiskExtents), MAX_EXTENTS) - 1 do
                LVolume.DiskNumbers := LVolume.DiskNumbers + [Integer(LExtents.Extents[I].DiskNumber)];
          finally
            CloseHandle(LHandle);
          end;
          LList.Add(LVolume);
        end;
      end;
      Inc(LRoot, StrLen(LRoot) + 1);
    end;
    AVolumes := LList.ToArray;
    Result := True;
  finally
    SetErrorMode(LOldMode);
    LList.Free;
  end;
end;

function TMHWinDiskApi.ReadCounters(out ACounters: TArray<TMHRawDiskCounter>; out AError: string): Boolean;
var
  LIdle, LRead, LWrite: TArray<TMHPdhItem>;
  LItems: TDictionary<string, TMHRawDiskCounter>;
  LItem: TMHPdhItem;
  LCounter: TMHRawDiskCounter;
  LNumber: Integer;
  LLetters: string;
begin
  ACounters := nil;
  AError := FCounterError;
  if FCounterError <> '' then
    Exit(False);
  if not FPdh.Collect or not FPdh.ReadArray(FIdle, LIdle) then
  begin
    AError := FPdh.LastError;
    Exit(False);
  end;
  FPdh.ReadArray(FRead, LRead);
  FPdh.ReadArray(FWrite, LWrite);
  LItems := TDictionary<string, TMHRawDiskCounter>.Create;
  try
    for LItem in LIdle do
      if MHParseDiskInstance(LItem.Name, LNumber, LLetters) then
      begin
        LCounter := Default(TMHRawDiskCounter);
        LCounter.Number := LNumber;
        LCounter.Letters := LLetters;
        LCounter.ActivePercent := EnsureRange(100 - LItem.Value, 0, 100);
        LItems.AddOrSetValue(LItem.Name, LCounter);
      end;
    for LItem in LRead do
      if LItems.TryGetValue(LItem.Name, LCounter) then
      begin
        LCounter.ReadBytesPerSec := LItem.Value;
        LItems[LItem.Name] := LCounter;
      end;
    for LItem in LWrite do
      if LItems.TryGetValue(LItem.Name, LCounter) then
      begin
        LCounter.WriteBytesPerSec := LItem.Value;
        LItems[LItem.Name] := LCounter;
      end;
    ACounters := LItems.Values.ToArray;
    Result := True;
  finally
    LItems.Free;
  end;
end;

end.
