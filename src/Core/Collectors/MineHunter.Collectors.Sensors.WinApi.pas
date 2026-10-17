unit MineHunter.Collectors.Sensors.WinApi;

{
  Реализация IMHSensorApi.

  Накопители: \\.\PhysicalDriveN открывается с нулевыми правами доступа
  (достаточно для IOCTL_STORAGE_QUERY_PROPERTY, права администратора не
  нужны); запрашиваются StorageDeviceProperty (модель) и
  StorageDeviceTemperatureProperty (winioctl.h, Windows 10+). Накопители без
  поддержки температуры пропускаются. Опрос — не чаще раза в DISK_REFRESH_MS.

  Процессор: WMI root\LibreHardwareMonitor или root\OpenHardwareMonitor
  (класс Sensor, SensorType = 'Temperature', идентификатор …cpu/…). Работает,
  только если пользователь сам запустил одну из этих программ; MineHunter
  их не устанавливает и драйверов не загружает. Опрос — не чаще раза в
  CPU_REFRESH_MS; объекты COM живут только внутри вызова.
}

interface

uses
  MineHunter.Collectors.Sensors;

type
  TMHWinSensorApi = class(TInterfacedObject, IMHSensorApi)
  private
    FDiskTick: UInt64;
    FDisks: TArray<TMHTemperatureReading>;
    FDiskReason: string;
    FCpuTick: UInt64;
    FCpu: TArray<TMHTemperatureReading>;
    FCpuReason: string;
    procedure RefreshDisks;
    procedure RefreshCpu;
    class function QueryHardwareMonitor(const ANamespace, ASource: string): TArray<TMHTemperatureReading>; static;
  public
    function ReadDiskTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
    function ReadCpuTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
  end;

implementation

uses
  Winapi.Windows, Winapi.ActiveX, System.SysUtils, System.Variants, System.Win.ComObj,
  System.Generics.Collections;

const
  DISK_REFRESH_MS = 60 * 1000;
  CPU_REFRESH_MS = 10 * 1000;
  MAX_PHYSICAL_DRIVES = 16;
  // CTL_CODE(IOCTL_STORAGE_BASE = 0x2D, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
  IOCTL_STORAGE_QUERY_PROPERTY = $002D1400;
  StorageDeviceProperty = 0;
  StorageDeviceTemperatureProperty = 52;
  PropertyStandardQuery = 0;
  wbemFlagForwardOnly = $00000020;

type
  TStoragePropertyQuery = record
    PropertyId: Integer;
    QueryType: Integer;
    AdditionalParameters: array[0..0] of Byte;
  end;

  TStorageDeviceDescriptor = record
    Version: DWORD;
    Size: DWORD;
    DeviceType: Byte;
    DeviceTypeModifier: Byte;
    RemovableMedia: Boolean;
    CommandQueueing: Boolean;
    VendorIdOffset: DWORD;
    ProductIdOffset: DWORD;
    ProductRevisionOffset: DWORD;
    SerialNumberOffset: DWORD;
    BusType: Integer;
    RawPropertiesLength: DWORD;
  end;

  TStorageTemperatureInfo = record
    Index: Word;
    Temperature: SmallInt;
    OverThreshold: SmallInt;
    UnderThreshold: SmallInt;
    OverThresholdChangable: Boolean;
    UnderThresholdChangable: Boolean;
    EventGenerated: Boolean;
    Reserved0: Byte;
    Reserved1: DWORD;
  end;

  TStorageTemperatureDataDescriptor = record
    Version: DWORD;
    Size: DWORD;
    CriticalTemperature: SmallInt;
    WarningTemperature: SmallInt;
    InfoCount: Word;
    Reserved0: array[0..1] of Byte;
    Reserved1: array[0..1] of DWORD;
    // далее TemperatureInfo[InfoCount]
  end;

{$IF SizeOf(TStoragePropertyQuery) <> 12}
  {$MESSAGE ERROR 'STORAGE_PROPERTY_QUERY: неверный размер'}
{$IFEND}
{$IF SizeOf(TStorageTemperatureInfo) <> 16}
  {$MESSAGE ERROR 'STORAGE_TEMPERATURE_INFO: неверный размер'}
{$IFEND}
{$IF SizeOf(TStorageTemperatureDataDescriptor) <> 24}
  {$MESSAGE ERROR 'STORAGE_TEMPERATURE_DATA_DESCRIPTOR: неверный размер'}
{$IFEND}

function QueryProperty(ADevice: THandle; APropertyId: Integer; var ABuffer: TBytes): Boolean;
var
  LQuery: TStoragePropertyQuery;
  LReturned: DWORD;
begin
  FillChar(LQuery, SizeOf(LQuery), 0);
  LQuery.PropertyId := APropertyId;
  LQuery.QueryType := PropertyStandardQuery;
  FillChar(ABuffer[0], Length(ABuffer), 0);
  Result := DeviceIoControl(ADevice, IOCTL_STORAGE_QUERY_PROPERTY, @LQuery, SizeOf(LQuery),
    @ABuffer[0], Length(ABuffer), LReturned, nil) and (LReturned >= 8);
end;

function AnsiAt(const ABuffer: TBytes; AOffset: DWORD): string;
var
  LEnd: Integer;
begin
  Result := '';
  if (AOffset = 0) or (AOffset >= DWORD(Length(ABuffer))) then
    Exit;
  LEnd := AOffset;
  while (LEnd < Length(ABuffer)) and (ABuffer[LEnd] <> 0) do
    Inc(LEnd);
  Result := Trim(TEncoding.ANSI.GetString(ABuffer, AOffset, LEnd - Integer(AOffset)));
end;

{ TMHWinSensorApi }

procedure TMHWinSensorApi.RefreshDisks;
var
  LList: TList<TMHTemperatureReading>;
  LReading: TMHTemperatureReading;
  LDevice: THandle;
  LBuffer: TBytes;
  LDescriptor: TStorageDeviceDescriptor;
  LTemperature: TStorageTemperatureDataDescriptor;
  LInfo: TStorageTemperatureInfo;
  LName: string;
  I, J: Integer;
  LFound, LOpened: Integer;
  LMax: SmallInt;
begin
  LList := TList<TMHTemperatureReading>.Create;
  try
    LFound := 0;
    LOpened := 0;
    SetLength(LBuffer, 4096);
    for I := 0 to MAX_PHYSICAL_DRIVES - 1 do
    begin
      LDevice := CreateFile(PChar('\\.\PhysicalDrive' + IntToStr(I)), 0,
        FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
      if LDevice = INVALID_HANDLE_VALUE then
        Continue;
      Inc(LOpened);
      try
        LName := Format('Диск %d', [I]);
        if QueryProperty(LDevice, StorageDeviceProperty, LBuffer) and
           (Length(LBuffer) >= SizeOf(LDescriptor)) then
        begin
          Move(LBuffer[0], LDescriptor, SizeOf(LDescriptor));
          if AnsiAt(LBuffer, LDescriptor.ProductIdOffset) <> '' then
            LName := Trim(AnsiAt(LBuffer, LDescriptor.VendorIdOffset) + ' ' +
              AnsiAt(LBuffer, LDescriptor.ProductIdOffset));
        end;
        if not QueryProperty(LDevice, StorageDeviceTemperatureProperty, LBuffer) then
          Continue;
        Move(LBuffer[0], LTemperature, SizeOf(LTemperature));
        if LTemperature.InfoCount = 0 then
          Continue;
        // Самый горячий датчик накопителя (индекс 0 часто — сводное значение).
        LMax := Low(SmallInt);
        for J := 0 to Integer(LTemperature.InfoCount) - 1 do
        begin
          if SizeOf(LTemperature) + (J + 1) * SizeOf(LInfo) > Length(LBuffer) then
            Break;
          Move(LBuffer[SizeOf(LTemperature) + J * SizeOf(LInfo)], LInfo, SizeOf(LInfo));
          if LInfo.Temperature > LMax then
            LMax := LInfo.Temperature;
        end;
        if (LMax <= 0) or (LMax >= 150) then
          Continue;
        LReading := Default(TMHTemperatureReading);
        LReading.Device := LName;
        LReading.Source := 'storage';
        LReading.Celsius := LMax;
        if (LTemperature.WarningTemperature > 0) and (LTemperature.WarningTemperature < 150) then
        begin
          LReading.HasWarning := True;
          LReading.WarningCelsius := LTemperature.WarningTemperature;
        end;
        LList.Add(LReading);
        Inc(LFound);
      finally
        CloseHandle(LDevice);
      end;
    end;
    FDisks := LList.ToArray;
    if LFound > 0 then
      FDiskReason := ''
    else if LOpened = 0 then
      FDiskReason := 'накопители недоступны'
    else
      FDiskReason := 'накопители не сообщают температуру';
  finally
    LList.Free;
  end;
end;

class function TMHWinSensorApi.QueryHardwareMonitor(const ANamespace,
  ASource: string): TArray<TMHTemperatureReading>;
var
  LLocator, LService, LObjects, LItem, LValue: OleVariant;
  LEnum: IEnumVARIANT;
  LFetched: LongWord;
  LList: TList<TMHTemperatureReading>;
  LReading: TMHTemperatureReading;
  LIdentifier: string;
begin
  Result := nil;
  LList := TList<TMHTemperatureReading>.Create;
  try
    LLocator := CreateOleObject('WbemScripting.SWbemLocator');
    LService := LLocator.ConnectServer('.', ANamespace);
    LObjects := LService.ExecQuery(
      'SELECT Name, Value, Identifier FROM Sensor WHERE SensorType=''Temperature''',
      'WQL', wbemFlagForwardOnly);
    LEnum := IUnknown(LObjects._NewEnum) as IEnumVARIANT;
    while LEnum.Next(1, LItem, LFetched) = S_OK do
    begin
      LValue := LItem.Identifier;
      LIdentifier := LowerCase(VarToStr(LValue));
      // /intelcpu/0/temperature/…, /amdcpu/0/temperature/…
      if LIdentifier.Contains('cpu/') then
      begin
        LReading := Default(TMHTemperatureReading);
        LReading.Source := ASource;
        LValue := LItem.Name;
        LReading.Device := VarToStr(LValue);
        LValue := LItem.Value;
        if not VarIsNull(LValue) and not VarIsEmpty(LValue) then
        begin
          LReading.Celsius := Double(LValue);
          LList.Add(LReading);
        end;
      end;
      LItem := Unassigned;
    end;
    Result := LList.ToArray;
  finally
    LValue := Unassigned;
    LItem := Unassigned;
    LEnum := nil;
    LObjects := Unassigned;
    LService := Unassigned;
    LLocator := Unassigned;
    LList.Free;
  end;
end;

procedure TMHWinSensorApi.RefreshCpu;
var
  LInit: HResult;
begin
  FCpu := nil;
  LInit := CoInitializeEx(nil, COINIT_MULTITHREADED);
  if Failed(LInit) and (LInit <> RPC_E_CHANGED_MODE) then
  begin
    FCpuReason := Format('не удалось инициализировать COM (0x%.8x)', [Cardinal(LInit)]);
    Exit;
  end;
  try
    try
      FCpu := QueryHardwareMonitor('root\LibreHardwareMonitor', 'LibreHardwareMonitor');
    except
      // Пространства имён нет — программа не запущена; пробуем OpenHardwareMonitor.
      FCpu := nil;
    end;
    if Length(FCpu) = 0 then
      try
        FCpu := QueryHardwareMonitor('root\OpenHardwareMonitor', 'OpenHardwareMonitor');
      except
        FCpu := nil;
      end;
    if Length(FCpu) > 0 then
      FCpuReason := ''
    else
      FCpuReason := 'Windows не сообщает температуру ядер без драйвера; запустите ' +
        'LibreHardwareMonitor, чтобы MineHunter получил её';
  finally
    if Succeeded(LInit) then
      CoUninitialize;
  end;
end;

function TMHWinSensorApi.ReadDiskTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
var
  LNow: UInt64;
begin
  LNow := GetTickCount64;
  if (FDiskTick = 0) or (LNow - FDiskTick >= DISK_REFRESH_MS) then
  begin
    FDiskTick := LNow;
    try
      RefreshDisks;
    except
      on E: Exception do
      begin
        FDisks := nil;
        FDiskReason := 'ошибка опроса накопителей: ' + E.Message;
      end;
    end;
  end;
  AReason := FDiskReason;
  Result := FDisks;
end;

function TMHWinSensorApi.ReadCpuTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
var
  LNow: UInt64;
begin
  LNow := GetTickCount64;
  if (FCpuTick = 0) or (LNow - FCpuTick >= CPU_REFRESH_MS) then
  begin
    FCpuTick := LNow;
    try
      RefreshCpu;
    except
      on E: Exception do
      begin
        FCpu := nil;
        FCpuReason := 'ошибка опроса датчиков процессора: ' + E.Message;
      end;
    end;
  end;
  AReason := FCpuReason;
  Result := FCpu;
end;

end.
