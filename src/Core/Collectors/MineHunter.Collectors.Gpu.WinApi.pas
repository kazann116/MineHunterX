unit MineHunter.Collectors.Gpu.WinApi;

{
  Реализация IMHGpuApi.

  Загрузка и видеопамять — счётчики производительности Windows (PDH):
    \GPU Engine(*)\Utilization Percentage,
    \GPU Process Memory(*)\Dedicated Usage,
    \GPU Adapter Memory(*)\Dedicated Usage.
  Они есть начиная с Windows 10 1709 при драйвере WDDM 2.0+; права
  администратора не нужны.

  Температура:
    1) D3DKMT (gdi32.dll, d3dkmthk.h из Windows SDK): D3DKMTEnumAdapters2 и
       D3DKMTQueryAdapterInfo(KMTQAITYPE_ADAPTERPERFDATA) — данные драйвера
       (WDDM 2.4+, Windows 10 1803+), то же, что диспетчер задач показывает
       для дискретных видеокарт. Программные адаптеры пропускаются.
    2) NVML (nvml.dll из драйвера NVIDIA) — температура, если D3DKMT её не дал,
       и потребляемая мощность (nvmlDeviceGetPowerUsage, мВт) для оценки
       стоимости электроэнергии.
       Библиотека загружается только из System32 или из каталога NVSMI в
       Program Files (защита от подмены DLL), функции — через GetProcAddress.
  Дескрипторы адаптеров открываются на время опроса и сразу закрываются.
  Датчики опрашиваются не чаще раза в SENSOR_REFRESH_MS.
}

interface

uses
  Winapi.Windows,
  MineHunter.Collectors.Gpu, MineHunter.Collectors.Pdh;

type
  TMHWinGpuApi = class(TInterfacedObject, IMHGpuApi)
  private type
    TNvmlDevice = Pointer;
    TNvmlInit = function: Integer; cdecl;
    TNvmlShutdown = function: Integer; cdecl;
    TNvmlDeviceGetCount = function(out ACount: Cardinal): Integer; cdecl;
    TNvmlDeviceGetHandleByIndex = function(AIndex: Cardinal; out ADevice: TNvmlDevice): Integer; cdecl;
    TNvmlDeviceGetTemperature = function(ADevice: TNvmlDevice; ASensor: Integer;
      out ATemperature: Cardinal): Integer; cdecl;
    TNvmlDeviceGetTemperatureThreshold = function(ADevice: TNvmlDevice; AThreshold: Integer;
      out ATemperature: Cardinal): Integer; cdecl;
    TNvmlDeviceGetName = function(ADevice: TNvmlDevice; AName: PAnsiChar;
      ALength: Cardinal): Integer; cdecl;
    TNvmlDeviceGetPowerUsage = function(ADevice: TNvmlDevice; out AMilliwatts: Cardinal): Integer; cdecl;
  private
    FPdh: TMHPdhQuery;
    FEngineCounter: THandle;
    FProcessMemoryCounter: THandle;
    FAdapterMemoryCounter: THandle;
    FCounterError: string;
    FSensorTick: UInt64;
    FSensors: TArray<TMHGpuSensor>;
    FSensorReason: string;
    // NVML
    FNvmlTried: Boolean;
    FNvml: HMODULE;
    FNvmlReady: Boolean;
    FNvmlError: string;
    FNvmlShutdown: TNvmlShutdown;
    FNvmlGetCount: TNvmlDeviceGetCount;
    FNvmlGetHandle: TNvmlDeviceGetHandleByIndex;
    FNvmlGetTemperature: TNvmlDeviceGetTemperature;
    FNvmlGetThreshold: TNvmlDeviceGetTemperatureThreshold;
    FNvmlGetName: TNvmlDeviceGetName;
    FNvmlGetPower: TNvmlDeviceGetPowerUsage;
    function ReadD3dkmtSensors(out AReason: string): TArray<TMHGpuSensor>;
    procedure InitNvml;
    function ReadNvmlSensors(out AReason: string): TArray<TMHGpuSensor>;
    procedure RefreshSensors;
  public
    constructor Create;
    destructor Destroy; override;
    function GetCounters: TMHGpuCounters;
    function GetSensors(out AReason: string): TArray<TMHGpuSensor>;
  end;

implementation

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Lang;

const
  SENSOR_REFRESH_MS = 5000;
  LOAD_LIBRARY_SEARCH_SYSTEM32 = $00000800;
  LOAD_WITH_ALTERED_SEARCH_PATH = $00000008;

  // KMTQUERYADAPTERINFOTYPE (d3dkmthk.h)
  KMTQAITYPE_ADAPTERREGISTRYINFO = 8;
  KMTQAITYPE_ADAPTERTYPE = 15;
  KMTQAITYPE_PHYSICALADAPTERCOUNT = 30;
  KMTQAITYPE_ADAPTERPERFDATA = 62;
  KMTQAITYPE_ADAPTERPERFDATA_CAPS = 63;
  /// D3DKMT_ADAPTERTYPE.SoftwareDevice (бит 2).
  ADAPTERTYPE_SOFTWARE_DEVICE = $4;
  STATUS_SUCCESS = 0;
  MAX_ADAPTERS = 64;

  // nvml.h
  NVML_SUCCESS = 0;
  NVML_TEMPERATURE_GPU = 0;
  NVML_TEMPERATURE_THRESHOLD_SLOWDOWN = 1;

type
  NTSTATUS = Longint;
  D3DKMT_HANDLE = Cardinal;

  TD3DKMTAdapterInfo = record
    hAdapter: D3DKMT_HANDLE;
    AdapterLuidLow: DWORD;
    AdapterLuidHigh: Longint;
    NumOfSources: ULONG;
    bPrecisePresentRegionsPreferred: BOOL;
  end;

  TD3DKMTEnumAdapters2 = record
    NumAdapters: ULONG;
    pAdapters: Pointer;
  end;

  TD3DKMTQueryAdapterInfo = record
    hAdapter: D3DKMT_HANDLE;
    QueryType: Integer;
    pPrivateDriverData: Pointer;
    PrivateDriverDataSize: UINT;
  end;

  TD3DKMTCloseAdapter = record
    hAdapter: D3DKMT_HANDLE;
  end;

  TD3DKMTAdapterPerfData = record
    PhysicalAdapterIndex: UINT32;
    MemoryFrequency: UInt64;
    MaxMemoryFrequency: UInt64;
    MaxMemoryFrequencyOC: UInt64;
    MemoryBandwidth: UInt64;
    PCIEBandwidth: UInt64;
    FanRPM: ULONG;
    Power: ULONG;
    /// Десятые доли градуса Цельсия.
    Temperature: ULONG;
    PowerStateOverride: Byte;
  end;

  TD3DKMTAdapterPerfDataCaps = record
    PhysicalAdapterIndex: UINT32;
    MaxMemoryBandwidth: UInt64;
    MaxPCIEBandwidth: UInt64;
    MaxFanRPM: ULONG;
    TemperatureMax: ULONG;
    TemperatureWarning: ULONG;
  end;

  TD3DKMTAdapterRegistryInfo = record
    AdapterString: array[0..MAX_PATH - 1] of WideChar;
    BiosString: array[0..MAX_PATH - 1] of WideChar;
    DacType: array[0..MAX_PATH - 1] of WideChar;
    ChipType: array[0..MAX_PATH - 1] of WideChar;
  end;

  TD3DKMTEnumAdapters2Func = function(var AArgs: TD3DKMTEnumAdapters2): NTSTATUS; stdcall;
  TD3DKMTQueryAdapterInfoFunc = function(const AArgs: TD3DKMTQueryAdapterInfo): NTSTATUS; stdcall;
  TD3DKMTCloseAdapterFunc = function(const AArgs: TD3DKMTCloseAdapter): NTSTATUS; stdcall;

// Раскладка структур должна совпадать с d3dkmthk.h для x64.
{$IF SizeOf(TD3DKMTAdapterInfo) <> 20}
  {$MESSAGE ERROR 'D3DKMT_ADAPTERINFO: неверный размер'}
{$IFEND}
{$IF SizeOf(TD3DKMTEnumAdapters2) <> 16}
  {$MESSAGE ERROR 'D3DKMT_ENUMADAPTERS2: неверный размер'}
{$IFEND}
{$IF SizeOf(TD3DKMTQueryAdapterInfo) <> 24}
  {$MESSAGE ERROR 'D3DKMT_QUERYADAPTERINFO: неверный размер'}
{$IFEND}
{$IF SizeOf(TD3DKMTAdapterPerfData) <> 64}
  {$MESSAGE ERROR 'D3DKMT_ADAPTER_PERFDATA: неверный размер'}
{$IFEND}
{$IF SizeOf(TD3DKMTAdapterPerfDataCaps) <> 40}
  {$MESSAGE ERROR 'D3DKMT_ADAPTER_PERFDATACAPS: неверный размер'}
{$IFEND}

var
  GD3dkmtLoaded: Boolean;
  GEnumAdapters2: TD3DKMTEnumAdapters2Func;
  GQueryAdapterInfo: TD3DKMTQueryAdapterInfoFunc;
  GCloseAdapter: TD3DKMTCloseAdapterFunc;

/// gdi32.dll всегда загружена в процесс VCL; функции берутся динамически,
/// чтобы на старых системах отсутствие экспорта не мешало запуску.
function LoadD3dkmt: Boolean;
var
  LGdi: HMODULE;
begin
  if not GD3dkmtLoaded then
  begin
    LGdi := GetModuleHandle('gdi32.dll');
    if LGdi = 0 then
      LGdi := LoadLibraryEx('gdi32.dll', 0, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if LGdi <> 0 then
    begin
      @GEnumAdapters2 := GetProcAddress(LGdi, 'D3DKMTEnumAdapters2');
      @GQueryAdapterInfo := GetProcAddress(LGdi, 'D3DKMTQueryAdapterInfo');
      @GCloseAdapter := GetProcAddress(LGdi, 'D3DKMTCloseAdapter');
    end;
    GD3dkmtLoaded := True;
  end;
  Result := Assigned(GEnumAdapters2) and Assigned(GQueryAdapterInfo) and Assigned(GCloseAdapter);
end;

function QueryInfo(AAdapter: D3DKMT_HANDLE; AType: Integer; AData: Pointer; ASize: UINT): Boolean;
var
  LQuery: TD3DKMTQueryAdapterInfo;
begin
  LQuery.hAdapter := AAdapter;
  LQuery.QueryType := AType;
  LQuery.pPrivateDriverData := AData;
  LQuery.PrivateDriverDataSize := ASize;
  Result := GQueryAdapterInfo(LQuery) = STATUS_SUCCESS;
end;

{ TMHWinGpuApi }

constructor TMHWinGpuApi.Create;
begin
  inherited Create;
  FPdh := TMHPdhQuery.Create;
  FEngineCounter := FPdh.AddCounter('\GPU Engine(*)\Utilization Percentage');
  if FEngineCounter = 0 then
    FCounterError := MHL('счётчики GPU отсутствуют (нужны Windows 10 1709+ и драйвер видеокарты WDDM 2.0+)',
      'GPU counters are missing (Windows 10 1709+ and a WDDM 2.0+ graphics driver are required)');
  FProcessMemoryCounter := FPdh.AddCounter('\GPU Process Memory(*)\Dedicated Usage');
  FAdapterMemoryCounter := FPdh.AddCounter('\GPU Adapter Memory(*)\Dedicated Usage');
end;

destructor TMHWinGpuApi.Destroy;
begin
  if FNvml <> 0 then
  begin
    if FNvmlReady and Assigned(FNvmlShutdown) then
      FNvmlShutdown();
    FreeLibrary(FNvml);
  end;
  FPdh.Free;
  inherited;
end;

function ToSamples(const AItems: TArray<TMHPdhItem>): TArray<TMHGpuCounterSample>;
var
  I: Integer;
begin
  SetLength(Result, Length(AItems));
  for I := 0 to High(AItems) do
  begin
    Result[I].InstanceName := AItems[I].Name;
    Result[I].Value := AItems[I].Value;
  end;
end;

function TMHWinGpuApi.GetCounters: TMHGpuCounters;
var
  LItems: TArray<TMHPdhItem>;
begin
  Result := Default(TMHGpuCounters);
  if FEngineCounter = 0 then
  begin
    Result.Reason := FCounterError;
    Exit;
  end;
  if not FPdh.Collect then
  begin
    Result.Reason := FPdh.LastError;
    Exit;
  end;
  if FPdh.Collects < 2 then
  begin
    Result.Pending := True;
    Result.Reason := MHL('загрузка будет доступна после следующего замера', 'load will be available after the next measurement');
    Exit;
  end;
  if not FPdh.ReadArray(FEngineCounter, LItems) then
  begin
    Result.Reason := MHL('счётчики GPU вернули некорректные данные', 'GPU counters returned invalid data');
    Exit;
  end;
  Result.Engines := ToSamples(LItems);
  if FPdh.ReadArray(FProcessMemoryCounter, LItems) then
    Result.ProcessMemory := ToSamples(LItems);
  if FPdh.ReadArray(FAdapterMemoryCounter, LItems) then
    Result.AdapterMemory := ToSamples(LItems);
  Result.Available := True;
end;

function TMHWinGpuApi.ReadD3dkmtSensors(out AReason: string): TArray<TMHGpuSensor>;
var
  LEnum: TD3DKMTEnumAdapters2;
  LAdapters: array of TD3DKMTAdapterInfo;
  LClose: TD3DKMTCloseAdapter;
  LType, LPhysCount: UINT;
  LRegistry: TD3DKMTAdapterRegistryInfo;
  LPerf: TD3DKMTAdapterPerfData;
  LCaps: TD3DKMTAdapterPerfDataCaps;
  LList: TList<TMHGpuSensor>;
  LSensor: TMHGpuSensor;
  LName: string;
  I, J: Integer;
  LHardware: Integer;
begin
  Result := nil;
  AReason := '';
  if not LoadD3dkmt then
  begin
    AReason := MHL('D3DKMT недоступен в этой версии Windows', 'D3DKMT is not available in this version of Windows');
    Exit;
  end;
  LEnum := Default(TD3DKMTEnumAdapters2);
  if (GEnumAdapters2(LEnum) <> STATUS_SUCCESS) or (LEnum.NumAdapters = 0) then
  begin
    AReason := MHL('видеоадаптеры не найдены', 'no video adapters found');
    Exit;
  end;
  if LEnum.NumAdapters > MAX_ADAPTERS then
    LEnum.NumAdapters := MAX_ADAPTERS;
  SetLength(LAdapters, LEnum.NumAdapters);
  LEnum.pAdapters := @LAdapters[0];
  if GEnumAdapters2(LEnum) <> STATUS_SUCCESS then
  begin
    AReason := MHL('не удалось перечислить видеоадаптеры', 'failed to enumerate video adapters');
    Exit;
  end;
  LList := TList<TMHGpuSensor>.Create;
  try
    LHardware := 0;
    for I := 0 to Integer(LEnum.NumAdapters) - 1 do
      try
        LType := 0;
        if QueryInfo(LAdapters[I].hAdapter, KMTQAITYPE_ADAPTERTYPE, @LType, SizeOf(LType)) and
           (LType and ADAPTERTYPE_SOFTWARE_DEVICE <> 0) then
          Continue; // Microsoft Basic Render Driver и т.п.
        Inc(LHardware);
        LName := '';
        FillChar(LRegistry, SizeOf(LRegistry), 0);
        if QueryInfo(LAdapters[I].hAdapter, KMTQAITYPE_ADAPTERREGISTRYINFO, @LRegistry, SizeOf(LRegistry)) then
          LName := Trim(string(PWideChar(@LRegistry.AdapterString[0])));
        if LName = '' then
          LName := Format(MHL('Видеоадаптер %d', 'Video adapter %d'), [LHardware]);
        LPhysCount := 1;
        if not QueryInfo(LAdapters[I].hAdapter, KMTQAITYPE_PHYSICALADAPTERCOUNT, @LPhysCount,
           SizeOf(LPhysCount)) or (LPhysCount = 0) or (LPhysCount > 8) then
          LPhysCount := 1;
        for J := 0 to Integer(LPhysCount) - 1 do
        begin
          LSensor := Default(TMHGpuSensor);
          LSensor.AdapterName := LName;
          LSensor.Source := 'D3DKMT';
          LPerf := Default(TD3DKMTAdapterPerfData);
          LPerf.PhysicalAdapterIndex := J;
          // 0 — драйвер не сообщает температуру.
          if QueryInfo(LAdapters[I].hAdapter, KMTQAITYPE_ADAPTERPERFDATA, @LPerf, SizeOf(LPerf)) and
             (LPerf.Temperature > 0) then
          begin
            LSensor.HasTemperature := True;
            LSensor.TemperatureCelsius := LPerf.Temperature / 10;
          end;
          LCaps := Default(TD3DKMTAdapterPerfDataCaps);
          LCaps.PhysicalAdapterIndex := J;
          // Порог предупреждения — тоже в десятых градуса; неправдоподобные значения игнорируются.
          if QueryInfo(LAdapters[I].hAdapter, KMTQAITYPE_ADAPTERPERFDATA_CAPS, @LCaps, SizeOf(LCaps)) and
             (LCaps.TemperatureWarning >= 400) and (LCaps.TemperatureWarning <= 1300) then
          begin
            LSensor.HasSlowdown := True;
            LSensor.SlowdownCelsius := LCaps.TemperatureWarning / 10;
          end;
          LList.Add(LSensor);
        end;
      finally
        LClose.hAdapter := LAdapters[I].hAdapter;
        GCloseAdapter(LClose);
      end;
    Result := LList.ToArray;
    if LHardware = 0 then
      AReason := MHL('аппаратные видеоадаптеры не найдены', 'no hardware video adapters found');
  finally
    LList.Free;
  end;
end;

procedure TMHWinGpuApi.InitNvml;
var
  LPath: string;
  LInit: TNvmlInit;
begin
  FNvmlTried := True;
  FNvml := LoadLibraryEx('nvml.dll', 0, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if FNvml = 0 then
  begin
    LPath := GetEnvironmentVariable('ProgramW6432');
    if LPath = '' then
      LPath := GetEnvironmentVariable('ProgramFiles');
    if LPath <> '' then
    begin
      LPath := IncludeTrailingPathDelimiter(LPath) + 'NVIDIA Corporation\NVSMI\nvml.dll';
      if FileExists(LPath) then
        FNvml := LoadLibraryEx(PChar(LPath), 0, LOAD_WITH_ALTERED_SEARCH_PATH);
    end;
  end;
  if FNvml = 0 then
  begin
    FNvmlError := MHL('драйвер NVIDIA (nvml.dll) не найден', 'NVIDIA driver (nvml.dll) not found');
    Exit;
  end;
  @LInit := GetProcAddress(FNvml, 'nvmlInit_v2');
  @FNvmlShutdown := GetProcAddress(FNvml, 'nvmlShutdown');
  @FNvmlGetCount := GetProcAddress(FNvml, 'nvmlDeviceGetCount_v2');
  @FNvmlGetHandle := GetProcAddress(FNvml, 'nvmlDeviceGetHandleByIndex_v2');
  @FNvmlGetTemperature := GetProcAddress(FNvml, 'nvmlDeviceGetTemperature');
  @FNvmlGetThreshold := GetProcAddress(FNvml, 'nvmlDeviceGetTemperatureThreshold');
  @FNvmlGetName := GetProcAddress(FNvml, 'nvmlDeviceGetName');
  @FNvmlGetPower := GetProcAddress(FNvml, 'nvmlDeviceGetPowerUsage');
  if not (Assigned(LInit) and Assigned(FNvmlShutdown) and Assigned(FNvmlGetCount) and
          Assigned(FNvmlGetHandle) and Assigned(FNvmlGetTemperature)) then
  begin
    FNvmlError := MHL('nvml.dll не содержит нужных функций', 'nvml.dll does not contain the required functions');
    Exit;
  end;
  if LInit() <> NVML_SUCCESS then
  begin
    FNvmlError := MHL('NVML не инициализирован (видеокарта NVIDIA не найдена или драйвер не отвечает)',
      'NVML is not initialized (no NVIDIA graphics card found or the driver is not responding)');
    Exit;
  end;
  FNvmlReady := True;
end;

function TMHWinGpuApi.ReadNvmlSensors(out AReason: string): TArray<TMHGpuSensor>;
var
  LCount, LTemp, LThreshold, I, LLimit, LMilliwatts: Cardinal;
  LDevice: TNvmlDevice;
  LName: array[0..95] of AnsiChar;
  LSensor: TMHGpuSensor;
  LList: TList<TMHGpuSensor>;
begin
  Result := nil;
  AReason := '';
  if not FNvmlTried then
    InitNvml;
  if not FNvmlReady then
  begin
    AReason := FNvmlError;
    Exit;
  end;
  if (FNvmlGetCount(LCount) <> NVML_SUCCESS) or (LCount = 0) then
  begin
    AReason := MHL('видеокарты NVIDIA не найдены', 'no NVIDIA graphics cards found');
    Exit;
  end;
  LList := TList<TMHGpuSensor>.Create;
  try
    LLimit := LCount;
    if LLimit > 16 then
      LLimit := 16;
    for I := 0 to LLimit - 1 do
    begin
      if FNvmlGetHandle(I, LDevice) <> NVML_SUCCESS then
        Continue;
      LSensor := Default(TMHGpuSensor);
      LSensor.Source := 'NVML';
      FillChar(LName, SizeOf(LName), 0);
      if Assigned(FNvmlGetName) and (FNvmlGetName(LDevice, @LName[0], Length(LName) - 1) = NVML_SUCCESS) then
        LSensor.AdapterName := string(UTF8String(PAnsiChar(@LName[0])));
      if LSensor.AdapterName = '' then
        LSensor.AdapterName := Format('NVIDIA GPU %d', [I]);
      if FNvmlGetTemperature(LDevice, NVML_TEMPERATURE_GPU, LTemp) = NVML_SUCCESS then
      begin
        LSensor.HasTemperature := True;
        LSensor.TemperatureCelsius := LTemp;
      end;
      if Assigned(FNvmlGetThreshold) and
         (FNvmlGetThreshold(LDevice, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, LThreshold) = NVML_SUCCESS) and
         (LThreshold >= 40) and (LThreshold <= 130) then
      begin
        LSensor.HasSlowdown := True;
        LSensor.SlowdownCelsius := LThreshold;
      end;
      // Видеокарты без датчика мощности (часть ноутбучных) возвращают NOT_SUPPORTED.
      if Assigned(FNvmlGetPower) and (FNvmlGetPower(LDevice, LMilliwatts) = NVML_SUCCESS) and
         (LMilliwatts < 2000000) then
      begin
        LSensor.HasPower := True;
        LSensor.PowerWatts := LMilliwatts / 1000;
      end;
      LList.Add(LSensor);
    end;
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

procedure TMHWinGpuApi.RefreshSensors;
var
  LD3dReason, LNvmlReason: string;
  LSensor, LCopy: TMHGpuSensor;
  LNvml: TArray<TMHGpuSensor>;
  LHasTemperature, LD3dHasTemperature: Boolean;
begin
  FSensors := ReadD3dkmtSensors(LD3dReason);
  LHasTemperature := False;
  for LSensor in FSensors do
    LHasTemperature := LHasTemperature or LSensor.HasTemperature;
  FSensorReason := '';
  // NVML опрашивается всегда: это единственный источник мощности. Температура из
  // NVML берётся, только если D3DKMT её не дал (иначе адаптер учитывался бы дважды).
  LNvml := ReadNvmlSensors(LNvmlReason);
  LD3dHasTemperature := LHasTemperature;
  for LSensor in LNvml do
  begin
    LCopy := LSensor;
    if LD3dHasTemperature then
    begin
      LCopy.HasTemperature := False;
      LCopy.HasSlowdown := False;
    end;
    if LCopy.HasTemperature or LCopy.HasPower then
      FSensors := FSensors + [LCopy];
    LHasTemperature := LHasTemperature or LCopy.HasTemperature;
  end;
  if LHasTemperature then
    Exit;
  if not LHasTemperature then
  begin
    if LD3dReason = '' then
      LD3dReason := MHL('драйвер видеокарты не сообщает температуру', 'the graphics driver does not report temperature');
    FSensorReason := LD3dReason + '; NVML: ' + LNvmlReason;
  end;
end;

function TMHWinGpuApi.GetSensors(out AReason: string): TArray<TMHGpuSensor>;
var
  LNow: UInt64;
begin
  LNow := GetTickCount64;
  if (FSensorTick = 0) or (LNow - FSensorTick >= SENSOR_REFRESH_MS) then
  begin
    FSensorTick := LNow;
    try
      RefreshSensors;
    except
      on E: Exception do
      begin
        FSensors := nil;
        FSensorReason := MHL('ошибка опроса датчиков: ', 'sensor polling error: ') + E.Message;
      end;
    end;
  end;
  AReason := FSensorReason;
  Result := FSensors;
end;

end.
