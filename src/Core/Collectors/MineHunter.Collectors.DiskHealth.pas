unit MineHunter.Collectors.DiskHealth;

{
  Атрибуты здоровья дисков — те же, что показывает CrystalDiskInfo.
  - NVMe: журнал «SMART / Health Information» (Log Page 02h, 512 байт; NVMe 1.4,
    раздел 5.14.1.2). Поля журнала нумеруются 01–0F в порядке CrystalDiskInfo.
    Windows отдаёт журнал через IOCTL_STORAGE_QUERY_PROPERTY
    (StorageDeviceProtocolSpecificProperty) без прав администратора.
  - SATA: SMART READ DATA (512 байт: версия, 30 записей по 12 байт — номер,
    флаги, текущее, худшее, 6 байт «сырого» значения) и READ THRESHOLDS
    (пороги по номеру атрибута). Нужны права администратора.
  Здесь только разбор буферов (без обращения к ОС): названия и понятные значения
  строятся при показе, чтобы не зависеть от языка в момент опроса.
}

interface

uses
  System.SysUtils, MineHunter.Core.Types;

const
  MH_HEALTH_SOURCE_NVME = 'NVMe';
  MH_HEALTH_SOURCE_SMART = 'SMART';
  /// Размер журнала здоровья NVMe и буферов SMART.
  MH_HEALTH_LOG_SIZE = 512;

type
  /// Разобранные сведения о здоровье диска (-1 — значение неизвестно).
  TMHDiskHealthData = record
    Source: string;
    Attributes: TArray<TMHDiskAttribute>;
    HasTemperature: Boolean;
    TemperatureCelsius: Double;
    HasWear: Boolean;
    WearPercent: Double;
    PowerOnHours: Int64;
    PowerCycles: Int64;
    UnsafeShutdowns: Int64;
    /// NVMe: ошибки целостности носителя и данных (неисправленные ошибки чтения).
    MediaErrors: Int64;
    /// Прочитано и записано за всё время, байт (0 — неизвестно).
    TotalReadBytes: Double;
    TotalWrittenBytes: Double;
    ReallocatedSectors: Int64;
    PendingSectors: Int64;
    UncorrectableSectors: Int64;
    CriticalWarning: Integer;
    AvailableSparePercent: Integer;
    SpareThresholdPercent: Integer;
    class function Create(const ASource: string): TMHDiskHealthData; static;
  end;

/// Разбор журнала здоровья NVMe. False — буфер короче 512 байт.
function MHParseNvmeHealthLog(const ALog: TBytes; out AData: TMHDiskHealthData): Boolean;
/// Разбор SMART READ DATA и READ THRESHOLDS (пороги могут отсутствовать). False — нет
/// ни одного атрибута или буфер короче 362 байт.
function MHParseAtaSmart(const AValues, AThresholds: TBytes; out AData: TMHDiskHealthData): Boolean;

/// Название атрибута для показа.
function MHDiskAttributeName(const ASource: string; AId: Integer): string;
/// Понятное значение атрибута («1748 ч», «3709 ГБ», «32 °C»); пусто — показывать Raw.
function MHDiskAttributeText(const ASource: string; const AAttribute: TMHDiskAttribute): string;
/// «Сырое» значение шестнадцатеричным числом, как в CrystalDiskInfo (12 цифр для SMART, 14 для NVMe).
function MHDiskAttributeRawHex(const ASource: string; const AAttribute: TMHDiskAttribute): string;
/// Расшифровка битов критического предупреждения NVMe.
function MHNvmeCriticalWarningText(AValue: Integer): string;

implementation

uses
  System.Math, MineHunter.Core.Lang;

const
  // Номера атрибутов SMART, которые разбираются в отдельные поля.
  SMART_REALLOCATED = $05;
  SMART_POWER_ON_HOURS = $09;
  SMART_POWER_CYCLES = $0C;
  SMART_UNEXPECTED_POWER_LOSS = $AE;
  SMART_POWER_OFF_RETRACT = $C0;
  SMART_AIRFLOW_TEMPERATURE = $BE;
  SMART_TEMPERATURE = $C2;
  SMART_PENDING = $C5;
  SMART_UNCORRECTABLE = $C6;
  SMART_ENTRY_COUNT = 30;
  SMART_ENTRY_SIZE = 12;

  // Номера полей журнала NVMe (как в CrystalDiskInfo).
  NVME_CRITICAL_WARNING = 1;
  NVME_TEMPERATURE = 2;
  NVME_SPARE = 3;
  NVME_SPARE_THRESHOLD = 4;
  NVME_PERCENTAGE_USED = 5;
  NVME_DATA_READ = 6;
  NVME_DATA_WRITTEN = 7;
  NVME_READ_COMMANDS = 8;
  NVME_WRITE_COMMANDS = 9;
  NVME_BUSY_TIME = 10;
  NVME_POWER_CYCLES = 11;
  NVME_POWER_ON_HOURS = 12;
  NVME_UNSAFE_SHUTDOWNS = 13;
  NVME_MEDIA_ERRORS = 14;
  NVME_ERROR_LOG_ENTRIES = 15;

  /// Единица «Data Units Read/Written» — 1000 блоков по 512 байт.
  NVME_DATA_UNIT_BYTES = 512000.0;
  KELVIN_OFFSET = 273;

type
  TNvmeField = record
    Offset: Integer;
    Size: Integer;
  end;

  TWarningBit = record
    Ru: string;
    En: string;
  end;

class function TMHDiskHealthData.Create(const ASource: string): TMHDiskHealthData;
begin
  Result := Default(TMHDiskHealthData);
  Result.Source := ASource;
  Result.PowerOnHours := -1;
  Result.PowerCycles := -1;
  Result.UnsafeShutdowns := -1;
  Result.MediaErrors := -1;
  Result.ReallocatedSectors := -1;
  Result.PendingSectors := -1;
  Result.UncorrectableSectors := -1;
  Result.CriticalWarning := -1;
  Result.AvailableSparePercent := -1;
  Result.SpareThresholdPercent := -1;
end;

function ReadLE(const ABytes: TBytes; AOffset, ACount: Integer): UInt64;
var
  I: Integer;
begin
  Result := 0;
  for I := ACount - 1 downto 0 do
    Result := (Result shl 8) or ABytes[AOffset + I];
end;

/// 128-битный счётчик NVMe: старшие 64 бита на практике нулевые; если нет — насыщение.
function ReadCounter128(const ABytes: TBytes; AOffset: Integer): UInt64;
begin
  if ReadLE(ABytes, AOffset + 8, 8) <> 0 then
    Result := High(Int64)
  else
    Result := ReadLE(ABytes, AOffset, 8);
  if Result > UInt64(High(Int64)) then
    Result := High(Int64);
end;

function Low32(ARaw: UInt64): Int64;
begin
  Result := Int64(ARaw and $FFFFFFFF);
end;

function Attribute(AId: Integer; ARaw: UInt64; ACurrent: Integer = -1; AWorst: Integer = -1;
  AThreshold: Integer = -1): TMHDiskAttribute;
begin
  Result.Id := AId;
  Result.Current := ACurrent;
  Result.Worst := AWorst;
  Result.Threshold := AThreshold;
  Result.Raw := ARaw;
end;

function MHParseNvmeHealthLog(const ALog: TBytes; out AData: TMHDiskHealthData): Boolean;
const
  // Смещение и длина каждого поля журнала в порядке номеров 01–0F.
  FIELDS: array[NVME_CRITICAL_WARNING..NVME_ERROR_LOG_ENTRIES] of TNvmeField = (
    (Offset: 0; Size: 1), (Offset: 1; Size: 2), (Offset: 3; Size: 1), (Offset: 4; Size: 1), (Offset: 5; Size: 1),
    (Offset: 32; Size: 16), (Offset: 48; Size: 16), (Offset: 64; Size: 16), (Offset: 80; Size: 16),
    (Offset: 96; Size: 16), (Offset: 112; Size: 16), (Offset: 128; Size: 16), (Offset: 144; Size: 16),
    (Offset: 160; Size: 16), (Offset: 176; Size: 16));
var
  I: Integer;
  LRaw: UInt64;
  LKelvin: Integer;
begin
  AData := TMHDiskHealthData.Create(MH_HEALTH_SOURCE_NVME);
  if Length(ALog) < MH_HEALTH_LOG_SIZE then
    Exit(False);
  SetLength(AData.Attributes, Length(FIELDS));
  for I := Low(FIELDS) to High(FIELDS) do
  begin
    if FIELDS[I].Size = 16 then
      LRaw := ReadCounter128(ALog, FIELDS[I].Offset)
    else
      LRaw := ReadLE(ALog, FIELDS[I].Offset, FIELDS[I].Size);
    AData.Attributes[I - Low(FIELDS)] := Attribute(I, LRaw);
  end;
  AData.CriticalWarning := ALog[0];
  LKelvin := Integer(ReadLE(ALog, 1, 2));
  // 0 — датчик не сообщает; правдоподобный диапазон — от −20 до 150 °C.
  if (LKelvin > KELVIN_OFFSET - 20) and (LKelvin < KELVIN_OFFSET + 150) then
  begin
    AData.HasTemperature := True;
    AData.TemperatureCelsius := LKelvin - KELVIN_OFFSET;
  end;
  AData.AvailableSparePercent := ALog[3];
  AData.SpareThresholdPercent := ALog[4];
  // «Percentage Used» может превышать 100 (ресурс исчерпан, диск работает) — показываем не больше 100.
  AData.HasWear := True;
  AData.WearPercent := Min(100, Integer(ALog[5]));
  AData.TotalReadBytes := ReadCounter128(ALog, 32) * NVME_DATA_UNIT_BYTES;
  AData.TotalWrittenBytes := ReadCounter128(ALog, 48) * NVME_DATA_UNIT_BYTES;
  AData.PowerCycles := Int64(ReadCounter128(ALog, 112));
  AData.PowerOnHours := Int64(ReadCounter128(ALog, 128));
  AData.UnsafeShutdowns := Int64(ReadCounter128(ALog, 144));
  AData.MediaErrors := Int64(ReadCounter128(ALog, 160));
  Result := True;
end;

function MHParseAtaSmart(const AValues, AThresholds: TBytes; out AData: TMHDiskHealthData): Boolean;
var
  I, J, LOffset, LId, LThreshold: Integer;
  LRaw: UInt64;
  LHasThresholds: Boolean;
  LTemperature: Integer;
begin
  AData := TMHDiskHealthData.Create(MH_HEALTH_SOURCE_SMART);
  if Length(AValues) < 2 + SMART_ENTRY_COUNT * SMART_ENTRY_SIZE then
    Exit(False);
  LHasThresholds := Length(AThresholds) >= 2 + SMART_ENTRY_COUNT * SMART_ENTRY_SIZE;
  for I := 0 to SMART_ENTRY_COUNT - 1 do
  begin
    LOffset := 2 + I * SMART_ENTRY_SIZE;
    LId := AValues[LOffset];
    if LId = 0 then
      Continue;
    LRaw := ReadLE(AValues, LOffset + 5, 6);
    // Порог ищется по номеру атрибута: порядок записей в двух ответах может различаться.
    LThreshold := -1;
    if LHasThresholds then
      for J := 0 to SMART_ENTRY_COUNT - 1 do
        if AThresholds[2 + J * SMART_ENTRY_SIZE] = LId then
        begin
          LThreshold := AThresholds[2 + J * SMART_ENTRY_SIZE + 1];
          Break;
        end;
    AData.Attributes := AData.Attributes + [Attribute(LId, LRaw, AValues[LOffset + 3], AValues[LOffset + 4], LThreshold)];
    // У многих производителей в старших байтах — служебные данные (минуты, максимум и минимум
    // температуры), поэтому счётчики берутся из младших байтов, как в CrystalDiskInfo.
    case LId of
      SMART_REALLOCATED: AData.ReallocatedSectors := Low32(LRaw);
      SMART_POWER_ON_HOURS: AData.PowerOnHours := Low32(LRaw);
      SMART_POWER_CYCLES: AData.PowerCycles := Low32(LRaw);
      SMART_UNEXPECTED_POWER_LOSS: AData.UnsafeShutdowns := Low32(LRaw);
      SMART_POWER_OFF_RETRACT:
        if AData.UnsafeShutdowns < 0 then
          AData.UnsafeShutdowns := Low32(LRaw);
      SMART_PENDING: AData.PendingSectors := Low32(LRaw);
      SMART_UNCORRECTABLE: AData.UncorrectableSectors := Low32(LRaw);
      SMART_TEMPERATURE, SMART_AIRFLOW_TEMPERATURE:
        begin
          LTemperature := Integer(LRaw and $FF);
          // Основной датчик (C2) важнее температуры воздушного потока (BE).
          if (LTemperature > 0) and (LTemperature < 120) and
             (not AData.HasTemperature or (LId = SMART_TEMPERATURE)) then
          begin
            AData.HasTemperature := True;
            AData.TemperatureCelsius := LTemperature;
          end;
        end;
    end;
  end;
  Result := Length(AData.Attributes) > 0;
end;

function NvmeName(AId: Integer): string;
begin
  case AId of
    NVME_CRITICAL_WARNING: Result := MHL('Критическое предупреждение', 'Critical Warning');
    NVME_TEMPERATURE: Result := MHL('Составная температура', 'Composite Temperature');
    NVME_SPARE: Result := MHL('Доступный запас', 'Available Spare');
    NVME_SPARE_THRESHOLD: Result := MHL('Порог доступного запаса', 'Available Spare Threshold');
    NVME_PERCENTAGE_USED: Result := MHL('Процент использования', 'Percentage Used');
    NVME_DATA_READ: Result := MHL('Единицы данных — чтение', 'Data Units Read');
    NVME_DATA_WRITTEN: Result := MHL('Единицы данных — запись', 'Data Units Written');
    NVME_READ_COMMANDS: Result := MHL('Команды хост-чтения', 'Host Read Commands');
    NVME_WRITE_COMMANDS: Result := MHL('Команды хост-записи', 'Host Write Commands');
    NVME_BUSY_TIME: Result := MHL('Время работы контроллера', 'Controller Busy Time');
    NVME_POWER_CYCLES: Result := MHL('Включения/отключения', 'Power Cycles');
    NVME_POWER_ON_HOURS: Result := MHL('Часы работы', 'Power On Hours');
    NVME_UNSAFE_SHUTDOWNS: Result := MHL('Небезопасные отключения', 'Unsafe Shutdowns');
    NVME_MEDIA_ERRORS: Result := MHL('Ошибки целостности носителя и данных', 'Media and Data Integrity Errors');
    NVME_ERROR_LOG_ENTRIES: Result := MHL('Записи в журнале информации об ошибках', 'Number of Error Information Log Entries');
  else
    Result := Format(MHL('Поле %d', 'Field %d'), [AId]);
  end;
end;

function SmartName(AId: Integer): string;
begin
  case AId of
    $01: Result := MHL('Частота ошибок чтения', 'Read Error Rate');
    $02: Result := MHL('Производительность', 'Throughput Performance');
    $03: Result := MHL('Время раскрутки', 'Spin-Up Time');
    $04: Result := MHL('Запуски/остановки шпинделя', 'Start/Stop Count');
    $05: Result := MHL('Переназначенные секторы', 'Reallocated Sectors Count');
    $07: Result := MHL('Частота ошибок позиционирования', 'Seek Error Rate');
    $08: Result := MHL('Производительность позиционирования', 'Seek Time Performance');
    $09: Result := MHL('Часы работы', 'Power-On Hours');
    $0A: Result := MHL('Повторы раскрутки', 'Spin Retry Count');
    $0B: Result := MHL('Повторы калибровки', 'Recalibration Retries');
    $0C: Result := MHL('Включения/отключения', 'Power Cycle Count');
    $AA: Result := MHL('Резервные блоки', 'Available Reserved Space');
    $AB: Result := MHL('Ошибки программирования', 'Program Fail Count');
    $AC: Result := MHL('Ошибки стирания', 'Erase Fail Count');
    $AD: Result := MHL('Выравнивание износа', 'Wear Leveling Count');
    $AE: Result := MHL('Неожиданные отключения питания', 'Unexpected Power Loss Count');
    $B1: Result := MHL('Выравнивание износа', 'Wear Range Delta');
    $B3: Result := MHL('Использовано резервных блоков', 'Used Reserved Block Count Total');
    $B4: Result := MHL('Неиспользованные резервные блоки', 'Unused Reserved Block Count Total');
    $B5: Result := MHL('Ошибки программирования', 'Program Fail Count Total');
    $B6: Result := MHL('Ошибки стирания', 'Erase Fail Count Total');
    $B7: Result := MHL('Понижение скорости SATA', 'SATA Downshift Error Count');
    $B8: Result := MHL('Сквозные ошибки', 'End-to-End Error');
    $BB: Result := MHL('Неисправимые ошибки', 'Reported Uncorrectable Errors');
    $BC: Result := MHL('Тайм-ауты команд', 'Command Timeout');
    $BD: Result := MHL('Записи с большой высоты', 'High Fly Writes');
    $BE: Result := MHL('Температура воздушного потока', 'Airflow Temperature');
    $BF: Result := MHL('Ударные нагрузки', 'G-Sense Error Rate');
    $C0: Result := MHL('Аварийные парковки головок', 'Power-off Retract Count');
    $C1: Result := MHL('Циклы загрузки/выгрузки головок', 'Load/Unload Cycle Count');
    $C2: Result := MHL('Температура', 'Temperature');
    $C3: Result := MHL('Исправленные аппаратно ошибки', 'Hardware ECC Recovered');
    $C4: Result := MHL('События переназначения', 'Reallocation Event Count');
    $C5: Result := MHL('Нестабильные секторы', 'Current Pending Sector Count');
    $C6: Result := MHL('Неисправимые секторы', 'Uncorrectable Sector Count');
    $C7: Result := MHL('Ошибки передачи (CRC)', 'UltraDMA CRC Error Count');
    $C8: Result := MHL('Частота ошибок записи', 'Write Error Rate');
    $DC: Result := MHL('Смещение диска', 'Disk Shift');
    $DF: Result := MHL('Повторы загрузки головок', 'Load/Unload Retry Count');
    $E1: Result := MHL('Циклы загрузки головок', 'Load/Unload Cycle Count');
    $E7: Result := MHL('Остаток ресурса SSD', 'SSD Life Left');
    $E8: Result := MHL('Доступный резерв', 'Available Reserved Space');
    $E9: Result := MHL('Индикатор износа', 'Media Wearout Indicator');
    $EB: Result := MHL('Хорошие блоки / свободные блоки', 'Good Block Count / System Free Block Count');
    $F0: Result := MHL('Время полёта головок', 'Head Flying Hours');
    $F1: Result := MHL('Всего записано', 'Total Host Writes');
    $F2: Result := MHL('Всего прочитано', 'Total Host Reads');
  else
    Result := MHL('Атрибут производителя', 'Vendor Specific');
  end;
end;

function MHDiskAttributeName(const ASource: string; AId: Integer): string;
begin
  if ASource = MH_HEALTH_SOURCE_NVME then
    Result := NvmeName(AId)
  else
    Result := SmartName(AId);
end;

/// Объём «как в CrystalDiskInfo»: двоичные ГБ, при 100 ТБ и больше — ТБ.
function VolumeText(ABytes: Double): string;
const
  GIB = 1024.0 * 1024 * 1024;
begin
  if ABytes >= 100 * 1024 * GIB then
    Result := FormatFloat('0.0', ABytes / (1024 * GIB)) + MHL(' ТБ', ' TB')
  else
    Result := FormatFloat('0', ABytes / GIB) + MHL(' ГБ', ' GB');
end;

function MHNvmeCriticalWarningText(AValue: Integer): string;
const
  BITS: array[0..5] of TWarningBit = (
    (Ru: 'запас ниже порога'; En: 'spare below threshold'),
    (Ru: 'температура вне допустимых пределов'; En: 'temperature out of range'),
    (Ru: 'надёжность снижена из-за ошибок носителя'; En: 'reliability degraded by media errors'),
    (Ru: 'носитель только для чтения'; En: 'media placed in read-only mode'),
    (Ru: 'отказ резервного питания кэша'; En: 'volatile memory backup failed'),
    (Ru: 'журнал постоянной памяти только для чтения'; En: 'persistent memory region read-only'));
var
  I: Integer;
begin
  if AValue <= 0 then
    Exit(MHL('нет', 'none'));
  Result := '';
  for I := Low(BITS) to High(BITS) do
    if AValue and (1 shl I) <> 0 then
    begin
      if Result <> '' then
        Result := Result + ', ';
      Result := Result + MHL(BITS[I].Ru, BITS[I].En);
    end;
  if Result = '' then
    Result := Format(MHL('код %d', 'code %d'), [AValue]);
end;

function MHDiskAttributeText(const ASource: string; const AAttribute: TMHDiskAttribute): string;
var
  LLow, LRaw: Int64;
begin
  Result := '';
  LRaw := Int64(AAttribute.Raw and UInt64(High(Int64)));
  if ASource = MH_HEALTH_SOURCE_NVME then
    case AAttribute.Id of
      NVME_CRITICAL_WARNING: Result := MHNvmeCriticalWarningText(Integer(LRaw and $FF));
      NVME_TEMPERATURE:
        if LRaw > 0 then
          Result := Format('%d °C', [Integer(LRaw) - KELVIN_OFFSET]);
      NVME_SPARE, NVME_SPARE_THRESHOLD, NVME_PERCENTAGE_USED:
        Result := Format('%d %%', [LRaw]);
      NVME_DATA_READ, NVME_DATA_WRITTEN:
        Result := VolumeText(LRaw * NVME_DATA_UNIT_BYTES);
      NVME_BUSY_TIME:
        Result := Format(MHL('%d мин', '%d min'), [LRaw]);
      NVME_POWER_CYCLES, NVME_UNSAFE_SHUTDOWNS, NVME_MEDIA_ERRORS, NVME_ERROR_LOG_ENTRIES,
      NVME_READ_COMMANDS, NVME_WRITE_COMMANDS:
        Result := IntToStr(LRaw);
      NVME_POWER_ON_HOURS:
        Result := Format(MHL('%d ч', '%d h'), [LRaw]);
    end
  else
  begin
    LLow := Low32(AAttribute.Raw);
    case AAttribute.Id of
      SMART_POWER_ON_HOURS:
        Result := Format(MHL('%d ч', '%d h'), [LLow]);
      SMART_TEMPERATURE, SMART_AIRFLOW_TEMPERATURE:
        Result := Format('%d °C', [Integer(LRaw and $FF)]);
      SMART_REALLOCATED, SMART_POWER_CYCLES, SMART_UNEXPECTED_POWER_LOSS, SMART_POWER_OFF_RETRACT,
      SMART_PENDING, SMART_UNCORRECTABLE, $BB, $C4, $C7:
        Result := IntToStr(LLow);
    end;
  end;
end;

function MHDiskAttributeRawHex(const ASource: string; const AAttribute: TMHDiskAttribute): string;
begin
  if ASource = MH_HEALTH_SOURCE_NVME then
    Result := IntToHex(AAttribute.Raw, 14)
  else
    Result := IntToHex(AAttribute.Raw, 12);
end;

end.
