unit MineHunter.Tests.DiskHealth;

{
  Атрибуты здоровья дисков: разбор журнала NVMe и SMART SATA на эталонных буферах.
  NVMe — значения со снимка CrystalDiskInfo клиента (WD Blue SN570 250GB),
  SATA — ответ SMART настоящего диска ST500DM002 и упаковка счётчиков Seagate.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Collectors.DiskHealth;

type
  [TestFixture]
  [Category('Unit')]
  TDiskHealthParseTests = class
  public
    [Test] procedure Nvme_ValuesAsInCrystalDiskInfo;
    [Test] procedure Nvme_TextsAndRawHex;
    [Test] procedure Nvme_ShortBuffer_False;
    [Test] procedure Nvme_CriticalWarningWearOverflowAndHugeCounters;
    [Test] procedure Smart_RealDiskWithBadSectors;
    [Test] procedure Smart_PackedRawValuesAndTemperaturePriority;
    [Test] procedure Smart_EmptyOrShort_False;
    [Test] procedure Names_KnownAndVendor;
  end;

  [TestFixture]
  [Category('Integration')]
  TDiskHealthIntegrationTests = class
  public
    [Test] procedure RealNvmeDisks_HealthLogWithoutAdminRights;
  end;

implementation

uses
  MineHunter.Collectors.Disks, MineHunter.Collectors.Disks.WinApi;

procedure PutLE(var ABytes: TBytes; AOffset, ACount: Integer; AValue: UInt64);
var
  I: Integer;
begin
  for I := 0 to ACount - 1 do
    ABytes[AOffset + I] := Byte(AValue shr (8 * I));
end;

/// Журнал NVMe со значениями со снимка CrystalDiskInfo клиента.
function ClientNvmeLog: TBytes;
begin
  SetLength(Result, 512);
  FillChar(Result[0], 512, 0);
  Result[0] := 0;                       // 01 критическое предупреждение
  PutLE(Result, 1, 2, $131);            // 02 температура, K (305 K = 32 °C)
  Result[3] := $64;                     // 03 доступный запас, 100 %
  Result[4] := $0A;                     // 04 порог запаса, 10 %
  Result[5] := 0;                       // 05 процент использования
  PutLE(Result, 32, 8, $76B2E7);        // 06 единицы данных — чтение
  PutLE(Result, 48, 8, $3D6283);        // 07 единицы данных — запись
  PutLE(Result, 64, 8, $73331A3);       // 08 команды чтения
  PutLE(Result, 80, 8, $55C8D5A);       // 09 команды записи
  PutLE(Result, 96, 8, $142);           // 0A время работы контроллера, мин
  PutLE(Result, 112, 8, $10A);          // 0B включения
  PutLE(Result, 128, 8, $6D4);          // 0C часы работы
  PutLE(Result, 144, 8, 3);             // 0D небезопасные отключения
end;

function FindAttribute(const AData: TMHDiskHealthData; AId: Integer): TMHDiskAttribute;
var
  LAttribute: TMHDiskAttribute;
begin
  Result := Default(TMHDiskAttribute);
  for LAttribute in AData.Attributes do
    if LAttribute.Id = AId then
      Exit(LAttribute);
  Assert.Fail('Нет атрибута ' + IntToHex(AId, 2));
end;

{ TDiskHealthParseTests }

procedure TDiskHealthParseTests.Nvme_ValuesAsInCrystalDiskInfo;
var
  LData: TMHDiskHealthData;
  I: Integer;
begin
  Assert.IsTrue(MHParseNvmeHealthLog(ClientNvmeLog, LData));
  Assert.AreEqual(MH_HEALTH_SOURCE_NVME, LData.Source);
  Assert.AreEqual(15, Integer(Length(LData.Attributes)), 'Поля 01–0F, как в CrystalDiskInfo');
  for I := 0 to 14 do
    Assert.AreEqual(I + 1, LData.Attributes[I].Id);
  Assert.AreEqual<Int64>(1748, LData.PowerOnHours, 'Общее время работы 1748 ч');
  Assert.AreEqual<Int64>(266, LData.PowerCycles, 'Число включений 266');
  Assert.AreEqual<Int64>(3, LData.UnsafeShutdowns);
  Assert.AreEqual<Int64>(0, LData.MediaErrors);
  Assert.IsTrue(LData.HasTemperature);
  Assert.AreEqual(32.0, LData.TemperatureCelsius, 0.01);
  Assert.IsTrue(LData.HasWear);
  Assert.AreEqual(0.0, LData.WearPercent, 0.01);
  Assert.AreEqual(100, LData.AvailableSparePercent);
  Assert.AreEqual(10, LData.SpareThresholdPercent);
  Assert.AreEqual(0, LData.CriticalWarning);
  // «Всего хост-чтений 3709 GB», «хост-записей 1918 GB» — двоичные гигабайты.
  Assert.AreEqual(3709.0, Round(LData.TotalReadBytes / (1024.0 * 1024 * 1024)), 0.5);
  Assert.AreEqual(1918.0, Round(LData.TotalWrittenBytes / (1024.0 * 1024 * 1024)), 0.5);
  Assert.AreEqual(-1, FindAttribute(LData, 12).Current, 'У NVMe нет нормализованных значений');
end;

procedure TDiskHealthParseTests.Nvme_TextsAndRawHex;
var
  LData: TMHDiskHealthData;
begin
  MHParseNvmeHealthLog(ClientNvmeLog, LData);
  Assert.AreEqual('1748 ч', MHDiskAttributeText(LData.Source, FindAttribute(LData, 12)));
  Assert.AreEqual('32 °C', MHDiskAttributeText(LData.Source, FindAttribute(LData, 2)));
  Assert.AreEqual('3709 ГБ', MHDiskAttributeText(LData.Source, FindAttribute(LData, 6)));
  Assert.AreEqual('100 %', MHDiskAttributeText(LData.Source, FindAttribute(LData, 3)));
  Assert.AreEqual('нет', MHDiskAttributeText(LData.Source, FindAttribute(LData, 1)));
  Assert.AreEqual('322 мин', MHDiskAttributeText(LData.Source, FindAttribute(LData, 10)));
  // «Сырое» значение — как в столбце Raw CrystalDiskInfo.
  Assert.AreEqual('000000000006D4', MHDiskAttributeRawHex(LData.Source, FindAttribute(LData, 12)));
  Assert.AreEqual('00000000000131', MHDiskAttributeRawHex(LData.Source, FindAttribute(LData, 2)));
  Assert.AreEqual('Часы работы', MHDiskAttributeName(LData.Source, 12));
end;

procedure TDiskHealthParseTests.Nvme_ShortBuffer_False;
var
  LData: TMHDiskHealthData;
begin
  Assert.IsFalse(MHParseNvmeHealthLog(nil, LData));
  Assert.IsFalse(MHParseNvmeHealthLog(Copy(ClientNvmeLog, 0, 511), LData));
  Assert.AreEqual<Int64>(-1, LData.PowerOnHours, 'Неизвестно — не ноль');
end;

procedure TDiskHealthParseTests.Nvme_CriticalWarningWearOverflowAndHugeCounters;
var
  LLog: TBytes;
  LData: TMHDiskHealthData;
begin
  LLog := ClientNvmeLog;
  LLog[0] := $05;              // запас ниже порога и снижена надёжность
  LLog[5] := 120;              // ресурс превышен — диск продолжает работать
  PutLE(LLog, 1, 2, 0);        // датчик температуры молчит
  PutLE(LLog, 160, 8, 12);     // ошибки носителя
  PutLE(LLog, 128 + 8, 8, 1);  // старшие 64 бита счётчика часов — насыщение, без переполнения
  Assert.IsTrue(MHParseNvmeHealthLog(LLog, LData));
  Assert.AreEqual(5, LData.CriticalWarning);
  Assert.AreEqual(100.0, LData.WearPercent, 0.01);
  Assert.IsFalse(LData.HasTemperature);
  Assert.AreEqual<Int64>(12, LData.MediaErrors);
  Assert.AreEqual<Int64>(High(Int64), LData.PowerOnHours);
  Assert.AreEqual('запас ниже порога, надёжность снижена из-за ошибок носителя', MHNvmeCriticalWarningText(5));
  Assert.AreEqual('нет', MHNvmeCriticalWarningText(0));
end;

procedure PutSmart(var AValues: TBytes; AIndex, AId, ACurrent, AWorst: Integer; ARaw: UInt64);
var
  LOffset: Integer;
begin
  LOffset := 2 + AIndex * 12;
  AValues[LOffset] := AId;
  AValues[LOffset + 3] := ACurrent;
  AValues[LOffset + 4] := AWorst;
  PutLE(AValues, LOffset + 5, 6, ARaw);
end;

procedure PutThreshold(var AThresholds: TBytes; AIndex, AId, AThreshold: Integer);
begin
  AThresholds[2 + AIndex * 12] := AId;
  AThresholds[2 + AIndex * 12 + 1] := AThreshold;
end;

procedure TDiskHealthParseTests.Smart_RealDiskWithBadSectors;
var
  LValues, LThresholds: TBytes;
  LData: TMHDiskHealthData;
begin
  // Ответ SMART настоящего диска ST500DM002 (5 из его атрибутов).
  SetLength(LValues, 512);
  FillChar(LValues[0], 512, 0);
  PutSmart(LValues, 0, $05, 100, 100, 0);
  PutSmart(LValues, 1, $09, 86, 86, 12762);
  PutSmart(LValues, 2, $0C, 98, 98, 2668);
  PutSmart(LValues, 3, $C2, 38, 47, 140737488355366);
  PutSmart(LValues, 4, $C5, 100, 100, 8);
  PutSmart(LValues, 5, $C6, 100, 100, 8);
  // Пороги — в другом порядке: ищутся по номеру атрибута.
  SetLength(LThresholds, 512);
  FillChar(LThresholds[0], 512, 0);
  PutThreshold(LThresholds, 0, $0C, 20);
  PutThreshold(LThresholds, 1, $05, 36);
  Assert.IsTrue(MHParseAtaSmart(LValues, LThresholds, LData));
  Assert.AreEqual(MH_HEALTH_SOURCE_SMART, LData.Source);
  Assert.AreEqual(6, Integer(Length(LData.Attributes)));
  Assert.AreEqual<Int64>(12762, LData.PowerOnHours);
  Assert.AreEqual<Int64>(2668, LData.PowerCycles);
  Assert.AreEqual<Int64>(0, LData.ReallocatedSectors);
  Assert.AreEqual<Int64>(8, LData.PendingSectors);
  Assert.AreEqual<Int64>(8, LData.UncorrectableSectors);
  Assert.IsTrue(LData.HasTemperature);
  Assert.AreEqual(38.0, LData.TemperatureCelsius, 0.01, 'Младший байт: 0x800000000026 → 38 °C');
  Assert.AreEqual(36, FindAttribute(LData, $05).Threshold);
  Assert.AreEqual(20, FindAttribute(LData, $0C).Threshold);
  Assert.AreEqual(-1, FindAttribute(LData, $09).Threshold, 'Порога нет');
  Assert.AreEqual(86, FindAttribute(LData, $09).Current);
  Assert.AreEqual('8', MHDiskAttributeText(LData.Source, FindAttribute(LData, $C5)));
  Assert.AreEqual('800000000026', MHDiskAttributeRawHex(LData.Source, FindAttribute(LData, $C2)));
  Assert.IsFalse(LData.HasWear, 'Износ SATA SSD у каждого производителя свой — не угадывается');
end;

procedure TDiskHealthParseTests.Smart_PackedRawValuesAndTemperaturePriority;
var
  LValues: TBytes;
  LData: TMHDiskHealthData;
begin
  SetLength(LValues, 512);
  FillChar(LValues[0], 512, 0);
  // Seagate: в старших байтах часов — служебные данные; часы — младшие 32 бита.
  PutSmart(LValues, 0, $09, 72, 72, 279555126354349);
  // Температура воздушного потока раньше основного датчика: основной важнее.
  PutSmart(LValues, 1, $BE, 59, 52, $2F1E0030);
  PutSmart(LValues, 2, $C2, 41, 48, 77309411369);
  PutSmart(LValues, 3, $C0, 100, 100, 20);
  Assert.IsTrue(MHParseAtaSmart(LValues, nil, LData));
  Assert.AreEqual<Int64>(25005, LData.PowerOnHours);
  Assert.AreEqual(41.0, LData.TemperatureCelsius, 0.01);
  Assert.AreEqual<Int64>(20, LData.UnsafeShutdowns, 'Аварийные парковки — аварийные отключения');
  Assert.AreEqual('25005 ч', MHDiskAttributeText(LData.Source, FindAttribute(LData, $09)));
  Assert.AreEqual(-1, FindAttribute(LData, $09).Threshold, 'Без ответа READ THRESHOLDS порогов нет');
  Assert.AreEqual<Int64>(-1, LData.PendingSectors, 'Атрибута нет — неизвестно');
end;

procedure TDiskHealthParseTests.Smart_EmptyOrShort_False;
var
  LValues: TBytes;
  LData: TMHDiskHealthData;
begin
  SetLength(LValues, 512);
  FillChar(LValues[0], 512, 0);
  Assert.IsFalse(MHParseAtaSmart(LValues, nil, LData), 'Ни одного атрибута');
  Assert.IsFalse(MHParseAtaSmart(Copy(LValues, 0, 100), nil, LData));
end;

procedure TDiskHealthParseTests.Names_KnownAndVendor;
begin
  Assert.AreEqual('Нестабильные секторы', MHDiskAttributeName(MH_HEALTH_SOURCE_SMART, $C5));
  Assert.AreEqual('Атрибут производителя', MHDiskAttributeName(MH_HEALTH_SOURCE_SMART, $FE));
  Assert.AreEqual('Небезопасные отключения', MHDiskAttributeName(MH_HEALTH_SOURCE_NVME, 13));
end;

{ TDiskHealthIntegrationTests }

procedure TDiskHealthIntegrationTests.RealNvmeDisks_HealthLogWithoutAdminRights;
var
  LApi: IMHDiskApi;
  LDisks: TArray<TMHRawDisk>;
  LDisk: TMHRawDisk;
  LData: TMHDiskHealthData;
  LError: string;
  LDenied: Boolean;
  LChecked: Integer;
begin
  LApi := TMHWinDiskApi.Create;
  Assert.IsTrue(LApi.ReadDisks(LDisks, LError), LError);
  LChecked := 0;
  for LDisk in LDisks do
    if SameText(LDisk.Bus, 'NVMe') then
    begin
      Assert.IsTrue(LApi.ReadHealth(LDisk.Number, LDisk.Bus, LData, LError, LDenied),
        Format('Диск %d: %s', [LDisk.Number, LError]));
      Assert.IsFalse(LDenied);
      Assert.AreEqual(15, Integer(Length(LData.Attributes)));
      Assert.IsTrue(LData.PowerOnHours > 0, 'Наработка прочитана');
      Assert.IsTrue(LData.PowerCycles > 0);
      Inc(LChecked);
    end
    else if SameText(LDisk.Bus, 'USB') then
      Assert.IsFalse(LApi.ReadHealth(LDisk.Number, LDisk.Bus, LData, LError, LDenied), 'Через USB не запрашивается');
  if LChecked = 0 then
    Assert.Pass('На этом компьютере нет дисков NVMe');
end;

initialization
  TDUnitX.RegisterTestFixture(TDiskHealthParseTests);
  TDUnitX.RegisterTestFixture(TDiskHealthIntegrationTests);

end.
