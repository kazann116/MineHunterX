unit MineHunter.Analysis.Disks;

{
  Правила по дискам: мало места на разделе, состояние диска по оценке
  Windows (учитывает прогноз отказа SMART), износ SSD, ошибки чтения и записи.
  Это причины замедления и риски потери данных, а не угрозы: находки получают
  категорию «необычная нагрузка» (fcPerformance) и умеренные оценки.
  Также — текст «кто грузит диск» для объяснения нагрузки.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types;

const
  EV_DISK_LOW_SPACE = 'DISK_LOW_SPACE';
  EV_DISK_HEALTH = 'DISK_HEALTH';
  EV_DISK_WEAR = 'DISK_WEAR';
  EV_DISK_ERRORS = 'DISK_ERRORS';

type
  TMHSpaceLevel = (slOk, slLow, slCritical);

/// Насколько мало места на разделе. Маленькие (< 1 ГБ) и съёмные разделы не оцениваются.
function MHVolumeSpaceLevel(const AVolume: TMHVolumeInfo): TMHSpaceLevel;

function MHAnalyzeDisks(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const ARulesetVersion: string): TMHFindings;

/// Самый занятый диск (по доле времени работы). False — данных нет.
function MHBusiestDisk(const ASnapshot: TMHSnapshot; out ADisk: TMHDiskInfo): Boolean;

/// «Диск 1 (ST500DM002; F: H:)».
function MHDiskLabel(const ADisk: TMHDiskInfo): string;

/// Процессы с наибольшим вводом-выводом: «setup.exe 25,1 МБ/с, …» ('' — нет данных).
function MHTopIoProcesses(const ASnapshot: TMHSnapshot; ATop: Integer = 3; AMinBytesPerSec: Double = 64 * 1024): string;

/// Байты в секунду в читаемом виде.
function MHFormatRate(ABytesPerSec: Double): string;
function MHFormatSize(ABytes: Double): string;

implementation

uses
  Winapi.Windows, System.Math, System.Hash, System.Generics.Collections, System.Generics.Defaults,
  MineHunter.Core.Lang;

const
  GB = 1024.0 * 1024 * 1024;

function FindingId(const AKey: string): TGUID;
var
  LBytes: TBytes;
begin
  LBytes := THashMD5.GetHashBytes(AKey);
  Move(LBytes[0], Result, SizeOf(TGUID));
  Result.D3 := (Result.D3 and $0FFF) or $3000;
  Result.D4[0] := (Result.D4[0] and $3F) or $80;
end;

function MHFormatSize(ABytes: Double): string;
begin
  if ABytes >= 1024 * GB then
    Result := FormatFloat('0.0', ABytes / (1024 * GB)) + MHL(' ТБ', ' TB')
  else if ABytes >= GB then
    Result := FormatFloat('0.0', ABytes / GB) + MHL(' ГБ', ' GB')
  else if ABytes >= 1024 * 1024 then
    Result := FormatFloat('0', ABytes / (1024 * 1024)) + MHL(' МБ', ' MB')
  else
    Result := FormatFloat('0', ABytes / 1024) + MHL(' КБ', ' KB');
end;

function MHFormatRate(ABytesPerSec: Double): string;
begin
  if ABytesPerSec >= 1024 * 1024 then
    Result := FormatFloat('0.0', ABytesPerSec / (1024 * 1024)) + MHL(' МБ/с', ' MB/s')
  else
    Result := FormatFloat('0', ABytesPerSec / 1024) + MHL(' КБ/с', ' KB/s');
end;

function MHVolumeSpaceLevel(const AVolume: TMHVolumeInfo): TMHSpaceLevel;
var
  LFree, LPercent, LLowBytes: Double;
begin
  Result := slOk;
  if AVolume.Removable or (AVolume.TotalBytes < GB) then
    Exit;
  LFree := AVolume.FreeBytes;
  LPercent := AVolume.FreePercent;
  // Системному разделу места нужно больше: обновления, файл подкачки, временные файлы.
  if AVolume.IsSystem then
    LLowBytes := 10 * GB
  else
    LLowBytes := 5 * GB;
  if (LPercent < 5) or (LFree < 2 * GB) then
    Result := slCritical
  else if (LPercent < 10) or (LFree < LLowBytes) then
    Result := slLow;
end;

function MHDiskLabel(const ADisk: TMHDiskInfo): string;
begin
  Result := Format(MHL('Диск %d', 'Disk %d'), [ADisk.Number]);
  if (ADisk.Model <> '') and not SameText(ADisk.Model, Result) then
  begin
    Result := Result + ' (' + ADisk.Model;
    if ADisk.Volumes <> '' then
      Result := Result + '; ' + ADisk.Volumes;
    Result := Result + ')';
  end
  else if ADisk.Volumes <> '' then
    Result := Result + ' (' + ADisk.Volumes + ')';
end;

function MHBusiestDisk(const ASnapshot: TMHSnapshot; out ADisk: TMHDiskInfo): Boolean;
var
  LDisk: TMHDiskInfo;
begin
  Result := False;
  ADisk := Default(TMHDiskInfo);
  for LDisk in ASnapshot.Disks do
    if LDisk.HasActivity and (not Result or (LDisk.ActivePercent > ADisk.ActivePercent)) then
    begin
      ADisk := LDisk;
      Result := True;
    end;
end;

/// Чтение + запись процесса, байт/с.
function Total(const AInfo: TMHProcessInfo): Double;
begin
  Result := 0;
  if AInfo.IoRead.HasValue then
    Result := Result + AInfo.IoRead.Value;
  if AInfo.IoWrite.HasValue then
    Result := Result + AInfo.IoWrite.Value;
end;

function MHTopIoProcesses(const ASnapshot: TMHSnapshot; ATop: Integer; AMinBytesPerSec: Double): string;
var
  LList: TList<TMHProcessInfo>;
  LInfo: TMHProcessInfo;
  I: Integer;
begin
  Result := '';
  LList := TList<TMHProcessInfo>.Create;
  try
    for LInfo in ASnapshot.Processes do
      // Сам MineHunter (хеширование файлов при запуске) причиной замедления не называется.
      if (LInfo.IoRead.HasValue or LInfo.IoWrite.HasValue) and (Total(LInfo) >= AMinBytesPerSec) and
         not SameText(LInfo.SourceId, MH_SELF_SOURCE_ID) and (LInfo.Id.Pid <> GetCurrentProcessId) then
        LList.Add(LInfo);
    LList.Sort(TComparer<TMHProcessInfo>.Construct(
      function(const A, B: TMHProcessInfo): Integer
      begin
        Result := CompareValue(Total(B), Total(A));
        if Result = 0 then
          Result := CompareText(A.Name, B.Name);
      end));
    for I := 0 to Min(ATop, LList.Count) - 1 do
    begin
      if Result <> '' then
        Result := Result + ', ';
      Result := Result + LList[I].Name + ' ' + MHFormatRate(Total(LList[I]));
    end;
  finally
    LList.Free;
  end;
end;

function NewFinding(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const ARuleset, AKey, ATitle, ASummary: string; const AEvidence: TArray<TMHEvidence>;
  const ARecommendations: TArray<string>): TMHFinding;
var
  LEvidence: TMHEvidence;
begin
  Result := Default(TMHFinding);
  Result.Category := fcPerformance;
  Result.Key := AKey;
  Result.Id := FindingId(AKey);
  Result.Title := ATitle;
  Result.Evidence := AEvidence;
  Result.RawScore := 0;
  for LEvidence in AEvidence do
    Inc(Result.RawScore, LEvidence.Weight);
  Result.Score := MHClampScore(Result.RawScore);
  Result.Level := AThresholds.LevelOf(Result.Score);
  Result.Confidence := 1.0;
  Result.RulesetVersion := ARuleset;
  Result.DetectedAtUtc := ASnapshot.TimestampUtc;
  Result.Summary := MHL('Риск для скорости работы и сохранности данных, а не угроза. ',
    'A risk to performance and data safety, not a threat. ') + ASummary;
  Result.Recommendations := ARecommendations;
end;

function SpaceFinding(const ASnapshot: TMHSnapshot; const AVolume: TMHVolumeInfo; ALevel: TMHSpaceLevel;
  const AThresholds: TMHRiskThresholds; const ARuleset: string): TMHFinding;
var
  LTitle, LObserved: string;
  LWeight: Integer;
  LRecommend: TArray<string>;
begin
  LObserved := Format(MHL('свободно %s из %s (%.1f%%)', 'free %s of %s (%.1f%%)'),
    [MHFormatSize(AVolume.FreeBytes), MHFormatSize(AVolume.TotalBytes), AVolume.FreePercent]);
  if ALevel = slCritical then
  begin
    LTitle := Format(MHL('Раздел %s почти заполнен', 'Volume %s is almost full'), [AVolume.Name]);
    LWeight := 40;
  end
  else
  begin
    LTitle := Format(MHL('Мало свободного места на разделе %s', 'Low free space on volume %s'), [AVolume.Name]);
    LWeight := 25;
  end;
  if AVolume.IsSystem then
  begin
    Inc(LWeight, 5);
    LRecommend := [MHL('Когда на разделе с Windows мало места, система замедляется, не может установить ' +
      'обновления и создать точки восстановления.', 'When the Windows volume runs low on space, the system ' +
      'slows down and cannot install updates or create restore points.'),
      MHL('Запустите «Очистку диска» (cleanmgr) с очисткой системных файлов, удалите ненужные программы ' +
      'и перенесите личные файлы на другой раздел.', 'Run Disk Cleanup (cleanmgr) including system files, ' +
      'uninstall programs you do not need and move personal files to another volume.')];
  end
  else
    LRecommend := [MHL('Удалите или перенесите ненужные файлы. При почти полном разделе запись ' +
      'замедляется, а файлы сильнее фрагментируются.', 'Delete or move files you do not need. ' +
      'On an almost full volume writing slows down and files get more fragmented.')];
  Result := NewFinding(ASnapshot, AThresholds, ARuleset, 'disk:space:' + AVolume.Name.ToLower, LTitle,
    LTitle + ': ' + LObserved + '.',
    [TMHEvidence.Create(EV_DISK_LOW_SPACE, LTitle, LWeight, LObserved)], LRecommend);
  Result.ProcessName := AVolume.Name;
end;

function HealthFinding(const ASnapshot: TMHSnapshot; const ADisk: TMHDiskInfo;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LTitle, LText: string;
  LErrors: Int64;
begin
  LEvidence := nil;
  LTitle := '';
  case ADisk.Health of
    dhUnhealthy:
      begin
        LTitle := MHL('Диск неисправен по оценке Windows', 'Windows reports the disk as unhealthy');
        LText := LTitle;
        if ADisk.HealthDetails <> '' then
          LText := LText + ': ' + ADisk.HealthDetails;
        LEvidence := LEvidence + [TMHEvidence.Create(EV_DISK_HEALTH, LText, 60, ADisk.HealthDetails)];
      end;
    dhWarning:
      begin
        LTitle := MHL('Диск сообщает о неполадках', 'The disk reports problems');
        LText := MHL('Windows отмечает предупреждение о состоянии диска (например, прогноз отказа SMART)',
          'Windows reports a disk health warning (for example, a SMART failure prediction)');
        LEvidence := LEvidence + [TMHEvidence.Create(EV_DISK_HEALTH, LText, 40, ADisk.HealthDetails)];
      end;
  end;
  if ADisk.HasWear and (ADisk.WearPercent >= 80) then
  begin
    if LTitle = '' then
      LTitle := MHL('Ресурс SSD почти исчерпан', 'The SSD is close to the end of its life');
    LEvidence := LEvidence + [TMHEvidence.Create(EV_DISK_WEAR,
      MHL('Израсходована большая часть ресурса записи SSD', 'Most of the SSD write endurance is used'),
      IfThen(ADisk.WearPercent >= 95, 50, 30), Format(MHL('износ %.0f%%', 'wear %.0f%%'), [ADisk.WearPercent]))];
  end;
  if ADisk.HasErrors then
  begin
    LErrors := ADisk.ReadErrors + ADisk.WriteErrors;
    if LErrors > 0 then
    begin
      if LTitle = '' then
        LTitle := MHL('Диск сообщает об ошибках чтения или записи', 'The disk reports read or write errors');
      LEvidence := LEvidence + [TMHEvidence.Create(EV_DISK_ERRORS,
        MHL('Счётчики диска фиксируют ошибки чтения или записи', 'The disk counters record read or write errors'),
        IfThen(LErrors >= 100, 35, 15),
        Format(MHL('ошибок чтения: %d, записи: %d за всё время', 'read errors: %d, write errors: %d in total'),
          [ADisk.ReadErrors, ADisk.WriteErrors]))];
    end;
  end;
  Result := Length(LEvidence) > 0;
  if not Result then
    Exit;
  AFinding := NewFinding(ASnapshot, AThresholds, ARuleset,
    Format('disk:health:%d:%s', [ADisk.Number, ADisk.Model.ToLower]), LTitle,
    MHDiskLabel(ADisk) + ': ' + LTitle + '.', LEvidence,
    [MHL('Сделайте резервную копию важных данных с этого диска.', 'Back up important data from this disk.'),
     MHL('Проверьте диск программой производителя или командой «chkdsk»; если число ошибок растёт ' +
     'или состояние ухудшается — замените диск.', 'Check the disk with the manufacturer''s tool or ' +
     '"chkdsk"; if the number of errors grows or the state gets worse, replace the disk.')]);
  AFinding.ProcessName := MHDiskLabel(ADisk);
  // Неисправный диск — повод действовать сразу, даже при умеренной сумме признаков.
  if (ADisk.Health = dhUnhealthy) and (AFinding.Level < rlSuspicious) then
    AFinding.Level := rlSuspicious;
end;

function MHAnalyzeDisks(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const ARulesetVersion: string): TMHFindings;
var
  LVolume: TMHVolumeInfo;
  LLevel: TMHSpaceLevel;
  LDisk: TMHDiskInfo;
  LFinding: TMHFinding;
begin
  Result := nil;
  for LVolume in ASnapshot.Volumes do
  begin
    LLevel := MHVolumeSpaceLevel(LVolume);
    if LLevel <> slOk then
    begin
      LFinding := SpaceFinding(ASnapshot, LVolume, LLevel, AThresholds, ARulesetVersion);
      if LFinding.Score >= AThresholds.Low then
        Result := Result + [LFinding];
    end;
  end;
  for LDisk in ASnapshot.Disks do
    if HealthFinding(ASnapshot, LDisk, AThresholds, ARulesetVersion, LFinding) and
       (LFinding.Score >= AThresholds.Low) then
      Result := Result + [LFinding];
end;

end.
