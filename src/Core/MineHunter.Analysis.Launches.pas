unit MineHunter.Analysis.Launches;

{
  Правила по событиям запуска процессов (ETW): программа, которая многократно
  запускается и через несколько секунд завершается. Так ведут себя загрузчики
  и «сторожа» майнеров (перезапуск по заданию планировщика, проверка, не открыт
  ли диспетчер задач), а также сценарии PowerShell/cmd, запускаемые по
  расписанию. Сами по себе частые короткие запуски нормальны для сборки
  программ, git, браузеров и служб Windows, поэтому один признак даёт лишь
  «требует проверки», а уровень повышают расположение, имя и сценарный хост.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Analysis.Tamper;

const
  EV_LAUNCH_LOOP = 'LAUNCH_LOOP';
  EV_LAUNCH_LOCATION = 'LAUNCH_SUSPICIOUS_LOCATION';
  EV_LAUNCH_MINER_NAME = 'LAUNCH_MINER_NAME';
  EV_LAUNCH_SCRIPT_HOST = 'LAUNCH_SCRIPT_HOST';
  EV_LAUNCH_STANDARD = 'LAUNCH_STANDARD_LOCATION';
  EV_LAUNCH_WORKLOAD = 'LAUNCH_KNOWN_WORKLOAD';

  /// Минимум запусков и коротких запусков за окно для правила.
  MH_LAUNCH_MIN_STARTS = 8;
  MH_LAUNCH_MIN_SHORT = 6;

function MHAnalyzeLaunches(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const AIsExcluded: TMHExclusionCheck; const ARulesetVersion: string): TMHFindings;

/// Сценарные хосты Windows (powershell, cmd, wscript, cscript, mshta).
function MHIsScriptHost(const AName: string): Boolean;

implementation

uses
  System.Hash, MineHunter.Core.Lang, MineHunter.Analysis.Indicators;

const
  SCRIPT_HOSTS: array[0..6] of string = ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'rundll32.exe');
  /// Процессы, которые запускают задания планировщика и службы.
  SCHEDULER_PARENTS: array[0..3] of string = ('svchost.exe', 'taskeng.exe', 'taskhostw.exe', 'wmiprvse.exe');

function InList(const AValue: string; const AList: array of string): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

function MHIsScriptHost(const AName: string): Boolean;
begin
  Result := InList(ExtractFileName(AName), SCRIPT_HOSTS);
end;

function FindingId(const AKey: string): TGUID;
var
  LBytes: TBytes;
begin
  LBytes := THashMD5.GetHashBytes(AKey);
  Move(LBytes[0], Result, SizeOf(TGUID));
  Result.D3 := (Result.D3 and $0FFF) or $3000;
  Result.D4[0] := (Result.D4[0] and $3F) or $80;
end;

function FileSha(const ASnapshot: TMHSnapshot; const APath: string): string;
var
  LFile: TMHFileInfo;
begin
  if (APath <> '') and ASnapshot.FindFile(APath, LFile) then
    Result := LFile.Sha256
  else
    Result := '';
end;

function AnalyzeLaunch(const ASnapshot: TMHSnapshot; const AStat: TMHLaunchStat;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LName, LReason, LObserved, LSummary: string;
  LRaw: Integer;
  LItem: TMHEvidence;
  LWorkload: TMHWorkloadCategory;
  LScript, LByScheduler: Boolean;
begin
  Result := False;
  AFinding := Default(TMHFinding);
  if (AStat.Starts < MH_LAUNCH_MIN_STARTS) or (AStat.ShortLived < MH_LAUNCH_MIN_SHORT) then
    Exit;
  LName := AStat.Name;
  if LName = '' then
    LName := ExtractFileName(AStat.ImagePath);
  LObserved := Format(MHL('%d запусков за %d мин, из них %d завершились быстрее %d с',
    '%d launches in %d min, %d of them exited in under %d s'),
    [AStat.Starts, AStat.WindowMinutes, AStat.ShortLived, AStat.ShortLivedSeconds]);
  if AStat.Exited > 0 then
    LObserved := LObserved + Format(MHL(' (в среднем %.1f с)', ' (%.1f s on average)'), [AStat.AverageLifetimeSeconds]);
  LEvidence := [TMHEvidence.Create(EV_LAUNCH_LOOP,
    MHL('Программа многократно запускается и почти сразу завершается — так работают загрузчики ',
    'The program repeatedly starts and exits almost immediately — this is how loaders ') +
    MHL('и «сторожа», перезапускающие скрытые программы', 'and "watchdogs" that restart hidden programs work'),
    25, LObserved)];

  if MHIsSuspiciousLocation(AStat.ImagePath, LReason) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_LAUNCH_LOCATION,
      MHL('Файл находится в нетипичном для программ месте: ', 'The file is in a location atypical for programs: ') +
      LReason, 20, AStat.ImagePath)];
  if MHIsKnownMinerName(LName) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_LAUNCH_MINER_NAME,
      MHL('Имя совпадает с известной программой для майнинга', 'The name matches a known mining program'), 35, LName)];
  LScript := MHIsScriptHost(LName);
  LByScheduler := InList(AStat.LastParentName, SCHEDULER_PARENTS);
  if LScript and LByScheduler then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_LAUNCH_SCRIPT_HOST,
      MHL('Сценарий (', 'Script (') + LName +
      MHL(') раз за разом запускается службой или планировщиком заданий',
      ') is launched over and over by a service or the Task Scheduler'), 15,
      MHL('родитель: ', 'parent: ') + AStat.LastParentName)];

  // Оправдывающие факторы: известная вычислительная нагрузка и стандартные папки установки.
  LWorkload := MHWorkloadCategoryOf(LName, AStat.ImagePath);
  if LWorkload in [wlBuild, wlUpdate, wlSecurity, wlBrowser] then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_LAUNCH_WORKLOAD,
      MHL('Похоже на известную нагрузку: ', 'Looks like a known workload: ') +
      MHWorkloadCategoryToString(LWorkload), -30, LName)];
  if not LScript and MHIsStandardInstallLocation(AStat.ImagePath) then
    LEvidence := LEvidence + [TMHEvidence.Create(EV_LAUNCH_STANDARD,
      MHL('Программа установлена в стандартную папку (Program Files или Windows)',
      'The program is installed in a standard folder (Program Files or Windows)'), -15, AStat.ImagePath)];

  LRaw := 0;
  for LItem in LEvidence do
    Inc(LRaw, LItem.Weight);
  if MHClampScore(LRaw) < AThresholds.Low then
    Exit;

  AFinding.Category := fcSuspicious;
  AFinding.ProcessName := LName;
  AFinding.ImagePath := AStat.ImagePath;
  AFinding.ParentPid := AStat.LastParentPid;
  AFinding.Title := MHL('Программа часто запускается и сразу завершается',
    'A program frequently starts and immediately exits');
  AFinding.Evidence := LEvidence;
  AFinding.RawScore := LRaw;
  AFinding.Score := MHClampScore(LRaw);
  AFinding.Level := AThresholds.LevelOf(AFinding.Score);
  AFinding.Confidence := 1.0;
  AFinding.RulesetVersion := ARuleset;
  AFinding.DetectedAtUtc := ASnapshot.TimestampUtc;
  LSummary := Format('%s: %s.', [LName, LObserved]);
  if AStat.LastParentName <> '' then
    LSummary := LSummary + Format(MHL(' Последний раз её запустил %s (PID %d).',
      ' It was last launched by %s (PID %d).'), [AStat.LastParentName, AStat.LastParentPid]);
  AFinding.Summary := Format(MHL('%s Оценка %d из 100 (%s). Это повод для проверки, а не диагноз.',
    '%s Score %d out of 100 (%s). This is a reason to check, not a diagnosis.'),
    [LSummary, AFinding.Score, MHRiskLevelToString(AFinding.Level)]);
  AFinding.Recommendations := [
    MHL('Посмотрите, что запускает программу: задания планировщика и автозапуск на странице «Находки» ',
    'Check what launches the program: scheduled tasks and autostart on the "Findings" page ') +
    MHL('и в отчёте «Проверить сейчас» (раздел «Что изменилось»).',
    'and in the "Check now" report ("What changed" section).'),
    MHL('Если программа вам незнакома — проверьте файл Microsoft Defender из карточки находки.',
    'If you do not recognize the program, scan the file with Microsoft Defender from the finding card.'),
    MHL('Сборка программ, git, обновления и браузеры тоже часто запускают короткие процессы — ',
    'Software builds, git, updates and browsers also often launch short-lived processes — ') +
    MHL('если это ваша работа, добавьте программу в разрешённые.',
    'if this is your work, add the program to the allowed list.')];
  AFinding.Key := 'launch:' + AStat.ImagePath.ToLower;
  AFinding.Id := FindingId(AFinding.Key);
  Result := True;
end;

function MHAnalyzeLaunches(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const AIsExcluded: TMHExclusionCheck; const ARulesetVersion: string): TMHFindings;
var
  LStat: TMHLaunchStat;
  LFinding: TMHFinding;
begin
  Result := nil;
  for LStat in ASnapshot.Launches do
  begin
    if LStat.ImagePath = '' then
      Continue;
    if Assigned(AIsExcluded) and AIsExcluded(MHProgramKey(LStat.ImagePath, LStat.Name),
       FileSha(ASnapshot, LStat.ImagePath)) then
      Continue;
    if AnalyzeLaunch(ASnapshot, LStat, AThresholds, ARulesetVersion, LFinding) then
      Result := Result + [LFinding];
  end;
end;

end.
