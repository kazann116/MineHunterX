unit MineHunter.Analysis.Tamper;

{
  Правила оценки признаков вмешательства в защиту системы (подписки WMI,
  исключения Defender, перехват запуска программ, hosts, политики).

  Каждый признак — отдельная находка с объяснением, оправдывающими факторами
  и рекомендациями. Оправдания учитывают типичные легальные случаи:
  Process Explorer вместо диспетчера задач, исключения, заданные политикой
  организации, отключение обновлений через hosts, подписанные программы
  производителей в Program Files, отладчики разработчика.

  Чистые функции: только данные снимка, без обращений к системе.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types;

const
  EV_WMI_PERSISTENCE = 'WMI_PERSISTENCE';
  EV_AV_EXCLUSION = 'AV_EXCLUSION';
  EV_AV_EXCLUDED = 'AV_EXCLUDED';
  EV_EXECUTION_HIJACK = 'EXECUTION_HIJACK';
  EV_ACCESSIBILITY_HIJACK = 'ACCESSIBILITY_HIJACK';
  EV_SILENT_EXIT = 'SILENT_EXIT_MONITOR';
  EV_HOSTS_BLOCK = 'HOSTS_SECURITY_BLOCK';
  EV_HOSTS_RELOCATED = 'HOSTS_RELOCATED';
  EV_POLICY_RESTRICTION = 'POLICY_RESTRICTION';
  EV_TAMPER_LINK = 'TAMPER_LINK';
  EV_CORPORATE_POLICY = 'CORPORATE_POLICY';
  EV_DEV_TOOL = 'DEVELOPER_TOOL';
  EV_INERT = 'NOT_TRIGGERED';
  EV_UPDATES_ONLY = 'UPDATES_ONLY';
  EV_POLICY_NO_DOMAIN = 'POLICY_WITHOUT_DOMAIN';
  EV_MINER_ARTIFACT = 'MINER_ARTIFACT';
  EV_HIDDEN_FILE = 'HIDDEN_SYSTEM_FILE';
  EV_PROGRAMDATA_EXE = 'PROGRAMDATA_EXECUTABLE';
  EV_FILES_GONE = 'FILES_GONE';

type
  /// Проверка исключения пользователя: ключ находки и SHA-256 файла.
  TMHExclusionCheck = reference to function(const AKey, ASha256: string): Boolean;

/// Находки по признакам вмешательства снимка.
function MHAnalyzeTamper(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const AIsExcluded: TMHExclusionCheck; const ARulesetVersion: string): TMHFindings;

/// Признаки вмешательства, относящиеся к программе AImagePath: её папка или имя
/// исключены из проверки антивирусом, её запускает подписка WMI или перехват IFEO.
/// AExcludedFromAv = True, если программа исключена из проверки Defender.
function MHTamperEvidenceFor(const ASnapshot: TMHSnapshot; const AImagePath, AName: string;
  out AExcludedFromAv: Boolean): TArray<TMHEvidence>;

implementation

uses
  System.Math, System.StrUtils, System.Hash,
  MineHunter.Core.Paths, MineHunter.Analysis.Indicators;

const
  /// Обновления Windows блокируют и намеренно — это слабее, чем блокировка антивирусов.
  UPDATE_DOMAIN_HINTS: array[0..3] of string = ('windowsupdate', 'update.microsoft.com',
    'definitionupdates', 'go.microsoft.com');
  /// Отладчики, которые разработчики ставят в IFEO для своих программ.
  DEV_DEBUGGERS: array[0..5] of string = ('vsjitdebugger.exe', 'windbg.exe', 'windbgx.exe',
    'devenv.exe', 'ntsd.exe', 'cdb.exe');

procedure AddEvidence(var AItems: TArray<TMHEvidence>; const ACode, ADescription: string;
  AWeight: Integer; const AObserved: string = '');
begin
  AItems := AItems + [TMHEvidence.Create(ACode, ADescription, AWeight, AObserved)];
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

function InList(const AValue: string; const AList: array of string): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

/// Корень диска, каталог Windows, профиль пользователя и другие папки целиком.
function IsBroadPath(const APath: string): Boolean;
var
  LPath: string;
begin
  LPath := ExcludeTrailingPathDelimiter(MHNormalizePath(APath)).ToLower;
  Result := (LPath = '') or (Length(LPath) <= 2) or LPath.EndsWith(':') or
    LPath.EndsWith(':\windows') or LPath.EndsWith(':\windows\system32') or
    LPath.EndsWith(':\users') or LPath.EndsWith(':\programdata') or
    LPath.EndsWith(':\program files') or LPath.EndsWith(':\program files (x86)') or
    (LPath.Contains(':\users\') and (LPath.CountChar('\') = 2)) or
    LPath.EndsWith('\appdata') or LPath.EndsWith('\appdata\local') or
    LPath.EndsWith('\appdata\roaming') or LPath.EndsWith('\temp') or LPath.EndsWith('\downloads');
end;

function SignedVendorFile(const ASnapshot: TMHSnapshot; const APath: string; out ASigner: string): Boolean;
var
  LFile: TMHFileInfo;
begin
  ASigner := '';
  Result := (APath <> '') and ASnapshot.FindFile(APath, LFile) and (LFile.Signature = sgSignedTrusted) and
    MHIsStandardInstallLocation(APath);
  if Result then
    ASigner := LFile.Signer;
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

/// Признаки в команде: обфускация, скрытый сценарий, майнинг, расположение, подпись.
procedure CommandEvidence(const ASnapshot: TMHSnapshot; const AEntry: TMHTamperEntry;
  var AEvidence: TArray<TMHEvidence>; var AMining: Boolean);
var
  LReason, LToken, LFolder: string;
  LFile: TMHFileInfo;
begin
  LToken := MHFindObfuscatedCommand(AEntry.Value);
  if LToken <> '' then
    AddEvidence(AEvidence, 'OBFUSCATED_COMMAND', 'Команда скрыта (закодирована)', 35, LToken)
  else
  begin
    LToken := MHFindHiddenScriptLaunch(AEntry.Value);
    if LToken <> '' then
      AddEvidence(AEvidence, 'HIDDEN_SCRIPT', 'Сценарий запускается скрыто', 20, LToken);
  end;
  LToken := MHFindMinerCommandToken(AEntry.Value);
  if (LToken <> '') or ((AEntry.ImagePath <> '') and MHIsKnownMinerName(AEntry.ImagePath)) then
  begin
    if LToken = '' then
      LToken := ExtractFileName(AEntry.ImagePath);
    AddEvidence(AEvidence, 'MINER_CMDLINE', 'Команда запускает майнер', 40, LToken);
    AMining := True;
  end;
  if (AEntry.ImagePath <> '') and MHIsSuspiciousLocation(AEntry.ImagePath, LReason) then
    AddEvidence(AEvidence, 'SUSPICIOUS_LOCATION', 'Программа находится в необычном месте', 20, LReason)
  else if (AEntry.ImagePath <> '') and MHFindRandomLookingFolder(AEntry.ImagePath, LFolder) then
    AddEvidence(AEvidence, 'RANDOM_FOLDER', 'Программа в папке со случайным именем', 20, LFolder);
  if (AEntry.ImagePath <> '') and ASnapshot.FindFile(AEntry.ImagePath, LFile) then
    case LFile.Signature of
      sgUnsigned:
        AddEvidence(AEvidence, 'UNSIGNED', 'Файл без цифровой подписи', 10);
      sgSignedUntrusted:
        AddEvidence(AEvidence, 'SIGNATURE_INVALID', 'Подпись недействительна', 25, LFile.Error);
    end;
end;

function HasPositiveBeyond(const AEvidence: TArray<TMHEvidence>; const ABaseCode: string): Boolean;
var
  LEvidence: TMHEvidence;
begin
  for LEvidence in AEvidence do
    if (LEvidence.Weight > 0) and (LEvidence.Code <> ABaseCode) then
      Exit(True);
  Result := False;
end;

function Finish(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const AImagePath, AName, AKey, ATitle, ASummary: string; ACategory: TMHFindingCategory;
  const AEvidence: TArray<TMHEvidence>; const ARecommend: TArray<string>;
  const ARulesetVersion: string; out AFinding: TMHFinding): Boolean;
var
  LRaw: Integer;
  LEvidence: TMHEvidence;
begin
  AFinding := Default(TMHFinding);
  LRaw := 0;
  for LEvidence in AEvidence do
    Inc(LRaw, LEvidence.Weight);
  Result := (Length(AEvidence) > 0) and (MHClampScore(LRaw) >= AThresholds.Low);
  if not Result then
    Exit;
  AFinding.Category := ACategory;
  if AImagePath <> '' then
    AFinding.ProcessName := ExtractFileName(AImagePath)
  else
    AFinding.ProcessName := AName;
  AFinding.ImagePath := AImagePath;
  AFinding.Title := ATitle;
  AFinding.Evidence := AEvidence;
  AFinding.Recommendations := ARecommend;
  AFinding.RawScore := LRaw;
  AFinding.Score := MHClampScore(LRaw);
  AFinding.Level := AThresholds.LevelOf(AFinding.Score);
  AFinding.Confidence := 1.0;
  AFinding.RulesetVersion := ARulesetVersion;
  AFinding.DetectedAtUtc := ASnapshot.TimestampUtc;
  AFinding.Summary := Format('%s Оценка %d из 100 (%s). Это повод для проверки, а не диагноз.',
    [ASummary, AFinding.Score, MHRiskLevelToString(AFinding.Level)]);
  AFinding.Key := AKey;
  AFinding.Id := FindingId(AKey);
end;

{ Правила по видам }

function AnalyzeWmi(const ASnapshot: TMHSnapshot; const AEntry: TMHTamperEntry;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LRecommend: TArray<string>;
  LMining: Boolean;
  LSigner: string;
  LCategory: TMHFindingCategory;
begin
  LEvidence := nil;
  LMining := False;
  AddEvidence(LEvidence, EV_WMI_PERSISTENCE,
    'Подписка WMI выполняет команду по событию — скрытый автозапуск, которого нет в обычных списках', 50,
    AEntry.Name + ': ' + Copy(AEntry.Value, 1, 200));
  if AEntry.Details.Contains('сценарий') then
    AddEvidence(LEvidence, 'WMI_SCRIPT', 'Подписка содержит встроенный сценарий (VBScript/JScript)', 10);
  CommandEvidence(ASnapshot, AEntry, LEvidence, LMining);
  if AEntry.Details.Contains('не привязана') then
    AddEvidence(LEvidence, EV_INERT, 'Подписка не привязана к событию и сама не срабатывает', -20);
  if SignedVendorFile(ASnapshot, AEntry.ImagePath, LSigner) and
     not HasPositiveBeyond(LEvidence, EV_WMI_PERSISTENCE) then
    AddEvidence(LEvidence, 'SIGNED_TRUSTED', 'Запускает подписанную программу из Program Files', -20, LSigner);
  LRecommend := ['Посмотрите подписку в PowerShell от имени администратора: Get-CimInstance ' +
    '-Namespace root\subscription -ClassName CommandLineEventConsumer, ActiveScriptEventConsumer.',
    'Подписки WMI создают и программы управления компьютером в организации, и резервное копирование — ' +
    'не удаляйте подписку, если знаете, какая программа её создала.'];
  if LMining then
  begin
    LRecommend := LRecommend + ['Команда подписки запускает майнер — проверьте файл в Microsoft Defender.'];
    LCategory := fcMining;
  end
  else
    LCategory := fcPersistence;
  Result := Finish(ASnapshot, AThresholds, AEntry.ImagePath, AEntry.Name, 'tamper:wmi:' + AEntry.Name.ToLower,
    'Скрытый автозапуск через WMI: ' + AEntry.Name,
    'Подписка «' + AEntry.Name + '» запускает: ' + Copy(AEntry.Value, 1, 300) + '.',
    LCategory, LEvidence, LRecommend, ARuleset, AFinding);
end;

/// Ключ группы исключений: отдельные файлы — по папке, папки и прочее — по значению.
function DefenderGroupKey(const AEntry: TMHTamperEntry): string;
begin
  if (AEntry.Details.StartsWith('путь') or AEntry.Details.StartsWith('процесс')) and
     (ExtractFileExt(AEntry.Name) <> '') and (ExtractFileDir(AEntry.ImagePath) <> '') then
    Result := 'files:' + ExtractFileDir(AEntry.ImagePath).ToLower
  else
    Result := 'item:' + AEntry.Name.ToLower;
end;

/// Политика и домен: в организации исключения и запреты задаёт администратор,
/// на домашнем компьютере политику обычно прописывает сама вредоносная программа.
procedure PolicyEvidence(const AEntries: TArray<TMHTamperEntry>; var AEvidence: TArray<TMHEvidence>);
var
  LEntry: TMHTamperEntry;
  LByPolicy, LManaged: Boolean;
begin
  LByPolicy := False;
  LManaged := False;
  for LEntry in AEntries do
  begin
    LByPolicy := LByPolicy or LEntry.Details.Contains('политикой') or (LEntry.Kind = tpPolicyRestriction);
    LManaged := LManaged or LEntry.ManagedComputer;
  end;
  if not LByPolicy then
    Exit;
  if LManaged then
    AddEvidence(AEvidence, EV_CORPORATE_POLICY,
      'Задано политикой на компьютере организации (обычно это делает администратор)', -10)
  else
    AddEvidence(AEvidence, EV_POLICY_NO_DOMAIN,
      'Задано через политику, хотя компьютер не управляется организацией — так делают вредоносные программы',
      10);
end;

function AnalyzeDefenderGroup(const ASnapshot: TMHSnapshot; const AEntries: TArray<TMHTamperEntry>;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LEntry: TMHTamperEntry;
  LReason, LFolder, LNames, LMasquerade, LArtifacts, LKind, LTitle, LDir: string;
  LWeight, LBest, LMissing, LHidden, LProgramDataExe: Integer;
  LBestText: string;
  LMining, LMinerName, LIsFiles: Boolean;
  LCategory: TMHFindingCategory;
begin
  LEvidence := nil;
  LMinerName := False;
  LBest := 0;
  LBestText := '';
  LNames := '';
  LMasquerade := '';
  LArtifacts := '';
  LMissing := 0;
  LHidden := 0;
  LProgramDataExe := 0;
  LMining := False;
  LIsFiles := DefenderGroupKey(AEntries[0]).StartsWith('files:');
  for LEntry in AEntries do
  begin
    LKind := LEntry.Details;
    if LKind.StartsWith('расширение') then
    begin
      if MHIsExecutableExtension(LEntry.Name) then
      begin
        LWeight := 45;
        LReason := 'Из проверки антивирусом исключены все файлы этого типа — так прячут программы и сценарии';
      end
      else
      begin
        LWeight := 10;
        LReason := 'Исключение антивируса по расширению файлов';
      end;
    end
    else if LKind.StartsWith('IP') then
    begin
      LWeight := 10;
      LReason := 'Исключение антивируса по IP-адресу';
    end
    else if IsBroadPath(LEntry.Name) then
    begin
      LWeight := 45;
      LReason := 'Из проверки антивирусом исключён целый диск или системная папка';
    end
    else if MHIsSuspiciousLocation(LEntry.ImagePath, LFolder) then
    begin
      LWeight := 45;
      LReason := 'Из проверки антивирусом исключена папка в необычном месте — так майнеры защищают себя';
    end
    else if MHFindRandomLookingFolder(LEntry.ImagePath, LFolder) then
    begin
      LWeight := 45;
      LReason := 'Из проверки антивирусом исключена папка со случайным именем';
    end
    else
    begin
      LWeight := 15;
      LReason := 'Исключение антивируса — убедитесь, что добавляли его сами (например, папку проектов)';
    end;
    if LWeight > LBest then
    begin
      LBest := LWeight;
      LBestText := LReason;
    end;
    if Length(LNames) < 400 then
      LNames := LNames + IfThen(LNames <> '', ', ', '') + IfThen(LIsFiles, ExtractFileName(LEntry.Name), LEntry.Name);
    if (LEntry.ImagePath <> '') and MHIsMasqueradedSystemFile(LEntry.ImagePath) and
       not LMasquerade.Contains(ExtractFileName(LEntry.ImagePath)) then
      LMasquerade := LMasquerade + IfThen(LMasquerade <> '', ', ', '') + ExtractFileName(LEntry.ImagePath);
    if LEntry.Details.Contains('рядом: ') and (LArtifacts = '') then
      LArtifacts := Copy(LEntry.Details, Pos('рядом: ', LEntry.Details) + Length('рядом: '), 200);
    if LEntry.Details.Contains('файла нет') then
      Inc(LMissing);
    if LEntry.Details.Contains('скрытый и системный') then
      Inc(LHidden);
    if LEntry.ImagePath.ToLower.Contains(':\programdata') and SameText(ExtractFileExt(LEntry.Name), '.exe') then
      Inc(LProgramDataExe);
    if MHIsKnownMinerName(LEntry.Name) then
      LMinerName := True;
  end;
  AddEvidence(LEvidence, EV_AV_EXCLUSION, LBestText, LBest, LNames);
  if LMasquerade <> '' then
    AddEvidence(LEvidence, 'MASQUERADE',
      'Исключены программы с именами системных файлов Windows, но вне системной папки', 40, LMasquerade);
  if LArtifacts <> '' then
  begin
    AddEvidence(LEvidence, EV_MINER_ARTIFACT,
      'Рядом лежит драйвер WinRing0, которым пользуется майнер XMRig', 40, LArtifacts);
    LMining := True;
  end;
  if LHidden > 0 then
    AddEvidence(LEvidence, EV_HIDDEN_FILE, 'Исключённые программы скрыты атрибутами «скрытый» и «системный»', 20,
      Format('%d файл(ов)', [LHidden]));
  if LProgramDataExe > 0 then
    AddEvidence(LEvidence, EV_PROGRAMDATA_EXE,
      'Из проверки исключены отдельные программы в ProgramData — обычные программы так не делают', 20,
      Format('%d программ(ы)', [LProgramDataExe]));
  if LMinerName then
  begin
    AddEvidence(LEvidence, 'MINER_NAME', 'Из проверки исключена программа с именем известного майнера', 35);
    LMining := True;
  end;
  PolicyEvidence(AEntries, LEvidence);
  if (LMissing > 0) and (LMissing = Length(AEntries)) then
    AddEvidence(LEvidence, EV_FILES_GONE, 'Исключённых файлов уже нет на диске (осталась только запись)', -15);
  if LMining then
    LCategory := fcMining
  else
    LCategory := fcSuspicious;
  if LIsFiles and (Length(AEntries) > 1) then
  begin
    LDir := ExtractFileDir(AEntries[0].ImagePath);
    LTitle := Format('Исключены из проверки Defender: %d программ(ы) в %s', [Length(AEntries), LDir]);
  end
  else
  begin
    LDir := AEntries[0].Name;
    LTitle := 'Исключение Microsoft Defender: ' + AEntries[0].Name;
  end;
  Result := Finish(ASnapshot, AThresholds, '', LDir, 'tamper:defender:' + DefenderGroupKey(AEntries[0]),
    LTitle, Format('Microsoft Defender не проверяет: %s.', [LNames]), LCategory, LEvidence,
    ['Если вы не добавляли эти исключения, удалите их: «Безопасность Windows» → «Защита от вирусов и угроз» → ' +
     '«Управление настройками» → «Исключения» (исключения, заданные политикой, удаляются в разделе реестра ' +
     'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions от имени администратора).',
     'Затем полностью проверьте компьютер Microsoft Defender; файлы можно поместить в карантин из карточки находки.'],
    ARuleset, AFinding);
end;

function AnalyzeIfeoGroup(const ASnapshot: TMHSnapshot; const AEntries: TArray<TMHTamperEntry>;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LEntry, LFirst: TMHTamperEntry;
  LTargets, LReason, LCode: string;
  LWeight, LBest: Integer;
  LMining: Boolean;
  LSigner: string;
begin
  Result := False;
  AFinding := Default(TMHFinding);
  LEvidence := nil;
  LTargets := '';
  LBest := 0;
  LCode := EV_EXECUTION_HIJACK;
  LReason := '';
  LFirst := AEntries[0];
  for LEntry in AEntries do
  begin
    // Process Explorer / System Informer вместо диспетчера задач — штатная настройка этих программ.
    if SameText(LEntry.Name, 'taskmgr.exe') and MHIsTaskManagerReplacement(LEntry.ImagePath) then
      Continue;
    LTargets := LTargets + IfThen(LTargets <> '', ', ', '') + LEntry.Name;
    if MHIsAccessibilityBinary(LEntry.Name) then
    begin
      LWeight := 60;
      if LWeight > LBest then
      begin
        LCode := EV_ACCESSIBILITY_HIJACK;
        LReason := 'Подменены специальные возможности экрана входа — так получают доступ к компьютеру без пароля';
      end;
    end
    else if MHIsProtectedToolName(LEntry.Name) then
    begin
      LWeight := 60;
      if LWeight > LBest then
      begin
        LCode := EV_EXECUTION_HIJACK;
        LReason := 'Запуск антивируса или программы мониторинга заблокирован — так майнеры не дают себя увидеть и удалить';
      end;
    end
    else if InList(ExtractFileName(LEntry.ImagePath), DEV_DEBUGGERS) then
    begin
      LWeight := 10;
      if LWeight > LBest then
      begin
        LCode := EV_DEV_TOOL;
        LReason := 'Отладчик разработчика назначен для программы (обычно это сделали намеренно)';
      end;
    end
    else
    begin
      LWeight := 30;
      if LWeight > LBest then
      begin
        LCode := EV_EXECUTION_HIJACK;
        LReason := 'Запуск программы перехвачен: вместо неё выполняется другая команда';
      end;
    end;
    LBest := Max(LBest, LWeight);
  end;
  if LTargets = '' then
    Exit;
  AddEvidence(LEvidence, LCode, LReason, LBest, LTargets + ' → ' + LFirst.Value);
  LMining := False;
  CommandEvidence(ASnapshot, LFirst, LEvidence, LMining);
  if (LCode = EV_EXECUTION_HIJACK) and (LBest < 60) and SignedVendorFile(ASnapshot, LFirst.ImagePath, LSigner) and
     not HasPositiveBeyond(LEvidence, EV_EXECUTION_HIJACK) then
    AddEvidence(LEvidence, 'SIGNED_TRUSTED', 'Вместо программы запускается подписанная программа из Program Files',
      -15, LSigner);
  Result := Finish(ASnapshot, AThresholds, LFirst.ImagePath, LTargets, 'tamper:ifeo:' + LFirst.Value.ToLower,
    'Перехват запуска программ: ' + LTargets,
    Format('При запуске %s Windows выполняет: %s.', [LTargets, LFirst.Value]), fcPersistence, LEvidence,
    ['Если вы не настраивали замену этих программ, удалите значение Debugger в разделах ' +
     'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<программа> ' +
     '(редактор реестра от имени администратора).',
     'Если перехвачен запуск антивируса — после удаления перезагрузите компьютер и выполните полную проверку.'],
    ARuleset, AFinding);
end;

function AnalyzeSilentExit(const ASnapshot: TMHSnapshot; const AEntry: TMHTamperEntry;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LMining: Boolean;
  LSigner: string;
begin
  LEvidence := nil;
  LMining := False;
  AddEvidence(LEvidence, EV_SILENT_EXIT,
    'При завершении программы Windows запускает другую команду — малоизвестный способ автозапуска', 40,
    AEntry.Name + ' → ' + AEntry.Value);
  CommandEvidence(ASnapshot, AEntry, LEvidence, LMining);
  if SignedVendorFile(ASnapshot, AEntry.ImagePath, LSigner) and
     not HasPositiveBeyond(LEvidence, EV_SILENT_EXIT) then
    AddEvidence(LEvidence, 'SIGNED_TRUSTED', 'Запускается подписанная программа из Program Files', -15, LSigner);
  Result := Finish(ASnapshot, AThresholds, AEntry.ImagePath, AEntry.Name, 'tamper:silentexit:' + AEntry.Name.ToLower,
    'Запуск при завершении программы: ' + AEntry.Name,
    Format('При завершении %s запускается: %s.', [AEntry.Name, AEntry.Value]), fcPersistence, LEvidence,
    ['Если вы не настраивали мониторинг завершения программ, удалите раздел ' + AEntry.Location +
     ' (редактор реестра от имени администратора).'], ARuleset, AFinding);
end;

function AnalyzeHosts(const ASnapshot: TMHSnapshot; const AEntries: TArray<TMHTamperEntry>;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LEntry, LFirst: TMHTamperEntry;
  LDomains: string;
  LCount, LSecurity: Integer;
  LHint: string;
  LIsUpdate: Boolean;
begin
  Result := False;
  AFinding := Default(TMHFinding);
  LDomains := '';
  LCount := 0;
  LSecurity := 0;
  for LEntry in AEntries do
  begin
    if LCount = 0 then
      LFirst := LEntry;
    Inc(LCount);
    if LCount <= 5 then
      LDomains := LDomains + IfThen(LDomains <> '', ', ', '') + LEntry.Name;
    LIsUpdate := False;
    for LHint in UPDATE_DOMAIN_HINTS do
      if LEntry.Name.Contains(LHint) then
        LIsUpdate := True;
    if not LIsUpdate then
      Inc(LSecurity);
  end;
  if LCount = 0 then
    Exit;
  if LCount > 5 then
    LDomains := LDomains + Format(' и ещё %d', [LCount - 5]);
  LEvidence := nil;
  if LSecurity > 0 then
    AddEvidence(LEvidence, EV_HOSTS_BLOCK,
      'Файл hosts блокирует сайты антивирусов — так вредоносные программы мешают себя обнаружить', 50, LDomains)
  else
  begin
    AddEvidence(LEvidence, EV_HOSTS_BLOCK, 'Файл hosts блокирует обновления Windows и Defender', 35, LDomains);
    AddEvidence(LEvidence, EV_UPDATES_ONLY,
      'Обновления иногда отключают так намеренно — проверьте, делали ли это вы', -10);
  end;
  Result := Finish(ASnapshot, AThresholds, '', 'hosts', 'tamper:hosts',
    Format('Файл hosts блокирует %d сайт(ов) защиты', [LCount]),
    'В файле ' + LFirst.Location + ' перенаправлены: ' + LDomains + '.', fcSuspicious, LEvidence,
    ['Откройте файл hosts в Блокноте от имени администратора и удалите строки с этими сайтами, ' +
     'если не добавляли их сами.',
     'После этого запустите обновление и проверку Microsoft Defender.'], ARuleset, AFinding);
end;

function AnalyzeHostsRelocated(const ASnapshot: TMHSnapshot; const AEntry: TMHTamperEntry;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
begin
  LEvidence := nil;
  AddEvidence(LEvidence, EV_HOSTS_RELOCATED,
    'Каталог файла hosts перенесён — так подменяют разрешение адресов незаметно для пользователя', 55,
    AEntry.Value);
  Result := Finish(ASnapshot, AThresholds, '', 'hosts', 'tamper:hosts-relocated',
    'Файл hosts перенесён в другое место', AEntry.Details + '.', fcSuspicious, LEvidence,
    ['Верните значение DataBasePath в разделе ' + AEntry.Location + ' к %SystemRoot%\System32\drivers\etc ' +
     '(редактор реестра от имени администратора) и проверьте компьютер антивирусом.'], ARuleset, AFinding);
end;

/// Отключение защиты Microsoft Defender политиками.
function IsDefenderPolicy(const AName: string): Boolean;
begin
  Result := SameText(AName, 'DisableAntiSpyware') or SameText(AName, 'DisableAntiVirus') or
    SameText(AName, 'DisableRealtimeMonitoring') or SameText(AName, 'DisableBehaviorMonitoring') or
    SameText(AName, 'DisableOnAccessProtection');
end;

function AnalyzePolicyGroup(const ASnapshot: TMHSnapshot; const AEntries: TArray<TMHTamperEntry>;
  const AThresholds: TMHRiskThresholds; const ARuleset: string; out AFinding: TMHFinding): Boolean;
var
  LEvidence: TArray<TMHEvidence>;
  LEntry: TMHTamperEntry;
  LTitle, LText, LValues, LKey: string;
  LWeight: Integer;
begin
  LEntry := AEntries[0];
  LValues := '';
  for LEntry in AEntries do
    LValues := LValues + IfThen(LValues <> '', ', ', '') + LEntry.Name + ' = ' + LEntry.Value;
  LEntry := AEntries[0];
  if IsDefenderPolicy(LEntry.Name) then
  begin
    LTitle := 'Защита Microsoft Defender отключена политикой';
    LText := 'Защита Microsoft Defender отключена политикой — компьютер остаётся без антивируса';
    LWeight := 45;
    LKey := 'tamper:policy:defender';
  end
  else
  begin
    LKey := 'tamper:policy:' + LEntry.Details.ToLower + ':' + LEntry.Name.ToLower;
    if SameText(LEntry.Name, 'DisableTaskMgr') then
    begin
      LTitle := 'Диспетчер задач отключён';
      LText := 'Диспетчер задач отключён политикой — так майнеры мешают увидеть нагрузку';
      LWeight := 40;
    end
    else if SameText(LEntry.Name, 'DisableRegistryTools') then
    begin
      LTitle := 'Редактор реестра отключён';
      LText := 'Редактор реестра отключён политикой — так мешают удалить автозапуск';
      LWeight := 35;
    end
    else if SameText(LEntry.Name, 'DisableCMD') then
    begin
      LTitle := 'Командная строка отключена';
      LText := 'Командная строка отключена политикой';
      LWeight := 20;
    end
    else
    begin
      LTitle := 'Контроль учётных записей (UAC) отключён';
      LText := 'Контроль учётных записей отключён — программы получают права администратора без запроса';
      LWeight := 20;
    end;
  end;
  LEvidence := nil;
  AddEvidence(LEvidence, EV_POLICY_RESTRICTION, LText, LWeight, LValues);
  PolicyEvidence(AEntries, LEvidence);
  Result := Finish(ASnapshot, AThresholds, '', LEntry.Name, LKey, LTitle, LText + '.', fcSuspicious, LEvidence,
    ['Если компьютер не управляется организацией, удалите эти значения в разделе ' + LEntry.Location +
     ' (редактор реестра от имени администратора) и перезагрузите компьютер.',
     'В организации такие запреты может задать администратор — уточните у него.'], ARuleset, AFinding);
end;

function MHAnalyzeTamper(const ASnapshot: TMHSnapshot; const AThresholds: TMHRiskThresholds;
  const AIsExcluded: TMHExclusionCheck; const ARulesetVersion: string): TMHFindings;
var
  LEntry: TMHTamperEntry;
  LHosts, LGroup: TArray<TMHTamperEntry>;
  LGroups: TArray<TArray<TMHTamperEntry>>;
  LGroupKeys: TArray<string>;
  LFinding: TMHFinding;
  LOk: Boolean;
  LKey: string;
  I, LIndex: Integer;

  procedure AddToGroup(const AGroupKey: string; const AItem: TMHTamperEntry);
  var
    J: Integer;
  begin
    for J := 0 to High(LGroupKeys) do
      if LGroupKeys[J] = AGroupKey then
      begin
        LGroups[J] := LGroups[J] + [AItem];
        Exit;
      end;
    LGroupKeys := LGroupKeys + [AGroupKey];
    LGroups := LGroups + [[AItem]];
  end;

  procedure Emit(const AFinding: TMHFinding);
  begin
    if not (Assigned(AIsExcluded) and AIsExcluded(AFinding.Key, FileSha(ASnapshot, AFinding.ImagePath))) then
      Result := Result + [AFinding];
  end;

begin
  Result := nil;
  LHosts := nil;
  LGroups := nil;
  LGroupKeys := nil;
  // Однородные признаки группируются: одна находка на папку исключений, на команду
  // перехвата и на отключение Defender политиками.
  for LEntry in ASnapshot.Tamper do
    case LEntry.Kind of
      tpDefenderExclusion: AddToGroup('defender|' + DefenderGroupKey(LEntry), LEntry);
      tpIfeoDebugger: AddToGroup('ifeo|' + LEntry.Value.ToLower, LEntry);
      tpPolicyRestriction:
        if IsDefenderPolicy(LEntry.Name) then
          AddToGroup('policy|defender', LEntry)
        else
          AddToGroup('policy|' + LEntry.Details.ToLower + '|' + LEntry.Name.ToLower, LEntry);
      tpHostsRedirect:
        if SameText(LEntry.Name, 'DataBasePath') then
        begin
          if AnalyzeHostsRelocated(ASnapshot, LEntry, AThresholds, ARulesetVersion, LFinding) then
            Emit(LFinding);
        end
        else
          LHosts := LHosts + [LEntry];
      tpWmiSubscription:
        if AnalyzeWmi(ASnapshot, LEntry, AThresholds, ARulesetVersion, LFinding) then
          Emit(LFinding);
      tpSilentExitMonitor:
        if AnalyzeSilentExit(ASnapshot, LEntry, AThresholds, ARulesetVersion, LFinding) then
          Emit(LFinding);
    end;
  for I := 0 to High(LGroups) do
  begin
    LGroup := LGroups[I];
    LKey := LGroupKeys[I];
    LIndex := Pos('|', LKey);
    LKey := Copy(LKey, 1, LIndex - 1);
    if LKey = 'defender' then
      LOk := AnalyzeDefenderGroup(ASnapshot, LGroup, AThresholds, ARulesetVersion, LFinding)
    else if LKey = 'ifeo' then
      LOk := AnalyzeIfeoGroup(ASnapshot, LGroup, AThresholds, ARulesetVersion, LFinding)
    else
      LOk := AnalyzePolicyGroup(ASnapshot, LGroup, AThresholds, ARulesetVersion, LFinding);
    if LOk then
      Emit(LFinding);
  end;
  if (Length(LHosts) > 0) and AnalyzeHosts(ASnapshot, LHosts, AThresholds, ARulesetVersion, LFinding) then
    Emit(LFinding);
end;

function MHTamperEvidenceFor(const ASnapshot: TMHSnapshot; const AImagePath, AName: string;
  out AExcludedFromAv: Boolean): TArray<TMHEvidence>;
var
  LEntry: TMHTamperEntry;
  LPath, LExcluded: string;
  LLinked: Boolean;
begin
  Result := nil;
  AExcludedFromAv := False;
  LLinked := False;
  LPath := MHNormalizePath(AImagePath).ToLower;
  for LEntry in ASnapshot.Tamper do
    case LEntry.Kind of
      tpDefenderExclusion:
        if not AExcludedFromAv then
        begin
          LExcluded := ExcludeTrailingPathDelimiter(MHNormalizePath(LEntry.Name)).ToLower;
          if LEntry.Details.StartsWith('процесс') then
            AExcludedFromAv := SameText(ExtractFileName(LEntry.Name), AName) or
              ((LPath <> '') and (LExcluded = LPath))
          else if LEntry.Details.StartsWith('путь') and (LPath <> '') and (LExcluded <> '') then
            AExcludedFromAv := (LPath = LExcluded) or LPath.StartsWith(LExcluded + '\');
          if AExcludedFromAv then
            AddEvidence(Result, EV_AV_EXCLUDED, 'Программа исключена из проверки антивирусом', 25,
              LEntry.Name);
        end;
      tpWmiSubscription, tpIfeoDebugger, tpSilentExitMonitor:
        if not LLinked and (LPath <> '') and SameText(MHNormalizePath(LEntry.ImagePath), LPath) then
        begin
          LLinked := True;
          AddEvidence(Result, EV_TAMPER_LINK, 'Программу запускает скрытый механизм: ' +
            MHTamperKindToString(LEntry.Kind), 20, LEntry.Name);
        end;
    end;
end;

end.
