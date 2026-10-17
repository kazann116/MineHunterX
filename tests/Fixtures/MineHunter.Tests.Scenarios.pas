unit MineHunter.Tests.Scenarios;

{
  Синтетические сценарии для анализатора угроз: последовательности снимков
  с «нагрузкой», подписями, расположением, контекстом и сетью.

  Безопасность: никакого настоящего вредоносного кода — только данные.
  Адреса — из диапазонов для документации (RFC 5737), имена пользователей
  обезличены.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types;

type
  TCpuStep = record
    FromMinute: Double;
    Cpu: Double;
  end;

  TScenarioProcess = record
    Pid: Cardinal;
    Name: string;
    Path: string;
    Signature: TMHSignatureState;
    Signer: string;
    /// Нагрузка по этапам: с минуты FromMinute — значение Cpu (% машины).
    Plan: TArray<TCpuStep>;
    HasWindow: Boolean;
    Foreground: Boolean;
    CommandLine: string;
    RemotePort: Word;
    /// Процесс появляется с этой минуты (0 — с начала).
    StartMinute: Double;
    /// Загрузка GPU (самый загруженный движок) и вычислительных движков, %.
    Gpu: Double;
    GpuCompute: Double;
  end;

  TScenario = record
    Name: string;
    Description: string;
    Malicious: Boolean;
    /// Имя процесса или записи автозапуска, по которой проверяется результат.
    Target: string;
    MinLevel: TMHRiskLevel;
    MaxLevel: TMHRiskLevel;
    ExpectCategory: Boolean;
    Category: TMHFindingCategory;
    Snapshots: TArray<TMHSnapshot>;
    Exclusions: TArray<TMHExclusion>;
  end;

const
  SCENARIO_CPU_COUNT = 8;
  SCENARIO_STEP_SECONDS = 10;
  SCENARIO_MINUTES = 15;

/// Все сценарии: вредоносные (ожидается «подозрительно» и выше) и легальные
/// (ожидается не выше «низкого» уровня).
function BuildScenarios: TArray<TScenario>;

/// Последовательность снимков для заданных процессов.
function BuildSnapshots(const AProcesses: TArray<TScenarioProcess>; AUserIdleSeconds: Cardinal;
  AFullscreen: Boolean; const AAutostart: TArray<TMHAutostartEntry>;
  AMinutes: Integer = SCENARIO_MINUTES; AStepSeconds: Integer = SCENARIO_STEP_SECONDS): TArray<TMHSnapshot>;

function Proc(APid: Cardinal; const AName, APath: string; ASignature: TMHSignatureState;
  const ASigner: string; const APlan: array of Double): TScenarioProcess;

/// Максимальный уровень среди находок, относящихся к цели (по имени процесса).
function MaxLevelFor(const AFindings: TMHFindings; const ATarget: string;
  out AFinding: TMHFinding): TMHRiskLevel;

const
  SCENARIO_START: TDateTime = 46311.5; // 2026-10-16 12:00 UTC
  USER_DIR = 'C:\Users\user\';

implementation

uses
  System.Math,
  MineHunter.Core.Paths;

function Proc(APid: Cardinal; const AName, APath: string; ASignature: TMHSignatureState;
  const ASigner: string; const APlan: array of Double): TScenarioProcess;
var
  I: Integer;
begin
  Result := Default(TScenarioProcess);
  Result.Pid := APid;
  Result.Name := AName;
  Result.Path := APath;
  Result.Signature := ASignature;
  Result.Signer := ASigner;
  // APlan: пары (минута, нагрузка).
  SetLength(Result.Plan, Length(APlan) div 2);
  for I := 0 to High(Result.Plan) do
  begin
    Result.Plan[I].FromMinute := APlan[I * 2];
    Result.Plan[I].Cpu := APlan[I * 2 + 1];
  end;
end;

function CpuAt(const AProcess: TScenarioProcess; AMinute: Double): Double;
var
  LStep: TCpuStep;
begin
  Result := 0;
  for LStep in AProcess.Plan do
    if AMinute >= LStep.FromMinute then
      Result := LStep.Cpu;
end;

function BuildSnapshots(const AProcesses: TArray<TScenarioProcess>; AUserIdleSeconds: Cardinal;
  AFullscreen: Boolean; const AAutostart: TArray<TMHAutostartEntry>;
  AMinutes, AStepSeconds: Integer): TArray<TMHSnapshot>;
var
  LCount, I, J: Integer;
  LTime: TDateTime;
  LMinute, LTotal, LGpuTotal: Double;
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
  LFile: TMHFileInfo;
  LConnection: TMHNetConnection;
  LProcess: TScenarioProcess;
begin
  LCount := AMinutes * 60 div AStepSeconds + 1;
  SetLength(Result, LCount);
  for I := 0 to LCount - 1 do
  begin
    LMinute := I * AStepSeconds / 60;
    LTime := SCENARIO_START + I * AStepSeconds / SecsPerDay;
    LSnapshot := TMHSnapshot.Create(I + 1, LTime);
    LSnapshot.Context.Available := True;
    LSnapshot.Context.UserIdleSeconds := AUserIdleSeconds;
    LSnapshot.Context.FullscreenActive := AFullscreen;
    if AFullscreen then
      LSnapshot.Context.WorkContext := wcGaming
    else if AUserIdleSeconds >= 300 then
      LSnapshot.Context.WorkContext := wcIdle
    else
      LSnapshot.Context.WorkContext := wcWork;
    LTotal := 3;
    LGpuTotal := 0;
    for J := 0 to High(AProcesses) do
    begin
      LProcess := AProcesses[J];
      if LMinute < LProcess.StartMinute then
        Continue;
      LInfo := TMHProcessInfo.Create(TMHProcessId.Create(LProcess.Pid, 133000000000000000 + LProcess.Pid),
        LProcess.Name, LTime);
      LInfo.ImagePath := LProcess.Path;
      LInfo.Access := alFull;
      LInfo.ParentPid := 1000;
      LInfo.ThreadCount := 8;
      LInfo.SourceId := 'processes';
      LInfo.CommandLine := LProcess.CommandLine;
      LInfo.HasVisibleWindow := LProcess.HasWindow;
      LInfo.Signature := LProcess.Signature;
      // Первый снимок процесса — без CPU, как у настоящего коллектора.
      if LMinute > LProcess.StartMinute then
        LInfo.Cpu := TMHMetric.Available(mkCpuPercent, CpuAt(LProcess, LMinute), LTime);
      // Счётчики GPU, как у настоящего коллектора, есть у всех процессов.
      LInfo.Gpu := TMHMetric.Available(mkGpuPercent, LProcess.Gpu, LTime);
      LInfo.GpuCompute := TMHMetric.Available(mkGpuComputePercent, LProcess.GpuCompute, LTime);
      LGpuTotal := LGpuTotal + LProcess.Gpu;
      LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 100 * 1048576, LTime);
      LSnapshot.Processes := LSnapshot.Processes + [LInfo];
      if LInfo.Cpu.HasValue then
        LTotal := LTotal + LInfo.Cpu.Value;
      if LProcess.HasWindow then
        LSnapshot.Context.VisibleWindowPids := LSnapshot.Context.VisibleWindowPids + [LProcess.Pid];
      if LProcess.Foreground then
        LSnapshot.Context.ForegroundPid := LProcess.Pid;
      if LProcess.Path <> '' then
      begin
        LFile := TMHFileInfo.Create(MHNormalizePath(LProcess.Path));
        LFile.SizeBytes := 1048576;
        LFile.Signature := LProcess.Signature;
        LFile.Signer := LProcess.Signer;
        if LProcess.Signature = sgSignedTrusted then
          LFile.SignatureSource := 'embedded';
        LFile.Sha256 := LowerCase(IntToHex(LProcess.Pid, 8)) + StringOfChar('0', 56);
        LSnapshot.Files := LSnapshot.Files + [LFile];
      end;
      if LProcess.RemotePort <> 0 then
      begin
        LConnection := Default(TMHNetConnection);
        LConnection.Transport := ntTcp;
        LConnection.LocalAddress := '192.168.1.10';
        LConnection.LocalPort := 50000 + J;
        LConnection.RemoteAddress := '203.0.113.10';
        LConnection.RemotePort := LProcess.RemotePort;
        LConnection.State := 'ESTABLISHED';
        LConnection.OwningPid := LProcess.Pid;
        LSnapshot.Connections := LSnapshot.Connections + [LConnection];
      end;
    end;
    LSnapshot.Autostart := AAutostart;
    // Как настоящий коллектор файлов: пути из автозапуска тоже проверяются.
    for J := 0 to High(AAutostart) do
      if not LSnapshot.FindFile(AAutostart[J].ImagePath, LFile) then
      begin
        LFile := TMHFileInfo.Create(AAutostart[J].ImagePath);
        LFile.SizeBytes := 1048576;
        // Файлы Windows подписаны Microsoft, остальные в сценариях — без подписи.
        if AAutostart[J].ImagePath.ToLower.StartsWith('c:\windows\') then
        begin
          LFile.Signature := sgSignedTrusted;
          LFile.Signer := 'Microsoft Windows';
          LFile.SignatureSource := 'catalog';
        end
        else
          LFile.Signature := sgUnsigned;
        LSnapshot.Files := LSnapshot.Files + [LFile];
      end;
    LSnapshot.Metrics := [TMHMetric.Available(mkCpuPercent, Min(100.0, LTotal), LTime),
      TMHMetric.Available(mkMemoryLoadPercent, 55, LTime),
      TMHMetric.Available(mkDiskActivePercent, 5, LTime),
      TMHMetric.Available(mkGpuPercent, Min(100.0, LGpuTotal), LTime)];
    Result[I] := LSnapshot;
  end;
end;

function MaxLevelFor(const AFindings: TMHFindings; const ATarget: string;
  out AFinding: TMHFinding): TMHRiskLevel;
var
  LFinding: TMHFinding;
begin
  Result := rlNone;
  AFinding := Default(TMHFinding);
  for LFinding in AFindings do
    if SameText(LFinding.ProcessName, ATarget) and (LFinding.Level >= Result) then
    begin
      if (LFinding.Level > Result) or (AFinding.Key = '') then
        AFinding := LFinding;
      Result := LFinding.Level;
    end;
end;

function Autostart(AKind: TMHAutostartKind; const AName, AImage, ALocation: string): TMHAutostartEntry;
begin
  Result := Default(TMHAutostartEntry);
  Result.Kind := AKind;
  Result.Scope := asUser;
  Result.Name := AName;
  Result.Command := '"' + AImage + '"';
  Result.ImagePath := MHNormalizePath(AImage);
  Result.Location := ALocation;
  Result.Enabled := True;
end;

function Scenario(const AName, ADescription, ATarget: string; AMalicious: Boolean;
  AMin, AMax: TMHRiskLevel; const ASnapshots: TArray<TMHSnapshot>): TScenario;
begin
  Result := Default(TScenario);
  Result.Name := AName;
  Result.Description := ADescription;
  Result.Target := ATarget;
  Result.Malicious := AMalicious;
  Result.MinLevel := AMin;
  Result.MaxLevel := AMax;
  Result.Snapshots := ASnapshots;
end;

function WithCategory(const AScenario: TScenario; ACategory: TMHFindingCategory): TScenario;
begin
  Result := AScenario;
  Result.ExpectCategory := True;
  Result.Category := ACategory;
end;

/// Фоновые обычные процессы, присутствующие во всех сценариях.
function Background: TArray<TScenarioProcess>;
begin
  Result := [
    Proc(500, 'explorer.exe', 'C:\Windows\explorer.exe', sgSignedTrusted, 'Microsoft Windows', [0, 1]),
    Proc(600, 'svchost.exe', 'C:\Windows\System32\svchost.exe', sgSignedTrusted, 'Microsoft Windows', [0, 0.5])];
  Result[0].HasWindow := True;
end;

function BuildScenarios: TArray<TScenario>;
var
  P, LTaskmgr: TScenarioProcess;
  LAuto: TMHAutostartEntry;
  LScenario: TScenario;
begin
  Result := nil;

  // ===== Вредоносные (имитация) =====
  P := Proc(2001, 'svcupdate.exe', USER_DIR + 'AppData\Local\Temp\svcupdate.exe', sgUnsigned, '', [0, 60]);
  P.RemotePort := 3333;
  LAuto := Autostart(akRegistryRun, 'SvcUpdate', P.Path,
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run');
  Result := Result + [WithCategory(Scenario('hidden_miner_temp',
    'Неподписанный фоновый процесс из Temp: 60% CPU, пользователь отошёл, соединение с портом пула, автозапуск',
    'svcupdate.exe', True, rlHighlySuspicious, rlHighlySuspicious,
    BuildSnapshots(Background + [P], 900, False, [LAuto])), fcMining)];

  P := Proc(2002, 'xmrig.exe', USER_DIR + 'Downloads\xmrig-6.21\xmrig.exe', sgUnsigned, '', [0, 40]);
  P.CommandLine := '"' + P.Path + '" -o stratum+tcp://pool.example.invalid:3333 --donate-level 1';
  Result := Result + [WithCategory(Scenario('xmrig_stratum',
    'xmrig из папки «Загрузки» с параметрами stratum и donate-level',
    'xmrig.exe', True, rlHighlySuspicious, rlHighlySuspicious,
    BuildSnapshots(Background + [P], 10, False, nil)), fcMining)];

  P := Proc(2003, 'svchost.exe', 'C:\Users\Public\svchost.exe', sgUnsigned, '', [0, 30]);
  Result := Result + [WithCategory(Scenario('masquerade_svchost',
    'Файл с именем svchost.exe в общей папке пользователей, без подписи, 30% CPU',
    'svchost.exe', True, rlSuspicious, rlHighlySuspicious,
    BuildSnapshots(Background + [P], 10, False, nil)), fcSuspicious)];

  // Нагрузка 50%, на 12-й минуте открывается диспетчер задач — нагрузка падает до 2%.
  P := Proc(2004, 'winsvc.exe', 'C:\ProgramData\winsvc.exe', sgUnsigned, '', [0, 50, 12, 2]);
  // Диспетчер задач появляется только с 12-й минуты.
  LTaskmgr := Proc(2999, 'Taskmgr.exe', 'C:\Windows\System32\Taskmgr.exe', sgSignedTrusted,
    'Microsoft Windows', [0, 2]);
  LTaskmgr.StartMinute := 12;
  LTaskmgr.HasWindow := True;
  LTaskmgr.Foreground := True;
  LScenario := Scenario('hides_from_taskmgr',
    'Процесс снижает нагрузку при запуске диспетчера задач', 'winsvc.exe', True,
    rlSuspicious, rlHighlySuspicious, BuildSnapshots(Background + [P, LTaskmgr], 20, False, nil));
  Result := Result + [WithCategory(LScenario, fcMining)];

  LAuto := Autostart(akRegistryRun, 'Updater', 'C:\Users\Public\Libraries\xmrig.exe',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run');
  Result := Result + [WithCategory(Scenario('autostart_miner_not_running',
    'Запись автозапуска указывает на xmrig.exe в общей папке (процесс не запущен)',
    'xmrig.exe', True, rlSuspicious, rlHighlySuspicious,
    BuildSnapshots(Background, 10, False, [LAuto])), fcPersistence)];

  // Реальный приём закрепления: системная папка заданий, сценарий в папке со случайным
  // именем, файл скрыт (недоступен).
  LAuto := Autostart(akScheduledTask, '\Microsoft\Windows\SysFilesL\RecoveryHosts',
    'C:\ProgramData\Microsoft\MapData\YfBZXN4ndJYr5fK\SysFilesL.bat', '\Microsoft\Windows\SysFilesL');
  LScenario := WithCategory(Scenario('masquerading_task_script',
    'Задание в папке \Microsoft\Windows запускает .bat из папки со случайным именем',
    'SysFilesL.bat', True, rlSuspicious, rlHighlySuspicious,
    BuildSnapshots(Background, 10, False, [LAuto])), fcPersistence);
  Result := Result + [LScenario];

  LAuto := Autostart(akRegistryRun, 'Updater', 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run');
  LAuto.Command := 'powershell.exe -w hidden -enc SQBFAFgA';
  Result := Result + [WithCategory(Scenario('encoded_powershell_autostart',
    'Автозапуск PowerShell со скрытым окном и закодированной командой',
    'powershell.exe', True, rlNeedsReview, rlHighlySuspicious,
    BuildSnapshots(Background, 10, False, [LAuto])), fcPersistence)];

  P := Proc(2006, 'scvhost.exe', USER_DIR + 'AppData\Roaming\Microsoft\scvhost.exe', sgUnsigned, '', [0, 20]);
  Result := Result + [Scenario('lookalike_name',
    'Имя scvhost.exe похоже на svchost.exe, без подписи, фоновая нагрузка',
    'scvhost.exe', True, rlNeedsReview, rlHighlySuspicious,
    BuildSnapshots(Background + [P], 10, False, nil))];

  // Майнер на видеокарте: процессор почти не нагружен, вычислительные блоки GPU — полностью.
  P := Proc(2007, 'gpuupd.exe', 'C:\ProgramData\GpuUpdate\gpuupd.exe', sgUnsigned, '', [0, 3]);
  P.Gpu := 97;
  P.GpuCompute := 97;
  Result := Result + [WithCategory(Scenario('gpu_miner_compute',
    'Неподписанный фоновый процесс без окна: 3% CPU, 97% вычислений GPU, пользователь отошёл',
    'gpuupd.exe', True, rlSuspicious, rlHighlySuspicious,
    BuildSnapshots(Background + [P], 900, False, nil)), fcMining)];

  // ===== Легальная нагрузка (проверка ложных срабатываний) =====
  P := Proc(3001, 'game.exe', 'C:\Program Files (x86)\Steam\steamapps\common\Game\game.exe', sgUnsigned, '', [0, 70]);
  P.HasWindow := True;
  P.Foreground := True;
  Result := Result + [Scenario('fp_fullscreen_game',
    'Игра без подписи в полноэкранном режиме, 70% CPU', 'game.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 5, True, nil))];

  P := Proc(3002, 'dcc64.exe', 'C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\dcc64.exe',
    sgSignedTrusted, 'Embarcadero Technologies Inc', [0, 90]);
  Result := Result + [Scenario('fp_compilation',
    'Компиляция: dcc64.exe, 90% CPU в течение 15 минут', 'dcc64.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 20, False, nil))];

  P := Proc(3003, 'blender.exe', 'C:\Program Files\Blender Foundation\Blender 4.2\blender.exe',
    sgSignedTrusted, 'Blender Foundation', [0, 95]);
  P.HasWindow := True;
  Result := Result + [Scenario('fp_render_overnight',
    'Рендеринг в Blender ночью: 95% CPU, пользователь отошёл', 'blender.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 3600, False, nil))];

  P := Proc(3004, 'TiWorker.exe',
    'C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.4000_none_7c8a7c4d0b2f2d1a\TiWorker.exe',
    sgSignedTrusted, 'Microsoft Windows', [0, 30]);
  Result := Result + [Scenario('fp_windows_update',
    'Установка обновлений Windows в фоне', 'TiWorker.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 900, False, nil))];

  P := Proc(3005, 'MsMpEng.exe',
    'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe',
    sgSignedTrusted, 'Microsoft Windows Publisher', [0, 25]);
  Result := Result + [Scenario('fp_defender_scan',
    'Проверка Microsoft Defender в фоне', 'MsMpEng.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 900, False, nil))];

  P := Proc(3006, 'chrome.exe', 'C:\Program Files\Google\Chrome\Application\chrome.exe',
    sgSignedTrusted, 'Google LLC', [0, 20]);
  P.HasWindow := True;
  P.Foreground := True;
  Result := Result + [Scenario('fp_browser_video',
    'Просмотр видео в браузере', 'chrome.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 5, False, nil))];

  P := Proc(3007, 'tool.exe', 'C:\Program Files\Vendor\tool.exe', sgUnsigned, '', [0, 90, 3, 1]);
  Result := Result + [Scenario('fp_short_spike',
    'Кратковременный всплеск нагрузки (3 минуты)', 'tool.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 10, False, nil))];

  P := Proc(3008, 'xmrig.exe', 'D:\Mining\xmrig.exe', sgUnsigned, '', [0, 80]);
  LScenario := Scenario('fp_user_allowed_miner',
    'Майнер, который пользователь запускает сам и добавил в исключения', 'xmrig.exe', False,
    rlNone, rlNone, BuildSnapshots(Background + [P], 900, False, nil));
  LScenario.Exclusions := [Default(TMHExclusion)];
  LScenario.Exclusions[0].Key := MHProgramKey(MHNormalizePath(P.Path), P.Name);
  LScenario.Exclusions[0].Name := 'xmrig';
  Result := Result + [LScenario];

  P := Proc(3009, 'portable.exe', USER_DIR + 'AppData\Local\Programs\Portable\portable.exe', sgUnsigned, '', [0, 1]);
  Result := Result + [Scenario('fp_unsigned_idle_app',
    'Неподписанная программа без нагрузки', 'portable.exe', False, rlNone, rlNone,
    BuildSnapshots(Background + [P], 10, False, nil))];

  LAuto := Autostart(akScheduledTask, '\Microsoft\Windows\Defrag\ScheduledDefrag',
    'C:\Windows\System32\defrag.exe', '\Microsoft\Windows\Defrag');
  Result := Result + [Scenario('fp_system_task',
    'Обычное системное задание Windows (дефрагментация)', 'defrag.exe', False, rlNone, rlNone,
    BuildSnapshots(Background, 10, False, [LAuto]))];

  LAuto := Autostart(akScheduledTask, '\GoogleUpdateTaskMachineUA',
    'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe', '\');
  Result := Result + [Scenario('fp_vendor_updater_task',
    'Задание обновления браузера из Program Files', 'GoogleUpdate.exe', False, rlNone, rlNone,
    BuildSnapshots(Background, 10, False, [LAuto]))];

  LAuto := Autostart(akStartupFolder, 'backup.cmd', 'C:\Program Files\Vendor\Backup\backup.cmd',
    USER_DIR + 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup');
  Result := Result + [Scenario('fp_vendor_script_startup',
    'Сценарий резервного копирования производителя из Program Files', 'backup.cmd', False, rlNone, rlNone,
    BuildSnapshots(Background, 10, False, [LAuto]))];

  // Неподписанная служба открытого ПО в Program Files (как pg_ctl у PostgreSQL).
  P := Proc(3011, 'pg_ctl.exe', 'C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe', sgUnsigned, '', [0, 0.5]);
  LAuto := Autostart(akService, 'postgresql-x64-18', P.Path, 'services');
  LAuto.Command := '"' + P.Path + '" runservice -N "postgresql-x64-18"';
  Result := Result + [Scenario('fp_unsigned_service_program_files',
    'Неподписанная служба открытого ПО в Program Files', 'pg_ctl.exe', False, rlNone, rlNone,
    BuildSnapshots(Background + [P], 10, False, [LAuto]))];

  // Своя автоматизация: скрытое окно PowerShell запускает видимый сценарий пользователя.
  LAuto := Autostart(akScheduledTask, '\TokenSync', 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '\');
  LAuto.Command := 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File E:\Scripts\sync.ps1';
  Result := Result + [Scenario('fp_user_hidden_script_task',
    'Задание пользователя: PowerShell со скрытым окном запускает его собственный сценарий', 'powershell.exe',
    False, rlNone, rlLow, BuildSnapshots(Background, 10, False, [LAuto]))];

  P := Proc(3010, 'Dropbox.exe', 'C:\Program Files (x86)\Dropbox\Client\Dropbox.exe',
    sgSignedTrusted, 'Dropbox, Inc', [0, 30]);
  Result := Result + [Scenario('fp_signed_background_sync',
    'Подписанная программа синхронизации в фоне, 30% CPU', 'Dropbox.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 900, False, nil))];

  // Игра нагружает графический движок GPU (3D), а не вычислительный.
  P := Proc(3012, 'witcher3.exe', 'C:\Games\The Witcher 3\bin\x64\witcher3.exe', sgSignedTrusted,
    'CD PROJEKT S.A.', [0, 35]);
  P.Gpu := 96;
  P.HasWindow := True;
  P.Foreground := True;
  Result := Result + [Scenario('fp_game_gpu',
    'Игра в полноэкранном режиме: 96% GPU (3D), 35% CPU', 'witcher3.exe', False, rlNone, rlLow,
    BuildSnapshots(Background + [P], 5, True, nil))];

  // Рендеринг на видеокарте (CUDA) с открытым окном, пока пользователь отошёл.
  P := Proc(3013, 'blender.exe', 'C:\Program Files\Blender Foundation\Blender 4.2\blender.exe',
    sgSignedTrusted, 'Blender Foundation', [0, 8]);
  P.Gpu := 99;
  P.GpuCompute := 99;
  P.HasWindow := True;
  Result := Result + [Scenario('fp_gpu_render_cuda',
    'Рендеринг в Blender на видеокарте (CUDA, 99%), окно открыто, пользователь отошёл', 'blender.exe',
    False, rlNone, rlLow, BuildSnapshots(Background + [P], 3600, False, nil))];

  // Добровольные научные вычисления на GPU в фоне (Folding@home).
  P := Proc(3014, 'FahCore_22.exe', 'C:\Program Files\FAHClient\cores\FahCore_22.exe',
    sgSignedTrusted, 'Folding@home Consortium', [0, 4]);
  P.Gpu := 95;
  P.GpuCompute := 95;
  Result := Result + [Scenario('fp_folding_at_home_gpu',
    'Folding@home считает на видеокарте в фоне (95% вычислений GPU), подписан', 'FahCore_22.exe',
    False, rlNone, rlLow, BuildSnapshots(Background + [P], 900, False, nil))];

  // Кодирование видео через NVENC: движок videoencode, не вычисления.
  P := Proc(3015, 'obs64.exe', 'C:\Program Files\obs-studio\bin\64bit\obs64.exe', sgSignedTrusted,
    'OBS Project', [0, 12]);
  P.Gpu := 45;
  P.HasWindow := True;
  Result := Result + [Scenario('fp_stream_encoding',
    'Запись или трансляция в OBS: кодирование на видеокарте (45%), окно открыто', 'obs64.exe',
    False, rlNone, rlLow, BuildSnapshots(Background + [P], 30, False, nil))];
end;

end.
