unit MineHunter.Collectors.Tamper;

{
  Коллектор признаков вмешательства в защиту системы. Это приёмы, которыми
  майнеры и другие нежелательные программы прячутся и защищают себя, и которые
  почти не встречаются у обычных программ:
    - подписки WMI, запускающие команду или сценарий («бесфайловый» автозапуск);
    - исключения Microsoft Defender (путь, процесс, расширение);
    - перехват запуска программ: Debugger в Image File Execution Options и
      MonitorProcess в SilentProcessExit;
    - перенаправление в hosts сайтов антивирусов и обновлений Windows;
    - политики, отключающие диспетчер задач, редактор реестра или защиту.

  Коллектор только собирает факты; оценку (с учётом подписи, расположения и
  оправдывающих случаев) даёт анализатор. Реализация — Tamper.WinApi.
  Подписки WMI и исключения Defender видны только с правами администратора —
  без них источник частичный, с причиной.

  Источники меняются редко, поэтому результат кэшируется на ARefreshSeconds.
  Не потокобезопасен.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Источники признаков вмешательства; каждый может отказать независимо.
  TMHTamperSource = (tsrWmi, tsrDefender, tsrIfeo, tsrHosts, tsrPolicies);

  /// Соглашение как у автозапуска: False — источник прочитать не удалось
  /// (AError — причина); True с непустым AError — данные частичные.
  IMHTamperApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1CB0}']
    function ReadWmiSubscriptions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadDefenderExclusions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    /// IFEO Debugger и SilentProcessExit MonitorProcess.
    function ReadExecutionHijacks(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    /// Текст файла hosts, его фактический путь и путь по умолчанию
    /// (не совпадают — каталог hosts перенесён через DataBasePath).
    function ReadHostsFile(out AText, APath, ADefaultPath: string; out AError: string): Boolean;
    function ReadPolicies(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    /// Компьютер входит в домен организации.
    function IsManagedComputer: Boolean;
  end;

  TMHTamperCollector = class(TInterfacedObject, IMHCollector, IMHCacheInvalidation)
  public const
    SourceIdValue = 'tamper';
    DefaultRefreshSeconds = 120;
  private
    FApi: IMHTamperApi;
    FClock: IMHClock;
    FRefreshSeconds: Integer;
    FHasCache: Boolean;
    FCacheUtc: TDateTime;
    FCached: TArray<TMHTamperEntry>;
    FCachedState: TMHSourceState;
    FCachedMessage: string;
    FReadCount: Integer;
    procedure Refresh;
  public
    constructor Create(const AApi: IMHTamperApi; const AClock: IMHClock;
      ARefreshSeconds: Integer = DefaultRefreshSeconds);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Сбрасывает кэш: следующий Collect перечитает источники.
    procedure Invalidate;
    /// Сколько раз источники перечитывались (для тестов кэширования).
    property ReadCount: Integer read FReadCount;
  end;

/// Записи hosts, перенаправляющие домены антивирусов и обновлений Windows.
/// Обычные записи (блокировка рекламы, свои сайты) не возвращаются.
function MHParseHostsRedirects(const AText, ALocation: string): TArray<TMHTamperEntry>;

implementation

uses
  System.Math, System.StrUtils,
  MineHunter.Analysis.Indicators, MineHunter.Core.Lang;

function MHParseHostsRedirects(const AText, ALocation: string): TArray<TMHTamperEntry>;
var
  LLines, LParts: TArray<string>;
  LLine, LHost: string;
  LHash, I: Integer;
  LEntry: TMHTamperEntry;
begin
  Result := nil;
  LLines := AText.Replace(#13, '').Split([#10]);
  for LLine in LLines do
  begin
    LHash := LLine.IndexOf('#');
    if LHash >= 0 then
      LParts := LLine.Substring(0, LHash).Trim.Split([' ', #9], TStringSplitOptions.ExcludeEmpty)
    else
      LParts := LLine.Trim.Split([' ', #9], TStringSplitOptions.ExcludeEmpty);
    if Length(LParts) < 2 then
      Continue;
    for I := 1 to High(LParts) do
    begin
      LHost := LParts[I].ToLower;
      if MHIsSecurityDomain(LHost) then
      begin
        LEntry := TMHTamperEntry.Create(tpHostsRedirect, LHost, LParts[0], ALocation);
        LEntry.Details := Format('%s → %s', [LHost, LParts[0]]);
        Result := Result + [LEntry];
      end;
    end;
  end;
end;

/// Одинаковые записи (64- и 32-битное представление реестра и т.п.) — один раз;
/// отмечает, управляется ли компьютер организацией.
function DeduplicateTamper(const AEntries: TArray<TMHTamperEntry>; AManaged: Boolean): TArray<TMHTamperEntry>;
var
  LEntry: TMHTamperEntry;
  LSeen: TArray<string>;
  LKey, LOther: string;
  LDuplicate: Boolean;
begin
  Result := nil;
  LSeen := nil;
  for LEntry in AEntries do
  begin
    LKey := Format('%d|%s|%s|%s', [Ord(LEntry.Kind), LEntry.Name.ToLower, LEntry.Value.ToLower,
      LEntry.Details.ToLower]);
    LDuplicate := False;
    for LOther in LSeen do
      if LOther = LKey then
        LDuplicate := True;
    if LDuplicate then
      Continue;
    LSeen := LSeen + [LKey];
    Result := Result + [LEntry];
    Result[High(Result)].ManagedComputer := AManaged;
  end;
end;

{ TMHTamperCollector }

constructor TMHTamperCollector.Create(const AApi: IMHTamperApi; const AClock: IMHClock;
  ARefreshSeconds: Integer);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
  FRefreshSeconds := Max(1, ARefreshSeconds);
end;

function TMHTamperCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHTamperCollector.GetDisplayName: string;
begin
  Result := MHL('Признаки вмешательства в защиту системы', 'Signs of tampering with system protection');
end;

procedure TMHTamperCollector.Refresh;
const
  NAMES: array[TMHTamperSource] of string = ('подписки WMI', 'исключения Defender',
    'перехват запуска программ', 'файл hosts', 'политики');
var
  LSource: TMHTamperSource;
  LEntries, LAll: TArray<TMHTamperEntry>;
  LError, LText, LPath, LDefaultPath, LNotes: string;
  LRelocated: TMHTamperEntry;
  LOk: Boolean;
  LFailed, LPartial: Integer;
begin
  Inc(FReadCount);
  LAll := nil;
  LNotes := '';
  LFailed := 0;
  LPartial := 0;
  for LSource := Low(TMHTamperSource) to High(TMHTamperSource) do
  begin
    LEntries := nil;
    LError := '';
    try
      case LSource of
        tsrWmi: LOk := FApi.ReadWmiSubscriptions(LEntries, LError);
        tsrDefender: LOk := FApi.ReadDefenderExclusions(LEntries, LError);
        tsrIfeo: LOk := FApi.ReadExecutionHijacks(LEntries, LError);
        tsrHosts:
          begin
            LOk := FApi.ReadHostsFile(LText, LPath, LDefaultPath, LError);
            if LOk then
            begin
              LEntries := MHParseHostsRedirects(LText, LPath);
              // Перенесённый каталог hosts — сам по себе признак вмешательства.
              if (LDefaultPath <> '') and not SameText(LPath, LDefaultPath) then
              begin
                LRelocated := TMHTamperEntry.Create(tpHostsRedirect, 'DataBasePath', LPath,
                  'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters');
                LRelocated.Details := MHL('файл hosts перенесён из стандартного места: ',
                  'hosts file moved from its standard location: ') + LDefaultPath;
                LEntries := LEntries + [LRelocated];
              end;
            end;
          end;
      else
        LOk := FApi.ReadPolicies(LEntries, LError);
      end;
    except
      on E: Exception do
      begin
        LOk := False;
        LError := E.Message;
      end;
    end;
    if LOk then
      LAll := LAll + LEntries
    else
      Inc(LFailed);
    if LError <> '' then
    begin
      if LOk then
        Inc(LPartial);
      LNotes := LNotes + Format('%s: %s. ', [NAMES[LSource], LError]);
    end;
  end;
  FCached := DeduplicateTamper(LAll, FApi.IsManagedComputer);
  FCachedMessage := Trim(LNotes);
  if LFailed = Ord(High(TMHTamperSource)) + 1 then
    FCachedState := ssError
  else if (LFailed > 0) or (LPartial > 0) then
    FCachedState := ssPartial
  else
    FCachedState := ssSuccess;
  // Полный отказ не кэшируется: следующий опрос повторит чтение.
  FHasCache := FCachedState <> ssError;
  FCacheUtc := FClock.NowUtc;
end;

procedure TMHTamperCollector.Invalidate;
begin
  FHasCache := False;
end;

function TMHTamperCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  if not FHasCache or ((FClock.NowUtc - FCacheUtc) * SecsPerDay >= FRefreshSeconds) then
    Refresh;
  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, FCachedState,
    FCachedMessage, LNow));
  // Подписки WMI и исключения Defender видны только администратору.
  Result.Status.RequiresElevation := (FCachedState = ssPartial) and
    (FCachedMessage.Contains('администратор'));
  Result.Status.ItemCount := Length(FCached);
  Result.Tamper := FCached;
end;

end.
