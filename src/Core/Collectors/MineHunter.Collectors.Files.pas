unit MineHunter.Collectors.Files;

{
  Инспектор исполняемых файлов: SHA-256 и цифровая подпись Authenticode.

  Пути берутся из снимка текущего цикла (TMHSnapshot.Processes[].ImagePath,
  TMHSnapshot.Autostart[].ImagePath и TMHSnapshot.Tamper[].ImagePath), поэтому
  коллектор регистрируется ПОСЛЕ коллекторов процессов, автозапуска и tamper.

  Проверка подписи и хеширование дорогие, поэтому:
    - результаты кешируются по пути (без учёта регистра); запись действительна,
      пока не изменились размер и время последней записи файла;
    - за один цикл проверяется не больше AMaxFilesPerCycle файлов и не дольше
      ABudgetMs миллисекунд (хотя бы один файл проверяется всегда, чтобы
      очередь продвигалась даже при очень медленном диске); остальные файлы
      возвращаются со статусом sgNotChecked и проверяются в следующих циклах;
    - файл больше AMaxHashBytes не хешируется (подпись всё равно проверяется);
    - неудачная проверка (файл не найден, нет доступа, сбой API) повторяется
      не чаще одного раза в минуту для каждого пути;
    - размер кеша ограничен: при превышении удаляются записи, которые дольше
      всего не использовались (LRU).

  Отсутствие подписи не означает вредоносность — это только один из признаков
  для анализатора. Сетевых обращений нет (см. MineHunter.Collectors.Files.WinApi).

  Логика отделена от Windows API интерфейсом IMHFileApi и проверяется
  детерминированными unit-тестами с поддельной реализацией.

  Коллектор не потокобезопасен: сканер вызывает Collect последовательно.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Абстракция системных вызовов инспектора файлов.
  /// Методы не выбрасывают исключений при штатных отказах.
  IMHFileApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C73}']
    /// Размер и время последней записи (UTC). False — файл не найден или недоступен.
    function GetFileStamp(const APath: string; out ASize: Int64;
      out ALastWriteUtc: TDateTime): Boolean;
    /// SHA-256 в нижнем регистре hex. False и AError — если прочитать файл не удалось.
    function ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
    /// Проверка подписи Authenticode (встроенной или каталожной).
    /// True — получен определённый результат (sgSignedTrusted, sgSignedUntrusted,
    /// sgUnsigned; для sgSignedUntrusted AError содержит пояснение).
    /// False — проверить не удалось: AState = sgCheckFailed, причина в AError.
    /// ASource: 'embedded', 'catalog' или ''.
    function VerifySignature(const APath: string; out AState: TMHSignatureState;
      out ASigner, ASource, AError: string): Boolean;
    /// Монотонный счётчик миллисекунд для учёта бюджета времени цикла.
    function TickMs: UInt64;
  end;

  TMHFileCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'files';
    /// Повтор неудачной проверки — не чаще одного раза в минуту.
    RetryIntervalMs = 60 * 1000;
    PendingText = 'проверка запланирована';
    TooLargeText = 'файл слишком большой для расчёта хеша';
    UnavailableText = 'файл не найден или недоступен';
  private type
    TCacheEntry = record
      Info: TMHFileInfo;
      /// Проверка не удалась: запись используется до истечения RetryIntervalMs.
      Failed: Boolean;
      /// IMHClock.TickMs момента проверки.
      CheckedTick: UInt64;
      /// Номер последнего обращения (для вытеснения LRU).
      LastUsed: UInt64;
    end;
  private
    FApi: IMHFileApi;
    FClock: IMHClock;
    FBudgetMs: Cardinal;
    FMaxFilesPerCycle: Integer;
    FMaxHashBytes: Int64;
    FMaxCacheEntries: Integer;
    FCache: TDictionary<string, TCacheEntry>;
    FUseCounter: UInt64;
    function GatherPaths(const ASnapshot: TMHSnapshot): TArray<string>;
    function TryGetCached(const AKey, APath: string; out AInfo: TMHFileInfo;
      out AFailed: Boolean): Boolean;
    function Inspect(const APath: string; out AFailed: Boolean): TMHFileInfo;
    procedure Store(const AKey: string; const AInfo: TMHFileInfo; AFailed: Boolean);
    procedure TrimCache;
  public
    /// ABudgetMs — бюджет времени на проверку файлов за цикл;
    /// AMaxFilesPerCycle — не больше стольких проверок за цикл (>= 1);
    /// AMaxHashBytes — файлы большего размера не хешируются (>= 0);
    /// AMaxCacheEntries — предельный размер кеша (>= 1).
    constructor Create(const AApi: IMHFileApi; const AClock: IMHClock;
      ABudgetMs: Cardinal = 300; AMaxFilesPerCycle: Integer = 30;
      AMaxHashBytes: Int64 = 512 * 1024 * 1024; AMaxCacheEntries: Integer = 5000);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    /// Число записей в кеше (включая неудачные проверки).
    function CacheCount: Integer;
  end;

implementation

uses
  System.Generics.Defaults,
  MineHunter.Core.Paths, MineHunter.Core.Lang;

/// Абсолютный путь: «X:\...» или сетевой «\\server\...».
/// Относительные пути не проверяются: результат зависел бы от текущего каталога.
function IsAbsolutePath(const APath: string): Boolean;
begin
  Result := ((Length(APath) >= 3) and (APath[2] = ':') and (APath[3] = '\')) or
    ((Length(APath) >= 3) and (APath[1] = '\') and (APath[2] = '\'));
end;

function JoinError(const A, B: string): string;
begin
  if A = '' then
    Result := B
  else if B = '' then
    Result := A
  else
    Result := A + '; ' + B;
end;

{ TMHFileCollector }

constructor TMHFileCollector.Create(const AApi: IMHFileApi; const AClock: IMHClock;
  ABudgetMs: Cardinal; AMaxFilesPerCycle: Integer; AMaxHashBytes: Int64;
  AMaxCacheEntries: Integer);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  if AMaxFilesPerCycle < 1 then
    raise EArgumentOutOfRangeException.Create('AMaxFilesPerCycle');
  if AMaxHashBytes < 0 then
    raise EArgumentOutOfRangeException.Create('AMaxHashBytes');
  if AMaxCacheEntries < 1 then
    raise EArgumentOutOfRangeException.Create('AMaxCacheEntries');
  FApi := AApi;
  FClock := AClock;
  FBudgetMs := ABudgetMs;
  FMaxFilesPerCycle := AMaxFilesPerCycle;
  FMaxHashBytes := AMaxHashBytes;
  FMaxCacheEntries := AMaxCacheEntries;
  FCache := TDictionary<string, TCacheEntry>.Create;
end;

destructor TMHFileCollector.Destroy;
begin
  FCache.Free;
  inherited;
end;

function TMHFileCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHFileCollector.GetDisplayName: string;
begin
  Result := MHL('Файлы и подписи', 'Files and signatures');
end;

function TMHFileCollector.CacheCount: Integer;
begin
  Result := FCache.Count;
end;

function TMHFileCollector.GatherPaths(const ASnapshot: TMHSnapshot): TArray<string>;
var
  LSeen: TDictionary<string, Boolean>;
  LList: TList<string>;

  procedure AddPath(const ARaw: string);
  var
    LPath, LKey: string;
  begin
    LPath := MHNormalizePath(ARaw);
    if not IsAbsolutePath(LPath) then
      Exit;
    LKey := LPath.ToLower;
    if LSeen.ContainsKey(LKey) then
      Exit;
    LSeen.Add(LKey, True);
    LList.Add(LPath);
  end;

var
  I: Integer;
begin
  LSeen := TDictionary<string, Boolean>.Create;
  LList := TList<string>.Create;
  try
    for I := 0 to High(ASnapshot.Processes) do
      AddPath(ASnapshot.Processes[I].ImagePath);
    for I := 0 to High(ASnapshot.Autostart) do
      AddPath(ASnapshot.Autostart[I].ImagePath);
    // Программы, на которые указывают признаки вмешательства (WMI, IFEO и т.п.).
    for I := 0 to High(ASnapshot.Tamper) do
      AddPath(ASnapshot.Tamper[I].ImagePath);
    Result := LList.ToArray;
  finally
    LList.Free;
    LSeen.Free;
  end;
end;

function TMHFileCollector.TryGetCached(const AKey, APath: string;
  out AInfo: TMHFileInfo; out AFailed: Boolean): Boolean;
var
  LEntry: TCacheEntry;
  LSize: Int64;
  LLastWrite: TDateTime;
begin
  AInfo := Default(TMHFileInfo);
  AFailed := False;
  if not FCache.TryGetValue(AKey, LEntry) then
    Exit(False);

  if LEntry.Failed then
    // Неудачную проверку не повторяем чаще RetryIntervalMs.
    Result := FClock.TickMs - LEntry.CheckedTick < RetryIntervalMs
  else
    // Успешная запись действительна, пока файл не изменился.
    Result := FApi.GetFileStamp(APath, LSize, LLastWrite) and
      (LSize = LEntry.Info.SizeBytes) and (LLastWrite = LEntry.Info.LastWriteUtc);

  if Result then
  begin
    Inc(FUseCounter);
    LEntry.LastUsed := FUseCounter;
    FCache[AKey] := LEntry;
    AInfo := LEntry.Info;
    AFailed := LEntry.Failed;
    // Путь берётся из текущего снимка: регистр букв мог отличаться.
    AInfo.Path := APath;
  end;
end;

function TMHFileCollector.Inspect(const APath: string; out AFailed: Boolean): TMHFileInfo;
var
  LSize: Int64;
  LLastWrite: TDateTime;
  LState: TMHSignatureState;
  LSigner, LSource, LError, LHash: string;
begin
  Result := TMHFileInfo.Create(APath);
  AFailed := False;
  try
    if not FApi.GetFileStamp(APath, LSize, LLastWrite) then
    begin
      Result.Signature := sgCheckFailed;
      Result.Error := UnavailableText;
      AFailed := True;
      Exit;
    end;
    Result.SizeBytes := LSize;
    Result.LastWriteUtc := LLastWrite;

    if FApi.VerifySignature(APath, LState, LSigner, LSource, LError) then
    begin
      Result.Signature := LState;
      Result.Signer := LSigner;
      Result.SignatureSource := LSource;
      Result.Error := LError;
    end
    else
    begin
      Result.Signature := sgCheckFailed;
      Result.Error := MHL('подпись: ', 'signature: ') + LError;
      AFailed := True;
    end;

    if LSize > FMaxHashBytes then
      Result.Error := JoinError(Result.Error, TooLargeText)
    else if FApi.ComputeSha256(APath, LHash, LError) then
      Result.Sha256 := LHash
    else
    begin
      Result.Error := JoinError(Result.Error, MHL('хеш: ', 'hash: ') + LError);
      AFailed := True;
    end;
  except
    // Сбой одного файла не должен прерывать проверку остальных.
    on E: Exception do
    begin
      Result.Signature := sgCheckFailed;
      Result.Error := JoinError(Result.Error, E.Message);
      AFailed := True;
    end;
  end;
end;

procedure TMHFileCollector.Store(const AKey: string; const AInfo: TMHFileInfo;
  AFailed: Boolean);
var
  LEntry: TCacheEntry;
begin
  Inc(FUseCounter);
  LEntry.Info := AInfo;
  LEntry.Failed := AFailed;
  LEntry.CheckedTick := FClock.TickMs;
  LEntry.LastUsed := FUseCounter;
  FCache.AddOrSetValue(AKey, LEntry);
end;

procedure TMHFileCollector.TrimCache;
var
  LOrder: TArray<TPair<UInt64, string>>;
  LPair: TPair<string, TCacheEntry>;
  I, LExcess: Integer;
begin
  LExcess := FCache.Count - FMaxCacheEntries;
  if LExcess <= 0 then
    Exit;
  SetLength(LOrder, FCache.Count);
  I := 0;
  for LPair in FCache do
  begin
    LOrder[I] := TPair<UInt64, string>.Create(LPair.Value.LastUsed, LPair.Key);
    Inc(I);
  end;
  // Вытесняем записи, к которым дольше всего не обращались (LRU).
  TArray.Sort<TPair<UInt64, string>>(LOrder, TComparer<TPair<UInt64, string>>.Construct(
    function(const ALeft, ARight: TPair<UInt64, string>): Integer
    begin
      if ALeft.Key < ARight.Key then
        Result := -1
      else if ALeft.Key > ARight.Key then
        Result := 1
      else
        Result := 0;
    end));
  for I := 0 to LExcess - 1 do
    FCache.Remove(LOrder[I].Value);
end;

function TMHFileCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LPaths: TArray<string>;
  LFiles: TArray<TMHFileInfo>;
  LStartTick: UInt64;
  LInspected, LPending, LFailedCount, I: Integer;
  LKey: string;
  LInfo: TMHFileInfo;
  LFailed: Boolean;
  LState: TMHSourceState;
  LMessage: string;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;

  LPaths := GatherPaths(ASnapshot);
  SetLength(LFiles, Length(LPaths));
  LStartTick := FApi.TickMs;
  LInspected := 0;
  LPending := 0;
  LFailedCount := 0;

  for I := 0 to High(LPaths) do
  begin
    LKey := LPaths[I].ToLower;
    if TryGetCached(LKey, LPaths[I], LInfo, LFailed) then
    begin
      if LFailed then
        Inc(LFailedCount);
      LFiles[I] := LInfo;
      Continue;
    end;

    // Хотя бы одна проверка за цикл выполняется всегда, иначе очередь
    // не продвинется при медленном диске или нулевом бюджете.
    if (LInspected >= FMaxFilesPerCycle) or
       ((LInspected > 0) and (FApi.TickMs - LStartTick >= FBudgetMs)) then
    begin
      LInfo := TMHFileInfo.Create(LPaths[I]);
      LInfo.Signature := sgNotChecked;
      LInfo.Error := PendingText;
      LFiles[I] := LInfo;
      Inc(LPending);
      Continue;
    end;

    LInfo := Inspect(LPaths[I], LFailed);
    Inc(LInspected);
    if LFailed then
      Inc(LFailedCount);
    Store(LKey, LInfo, LFailed);
    LFiles[I] := LInfo;
  end;

  TrimCache;

  LState := ssSuccess;
  LMessage := '';
  if LPending > 0 then
  begin
    LState := ssPartial;
    LMessage := Format(MHL('Проверено %d из %d файлов; остальные — в следующих циклах.',
      'Checked %d of %d files; the rest in the next cycles.'),
      [Length(LPaths) - LPending, Length(LPaths)]);
  end;
  if LFailedCount > 0 then
  begin
    LState := ssPartial;
    LMessage := Trim(LMessage + Format(MHL(' Не удалось проверить %d из %d файлов.',
      ' Could not check %d of %d files.'),
      [LFailedCount, Length(LPaths)]));
  end;

  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState,
    LMessage, LNow));
  Result.Status.ItemCount := Length(LFiles);
  Result.Files := LFiles;
end;

end.
