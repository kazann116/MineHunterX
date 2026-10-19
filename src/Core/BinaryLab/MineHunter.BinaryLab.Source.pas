unit MineHunter.BinaryLab.Source;

{
  Источник байтов для BinaryLab.

  - TMHFileSource открывает файл только на чтение (GENERIC_READ) с разрешением
    совместного доступа на чтение, запись и удаление: анализ работает и для
    запущенных программ и не мешает другим процессам. Чтение позиционное
    (OVERLAPPED со смещением), поэтому один источник можно читать из разных
    потоков. Файл никогда не изменяется и не загружается загрузчиком Windows.
  - TMHBytesSource — данные в памяти (тесты, ресурсы).
  - TMHBinaryReader — чтение структур с проверкой границ и небольшим кэшем
    окна: разбор PE делает тысячи мелких чтений.
  - MHReadChunks — потоковый обход файла блоками с перекрытием (для поиска
    строк и сигнатур на границах блоков) и проверкой отмены. Память —
    один блок, независимо от размера файла.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types;

type
  IMHBinarySource = interface
    ['{8C3E2A51-6B7D-4F90-A1C2-5D4E3F2A1B01}']
    function GetSize: Int64;
    function GetName: string;
    /// Читает до ACount байт со смещения AOffset. Возвращает число прочитанных
    /// байт (0 — смещение за концом данных). Исключение — только при сбое чтения.
    function ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
    property Size: Int64 read GetSize;
    property Name: string read GetName;
  end;

  TMHFileSource = class(TInterfacedObject, IMHBinarySource)
  private
    FHandle: THandle;
    FPath: string;
    FSize: Int64;
    FLastWriteUtc: TDateTime;
  public
    /// EMHBinaryLabError — файл не найден, это папка или нет доступа.
    constructor Create(const APath: string);
    destructor Destroy; override;
    function GetSize: Int64;
    function GetName: string;
    function ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
    property LastWriteUtc: TDateTime read FLastWriteUtc;
  end;

  TMHBytesSource = class(TInterfacedObject, IMHBinarySource)
  private
    FData: TBytes;
    FName: string;
  public
    constructor Create(const AData: TBytes; const AName: string = '');
    function GetSize: Int64;
    function GetName: string;
    function ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
  end;

  /// Чтение структур с проверкой границ. Не потокобезопасен (свой кэш):
  /// каждому потоку — свой экземпляр поверх общего источника.
  TMHBinaryReader = class
  private const
    CACHE_SIZE = 64 * 1024;
  private
    FSource: IMHBinarySource;
    FSize: Int64;
    FCache: TBytes;
    FCacheOffset: Int64;
    FCacheCount: Integer;
    function Fill(AOffset: Int64): Boolean;
  public
    constructor Create(const ASource: IMHBinarySource);
    /// True — прочитано ровно ACount байт.
    function TryRead(AOffset: Int64; var ABuffer; ACount: Integer): Boolean;
    /// До ACount байт (меньше у конца файла; пусто — за концом или ACount <= 0).
    function ReadBytes(AOffset: Int64; ACount: Integer): TBytes;
    function TryReadByte(AOffset: Int64; out AValue: Byte): Boolean;
    function TryReadWord(AOffset: Int64; out AValue: Word): Boolean;
    function TryReadDWord(AOffset: Int64; out AValue: Cardinal): Boolean;
    function TryReadQWord(AOffset: Int64; out AValue: UInt64): Boolean;
    /// Строка ASCII до нулевого байта (не длиннее AMaxLength). Непечатаемые
    /// символы заменяются на «?». '' — смещение вне файла.
    function ReadAnsiZ(AOffset: Int64; AMaxLength: Integer): string;
    /// ACharCount символов UTF-16LE (обрезается у конца файла).
    function ReadUtf16(AOffset: Int64; ACharCount: Integer): string;
    /// Данные начинаются с ASignature.
    function MatchesAt(AOffset: Int64; const ASignature: array of Byte): Boolean;
    function InRange(AOffset, ACount: Int64): Boolean;
    property Size: Int64 read FSize;
    property Source: IMHBinarySource read FSource;
  end;

  /// Обработчик блока: AData[0..ACount-1] — байты с файлового смещения ABase.
  /// False — прекратить обход.
  TMHChunkProc = reference to function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean;

/// Обходит [AStart, AStart + ALimit) блоками по AChunkSize байт. Каждый блок,
/// кроме первого, начинается на AOverlap байт раньше конца предыдущего
/// (сигнатура на границе блоков не теряется). Перед каждым блоком вызывается
/// ACancel (если задана): True — EMHBinaryLabCancelled.
procedure MHReadChunks(const ASource: IMHBinarySource; AStart, ALimit: Int64;
  AChunkSize, AOverlap: Integer; const AProc: TMHChunkProc; const ACancel: TMHCancelCheck = nil);

/// Первое вхождение APattern начиная с AFrom (-1 — не найдено). AIgnoreCase —
/// без учёта регистра латинских букв (для поиска текста). Читает блоками,
/// проверяет отмену; ALimit — сколько байт просмотреть (<= 0 — до конца).
function MHFindBytes(const ASource: IMHBinarySource; const APattern: TBytes; AFrom: Int64;
  AIgnoreCase: Boolean = False; const ACancel: TMHCancelCheck = nil; ALimit: Int64 = 0): Int64;
/// Шаблон из шестнадцатеричной записи: «4D 5A 90», «4d5a90», «0x4D,0x5A».
/// False — пустая строка, нечётное число цифр или посторонние символы.
function MHParseHexPattern(const AText: string; out APattern: TBytes): Boolean;
/// Байты текста для поиска: ASCII (символы вне ASCII заменяются на «?») или UTF-16LE.
function MHTextPattern(const AText: string; AUtf16: Boolean): TBytes;

/// EMHBinaryLabCancelled, если ACancel задана и вернула True.
procedure MHCheckCancel(const ACancel: TMHCancelCheck);

implementation

uses
  Winapi.Windows, System.Math,
  MineHunter.Core.Lang;

function ToApiPath(const APath: string): string;
begin
  // Длинные пути (> MAX_PATH) — через префикс \\?\ (только для полного пути с буквой диска).
  if (Length(APath) >= MAX_PATH) and (Length(APath) > 2) and (APath[2] = ':') then
    Result := '\\?\' + APath
  else
    Result := APath;
end;

function FileTimeToUtc(const ATime: TFileTime): TDateTime;
var
  LSystem: TSystemTime;
begin
  if ((ATime.dwLowDateTime = 0) and (ATime.dwHighDateTime = 0)) or
     not FileTimeToSystemTime(ATime, LSystem) then
    Exit(0);
  Result := SystemTimeToDateTime(LSystem);
end;

{ TMHFileSource }

constructor TMHFileSource.Create(const APath: string);
var
  LSize: Int64;
  LInfo: TByHandleFileInformation;
  LCode: DWORD;
begin
  inherited Create;
  FHandle := INVALID_HANDLE_VALUE;
  FPath := APath;
  FillChar(LInfo, SizeOf(LInfo), 0);
  if Trim(APath) = '' then
    raise EMHBinaryLabError.Create(MHL('Не указан файл', 'No file specified'));
  FHandle := CreateFile(PChar(ToApiPath(APath)), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  if FHandle = INVALID_HANDLE_VALUE then
  begin
    LCode := GetLastError;
    raise EMHBinaryLabError.CreateFmt(MHL('Не удалось открыть «%s»: %s', 'Cannot open "%s": %s'),
      [APath, SysErrorMessage(LCode)]);
  end;
  if GetFileInformationByHandle(FHandle, LInfo) and
     (LInfo.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY <> 0) then
  begin
    CloseHandle(FHandle);
    FHandle := INVALID_HANDLE_VALUE;
    raise EMHBinaryLabError.CreateFmt(MHL('«%s» — это папка, а не файл', '"%s" is a folder, not a file'), [APath]);
  end;
  if not GetFileSizeEx(FHandle, LSize) then
  begin
    LCode := GetLastError;
    CloseHandle(FHandle);
    FHandle := INVALID_HANDLE_VALUE;
    raise EMHBinaryLabError.CreateFmt(MHL('Не удалось узнать размер «%s»: %s', 'Cannot get the size of "%s": %s'),
      [APath, SysErrorMessage(LCode)]);
  end;
  FSize := LSize;
  FLastWriteUtc := FileTimeToUtc(LInfo.ftLastWriteTime);
end;

destructor TMHFileSource.Destroy;
begin
  if FHandle <> INVALID_HANDLE_VALUE then
    CloseHandle(FHandle);
  inherited;
end;

function TMHFileSource.GetName: string;
begin
  Result := FPath;
end;

function TMHFileSource.GetSize: Int64;
begin
  Result := FSize;
end;

function TMHFileSource.ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
var
  LOverlapped: TOverlapped;
  LRead: DWORD;
  LCode: DWORD;
begin
  Result := 0;
  if (ACount <= 0) or (AOffset < 0) or (AOffset >= FSize) then
    Exit;
  ACount := Integer(Min(Int64(ACount), FSize - AOffset));
  FillChar(LOverlapped, SizeOf(LOverlapped), 0);
  LOverlapped.Offset := DWORD(AOffset and $FFFFFFFF);
  LOverlapped.OffsetHigh := DWORD(AOffset shr 32);
  LRead := 0;
  if not ReadFile(FHandle, ABuffer, DWORD(ACount), LRead, @LOverlapped) then
  begin
    LCode := GetLastError;
    // Файл укоротили во время анализа — данных просто нет.
    if LCode = ERROR_HANDLE_EOF then
      Exit(0);
    raise EMHBinaryLabError.CreateFmt(MHL('Ошибка чтения по смещению %s: %s', 'Read error at offset %s: %s'),
      [MHHexOffset(AOffset), SysErrorMessage(LCode)]);
  end;
  Result := Integer(LRead);
end;

{ TMHBytesSource }

constructor TMHBytesSource.Create(const AData: TBytes; const AName: string);
begin
  inherited Create;
  FData := AData;
  FName := AName;
end;

function TMHBytesSource.GetName: string;
begin
  Result := FName;
end;

function TMHBytesSource.GetSize: Int64;
begin
  Result := Length(FData);
end;

function TMHBytesSource.ReadAt(AOffset: Int64; var ABuffer; ACount: Integer): Integer;
begin
  Result := 0;
  if (ACount <= 0) or (AOffset < 0) or (AOffset >= Length(FData)) then
    Exit;
  Result := Integer(Min(Int64(ACount), Int64(Length(FData)) - AOffset));
  Move(FData[AOffset], ABuffer, Result);
end;

{ TMHBinaryReader }

constructor TMHBinaryReader.Create(const ASource: IMHBinarySource);
begin
  inherited Create;
  if ASource = nil then
    raise EArgumentNilException.Create('ASource');
  FSource := ASource;
  FSize := ASource.Size;
  SetLength(FCache, CACHE_SIZE);
  FCacheOffset := -1;
  FCacheCount := 0;
end;

function TMHBinaryReader.InRange(AOffset, ACount: Int64): Boolean;
begin
  Result := (AOffset >= 0) and (ACount >= 0) and (AOffset <= FSize) and (ACount <= FSize - AOffset);
end;

function TMHBinaryReader.Fill(AOffset: Int64): Boolean;
begin
  FCacheOffset := AOffset;
  FCacheCount := FSource.ReadAt(AOffset, FCache[0], CACHE_SIZE);
  Result := FCacheCount > 0;
end;

function TMHBinaryReader.TryRead(AOffset: Int64; var ABuffer; ACount: Integer): Boolean;
begin
  if ACount = 0 then
    Exit(InRange(AOffset, 0));
  if (ACount < 0) or not InRange(AOffset, ACount) then
    Exit(False);
  if ACount > CACHE_SIZE div 2 then
    Exit(FSource.ReadAt(AOffset, ABuffer, ACount) = ACount);
  if (FCacheOffset < 0) or (AOffset < FCacheOffset) or
     (AOffset + ACount > FCacheOffset + FCacheCount) then
    if not Fill(AOffset) then
      Exit(False);
  if AOffset + ACount > FCacheOffset + FCacheCount then
    Exit(False);
  Move(FCache[AOffset - FCacheOffset], ABuffer, ACount);
  Result := True;
end;

function TMHBinaryReader.ReadBytes(AOffset: Int64; ACount: Integer): TBytes;
var
  LCount: Integer;
begin
  Result := nil;
  if (ACount <= 0) or (AOffset < 0) or (AOffset >= FSize) then
    Exit;
  LCount := Integer(Min(Int64(ACount), FSize - AOffset));
  SetLength(Result, LCount);
  LCount := FSource.ReadAt(AOffset, Result[0], LCount);
  SetLength(Result, LCount);
end;

function TMHBinaryReader.TryReadByte(AOffset: Int64; out AValue: Byte): Boolean;
begin
  AValue := 0;
  Result := TryRead(AOffset, AValue, SizeOf(AValue));
end;

function TMHBinaryReader.TryReadWord(AOffset: Int64; out AValue: Word): Boolean;
begin
  AValue := 0;
  Result := TryRead(AOffset, AValue, SizeOf(AValue));
end;

function TMHBinaryReader.TryReadDWord(AOffset: Int64; out AValue: Cardinal): Boolean;
begin
  AValue := 0;
  Result := TryRead(AOffset, AValue, SizeOf(AValue));
end;

function TMHBinaryReader.TryReadQWord(AOffset: Int64; out AValue: UInt64): Boolean;
begin
  AValue := 0;
  Result := TryRead(AOffset, AValue, SizeOf(AValue));
end;

function TMHBinaryReader.ReadAnsiZ(AOffset: Int64; AMaxLength: Integer): string;
var
  LBytes: TBytes;
  I: Integer;
  LBuilder: TStringBuilder;
begin
  Result := '';
  LBytes := ReadBytes(AOffset, AMaxLength);
  LBuilder := TStringBuilder.Create;
  try
    for I := 0 to High(LBytes) do
    begin
      if LBytes[I] = 0 then
        Break;
      if (LBytes[I] >= $20) and (LBytes[I] < $7F) then
        LBuilder.Append(Char(LBytes[I]))
      else
        LBuilder.Append('?');
    end;
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function TMHBinaryReader.ReadUtf16(AOffset: Int64; ACharCount: Integer): string;
var
  LBytes: TBytes;
begin
  Result := '';
  if ACharCount <= 0 then
    Exit;
  LBytes := ReadBytes(AOffset, ACharCount * 2);
  if Length(LBytes) < 2 then
    Exit;
  SetLength(Result, Length(LBytes) div 2);
  Move(LBytes[0], Result[1], (Length(LBytes) div 2) * 2);
end;

function TMHBinaryReader.MatchesAt(AOffset: Int64; const ASignature: array of Byte): Boolean;
var
  LBytes: TBytes;
  I: Integer;
begin
  if Length(ASignature) = 0 then
    Exit(True);
  SetLength(LBytes, Length(ASignature));
  if not TryRead(AOffset, LBytes[0], Length(LBytes)) then
    Exit(False);
  for I := 0 to High(ASignature) do
    if LBytes[I] <> ASignature[I] then
      Exit(False);
  Result := True;
end;

{ Функции }

procedure MHCheckCancel(const ACancel: TMHCancelCheck);
begin
  if Assigned(ACancel) and ACancel then
    raise EMHBinaryLabCancelled.Create(MHL('Анализ отменён', 'Analysis cancelled'));
end;

function LowerAscii(AByte: Byte): Byte; inline;
begin
  if AByte in [Ord('A')..Ord('Z')] then
    Result := AByte + 32
  else
    Result := AByte;
end;

function MHFindBytes(const ASource: IMHBinarySource; const APattern: TBytes; AFrom: Int64;
  AIgnoreCase: Boolean; const ACancel: TMHCancelCheck; ALimit: Int64): Int64;
var
  LFound: Int64;
  LPattern: TBytes;
  I: Integer;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := -1;
  if (ASource = nil) or (Length(APattern) = 0) or (AFrom < 0) or (AFrom >= ASource.Size) then
    Exit;
  if ALimit <= 0 then
    ALimit := ASource.Size;
  LPattern := Copy(APattern);
  if AIgnoreCase then
    for I := 0 to High(LPattern) do
      LPattern[I] := LowerAscii(LPattern[I]);
  LFound := -1;
  MHReadChunks(ASource, AFrom, ALimit, 1024 * 1024, Length(LPattern) - 1,
    function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
    var
      P, J: Integer;
      LFirst: Byte;
    begin
      LFirst := LPattern[0];
      for P := 0 to ACount - Length(LPattern) do
      begin
        if AIgnoreCase then
        begin
          if LowerAscii(AData[P]) <> LFirst then
            Continue;
          J := 1;
          while (J < Length(LPattern)) and (LowerAscii(AData[P + J]) = LPattern[J]) do
            Inc(J);
        end
        else
        begin
          if AData[P] <> LFirst then
            Continue;
          J := 1;
          while (J < Length(LPattern)) and (AData[P + J] = LPattern[J]) do
            Inc(J);
        end;
        if J = Length(LPattern) then
        begin
          LFound := ABase + P;
          Exit(False);
        end;
      end;
      Result := True;
    end, ACancel);
  Result := LFound;
end;

function MHParseHexPattern(const AText: string; out APattern: TBytes): Boolean;
var
  LDigits: string;
  LText: string;
  I: Integer;
  C: Char;
begin
  APattern := nil;
  LText := AText.Replace('0x', ' ', [rfReplaceAll, rfIgnoreCase]);
  LDigits := '';
  for C in LText do
    if CharInSet(C, ['0'..'9', 'a'..'f', 'A'..'F']) then
      LDigits := LDigits + C
    else if not CharInSet(C, [' ', ',', '-', ':', #9]) then
      Exit(False);
  if (LDigits = '') or Odd(Length(LDigits)) then
    Exit(False);
  SetLength(APattern, Length(LDigits) div 2);
  for I := 0 to High(APattern) do
    APattern[I] := StrToInt('$' + Copy(LDigits, I * 2 + 1, 2));
  Result := True;
end;

function MHTextPattern(const AText: string; AUtf16: Boolean): TBytes;
var
  I: Integer;
begin
  if AUtf16 then
  begin
    SetLength(Result, Length(AText) * 2);
    if AText <> '' then
      Move(AText[1], Result[0], Length(Result));
    Exit;
  end;
  SetLength(Result, Length(AText));
  for I := 1 to Length(AText) do
    if Ord(AText[I]) < $80 then
      Result[I - 1] := Ord(AText[I])
    else
      Result[I - 1] := Ord('?');
end;

procedure MHReadChunks(const ASource: IMHBinarySource; AStart, ALimit: Int64;
  AChunkSize, AOverlap: Integer; const AProc: TMHChunkProc; const ACancel: TMHCancelCheck);
var
  LBuffer: TBytes;
  LEnd, LPos: Int64;
  LWant, LRead: Integer;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  if (ASource = nil) or not Assigned(AProc) then
    Exit;
  AChunkSize := Max(AChunkSize, 4096);
  AOverlap := EnsureRange(AOverlap, 0, AChunkSize div 2);
  AStart := Max(Int64(0), AStart);
  LEnd := Min(ASource.Size, AStart + Max(Int64(0), ALimit));
  if AStart >= LEnd then
    Exit;
  SetLength(LBuffer, AChunkSize);
  LPos := AStart;
  while LPos < LEnd do
  begin
    MHCheckCancel(ACancel);
    LWant := Integer(Min(Int64(AChunkSize), LEnd - LPos));
    LRead := ASource.ReadAt(LPos, LBuffer[0], LWant);
    if LRead <= 0 then
      Break;
    if not AProc(LPos, LBuffer, LRead) then
      Break;
    if LPos + LRead >= LEnd then
      Break;
    // Следующий блок перекрывает конец текущего на AOverlap байт.
    LPos := LPos + Max(1, LRead - AOverlap);
  end;
end;

end.
