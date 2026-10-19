unit MineHunter.BinaryLab.Pe;

{
  PE Analyzer: разбор исполняемых файлов Windows (PE32 и PE32+) по байтам,
  без загрузки файла загрузчиком Windows.

  Разбираются: заголовки MS-DOS/PE/дополнительный, таблица секций, каталоги
  данных, импорт (обычный и отложенный, по именам и порядковым номерам),
  экспорт (с переадресацией), дерево ресурсов (тип → имя → язык), функции
  обратного вызова TLS, каталог CLR (.NET), каталог безопасности (подпись),
  оверлей, контрольная сумма.

  Защита от повреждённых и намеренно искажённых файлов:
  - каждое поле читается через TMHBinaryReader с проверкой границ;
  - счётчики из файла ограничиваются лимитами TMHBinaryLabOptions и
    спецификацией (не больше 96 секций, 16 каталогов);
  - обход ресурсов — не глубже 3 уровней, с учётом посещённых каталогов
    (циклические ссылки не зацикливают разбор);
  - всё, что не удалось разобрать, попадает в Warnings, разбор продолжается.

  Энтропия и хеши секций заполняются отдельно (MHFillSectionMetrics), чтобы
  разбор заголовков оставался быстрым.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

/// Разбор PE из AReader (с начала файла). Не PE — Result.Valid = False и
/// причина в Warnings.
function MHParsePe(AReader: TMHBinaryReader; const AOptions: TMHBinaryLabOptions;
  const ACancel: TMHCancelCheck = nil): TMHPeInfo;

/// Смещение в файле по RVA (MH_NO_OFFSET — адрес не отображается на данные файла).
function MHPeRvaToOffset(const APe: TMHPeInfo; ARva: Cardinal): Int64;

/// Контрольная сумма PE по алгоритму CheckSumMappedFile (поле CheckSum
/// пропускается). AChecksumOffset — смещение поля CheckSum.
function MHComputePeChecksum(const ASource: IMHBinarySource; AChecksumOffset: Int64;
  const ACancel: TMHCancelCheck = nil): Cardinal;

/// SHA-256 диапазона файла ('' — диапазон пуст или вне файла).
function MHRangeSha256(const ASource: IMHBinarySource; AOffset, ASize: Int64;
  const ACancel: TMHCancelCheck = nil): string;

/// Имя подсистемы Windows.
function MHSubsystemName(ASubsystem: Word): string;
/// Имя стандартного типа ресурса («ICON», «VERSION»…); '' — нестандартный.
function MHResourceTypeName(ATypeId: Cardinal): string;
/// Описание местоположения смещения в PE: «заголовки», «секция .text»,
/// «оверлей», «подпись» ('' — неизвестно или файл не PE).
function MHPeLocate(const APe: TMHPeInfo; AFileSize, AOffset: Int64): string;

const
  /// Индексы каталогов данных.
  PE_DIR_EXPORT = 0;
  PE_DIR_IMPORT = 1;
  PE_DIR_RESOURCE = 2;
  PE_DIR_SECURITY = 4;
  PE_DIR_TLS = 9;
  PE_DIR_DELAY_IMPORT = 13;
  PE_DIR_CLR = 14;
  /// Предел секций по спецификации PE.
  PE_MAX_SECTIONS = 96;

implementation

uses
  System.Math, System.Hash, System.Generics.Collections,
  MineHunter.Core.Lang, MineHunter.BinaryLab.FileType;

const
  DIR_NAMES: array[0..15] of string = ('Export', 'Import', 'Resource', 'Exception', 'Security',
    'BaseReloc', 'Debug', 'Architecture', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT',
    'DelayImport', 'CLR', 'Reserved');
  MAX_IMPORT_DESCRIPTORS = 4096;
  MAX_NAME_LENGTH = 512;
  MAX_TLS_CALLBACKS = 256;
  MAX_RESOURCE_ENTRIES_PER_DIR = 4096;

type
  TPeParser = class
  private
    FReader: TMHBinaryReader;
    FOptions: TMHBinaryLabOptions;
    FCancel: TMHCancelCheck;
    FPe: TMHPeInfo;
    FOptionalOffset: Int64;
    FOptionalSize: Word;
    FWarnings: TList<string>;
    procedure Warn(const AText: string);
    function Dir(AIndex: Integer; out ARva, ASize: Cardinal): Boolean;
    function RvaOffset(ARva: Cardinal): Int64;
    function ReadAnsiAtRva(ARva: Cardinal): string;
    function HeadersOk: Boolean;
    procedure ParseOptional;
    procedure ParseSections;
    procedure ParseImports;
    procedure ParseDelayImports;
    procedure ParseExports;
    procedure ParseResources;
    procedure ParseTls;
    procedure ParseSecurity;
    procedure ComputeOverlay;
    procedure ComputeEntryPoint;
  public
    constructor Create(AReader: TMHBinaryReader; const AOptions: TMHBinaryLabOptions;
      const ACancel: TMHCancelCheck);
    destructor Destroy; override;
    function Parse: TMHPeInfo;
  end;

{ Функции }

function MHSubsystemName(ASubsystem: Word): string;
begin
  case ASubsystem of
    1:  Result := MHL('Native (драйвер или системный компонент)', 'Native (driver or system component)');
    2:  Result := MHL('Windows, графический интерфейс', 'Windows GUI');
    3:  Result := MHL('Windows, консоль', 'Windows console');
    5:  Result := 'OS/2';
    7:  Result := 'POSIX';
    9:  Result := 'Windows CE';
    10: Result := MHL('Приложение EFI', 'EFI application');
    11: Result := MHL('Драйвер загрузки EFI', 'EFI boot service driver');
    12: Result := MHL('Драйвер EFI времени выполнения', 'EFI runtime driver');
    13: Result := 'EFI ROM';
    14: Result := 'Xbox';
    16: Result := MHL('Приложение загрузки Windows', 'Windows boot application');
  else
    Result := Format(MHL('неизвестная (%d)', 'unknown (%d)'), [ASubsystem]);
  end;
end;

function MHResourceTypeName(ATypeId: Cardinal): string;
begin
  case ATypeId of
    1:  Result := 'CURSOR';
    2:  Result := 'BITMAP';
    3:  Result := 'ICON';
    4:  Result := 'MENU';
    5:  Result := 'DIALOG';
    6:  Result := 'STRING';
    7:  Result := 'FONTDIR';
    8:  Result := 'FONT';
    9:  Result := 'ACCELERATOR';
    10: Result := 'RCDATA';
    11: Result := 'MESSAGETABLE';
    12: Result := 'GROUP_CURSOR';
    14: Result := 'GROUP_ICON';
    16: Result := 'VERSION';
    17: Result := 'DLGINCLUDE';
    19: Result := 'PLUGPLAY';
    20: Result := 'VXD';
    21: Result := 'ANICURSOR';
    22: Result := 'ANIICON';
    23: Result := 'HTML';
    24: Result := 'MANIFEST';
  else
    Result := '';
  end;
end;

function MHPeRvaToOffset(const APe: TMHPeInfo; ARva: Cardinal): Int64;
var
  LSection: TMHPeSection;
  LRawStart: Cardinal;
  LDelta: Cardinal;
begin
  Result := MH_NO_OFFSET;
  if not APe.Valid then
    Exit;
  // Заголовки отображаются как есть.
  if ARva < APe.SizeOfHeaders then
    Exit(ARva);
  for LSection in APe.Sections do
  begin
    if (ARva < LSection.VirtualAddress) or
       (UInt64(ARva) >= UInt64(LSection.VirtualAddress) + Max(LSection.VirtualSize, LSection.RawSize)) then
      Continue;
    LDelta := ARva - LSection.VirtualAddress;
    // Данные за пределами SizeOfRawData — нули в памяти, в файле их нет.
    if LDelta >= LSection.RawSize then
      Exit(MH_NO_OFFSET);
    // Загрузчик округляет PointerToRawData вниз до 512 байт.
    LRawStart := LSection.RawOffset;
    if APe.FileAlignment >= 512 then
      LRawStart := LRawStart and not Cardinal(511);
    Exit(Int64(LRawStart) + LDelta);
  end;
end;

function MHPeLocate(const APe: TMHPeInfo; AFileSize, AOffset: Int64): string;
var
  LSection: TMHPeSection;
begin
  Result := '';
  if not APe.Valid or (AOffset < 0) then
    Exit;
  if (APe.CertificateSize > 0) and (APe.CertificateOffset >= 0) and (AOffset >= APe.CertificateOffset) and
     (AOffset < APe.CertificateOffset + APe.CertificateSize) then
    Exit(MHL('подпись', 'signature'));
  if (APe.OverlaySize > 0) and (AOffset >= APe.OverlayOffset) and (AOffset < APe.OverlayOffset + APe.OverlaySize) then
    Exit(MHL('оверлей', 'overlay'));
  for LSection in APe.Sections do
    if (LSection.RawSize > 0) and (AOffset >= LSection.RawOffset) and
       (AOffset < Int64(LSection.RawOffset) + LSection.RawSize) then
      Exit(MHL('секция ', 'section ') + LSection.Name);
  if AOffset < APe.SizeOfHeaders then
    Exit(MHL('заголовки', 'headers'));
end;

function MHComputePeChecksum(const ASource: IMHBinarySource; AChecksumOffset: Int64;
  const ACancel: TMHCancelCheck): Cardinal;
var
  LSum: UInt64;
  LOdd: Boolean;
  LCarry: Byte;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  LSum := 0;
  LOdd := False;
  LCarry := 0;
  // Сумма 16-битных слов с переносом; слова поля CheckSum пропускаются.
  MHReadChunks(ASource, 0, ASource.Size, 1024 * 1024, 0,
    function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
    var
      I: Integer;
      LPos: Int64;
      LWord: Cardinal;
    begin
      I := 0;
      if LOdd and (ACount > 0) then
      begin
        LPos := ABase - 1;
        if (LPos <> AChecksumOffset) and (LPos <> AChecksumOffset + 2) then
        begin
          LSum := LSum + LCarry + Cardinal(AData[0]) shl 8;
          LSum := (LSum and $FFFF) + (LSum shr 16);
        end;
        LOdd := False;
        I := 1;
      end;
      while I < ACount do
      begin
        LPos := ABase + I;
        if I + 1 >= ACount then
        begin
          // Половина слова на границе блока — дочитается в следующем.
          LCarry := AData[I];
          LOdd := True;
          Break;
        end;
        if (LPos <> AChecksumOffset) and (LPos <> AChecksumOffset + 2) then
        begin
          LWord := AData[I] or (Cardinal(AData[I + 1]) shl 8);
          LSum := LSum + LWord;
          LSum := (LSum and $FFFF) + (LSum shr 16);
        end;
        Inc(I, 2);
      end;
      Result := True;
    end, ACancel);
  if LOdd and (ASource.Size - 1 <> AChecksumOffset) and (ASource.Size - 1 <> AChecksumOffset + 2) then
  begin
    LSum := LSum + LCarry;
    LSum := (LSum and $FFFF) + (LSum shr 16);
  end;
  LSum := (LSum and $FFFF) + (LSum shr 16);
  Result := Cardinal(LSum and $FFFF) + Cardinal(ASource.Size);
end;

function MHRangeSha256(const ASource: IMHBinarySource; AOffset, ASize: Int64;
  const ACancel: TMHCancelCheck): string;
var
  LHash: THashSHA2;
  LEnd: Int64;
var
  LHoldSource: IMHBinarySource;
begin
  // Ссылка на источник на время работы: объект, созданный прямо в аргументе,
  // иначе не освобождается (const-параметр интерфейса не увеличивает счётчик).
  LHoldSource := ASource;
  Result := '';
  if (ASource = nil) or (AOffset < 0) or (AOffset >= ASource.Size) or (ASize <= 0) then
    Exit;
  LEnd := Min(ASource.Size, AOffset + ASize);
  LHash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  MHReadChunks(ASource, AOffset, LEnd - AOffset, 1024 * 1024, 0,
    function(ABase: Int64; const AData: TBytes; ACount: Integer): Boolean
    begin
      LHash.Update(AData, ACount);
      Result := True;
    end, ACancel);
  Result := LHash.HashAsString.ToLower;
end;

function MHParsePe(AReader: TMHBinaryReader; const AOptions: TMHBinaryLabOptions;
  const ACancel: TMHCancelCheck): TMHPeInfo;
var
  LParser: TPeParser;
begin
  LParser := TPeParser.Create(AReader, AOptions.Normalized, ACancel);
  try
    Result := LParser.Parse;
  finally
    LParser.Free;
  end;
end;

{ TPeParser }

constructor TPeParser.Create(AReader: TMHBinaryReader; const AOptions: TMHBinaryLabOptions;
  const ACancel: TMHCancelCheck);
begin
  inherited Create;
  FReader := AReader;
  FOptions := AOptions;
  FCancel := ACancel;
  FWarnings := TList<string>.Create;
end;

destructor TPeParser.Destroy;
begin
  FWarnings.Free;
  inherited;
end;

procedure TPeParser.Warn(const AText: string);
begin
  if not FWarnings.Contains(AText) then
    FWarnings.Add(AText);
end;

function TPeParser.Dir(AIndex: Integer; out ARva, ASize: Cardinal): Boolean;
begin
  ARva := 0;
  ASize := 0;
  if AIndex > High(FPe.DataDirectories) then
    Exit(False);
  ARva := FPe.DataDirectories[AIndex].Rva;
  ASize := FPe.DataDirectories[AIndex].Size;
  Result := (ARva <> 0) and (ASize <> 0);
end;

function TPeParser.RvaOffset(ARva: Cardinal): Int64;
begin
  Result := MHPeRvaToOffset(FPe, ARva);
  if (Result <> MH_NO_OFFSET) and (Result >= FReader.Size) then
    Result := MH_NO_OFFSET;
end;

function TPeParser.ReadAnsiAtRva(ARva: Cardinal): string;
var
  LOffset: Int64;
begin
  LOffset := RvaOffset(ARva);
  if LOffset = MH_NO_OFFSET then
    Exit('');
  Result := FReader.ReadAnsiZ(LOffset, MAX_NAME_LENGTH);
end;

function TPeParser.HeadersOk: Boolean;
var
  LLfanew, LSignature: Cardinal;
  LPe: Int64;
begin
  Result := False;
  if not FReader.MatchesAt(0, [$4D, $5A]) then
  begin
    Warn(MHL('Нет заголовка MZ — это не исполняемый файл Windows', 'No MZ header — not a Windows executable'));
    Exit;
  end;
  if not FReader.TryReadDWord($3C, LLfanew) then
  begin
    Warn(MHL('Файл обрезан: нет поля e_lfanew', 'Truncated file: no e_lfanew field'));
    Exit;
  end;
  if (LLfanew < $40) or (LLfanew > MH_MAX_LFANEW) or (Int64(LLfanew) + 24 > FReader.Size) then
  begin
    Warn(Format(MHL('Смещение заголовка PE (e_lfanew = 0x%x) вне файла или недопустимо',
      'PE header offset (e_lfanew = 0x%x) is outside the file or invalid'), [LLfanew]));
    Exit;
  end;
  LPe := LLfanew;
  if not FReader.TryReadDWord(LPe, LSignature) or (LSignature <> $00004550) then
  begin
    Warn(MHL('Нет сигнатуры PE — программа MS-DOS или повреждённый файл',
      'No PE signature — MS-DOS program or damaged file'));
    Exit;
  end;
  FPe.HeaderOffset := LLfanew;
  FReader.TryReadWord(LPe + 4, FPe.Machine);
  FReader.TryReadWord(LPe + 6, FPe.NumberOfSections);
  FReader.TryReadDWord(LPe + 8, FPe.TimeDateStamp);
  FReader.TryReadWord(LPe + 20, FOptionalSize);
  FReader.TryReadWord(LPe + 22, FPe.Characteristics);
  FPe.MachineName := MHMachineName(FPe.Machine);
  FOptionalOffset := LPe + 24;
  if not FReader.TryReadWord(FOptionalOffset, FPe.Magic) or ((FPe.Magic <> $10B) and (FPe.Magic <> $20B)) then
  begin
    Warn(Format(MHL('Неизвестный формат дополнительного заголовка (Magic = 0x%x)',
      'Unknown optional header format (Magic = 0x%x)'), [FPe.Magic]));
    Exit;
  end;
  FPe.Is64 := FPe.Magic = $20B;
  Result := True;
end;

procedure TPeParser.ParseOptional;
var
  LMajor, LMinor: Byte;
  LWordMajor, LWordMinor: Word;
  LBase32: Cardinal;
  LDirBase, LDirCount, I: Integer;
  LMinSize: Integer;
begin
  if FPe.Is64 then
    LMinSize := 112
  else
    LMinSize := 96;
  if FOptionalSize < LMinSize then
    Warn(Format(MHL('Дополнительный заголовок короче стандартного (%d байт)',
      'The optional header is shorter than standard (%d bytes)'), [FOptionalSize]));
  if FReader.TryReadByte(FOptionalOffset + 2, LMajor) and FReader.TryReadByte(FOptionalOffset + 3, LMinor) then
    FPe.LinkerVersion := Format('%d.%d', [LMajor, LMinor]);
  FReader.TryReadDWord(FOptionalOffset + 16, FPe.EntryPointRva);
  if FPe.Is64 then
    FReader.TryReadQWord(FOptionalOffset + 24, FPe.ImageBase)
  else if FReader.TryReadDWord(FOptionalOffset + 28, LBase32) then
    FPe.ImageBase := LBase32;
  FReader.TryReadDWord(FOptionalOffset + 32, FPe.SectionAlignment);
  FReader.TryReadDWord(FOptionalOffset + 36, FPe.FileAlignment);
  if FReader.TryReadWord(FOptionalOffset + 40, LWordMajor) and FReader.TryReadWord(FOptionalOffset + 42, LWordMinor) then
    FPe.OsVersion := Format('%d.%d', [LWordMajor, LWordMinor]);
  FReader.TryReadDWord(FOptionalOffset + 56, FPe.SizeOfImage);
  FReader.TryReadDWord(FOptionalOffset + 60, FPe.SizeOfHeaders);
  FReader.TryReadDWord(FOptionalOffset + 64, FPe.CheckSum);
  FReader.TryReadWord(FOptionalOffset + 68, FPe.Subsystem);
  FReader.TryReadWord(FOptionalOffset + 70, FPe.DllCharacteristics);
  FPe.SubsystemName := MHSubsystemName(FPe.Subsystem);
  if FPe.Is64 then
    LDirBase := 112
  else
    LDirBase := 96;
  FReader.TryReadDWord(FOptionalOffset + LDirBase - 4, FPe.NumberOfRvaAndSizes);
  // Каталогов не больше 16 и не больше, чем помещается в заявленный размер заголовка.
  LDirCount := Min(Int64(FPe.NumberOfRvaAndSizes), 16);
  LDirCount := Max(0, Min(LDirCount, (Integer(FOptionalSize) - LDirBase) div 8));
  if FPe.NumberOfRvaAndSizes > 16 then
    Warn(Format(MHL('Заявлено %d каталогов данных (по спецификации не больше 16)',
      'Declares %d data directories (the specification allows at most 16)'), [FPe.NumberOfRvaAndSizes]));
  SetLength(FPe.DataDirectories, LDirCount);
  for I := 0 to LDirCount - 1 do
  begin
    FPe.DataDirectories[I].Name := DIR_NAMES[I];
    FReader.TryReadDWord(FOptionalOffset + LDirBase + I * 8, FPe.DataDirectories[I].Rva);
    FReader.TryReadDWord(FOptionalOffset + LDirBase + I * 8 + 4, FPe.DataDirectories[I].Size);
  end;
  if FPe.Subsystem = IMAGE_SUBSYSTEM_NATIVE then
    FPe.Kind := pkDriver
  else if FPe.Characteristics and IMAGE_FILE_DLL <> 0 then
    FPe.Kind := pkDll
  else
    FPe.Kind := pkExe;
end;

procedure TPeParser.ParseSections;
var
  LTable: Int64;
  LCount, I, J: Integer;
  LName: TBytes;
  LSection: TMHPeSection;
  LBuilder: TStringBuilder;
begin
  LTable := FOptionalOffset + FOptionalSize;
  LCount := FPe.NumberOfSections;
  if LCount = 0 then
    Warn(MHL('В файле нет ни одной секции', 'The file has no sections'));
  if LCount > PE_MAX_SECTIONS then
  begin
    Warn(Format(MHL('Заявлено %d секций (по спецификации не больше 96) — разобраны первые 96',
      'Declares %d sections (the specification allows at most 96) — the first 96 were parsed'), [LCount]));
    LCount := PE_MAX_SECTIONS;
  end;
  SetLength(FPe.Sections, 0);
  LBuilder := TStringBuilder.Create;
  try
    for I := 0 to LCount - 1 do
    begin
      if not FReader.InRange(LTable + I * 40, 40) then
      begin
        Warn(Format(MHL('Таблица секций обрезана: прочитано %d из %d', 'The section table is truncated: %d of %d read'),
          [I, FPe.NumberOfSections]));
        Break;
      end;
      LSection := Default(TMHPeSection);
      LSection.Index := I;
      LName := FReader.ReadBytes(LTable + I * 40, 8);
      LBuilder.Clear;
      for J := 0 to High(LName) do
      begin
        if LName[J] = 0 then
          Break;
        if (LName[J] >= $20) and (LName[J] < $7F) then
          LBuilder.Append(Char(LName[J]))
        else
          LBuilder.Append('?');
      end;
      LSection.Name := LBuilder.ToString;
      FReader.TryReadDWord(LTable + I * 40 + 8, LSection.VirtualSize);
      FReader.TryReadDWord(LTable + I * 40 + 12, LSection.VirtualAddress);
      FReader.TryReadDWord(LTable + I * 40 + 16, LSection.RawSize);
      FReader.TryReadDWord(LTable + I * 40 + 20, LSection.RawOffset);
      FReader.TryReadDWord(LTable + I * 40 + 36, LSection.Characteristics);
      LSection.Entropy := -1;
      if (LSection.RawSize > 0) and (Int64(LSection.RawOffset) + LSection.RawSize > FReader.Size) then
        Warn(Format(MHL('Секция %s выходит за конец файла', 'Section %s extends beyond the end of the file'),
          [LSection.Name]));
      FPe.Sections := FPe.Sections + [LSection];
    end;
  finally
    LBuilder.Free;
  end;
end;

procedure TPeParser.ParseImports;
var
  LRva, LSize, LNameRva, LLookup, LFirst, LThunk32, LHintRva: Cardinal;
  LThunk64: UInt64;
  LDesc, LThunkOffset: Int64;
  LImport: TMHPeImport;
  LCount, LFunctions, LThunkSize: Integer;
  LOrdinal: Boolean;
  LValue: UInt64;
  LList: TList<string>;
begin
  if not Dir(PE_DIR_IMPORT, LRva, LSize) then
    Exit;
  LDesc := RvaOffset(LRva);
  if LDesc = MH_NO_OFFSET then
  begin
    Warn(MHL('Каталог импорта указывает за пределы данных файла', 'The import directory points outside the file data'));
    Exit;
  end;
  if FPe.Is64 then
    LThunkSize := 8
  else
    LThunkSize := 4;
  LFunctions := FPe.ImportedFunctionCount;
  LList := TList<string>.Create;
  try
    for LCount := 0 to MAX_IMPORT_DESCRIPTORS - 1 do
    begin
      MHCheckCancel(FCancel);
      if not FReader.TryReadDWord(LDesc + LCount * 20, LLookup) or
         not FReader.TryReadDWord(LDesc + LCount * 20 + 12, LNameRva) or
         not FReader.TryReadDWord(LDesc + LCount * 20 + 16, LFirst) then
      begin
        Warn(MHL('Таблица импорта обрезана', 'The import table is truncated'));
        Break;
      end;
      if (LLookup = 0) and (LNameRva = 0) and (LFirst = 0) then
        Break;
      LImport := Default(TMHPeImport);
      LImport.Dll := ReadAnsiAtRva(LNameRva);
      if LImport.Dll = '' then
        Warn(MHL('Имя библиотеки импорта не читается', 'An import library name cannot be read'));
      if LLookup = 0 then
        LLookup := LFirst;
      LThunkOffset := RvaOffset(LLookup);
      LList.Clear;
      if LThunkOffset <> MH_NO_OFFSET then
        while True do
        begin
          if LFunctions >= FOptions.MaxImportedFunctions then
          begin
            Warn(MHL('Импортированных функций больше лимита — список обрезан',
              'More imported functions than the limit — the list is truncated'));
            Break;
          end;
          if FPe.Is64 then
          begin
            if not FReader.TryReadQWord(LThunkOffset, LThunk64) then
              Break;
            LValue := LThunk64;
            LOrdinal := LThunk64 and UInt64($8000000000000000) <> 0;
          end
          else
          begin
            if not FReader.TryReadDWord(LThunkOffset, LThunk32) then
              Break;
            LValue := LThunk32;
            LOrdinal := LThunk32 and $80000000 <> 0;
          end;
          if LValue = 0 then
            Break;
          if LOrdinal then
            LList.Add('#' + IntToStr(LValue and $FFFF))
          else
          begin
            LHintRva := Cardinal(LValue and $7FFFFFFF);
            if RvaOffset(LHintRva) = MH_NO_OFFSET then
              LList.Add('?')
            else
              LList.Add(FReader.ReadAnsiZ(RvaOffset(LHintRva) + 2, MAX_NAME_LENGTH));
          end;
          Inc(LFunctions);
          Inc(LThunkOffset, LThunkSize);
        end
      else
        Warn(Format(MHL('Таблица функций импорта %s вне данных файла', 'The import function table of %s is outside the file data'),
          [LImport.Dll]));
      LImport.Functions := LList.ToArray;
      FPe.Imports := FPe.Imports + [LImport];
    end;
  finally
    LList.Free;
  end;
  FPe.ImportedFunctionCount := LFunctions;
end;

procedure TPeParser.ParseDelayImports;
var
  LRva, LSize, LAttributes, LNameRva, LIntRva, LThunk32: Cardinal;
  LThunk64, LValue: UInt64;
  LDesc, LThunkOffset: Int64;
  LImport: TMHPeImport;
  LCount, LFunctions, LThunkSize: Integer;
  LList: TList<string>;
  LOrdinal, LVaBased: Boolean;

  function ToRva(AValue: UInt64): Cardinal;
  begin
    // Старый формат (Attributes = 0) хранит виртуальные адреса, а не RVA.
    if LVaBased and (AValue >= FPe.ImageBase) then
      Result := Cardinal(AValue - FPe.ImageBase)
    else
      Result := Cardinal(AValue);
  end;

begin
  if not Dir(PE_DIR_DELAY_IMPORT, LRva, LSize) then
    Exit;
  LDesc := RvaOffset(LRva);
  if LDesc = MH_NO_OFFSET then
  begin
    Warn(MHL('Каталог отложенного импорта вне данных файла', 'The delay import directory is outside the file data'));
    Exit;
  end;
  if FPe.Is64 then
    LThunkSize := 8
  else
    LThunkSize := 4;
  LFunctions := FPe.ImportedFunctionCount;
  LList := TList<string>.Create;
  try
    for LCount := 0 to MAX_IMPORT_DESCRIPTORS - 1 do
    begin
      MHCheckCancel(FCancel);
      if not FReader.TryReadDWord(LDesc + LCount * 32, LAttributes) or
         not FReader.TryReadDWord(LDesc + LCount * 32 + 4, LNameRva) or
         not FReader.TryReadDWord(LDesc + LCount * 32 + 16, LIntRva) then
        Break;
      if (LNameRva = 0) and (LIntRva = 0) then
        Break;
      LVaBased := LAttributes and 1 = 0;
      LImport := Default(TMHPeImport);
      LImport.Delayed := True;
      LImport.Dll := ReadAnsiAtRva(ToRva(LNameRva));
      LList.Clear;
      LThunkOffset := RvaOffset(ToRva(LIntRva));
      if LThunkOffset <> MH_NO_OFFSET then
        while LFunctions < FOptions.MaxImportedFunctions do
        begin
          if FPe.Is64 then
          begin
            if not FReader.TryReadQWord(LThunkOffset, LThunk64) then
              Break;
            LValue := LThunk64;
            LOrdinal := LThunk64 and UInt64($8000000000000000) <> 0;
          end
          else
          begin
            if not FReader.TryReadDWord(LThunkOffset, LThunk32) then
              Break;
            LValue := LThunk32;
            LOrdinal := LThunk32 and $80000000 <> 0;
          end;
          if LValue = 0 then
            Break;
          if LOrdinal then
            LList.Add('#' + IntToStr(LValue and $FFFF))
          else if RvaOffset(ToRva(LValue)) = MH_NO_OFFSET then
            LList.Add('?')
          else
            LList.Add(FReader.ReadAnsiZ(RvaOffset(ToRva(LValue)) + 2, MAX_NAME_LENGTH));
          Inc(LFunctions);
          Inc(LThunkOffset, LThunkSize);
        end;
      LImport.Functions := LList.ToArray;
      FPe.Imports := FPe.Imports + [LImport];
    end;
  finally
    LList.Free;
  end;
  FPe.ImportedFunctionCount := LFunctions;
end;

procedure TPeParser.ParseExports;
var
  LRva, LSize, LNameRva, LBase, LFunctionCount, LNameCount, LFunctions, LNames, LOrdinals: Cardinal;
  LFuncRva, LNamePtr: Cardinal;
  LDir: Int64;
  LNameByIndex: TDictionary<Cardinal, string>;
  LOrdinalIndex: Word;
  I: Cardinal;
  LExport: TMHPeExport;
  LList: TList<TMHPeExport>;
  LName: string;
begin
  if not Dir(PE_DIR_EXPORT, LRva, LSize) then
    Exit;
  LDir := RvaOffset(LRva);
  if (LDir = MH_NO_OFFSET) or not FReader.InRange(LDir, 40) then
  begin
    Warn(MHL('Каталог экспорта вне данных файла', 'The export directory is outside the file data'));
    Exit;
  end;
  FReader.TryReadDWord(LDir + 12, LNameRva);
  FReader.TryReadDWord(LDir + 16, LBase);
  FReader.TryReadDWord(LDir + 20, LFunctionCount);
  FReader.TryReadDWord(LDir + 24, LNameCount);
  FReader.TryReadDWord(LDir + 28, LFunctions);
  FReader.TryReadDWord(LDir + 32, LNames);
  FReader.TryReadDWord(LDir + 36, LOrdinals);
  FPe.ExportName := ReadAnsiAtRva(LNameRva);
  if (LFunctionCount > Cardinal(FOptions.MaxExports)) or (LNameCount > Cardinal(FOptions.MaxExports)) then
    Warn(Format(MHL('Экспортов заявлено %d — разобраны первые %d', 'Declares %d exports — the first %d were parsed'),
      [Max(LFunctionCount, LNameCount), FOptions.MaxExports]));
  LFunctionCount := Min(LFunctionCount, Cardinal(FOptions.MaxExports));
  LNameCount := Min(LNameCount, Cardinal(FOptions.MaxExports));
  LNameByIndex := TDictionary<Cardinal, string>.Create;
  LList := TList<TMHPeExport>.Create;
  try
    if LNameCount > 0 then
      for I := 0 to LNameCount - 1 do
      begin
        if I mod 1024 = 0 then
          MHCheckCancel(FCancel);
        if (RvaOffset(LNames) = MH_NO_OFFSET) or (RvaOffset(LOrdinals) = MH_NO_OFFSET) or
           not FReader.TryReadDWord(RvaOffset(LNames) + Int64(I) * 4, LNamePtr) or
           not FReader.TryReadWord(RvaOffset(LOrdinals) + Int64(I) * 2, LOrdinalIndex) then
        begin
          Warn(MHL('Таблица имён экспорта обрезана', 'The export name table is truncated'));
          Break;
        end;
        LName := ReadAnsiAtRva(LNamePtr);
        if not LNameByIndex.ContainsKey(LOrdinalIndex) then
          LNameByIndex.Add(LOrdinalIndex, LName);
      end;
    if LFunctionCount > 0 then
      for I := 0 to LFunctionCount - 1 do
      begin
        if I mod 1024 = 0 then
          MHCheckCancel(FCancel);
        if (RvaOffset(LFunctions) = MH_NO_OFFSET) or
           not FReader.TryReadDWord(RvaOffset(LFunctions) + Int64(I) * 4, LFuncRva) then
        begin
          Warn(MHL('Таблица адресов экспорта обрезана', 'The export address table is truncated'));
          Break;
        end;
        if LFuncRva = 0 then
          Continue;
        LExport := Default(TMHPeExport);
        LExport.Ordinal := LBase + I;
        LExport.Rva := LFuncRva;
        LNameByIndex.TryGetValue(I, LExport.Name);
        // Адрес внутри каталога экспорта — строка переадресации «DLL.Функция».
        if (LFuncRva >= LRva) and (UInt64(LFuncRva) < UInt64(LRva) + LSize) then
          LExport.Forwarder := ReadAnsiAtRva(LFuncRva);
        LList.Add(LExport);
      end;
    FPe.ExportedFunctions := LList.ToArray;
  finally
    LList.Free;
    LNameByIndex.Free;
  end;
end;

procedure TPeParser.ParseResources;
var
  LRva, LSize: Cardinal;
  LBase: Int64;
  LVisited: TDictionary<Int64, Boolean>;
  LList: TList<TMHPeResource>;
  LLimitWarned: Boolean;

  function EntryName(AValue: Cardinal; ALevel: Integer): string;
  var
    LLength: Word;
    LOffset: Int64;
  begin
    if AValue and $80000000 <> 0 then
    begin
      // Имя-строка: длина (WORD) и символы UTF-16 относительно начала ресурсов.
      LOffset := LBase + (AValue and $7FFFFFFF);
      if FReader.TryReadWord(LOffset, LLength) then
        Exit(FReader.ReadUtf16(LOffset + 2, Min(LLength, 256)));
      Exit('?');
    end;
    if ALevel = 0 then
    begin
      Result := MHResourceTypeName(AValue);
      if Result = '' then
        Result := '#' + IntToStr(AValue);
    end
    else
      Result := IntToStr(AValue);
  end;

  procedure Walk(ADirOffset: Int64; ALevel: Integer; const AType, AName: string);
  var
    LNamed, LIds: Word;
    LCount, I: Integer;
    LEntryName, LEntryOffset, LDataRva, LDataSize: Cardinal;
    LEntry: Int64;
    LResource: TMHPeResource;
    LLabel: string;
  begin
    if (ALevel > 2) or LVisited.ContainsKey(ADirOffset) then
    begin
      Warn(MHL('Дерево ресурсов содержит циклические или слишком глубокие ссылки',
        'The resource tree contains circular or too deep references'));
      Exit;
    end;
    LVisited.Add(ADirOffset, True);
    if not FReader.TryReadWord(ADirOffset + 12, LNamed) or not FReader.TryReadWord(ADirOffset + 14, LIds) then
    begin
      Warn(MHL('Каталог ресурсов обрезан', 'A resource directory is truncated'));
      Exit;
    end;
    LCount := Min(Integer(LNamed) + LIds, MAX_RESOURCE_ENTRIES_PER_DIR);
    for I := 0 to LCount - 1 do
    begin
      if LList.Count >= FOptions.MaxResources then
      begin
        if not LLimitWarned then
          Warn(MHL('Ресурсов больше лимита — список обрезан', 'More resources than the limit — the list is truncated'));
        LLimitWarned := True;
        Exit;
      end;
      LEntry := ADirOffset + 16 + I * 8;
      if not FReader.TryReadDWord(LEntry, LEntryName) or not FReader.TryReadDWord(LEntry + 4, LEntryOffset) then
      begin
        Warn(MHL('Каталог ресурсов обрезан', 'A resource directory is truncated'));
        Exit;
      end;
      LLabel := EntryName(LEntryName, ALevel);
      if LEntryOffset and $80000000 <> 0 then
      begin
        case ALevel of
          0: Walk(LBase + (LEntryOffset and $7FFFFFFF), 1, LLabel, '');
          1: Walk(LBase + (LEntryOffset and $7FFFFFFF), 2, AType, LLabel);
        else
          Warn(MHL('Дерево ресурсов глубже трёх уровней', 'The resource tree is deeper than three levels'));
        end;
        Continue;
      end;
      // Описание данных: RVA, размер.
      if not FReader.TryReadDWord(LBase + LEntryOffset, LDataRva) or
         not FReader.TryReadDWord(LBase + LEntryOffset + 4, LDataSize) then
      begin
        Warn(MHL('Описание данных ресурса вне файла', 'A resource data entry is outside the file'));
        Continue;
      end;
      LResource := Default(TMHPeResource);
      case ALevel of
        0:
          begin
            LResource.TypeName := LLabel;
            LResource.Name := '';
          end;
        1:
          begin
            LResource.TypeName := AType;
            LResource.Name := LLabel;
          end;
      else
        LResource.TypeName := AType;
        LResource.Name := AName;
        LResource.Language := LEntryName and $FFFF;
      end;
      LResource.Size := LDataSize;
      LResource.Offset := RvaOffset(LDataRva);
      LResource.Entropy := -1;
      if (LResource.Offset <> MH_NO_OFFSET) and not FReader.InRange(LResource.Offset, LDataSize) then
        Warn(Format(MHL('Ресурс %s/%s выходит за конец файла', 'Resource %s/%s extends beyond the end of the file'),
          [LResource.TypeName, LResource.Name]));
      LList.Add(LResource);
    end;
  end;

var
  LResource: TMHPeResource;
  LKind: TMHBinaryKind;
  LDescription: string;
  LObjectSize: Int64;
  I: Integer;
begin
  if not Dir(PE_DIR_RESOURCE, LRva, LSize) then
    Exit;
  LBase := RvaOffset(LRva);
  if LBase = MH_NO_OFFSET then
  begin
    Warn(MHL('Каталог ресурсов вне данных файла', 'The resource directory is outside the file data'));
    Exit;
  end;
  LLimitWarned := False;
  LVisited := TDictionary<Int64, Boolean>.Create;
  LList := TList<TMHPeResource>.Create;
  try
    Walk(LBase, 0, '', '');
    // Вид содержимого ресурса: программа, архив, документ внутри ресурса.
    for I := 0 to LList.Count - 1 do
    begin
      LResource := LList[I];
      LResource.ContentKind := bkUnknown;
      if (LResource.Offset <> MH_NO_OFFSET) and (LResource.Size >= 4) and
         MHIdentifyAt(FReader, LResource.Offset, True, LKind, LDescription, LObjectSize) then
        LResource.ContentKind := LKind;
      LList[I] := LResource;
    end;
    FPe.Resources := LList.ToArray;
  finally
    LList.Free;
    LVisited.Free;
  end;
end;

procedure TPeParser.ParseTls;
var
  LRva, LSize, LCallbacks32, LValue32: Cardinal;
  LCallbacks64, LValue64, LCallbacksVa: UInt64;
  LDir, LOffset: Int64;
  I: Integer;
begin
  if not Dir(PE_DIR_TLS, LRva, LSize) then
    Exit;
  LDir := RvaOffset(LRva);
  if LDir = MH_NO_OFFSET then
  begin
    Warn(MHL('Каталог TLS вне данных файла', 'The TLS directory is outside the file data'));
    Exit;
  end;
  if FPe.Is64 then
  begin
    if not FReader.TryReadQWord(LDir + 24, LCallbacks64) then
      Exit;
    LCallbacksVa := LCallbacks64;
  end
  else
  begin
    if not FReader.TryReadDWord(LDir + 12, LCallbacks32) then
      Exit;
    LCallbacksVa := LCallbacks32;
  end;
  if (LCallbacksVa = 0) or (LCallbacksVa < FPe.ImageBase) or (LCallbacksVa - FPe.ImageBase > $FFFFFFFF) then
    Exit;
  LOffset := RvaOffset(Cardinal(LCallbacksVa - FPe.ImageBase));
  if LOffset = MH_NO_OFFSET then
  begin
    Warn(MHL('Таблица функций TLS вне данных файла', 'The TLS callback table is outside the file data'));
    Exit;
  end;
  for I := 0 to MAX_TLS_CALLBACKS - 1 do
  begin
    if FPe.Is64 then
    begin
      if not FReader.TryReadQWord(LOffset + I * 8, LValue64) or (LValue64 = 0) then
        Break;
    end
    else if not FReader.TryReadDWord(LOffset + I * 4, LValue32) or (LValue32 = 0) then
      Break;
    Inc(FPe.TlsCallbackCount);
  end;
end;

procedure TPeParser.ParseSecurity;
var
  LRva, LSize: Cardinal;
begin
  FPe.CertificateOffset := MH_NO_OFFSET;
  // Для каталога безопасности «RVA» — это смещение в файле.
  if not Dir(PE_DIR_SECURITY, LRva, LSize) then
    Exit;
  if not FReader.InRange(LRva, LSize) then
  begin
    Warn(MHL('Каталог подписи указывает за пределы файла', 'The signature directory points outside the file'));
    Exit;
  end;
  FPe.CertificateOffset := LRva;
  FPe.CertificateSize := LSize;
end;

procedure TPeParser.ComputeOverlay;
var
  LSection: TMHPeSection;
  LEnd, LLimit: Int64;
begin
  LEnd := Min(Int64(FPe.SizeOfHeaders), FReader.Size);
  for LSection in FPe.Sections do
    if LSection.RawSize > 0 then
      LEnd := Max(LEnd, Min(Int64(LSection.RawOffset) + LSection.RawSize, FReader.Size));
  LLimit := FReader.Size;
  if (FPe.CertificateOffset >= LEnd) and (FPe.CertificateSize > 0) then
    LLimit := FPe.CertificateOffset;
  FPe.OverlayOffset := LEnd;
  FPe.OverlaySize := Max(Int64(0), LLimit - LEnd);
  if FPe.OverlaySize = 0 then
    FPe.OverlayOffset := MH_NO_OFFSET;
end;

procedure TPeParser.ComputeEntryPoint;
var
  LSection: TMHPeSection;
begin
  FPe.EntryPointOffset := MH_NO_OFFSET;
  FPe.EntryPointSection := '';
  if FPe.EntryPointRva = 0 then
    Exit;
  FPe.EntryPointOffset := RvaOffset(FPe.EntryPointRva);
  if FPe.SectionOfRva(FPe.EntryPointRva, LSection) then
    FPe.EntryPointSection := LSection.Name;
end;

function TPeParser.Parse: TMHPeInfo;
var
  LRva, LSize: Cardinal;
begin
  FPe := Default(TMHPeInfo);
  FPe.EntryPointOffset := MH_NO_OFFSET;
  FPe.OverlayOffset := MH_NO_OFFSET;
  FPe.CertificateOffset := MH_NO_OFFSET;
  if HeadersOk then
  begin
    FPe.Valid := True;
    ParseOptional;
    ParseSections;
    MHCheckCancel(FCancel);
    // Каждая часть разбирается независимо: сбой одной не отменяет остальные.
    try
      ParseImports;
      ParseDelayImports;
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Warn(MHL('Ошибка разбора импорта: ', 'Import parsing error: ') + E.Message);
    end;
    try
      ParseExports;
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Warn(MHL('Ошибка разбора экспорта: ', 'Export parsing error: ') + E.Message);
    end;
    try
      ParseResources;
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Warn(MHL('Ошибка разбора ресурсов: ', 'Resource parsing error: ') + E.Message);
    end;
    try
      ParseTls;
    except
      on E: EMHBinaryLabCancelled do
        raise;
      on E: Exception do
        Warn(MHL('Ошибка разбора TLS: ', 'TLS parsing error: ') + E.Message);
    end;
    ParseSecurity;
    FPe.IsDotNet := Dir(PE_DIR_CLR, LRva, LSize);
    ComputeOverlay;
    ComputeEntryPoint;
  end;
  FPe.Warnings := FWarnings.ToArray;
  Result := FPe;
end;

end.
