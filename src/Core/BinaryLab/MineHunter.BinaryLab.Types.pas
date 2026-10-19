unit MineHunter.BinaryLab.Types;

{
  BinaryLab — глубокий статический анализ файлов (исполняемые файлы, драйверы,
  данные). Этот модуль — общие типы результата анализа, параметры и лимиты.

  Принципы BinaryLab:
  - Файл только читается: открывается на чтение с разрешением совместного
    доступа, не запускается и не загружается загрузчиком Windows
    (ни LoadLibrary, ни LoadLibraryEx). Разбор — по байтам из файла.
  - Все размеры, смещения и счётчики из файла считаются недоверенными:
    каждое чтение проверяется на границы, циклы и глубина обхода ограничены,
    память — лимитами TMHBinaryLabOptions. Повреждённый файл даёт отчёт
    с предупреждениями, а не исключение.
  - Ни один признак сам по себе не означает угрозу: оценка BinaryLab —
    повод для проверки, у каждого признака есть объяснение.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types;

const
  /// Версия правил BinaryLab (в отчётах и признаках движка угроз).
  MH_BINARYLAB_VERSION = 'BL-2026.10.1';

  /// Смещение неизвестно / не применимо.
  MH_NO_OFFSET = Int64(-1);

type
  EMHBinaryLabError = class(EMHError);
  /// Анализ отменён пользователем.
  EMHBinaryLabCancelled = class(EMHBinaryLabError);

  /// Вид содержимого (определяется по байтам, а не по расширению).
  TMHBinaryKind = (
    bkUnknown,     // двоичные данные без известной сигнатуры
    bkEmpty,       // файл нулевого размера
    bkPE,          // исполняемый файл Windows (EXE, DLL, SYS)
    bkMsDos,       // заголовок MZ без корректного PE
    bkElf,         // исполняемый файл Linux
    bkMachO,       // исполняемый файл macOS
    bkZip,         // ZIP (а также JAR, DOCX, XLSX, APK)
    bkRar,
    bk7z,
    bkGzip,
    bkCab,
    bkOle,         // составной документ OLE (DOC, XLS, MSI)
    bkPdf,
    bkPng,
    bkJpeg,
    bkGif,
    bkBmp,
    bkIco,
    bkScript,      // текстовый сценарий (PowerShell, BAT, VBS, JS, shell)
    bkText         // прочий текст
  );

  /// Вид исполняемого файла PE.
  TMHPeKind = (pkNone, pkExe, pkDll, pkDriver);

  TMHBinaryTypeInfo = record
  public
    Kind: TMHBinaryKind;
    PeKind: TMHPeKind;
    /// Понятное описание: «Исполняемый файл Windows x64 (DLL)».
    Description: string;
    /// Расширение файла (нижний регистр, с точкой; '' — нет).
    Extension: string;
    /// Расширения, обычные для такого содержимого ('.exe;.dll').
    ExpectedExtensions: string;
    /// Расширение не соответствует содержимому (например, PE с расширением .jpg).
    ExtensionMismatch: Boolean;
  end;

  /// Секция PE.
  TMHPeSection = record
  public
    Index: Integer;
    Name: string;
    VirtualAddress: Cardinal;
    VirtualSize: Cardinal;
    RawOffset: Cardinal;
    RawSize: Cardinal;
    Characteristics: Cardinal;
    /// Энтропия данных секции в файле, 0..8 бит на байт (-1 — нет данных в файле).
    Entropy: Double;
    /// SHA-256 данных секции в файле ('' — нет данных или секция больше лимита).
    Sha256: string;
    function IsExecutable: Boolean;
    function IsWritable: Boolean;
    function IsReadable: Boolean;
    function ContainsCode: Boolean;
    /// «R-X», «RW-», «RWX».
    function AccessText: string;
  end;

  TMHPeImport = record
  public
    Dll: string;
    /// Имена функций; импорт по порядковому номеру — «#123».
    Functions: TArray<string>;
    /// Отложенная загрузка (delay import).
    Delayed: Boolean;
  end;

  TMHPeExport = record
  public
    Ordinal: Cardinal;
    Name: string;
    Rva: Cardinal;
    /// Переадресация «другая.dll.Функция» ('' — нет).
    Forwarder: string;
  end;

  TMHPeResource = record
  public
    /// Тип: «ICON», «VERSION», «RCDATA» или номер/имя для нестандартных.
    TypeName: string;
    Name: string;
    Language: Cardinal;
    /// Смещение данных в файле (MH_NO_OFFSET — вне файла).
    Offset: Int64;
    Size: Cardinal;
    /// 0..8 (-1 — данных нет в файле).
    Entropy: Double;
    /// Вид содержимого ресурса по сигнатуре (bkUnknown — обычные данные).
    ContentKind: TMHBinaryKind;
  end;

  TMHPeDataDirectory = record
  public
    Name: string;
    Rva: Cardinal;
    Size: Cardinal;
  end;

  /// Результат разбора PE. Valid = False — файл не PE или заголовок повреждён.
  TMHPeInfo = record
  public
    Valid: Boolean;
    Is64: Boolean;
    Kind: TMHPeKind;
    /// Смещение заголовка PE (e_lfanew).
    HeaderOffset: Cardinal;
    Machine: Word;
    MachineName: string;
    NumberOfSections: Word;
    TimeDateStamp: Cardinal;
    Characteristics: Word;
    Magic: Word;
    LinkerVersion: string;
    OsVersion: string;
    Subsystem: Word;
    SubsystemName: string;
    DllCharacteristics: Word;
    ImageBase: UInt64;
    EntryPointRva: Cardinal;
    /// Смещение точки входа в файле (MH_NO_OFFSET — вне данных файла).
    EntryPointOffset: Int64;
    /// Секция с точкой входа ('' — ни в одной).
    EntryPointSection: string;
    SizeOfImage: Cardinal;
    SizeOfHeaders: Cardinal;
    FileAlignment: Cardinal;
    SectionAlignment: Cardinal;
    /// Контрольная сумма из заголовка и вычисленная (0 — не вычислялась).
    CheckSum: Cardinal;
    ComputedCheckSum: Cardinal;
    NumberOfRvaAndSizes: Cardinal;
    Sections: TArray<TMHPeSection>;
    DataDirectories: TArray<TMHPeDataDirectory>;
    Imports: TArray<TMHPeImport>;
    ExportedFunctions: TArray<TMHPeExport>;
    /// Имя библиотеки из каталога экспорта.
    ExportName: string;
    Resources: TArray<TMHPeResource>;
    /// Данные после конца последней секции (и не подпись).
    OverlayOffset: Int64;
    OverlaySize: Int64;
    /// Энтропия оверлея по всему диапазону (0 — не вычислялась).
    OverlayEntropy: Double;
    /// Каталог безопасности (подпись Authenticode в файле).
    CertificateOffset: Int64;
    CertificateSize: Cardinal;
    /// Есть каталог CLR (сборка .NET).
    IsDotNet: Boolean;
    /// Число функций обратного вызова TLS (выполняются до точки входа).
    TlsCallbackCount: Integer;
    /// Всего импортированных функций.
    ImportedFunctionCount: Integer;
    /// Проблемы разбора (обрезанные таблицы, выход за границы и т.п.).
    Warnings: TArray<string>;
    function FindSection(const AName: string; out ASection: TMHPeSection): Boolean;
    /// Раздел, содержащий RVA (False — ни один).
    function SectionOfRva(ARva: Cardinal; out ASection: TMHPeSection): Boolean;
    function ImportsFunction(const AName: string): Boolean;
  end;

  TMHBinarySignature = record
  public
    State: TMHSignatureState;
    Signer: string;
    /// 'embedded' — подпись в файле, 'catalog' — каталог Windows, '' — нет.
    Source: string;
    Error: string;
  end;

  TMHEntropyBlock = record
  public
    Offset: Int64;
    Size: Integer;
    /// 0..8 бит на байт.
    Entropy: Single;
  end;

  /// Характер области по энтропии.
  TMHEntropyClass = (
    ecEmpty,       // заполнение (нули, повтор одного байта), < 1
    ecText,        // текст, таблицы, 1..5
    ecCode,        // машинный код и данные, 5..6.8
    ecCompressed,  // сжатые данные, 6.8..7.6
    ecEncrypted    // шифрованные или сильно сжатые (упаковщики), >= 7.6
  );

  TMHEntropyRegion = record
  public
    Offset: Int64;
    Size: Int64;
    AverageEntropy: Double;
    EntropyClass: TMHEntropyClass;
    /// Где находится: секция PE, оверлей, ресурс или ''.
    Location: string;
  end;

  TMHEntropyInfo = record
  public
    /// Энтропия всего прочитанного содержимого.
    Overall: Double;
    BlockSize: Integer;
    Blocks: TArray<TMHEntropyBlock>;
    /// Области высокой энтропии (сжатые или шифрованные), объединённые из блоков.
    HighRegions: TArray<TMHEntropyRegion>;
    /// Частоты байтов 0..255 (распределение данных).
    Histogram: array[Byte] of Int64;
    /// Прочитано байт (меньше размера файла, если сработал лимит).
    BytesScanned: Int64;
  end;

  TMHStringEncoding = (seAscii, seUtf16);

  /// Категория строки (индикатор). scPlain — без особенностей.
  TMHStringCategory = (
    scPlain,
    scUrl,
    scIp,
    scDomain,
    scEmail,
    scPath,
    scRegistry,
    scCommand,      // командная строка, PowerShell, cmd
    scMining,       // майнинг: stratum, пулы, имена майнеров, параметры
    scWallet,       // адрес криптокошелька
    scSuspiciousApi,// функции внедрения кода, обхода защиты
    scBase64        // длинный блок Base64
  );

  TMHBinaryString = record
  public
    Offset: Int64;
    Encoding: TMHStringEncoding;
    Text: string;
    Category: TMHStringCategory;
  end;

  TMHStringsInfo = record
  public
    Items: TArray<TMHBinaryString>;
    /// Найдено всего (может быть больше Length(Items), если сработал лимит).
    TotalFound: Integer;
    Truncated: Boolean;
    CountByCategory: array[TMHStringCategory] of Integer;
  end;

  /// Вложенный объект внутри файла.
  TMHEmbeddedObject = record
  public
    Offset: Int64;
    /// Размер, если его удалось определить по заголовку (-1 — неизвестен).
    Size: Int64;
    Kind: TMHBinaryKind;
    Description: string;
    /// Где найден: «оверлей», «ресурс RCDATA/101», «секция .data».
    Location: string;
  end;

  TMHAnomalySeverity = (asInfo, asLow, asMedium, asHigh);

  TMHBinaryAnomaly = record
  public
    /// Стабильный код (BL_ENTRY_OUTSIDE_SECTIONS и т.п.).
    Code: string;
    Severity: TMHAnomalySeverity;
    Title: string;
    /// Пояснение: что найдено и почему это может быть важно.
    Details: string;
    Offset: Int64;
    Size: Int64;
    /// Вклад в оценку 0..100 (0 — справочная особенность).
    Weight: Integer;
    class function Create(const ACode: string; ASeverity: TMHAnomalySeverity;
      const ATitle, ADetails: string; AWeight: Integer; AOffset: Int64 = MH_NO_OFFSET;
      ASize: Int64 = 0): TMHBinaryAnomaly; static;
  end;

  /// Полный отчёт BinaryLab по файлу.
  TMHBinaryReport = record
  public
    Path: string;
    FileName: string;
    Size: Int64;
    Sha256: string;
    LastWriteUtc: TDateTime;
    AnalyzedAtUtc: TDateTime;
    DurationMs: Cardinal;
    FileType: TMHBinaryTypeInfo;
    Pe: TMHPeInfo;
    Signature: TMHBinarySignature;
    Entropy: TMHEntropyInfo;
    Strings: TMHStringsInfo;
    Embedded: TArray<TMHEmbeddedObject>;
    Anomalies: TArray<TMHBinaryAnomaly>;
    /// Оценка 0..100: сумма весов аномалий (с поправкой на доверенную подпись).
    Score: Integer;
    Level: TMHRiskLevel;
    /// Короткий итог для пользователя.
    Verdict: string;
    /// Сработал лимит: часть файла не проверена.
    Partial: Boolean;
    /// Пояснения о лимитах и пропущенных проверках.
    Notes: TArray<string>;
    /// Ошибки чтения и разбора (анализ продолжен, насколько возможно).
    Errors: TArray<string>;
    RulesVersion: string;
    function HasAnomaly(const ACode: string): Boolean;
  end;

  TMHDiffChange = (dcAdded, dcRemoved, dcChanged);

  TMHDiffItem = record
  public
    /// Область: header, section, import, export, resource, string, block.
    Area: string;
    Change: TMHDiffChange;
    Name: string;
    OldValue: string;
    NewValue: string;
  end;

  TMHByteRange = record
  public
    Offset: Int64;
    Size: Int64;
  end;

  /// Результат сравнения двух файлов (BinaryDiff).
  TMHBinaryDiff = record
  public
    LeftPath: string;
    RightPath: string;
    LeftSize: Int64;
    RightSize: Int64;
    LeftSha256: string;
    RightSha256: string;
    Identical: Boolean;
    Items: TArray<TMHDiffItem>;
    /// Изменённые диапазоны байтов (по левому файлу; блоками BlockSize).
    ChangedRanges: TArray<TMHByteRange>;
    BlockSize: Integer;
    ChangedBytes: Int64;
    /// Доля совпадающих блоков, 0..100.
    SimilarityPercent: Double;
    /// Сработал лимит: сравнены не все байты или не все элементы.
    Truncated: Boolean;
    function CountOf(const AArea: string): Integer;
  end;

  /// Параметры и лимиты анализа.
  TMHBinaryLabOptions = record
  public
    /// Сколько байт файла читать для энтропии, строк и вложений (дальше — лимит).
    MaxScanBytes: Int64;
    /// Размер блока энтропии (0 — подбирается: не больше MaxEntropyBlocks блоков).
    EntropyBlockSize: Integer;
    MaxEntropyBlocks: Integer;
    MinStringLength: Integer;
    MaxStringLength: Integer;
    MaxStrings: Integer;
    MaxEmbedded: Integer;
    MaxImportedFunctions: Integer;
    MaxResources: Integer;
    MaxExports: Integer;
    /// Секция больше этого — хеш не считается (энтропия считается по MaxScanBytes).
    MaxSectionHashBytes: Int64;
    /// Проверять подпись Authenticode (WinVerifyTrust; файл не изменяется).
    VerifySignature: Boolean;
    /// Вычислять контрольную сумму PE (читается весь файл до MaxScanBytes).
    ComputeChecksum: Boolean;
    class function Default: TMHBinaryLabOptions; static;
    function Normalized: TMHBinaryLabOptions;
  end;

  /// Проверка отмены (True — прервать анализ).
  TMHCancelCheck = reference to function: Boolean;
  /// Где находится смещение файла: «секция .text», «оверлей», «заголовки PE» ('' — неизвестно).
  TMHLocateFunc = reference to function(AOffset: Int64): string;
  /// Ход анализа: этап и процент 0..100.
  TMHBinaryProgress = reference to procedure(const AStage: string; APercent: Integer);

function MHBinaryKindTitle(AKind: TMHBinaryKind): string;
function MHBinaryKindToName(AKind: TMHBinaryKind): string;
function MHPeKindTitle(AKind: TMHPeKind): string;
function MHStringCategoryTitle(ACategory: TMHStringCategory): string;
function MHStringCategoryToName(ACategory: TMHStringCategory): string;
function MHEntropyClassOf(AEntropy: Double): TMHEntropyClass;
function MHEntropyClassTitle(AClass: TMHEntropyClass): string;
function MHAnomalySeverityTitle(ASeverity: TMHAnomalySeverity): string;
function MHAnomalySeverityToName(ASeverity: TMHAnomalySeverity): string;
function MHDiffChangeTitle(AChange: TMHDiffChange): string;
function MHDiffChangeToName(AChange: TMHDiffChange): string;
/// Энтропия Шеннона по частотам байтов, 0..8 бит на байт.
function MHShannonEntropy(const ACounts: array of Int64; ATotal: Int64): Double;
/// «0x0001F400».
function MHHexOffset(AOffset: Int64): string;

implementation

uses
  System.Math, System.StrUtils,
  MineHunter.Core.Lang;

const
  IMAGE_SCN_CNT_CODE = $00000020;
  IMAGE_SCN_MEM_EXECUTE = $20000000;
  IMAGE_SCN_MEM_READ = $40000000;
  IMAGE_SCN_MEM_WRITE = $80000000;

{ TMHPeSection }

function TMHPeSection.IsExecutable: Boolean;
begin
  Result := Characteristics and IMAGE_SCN_MEM_EXECUTE <> 0;
end;

function TMHPeSection.IsWritable: Boolean;
begin
  Result := Characteristics and IMAGE_SCN_MEM_WRITE <> 0;
end;

function TMHPeSection.IsReadable: Boolean;
begin
  Result := Characteristics and IMAGE_SCN_MEM_READ <> 0;
end;

function TMHPeSection.ContainsCode: Boolean;
begin
  Result := Characteristics and IMAGE_SCN_CNT_CODE <> 0;
end;

function TMHPeSection.AccessText: string;
begin
  Result := IfThen(IsReadable, 'R', '-') + IfThen(IsWritable, 'W', '-') + IfThen(IsExecutable, 'X', '-');
end;

{ TMHPeInfo }

function TMHPeInfo.FindSection(const AName: string; out ASection: TMHPeSection): Boolean;
var
  LSection: TMHPeSection;
begin
  for LSection in Sections do
    if SameText(LSection.Name, AName) then
    begin
      ASection := LSection;
      Exit(True);
    end;
  ASection := Default(TMHPeSection);
  Result := False;
end;

function TMHPeInfo.SectionOfRva(ARva: Cardinal; out ASection: TMHPeSection): Boolean;
var
  LSection: TMHPeSection;
  LSize: Cardinal;
begin
  for LSection in Sections do
  begin
    LSize := Max(LSection.VirtualSize, LSection.RawSize);
    if (ARva >= LSection.VirtualAddress) and (UInt64(ARva) < UInt64(LSection.VirtualAddress) + LSize) then
    begin
      ASection := LSection;
      Exit(True);
    end;
  end;
  ASection := Default(TMHPeSection);
  Result := False;
end;

function TMHPeInfo.ImportsFunction(const AName: string): Boolean;
var
  LImport: TMHPeImport;
  LName: string;
begin
  for LImport in Imports do
    for LName in LImport.Functions do
      if SameText(LName, AName) then
        Exit(True);
  Result := False;
end;

{ TMHBinaryAnomaly }

class function TMHBinaryAnomaly.Create(const ACode: string; ASeverity: TMHAnomalySeverity;
  const ATitle, ADetails: string; AWeight: Integer; AOffset: Int64; ASize: Int64): TMHBinaryAnomaly;
begin
  Result.Code := ACode;
  Result.Severity := ASeverity;
  Result.Title := ATitle;
  Result.Details := ADetails;
  Result.Weight := AWeight;
  Result.Offset := AOffset;
  Result.Size := ASize;
end;

{ TMHBinaryReport }

function TMHBinaryReport.HasAnomaly(const ACode: string): Boolean;
var
  LItem: TMHBinaryAnomaly;
begin
  for LItem in Anomalies do
    if LItem.Code = ACode then
      Exit(True);
  Result := False;
end;

{ TMHBinaryDiff }

function TMHBinaryDiff.CountOf(const AArea: string): Integer;
var
  LItem: TMHDiffItem;
begin
  Result := 0;
  for LItem in Items do
    if LItem.Area = AArea then
      Inc(Result);
end;

{ TMHBinaryLabOptions }

class function TMHBinaryLabOptions.Default: TMHBinaryLabOptions;
begin
  Result.MaxScanBytes := 256 * 1024 * 1024;
  Result.EntropyBlockSize := 0;
  Result.MaxEntropyBlocks := 4096;
  Result.MinStringLength := 5;
  Result.MaxStringLength := 1024;
  Result.MaxStrings := 20000;
  Result.MaxEmbedded := 200;
  Result.MaxImportedFunctions := 10000;
  Result.MaxResources := 4096;
  Result.MaxExports := 20000;
  Result.MaxSectionHashBytes := 64 * 1024 * 1024;
  Result.VerifySignature := True;
  Result.ComputeChecksum := True;
end;

function TMHBinaryLabOptions.Normalized: TMHBinaryLabOptions;
begin
  Result := Self;
  Result.MaxScanBytes := EnsureRange(MaxScanBytes, 4096, Int64(4) * 1024 * 1024 * 1024);
  if EntropyBlockSize <> 0 then
    Result.EntropyBlockSize := EnsureRange(EntropyBlockSize, 64, 16 * 1024 * 1024);
  Result.MaxEntropyBlocks := EnsureRange(MaxEntropyBlocks, 16, 65536);
  Result.MinStringLength := EnsureRange(MinStringLength, 3, 64);
  Result.MaxStringLength := EnsureRange(MaxStringLength, Result.MinStringLength, 65536);
  Result.MaxStrings := EnsureRange(MaxStrings, 0, 1000000);
  Result.MaxEmbedded := EnsureRange(MaxEmbedded, 0, 100000);
  Result.MaxImportedFunctions := EnsureRange(MaxImportedFunctions, 0, 1000000);
  Result.MaxResources := EnsureRange(MaxResources, 0, 1000000);
  Result.MaxExports := EnsureRange(MaxExports, 0, 1000000);
  Result.MaxSectionHashBytes := Max(Int64(0), MaxSectionHashBytes);
end;

{ Функции }

function MHBinaryKindTitle(AKind: TMHBinaryKind): string;
begin
  case AKind of
    bkEmpty:   Result := MHL('Пустой файл', 'Empty file');
    bkPE:      Result := MHL('Исполняемый файл Windows (PE)', 'Windows executable (PE)');
    bkMsDos:   Result := MHL('Программа MS-DOS или повреждённый PE', 'MS-DOS program or damaged PE');
    bkElf:     Result := MHL('Исполняемый файл Linux (ELF)', 'Linux executable (ELF)');
    bkMachO:   Result := MHL('Исполняемый файл macOS (Mach-O)', 'macOS executable (Mach-O)');
    bkZip:     Result := MHL('Архив ZIP (или документ Office, JAR)', 'ZIP archive (or Office document, JAR)');
    bkRar:     Result := MHL('Архив RAR', 'RAR archive');
    bk7z:      Result := MHL('Архив 7-Zip', '7-Zip archive');
    bkGzip:    Result := MHL('Сжатые данные GZIP', 'GZIP compressed data');
    bkCab:     Result := MHL('Архив CAB', 'CAB archive');
    bkOle:     Result := MHL('Составной документ OLE (DOC, XLS, MSI)', 'OLE compound document (DOC, XLS, MSI)');
    bkPdf:     Result := MHL('Документ PDF', 'PDF document');
    bkPng:     Result := MHL('Изображение PNG', 'PNG image');
    bkJpeg:    Result := MHL('Изображение JPEG', 'JPEG image');
    bkGif:     Result := MHL('Изображение GIF', 'GIF image');
    bkBmp:     Result := MHL('Изображение BMP', 'BMP image');
    bkIco:     Result := MHL('Значок ICO', 'ICO icon');
    bkScript:  Result := MHL('Сценарий (скрипт)', 'Script');
    bkText:    Result := MHL('Текст', 'Text');
  else
    Result := MHL('Двоичные данные', 'Binary data');
  end;
end;

function MHBinaryKindToName(AKind: TMHBinaryKind): string;
const
  NAMES: array[TMHBinaryKind] of string = ('unknown', 'empty', 'pe', 'msdos', 'elf', 'macho', 'zip',
    'rar', '7z', 'gzip', 'cab', 'ole', 'pdf', 'png', 'jpeg', 'gif', 'bmp', 'ico', 'script', 'text');
begin
  Result := NAMES[AKind];
end;

function MHPeKindTitle(AKind: TMHPeKind): string;
begin
  case AKind of
    pkExe:    Result := MHL('программа (EXE)', 'program (EXE)');
    pkDll:    Result := MHL('библиотека (DLL)', 'library (DLL)');
    pkDriver: Result := MHL('драйвер (SYS)', 'driver (SYS)');
  else
    Result := '';
  end;
end;

function MHStringCategoryTitle(ACategory: TMHStringCategory): string;
begin
  case ACategory of
    scUrl:           Result := MHL('Адрес URL', 'URL');
    scIp:            Result := MHL('IP-адрес', 'IP address');
    scDomain:        Result := MHL('Домен', 'Domain');
    scEmail:         Result := MHL('Почта', 'E-mail');
    scPath:          Result := MHL('Путь', 'Path');
    scRegistry:      Result := MHL('Реестр', 'Registry');
    scCommand:       Result := MHL('Команда', 'Command');
    scMining:        Result := MHL('Майнинг', 'Mining');
    scWallet:        Result := MHL('Криптокошелёк', 'Crypto wallet');
    scSuspiciousApi: Result := MHL('Подозрительная функция', 'Suspicious API');
    scBase64:        Result := 'Base64';
  else
    Result := MHL('Строка', 'String');
  end;
end;

function MHStringCategoryToName(ACategory: TMHStringCategory): string;
const
  NAMES: array[TMHStringCategory] of string = ('plain', 'url', 'ip', 'domain', 'email', 'path',
    'registry', 'command', 'mining', 'wallet', 'suspicious_api', 'base64');
begin
  Result := NAMES[ACategory];
end;

function MHEntropyClassOf(AEntropy: Double): TMHEntropyClass;
begin
  if AEntropy < 1 then
    Result := ecEmpty
  else if AEntropy < 5 then
    Result := ecText
  else if AEntropy < 6.8 then
    Result := ecCode
  else if AEntropy < 7.6 then
    Result := ecCompressed
  else
    Result := ecEncrypted;
end;

function MHEntropyClassTitle(AClass: TMHEntropyClass): string;
begin
  case AClass of
    ecEmpty:      Result := MHL('заполнение', 'padding');
    ecText:       Result := MHL('текст и таблицы', 'text and tables');
    ecCode:       Result := MHL('код и данные', 'code and data');
    ecCompressed: Result := MHL('сжатые данные', 'compressed data');
  else
    Result := MHL('шифрованные или упакованные данные', 'encrypted or packed data');
  end;
end;

function MHAnomalySeverityTitle(ASeverity: TMHAnomalySeverity): string;
begin
  case ASeverity of
    asInfo:   Result := MHL('сведения', 'info');
    asLow:    Result := MHL('низкая', 'low');
    asMedium: Result := MHL('средняя', 'medium');
  else
    Result := MHL('высокая', 'high');
  end;
end;

function MHAnomalySeverityToName(ASeverity: TMHAnomalySeverity): string;
const
  NAMES: array[TMHAnomalySeverity] of string = ('info', 'low', 'medium', 'high');
begin
  Result := NAMES[ASeverity];
end;

function MHDiffChangeTitle(AChange: TMHDiffChange): string;
begin
  case AChange of
    dcAdded:   Result := MHL('добавлено', 'added');
    dcRemoved: Result := MHL('удалено', 'removed');
  else
    Result := MHL('изменено', 'changed');
  end;
end;

function MHDiffChangeToName(AChange: TMHDiffChange): string;
const
  NAMES: array[TMHDiffChange] of string = ('added', 'removed', 'changed');
begin
  Result := NAMES[AChange];
end;

function MHShannonEntropy(const ACounts: array of Int64; ATotal: Int64): Double;
var
  I: Integer;
  P: Double;
begin
  Result := 0;
  if ATotal <= 0 then
    Exit;
  for I := Low(ACounts) to High(ACounts) do
    if ACounts[I] > 0 then
    begin
      P := ACounts[I] / ATotal;
      Result := Result - P * Log2(P);
    end;
  // Погрешность вычислений не должна выводить значение за 0..8.
  Result := EnsureRange(Result, 0, 8);
end;

function MHHexOffset(AOffset: Int64): string;
begin
  if AOffset < 0 then
    Result := '—'
  else if AOffset > $FFFFFFFF then
    Result := '0x' + IntToHex(AOffset, 12)
  else
    Result := '0x' + IntToHex(AOffset, 8);
end;

end.
