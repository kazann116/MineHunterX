unit MineHunter.BinaryLab.Anomalies;

{
  Anomaly Detector: подозрительные структуры PE, необычные секции, скрытые
  данные, несоответствия формата и индикаторы в строках.

  Каждая аномалия — код, серьёзность, вес (вклад в оценку 0..100) и понятное
  объяснение, почему это может быть важно и когда это нормально. Ни одна
  аномалия сама по себе не означает заражение: упаковщики используют и
  легальные программы, установщики хранят архивы в оверлее, игры защищаются
  от отладки. Поэтому:
  - доверенная подпись уменьшает оценку вдвое (признаки остаются в отчёте);
  - сборки .NET не считаются «программами без импорта»;
  - высокая энтропия ресурсов (картинки, сжатые данные) не считается упаковкой.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.BinaryLab.Types;

const
  BL_EXTENSION_MISMATCH = 'BL_EXTENSION_MISMATCH';
  BL_PE_DAMAGED = 'BL_PE_DAMAGED';
  BL_ENTRY_OUTSIDE_SECTIONS = 'BL_ENTRY_OUTSIDE_SECTIONS';
  BL_ENTRY_IN_LAST_SECTION = 'BL_ENTRY_IN_LAST_SECTION';
  BL_ENTRY_IN_WRITABLE = 'BL_ENTRY_IN_WRITABLE';
  BL_ENTRY_NOT_EXECUTABLE = 'BL_ENTRY_NOT_EXECUTABLE';
  BL_RWX_SECTION = 'BL_RWX_SECTION';
  BL_PACKER_SECTIONS = 'BL_PACKER_SECTIONS';
  BL_ODD_SECTION_NAMES = 'BL_ODD_SECTION_NAMES';
  BL_PACKED_CODE = 'BL_PACKED_CODE';
  BL_HIGH_ENTROPY_DATA = 'BL_HIGH_ENTROPY_DATA';
  BL_VIRTUAL_CODE_SECTION = 'BL_VIRTUAL_CODE_SECTION';
  BL_SECTION_BEYOND_FILE = 'BL_SECTION_BEYOND_FILE';
  BL_SECTION_OVERLAP = 'BL_SECTION_OVERLAP';
  BL_IMAGE_SIZE_MISMATCH = 'BL_IMAGE_SIZE_MISMATCH';
  BL_NO_IMPORTS = 'BL_NO_IMPORTS';
  BL_DYNAMIC_IMPORTS_ONLY = 'BL_DYNAMIC_IMPORTS_ONLY';
  BL_FEW_IMPORTS = 'BL_FEW_IMPORTS';
  BL_INJECTION_API = 'BL_INJECTION_API';
  BL_ANTI_DEBUG_API = 'BL_ANTI_DEBUG_API';
  BL_TLS_CALLBACKS = 'BL_TLS_CALLBACKS';
  BL_TIMESTAMP_FUTURE = 'BL_TIMESTAMP_FUTURE';
  BL_CHECKSUM_MISMATCH = 'BL_CHECKSUM_MISMATCH';
  BL_ENCRYPTED_OVERLAY = 'BL_ENCRYPTED_OVERLAY';
  BL_OVERLAY = 'BL_OVERLAY';
  BL_EMBEDDED_EXECUTABLE = 'BL_EMBEDDED_EXECUTABLE';
  BL_EMBEDDED_ARCHIVE = 'BL_EMBEDDED_ARCHIVE';
  BL_EMBEDDED_SCRIPT = 'BL_EMBEDDED_SCRIPT';
  BL_MINING_STRINGS = 'BL_MINING_STRINGS';
  BL_WALLET_STRINGS = 'BL_WALLET_STRINGS';
  BL_COMMAND_STRINGS = 'BL_COMMAND_STRINGS';
  BL_UNSIGNED_DRIVER = 'BL_UNSIGNED_DRIVER';
  BL_SIGNATURE_INVALID = 'BL_SIGNATURE_INVALID';
  BL_UNSIGNED = 'BL_UNSIGNED';
  BL_DOTNET = 'BL_DOTNET';
  BL_HEADER_ANOMALY = 'BL_HEADER_ANOMALY';
  BL_HIGH_ENTROPY_FILE = 'BL_HIGH_ENTROPY_FILE';
  BL_PARTIAL_ANALYSIS = 'BL_PARTIAL_ANALYSIS';

  /// Энтропия кода выше этого порога — код сжат или зашифрован (обычный код 5.5–6.8).
  BL_PACKED_CODE_ENTROPY = 7.2;
  /// Энтропия данных выше этого порога — шифрованные или сильно сжатые данные.
  BL_ENCRYPTED_ENTROPY = 7.6;

/// Аномалии по готовым данным отчёта (PE, энтропия, строки, вложения, подпись).
/// ANowUtc — для проверки времени сборки «из будущего».
function MHDetectAnomalies(const AReport: TMHBinaryReport; ANowUtc: TDateTime): TArray<TMHBinaryAnomaly>;

/// Оценка, уровень и итог по аномалиям отчёта.
procedure MHScoreBinaryReport(var AReport: TMHBinaryReport; const AThresholds: TMHRiskThresholds);

/// Известный упаковщик или протектор по имени секции ('' — нет).
function MHPackerBySectionName(const AName: string): string;
/// Известный установщик по строкам файла (Inno Setup, NSIS…; '' — не распознан).
function MHDetectInstaller(const AReport: TMHBinaryReport): string;

implementation

uses
  System.Math, System.DateUtils, System.StrUtils,
  MineHunter.Core.Lang;

const
  STANDARD_SECTIONS: array[0..33] of string = ('.text', '.data', '.rdata', '.idata', '.edata', '.rsrc',
    '.reloc', '.pdata', '.tls', '.bss', '.crt', '.didat', '.CRT', 'CODE', 'DATA', 'BSS', '.itext',
    '.gfids', '.00cfg', '.xdata', '.sdata', '.debug', '.cormeta', '.didata', '.giats', '.fptable',
    '.retplne', '.voltbl', '.textbss', 'INIT', 'PAGE', '.orpc', '_RDATA', '.mrdata');

function MHPackerBySectionName(const AName: string): string;
const
  PACKERS: array[0..23, 0..1] of string = (
    ('UPX0', 'UPX'), ('UPX1', 'UPX'), ('UPX2', 'UPX'), ('.aspack', 'ASPack'), ('.adata', 'ASPack'),
    ('.packed', 'RLPack'), ('.themida', 'Themida'), ('.winlice', 'WinLicense'), ('.vmp0', 'VMProtect'),
    ('.vmp1', 'VMProtect'), ('.vmp2', 'VMProtect'), ('.enigma1', 'Enigma Protector'),
    ('.enigma2', 'Enigma Protector'), ('.MPRESS1', 'MPRESS'), ('.MPRESS2', 'MPRESS'), ('.petite', 'Petite'),
    ('.nsp0', 'NsPack'), ('.nsp1', 'NsPack'), ('.perplex', 'Perplex'), ('.yP', 'Y0da Protector'),
    ('.y0da', 'Y0da Protector'), ('PEC2', 'PECompact'), ('pec1', 'PECompact'), ('.ccg', 'CCG'));
var
  I: Integer;
begin
  for I := Low(PACKERS) to High(PACKERS) do
    if SameText(AName, PACKERS[I, 0]) then
      Exit(PACKERS[I, 1]);
  Result := '';
end;

function MHDetectInstaller(const AReport: TMHBinaryReport): string;
const
  MARKERS: array[0..9, 0..1] of string = (
    ('inno setup', 'Inno Setup'), ('jrsoftware.org', 'Inno Setup'), ('nullsoft install system', 'NSIS'),
    ('nsis error', 'NSIS'), ('installshield', 'InstallShield'), ('wix toolset', 'WiX'),
    ('7-zip sfx', '7-Zip SFX'), ('winrar sfx', 'WinRAR SFX'), ('setup factory', 'Setup Factory'),
    ('advanced installer', 'Advanced Installer'));
var
  LItem: TMHBinaryString;
  LLower: string;
  I: Integer;
begin
  for LItem in AReport.Strings.Items do
  begin
    LLower := LItem.Text.ToLower;
    for I := Low(MARKERS) to High(MARKERS) do
      if LLower.Contains(MARKERS[I, 0]) then
        Exit(MARKERS[I, 1]);
  end;
  Result := '';
end;

function IsStandardSection(const AName: string): Boolean;
var
  LName: string;
begin
  for LName in STANDARD_SECTIONS do
    if SameText(LName, AName) then
      Exit(True);
  // Секции компоновщиков вида .text$mn, .idata$5, PAGEKD и т.п.
  Result := AName.StartsWith('.text', True) or AName.StartsWith('.rdata', True) or
    AName.StartsWith('.data', True) or AName.StartsWith('PAGE', True) or AName.StartsWith('.idata', True);
end;

function JoinLimited(const AItems: TArray<string>; ALimit: Integer): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Min(High(AItems), ALimit - 1) do
  begin
    if Result <> '' then
      Result := Result + ', ';
    Result := Result + AItems[I];
  end;
  if Length(AItems) > ALimit then
    Result := Result + Format(MHL(' и ещё %d', ' and %d more'), [Length(AItems) - ALimit]);
end;

function StringsOf(const AReport: TMHBinaryReport; ACategory: TMHStringCategory; ALimit: Integer): TArray<string>;
var
  LItem: TMHBinaryString;
  LText: string;
begin
  Result := nil;
  for LItem in AReport.Strings.Items do
    if LItem.Category = ACategory then
    begin
      LText := LItem.Text;
      if Length(LText) > 80 then
        LText := Copy(LText, 1, 77) + '...';
      Result := Result + ['«' + LText + '»'];
      if Length(Result) >= ALimit then
        Break;
    end;
end;

function IsPrintableName(const AName: string): Boolean;
var
  C: Char;
begin
  if AName = '' then
    Exit(False);
  for C in AName do
    if (C < ' ') or (C > '~') or (C = '?') then
      Exit(False);
  Result := True;
end;

function OverlayEntropy(const AReport: TMHBinaryReport): Double;
var
  LBlock: TMHEntropyBlock;
  LSum: Double;
  LCount: Int64;
  LStart, LEnd: Int64;
begin
  // Точное значение по всему оверлею (считает анализатор); иначе — средняя
  // энтропия блоков, целиком лежащих в оверлее (-1 — нет данных).
  if AReport.Pe.OverlayEntropy > 0 then
    Exit(AReport.Pe.OverlayEntropy);
  Result := -1;
  LStart := AReport.Pe.OverlayOffset;
  LEnd := LStart + AReport.Pe.OverlaySize;
  LSum := 0;
  LCount := 0;
  for LBlock in AReport.Entropy.Blocks do
    if (LBlock.Offset >= LStart) and (LBlock.Offset + LBlock.Size <= LEnd) then
    begin
      LSum := LSum + LBlock.Entropy * LBlock.Size;
      Inc(LCount, LBlock.Size);
    end;
  if LCount > 0 then
    Result := LSum / LCount;
end;

function PowerOfTwo(AValue: Cardinal): Boolean;
begin
  Result := (AValue <> 0) and (AValue and (AValue - 1) = 0);
end;

function MHDetectAnomalies(const AReport: TMHBinaryReport; ANowUtc: TDateTime): TArray<TMHBinaryAnomaly>;
var
  LList: TArray<TMHBinaryAnomaly>;

  procedure Add(const ACode: string; ASeverity: TMHAnomalySeverity; const ATitle, ADetails: string;
    AWeight: Integer; AOffset: Int64 = MH_NO_OFFSET; ASize: Int64 = 0);
  begin
    LList := LList + [TMHBinaryAnomaly.Create(ACode, ASeverity, ATitle, ADetails, AWeight, AOffset, ASize)];
  end;

  function HasImport(const AName: string): Boolean;
  begin
    Result := AReport.Pe.ImportsFunction(AName) or AReport.Pe.ImportsFunction(AName + 'A') or
      AReport.Pe.ImportsFunction(AName + 'W');
  end;

var
  LPe: TMHPeInfo;
  LSection, LEntrySection, LOther: TMHPeSection;
  LPackers, LOdd, LRwx, LPacked, LHighData, LVirtual, LBeyond, LOverlaps, LHeaderIssues: TArray<string>;
  LPacker, LText: string;
  LHasEntry, LExecutable: Boolean;
  LObject: TMHEmbeddedObject;
  LExecutables, LArchives, LScripts, LCommands, I, J: Integer;
  LFirstExecutable, LImageEnd: Int64;
  LImport: TMHPeImport;
  LFunction: string;
  LOnlyDynamic: Boolean;
  LBuildTime: TDateTime;
  LOverlayEntropy: Double;
  LSeverity: TMHAnomalySeverity;
  LInstaller: string;
begin
  LList := nil;
  LPe := AReport.Pe;
  LExecutable := AReport.FileType.Kind in [bkPE, bkMsDos, bkElf, bkMachO];

  // --- Файл в целом ---
  if AReport.FileType.ExtensionMismatch then
  begin
    if LExecutable then
      Add(BL_EXTENSION_MISMATCH, asHigh, MHL('Исполняемый файл с чужим расширением', 'Executable with a foreign extension'),
        Format(MHL('Содержимое — %s, а расширение «%s». Программу, переименованную в картинку, документ или ' +
          'файл данных, пользователь не распознает как программу — частый приём маскировки.',
          'The content is %s but the extension is "%s". A program renamed to an image, document or data file ' +
          'is not recognised as a program — a common disguise.'),
          [AReport.FileType.Description, AReport.FileType.Extension]), 25)
    else
      Add(BL_EXTENSION_MISMATCH, asLow, MHL('Расширение не соответствует содержимому', 'Extension does not match the content'),
        Format(MHL('Содержимое — %s, а расширение «%s».', 'The content is %s but the extension is "%s".'),
          [AReport.FileType.Description, AReport.FileType.Extension]), 5);
  end;

  if AReport.Partial then
    Add(BL_PARTIAL_ANALYSIS, asInfo, MHL('Проверена только часть файла', 'Only part of the file was checked'),
      MHL('Файл больше лимита сканирования: энтропия, строки и вложения проверены в начале файла.',
        'The file exceeds the scan limit: entropy, strings and embedded objects were checked at the start of the file.'), 0);

  // --- Вложенные объекты ---
  LExecutables := 0;
  LArchives := 0;
  LScripts := 0;
  LFirstExecutable := MH_NO_OFFSET;
  for LObject in AReport.Embedded do
    case LObject.Kind of
      bkPE, bkElf, bkMachO:
        begin
          Inc(LExecutables);
          if LFirstExecutable = MH_NO_OFFSET then
            LFirstExecutable := LObject.Offset;
        end;
      bkZip, bkRar, bk7z, bkGzip, bkCab:
        Inc(LArchives);
      bkScript:
        Inc(LScripts);
    end;
  LInstaller := MHDetectInstaller(AReport);
  if (LExecutables > 0) and (LInstaller <> '') then
    Add(BL_EMBEDDED_EXECUTABLE, asInfo, MHL('Внутри установщика есть программы', 'The installer contains programs'),
      Format(MHL('Найдено исполняемых объектов внутри файла: %d. Строки указывают на установщик %s — он и ' +
        'хранит устанавливаемые программы.', 'Executable objects found inside the file: %d. The strings point to the ' +
        '%s installer, which stores the programs it installs.'), [LExecutables, LInstaller]), 0, LFirstExecutable)
  else if LExecutables > 0 then
    Add(BL_EMBEDDED_EXECUTABLE, asMedium, MHL('Внутри файла спрятана другая программа', 'Another program is hidden inside the file'),
      Format(MHL('Найдено исполняемых объектов внутри файла: %d. Так устроены установщики и самораспаковывающиеся ' +
        'архивы, но также «дропперы», которые извлекают и запускают вредоносную программу.',
        'Executable objects found inside the file: %d. Installers and self-extracting archives work this way, but ' +
        'so do droppers that extract and launch malware.'), [LExecutables]), 15, LFirstExecutable);
  if LArchives > 0 then
    Add(BL_EMBEDDED_ARCHIVE, asInfo, MHL('Внутри файла есть архивы', 'The file contains archives'),
      Format(MHL('Найдено архивов внутри файла: %d. Обычно это установщик или ресурсы программы.',
        'Archives found inside the file: %d. Usually an installer or program resources.'), [LArchives]), 0);
  if (LScripts > 0) and LExecutable then
    Add(BL_EMBEDDED_SCRIPT, asInfo, MHL('В программе есть фрагменты сценариев', 'The program contains script fragments'),
      Format(MHL('Фрагментов сценариев (PowerShell, cmd, VBScript, JavaScript): %d. Программа может запускать ' +
        'команды через интерпретатор.', 'Script fragments (PowerShell, cmd, VBScript, JavaScript): %d. The program ' +
        'may run commands through an interpreter.'), [LScripts]), 0);

  // --- Строки-индикаторы ---
  if AReport.Strings.CountByCategory[scMining] > 0 then
    Add(BL_MINING_STRINGS, asHigh, MHL('Строки, связанные с майнингом', 'Mining-related strings'),
      Format(MHL('Найдено: %d, например %s. Адреса пулов (stratum), имена майнеров и их параметры в программе, ' +
        'которая не является майнером, — сильный признак скрытого майнинга.',
        'Found: %d, for example %s. Pool addresses (stratum), miner names and parameters in a program that is not ' +
        'a miner are a strong sign of hidden mining.'),
        [AReport.Strings.CountByCategory[scMining], JoinLimited(StringsOf(AReport, scMining, 3), 3)]), 30);
  if (AReport.Strings.CountByCategory[scWallet] > 0) and (AReport.Strings.CountByCategory[scMining] > 0) then
    Add(BL_WALLET_STRINGS, asMedium, MHL('Адреса криптокошельков', 'Crypto wallet addresses'),
      Format(MHL('Найдено: %d, например %s. Вместе со строками майнинга это адрес, на который начисляется добыча.',
        'Found: %d, for example %s. Together with mining strings this is the address that receives the rewards.'),
        [AReport.Strings.CountByCategory[scWallet], JoinLimited(StringsOf(AReport, scWallet, 2), 2)]), 15)
  else if AReport.Strings.CountByCategory[scWallet] > 0 then
    Add(BL_WALLET_STRINGS, asInfo, MHL('Строки, похожие на адреса кошельков', 'Strings resembling wallet addresses'),
      Format(MHL('Найдено: %d, например %s. Без строк майнинга это не признак: так же выглядят хеши и ключи.',
        'Found: %d, for example %s. Without mining strings this is not a sign: hashes and keys look the same.'),
        [AReport.Strings.CountByCategory[scWallet], JoinLimited(StringsOf(AReport, scWallet, 2), 2)]), 0);
  LCommands := AReport.Strings.CountByCategory[scCommand];
  if LCommands > 0 then
  begin
    if LCommands >= 3 then
      LSeverity := asMedium
    else
      LSeverity := asLow;
    Add(BL_COMMAND_STRINGS, LSeverity, MHL('Командные строки и системные утилиты', 'Command lines and system utilities'),
      Format(MHL('Найдено: %d, например %s. Вызовы PowerShell, schtasks, reg, vssadmin и т.п. встречаются в ' +
        'установщиках, но также в программах, которые закрепляются в системе или отключают защиту.',
        'Found: %d, for example %s. Calls to PowerShell, schtasks, reg, vssadmin etc. occur in installers, but ' +
        'also in programs that persist in the system or disable protection.'),
        [LCommands, JoinLimited(StringsOf(AReport, scCommand, 3), 3)]), IfThen(LCommands >= 3, 8, 3));
  end;

  if not LPe.Valid then
  begin
    if AReport.FileType.Kind = bkMsDos then
      Add(BL_PE_DAMAGED, asMedium, MHL('Заголовок исполняемого файла повреждён', 'The executable header is damaged'),
        MHL('Файл начинается как программа Windows (MZ), но заголовок PE отсутствует или испорчен. ' +
          'Это бывает у обрезанных загрузок и у файлов, искажённых намеренно, чтобы помешать анализу.',
          'The file starts like a Windows program (MZ) but the PE header is missing or corrupted. This happens ' +
          'with truncated downloads and with files deliberately malformed to hinder analysis.'), 10);
    if (AReport.Entropy.Overall >= BL_ENCRYPTED_ENTROPY) and (AReport.Size >= 4096) then
      Add(BL_HIGH_ENTROPY_FILE, asInfo, MHL('Данные сжаты или зашифрованы', 'The data is compressed or encrypted'),
        Format(MHL('Энтропия всего файла %.2f из 8. Для архивов и медиафайлов это нормально.',
          'Entropy of the whole file is %.2f of 8. Normal for archives and media files.'), [AReport.Entropy.Overall]), 0);
    Exit(LList);
  end;

  // --- Подпись ---
  case AReport.Signature.State of
    sgSignedUntrusted:
      Add(BL_SIGNATURE_INVALID, asHigh, MHL('Подпись недействительна', 'The signature is invalid'),
        MHL('Подпись повреждена, сертификат не доверен или файл изменён после подписания: ',
          'The signature is damaged, the certificate is not trusted or the file was modified after signing: ') +
        AReport.Signature.Error, 25);
    sgUnsigned:
      if LPe.Kind = pkDriver then
        Add(BL_UNSIGNED_DRIVER, asHigh, MHL('Драйвер без цифровой подписи', 'Driver without a digital signature'),
          MHL('64-разрядная Windows загружает только подписанные драйверы. Неподписанный драйвер работает лишь при ' +
            'отключённой проверке подписей — так часто действуют руткиты.',
            '64-bit Windows loads only signed drivers. An unsigned driver works only with signature enforcement ' +
            'disabled — rootkits often rely on this.'), 25)
      else
        Add(BL_UNSIGNED, asLow, MHL('Нет цифровой подписи', 'No digital signature'),
          MHL('Многие легальные программы не подписаны, поэтому это не доказательство угрозы, но издателя ' +
            'проверить нельзя.', 'Many legitimate programs are unsigned, so this is not proof of a threat, but the ' +
            'publisher cannot be verified.'), 5);
  end;
  if LPe.IsDotNet then
    Add(BL_DOTNET, asInfo, MHL('Сборка .NET', '.NET assembly'),
      MHL('Код .NET выполняется средой CLR: короткая таблица импорта для таких файлов нормальна.',
        '.NET code runs in the CLR: a short import table is normal for such files.'), 0);

  // --- Повреждения и искажения заголовков ---
  if Length(LPe.Warnings) > 0 then
    Add(BL_PE_DAMAGED, asMedium, MHL('Структура PE повреждена или искажена', 'The PE structure is damaged or malformed'),
      MHL('Обнаружено при разборе: ', 'Found while parsing: ') + JoinLimited(LPe.Warnings, 3) +
      MHL('. Загрузчик Windows прощает многие ошибки, и вредоносные программы этим пользуются, чтобы сбить ' +
        'анализаторы.', '. The Windows loader tolerates many errors, and malware exploits this to confuse analysers.'), 10);
  LHeaderIssues := nil;
  if (LPe.FileAlignment <> 0) and (not PowerOfTwo(LPe.FileAlignment) or (LPe.FileAlignment > 65536)) then
    LHeaderIssues := LHeaderIssues + [Format('FileAlignment = 0x%x', [LPe.FileAlignment])];
  if (LPe.SectionAlignment <> 0) and not PowerOfTwo(LPe.SectionAlignment) then
    LHeaderIssues := LHeaderIssues + [Format('SectionAlignment = 0x%x', [LPe.SectionAlignment])];
  if (LPe.SectionAlignment <> 0) and (LPe.FileAlignment > LPe.SectionAlignment) then
    LHeaderIssues := LHeaderIssues + [MHL('выравнивание в файле больше выравнивания в памяти',
      'file alignment is larger than section alignment')];
  if LPe.NumberOfSections = 0 then
    LHeaderIssues := LHeaderIssues + [MHL('нет секций', 'no sections')];
  if Length(LHeaderIssues) > 0 then
    Add(BL_HEADER_ANOMALY, asMedium, MHL('Необычные значения заголовка', 'Unusual header values'),
      JoinLimited(LHeaderIssues, 4) + MHL('. Компиляторы такие значения не создают — их выставляют вручную или ' +
        'упаковщиками.', '. Compilers do not produce such values — they are set manually or by packers.'), 10);

  // --- Точка входа ---
  LHasEntry := LPe.EntryPointRva <> 0;
  LEntrySection := Default(TMHPeSection);
  if LHasEntry and not LPe.SectionOfRva(LPe.EntryPointRva, LEntrySection) then
    Add(BL_ENTRY_OUTSIDE_SECTIONS, asHigh, MHL('Точка входа вне секций', 'Entry point outside sections'),
      Format(MHL('Выполнение начинается с адреса 0x%x, который не принадлежит ни одной секции (например, в ' +
        'заголовках). Обычные компиляторы так не делают — это приём упаковщиков и заражённых файлов.',
        'Execution starts at 0x%x, which belongs to no section (for example, in the headers). Regular compilers ' +
        'never do this — it is a technique of packers and infected files.'), [LPe.EntryPointRva]), 20,
      LPe.EntryPointOffset)
  else if LHasEntry then
  begin
    if (Length(LPe.Sections) > 1) and (LEntrySection.Index = LPe.Sections[High(LPe.Sections)].Index) and
       not LEntrySection.ContainsCode then
      Add(BL_ENTRY_IN_LAST_SECTION, asMedium, MHL('Точка входа в последней секции', 'Entry point in the last section'),
        Format(MHL('Выполнение начинается в последней секции «%s», а не в секции кода. Так выглядят упакованные ' +
          'программы и файлы, к которым дописан посторонний код.',
          'Execution starts in the last section "%s" rather than in the code section. This is how packed programs ' +
          'and files with appended foreign code look.'), [LEntrySection.Name]), 10, LPe.EntryPointOffset);
    if LEntrySection.IsWritable then
      Add(BL_ENTRY_IN_WRITABLE, asMedium, MHL('Точка входа в секции, доступной для записи', 'Entry point in a writable section'),
        Format(MHL('Секция «%s» с точкой входа доступна и для записи, и для выполнения: код может изменять сам себя ' +
          '(распаковка, расшифровка).', 'Section "%s" with the entry point is both writable and executable: the code ' +
          'can modify itself (unpacking, decryption).'), [LEntrySection.Name]), 12, LPe.EntryPointOffset);
    if not LEntrySection.IsExecutable and not LEntrySection.ContainsCode then
      Add(BL_ENTRY_NOT_EXECUTABLE, asMedium, MHL('Точка входа в секции данных', 'Entry point in a data section'),
        Format(MHL('Секция «%s» с точкой входа не помечена как исполняемая.',
          'Section "%s" containing the entry point is not marked as executable.'), [LEntrySection.Name]), 12,
        LPe.EntryPointOffset);
  end;

  // --- Секции ---
  LPackers := nil;
  LOdd := nil;
  LRwx := nil;
  LPacked := nil;
  LHighData := nil;
  LVirtual := nil;
  LBeyond := nil;
  LOverlaps := nil;
  for LSection in LPe.Sections do
  begin
    LPacker := MHPackerBySectionName(LSection.Name);
    if (LPacker <> '') and (IndexStr(LPacker, LPackers) < 0) then
      LPackers := LPackers + [LPacker]
    else if (LPacker = '') and not IsStandardSection(LSection.Name) then
      LOdd := LOdd + ['«' + LSection.Name + '»'];
    if LSection.IsReadable and LSection.IsWritable and LSection.IsExecutable then
      LRwx := LRwx + [LSection.Name];
    if (LSection.IsExecutable or LSection.ContainsCode) and (LSection.Entropy >= BL_PACKED_CODE_ENTROPY) and
       (LSection.RawSize >= 1024) then
      LPacked := LPacked + [Format('%s (%.2f)', [LSection.Name, LSection.Entropy])];
    if not (LSection.IsExecutable or LSection.ContainsCode) and not SameText(LSection.Name, '.rsrc') and
       (LSection.Entropy >= BL_ENCRYPTED_ENTROPY) and (LSection.RawSize >= 4096) then
      LHighData := LHighData + [Format('%s (%.2f)', [LSection.Name, LSection.Entropy])];
    if (LSection.IsExecutable or LSection.ContainsCode) and (LSection.RawSize = 0) and (LSection.VirtualSize > 0) then
      LVirtual := LVirtual + [LSection.Name];
    if (LSection.RawSize > 0) and (Int64(LSection.RawOffset) + LSection.RawSize > AReport.Size) then
      LBeyond := LBeyond + [LSection.Name];
  end;
  for I := 0 to High(LPe.Sections) do
    for J := I + 1 to High(LPe.Sections) do
    begin
      LSection := LPe.Sections[I];
      LOther := LPe.Sections[J];
      if (LSection.RawSize > 0) and (LOther.RawSize > 0) and
         (Int64(LSection.RawOffset) < Int64(LOther.RawOffset) + LOther.RawSize) and
         (Int64(LOther.RawOffset) < Int64(LSection.RawOffset) + LSection.RawSize) then
        LOverlaps := LOverlaps + [LSection.Name + '/' + LOther.Name];
    end;
  if Length(LPackers) > 0 then
    Add(BL_PACKER_SECTIONS, asMedium, MHL('Признаки упаковщика или протектора', 'Signs of a packer or protector'),
      Format(MHL('Имена секций указывают на %s. Упаковщики сжимают или шифруют код, и его нельзя проверить без ' +
        'запуска. Ими пользуются и легальные программы (защита от взлома), и вредоносные (сокрытие от антивирусов).',
        'Section names indicate %s. Packers compress or encrypt code so it cannot be checked without running it. ' +
        'Both legitimate programs (anti-cracking) and malware (hiding from antivirus) use them.'),
        [JoinLimited(LPackers, 3)]), 15);
  if Length(LOdd) > 0 then
  begin
    LText := JoinLimited(LOdd, 4);
    LSeverity := asLow;
    for LSection in LPe.Sections do
      if (MHPackerBySectionName(LSection.Name) = '') and not IsPrintableName(LSection.Name) then
        LSeverity := asMedium;
    Add(BL_ODD_SECTION_NAMES, LSeverity, MHL('Нестандартные имена секций', 'Non-standard section names'),
      Format(MHL('Секции %s не создаются распространёнными компиляторами. Пустые и нечитаемые имена — признак ' +
        'ручной правки или упаковки.', 'Sections %s are not produced by common compilers. Empty or unreadable names ' +
        'indicate manual editing or packing.'), [LText]), IfThen(LSeverity = asMedium, 10, 3));
  end;
  if Length(LRwx) > 0 then
    Add(BL_RWX_SECTION, asMedium, MHL('Секции с правами чтения, записи и выполнения', 'Read-write-execute sections'),
      Format(MHL('Секции %s одновременно доступны для записи и выполнения. Компиляторы разделяют код и данные; ' +
        'совмещение нужно для самораспаковки или внедрения кода.',
        'Sections %s are writable and executable at the same time. Compilers separate code and data; combining ' +
        'them is needed for self-unpacking or code injection.'), [JoinLimited(LRwx, 4)]), 12);
  if Length(LPacked) > 0 then
    Add(BL_PACKED_CODE, asHigh, MHL('Код сжат или зашифрован', 'The code is compressed or encrypted'),
      Format(MHL('Энтропия исполняемых секций %s выше %.1f (обычный машинный код — 5.5–6.8). Настоящий код ' +
        'появится только в памяти после распаковки.', 'Entropy of executable sections %s is above %.1f (regular ' +
        'machine code is 5.5–6.8). The real code appears only in memory after unpacking.'),
        [JoinLimited(LPacked, 3), BL_PACKED_CODE_ENTROPY]), 20);
  if Length(LHighData) > 0 then
    Add(BL_HIGH_ENTROPY_DATA, asMedium, MHL('Шифрованные данные в секциях', 'Encrypted data in sections'),
      Format(MHL('Секции данных %s почти случайны — так выглядят шифрованные или сжатые вложения.',
        'Data sections %s are almost random — this is how encrypted or compressed payloads look.'),
        [JoinLimited(LHighData, 3)]), 10);
  if Length(LVirtual) > 0 then
    Add(BL_VIRTUAL_CODE_SECTION, asMedium, MHL('Пустая секция кода', 'Empty code section'),
      Format(MHL('Исполняемые секции %s занимают память, но не содержат данных в файле: код в них записывается ' +
        'при запуске (типично для UPX и подобных упаковщиков).', 'Executable sections %s occupy memory but have no ' +
        'data in the file: code is written into them at run time (typical for UPX and similar packers).'),
        [JoinLimited(LVirtual, 3)]), 12);
  if Length(LBeyond) > 0 then
    Add(BL_SECTION_BEYOND_FILE, asMedium, MHL('Секции выходят за конец файла', 'Sections extend beyond the end of the file'),
      Format(MHL('Секции %s заявлены длиннее, чем файл: файл обрезан или заголовок искажён.',
        'Sections %s are declared longer than the file: the file is truncated or the header is malformed.'),
        [JoinLimited(LBeyond, 3)]), 10);
  if Length(LOverlaps) > 0 then
    Add(BL_SECTION_OVERLAP, asMedium, MHL('Секции перекрываются в файле', 'Sections overlap in the file'),
      Format(MHL('Данные секций %s занимают одни и те же байты файла — компиляторы так не делают.',
        'Sections %s share the same file bytes — compilers never do this.'), [JoinLimited(LOverlaps, 3)]), 10);
  if Length(LPe.Sections) > 0 then
  begin
    LSection := LPe.Sections[High(LPe.Sections)];
    LImageEnd := Int64(LSection.VirtualAddress) + Max(LSection.VirtualSize, LSection.RawSize);
    if (LPe.SizeOfImage > 0) and (LPe.SizeOfImage < LImageEnd) then
      Add(BL_IMAGE_SIZE_MISMATCH, asLow, MHL('Размер образа меньше секций', 'Image size is smaller than the sections'),
        Format(MHL('SizeOfImage = 0x%x, а секции заканчиваются на 0x%x.', 'SizeOfImage = 0x%x but the sections end at 0x%x.'),
          [LPe.SizeOfImage, LImageEnd]), 5);
  end;

  // --- Импорт ---
  if not LPe.IsDotNet and (LPe.Kind <> pkDriver) and (Length(LPe.Sections) > 0) then
  begin
    if LPe.ImportedFunctionCount = 0 then
      Add(BL_NO_IMPORTS, asMedium, MHL('Нет таблицы импорта', 'No import table'),
        MHL('Программа не объявляет ни одной функции Windows. Обычные программы импортируют десятки функций; ' +
          'пустой импорт — признак упаковки или ручной загрузки функций для сокрытия поведения.',
          'The program declares no Windows functions. Regular programs import dozens of functions; an empty import ' +
          'table indicates packing or manual function loading to hide behaviour.'), 12)
    else
    begin
      LOnlyDynamic := True;
      for LImport in LPe.Imports do
        for LFunction in LImport.Functions do
          if not (SameText(LFunction, 'GetProcAddress') or SameText(LFunction, 'LoadLibraryA') or
             SameText(LFunction, 'LoadLibraryW') or SameText(LFunction, 'LoadLibraryExA') or
             SameText(LFunction, 'LoadLibraryExW') or SameText(LFunction, 'GetModuleHandleA') or
             SameText(LFunction, 'GetModuleHandleW') or SameText(LFunction, 'VirtualAlloc') or
             SameText(LFunction, 'VirtualProtect') or SameText(LFunction, 'ExitProcess')) then
            LOnlyDynamic := False;
      if LOnlyDynamic then
        Add(BL_DYNAMIC_IMPORTS_ONLY, asHigh, MHL('Импорт только для ручной загрузки функций', 'Imports only for manual function loading'),
          MHL('Таблица импорта содержит лишь LoadLibrary/GetProcAddress/VirtualAlloc и подобные: остальные функции ' +
            'находятся при выполнении. Классический признак упаковщика или загрузчика вредоносного кода.',
            'The import table contains only LoadLibrary/GetProcAddress/VirtualAlloc and similar: other functions are ' +
            'resolved at run time. A classic sign of a packer or malware loader.'), 15)
      else if LPe.ImportedFunctionCount <= 3 then
        Add(BL_FEW_IMPORTS, asMedium, MHL('Очень мало импортированных функций', 'Very few imported functions'),
          Format(MHL('Импортировано функций: %d. Обычные программы импортируют десятки.',
            'Imported functions: %d. Regular programs import dozens.'), [LPe.ImportedFunctionCount]), 10);
    end;
  end;
  if HasImport('WriteProcessMemory') and
     (HasImport('VirtualAllocEx') or HasImport('NtAllocateVirtualMemory')) and
     (HasImport('CreateRemoteThread') or HasImport('CreateRemoteThreadEx') or HasImport('NtCreateThreadEx') or
      HasImport('QueueUserAPC') or HasImport('SetThreadContext') or HasImport('RtlCreateUserThread')) then
    Add(BL_INJECTION_API, asHigh, MHL('Функции внедрения кода в другие процессы', 'Functions for injecting code into other processes'),
      MHL('Импортируются выделение памяти в чужом процессе, запись в неё и запуск потока. Так работают отладчики ' +
        'и некоторые средства защиты, но это и стандартная схема внедрения вредоносного кода (в том числе майнеров ' +
        'в системные процессы).', 'Imports memory allocation in another process, writing to it and starting a thread. ' +
        'Debuggers and some security tools do this, but it is also the standard scheme of malicious code injection ' +
        '(including miners injected into system processes).'), 20);
  if (HasImport('IsDebuggerPresent') or HasImport('CheckRemoteDebuggerPresent')) and
     (HasImport('NtQueryInformationProcess') or HasImport('NtSetInformationThread') or
      HasImport('OutputDebugString')) then
    Add(BL_ANTI_DEBUG_API, asLow, MHL('Проверки отладчика', 'Debugger checks'),
      MHL('Программа проверяет, не запущена ли она под отладчиком. Это обычно для игр и защищённых программ, ' +
        'но и для вредоносных, которые скрывают поведение при анализе.',
        'The program checks whether it runs under a debugger. Common for games and protected software, but also ' +
        'for malware that hides its behaviour under analysis.'), 5);

  // --- Прочие особенности ---
  if LPe.TlsCallbackCount > 0 then
    Add(BL_TLS_CALLBACKS, asLow, MHL('Код TLS выполняется до точки входа', 'TLS code runs before the entry point'),
      Format(MHL('Функций обратного вызова TLS: %d. Они выполняются раньше основной программы; этим пользуются ' +
        'защиты от отладки и вредоносные программы.', 'TLS callbacks: %d. They run before the main program; ' +
        'anti-debugging protections and malware use them.'), [LPe.TlsCallbackCount]), 3);
  if (LPe.TimeDateStamp <> 0) and (ANowUtc > 0) then
  begin
    LBuildTime := UnixToDateTime(LPe.TimeDateStamp, True);
    if LBuildTime > ANowUtc + 1 then
      Add(BL_TIMESTAMP_FUTURE, asInfo, MHL('Время сборки в будущем', 'Build time in the future'),
        Format(MHL('В заголовке указано время сборки %s UTC. Так бывает при воспроизводимой сборке (поле содержит ' +
          'хеш) или при подделке заголовка.', 'The header states build time %s UTC. This happens with reproducible ' +
          'builds (the field holds a hash) or with forged headers.'),
          [FormatDateTime('yyyy-mm-dd hh:nn', LBuildTime)]), 2);
  end;
  if (LPe.ComputedCheckSum <> 0) and (LPe.CheckSum <> LPe.ComputedCheckSum) then
  begin
    if LPe.Kind = pkDriver then
      Add(BL_CHECKSUM_MISMATCH, asMedium, MHL('Неверная контрольная сумма драйвера', 'Invalid driver checksum'),
        Format(MHL('В заголовке 0x%x, фактически 0x%x. Windows требует верную сумму у драйверов: файл изменён ' +
          'после сборки.', 'Header 0x%x, actual 0x%x. Windows requires a valid checksum for drivers: the file was ' +
          'modified after it was built.'), [LPe.CheckSum, LPe.ComputedCheckSum]), 12)
    else if LPe.CheckSum <> 0 then
      Add(BL_CHECKSUM_MISMATCH, asLow, MHL('Контрольная сумма не совпадает', 'Checksum mismatch'),
        Format(MHL('В заголовке 0x%x, фактически 0x%x: файл мог быть изменён после сборки.',
          'Header 0x%x, actual 0x%x: the file may have been modified after it was built.'),
          [LPe.CheckSum, LPe.ComputedCheckSum]), 3);
  end;
  if LPe.OverlaySize > 0 then
  begin
    LOverlayEntropy := OverlayEntropy(AReport);
    // Установщики хранят в оверлее сжатые файлы без известной сигнатуры архива.
    if LInstaller <> '' then
      Add(BL_OVERLAY, asInfo, MHL('Данные установщика после конца программы', 'Installer data after the end of the program'),
        Format(MHL('%s байт после образа программы. Строки файла указывают на установщик %s: сжатые данные ' +
          'в оверлее для него — норма.', '%s bytes after the program image. The file strings point to the %s ' +
          'installer: compressed data in the overlay is normal for it.'),
          [FormatFloat('#,##0', LPe.OverlaySize), LInstaller]), 0, LPe.OverlayOffset, LPe.OverlaySize)
    else if (LOverlayEntropy >= BL_ENCRYPTED_ENTROPY) and (LPe.OverlaySize >= 65536) and
       (AReport.Signature.State <> sgSignedTrusted) and (LArchives = 0) then
      Add(BL_ENCRYPTED_OVERLAY, asMedium, MHL('Шифрованные данные после конца программы', 'Encrypted data after the end of the program'),
        Format(MHL('После образа программы дописано %s байт почти случайных данных (энтропия %.2f) без известного ' +
          'формата. Так хранят зашифрованную полезную нагрузку.', '%s bytes of almost random data (entropy %.2f) ' +
          'without a known format are appended after the program image. Encrypted payloads are stored this way.'),
          [FormatFloat('#,##0', LPe.OverlaySize), LOverlayEntropy]), 10, LPe.OverlayOffset, LPe.OverlaySize)
    else
      Add(BL_OVERLAY, asInfo, MHL('Данные после конца программы (оверлей)', 'Data after the end of the program (overlay)'),
        Format(MHL('%s байт после образа программы. Установщики и самораспаковывающиеся архивы хранят здесь ' +
          'содержимое.', '%s bytes after the program image. Installers and self-extracting archives keep their ' +
          'content here.'), [FormatFloat('#,##0', LPe.OverlaySize)]), 0, LPe.OverlayOffset, LPe.OverlaySize);
  end;
  Result := LList;
end;

procedure MHScoreBinaryReport(var AReport: TMHBinaryReport; const AThresholds: TMHRiskThresholds);
var
  LAnomaly: TMHBinaryAnomaly;
  LRaw, LCount: Integer;
  LTop: TArray<TMHBinaryAnomaly>;
  LTitles: string;
  I, J: Integer;
  LSwap: TMHBinaryAnomaly;
begin
  LRaw := 0;
  LCount := 0;
  for LAnomaly in AReport.Anomalies do
    if LAnomaly.Weight > 0 then
    begin
      Inc(LRaw, LAnomaly.Weight);
      Inc(LCount);
    end;
  // Доверенная подпись: признаки остаются, но вес снижается вдвое.
  if AReport.Signature.State = sgSignedTrusted then
    LRaw := LRaw div 2;
  AReport.Score := EnsureRange(LRaw, 0, 100);
  AReport.Level := AThresholds.LevelOf(AReport.Score);
  if (LCount = 0) or (AReport.Score < AThresholds.Low) then
  begin
    AReport.Verdict := MHL('Явных признаков угрозы не найдено. Это не гарантия безопасности: статический анализ ' +
      'не видит поведения программы при запуске.', 'No clear signs of a threat were found. This is not a guarantee ' +
      'of safety: static analysis cannot see how the program behaves when run.');
    Exit;
  end;
  // Три самых весомых признака — в итог.
  LTop := Copy(AReport.Anomalies);
  for I := 0 to High(LTop) - 1 do
    for J := I + 1 to High(LTop) do
      if LTop[J].Weight > LTop[I].Weight then
      begin
        LSwap := LTop[I];
        LTop[I] := LTop[J];
        LTop[J] := LSwap;
      end;
  LTitles := '';
  for I := 0 to Min(2, High(LTop)) do
    if LTop[I].Weight > 0 then
    begin
      if LTitles <> '' then
        LTitles := LTitles + '; ';
      LTitles := LTitles + LTop[I].Title;
    end;
  AReport.Verdict := Format(MHL('Оценка %d из 100 (%s). Главные признаки: %s. Это повод для проверки, а не диагноз.',
    'Score %d of 100 (%s). Main signs: %s. This is a reason to check, not a diagnosis.'),
    [AReport.Score, MHRiskLevelToString(AReport.Level), LTitles]);
  if AReport.Signature.State = sgSignedTrusted then
    AReport.Verdict := AReport.Verdict + MHL(' Файл подписан доверенным издателем — оценка снижена вдвое.',
      ' The file is signed by a trusted publisher — the score is halved.');
end;

end.
