unit MineHunter.BinaryLab.FileType;

{
  Определение вида файла по содержимому (сигнатурам), а не по расширению.
  Расширение используется только для сравнения: исполняемый файл с
  расширением .jpg или .dat — частый приём маскировки.

  MHIdentifyAt проверяет объект на произвольном смещении (для поиска
  вложенных файлов): короткие сигнатуры подтверждаются полями заголовка,
  чтобы случайные байты не давали ложных срабатываний.
}

interface

uses
  System.SysUtils,
  MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source;

type
  /// Краткие сведения о PE по смещению (без полного разбора).
  TMHPeQuickInfo = record
  public
    Is64: Boolean;
    Machine: Word;
    Kind: TMHPeKind;
    Subsystem: Word;
    /// Конец данных образа в файле: максимум (смещение + размер) секций и заголовков.
    ImageEnd: Int64;
  end;

/// Вид файла по первым байтам и расширению AFileName.
function MHDetectBinaryType(AReader: TMHBinaryReader; const AFileName: string): TMHBinaryTypeInfo;

/// Есть ли корректный PE (MZ + PE\0\0 + известный формат) по смещению AOffset.
function MHProbePe(AReader: TMHBinaryReader; AOffset: Int64; out AInfo: TMHPeQuickInfo): Boolean;

/// Объект с известной сигнатурой по смещению AOffset. AStrict — для середины
/// файла: принимаются только сигнатуры, подтверждённые заголовком (текст и
/// слабые сигнатуры вроде «BM» отбрасываются). ASize — размер, если его
/// можно определить по заголовку, иначе -1.
function MHIdentifyAt(AReader: TMHBinaryReader; AOffset: Int64; AStrict: Boolean;
  out AKind: TMHBinaryKind; out ADescription: string; out ASize: Int64): Boolean;

/// Имя архитектуры по полю Machine заголовка PE.
function MHMachineName(AMachine: Word): string;
/// Расширения, обычные для вида содержимого ('.exe;.dll;…').
function MHExpectedExtensions(AKind: TMHBinaryKind): string;
/// Расширение из списка (без учёта регистра).
function MHExtensionInList(const AExtension, AList: string): Boolean;

const
  IMAGE_FILE_MACHINE_I386 = $014C;
  IMAGE_FILE_MACHINE_AMD64 = $8664;
  IMAGE_FILE_MACHINE_ARM64 = $AA64;
  IMAGE_FILE_MACHINE_ARM = $01C0;
  IMAGE_FILE_MACHINE_ARMNT = $01C4;
  IMAGE_FILE_MACHINE_IA64 = $0200;
  IMAGE_FILE_DLL = $2000;
  IMAGE_SUBSYSTEM_NATIVE = 1;
  /// Предел e_lfanew: заголовок PE дальше 16 МБ от начала не встречается.
  MH_MAX_LFANEW = 16 * 1024 * 1024;

implementation

uses
  System.Math, System.StrUtils,
  MineHunter.Core.Lang;

const
  PE_EXTENSIONS = '.exe;.dll;.sys;.ocx;.cpl;.scr;.drv;.efi;.mui;.ax;.com;.acm;.tsp;.node;.pyd;' +
    '.winmd;.mun;.ime;.tlb;.rll;.fon';
  SCRIPT_EXTENSIONS = '.ps1;.psm1;.psd1;.bat;.cmd;.vbs;.vbe;.js;.jse;.wsf;.wsh;.hta;.sh;.py;.pl;.rb';
  TEXT_EXTENSIONS = '.txt;.log;.ini;.cfg;.conf;.xml;.json;.csv;.md;.htm;.html;.inf;.reg;.yml;.yaml';

function MHMachineName(AMachine: Word): string;
begin
  case AMachine of
    IMAGE_FILE_MACHINE_I386:  Result := 'x86';
    IMAGE_FILE_MACHINE_AMD64: Result := 'x64';
    IMAGE_FILE_MACHINE_ARM64: Result := 'ARM64';
    IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARMNT: Result := 'ARM';
    IMAGE_FILE_MACHINE_IA64:  Result := 'IA-64';
  else
    Result := Format('0x%.4x', [AMachine]);
  end;
end;

function MHExpectedExtensions(AKind: TMHBinaryKind): string;
begin
  case AKind of
    bkPE, bkMsDos: Result := PE_EXTENSIONS;
    bkElf:    Result := '.so;.elf;.o;.ko;.bin';
    bkMachO:  Result := '.dylib;.bundle;.o';
    bkZip:    Result := '.zip;.jar;.apk;.docx;.xlsx;.pptx;.docm;.xlsm;.odt;.ods;.odp;.vsix;.nupkg;' +
      '.appx;.msix;.xpi;.epub;.whl;.kmz;.3mf;.crx';
    bkRar:    Result := '.rar';
    bk7z:     Result := '.7z';
    bkGzip:   Result := '.gz;.tgz';
    bkCab:    Result := '.cab;.msu';
    bkOle:    Result := '.doc;.xls;.ppt;.msi;.msp;.mst;.msg;.vsd;.pub';
    bkPdf:    Result := '.pdf';
    bkPng:    Result := '.png';
    bkJpeg:   Result := '.jpg;.jpeg;.jpe;.jfif';
    bkGif:    Result := '.gif';
    bkBmp:    Result := '.bmp;.dib';
    bkIco:    Result := '.ico;.cur';
    bkScript: Result := SCRIPT_EXTENSIONS;
    bkText:   Result := TEXT_EXTENSIONS + ';' + SCRIPT_EXTENSIONS;
  else
    Result := '';
  end;
end;

function MHExtensionInList(const AExtension, AList: string): Boolean;
var
  LItem: string;
begin
  if AExtension = '' then
    Exit(False);
  for LItem in AList.Split([';']) do
    if SameText(LItem, AExtension) then
      Exit(True);
  Result := False;
end;

function KnownExtension(const AExtension: string): Boolean;
var
  LKind: TMHBinaryKind;
begin
  for LKind := Low(TMHBinaryKind) to High(TMHBinaryKind) do
    if MHExtensionInList(AExtension, MHExpectedExtensions(LKind)) then
      Exit(True);
  Result := False;
end;

function MHProbePe(AReader: TMHBinaryReader; AOffset: Int64; out AInfo: TMHPeQuickInfo): Boolean;
var
  LLfanew, LSignature, LRawSize, LRawOffset, LHeaders: Cardinal;
  LPe, LOptional, LSectionTable, LEnd: Int64;
  LMachine, LSections, LOptionalSize, LMagic, LCharacteristics, LSubsystem: Word;
  I: Integer;
begin
  AInfo := Default(TMHPeQuickInfo);
  Result := False;
  if not AReader.MatchesAt(AOffset, [$4D, $5A]) then
    Exit;
  if not AReader.TryReadDWord(AOffset + $3C, LLfanew) or (LLfanew < $40) or (LLfanew > MH_MAX_LFANEW) then
    Exit;
  LPe := AOffset + LLfanew;
  if not AReader.TryReadDWord(LPe, LSignature) or (LSignature <> $00004550) then
    Exit;
  if not AReader.TryReadWord(LPe + 4, LMachine) or not AReader.TryReadWord(LPe + 6, LSections) or
     not AReader.TryReadWord(LPe + 20, LOptionalSize) or not AReader.TryReadWord(LPe + 22, LCharacteristics) then
    Exit;
  LOptional := LPe + 24;
  if not AReader.TryReadWord(LOptional, LMagic) or ((LMagic <> $10B) and (LMagic <> $20B)) then
    Exit;
  AInfo.Is64 := LMagic = $20B;
  AInfo.Machine := LMachine;
  if AReader.TryReadWord(LOptional + 68, LSubsystem) then
    AInfo.Subsystem := LSubsystem;
  if AInfo.Subsystem = IMAGE_SUBSYSTEM_NATIVE then
    AInfo.Kind := pkDriver
  else if LCharacteristics and IMAGE_FILE_DLL <> 0 then
    AInfo.Kind := pkDll
  else
    AInfo.Kind := pkExe;
  // Конец образа в файле — по таблице секций (не больше 96 секций по спецификации).
  LSectionTable := LOptional + LOptionalSize;
  LEnd := LSectionTable + Int64(Min(LSections, 96)) * 40;
  if AReader.TryReadDWord(LOptional + 60, LHeaders) then
    LEnd := Max(LEnd, LPe - LLfanew + LHeaders);
  for I := 0 to Min(LSections, 96) - 1 do
    if AReader.TryReadDWord(LSectionTable + I * 40 + 16, LRawSize) and
       AReader.TryReadDWord(LSectionTable + I * 40 + 20, LRawOffset) and (LRawSize > 0) then
      LEnd := Max(LEnd, AOffset + Int64(LRawOffset) + LRawSize);
  AInfo.ImageEnd := LEnd;
  Result := True;
end;

function PeDescription(const AInfo: TMHPeQuickInfo): string;
begin
  Result := Format(MHL('Исполняемый файл Windows %s — %s', 'Windows executable %s — %s'),
    [MHMachineName(AInfo.Machine), MHPeKindTitle(AInfo.Kind)]);
end;

function IsTextByte(AByte: Byte): Boolean;
begin
  Result := (AByte in [9, 10, 13]) or (AByte >= $20) and (AByte <> $7F);
end;

/// Похоже ли начало файла на текст (без нулевых байтов, почти всё печатаемое).
function LooksLikeText(const AData: TBytes; out AText: string): Boolean;
var
  I, LPrintable, LStart: Integer;
begin
  AText := '';
  if Length(AData) = 0 then
    Exit(False);
  // UTF-16 с меткой порядка байтов.
  if (Length(AData) >= 2) and (AData[0] = $FF) and (AData[1] = $FE) then
  begin
    SetLength(AText, (Length(AData) - 2) div 2);
    if AText <> '' then
      Move(AData[2], AText[1], Length(AText) * 2);
    Exit(True);
  end;
  LStart := 0;
  if (Length(AData) >= 3) and (AData[0] = $EF) and (AData[1] = $BB) and (AData[2] = $BF) then
    LStart := 3;
  LPrintable := 0;
  for I := LStart to High(AData) do
  begin
    if AData[I] = 0 then
      Exit(False);
    if IsTextByte(AData[I]) then
      Inc(LPrintable);
  end;
  Result := (Length(AData) - LStart > 0) and (LPrintable >= (Length(AData) - LStart) * 0.95);
  if Result then
    AText := TEncoding.UTF8.GetString(AData, LStart, Length(AData) - LStart);
end;

function LooksLikeScript(const AText: string): Boolean;
const
  MARKERS: array[0..15] of string = ('@echo off', 'powershell', 'param(', 'set-executionpolicy',
    'invoke-expression', 'iex ', 'wscript.', 'createobject(', 'cscript', '<script', 'cmd /c',
    'cmd.exe /c', 'start-process', 'new-object ', 'function ', 'dim ');
var
  LLower: string;
  LMarker: string;
begin
  if AText.StartsWith('#!') then
    Exit(True);
  LLower := AText.ToLower;
  for LMarker in MARKERS do
    if LLower.Contains(LMarker) then
      Exit(True);
  Result := False;
end;

function MHIdentifyAt(AReader: TMHBinaryReader; AOffset: Int64; AStrict: Boolean;
  out AKind: TMHBinaryKind; out ADescription: string; out ASize: Int64): Boolean;
var
  LPe: TMHPeQuickInfo;
  LWord: Word;
  LDWord, LDWord2: Cardinal;
  LByte: Byte;
  LHead: TBytes;
  LText: string;
begin
  AKind := bkUnknown;
  ADescription := '';
  ASize := -1;
  Result := True;
  if AReader.MatchesAt(AOffset, [$4D, $5A]) then
  begin
    if MHProbePe(AReader, AOffset, LPe) then
    begin
      AKind := bkPE;
      ADescription := PeDescription(LPe);
      ASize := LPe.ImageEnd - AOffset;
      Exit;
    end;
    if not AStrict then
    begin
      AKind := bkMsDos;
      ADescription := MHBinaryKindTitle(bkMsDos);
      Exit;
    end;
  end
  else if AReader.MatchesAt(AOffset, [$7F, $45, $4C, $46]) and AReader.TryReadByte(AOffset + 4, LByte) and
    (LByte in [1, 2]) then
  begin
    AKind := bkElf;
    ADescription := MHBinaryKindTitle(bkElf) + IfThen(LByte = 2, ' 64-bit', ' 32-bit');
    Exit;
  end
  else if (AReader.MatchesAt(AOffset, [$FE, $ED, $FA, $CE]) or AReader.MatchesAt(AOffset, [$FE, $ED, $FA, $CF]) or
    AReader.MatchesAt(AOffset, [$CE, $FA, $ED, $FE]) or AReader.MatchesAt(AOffset, [$CF, $FA, $ED, $FE])) then
  begin
    AKind := bkMachO;
    ADescription := MHBinaryKindTitle(bkMachO);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$50, $4B, $03, $04]) then
  begin
    // Локальный заголовок ZIP: версия для распаковки разумная, метод сжатия известный.
    if not AStrict or (AReader.TryReadWord(AOffset + 4, LWord) and (LWord <= 100) and
       AReader.TryReadWord(AOffset + 8, LWord) and (LWord in [0, 8, 9, 12, 14, 93, 95, 98, 99])) then
    begin
      AKind := bkZip;
      ADescription := MHBinaryKindTitle(bkZip);
      Exit;
    end;
  end
  else if not AStrict and AReader.MatchesAt(AOffset, [$50, $4B, $05, $06]) then
  begin
    AKind := bkZip;
    ADescription := MHBinaryKindTitle(bkZip);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$52, $61, $72, $21, $1A, $07]) then
  begin
    AKind := bkRar;
    ADescription := MHBinaryKindTitle(bkRar);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$37, $7A, $BC, $AF, $27, $1C]) then
  begin
    AKind := bk7z;
    ADescription := MHBinaryKindTitle(bk7z);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$1F, $8B, $08]) then
  begin
    // Флаги GZIP: старшие три бита зарезервированы и должны быть нулевыми.
    if AReader.TryReadByte(AOffset + 3, LByte) and (LByte and $E0 = 0) then
    begin
      AKind := bkGzip;
      ADescription := MHBinaryKindTitle(bkGzip);
      Exit;
    end;
  end
  else if AReader.MatchesAt(AOffset, [$4D, $53, $43, $46]) then
  begin
    // CAB: зарезервированное поле нулевое, размер архива не меньше заголовка.
    if AReader.TryReadDWord(AOffset + 4, LDWord) and (LDWord = 0) and
       AReader.TryReadDWord(AOffset + 8, LDWord2) and (LDWord2 >= 36) then
    begin
      AKind := bkCab;
      ADescription := MHBinaryKindTitle(bkCab);
      ASize := LDWord2;
      Exit;
    end;
  end
  else if AReader.MatchesAt(AOffset, [$D0, $CF, $11, $E0, $A1, $B1, $1A, $E1]) then
  begin
    AKind := bkOle;
    ADescription := MHBinaryKindTitle(bkOle);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$25, $50, $44, $46, $2D]) then
  begin
    AKind := bkPdf;
    ADescription := MHBinaryKindTitle(bkPdf);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$89, $50, $4E, $47, $0D, $0A, $1A, $0A]) then
  begin
    AKind := bkPng;
    ADescription := MHBinaryKindTitle(bkPng);
    Exit;
  end
  else if AReader.MatchesAt(AOffset, [$FF, $D8, $FF]) then
  begin
    // В середине файла FF D8 FF встречается случайно — нужен маркер APP0/APP1/DQT.
    if not AStrict or (AReader.TryReadByte(AOffset + 3, LByte) and (LByte in [$E0, $E1, $DB, $EE])) then
    begin
      AKind := bkJpeg;
      ADescription := MHBinaryKindTitle(bkJpeg);
      Exit;
    end;
  end
  else if AReader.MatchesAt(AOffset, [$47, $49, $46, $38, $37, $61]) or
    AReader.MatchesAt(AOffset, [$47, $49, $46, $38, $39, $61]) then
  begin
    AKind := bkGif;
    ADescription := MHBinaryKindTitle(bkGif);
    Exit;
  end;

  if not AStrict then
  begin
    if AReader.MatchesAt(AOffset, [$42, $4D]) and AReader.TryReadDWord(AOffset + 2, LDWord) and
       (LDWord >= 26) and (Int64(LDWord) <= AReader.Size - AOffset) and AReader.TryReadDWord(AOffset + 6, LDWord2) and
       (LDWord2 = 0) then
    begin
      AKind := bkBmp;
      ADescription := MHBinaryKindTitle(bkBmp);
      ASize := LDWord;
      Exit;
    end;
    if AReader.MatchesAt(AOffset, [0, 0, 1, 0]) and AReader.TryReadWord(AOffset + 4, LWord) and
       (LWord in [1..64]) then
    begin
      AKind := bkIco;
      ADescription := MHBinaryKindTitle(bkIco);
      Exit;
    end;
    LHead := AReader.ReadBytes(AOffset, 4096);
    if LooksLikeText(LHead, LText) then
    begin
      if LooksLikeScript(LText) then
        AKind := bkScript
      else
        AKind := bkText;
      ADescription := MHBinaryKindTitle(AKind);
      Exit;
    end;
  end;
  Result := False;
end;

function MHDetectBinaryType(AReader: TMHBinaryReader; const AFileName: string): TMHBinaryTypeInfo;
var
  LSize: Int64;
  LPe: TMHPeQuickInfo;
begin
  Result := Default(TMHBinaryTypeInfo);
  Result.Extension := ExtractFileExt(AFileName).ToLower;
  if AReader.Size = 0 then
  begin
    Result.Kind := bkEmpty;
    Result.Description := MHBinaryKindTitle(bkEmpty);
    Exit;
  end;
  if not MHIdentifyAt(AReader, 0, False, Result.Kind, Result.Description, LSize) then
  begin
    Result.Kind := bkUnknown;
    Result.Description := MHBinaryKindTitle(bkUnknown);
  end;
  if (Result.Kind = bkPE) and MHProbePe(AReader, 0, LPe) then
    Result.PeKind := LPe.Kind;
  // Текст с расширением сценария — сценарий, даже без характерных команд.
  if (Result.Kind = bkText) and MHExtensionInList(Result.Extension, SCRIPT_EXTENSIONS) then
  begin
    Result.Kind := bkScript;
    Result.Description := MHBinaryKindTitle(bkScript);
  end;
  Result.ExpectedExtensions := MHExpectedExtensions(Result.Kind);
  if Result.Extension <> '' then
    case Result.Kind of
      bkPE, bkMsDos, bkElf, bkMachO:
        Result.ExtensionMismatch := not MHExtensionInList(Result.Extension, Result.ExpectedExtensions);
      bkUnknown, bkEmpty, bkText:
        Result.ExtensionMismatch := False;
    else
      Result.ExtensionMismatch := KnownExtension(Result.Extension) and
        not MHExtensionInList(Result.Extension, Result.ExpectedExtensions);
    end;
end;

end.
