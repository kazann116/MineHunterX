unit MineHunter.Tests.PeBuilder;

{
  Построитель синтетических PE-файлов для тестов BinaryLab. Файлы собираются
  в памяти по спецификации PE/COFF (PE32 и PE32+): заголовки, секции,
  импорт (в том числе по порядковым номерам), экспорт (с переадресацией),
  ресурсы (дерево тип → имя → язык), TLS с функциями обратного вызова,
  каталог CLR, оверлей и данные подписи. Повреждения тесты вносят в готовые
  байты (Poke*), используя смещения из свойств построителя.

  Код построителя не зависит от BinaryLab: тест сверяет разбор с тем, что
  было записано, а не с другой реализацией того же разбора.
}

interface

uses
  System.SysUtils, System.Generics.Collections;

const
  SCN_CODE = $00000020;
  SCN_IDATA = $00000040;
  SCN_EXEC = $20000000;
  SCN_READ = $40000000;
  SCN_WRITE = $80000000;
  SCN_TEXT = SCN_CODE or SCN_EXEC or SCN_READ;
  SCN_RDATA = SCN_IDATA or SCN_READ;
  SCN_DATA = SCN_IDATA or SCN_READ or SCN_WRITE;

  TEST_FILE_ALIGN = $200;
  TEST_SECTION_ALIGN = $1000;

  RT_ICON_ID = 3;
  RT_RCDATA_ID = 10;
  RT_VERSION_ID = 16;
  RT_MANIFEST_ID = 24;

type
  TTestPeSection = record
    Name: string;
    Data: TBytes;
    /// 0 — равен длине данных.
    VirtualSize: Cardinal;
    Characteristics: Cardinal;
  end;

  TTestPeImport = record
    Dll: string;
    /// «#12» — импорт по порядковому номеру.
    Functions: TArray<string>;
  end;

  TTestPeResource = record
    TypeId: Word;
    NameId: Word;
    Language: Word;
    Data: TBytes;
  end;

  TTestPeBuilder = class
  private
    FSections: TList<TTestPeSection>;
    FImports: TList<TTestPeImport>;
    FExportNames: TList<string>;
    FExportForwarders: TList<string>;
    FResources: TList<TTestPeResource>;
    FPeOffset: Integer;
    FSectionTableOffset: Integer;
    FOptionalOffset: Integer;
    FRawOffsets: TList<Cardinal>;
    FRvas: TList<Cardinal>;
    FSectionNames: TList<string>;
    FImageEnd: Integer;
    FCertificateOffset: Integer;
  public
    Is64: Boolean;
    Dll: Boolean;
    Machine: Word;
    Subsystem: Word;
    TimeDateStamp: Cardinal;
    /// 0 — начало первой исполняемой секции.
    EntryPointRva: Cardinal;
    ExportDllName: string;
    TlsCallbackCount: Integer;
    DotNet: Boolean;
    Overlay: TBytes;
    Certificate: TBytes;
    /// Записать правильную контрольную сумму (иначе 0).
    WriteChecksum: Boolean;
    constructor Create(AIs64: Boolean = True);
    destructor Destroy; override;
    procedure AddSection(const AName: string; const AData: TBytes; ACharacteristics: Cardinal;
      AVirtualSize: Cardinal = 0);
    procedure AddImport(const ADll: string; const AFunctions: array of string);
    /// AForwarder — «KERNEL32.Sleep» для переадресации ('' — обычная функция).
    procedure AddExport(const AName: string; const AForwarder: string = '');
    procedure AddResource(ATypeId, ANameId, ALanguage: Word; const AData: TBytes);
    function Build: TBytes;
    /// Смещения последнего Build.
    property PeOffset: Integer read FPeOffset;
    property OptionalOffset: Integer read FOptionalOffset;
    property SectionTableOffset: Integer read FSectionTableOffset;
    /// Конец данных образа (начало оверлея).
    property ImageEnd: Integer read FImageEnd;
    property CertificateOffset: Integer read FCertificateOffset;
    function SectionRawOffset(const AName: string): Cardinal;
    function SectionRva(const AName: string): Cardinal;
  end;

/// Простой код x64 (пролог, вызовы, возврат) — для секции .text.
function TestCodeBytes(ASize: Integer): TBytes;
/// Псевдослучайные байты (энтропия около 8) с фиксированным начальным числом.
function TestRandomBytes(ASize: Integer; ASeed: Cardinal = 12345): TBytes;
/// Байты строки ASCII (без завершающего нуля).
function TestAscii(const AText: string): TBytes;
/// Байты строки UTF-16LE (без завершающего нуля).
function TestUtf16(const AText: string): TBytes;
/// Массив байтов из перечисления (внутри TestConcat литерал [..] был бы множеством).
function TestBytes(const AValues: array of Byte): TBytes;
/// Склеивает массивы байтов.
function TestConcat(const AParts: array of TBytes): TBytes;
/// Минимальная корректная DLL x64 с импортом и экспортом.
function TestMinimalPe(AIs64: Boolean = True): TBytes;

procedure PokeWord(var AData: TBytes; AOffset: Integer; AValue: Word);
procedure PokeDWord(var AData: TBytes; AOffset: Integer; AValue: Cardinal);
function PeekDWord(const AData: TBytes; AOffset: Integer): Cardinal;

implementation

uses
  System.Math;

type
  TBuf = class
  private
    FData: TBytes;
    FSize: Integer;
    procedure Ensure(ASize: Integer);
  public
    procedure PutByte(AOffset: Integer; AValue: Byte);
    procedure PutWord(AOffset: Integer; AValue: Word);
    procedure PutDWord(AOffset: Integer; AValue: Cardinal);
    procedure PutQWord(AOffset: Integer; AValue: UInt64);
    procedure PutBytes(AOffset: Integer; const AValue: TBytes);
    procedure PutAnsiZ(AOffset: Integer; const AValue: string);
    function Align(AValue: Integer): Integer;
    function ToBytes: TBytes;
    property Size: Integer read FSize;
  end;

function AlignUp(AValue, AAlign: Cardinal): Cardinal;
begin
  Result := (AValue + AAlign - 1) div AAlign * AAlign;
end;

{ TBuf }

procedure TBuf.Ensure(ASize: Integer);
begin
  if ASize > Length(FData) then
    SetLength(FData, Max(ASize, Length(FData) * 2 + 256));
  if ASize > FSize then
  begin
    FillChar(FData[FSize], ASize - FSize, 0);
    FSize := ASize;
  end;
end;

procedure TBuf.PutByte(AOffset: Integer; AValue: Byte);
begin
  Ensure(AOffset + 1);
  FData[AOffset] := AValue;
end;

procedure TBuf.PutWord(AOffset: Integer; AValue: Word);
begin
  Ensure(AOffset + 2);
  Move(AValue, FData[AOffset], 2);
end;

procedure TBuf.PutDWord(AOffset: Integer; AValue: Cardinal);
begin
  Ensure(AOffset + 4);
  Move(AValue, FData[AOffset], 4);
end;

procedure TBuf.PutQWord(AOffset: Integer; AValue: UInt64);
begin
  Ensure(AOffset + 8);
  Move(AValue, FData[AOffset], 8);
end;

procedure TBuf.PutBytes(AOffset: Integer; const AValue: TBytes);
begin
  Ensure(AOffset + Length(AValue));
  if Length(AValue) > 0 then
    Move(AValue[0], FData[AOffset], Length(AValue));
end;

procedure TBuf.PutAnsiZ(AOffset: Integer; const AValue: string);
begin
  PutBytes(AOffset, TestAscii(AValue));
  PutByte(AOffset + Length(AValue), 0);
end;

function TBuf.Align(AValue: Integer): Integer;
begin
  Result := AlignUp(FSize, AValue);
  Ensure(Result);
end;

function TBuf.ToBytes: TBytes;
begin
  Result := Copy(FData, 0, FSize);
end;

{ Функции }

function TestCodeBytes(ASize: Integer): TBytes;
const
  // push rbp; mov rbp,rsp; sub rsp,20h; call rel32; xor eax,eax; add rsp,20h; pop rbp; ret
  PATTERN: array[0..21] of Byte = ($55, $48, $89, $E5, $48, $83, $EC, $20, $E8, $10, $00, $00, $00,
    $31, $C0, $48, $83, $C4, $20, $5D, $C3, $CC);
var
  I: Integer;
begin
  SetLength(Result, ASize);
  for I := 0 to ASize - 1 do
    Result[I] := PATTERN[I mod Length(PATTERN)];
end;

function TestRandomBytes(ASize: Integer; ASeed: Cardinal): TBytes;
var
  I: Integer;
  LState: Cardinal;
begin
  SetLength(Result, ASize);
  LState := ASeed;
  for I := 0 to ASize - 1 do
  begin
    // xorshift32
    LState := LState xor (LState shl 13);
    LState := LState xor (LState shr 17);
    LState := LState xor (LState shl 5);
    Result[I] := Byte(LState shr 8);
  end;
end;

function TestAscii(const AText: string): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(AText));
  for I := 1 to Length(AText) do
    Result[I - 1] := Byte(Ord(AText[I]) and $FF);
end;

function TestUtf16(const AText: string): TBytes;
begin
  SetLength(Result, Length(AText) * 2);
  if AText <> '' then
    Move(AText[1], Result[0], Length(Result));
end;

function TestBytes(const AValues: array of Byte): TBytes;
begin
  SetLength(Result, Length(AValues));
  if Length(AValues) > 0 then
    Move(AValues[0], Result[0], Length(AValues));
end;

function TestConcat(const AParts: array of TBytes): TBytes;
var
  LPart: TBytes;
  LPos: Integer;
begin
  LPos := 0;
  for LPart in AParts do
    Inc(LPos, Length(LPart));
  SetLength(Result, LPos);
  LPos := 0;
  for LPart in AParts do
    if Length(LPart) > 0 then
    begin
      Move(LPart[0], Result[LPos], Length(LPart));
      Inc(LPos, Length(LPart));
    end;
end;

procedure PokeWord(var AData: TBytes; AOffset: Integer; AValue: Word);
begin
  Move(AValue, AData[AOffset], 2);
end;

procedure PokeDWord(var AData: TBytes; AOffset: Integer; AValue: Cardinal);
begin
  Move(AValue, AData[AOffset], 4);
end;

function PeekDWord(const AData: TBytes; AOffset: Integer): Cardinal;
begin
  Move(AData[AOffset], Result, 4);
end;

function TestMinimalPe(AIs64: Boolean): TBytes;
var
  LBuilder: TTestPeBuilder;
begin
  LBuilder := TTestPeBuilder.Create(AIs64);
  try
    LBuilder.Dll := True;
    LBuilder.AddSection('.text', TestCodeBytes(1024), SCN_TEXT);
    LBuilder.AddSection('.data', TestAscii('Hello from test data section'), SCN_DATA);
    LBuilder.AddImport('KERNEL32.dll', ['GetProcAddress', 'LoadLibraryW', 'Sleep']);
    LBuilder.AddExport('TestFunction');
    Result := LBuilder.Build;
  finally
    LBuilder.Free;
  end;
end;

{ TTestPeBuilder }

constructor TTestPeBuilder.Create(AIs64: Boolean);
begin
  inherited Create;
  FSections := TList<TTestPeSection>.Create;
  FImports := TList<TTestPeImport>.Create;
  FExportNames := TList<string>.Create;
  FExportForwarders := TList<string>.Create;
  FResources := TList<TTestPeResource>.Create;
  FRawOffsets := TList<Cardinal>.Create;
  FRvas := TList<Cardinal>.Create;
  FSectionNames := TList<string>.Create;
  Is64 := AIs64;
  if AIs64 then
    Machine := $8664
  else
    Machine := $014C;
  Subsystem := 2;
  TimeDateStamp := $65000000; // 2023 год
  ExportDllName := 'test.dll';
end;

destructor TTestPeBuilder.Destroy;
begin
  FSections.Free;
  FImports.Free;
  FExportNames.Free;
  FExportForwarders.Free;
  FResources.Free;
  FRawOffsets.Free;
  FRvas.Free;
  FSectionNames.Free;
  inherited;
end;

procedure TTestPeBuilder.AddSection(const AName: string; const AData: TBytes; ACharacteristics,
  AVirtualSize: Cardinal);
var
  LSection: TTestPeSection;
begin
  LSection.Name := AName;
  LSection.Data := AData;
  LSection.Characteristics := ACharacteristics;
  LSection.VirtualSize := AVirtualSize;
  FSections.Add(LSection);
end;

procedure TTestPeBuilder.AddImport(const ADll: string; const AFunctions: array of string);
var
  LImport: TTestPeImport;
  I: Integer;
begin
  LImport.Dll := ADll;
  SetLength(LImport.Functions, Length(AFunctions));
  for I := 0 to High(AFunctions) do
    LImport.Functions[I] := AFunctions[I];
  FImports.Add(LImport);
end;

procedure TTestPeBuilder.AddExport(const AName, AForwarder: string);
begin
  FExportNames.Add(AName);
  FExportForwarders.Add(AForwarder);
end;

procedure TTestPeBuilder.AddResource(ATypeId, ANameId, ALanguage: Word; const AData: TBytes);
var
  LResource: TTestPeResource;
begin
  LResource.TypeId := ATypeId;
  LResource.NameId := ANameId;
  LResource.Language := ALanguage;
  LResource.Data := AData;
  FResources.Add(LResource);
end;

function TTestPeBuilder.SectionRawOffset(const AName: string): Cardinal;
var
  I: Integer;
begin
  for I := 0 to FSectionNames.Count - 1 do
    if FSectionNames[I] = AName then
      Exit(FRawOffsets[I]);
  raise EArgumentException.Create('Нет секции ' + AName);
end;

function TTestPeBuilder.SectionRva(const AName: string): Cardinal;
var
  I: Integer;
begin
  for I := 0 to FSectionNames.Count - 1 do
    if FSectionNames[I] = AName then
      Exit(FRvas[I]);
  raise EArgumentException.Create('Нет секции ' + AName);
end;

function TTestPeBuilder.Build: TBytes;
var
  LAll: TList<TTestPeSection>;
  LDirs: array[0..15] of record Rva, Size: Cardinal; end;
  LNextRva: Cardinal;
  LImageBase: UInt64;
  LThunk: Integer;

  function BuildImports(ARva: Cardinal): TBytes;
  var
    LBuf: TBuf;
    LDesc, LPos, I, J: Integer;
    LIlt, LNames: TArray<Integer>;
    LFunc: string;
    LValue: UInt64;
  begin
    LBuf := TBuf.Create;
    try
      LDesc := (FImports.Count + 1) * 20;
      LBuf.Align(1);
      LBuf.PutDWord(LDesc - 4, 0);
      SetLength(LIlt, FImports.Count);
      SetLength(LNames, FImports.Count);
      // Таблицы ILT и IAT (одинаковые), затем имена функций и библиотек.
      LPos := LDesc;
      for I := 0 to FImports.Count - 1 do
      begin
        LIlt[I] := LPos;
        Inc(LPos, (Length(FImports[I].Functions) + 1) * LThunk * 2);
      end;
      LBuf.PutByte(LPos, 0);
      for I := 0 to FImports.Count - 1 do
      begin
        for J := 0 to High(FImports[I].Functions) do
        begin
          LFunc := FImports[I].Functions[J];
          if LFunc.StartsWith('#') then
          begin
            if Is64 then
              LValue := UInt64($8000000000000000) or StrToInt(LFunc.Substring(1))
            else
              LValue := $80000000 or Cardinal(StrToInt(LFunc.Substring(1)));
          end
          else
          begin
            LPos := LBuf.Align(2);
            LBuf.PutWord(LPos, J);
            LBuf.PutAnsiZ(LPos + 2, LFunc);
            LValue := ARva + Cardinal(LPos);
          end;
          if Is64 then
          begin
            LBuf.PutQWord(LIlt[I] + J * 8, LValue);
            LBuf.PutQWord(LIlt[I] + (Length(FImports[I].Functions) + 1 + J) * 8, LValue);
          end
          else
          begin
            LBuf.PutDWord(LIlt[I] + J * 4, Cardinal(LValue));
            LBuf.PutDWord(LIlt[I] + (Length(FImports[I].Functions) + 1 + J) * 4, Cardinal(LValue));
          end;
        end;
        LNames[I] := LBuf.Size;
        LBuf.PutAnsiZ(LNames[I], FImports[I].Dll);
      end;
      for I := 0 to FImports.Count - 1 do
      begin
        LBuf.PutDWord(I * 20 + 0, ARva + Cardinal(LIlt[I]));
        LBuf.PutDWord(I * 20 + 12, ARva + Cardinal(LNames[I]));
        LBuf.PutDWord(I * 20 + 16, ARva + Cardinal(LIlt[I] + (Length(FImports[I].Functions) + 1) * LThunk));
      end;
      LDirs[1].Rva := ARva;
      LDirs[1].Size := LDesc;
      Result := LBuf.ToBytes;
    finally
      LBuf.Free;
    end;
  end;

  function BuildExports(ARva, ACodeRva: Cardinal): TBytes;
  var
    LBuf: TBuf;
    LCount, I, LEat, LNamePtrs, LOrdinals, LPos: Integer;
  begin
    LBuf := TBuf.Create;
    try
      LCount := FExportNames.Count;
      LEat := 40;
      LNamePtrs := LEat + LCount * 4;
      LOrdinals := LNamePtrs + LCount * 4;
      LBuf.PutByte(LOrdinals + LCount * 2, 0);
      LBuf.PutDWord(16, 1);                    // Base
      LBuf.PutDWord(20, LCount);               // NumberOfFunctions
      LBuf.PutDWord(24, LCount);               // NumberOfNames
      LBuf.PutDWord(28, ARva + Cardinal(LEat));
      LBuf.PutDWord(32, ARva + Cardinal(LNamePtrs));
      LBuf.PutDWord(36, ARva + Cardinal(LOrdinals));
      for I := 0 to LCount - 1 do
      begin
        LPos := LBuf.Size;
        LBuf.PutAnsiZ(LPos, FExportNames[I]);
        LBuf.PutDWord(LNamePtrs + I * 4, ARva + Cardinal(LPos));
        LBuf.PutWord(LOrdinals + I * 2, I);
        if FExportForwarders[I] <> '' then
        begin
          LPos := LBuf.Size;
          LBuf.PutAnsiZ(LPos, FExportForwarders[I]);
          LBuf.PutDWord(LEat + I * 4, ARva + Cardinal(LPos));
        end
        else
          LBuf.PutDWord(LEat + I * 4, ACodeRva + Cardinal(I * 16));
      end;
      LPos := LBuf.Size;
      LBuf.PutAnsiZ(LPos, ExportDllName);
      LBuf.PutDWord(12, ARva + Cardinal(LPos));
      LDirs[0].Rva := ARva;
      LDirs[0].Size := LBuf.Size;
      Result := LBuf.ToBytes;
    finally
      LBuf.Free;
    end;
  end;

  function BuildResources(ARva: Cardinal): TBytes;
  var
    LBuf: TBuf;
    LTypes: TList<Word>;
    LRes: TTestPeResource;
    LTypeDir, LNameDir, LLangDir, LEntry, LDataEntry, LData, I, J, LNamesOfType: Integer;
    LTypeDirs: TArray<Integer>;

    procedure PutDir(AOffset, AIdCount: Integer);
    begin
      LBuf.PutWord(AOffset + 14, AIdCount);
    end;

  begin
    LBuf := TBuf.Create;
    LTypes := TList<Word>.Create;
    try
      for LRes in FResources do
        if not LTypes.Contains(LRes.TypeId) then
          LTypes.Add(LRes.TypeId);
      // Корень: каталог типов.
      PutDir(0, LTypes.Count);
      SetLength(LTypeDirs, LTypes.Count);
      LTypeDir := 16 + LTypes.Count * 8;
      LBuf.PutByte(LTypeDir - 1, 0);
      for I := 0 to LTypes.Count - 1 do
      begin
        LNamesOfType := 0;
        for LRes in FResources do
          if LRes.TypeId = LTypes[I] then
            Inc(LNamesOfType);
        LTypeDirs[I] := LBuf.Size;
        LBuf.PutDWord(16 + I * 8, LTypes[I]);
        LBuf.PutDWord(16 + I * 8 + 4, $80000000 or Cardinal(LTypeDirs[I]));
        PutDir(LTypeDirs[I], LNamesOfType);
        LBuf.PutByte(LTypeDirs[I] + 16 + LNamesOfType * 8 - 1, 0);
        LEntry := 0;
        for J := 0 to FResources.Count - 1 do
          if FResources[J].TypeId = LTypes[I] then
          begin
            // Каталог имени → каталог языков (одна запись) → описание данных.
            LNameDir := LBuf.Size;
            LBuf.PutDWord(LTypeDirs[I] + 16 + LEntry * 8, FResources[J].NameId);
            LBuf.PutDWord(LTypeDirs[I] + 16 + LEntry * 8 + 4, $80000000 or Cardinal(LNameDir));
            PutDir(LNameDir, 1);
            LLangDir := LNameDir + 16;
            LDataEntry := LLangDir + 8;
            LBuf.PutDWord(LLangDir, FResources[J].Language);
            LBuf.PutDWord(LLangDir + 4, LDataEntry);
            LBuf.PutDWord(LDataEntry + 12, 0);
            LData := LBuf.Align(4);
            LBuf.PutBytes(LData, FResources[J].Data);
            LBuf.PutDWord(LDataEntry, ARva + Cardinal(LData));
            LBuf.PutDWord(LDataEntry + 4, Length(FResources[J].Data));
            Inc(LEntry);
          end;
      end;
      LDirs[2].Rva := ARva;
      LDirs[2].Size := LBuf.Size;
      Result := LBuf.ToBytes;
    finally
      LTypes.Free;
      LBuf.Free;
    end;
  end;

  function BuildTls(ARva, ACodeRva: Cardinal): TBytes;
  var
    LBuf: TBuf;
    LDirSize, LCallbacks, I: Integer;
  begin
    LBuf := TBuf.Create;
    try
      if Is64 then
        LDirSize := 40
      else
        LDirSize := 24;
      LCallbacks := AlignUp(LDirSize, 8);
      if Is64 then
      begin
        LBuf.PutQWord(24, LImageBase + ARva + Cardinal(LCallbacks));
        for I := 0 to TlsCallbackCount - 1 do
          LBuf.PutQWord(LCallbacks + I * 8, LImageBase + ACodeRva + Cardinal(I * 32));
        LBuf.PutQWord(LCallbacks + TlsCallbackCount * 8, 0);
      end
      else
      begin
        LBuf.PutDWord(12, Cardinal(LImageBase) + ARva + Cardinal(LCallbacks));
        for I := 0 to TlsCallbackCount - 1 do
          LBuf.PutDWord(LCallbacks + I * 4, Cardinal(LImageBase) + ACodeRva + Cardinal(I * 32));
        LBuf.PutDWord(LCallbacks + TlsCallbackCount * 4, 0);
      end;
      LDirs[9].Rva := ARva;
      LDirs[9].Size := LDirSize;
      Result := LBuf.ToBytes;
    finally
      LBuf.Free;
    end;
  end;

  procedure AddGenerated(const AName: string; const AData: TBytes; ACharacteristics: Cardinal);
  var
    LSection: TTestPeSection;
  begin
    LSection.Name := AName;
    LSection.Data := AData;
    LSection.Characteristics := ACharacteristics;
    LSection.VirtualSize := 0;
    LAll.Add(LSection);
    LNextRva := AlignUp(LNextRva + Max(1, Length(AData)), TEST_SECTION_ALIGN);
  end;

var
  LBuf: TBuf;
  LOptionalSize, LHeaders, I, LRaw, LDirBase: Integer;
  LCodeRva, LEntry, LSizeOfImage, LVSize, LSum, LCheckOffset: Cardinal;
  LSection: TTestPeSection;
  LName: TBytes;
  LResult: TBytes;
  LWord: Word;
  LTotal: UInt64;
begin
  FillChar(LDirs, SizeOf(LDirs), 0);
  FRawOffsets.Clear;
  FRvas.Clear;
  FSectionNames.Clear;
  if Is64 then
  begin
    LThunk := 8;
    LImageBase := $140000000;
    if Dll then
      LImageBase := $180000000;
    LOptionalSize := 240;
  end
  else
  begin
    LThunk := 4;
    LImageBase := $400000;
    if Dll then
      LImageBase := $10000000;
    LOptionalSize := 224;
  end;
  LAll := TList<TTestPeSection>.Create;
  LBuf := TBuf.Create;
  try
    FPeOffset := $80;
    FOptionalOffset := FPeOffset + 24;
    FSectionTableOffset := FOptionalOffset + LOptionalSize;
    // Число секций известно заранее: пользовательские + создаваемые.
    I := FSections.Count + Ord(FImports.Count > 0) + Ord(FExportNames.Count > 0) +
      Ord(FResources.Count > 0) + Ord(TlsCallbackCount > 0) + Ord(DotNet);
    LHeaders := AlignUp(FSectionTableOffset + I * 40, TEST_FILE_ALIGN);

    LNextRva := TEST_SECTION_ALIGN;
    LCodeRva := 0;
    for LSection in FSections do
    begin
      LAll.Add(LSection);
      if (LCodeRva = 0) and (LSection.Characteristics and SCN_EXEC <> 0) then
        LCodeRva := LNextRva;
      LVSize := LSection.VirtualSize;
      if LVSize = 0 then
        LVSize := Max(1, Length(LSection.Data));
      LNextRva := AlignUp(LNextRva + LVSize, TEST_SECTION_ALIGN);
    end;
    if LCodeRva = 0 then
      LCodeRva := TEST_SECTION_ALIGN;
    if FImports.Count > 0 then
      AddGenerated('.idata', BuildImports(LNextRva), SCN_RDATA or SCN_WRITE);
    if FExportNames.Count > 0 then
      AddGenerated('.edata', BuildExports(LNextRva, LCodeRva), SCN_RDATA);
    if FResources.Count > 0 then
      AddGenerated('.rsrc', BuildResources(LNextRva), SCN_RDATA);
    if TlsCallbackCount > 0 then
      AddGenerated('.tls', BuildTls(LNextRva, LCodeRva), SCN_DATA);
    if DotNet then
    begin
      LDirs[14].Rva := LNextRva;
      LDirs[14].Size := 72;
      AddGenerated('.cormeta', TestRandomBytes(72, 7), SCN_RDATA);
    end;

    // Заголовок MS-DOS.
    LBuf.PutWord(0, $5A4D);
    LBuf.PutDWord($3C, FPeOffset);
    LBuf.PutAnsiZ($40, 'This program cannot be run in DOS mode.');
    // Заголовок PE.
    LBuf.PutDWord(FPeOffset, $00004550);
    LBuf.PutWord(FPeOffset + 4, Machine);
    LBuf.PutWord(FPeOffset + 6, LAll.Count);
    LBuf.PutDWord(FPeOffset + 8, TimeDateStamp);
    LBuf.PutWord(FPeOffset + 20, LOptionalSize);
    LWord := $0002 or $0020; // EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE
    if Dll then
      LWord := LWord or $2000;
    LBuf.PutWord(FPeOffset + 22, LWord);
    // Дополнительный заголовок.
    if Is64 then
      LBuf.PutWord(FOptionalOffset, $20B)
    else
      LBuf.PutWord(FOptionalOffset, $10B);
    LBuf.PutByte(FOptionalOffset + 2, 14);
    LBuf.PutByte(FOptionalOffset + 3, 38);
    LEntry := EntryPointRva;
    if LEntry = 0 then
      LEntry := LCodeRva;
    LBuf.PutDWord(FOptionalOffset + 16, LEntry);
    LBuf.PutDWord(FOptionalOffset + 20, LCodeRva);
    if Is64 then
      LBuf.PutQWord(FOptionalOffset + 24, LImageBase)
    else
      LBuf.PutDWord(FOptionalOffset + 28, Cardinal(LImageBase));
    LBuf.PutDWord(FOptionalOffset + 32, TEST_SECTION_ALIGN);
    LBuf.PutDWord(FOptionalOffset + 36, TEST_FILE_ALIGN);
    LBuf.PutWord(FOptionalOffset + 40, 6);
    LBuf.PutWord(FOptionalOffset + 48, 6);
    LSizeOfImage := LNextRva;
    LBuf.PutDWord(FOptionalOffset + 56, LSizeOfImage);
    LBuf.PutDWord(FOptionalOffset + 60, LHeaders);
    LBuf.PutWord(FOptionalOffset + 68, Subsystem);
    LBuf.PutWord(FOptionalOffset + 70, $8160); // DYNAMIC_BASE, NX_COMPAT, TERMINAL_SERVER_AWARE, HIGH_ENTROPY_VA
    if Is64 then
      LDirBase := FOptionalOffset + 112
    else
      LDirBase := FOptionalOffset + 96;
    LBuf.PutDWord(LDirBase - 4, 16);

    // Таблица секций и данные.
    LRaw := LHeaders;
    LBuf.PutByte(LHeaders - 1, 0);
    LNextRva := TEST_SECTION_ALIGN;
    for I := 0 to LAll.Count - 1 do
    begin
      LSection := LAll[I];
      LVSize := LSection.VirtualSize;
      if LVSize = 0 then
        LVSize := Max(1, Length(LSection.Data));
      LName := TestAscii(Copy(LSection.Name, 1, 8));
      LBuf.PutBytes(FSectionTableOffset + I * 40, LName);
      LBuf.PutDWord(FSectionTableOffset + I * 40 + 8, LVSize);
      LBuf.PutDWord(FSectionTableOffset + I * 40 + 12, LNextRva);
      LBuf.PutDWord(FSectionTableOffset + I * 40 + 16, AlignUp(Length(LSection.Data), TEST_FILE_ALIGN));
      if Length(LSection.Data) > 0 then
        LBuf.PutDWord(FSectionTableOffset + I * 40 + 20, LRaw);
      LBuf.PutDWord(FSectionTableOffset + I * 40 + 36, LSection.Characteristics);
      FSectionNames.Add(LSection.Name);
      FRvas.Add(LNextRva);
      if Length(LSection.Data) > 0 then
      begin
        FRawOffsets.Add(LRaw);
        LBuf.PutBytes(LRaw, LSection.Data);
        LRaw := AlignUp(LRaw + Length(LSection.Data), TEST_FILE_ALIGN);
        LBuf.PutByte(LRaw - 1, 0);
      end
      else
        FRawOffsets.Add(0);
      LNextRva := AlignUp(LNextRva + LVSize, TEST_SECTION_ALIGN);
    end;
    FImageEnd := LRaw;
    // Оверлей и подпись (каталог безопасности указывает смещение в файле).
    LBuf.PutBytes(LRaw, Overlay);
    LRaw := LRaw + Length(Overlay);
    FCertificateOffset := 0;
    if Length(Certificate) > 0 then
    begin
      LRaw := AlignUp(LRaw, 8);
      FCertificateOffset := LRaw;
      LBuf.PutDWord(LRaw, 8 + Length(Certificate));
      LBuf.PutWord(LRaw + 4, $0200);
      LBuf.PutWord(LRaw + 6, $0002);
      LBuf.PutBytes(LRaw + 8, Certificate);
      LDirs[4].Rva := LRaw;
      LDirs[4].Size := 8 + Length(Certificate);
    end;
    for I := 0 to 15 do
    begin
      LBuf.PutDWord(LDirBase + I * 8, LDirs[I].Rva);
      LBuf.PutDWord(LDirBase + I * 8 + 4, LDirs[I].Size);
    end;
    LResult := LBuf.ToBytes;
    if WriteChecksum then
    begin
      // Алгоритм CheckSumMappedFile: сумма 16-битных слов с переносом, без поля CheckSum, плюс длина.
      LCheckOffset := FOptionalOffset + 64;
      LTotal := 0;
      I := 0;
      while I < Length(LResult) do
      begin
        if (Cardinal(I) <> LCheckOffset) and (Cardinal(I) <> LCheckOffset + 2) then
        begin
          if I + 1 < Length(LResult) then
            LTotal := LTotal + LResult[I] + Cardinal(LResult[I + 1]) shl 8
          else
            LTotal := LTotal + LResult[I];
          LTotal := (LTotal and $FFFF) + (LTotal shr 16);
        end;
        Inc(I, 2);
      end;
      LTotal := (LTotal and $FFFF) + (LTotal shr 16);
      LSum := Cardinal(LTotal and $FFFF) + Cardinal(Length(LResult));
      PokeDWord(LResult, LCheckOffset, LSum);
    end;
    Result := LResult;
  finally
    LBuf.Free;
    LAll.Free;
  end;
end;

end.
