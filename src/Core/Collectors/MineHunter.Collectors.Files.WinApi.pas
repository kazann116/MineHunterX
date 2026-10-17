unit MineHunter.Collectors.Files.WinApi;

{
  Реализация IMHFileApi на документированных функциях Windows.

  SHA-256: потоковое чтение блоками по 1 МБ, хеш System.Hash.THashSHA2.
  Файл открывается с FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
  чтобы читались и образы запущенных процессов.

  Подпись: WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) без интерфейса
  пользователя. Сначала проверяется встроенная подпись Authenticode; если её
  нет — подпись каталога Windows (CryptCATAdmin*: хеш SHA-256, затем SHA-1
  для старых каталогов). Так проверяются системные файлы, которые подписаны
  только через каталоги (notepad.exe, kernel32.dll и т.п.).

  Приватность: сеть не используется. Отзыв сертификатов не проверяется
  (WTD_REVOKE_NONE), загрузка CRL/AIA разрешена только из локального кеша
  (WTD_CACHE_ONLY_URL_RETRIEVAL).

  Объявления. Из Winapi.Windows (Delphi 12) используются уже объявленные там
  WINTRUST_DATA, WINTRUST_FILE_INFO, WINTRUST_CATALOG_INFO, WinVerifyTrust,
  константы WTD_*, TRUST_E_*, CERT_E_* и CERT_CONTEXT — они соответствуют
  wintrust.h и wincrypt.h. Недостающие структуры и функции (mscat.h, wintrust.h,
  wincrypt.h, bcrypt.h) объявлены ниже; размеры записей для Win64 сверяются
  при компиляции.

  Каждый открытый дескриптор и контекст освобождается в finally.
}

interface

uses
  MineHunter.Core.Types, MineHunter.Collectors.Files;

type
  TMHWinFileApi = class(TInterfacedObject, IMHFileApi)
  public
    function GetFileStamp(const APath: string; out ASize: Int64;
      out ALastWriteUtc: TDateTime): Boolean;
    function ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
    function VerifySignature(const APath: string; out AState: TMHSignatureState;
      out ASigner, ASource, AError: string): Boolean;
    function TickMs: UInt64;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Hash;

const
  WINTRUST_DLL = 'wintrust.dll';
  CRYPT32_DLL = 'crypt32.dll';

  // winerror.h — отсутствуют в Winapi.Windows.
  TRUST_E_CERT_SIGNATURE = HRESULT($80096004);
  TRUST_E_BAD_DIGEST = HRESULT($80096010);

  // wincrypt.h
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

  // bcrypt.h
  BCRYPT_SHA256_ALGORITHM = 'SHA256';

  HASH_BUFFER_SIZE = 1024 * 1024;
  MAX_HASH_BYTES = 64;

type
  // mscat.h
  HCATINFO = THandle;

  CATALOG_INFO_ = record
    cbStruct: DWORD;
    wszCatalogFile: array[0..MAX_PATH - 1] of WideChar;
  end;
  CATALOG_INFO = CATALOG_INFO_;
  PCATALOG_INFO = ^CATALOG_INFO;

  // wintrust.h
  CRYPT_PROVIDER_CERT = record
    cbStruct: DWORD;
    pCert: PCCERT_CONTEXT;
    fCommercial: BOOL;
    fTrustedRoot: BOOL;
    fSelfSigned: BOOL;
    fTestCert: BOOL;
    dwRevokedReason: DWORD;
    dwConfidence: DWORD;
    dwError: DWORD;
    pTrustListContext: Pointer;   // CTL_CONTEXT *
    fTrustListSignerCert: BOOL;
    pCtlContext: Pointer;         // PCCTL_CONTEXT
    dwCtlError: DWORD;
    fIsCyclic: BOOL;
    pChainElement: Pointer;       // PCERT_CHAIN_ELEMENT
  end;
  PCRYPT_PROVIDER_CERT = ^CRYPT_PROVIDER_CERT;

  // wintrust.h
  CRYPT_PROVIDER_SGNR = record
    cbStruct: DWORD;
    sftVerifyAsOf: TFileTime;
    csCertChain: DWORD;
    pasCertChain: PCRYPT_PROVIDER_CERT;
    dwSignerType: DWORD;
    psSigner: Pointer;            // CMSG_SIGNER_INFO *
    dwError: DWORD;
    csCounterSigners: DWORD;
    pasCounterSigners: Pointer;   // struct _CRYPT_PROVIDER_SGNR *
    pChainContext: Pointer;       // PCCERT_CHAIN_CONTEXT
  end;
  PCRYPT_PROVIDER_SGNR = ^CRYPT_PROVIDER_SGNR;

  /// CRYPT_PROVIDER_DATA используется только как непрозрачный указатель.
  PCRYPT_PROVIDER_DATA = Pointer;

{$IFDEF CPUX64}
  // Сверка раскладки с Windows SDK (x64).
  {$IF SizeOf(CATALOG_INFO) <> 524} {$MESSAGE ERROR 'CATALOG_INFO: неверный размер'} {$ENDIF}
  {$IF SizeOf(CRYPT_PROVIDER_CERT) <> 88} {$MESSAGE ERROR 'CRYPT_PROVIDER_CERT: неверный размер'} {$ENDIF}
  {$IF SizeOf(CRYPT_PROVIDER_SGNR) <> 64} {$MESSAGE ERROR 'CRYPT_PROVIDER_SGNR: неверный размер'} {$ENDIF}
  {$IF SizeOf(WINTRUST_DATA) <> 88} {$MESSAGE ERROR 'WINTRUST_DATA: неверный размер'} {$ENDIF}
  {$IF SizeOf(WINTRUST_FILE_INFO) <> 32} {$MESSAGE ERROR 'WINTRUST_FILE_INFO: неверный размер'} {$ENDIF}
  {$IF SizeOf(WINTRUST_CATALOG_INFO) <> 72} {$MESSAGE ERROR 'WINTRUST_CATALOG_INFO: неверный размер'} {$ENDIF}
{$ENDIF}

// mscat.h (CryptCATAdminAcquireContext2 и CryptCATAdminCalcHashFromFileHandle2 — Windows 8+)
function CryptCATAdminAcquireContext2(var phCatAdmin: HCATADMIN; pgSubsystem: PGUID;
  pwszHashAlgorithm: PWideChar; pStrongHashPolicy: Pointer; dwFlags: DWORD): BOOL; stdcall;
  external WINTRUST_DLL name 'CryptCATAdminAcquireContext2';
function CryptCATAdminCalcHashFromFileHandle2(hCatAdmin: HCATADMIN; hFile: THandle;
  var pcbHash: DWORD; pbHash: PByte; dwFlags: DWORD): BOOL; stdcall;
  external WINTRUST_DLL name 'CryptCATAdminCalcHashFromFileHandle2';
function CryptCATAdminEnumCatalogFromHash(hCatAdmin: HCATADMIN; pbHash: PByte; cbHash: DWORD;
  dwFlags: DWORD; phPrevCatInfo: Pointer): HCATINFO; stdcall;
  external WINTRUST_DLL name 'CryptCATAdminEnumCatalogFromHash';
function CryptCATCatalogInfoFromContext(hCatInfo: HCATINFO; psCatInfo: PCATALOG_INFO;
  dwFlags: DWORD): BOOL; stdcall;
  external WINTRUST_DLL name 'CryptCATCatalogInfoFromContext';
function CryptCATAdminReleaseCatalogContext(hCatAdmin: HCATADMIN; hCatInfo: HCATINFO;
  dwFlags: DWORD): BOOL; stdcall;
  external WINTRUST_DLL name 'CryptCATAdminReleaseCatalogContext';
function CryptCATAdminReleaseContext(hCatAdmin: HCATADMIN; dwFlags: DWORD): BOOL; stdcall;
  external WINTRUST_DLL name 'CryptCATAdminReleaseContext';

// wintrust.h
function WTHelperProvDataFromStateData(hStateData: THandle): PCRYPT_PROVIDER_DATA; stdcall;
  external WINTRUST_DLL name 'WTHelperProvDataFromStateData';
function WTHelperGetProvSignerFromChain(pProvData: PCRYPT_PROVIDER_DATA; idxSigner: DWORD;
  fCounterSigner: BOOL; idxCounterSigner: DWORD): PCRYPT_PROVIDER_SGNR; stdcall;
  external WINTRUST_DLL name 'WTHelperGetProvSignerFromChain';

// wincrypt.h
function CertGetNameStringW(pCertContext: PCCERT_CONTEXT; dwType, dwFlags: DWORD;
  pvTypePara: Pointer; pszNameString: PWideChar; cchNameString: DWORD): DWORD; stdcall;
  external CRYPT32_DLL name 'CertGetNameStringW';

/// Путь для API: длинные пути (>= MAX_PATH) получают префикс «\\?\».
function ToApiPath(const APath: string): string;
begin
  if (Length(APath) < MAX_PATH) or APath.StartsWith('\\?\') then
    Result := APath
  else if APath.StartsWith('\\') then
    Result := '\\?\UNC\' + Copy(APath, 3, MaxInt)
  else
    Result := '\\?\' + APath;
end;

function OpenForRead(const APath: string; AFlags: DWORD): THandle;
begin
  Result := CreateFile(PChar(ToApiPath(APath)), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL or AFlags, 0);
end;

function LastErrorText(ACode: DWORD): string;
begin
  Result := Format('%s (код %d)', [SysErrorMessage(ACode), ACode]);
end;

function HashToHexUpper(const AHash: TBytes; ALength: DWORD): string;
const
  HEX: array[0..15] of Char = '0123456789ABCDEF';
var
  I: Integer;
begin
  SetLength(Result, ALength * 2);
  for I := 0 to Integer(ALength) - 1 do
  begin
    Result[I * 2 + 1] := HEX[AHash[I] shr 4];
    Result[I * 2 + 2] := HEX[AHash[I] and $F];
  end;
end;

/// Имя издателя из состояния WinVerifyTrust ('' — нет данных).
function SignerFromState(AStateData: THandle): string;
var
  LProvData: PCRYPT_PROVIDER_DATA;
  LSigner: PCRYPT_PROVIDER_SGNR;
  LCert: PCCERT_CONTEXT;
  LLength: DWORD;
begin
  Result := '';
  if AStateData = 0 then
    Exit;
  LProvData := WTHelperProvDataFromStateData(AStateData);
  if LProvData = nil then
    Exit;
  LSigner := WTHelperGetProvSignerFromChain(LProvData, 0, False, 0);
  if (LSigner = nil) or (LSigner^.csCertChain = 0) or (LSigner^.pasCertChain = nil) then
    Exit;
  // pasCertChain[0] — сертификат самого подписанта.
  LCert := LSigner^.pasCertChain^.pCert;
  if LCert = nil then
    Exit;
  LLength := CertGetNameStringW(LCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0);
  if LLength <= 1 then
    Exit;
  SetLength(Result, LLength);
  LLength := CertGetNameStringW(LCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,
    PWideChar(Result), LLength);
  if LLength <= 1 then
    Result := ''
  else
    SetLength(Result, LLength - 1);
end;

/// WinVerifyTrust с открытием и обязательным закрытием состояния проверки.
/// AData: заполнены только dwUnionChoice и указатель объединения.
function RunWinVerifyTrust(var AData: WINTRUST_DATA; out ASigner: string;
  out ALastError: DWORD): Longint;
var
  LAction: TGUID;
begin
  LAction := WINTRUST_ACTION_GENERIC_VERIFY_V2;
  AData.cbStruct := SizeOf(AData);
  AData.dwUIChoice := WTD_UI_NONE;
  AData.fdwRevocationChecks := WTD_REVOKE_NONE;
  AData.dwStateAction := WTD_STATEACTION_VERIFY;
  AData.hWVTStateData := 0;
  // Только локальный кеш: никаких сетевых запросов CRL/AIA.
  AData.dwProvFlags := WTD_CACHE_ONLY_URL_RETRIEVAL;
  ASigner := '';
  Result := WinVerifyTrust(0, LAction, @AData);
  ALastError := GetLastError;
  try
    ASigner := SignerFromState(AData.hWVTStateData);
  finally
    AData.dwStateAction := WTD_STATEACTION_CLOSE;
    WinVerifyTrust(0, LAction, @AData);
  end;
end;

function VerifyEmbedded(const APath: string; AFile: THandle; out ASigner: string;
  out ALastError: DWORD): Longint;
var
  LFileInfo: WINTRUST_FILE_INFO;
  LData: WINTRUST_DATA;
begin
  FillChar(LFileInfo, SizeOf(LFileInfo), 0);
  LFileInfo.cbStruct := SizeOf(LFileInfo);
  LFileInfo.pcwszFilePath := PWideChar(APath);
  LFileInfo.hFile := AFile;
  FillChar(LData, SizeOf(LData), 0);
  LData.dwUnionChoice := WTD_CHOICE_FILE;
  LData.pFile := @LFileInfo;
  Result := RunWinVerifyTrust(LData, ASigner, ALastError);
end;

type
  TCatalogOutcome = (coNotFound, coVerified, coFailed);

/// Поиск файла в каталогах Windows с заданным алгоритмом хеша
/// (nil — SHA-1 по умолчанию) и проверка подписи найденного каталога.
function VerifyCatalogWith(const APath: string; AFile: THandle; AAlgorithm: PWideChar;
  out ACode: Longint; out ASigner, AError: string): TCatalogOutcome;
var
  LAdmin: HCATADMIN;
  LCatInfo: HCATINFO;
  LHash: TBytes;
  LHashSize, LLastError: DWORD;
  LCatalog: CATALOG_INFO;
  LMember: WINTRUST_CATALOG_INFO;
  LData: WINTRUST_DATA;
  LTag: string;
begin
  ACode := 0;
  ASigner := '';
  AError := '';
  LAdmin := 0;
  if not CryptCATAdminAcquireContext2(LAdmin, nil, AAlgorithm, nil, 0) then
  begin
    AError := 'CryptCATAdminAcquireContext2: ' + LastErrorText(GetLastError);
    Exit(coFailed);
  end;
  try
    SetLength(LHash, MAX_HASH_BYTES);
    LHashSize := Length(LHash);
    SetFilePointer(AFile, 0, nil, FILE_BEGIN);
    if not CryptCATAdminCalcHashFromFileHandle2(LAdmin, AFile, LHashSize, PByte(LHash), 0) then
    begin
      AError := 'CryptCATAdminCalcHashFromFileHandle2: ' + LastErrorText(GetLastError);
      Exit(coFailed);
    end;

    LCatInfo := CryptCATAdminEnumCatalogFromHash(LAdmin, PByte(LHash), LHashSize, 0, nil);
    if LCatInfo = 0 then
      Exit(coNotFound);
    try
      FillChar(LCatalog, SizeOf(LCatalog), 0);
      LCatalog.cbStruct := SizeOf(LCatalog);
      if not CryptCATCatalogInfoFromContext(LCatInfo, @LCatalog, 0) then
      begin
        AError := 'CryptCATCatalogInfoFromContext: ' + LastErrorText(GetLastError);
        Exit(coFailed);
      end;

      // Тег элемента каталога — хеш файла в верхнем регистре hex.
      LTag := HashToHexUpper(LHash, LHashSize);
      FillChar(LMember, SizeOf(LMember), 0);
      LMember.cbStruct := SizeOf(LMember);
      LMember.pcwszCatalogFilePath := @LCatalog.wszCatalogFile[0];
      LMember.pcwszMemberTag := PWideChar(LTag);
      LMember.pcwszMemberFilePath := PWideChar(APath);
      LMember.hMemberFile := AFile;
      LMember.pbCalculatedFileHash := PByte(LHash);
      LMember.cbCalculatedFileHash := LHashSize;
      LMember.hCatAdmin := LAdmin;

      FillChar(LData, SizeOf(LData), 0);
      LData.dwUnionChoice := WTD_CHOICE_CATALOG;
      LData.pCatalog := @LMember;
      ACode := RunWinVerifyTrust(LData, ASigner, LLastError);
      Result := coVerified;
    finally
      CryptCATAdminReleaseCatalogContext(LAdmin, LCatInfo, 0);
    end;
  finally
    CryptCATAdminReleaseContext(LAdmin, 0);
  end;
end;

function VerifyCatalog(const APath: string; AFile: THandle; out ACode: Longint;
  out ASigner, AError: string): TCatalogOutcome;
var
  LError: string;
begin
  // Современные каталоги содержат SHA-256, старые — только SHA-1.
  Result := VerifyCatalogWith(APath, AFile, BCRYPT_SHA256_ALGORITHM, ACode, ASigner, AError);
  if Result = coVerified then
    Exit;
  LError := AError;
  Result := VerifyCatalogWith(APath, AFile, nil, ACode, ASigner, AError);
  if (Result = coNotFound) and (LError <> '') then
  begin
    // SHA-256 проверить не удалось, а по SHA-1 файл не найден: результат неполный.
    AError := LError;
    Result := coFailed;
  end;
end;

/// Перевод кода WinVerifyTrust в состояние подписи.
/// False — проверка не дала определённого результата.
function MapTrustResult(ACode: Longint; out AState: TMHSignatureState;
  out AError: string): Boolean;
begin
  Result := True;
  AState := sgSignedUntrusted;
  AError := '';
  case ACode of
    ERROR_SUCCESS:
      AState := sgSignedTrusted;
    TRUST_E_BAD_DIGEST:
      AError := 'файл изменён после подписания';
    TRUST_E_EXPLICIT_DISTRUST:
      AError := 'сертификат подписи явно запрещён в системе';
    CERT_E_UNTRUSTEDROOT:
      AError := 'цепочка сертификатов заканчивается недоверенным корнем';
    CERT_E_CHAINING:
      AError := 'не удалось построить цепочку до доверенного корневого сертификата';
    TRUST_E_SUBJECT_NOT_TRUSTED:
      AError := 'издатель не является доверенным';
    CERT_E_EXPIRED:
      AError := 'срок действия сертификата истёк, а метки времени нет';
    CERT_E_REVOKED:
      AError := 'сертификат подписи отозван';
    TRUST_E_CERT_SIGNATURE:
      AError := 'подпись сертификата недействительна';
  else
    AState := sgCheckFailed;
    AError := Format('WinVerifyTrust: 0x%.8x %s', [Cardinal(ACode), SysErrorMessage(Cardinal(ACode))]);
    Result := False;
  end;
end;

function IsNoSignatureCode(ACode: Longint): Boolean;
begin
  Result := (ACode = TRUST_E_NOSIGNATURE) or (ACode = TRUST_E_SUBJECT_FORM_UNKNOWN) or
    (ACode = TRUST_E_PROVIDER_UNKNOWN);
end;

{ TMHWinFileApi }

function TMHWinFileApi.GetFileStamp(const APath: string; out ASize: Int64;
  out ALastWriteUtc: TDateTime): Boolean;
var
  LData: TWin32FileAttributeData;
  LSystemTime: TSystemTime;
begin
  ASize := -1;
  ALastWriteUtc := 0;
  Result := False;
  if APath = '' then
    Exit;
  if not GetFileAttributesEx(PChar(ToApiPath(APath)), GetFileExInfoStandard, @LData) then
    Exit;
  if LData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY <> 0 then
    Exit;
  if not FileTimeToSystemTime(LData.ftLastWriteTime, LSystemTime) then
    Exit;
  ASize := Int64(LData.nFileSizeHigh) shl 32 or LData.nFileSizeLow;
  ALastWriteUtc := SystemTimeToDateTime(LSystemTime);
  Result := True;
end;

function TMHWinFileApi.ComputeSha256(const APath: string; out AHash, AError: string): Boolean;
var
  LFile: THandle;
  LHash: THashSHA2;
  LBuffer: TBytes;
  LRead: DWORD;
begin
  AHash := '';
  AError := '';
  LFile := OpenForRead(APath, FILE_FLAG_SEQUENTIAL_SCAN);
  if LFile = INVALID_HANDLE_VALUE then
  begin
    AError := LastErrorText(GetLastError);
    Exit(False);
  end;
  try
    LHash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
    SetLength(LBuffer, HASH_BUFFER_SIZE);
    repeat
      if not ReadFile(LFile, LBuffer[0], Length(LBuffer), LRead, nil) then
      begin
        AError := LastErrorText(GetLastError);
        Exit(False);
      end;
      if LRead > 0 then
        LHash.Update(LBuffer, LRead);
    until LRead = 0;
    AHash := LHash.HashAsString;
    Result := True;
  finally
    CloseHandle(LFile);
  end;
end;

function TMHWinFileApi.VerifySignature(const APath: string; out AState: TMHSignatureState;
  out ASigner, ASource, AError: string): Boolean;
var
  LApiPath, LCatalogError: string;
  LFile: THandle;
  LCode, LCatalogCode: Longint;
  LLastError: DWORD;
begin
  AState := sgCheckFailed;
  ASigner := '';
  ASource := '';
  AError := '';
  LApiPath := ToApiPath(APath);
  LFile := OpenForRead(APath, 0);
  if LFile = INVALID_HANDLE_VALUE then
  begin
    AError := LastErrorText(GetLastError);
    Exit(False);
  end;
  try
    LCode := VerifyEmbedded(LApiPath, LFile, ASigner, LLastError);
    if not IsNoSignatureCode(LCode) then
    begin
      ASource := 'embedded';
      Exit(MapTrustResult(LCode, AState, AError));
    end;

    // Встроенной подписи нет — ищем файл в каталогах Windows.
    ASigner := '';
    case VerifyCatalog(LApiPath, LFile, LCatalogCode, ASigner, LCatalogError) of
      coVerified:
        begin
          ASource := 'catalog';
          Result := MapTrustResult(LCatalogCode, AState, AError);
        end;
      coFailed:
        begin
          AError := 'проверка каталогов Windows: ' + LCatalogError;
          Result := False;
        end;
    else
      // Для TRUST_E_NOSIGNATURE причину уточняет GetLastError (см. пример
      // WinVerifyTrust в документации Microsoft): иная ошибка — сбой чтения.
      if (LCode = TRUST_E_NOSIGNATURE) and not IsNoSignatureCode(Longint(LLastError)) and
         (LLastError <> ERROR_SUCCESS) then
      begin
        AError := 'не удалось прочитать подпись: ' + LastErrorText(LLastError);
        Result := False;
      end
      else
      begin
        AState := sgUnsigned;
        Result := True;
      end;
    end;
  finally
    CloseHandle(LFile);
  end;
end;

function TMHWinFileApi.TickMs: UInt64;
begin
  Result := GetTickCount64;
end;

end.
