unit MineHunter.Core.FileScan.WinApi;

{
  IMHFileScanFs для Windows: FindFirstFileEx (FindExInfoBasic, LARGE_FETCH —
  без коротких имён и с крупными порциями), длинные пути через префикс \\?\,
  чтение файлов с разделением доступа (файл, открытый другой программой,
  тоже читается) и последовательным доступом.
}

interface

uses
  System.SysUtils, MineHunter.Core.FileScan;

type
  TMHWinFileScanFs = class(TInterfacedObject, IMHFileScanFs)
  public
    function ListDirectory(const APath: string; out AEntries: TArray<TMHFsEntry>): Boolean;
    function ReadHead(const APath: string; AMaxBytes: Integer; out AData: TBytes): Boolean;
  end;

/// Корни локальных несъёмных дисков: «C:\», «D:\» …
function MHLocalFixedRoots: TArray<string>;

/// Атрибуты файла или папки средствами Windows (GetFileAttributes); MH_NO_ATTRIBUTES — нет.
function MHWinFileAttributes(const APath: string): Cardinal;

implementation

uses
  Winapi.Windows, System.Generics.Collections;

const
  FIND_FIRST_EX_LARGE_FETCH = 2;

function LongPath(const APath: string): string;
begin
  if APath.StartsWith('\\?\') or APath.StartsWith('\\.\') then
    Result := APath
  else if APath.StartsWith('\\') then
    Result := '\\?\UNC\' + Copy(APath, 3, MaxInt)
  else
    Result := '\\?\' + APath;
end;

function MHLocalFixedRoots: TArray<string>;
var
  LBuffer: array[0..1023] of Char;
  LRoot: PChar;
  LLength: DWORD;
begin
  Result := nil;
  LLength := GetLogicalDriveStrings(Length(LBuffer) - 1, LBuffer);
  if (LLength = 0) or (LLength > DWORD(Length(LBuffer))) then
    Exit;
  LRoot := @LBuffer[0];
  while LRoot^ <> #0 do
  begin
    if GetDriveType(LRoot) = DRIVE_FIXED then
      Result := Result + [string(LRoot)];
    Inc(LRoot, StrLen(LRoot) + 1);
  end;
end;

{ TMHWinFileScanFs }

function TMHWinFileScanFs.ListDirectory(const APath: string; out AEntries: TArray<TMHFsEntry>): Boolean;
var
  LFind: THandle;
  LData: TWin32FindData;
  LList: TList<TMHFsEntry>;
  LEntry: TMHFsEntry;
  LName: string;
  LOldMode: UINT;
begin
  AEntries := nil;
  LOldMode := SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOOPENFILEERRORBOX);
  try
    LFind := FindFirstFileEx(PChar(LongPath(IncludeTrailingPathDelimiter(APath)) + '*'), FindExInfoBasic,
      @LData, FindExSearchNameMatch, nil, FIND_FIRST_EX_LARGE_FETCH);
    if LFind = INVALID_HANDLE_VALUE then
      Exit(GetLastError = ERROR_FILE_NOT_FOUND); // пустая папка — не ошибка
    LList := TList<TMHFsEntry>.Create;
    try
      repeat
        LName := string(PChar(@LData.cFileName[0]));
        if (LName = '.') or (LName = '..') then
          Continue;
        LEntry.Name := LName;
        LEntry.Attributes := LData.dwFileAttributes;
        LEntry.SizeBytes := Int64(LData.nFileSizeHigh) shl 32 or LData.nFileSizeLow;
        LList.Add(LEntry);
      until not FindNextFile(LFind, LData);
      AEntries := LList.ToArray;
      Result := True;
    finally
      Winapi.Windows.FindClose(LFind);
      LList.Free;
    end;
  finally
    SetErrorMode(LOldMode);
  end;
end;

function TMHWinFileScanFs.ReadHead(const APath: string; AMaxBytes: Integer; out AData: TBytes): Boolean;
var
  LHandle: THandle;
  LRead, LTotal: DWORD;
  LChunk: Integer;
begin
  AData := nil;
  if AMaxBytes <= 0 then
    Exit(False);
  LHandle := CreateFile(PChar(LongPath(APath)), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if LHandle = INVALID_HANDLE_VALUE then
    Exit(False);
  try
    SetLength(AData, AMaxBytes);
    LTotal := 0;
    while Integer(LTotal) < AMaxBytes do
    begin
      LChunk := AMaxBytes - Integer(LTotal);
      if LChunk > 1024 * 1024 then
        LChunk := 1024 * 1024;
      if not ReadFile(LHandle, AData[LTotal], LChunk, LRead, nil) or (LRead = 0) then
        Break;
      Inc(LTotal, LRead);
    end;
    SetLength(AData, LTotal);
    Result := LTotal > 0;
  finally
    CloseHandle(LHandle);
  end;
end;

function MHWinFileAttributes(const APath: string): Cardinal;
begin
  if APath = '' then
    Exit(MH_NO_ATTRIBUTES);
  Result := GetFileAttributes(PChar(LongPath(APath)));
end;

end.
