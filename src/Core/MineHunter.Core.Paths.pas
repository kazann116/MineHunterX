unit MineHunter.Core.Paths;

{
  Нормализация путей к исполняемым файлам. Чистые функции без обращения к ОС:
  каталог Windows передаётся параметром, чтобы результат был детерминирован.

  Нормализация нужна, чтобы один и тот же файл из разных источников
  (процессы, службы, автозапуск) сравнивался как один объект и чтобы
  подмена путей вида «\\?\C:\...» или «C:/...» не обходила проверки.
}

interface

/// Приводит путь к канонической форме Win32:
///  - убирает пробелы по краям и обрамляющие кавычки;
///  - заменяет «/» на «\»;
///  - убирает префиксы «\\?\», «\??\», «\\.\»; «\\?\UNC\srv» -> «\\srv»;
///  - «\SystemRoot\» и «%SystemRoot%\» -> AWindowsDir (если он задан);
///  - схлопывает повторные «\» (кроме ведущих «\\» сетевого пути);
///  - разрешает сегменты «.» и «..» (не поднимаясь выше корня).
/// Регистр не меняется: для сравнения используйте MHSamePath.
function MHNormalizePath(const APath: string; const AWindowsDir: string = ''): string;

/// Сравнение путей без учёта регистра после нормализации.
function MHSamePath(const A, B: string; const AWindowsDir: string = ''): Boolean;

implementation

uses
  System.SysUtils, System.StrUtils, System.Generics.Collections;

function StripPrefix(const S, APrefix: string; out ARest: string): Boolean;
begin
  Result := StartsText(APrefix, S);
  if Result then
    ARest := Copy(S, Length(APrefix) + 1, MaxInt);
end;

function MHNormalizePath(const APath: string; const AWindowsDir: string): string;
var
  S, LRest, LRoot, LWinDir: string;
  LIsUnc: Boolean;
  LParts: TArray<string>;
  LStack: TList<string>;
  LPart: string;
begin
  S := Trim(APath);
  if (Length(S) >= 2) and (S[1] = '"') and (S[Length(S)] = '"') then
    S := Trim(Copy(S, 2, Length(S) - 2));
  if S = '' then
    Exit('');
  S := StringReplace(S, '/', '\', [rfReplaceAll]);

  if StripPrefix(S, '\\?\UNC\', LRest) then
    S := '\\' + LRest
  else if StripPrefix(S, '\\?\', LRest) or StripPrefix(S, '\??\', LRest) or
          StripPrefix(S, '\\.\', LRest) then
    S := LRest;

  LWinDir := ExcludeTrailingPathDelimiter(Trim(AWindowsDir));
  if LWinDir <> '' then
  begin
    if StripPrefix(S, '\SystemRoot\', LRest) or StripPrefix(S, '%SystemRoot%\', LRest) then
      S := LWinDir + '\' + LRest;
  end;

  LIsUnc := StartsStr('\\', S);
  if LIsUnc then
  begin
    LRoot := '\\';
    S := Copy(S, 3, MaxInt);
  end
  else if (Length(S) >= 2) and (S[2] = ':') then
  begin
    LRoot := Copy(S, 1, 2) + '\';
    S := Copy(S, 3, MaxInt);
  end
  else if StartsStr('\', S) then
    LRoot := '\'
  else
    LRoot := '';

  LParts := S.Split(['\'], TStringSplitOptions.ExcludeEmpty);
  LStack := TList<string>.Create;
  try
    for LPart in LParts do
      if LPart = '.' then
        Continue
      else if LPart = '..' then
      begin
        // Для UNC первые два сегмента (сервер и общий ресурс) — это корень.
        if (LStack.Count > 0) and not (LIsUnc and (LStack.Count <= 2)) then
          LStack.Delete(LStack.Count - 1);
      end
      else
        LStack.Add(LPart);
    Result := LRoot + string.Join('\', LStack.ToArray);
  finally
    LStack.Free;
  end;
end;

function MHSamePath(const A, B: string; const AWindowsDir: string): Boolean;
begin
  Result := SameText(MHNormalizePath(A, AWindowsDir), MHNormalizePath(B, AWindowsDir));
end;

end.
