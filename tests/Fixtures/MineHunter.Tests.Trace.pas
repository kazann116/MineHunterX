unit MineHunter.Tests.Trace;

{
  Построчная трассировка проверок BinaryLab (tools/binarylab_assert_trace.py).
  Скрипт вставляет TraceHit('<файл>:<строка>') перед строками Assert в копии
  тестов; при завершении процесса выполненные строки записываются в файл из
  переменной окружения MH_TRACE_FILE. В обычной сборке тестов модуль не
  используется.
}

interface

/// Отмечает, что строка проверки AId выполнена.
procedure TraceHit(const AId: string);

implementation

uses
  System.SysUtils, System.Classes, System.SyncObjs, System.Generics.Collections;

var
  GLock: TCriticalSection;
  GHits: TDictionary<string, Integer>;

procedure TraceHit(const AId: string);
var
  LCount: Integer;
begin
  GLock.Enter;
  try
    GHits.TryGetValue(AId, LCount);
    GHits.AddOrSetValue(AId, LCount + 1);
  finally
    GLock.Leave;
  end;
end;

procedure SaveHits;
var
  LFile: string;
  LLines: TStringList;
  LPair: TPair<string, Integer>;
begin
  LFile := GetEnvironmentVariable('MH_TRACE_FILE');
  if LFile = '' then
    Exit;
  LLines := TStringList.Create;
  try
    for LPair in GHits do
      LLines.Add(LPair.Key + #9 + IntToStr(LPair.Value));
    LLines.Sort;
    LLines.SaveToFile(LFile, TEncoding.UTF8);
  finally
    LLines.Free;
  end;
end;

initialization
  GLock := TCriticalSection.Create;
  GHits := TDictionary<string, Integer>.Create;

finalization
  SaveHits;
  GHits.Free;
  GLock.Free;

end.
