unit MineHunter.Core.Lang;

{
  Язык текстов, которые формирует библиотека (объяснения находок, рекомендации,
  причины нагрузки, отчёты). По умолчанию — русский. Приложение задаёт язык один
  раз при запуске (MHSetCoreEnglish) до начала сканирования; чтение флага из
  потока сканера безопасно (Boolean, меняется только при запуске).
}

interface

procedure MHSetCoreEnglish(AValue: Boolean);
function MHCoreEnglish: Boolean;
/// Текст на текущем языке: ARu — русский вариант, AEn — английский.
/// Строки формата должны содержать одинаковые спецификаторы в одном порядке.
function MHL(const ARu, AEn: string): string;

implementation

var
  GEnglish: Boolean = False;

procedure MHSetCoreEnglish(AValue: Boolean);
begin
  GEnglish := AValue;
end;

function MHCoreEnglish: Boolean;
begin
  Result := GEnglish;
end;

function MHL(const ARu, AEn: string): string;
begin
  if GEnglish then
    Result := AEn
  else
    Result := ARu;
end;

end.
