unit MineHunter.App.Theme;

{
  Цветовая тема интерфейса. Тёмная тема — стиль VCL «Windows10 Dark»
  (встроен ресурсом VCLSTYLE, см. MineHunter.App.Styles.rc), светлая —
  системное оформление Windows. Собственные элементы (графики, карточки)
  берут цвета через MHThemeColor, чтобы совпадать с выбранным стилем.
}

interface

uses
  Vcl.Graphics, MineHunter.Core.Settings;

/// Применяет тему. False — стиль недоступен (тема остаётся прежней).
function MHApplyTheme(ATheme: TMHUiTheme): Boolean;
/// Тёмный стиль доступен (ресурс встроен в программу).
function MHDarkThemeAvailable: Boolean;
function MHIsDarkTheme: Boolean;
/// Системный цвет (clWindow, clWindowText…) в текущем стиле.
function MHThemeColor(AColor: TColor): TColor;

implementation

uses
  System.SysUtils, Vcl.Themes,
  Vcl.Styles; // регистрирует формат стилей .vsf — без него ресурс VCLSTYLE не загружается

const
  SYSTEM_STYLE = 'Windows';

function DarkStyleName: string;
var
  LName: string;
begin
  for LName in TStyleManager.StyleNames do
    if SameText(LName, 'Windows10 Dark') then
      Exit(LName);
  for LName in TStyleManager.StyleNames do
    if LName.Contains('Dark') then
      Exit(LName);
  Result := '';
end;

function MHDarkThemeAvailable: Boolean;
begin
  Result := DarkStyleName <> '';
end;

function MHApplyTheme(ATheme: TMHUiTheme): Boolean;
var
  LName: string;
begin
  if ATheme = utDark then
    LName := DarkStyleName
  else
    LName := SYSTEM_STYLE;
  if LName = '' then
    Exit(False);
  if SameText(TStyleManager.ActiveStyle.Name, LName) then
    Exit(True);
  Result := TStyleManager.TrySetStyle(LName, False);
end;

function MHIsDarkTheme: Boolean;
begin
  Result := not TStyleManager.ActiveStyle.IsSystemStyle and
    TStyleManager.ActiveStyle.Name.Contains('Dark');
end;

function MHThemeColor(AColor: TColor): TColor;
begin
  if TStyleManager.ActiveStyle.IsSystemStyle then
    Result := AColor
  else
    Result := TStyleManager.ActiveStyle.GetSystemColor(AColor);
end;

end.
