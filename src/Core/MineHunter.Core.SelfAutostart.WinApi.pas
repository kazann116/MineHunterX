unit MineHunter.Core.SelfAutostart.WinApi;

{ Реализация IMHRunKeyOps для HKCU\Software\Microsoft\Windows\CurrentVersion\Run. }

interface

uses
  System.SysUtils, MineHunter.Core.SelfAutostart;

type
  TMHWinRunKeyOps = class(TInterfacedObject, IMHRunKeyOps)
  public
    function ReadRunValue(const AName: string; out AValue: string): Boolean;
    function WriteRunValue(const AName, AValue: string; out AError: string): Boolean;
    function DeleteRunValue(const AName: string; out AError: string): Boolean;
  end;

implementation

uses
  Winapi.Windows, System.Win.Registry;

const
  RUN_KEY = 'Software\Microsoft\Windows\CurrentVersion\Run';

function TMHWinRunKeyOps.ReadRunValue(const AName: string; out AValue: string): Boolean;
var
  LReg: TRegistry;
begin
  AValue := '';
  Result := False;
  LReg := TRegistry.Create(KEY_READ);
  try
    LReg.RootKey := HKEY_CURRENT_USER;
    if not LReg.OpenKeyReadOnly(RUN_KEY) then
      Exit;
    try
      if LReg.ValueExists(AName) and (LReg.GetDataType(AName) in [rdString, rdExpandString]) then
      begin
        AValue := LReg.ReadString(AName);
        Result := AValue <> '';
      end;
    except
      on E: ERegistryException do
        Result := False;
    end;
  finally
    LReg.Free;
  end;
end;

function TMHWinRunKeyOps.WriteRunValue(const AName, AValue: string; out AError: string): Boolean;
var
  LReg: TRegistry;
begin
  AError := '';
  LReg := TRegistry.Create(KEY_READ or KEY_SET_VALUE);
  try
    LReg.RootKey := HKEY_CURRENT_USER;
    try
      if not LReg.OpenKey(RUN_KEY, True) then
      begin
        AError := SysErrorMessage(LReg.LastError);
        Exit(False);
      end;
      LReg.WriteString(AName, AValue);
      Result := True;
    except
      on E: ERegistryException do
      begin
        AError := E.Message;
        Result := False;
      end;
    end;
  finally
    LReg.Free;
  end;
end;

function TMHWinRunKeyOps.DeleteRunValue(const AName: string; out AError: string): Boolean;
var
  LReg: TRegistry;
begin
  AError := '';
  LReg := TRegistry.Create(KEY_READ or KEY_SET_VALUE);
  try
    LReg.RootKey := HKEY_CURRENT_USER;
    if not LReg.OpenKey(RUN_KEY, False) then
      Exit(True); // ветки нет — записи тоже нет
    if not LReg.ValueExists(AName) then
      Exit(True);
    Result := LReg.DeleteValue(AName);
    if not Result then
      AError := SysErrorMessage(LReg.LastError);
  finally
    LReg.Free;
  end;
end;

end.
