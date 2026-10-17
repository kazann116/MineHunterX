unit MineHunter.Core.Updates.WinApi;

{ IMHHttpGet на System.Net.HttpClient (WinHTTP, системные сертификаты и прокси). }

interface

uses
  System.SysUtils, MineHunter.Core.Updates;

type
  TMHNetHttpGet = class(TInterfacedObject, IMHHttpGet)
  public const
    TimeoutMs = 8000;
    MaxBodyBytes = 1024 * 1024;
  public
    function Get(const AUrl: string; out AStatus: Integer; out ABody: string; out AError: string): Boolean;
  end;

implementation

uses
  System.Classes, System.Net.HttpClient, System.Net.URLClient, System.NetConsts, MineHunter.Core.Types;

function TMHNetHttpGet.Get(const AUrl: string; out AStatus: Integer; out ABody: string;
  out AError: string): Boolean;
var
  LClient: THTTPClient;
  LResponse: IHTTPResponse;
  LStream: TBytesStream;
begin
  AStatus := 0;
  ABody := '';
  AError := '';
  LClient := THTTPClient.Create;
  LStream := TBytesStream.Create;
  try
    LClient.ConnectionTimeout := TimeoutMs;
    LClient.ResponseTimeout := TimeoutMs;
    LClient.UserAgent := 'MineHunterX/' + MH_CORE_VERSION;
    LClient.Accept := 'application/vnd.github+json';
    try
      LResponse := LClient.Get(AUrl, LStream);
      AStatus := LResponse.StatusCode;
      if LStream.Size > MaxBodyBytes then
      begin
        AError := 'слишком большой ответ';
        Exit(False);
      end;
      ABody := TEncoding.UTF8.GetString(LStream.Bytes, 0, LStream.Size);
      Result := True;
    except
      on E: ENetException do
      begin
        AError := E.Message;
        Result := False;
      end;
    end;
  finally
    LStream.Free;
    LClient.Free;
  end;
end;

end.
