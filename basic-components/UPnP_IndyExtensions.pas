{
  UPnP_IndyExtensions:
  Indy TCP and UDP handlers and interfaces for UPnP Device and Service objects.
  Copyright (c) 2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_IndyExtensions.pas,v 1.23 2005/08/16 21:00:32 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Status:

  Revision History:
    June 2005
      - Created
    July 22, 2005
      - Release v1.5.3
}

unit UPnP_IndyExtensions;

interface

uses
  Classes,
  Windows,
  Contnrs,
  SysUtils,
  SyncObjs,
  IdContext,
  IdCustomHTTPServer,
  IdGlobal,
  IdGlobalProtocols,
  IdHeaderList,
  IdHTTP,
  IdHTTPServer,
  IdIntercept,
  IdIOHandlerStack,
  IdIPMCastBase,
  IdIPMCastClient,
  IdIPMCastServer,
  IdLogEvent,
  IdServerInterceptLogEvent,
  IdSocketHandle,
  IdStackBSDBase,
  IdStackConsts,
  IdThread,
  IdUDPClient,
  IdURI,
  UPnP_XmlStreamer;

type
  // Forward declaration
  TUPnP_HeaderList = class;

  {
    TUPnP_LoggingType:
    defines the types for logging
  }
  TUPnP_LoggingCallbackProc = procedure(aLoggingType, aMessage: string) of object;

  {
    TUPnP_IdSocketHandle:
    redeclared to remove dependencies in other units
  }
  TUPnP_IdSocketHandle = class(TIdSocketHandle)
  end;

  {
    TUPnP_UDPRequestCallbackProc:
    Call back procedure for UDP requests to TUPnP_MulticastListener
  }
  TUPnP_UDPRequestCallbackProc = procedure(aData: TStream; aBinding: TUPnP_IdSocketHandle) of object;

  {
    TUPnP_MulticastListener:
    Server that listens for UPnP Multicast messages
  }
  TUPnP_MulticastListener = class(TIdIPMCastClient)
  protected
    fOnLog: TUPnP_LoggingCallbackProc;
    fOnUDPRequest: TUPnP_UDPRequestCallbackProc;
    function GetBinding: TIdSocketHandle; override;
    procedure DoIPMCastRead(AData: TStream; ABinding: TIdSocketHandle); override;
  public
    property OnUDPRequest: TUPnP_UDPRequestCallbackProc Read fOnUDPRequest Write fOnUDPRequest;
    property OnLog: TUPnP_LoggingCallbackProc Read fOnLog Write fOnLog;
  end;

  {
    TUPnP_MulticastSender:
    Server that transmits UPnP Multicast messages
  }
  TUPnP_MulticastSender = class(TIdIPMCastServer)
  protected
    fOnLog: TUPnP_LoggingCallbackProc;
    function GetBinding: TIdSocketHandle; override;
  public
    procedure Transmit(aString: string);
    property OnLog: TUPnP_LoggingCallbackProc Read fOnLog Write fOnLog;
  end;

  {
    TUPnP_UnicastSender:
    Server that transmits UPnP UDP Unicast messages
  }
  TUPnP_UnicastSender = class(TIdUdpClient)
  protected
    fOnLog: TUPnP_LoggingCallbackProc;
  public
    procedure SendBuffer(AHost: string; const APort: integer;
      const ABuffer: TIdBytes); override;
    property OnLog: TUPnP_LoggingCallbackProc Read fOnLog Write fOnLog;
  end;

  {
    TUPnP_IdHTTPRequestInfo:
    Overrides TIdHTTPRequestInfo adding a Text property
  }
  TUPnP_IdHTTPRequestInfo = class(TIdHTTPRequestInfo)
  protected
    procedure SetText(aText: string);
  public
    property Text: string Write SetText;
  end;

  {
    TUPnP_IdHTTPResponseInfo:
    Overrides TIdHTTPResponseInfo adding a Text property
  }
  TUPnP_IdHTTPResponseInfo = class(TIdHTTPResponseInfo)
  protected
    function GetText: string;
  public
    property Text: string Read GetText;
  end;

  {
    TUPnP_TCPRequestCallbackProc:
    Call back procedure for TCP requests to TUPnP_HTTPServer
  }
  TUPnP_TCPRequestCallbackProc = procedure(aRequestInfo: TUPnP_IdHTTPRequestInfo;
      aResponseInfo: TUPnP_IdHTTPResponseInfo) of object;

  {
    TUPnP_HTTPServer:
    Server that handles incoming UPnP HTTP requests
  }
  TUPnP_HTTPServer = class(TIdHTTPServer)
  protected
    fOnLog: TUPnP_LoggingCallbackProc;
    fOnTCPRequest: TUPnP_TCPRequestCallbackProc;
    procedure SetOnTCPRequest(aOnTCPRequest: TUPnP_TCPRequestCallbackProc);
    procedure DoOnLogString(ASender: TIdServerInterceptLogEvent; AText: string);
    procedure DoOnCommandXXX(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
    procedure SetOnLog(aOnLog: TUPnP_LoggingCallbackProc);
    procedure CreateXMLPostStream(AContext: TIdContext; var vPostStream: TStream);
    procedure SetActive(AValue: Boolean); override;
  public
    destructor Destroy; override;
    property OnLog: TUPnP_LoggingCallbackProc Read fOnLog Write SetOnLog;
    property OnTCPRequest: TUPnP_TCPRequestCallbackProc Read fOnTCPRequest Write SetOnTCPRequest;
  end;

  {
    TUPnP_NotificationCollection:
    A collection of notification messages
  }
  TUPnP_NotificationCollection = class(TObjectList)
  protected
    function GetNotification(Index: integer): TUPnP_HeaderList;
  public
    property Notifications[Index: integer]: TUPnP_HeaderList Read GetNotification;
  end;

  {
    TUPnP_HeaderList:
    UPnP headerList prototype
  }
  TUPnP_HeaderList = class(TIdHeaderList)
  protected
    function GetAsText: string; virtual; abstract;
  public
    procedure AddToCollection(aCollection: TUPnP_NotificationCollection);
    property AsText: string Read GetAsText;
  end;

  {
    TUPnP_ByeByeHeader:
    HeaderList for creating SSDP ByeBye multicast messages
  }
  TUPnP_ByeByeNotification = class(TUPnP_HeaderList)
  protected
    procedure SetSearchTarget(aString: string);
    procedure SetUSN(aString: string);
    function GetAsText: string; override;
    procedure SetHost(aHost: string);
  public
    constructor Create; virtual;
    property SearchTarget: string Write SetSearchTarget;
    property USN: string Write SetUSN;
    property Host: string Write SetHost;
  end;

  {
    TUPnP_AliveNotification:
    HeaderList for creating SSDP Alive multicast messages
    Extends TUPnP_ByeByeHeader...
  }
  TUPnP_AliveNotification = class(TUPnP_ByeByeNotification)
  protected
    procedure SetLocation(aString: string);
    procedure SetMaxAge(aAge: cardinal);
  public
    constructor Create; override;
    property Location: string Write SetLocation;
    property MaxAge: cardinal Write SetMaxAge;
  end;

  {
    TUPnP_MSearchRequest:
    HTTP header list for capturing SSDP M-SEARCH multicast requests
  }
  TUPnP_MSearchRequest = class(TIdHeaderList)
  protected
    fCommandLine: string;
    fIP: string;
    fPort: TIdPort;
    fHost: string;
    function GetMxDelay: integer;
    function GetSearchTarget: string;
  public
    constructor Create(aData: TStream); overload;
    function IsValidSearchRequest: boolean;
    property MxDelay: integer Read GetMxDelay;
    property SearchTarget: string Read GetSearchTarget;
    property IP: string Read fIP Write fIP;
    property Port: TIdPort Read fPort Write fPort;
    property Host: string Write fHost;
  end;

  {
    TUPnP_MSearchResponse:
    HeaderList for creating SSDP M-SEARCH multicast responses
  }
  TUPnP_MSearchResponse = class(TUPnP_HeaderList)
  protected
    fIP: string;
    fPort: TIdPort;
    procedure SetLocation(aString: string);
    procedure SetSearchTarget(aString: string);
    procedure SetUSN(aString: string);
    function GetAsText: string; override;
    procedure SetMaxAge(aAge: cardinal);
  public
    constructor Create; virtual;
    property Location: string Write SetLocation;
    property SearchTarget: string Write SetSearchTarget;
    property USN: string Write SetUSN;
    property MaxAge: cardinal Write SetMaxAge;
    property IP: string Read fIP Write fIP;
    property Port: TIdPort Read fPort Write fPort;
  end;

  {
    TUPnP_IdHTTP:
    Overridden version of TIdHTTP adding a new NOTIFY method
  }
  TUPnP_IdHTTP = class(TIdHTTP)
  public
    procedure Notify(FetchResponse: boolean);
  end;

  {
    TUPnP_IdHTTPRequest:
    Expose the protected methods of TIdHTTPRequest
  }
  TUPnP_IdHTTPRequest = class(TIdHTTPRequest)
  end;

  {
    TUPnP_IdHTTPResponse:
    Expose the protected methods of TIdHTTPResponse
  }
  TUPnP_IdHTTPResponse = class(TIdHTTPResponse)
  end;

  {
    TUPnP_HTTPServerRequestWrapper:
    Wrapper around a TCP HTTP server header request list
    Provides an interface to the Source stream as an XML stream
  }
  TUPnP_HTTPServerRequestWrapper = class
  protected
    fRequest: TUPnP_IdHTTPRequestInfo;
    fSoapActionHeader: string;
    fSOAPAction: string;
    function GetXmlStream: TUPnP_XMLStream;
    function GetSID: string;
    function GetNT: string;
    function GetCallback: string;
    function GetMAN: string;
    function GetTimeout: cardinal;
    function GetHeader(aName: string): string;
    function GetSOAPAction: string;
    function GetSoapActionHeader: string;
  public
    constructor Create(aRequest: TUPnP_IdHTTPRequestInfo);
    function HasXmlStream: boolean;
    property Request: TUPnP_IdHTTPRequestInfo Read fRequest;
    property XmlStream: TUPnP_XMLStream Read GetXmlStream;
    property SID: string Read GetSID;
    property NT: string Read GetNT;
    property Callback: string Read GetCallback;
    property MAN: string Read GetMAN;
    property Timeout: cardinal Read GetTimeout;
    property Header[aName: string]: string Read GetHeader;
    property SOAPAction: string Read GetSOAPAction;
    property SoapActionHeader: string Read GetSoapActionHeader;
  end;

  {
    TUPnP_HTTPServerResponseWrapper:
    Wrapper around a TCP HTTP server header response list
    Provides an interface to the Content stream as an XML stream
  }
  TUPnP_HTTPServerResponseWrapper = class
  protected
    fResponse: TUPnP_IdHTTPResponseInfo;
    fXmlStream: TUPnP_XMLStream;
    function GetXmlStream: TUPnP_XMLStream;
    procedure SetSID(aSID: string);
    procedure SetTimeOut(aTimeOut: integer);
    procedure SetExt(aEXT: boolean);
  public
    constructor Create(aResponse: TUPnP_IdHTTPResponseInfo);
    property Response: TUPnP_IdHTTPResponseInfo Read fResponse;
    property XmlStream: TUPnP_XMLStream Read GetXmlStream;
    property SID: string Write SetSID;
    property TimeOut: integer Write SetTimeOut;
    property EXT: boolean Write SetExt;
  end;

  {
    TUPnP_SubscriptionClientThreadState:
    Enumerator of possible states for TUPnP_SubscriptionClientThread
  }
  TUPnP_SubscriptionClientThreadState =
    (sctNotStarted, sctInitialising, sctConnecting, sctFinalising, sctDone);

  {
    TUPnP_SubscriptionClientThread:
    A thread that sends UPnP event notifications
  }
  TUPnP_SubscriptionClientThread = class(TThread)
  protected
    fOwner: TComponent;
    fState: TUPnP_SubscriptionClientThreadState;
    fAborted: boolean;
    fHTTP: TUPnP_IdHTTP;
    fIdLogEvent: TIdLogEvent;
    fOnLog: TUPnP_LoggingCallbackProc;
    fSyncMessage: string;
    fXmlStream: TUPnP_XMLStream;
    fURL: string;
    fSID: string;
    fSEQ: integer;
    fSocketTimeOut: integer;
    fLock: TCriticalSection;
    fOnAfterExecute: TNotifyEvent;
    fTimeoutTime: TDateTime;
    function GeXmlStream: TUPnP_XMLStream;
    procedure DoOnLogBytes(ASender: TIdConnectionIntercept; var ABuffer: TIdBytes);
    procedure SetOnLog(aOnLog: TUPnP_LoggingCallbackProc);
    procedure syncDoLogCallback;
    procedure Execute; override;
  public
    constructor Create(CreateSuspended: Boolean; aOwner: TComponent);
    destructor Destroy; override;
    procedure Interrupt;
    function TimedOut: boolean;
    property OnLog: TUPnP_LoggingCallbackProc Read fOnLog Write SetOnLog;
    property XmlStream: TUPnP_XMLStream Read GeXmlStream;
    property SID: string Write fSID;
    property SEQ: integer Write fSEQ;
    property URL: string Write fURL;
    property SocketTimeOut: integer Write fSocketTimeOut;
    property State: TUPnP_SubscriptionClientThreadState Read fState;
    property Lock: TCriticalSection read fLock;
  end;

procedure ParseURL(aAddress: string; var scheme, host, page, port: string);
function GetIPAddress: string;
function BuildURL(scheme, host, page, port: string): string;
function IsIP(aURL: string): boolean;

const
  {  constant redeclared to remove dependencies in other units }
  upnp_hcGET: THTTPCommandType = hcGET;

implementation

uses
  IdIOHandler,
  IdResourceStringsCore,
  IdResourceStringsProtocols,
  IdStack,
  IdStreamVCL,
  IdException,
  UPnP_Components,
  UPnP_Globals,
  UPnP_Strings;

function GetIPAddress: string;
{
  Get the current local IP address.
  Status:
}
begin
{$ifdef USE_VPN }
  // if we have a second connection open, then use that one
  if GBSDStack.LocalAddresses.Count > 1 then
  begin
    Result := GBSDStack.LocalAddresses[1];
  end
  else
{$endif}
  begin
    Result := GBSDStack.LocalAddress;
  end;
end;

function IsIP(aURL: string): boolean;
{
  Check if URL is a good dotted IP
  Status:
}
begin
  Result := GBSDStack.IsIP(aURL);
end;

procedure ParseURL(aAddress: string; var scheme, host, page, port: string);
{
  Breaks a URL down into constituent SCHEME, HOST, PAGE & PORT information
  Status:
}
var
  lURI: TIdURI;
begin
  lURI := TIdURI.Create(aAddress);
  try
    scheme := lURI.Protocol;
    host   := lURI.Host;
    page   := lURI.Document;
    port   := lURI.Port;
  finally
    lURI.Free;
  end;
end;

function BuildURL(scheme, host, page, port: string): string;
{
  Builds a URL from constituent SCHEME, HOST, PAGE & PORT parts
  Status:
}
var
  lURI: TIdURI;
begin
  lURI := TIdURI.Create();
  try
    lURI.Protocol := scheme;
    lURI.Host := host;
    lURI.Document := page;
    lURI.Port := port;
    Result := lURI.URI;
  finally
    lURI.Free;
  end;
end;

procedure TUPnP_HeaderList.AddToCollection(aCollection: TUPnP_NotificationCollection);
{
  Add ourselves to a TUPnP_NotificationCollection list
  Status:
}
begin
  Assert(assigned(aCollection));
  aCollection.Add(self);
end;

constructor TUPnP_ByeByeNotification.Create;
{
  Create a UPnP ByeBye notification sender
  Status:

  Notification format is:

    NOTIFY * HTTP/1.1
    HOST: 239.255.255.250:1900
    NT: *** SEE SPECICATION
    NTS: ssdp:byebye
    USN: *** SEE SPECICATION
}
begin
  inherited;
  FFoldLines      := False;
  Values[NTS_Hdr] := SsdpByeBye;
end;

procedure TUPnP_ByeByeNotification.SetHost(aHost: string);
{
  Property setter
  Status:
}
begin
  Values[Host_Hdr] := aHost;
end;

procedure TUPnP_ByeByeNotification.SetSearchTarget(aString: string);
{
  Property setter
  Status:
}
begin
  Values[NT_Hdr] := aString;
end;

procedure TUPnP_ByeByeNotification.SetUSN(aString: string);
{
  Property setter
  Status:
}
begin
  Values[USN_Hdr] := aString;
end;

function TUPnP_ByeByeNotification.GetAsText: string;
{
  Get the notification as a text string
  Status:
}
begin
  Result := MulticastNotify + crlf + Text + crlf;
end;

constructor TUPnP_AliveNotification.Create;
{
  Create a UPnP Alive notification sender
  Status:

  Notification format is:

    NOTIFY * HTTP/1.1
    HOST: 239.255.255.250:1900
    CACHE-CONTROL: max-age = seconds until advertisement expires
    LOCATION: URL for UPnP description for root device
    NT: *** SEE SPECICATION
    NTS: ssdp:alive
    SERVER: OS/version UPnP/1.0 product/version
    USN: *** SEE SPECICATION
}
begin
  inherited;
  Values[NTS_Hdr]    := SsdpAlive;
  Values[Server_Hdr] := Server_Header;
end;

procedure TUPnP_AliveNotification.SetMaxAge(aAge: cardinal);
{
  Property setter
  Status:
}
begin
  Values[CacheControl_Hdr] := max_age + IntToStr(aAge);
end;

procedure TUPnP_AliveNotification.SetLocation(aString: string);
{
  Property setter
  Status:
}
begin
  Values[Location_Hdr] := aString;
end;

constructor TUPnP_MSearchRequest.Create(aData: TStream);
{
  Build a M-Serach request header from the multicast bytes recieved over the wire
  Status:

  Format is:
    M-SEARCH * HTTP/1.1
    HOST: 239.255.255.250:1900
    MAN: "ssdp:discover"
    MX: seconds to delay response
    ST: search target
}
var
  strs: TStringList;
begin
  Assert(assigned(aData));
  Create;
  Sorted    := False;
  FoldLines := False;
  strs      := TStringList.Create;
  try
    strs.LoadFromStream(aData);
    AddStrings(strs);
  finally
    strs.Free;
  end;
  fCommandLine := Strings[0];
end;

function TUPnP_MSearchRequest.IsValidSearchRequest: boolean;
{
  Check if the header syntax is a valid M-Search
  Status:
}
begin
  Result := (fCommandLine = MulticastSearch) and
    (Values[Host_Hdr] = fHost) and
    // Windows ME provides a non quoted string, and other CP's provide a
    // quoted string => use Pos
    (Pos(SsdpDiscover, Values[MAN_Hdr]) <> 0) and
    (GetMxDelay > 0) and
    (GetSearchTarget <> '');
end;

function TUPnP_MSearchRequest.GetMxDelay: integer;
{
  Propert getter
  Status:
}
begin
  Result := StrToIntDef(Values[MX_Hdr], -1);
end;

function TUPnP_MSearchRequest.GetSearchTarget: string;
{
  Propert getter
  Status:
}
begin
  Result := Values[ST_Hdr];
end;

constructor TUPnP_MSearchResponse.Create;
{
  Create a UPnP M-Search response notification sender
  Status:

  Response format is:
    HTTP/1.1 200 OK
    CACHE-CONTROL: max-age = seconds until advertisement expires
    DATE: when response was generated
    EXT:
    LOCATION: URL for UPnP description for root device
    SERVER: OS/version UPnP/1.0 product/version
    ST: *** SEE SPECICATION
    USN: *** SEE SPECICATION
}
begin
  inherited;
  Sorted    := False;
  FoldLines := False;
  Values[Date_Hdr] := DateTimeGMTToHttpStr(NowGMT);
  // IdHeaderList does not accept empty headers so we have to cheat by using %s
  Values[EXT_Hdr] := '%s';
  Values[Server_Hdr] := Server_Header;
end;

function TUPnP_MSearchResponse.GetAsText: string;
{
  Get the notification as a text string
  Status:
}
begin
  // IdHeaderList does not accept empty headers so we have to cheat and replace %s with empty string
  Result := Http_200_Ok + crlf + Format(Text, ['']) + crlf;
end;

procedure TUPnP_MSearchResponse.SetMaxAge(aAge: cardinal);
{
  Property setter
  Status:
}
begin
  Values[CacheControl_Hdr] := max_age + IntToStr(aAge);
end;

procedure TUPnP_MSearchResponse.SetLocation(aString: string);
{
  Property setter
  Status:
}
begin
  Values[Location_Hdr] := aString;
end;

procedure TUPnP_MSearchResponse.SetSearchTarget(aString: string);
{
  Property setter
  Status:
}
begin
  Values[ST_Hdr] := aString;
end;

procedure TUPnP_MSearchResponse.SetUSN(aString: string);
{
  Property setter
  Status:
}
begin
  Values[USN_Hdr] := aString;
end;

procedure TUPnP_UnicastSender.SendBuffer(AHost: string; const APort: integer;
  const ABuffer: TIdBytes);
{
  Log the output before sending it
  Status:
}
begin
  if assigned(fOnLog) then
  begin
    fOnLog(ClassName, BytesToString(aBuffer));
  end;
  inherited;
end;

function TUPnP_NotificationCollection.GetNotification(Index: integer): TUPnP_HeaderList;
{
  Property getter
  Status:
}
begin
  Result := GetItem(Index) as TUPnP_HeaderList;
end;

procedure TUPNP_IdHTTPRequestInfo.SetText(aText: string);
{
  Parse the Text into HTTP command, headers and content
  Status:
}
var
  tmp1: string;
  tmp2: string;
  i, j: integer;
  lURI: TIdURI;
begin
  // get the raw command line
  i := Pos(crlf, aText);
  fRawHTTPCommand := Copy(aText, 1, i - 1);

  // get & process the headers
  j := Pos(crlf + crlf, aText);
  fRawHeaders.Text := Copy(aText, i + 2, j - i);
  ProcessHeaders;

  // create the content stream and write its data
  tmp1 := Copy(aText, j + 4, MaxInt);
  fContentLength := length(tmp1);
  fPostStream := TUPnP_XmlStream.Create;
  TUPnP_XmlStream(fPostStream).WriteValues([tmp1]);

  // parse the raw command line for Command
  i := Pos(' ', fRawHTTPCommand);
  fCommand := UpperCase(Copy(fRawHTTPCommand, 1, i - 1));

  // determine CommandType
  fCommandType := hcUnknown;
  for j := Low(HTTPRequestStrings) to High(HTTPRequestStrings) do
  begin
    if TextIsSame(fCommand, HTTPRequestStrings[j]) then
    begin
      fCommandType := THTTPCommandType(j);
      break;
    end;
  end;

  // parse the raw command line for Document
  tmp2 := Copy(fRawHTTPCommand, i + 1, MaxInt);
  i    := Pos(' ', tmp2);
  lURI := TIdURI.Create(Copy(tmp2, 1, i - 1));
  fDocument := TIdURI.URLDecode(lURI.Path) + TIdURI.URLDecode(lURI.Document) +
    lURI.Params;
  lURI.Free;

  // and parse for Version
  fVersion := Copy(fRawHTTPCommand, i + 1, MaxInt);
end;

function TUPNP_IdHTTPResponseInfo.GetText: string;
{
  Get the HTTP command, headers and content as a text
  Status:
}
var
  lContent: string;
begin
  // adjust ContentLength, and get the content as a string
  if Assigned(ContentStream) then
  begin
    fContentLength := ContentStream.Size;
    SetLength(lContent, fContentLength);
    ContentStream.Position := 0;
    ContentStream.Read(lContent[1], fContentLength);
  end;

  // transfer the headers into the string list
  SetHeaders;

  // write the command line, headers (with an extra terminating crlf)
  // and content
  Result :=
    Format(Http_Response, [ResponseNo, ResponseText, RawHeaders.Text, lContent]);
end;

constructor TUPnP_HTTPServerRequestWrapper.Create(aRequest: TUPnP_IdHTTPRequestInfo);
{
  Create a UPnP HTTP server request header
  Status:
}
begin
  inherited Create;
  fRequest := aRequest;
end;

function TUPnP_HTTPServerRequestWrapper.HasXmlStream: boolean;
{
  Check if we have an Xml stream
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := (fRequest.PostStream is TUPnP_XMLStream);
end;

function TUPnP_HTTPServerRequestWrapper.GetXmlStream: TUPnP_XMLStream;
{
  Status:
}
begin
  Assert(assigned(fRequest));
  Assert(HasXmlStream);
  Result := TUPnP_XMLStream(fRequest.PostStream);
end;

function TUPnP_HTTPServerRequestWrapper.GetSID: string;
{
  Property getter
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := fRequest.RawHeaders.Values[SID_Hdr];
end;

function TUPnP_HTTPServerRequestWrapper.GetNT: string;
{
  Property getter
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := fRequest.RawHeaders.Values[NT_Hdr];
end;

function TUPnP_HTTPServerRequestWrapper.GetCallback: string;
{
  Property getter
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := fRequest.RawHeaders.Values[Callback_Hdr];
end;

function TUPnP_HTTPServerRequestWrapper.GetMAN: string;
{
  Property getter
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := fRequest.RawHeaders.Values[MAN_Hdr];
end;

function TUPnP_HTTPServerRequestWrapper.GetTimeout: cardinal;
{
  Property getter
  Status:
}
var
  i:   integer;
  hdr: string;
begin
  Assert(assigned(fRequest));
  hdr := Lowercase(fRequest.RawHeaders.Values[Timeout_Hdr]);
  i   := Pos(SecondHdrLower, hdr);
  if i > 0 then
  begin
    Result := StrToIntDef(Trim(Copy(hdr, i + length(SecondHdrLower), length(hdr))), MaxInt);
  end
  else
  begin
    Result := MaxInt;
  end;
end;

function TUPnP_HTTPServerRequestWrapper.GetHeader(aName: string): string;
{
  Property getter
  Status:
}
begin
  Assert(assigned(fRequest));
  Result := fRequest.RawHeaders.Values[aName];
end;

function TUPnP_HTTPServerRequestWrapper.GetSoapActionHeader: string;
{
  Gets the Soap action header
  Status:
}
begin
  GetSOAPAction;
  Result := fSoapActionHeader;
end;

function TUPnP_HTTPServerRequestWrapper.GetSOAPAction: string;
{
  Gets the Soap action
  Status:
}
var
  i, j: integer;
  man:  string;
begin
  if fSOAPAction = '' then
  begin
    fSOAPAction := '?';

    // check if there is a MAN header i.e. it is an M-Post request
    man := GetMAN;
    if man <> '' then
    begin
      // we are looking for a 'ns-SOAPACTION' header (where ns = namespace)
      // look in the MAN header for the ns field after the ';'
      i := Pos('; ns=', man);
      if i <> 0 then
      begin
        // build the header in the form 'ns-SOAPACTION'
        fSoapActionHeader := Header[Trim(Copy(man, i + 1, length(man))) +
          '-' + SoapAction_Hdr];
      end;
    end

    else
    begin
      // it is a regular POST => we are just looking for a 'SOAPACTION' header
      fSoapActionHeader := Header[SoapAction_Hdr];
    end;

    // and finally get the action after the # character..
    if fSoapActionHeader <> '' then
    begin
      i := Pos('#', fSoapActionHeader);
      if i > 0 then
      begin
        j := Pos('"', fSoapActionHeader[i]);
        if j = 0 then
        begin
          j := length(fSoapActionHeader);
        end;
        fSOAPAction := Copy(fSoapActionHeader, i + 1, j - i - 1);
      end;
    end;
  end;

  Result := fSOAPAction;
end;

constructor TUPnP_HTTPServerResponseWrapper.Create(aResponse: TUPnP_IdHTTPResponseInfo);
{
  Create a UPnP HTTP server response header
  Status:
}
begin
  inherited Create;
  fResponse := aResponse;
end;

function TUPnP_HTTPServerResponseWrapper.GetXmlStream: TUPnP_XMLStream;
{
  Create an Xml stream object
  Assign the Xml stream to -- to be sent -- content stream
  Status:
}
begin
  Assert(assigned(fResponse));
  if not assigned(fXmlStream) then
  begin
    fXmlStream := TUPnP_XMLStream.Create;
    fResponse.ContentStream := fXmlStream;
    fResponse.ContentType := text_xml_utf8;
    fResponse.FreeContentStream := True;
  end;
  Result := fXmlStream;
end;

procedure TUPnP_HTTPServerResponseWrapper.SetSID(aSID: string);
{
  Property setter
  Status:
}
begin
  Assert(assigned(fResponse));
  fResponse.CustomHeaders.Values[SID_Hdr] := aSID;
end;

procedure TUPnP_HTTPServerResponseWrapper.SetTimeOut(aTimeOut: integer);
{
  Property setter
  Status:
}
begin
  Assert(assigned(fResponse));
  fResponse.CustomHeaders.Values[Timeout_Hdr] := SecondHdrFirstCap + IntToStr(aTimeout);
end;

procedure TUPnP_HTTPServerResponseWrapper.SetExt(aEXT: boolean);
{
  Property setter -- set an empty EXT header
  Status:
}
var
  i: integer;
begin
  Assert(assigned(fResponse));

  with fResponse.CustomHeaders do
  begin
    i := IndexOfName(Ext_Hdr);
    if aEXT then
    begin
      if i < 0 then
      begin
        i := Add('');
      end;
      Strings[i] := Ext_Hdr + NameValueSeparator;
    end
    else
    begin
      if i >= 0 then
      begin
        Delete(i);
      end;
    end;
  end;
end;

procedure TUPnP_MulticastListener.DoIPMCastRead(aData: TStream;
  aBinding: TIdSocketHandle);
var
  ss:   string;
  p, s: int64;
begin
  Assert(assigned(aData));
  if assigned(fOnLog) then
  begin
    s := aData.Size;
    p := aData.Position;
    SetLength(ss, s);
    aData.Position := 0;
    aData.Read(ss[1], s);
    aData.Position := p;
    fOnLog(ClassName, ss);
  end;
  if Assigned(fOnUDPRequest) then
  begin
    // beware the typecast below...
    fOnUDPRequest(aData, TUPnP_IdSocketHandle(aBinding));
  end;
  inherited;
end;

function TUPnP_MulticastListener.GetBinding: TIdSocketHandle;
{$define AFG_NEW_CODE}
{
  Overridden version of GetBinding to allow multicast ports to be reused...
  Status:
}
var
  i: integer;
  Multicast: TMultiCast;
begin
  if not Assigned(FCurrentBinding) then
  begin
    if Bindings.Count < 1 then
    begin
      if DefaultPort > 0 then
      begin
        Bindings.Add;
      end
      else
      begin
        raise EIdMCastNoBindings.Create(RSNoBindingsSpecified);
      end;
    end;
    for i := 0 to Bindings.Count - 1 do
    begin
{$IFDEF LINUX}
      Bindings[i].AllocateSocket(integer(Id_SOCK_DGRAM));
{$ELSE}
      Bindings[i].AllocateSocket(Id_SOCK_DGRAM);
{$ENDIF}
      // ++++++++++++++++
{$ifdef AFG_NEW_CODE}
      // allow re-use of addresses
      Bindings[i].SetSockOpt(Id_SOL_SOCKET, Id_SO_REUSEADDR, integer(True));
{$endif}
      // ++++++++++++++++
      Bindings[i].Bind;
      GBSDStack.TranslateStringToTInAddr(FMulticastGroup,
        Multicast.IMRMultiAddr, Id_IPv4);
      Multicast.IMRInterface.S_addr := Id_INADDR_ANY;
      GBSDStack.SetSocketOption(Bindings[i].Handle, Id_IPPROTO_IP,
        Id_IP_ADD_MEMBERSHIP, PChar(@Multicast), SizeOf(Multicast));
    end;
    FCurrentBinding := Bindings[0];
    FListenerThread := TIdIPMCastListenerThread.Create(Self);
    FListenerThread.Start;
  end;
  Result := FCurrentBinding;
end;

procedure TUPnP_MulticastSender.Transmit(aString: string);
{
  Log the output before sending it
  Status:
}
begin
  if assigned(fOnLog) then
  begin
    fOnLog(ClassName, aString);
  end;
  Send(astring);
end;

function TUPnP_MulticastSender.GetBinding: TIdSocketHandle;
{$define AFG_NEW_CODE}
var
  Multicast: TMultiCast;
begin
  if not Assigned(FBinding) then
  begin
    FBinding := TIdSocketHandle.Create(nil);
  end;
  if not FBinding.HandleAllocated then
  begin
{$IFDEF LINUX}
    FBinding.AllocateSocket(integer(Id_SOCK_DGRAM));
{$ELSE}
    FBinding.AllocateSocket(Id_SOCK_DGRAM);
{$ENDIF}
    // ++++++++++++++++
{$ifdef AFG_NEW_CODE}
    // allow re-use of addresses
    fBinding.SetSockOpt(Id_SOL_SOCKET, Id_SO_REUSEADDR, integer(True));
{$endif}
    // ++++++++++++++++
    FBinding.Bind;
    //Multicast.IMRMultiAddr :=  GBSDStack.StringToTIn4Addr(FMulticastGroup);
    //Hope the following is correct for StringToTIn4Addr(), should be checked...
    GBSDStack.TranslateStringToTInAddr(FMulticastGroup, Multicast.IMRMultiAddr, Id_IPv4);
    Multicast.IMRInterface.S_addr := Id_INADDR_ANY;
    GBSDStack.SetSocketOption(FBinding.Handle, Id_IPPROTO_IP,
      Id_IP_ADD_MEMBERSHIP, PChar(@Multicast), SizeOf(Multicast));
    SetTTLOption(FBinding, FTimeToLive);
    Loopback := True;
  end;
  Result := FBinding;
end;

destructor TUPnP_HTTPServer.Destroy;
{
  Destructor
  Status:
}
begin
  SetOnLog(nil);
  inherited;
end;

procedure TUPnP_HTTPServer.SetOnTCPRequest(aOnTCPRequest: TUPnP_TCPRequestCallbackProc);
{
  Property setter
  Status:
}
begin
  fOnTCPRequest := aOnTCPRequest;
  if assigned(fOnTCPRequest) then
  begin
    OnCommandGet := DoOnCommandXXX;
    OnCommandOther := DoOnCommandXXX;
  end
  else
  begin
    OnCommandGet := nil;
    OnCommandOther := nil;
  end;
end;

procedure TUPnP_HTTPServer.DoOnCommandXXX(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
{
  Command dispatcher
  Status:
}
begin
  if assigned(fOnTCPRequest) then
  begin
    // beware the following two type casts...
    fOnTCPRequest(TUPnP_IdHTTPRequestInfo(aRequestInfo), TUPnP_IdHTTPResponseInfo(aResponseInfo));
  end;
end;

procedure TUPnP_HTTPServer.SetOnLog(aOnLog: TUPnP_LoggingCallbackProc);
{
  Property setter
  Status:
}
begin
  fOnLog := aOnLog;
  if assigned(fOnLog) then
  begin
    Intercept := TIdServerInterceptLogEvent.Create;
    with TIdServerInterceptLogEvent(Intercept) do
    begin
      OnLogString := DoOnLogString;
      LogTime := False;
      ReplaceCRLF := False;
    end;
  end
  else
  begin
    if assigned(Intercept) then
    begin
      Intercept.Free;
    end;
  end;
end;

procedure TUPnP_HTTPServer.DoOnLogString(ASender: TIdServerInterceptLogEvent;
  AText: string);
{
  Handler for logging callbacks
  Status:
}
begin
  if assigned(fOnLog) then
  begin
    fOnLog(ClassName, aText);
  end;
end;

procedure TUPnP_HTTPServer.CreateXMLPostStream(AContext: TIdContext;
  var vPostStream: TStream);
{
  Callback that creates a new XML stream
  Status:
}
begin
  vPostStream := TUPnP_XMLStream.Create;
end;

procedure TUPnP_HTTPServer.SetActive(AValue: Boolean);
{
  Choose a free port and connect the HTTP server online
  Status:
}
var
  tries: integer;
begin
  if aValue and (not fActive) then
  begin
    // hook up our callback
    OnCreatePostStream := CreateXMLPostStream;

    // set the Server header
    ServerSoftware := Server_Header;

    // don't allow socket re-use
    ReuseSocket := rsFalse;

    StopDelphiIdeOnException(False);
    try

      // try 5 attempts to find an unused port
      tries := 5;
      while tries > 0 do
      begin

        try
          // try to bind to the port
          inherited;
          // if we get here, we are connected, so we can break...
          break;
        except
          on exception do ;
        end;

        // otherwise do the loop again
        Dec(tries);

        // this time select a default port at random
        DefaultPort := $400 + Random($FBFF);

        // and assign it to any already existing binding
        if Bindings.Count > 0 then
        begin
          Bindings[0].Port := DefaultPort;
        end;
      end;

    finally
      StopDelphiIdeOnException(True);
    end;
  end
  else inherited;
end;

constructor TUPnP_SubscriptionClientThread.Create(CreateSuspended: Boolean; aOwner: TComponent);
{
  Constructor
  Status:
}
begin
  inherited Create(CreateSuspended);
  fOwner := aOwner;
  fLock := TCriticalSection.Create;
  fState := sctNotStarted;
  fAborted := false;
  FreeOnTerminate := true;
end;

destructor TUPnP_SubscriptionClientThread.Destroy;
{
  Destructor
  Status:
}
begin
  OnLog := nil;
  if Assigned(fXmlStream) then
  begin
    FreeAndNil(fXmlStream);
  end;
  FreeAndNil(fLock);
  inherited;
end;

procedure TUPnP_SubscriptionClientThread.syncDoLogCallback;
{
  Method called via Synchronize to pass on log messages to the VCL
  Status:
}
begin
  Assert(assigned(fOnLog));
  fOnLog(ClassName, fSyncMessage);
end;

procedure TUPnP_SubscriptionClientThread.DoOnLogBytes(ASender: TIdConnectionIntercept;
  var ABuffer: TIdBytes);
{
  Handler for logging callbacks
  Status:
}
begin
  if assigned(fOnLog) then
  begin
    fSyncMessage := BytesToString(aBuffer);
    Synchronize(syncDoLogCallback);
    fSyncMessage := '';
  end;
end;

procedure TUPnP_SubscriptionClientThread.SetOnLog(aOnLog: TUPnP_LoggingCallbackProc);
{
  Property setter
  Status:
}
begin
  fOnLog := aOnLog;
  if assigned(fOnLog) then
  begin
    if not assigned(fIdLogEvent) then
    begin
      fIdLogEvent := TIdLogEvent.Create;
    end;
    fIdLogEvent.OnSend      := DoOnLogBytes;
    fIdLogEvent.OnReceive   := DoOnLogBytes;
    fIdLogEvent.LogTime     := False;
    fIdLogEvent.ReplaceCRLF := False;
    fIdLogEvent.Active      := True;
  end
  else
  begin
    if assigned(fIdLogEvent) then
    begin
      FreeAndNil(fIdLogEvent);
    end;
  end;
end;

procedure TUPnP_SubscriptionClientThread.Interrupt;
{
  Shutdown the socket
  Status:
}
begin
  fAborted := true;
  if (fState = sctConnecting) and assigned(fHTTP) then
  begin
    StopDelphiIdeOnException(false);
    try
      fHTTP.Disconnect;
    except
      on exception do;
    end;
    StopDelphiIdeOnException(true);
  end;
end;

function TUPnP_SubscriptionClientThread.TimedOut: boolean;
{
  Check if the time out has expired
  Status:
}
begin
  if fState = sctConnecting then
  begin
    result := (Now > fTimeoutTime);
  end
  else
  begin
    result := false;
  end;
end;

procedure TUPnP_SubscriptionClientThread.Execute;
{
  Send the subscription notification
  Status:
}
begin
  // initialise
  fLock.Enter;
  try
    // update the state
    fState := sctInitialising;

    // create an HTTP client
    fHTTP := TUPnP_IdHTTP.Create;

    // set up basic parameters
    with fHTTP do
    begin
      // set up the logging callbacks - if any
      if Assigned(fIdLogEvent) then
      begin
        IOHandler := TIdIOHandlerStack.Create(fHTTP);
        IOHandler.Intercept := fIdLogEvent;
        IOHandler.ReadTimeout := ReadTimeout;
      end;
    end;

    // set up the HTTP request parameters
    with fHTTP.Request do
    begin
      URL := fURL;
      Source := fXmlStream;
      ContentType := MimeTypeStr[xml];
      UserAgent := '';
      AcceptEncoding := '';
      Accept := '';
      CustomHeaders.Values[NT_Hdr] := upnpevent;
      CustomHeaders.Values[NTS_Hdr] := upnppropchange;
      CustomHeaders.Values[SID_Hdr] := fSID;
      CustomHeaders.Values[SEQ_Hdr] := IntToStr(fSEQ);
    end;

    // set the expiry time
    fTimeoutTime := Now + (fSocketTimeOut / 86400);

    // update the state
    fState := sctConnecting;
  finally
    fLock.Leave;
  end;

  // try to make the call
  if not fAborted then
  begin

    // post the subscription
    try
      fHTTP.Notify(True);
//      fHTTP.Notify(False);
    except
      on exception do ;
    end;

  end;

  // clean up
  fLock.Enter;
  try
    // update the state
    fState := sctFinalising;

    if Assigned(fIdLogEvent) then
    begin
      fHTTP.IOHandler.Free;
      fHTTP.IOHandler := nil;
    end;

    // destroy the HTTP client
    FreeAndNil(fHTTP);

    if assigned(fOnAfterExecute) then
    begin
      fOnAfterExecute(self);
    end;

    // update the state
    fState := sctDone;
  finally
    fLock.Leave;
  end;

  // notify owner that the thread is done
  if fOwner is TUPnP_SubscriptionItem then
  begin
    TUPnP_SubscriptionItem(fOwner).NotifyThreadDone(self);
  end;
end;

function TUPnP_SubscriptionClientThread.GeXmlStream: TUPnP_XMLStream;
{
  Create the XML payload
  Status:
}
begin
  if not assigned(fXmlStream) then
  begin
    fXmlStream := TUPnP_XMLStream.Create;
  end;
  Result := fXmlStream;
end;

procedure TUPnP_IdHTTP.Notify(FetchResponse: boolean);
{
  Execute the NOTIFY method
  Status:
}
var
  lStrm: TIdStreamVCL;
  i: integer;
  lHdr: string;
begin
  try
    // a straight HTTP/1.1 POST is closest to what we are actually doing...
    ProtocolVersion := pv1_1;
    Request.Method := hmPost;
    HandleRedirects := False;

    // prepare the request headers
    PrepareRequest(Request);

    // set host, port and IP version
    SetHostAndPort;
    IPVersion := fURI.IPVersion;

    // set the headers (pre- check that our kludge typecast is legal)
    if Request is TIdHTTPRequest then
    begin
      TUPnP_IdHTTPRequest(Request).SetHeaders;
    end;

    // try to connect the socket
    Connect;

    // write the request data
    IOHandler.WriteBufferOpen;
    try
      // write the HTTP Notify method line
      IOHandler.WriteLn(Format(fmtNotiify, [Request.URL]));

      // write the HTTP headers
      for i := 0 to Request.RawHeaders.Count - 1 do
      begin
        if Length(Request.RawHeaders.Strings[i]) > 0 then
        begin
          IOHandler.WriteLn(Request.RawHeaders.Strings[i]);
        end;
      end;

      // write the empty line
      IOHandler.WriteLn('');

      // write the source stream
      lStrm := TIdStreamVCL.Create(Request.Source);
      try
        IOHandler.Write(lStrm, 0, false);
      finally
        FreeAndNil(lStrm);
      end;

      // clean up
      IOHandler.WriteBufferClose;

    except
      // clean up and promote the exception
      IOHandler.WriteBufferCancel;
      raise;
    end;

    // try to get the response data
    if FetchResponse then
    begin
      try

        // read the HTTP response line
        Response.ResponseText := IOHandler.ReadLn;

        // read the HTTP response headers
        Response.RawHeaders.Clear;
        lHdr := IOHandler.ReadLn;
        i := 0;
        while (lHdr <> '') and (i < MaxHeaderLines) do
        begin
          Response.RawHeaders.Add(lHdr);
          lHdr := IOHandler.ReadLn;
          inc(i);
        end;

        // process the response headers (pre- check that our kludge typecast is legal)
        if Response is TIdHTTPResponse then
        begin
          TUPnP_IdHTTPResponse(Response).ProcessHeaders;
        end;

        // read the response content
        ReadResult(Response);

      except
        // a graceful disconnect is basically Ok here, so swallow it ...
        on E: EIdConnClosedGracefully do ;
      else
        // otherwise promote the exception
        raise;
      end;
    end;

  finally
    // always disconnect
    Disconnect;
  end;
end;

initialization
  // initialize the stack
  TIdStack.IncUsage;

finalization
  // finalize the stack
  TIdStack.DecUsage;
end.

