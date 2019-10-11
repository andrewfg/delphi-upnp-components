{
  UPnP_Components:
  This a Delphi implementation of components for UPnP Device and Service objects.
  Copyright (c) 2001..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_Components.pas,v 1.34 2005/09/18 09:57:55 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Revision History:
    July 1st, 2000
      - Started work
    July 15th, 2000
      - SSDP written & tested
    August 3rd, 2000
      - Description, Presentation & Icon server written & tested
    August 12th, 2000
      - SOAP, GENA written
    August 17th, 2000
      - Definition of all classes, field & methods finalised
    August 29th, 2000
      - Coding substantially completed
    September 3rd, 2000
      - Commenting completed. Test phase begin
    September 9th, 2000
      - Radical restructuring of Winsock architecture
    September 28th, 2000
      - Discovery, Description, Control, Presentation, Eventing all substantially working
      - Tweak phase started
    October 10th, 2000
      - Exception handling added
    October 11th, 2000
      - HTTP server detects if default port is occupied and tries alternates
    October 11th, 2000
      - Works with Windows Me CP & UCP. Declare "Beta Release"
    October 12th, 2000
      - Automatic URL creation on component name change
    October 13th, 2000
      - Bug in QueryStateVariable fixed
    October 16th, 2000
      - fCheckEmbeddedItems added
    October 17th, 2000
      - About_UPnP_Objects added
    October 18th, 2000
      - Release Candidate 1
    December 3rd, 2000
      - Error reporting improved. RC-2
    December 13th, 2000
      - AlwaysMakeNewUID and AutoConnect functionality added
    January 15th, 2001
      - Random delay on AutoConnect,
      - Content-Type checking on Control messages
      - Ignore <?xml > and <!-- > tags in control messages
      - Check action names in xml
      - Return error codes and error message from user actions
      - Parser accepts <tagname/> as the same as <tagname></tagname>
      - Wrap event sequence key to 1 rather than 0
    January 27, 2001
      - ModelName, ServiceID and IconName differentiated from component names
    February 8, 2001
      - .PNG graphic types added
    March 5th, 2001
      - Merged fCheckEmbeddedItems into DoFixups
    March 8th, 2001
      - Minor cosmetics
    April 13th, 2001
      - Component local fRootDevice added to objects; global g_RootDevice removed;
        constructors and DoFixups extended to initialise fRootDevice accordingly
      - Corrected check for HTTP error conditions (2x)
      - Action execute automatically sets the new IN RSV values from in-args, and automatically
        returns the out-args from the OUT RSV's
      - Fixed problem with Control Action Invoke on Windows XP
    April 21st, 2001
      - Repeated strings all centralised to minimise memory
    April 28th, 2001
      - Automatically correct for \0 bug on Windows Me eventing
      - Remaining strings centralised
      - if there are no evented variables then leave eventSubURL tag empty
      - ServiceSchema and ServiceID schema published...
    May 4th, 2001
      - Registration function added
    May 22nd, 2001
      - xml parsing procedures speeded up
    June 5th, 2001
      - Implemented truncated M-Search e.g. for device/service types w/o version number
      - Improve formatting & speed of HTTP output
    June 10th, 2001
      - Version 1.0 declared
    June 21st, 2001
      - M-Search permits UUID's with or without hyphens
    June 27th, 2001
      - OnStateVariableChanged event added
    June 28th, 2001
      - Only process 3+2d+k messages ( rather than 3+2d+s )
      - Default max_age set to 2100 rather than 1800 ( spec says it must be > 1800 )
    July 15th, 2001
      - Excess #0 byte removed from UDP messages
      - XML_VerString not sent in event messages (compatibility with Windows ME
    August 1st, 2001
      - Path names standardised
      - StateVariable.Value returns DefaultValue if Value = ''
    August 8th, 2001
      - ServiceNameSpace implemented (and DeviceNameSpace as stub)
    January 2002
      - New SOAP error codes for UPnP security
      - Security permission object created & permissions list added to Actions & StateVariables
      - Store and read UIDs from registry
      - RequiresAuthorisation and RequiresPrivacy properties added
      - fDontPassArguments flag added
      - Various refinements in XML parser
    April 2002
      - UPnP security DSig checking and wrapping added (references UPnP_DevSec module)
    May 18th, 2002
      - UDP response handling cleaned up to comply with UPnP Certification Test requirements
    June 2005
      - Socket handling migrated to Indy descendents
    July 22, 2005
      - Release v1.5.3
    September 18, 2005
      - Added XML encoding & decoding to state variable payload transfers
      - Release v1.5.04
}

unit UPnP_Components;

interface

uses
  Classes,
  ComObj,
  Contnrs,
  Controls,
  ExtCtrls,
  Forms,
  Graphics,
  Messages,
  SyncObjs,
  SysUtils,
  UPnP_Globals,
  UPnP_IndyExtensions,
  UPnP_XmlStreamer, Windows;

type
  {
    TUPnP_VariableType: defines the types of variables acceptable in UPnP...
  }
  TUPnP_VariableType = (ui1, ui2, ui4, i1, i2, i4, int, r4, r8, number, fixed_14_4,
    float_, char_, string_, date_, dateTime, dateTime_tz, time,
    time_tz, boolean_, bin_base64, bin_hex, uri, uuid);

  {
    TUPnP_ArgumentType: defines the types of arguments acceptable in UPnP...
  }
  TUPnP_ArgumentType = (Input, Output, OutputRetVal);

  {
    Defines the type of allowed values for state variables
  }
  TUPnP_AllowedValueType = (Anything, List, Range);

  {
    BitMask
  }
  TUPnP_BitMask = set of byte;

  {
    Logging flags
  }
  TUPnP_Logging_Flag  = (fLogMultiCastServer, fLogMultiCastClient,
    fLogUnicastClient, fLogTCPServer, fLogTCPClient);
  TUPnP_Logging_Flags = set of TUPnP_Logging_Flag;

  {
    Forward declarations
  }
  TUPnP_Component   = class;
  TUPnP_RootDevice  = class;
  TUPnP_StateVariable = class;
  TUPnP_CustomService = class;
  TUPnP_Service     = class;
  TUPnP_Action      = class;
  TUPnP_DeviceItem  = class;
  TUPnP_IconItem    = class;
  TUPnP_ServiceItem = class;
  TUPnP_ActionItem  = class;
  TUPnP_ArgumentItem = class;
  TUPnP_StateVariableItem = class;
  TUPnP_SubscriptionItem = class;
  TUPnP_DeviceCollection = class;
  TUPnP_ServiceCollection = class;
  TUPnP_IconCollection = class;
  TUPnP_StateVariableCollection = class;
  TUPnP_ActionCollection = class;
  TUPnP_ArgumentCollection = class;
  TUPnP_SubscriptionCollection = class;
  TUPnP_CustomDevice = class;
  TUPnP_SecurityPermission = class;
  TUPnP_SecurityPermissionItem = class;
  TUPnP_SecurityPermissionCollection = class;
  TUPnP_DeviceSecurityBase = class;

  {
    ELinkException: an exception type for bad link errors (missing or bad targets)
  }
  ELinkException = class(Exception);

  {
    TUPnP_ActionExecute: This is an event handler template which allows programmers
    to assign their own 'OnActionExecute' commands for TUPnP_Actions
    NB the function should return true if OK, otherwise it should return an integer error code
       and an error string
  }
  TUPnP_ActionExecute = function(Caller: TUPnP_Action;
    var ErrorCode, ErrorMessage: string): boolean of object;

  {
    types of HTTP response strings
  }
  THTTPResponseCodes = (msg_http_OK,
    err_Bad_Request,
    err_Not_Found,
    err_Precondition_Failed,
    err_Unsupported_Media_Type,
    err_Internal_Server_Error,
    err_Service_Unavailable);

  {
    types of SOAP errors
  }
  TSOAPErrorCodes = (err_Invalid_Action,
    err_Invalid_Arguments,
    err_Out_Of_Sync,
    err_Invalid_Variable,
    err_Action_Failed,
    err_Argument_Value_Invalid,
    err_Argument_Value_Out_of_Range,
    err_Optional_Action_Not_Implemented,
    err_Out_Of_Memoryx,
    err_RSV_Not_Implemented,
    err_Action_Not_Authorized,
    err_Action_Not_Permitted,
    err_Signature_Failure,
    err_Signature_Malformed_or_Missing,
    err_Invalid_Sequence,
    err_Invalid_ControlURL,
    err_Signature_Bad_Digest,
    err_Algorithm_Not_Supported,
    err_No_IPSec,
    err_Wrong_Device,
    err_Invalid_Decryption_Key,
    err_Insufficient_Memory,
    err_Device_Already_Owned,
    err_Malformed_Ownership_Claim,
    err_May_Not_Delete_Self,
    err_Owner_Does_Not_Exist,
    err_Owner_Already_Present,
    err_Less_Than_Two_Owners,
    err_ACL_Entry_Already_Present,
    err_ACL_Entry_Does_Not_Exist,
    err_Malformed_ACL_Entry,
    err_Incorrect_ACL_Version,
    err_Invalid_Session_Key_ID,
    err_Invalid_Session_Sequence,
    err_Session_Key_Does_Not_Exist,
    err_Bad_Public_Key);

  code_desc = (Code, Desc);

  {
    types of SOAP authorisation results
  }
  TUPnP_AuthorisationResult = (auth_MalformedSoap,
    auth_UnknownSession,
    auth_Bad_PublicKey,
    auth_InsufficientPermissions,
    auth_WrongSequenceNumber,
    auth_SignatureNotVerified,
    auth_BadControlURL,
    auth_BadDigest,
    auth_GeneralError,
    auth_Accepted);

  {
    Use a basic TComponent for minimum footprint ..
  }
  TUPnP_Component = class(TComponent)
  protected
    fConnected: boolean;
    fRootDevice: TUPnP_RootDevice;
    fOwnerDevice: TUPnP_CustomDevice;
    fOwnerService: TUPnP_CustomService;
    fOwnerAction: TUPnP_Action;
    fOnStateChange: TNotifyEvent;
    fPropertyCount: cardinal;
    syncStateChangeCritSect: TCriticalSection;
    syncSender: TObject;
    procedure syncStateChange;
    procedure SetRootDevice(aRootDevice: TUPnP_RootDevice);
    procedure SetOwnerDevice(aOwnerDevice: TUPnP_CustomDevice);
    procedure SetOwnerService(aOwnerService: TUPnP_CustomService);
    procedure SetOwnerAction(aOwnerAction: TUPnP_Action);
    function GetDisplayName: string; virtual; abstract;
    procedure PublishEvents; virtual;
    procedure HTTPError(Response: TUPnP_HTTPServerResponseWrapper;
      ErrCode: THTTPResponseCodes);
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); virtual;
    procedure Connect; virtual;
    procedure Disconnect; virtual;
    function GetPropertyName(anIndex: cardinal): string; virtual;
    function GetPropertyValue(anIndex: cardinal): string; virtual;
    procedure SetPropertyValue(anIndex: cardinal; aValue: string); virtual;
    function GetPropertyEditable(anIndex: cardinal): boolean; virtual;
    procedure DoStateChange(Sender: TObject); virtual;
    class function PropertyAsHTML(aName, aValue: string): string;
    class function LinkAsHTML(aName, aValue: string): string;
    function AsHTML: string; virtual;
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Reset; virtual;
    class procedure About;
    class function ServeFile(const aFileName: string;
      Response: TUPnP_HTTPServerResponseWrapper): boolean;
    class function GetMimeType(aFileName: string): TUPnP_MimeType;
    property PropertyName[anIndex: cardinal]: string Read GetPropertyName;
    property PropertyValue[anIndex: cardinal]: string
      Read GetPropertyValue Write SetPropertyValue;
    property IsPropertyEditable[anIndex: cardinal]: boolean Read GetPropertyEditable;
    property PropertyCount: cardinal Read fPropertyCount;
  published
    property OnStateChange: TNotifyEvent Read fOnStateChange Write fOnStateChange;
  end;

  {
    TUPnP_Icon:
    Recommended.
    Icon to depict device in a control point UI.
    Recommend one icon in each of the following sizes (width x height x depth):
    16x16x1, 16x16x8, 32x32x1, 32x32x8, 48x48x1, 48x48x8.
  }
  TUPnP_Icon = class(TUPnP_Component)
  protected
    fwidth: integer;
    fheight: integer;
    fdepth: integer;
    fURL: string;
    fIconName: string;
    fMimeType: TUPnP_MimeType;
    fPicture: TPicture;
    procedure SetPicture(aPicture: TPicture);
    function ServeImage(Response: TUPnP_HTTPServerResponseWrapper): boolean;
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    function ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    procedure SetIconName(aName: string);
    function GetDisplayName: string; override;
    procedure SetName(const NewName: TComponentName); override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    function AsHTML: string; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property IconWidth: integer Read fWidth Write fWidth default 32;
    property IconHeight: integer Read fHeight Write fHeight default 32;
    property IconDepth: integer Read fDepth Write fDepth default 8;
    property IconName: string Read fIconName Write SetIconName;
    property Picture: TPicture Read fPicture Write SetPicture;
    property MimeType: TUPnP_MimeType Read fMimeType Write fMimeType;
  end;

  {
    TUPnP_CustomDevice:
    Base UPnP device object.
    Actual device objects are derived from this
  }
  TUPnP_CustomDevice = class(TUPnP_Component)
  protected
    fDeviceVersion: string;
    fdeviceType: string;
    fdeviceSchema: string;
    fmodelName: string;
    ffriendlyName: string;
    fmanufacturer: string;
    fmanufacturerURL: string;
    fmodelDescription: string;
    fmodelNumber: string;
    fmodelURL: string;
    fserialNumber: string;
    fpresentationURL: string;
    fUDN: string;
    fUPC: string;
    fPresentationHTMLText: TStringList;
    fDescriptionURL: string;
    fIcons: TUPnP_IconCollection;
    fServices: TUPnP_ServiceCollection;
    fdevices: TUPnP_DeviceCollection;
    fAlwaysMakeNewUID: boolean;
    fDeviceTypeExpanded: string;
    fRegistryPath: string;
    procedure SetDevices(Value: TUPnP_DeviceCollection);
    procedure SetDevicetype(aName: string);
    procedure SetIcons(Value: TUPnP_IconCollection);
    procedure SetServices(Value: TUPnP_ServiceCollection);
    procedure SetPresentationHTMLText(Value: TStringList);
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    procedure CollectAliveMessages(aList: TUPnP_NotificationCollection); virtual;
    procedure CollectByeByeMessages(aList: TUPnP_NotificationCollection); virtual;
    procedure CollectMSearchResponses(Request: TUPnP_MSearchRequest;
      aList: TUPnP_NotificationCollection); virtual;
    function ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessDescriptionGet(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessPresentationGet(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function GetDescriptionURL: string; virtual;
    procedure OnHeartBeat(Sender: TObject); virtual;
    procedure PublishEvents; override;
    procedure SetModelName(aName: string);
    function GetDisplayName: string; override;
    procedure SetName(const NewName: TComponentName); override;
    procedure GetRegistryData;
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    procedure Connect; override;
    procedure Disconnect; override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    procedure DoStateChange(Sender: TObject); override;
    function AsHTML: string; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Reset; override;
    property Devices: TUPnP_DeviceCollection Read fDevices Write SetDevices;
    property Icons: TUPnP_IconCollection Read fIcons Write SetIcons;
    property Services: TUPnP_ServiceCollection Read fServices Write SetServices;
    property OwnerDevice: TUPnP_CustomDevice Read fOwnerDevice;
    property RootDevice: TUPnP_RootDevice Read fRootDevice;
    property RegistryPath: string Read fRegistryPath;
    property DeviceSchema: string Read fdeviceSchema Write fdeviceSchema;
    property DeviceType: string Read fdevicetype Write SetDevicetype;
    property DeviceVersion: string Read fDeviceVersion Write fDeviceVersion;
    property Manufacturer: string Read fmanufacturer Write fmanufacturer;
    property ManufacturerURL: string Read fmanufacturerURL Write fmanufacturerURL;
    property FriendlyName: string Read ffriendlyName Write ffriendlyName;
    property ModelDescription: string Read fmodelDescription Write fmodelDescription;
    property ModelName: string Read fmodelName Write SetModelName;
    property ModelNumber: string Read fmodelNumber Write fmodelNumber;
    property ModelURL: string Read fmodelURL Write fmodelURL;
    property SerialNumber: string Read fserialNumber Write fserialNumber;
    property UniqueDeviceNumber: string Read fUDN Write fUDN;
    property UniversalProductCode: string Read fUPC Write fUPC;
    property PresentationHTMLText: TStringList
      Read fPresentationHTMLText Write SetPresentationHTMLText;
    property AlwaysMakeNewUID: boolean Read fAlwaysMakeNewUID Write fAlwaysMakeNewUID;
  end;

  {
    TUPnP_Device:
    Actual implementation of a UPnP device.
  }
  TUPnP_Device = class(TUPnP_CustomDevice)
  published
    property AlwaysMakeNewUID;
    property DeviceSchema;
    property DeviceType;
    property DeviceVersion;
    property FriendlyName;
    property Manufacturer;
    property ManufacturerURL;
    property ModelDescription;
    property ModelName;
    property ModelNumber;
    property ModelURL;
    property SerialNumber;
    property PresentationHTMLText;
    property UniqueDeviceNumber;
    property UniversalProductCode;
    property Icons;
    property Devices;
    property Services;
  end;

  {
    TUPnP_RootDevice:
    Special variant of a TUPnP_Device to handle the specific actions that are only
    required of root devices.
  }
  TUPnP_RootDevice = class(TUPnP_CustomDevice)
  protected
    fUdpMulticastSender: TUPnP_MulticastSender;
    fUdpMulticastListener: TUPnP_MulticastListener;
    fUdpUnicastSender: TUPnP_UnicastSender;
    fTcpServer: TUPnP_HTTPServer;
    fURLBase: string;
    fExpiry: TDateTime;
    fAutoConnect: boolean;
    fTimeToLive: cardinal;
    fHeartBeatInterval: cardinal;
    fMaxAge: cardinal;
    fSocketTimeout: cardinal;
    fMultiCastIPAddress: string;
    fMultiCastPort: cardinal;
    fHTTPPort: cardinal;
    fOnLogMessage: TUPnP_LoggingCallbackProc;
    fLoggingFlags: TUPnP_Logging_Flags;
    fAliveMessages: TUPnP_NotificationCollection;
    fByeByeMessages: TUPnP_NotificationCollection;
    fMXResponses: TUPnP_NotificationCollection;
    fSocketsInitialised: boolean;
    fHeartBeatTimer: TTimer;
    fAliveTimer: TTimer;
    fMXTimer: TTimer;
    fGoOfflineTimer: TTimer;
    fPublishEventsTimer: TTimer;
    fFirstShow: boolean;
    fOldShowEvent: TNotifyEvent;
    fOldCloseQueryEvent: TCloseQueryEvent;
    fApplicationClosing: boolean;
    syncLoggingCritSect: TCriticalSection;
    syncLoggingType: string;
    syncLoggingMessage: string;
    procedure Show(Sender: TObject);
    procedure CloseQuery(Sender: TObject; var CanClose: boolean);
    procedure InitSockets;
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); override;
    procedure CollectMSearchResponses(Request: TUPnP_MSearchRequest;
      aList: TUPnP_NotificationCollection); override;
    function ProcessDescriptionGet(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; override;
    function GetDescriptionURL: string; override;
    procedure DispatchHTTPRequest(aRequestInfo: TUPnP_IdHTTPRequestInfo;
      aResponseInfo: TUPnP_IdHTTPResponseInfo);
    procedure DispatchUDPRequest(aData: TStream; aBinding: TUPnP_IdSocketHandle);
    procedure Connect; override;
    procedure Disconnect; override;
    procedure OnHeartBeat(Sender: TObject); override;
    procedure OnMXTimer(Sender: TObject);
    procedure OnAliveTimer(Sender: TObject);
    procedure OnGoOffline(Sender: TObject);
    procedure OnPublishEvents(Sender: TObject);
    procedure SetConnected(aValue: boolean); virtual;
    procedure CollectByeByeMessages(aList: TUPnP_NotificationCollection); override;
    procedure CollectAliveMessages(aList: TUPnP_NotificationCollection); override;
    procedure GetAliveMessages;
    procedure GetByeByeMessages;
    procedure SendByeByeNotifications;
    procedure SetTimeToLive(aTTL: cardinal);
    procedure SetHeartBeatInterval(aValue: cardinal);
    procedure SetMaxAge(avalue: cardinal);
    procedure SetSocketTimeout(aValue: cardinal);
    function GetIPAddress: string;
    procedure DoRootFixups;
    procedure SetLoggingFlags(aLoggingFlags: TUPnP_Logging_Flags);
    procedure SetOnLogMessage(aOnLogMessage: TUPnP_LoggingCallbackProc);
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    procedure SetPropertyValue(anIndex: cardinal; aValue: string); override;
    function GetPropertyEditable(anIndex: cardinal): boolean; override;
    procedure LoggingCallback(aLoggingType, aMessage: string);
    procedure syncLoggingCallback;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Loaded; override;
    function DoRecursiveHTTPCall(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    procedure MustPublishEvents;
    procedure MustGoOffline;
    { Following are non- published properties: to be used at run-time only }
    property Connected: boolean Read fConnected Write SetConnected;
    property URLBase: string Read fURLBase;
  published
    property DeviceSchema;
    property DeviceType;
    property DeviceVersion;
    property Manufacturer;
    property ManufacturerURL;
    property FriendlyName;
    property ModelDescription;
    property ModelName;
    property ModelNumber;
    property ModelURL;
    property SerialNumber;
    property PresentationHTMLText;
    property UniqueDeviceNumber;
    property UniversalProductCode;
    property Icons;
    property Devices;
    property Services;
    property AlwaysMakeNewUID;
    property AutoConnect: boolean Read fAutoConnect Write fAutoConnect default False;
    property TimeToLive: cardinal Read fTimeToLive Write SetTimeToLive default 4;
    property HeartBeatInterval: cardinal Read fHeartBeatInterval
      Write SetHeartBeatInterval default 10;
    property MaxAge: cardinal Read fMaxAge Write SetMaxAge default 2100;
    property SocketTimeout: cardinal Read fSocketTimeout Write fSocketTimeout default 30;
    property MultiCastPort: cardinal
      Read fMultiCastPort Write fMultiCastPort default 1900;
    property HTTPPort: cardinal Read fHTTPPort Write fHTTPPort default 8080;
    property MultiCastIPAddress: string Read fMultiCastIPAddress
      Write fMultiCastIPAddress; // default = '239.255.255.250';
    property OnLogMessage: TUPnP_LoggingCallbackProc
      Read fOnLogMessage Write SetOnLogMessage;
    property LoggingFlags: TUPnP_Logging_Flags Read fLoggingFlags Write SetLoggingFlags;
  end;

  {
    TUPnP_CustomService:
  }
  TUPnP_CustomService = class(TUPnP_Component)
  protected
    fServiceVersion: string;
    fServiceId: string;
    fserviceType: string;
    fserviceSchema: string;
    fServiceIDSchema: string;
    fSCPDURL: string;
    fcontrolURL: string;
    feventSubURL: string;
    fStateVariables: TUPnP_StateVariableCollection;
    fActions: TUPnP_ActionCollection;
    fSubscriptions: TUPnP_SubscriptionCollection;
    fEventNotificationDisabled: boolean;
    fServiceTypeExpanded: string;
    fFirstInstance: boolean;
    procedure SetActions(Value: TUPnP_ActionCollection);
    procedure SetStateVariables(Value: TUPnP_StateVariableCollection);
    function GetUDN: string;
    procedure SaveToXMLShort(ShortXMLDescription: TUPnP_XMLStream); virtual;
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    procedure CollectAliveMessages(aList: TUPnP_NotificationCollection); virtual;
    procedure CollectByeByeMessages(aList: TUPnP_NotificationCollection); virtual;
    procedure CollectMSearchResponses(Request: TUPnP_MSearchRequest;
      aList: TUPnP_NotificationCollection); virtual;
    function ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessDescriptionRequest(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessControlRequest(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessEventRequest(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessSUBSCRIBE(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function ProcessUNSUBSCRIBE(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function GetDescriptionURL: string; virtual;
    procedure PublishEvents; override;
    procedure SOAPError(Response: TUPnP_HTTPServerResponseWrapper;
      ErrCode: TSOAPErrorCodes);
    procedure CustomSOAPError(Response: TUPnP_HTTPServerResponseWrapper;
      ErrCode, ErrMsg: string);
    procedure OnHeartBeat(Sender: TObject); virtual;
    function GetDisplayName: string; override;
    function ProcessSOAPAction(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    procedure SetName(const NewName: TComponentName); override;
    procedure SetServiceType(const aName: string);
    procedure SetServiceID(const aName: string);
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    procedure Disconnect; override;
    property ServiceType: string Read fserviceType Write SetServiceType;
    property ServiceVersion: string Read fServiceVersion Write fServiceVersion;
    property ServiceSchema: string Read fServiceSchema Write fServiceSchema;
    property ServiceIDSchema: string Read fServiceIDSchema Write fServiceIDSchema;
    property EventNotificationDisabled: boolean
      Read fEventNotificationDisabled Write fEventNotificationDisabled;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    procedure DoStateChange(Sender: TObject); override;
    function AsHTML: string; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    property OwnerDevice: TUPnP_CustomDevice Read fOwnerDevice;
    property ControlURL: string Read fcontrolURL;
    property ServiceId: string Read fServiceId Write SetServiceID;
    property Actions: TUPnP_ActionCollection Read fActions Write SetActions;
    property StateVariables: TUPnP_StateVariableCollection
      Read fStateVariables Write SetStateVariables;
  end;

  {
    TUPnP_Service:
  }
  TUPnP_Service = class(TUPnP_CustomService)
  public
    property EventNotificationDisabled;
  published
    property ServiceId;
    property ServiceIDSchema;
    property ServiceType;
    property ServiceSchema;
    property ServiceVersion;
    property Actions;
    property StateVariables;
  end;

  {
    TUPnP_DeviceSecurityBase:
    Primitives for TUPnP_DeviceSecurity
  }
  TUPnP_DeviceSecurityBase = class(TUPnP_CustomService)
  protected
    function CheckDsigAuthorisation(aCaller: TUPnP_Component;
      aRequest: TUPnP_XMLStream): TUPnP_AuthorisationResult; virtual; abstract;
    procedure Sign(aCaller: TUPnP_Component; aBody: TUPnP_XMLStream;
      out aSecurityInfo: TUPnP_XMLStream); virtual; abstract;
  end;

  {
    TUPnP_Argument:
    Defines each of the elements of the formal argument list for an Action.
  }
  TUPnP_Argument = class(TUPnP_Component)
  protected
    fargumentname: string;
    fdirection: TUPnP_ArgumentType;
    frelatedStateVariable: TUPnP_StateVariable;
    fValue: string;
    fDontUpdateRSV: boolean;
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    function GetDisplayName: string; override;
    procedure SetName(const NewName: TComponentName); override;
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    function GetArgHTML(aServiceID, aActionName: string): string;
    procedure GetArgCode(aServiceID, aActionName: string; var inArgCode: string;
      var inArgCount: integer; var invokeCode: string; var outArgCode: string;
      var outArgCount: integer);
  public
    constructor Create(AOwner: TComponent); override;
    property OwnerAction: TUPnP_Action Read fOwnerAction;
    property Value: string Read fValue Write fValue;
  published
    property ArgumentName: string Read fArgumentname Write fArgumentname;
    property Direction: TUPnP_ArgumentType Read fdirection Write fdirection;
    property RelatedStateVariable: TUPnP_StateVariable
      Read frelatedStateVariable Write frelatedStateVariable;
    property DontUpdateRSV: boolean Read fDontUpdateRSV Write fDontUpdateRSV;
  end;

  {
    TUPnP_Action:
    Each action may have zero or more arguments.
  }
  TUPnP_Action = class(TUPnP_Component)
  protected
    factionname: string;
    fArguments: TUPnP_ArgumentCollection;
    fOnActionExecute: TUPnP_ActionExecute;
    fRequiresSigning: boolean;
    fRequiresAuthorization: boolean;
    fRequiresPrivacy: boolean;
    fSecurityPermissions: TUPnP_SecurityPermissionCollection;
    fDontPassArguments: TUPnP_BitMask;
    fDevSec: TUPnP_DeviceSecurityBase;
    fSignResponse: boolean;
    syncActionExecuteCritSect: TCriticalSection;
    syncErrCode: string;
    syncErrMsg: string;
    syncResult: boolean;
    procedure syncActionExecute;
    procedure SetArguments(Value: TUPnP_ArgumentCollection);
    procedure SetSecurityPermissions(Value: TUPnP_SecurityPermissionCollection);
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    function ProcessSOAPAction(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function GetDisplayName: string; override;
    procedure SetName(const NewName: TComponentName); override;
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    function AsHTML: string; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    property OwnerService: TUPnP_CustomService Read fOwnerService;
    property SignResponse: boolean Read fSignResponse Write fSignResponse;
  published
    property ActionName: string Read factionname Write factionname;
    property RequiresAuthorisation: boolean
      Read fRequiresAuthorization Write fRequiresAuthorization;
    property RequiresPrivacy: boolean Read fRequiresPrivacy Write fRequiresPrivacy;
    property RequiresSigning: boolean Read fRequiresSigning Write fRequiresSigning;
    property Arguments: TUPnP_ArgumentCollection Read fArguments Write SetArguments;
    property SecurityPermissions: TUPnP_SecurityPermissionCollection
      Read fSecurityPermissions Write SetSecurityPermissions;
    property OnActionExecute: TUPnP_ActionExecute
      Read fOnActionExecute Write fOnActionExecute;
  end;

  {
    TUPnP_StateVariable:
  }
  TUPnP_StateVariable = class(TUPnP_Component)
  protected
    fVariableName: string;
    fValue: string;
    fdataType: TUPnP_VariableType;
    fdefaultValue: string;
    fAllowedValues: TUPnP_AllowedValueType;
    fallowedStrings: TStringList;
    fminimum: single;
    fmaximum: single;
    fstep: single;
    fSendEvents: boolean;
    fEventTriggered: boolean;
    fRequiresSigning: boolean;
    fRequiresAuthorization: boolean;
    fRequiresPrivacy: boolean;
    fSecurityPermissions: TUPnP_SecurityPermissionCollection;
    fDevSec: TUPnP_DeviceSecurityBase;
    fSignResponse: boolean;
    fContainsXML: boolean;
    procedure SaveToXML(DescriptionXML: TUPnP_XMLStream); virtual;
    procedure SetDefaultValue(aValue: string);
    procedure SetValue(aValue: string);
    function GetValue: string;
    procedure SetEncodedValue(aValue: string);
    function GetEncodedValue: string;
    function GetDefaultValue: string;
    procedure SetAllowedStrings(aStrings: TStringList);
    procedure SaveEventToXML(EventXML: TUPnP_XMLStream); virtual;
    function ProcessSOAPAction(Request: TUPnP_HTTPServerRequestWrapper;
      Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function GetDisplayName: string; override;
    procedure SetSecurityPermissions(Value: TUPnP_SecurityPermissionCollection);
    procedure SetName(const NewName: TComponentName); override;
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
    procedure SetPropertyValue(anIndex: cardinal; aValue: string); override;
    function GetPropertyEditable(anIndex: cardinal): boolean; override;
    procedure DoStateChange(Sender: TObject); override;
    procedure SetDataType(aDataType: TUPnP_VariableType);
    procedure SetAllowedValues(aAllowedValues: TUPnP_AllowedValueType);
    procedure SetMinimum(aMinimum: single);
    procedure SetMaximum(aMaximum: single);
    procedure SetStep(aStep: single);
    function BoolStrAsIntStr(aBoolStr: string): string;
    function BoolStrAsTextStr(aBoolStr: string): string;
    function ConstrainValue(aValue: string): string;
    function AsArgHTML(aServiceID, aActionName, aArgumentName: string): string;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure CheckValueOK(aValue: string);
    property OwnerService: TUPnP_CustomService Read fOwnerService;
    property EncodedValue: string Read GetEncodedValue Write SetEncodedValue;
  published
    property StateVariableName: string Read fvariablename Write fvariablename;
    property DataType: TUPnP_VariableType Read fdataType Write SetDataType;
    property AllowedStrings: TStringList Read fallowedStrings Write SetAllowedStrings;
    property AllowedValues: TUPnP_AllowedValueType
      Read fAllowedValues Write SetAllowedValues default Anything;
    property Minimum: single Read fminimum Write SetMinimum;
    property Maximum: single Read fmaximum Write SetMaximum;
    property Step: single Read fstep Write SetStep;
    property RequiresAuthorisation: boolean
      Read fRequiresAuthorization Write fRequiresAuthorization;
    property RequiresPrivacy: boolean Read fRequiresPrivacy Write fRequiresPrivacy;
    property RequiresSigning: boolean Read fRequiresSigning Write fRequiresSigning;
    property SecurityPermissions: TUPnP_SecurityPermissionCollection
      Read fSecurityPermissions Write SetSecurityPermissions;
    property SendEvents: boolean Read fSendEvents Write fSendEvents;
    { Note: DefaultValue and Value must be declared AFTER the DataType and AllowedXX properties }
    property DefaultValue: string Read GetDefaultValue Write SetDefaultValue;
    property Value: string Read GetValue Write SetValue;
    property ContainsXML: boolean Read fContainsXML Write fContainsXML default False;
  end;

  {
    TUPnP_SecurityPermission:
    Defines the security permissions for Actions and StateVariables.
  }
  TUPnP_SecurityPermission = class(TUPnP_Component)
  protected
    fUIName, fACLentryName, fFullDescriptionURL, fShortDescription: string;
    function GetDisplayName: string; override;
    procedure SetName(const NewName: TComponentName); override;
    procedure DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList); override;
    function GetPropertyName(anIndex: cardinal): string; override;
    function GetPropertyValue(anIndex: cardinal): string; override;
  public
    constructor Create(AOwner: TComponent); override;
    procedure SaveToXML(aBuffer: TUPnP_XMLStream); virtual;
  published
    property UIName: string Read fUIName Write fUIName;
    property ACLentryName: string Read fACLentryName Write fACLentryName;
    property FullDescriptionURL: string Read fFullDescriptionURL
      Write fFullDescriptionURL;
    property ShortDescription: string Read fShortDescription Write fShortDescription;
  end;

  {
    TUPnP_URLStrings:
    A stringlist that separates out URLs in the format <url><url>
  }
  TUPnP_URLStrings = class(TStringList)
  public
    constructor Create(aString: string); overload;
  end;

  {
    TUPnP_SubscriptionItem:
    This is a class of object that records Control Point's subscriptions to TUPnP_CustomService's
    The TUPnP_CustomService maintains a list of TUPnP_SubscriptionItem's, it does the following:
      - adds new subscriptions when requested
      - deletes existing subscriptions when requested
      - deletes existing subscriptions when they expire
  }
  TUPnP_SubscriptionItem = class(TUPnP_Component)
  protected
    fSID: string;
    fCallBackURLs: TUPnP_URLStrings;
    fActiveURLIndex: integer;
    fExpiry: TDateTime;
    fSequenceKey: cardinal;
    fIsOldWinMeVersion: boolean;
    fVariables: integer;
    fPublishPendingFlags: PChar;
    fSubscriptionClientThread: TUPnP_SubscriptionClientThread;
    function Subscribe(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function Renew(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    function UnSubscribe(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; virtual;
    procedure PublishEvents; override;
    function Expired: boolean;
    function TimedOut: boolean;
    procedure SetPublishPendingFlag(aNo: integer);
    function GetDisplayName: string; override;
    procedure DestroyPendingThread;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure NotifyThreadDone(aThread: TThread);
  end;

  {
    TUPnP_CollectionItem:
    Common abstract collection item
  }
  TUPnP_CollectionItem = class(TCollectionItem)
  public
    procedure AssignComponent(aComponent: TUPnP_Component); virtual;
  end;

  {
    TUPnP_DeviceItem:
    "wrapper" to put TUPnP_Device in a TUPnP_DeviceCollection
  }
  TUPnP_DeviceItem = class(TUPnP_CollectionItem)
  protected
    fDevice: TUPnP_Device;
    procedure SetDevice(Value: TUPnP_Device);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property Device: TUPnP_Device Read fDevice Write SetDevice;
  end;

  {
    TUPnP_IconItem:
    "wrapper" to put TUPnP_Icon in a TUPnP_IconCollection
  }
  TUPnP_IconItem = class(TUPnP_CollectionItem)
  protected
    fIcon: TUPnP_Icon;
    procedure SetIcon(Value: TUPnP_Icon);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property Icon: TUPnP_Icon Read fIcon Write SetIcon;
  end;

  {
    TUPnP_ServiceItem:
    "wrapper" to put TUPnP_CustomService in a TUPnP_ServiceCollection
  }
  TUPnP_ServiceItem = class(TUPnP_CollectionItem)
  protected
    fService: TUPnP_CustomService;
    procedure SetService(Value: TUPnP_CustomService);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property Service: TUPnP_CustomService Read fService Write SetService;
  end;

  {
    TUPnP_ActionItem:
    "wrapper" to put TUPnP_Action in a TUPnP_ActionCollection
  }
  TUPnP_ActionItem = class(TUPnP_CollectionItem)
  protected
    fAction: TUPnP_Action;
    procedure SetAction(Value: TUPnP_Action);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property Action: TUPnP_Action Read fAction Write SetAction;
  end;

  {
    TUPnP_ArgumentItem:
    "wrapper" to put TUPnP_Argument in a TUPnP_ArgumentCollection
  }
  TUPnP_ArgumentItem = class(TUPnP_CollectionItem)
  protected
    fArgument: TUPnP_Argument;
    procedure SetArgument(Value: TUPnP_Argument);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property Argument: TUPnP_Argument Read fArgument Write SetArgument;
  end;

  {
    TUPnP_StateVariableItem:
    "wrapper" to put TUPnP_StateVariable in a TUPnP_StateVariableCollection
  }
  TUPnP_StateVariableItem = class(TUPnP_CollectionItem)
  protected
    fStateVariable: TUPnP_StateVariable;
    procedure SetStateVariable(Value: TUPnP_StateVariable);
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property StateVariable: TUPnP_StateVariable
      Read fStateVariable Write SetStateVariable;
  end;

  {
    TUPnP_SecurityPermissionItem:
    "wrapper" to put TUPnP_SecurityPermission in a TUPnP_SecurityPermissionCollection
  }
  TUPnP_SecurityPermissionItem = class(TUPnP_CollectionItem)
  protected
    fSecurityPermission: TUPnP_SecurityPermission;
    function GetDisplayName: string; override;
  public
    procedure AssignComponent(aComponent: TUPnP_Component); override;
  published
    property SecurityPermission: TUPnP_SecurityPermission
      Read fSecurityPermission Write fSecurityPermission;
  end;

  {
    TUPnP_OwnedCollection
  }
  TUPnP_OwnedCollection = class(TOwnedCollection)
  end;

  {
    TUPnP_DeviceCollection:
    A TOwnedCollection, that allows TUPnP_Device's (embedded in a TUPnP_DeviceItem) to be
    added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_Device directly
  }
  TUPnP_DeviceCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerDevice: TUPnP_CustomDevice;
    function GetDevice(index: integer): TUPnP_CustomDevice;
  public
    constructor Create(AOwner: TPersistent); virtual;
    property Device[i: integer]: TUPnP_CustomDevice Read GetDevice; default;
  end;

  {
    TUPnP_ServiceCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_CustomService's (embedded in a TUPnP_ServiceItem) to be
    added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_CustomService directly
  }
  TUPnP_ServiceCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerDevice: TUPnP_CustomDevice;
    function GetService(index: integer): TUPnP_CustomService;
  public
    constructor Create(AOwner: TPersistent); virtual;
    property Service[i: integer]: TUPnP_CustomService Read GetService; default;
  end;

  {
    TUPnP_IconCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_Icon's (embedded in a TUPnP_IconItem) to be
    added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_Icon directly
  }
  TUPnP_IconCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerDevice: TUPnP_CustomDevice;
    function GetIcon(index: integer): TUPnP_Icon;
  public
    constructor Create(AOwner: TPersistent); virtual;
    property Icon[i: integer]: TUPnP_Icon Read GetIcon; default;
  end;

  {
    TUPnP_StateVariableCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_StateVariable's (embedded in a TUPnP_StateVariableItem)
    to be added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_StateVariable directly
  }
  TUPnP_StateVariableCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerService: TUPnP_CustomService;
    function GetStateVariable(index: integer): TUPnP_StateVariable;
  public
    constructor Create(AOwner: TPersistent); virtual;
    property StateVariable[i: integer]: TUPnP_StateVariable Read GetStateVariable;
      default;
  end;

  {
    TUPnP_ActionCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_Action's (embedded in a TUPnP_ActionItem) to be
    added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_Action directly
  }
  TUPnP_ActionCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerService: TUPnP_CustomService;
    { pointer to the encapsulating service }
    function fGetAction(index: integer): TUPnP_Action;
    { get a pointer to the specified object in the collection }
  public
    property Action[i: integer]: TUPnP_Action Read fGetAction; default;
    constructor Create(AOwner: TPersistent); virtual;
  end;

  {
    TUPnP_ArgumentCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_Argument's (embedded in a TUPnP_ArgumentItem) to be
    added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_Argument directly
  }
  TUPnP_ArgumentCollection = class(TUPnP_OwnedCollection)
  protected
    //    fOwnerAction: TUPnP_Action;
    { pointer to the encapsulating action }
    function fGetArgument(index: integer): TUPnP_Argument;
    { get a pointer to the specified object in the collection }
  public
    constructor Create(AOwner: TPersistent); virtual;
    property Argument[i: integer]: TUPnP_Argument Read fGetArgument; default;
  end;

  {
    TUPnP_SecurityPermissionCollection:
    A TUPnP_OwnedCollection, that allows TUPnP_SecurityPermission's (embedded in a
    TUPnP_SecurityPermissionItem) to be added to the collection by means of the Object Inspector
    at design time
    Also has a property to access the embedded TUPnP_SecurityPermission directly
  }
  TUPnP_SecurityPermissionCollection = class(TUPnP_OwnedCollection)
  protected
    function fGetSecurityPermission(index: integer): TUPnP_SecurityPermission;
    { get a pointer to the specified object in the collection }
  public
    constructor Create(AOwner: TPersistent); virtual;
    property SecurityPermission[i: integer]: TUPnP_SecurityPermission
      Read fGetSecurityPermission; default;
  end;

  {
    TUPnP_SubscriptionCollection:
    A TOwnedCollection, that allows TUPnP_Subscription's (embedded in a TUPnP_SubscriptionItem)
    to be added to the collection by means of the Object Inspector at design time
    Also has a property to access the embedded TUPnP_Subscription directly
  }
  TUPnP_SubscriptionCollection = class(TObjectList)
  protected
    function fGetSubscription(index: integer): TUPnP_SubscriptionItem;
    { get a pointer to the specified object in the collection }
  public
    property Subscription[i: integer]: TUPnP_SubscriptionItem Read fGetSubscription;
      default;
  end;

// helper functions
function min(a, b: integer): integer;
function max(a, b: integer): integer;
function NowGMT: TDateTime;
function EscapedToXml(aString: string): string;
function XmlToEscaped(aString: string): string;

procedure StopDelphiIdeOnException(aEnable: boolean);

procedure Register;

implementation

uses
  Dialogs,
  Registry,
  StrUtils,
  UPnP_GraphicsExtensions,
  UPnP_Strings;

type
  // a "throw away" exception class; Note: must not be instantiated !!
  EIgnoreException = class(Exception);

var
  // temporary holder for exception class
  oldExceptionClass: TClass;

procedure StopDelphiIdeOnException(aEnable: boolean);
{
  Enable or disable the Delphi Debugger's "Stop on Exceptions" feature
  Status: FULLY TESTED
}
begin
{$warnings off}
  if DebugHook <> 0 then
{$warnings on}
  begin
    if aEnable = False then
    begin
      // re- route ExceptionClass to our "throw away" exception class
      if ExceptionClass <> EIgnoreException then
      begin
        oldExceptionClass := ExceptionClass;
        ExceptionClass    := EIgnoreException;
      end;
    end
    else
    begin
      // re- route ExceptionClass to the old exception class
      if ExceptionClass = EIgnoreException then
      begin
        ExceptionClass := oldExceptionClass;
      end;
    end;
  end;
end;

procedure Register;
{
  Register all components with Delphi
  Status: FULLY TESTED
}
begin
  RegisterComponents(_UPnP, [TUPnP_RootDevice,
    TUPnP_Device,
    TUPnP_Icon,
    TUPnP_Service,
    TUPnP_StateVariable,
    TUPnP_Action,
    TUPnP_Argument,
    TUPnP_SecurityPermission]);
end;

function NowGMT: TDateTime;
{
  Get Now in GMT form
  Status: FULLY TESTED
}
var
  st: TSystemTime;
begin
  GetSystemTime(st);
  Result := SystemTimeToDateTime(st);
end;

function CreateClassID_NoBraces: string;
{
  Returns a CLSID without the braces
  Status: FULLY TESTED
}
begin
  Result := Copy(CreateClassID, 2, 36);
end;

function min(a, b: integer): integer;
{
  Returns the lesser of two numbers
  Status: FULLY TESTED
}
begin
  if a > b then
  begin
    Result := b;
  end
  else
  begin
    Result := a;
  end;
end;

function max(a, b: integer): integer;
{
  Returns the greater of two numbers
  Status: FULLY TESTED
}
begin
  if a < b then
  begin
    Result := b;
  end
  else
  begin
    Result := a;
  end;
end;

class function TUPnP_Component.GetMimeType(aFileName: string): TUPnP_MimeType;
{
  Returns a file's Mime type depending on it's file name extension
  Status: FULLY TESTED
}
var
  s: string;
begin
  // get the mimetype according to the URL filename extension
  s := LowerCase(ExtractFileExt(aFileName));
  if s = MimeTypeExtension[HTML] then
  begin
    Result := HTML;
  end
  else if s = MimeTypeExtension[bmp] then
  begin
    Result := BMP;
  end
  else if s = MimeTypeExtension[jpg] then
  begin
    Result := JPG;
  end
  else if s = MimeTypeExtension[gif] then
  begin
    Result := GIF;
  end
  else if s = MimeTypeExtension[png] then
  begin
    Result := PNG;
  end
  else if s = MimeTypeExtension[xml] then
  begin
    Result := XML;
  end
  else if s = MimeTypeExtension[txt] then
  begin
    Result := TXT;
  end
  else if s = MimeTypeExtension[css] then
  begin
    Result := CSS;
  end
  else  // 'html' is a valid alternative to 'htm'...
  if s = dotHTML then
  begin
    Result := HTML;
  end
  else
  begin
    Result := UNKNOWN;
  end;
end;

function TUPnP_Component.AsHTML: string;
{
  Render a component as HTML
  Status: FULLY TESTED
}
begin
  { abstract }
  Result := '';
end;

class function TUPnP_Component.PropertyAsHTML(aName, aValue: string): string;
{
  Render a property as HTML
  Status: FULLY TESTED
}
begin
  Result := Format(propertyTemplate, [aName, aValue]);
end;

class function TUPnP_Component.LinkAsHTML(aName, aValue: string): string;
{
  Render a hyperlink property as HTML
  Status: FULLY TESTED
}
begin
  Result := Format(linkTemplate, [aName, aValue, aValue]);
end;

class function TUPnP_Component.ServeFile(const aFileName: string;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Serves up a file in HTTP form
  Status: FULLY TESTED
}
var
  st: TFileStream;
  fn: string;
begin
  // preset result to false
  Result := False;

  // set the current directory
  SetCurrentDir(ExtractFilePath(ParamStr(0)));
  fn := ExpandUNCFileName(aFileName);

  // if we have assigned a file containing HTML text then serve it up...
  if FileExists(fn) then
  begin

    st := TFileStream.Create(fn, fmOpenRead + fmShareDenyNone);
    Response.Response.ContentStream := st;
    Response.Response.ContentType := MimeTypeStr[GetMimeType(fn)];
    Response.Response.ResponseNo := 200;
    Response.Response.FreeContentStream := True;

    // we succeeded, so set result to true
    Result := True;
  end
  else
  begin
    Response.Response.ResponseNo := 404;
  end;
end;

constructor TUPnP_CustomDevice.Create(AOwner: TComponent);
{
  Creates the object, and collections for the embedded objects
  and initialises variables
  Status: FULLY TESTED
}
begin
  inherited;

  // create the various lists
  fIcons    := TUPnP_IconCollection.Create(self);
  fDevices  := TUPnP_DeviceCollection.Create(self);
  fServices := TUPnP_ServiceCollection.Create(self);
  fPresentationHTMLText := TStringList.Create;

  // create a UUID
  fUDN := CreateClassID_NoBraces;

  // default device schema is the UPnP schema...
  fDeviceSchema := Device_schema;

  // initialise the model name
  SetModelName(Name);

  // initialise other strings
  fdeviceType    := default_DeviceType;
  fDeviceVersion := '1';

  Inc(fPropertyCount, 12);
end;

procedure TUPnP_CustomDevice.Reset;
{
  Reset the device
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].Reset;
  end;

  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].Reset;
  end;
end;

function TUPnP_CustomDevice.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_DeviceType;
    end;
    2:
    begin
      Result := ui_DeviceVersion;
    end;
    3:
    begin
      Result := ui_FriendlyName;
    end;
    4:
    begin
      Result := ui_Manufacturer;
    end;
    5:
    begin
      Result := ui_ManufacturerURL;
    end;
    6:
    begin
      Result := ui_ModelDescription;
    end;
    7:
    begin
      Result := ui_ModelName;
    end;
    8:
    begin
      Result := ui_ModelNumber;
    end;
    9:
    begin
      Result := ui_ModelURL;
    end;
    10:
    begin
      Result := ui_SerialNumber;
    end;
    11:
    begin
      Result := ui_UDN;
    end;
    12:
    begin
      Result := ui_UPC;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_CustomDevice.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := fDeviceType;
    end;
    2:
    begin
      Result := fDeviceVersion;
    end;
    3:
    begin
      Result := fFriendlyName;
    end;
    4:
    begin
      Result := fManufacturer;
    end;
    5:
    begin
      Result := fManufacturerURL;
    end;
    6:
    begin
      Result := fModelDescription;
    end;
    7:
    begin
      Result := fModelName;
    end;
    8:
    begin
      Result := fModelNumber;
    end;
    9:
    begin
      Result := fModelURL;
    end;
    10:
    begin
      Result := fSerialNumber;
    end;
    11:
    begin
      Result := fUDN;
    end;
    12:
    begin
      Result := fUPC;
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

procedure TUPnP_CustomDevice.DoStateChange(Sender: TObject);
{
  Send state change events
  Status: FULLY TESTED
}
begin
  inherited;
  if assigned(fOwnerDevice) then
  begin
    fOwnerDevice.DoStateChange(Sender);
  end;
end;

function TUPnP_CustomDevice.GetDisplayName: string;
{
  Return the display name of the object
  Status: FULLY TESTED
}
begin
  Result := fModelName;
end;

procedure TUPnP_CustomDevice.GetRegistryData;
{
  Checks if the registry entry exists, creates it if needed, and gets some persistent data
  Status: FULLY TESTED
}
var
  Reg: TRegistry;
  firstload: boolean;
begin
  // don't do anything if we are designing mode
  if not (csDesigning in ComponentState) then
  begin

    fRegistryPath := _RegistryPathX + fDeviceType;

{$warnings off}
    // only touch the registry if we are not debugging and we don't have a default device type
    if (DebugHook = 0) and (fDeviceType <> default_DeviceType) then
    begin
{$warnings on}

      // we are in full native running mode, so do the registry stuff
      Reg := TRegistry.Create;
      try
        Reg.RootKey := HKEY_LOCAL_MACHINE;

        // if the registry path does not exist then it is our first time loading
        firstload := not Reg.KeyExists(fRegistryPath);

        // open resp. create the registry entry
        Reg.OpenKey(fRegistryPath, True);

        // if it is our first time loading
        if firstload then
        begin
          // if the AlwaysMakeNewUID property is true then create a new UUID
          if fAlwaysMakeNewUID then
          begin
            fUDN := CreateClassID_NoBraces;
          end;
          Reg.WriteString(_UDN, fUDN);
        end
        else
        begin
          // load the stored UUID
          fUDN := Reg.ReadString(_UDN);
        end;
      finally
        Reg.CloseKey;
        Reg.Free;
      end;
    end
    else
    begin
      // otherwise just create a plain UDN
      if fUDN = '' then
      begin
        fUDN := CreateClassID_NoBraces;
      end;
    end;
  end;
end;

destructor TUPnP_CustomDevice.Destroy;
{
  Free the embedded objects
  Status: FULLY TESTED
}
begin
  if fConnected then
  begin
    Disconnect;
  end;

  fIcons.Free;
  fDevices.Free;
  fServices.Free;
  fPresentationHTMLText.Free;
  inherited;
end;

function TUPnP_CustomDevice.AsHTML: string;
{
  Render as HTML
  Status: FULLY TESTED
}
var
  propHTML: string;
  deviceHTML: string;
  i: integer;
begin
  // device own properties...
  propHTML :=
    PropertyAsHTML(ui_DeviceType, fdeviceType) +
    PropertyAsHTML(ui_FriendlyName, ffriendlyName) +
    PropertyAsHTML(ui_Manufacturer, fmanufacturer) +
    PropertyAsHTML(ui_ModelDescription, fmodelDescription) +
    PropertyAsHTML(ui_ModelName, fModelName) +
    PropertyAsHTML(ui_ModelNumber, fmodelNumber) +
    PropertyAsHTML(ui_SerialNumber, fserialNumber) +
    PropertyAsHTML(ui_UDN, fUDN) +
    PropertyAsHTML(ui_UPC, fUPC) +
    LinkAsHTML(ui_ManufacturerURL, fmanufacturerURL) +
    LinkAsHTML(ui_ModelURL, fmodelURL) +
    LinkAsHTML(ui_DeviceDescription, GetDescriptionURL);

  // icons...
  for i := 0 to pred(Icons.Count) do
  begin
    propHTML := propHTML + Icons[i].AsHTML;
  end;

  { parameters:
      DEVICE ID 4x, DDD URL, DEVICE ID 6x, DEVICE TYPE,
      DEVICE PROPERTIES, DEVICE ID
  }
  deviceHTML := Format(deviceWrapper, [fmodelName, fmodelName, fmodelName,
    fmodelName, fDescriptionURL, fmodelName, fmodelName, fmodelName,
    fmodelName, fmodelName, fmodelName, fdeviceType, propHTML, fmodelName]);

  // services...
  for i := 0 to pred(Services.Count) do
  begin
    deviceHTML := deviceHTML + Services[i].AsHTML;
  end;

  // embedded devices...
  for i := 0 to pred(Devices.Count) do
  begin
    deviceHTML := deviceHTML + Devices[i].AsHTML;
  end;

  Result := deviceHTML;
end;

procedure TUPnP_CustomDevice.Connect;
{
  Connect the embedded objects
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].Connect;
  end;

  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].Connect;
  end;
end;

procedure TUPnP_CustomDevice.Disconnect;
{
  Disconnect the embedded objects
  Status: FULLY TESTED
}
var
  i: integer;
begin
  if not (csDestroying in ComponentState) then
  begin

    for i := 0 to pred(fServices.Count) do
    begin
      fServices[i].Disconnect;
    end;

    for i := 0 to pred(fDevices.Count) do
    begin
      fDevices[i].Disconnect;
    end;
  end;

  inherited;
end;

procedure TUPnP_CustomDevice.DoFixups(aRoot: TUPnP_RootDevice;
  aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  // set the root device
  SetRootDevice(aRoot);

  // scan the icons
  with fIcons do
  begin
    for i := 0 to pred(Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [IconStr, Name, Err_Not_Set]);
      end;

      if not (Icon[i] is TUPnP_Icon) then
      begin
        raise ELinkException.CreateFmt(BadLink, [IconStr, Name, Err_Invalid]);
      end;

      fIcons[i].DoFixups(aRoot, aServiceList);
    end;
  end;

  // scan the devices
  with fDevices do
  begin
    for i := 0 to pred(Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [DeviceStr, Name, Err_Not_Set]);
      end;

      if not (Device[i] is TUPnP_CustomDevice) then
      begin
        raise ELinkException.CreateFmt(BadLink, [DeviceStr, Name, Err_Invalid]);
      end;

      fDevices[i].DoFixups(aRoot, aServiceList);
    end;
  end;

  // if ServiceList is assigned, clear it.
  // - this list is used to detect multiple instances any given service type
  if Assigned(aServiceList) then
  begin
    aServiceList.Clear;
  end;

  // scan the services
  with fServices do
  begin
    for i := 0 to pred(Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [ServiceStr, Name, Err_Not_Set]);
      end;

      if not (Service[i] is TUPnP_CustomService) then
      begin
        raise ELinkException.CreateFmt(BadLink, [ServiceStr, Name, Err_Invalid]);
      end;

      fServices[i].DoFixups(aRoot, aServiceList);
    end;
  end;
end;

procedure TUPnP_CustomDevice.SetDevices(Value: TUPnP_DeviceCollection);
{
  Used by Object Inspector at design time to assign devices to the device collection
  Status: FULLY TESTED
}
begin
  fDevices.Assign(Value);
end;

procedure TUPnP_CustomDevice.SetIcons(Value: TUPnP_IconCollection);
{
  Used by Object Inspector at design time to assign icons to the icons collection
  Status: FULLY TESTED
}
begin
  fIcons.Assign(Value);
end;

procedure TUPnP_CustomDevice.SetServices(Value: TUPnP_ServiceCollection);
{
  Used by Object Inspector at design time to assign services to the services collection
  Status: FULLY TESTED
}
begin
  fServices.Assign(Value);
end;

procedure TUPnP_CustomDevice.SetModelName(aName: string);
{
  Changes the ModelName
  Status: FULLY TESTED
}
begin
  fModelName      := aName;
  fPresentationURL := '/' + fModelName + _presentationPath;
  fDescriptionURL := '/' + fModelName + _descriptionPath;
end;

procedure TUPnP_CustomDevice.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // describe the device's own parameters
  with DescriptionXML do
  begin
    WriteTagStart(_device);
    WriteTagAndValue(_deviceType, fDeviceTypeExpanded);
    WriteTagAndValue(_friendlyName, ffriendlyName);
    WriteTagAndValue(_manufacturer, fmanufacturer);
    WriteTagAndValue(_manufacturerURL, fmanufacturerURL);
    WriteTagAndValue(_modelDescription, fmodelDescription);
    WriteTagAndValue(_modelName, fmodelName);
    WriteTagAndValue(_modelNumber, fmodelNumber);
    WriteTagAndValue(_modelURL, fmodelURL);
    WriteTagAndValue(_serialNumber, fserialNumber);
    WriteTagAndValue(_UDN, UUIDStr + fUDN);
    WriteTagAndValue(_UPC, fUPC);

    // ask the embedded icons (if any) to describe themselves
    if ficons.Count > 0 then
    begin
      WriteTagStart(_iconList);
      try
        for i := 0 to pred(ficons.Count) do
        begin
          fIcons[i].SaveToXML(DescriptionXML);
        end;
      finally
        WriteTagEnd(_iconList);
      end;
    end;

    // ask the embedded services (if any) to describe themselves
    if fservices.Count > 0 then
    begin
      WriteTagStart(_serviceList);
      try
        for i := 0 to pred(fservices.Count) do
        begin
          fServices[i].SaveToXMLShort(DescriptionXML);
        end;
      finally
        WriteTagEnd(_serviceList);
      end;
    end;

    // ask the embedded devices (if any) to describe themselves
    // note that this could be called "recursively" for nested devices...
    if fdevices.Count > 0 then
    begin
      WriteTagStart(_deviceList);
      try
        for i := 0 to pred(fdevices.Count) do
        begin
          fDevices[i].SaveToXML(DescriptionXML);
        end;
      finally
        WriteTagEnd(_deviceList);
      end;
    end;

    // describe the "footer"
    WriteTagAndValue(_presentationURL, fpresentationURL);
    WriteTagEnd(_device);
  end;
end;

function TUPnP_CustomDevice.ProcessPresentationGet(Request:
  TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Responds to HTTP GET calls to the object's Presentation URL,
  Status: FULLY TESTED

  Responds either
  - by calling the programmers own callback procedure, or
  - by sending a programmer defined HTML file, or
  - (if all else fails) by sending a sparse HTML page (created on the fly)
}
begin
  // we will always handle this, so always return true...
  Result := True;

  if fPresentationHTMLText.Count > 0 then
  begin
    // serve the presentation HTML text
    Response.Response.ContentText := fPresentationHTMLText.Text;
    Response.Response.ContentType := MimeTypeStr[html];
    Response.Response.ResponseNo  := 200;
  end

  else
  begin
    // otherwise just show the standard web page
    Response.Response.ContentText := Format(htmlWrapper, [AsHTML]);
    Response.Response.ContentType := MimeTypeStr[html];
    Response.Response.ResponseNo  := 200;
  end;
end;

function TUPnP_CustomDevice.ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles TCP HTTP requests to this device
  Status: FULLY TESTED
}
var
  i:   integer;
  doc: string;
begin
  // Preset "result" to true so we can just exit if we handle the call
  //  (actually we always handle it - even if it is an error... )
  Result := True;

  if (Request.Request.CommandType = upnp_hcGET) then
  begin
    // get the path name
    doc := Request.Request.Document;

    // check if it is a call to our description URL and then handle it
    if AnsiSameText(doc, fDescriptionURL) and
      ProcessDescriptionGet(Request, Response) then
    begin
      exit;
    end;

    // check if it is a call for our Presentation URL and then handle it
    if AnsiSameText(doc, fPresentationURL) and
      ProcessPresentationGet(Request, Response) then
    begin
      exit;
    end;
  end;

  // attempt to process UPnP calls to the embedded services (if any)
  for i := 0 to pred(fServices.Count) do
  begin
    if fServices[i].ProcessHTTPRequest(Request, Response) then
    begin
      exit;
    end;
  end;

  // attempt to process UPnP calls to the embedded devices (if any)
  for i := 0 to pred(fDevices.Count) do
  begin
    if fDevices[i].ProcessHTTPRequest(Request, Response) then
    begin
      exit;
    end;
  end;

  // attempt to process UPnP calls to the embedded icons (if any)
  for i := 0 to pred(fIcons.Count) do
  begin
    if fIcons[i].ProcessHTTPRequest(Request, Response) then
    begin
      exit;
    end;
  end;

  // finally check if it is a general server call for any other file, and if so handle it
  if (Request.Request.CommandType = upnp_hcGET) then
  begin
    if ServeFile(doc, Response) then
    begin
      exit;
    end;
  end;

  // if we got this far, we should return a 404 error
  HTTPError(Response, err_Not_Found);
end;

function TUPnP_CustomDevice.ProcessDescriptionGet
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Returns the XML self description of the object
  Status: FULLY TESTED
}
begin
  // this is always overriden, so we do not need to handle the call...
  Result := False;
end;

procedure TUPnP_CustomDevice.CollectMSearchResponses(Request: TUPnP_MSearchRequest;
  aList: TUPnP_NotificationCollection);
{
  Receives a UPnP discovery request (M-Search)
  Status: FULLY TESTED

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

  function UUID_Match(aUID, aString: string): boolean;
  {
    Helper function that checks for a uuid match
  }
  var
    i, j, im, jm: integer;
  begin
    // preset result to false
    Result := False;

    // look for the uuid: prefix, and exit if not found
    if Pos(UUIDStr, aString) <> 1 then
    begin
      exit;
    end;

    // set up the initial indexes
    i := 1;
    j := length(UUIDStr) + 1;

    // set the maximum values of the indexes
    im := length(aUID);
    jm := length(aString);

    // loop
    while True do
    begin
      // no match - exit
      if aUID[i] <> aString[j] then
      begin
        exit;
      end;

      // increment the index into aUID
      Inc(i);
      // test for end of string
      if i > im then
      begin
        // we succesfully got here so exit with result = true
        Result := True;
        exit;
      end;
      // skip over any hyphens
      if aUID[i] = '-' then
      begin
        Inc(i);
      end;
      // end of string - exit
      if i > im then
      begin
        exit;
      end;

      // increment the index into aString
      Inc(j);
      // end of string - exit
      if j > jm then
      begin
        exit;
      end;
      // skip over any hyphens
      if aString[j] = '-' then
      begin
        Inc(j);
      end;
      // end of string - exit
      if j > jm then
      begin
        exit;
      end;
    end;
  end;

var
  i: integer;
  lResponse: TUPnP_MSearchResponse;
begin
  Assert(assigned(fRootDevice));

  // if the Search Target is ssdp:all or the ST header is empty...
  if SameText(SSDPAll, Request.SearchTarget) then
  begin
    // create a UDP Multicast sender socket
    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := UUIDStr + fUDN;
    lResponse.USN  := UUIDStr + fUDN;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);

    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := fDeviceTypeExpanded;
    lResponse.USN  := UUIDStr + fUDN + DoubleColon + fDeviceTypeExpanded;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);
  end;

  // if the search mask is uuid: plus our own UDN ...
  if UUID_Match(fUDN, Request.SearchTarget) then
  begin
    // create a UDP Multicast sender socket
    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := UUIDStr + fUDN;
    lResponse.USN  := UUIDStr + fUDN;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);

    // UUID's are unique, so there is no need to process anything else...
    exit;
  end;

  // if search target is a substring of our expanded device type
  if Pos(Request.SearchTarget, fDeviceTypeExpanded) > 0 then
  begin
    // create a UDP Multicast sender socket
    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := fDeviceTypeExpanded;
    lResponse.USN  := UUIDStr + fUDN + DoubleColon + fDeviceTypeExpanded;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);
  end;

  // ask the embedded services (if any) to notify themselves
  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].CollectMSearchResponses(Request, aList);
  end;

  // ask the embedded devices (if any) to notify themselves
  // note that this could be called "recursively" for nested devices...
  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].CollectMSearchResponses(Request, aList);
  end;
end;

procedure TUPnP_CustomDevice.SetPresentationHTMLText(Value: TStringList);
{
  Property setter
  Status: FULLY TESTED
}
begin
  fPresentationHTMLText.Assign(Value);
end;

procedure TUPnP_CustomDevice.CollectAliveMessages(aList: TUPnP_NotificationCollection);
{
  Sends an HTTP "alive" message on UDP multicast in the following format:
  Status: FULLY TESTED
}
var
  i: integer;
  lResponse: TUPnP_AliveNotification;
begin
  Assert(assigned(fRootDevice));

  // create a UDP Multicast sender socket
  lResponse      := TUPnP_AliveNotification.Create;
  lResponse.Location := GetDescriptionURL;
  lResponse.SearchTarget := UUIDStr + fUDN;
  lResponse.USN  := UUIDStr + fUDN;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.MaxAge := fRootDevice.fMaxAge;
  lResponse.AddToCollection(aList);

  lResponse      := TUPnP_AliveNotification.Create;
  lResponse.Location := GetDescriptionURL;
  lResponse.SearchTarget := fDeviceTypeExpanded;
  lResponse.USN  := UUIDStr + fUDN + DoubleColon + fDeviceTypeExpanded;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.MaxAge := fRootDevice.fMaxAge;
  lResponse.AddToCollection(aList);

  // ask the embedded services (if any) to notify themselves
  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].CollectAliveMessages(aList);
  end;

  // ask the embedded devices (if any) to notify themselves
  // note that this could be called "recursively" for nested devices...
  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].CollectAliveMessages(aList);
  end;
end;

procedure TUPnP_CustomDevice.CollectByeByeMessages(aList: TUPnP_NotificationCollection);
{
  Sends an HTTP "byebye" message on UDP multicast in the following format:
  Status: FULLY TESTED
}
var
  i: integer;
  lResponse: TUPnP_ByeByeNotification;
begin
  Assert(assigned(fRootDevice));

  lResponse      := TUPnP_ByeByeNotification.Create;
  lResponse.SearchTarget := UUIDStr + fUDN;
  lResponse.USN  := UUIDStr + fUDN;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.AddToCollection(aList);

  lResponse      := TUPnP_ByeByeNotification.Create;
  lResponse.SearchTarget := fDeviceTypeExpanded;
  lResponse.USN  := UUIDStr + fUDN + DoubleColon + fDeviceTypeExpanded;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.AddToCollection(aList);

  // ask the embedded services (if any) to notify themselves
  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].CollectByeByeMessages(aList);
  end;

  // ask the embedded devices (if any) to notify themselves
  // note that this could be called "recursively" for nested devices...
  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].CollectByeByeMessages(aList);
  end;
end;

function TUPnP_CustomDevice.GetDescriptionURL: string;
{
  Get the Owner Devices Description URL
   - may call itself recursively for nested devices
  Status: FULLY TESTED
}
begin
  Assert(assigned(fOwnerDevice));
  Result := fOwnerDevice.GetDescriptionURL;
end;

procedure TUPnP_CustomDevice.OnHeartBeat(Sender: TObject);
{
  Checks whether the subscriptions on any embedded objects have expired
  Status: FULLY TESTED
}
var
  i: integer;
begin
  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].OnHeartBeat(Sender);
  end;

  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].OnHeartBeat(Sender);
  end;
end;

procedure TUPnP_CustomDevice.PublishEvents;
{
  Asks any embedded objects to publish any outstanding event messages
  Status: FULLY TESTED
}
var
  i: integer;
begin
  for i := 0 to pred(fServices.Count) do
  begin
    fServices[i].PublishEvents;
  end;

  for i := 0 to pred(fDevices.Count) do
  begin
    fDevices[i].PublishEvents;
  end;
end;

procedure TUPnP_CustomDevice.SetDeviceType(aName: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fModelName = '') then
    begin
      ModelName := aName;
    end;
  end;
  fDeviceType := aName;
end;

procedure TUPnP_CustomDevice.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fdeviceType = default_DeviceType) or (fdeviceType = '') then
    begin
      DeviceType := NewName;
    end;
  end;
  inherited;
end;

constructor TUPnP_CustomService.Create(AOwner: TComponent);
{
  Creates the object, and collection lists for embedded objects,
  and initialises variables
  Status: FULLY TESTED
}
begin
  inherited;

  // create the various lists
  fActions := TUPnP_ActionCollection.Create(self);
  fStateVariables := TUPnP_StateVariableCollection.Create(self);
  fSubscriptions := TUPnP_SubscriptionCollection.Create;
  fSubscriptions.OwnsObjects := True;

  // default service schema is the UPnP schema...
  fServiceSchema := Service_Schema;

  // default service ID schema is the UPnP schema...
  fServiceIDSchema := ServiceID_Schema;

  // initialise serviceID
  ServiceID := Name;

  // initialise other stuff
  fServiceVersion := '1';
  fserviceType    := default_ServiceType;
  fFirstInstance  := True;

  Inc(fPropertyCount, 3);
end;

destructor TUPnP_CustomService.Destroy;
{
  Free the embedded objects
  Status: FULLY TESTED
}
begin
  if fConnected then
  begin
    Disconnect;
  end;

  fActions.Free;
  fStateVariables.Free;
  fSubscriptions.Free;
  inherited;
end;

function TUPnP_CustomService.AsHTML: string;
{
  Render as HTML
  Status: FULLY TESTED
}
var
  propHTML: string;
  eventCode: string;
  qsvTmp: string;
  qsvCodeA: string;
  qsvCodeB: string;
  lVarName: string;
  i: integer;
begin
  eventCode := '';
  qsvCodeB  := '';
  qsvCodeA  := '';

  // get the property HTML for the service itself
  propHTML := PropertyAsHTML(ui_ServiceID, fServiceId) +
    PropertyAsHTML(ui_ServiceType, fserviceType) +
    LinkAsHTML(ui_ServiceDescription, fSCPDURL);

  // get the property HTML, Event Code and QSV code for the state variables
  for i := 0 to pred(fStateVariables.Count) do
  begin
    lVarName := fStateVariables[i].fVariableName;

    propHTML := propHTML + Format(serviceTemplate,
      [lVarName, eventedStr[fStateVariables[i].fSendEvents],
      fServiceID, lVarName]);

    qsvTmp := Format(qsvCodeTemplate, [fServiceID, lVarName, fServiceID,
      lVarName, BoolToStr(fStateVariables[i].fContainsXML)]);

    qsvCodeB := qsvCodeB + qsvTmp;

    if fStateVariables[i].fSendEvents then
    begin
      eventCode := eventCode + Format(eventCodeTemplate,
        [lVarName, fServiceID, lVarName, BoolToStr(fStateVariables[i].fContainsXML)]);
    end
    else
    begin
      qsvCodeA := qsvCodeA + qsvTmp;
    end;
  end;

  // get the HTML for the Actions
  for i := 0 to pred(fActions.Count) do
  begin
    propHTML := propHTML + fActions[i].AsHTML;
  end;

  { 16x parameters:
      SERVICE ID, SERVICE TYPE, SERVICE ID, SERVICE PROPERTY HTML, SERVICE ID,
      SERVICE EVENT CODE, SERVICE ID 2x, DEVICE ID, SERVICE ID, SERVICE QSV CODE,
      SERVICE ID, SERVICE ID, SERVICE ID, SERVICE QSV CODE, SERVICE ID
  }
  Result := Format(serviceWrapper, [fServiceId, fserviceType, fServiceId, propHTML,
    fServiceId, eventCode, fServiceId, fServiceId, fOwnerDevice.fmodelName,
    fServiceId, fServiceId, fServiceId, qsvCodeA, fServiceId, qsvCodeB, fServiceId]);
end;

function TUPnP_CustomService.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_ServiceId;
    end;
    2:
    begin
      Result := ui_ServiceType;
    end;
    3:
    begin
      Result := ui_ServiceVersion;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_CustomService.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := fServiceId;
    end;
    2:
    begin
      Result := fServiceType;
    end;
    3:
    begin
      Result := fServiceVersion;
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

procedure TUPnP_CustomService.DoStateChange(Sender: TObject);
{
  Send state change events
  Status: FULLY TESTED
}
begin
  inherited;
  if assigned(fOwnerDevice) then
  begin
    fOwnerDevice.DoStateChange(Sender);
  end;
end;

function TUPnP_CustomService.GetDisplayName: string;
{
  Return the display name of the object
  Status: FULLY TESTED
}
begin
  Result := fServiceID;
end;

function TUPnP_CustomService.GetUDN: string;
{
  Get the owner device's Uniqe Device Number
  Status: FULLY TESTED
}
begin
  Assert(assigned(fOwnerDevice));
  Result := fOwnerDevice.fUDN;
end;

procedure TUPnP_CustomService.SaveToXMLShort(ShortXMLDescription: TUPnP_XMLStream);
{
  Writes the "short" XML description of the service for use in the
  enclosing device's XML self description
  Status: FULLY TESTED
}
var
  i: integer;
  anyeventedvariables: boolean;
begin

  // check if there any evented variables in the service
  anyeventedvariables := False;
  for i := 0 to pred(fStateVariables.Count) do
  begin
    if fStateVariables[i].fSendEvents then
    begin
      anyeventedvariables := True;
      break;
    end;
  end;

  // describe the services's own parameters
  // NB this is called as part of a Describe Device call
  with ShortXMLDescription do
  begin
    WriteTagStart(_service);
    try
      WriteTagAndValue(_serviceType, fServiceTypeExpanded);
      // format the serviceID search header as "urn:upnp-org:serviceID:serviceID"
      WriteTagAndValue(_serviceId, Format(Schemas_ServiceIdHdrFmt,
        [fServiceIDSchema, fServiceID]));
      WriteTagAndValue(_SCPDURL, fSCPDURL);
      WriteTagAndValue(_controlURL, fcontrolURL);

      // if there are any evented variables then fill the eventSubURL tag
      if anyeventedvariables then
      begin
        WriteTagAndValue(_eventSubURL, feventSubURL);
      end
      else
      begin
        WriteTagAndValue(_eventSubURL, '');
      end

    finally
      WriteTagEnd(_service);
    end;
  end;
end;

function TUPnP_CustomService.ProcessSUBSCRIBE
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles event subscription requests by creating or renewing a subscription entry
  Status: FULLY TESTED

  Format of new subscription request is:
  SUBSCRIBE publisher path HTTP/1.1
  HOST: publisher host:publisher port
  CALLBACK: <delivery URL>
  NT: upnp:event
  TIMEOUT: Second-requested subscription duration

  Format of renewal request is:
  SUBSCRIBE publisher path HTTP/1.1
  HOST: publisher host:publisher port
  SID: uuid:subscription UUID
  TIMEOUT: Second-requested subscription duration
}
var
  i:  integer;
  sx: TUPnp_SubscriptionItem;
begin
  // preset result to true
  Result := True;

  // SID => renewal request
  if Request.SID <> '' then
  begin
    if (Request.NT <> '') or (Request.Callback <> '') then
      // wrong combination of headers
    begin
      HTTPError(Response, err_Bad_Request);
      exit;
    end;

    // check all subscriptions for one that matches -- if found then renew it
    for i := 0 to pred(fSubscriptions.Count) do
    begin
      if fSubscriptions[i].Renew(Request, Response) then
      begin
        exit;
      end;
    end;

    // could not find a match...
    HTTPError(Response, err_Precondition_Failed);
    exit;
  end;

  // NT + CALLBACK => new subscription request
  // check for either upnp:propchange (Windows Me) or upnp:event (UPnP specification)
  if SameText(Request.NT, upnpevent) or SameText(Request.NT, upnppropchange) then
  begin
    if Request.Callback <> '' then
    begin
      // create a subscription
      sx := TUPnP_SubscriptionItem.Create(self);

      // try to open the subscription
      if sx.Subscribe(Request, Response) then
      begin
        // add it to the subscription list
        fSubscriptions.Add(sx);
        exit;
      end
      else
        // bad subscription -- fall through...
      begin
        sx.Free;
      end;
    end;
    // missing Callback header -- fall through...
  end;

  // if we got this far it was bad - for one reason or another...
  HTTPError(Response, err_Precondition_Failed);
end;

function TUPnP_CustomService.ProcessUNSUBSCRIBE
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Processes un-subscribe requests for event call backs
  Status: FULLY TESTED

  Format of renewal request is:
  UNSUBSCRIBE publisher path HTTP/1.1
  HOST: publisher host:publisher port
  SID: uuid:subscription UUID

  Format of response is:
  HTTP/1.1 200 OK
}
var
  i: integer;
begin
  // preset result to true
  Result := True;

  // SID => unsubscribe request
  if Request.SID <> '' then
  begin
    if (Request.NT <> '') or (Request.Callback <> '') then
      // wrong combination of headers
    begin
      HTTPError(Response, err_Bad_Request);
      exit;
    end;

    // check all subscriptions to see to which one the unsubscribe applies
    for i := 0 to pred(fSubscriptions.Count) do
    begin
      if fSubscriptions[i].UnSubscribe(Request, Response) then
      begin
        // found a match - remove it from our list
        fSubscriptions.Delete(i);
        exit;
      end;
    end;

    // if we got here, then we couldn't find the SID - fall through...
  end;

  // if we got this far it was bad - for one reason or another...
  HTTPError(Response, err_Precondition_Failed);
end;

procedure TUPnP_CustomService.PublishEvents;
{
  Publish any outstanding events
  Status: FULLY TESTED
}
var
  i, j: integer;
begin
  // check all state variables to see if an event is waiting to be sent...
  for i := 0 to pred(fStateVariables.Count) do
  begin

    // if there is a pending event then
    with fStateVariables[i] do
    begin
      if fSendEvents and fEventTriggered then
      begin

        // set the flag to send the message to each subscriber
        for j := 0 to pred(fSubscriptions.Count) do
        begin
          fSubscriptions[j].SetPublishPendingFlag(i);
        end;

        // clear the event triggered flag
        fEventTriggered := False;
      end;
    end;
  end;

  // trigger the sending of the event for each subscriber
  for j := 0 to pred(fSubscriptions.Count) do
  begin
    fSubscriptions[j].PublishEvents;
  end;
end;

function TUPnP_CustomService.ProcessSOAPAction(Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles a SOAP request in the following format(s):
  Status: FULLY TESTED

  EITHER
  ======
    <soap:Envelope
        xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <soap:Body>
          <u:QueryStateVariable xmlns:u="urn:schemas-upnp-org:control-1-0">
              <u:varName>variableName</u:varName>
          </u:QueryStateVariable>
      </soap:Body>
    </soap:Envelope>

  OR
  ==
    <soap:Envelope
      xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
      soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <soap:Body>
            <u:actionName xmlns:u="urn:schemas-upnp-org:service:serviceType:v">
                  <argumentName>in arg value</argumentName>
                  other in args and their values go here, if any
            </u:actionName>
        </soap:Body>
    </soap:Envelope>
}
var
  i: integer;
begin
  // preset result so we can exit
  Result := True;

  // get the requested variable name from the request XML
  if Request.HasXmlStream then
  begin

    with Request.XMLStream do
    begin
      ResetParser;
      // Go to the Body
      GotoTagName(_Body);
      // move on to next tag
      NextTag;

      // if the soap action and tagname is QSV then process it
      if (Request.SOAPAction = _QueryStateVariable) and
        (TagName = _QueryStateVariable) then
      begin
        NextTag;

        // check for varName tag
        if SameText(TagName, _varName) then
        begin
          // find the correct variable name
          for i := 0 to pred(fStateVariables.Count) do
          begin
            if TagValue = fStateVariables[i].fVariableName then
            begin
              // and execute the query
              if fStateVariables[i].ProcessSOAPAction(Request, Response) then
              begin
                exit;
              end;
            end;
          end;
        end;

        // send invalid variable error message if we got this far
        SOAPError(Response, err_Invalid_Variable);
        Result := False;
        exit;
      end;

      // try to process it as an action
      // if the soap action and tagname match then process it
      if (Request.SOAPAction = TagName) then
      begin

        // find the correct action name
        for i := 0 to pred(fActions.Count) do
        begin
          if Request.SOAPAction = fActions[i].fActionName then
          begin
            // and execute the query
            Result := fActions[i].ProcessSOAPAction(Request, Response);
            exit;
          end;
        end;

        // send unknown action error message if we got this far
        SOAPError(Response, err_Invalid_Action);
        Result := False;
        exit;
      end;
    end;
  end;

  // return a general error message if we got this far
  Result := False;
end;

function TUPnP_CustomService.ProcessControlRequest
  (Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles HTTP requests on the control URL
  Status: FULLY TESTED

  Receives a SOAP HTTP INVOKE request in the following format(s):

  INVOKE
  ======
    POST path of control URL HTTP/1.1
    HOST: host of control URL:port of control URL
    CONTENT-LENGTH: bytes in body
    CONTENT-TYPE: text/xml; charset="utf-8"
    SOAPACTION: "urn:schemas-upnp-org:service:serviceType:v#actionName"

  NOTES
  =====
  If a request with POST is rejected with a response of "405 Method Not Allowed", then a
  control point may send a second request with method M-POST and MAN in the following format.

    M-POST path of control URL HTTP/1.1
    HOST: host of control URL:port of control URL
    CONTENT-LENGTH: bytes in body
    CONTENT-TYPE: text/xml; charset="utf-8"
    MAN: "http://schemas.xmlsoap.org/soap/envelope/"; ns=01
    01-SOAPACTION: "urn:schemas-upnp-org:service:serviceType:v#actionName"

  IMPLEMENTATION
  ==============
  The service checks if the POST URL refers to itself, and if so parses the XML envelope
  to determine if a valid action has been requested.

  Returns either
    i) an OK (200) response with the respective new control point value in XML,
    ii) an error (500) response
}
var
  s: string;
begin
  // Preset "result" to false so we can just exit if we can't handle the call
  Result := False;

  // get the method
  s := Request.Request.Command;

  // if it is not a POST or M-POST, it's not for us...
  if (not SameText(s, method_Post)) and (not SameText(s, method_MPost)) then
  begin
    exit;
  end;

  // check the content type is text/xml or application/xml -- if not then return error 415
  s := LowerCase(Request.Request.ContentType);
  if (Pos(MimeTypeStr[xml], s) = 0) and (Pos(application_Xml, s) = 0) then
  begin
    HTTPError(Response, err_Unsupported_Media_Type);
    Result := True;
    exit;
  end;

  // if there is a Soap Action header then attempt to process the SOAP Action call
  if (Request.SOAPAction <> '') then
  begin

    if ProcessSOAPAction(Request, Response) then
    begin
      // write the HTTP response
      with Response.Response do
      begin
        // write the headers
        ResponseNo := 200;
        ContentType := text_xml_utf8;
        Date   := NowGMT;
        Server := Server_Header;
      end;
      Response.EXT := True;
    end

    else
    begin
      // if we got response XML then send the full response
      if assigned(Response.Response.ContentStream) then
      begin
        with Response.Response do
        begin
          ResponseNo := 500;
          ContentType := text_xml_utf8;
          Date   := NowGMT;
          Server := Server_Header;
        end;
        Response.EXT := True;
      end
      // otherwise return a general server error
      else
      begin
        HTTPError(Response, err_Internal_Server_Error);
      end;
    end;

    // we handled the call one way or another ...
    Result := True;
  end;
end;

procedure TUPnP_CustomService.CollectMSearchResponses(Request: TUPnP_MSearchRequest;
  aList: TUPnP_NotificationCollection);
{
  Receives a UPnP discovery request (M-Search)
  Status: FULLY TESTED

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
var
  lResponse: TUPnP_MSearchResponse;
begin
  // if the Search Target is ssdp:all or is a substring of our expanded service type string
  if SameText(SSDPAll, Request.SearchTarget) or
    (Pos(Request.SearchTarget, fServiceTypeExpanded) > 0) then
  begin
    // create a UDP Multicast sender socket
    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := fServiceTypeExpanded;
    lResponse.USN  := UUIDStr + GetUDN + DoubleColon + fServiceTypeExpanded;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);
  end;
end;

function TUPnP_CustomService.ProcessEventRequest
  (Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles HTTP requests on the Eventing URL
  Status: FULLY TESTED
}
var
  cmd: string;
begin
  // Preset "result" to true so we can just exit if we handle the call
  Result := True;

  // get the method
  cmd := Request.Request.Command;

  // if it is a SUBSCRIBE for our Eventing URL, then handle it...
  if SameText(cmd, method_Subscribe) then
  begin
    if ProcessSUBSCRIBE(Request, Response) then
    begin
      exit;
    end;
  end;

  // if it is an UNSUBSCRIBE for our Eventing URL, then handle it...
  if SameText(cmd, method_UnSubscribe) then
  begin
    if ProcessUNSUBSCRIBE(Request, Response) then
    begin
      exit;
    end;
  end;

  // If we got to this point, then we did not handle the call...
  Result := False;
end;

function TUPnP_CustomService.ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles TCP HTTP requests for the service
  Status: FULLY TESTED
}
var
  doc, cmd: string;
begin
  // Preset "result" to true so we can just exit if we handle the call
  Result := True;

  // get the path name
  doc := Request.Request.Document;
  cmd := Request.Request.Command;

  // check if it is a call to our eventing URL
  if AnsiSameText(doc, feventSubURL) then
  begin
    if SameText(cmd, method_Subscribe) then
    begin
      if ProcessEventRequest(Request, Response) then
      begin
        exit;
      end;
    end;

    if SameText(cmd, method_UnSubscribe) then
    begin
      if ProcessEventRequest(Request, Response) then
      begin
        exit;
      end;
    end;
  end;

  // check if it is a GET call to our description URL, and if so process it...
  if AnsiSameText(doc, fSCPDURL) then
  begin
    if SameText(cmd, method_Get) then
    begin
      if ProcessDescriptionRequest(Request, Response) then
      begin
        exit;
      end;
    end;
  end;

  // check if it is a POST call to our control URL
  if AnsiSameText(doc, fControlURL) then
  begin
    if SameText(cmd, method_Post) then
    begin
      if ProcessControlRequest(Request, Response) then
      begin
        exit;
      end;
    end;

    // check if it is an M-POST call to our control URL
    if SameText(cmd, method_MPost) then
    begin
      if ProcessControlRequest(Request, Response) then
      begin
        exit;
      end;
    end;
  end;

  // If we got to this point, then we did not handle the call...
  Result := False;
end;

function TUPnP_CustomService.ProcessDescriptionRequest
  (Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Processes an HTTP get request for an XML description.
  Status: FULLY TESTED

  Request is in the following format:
    GET path to description HTTP/1.1
    HOST: host for description:port for description
    ACCEPT-LANGUAGE: language preferred by control point

  Response is in the format below:
    HTTP/1.1 200 OK
    CONTENT-LANGUAGE: language used in description
    CONTENT-LENGTH: Bytes in body
    CONTENT-TYPE: text/xml
    DATE: when responded
}
begin
  // get the XML body text for the Service
  SaveToXML(Response.XMLStream);
  with Response do
  begin
    Response.ResponseNo := 200;
    Response.ContentType := MimeTypeStr[xml];
    Response.Date   := NowGMT;
    Response.Server := Server_Header;
  end;
  Result := True;
end;

procedure TUPnP_CustomService.CollectAliveMessages(aList: TUPnP_NotificationCollection);
{
  Sends an HTTP "alive" message on UDP multicast
  Status: FULLY TESTED
}
var
  lResponse: TUPnP_AliveNotification;
begin
  Assert(assigned(fRootDevice));

  // when we go online, store the expanded service type string: urn:schemas-upnp-org:service:serviceType:v
  fServiceTypeExpanded := Format(Schemas_ServiceHdrFmt,
    [fServiceSchema, fServiceType, fServiceVersion]);

  // no need to send alive messages if we are not the first instance of this service type
  if not fFirstInstance then
  begin
    exit;
  end;

  // create a UDP Multicast sender socket
  lResponse      := TUPnP_AliveNotification.Create;
  lResponse.Location := GetDescriptionURL;
  lResponse.SearchTarget := fServiceTypeExpanded;
  lResponse.USN  := UUIDStr + GetUDN + DoubleColon + fServiceTypeExpanded;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.MaxAge := fRootDevice.fMaxAge;
  lResponse.AddToCollection(aList);
end;

procedure TUPnP_CustomService.Disconnect;
{
  Go off line
  Status: FULLY TESTED
}
begin
  // going off-line so clear all subscriptions
  while fSubscriptions.Count > 0 do
  begin
    fSubscriptions.Delete(0);
  end;
  inherited;
end;

procedure TUPnP_CustomService.CollectByeByeMessages(aList: TUPnP_NotificationCollection);
{
  Sends an HTTP "byebye" message on UDP multicast
  Status: FULLY TESTED
}
var
  lResponse: TUPnP_ByeByeNotification;
begin
  Assert(assigned(fRootDevice));

  // no need to send byebye messages if we are not the first instance of this service type
  if not fFirstInstance then
  begin
    exit;
  end;

  // send the URN device type notify message
  lResponse      := TUPnP_ByeByeNotification.Create;
  lResponse.SearchTarget := fServiceTypeExpanded;
  lResponse.USN  := UUIDStr + GetUDN + DoubleColon + fServiceTypeExpanded;
  lResponse.Host := Format(fmt_SU, [fRootDevice.fMultiCastIPAddress,
    fRootDevice.fMultiCastPort]);
  lResponse.AddToCollection(aList);
end;

procedure TUPnP_CustomService.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // the service must provide special header data
  with DescriptionXML do
  begin
    WriteTagStart(XML_VerString);
    WriteTagStartAndAttributes(_scpd, [_scpdXmlNS]);
    WriteTagStart(_specVersion);
    WriteTagAndValue(_major, _majorVersion);
    WriteTagAndValue(_minor, _minorVersion);
    WriteTagEnd(_specVersion);

    try
      // ask the embedded Actions (should be at least one) to describe themselves
      if factions.Count > 0 then
      begin
        WriteTagStart(_actionList);
        try
          for i := 0 to pred(factions.Count) do
          begin
            factions[i].SaveToXML(DescriptionXML);
          end;
        finally
          WriteTagEnd(_actionList);
        end;
      end;

      // ask the embedded State Variables (should be at least one) to describe themselves
      if fStateVariables.Count > 0 then
      begin
        WriteTagStart(_serviceStateTable);
        try
          for i := 0 to pred(fStateVariables.Count) do
          begin
            fStateVariables[i].SaveToXML(DescriptionXML);
          end;
        finally
          WriteTagEnd(_serviceStateTable);
        end;
      end;

    finally
      // the service must provide special footer data
      WriteTagEnd(_scpd);

      // add 1 new line at end
      WriteValues([CRLF]);
    end;
  end;
end;

function TUPnP_CustomService.GetDescriptionURL: string;
{
  Get the Owner Devices Description URL
   - may call itself recursively for nested devices.
  Status: FULLY TESTED
}
begin
  Assert(assigned(fOwnerDevice));
  Result := fOwnerDevice.GetDescriptionURL;
end;

procedure TUPnP_CustomService.CustomSOAPError(Response: TUPnP_HTTPServerResponseWrapper;
  ErrCode, ErrMsg: string);
{
  Return a SOAP Error 500 as below:-
  Status: FULLY TESTED

  HTTP/1.1 500 Internal Server Error
  CONTENT-LENGTH: bytes in body
  CONTENT-TYPE: text/xml; charset="utf-8"
  DATE: when response was generated
  EXT:
  SERVER: OS/version UPnP/1.0 product/version

  <soap:Envelope
    xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <soap:Body>
      <soap:Fault>
        <faultcode>soap:Client</faultcode>
        <faultstring>UPnPError</faultstring>
        <detail>
          <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
            <errorCode>error code</errorCode>
            <errorDescription>error string</errorDescription>
          </UPnPError>
        </detail>
      </soap:Fault>
    </soap:Body>
  </soap:Envelope>
}
begin
  with Response.XMLStream do
  begin
    WriteTagStart(XML_VerString);
    WriteTagStartAndAttributes(_sEnvelope, [_sEnvelopeAttrs]);
    WriteTagStart(_sBody);
    WriteTagStart(_sFault);
    WriteTagAndValue(_faultcode, _sClient);
    WriteTagAndValue(_faultstring, _UPnPError);
    WriteTagStart(_detail);
    WriteTagStartAndAttributes(_UPnPError, [_UPnPErrorXmlNS]);
    WriteTagAndValue(_errorCode, ErrCode);
    WriteTagAndValue(_errorDescription, ErrMsg);
    WriteTagEnd(_UPnPError);
    WriteTagEnd(_detail);
    WriteTagEnd(_sFault);
    WriteTagEnd(_sBody);
    WriteTagEnd(_sEnvelope);
    // add 1 new line at end
    WriteValues([CRLF]);
  end;
end;

procedure TUPnP_CustomService.SOAPError(Response: TUPnP_HTTPServerResponseWrapper;
  ErrCode: TSOAPErrorCodes);
{
  send a standard SOAP error message
  Status: FULLY TESTED
}
begin
  CustomSOAPError(Response, SOAP_Error[ErrCode, code], SOAP_Error[ErrCode, desc]);
end;

procedure TUPnP_CustomService.OnHeartBeat(Sender: TObject);
{
  Checks whether any event subscriptions have timed out, and if so deletes them
  Status: FULLY TESTED
}
var
  i: integer;
begin
  i := 0;
  while i < fSubscriptions.Count do
  begin

    // check for thread time outs
    if fSubscriptions[i].TimedOut then
    begin
      fSubscriptions[i].DestroyPendingThread;
    end;

    // check for subscription expiry
    if fSubscriptions[i].Expired then
    begin
      fSubscriptions.Delete(i);
    end
    else
    begin
      Inc(i);
    end;
  end;
end;

procedure TUPnP_CustomService.DoFixups(aRoot: TUPnP_RootDevice;
  aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  Assert(assigned(fOwnerDevice));

  // set the root device
  SetRootDevice(aRoot);

  // assign the URL's
  fSCPDURL     := '/' + fOwnerDevice.fModelName + '/' + fServiceID + _scpdPath;
  fcontrolURL  := '/' + fOwnerDevice.fModelName + '/' + fServiceID + _controlPath;
  feventSubURL := '/' + fOwnerDevice.fModelName + '/' + fServiceID + _eventPath;

  // scan the state variables
  with fStateVariables do
  begin
    for i := 0 to pred(Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [StateVariableStr, Name, Err_Not_Set]);
      end;

      if not (StateVariable[i] is TUPnP_StateVariable) then
      begin
        raise ELinkException.CreateFmt(BadLink, [StateVariableStr, Name, Err_Invalid]);
      end;

      fStateVariables[i].DoFixups(aRoot, aServiceList);
    end;
  end;

  // scan the actions
  with fActions do
  begin
    for i := 0 to pred(Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [ActionStr, Name, Err_Not_Set]);
      end;

      if not (Action[i] is TUPnP_Action) then
      begin
        raise ELinkException.CreateFmt(BadLink, [ActionStr, Name, Err_Invalid]);
      end;

      fActions[i].DoFixups(aRoot, aServiceList);
    end;
  end;

  // if ServiceList is assigned, we must check if we are the first instance of this service type
  if Assigned(aServiceList) then
  begin
    // we are the first instance if our service type is not already in the list
    fFirstInstance := (aServiceList.IndexOf(fServiceType) < 0);
    // if we are the first instance then add ourselves to the list
    if fFirstInstance then
    begin
      aServiceList.Add(fServiceType);
    end;
  end;
end;

procedure TUPnP_CustomService.SetStateVariables(Value: TUPnP_StateVariableCollection);
{
  Used by Object Inspector at design time to StateVariables arguments to the StateVariables collection
  Status: FULLY TESTED
}
begin
  fStateVariables.Assign(Value);
end;

procedure TUPnP_CustomService.SetActions(Value: TUPnP_ActionCollection);
{
  Used by Object Inspector at design time to assign Actions to the Actions collection
  Status: FULLY TESTED
}
begin
  fActions.Assign(Value);
end;

procedure TUPnP_CustomService.SetServiceID(const aName: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if fServiceType = '' then
    begin
      fServiceType := aName;
    end;
  end;
  fServiceId := aName;
end;

procedure TUPnP_CustomService.SetServiceType(const aName: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if fServiceId = '' then
    begin
      fServiceId := aName;
    end;
  end;
  fServiceType := aName;
end;

procedure TUPnP_CustomService.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fServiceType = default_ServiceType) or (fServiceType = '') then
    begin
      ServiceType := NewName;
    end;
  end;
  inherited;
end;

constructor TUPnP_Action.Create(AOwner: TComponent);
{
  Creates the object and a collection for it's respective embedded objects
  Status: FULLY TESTED
}
begin
  inherited;

  // create a critical section
  syncActionExecuteCritSect := TCriticalSection.Create;

  // create the various lists
  fArguments := TUPnP_ArgumentCollection.Create(self);
  fSecurityPermissions := TUPnP_SecurityPermissionCollection.Create(self);

  ActionName := Name;
  fDevSec    := nil;

  // initialise the DONT_PASS bit mask (by default pass all arguments)
  fDontPassArguments := [];

  Inc(fPropertyCount, 4);
end;

function TUPnP_Action.AsHTML: string;
{
  Render as HTML
  Status: FULLY TESTED
}
var
  argsHTML: string;
  i: integer;
  inArgCode: string;
  outArgCode: string;
  inArgCount: integer;
  outArgCount: integer;
  vbscript: string;
  inArgsID: string;
  invokeCode: string;
begin
  Assert(assigned(fOwnerService));

  // initialize
  argsHTML    := '';
  inArgCode   := '';
  outArgCode  := '';
  inArgCount  := 0;
  outArgCount := 0;
  invokeCode  := Format(invokeCodeTemplatePlain, [fOwnerService.fServiceId,
    fActionName]);

  for i := 0 to pred(fArguments.Count) do
  begin

    // determine if we have an ID attribute
    if fArguments[i].fDirection <> Input then
    begin
      inArgsID := Format(inArgIDTemplate, [fOwnerService.fServiceId, fActionName,
        fArguments[i].fArgumentName]);
    end
    else
    begin
      inArgsID := '';
    end;

    // create the argument HTML table row
    argsHTML := argsHTML + Format(argRowTemplate, [fArguments[i].fArgumentName,
      inArgsID, fArguments[i].GetArgHTML(fOwnerService.fServiceId, fActionName)]);

    // create the argument VBScript code
    fArguments[i].GetArgCode(fOwnerService.fServiceId, fActionName, inArgCode,
      inArgCount, invokeCode, outArgCode, outArgCount);
  end;

  // wrap the vbscript
  vbscript := Format(actionCodeTemplate, [fOwnerService.fServiceId, fActionName,
    inArgCount, outArgCount, inArgCode, invokeCode, outArgCode]);

  // create the whole action table
  Result := Format(actionTemplate, [fActionName, fActionName,
    fOwnerService.fServiceId, fActionName, argsHTML, vbscript]);
end;

function TUPnP_Action.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_ActionName;
    end;
    2:
    begin
      Result := ui_RequiresAuthorization;
    end;
    3:
    begin
      Result := ui_RequiresPrivacy;
    end;
    4:
    begin
      Result := ui_RequiresSigning;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_Action.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := fActionName;
    end;
    2:
    begin
      Result := BoolToStr(fRequiresAuthorization, True);
    end;
    3:
    begin
      Result := BoolToStr(fRequiresPrivacy, True);
    end;
    4:
    begin
      Result := BoolToStr(fRequiresSigning, True);
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

procedure TUPnP_Action.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fActionName = '') or (fActionName = Name) then
    begin
      ActionName := NewName;
    end;
  end;
  inherited;
end;

destructor TUPnP_Action.Destroy;
{
  Free the embedded objects
  Status: FULLY TESTED
}
begin
  fArguments.Free;
  fSecurityPermissions.Free;
  syncActionExecuteCritSect.Free;
  inherited;
end;

function TUPnP_Action.GetDisplayName: string;
{
  Return the display name of the object
}
begin
  Result := fActionName;
end;

function TUPnP_Action.ProcessSOAPAction
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Checks if the Request contains a valid SOAP action command. If so, then
  - sets the In parameters to the values passed in the request
  - calls the Execute procedure
  - writes the returned Out parameters in SOAP XML response format
  - sends the reply to the TCP socket
  Status: FULLY TESTED
}
var
  i:   integer;
  authresult: TUPnP_AuthorisationResult;
  err: TSOAPErrorCodes;
  tmpevdis: boolean;
  errcode, errmsg: string;
  body, securityinfo: TUPnP_XMLStream;
begin
  Assert(assigned(fRootDevice));
  Assert(assigned(fOwnerService));

  Result := False;

  // check if the message is signed
  with Request.XMLStream do
  begin
    ResetParser;
    SignResponse := GotoTagName(_SecurityInfo);
    ResetParser;
  end;

  // check if the call requires a signature
  if fRequiresAuthorization or fRequiresSigning or SignResponse then
  begin

    // get the DeviceSecurity service
    if not Assigned(fDevSec) then
    begin
      for i := 0 to pred(fRootDevice.Services.Count) do
      begin
        if fRootDevice.Services[i] is TUPnP_DeviceSecurityBase then
        begin
          fDevSec := TUPnP_DeviceSecurityBase(fRootDevice.Services[i]);
          break;
        end;
      end;
    end;

    // use the DeviceSecurity service to check the signature
    if Assigned(fDevSec) then
    begin
      authresult := fDevSec.CheckDsigAuthorisation(self, Request.XMLStream);
    end
    else
    begin
      authresult := auth_GeneralError;
    end;
  end

  // the call is authorised unless found otherwise...
  else
  begin
    authresult := auth_Accepted;
  end;

  // if not authorised then ...
  if authresult <> auth_Accepted then
  begin
    case authresult of
      auth_MalformedSoap:
      begin
        err := err_Signature_Malformed_or_Missing;
      end;

      auth_UnknownSession:
      begin
        err := err_Invalid_Session_Key_ID;
      end;

      auth_InsufficientPermissions:
      begin
        err := err_Action_Not_Authorized;
      end;

      auth_WrongSequenceNumber:
      begin
        err := err_Invalid_Sequence;
      end;

      auth_SignatureNotVerified:
      begin
        err := err_Signature_Failure;
      end;

      auth_BadDigest:
      begin
        err := err_Signature_Failure;
      end;

      // err_Signature_Bad_Digest;

      auth_Bad_PublicKey:
      begin
        err := err_Bad_Public_Key;
      end;

      auth_BadControlURL:
      begin
        err := err_Invalid_ControlURL;
      end;

      else
      begin
        err := err_Action_Failed;
      end;
    end;

    //  => return an error code
    fOwnerService.SOAPError(Response, err);
    exit;
  end;

  Request.XMLStream.ResetParser;
  // Go to the ActionName
  //  - no need to check if it is OK, since the caller has already done this...
  Request.XMLStream.GotoTagName(fActionName);

  if farguments.Count > 0 then
    // we have to get the arguments from XML
  begin

    i := 0;
    repeat
      with fArguments[i] do
      begin
        // if the argument is Output, there is no need to do any further parsing
        //  (since In arguments MUST be declared before Out arguments)
        if fdirection >= Output then
        begin
          break;
        end;

        // move on to next tag
        Request.XMLStream.NextTag;

        // if argument name is wrong then we failed...
        if Request.XMLStream.TagName <> argumentname then
        begin
          //  => return an error code 500,402
          fOwnerService.SOAPError(Response, err_Invalid_Arguments);
          exit;
        end;

        // no related state variable...
        if (frelatedStateVariable = nil) then
        begin
          //  => return an error code 500,402
          fOwnerService.SOAPError(Response, err_RSV_Not_Implemented);
          exit;
        end;

        try
          // test if the value matches that of the relatedStateVariable
          frelatedStateVariable.CheckValueOK(Request.XMLStream.TagValue);
        except
          // arg value does NOT match - i.e. then we failed => exit
          //  (swallows exception)
          on ERangeError do
          begin
            // argument is out of range
            fOwnerService.SOAPError(Response, err_Argument_Value_Out_of_Range);
            exit;
          end;
          else
          begin
            // argument is otherwise bad
            fOwnerService.SOAPError(Response, err_Argument_Value_Invalid);
            exit;
          end;
        end;

        // assign the argument value
        fValue := Request.XMLStream.TagValue;

      end;
      Inc(i);
    until i = farguments.Count;
  end;

  // if we got here, all the arguments (if any) are OK

  // preload error code and message in case the user forgets..
  errcode := SOAP_Error[err_Action_Failed, code];
  errmsg  := SOAP_Error[err_Action_Failed, desc];

  // turn off eventing
  tmpevdis := fOwnerService.fEventNotificationDisabled;
  fOwnerService.fEventNotificationDisabled := True;

  try
    try

      // assign the in-args to their respective RSV's
      for i := 0 to pred(farguments.Count) do
      begin

        // if the DontPass bit is set, then don't pass the argument
        if not (i in fDontPassArguments) then
        begin
          with fArguments[i] do
          begin
            if (fdirection = Input) and (not fDontUpdateRSV) then
            begin
              // use the RSV's public property value in order to trigger events...
              frelatedStateVariable.EncodedValue := fValue;
            end;
          end;
        end;
      end;
      Result := True;

    except
      on E: Exception do
      begin
        errcode := SOAP_Error[err_Argument_Value_Invalid, code];
        errmsg  := SOAP_Error[err_Argument_Value_Invalid, desc];
        Result  := False;
      end;
    end;

    // execute the action externally
    if Result and assigned(fOnActionExecute) then
    begin

      // wrap the OnActionExecute call-back in a critical section
      syncActionExecuteCritSect.Enter;
      try

        // execute the call-back -- but synchronize with the VCL thread...
        TThread.Synchronize(nil, syncActionExecute);
        errcode := syncErrCode;
        errmsg  := syncErrMsg;
        Result  := syncResult;

      finally
        // quit the critical section
        syncActionExecuteCritSect.Leave;
      end;
    end;

  finally
    // re-enable eventing
    fOwnerService.fEventNotificationDisabled := tmpevdis;
  end;

  if not Result then
  begin
    // if action failed then return a SOAP error code
    fOwnerService.CustomSOAPError(Response, errcode, errmsg);
    exit;
  end;

  // assign the RSV's to the out-args
  for i := 0 to pred(farguments.Count) do
  begin

    // if the DontPass bit is set, then don't pass the argument
    if not (i in fDontPassArguments) then
    begin
      with fArguments[i] do
      begin
        if (fdirection >= Output) and (not fDontUpdateRSV) then
        begin
          // set the value; add escaping if necessary...
          fValue := frelatedStateVariable.EncodedValue;
        end;
      end;
    end;
  end;

  // create the response body
  body := TUPnP_XMLStream.Create;
  try
    // write the body of the response
    with body do
    begin
      if SignResponse then
      begin
        WriteTagStartAndAttributes(_sBody, [_sBodyAttrSigned]);
      end
      else
      begin
        WriteTagStart(_sBody);
      end;

      WriteTagStart(Format(_uResponseFmtXmlNS, [Trim(factionName),
        fOwnerService.fServiceTypeExpanded]));

      for i := 0 to pred(fArguments.Count) do
      begin
        with fArguments[i] do
          // if it is an output argument then write it...
        begin
          if fDirection >= Output then
          begin
            WriteTagAndValue(fargumentName, fValue);
          end;
        end;
      end;

      WriteTagEnd(Format(_uResponseFmt, [Trim(factionName)]));
      WriteTagEnd(_sBody);
    end;

    securityinfo := nil;
    try
      // sign the body thereby creating the SecurityInfo
      if SignResponse and Assigned(fDevSec) then
      begin
        fDevSec.Sign(self, body, securityinfo);
      end;

      // write the response envelope
      with Response.XMLStream do
      begin
        // write the envelope start
        WriteTagStart(XML_VerString);
        WriteTagStartAndAttributes(_sEnvelope, [_sEnvelopeAttrs]);

        // write the security info header
        if Assigned(securityinfo) then
        begin
          WriteTagStart(_sHeader);
          WriteStream(securityinfo);
          WriteTagEnd(_sHeader);
        end;

        // write the body
        WriteStream(body);

        // write the envelope end
        WriteTagEnd(_sEnvelope);

        // add 1 new line at end
        WriteValues([CRLF]);
      end;

    finally
      if Assigned(securityinfo) then
      begin
        securityinfo.Free;
      end;
    end;

  finally
    body.Free;
  end;

  // if eventing is enabled then post a message to the root window to initiate eventing
  if not tmpevdis then
  begin
    fRootDevice.MustPublishEvents;
  end;
end;

procedure TUPnP_Action.syncActionExecute;
{
  VCL thread synchronized call to fOnActionExecute
  Status: FULLY TESTED
}
begin
  try
    syncResult := fOnActionExecute(self, syncErrCode, syncErrMsg);
  except
    // catch errors
    on E: Exception do
    begin
      syncErrCode := SOAP_Error[err_Action_Failed, code];
      syncErrMsg  := E.Message;
      syncResult  := False;
    end;
  end;
end;

procedure TUPnP_Action.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // describe the Action's parameters
  with DescriptionXML do
  begin
    WriteTagStart(_action);
    try
      WriteTagAndValue(_name, factionname);

      // ask the embedded arguments (should be at least one) to describe themselves
      if fArguments.Count > 0 then
      begin
        WriteTagStart(_argumentList);
        try
          for i := 0 to pred(fArguments.Count) do
          begin
            fArguments[i].SaveToXML(DescriptionXML);
          end;
        finally
          WriteTagEnd(_argumentList);
        end;
      end;

    finally
      // close the description of the Action's parameters
      WriteTagEnd(_action);
    end;
  end;
end;

procedure TUPnP_Action.DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  // set the root device
  SetRootDevice(aRoot);

  with fArguments do
  begin
    for i := 0 to pred(farguments.Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [ArgumentStr, Name, Err_Not_Set]);
      end;

      if not (Argument[i] is TUPnP_Argument) then
      begin
        raise ELinkException.CreateFmt(BadLink, [ArgumentStr, Name, Err_Invalid]);
      end;

      fArguments[i].DoFixups(aRoot, aServiceList);
    end;
  end;

  with fSecurityPermissions do
  begin
    for i := 0 to pred(fSecurityPermissions.Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [PermissionStr, Name, Err_Not_Set]);
      end;

      if not (SecurityPermission[i] is TUPnP_SecurityPermission) then
      begin
        raise ELinkException.CreateFmt(BadLink, [PermissionStr, Name, Err_Invalid]);
      end;

      fSecurityPermissions[i].DoFixups(aRoot, aServiceList);
    end;
  end;
end;

procedure TUPnP_Action.SetArguments(Value: TUPnP_ArgumentCollection);
{
  Used by Object Inspector at design time to assign arguments to the argument collection
  Status: FULLY TESTED
}
begin
  fArguments.Assign(Value);
end;

procedure TUPnP_Action.SetSecurityPermissions(Value: TUPnP_SecurityPermissionCollection);
{
  Used by Object Inspector at design time to assign permissions to the SecurityPermissions collection
  Status: FULLY TESTED
}
begin
  fSecurityPermissions.Assign(Value);
end;

constructor TUPnP_RootDevice.Create(AOwner: TComponent);
{
  Creates the object and initialises important variables
  Status: FULLY TESTED
}
begin
  inherited;

  // create a critical section
  syncLoggingCritSect := TCriticalSection.Create;

  // initialise the root device variable
  fRootDevice := self;

  // not connected
  fConnected := False;

  // can't permit roots inside roots!
  fOwnerDevice := nil;

  // get the default URL base (= the IP address)
  fURLBase := BuildURL(s_HTTP, GetIPAddress, '', '');

  // currently no servers running
  fUdpMulticastSender := nil;
  fTcpServer := nil;
  fUdpUnicastSender := nil;

  // initialise IP default values
  fMultiCastIPAddress := '239.255.255.250';
  fTimeToLive := 4;
  fHeartBeatInterval := 10;
  fMaxAge     := 2100;
  fSocketTimeout := 30;
  fMultiCastPort := 1900;
  fHTTPPort   := 8080;

  // create message string lists
  fAliveMessages  := TUPnP_NotificationCollection.Create;
  fByeByeMessages := TUPnP_NotificationCollection.Create;
  fMXResponses    := TUPnP_NotificationCollection.Create;

  // set first show flag
  fFirstShow := True;

  Inc(fPropertyCount, 9);
end;

destructor TUPnP_RootDevice.Destroy;
{
  Destroys the object and cleans up
  Status: FULLY TESTED
}
begin
  if fConnected then
  begin
    Disconnect;
  end;

  // turn off logging
  LoggingFlags := [];

  // destroy the servers using FreeAndNil (since they may not have been assigned yet)
  FreeAndNil(fUdpMulticastSender);
  FreeAndNil(fUdpMulticastListener);
  FreeAndNil(fUdpUnicastSender);
  FreeAndNil(fTcpServer);

  // free timers
  FreeAndNil(fMXTimer);
  FreeAndNil(fHeartBeatTimer);
  FreeAndNil(fGoOfflineTimer);
  FreeAndNil(fPublishEventsTimer);
  FreeAndNil(fAliveTimer);

  // destroy other objects
  fAliveMessages.Free;
  fByeByeMessages.Free;
  fMXResponses.Free;

  // free the critical section
  syncLoggingCritSect.Free;

  inherited;
end;

function TUPnP_RootDevice.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    13:
    begin
      Result := ui_Connected;
    end;
    14:
    begin
      Result := ui_TimeToLive;
    end;
    15:
    begin
      Result := ui_HeartbeatInterval;
    end;
    16:
    begin
      Result := ui_MaxAge;
    end;
    17:
    begin
      Result := ui_SocketTimeout;
    end;
    18:
    begin
      Result := ui_MulticastPort;
    end;
    19:
    begin
      Result := ui_HTTPPort;
    end;
    20:
    begin
      Result := ui_MulticastIPAddress;
    end;
    21:
    begin
      Result := ui_URLbase;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_RootDevice.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    13:
    begin
      Result := BoolToStr(fConnected, True);
    end;
    14:
    begin
      Result := IntToStr(fTimeToLive);
    end;
    15:
    begin
      Result := IntToStr(fHeartbeatInterval);
    end;
    16:
    begin
      Result := IntToStr(fMaxAge);
    end;
    17:
    begin
      Result := IntToStr(fSocketTimeout);
    end;
    18:
    begin
      Result := IntToStr(fMulticastPort);
    end;
    19:
    begin
      Result := IntToStr(fHTTPPort);
    end;
    20:
    begin
      Result := fMulticastIPAddress;
    end;
    21:
    begin
      Result := fURLbase;
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

procedure TUPnP_RootDevice.SetPropertyValue(anIndex: cardinal; aValue: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  case anIndex of
    13:
    begin
      Connected := StrToBool(aValue);
    end;
    14:
    begin
      TimeToLive := StrToIntDef(aValue, fTimeToLive);
    end;
    16:
    begin
      MaxAge := StrToIntDef(aValue, fMaxAge);
    end;
    else
    begin
      inherited;
    end;
  end;
end;

function TUPnP_RootDevice.GetPropertyEditable(anIndex: cardinal): boolean;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    13:
    begin
      Result := True;
    end;
    14:
    begin
      Result := True;
    end;
    16:
    begin
      Result := True;
    end;
    else
    begin
      Result := inherited GetPropertyEditable(anIndex);
    end;
  end;
end;

procedure TUPnP_RootDevice.syncLoggingCallback;
{
  LoggingCallback may be called from within an Indy thread,
  so we use this method to provide VCL safety...
  Status: FULLY TESTED
}
begin
  fOnLogMessage(syncLoggingType, syncLoggingMessage);
end;

procedure TUPnP_RootDevice.LoggingCallback(aLoggingType, aMessage: string);
{
  Callback for logging; => see syncLoggingCallback above!
  Status;
}
begin
  if assigned(fOnLogMessage) and not (csDestroying in ComponentState) then
  begin

    // wrap the call in a critical section
    syncLoggingCritSect.Enter;
    try

      // put message info in component local variables
      syncLoggingType    := aLoggingType;
      syncLoggingMessage := aMessage;

      // we might get called from within an Indy thread, so we use TThread's
      //  Synchronize class method to prevent trouble with the VCL...
      TThread.Synchronize(nil, syncLoggingCallback);

      // clean up the component local variables
      syncLoggingType    := '';
      syncLoggingMessage := '';

    finally
      // quit the critical section
      syncLoggingCritSect.Leave;
    end;
  end;
end;

procedure TUPnP_RootDevice.Loaded;
{
  Once the component has been loaded we can do the fixups and go online (if allowed)
  Status: FULLY TESTED
}
begin
  inherited;

  if not (csDesigning in ComponentState) then
  begin

    // do fixups
    DoRootFixups;

    // hook the owner form's OnShow and OnCloseQuery handlers
    if Owner is TForm then
    begin
      fOldShowEvent := TForm(Owner).OnShow;
      TForm(Owner).OnShow := Show;
      fOldCloseQueryEvent := TForm(Owner).OnCloseQuery;
      TForm(Owner).OnCloseQuery := CloseQuery;
    end;
  end;
end;

function TUPnP_RootDevice.GetIPAddress: string;
{
  Gets the IP address of the host PC
  Status: FULLY TESTED
}
begin
  Result := UPnP_IndyExtensions.GetIPAddress;
end;

procedure TUPnP_RootDevice.Show(Sender: TObject);
{
  Intercepts calls to Owner Form's OnShow
  Executes AutoConnect
  Status: FULLY TESTED
}
begin
  Assert(not (csDesigning in ComponentState));

  // call inherited event handler (if any) ...
  if assigned(fOldShowEvent) then
  begin
    fOldShowEvent(Sender);
  end;

  // auto connect
  if fFirstShow and fAutoConnect then
  begin
    Connected := True;
  end;
  fFirstShow := False;
end;

procedure TUPnP_RootDevice.CloseQuery(Sender: TObject; var CanClose: boolean);
{
  Intercepts calls to Owner Form's OnCloseQuery
  Disconnects the communications & waits for threads to terminate
  Status: FULLY TESTED
}
begin
  Assert(not (csDesigning in ComponentState));

  // call inherited event handler (if any) ...
  if Assigned(fOldCloseQueryEvent) then
  begin
    fOldCloseQueryEvent(Sender, CanClose);
  end;

  if CanClose then
  begin
    // set the fApplicationClosing flag
    fApplicationClosing := True;

    // if needed, then go offline
    if Connected then
    begin
      Connected := False;
    end;
  end;
end;

procedure TUPnP_RootDevice.InitSockets;
{
  Create IP sockects
  Status: FULLY TESTED
}
begin
  try
    // create the UDP sender socket
    if not Assigned(fUdpMulticastSender) then
    begin
      fUdpMulticastSender := TUPnP_MulticastSender.Create;// .Create(self);
    end;

    // and initialise it
    fUdpMulticastSender.TimeToLive := fTimeToLive;
    fUdpMulticastSender.MulticastGroup := fMultiCastIPAddress;
    fUdpMulticastSender.Port     := fMultiCastPort;
    fUdpMulticastSender.Loopback := True;

    // create the UDP listener socket
    if not Assigned(fUdpMulticastListener) then
    begin
      fUdpMulticastListener := TUPnP_MulticastListener.Create;// .Create(self);
    end;

    // and initialise it
    fUdpMulticastListener.MulticastGroup := fMultiCastIPAddress;
    fUdpMulticastListener.DefaultPort    := fMultiCastPort;
    fUdpMulticastListener.OnUDPRequest   := DispatchUDPRequest;

    // create the TCP listener socket
    if not Assigned(fTcpServer) then
    begin
      fTcpServer := TUPnP_HTTPServer.Create; //.Create(self);
    end;

    // and initialise it
    fTcpServer.OnTCPRequest := DispatchHTTPRequest;
    fTcpServer.DefaultPort  := fHTTPPort;

    // create the UDP sender
    if not Assigned(fUdpUnicastSender) then
    begin
      fUdpUnicastSender := TUPnP_UnicastSender.Create;// .Create(self);
    end;

    // create the heartbeat timer
    if not Assigned(fHeartBeatTimer) then
    begin
      fHeartBeatTimer := TTimer.Create(self);
    end;

    // and initialise it
    fHeartBeatTimer.Enabled  := True;
    fHeartBeatTimer.Interval := fHeartBeatInterval * 1000;
    fHeartBeatTimer.OnTimer  := OnHeartBeat;

    // create the MX timer
    if not Assigned(fMXTimer) then
    begin
      fMXTimer := TTimer.Create(self);
    end;

    // and initialise it
    fMXTimer.Enabled  := False;
    fMXTimer.Interval := 5000;
    fMXTimer.OnTimer  := OnMXTimer;

    // create the Alive timer
    if not Assigned(fAliveTimer) then
    begin
      fAliveTimer := TTimer.Create(self);
    end;

    // and initialise it
    fAliveTimer.Enabled  := False;
    fAliveTimer.Interval := 100;
    fAliveTimer.OnTimer  := OnAliveTimer;

    // create the Go Offline timer
    if not Assigned(fGoOfflineTimer) then
    begin
      fGoOfflineTimer := TTimer.Create(self);
    end;

    // and initialise it
    fGoOfflineTimer.Enabled  := False;
    fGoOfflineTimer.Interval := 500;
    fGoOfflineTimer.OnTimer  := OnGoOffline;

    // create the Publish Events timer
    if not Assigned(fPublishEventsTimer) then
    begin
      fPublishEventsTimer := TTimer.Create(self);
    end;

    // and initialise it
    fPublishEventsTimer.Enabled  := False;
    fPublishEventsTimer.Interval := 500;
    fPublishEventsTimer.OnTimer  := OnPublishEvents;

    // if we got here, all is Ok
    fSocketsInitialised := True;

  except
    on Exception do ;
  end;
end;

procedure TUPnP_RootDevice.Connect;
{
  Startup IP communications
  Status: FULLY TESTED
}
var
  scheme, host, page, port: string;
begin
  // each time we go online, ensure that we have the correct persistent data
  GetRegistryData;

  // when we go online, create the expanded device type string: urn:schemas-upnp-org:device:deviceType:v
  fDeviceTypeExpanded := Format(Schemas_DeviceHdrFmt,
    [fDeviceSchema, fDeviceType, fDeviceVersion]);

  inherited;

  if not fSocketsInitialised then
  begin
    InitSockets;
  end;

  if Assigned(fUdpMulticastSender) then
  begin
    fUdpMulticastSender.Active := True;
  end;

  if Assigned(fUdpUnicastSender) then
  begin
    fUdpUnicastSender.Active := True;
  end;

  if Assigned(fUdpMulticastListener) then
  begin
    fUdpMulticastListener.Active := True;
  end;

  if Assigned(fTcpServer) then
  begin
    fTcpServer.Active := True;
  end;

  // insert the chosen port number into the fURLBase
  UPnP_IndyExtensions.ParseURL(fURLBase, scheme, host, page, port);
  port     := IntToStr(fTcpServer.DefaultPort);
  fURLBase := UPnP_IndyExtensions.BuildURL(scheme, host, page, port);

  // set a timer to periodically check for subscription expiry
  if assigned(fHeartBeatTimer) then
  begin
    fHeartBeatTimer.Enabled := True;
  end;

  // link up the logging callbacks
  LoggingFlags := fLoggingFlags;

  // get the alive messages
  GetAliveMessages;

  // get the byebye messages (for future use)
  GetByeByeMessages;

  // send the notifications
  fAliveTimer.Enabled := True;

  // set the expiry time -- allowing three timer intervals for safety
  fExpiry := Now + ((fmaxage - (3 * fHeartBeatInterval)) / 86400);
end;

procedure TUPnP_RootDevice.Disconnect;
{
  Shutdown IP communications
  Status: FULLY TESTED
}
begin
  // kill the timer that checks for subscription expiry
  if assigned(fHeartBeatTimer) then
  begin
    fHeartBeatTimer.Enabled := False;
  end;

  // send byebye notifications
  SendByeByeNotifications;

  // disconnecting always seems to cause exceptions in the Indy library,
  //  so we temporarily prevent the Delphi Debugger from trapping them...
  StopDelphiIdeOnException(False);
  try

    // shutdown the Multicast sender
    if Assigned(fUdpMulticastSender) then
    begin
      try
        fUdpMulticastSender.Active := False;
      except
        // swallow any exceptions
        on Exception do ;
      end;
    end;

    // shutdown the Multicast listener
    if Assigned(fUdpMulticastListener) then
    begin
      try
        fUdpMulticastListener.Active := False;
      except
        // swallow any exceptions
        on Exception do ;
      end;
    end;

    // shutdown the UDP unicast sender
    if Assigned(fUdpUnicastSender) then
    begin
      try
        fUdpUnicastSender.Active := False;
      except
        // swallow any exceptions
        on Exception do ;
      end;
    end;

    // shutdown the TCP server
    if Assigned(fTcpServer) then
    begin
      try
        fTcpServer.Active := False;
      except
        // swallow any exceptions
        on Exception do ;
      end;
    end;

  finally
    // re-enable the Delphi Debugger's exception trapping
    StopDelphiIdeOnException(True);
  end;

  inherited;
end;

function TUPnP_RootDevice.GetDescriptionURL: string;
{
  Returns the description URL as a fully qualified address in the form
    http://domain.com/url OR http://111.222.111.222/url
  Status: FULLY TESTED
}
var
  scheme, host, page, port: string;
begin
  UPnP_IndyExtensions.ParseURL(fURLBase, scheme, host, page, port);
  Result := UPnP_IndyExtensions.BuildURL(scheme, host, fDescriptionURL, port);
end;

procedure TUPnP_RootDevice.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
begin
  // the root device must provide additional header data
  with DescriptionXML do
  begin
    WriteTagStart(XML_VerString);
    WriteTagStartAndAttributes(_root, [_rootXmlNS]);
    WriteTagStart(_specVersion);
    WriteTagAndValue(_major, _majorVersion);
    WriteTagAndValue(_minor, _minorVersion);
    WriteTagEnd(_specVersion);
    WriteTagAndValue(_URLBase, fURLBase);

    // then we just describe the device itself...
    inherited;

    // the root device must also provide corresponding additional footer data
    WriteTagEnd(_root);

    // add 1 new line at end
    WriteValues([CRLF]);
  end;
end;

procedure TUPnP_RootDevice.CollectAliveMessages(aList: TUPnP_NotificationCollection);
{
 Sends an HTTP alive message on multicast
  Status: FULLY TESTED
}
var
  lResponse: TUPnP_AliveNotification;
begin
  // send the extra notify message for root devices
  lResponse      := TUPnP_AliveNotification.Create;
  lResponse.Location := GetDescriptionURL;
  lResponse.SearchTarget := UPnPRootDevice;
  lResponse.USN  := UUIDStr + fUDN + DoubleColon + UPnPRootDevice;
  lResponse.Host := Format(fmt_SU, [fMultiCastIPAddress, fMultiCastPort]);
  lResponse.MaxAge := fMaxAge;
  lResponse.AddToCollection(aList);

  // and then send all the notify messages that non root devices have to send
  inherited;
end;

procedure TUPnP_RootDevice.CollectByeByeMessages(aList: TUPnP_NotificationCollection);
{
  Sends an HTTP ByBye message on multicast
  Status: FULLY TESTED
}
var
  lResponse: TUPnP_ByeByeNotification;
begin
  // send the extra notify message for root devices
  lResponse      := TUPnP_ByeByeNotification.Create;
  lResponse.SearchTarget := UPnPRootDevice;
  lResponse.USN  := UUIDStr + fUDN + DoubleColon + UPnPRootDevice;
  lResponse.Host := Format(fmt_SU, [fMultiCastIPAddress, fMultiCastPort]);
  lResponse.AddToCollection(aList);

  // and then send all the notify messages that non root devices have to send
  inherited;
end;

procedure TUPnP_RootDevice.DoRootFixups;
{
  Does a full fix up on the root device and all its children
  Status: FULLY TESTED
}
var
  ServiceList: TStringList;
begin
  // set up the call to DoFixups...
  ServiceList := TStringList.Create;
  try
    DoFixups(self, ServiceList);
  finally
    ServiceList.Free;
  end;
end;

procedure TUPnP_RootDevice.SendByeByeNotifications;
{
  Transmit the ByeBye messages
  Status: FULLY TESTED
}
var
  i: integer;
begin
  Assert(assigned(fUdpMulticastSender));

  for i := 0 to pred(fByeByeMessages.Count) do
  begin
    // send the notification
    fUdpMulticastSender.Transmit(fByeByeMessages.Notifications[i].AsText);

    // NOTE: we explicitly use Sleep() to slow things down... 
    Sleep(100);
  end;
end;

procedure TUPnP_RootDevice.GetAliveMessages;
{
  Collect the SSDP byebye messages
  Status: FULLY TESTED
}
begin
  Assert(assigned(fAliveMessages));
  fAliveMessages.Clear;
  CollectAliveMessages(fAliveMessages);
end;

procedure TUPnP_RootDevice.GetByeByeMessages;
{
  Collect the SSDP alive messages
  Status: FULLY TESTED
}
begin
  Assert(assigned(fByeByeMessages));
  fByeByeMessages.Clear;
  CollectByeByeMessages(fByeByeMessages);
end;

procedure TUPnP_RootDevice.SetConnected(aValue: boolean);
{
  Turns ON / OFF the IP processing. i.e. only Root Devices expose this...
  Status: FULLY TESTED
}
begin
  if fConnected <> aValue then
  begin
    if not (csDesigning in ComponentState) then
    begin

      if aValue then
      begin
        Connect;
      end
      else
      begin
        Disconnect;
      end;

      // trigger our OnStateChange event
      if not fApplicationClosing then
      begin
        DoStateChange(self);
      end;
    end;
  end;
end;

procedure TUPnP_RootDevice.DispatchHTTPRequest(aRequestInfo: TUPnP_IdHTTPRequestInfo;
  aResponseInfo: TUPnP_IdHTTPResponseInfo);
{
  Main dispatcher for handling incoming UPnP HTTP server messages
  Status: FULLY TESTED
}
var
  lRequest:  TUPnP_HTTPServerRequestWrapper;
  lResponse: TUPnP_HTTPServerResponseWrapper;
begin
  if fTcpServer.Active then
  begin
    // build wrappers around the request and response
    lRequest  := TUPnP_HTTPServerRequestWrapper.Create(aRequestInfo);
    lResponse := TUPnP_HTTPServerResponseWrapper.Create(aResponseInfo);
    try
      // dispatch the request
      ProcessHTTPRequest(lRequest, lResponse);
    finally
      // free the wrappers
      lResponse.Free;
      lRequest.Free;
    end;
  end;
end;

procedure TUPnP_RootDevice.DispatchUDPRequest(aData: TStream;
  aBinding: TUPnP_IdSocketHandle);
{
  Main dispatcher for handling incoming UPnP Udp multicast messages
  Status: FULLY TESTED
}
var
  lRequest: TUPnP_MSearchRequest;
begin
  if fUdpMulticastSender.Active then
  begin
    lRequest := TUPnP_MSearchRequest.Create(aData);
    try
      lRequest.IP   := aBinding.PeerIP;
      lRequest.Port := aBinding.PeerPort;
      lRequest.Host := Format(fmt_SU, [fMultiCastIPAddress, fMultiCastPort]);
      if lRequest.IsValidSearchRequest then
      begin
        CollectMSearchResponses(lRequest, fMXResponses);
        if fMXResponses.Count > 0 then
        begin
          fMXTimer.Interval :=
            Random(min(120, max(3, lRequest.MxDelay)) * 1000 div fMXResponses.Count);
          fMXTimer.Enabled  := True;
        end;
      end;
    finally
      lRequest.Free;
    end;
  end;
end;

function TUPnP_RootDevice.ProcessDescriptionGet
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Processes HTTP requests for an XML description.
  Status: FULLY TESTED

  Request is in the following format:
    GET path to description HTTP/1.1
    HOST: host for description:port for description
    ACCEPT-LANGUAGE: language preferred by control point

  The device or service checks if the GET URL refers to itself, and if so, returns
  an OK (200) response with the respective device / service description in XML

  Response is in the format below:
    HTTP/1.1 200 OK
    CONTENT-LANGUAGE: language used in description
    CONTENT-LENGTH: Bytes in body
    CONTENT-TYPE: text/xml
    DATE: when responded
}
begin
  // Preset "result" to true so we can just exit if we handle the call
  Result := True;
  // get the XML body text for the Device, plus it's embedded Devices and Services
  SaveToXML(Response.XmlStream);
  // return HTTP 200 OK
  Response.Response.ResponseNo := 200;
end;

procedure TUPnP_RootDevice.CollectMSearchResponses(Request: TUPnP_MSearchRequest;
  aList: TUPnP_NotificationCollection);
{
  Receives a UPnP discovery request (M-Search)
  Status: FULLY TESTED

  Parses the ST header to find if the search is relevant, and if so responds
  with HTTP message on uni-ticast in the following format:
    HTTP/1.1 200 OK
    CACHE-CONTROL: max-age = seconds until advertisement expires
    DATE: when response was generated
    EXT:
    LOCATION: URL for UPnP description for root device
    SERVER: OS/version UPnP/1.0 product/version
    ST: *** SEE SPECICATION
    USN: *** SEE SPECICATION
}
var
  lResponse: TUPnP_MSearchResponse;
begin
  // if the Search Target is ssdp:all or we are looking for a root device...
  if SameText(SSDPAll, Request.SearchTarget) or
    (Pos(UPnPRootDevice, Request.SearchTarget) > 0) then
  begin
    lResponse      := TUPnP_MSearchResponse.Create;
    lResponse.Location := GetDescriptionURL;
    lResponse.SearchTarget := UPnPRootDevice;
    lResponse.USN  := UUIDStr + fUDN + DoubleColon + UPnPRootDevice;
    lResponse.MaxAge := fRootDevice.fMaxAge;
    lResponse.IP   := Request.IP;
    lResponse.Port := Request.Port;
    lResponse.AddToCollection(aList);
  end;
  inherited;
end;

procedure TUPnP_RootDevice.SetTimeToLive(aTTL: cardinal);
{
  Sets the Time To Live value for TCP/IP routing - NB a TTL of zero is illegal
  Status: FULLY TESTED
}
begin
  if (aTTL <> fTimeToLive) and (aTTL > 0) then
  begin
    fTimeToLive := aTTL;
    if assigned(fUdpMulticastSender) then
    begin
      fUdpMulticastSender.TimeToLive := aTTL;
    end;
  end;
end;

procedure TUPnP_RootDevice.SetHeartBeatInterval(aValue: cardinal);
{
  Sets the heart beat timer interval (secs)
  Status: FULLY TESTED
}
begin
  fHeartBeatInterval := max(2, aValue);
  if assigned(fHeartBeatTimer) then
  begin
    fHeartBeatTimer.Interval := fHeartBeatInterval * 1000;
  end;
end;

procedure TUPnP_RootDevice.SetMaxAge(avalue: cardinal);
{
  Sets the max age of SSDP alive advertisements (secs)
  Status: FULLY TESTED
}
begin
  fmaxage := max(60, aValue);
end;

procedure TUPnP_RootDevice.SetSocketTimeout(aValue: cardinal);
{
  Sets the socket time out interval (secs)
  Status: FULLY TESTED
}
begin
  fSockettimeout := max(5000, aValue);
end;

procedure TUPnP_RootDevice.SetOnLogMessage(aOnLogMessage: TUPnP_LoggingCallbackProc);
{
  Property setter
  Status: FULLY TESTED
}
begin
  fOnLogMessage := aOnLogMessage;
  LoggingFlags  := fLoggingFlags;
end;

procedure TUPnP_RootDevice.SetLoggingFlags(aLoggingFlags: TUPnP_Logging_Flags);
{
  Property setter
  Status: FULLY TESTED
}
begin
  fLoggingFlags := aLoggingFlags;

  if assigned(fUdpMulticastSender) then
  begin
    if fLogMultiCastClient in fLoggingFlags then
    begin
      fUdpMulticastSender.OnLog := LoggingCallback;
    end
    else
    begin
      fUdpMulticastSender.OnLog := nil;
    end;
  end;

  if assigned(fUdpMulticastListener) then
  begin
    if fLogMultiCastServer in fLoggingFlags then
    begin
      fUdpMulticastListener.OnLog := LoggingCallback;
    end
    else
    begin
      fUdpMulticastListener.OnLog := nil;
    end;
  end;

  if assigned(fUdpUnicastSender) then
  begin
    if fLogUnicastClient in fLoggingFlags then
    begin
      fUdpUnicastSender.OnLog := LoggingCallback;
    end
    else
    begin
      fUdpUnicastSender.OnLog := nil;
    end;
  end;

  if assigned(fTcpServer) then
  begin
    if fLogTCPServer in fLoggingFlags then
    begin
      fTcpServer.OnLog := LoggingCallback;
    end
    else
    begin
      fTcpServer.OnLog := nil;
    end;
  end;
end;

procedure TUPnP_RootDevice.OnAliveTimer(Sender: TObject);
{
  Send all Alive responses
  Status: FULLY TESTED
}
begin
  Assert(Sender = fAliveTimer);

  // one notification for each tick
  if fAliveTimer.Tag < fAliveMessages.Count then
  begin
    // send the notification and increment the index
    fUdpMulticastSender.Transmit(fAliveMessages.Notifications[fAliveTimer.Tag].AsText);
    fAliveTimer.Tag := fAliveTimer.Tag + 1;
  end;

  // when done, disable the timer and reset the index
  if fAliveTimer.Tag >= fAliveMessages.Count then
  begin
    fAliveTimer.Enabled := False;
    fAliveTimer.Tag     := 0;
  end;
end;

procedure TUPnP_RootDevice.OnMXTimer(Sender: TObject);
{
  Send all accumulated M-Search responses
  Status: FULLY TESTED
}
begin
  Assert(Sender = fMXTimer);

  // send one notification for each tick
  if fMXResponses.Count > 0 then
  begin
    if fMXResponses.Notifications[0] is TUPnP_MSearchResponse then
    begin
      with TUPnP_MSearchResponse(fMXResponses.Notifications[0]) do
      begin
        fUdpUnicastSender.Send(IP, Port, AsText);
      end;
    end;
    fMXResponses.Delete(0);
  end;

  // disable the timer when done
  fMXTimer.Enabled := (fMXResponses.Count > 0);
end;

procedure TUPnP_RootDevice.OnHeartBeat(Sender: TObject);
{
  Checks whether the Alive Notifications need renewing and then
  check if subscriptions on any embedded objects have expired
  Status: FULLY TESTED
}
begin
  // handle the alive notifications
  if Now > fExpiry then
  begin

    // send the notifications
    fAliveTimer.Enabled := True;

    // set the new expiry time -- allowing three timer intervals for safety
    fExpiry := Now + ((fmaxage - (3 * fHeartBeatInterval)) / 86400);
  end;
  inherited;
end;

procedure TUPnP_RootDevice.OnGoOffline(Sender: TObject);
{
  Respond to the Go Offline timer
  Status: FULLY TESTED
}
begin
  fGoOfflineTimer.Enabled := False;
  Connected := False;
end;

procedure TUPnP_RootDevice.OnPublishEvents(Sender: TObject);
{
  Respond to the publish events timer
  Status: FULLY TESTED
}
begin
  fPublishEventsTimer.Enabled := False;
  PublishEvents;
end;

procedure TUPnP_RootDevice.MustPublishEvents;
{
  Set the publish events timer
  Status: FULLY TESTED
}
begin
  fPublishEventsTimer.Enabled := True;
end;

procedure TUPnP_RootDevice.MustGoOffline;
{
  Set the go offline timer
  Status: FULLY TESTED
}
begin
  fGoOfflineTimer.Enabled := True;
end;

function TUPnP_RootDevice.DoRecursiveHTTPCall(Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Recursively Handle an HTTP action call
  => Specifically for UPnP security
  Status: FULLY TESTED
}
begin
  Result := ProcessHTTPRequest(Request, Response);
end;

constructor TUPnP_Icon.Create(AOwner: TComponent);
{
  Create the object, and initialise the variables...
  Status: FULLY TESTED
}
begin
  inherited;
  fPicture := TPicture.Create;
  fwidth   := 32;
  fheight  := 32;
  fdepth   := 8;
  IconName := Name;
  Inc(fPropertyCount, 4);
end;

destructor TUPnP_Icon.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
  fPicture.Free;
  inherited;
end;

function TUPnP_Icon.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_Width;
    end;
    2:
    begin
      Result := ui_Height;
    end;
    3:
    begin
      Result := ui_Depth;
    end;
    4:
    begin
      Result := ui_MimeType;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_Icon.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := IntToStr(fWidth);
    end;
    2:
    begin
      Result := IntToStr(fHeight);
    end;
    3:
    begin
      Result := IntToStr(fDepth);
    end;
    4:
    begin
      Result := MimeTypeStr[fMimeType];
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

function TUPnP_Icon.GetDisplayName: string;
{
  Return the display name of the object
  Status: FULLY TESTED
}
begin
  Result := fIconName;
end;

procedure TUPnP_Icon.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
begin
  // describe the icon's own parameters
  with DescriptionXML do
  begin
    WriteTagStart(_icon);
    try
      WriteTagAndValue(_mimetype, MimeTypeStr[fMimeType]);
      WriteTagAndValue(_width, IntToStr(fWidth));
      WriteTagAndValue(_height, IntToStr(fHeight));
      WriteTagAndValue(_depth, IntToStr(fDepth));
      WriteTagAndValue(_url, fURL);
    finally
      WriteTagEnd(_icon);
    end;
  end;
end;

function TUPnP_Icon.ProcessHTTPRequest(Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Handles TCP HTTP GET requests, and returns the respective ICON file as
  binary data in the response buffer
  Status: FULLY TESTED
}
begin
  // set result to false, so we can exit fast...
  Result := False;

  // if it is not a GET for our Icon URL, then exit...
  if not AnsiSameText(Request.Request.Document, fURL) then
  begin
    exit;
  end;

  if not SameText(Request.Request.Command, method_Get) then
  begin
    exit;
  end;

  // if we have assigned a file containing the icon then serve it up...
  if fPicture = nil then
  begin
    HTTPError(Response, err_Not_Found);
  end
  else
  begin
    Result := ServeImage(Response);
  end;
end;

function TUPnP_Icon.ServeImage(Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Serves up the image in HTTP form
  Status: FULLY TESTED
}
var
  mSt: TMemoryStream;
begin
  mSt := TMemoryStream.Create;
  fPicture.Graphic.SaveToStream(mSt);

  // write the headers
  Response.Response.ResponseNo := 200;
  Response.Response.Date := NowGMT;
  Response.Response.ContentStream := mSt;
  Response.Response.FreeContentStream := True;
  Response.Response.ContentType := MimeTypeStr[fMimeType];

  // we succeeded, so set result to true
  Result := True;
end;

function TUPnP_Icon.AsHTML: string;
{
  Render as HTML
  Status: FULLY TESTED
}
begin
  Result := LinkAsHTML(ui_Icon, fURL);
end;

procedure TUPnP_Icon.SetPicture(aPicture: TPicture);
{
  Property setter for setting the picture
  Status: FULLY TESTED
}
begin
  fPicture.Assign(aPicture);
  fWidth    := fPicture.Width;
  fHeight   := fPicture.Height;
  fDepth    := TUPnP_GraphicsExtensions.GetImageDepth(fPicture.Graphic);
  fMimeType := TUPnP_GraphicsExtensions.GetImageMimeType(fPicture.Graphic);
end;

procedure TUPnP_Icon.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fIconName = '') or (fIconName = Name) then
    begin
      IconName := NewName;
    end;
  end;
  inherited;
end;

procedure TUPnP_Icon.SetIconName(aName: string);
{
  Sets the icon name and the URL
  Status: FULLY TESTED
}
begin
  fIconName := aName;
  fURL      := _iconPath + aName;
end;

constructor TUPnP_Argument.Create(AOwner: TComponent);
{
  Create the object and initialise the variables
  Status: FULLY TESTED
}
begin
  inherited;
  ArgumentName := Name;
  Inc(fPropertyCount, 2);
end;

function TUPnP_Argument.GetArgHTML(aServiceID, aActionName: string): string;
{
  Render as HTML
  Status: FULLY TESTED
}
begin
  Assert(assigned(frelatedStateVariable));

  if fdirection = Input then
  begin
    Result := frelatedStateVariable.AsArgHTML(aServiceID, aActionName, fArgumentName);
  end
  else
  begin
    Result := html_indent;
  end;
end;

procedure TUPnP_Argument.GetArgCode(aServiceID, aActionName: string;
  var inArgCode: string; var inArgCount: integer; var invokeCode: string;
  var outArgCode: string; var outArgCount: integer);
{
  Create the inArg and outArg VBScript code
  Status: FULLY TESTED
}
begin
  Assert(assigned(frelatedStateVariable));

  if invokeCode = '' then
  begin
    invokeCode := Format(invokeCodeTemplatePlain, [aServiceId, aActionName]);
  end;

  case fdirection of
    Input:
    begin
      if (frelatedStateVariable.fdataType = boolean_) then
      begin
        inArgCode := inArgCode + Format(inArgCodeTemplateBoolean, [inArgCount,
          aServiceId, aActionName, fArgumentName]);
      end
      else
      begin
        inArgCode := inArgCode + Format(inArgCodeTemplatePlain, [inArgCount,
          aServiceId, aActionName, fArgumentName]);
      end;
      Inc(inArgCount);
    end;

    Output:
    begin
      outArgCode := outArgCode + Format(outArgCodeTemplate, [aServiceId,
        aActionName, fArgumentName, outArgCount,
        BoolToStr(frelatedStateVariable.fContainsXML)]);
      Inc(outArgCount);
    end;

    OutputRetVal:
    begin
      outArgCode := outArgCode + Format(retvalArgCodeTemplate, [aServiceId,
        aActionName, fArgumentName, BoolToStr(frelatedStateVariable.fContainsXML)]);
      Inc(outArgCount);
      invokeCode := Format(invokeCodeTemplateRetVal, [aServiceId, aActionName]);
    end;
  end;
end;

function TUPnP_Argument.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_ArgumentName;
    end;
    2:
    begin
      Result := ui_Direction;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_Argument.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  Assert(assigned(fRelatedStateVariable));
  case anIndex of
    1:
    begin
      Result := fArgumentName;
    end;
    2:
    begin
      Result := ArgumentTypeStr[fDirection];
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

function TUPnP_Argument.GetDisplayName: string;
{
  Return the display name of the object
  Status: FULLY TESTED
}
begin
  Result := fArgumentName;
end;

procedure TUPnP_Argument.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fargumentName = '') or (fArgumentName = Name) then
    begin
      ArgumentName := NewName;
    end;
  end;
  inherited;
end;

procedure TUPnP_Argument.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
begin
  // describe the argument's parameters
  with DescriptionXML do
  begin
    WriteTagStart(_argument);
    try
      // NOTE the sequence: name, relatedStateVariable, direction , retval is important to
      //  ensure correct handling by Windows ME
      WriteTagAndValue(_name, fargumentname);
      WriteTagAndValue(_relatedStateVariable, frelatedStateVariable.fvariablename);
      WriteTagAndValue(_direction, ArgumentTypeStr[fdirection]);

      // only declare a "retval" if it is indeed a retval...
      if fdirection = OutputRetVal then
      begin
        WriteTagAndValue(_retval, '');
      end;
    finally
      WriteTagEnd(_argument);
    end;
  end;
end;

procedure TUPnP_Argument.DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
begin
  inherited;

  Assert(assigned(fRelatedStateVariable));

  // set the root device
  SetRootDevice(aRoot);
end;

constructor TUPnP_StateVariable.Create(AOwner: TComponent);
{
  Creates the object, and a collection for allowed values,
  and initialises variables
  Status: FULLY TESTED
}
begin
  inherited;

  // create the allowed value list
  fallowedStrings := TStringList.Create;

  // set the event triggered flag to false
  fEventTriggered := False;

  // set some default values
  fmaximum := 100;
  fstep    := 1;
  StateVariableName := Name;
  fDevSec  := nil;

  // create the security permissions list
  fSecurityPermissions := TUPnP_SecurityPermissionCollection.Create(self);

  fValue      := '';
  fDefaultValue := '';
  fSendEvents := True;

  Inc(fPropertyCount, 10);
end;

destructor TUPnP_StateVariable.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
  fallowedStrings.Free;
  fSecurityPermissions.Free;
  inherited;
end;

function TUPnP_StateVariable.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_StateVariableName;
    end;
    2:
    begin
      Result := ui_Value;
    end;
    3:
    begin
      Result := ui_DataType;
    end;
    4:
    begin
      Result := ui_DefaultValue;
    end;
    5:
    begin
      Result := ui_Minimum;
    end;
    6:
    begin
      Result := ui_Maximum;
    end;
    7:
    begin
      Result := ui_Step;
    end;
    8:
    begin
      Result := ui_AllowedValues;
    end;
    9:
    begin
      Result := ui_AllowedStrings;
    end;
    10:
    begin
      Result := ui_SendEvents;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_StateVariable.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := fVariableName;
    end;
    2:
    begin
      Result := Value;
    end;
    3:
    begin
      Result := VariableTypeStr[fDataType];
    end;
    4:
    begin
      Result := DefaultValue;
    end;
    5:
    begin
      Result := FloatToStr(fMinimum);
    end;
    6:
    begin
      Result := FloatToStr(fMaximum);
    end;
    7:
    begin
      Result := FloatToStr(fStep);
    end;
    8:
    begin
      Result := ui_AllowedValueType[fAllowedValues];
    end;
    9:
    begin
      Result := fAllowedStrings.CommaText;
    end;
    10:
    begin
      Result := BoolToStr(fSendEvents, True);
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

procedure TUPnP_StateVariable.SetPropertyValue(anIndex: cardinal; aValue: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  case anIndex of
    2:
    begin
      Value := aValue;
    end;
    else
    begin
      inherited;
    end;
  end;
end;

function TUPnP_StateVariable.GetPropertyEditable(anIndex: cardinal): boolean;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    2:
    begin
      Result := True;
    end;
    else
    begin
      Result := inherited GetPropertyEditable(anIndex);
    end;
  end;
end;

procedure TUPnP_StateVariable.DoStateChange(Sender: TObject);
{
  Send state change events
  Status: FULLY TESTED
}
begin
  inherited;
  if assigned(fOwnerService) then
  begin
    fOwnerService.DoStateChange(Sender);
  end;
end;

function TUPnP_StateVariable.GetDisplayName: string;
{
  Returns the Display Name
  Status: FULLY TESTED
}
begin
  Result := fVariableName;
end;

procedure TUPnP_StateVariable.DoFixups(aRoot: TUPnP_RootDevice;
  aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
var
  i: integer;
begin
  inherited;

  // set the root device
  SetRootDevice(aRoot);

  with fSecurityPermissions do
  begin
    for i := 0 to pred(fSecurityPermissions.Count) do
    begin
      if Items[i].DisplayName = Err_Not_Set then
      begin
        raise ELinkException.CreateFmt(BadLink, [PermissionStr, Name, Err_Not_Set]);
      end;

      if not (SecurityPermission[i] is TUPnP_SecurityPermission) then
      begin
        raise ELinkException.CreateFmt(BadLink, [PermissionStr, Name, Err_Invalid]);
      end;

      fSecurityPermissions[i].DoFixups(aRoot, aServiceList);
    end;
  end;
end;

procedure TUPnP_StateVariable.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fVariableName = '') or (fVariableName = Name) then
    begin
      StateVariableName := NewName;
    end;
  end;
  inherited;
end;

procedure TUPnP_StateVariable.SaveToXML(DescriptionXML: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // describe the State Variable's parameters
  with DescriptionXML do
  begin
    WriteTagStartAndAttributes(_stateVariable,
      [Format(_stateVariableAttr, [_yesno[fSendEvents]])]);
    try
      WriteTagAndValue(_name, fvariablename);
      WriteTagAndValue(_dataType, VariableTypeStr[fdataType]);
(**
      The following "if then" statement is added to avoid a problem with UPnP Certfication Test Tool v1.1
       (the tool fails the service if it advertises an empty <defaultValue> tag)
**)
      if fdefaultValue <> '' then
      begin
        WriteTagAndValue(_defaultValue, fdefaultValue);
      end;

      case fAllowedValues of
        Range:
        begin
          // describe the Allowed Value Range's parameters
          WriteTagStart(_allowedValueRange);
          try
            WriteTagAndValue(_minimum, FloatToStr(fminimum));
            WriteTagAndValue(_maximum, FloatToStr(fmaximum));
            WriteTagAndValue(_step, FloatToStr(fstep));
          finally
            WriteTagEnd(_allowedValueRange);
          end;
        end;

        List:
        begin
          // describe the Allowed Value Lists's parameters, if it contains anything
          if fallowedStrings.Count > 0 then
          begin
            WriteTagStart(_allowedValueList);
            try
              for i := 0 to pred(fallowedStrings.Count) do
              begin
                WriteTagAndValue(_allowedValue, fallowedStrings.Strings[i]);
              end;
            finally
              WriteTagEnd(_allowedValueList);
            end;
          end;
        end;
      end;

    finally
      WriteTagEnd(_stateVariable);
    end;
  end;
end;

procedure TUPnP_StateVariable.SetDataType(aDataType: TUPnP_VariableType);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fdataType := aDataType;

  // update the allowed values selector
  case fDataType of
    ui1,
    ui2,
    ui4,
    i1,
    i2,
    i4,
    int,
    r4,
    r8,
    number,
    fixed_14_4,
    float_:
    begin
      if fAllowedValues = List then
      begin
        fAllowedValues := Anything;
      end;
    end;

    char_,
    string_:
    begin
      if fAllowedValues = Range then
      begin
        fAllowedValues := Anything;
      end;
    end;

    else
    begin
      fAllowedValues := Anything;
    end;
  end;
end;

procedure TUPnP_StateVariable.SetAllowedValues(aAllowedValues: TUPnP_AllowedValueType);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fAllowedValues := aAllowedValues;

  // force testing / contraining of values within the new range
  if not (csLoading in ComponentState) then
  begin
    DefaultValue := fDefaultValue;
    Value := fValue;
  end;
end;

procedure TUPnP_StateVariable.SetMinimum(aMinimum: single);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fMinimum := aMinimum;

  // change the allowed values selector
  if fDataType in [ui1, ui2, ui4, i1, i2, i4, int, r4, r8, number,
    fixed_14_4, float_] then
  begin
    fAllowedValues := Range;
  end;

  // force testing / contraining of values within the new range
  if not (csLoading in ComponentState) then
  begin
    DefaultValue := fDefaultValue;
    Value := fValue;
  end;
end;

procedure TUPnP_StateVariable.SetMaximum(aMaximum: single);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fMaximum := aMaximum;

  // force allowed value updating (reuse the code in SetMinimum)...
  SetMinimum(fMinimum);
end;

procedure TUPnP_StateVariable.SetStep(aStep: single);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fStep := aStep;

  // force allowed value updating (reuse the code in SetMinimum)...
  SetMinimum(fMinimum);
end;

function TUPnP_StateVariable.BoolStrAsIntStr(aBoolStr: string): string;
{
  Convert a boolean string to an intger string
  Status: FULLY TESTED
}
begin
  if (aBoolStr = bool_1) or SameText(aBoolStr, bool_true) or
    SameText(aBoolStr, bool_yes) then
  begin
    Result := bool_1;
  end
  else
  begin
    Result := bool_0;
  end;
end;

function TUPnP_StateVariable.BoolStrAsTextStr(aBoolStr: string): string;
{
  Convert a boolean string to a text
  Status: FULLY TESTED
}
begin
  if (aBoolStr = bool_1) or SameText(aBoolStr, bool_True) or
    SameText(aBoolStr, bool_yes) then
  begin
    Result := bool_True;
  end
  else
  begin
    Result := bool_False;
  end;
end;

function TUPnP_StateVariable.AsArgHTML(aServiceID, aActionName,
  aArgumentName: string): string;
{
  Render the state variable as an action argument in HTML
  Status: FULLY TESTED
}
var
  optionsList: string;
  i: integer;
begin
  // boolean values
  if fDataType = boolean_ then
  begin
    optionsList :=
      Format(optionsTemplate, [optionSelected[Value = bool_0], bool_False, bool_False]) +
      Format(optionsTemplate, [optionSelected[Value = bool_1], bool_True, bool_True]);
    Result      := Format(inArgTemplateSelect, [aServiceID, aActionName,
      aArgumentName, optionsList]);
  end
  else  // list values
  if (fAllowedValues = List) and (fAllowedStrings.Count > 0) then
  begin
    optionsList := '';
    for i := 0 to pred(fAllowedStrings.Count) do
    begin
      optionsList := optionsList +
        Format(optionsTemplate, [optionSelected[Value = fAllowedStrings[i]],
        fAllowedStrings[i], fAllowedStrings[i]]);
    end;
    Result := Format(inArgTemplateSelect, [aServiceID, aActionName,
      aArgumentName, optionsList]);
  end
  else

    // plain values
  begin
    Result := Format(inArgTemplatePlain, [aServiceID, aActionName,
      aArgumentName, Value]);
  end;
end;

function TUPnP_StateVariable.ConstrainValue(aValue: string): string;
{
  Constrain a value to within the allowed value ranges
  Status: FULLY TESTED
}
var
  vvv: single;
begin
  // by default return the same as the input value
  Result := aValue;

  // adjust the constraints
  case fDataType of
    ui1,
    ui2,
    ui4,
    i1,
    i2,
    i4,
    int,
    r4,
    r8,
    number,
    fixed_14_4,
    float_:
    begin
      if fAllowedValues = Range then
      begin
        vvv := StrToFloat(aValue);

        // constrain to minimum and maximum
        if vvv < fMinimum then
        begin
          Result := FloatToStr(fMinimum);
        end;
        if vvv > fMaximum then
        begin
          Result := FloatToStr(fMaximum);
        end;

        { TODO 5 -oAFG -cNice to have: adjust Value to Step size }
      end;
    end;

    char_,
    string_:
    begin
      if (fAllowedValues = List) and (fallowedStrings.Count > 0) then
      begin

        // constrain to the allowed value list
        if fallowedStrings.IndexOf(aValue) < 0 then
        begin
          Result := fallowedStrings.Strings[0];
        end;
      end;
    end;
  end;
end;

procedure TUPnP_StateVariable.CheckValueOK(aValue: string);
{
  Checks if a (proposed) new state variable value is valid, and raises an exception if not
  Status: FULLY TESTED
}
var
  i: integer;
  r: single;
  b: boolean;
begin
  case fDataType of
    ui1,
    ui2,
    ui4,
    i1,
    i2,
    i4,
    int:
    begin
      // integers: check fminimum, fmaximum
      i := StrToInt(aValue);
      if fAllowedValues = Range then
      begin
        if (i < fMinimum) or (i > fMaximum) then
        begin
          raise ERangeError.CreateFmt(badIntegerFMT, [aValue]);
        end;
      end;
    end;

    r4,
    r8,
    number,
    fixed_14_4,
    float_:
    begin
      // reals: check fminimum, fmaximum
      r := StrToFloat(aValue);
      if fAllowedValues = Range then
      begin
        if (r < fMinimum) or (r > fMaximum) then
        begin
          raise ERangeError.CreateFmt(badFloatFMT, [aValue]);
        end;
      end;
    end;

    string_:
    begin
      // string: only check fallowedStrings
      if fAllowedValues = List then
      begin

        // remove any escaping
        if fContainsXML then
        begin
          aValue := EscapedToXml(aValue);
        end;

        // check fallowedStrings
        if fallowedStrings.IndexOf(aValue) < 0 then
        begin
          raise ERangeError.CreateFmt(badStringFMT, [aValue]);
        end;
      end;
    end;

    date_:
    begin
      // dates : check conversion
      StrToDate(aValue);
    end;

    dateTime,
    dateTime_tz:
    begin
      // dates & times : check conversion
      StrToDateTime(aValue);
    end;

    time,
    time_tz:
    begin
      // times : check conversion
      StrToTime(aValue);
    end;

    boolean_:
    begin
      // boolean: check for allowed values
      b := (aValue = bool_1) or (aValue = bool_0) or
        SameText(aValue, bool_true) or SameText(aValue, bool_false) or
        SameText(aValue, bool_yes) or SameText(aValue, bool_no);
      if not b then
      begin
        raise EConvertError.CreateFmt(badBooleanFMT, [aValue]);
      end;
    end;

    char_:
    begin
      // character length may only be 1
      if length(aValue) <> 1 then
      begin
        raise EConvertError.CreateFmt(badCharFMT, [aValue]);
      end;

      // check the fallowedStrings
      if (fAllowedValues = List) and (fallowedStrings.Count > 0) then
      begin
        if fallowedStrings.IndexOf(aValue) < 0 then
        begin
          raise ERangeError.CreateFmt(badCharFMT2, [aValue]);
        end;
      end;
    end;

    bin_base64,
    bin_hex,
    uri,
    uuid:
    begin
    { TODO 5 -oAFG -cNice to have: anything else => check it (currently not done) }
    end;
  end;
end;

function TUPnP_StateVariable.GetDefaultValue: string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  if fdataType = boolean_ then
  begin
    Result := BoolStrAsTextStr(fdefaultValue);
  end
  else
  begin
    Result := fdefaultValue;
  end;
end;

procedure TUPnP_StateVariable.SetEncodedValue(aValue: string);
{
  Remove XML escaping
  Status: FULLY TESTED
}
begin
  if fContainsXML then
  begin
    fValue := EscapedToXml(aValue);
  end
  else
  begin
    fValue := aValue;
  end;
end;

function TUPnP_StateVariable.GetEncodedValue: string;
{
  Add XML escaping
  Status: FULLY TESTED
}
begin
  if fContainsXML then
  begin
    Result := XmlToEscaped(fValue);
  end
  else
  begin
    Result := fValue;
  end;
end;

function TUPnP_StateVariable.GetValue: string;
{
  Get the value of the State Variable
  - if no value is set, then return the default value
  Status: FULLY TESTED
}
begin
  if fdataType = boolean_ then
  begin
    Result := BoolStrAsTextStr(fValue);
  end
  else
  begin
    Result := fValue;
  end;

  if Result = '' then
  begin
    Result := fDefaultValue;
  end;
end;

procedure TUPnP_StateVariable.SetValue(aValue: string);
{
  Checks if the variable's value has really changed and if the new value is valid
  - if so then sets the new value.
  If Eventing is enabled, then triggers the Owner Service to send the respective
  event message(s)
  Status: FULLY TESTED
}
var
  lChanging: boolean;
begin
  // if the data type is boolean then convert true & yes => 1 and false & no => 0 (Windows Me fix)
  if fDataType = boolean_ then
  begin
    aValue := BoolStrAsIntStr(aValue);
  end;

  if csLoading in ComponentState then
  begin
    fValue := aValue;
  end
  else if csDesigning in ComponentState then
  begin
    try
      // CheckValueOK raises an exception if the value is not OK
      CheckValueOK(aValue);
      fValue := aValue;
    except
      on E: Exception do
      begin
        MessageDlg(Format(setValFMT, [aValue, fVariableName, E.Message]),
          mtWarning, [mbOK], 0);
        fValue := fdefaultValue;
      end;
    end;
  end
  else

  begin
    Assert(assigned(fRootDevice));
    Assert(assigned(fOwnerService));

    // CheckValueOK raises an exception if the value is not OK
    CheckValueOK(aValue);

    // set the new value
    lChanging := (aValue <> fValue);
    fValue    := aValue;

    if lChanging then
    begin

      if fSendEvents then
      begin
        // set the event triggered flag
        fEventTriggered := True;

        // if eventing is enabled then send the event messages
        if Assigned(fOwnerService) and
          (not fOwnerService.fEventNotificationDisabled) and
          fRootDevice.fConnected then
          // tell the root to initiate eventing
        begin
          fRootDevice.MustPublishEvents;
        end;
      end;

      // trigger our own OnStateChange event
      DoStateChange(self);
    end;
  end;
end;

procedure TUPnP_StateVariable.SetDefaultValue(aValue: string);
{
  Checks if the variable's default value has really changed and if the new value is valid
  - if so then sets the new value.
  Status: FULLY TESTED
}
begin
  // if the data type is boolean then convert true & yes => 1 and false & no => 0 (Windows Me fix)
  if fDataType = boolean_ then
  begin
    aValue := BoolStrAsIntStr(aValue);
  end;

  if csLoading in ComponentState then
  begin
    fdefaultValue := aValue;
  end
  else

  begin
    try
      // CheckValueOK raises an exception if the value is not OK
      CheckValueOK(aValue);

      // assign it
      fdefaultValue := aValue;

    except
      on E: Exception do
      begin
        if csDesigning in ComponentState then
        begin
          MessageDlg(Format(setDefValFMT, [aValue, fVariableName, E.Message]),
            mtWarning, [mbOK], 0);
          fdefaultValue := ConstrainValue(aValue);
        end;
      end;
    end;
  end;
end;

procedure TUPnP_StateVariable.SaveEventToXML(EventXML: TUPnP_XMLStream);
{
  Creates the XML for an Event (change of state) message
  Status: FULLY TESTED

  Format is:
  <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
    <e:property>
      <variableName>new value</variableName>
    </e:property>
    Other variable names and values (if any) go here.
  </e:propertyset>
}
begin
  with EventXML do
  begin
    WriteTagStart(_eproperty);
    // write the value; add escaping if necessary...
    WriteTagAndValue(fvariableName, EncodedValue);
    WriteTagEnd(_eproperty);
  end;
end;

function TUPnP_StateVariable.ProcessSOAPAction
  (Request: TUPnP_HTTPServerRequestWrapper;
  Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Executes a SOAP QueryStateVariable request and creates the XML response
  Status: FULLY TESTED
}
var
  i:   integer;
  authresult: TUPnP_AuthorisationResult;
  err: TSOAPErrorCodes;
  body, securityinfo: TUPnP_XMLStream;
begin
  Assert(assigned(fRootDevice));
  Assert(assigned(fOwnerService));

  // exit if the call is not for us
  Result := False;
  if fvariablename <> Request.XMLStream.TagValue then
  begin
    exit;
  end;

  // check if the message is signed
  with Request.XMLStream do
  begin
    ResetParser;
    fSignResponse := GotoTagName(_SecurityInfo);
    ResetParser;
  end;

  // check if the call requires a signature
  if fRequiresAuthorization or fRequiresSigning or fSignResponse then
  begin

    // get the DeviceSecurity service
    if not Assigned(fDevSec) then
    begin

      for i := 0 to pred(fRootDevice.Services.Count) do
      begin
        if fRootDevice.Services[i] is TUPnP_DeviceSecurityBase then
        begin
          fDevSec := TUPnP_DeviceSecurityBase(fRootDevice.Services[i]);
          break;
        end;
      end;
    end;

    // use the DeviceSecurity service to check the signature
    if Assigned(fDevSec) then
    begin
      authresult := fDevSec.CheckDsigAuthorisation(self, Request.XMLStream);
    end
    else
    begin
      authresult := auth_GeneralError;
    end;
  end

  // the call is authorised unless found otherwise...
  else
  begin
    authresult := auth_Accepted;
  end;

  // if not authorised then ...
  if authresult <> auth_Accepted then
  begin
    case authresult of
      auth_MalformedSoap:
      begin
        err := err_Signature_Malformed_or_Missing;
      end;

      auth_UnknownSession:
      begin
        err := err_Invalid_Session_Key_ID;
      end;

      auth_InsufficientPermissions:
      begin
        err := err_Action_Not_Authorized;
      end;

      auth_WrongSequenceNumber:
      begin
        err := err_Invalid_Sequence;
      end;

      auth_SignatureNotVerified:
      begin
        err := err_Signature_Failure;
      end;

      auth_BadDigest:
      begin
        err := err_Signature_Bad_Digest;
      end;

      auth_Bad_PublicKey:
      begin
        err := err_Bad_Public_Key;
      end;

      auth_BadControlURL:
      begin
        err := err_Invalid_ControlURL;
      end;

      else
      begin
        err := err_Action_Failed;
      end;
    end;

    //  => return an error code
    fOwnerService.SOAPError(Response, err);
    Result := True;
    exit;
  end;

  // create the response body
  body := TUPnP_XMLStream.Create;
  try
    with body do
    begin
      if fSignResponse then
      begin
        WriteTagStartAndAttributes(_sBody, [_sBodyAttrSigned]);
      end
      else
      begin
        WriteTagStart(_sBody);
      end;

      // write the body of the response
      WriteTagStartAndAttributes(_uQSV, [_uQSV_XmlNS]);

      // write the value; add escaping if necessary...
      WriteTagAndValue(_return, EncodedValue);

      WriteTagEnd(_uQSV);
      WriteTagEnd(_sBody);
    end;

    securityinfo := nil;
    try
      // sign the body thereby creating the SecurityInfo
      if fSignResponse and Assigned(fDevSec) then
      begin
        fDevSec.Sign(self, body, securityinfo);
      end;

      // write the response envelope
      with Response.XMLStream do
      begin
        // write the envelope start
        WriteTagStart(XML_VerString);
        WriteTagStartAndAttributes(_sEnvelope, [_sEnvelopeAttrs]);

        // write the security info header
        if Assigned(securityinfo) then
        begin
          WriteTagStart(_sHeader);
          WriteStream(securityinfo);
          WriteTagEnd(_sHeader);
        end;

        // write the body
        WriteStream(body);

        // write the envelope end
        WriteTagEnd(_sEnvelope);

        // add 1 new line at end
        WriteLN('');
      end;

      // if we got here then we succeeded
      Result := True;

    finally
      if Assigned(securityinfo) then
      begin
        securityinfo.Free;
      end;
    end;
  finally
    body.Free;
  end;
end;

procedure TUPnP_StateVariable.SetAllowedStrings(aStrings: TStringList);
{
  Property setter
  Status: FULLY TESTED
}
begin
  // set the property
  fAllowedStrings.Assign(aStrings);

  // update the allowed values selector
  if (fAllowedStrings.Count > 0) and (fDataType in [char_, string_]) then
  begin
    fAllowedValues := List;
  end;

  // force testing / contraining of values within the new range
  if not (csLoading in ComponentState) then
  begin
    DefaultValue := fDefaultValue;
    Value := fValue;
  end;
end;

procedure TUPnP_StateVariable.SetSecurityPermissions(Value:
  TUPnP_SecurityPermissionCollection);
{
  Used by Object Inspector at design time to assign permissions to the SecurityPermissions collection
  Status: FULLY TESTED
}
begin
  fSecurityPermissions.Assign(Value);
end;

procedure TUPnP_SecurityPermission.DoFixups(aRoot: TUPnP_RootDevice;
  aServiceList: TStringList);
{
  Delayed call used for late binding (fixups) after loading from streams
  and/or scan through embedded items looking for bad entries
  Status: FULLY TESTED
}
begin
  inherited;

  // set the root device
  SetRootDevice(aRoot);
end;

procedure TUPnP_SecurityPermission.SetName(const NewName: TComponentName);
{
  Sets the component name (inherited) and also updates some dependant variables
  Status: FULLY TESTED
}
begin
  if (csDesigning in ComponentState) and not (csLoading in ComponentState) then
  begin
    if (fUIName = '') or (fUIName = Name) then
    begin
      UIName := NewName;
    end;
  end;
  inherited;
end;

procedure TUPnP_SecurityPermission.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Writes the object's self description XML
  Status: FULLY TESTED
}
begin
  with aBuffer do
  begin
    WriteTagStart(_permission);
    WriteTagAndValue(_UIName, fUIName);
    WriteTagAndValue(_ACLentry, Format(_PermsFmt, [fACLentryName]));
    WriteTagAndValue(_fullDescriptionURL, fFullDescriptionURL);
    WriteTagAndValue(_shortDescription, fShortDescription);
    WriteTagEnd(_permission);
  end;
end;

function TUPnP_SecurityPermission.GetDisplayName: string;
{
  Returns the Display Name
  Status: FULLY TESTED
}
begin
  Result := fUIName;
end;

constructor TUPnP_SecurityPermission.Create(AOwner: TComponent);
{
  Creates the object, and initialises variables
  Status: FULLY TESTED
}
begin
  inherited;
  UIName := Name;
  fACLentryName := '';
  fFullDescriptionURL := '';
  fShortDescription := '';
  Inc(fPropertyCount, 4);
end;

function TUPnP_SecurityPermission.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := ui_UIName;
    end;
    2:
    begin
      Result := ui_ACLEntryName;
    end;
    3:
    begin
      Result := ui_FullDescriptionURL;
    end;
    4:
    begin
      Result := ui_ShortDescription;
    end;
    else
    begin
      Result := inherited GetPropertyName(anIndex);
    end;
  end;
end;

function TUPnP_SecurityPermission.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    1:
    begin
      Result := fUIName;
    end;
    2:
    begin
      Result := fACLentryName;
    end;
    3:
    begin
      Result := fFullDescriptionURL;
    end;
    4:
    begin
      Result := fShortDescription;
    end;
    else
    begin
      Result := inherited GetPropertyValue(anIndex);
    end;
  end;
end;

constructor TUPnP_SubscriptionItem.Create(AOwner: TComponent);
{
  Create a subscription object
  Status: FULLY TESTED
}
begin
  Assert(aOwner is TUPnP_CustomService);

  inherited;

  // set up the input data
  SetOwnerService(TUPnP_CustomService(aOwner));
  SetRootDevice(fOwnerService.fRootDevice);
  fVariables := fOwnerService.fStateVariables.Count;

  // get memory for the flags, and set them to #1
  if fVariables > 0 then
  begin
    GetMem(fPublishPendingFlags, fVariables);
  end
  else
  begin
    fPublishPendingFlags := nil;
  end;
end;

destructor TUPnP_SubscriptionItem.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
  // destroy previously pending thread (if any)
  DestroyPendingThread;

  // free the flags
  if Assigned(fPublishPendingFlags) then
  begin
    FreeMem(fPublishPendingFlags, fVariables);
  end;

  // free the urls
  if assigned(fCallBackURLs) then
  begin
    fCallBackURLs.Free;
  end;

  inherited;
end;

function TUPnP_SubscriptionItem.GetDisplayName: string;
{
  Returns the Display Name
  Status: FULLY TESTED
}
begin
  Result := fCallBackURLs[0];
end;

procedure TUPnP_SubscriptionItem.SetPublishPendingFlag(aNo: integer);
{
  Set the flag for sending the respective event
  Status: FULLY TESTED
}
begin
  if Assigned(fPublishPendingFlags) and (aNo >= 0) and (aNo <= fVariables) then
  begin
    fPublishPendingFlags[aNo] := #1;
  end;
end;

function TUPnP_SubscriptionItem.Subscribe(Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Open a subscription
  Status: FULLY TESTED

  Format of response is:
  HTTP/1.1 200 OK
  DATE: when response was generated
  SERVER: OS/version UPnP/1.0 product/version
  SID: uuid:subscription-UUID
  TIMEOUT: Second-actual subscription duration
}
var
  lTimeout: cardinal;
begin
  Assert(assigned(fRootDevice));

  // store the callback URL (s)
  fCallBackURLs := TUPnP_URLStrings.Create(Request.Callback);

  // create the UUID string
  fSID := UUIDStr + CreateClassID_NoBraces;
  fSequenceKey := 0;

  // check subscription request NT to see if it is old Windows Me code
  // if so then set the flag...
  if SameText(Request.NT, upnppropchange) then
  begin
    fIsOldWinMeVersion := True;
  end;

  // get the Timeout; round down to MaxAge
  lTimeout := min(fRootDevice.fMaxAge, Request.Timeout);

  // store the new expiry time -- allowing two subscription check intervals for safety
  fExpiry := Now + ((lTimeout - (2 * fRootDevice.fHeartBeatInterval)) / 86400);

  // write the response
  with Response.Response do
  begin
    ResponseNo := 200;
    Date   := NowGMT;
    Server := Server_Header;
    ContentType := '';
  end;
  with Response do
  begin
    SID     := fSID;
    TimeOut := lTimeout;
  end;

  // and set up to publish the initial event
  if Assigned(fPublishPendingFlags) then
  begin
    FillChar(fPublishPendingFlags^, fVariables, #1);
  end;

  // tell the root device to publish its events
  fRootDevice.MustPublishEvents;

  // if we got here, then we were sucessful
  Result := True;
end;

function TUPnP_SubscriptionItem.Renew(Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  renew a subscription to eventing for a service
  Status: FULLY TESTED

  Format of response is:
  HTTP/1.1 200 OK
  DATE: when response was generated
  SERVER: OS/version UPnP/1.0 product/version
  SID: uuid:subscription-UUID
  TIMEOUT: Second-actual subscription duration
}
var
  lTimeout: cardinal;
begin
  Assert(assigned(fRootDevice));

  // preset the result to false for fast exit
  Result := False;

  // check if the message is to our own SID
  if not SameText(Request.SID, fSID) then
  begin
    exit;
  end;

  // get the Timeout; round down to MaxAge
  lTimeout := min(fRootDevice.fMaxAge, Request.Timeout);

  // store the new expiry time -- allowing two subscription check intervals for safety
  fExpiry := Now + ((lTimeout - (2 * fRootDevice.fHeartBeatInterval)) / 86400);

  // write the response
  with Response.Response do
  begin
    ResponseNo := 200;
    Date   := NowGMT;
    Server := Server_Header;
    ContentType := '';
  end;
  with Response do
  begin
    SID     := fSID;
    TimeOut := lTimeout;
  end;

  // if we got here, then we were sucessful
  Result := True;
end;

function TUPnP_SubscriptionItem.UnSubscribe(Request: TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Cancel a subscription to eventing for a service
  Status: FULLY TESTED

  Format of response is:
  HTTP/1.1 200 OK
}
begin
  // preset the result to false for fast exit
  Result := False;

  // check if the message is to our own SID
  if not SameText(Request.SID, fSID) then
  begin
    exit;
  end;

  // set all the flags to #0
  if Assigned(fPublishPendingFlags) then
  begin
    FillChar(fPublishPendingFlags^, fVariables, #0);
  end;

  // write the HTTP response message
  Response.Response.ResponseNo  := 200;
  Response.Response.ContentType := '';

  // if we got here, then we were sucessful
  Result := True;
end;

function TUPnP_SubscriptionItem.TimedOut: boolean;
{
  Checks if the subscription sender thread has timed out
  Status: FULLY TESTED
}
begin
  Result := Assigned(fSubscriptionClientThread) and fSubscriptionClientThread.TimedOut;
end;

function TUPnP_SubscriptionItem.Expired: boolean;
{
  Checks if the subscription has expired
  Status: FULLY TESTED
}
begin
  // and return true if we have expired
  Result := Now > fExpiry;
end;

procedure TUPnP_SubscriptionItem.NotifyThreadDone(aThread: TThread);
{
  Notification when the thread has terminated
  Status: FULLY TESTED
}
begin
  if aThread = fSubscriptionClientThread then
  begin
    fSubscriptionClientThread := nil;
  end;
end;

procedure TUPnP_SubscriptionItem.DestroyPendingThread;
{
  Destroy any existing pending thread
  Status: FULLY TESTED
}
begin
  // unhook the call back & terminate the thread
  if assigned(fSubscriptionClientThread) then
  begin
    with fSubscriptionClientThread do
    begin
      Lock.Enter;
      try
        Interrupt;
      finally
        Lock.Leave;
      end;
    end;
  end;
end;

procedure TUPnP_SubscriptionItem.PublishEvents;
{
  To send an event message, a publisher must send a request with method NOTIFY in the
  following format. Values in italics below are placeholders for actual values.
  Status: FULLY TESTED

  NOTIFY delivery path HTTP/1.1
  HOST: delivery host:delivery port
  CONTENT-TYPE: text/xml
  CONTENT-LENGTH: Bytes in body
  NT: upnp:event
  NTS: upnp:propchange
  SID: uuid:subscription-UUID
  SEQ: event key

  <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
    <e:property>
      <variableName>new value</variableName>
    </e:property>
    Other variable names and values (if any) go here.
  </e:propertyset>
}
var
  j: integer;
  lPublishPending: boolean;
begin
  Assert(assigned(fRootDevice));

  // determine if we have anything to publish
  lPublishPending := False;
  for j := 0 to pred(fVariables) do
  begin
    lPublishPending := lPublishPending or (fPublishPendingFlags[j] <> #0);
  end;

  if lPublishPending then
  begin
    // destroy previously pending thread (if any)
    DestroyPendingThread;

    // create a new subscription client thread
    fSubscriptionClientThread :=
      TUPnP_SubscriptionClientThread.Create(True, self);

    with fSubscriptionClientThread do
    begin
      // set some basic parameters
      SocketTimeOut := fRootDevice.fSocketTimeout;
      URL := fCallBackURLs.Strings[fActiveURLIndex];
      SID := fSID;
      SEQ := fSequenceKey;

      // set up the logging
      if fLogTCPClient in fRootDevice.fLoggingFlags then
      begin
        OnLog := fRootDevice.OnLogMessage;
      end
      else
      begin
        OnLog := nil;
      end;

      // write the GENA body
      with XmlStream do
      begin

        if not fIsOldWinMeVersion then
        begin
          // WinMe does not accept the XML version header
          WriteTagStart(XML_VerString);
        end;

        WriteTagStartAndAttributes(_epropertyset, [_epropertysetXmlNS]);

        // send the state of all evented variables if the flag is set
        for j := 0 to pred(fVariables) do
        begin
          if fPublishPendingFlags[j] <> #0 then
          begin
            with fOwnerService.fStateVariables[j] do
            begin
              if fSendEvents then
              begin
                SaveEventToXML(XmlStream);
              end;
            end;
          end;
        end;

        WriteTagEnd(_epropertyset);
        WriteNewLine;

        // for old Windows Me clients we have to append an extra \0
        if fIsOldWinMeVersion then
        begin
          WriteValues([#0]);
        end;
      end;

      // start to send the event
      Resume;
    end;

    // we are done, so set all the flags to #0
    if Assigned(fPublishPendingFlags) then
    begin
      FillChar(fPublishPendingFlags^, fVariables, #0);
    end;

    // increment the sequence count
    Inc(fSequenceKey);

    // if the sequence count wrapped then set it to 1
    if fSequenceKey = 0 then
    begin
      Inc(fSequenceKey);
    end;
  end;
end;

procedure TUPnP_CollectionItem.AssignComponent(aComponent: TUPnP_Component);
{
  Status: FULLY TESTED
}
begin
  { abstract }
end;

procedure TUPnP_DeviceItem.SetDevice(Value: TUPnP_Device);
{
  Sets the new value and,
  sets it's fOwnerDevice to point to the Collection's fOwnerDevice
  Status: FULLY TESTED
}
begin
  Value.SetOwnerDevice(TUPnP_Device(Collection.Owner));
  fDevice := Value;
end;

function TUPnP_DeviceItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fDevice) then
  begin
    Result := Format(fmt_item, [fDevice.Name, fDevice.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_DeviceItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnp_Device then
  begin
    SetDevice(TUPnp_Device(aComponent));
  end;
end;

procedure TUPnP_ServiceItem.SetService(Value: TUPnP_CustomService);
{
  Sets the new value and,
  sets it's fOwnerDevice to point to the Collection's fOwnerDevice
  Status: FULLY TESTED
}
begin
  Value.SetOwnerDevice(TUPnP_Device(Collection.Owner));
  fService := Value;
end;

function TUPnP_ServiceItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fService) then
  begin
    Result := Format(fmt_item, [fService.Name, fService.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_ServiceItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_CustomService then
  begin
    SetService(TUPnP_CustomService(aComponent));
  end;
end;

function TUPnP_IconItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fIcon) then
  begin
    Result := Format(fmt_item, [fIcon.Name, fIcon.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_IconItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_Icon then
  begin
    SetIcon(TUPnP_Icon(aComponent));
  end;
end;

procedure TUPnP_IconItem.SetIcon(Value: TUPnP_Icon);
{
  Sets the new value and,
  sets it's fOwnerDevice to point to the Collection's fOwnerDevice
  Status: FULLY TESTED
}
begin
  Value.SetOwnerDevice(TUPnP_Device(Collection.Owner));
  fIcon := Value;
end;

procedure TUPnP_StateVariableItem.SetStateVariable(Value: TUPnP_StateVariable);
{
  Sets the new value and,
  sets it's fOwnerService to point to the Collection's fOwnerService
  Status: FULLY TESTED
}
begin
  Value.SetOwnerService(TUPnP_Service(Collection.Owner));
  fStateVariable := Value;
end;

function TUPnP_StateVariableItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fStateVariable) then
  begin
    Result := Format(fmt_item, [fStateVariable.Name, fStateVariable.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_StateVariableItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_StateVariable then
  begin
    SetStateVariable(TUPnP_StateVariable(aComponent));
  end;
end;

procedure TUPnP_ActionItem.SetAction(Value: TUPnP_Action);
{
  Sets the new value and,
  sets it's fOwnerService to point to the Collection's fOwnerService
  Status: FULLY TESTED
}
begin
  Value.SetOwnerService(TUPnP_Service(Collection.Owner));
  fAction := Value;
end;

function TUPnP_ActionItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fAction) then
  begin
    Result := Format(fmt_item, [fAction.Name, fAction.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_ActionItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_Action then
  begin
    SetAction(TUPnP_Action(aComponent));
  end;
end;

function TUPnP_SecurityPermissionItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fSecurityPermission) then
  begin
    Result := Format(fmt_item, [fSecurityPermission.Name,
      fSecurityPermission.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_SecurityPermissionItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_SecurityPermission then
  begin
    fSecurityPermission := TUPnP_SecurityPermission(aComponent);
  end;
end;

procedure TUPnP_ArgumentItem.SetArgument(Value: TUPnP_Argument);
{
  Sets the new value and,
  sets it's fOwnerService to point to the Collection's fOwnerService
  Status: FULLY TESTED
}
begin
  Value.SetOwnerAction(TUPnP_Action(Collection.Owner));
  fArgument := Value;
end;

function TUPnP_ArgumentItem.GetDisplayName: string;
{
  Get the display name for Object Inspector property editor
  Status: FULLY TESTED
}
begin
  if Assigned(fArgument) then
  begin
    Result := Format(fmt_item, [fArgument.Name, fArgument.GetDisplayName]);
  end
  else
  begin
    Result := Err_Not_Set;
  end;
end;

procedure TUPnP_ArgumentItem.AssignComponent(aComponent: TUPnP_Component);
{
  Assign the provided component
  Status: FULLY TESTED
}
begin
  inherited;
  if aComponent is TUPnP_Argument then
  begin
    SetArgument(TUPnP_Argument(aComponent));
  end;
end;

constructor TUPnP_DeviceCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  and sets it's fOwnerdevice to point to the AOwner
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_CustomDevice);
  inherited Create(AOwner, TUPnP_DeviceItem);
end;

function TUPnP_DeviceCollection.GetDevice(index: integer): TUPnP_CustomDevice;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_DeviceItem).Device;
end;

constructor TUPnP_ServiceCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  and sets it's fOwnerdevice to point to the AOwner
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_CustomDevice);
  inherited Create(AOwner, TUPnP_ServiceItem);
end;

function TUPnP_ServiceCollection.GetService(index: integer): TUPnP_CustomService;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_ServiceItem).Service;
end;

constructor TUPnP_IconCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_CustomDevice);
  inherited Create(AOwner, TUPnP_IconItem);
end;

function TUPnP_IconCollection.GetIcon(index: integer): TUPnP_Icon;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_IconItem).Icon;
end;

constructor TUPnP_StateVariableCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  and sets it's fOwnerService to point to the AOwner
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_CustomService);
  inherited Create(AOwner, TUPnP_StateVariableItem);
end;

function TUPnP_StateVariableCollection.GetStateVariable(index: integer):
TUPnP_StateVariable;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_StateVariableItem).StateVariable;
end;

constructor TUPnP_ActionCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  and sets it's fOwnerService to point to the AOwner
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_CustomService);
  inherited Create(AOwner, TUPnP_ActionItem);
end;

function TUPnP_ActionCollection.fGetAction(index: integer): TUPnP_Action;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_ActionItem).Action;
end;

constructor TUPnP_ArgumentCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  and sets it's fOwnerAction to point to the AOwner
  Status: FULLY TESTED
}
begin
  Assert(AOwner is TUPnP_Action);
  inherited Create(AOwner, TUPnP_ArgumentItem);
end;

function TUPnP_ArgumentCollection.fGetArgument(index: integer): TUPnP_Argument;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_ArgumentItem).Argument;
end;

constructor TUPnP_SecurityPermissionCollection.Create(AOwner: TPersistent);
{
  Creates a collection of the desired type
  Status: FULLY TESTED
}
begin
  inherited Create(AOwner, TUPnP_SecurityPermissionItem);
end;

function TUPnP_SecurityPermissionCollection.fGetSecurityPermission(
  index: integer): TUPnP_SecurityPermission;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_SecurityPermissionItem).SecurityPermission;
end;

function TUPnP_SubscriptionCollection.fGetSubscription(index: integer):
TUPnP_SubscriptionItem;
{
  Returns a pointer to the component that is embedded in the (indexed) collection item
  will cause an RTTI exception if the component or the collection item are the wrong type
  Status: FULLY TESTED
}
begin
  Result := (Items[index] as TUPnP_SubscriptionItem);
end;

function GetFileVersion(const FileName: string; out MajorVersion: word;
  out MinorVersion: word; out Release: word; out Build: word): boolean;
{
  Get File Version Information
  Status: FULLY TESTED
}
var
  Size:   longword;
  Dummy:  longword;
  Buffer: array of byte;
  VSFixedFileInfo: PVSFixedFileInfo;

begin
  Result := False;
  Size   := GetFileVersionInfoSize(PChar(FileName), Dummy);

  if (Size > 0) then
  begin
    SetLength(Buffer, Size);
    GetFileVersionInfo(PChar(FileName), 0, Size, Buffer);

    if (VerQueryValue(Buffer, '\', Pointer(VSFixedFileInfo), Dummy)) then
    begin
      MajorVersion := HiWord(VSFixedFileInfo.dwFileVersionMS);
      MinorVersion := LoWord(VSFixedFileInfo.dwFileVersionMS);
      Release := HiWord(VSFixedFileInfo.dwFileVersionLS);
      Build  := LoWord(VSFixedFileInfo.dwFileVersionLS);
      Result := True;
    end;
  end;
end;

constructor TUPnP_Component.Create(AOwner: TComponent);
{
  Constructor
  Status: FULLY TESTED
}
begin
  inherited;
  fPropertyCount := 1;
  syncStateChangeCritSect := TCriticalSection.Create;
end;

destructor TUPnP_Component.Destroy;
{
  Clean up the UI stuff
  Status: FULLY TESTED
}
begin
  if fConnected then
  begin
    Disconnect;
  end;
  syncStateChangeCritSect.Free;
  inherited;
end;

procedure TUPnP_Component.Reset;
{
  Reset the component
  Status: FULLY TESTED
}
begin
  { abstract }
end;

procedure TUPnP_Component.SetRootDevice(aRootDevice: TUPnP_RootDevice);
{
  Hook up root device and ensure notification if it is freed
  Status: FULLY TESTED
}
begin
  fRootDevice := aRootDevice;
  if assigned(fRootDevice) then
  begin
    fRootDevice.FreeNotification(self);
  end;
end;

procedure TUPnP_Component.SetOwnerDevice(aOwnerDevice: TUPnP_CustomDevice);
{
  Hook up owner device and ensure notification if it is freed
  Status: FULLY TESTED
}
begin
  fOwnerDevice := aOwnerDevice;
  if assigned(fOwnerDevice) then
  begin
    fOwnerDevice.FreeNotification(self);
  end;
end;

procedure TUPnP_Component.SetOwnerService(aOwnerService: TUPnP_CustomService);
{
  Hook up owner service and ensure notification if it is freed
  Status: FULLY TESTED
}
begin
  fOwnerService := aOwnerService;
  if assigned(fOwnerService) then
  begin
    fOwnerService.FreeNotification(self);
  end;
end;

procedure TUPnP_Component.SetOwnerAction(aOwnerAction: TUPnP_Action);
{
  Hook up owner action and ensure notification if it is freed
  Status: FULLY TESTED
}
begin
  fOwnerAction := aOwnerAction;
  if assigned(fOwnerAction) then
  begin
    fOwnerAction.FreeNotification(self);
  end;
end;

procedure TUPnP_Component.Notification(AComponent: TComponent; Operation: TOperation);
{
  Unhook any "owner" objects
  Status: FULLY TESTED
}
begin
  if Operation = opRemove then
  begin
    if aComponent = fRootDevice then
    begin
      fRootDevice := nil;
    end;
    if aComponent = fOwnerDevice then
    begin
      fOwnerDevice := nil;
    end;
    if aComponent = fOwnerService then
    begin
      fOwnerService := nil;
    end;
    if aComponent = fOwnerAction then
    begin
      fOwnerAction := nil;
    end;
  end;
  inherited;
end;

procedure TUPnP_Component.Disconnect;
{
  Status: FULLY TESTED
}
begin
  fConnected := False;
end;

procedure TUPnP_Component.Connect;
{
  Status: FULLY TESTED
}
begin
  fConnected := True;
end;

procedure TUPnP_Component.DoFixups(aRoot: TUPnP_RootDevice; aServiceList: TStringList);
{
  Execute late binding (fixups) after loading from streams
  Status: FULLY TESTED
}
begin
  { abstract }
end;

procedure TUPnP_Component.PublishEvents;
{
  Always overridden
  Status: FULLY TESTED
}
begin
  { abstract }
end;

class procedure TUPnP_Component.About;
{
  Show the about box
  Status: FULLY TESTED
}
begin
  MessageDlg(Format(aboutFMT, [UPnP_Library_Name, UPnP_Library_Version,
    UPnP_Library_Copyright]), mtInformation, [mbOK], 0);
end;

procedure TUPnP_Component.HTTPError(Response: TUPnP_HTTPServerResponseWrapper;
  ErrCode: THTTPResponseCodes);
{
  Writes an HTTP error code
  Status: FULLY TESTED
}
begin
  Response.Response.ResponseNo := HTTP_ResponseNo[ErrCode];
  Response.Response.Date   := NowGMT;
  Response.Response.Server := Server_Header;
  Response.Response.ContentLength := 0;
end;

function TUPnP_Component.GetPropertyName(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    0:
    begin
      Result := ClassName;
    end;
    else
    begin
      Result := '';
    end;
  end;
end;

function TUPnP_Component.GetPropertyValue(anIndex: cardinal): string;
{
  Property getter
  Status: FULLY TESTED
}
begin
  case anIndex of
    0:
    begin
      if Name <> '' then
      begin
        Result := Name;
      end
      else
      begin
        Result := ui_unnamed;
      end;
    end;
    else
    begin
      Result := '';
    end;
  end;
end;

procedure TUPnP_Component.SetPropertyValue(anIndex: cardinal; aValue: string);
{
  Property setter
  Status: FULLY TESTED
}
begin
  { abstract }
end;

function TUPnP_Component.GetPropertyEditable(anIndex: cardinal): boolean;
{
  Property getter
  Status: FULLY TESTED
}
begin
  Result := False;
end;

procedure TUPnP_Component.syncStateChange;
{
  Synchronize the call to fOnStateChange in order to protect the VCL
  Status: FULLY TESTED
}
begin
  fOnStateChange(syncSender);
end;

procedure TUPnP_Component.DoStateChange(Sender: TObject);
{
  Send state change events; the state changes may be initiated on another
  (Indy) thread, so we use Synchronize to protect the VCL
  Status: FULLY TESTED
}
begin
  if assigned(fOnStateChange) and (not (csDestroying in ComponentState)) then
  begin

    // enter the critical section
    syncStateChangeCritSect.Enter;
    try

      // call the syncStateChange emthod
      syncSender := Sender;
      TThread.Synchronize(nil, syncStateChange);
      syncSender := nil;

    finally
      // leave the critical section
      syncStateChangeCritSect.Leave;
    end;
  end;
end;

constructor TUPnP_URLStrings.Create(aString: string);
{
  Construct the string list and load it from the <url><url> string
  Status: FULLY TESTED
}
begin
  Create;
  Sorted := False;
  Text   := AnsiReplaceStr(AnsiReplaceStr(AnsiReplaceStr(aString, '><', crlf),
    '<', ''), '>', '');
end;

// *********************** XML Escaping Utilities ********************

function XmlToEscaped(aString: string): string;
{
  Convert an XML text with ">" and "<" characters to an escaped version with "&gt;" and "&lt;"
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // preset the result
  Result := '';

  // loop through the whole input string
  for i := 1 to length(aString) do

    // if the input byte is <, > or & then append '&lt;', '&gt;' or '&amp;' to the output result
  begin
    case aString[i] of
      '>':
      begin
        Result := Result + '&gt;';
      end;
      '<':
      begin
        Result := Result + '&lt;';
      end;
      '&':
      begin
        Result := Result + '&amp;';
      end;
      else
      begin
        // otherwise just append the byte 1 for 1
        Result := Result + aString[i];
      end;
    end;
  end;
end;

function EscapedToXml(aString: string): string;
{
  Convert escaped text with "&gt;" and "&lt;" characters to an XML version with ">" and "<"
  Status: FULLY TESTED
}
var
  i, d: integer;
  p:    pchar;
begin
  // preset the result
  Result := '';

  // preset the counter
  i := 1;

  // loop through the whole input string
  while i <= length(aString) do
  begin

    // preset the increment to 1 byte
    d := 1;

    // look for the '&' escape character
    if (aString[i] = '&') then
    begin

      // set a pointer to the escape string
      p := PChar(aString) + i;

      // if the input is '&lt;'
      if StrLIComp(p, 'lt;', 3) = 0 then
      begin

        // append < to the output result
        Result := Result + '<';

        // set the increment to 4 bytes
        d := 4;
      end
      else
      begin
        // if the input is '&gt;'
        if StrLIComp(p, 'gt;', 3) = 0 then
        begin

          // append > to the output result
          Result := Result + '>';

          // set the increment to 4 bytes
          d := 4;
        end
        else
        begin
          // if the input is '&amp;'
          if StrLIComp(p, 'amp;', 4) = 0 then
          begin

            // append & to the output result
            Result := Result + '&';

            // set the increment to 5 bytes
            d := 5;
          end
          else
          begin
            // otherwise just copy the byte 1 to 1
            Result := Result + aString[i];
          end;
        end;
      end;
    end
    else
    begin
      // otherwise just copy the byte 1 to 1
      Result := Result + aString[i];
    end;

    // bump the input index
    Inc(i, d);
  end;
end;

initialization
  // initialize the "random" seed
  Randomize;
end.

