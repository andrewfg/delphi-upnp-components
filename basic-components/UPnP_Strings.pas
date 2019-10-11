{
  UPnP_Strings:
  Strings for UPnP Device and Service objects.
  Copyright (c) 2001..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_Strings.pas,v 1.19 2005/09/18 08:21:40 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Status:

  Revision History:
    June 2005
      - Moved to own unit
    July 22, 2005
      - Release v1.5.03
    September 18, 2005
      - Release v1.5.04
}

unit UPnP_Strings;

interface

uses
  UPnP_Components,
  UPnP_Globals;

const
  UPnP_Library_Name      = 'UPnP Components for Delphi';
  UPnP_Library_Copyright = 'Copyright (c) 2001..2005, Andrew Fiddian-Green';
  UPnP_Library_Version   = '1.5.04';

  Server_Header = 'Andrew Fiddian-Green/1.0, UPnP/1.0, Delphi Components/' +
    UPnP_Library_Version;

  ui_DeviceType                = 'Device Type';
  ui_DeviceVersion             = 'Device Version';
  ui_FriendlyName              = 'Friendly Name';
  ui_Manufacturer              = 'Manufacturer';
  ui_ManufacturerURL           = 'Manufacturer URL';
  ui_ModelDescription          = 'Model Description';
  ui_ModelName                 = 'Model Name';
  ui_ModelNumber               = 'Model Number';
  ui_ModelURL                  = 'Model URL';
  ui_SerialNumber              = 'Serial Number';
  ui_UDN                       = 'Unique Device Number';
  ui_UPC                       = 'Universal Product Code';
  ui_DeviceDescription         = 'Device Description';
  ui_ServiceID                 = 'Service ID';
  ui_ServiceType               = 'Service Type';
  ui_ServiceDescription        = 'Service Description';
  ui_ServiceVersion            = 'Service Version';
  ui_ActionName                = 'Action Name';
  ui_RequiresAuthorization     = 'Requires Authorization';
  ui_RequiresSigning           = 'Requires Signing';
  ui_RequiresPrivacy           = 'Requires Privacy';
  ui_Connected                 = 'Connected';
  ui_TimeToLive                = 'Time-To-Live';
  ui_HeartbeatInterval         = 'Heartbeat Interval';
  ui_MaxAge                    = 'Max-Age';
  ui_SocketTimeout             = 'Socket Timeout';
  ui_MulticastPort             = 'Multicast Port';
  ui_HTTPPort                  = 'HTTP Port';
  ui_URLbase                   = 'URL Base';
  ui_MulticastIPAddress        = 'Multicast IP Address';
  ui_MimeType                  = 'Mime Type';
  ui_Depth                     = 'Depth';
  ui_Width                     = 'Width';
  ui_Height                    = 'Height';
  ui_Icon                      = 'Icon';
  ui_ArgumentName              = 'Argument Name';
  ui_Direction                 = 'Direction';
  ui_StateVariableName         = 'State Variable Name';
  ui_Value                     = 'Value';
  ui_DataType                  = 'Data Type';
  ui_DefaultValue              = 'Default Value';
  ui_Minimum                   = 'Minimum';
  ui_Maximum                   = 'Maximum';
  ui_Step                      = 'Step';
  ui_AllowedValues             = 'AllowedValues';
  ui_AllowedStrings            = 'Allowed Strings';
  ui_SendEvents                = 'Send Events';
  ui_UIName                    = 'UI Name';
  ui_ACLEntryName              = 'ACL Entry Name';
  ui_FullDescriptionURL        = 'FullDescription URL';
  ui_ShortDescription          = 'Short Description';
  ui_unnamed                   = '{un-named}';

  ui_AllowedValueType: array[TUPnP_AllowedValueType] of string = ('Anything', 'List', 'Range');

  bool_1                       = '1';
  bool_0                       = '0';
  bool_yes                     = 'yes';
  bool_no                      = 'no';
  bool_True                    = 'True';
  bool_False                   = 'False';

  fmt_SU                       = '%s:%u';

  method_Get                   = 'GET';
  method_Post                  = 'POST';
  method_MPost                 = 'M-POST';
  method_MSearch               = 'M-SEARCH';
  method_Subscribe             = 'SUBSCRIBE';
  method_UnSubscribe           = 'UNSUBSCRIBE';
  s_HTTP                       = 'http';
  MulticastNotify              = 'NOTIFY * HTTP/1.1';
  fmtNotiify                   = 'NOTIFY %s HTTP/1.1';
  MulticastSearch              = 'M-SEARCH * HTTP/1.1';
  Http_200_Ok                  = 'HTTP/1.1 200 OK';
  Http_Response                = 'HTTP/1.1 %u  %s' + #13#10 + '%s' + #13#10 + '%s';
  USN_Hdr                      = 'USN';
  NT_Hdr                       = 'NT';
  NTS_Hdr                      = 'NTS';
  Date_Hdr                     = 'Date';
  Ext_Hdr                      = 'EXT';
  ST_Hdr                       = 'ST';
  SID_Hdr                      = 'SID';
  MX_Hdr                       = 'MX';
  MAN_Hdr                      = 'MAN';
  Callback_Hdr                 = 'Callback';
  TimeOut_Hdr                  = 'Timeout';
  SEQ_Hdr                      = 'SEQ';
  HOST_Hdr                     = 'Host';
  SoapAction_Hdr               = 'SOAPACTION';
  Server_Hdr                   = 'Server';
  CacheControl_Hdr             = 'Cache-Control';
  Location_Hdr                 = 'Location';
  Application_Xml              = 'application/xml';
  text_xml_utf8                = 'text/xml; charset="utf-8"';
  SecondHdrLower               = 'second-';
  SecondHdrFirstCap            = 'Second-';
  max_age                      = 'max-age=';
  SSDPAlive                    = 'ssdp:alive';
  SSDPByeBye                   = 'ssdp:byebye';
  SSDPAll                      = 'ssdp:all';
  SSDPDISCOVER                 = 'ssdp:discover';
  upnpevent                    = 'upnp:event';
  upnppropchange               = 'upnp:propchange';
  UPnPRootDevice               = 'upnp:rootdevice';
  UUIDStr                      = 'uuid:';
  Schemas_DeviceHdrFmt         = 'urn:%s:device:%s:%s';
  Schemas_ServiceHdrFmt        = 'urn:%s:service:%s:%s';
  Schemas_ServiceIdHdrFmt      = 'urn:%s:serviceId:%s';
  Device_schema                = 'schemas-upnp-org';
  Service_Schema               = 'schemas-upnp-org';
  ServiceID_Schema             = 'upnp-org';
  _UPnP                        = 'UPnP';
  DoubleColon                  = '::';
  SemiColonSpace               = '; ';

  _device                      = 'device';
  _deviceList                  = 'deviceList';
  _serviceList                 = 'serviceList';
  _iconList                    = 'iconList';
  _actionList                  = 'actionList';
  _serviceStateTable           = 'serviceStateTable';
  _service                     = 'service';
  _action                      = 'action';
  _argumentList                = 'argumentList';
  _specVersion                 = 'specVersion';
  _icon                        = 'icon';
  _argument                    = 'argument';
  _allowedValueRange           = 'allowedValueRange';
  _allowedValueList            = 'allowedValueList';
  _eproperty                   = 'e:property';
  _epropertysetXmlNS           = 'xmlns:e="urn:schemas-upnp-org:event-1-0"';
  _epropertyset                = 'e:propertyset';
  _deviceType                  = 'deviceType';
  _friendlyName                = 'friendlyName';
  _manufacturer                = 'manufacturer';
  _manufacturerURL             = 'manufacturerURL';
  _modelDescription            = 'modelDescription';
  _modelName                   = 'modelName';
  _modelNumber                 = 'modelNumber';
  _modelURL                    = 'modelURL';
  _serialNumber                = 'serialNumber';
  _UDN                         = 'UDN';
  _UPC                         = 'UPC';
  _presentationURL             = 'presentationURL';
  _serviceType                 = 'serviceType';
  _serviceId                   = 'serviceId';
  _SCPDURL                     = 'SCPDURL';
  _controlURL                  = 'controlURL';
  _eventSubURL                 = 'eventSubURL';
  _scpdXmlNS                   = 'xmlns="urn:schemas-upnp-org:service-1-0"';
  _major                       = 'major';
  _minor                       = 'minor';
  _scpd                        = 'scpd';
  _sEnvelopeAttrs              = 'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +
                                 'soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"';
  _sEnvelope                   = 'soap:Envelope';
  _sBody                       = 'soap:Body';
  _sFault                      = 'soap:Fault';
  _sClient                     = 'soap:Client';
  _sHeader                     = 'soap:Header';
  _faultcode                   = 'faultcode';
  _faultstring                 = 'faultstring';
  _UPnPError                   = 'UPnPError';
  _detail                      = 'detail';
  _UPnPErrorXmlNS              = 'xmlns="urn:schemas-upnp-org:control-1-0"';
  _errorCode                   = 'errorCode';
  _errorDescription            = 'errorDescription';
  _uResponseFmtXmlNS           = 'u:%sResponse xmlns:u="%s"';
  _uResponseFmt                = 'u:%sResponse';
  _rootXmlNS                   = 'xmlns="urn:schemas-upnp-org:device-1-0"';
  _root                        = 'root';
  _URLBase                     = 'URLBase';
  _name                        = 'name';
  _relatedStateVariable        = 'relatedStateVariable';
  _direction                   = 'direction';
  _retval                      = 'retval';
  _stateVariableAttr           = 'sendEvents="%s"';
  _dataType                    = 'dataType';
  _defaultValue                = 'defaultValue';
  _minimum                     = 'minimum';
  _maximum                     = 'maximum';
  _step                        = 'step';
  _allowedValue                = 'allowedValue';
  _stateVariable               = 'stateVariable';
  _uQSV_XmlNS                  = 'xmlns:u="urn:schemas-upnp-org:control-1-0"';
  _uQSV                        = 'u:QueryStateVariableResponse';
  _return                      = 'return';
  _varName                     = 'varName';
  _QueryStateVariable          = 'QueryStateVariable';
  _mimetype                    = 'mimetype';
  _width                       = 'width';
  _height                      = 'height';
  _depth                       = 'depth';
  _url                         = 'url';
  _scpdPath                    = '/scpd.xml';
  _controlPath                 = '/control';
  _eventPath                   = '/eventing';
  _presentationPath            = '/presentation.html';
  _descriptionPath             = '/description.xml';
  _iconPath                    = '/icons/';
  _UIName                      = 'UIname';
  _Body                        = 'Body';

  // security strings
  _SecurityInfo                = 'SecurityInfo';
  _id                          = 'Id';
  _DevSecNSbase                = 'urn:schemas-upnp-org:service:DeviceSecurity:1';
  _sBodyAttrSigned             = 'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:us="' +
                                 _devSecNSbase + '" us:' + _Id + '="Body"';
  _permission                  = 'Permission';
  _ACLentry                    = 'ACLEntry';
  _PermsFmt                    = '<mfgr:%s/>';
  _fullDescriptionURL          = 'FullDescriptionURL';
  _shortDescription            = 'ShortDescription';
  _DevSecAttrs                 = 'xmlns="' + _devSecNSbase + '"';
  _FreshnessAttrs              = 'xmlns="' + _devSecNSbase + '" xmlns:us="' +
                                 _devSecNSbase + '" us:' + _Id + '="Freshness"';


  //  date formatting strings }
  _dateFormat                  = 'yyyy-mm-dd"T"hh:nn:ss"Z"';
  _shortDateFormat             = 'yyyy-mm-dd';
  _shortTimeFormat             = 'hh:nn:ss';
  _DateSeparator               = '-';
  _TimeSeparator               = ':';

  _RegistryPathX = '\SOFTWARE\Andrew Fiddian-Green\' + UPnP_Library_Name + '\';

  // Other useful strings for UPnP
  _majorVersion                = '1';
  _minorVersion                = '0';
  XML_VerString                = '?xml version="1.0"?';

  crlf                         = #13#10;
  empty                        = '';
  _equals                      = '%s=%s';
  fmt_item                     = 'Component Name = %s; UPnP ID = %s';

  DeviceStr                    = 'Device';
  ServiceStr                   = 'Service';
  IconStr                      = 'Icon';
  ActionStr                    = 'Action';
  ArgumentStr                  = 'Argument';
  StateVariableStr             = 'State variable';
  StateVariableStr1            = 'StateVariable';
  PermissionStr                = 'SecurityPermission';
  RelatedStateVarStr           = 'Related State Variable';
  default_DeviceType           = 'thisDeviceType';
  default_ServiceType          = 'thisServiceType';
  Err_Not_Set                  = 'Empty Entry';
  Err_Invalid                  = 'Invalid Entry';
  BadLink                      = 'Bad link: One of the %ss in %s is an %s';
  ActionFailed                 = 'Action %s failed with error code %s, error message " %s "';
  GeneralError                 = UPnP_Library_Name + ' experienced the following error:-  ' +
                                 CRLF + '  %s' + CRLF + CRLF;

  setValFMT                    = 'Problem assigning value "%s" to variable "%s"' + #13 +
                                 'Message "%s"';
  setDefValFMT                 = 'Problem assigning default value "%s" to variable "%s"' + #13 +
                                 'Message "%s"';
  aboutFMT                     = '%s' + #13 + 'Version: %s' + #13 +'%s';
  badIntegerFMT                = 'Integer value <%s> is outside the allowed range';
  badFloatFMT                  = 'Float value <%s> is outside the allowed range';
  badStringFMT                 = 'String <%s> is not in the allowed value list';
  badBooleanFMT                = 'String <%s> is not a valid boolean value';
  badCharFMT                   = 'String <%s> is not a single character';
  badCharFMT2                  = 'Character <%s> is not in the allowed value list';

  _yesno: array[boolean] of pchar = (
    'no',
    'yes');

  { SOAP error response strings }
  SOAP_Error: array[TSOAPErrorCodes, code_desc] of string = (
    ('401', 'Invalid Action'),
    ('402', 'Invalid Arguments'),
    ('403', 'Out Of Sync'),
    ('404', 'Invalid Variable'),
    ('501', 'Action Failed'),
    ('600', 'Argument Value Invalid'),
    ('601', 'Argument Value Out of Range'),
    ('602', 'Optional Action Not Implemented'),
    ('603', 'Out of Memory'),
    ('800', 'Related State Variable Not Implemented'),
    ('701', 'Action Not Authorized'),
    ('652', 'Action Not Permitted'),
    ('711', 'Signature Failure'),
    ('712', 'Signature Malformed or Missing'),
    ('714', 'Invalid Sequence Number'),
    ('715', 'Invalid Control URL'),
    ('657', 'Bad Digest'),
    ('721', 'Algorithm Not Supported'),
    ('722', 'IPSec Not Supported'),
    ('731', 'Certificates: Wrong Device'),
    ('741', 'Invalid Key'),
    ('751', 'Insufficient Memory'),
    ('761', 'Device Already Owned'),
    ('762', 'HMAC Failed'),
    ('763', 'May Not Delete Self'),
    ('764', 'No Such Entry'),
    ('765', 'Already Present'),
    ('766', 'Less Than Two Owners'),
    ('771', 'Entry Already Present'),
    ('772', 'Entry Does Not Exist'),
    ('773', 'Malformed ACL Entry'),
    ('774', 'Incorrect ACL Version'),
    ('781', 'No Such Session'),
    ('782', 'Invalid Session Sequence'),
    ('783', 'Session Key Does Not Exist'),
    ('791', 'Bad Public key'));

  { HTTP responses }
  HTTP_ResponseNo: array[THTTPResponseCodes] of integer = (
    200,
    400,
    404,
    412,
    415,
    500,
    503);

{$ifdef debugHTML}
  hcrlf = crlf;
{$else}
  hcrlf = '';
{$endif}

  html_indent = '&nbsp;&nbsp;';

  { 1x parameter: DEVICE }
  htmlWrapper =
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" ' +
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' + hcrlf +
    '<html xmlns="http://www.w3.org/1999/xhtml" lang="en">' + hcrlf +
    '<head>' + hcrlf +
    '<meta http-equiv="Content-Type" content="text/html; charset=windows-1252" />' + hcrlf +
    '<title>Web Client for UPnP Devices; Copyright (c) 2005, Andrew Fiddian-Green</title>' + hcrlf +
    '<style>' + hcrlf +
    '<!--' + crlf +
    'h1 { font-family: Arial Black; color: #1871B5; font-size: 14pt; font-weight: normal; line-height: 100%% }' + crlf +
    'h2 { font-family: Arial Black; color: #FFFFFF; font-size: 12pt; font-weight: normal; line-height: 100%%;' +
    ' margin-left: 0; margin-top: 0; margin-bottom: 0; text-indent: 2 }' + crlf +
    'h3 { font-family: Arial Black; color: #029A9A; font-size: 14pt; font-weight: bold; margin-left: 6 }' + crlf +
    'table { font-family: Arial; font-size: 12pt }' + crlf +
    '-->' + hcrlf +
    '</style>' + hcrlf +
    '</head>' + hcrlf +
    '<body>' + hcrlf +
    '<script language="VBScript">' + crlf +
    'sub SetInnerText(anID, aValue, aIsXml)' + crlf +
    'if IsNull(aValue) then' + crlf +
    'ss = " "' + crlf +
    'else' + crlf +
    'ss = CStr(aValue)' + crlf +
    'if Len(ss) = 0 then ss = " "' + crlf +
    'end if' + crlf +
    'if aIsXml then' + crlf +
    'ss = replace(unescape(ss), "><", ">" + vbNewLine + "<")' + crlf +
    'end if' + crlf +
    'anID.innertext = ss' + crlf +
    'end sub'+ crlf +
    '</script>' + hcrlf +
    '<table border="0" width="100%%" cellspacing="0" cellpadding="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td width="140"><h3>SIEMENS</h3></td>' + hcrlf +
    '<td>' + hcrlf +
    '<table border="0" width="100%%" cellspacing="0" valign="top" cellpadding="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td><h1>Web Client for UPnP Devices</h1></td>' + hcrlf +
    '<td align="right"><font size="2">Created by Andrew Fiddian-Green<br />Copyright (c) 2005</font></td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '<tr>' + hcrlf +
    '<td width="140" valign="top"></td>' + hcrlf +
    '<td valign="top"><hr size="5" color="#1871B5" /></td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '%s' +
    '</body>' + hcrlf +
    '</html>' + hcrlf;

  { 14x parameters:
      DEVICE ID 4x, DDD URL, DEVICE ID 6x, DEVICE TYPE, DEVICE PROPERTIES, DEVICE ID
  }
  deviceWrapper =
    '<!-- Start: "%s" -->' + hcrlf +
    '<script language="VBScript">' + crlf +
    'dim %s_DDD' + crlf +
    'set %s_DDD = CreateObject("UPnP.DescriptionDocument")' + crlf +
    '%s_DDD.Load("%s")' + crlf +
    'dim %s_Device' + crlf +
    'set %s_Device = %s_DDD.RootDevice' + crlf +
    'dim %s_ServiceList' + crlf +
    'set %s_ServiceList = %s_Device.Services' + crlf +
    '</script>' + hcrlf +
    '<table border="0" width="100%%">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td>&nbsp;</td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '<table border="0" width="100%%" cellspacing="0" cellpadding="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td width="140" valign="top"></td>' + hcrlf +
    '<td>' + hcrlf +
    '<h1>Device: %s</h1>' + hcrlf +
    '<table border="1" width="100%%" cellspacing="0" bordercolor="#1871B5" cellpadding="2">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td bgcolor="#1871B5" width="250"><h2>Property name</h2></td>' + hcrlf +
    '<td bgcolor="#1871B5"><table border="0" width="100%%" cellpadding="0" cellspacing="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td><h2>Value</h2></td>' + hcrlf +
    '<td align="right" height="26">&nbsp;</td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '%s' +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '<!-- End: "%s" -->' + hcrlf;

  { 16x parameters:
      SERVICE ID, SERVICE TYPE, SERVICE ID, SERVICE PROPERTY HTML, SERVICE ID,
      SERVICE EVENT CODE, SERVICE ID 2x, DEVICE ID, SERVICE ID, SERVICE QSV CODE,
      SERVICE ID, SERVICE ID, SERVICE ID, SERVICE QSV CODE, SERVICE ID
  }
  serviceWrapper =
    '<!-- Start: "%s" -->' + hcrlf +
    '<table border="0" width="100%%"><tbody><tr><td>&nbsp;</td></tr></tbody></table>' + hcrlf +
    '<table border="0" width="100%%" cellspacing="0" cellpadding="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td width="140" valign="top"></td>' + hcrlf +
    '<td>' + hcrlf +
    '<h1>Service: %s</h1>' + hcrlf +
    '<table border="1" width="100%%" cellspacing="0" bordercolor="#1871B5" cellpadding="2">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td bgcolor="#1871B5" width="250"><h2>Property name</h2></td>' + hcrlf +
    '<td bgcolor="#1871B5">' + hcrlf +
    '<table border="0" width="100%%" cellpadding="0" cellspacing="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td><h2>Value</h2></td>' + hcrlf +
    '<td align="right"><input type="button" value="QueryStateVariables" name="%s_ExecuteQSV" /></td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '%s' +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '<script language="VBScript">' + crlf +
    'sub %s_EventHandler(callbackType, svcObj, varName, varValue)' + crlf +
    'if callbackType = "VARIABLE_UPDATE" then' + crlf +
    '%s' + 'end if' + crlf +
    'end sub' + crlf +
    'dim %s_Service' + crlf +
    'set %s_Service = %s_ServiceList("urn:upnp-org:serviceId:%s")' + crlf +
    '%s_Service.AddCallback GetRef("%s_EventHandler")' + crlf +
    '%s' +
    '</script>' + hcrlf +
    '<script language="VBScript" for="%s_ExecuteQSV" event="OnClick">' + crlf +
    'on error resume next' + crlf +
    '%s' +
    '</script>' + hcrlf +
    '<!-- End: "%s" -->' + hcrlf;

  { 4x parameters:
      STATE VARIABLE NAME, EVENTED, SERVICE ID, STATE VARIABLE NAME
  }
  serviceTemplate =
    '<tr><td valign="top" width="250">%s%s</td><td valign="top" ID="%s_%s">??</td></tr>' + hcrlf;

  eventedStr: array[boolean] of string = ('', '  [+]');

  { 4x parameters:
      STATE VARIABLE NAME, SERVICE ID, STATE VARIABLE NAME, IS XML
  }
  eventCodeTemplate =
    'if varName = "%s" then SetInnerText %s_%s, varValue, %s' + crlf;

  { 5x parameters:
      SERVICE ID, STATE VARIABLE NAME, SERVICE ID, STATE VARIABLE NAME, IS XML
  }
  qsvCodeTemplate =
    'SetInnerText %s_%s, %s_Service.QueryStateVariable("%s"), %s' + crlf;

  { 5x parameters:
      ACTION NAME, ACTION NAME, SERVICE ID, ACTION NAME, Args, VBScript Code
  }
  actionTemplate =
    '<tr>' + hcrlf +
    '<td valign="top" width="250">%s</td>' + hcrlf +
    '<td valign="top">' + hcrlf +
    '<table border="0" width="100%%" cellspacing="0" cellpadding="1">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td width="250" bgcolor="#CCCCCC">Argument name</td>' + hcrlf +
    '<td bgcolor="#CCCCCC">' + hcrlf +
    '<table border="0" width="100%%" cellpadding="0" cellspacing="0">' + hcrlf +
    '<tbody>' + hcrlf +
    '<tr>' + hcrlf +
    '<td>Value</td>' + hcrlf +
    '<td align="right"><input type="button" value="%s" name="%s_%s_Execute" /></td>' + hcrlf +
    '</tr>' + hcrlf +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf +
    '%s' +
    '%s' +
    '</tbody>' + hcrlf +
    '</table>' + hcrlf +
    '</td>' + hcrlf +
    '</tr>' + hcrlf;

  inArgIDTemplate =
    'ID="%s_%s_%s"';

  { 3x parameters:
      ARG NAME, InARG ID, ARG HTML
  }
  argRowTemplate =
    '<tr>' + hcrlf +
    '<td width="250" valign="top">%s</td>' + hcrlf +
    '<td %s valign="top">%s</td>' + hcrlf +
    '</tr>' + hcrlf;

  { 4x parameters:
      SERVICE ID, ACTION NAME, ARG NAME, ARG VALUE
  }
  inArgTemplatePlain =
    '<input type="text" name="%s_%s_%s" size="30" value="%s">' + hcrlf;

  { 4x parameters:
      SERVICE ID, ACTION NAME, ARG NAME, Options List
  }
  inArgTemplateSelect =
    '<select size="1" name="%s_%s_%s">%s</select>' + hcrlf;

  optionSelected: array[boolean] of string = ('', ' selected');

  { 3x parameters:
     optionSelected[IsSelected], optionValue, optionDisplayValue
  }
  optionsTemplate =
    '<option%s value="%s">%s</option>' + hcrlf;

  { 7x parameters:
     SERVICE ID, ACTION NAME, QTY InArgs, QTY OutArgs,
     InArgs Code, Invoke Code, OutArgs Code,
  }
  actionCodeTemplate =
    '<script language="VBScript" for="%s_%s_Execute" event="OnClick">' + crlf +
    'on error resume next' + crlf +
    'dim inargs(%d)' + crlf +
    'dim outargs(%d)' + crlf +
    '%s' +
    '%s' +
    '%s' +
    '</script>' + hcrlf;

  { 2x parameters:
      SERVICE ID, ACTION NAME
  }
  invokeCodeTemplatePlain =
    '%s_Service.InvokeAction "%s", inargs, outargs' + crlf;

  { 2x parameters:
      SERVICE ID, ACTION NAME
  }
  invokeCodeTemplateRetVal =
    'vvv = %s_Service.InvokeAction("%s", inargs, outargs)' + crlf;

  { 4x parameters:
     ARG No, SERVICE ID, ACTION NAME, ARG NAME
  }
  inArgCodeTemplatePlain =
    'inargs(%d) = %s_%s_%s.Value' + crlf;

  { 4x parameters:
     ARG No, SERVICE ID, ACTION NAME, ARG NAME
  }
  inArgCodeTemplateBoolean =
    'inargs(%d) = CBool(%s_%s_%s.Value)' + crlf;

  { 4x parameters:
     SERVICE ID, ACTION NAME, ARG NAME, IS XML
  }
  retvalArgCodeTemplate =
    'SetInnerText %s_%s_%s, vvv, %s' + crlf;

  { 5x parameters:
     SERVICE ID, ACTION NAME, ARG NAME, Arg No, IS XML
  }
  outArgCodeTemplate =
    'SetInnerText %s_%s_%s, outargs(%d), %s' + crlf;

  { 2x parameters:
      PROPERTY NAME, PROPERTY VALUE
  }
  propertyTemplate =
    '<tr><td width="250">%s</td><td>%s</td></tr>' + hcrlf;

  { 3x parameters:
      PROPERTY NAME, URL PROPERTY 2x
  }
  linkTemplate =
    '<tr><td width="250">%s</td><td><a href="%s" target="_blank">%s</a></td></tr>' + hcrlf;

  { Enumerated mime type string constants for icons }
  MimeTypeStr: array[TUPnP_MimeType] of string = (
    'application/octet-stream',
    'image/bmp',
    'image/jpeg',
    'image/gif',
    'image/png',
    'text/xml',
    'text/html',
    'text/plain',
    'text/css');

  { Enumerated file extensions for mime types }
  MimeTypeExtension: array[TUPnP_MimeType] of string = (
    '',
    '.bmp',
    '.jpg',
    '.gif',
    '.png',
    '.xml',
    '.htm',
    '.txt',
    '.css');

  dotHTML = '.html';

  { VariableTypeStr: the display strings of UPnP_VariableType... }
  VariableTypeStr: array[TUPnP_VariableType] of string = (
    'ui1',
    'ui2',
    'ui4',
    'i1',
    'i2',
    'i4',
    'int',
    'r4',
    'r8',
    'number',
    'fixed_14_4',
    'float',
    'char',
    'string',
    'date',
    'dateTime',
    'dateTime.tz',
    'time',
    'time.tz',
    'boolean',
    'bin.base64',
    'bin.hex',
    'uri',
    'uuid');

  { UPnP_ArgumentTypeStr: the display strings of UPnP_ArgumentType... }
  ArgumentTypeStr: array[TUPnP_ArgumentType] of string = (
    'in',
    'out',
    'out');

  _FilePath = 'Andrew Fiddian-Green\' + UPnP_Library_Name + '\';

implementation

end.

