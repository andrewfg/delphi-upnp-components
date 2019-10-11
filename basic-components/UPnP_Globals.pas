{
  UPnP_Globals:
  Global variables for UPnP Device and Service objects.
  Copyright (c) 2001..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_Globals.pas,v 1.4 2005/07/22 01:08:26 FiddianA Exp $

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
      - Release v1.5.3
}

unit UPnP_Globals;

interface

type
  {
    Defines the enumerated mime type for icons
  }
  TUPnP_MimeType = (UNKNOWN, BMP, JPG, GIF, PNG, XML, HTML, TXT, CSS);

var
  dateFormat: string;

implementation

uses
  SysUtils,
  Windows;

var
  bias: integer;
  tzi:  TTimeZoneInformation;
  sign: char;

initialization

  // get the time zone offset (bias)
  case GetTimeZoneInformation(tzi) of
    TIME_ZONE_ID_UNKNOWN:
    begin
      Bias := tzi.Bias;
    end;
    TIME_ZONE_ID_DAYLIGHT:
    begin
      Bias := tzi.DaylightBias;
    end;
    TIME_ZONE_ID_STANDARD:
    begin
      Bias := tzi.StandardBias;
    end;
    else
    begin
      Bias := 0;
    end;
  end;

  // sort out the sign
  if Bias > 0 then
  begin
    sign := '-';
  end
  else
  begin
    sign := '+';
  end;
  Bias := abs(Bias);

  // set up the date format string
  dateFormat := Format('ddd, d mmm yyyy hh:nn:ss %s%.2u%.2u',
    [sign, Bias div 60, Bias mod 60]);
end.

