{
  UPnP_GraphicsExtensions:
  Interfaces between UPnP objects (Icons) and graphics descendents.
  Copyright (c) 2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_GraphicsExtensions.pas,v 1.2 2005/07/22 01:08:26 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Status:

  Revision History:
    July 2005
      - Created
    July 22, 2005
      - Release v1.5.3
}

unit UPnP_GraphicsExtensions;

interface

uses
  GIFImage,
  Graphics,
  JPEG,
  PngImage,
  UPnP_Globals;

type
  TUPnP_GraphicsExtensions = class
    class function GetImageDepth(aGraphic: TGraphic): integer;
    class function GetImageMimeType(aGraphic: TGraphic): TUPnP_MimeType;
  end;

implementation

class function TUPnP_GraphicsExtensions.GetImageDepth(aGraphic: TGraphic): integer;
{
  Get the image bit depth
  Status:
}
begin
  if aGraphic is TBitmap then
  begin
    case TBitmap(aGraphic).PixelFormat of
      pf1bit:
      begin
        Result := 1;
      end;
      pf4bit:
      begin
        Result := 4;
      end;
      pf8bit:
      begin
        Result := 8;
      end;
      pf15bit:
      begin
        Result := 15;
      end;
      pf16bit:
      begin
        Result := 16;
      end;
      pf24bit:
      begin
        Result := 24;
      end;
      pf32bit:
      begin
        Result := 32;
      end;
      else
      begin
        Result := 0;
      end;
    end;
  end
  else
  if aGraphic is TJPEGImage then
  begin
    case TJPEGImage(aGraphic).PixelFormat of
      jf8Bit:
      begin
        Result := 8;
      end;
      jf24Bit:
      begin
        Result := 24;
      end;
      else
      begin
        Result := 0;
      end;
    end;
  end
  else
  if aGraphic is TGIFImage then
  begin
    Result := TGIFImage(aGraphic).BitsPerPixel;
  end
  else
  if aGraphic is TPngObject then
  begin
    Result := TPngObject(aGraphic).Header.BitDepth;
  end
  else

  begin
    Result := 0;
  end;
end;

class function TUPnP_GraphicsExtensions.GetImageMimeType(aGraphic: TGraphic)
: TUPnP_MimeType;
{
  Get the image Mime type
  Status:
}
begin
  if aGraphic is TBitmap then
  begin
    Result := BMP;
  end
  else
  if aGraphic is TJPEGImage then
  begin
    Result := JPG;
  end
  else
  if aGraphic is TGIFImage then
  begin
    Result := GIF;
  end
  else
  if aGraphic is TPngObject then
  begin
    Result := PNG;
  end
  else

  begin
    Result := UNKNOWN;
  end;
end;

end.

