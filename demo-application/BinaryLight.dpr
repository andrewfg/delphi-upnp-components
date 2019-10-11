{
  BinaryLight:
  Test program for UPnP components
  Copyright (c) 2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/BinaryLight.dpr,v 1.7 2005/10/02 14:01:31 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch
}

program BinaryLight;

uses
  Forms,
  BinaryLightUnit in 'BinaryLightUnit.pas' {BinaryLightForm},
  UPnP_GraphicsExtensions in 'UPnP_GraphicsExtensions.pas',
  UPnP_Components in 'UPnP_Components.pas',
  UPnP_DeviceSecurity in 'UPnP_DeviceSecurity.pas',
  UPnP_IndyExtensions in 'UPnP_IndyExtensions.pas',
  UPnP_XmlStreamer in 'UPnP_XmlStreamer.pas',
  UPnP_Globals in 'UPnP_Globals.pas',
  UPnP_Strings in 'UPnP_Strings.pas',
  UPnP_TreeView in 'UPnP_TreeView.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'Binary Light';
  Application.CreateForm(TBinaryLightForm, BinaryLightForm);
  Application.Run;
end.
