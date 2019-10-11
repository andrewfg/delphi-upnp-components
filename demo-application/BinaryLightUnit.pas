{
  BinaryLightUnit:
  Test program unit for UPnP components
  Copyright (c) 2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/BinaryLightUnit.pas,v 1.12 2005/10/02 14:01:31 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch
}

unit BinaryLightUnit;

interface

uses
  ActnCtrls, ActnList, ActnMan,
  ActnMenus, Classes, ComCtrls, Controls, Dialogs, ExtCtrls, Forms,
  GIFImage, Graphics, ImgList, Menus, Messages, StdCtrls, StdStyleActnCtrls,
  SysUtils, ToolWin, UPnP_Components, UPnP_DeviceSecurity, UPnP_IndyExtensions,
  UPnP_TreeView, Variants, Windows, XPMan,
  XPStyleActnCtrls;

type
  TBinaryLightForm = class(TForm)
    BinaryLight: TUPnP_RootDevice;
    UPnP_Icon1: TUPnP_Icon;
    UPnP_StateVariable1: TUPnP_StateVariable;
    UPnP_Action1: TUPnP_Action;
    UPnP_Argument1: TUPnP_Argument;
    UPnP_SecurityPermission1: TUPnP_SecurityPermission;
    UPnP_DeviceSecurity1: TUPnP_DeviceSecurity;
    UPnP_Service1: TUPnP_Service;
    UPnP_Action2: TUPnP_Action;
    UPnP_Action3: TUPnP_Action;
    UPnP_Argument2: TUPnP_Argument;
    UPnP_Argument3: TUPnP_Argument;
    UPnP_StateVariable2: TUPnP_StateVariable;
    XPManifest1: TXPManifest;
    FindDialog1: TFindDialog;
    PageControl1: TPageControl;
    CommsLog: TTabSheet;
    ObjectTree: TTabSheet;
    UPnP_TreeView1: TUPnP_TreeView;
    ActionMainMenuBar1: TActionMainMenuBar;
    ActionManager1: TActionManager;
    ExitAction: TAction;
    ClearAction: TAction;
    ConnectedAction: TAction;
    LogIPMClientAction: TAction;
    AboutAction: TAction;
    PrintAction: TAction;
    FindAction: TAction;
    RefreshAction: TAction;
    LogIPMServerAction: TAction;
    LogUDPClientAction: TAction;
    LogHTTPServerAction: TAction;
    LogHTTPClientAction: TAction;
    ClearAllAction: TAction;
    ModifyAction: TAction;
    SaveAction: TAction;
    SaveDialog1: TSaveDialog;
    Memo1: TMemo;
    ResetAction: TAction;
    procedure ConnectCmd(Sender: TObject);
    procedure BinaryLightLogMessage(aLoggingType, aMessage: string);
    procedure ClearCmd(Sender: TObject);
    procedure PrintCmd(Sender: TObject);
    procedure LogIPMServerCmd(Sender: TObject);
    procedure LogIPMClientCmd(Sender: TObject);
    procedure LogUDPClientCmd(Sender: TObject);
    procedure LogHTTPServerCmd(Sender: TObject);
    procedure LogHTTPClientCmd(Sender: TObject);
    procedure FindCmd(Sender: TObject);
    procedure FindDialog1Find(Sender: TObject);
    procedure AboutCmd(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure ConnectedActionUpdate(Sender: TObject);
    procedure ClearActionUpdate(Sender: TObject);
    procedure FindActionUpdate(Sender: TObject);
    procedure RefreshActionExecute(Sender: TObject);
    procedure RefreshActionUpdate(Sender: TObject);
    procedure ExitCmd(Sender: TObject);
    procedure ClearAllActionExecute(Sender: TObject);
    procedure ModifyActionExecute(Sender: TObject);
    procedure ModifyActionUpdate(Sender: TObject);
    procedure SaveActionExecute(Sender: TObject);
    procedure ResetActionExecute(Sender: TObject);
  private
    { Private declarations }
    fSelPos: integer;
  public
    { Public declarations }
  end;

var
  BinaryLightForm: TBinaryLightForm;

implementation

{$R *.dfm}

uses
  Printers;

procedure PrintStrings(Strings: TStrings);
var
  Prn: TextFile;
  i:   word;
begin
  AssignPrn(Prn);
  try
    Rewrite(Prn);
    try
      for i := 0 to Strings.Count - 1 do
      begin
        writeln(Prn, Strings.Strings[i]);
      end;
    finally
      CloseFile(Prn);
    end;
  except
    on EInOutError do
      MessageDlg('Error Printing text.', mtError, [mbOK], 0);
  end;
end;

procedure TBinaryLightForm.ConnectCmd(Sender: TObject);
begin
  BinaryLight.Connected := not BinaryLight.Connected;
end;

procedure TBinaryLightForm.BinaryLightLogMessage(aLoggingType, aMessage: string);
begin
  Memo1.Lines.Add(Format('+++ %s +++', [aLoggingType]));
  Memo1.Lines.Add(aMessage);
end;

procedure TBinaryLightForm.ClearCmd(Sender: TObject);
begin
  Memo1.Lines.Clear;
end;

procedure TBinaryLightForm.PrintCmd(Sender: TObject);
var
  strs: TStringList;
begin
  if PageControl1.ActivePage = CommsLog then
  begin
    PrintStrings(Memo1.Lines);
  end;
  if PageControl1.ActivePage = ObjectTree then
  begin
    strs := TStringList.Create;
    try
      UPnP_TreeView1.ConvertToStrings(strs);
      PrintStrings(strs);
    finally
      strs.Free;
    end;
  end;
end;

procedure TBinaryLightForm.LogIPMServerCmd(Sender: TObject);
begin
  if LogIPMServerAction.Checked then
  begin
    BinaryLight.LoggingFlags :=
      BinaryLight.LoggingFlags + [fLogMultiCastServer];
  end
  else
  begin
    BinaryLight.LoggingFlags :=
      BinaryLight.LoggingFlags - [fLogMultiCastServer];
  end;
end;

procedure TBinaryLightForm.LogIPMClientCmd(Sender: TObject);
begin
  if LogIPMClientAction.Checked then
  begin
    BinaryLight.LoggingFlags :=
      BinaryLight.LoggingFlags + [fLogMultiCastClient];
  end
  else
  begin
    BinaryLight.LoggingFlags :=
      BinaryLight.LoggingFlags - [fLogMultiCastClient];
  end;
end;

procedure TBinaryLightForm.LogUDPClientCmd(Sender: TObject);
begin
  if LogUDPClientAction.Checked then
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags + [fLogUnicastClient];
  end
  else
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags - [fLogUnicastClient];
  end;
end;

procedure TBinaryLightForm.LogHTTPServerCmd(Sender: TObject);
begin
  if LogHTTPServerAction.Checked then
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags + [fLogTCPServer];
  end
  else
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags - [fLogTCPServer];
  end;
end;

procedure TBinaryLightForm.LogHTTPClientCmd(Sender: TObject);
begin
  if LogHTTPClientAction.Checked then
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags + [fLogTCPClient];
  end
  else
  begin
    BinaryLight.LoggingFlags := BinaryLight.LoggingFlags - [fLogTCPClient];
  end;
end;

procedure TBinaryLightForm.FindCmd(Sender: TObject);
begin
  fSelPos := 0;
  FindDialog1.Execute;
end;

procedure TBinaryLightForm.FindDialog1Find(Sender: TObject);
var
  S: string;
  startpos: integer;
begin
  with TFindDialog(Sender) do
  begin
    {If the stored position is 0 this cannot be a find next. }
    if FSelPos = 0 then
    begin
      Options := Options - [frFindNext];
    end;

    { Figure out where to start the search and get the corresponding text from the memo. }
    if frfindNext in Options then
    begin
      { This is a find next, start after the end of the last found word. }
      StartPos := FSelPos + Length(Findtext);
      S := Copy(Memo1.Lines.Text, StartPos, MaxInt);
    end
    else
    begin
      { This is a find first, start at the, well, start. }
      S := Memo1.Lines.Text;
      StartPos := 1;
    end;

    if (frMatchCase in Options) then
      { Perform a global case-sensitive search for FindText in S }
    begin
      FSelPos := Pos(FindText, S);
    end
    else
      { Perform a global case-insensitive search }
    begin
      FSelPos := Pos(UpperCase(FindText), UpperCase(S));
    end;

    if FSelPos > 0 then
    begin
      { Found something, correct position for the location of the start of search. }
      FSelPos := FSelPos + StartPos - 1;
      Memo1.SelStart := FSelPos - 1;
      Memo1.SelLength := Length(FindText);
      Memo1.Perform(EM_SCROLLCARET, 0, 0);
      Memo1.SetFocus;
    end
    else
    begin
      { No joy, show a message. }
      if frfindNext in Options then
      begin
        S := Concat('There are no further occurences of "', FindText,
          '" in Memo1.');
      end
      else
      begin
        S := Concat('Could not find "', FindText, '" in Memo1.');
      end;
      MessageDlg(S, mtError, [mbOK], 0);
    end;
  end;
end;

procedure TBinaryLightForm.AboutCmd(Sender: TObject);
begin
  TUPnP_Component.About;
end;

procedure TBinaryLightForm.FormCreate(Sender: TObject);
begin
  UPnP_TreeView1.RootDevice := BinaryLight;
end;

procedure TBinaryLightForm.ConnectedActionUpdate(Sender: TObject);
begin
  ConnectedAction.Checked := BinaryLight.Connected;
end;

procedure TBinaryLightForm.ClearActionUpdate(Sender: TObject);
begin
  ClearAction.Enabled := (PageControl1.ActivePage = CommsLog);
end;

procedure TBinaryLightForm.FindActionUpdate(Sender: TObject);
begin
  FindAction.Enabled := (PageControl1.ActivePage = CommsLog);
end;

procedure TBinaryLightForm.RefreshActionExecute(Sender: TObject);
begin
  UPnP_TreeView1.Refresh;
end;

procedure TBinaryLightForm.RefreshActionUpdate(Sender: TObject);
begin
  RefreshAction.Enabled := (PageControl1.ActivePage = ObjectTree);
end;

procedure TBinaryLightForm.ExitCmd(Sender: TObject);
begin
  Close;
end;

procedure TBinaryLightForm.ClearAllActionExecute(Sender: TObject);
begin
  BinaryLight.LoggingFlags := [];
  LogIPMClientAction.Checked    := False;
  LogIPMServerAction.Checked    := False;
  LogUDPClientAction.Checked    := False;
  LogHTTPServerAction.Checked   := False;
  LogHTTPClientAction.Checked   := False;
end;

procedure TBinaryLightForm.ModifyActionExecute(Sender: TObject);
begin
  UPnP_TreeView1.EditSelection;
end;

procedure TBinaryLightForm.ModifyActionUpdate(Sender: TObject);
begin
  ModifyAction.Enabled := (PageControl1.ActivePage = ObjectTree);
end;

procedure TBinaryLightForm.SaveActionExecute(Sender: TObject);
var
  strs: TStringList;
begin
  if SaveDialog1.Execute then
  begin
    if PageControl1.ActivePage = CommsLog then
    begin
      Memo1.Lines.SaveToFile(SaveDialog1.FileName);
    end;
    if PageControl1.ActivePage = ObjectTree then
    begin
      strs := TStringList.Create;
      try
        UPnP_TreeView1.ConvertToStrings(strs);
        strs.SaveToFile(SaveDialog1.FileName);
      finally
        strs.Free;
      end;
    end;
  end;
end;

procedure TBinaryLightForm.ResetActionExecute(Sender: TObject);
begin
  BinaryLight.Connected := false;
  BinaryLight.Reset;
end;

end.

