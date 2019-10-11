{
  UPnP_TreeView:
  Tree Viewer for UPnP Device and Service objects.
  Copyright (c) 2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_TreeView.pas,v 1.5 2005/08/20 12:21:25 FiddianA Exp $

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

unit UPnP_TreeView;

interface

uses
  Classes,
  ComCtrls,
  Controls,
  UpnP_Components;

type
  TUPnP_TreeView = class(TCustomTreeView)
  protected
    fRootDevice: TUPnP_RootDevice;
    fOldOnStateChange: TNotifyEvent;
    procedure DoExpanding(Sender: TObject; Node: TTreeNode; var AllowExpansion: boolean);
    function CreateFolder(aNode: TTreeNode; aTitle: string): TTreeNode;
    function CreateTopNode(aNode: TTreeNode; aTitle: string; aImage: integer;
      aComponent: TUPnP_Component): TTreeNode;
    procedure CreateActionTree(aNode: TTreeNode; action: TUPnP_Action);
    procedure CreateArgumentTree(aNode: TTreeNode; argument: TUPnP_Argument);
    procedure CreateServiceTree(aNode: TTreeNode; service: TUPnP_CustomService);
    procedure CreateDeviceTree(aNode: TTreeNode; device: TUPnP_CustomDevice);
    procedure CreateVariableTree(aNode: TTreeNode; variable: TUPnP_StateVariable);
    procedure SetRootDevice(aRootDevice: TUPnP_RootDevice);
    procedure ProcessDoubleClick(Sender: TObject);
    procedure OnStateChange(Sender: TObject);
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Refresh;
    procedure EditSelection;
    property RootDevice: TUPnP_RootDevice Read fRootDevice Write SetRootDevice;
    procedure ConvertToStrings(strs: TStringList);
  published
    { inherited properties }
    property Align;
    property Anchors;
    property AutoExpand;
    property BevelEdges;
    property BevelInner;
    property BevelOuter;
    property BevelKind default bkNone;
    property BevelWidth;
    property BiDiMode;
    property BorderStyle;
    property BorderWidth;
    property ChangeDelay;
    property Color;
    property Ctl3D;
    property Constraints;
    property DragKind;
    property DragCursor;
    property DragMode;
    property Enabled;
    property Font;
    property HideSelection;
    property HotTrack;
    //    property Images;
    property Indent;
    property MultiSelect;
    property MultiSelectStyle;
    property ParentBiDiMode;
    property ParentColor default False;
    property ParentCtl3D;
    property ParentFont;
    property ParentShowHint;
    property PopupMenu;
    //    property ReadOnly;
    property RightClickSelect;
    property RowSelect;
    property ShowButtons;
    property ShowHint;
    property ShowLines;
    property ShowRoot;
    property SortType;
    //    property StateImages;
    property TabOrder;
    property TabStop default True;
    property ToolTips;
    property Visible;
(*
    property OnAddition;
    property OnAdvancedCustomDraw;
    property OnAdvancedCustomDrawItem;
    property OnChange;
    property OnChanging;
    property OnClick;
    property OnCollapsed;
    property OnCollapsing;
    property OnCompare;
    property OnContextPopup;
    property OnCreateNodeClass;
    property OnCustomDraw;
    property OnCustomDrawItem;
    property OnDblClick;
    property OnDeletion;
    property OnDragDrop;
    property OnDragOver;
    property OnEdited;
    property OnEditing;
    property OnEndDock;
    property OnEndDrag;
    property OnEnter;
    property OnExit;
    property OnExpanding;
    property OnExpanded;
    property OnGetImageIndex;
    property OnGetSelectedIndex;
    property OnKeyDown;
    property OnKeyPress;
    property OnKeyUp;
    property OnMouseDown;
    property OnMouseMove;
    property OnMouseUp;
    property OnStartDock;
    property OnStartDrag;
    { Items must be published after OnGetImageIndex and OnGetSelectedIndex }
    property Items;
*)
  end;

procedure Register;

implementation

{$R UPnP_TreeView.res}

uses
  Dialogs,
  Graphics,
  ImgList,
  SysUtils,
  UPnP_Strings;

procedure Register;
{
  Register all components with Delphi
  Status:
}
begin
  RegisterComponents(_UPnP, [TUPnP_TreeView]);
end;

const
  // image indexes
  var_img = 0;
  arg_img = 1;
  dvc_img = 2;
  icn_img = 3;
  roo_img = 4;
  svc_img = 5;
  act_img = 6;
  cls_img = 7;
  opn_img = 8;
  dot_img = 12;
  rdo_img = 13;
  wrt_img = 14;
  per_img = 15;
  sec_img = 16;

  // format string
  fmt_str = '%s:  %s';

function TUPnP_TreeView.CreateFolder(aNode: TTreeNode; aTitle: string): TTreeNode;
{
  Create a 'Folder' tree in the list view
  Status:
}
begin
  Result := Items.AddChild(aNode, aTitle);
  with Result do
  begin
    ImageIndex    := cls_img;
    SelectedIndex := ImageIndex;
  end;
end;

function TUPnP_TreeView.CreateTopNode(aNode: TTreeNode; aTitle: string;
  aImage: integer; aComponent: TUPnP_Component): TTreeNode;
{
  Create the top node for a UPnP object and add its own properties
  Status:
}
var
  i:    integer;
  node: TTreeNode;
begin
  // create the node
  Result := Items.AddChildObject(aNode, aTitle, aComponent);

  // set the image
  with Result do
  begin
    ImageIndex    := aImage;
    SelectedIndex := ImageIndex;
  end;

  // create the property sub- nodes
  for i := 1 to pred(aComponent.PropertyCount) do
  begin
    // add the node
    node := Items.AddChildObject(Result, Format(fmt_str,
      [aComponent.PropertyName[i], aComponent.PropertyValue[i]]), Pointer(i));

    // set the image indexes
    if aComponent.IsPropertyEditable[i] then
    begin
      node.ImageIndex := wrt_img;
    end
    else
    begin
      node.ImageIndex := rdo_img;
    end;
    node.SelectedIndex := node.ImageIndex;
  end;
end;

procedure TUPnP_TreeView.CreateArgumentTree(aNode: TTreeNode; argument: TUPnP_Argument);
{
  Create a tree in the list view for UPnP Argument objects
  Status:
}
var
  root: TTreeNode;
  node: TTreeNode;
begin
  // add the top node
  root := CreateTopNode(aNode, argument.ArgumentName, arg_img, argument);

  // add and fill the RSV folder
  if argument.RelatedStateVariable <> nil then
  begin
    node := CreateFolder(root, 'Related State Variable');
    CreateTopNode(node, argument.RelatedStateVariable.StateVariableName,
      var_img, argument.RelatedStateVariable);
  end;
end;

procedure TUPnP_TreeView.CreateActionTree(aNode: TTreeNode; action: TUPnP_Action);
{
  Create a tree in the list view for UPnP Action objects
  Status:
}
var
  root: TTreeNode;
  node: TTreeNode;
  i:    integer;
begin
  // add the top node
  root := CreateTopNode(aNode, action.ActionName, act_img, action);

  // add and fill the arguments folder
  if action.Arguments.Count > 0 then
  begin
    node := CreateFolder(root, 'Arguments');
    for i := 0 to pred(action.Arguments.Count) do
    begin
      CreateArgumentTree(node, action.Arguments[i]);
    end;
  end;

  // add and fill the permissions folder
  if action.SecurityPermissions.Count > 0 then
  begin
    node := CreateFolder(root, 'Security Permissions');
    for i := 0 to pred(action.SecurityPermissions.Count) do
    begin
      CreateTopNode(node, action.SecurityPermissions[i].UIName, per_img,
        action.SecurityPermissions[i]);
    end;
  end;
end;

procedure TUPnP_TreeView.CreateServiceTree(aNode: TTreeNode;
  service: TUPnP_CustomService);
{
  Create a tree in the list view for UPnP Service objects
  Status:
}
var
  root: TTreeNode;
  node: TTreeNode;
  i:    integer;
begin
  // select either the generic or the Device Security image
  if service is TUPnP_DeviceSecurityBase then
  begin
    i := sec_img;
  end
  else
  begin
    i := svc_img;
  end;

  // create the top node
  root := CreateTopNode(aNode, service.ServiceID, i, service);

  // add and fill the actions folder
  if service.Actions.Count > 0 then
  begin
    node := CreateFolder(root, 'Actions');
    for i := 0 to pred(service.Actions.Count) do
    begin
      CreateActionTree(node, service.Actions[i]);
    end;
  end;

  // add and fill the state variables folder
  if service.StateVariables.Count > 0 then
  begin
    node := CreateFolder(root, 'State Variables');
    for i := 0 to pred(service.StateVariables.Count) do
    begin
      CreateVariableTree(node, service.StateVariables[i]);
    end;
  end;
end;

procedure TUPnP_TreeView.CreateVariableTree(aNode: TTreeNode;
  variable: TUPnP_StateVariable);
{
  Create a tree in the list view for UPnP State Variable objects
  Status:
}
var
  root: TTreeNode;
  node: TTreeNode;
  i:    integer;
begin
  // add the top node
  root := CreateTopNode(aNode, variable.StateVariableName, var_img, variable);

  // add and fill the permissions folder
  if variable.SecurityPermissions.Count > 0 then
  begin
    node := CreateFolder(root, 'Security Permissions');
    for i := 0 to pred(variable.SecurityPermissions.Count) do
    begin
      CreateTopNode(node, variable.SecurityPermissions[i].UIName,
        per_img, variable.SecurityPermissions[i]);
    end;
  end;
end;

procedure TUPnP_TreeView.CreateDeviceTree(aNode: TTreeNode; device: TUPnP_CustomDevice);
{
  Create a tree in the list view for UPnP Device objects
  Status:
}
var
  root: TTreeNode;
  node: TTreeNode;
  i:    integer;
begin
  // select either the root device or generic device image
  if device is TUPnP_RootDevice then
  begin
    i := roo_img;
  end
  else
  begin
    i := dvc_img;
  end;

  // add the top node
  root := CreateTopNode(aNode, device.DeviceType, i, device);

  // add and fill the icons  folder
  if device.Icons.Count > 0 then
  begin
    node := CreateFolder(root, 'Icons');
    for i := 0 to pred(device.Icons.Count) do
    begin
      CreateTopNode(node, device.Icons[i].IconName, icn_img, device.Icons[i]);
    end;
  end;

  // add and fill the services folder
  if device.Services.Count > 0 then
  begin
    node := CreateFolder(root, 'Services');
    for i := 0 to pred(device.Services.Count) do
    begin
      CreateServiceTree(node, device.Services[i]);
    end;
  end;

  // add and fill the devices folder
  if device.Devices.Count > 0 then
  begin
    node := CreateFolder(root, 'Devices');
    for i := 0 to pred(device.Devices.Count) do
    begin
      CreateDeviceTree(node, device.Devices[i]);
    end;
  end;
end;

constructor TUPnP_TreeView.Create(AOwner: TComponent);
{
  Constructor
  Status:
}
begin
  inherited;
  Images := TImageList.Create(self);
  Images.ResourceLoad(rtBitmap, 'UPNP_TREEVIEW', clOlive);
  OnExpanding := DoExpanding;
  OnDblClick  := ProcessDoubleClick;
  AutoExpand  := True;
end;

destructor TUPnP_TreeView.Destroy;
{
  Destructor
  Status:
}
begin
  Images.Free;
  inherited;
end;

procedure TUPnP_TreeView.OnStateChange(Sender: TObject);
{
  Respond to state changes
  Status:
}
var
  i, j: integer;
  cpt:  TUPnP_Component;
begin
  // update ourself
  for i := 0 to pred(Items.Count) do
  begin
    // check all items to see if the sender UPnP object is in our list
    if (Items[i].Data = Sender) and (Sender is TUPnP_Component) then
    begin
      cpt := TUPnP_Component(Sender);
      // update all the property sub- nodes
      for j := 1 to pred(cpt.PropertyCount) do
      begin
        // update the node
        Items[i + j].Text := Format(fmt_str, [cpt.PropertyName[j], cpt.PropertyValue[j]]);
      end;
    end;
  end;

  // call the inherited event handler
  if assigned(fOldOnStateChange) then
  begin
    fOldOnStateChange(Sender);
  end;
end;

procedure TUPnP_TreeView.ProcessDoubleClick(Sender: TObject);
{
  Process double clicks
  Status:
}
begin
  EditSelection;
end;

procedure TUPnP_TreeView.EditSelection;
{
  If possible, edit the respective property
  Status:
}
var
  i:   integer;
  ok:  boolean;
  cpt: TUPnP_Component;
begin
  ok  := False;
  i   := 0;
  cpt := nil;

  // no data => not for us
  if Selected <> nil then
  begin

    // no data => not for us
    if Selected.Data <> nil then
    begin

      // if 0 < Data < 32 then probably Data is a Property index...
      if cardinal(Selected.Data) < 32 then
      begin

        // get the index
        i := cardinal(Selected.Data);

        // Parent's Data points should point to a valid UPnP component
        if Selected.Parent <> nil then
        begin
          cpt := Selected.Parent.Data;
          ok  := (cpt is TUPnP_Component);
        end;
      end

      // otherwise own Data should point to a valid UPnP component
      else
      begin
        cpt := Selected.Data;
        ok  := (cpt is TUPnP_Component);
      end;

      if ok then
      begin
        // is property editable?
        ok := cpt.IsPropertyEditable[i];
      end;
    end;
  end;

  if ok then
  begin
    with cpt do
    begin
      // then edit it
      PropertyValue[i] := InputBox('Edit Property',
        Format('Enter the new value for the "%s" property:', [PropertyName[i]]),
        PropertyValue[i]);
    end;
  end

  else
  begin
    Beep;
    MessageDlg('This property cannot be edited', mtWarning, [mbOK], 0);
  end;
end;

procedure TUPnP_TreeView.ConvertToStrings(strs: TStringList);
var
  node: TTreeNode;
begin
  node := Items.GetFirstnode;
  while node <> nil do
  begin
    strs.Add(StringOfChar(' ', 6 * node.Level) + node.Text);
    node := node.GetNext;
  end;
end;

procedure TUPnP_TreeView.Notification(AComponent: TComponent; Operation: TOperation);
{
  Unhook the root device
  Status:
}
begin
  if (Operation = opRemove) and (aComponent = fRootDevice) then
  begin
    RootDevice := nil;
  end;
  inherited;
end;

procedure TUPnP_TreeView.SetRootDevice(aRootDevice: TUPnP_RootDevice);
{
  Property setter
  Status:
}
begin
  if fRootDevice <> aRootDevice then
  begin
    if fRootDevice <> nil then
    begin
      fRootDevice.OnStateChange := fOldOnStateChange;
    end;
    fRootDevice := aRootDevice;
    fOldOnStateChange := nil;
    if fRootDevice <> nil then
    begin
      fOldOnStateChange := fRootDevice.OnStateChange;
      fRootDevice.OnStateChange := OnStateChange;
      fRootDevice.FreeNotification(self);
    end;
    Refresh;
  end;
end;

procedure TUPnP_TreeView.Refresh;
{
  Clear and refill (refresh) the Tree View nodes
  Status:
}
begin
  if (not (csLoading in ComponentState)) and (not (csDesigning in ComponentState)) then
  begin
    Items.Clear;
    CreateDeviceTree(nil, fRootDevice);
    Items[0].Expand(False);
  end;
end;

procedure TUPnP_TreeView.DoExpanding(Sender: TObject; Node: TTreeNode;
  var AllowExpansion: boolean);
{
  Change the foler icons from "closed" to "open" images
  Status:
}
begin
  with Node do
  begin
    case ImageIndex of
      opn_img:
      begin
        ImageIndex := cls_img;
      end;
      cls_img:
      begin
        ImageIndex := opn_img;
      end;
    end;
    SelectedIndex := ImageIndex;
  end;
  AllowExpansion := True;
end;

end.

