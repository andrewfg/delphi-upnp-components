object BinaryLightForm: TBinaryLightForm
  Left = 308
  Top = 115
  Width = 922
  Height = 728
  Caption = 'Binary Light Demo'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object PageControl1: TPageControl
    Left = 0
    Top = 24
    Width = 914
    Height = 670
    ActivePage = ObjectTree
    Align = alClient
    TabHeight = 24
    TabOrder = 0
    object ObjectTree: TTabSheet
      Caption = 'UPnP Object Tree'
      object UPnP_TreeView1: TUPnP_TreeView
        Left = 0
        Top = 0
        Width = 906
        Height = 636
        Align = alClient
        AutoExpand = True
        Indent = 19
        TabOrder = 0
      end
    end
    object CommsLog: TTabSheet
      Caption = 'Communications Log'
      object Memo1: TMemo
        Left = 0
        Top = 0
        Width = 1022
        Height = 636
        Align = alClient
        Font.Charset = ANSI_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Lucida Console'
        Font.Style = []
        ParentFont = False
        ScrollBars = ssVertical
        TabOrder = 0
      end
    end
  end
  object ActionMainMenuBar1: TActionMainMenuBar
    Left = 0
    Top = 0
    Width = 914
    Height = 24
    UseSystemFont = False
    ActionManager = ActionManager1
    Caption = 'ActionMainMenuBar1'
    ColorMap.HighlightColor = 15660791
    ColorMap.BtnSelectedColor = clBtnFace
    ColorMap.UnusedColor = 15660791
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = []
    Spacing = 0
  end
  object XPManifest1: TXPManifest
    Left = 28
    Top = 120
  end
  object BinaryLight: TUPnP_RootDevice
    DeviceSchema = 'schemas-upnp-org'
    DeviceType = 'BinaryLight'
    DeviceVersion = '1'
    Manufacturer = 'Me'
    ManufacturerURL = 'http://www.whitebear.ch'
    FriendlyName = 'My binary light'
    ModelDescription = 'Binary Light'
    ModelName = 'BinaryLight'
    ModelNumber = 'BL001'
    ModelURL = 'http://www.whitebear.ch'
    SerialNumber = '12345'
    UniqueDeviceNumber = 'EAA599EA-3657-46BA-BD27-BEFA9D5083A5'
    UniversalProductCode = '67890'
    Icons = <
      item
        Icon = UPnP_Icon1
      end>
    Devices = <>
    Services = <
      item
        Service = UPnP_Service1
      end
      item
        Service = UPnP_DeviceSecurity1
      end>
    AlwaysMakeNewUID = False
    MaxAge = 120
    MultiCastIPAddress = '239.255.255.250'
    OnLogMessage = BinaryLightLogMessage
    LoggingFlags = []
    Left = 66
    Top = 80
  end
  object UPnP_Icon1: TUPnP_Icon
    IconWidth = 103
    IconHeight = 60
    IconDepth = 4
    IconName = 'BinaryLight'
    Picture.Data = {
      0954474946496D61676547494638396167003C00B300007A7A7ACFEBCED9D9D9
      42424292D1909B9B9BE8F6E8282828B1DEB076C674BDBDBDEFEFEFF5FBF563BE
      61000000FFFFFF21F90400000000002C0000000067003C000004FFF0C949ABBD
      386BCD022244D28C64931088B1AD6CEBBE4F1796743D1201ACEFFC6420229BD0
      4660F48E48CB2F583A219E8168F439AB258CC9EC2E40682202AA96814B4368CF
      AC1F29F1C5F20C5D52184DA7901BB879361034D7EB64386E740623097F685C6C
      7A880123887B203990165D943D70299717859B303F01839E1487A32D93A617A8
      2C0503AEAE051BAFAF1500B3B70300050290B8B7000A0B140500B60F0313000E
      CBCB001BCCCC1503D0D4D0070A7FD5DA0E00BC12C0DC0EC9D4CE1AD5D2DBDA03
      C268E9DAE5C0CAE50FCAD0F318E714D3EED40774FCD59C095820A0E0387BCFA8
      A1B336E040BA7B49AAB972B8CD9B857ACC205AC837611F336C12FF047884D64E
      E1840214A121BB80B1594292FAA8813C086D6644931316A45CE68F25B997D162
      D6ACB0A05AAC070A8A290DD98A592E8B15384E50508D5DAD9FE6704A18E9C0E6
      56AC2DC515487734AAD609D5BC7EC39A41EA319916B8C223C74FAD5B09D5A0D2
      7499156647B86687D203D86FE3D90702EEAE45D837E85FC127F32EAE76A0D8CE
      6565F11EE6DAF3225B7C67B9CE1410D641E7D25D735E86285501576E18C26A0C
      ECF82BC3D7CCCA96CE8C94DA4AB4BE5DA5D3BB1776E3650B093BF83DD8DA85C2
      1494E7CE201B2872A184D751A81EF7AC7407BCAF326E1B9AF081F061C3BFF5AB
      19E000B5E2335A1787BD9FAB6EB10127BF0E5CDB0158C4F934DEFF05899507D9
      0A61C1C7156DFCE940954A1A3CC84C67B67DE44282172C18DD612E48C88C559E
      41585F6A2D60D81D7B0F28D64281D0A827C16AFB91C882893132481F0F973910
      E06E31C297DF818FD5962287175266D302A881B89E8525EA37A28D4714E55F2E
      B81937A28F023259E38628EA30D677A629B9E4325886A8E5935C0AB9C397CA1D
      20E6983222E864900D0ED9E50EAE1106C09B7096191F99197A47A40E0690F6DA
      7F05885201314AE1D742528D06C8E852DB353ADB0E04A47241079AAED080A2A3
      FCE047A71A3430AA295C2020CA2B6521799F5522B962D300DED09A8C760FB4E2
      A209A0FEB184AACF29A080450D2980D26F54E5191D48324E7394C243971AD2AB
      1632B031ED8D219148153B54E58A2D89CD3684986997C671451D328C006C5FE5
      748B1648126606EE4C038C65682E183862C82A47FC602EBF6D55909837034BB0
      6D65CBE245AF6BCA309C011378007CCA074C10C0C833711D50D07F5389E58055
      952189ED7B54F9832F0606406C020AA1643005083408A203B6122CB00FAEBDBD
      5896020E9DA70F36B09D8CF210868000F3108B90EA6B1C440B7142CB4A53B244
      D337E411B5A6633CA13514605CEDF5D760872DF6D864976DF6D97F4400003B}
    MimeType = GIF
    Left = 104
    Top = 80
  end
  object UPnP_StateVariable1: TUPnP_StateVariable
    StateVariableName = 'Target'
    DataType = boolean_
    Maximum = 100.000000000000000000
    Step = 1.000000000000000000
    RequiresAuthorisation = False
    RequiresPrivacy = False
    RequiresSigning = False
    SecurityPermissions = <>
    SendEvents = False
    DefaultValue = 'False'
    Value = 'False'
    Left = 180
    Top = 160
  end
  object UPnP_Action1: TUPnP_Action
    ActionName = 'GetTarget'
    RequiresAuthorisation = False
    RequiresPrivacy = False
    RequiresSigning = False
    Arguments = <
      item
        Argument = UPnP_Argument1
      end>
    SecurityPermissions = <>
    Left = 180
    Top = 80
  end
  object UPnP_Argument1: TUPnP_Argument
    ArgumentName = 'RetTargetValue'
    Direction = Output
    RelatedStateVariable = UPnP_StateVariable1
    DontUpdateRSV = False
    Left = 180
    Top = 120
  end
  object UPnP_SecurityPermission1: TUPnP_SecurityPermission
    UIName = 'UPnP_SecurityPermission1'
    ACLentryName = 'family'
    FullDescriptionURL = 'http://floofly.woofly.com'
    ShortDescription = 'Allows access to <family>'
    Left = 333
    Top = 80
  end
  object UPnP_DeviceSecurity1: TUPnP_DeviceSecurity
    SecureInformationActions = False
    SecureSetSessionKeys = False
    SecurityPermissions = <
      item
        SecurityPermission = UPnP_SecurityPermission1
      end>
    Secret = 'secret'
    Left = 294
    Top = 80
  end
  object UPnP_Service1: TUPnP_Service
    ServiceId = 'SwitchPower'
    ServiceIDSchema = 'upnp-org'
    ServiceType = 'SwitchPower'
    ServiceSchema = 'schemas-upnp-org'
    ServiceVersion = '1'
    Actions = <
      item
        Action = UPnP_Action1
      end
      item
        Action = UPnP_Action2
      end
      item
        Action = UPnP_Action3
      end>
    StateVariables = <
      item
        StateVariable = UPnP_StateVariable1
      end
      item
        StateVariable = UPnP_StateVariable2
      end>
    Left = 142
    Top = 80
  end
  object UPnP_Action2: TUPnP_Action
    ActionName = 'SetTarget'
    RequiresAuthorisation = False
    RequiresPrivacy = False
    RequiresSigning = False
    Arguments = <
      item
        Argument = UPnP_Argument2
      end>
    SecurityPermissions = <>
    Left = 218
    Top = 80
  end
  object UPnP_Action3: TUPnP_Action
    ActionName = 'GetStatus'
    RequiresAuthorisation = False
    RequiresPrivacy = False
    RequiresSigning = False
    Arguments = <
      item
        Argument = UPnP_Argument3
      end>
    SecurityPermissions = <>
    Left = 256
    Top = 80
  end
  object UPnP_Argument2: TUPnP_Argument
    ArgumentName = 'newTargetValue'
    Direction = Input
    RelatedStateVariable = UPnP_StateVariable1
    DontUpdateRSV = False
    Left = 218
    Top = 120
  end
  object UPnP_Argument3: TUPnP_Argument
    ArgumentName = 'ResultStatus'
    Direction = Output
    RelatedStateVariable = UPnP_StateVariable2
    DontUpdateRSV = False
    Left = 256
    Top = 120
  end
  object UPnP_StateVariable2: TUPnP_StateVariable
    StateVariableName = 'Status'
    DataType = boolean_
    Maximum = 100.000000000000000000
    Step = 1.000000000000000000
    RequiresAuthorisation = False
    RequiresPrivacy = False
    RequiresSigning = False
    SecurityPermissions = <>
    SendEvents = True
    DefaultValue = 'False'
    Value = 'False'
    Left = 256
    Top = 160
  end
  object FindDialog1: TFindDialog
    Options = [frDown, frHideWholeWord, frHideUpDown]
    OnFind = FindDialog1Find
    Left = 28
    Top = 160
  end
  object ActionManager1: TActionManager
    ActionBars = <
      item
        Items = <
          item
            Items = <
              item
                Action = ExitAction
                Caption = '&Exit'
                ShortCut = 32856
              end>
            Caption = '&File'
          end
          item
            Items = <
              item
                Action = ConnectedAction
                Caption = '&Connected'
              end
              item
                Action = ResetAction
              end>
            Caption = '&Device'
          end
          item
            Items = <
              item
                Action = ClearAction
                Caption = '&Clear'
              end
              item
                Action = PrintAction
                Caption = '&Print'
                ShortCut = 16464
              end
              item
                Action = FindAction
                Caption = '&Find...'
                ShortCut = 114
              end
              item
                Action = RefreshAction
                Caption = '&Refresh'
                ShortCut = 116
              end
              item
                Action = ModifyAction
                Caption = '&Modify...'
                ShortCut = 13
              end
              item
                Action = SaveAction
                Caption = '&Save to file...'
                ShortCut = 16467
              end>
            Caption = '&Edit'
          end
          item
            Items = <
              item
                Action = LogIPMClientAction
                Caption = '&IPM Client'
              end
              item
                Action = LogIPMServerAction
                Caption = 'I&PM Server'
              end
              item
                Action = LogUDPClientAction
                Caption = '&UDP Client'
              end
              item
                Action = LogHTTPServerAction
                Caption = '&HTTP Server'
              end
              item
                Action = LogHTTPClientAction
                Caption = 'H&TTP Client'
              end
              item
                Action = ClearAllAction
                Caption = '&Clear All'
              end>
            Caption = '&Logging'
          end
          item
            Items = <
              item
                Action = AboutAction
                Caption = '&About...'
              end>
            Caption = '&Help'
          end>
        ActionBar = ActionMainMenuBar1
      end>
    Left = 28
    Top = 80
    StyleName = 'XP Style'
    object ExitAction: TAction
      Category = 'File'
      Caption = 'Exit'
      ImageIndex = 43
      ShortCut = 32856
      OnExecute = ExitCmd
    end
    object ClearAction: TAction
      Category = 'Edit'
      Caption = 'Clear'
      OnExecute = ClearCmd
      OnUpdate = ClearActionUpdate
    end
    object ConnectedAction: TAction
      Category = 'Device'
      AutoCheck = True
      Caption = 'Connected'
      OnExecute = ConnectCmd
      OnUpdate = ConnectedActionUpdate
    end
    object LogIPMClientAction: TAction
      Category = 'Logging'
      AutoCheck = True
      Caption = 'IPM Client'
      OnExecute = LogIPMClientCmd
    end
    object AboutAction: TAction
      Category = 'Help'
      Caption = 'About...'
      OnExecute = AboutCmd
    end
    object PrintAction: TAction
      Category = 'Edit'
      Caption = 'Print'
      ShortCut = 16464
      OnExecute = PrintCmd
    end
    object FindAction: TAction
      Category = 'Edit'
      Caption = 'Find...'
      ShortCut = 114
      OnExecute = FindCmd
      OnUpdate = FindActionUpdate
    end
    object RefreshAction: TAction
      Category = 'Edit'
      Caption = 'Refresh'
      ShortCut = 116
      OnExecute = RefreshActionExecute
      OnUpdate = RefreshActionUpdate
    end
    object LogIPMServerAction: TAction
      Category = 'Logging'
      AutoCheck = True
      Caption = 'IPM Server'
      OnExecute = LogIPMServerCmd
    end
    object LogUDPClientAction: TAction
      Category = 'Logging'
      AutoCheck = True
      Caption = 'UDP Client'
      OnExecute = LogUDPClientCmd
    end
    object LogHTTPServerAction: TAction
      Category = 'Logging'
      AutoCheck = True
      Caption = 'HTTP Server'
      OnExecute = LogHTTPServerCmd
    end
    object LogHTTPClientAction: TAction
      Category = 'Logging'
      AutoCheck = True
      Caption = 'HTTP Client'
      OnExecute = LogHTTPClientCmd
    end
    object ClearAllAction: TAction
      Category = 'Logging'
      Caption = 'Clear All'
      OnExecute = ClearAllActionExecute
    end
    object ModifyAction: TAction
      Category = 'Edit'
      Caption = 'Modify...'
      ShortCut = 13
      OnExecute = ModifyActionExecute
      OnUpdate = ModifyActionUpdate
    end
    object SaveAction: TAction
      Category = 'Edit'
      Caption = 'Save to file...'
      ShortCut = 16467
      OnExecute = SaveActionExecute
    end
    object ResetAction: TAction
      Category = 'Device'
      Caption = 'Reset'
      OnExecute = ResetActionExecute
    end
  end
  object SaveDialog1: TSaveDialog
    DefaultExt = 'txt'
    Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 28
    Top = 198
  end
end
