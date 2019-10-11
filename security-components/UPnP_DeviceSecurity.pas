{
  UPnP_DeviceSecurity:
  This is an implementation of the elements comprising the UPnP DeviceSecurity service
  Copyright (c) 2002..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_DeviceSecurity.pas,v 1.15 2005/10/04 21:52:59 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Revision History:
    January 5th, 2002
      - Started work
    April 4th, 2002
      - All of the core code written; most of it tested; looking good...
    April 27th, 2002
      - First operational tests with DSig working
      - Utility routines transferred to this main source file
    May 1st, 2002
      - First full run with all functions working
    May 2nd, 2002
      - Source formatting and commenting
    August 12th, 2002
      - Microsoft Crypto API replaced by third party libraries
      - Substitute string model for buffer model
    June 2005
      - Socket handling migrated to Indy descendents
    July 22, 2005
      - Release v1.5.03
    September 14, 2005
      - Third party libraries replaced by Microsoft Crypto API (!!!)
    September 18, 2005
      - Release v1.5.04
}

{
  Note: Make the following define to use the Microsoft Crypto API
        instead of 3rd party libraries
}
{$define UseMSWindowsXPCryptoAPI}

unit UPnP_DeviceSecurity;

interface

uses
  Classes,
  Contnrs,
{$ifndef UseMSWindowsXPCryptoAPI}
  ElAES,
  FGInt,
  FGIntPrimeGeneration,
  FGIntRSA,
{$endif}
  ExtCtrls,
  Messages,
  SysUtils,
  UPnP_Components,
  UPnP_IndyExtensions,
  UPnP_XmlStreamer,
  WCrypt2,
  Windows;

{$ifdef UseMSWindowsXPCryptoAPI}
const
  {
    New declarations added in the Windows XP version of Crypto API
  }
  CRYPT_STRING_BASE64 = 1;
  ALG_SID_AES_128     = 14;
  PROV_RSA_AES        = 24;
  CALG_AES_128        = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_128);
  MS_ENH_RSA_AES_PROV = 'Microsoft Enhanced RSA and ' +
                        'AES Cryptographic Provider (Prototype)';

  function CryptBinaryToString(pbBinary: PBYTE;
                               cbBinary: DWORD;
                               dwFlags: DWORD;
                               pszString: PBYTE;
                               pcchString: PDWORD): BOOL; stdcall;

  function CryptStringToBinary(pszString: PBYTE;
                               cchString: DWORD;
                               dwFlags: DWORD;
                               pbBinary: PBYTE;
                               pcbBinary: PDWORD;
                               pdwSkip: PDWORD;
                               pdwFlags: PDWORD): BOOL; stdcall;
{$endif}

const
  // Length of RSA keys in bytes
  RSA_KeyLength = 128; {1024 bits}

  // Length of AES keys in bytes
  AES_KeyLength = 16; {128 bits}

  // Length of AES blocks in bytes
  AES_BlockLength = AES_KeyLength;

  // Length of HMAC blocks in bytes
  AES_HMACBlockLength = 64; {64 bytes}

  // Length of AES Initialization vectors in bytes
  AES_IVLength = 16; {128 bits}

type
  {
    TUPnP_KeyAlgorithm: type of key algorithm
  }
  TUPnP_KeyAlgorithm = (alg_bad, alg_AES_128, alg_SHA1_HMAC, alg_RSA);

  {
    TUPnP_KeyType: type of session keys
  }
  TUPnP_KeyType = (confidentiality, signing);

  {
    TUPnP_KeyDirection: direction of session keys
  }
  TUPnP_KeyDirection = (toDevice, fromDevice);

  {
    ECryptoException: an exception type for Crypto errors
  }
  EUPnP_CryptoException = class(Exception);

  {
    EUPnP_KeyException: an exception type for RSA private keys
  }
  EUPnP_KeyException = class(Exception);

{$ifdef UseMSWindowsXPCryptoAPI}
  {
    TPlainTextKeyBlob: blob for session keys
  }
  TPlainTextKeyBlob = record
    fBLOBHEADER: BLOBHEADER;
    fKeySize: dword;
    fKeyData: array[0..AES_KeyLength - 1] of byte;
  end;

  {
    TPublicKeyBlob: blob for public keys
  }
  TPublicKeyBlob = record
    fBLOBHEADER: BLOBHEADER;
    fRSAPUBKEY: RSAPUBKEY;
    fModulus: array[0..RSA_KeyLength - 1] of byte;
  end;
{$endif}

  // Forward declarations
  TUPnP_DeviceSecurity = class;
  TUPnP_PrivateKey     = class;

  {
    TUPnP_DevSec_Action:
    Common primitive for all UPnP Device Security actions
  }
  TUPnP_DevSec_Action = class(TUPnP_Action)
  private
    procedure fAddArgument(aName: string; aDirection: TUPnP_ArgumentType;
      aRSV: TUPnP_StateVariable);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

  TUPnP_DevSec_AddACLEntry = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_DeleteACLEntry = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_ReplaceACLEntry = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_ReadACL = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_WriteACL = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_FactorySecurityReset = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_SetTimeHint = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GrantOwnership = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_RevokeOwnership = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_ListOwners = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_TakeOwnership = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetDefinedPermissions = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetDefinedProfiles = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetPublicKeys = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetAlgorithmsAndProtocols = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetACLSizes = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_CacheCertificate = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_SetSessionKeys = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_ExpireSessionKeys = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_DecryptAndExecute = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  TUPnP_DevSec_GetLifetimeSequenceBase = class(TUPnP_DevSec_Action)
  public
    constructor Create(AOwner: TComponent); override;
  end;

  {
    TUPnP_DevSec_StateVar:
    Common primitive for creating UPnP Device Security state variables
  }
  TUPnP_DevSec_StateVar = class(TUPnP_StateVariable)
  public
    constructor Create(aOwner: TComponent; aDefaultValue: string;
      aEvented: boolean; aDataType: TUPnP_VariableType; aName: string);
      reintroduce; overload;
  end;

  {
    TUPnP_Subject_Type:
    Access Control List entry types
  }
  TUPnP_Subject_Type = (st_key, st_name, st_any);

  {
    TUPnP_ACL_Entry:
    Access Control List entry
  }
  TUPnP_ACL_Entry = class
  private
    fStatusOk: boolean;
    fIssuerType: TUPnP_Subject_Type;
    fSubjectType: TUPnP_Subject_Type;
    fIssuerString: string;
    fSubjectString: string;
    fValidityStart: string;
    fValidityEnd: string;
    fPermissions: TStringList;
    fMayNotDelegate: boolean;
    function IntersectsWith(aSubjectType: TUPnP_Subject_Type;
      aSubjectString: string;
      aPermissionCollection: TUPnP_SecurityPermissionCollection;
      aCheckDelegation: boolean): boolean;
  public
    constructor CreateFromAclXml(aBuffer: TUPnP_XMLStream);
    constructor CreateFromStream(aReader: TReader);
    constructor CreateFromHash(aHash: string);
    constructor CreateFromCertXML(aDevSec: TUPnP_DeviceSecurity;
      aBuffer: TUPnP_XMLStream);
    constructor Create;
    destructor Destroy; override;
    procedure SaveToCertXML(aBuffer: TUPnP_XMLStream;
      anIssuerRSAKey: TUPnP_PrivateKey; aDeviceHash: string);
    procedure SaveToXML(aBuffer: TUPnP_XMLStream);
    procedure SaveToStream(aWriter: TWriter);
  end;

  {
    TUPnP_AuthList:
    Access Control List
  }
  TUPnP_AuthList = class(TObjectList)
  private
    function fGetEntry(aIndex: integer): TUPnP_ACL_Entry;
  public
    constructor CreateFromStream(aReader: TReader);
    procedure SaveToStream(aWriter: TWriter);
    procedure SaveToXML(aBuffer: TUPnP_XMLStream);
    procedure DeleteExpiredEntries;
    property Entry[aIndex: integer]: TUPnP_ACL_Entry Read fGetEntry;
  end;

  {
    TUPnP_RSA_Key:
    RSA public key
  }
  TUPnP_RSA_Key = class
  private
    fInitialised: boolean;
    fDevSec: TUPnP_DeviceSecurity;
{$ifdef UseMSWindowsXPCryptoAPI}
    fKeyHandle: HCRYPTKEY;
{$else}
    n, e: TFGInt;
    function SignatureDigest(aPlainText: string): string;
    function PKCSPad(aString: string): string;
    function PKCSUnPad(aString: string): string;
{$endif}
    function PrependZeroByte(aString: string): string;
    function StripZeroByte(aString: string): string;
    function ModulusB64: string;
    function PublicExponentB64: string;
    procedure NotInitialisedException(aMethod: string);
    function ReverseString(aString: string): string;
  public
    constructor CreateFromXML(aDevSec: TUPnP_DeviceSecurity; aBuffer: TUPnP_XMLStream);
    destructor Destroy; override;
    procedure SaveToXML(aBuffer: TUPnP_XMLStream);
    function AsString: string;
    function Encrypt(aPlainText: string): string;
    function Verify(aPlainText, aSignature: string): boolean;
  end;

  {
    TUPnP_PrivateKey:
    RSA private key
  }
  TUPnP_PrivateKey = class(TUPnP_RSA_Key)
  private
{$ifdef UseMSWindowsXPCryptoAPI}
    fCAPIKeyExists: boolean;
{$else}
    p, q, dp, dq: TFGInt;
{$endif}
    procedure GenerateNewKey;
  public
    constructor CreateRandom(aDevSec: TUPnP_DeviceSecurity);
    constructor CreateFromStream(aDevSec: TUPnP_DeviceSecurity; aReader: TReader);
    destructor Destroy; override;
    procedure GenerateNewKeyDone;
    procedure GenerateNewKeyStart;
    procedure SaveToStream(aWriter: TWriter);
    function Decrypt(aCipherText: string): string;
    function Sign(aPlainText: string): string;
  end;

  {
    TUPnP_PK_InitialiseThread:
    Thread for initialising RSA public keys
  }
  TUPnP_PK_InitialiseThread = class(TThread)
  private
    fKey: TUPnP_PrivateKey;
  protected
    procedure Execute; override;
    constructor Create(aKey: TUPnP_PrivateKey); overload;
  end;

  {
    TUPnP_SessionKey:
    Session Key
  }
  TUPnP_SessionKey = class
  private
{$ifdef UseMSWindowsXPCryptoAPI}
    fIV: array[0..AES_IVLength - 1] of byte;
    fKey: array[0..AES_KeyLength - 1] of byte;
    fKeyHandle: HCRYPTKEY;
{$else}
    fIV: TAESBuffer;
    fKey: TAESKey128;
    fEncryptKey: TAESExpandedKey128;
    fDecryptKey: TAESExpandedKey128;
    fEncryptKeyExpanded: boolean;
    fDecryptKeyExpanded: boolean;
{$endif}
    fKeyType: TUPnP_KeyType;
    fDirection: TUPnP_KeyDirection;
    fCryptoProvider: HCRYPTPROV;
    procedure SetIV(anIV: string);
    function GetIV: string;
    function GetKV: string;
    procedure AppendPadding(var aString: string);
    procedure StripPadding(var aString: string);
{$ifdef UseMSWindowsXPCryptoAPI}
    procedure InitKey;
{$endif}
  public
    constructor CreateFromStream(aCryptoProvider: HCRYPTPROV; aReader: TReader);
    constructor CreateFromXML(aCryptoProvider: HCRYPTPROV; aBuffer: TUPnP_XMLStream);
    constructor CreateFromEncipheredBulkKey(aCryptoProvider: HCRYPTPROV;
      aPrivateKey: TUPnP_PrivateKey; aCipherText: string);
    constructor CreateRandom(aCryptoProvider: HCRYPTPROV);
    constructor CreateToEncipheredBulkKey(aCryptoProvider: HCRYPTPROV;
      aPublicKey: TUPnP_RSA_Key; out aCipherText: string);
    destructor Destroy; override;
    procedure SaveToStream(aWriter: TWriter);
    procedure SaveToXML(aBuffer: TUPnP_XMLStream);
    function Encrypt(aPlainText: string): string;
    function Decrypt(aCipherText: string): string;
    procedure NewRandomIV;
    property KeyValue: string Read GetKV;
    property InitialValue: string Read GetIV Write SetIV;
  end;

  {
    TUPnP_Session:
    Entry in the sessions list
  }
  TUPnP_Session = class
  private
    fKey: array[0..3] of TUPnP_SessionKey;
    fCPKeyID: integer;
    fDeviceKeyID: integer;
    fDeviceSequenceNumber: integer;
    fCPSequenceNumber: integer;
    fOwnerPKHashB64, fSequenceBase: string;
    function GetKey(aKeyType: TUPnP_KeyType;
      aKeyDirection: TUPnP_KeyDirection): TUPnP_SessionKey;
  public
    constructor CreateRandom(aDevSecService: TUPnP_DeviceSecurity); virtual;
    constructor CreateFromStream(aDevSecService: TUPnP_DeviceSecurity;
      aReader: TReader); virtual;
    constructor CreateFromXML(aDevSecService: TUPnP_DeviceSecurity;
      aBuffer: TUPnP_XMLStream); virtual;
    destructor Destroy; override;
    procedure SaveToStream(aWriter: TWriter);
    procedure SaveToXML(aBuffer: TUPnP_XMLStream);
    property Key[aKeyType: TUPnP_KeyType;
      aKeyDirection: TUPnP_KeyDirection]: TUPnP_SessionKey Read GetKey;
    property Owner: string Read fOwnerPKHashB64;
    property ID: integer Read fDeviceKeyID;
  end;

  {
    TUPnP_SessionsList:
    Secure Sessions List
  }
  TUPnP_SessionsList = class(TObjectList)
  private
    function fGetSession(aDeviceKeyID: integer): TUPnP_Session;
  public
    constructor CreateFromStream(aDevSecService: TUPnP_DeviceSecurity;
      aReader: TReader); virtual;
    procedure SaveToStream(aWriter: TWriter);
    property Session[aDeviceKeyID: integer]: TUPnP_Session Read fGetSession;
  end;

  {
    TUPnP_DigSig_DigestCallback:
    Call back used by TUPnP_DigitalSignature to fetch the references
  }
  TUPnP_DigSig_DigestCallback = procedure(anURI: string;
    out aDigest: string) of object;

  {
    TUPnP_DigitalSignature:
    Implements a UPnP Digital Signature
  }
  TUPnP_DigitalSignature = class
  public
    constructor Create(aDevSec: TUPnP_DeviceSecurity; aSignatureNode: string;
      aSessionList: TUPnP_SessionsList; aDSigParamList: TStringList;
      aSigDirection: TUPnP_KeyDirection; aDigestCallback: TUPnP_DigSig_DigestCallback;
      out aResult: TUPnP_AuthorisationResult; out aSessionKey: TUPnP_Session);
  end;

  {
    TUPnP_DeviceSecurity:
    Implements the DeviceSecurity Service
  }
  TUPnP_DeviceSecurity = class(TUPnP_DeviceSecurityBase)
  private
    fACLVersionValue: string;
    fSecret: string;
    fNumberOfOwners: TUPnP_DevSec_StateVar;
    //  fACLVersion: string;
    fTotalACLSize: TUPnP_DevSec_StateVar;
    fFreeACLSize: TUPnP_DevSec_StateVar;
    fTotalOwnerListSize: TUPnP_DevSec_StateVar;
    fFreeOwnerListSize: TUPnP_DevSec_StateVar;
    fTotalCertCacheSize: TUPnP_DevSec_StateVar;
    fFreeCertCacheSize: TUPnP_DevSec_StateVar;
    fEncryptedEvent: TUPnP_DevSec_StateVar;
    fLifetimeSequenceBase: TUPnP_DevSec_StateVar;
    fTimeHint: TUPnP_DevSec_StateVar;
    fA_ARG_TYPE_Int: TUPnP_DevSec_StateVar;
    fA_ARG_TYPE_String: TUPnP_DevSec_StateVar;
    fA_ARG_TYPE_Base64: TUPnP_DevSec_StateVar;
    fA_ARG_TYPE_Boolean: TUPnP_DevSec_StateVar;
    fSecureSetSessionKeysStreamed: boolean;
    fSecureInformationActionsStreamed: boolean;
    fSecureSetSessionKeys: boolean;
    fSecureInformationActions: boolean;
    fStateFileName: string;
    fACLentries: TUPnP_AuthList;
    fCertificates: TUPnP_AuthList;
    fSecurityOwners: TUPnP_AuthList;
    fSessions: TUPnP_SessionsList;
    fPrivateKey: TUPnP_PrivateKey;
    fCryptoProvider: HCRYPTPROV;
    fOnGenerateKeyStart: TNotifyEvent;
    fOnGenerateKeyDone: TNotifyEvent;
    fStateFileLoaded: boolean;
    fSoapDSigParameters: TStringList;
    fCertDSigParameters: TStringList;
    fOnFactoryReset: TNotifyEvent;
    fFactoryResetFlag: boolean;
    fSecurityPermissions: TUPnP_SecurityPermissionCollection;
    fControlRequest: TUPnP_HTTPServerRequestWrapper;
    fControlResponse: TUPnP_HTTPServerResponseWrapper;
    fDelayedCallbackTimer: TTimer;
    procedure SetSecurityPermissions(Value: TUPnP_SecurityPermissionCollection);
    procedure SetSecureInformationActions(aValue: boolean); virtual;
    procedure SetSecureSetSessionKeys(aValue: boolean); virtual;
    procedure LoadStateFile;
    procedure SaveStateFile;
    procedure SoapDigestCallBack(anURI: string; out aDigest: string);
    procedure CertDigestCallBack(anURI: string; out aDigest: string);
    function CreateCertificate(aCertificate, aSignature: string): TUPnP_ACL_Entry;
    function CacheCertificates(aCertSequence: string): boolean;

    // action implementations
    function OnGetPublicKeys(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGetAlgorithmsAndProtocols(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGetACLSizes(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnCacheCertificate(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnTakeOwnership(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGetDefinedPermissions(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGetDefinedProfiles(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnReadACL(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnWriteACL(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnAddACLEntry(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnDeleteACLEntry(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnReplaceACLEntry(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnFactorySecurityReset(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnSetTimeHint(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGrantOwnership(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnRevokeOwnership(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnListOwners(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnSetSessionKeys(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnExpireSessionKeys(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnDecryptAndExecute(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;
    function OnGetLifetimeSequenceBase(Caller: TUPnP_Action;
      var ErrorCode, ErrorMessage: string): boolean;

    // dsig checking functions
    function fGetDSigParameters(aRequest: TUPnP_XMLStream): TUPnP_AuthorisationResult;
    function fGetFullControlURL(aCaller: TUPnP_Component): string;
    function fVerifyPermissions(aCaller: TUPNP_Component;
      anOwnerPKHash: string): boolean;

    // random function
    function fRandomString: string;
    function fCheckAuthorised(aSubjectType: TUPnP_Subject_Type;
      aSubjectString: string;
      aPermissionCollection: TUPnP_SecurityPermissionCollection;
      aCheckDelegates: boolean): boolean;

    // security for persistent data
    procedure LoadStreamFromEncryptedFile(aStream: TMemoryStream;
      aFile, aPassword: string; aCryptoProv: HCRYPTPROV);
    procedure SaveStreamToEncryptedFile(aStream: TMemoryStream;
      aFile, aPassword: string; aCryptoProv: HCRYPTPROV);
  protected
    procedure CreateRegistryData;
    procedure GetRegistryData;
    procedure OnExpireSessionTimer(Sender: TObject);
    procedure DoHardFactoryReset;
    function ProcessControlRequest(Request: TUPnP_HTTPServerRequestWrapper;
      var Response: TUPnP_HTTPServerResponseWrapper): boolean; override;
    procedure Connect; override;
    procedure Disconnect; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure Loaded; override;
    function CheckDsigAuthorisation(aCaller: TUPnP_Component;
      aRequest: TUPnP_XMLStream): TUPnP_AuthorisationResult; override;
    procedure Sign(aCaller: TUPnP_Component; aBody: TUPnP_XMLStream;
      out aSecurityInfo: TUPnP_XMLStream); override;
    property OnGenerateKeyStart: TNotifyEvent
      Read fOnGenerateKeyStart Write fOnGenerateKeyStart;
    property OnGenerateKeyDone: TNotifyEvent
      Read fOnGenerateKeyDone Write fOnGenerateKeyDone;
    property OnFactoryReset: TNotifyEvent Read fOnFactoryReset Write fOnFactoryReset;
    procedure Load(aReader: TReader);
    procedure Save(aWriter: TWriter);
    procedure Reset; override;

  published
    property SecureInformationActions: boolean
      Read fSecureInformationActions Write SetSecureInformationActions;
    property SecureSetSessionKeys: boolean
      Read fSecureSetSessionKeys Write SetSecureSetSessionKeys;
    property SecurityPermissions: TUPnP_SecurityPermissionCollection
      Read fSecurityPermissions Write SetSecurityPermissions;
    property Secret: string Read fSecret Write fSecret;
  end;

  {
    TUPnP_SecUtils:
    Implements useful crypto class functions
  }
  TSecUtils = class
    class function CreateHMACDigest(aKey, aPlainText: string;
      aCryptoProvider: HCRYPTPROV): string;
    class function StringToHash(aString: string; aCryptoProvider: HCRYPTPROV): string;
  end;

  // helper functions
  function Base64ToBinary(Source: string): string;
  function BinaryToBase64(Source: string): string;

  procedure Register;

implementation

uses
  Registry,
  SHFolder,
  UPnP_DeviceSecurityStrings,
  UPnP_Globals,
  UPnP_Strings;

const
  // maximum number of ACL entries
  maxACL = 16;

  // maximum number of owner entries
  maxOwner = 4;

  // maximum number of certificate cache entries
  maxCache = 16;

procedure Register;
{
  Register components in IDE
  Status: FULLY TESTED
}
begin
  RegisterComponents(_UPnP, [TUPnP_DeviceSecurity]);
end;


// *********************** Error handling ********************

procedure RaiseException(aClass, aAction: string; aPosition: integer);
{
  Raise a crypto API exception
  Status: FULLY TESTED
}
begin
  // raise an exception
  if aClass = '' then
  begin
    // if there is no classname then use message format 1
    raise EUPnP_CryptoException.CreateFmt(fmt1, [GetLastError, aAction, aPosition]);
  end
  else
  begin
    // otherwise use message format 2
    raise EUPnP_CryptoException.CreateFmt(fmt2, [GetLastError, aClass,
      aAction, aPosition]);
  end;
end;


// *********************** Encrypted File Utilities ********************

procedure TUPnP_DeviceSecurity.LoadStreamFromEncryptedFile(aStream: TMemoryStream;
  aFile, aPassword: string; aCryptoProv: HCRYPTPROV);
{
  Create a plaintext memory stream from a password encrypted file
  Status: FULLY TESTED
}
var
  hHash:   hCryptHash;
  hKey:    hCryptKey;
  outSize: longint;
const
  actname = 'LoadStreamFromEncryptedFile';
begin
  // create a hash object; on failure raise an exception
  if not CryptCreateHash(aCryptoProv, CALG_MD5, 0, 0, @hHash) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  try
    // create a hash of the password; on failure raise an exception
    if not CryptHashData(hHash, @aPassword[1], length(aPassword), 0) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // derive a key from the hash and on failure raise an exception
    if not CryptDeriveKey(aCryptoProv, CALG_RC2, hHash, 0, @hKey) then
    begin
      RaiseException(ClassName, actname, 3);
    end;

    try

      // check that the file exists, and that the destination stream exists
      if FileExists(aFile) and Assigned(aStream) then
      begin

        // load the encrypted data from the file
        aStream.LoadFromFile(aFile);

        // get the data size
        outSize := aStream.Size;

        // decrypt the data and get the decrypted size data;
        //  on failure raise an exception
        if not CryptDecrypt(hKey, 0, True, 0, aStream.Memory, @outSize) then
        begin
          RaiseException(ClassName, actname, 4);
        end;

        // adjust the stream size to that of the decrypted data
        if outSize < aStream.Size then
        begin
          aStream.SetSize(outSize);
        end;

        // go to the stream start
        aStream.Seek(0, 0);
      end;

    finally
      // destroy the key; on failure raise an exception
      if not CryptDestroyKey(hKey) then
      begin
        RaiseException(ClassName, actname, 5);
      end;
    end;

  finally
    // destroy the hash; on failure raise an exception
    if not CryptDestroyHash(hHash) then
    begin
      RaiseException(ClassName, actname, 6);
    end;
  end;
end;

procedure TUPnP_DeviceSecurity.SaveStreamToEncryptedFile(aStream: TMemoryStream;
  aFile, aPassword: string; aCryptoProv: HCRYPTPROV);
{
  Save a plaintext memory stream to a password encrypted file
  Status: FULLY TESTED
}
var
  hHash: hCryptHash;
  hKey:  hCryptKey;
  inSize, outSize: longint;
const
  actname = 'SaveStreamToEncryptedFile';
begin
  // create a hash object; on failure raise an exception
  if not CryptCreateHash(aCryptoProv, CALG_MD5, 0, 0, @hHash) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  try

    // create a hash of the password; on failure raise an exception
    if not CryptHashData(hHash, @aPassword[1], length(aPassword), 0) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // derive a key from the hash; on failure raise an exception
    if not CryptDeriveKey(aCryptoProv, CALG_RC2, hHash, 0, @hKey) then
    begin
      RaiseException(ClassName, actname, 3);
    end;

    try

      // check if the output stream exists
      if Assigned(aStream) then
      begin

        // get the data size
        inSize  := aStream.Size;
        outSize := inSize;

        // determine the size of the encrypted data
        CryptEncrypt(hKey, 0, True, 0, nil, @outSize, 0);

        // get more memory if needed
        if outSize > inSize then
        begin
          aStream.SetSize(outSize);
        end;

        // encrypt the data
        if not CryptEncrypt(hKey, 0, True, 0, aStream.Memory, @inSize, outSize) then
        begin
          RaiseException(ClassName, actname, 4);
        end;

        // save the encrypted data to the file
        aStream.SaveToFile(aFile);
      end;

    finally
      // destroy the key; on failure raise an exception
      if not CryptDestroyKey(hKey) then
      begin
        RaiseException(ClassName, actname, 5);
      end;
    end;

  finally
    // destroy the hash; on failure raise an exception
    if not CryptDestroyHash(hHash) then
    begin
      RaiseException(ClassName, actname, 6);
    end;
  end;
end;

function DoGetPermissions(aTagValue: string; out aPermissions: string): boolean;
{
  Parse permissions entry in an xml tag value
  Status: FULLY TESTED
}
var
  aBuffer: TUPnP_XMLStream;
  perms:   TStringList;
begin
  Result  := True;
  aBuffer := TUPnP_XMLStream.Create;
  perms   := TStringList.Create;
  try
    with aBuffer do
    begin
      WriteValues([aTagValue]);
      ResetParser;

      // iterate through each entry in the 'access' section
      repeat

        // if it contains the 'all' tag => this subject has all permissions
        if TagName = _all then
        begin
          perms.Text := _allStar;
        end
        else
        begin
          //otherwise add the permission to the list
          perms.Add(TagName);
        end;

        // get the next tag
        NextTag;
      until EOF;
    end;

  finally
    aBuffer.Free;
    aPermissions := perms.Text;
    perms.Free;
  end;
end;

function DoGetHash(aTagValue: string; out aHash: string): boolean;
{
  Parse hash entry in an xml tag value
  Status: FULLY TESTED
}
var
  aBuffer: TUPnP_XMLStream;
begin
  Result  := False;
  aBuffer := TUPnP_XMLStream.Create;
  try
    with aBuffer do
    begin
      WriteValues([aTagValue]);
      ResetParser;

      // get the hash algorithm
      if (TagName = _algorithm) and (TagValue = _shaUC) then
      begin
        NextTag;

        // get the hash value
        if TagName = _value then
        begin
          aHash  := TagValue;
          Result := True;
        end;
      end;
    end;

  finally
    aBuffer.Free;
  end;
end;

function DoGetValidity(aTagValue: string;
  out aValidityStart, aValidityEnd: string): boolean;
{
  Parse validity dates entry in an xml tag value
  Status: FULLY TESTED
}
var
  aBuffer: TUPnP_XMLStream;
begin
  Result := True;
  // preset the validity dates to empty
  aValidityStart := '';
  aValidityEnd := '';

  aBuffer := TUPnP_XMLStream.Create;
  try
    with aBuffer do
    begin
      WriteValues([aTagValue]);
      ResetParser;

      // start validity date
      if TagName = _notbefore then
      begin
        aValidityStart := TagValue;
        NextTag;
      end;

      // end validity date
      if TagName = _notafter then
      begin
        aValidityEnd := TagValue;
        NextTag;
      end;
    end;
  finally
    aBuffer.Free;
  end;
end;


// ************************* TUPnP_DeviceSecurity **********************

constructor TUPnP_DeviceSecurity.Create(AOwner: TComponent);
{
  Creates the StateVariables and Actions needed for UPnP Security
  Status: FULLY TESTED
}
  procedure AddAction(aAction: TUPnP_Action; aCallback: TUPnP_ActionExecute);
  {
    Add an action to the Actions list
    Status: FULLY TESTED
  }
  var
    ci: TCollectionItem;
  begin

    // don't add nil actions
    if aAction = nil then
    begin
      exit;
    end;

    // assign the callback handler
    aAction.OnActionExecute := aCallback;

    // add a new entry to the list
    ci := fActions.Add;

    // and assign the action to the entry
    if ci is TUPnP_CollectionItem then
    begin
      TUPnP_CollectionItem(ci).AssignComponent(aAction);
    end;
  end;

  procedure AddVariable(aVariable: TUPnP_StateVariable);
  {
    Add the state variable to the StateVariables list
    Status: FULLY TESTED
  }
  var
    ci: TCollectionItem;
  begin
    // don't add nil variables
    if aVariable = nil then
    begin
      exit;
    end;

    // add a new entry to the list
    ci := fStateVariables.Add;

    // and assign the variable to the entry
    if ci is TUPnP_CollectionItem then
    begin
      TUPnP_CollectionItem(ci).AssignComponent(aVariable);
    end;
  end;

const
  actName = 'Create';
begin
  inherited;

  // initialise to a pretty dumb secret
  fSecret := _secret;

  fSecurityPermissions := TUPnP_SecurityPermissionCollection.Create(self);

  fSoapDSigParameters := TStringList.Create;
  fCertDSigParameters := TStringList.Create;

  fStateFileLoaded := False;

  fACLentries := nil;
  fCertificates := nil;
  fSecurityOwners := nil;
  fSessions   := nil;
  fPrivateKey := nil;

  fDelayedCallbackTimer := TTimer.Create(self);
  fDelayedCallbackTimer.Enabled := False;
  fDelayedCallbackTimer.Interval := 10;

  // initialise serviceID, serviceType and serviceVersion
  ServiceID      := Copy(ClassName, 7, length(ClassName) - 6);
  ServiceType    := ServiceID;
  ServiceVersion := '1';

{$ifdef UseMSWindowsXPCryptoAPI}
  // try the AES provider (Windows XP only)
  if (not CryptAcquireContext(@fCryptoProvider, UPnP_Library_Name,
    MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) and
    (not CryptAcquireContext(@fCryptoProvider, UPnP_Library_Name,
    MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
    CRYPT_NEWKEYSET)) then
  begin
    // if no provider found raise an exception
    RaiseException(ClassName, actname, 1);
  end;

{$else}
  // create standard security provider context;
  if (not CryptAcquireContext(@fCryptoProvider, UPnP_Library_Name,
    MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) and
    (not CryptAcquireContext(@fCryptoProvider, UPnP_Library_Name,
    MS_ENHANCED_PROV, PROV_RSA_FULL,
    CRYPT_NEWKEYSET)) then
  begin
    // if no provider found raise an exception
    RaiseException(ClassName, actname, 2);
  end;
{$endif}

  // create the DeviceSecurity state variables
  fNumberOfOwners := TUPnP_DevSec_StateVar.Create(self, '0',
    True, i4, 'NumberOfOwners');
  //fACLVersion := TUPnP_DevSec_StateVar.Create(self, '', false, string_, 'ACLVersion');
  fLifetimeSequenceBase := TUPnP_DevSec_StateVar.Create(self, '',
    True, string_, 'LifetimeSequenceBase');
  //fEncryptedEvent := TUPnP_DevSec_StateVar.Create(self, '', true, bin_base64,'EncryptedEvent');
  fTimeHint     := TUPnP_DevSec_StateVar.Create(self, '',
    False, string_, 'TimeHint');
  fTotalACLSize := TUPnP_DevSec_StateVar.Create(self, '0',
    False, i4, 'TotalACLSize');
  fFreeACLSize  := TUPnP_DevSec_StateVar.Create(self, '0',
    True, i4, 'FreeACLSize');
  fTotalOwnerListSize := TUPnP_DevSec_StateVar.Create(self, '0',
    False, i4, 'TotalOwnerListSize');
  fFreeOwnerListSize := TUPnP_DevSec_StateVar.Create(self, '0',
    True, i4, 'FreeOwnerListSize');
  fTotalCertCacheSize := TUPnP_DevSec_StateVar.Create(self, '0',
    False, i4, 'TotalCertCacheSize');
  fFreeCertCacheSize := TUPnP_DevSec_StateVar.Create(self, '0',
    True, i4, 'FreeCertCacheSize');
  fA_ARG_TYPE_String := TUPnP_DevSec_StateVar.Create(self, '',
    False, string_, 'A_ARG_TYPE_string');
  fA_ARG_TYPE_Base64 := TUPnP_DevSec_StateVar.Create(self, '',
    False, bin_base64, 'A_ARG_TYPE_base64');
  fA_ARG_TYPE_Int := TUPnP_DevSec_StateVar.Create(self, '0',
    False, i4, 'A_ARG_TYPE_int');
  fA_ARG_TYPE_Boolean := TUPnP_DevSec_StateVar.Create(self, '0',
    False, boolean_, 'A_ARG_TYPE_boolean');

  // initialise some of the state variables
  fLifetimeSequenceBase.fValue := fRandomString;
  // fACLVersion.fValue := fRandomString;
  fACLVersionValue     := fRandomString;
  fTotalACLSize.fValue := IntToStr(maxACL);
  fTotalOwnerListSize.fValue := IntToStr(maxOwner);
  fTotalCertCacheSize.fValue := IntToStr(maxCache);

  // add the DeviceSecurity state variables to the StateVariables list
  AddVariable(fNumberOfOwners);
  // AddVariable(fACLVersion);
  AddVariable(fLifetimeSequenceBase);
  AddVariable(fEncryptedEvent);
  AddVariable(fTimeHint);
  AddVariable(fTotalACLSize);
  AddVariable(fFreeACLSize);
  AddVariable(fTotalOwnerListSize);
  AddVariable(fFreeOwnerListSize);
  AddVariable(fTotalCertCacheSize);
  AddVariable(fFreeCertCacheSize);
  AddVariable(fA_ARG_TYPE_String);
  AddVariable(fA_ARG_TYPE_Base64);
  AddVariable(fA_ARG_TYPE_Int);
  AddVariable(fA_ARG_TYPE_Boolean);

  // add the DeviceSecurity actions to the Actions list
  AddAction(TUPnP_DevSec_GetPublicKeys.Create(self), OnGetPublicKeys);
  AddAction(TUPnP_DevSec_GetAlgorithmsAndProtocols.Create(self),
    OnGetAlgorithmsAndProtocols);
  AddAction(TUPnP_DevSec_GetACLSizes.Create(self), OnGetACLSizes);
  AddAction(TUPnP_DevSec_CacheCertificate.Create(self), OnCacheCertificate);
  AddAction(TUPnP_DevSec_SetTimeHint.Create(self), OnSetTimeHint);
  AddAction(TUPnP_DevSec_GetLifetimeSequenceBase.Create(self),
    OnGetLifetimeSequenceBase);
  AddAction(TUPnP_DevSec_SetSessionKeys.Create(self), OnSetSessionKeys);
  AddAction(TUPnP_DevSec_ExpireSessionKeys.Create(self), OnExpireSessionKeys);
  AddAction(TUPnP_DevSec_DecryptAndExecute.Create(self), OnDecryptAndExecute);
  AddAction(TUPnP_DevSec_TakeOwnership.Create(self), OnTakeOwnership);
  AddAction(TUPnP_DevSec_GetDefinedPermissions.Create(self), OnGetDefinedPermissions);
  AddAction(TUPnP_DevSec_GetDefinedProfiles.Create(self), OnGetDefinedProfiles);
  AddAction(TUPnP_DevSec_ReadACL.Create(self), OnReadACL);
  AddAction(TUPnP_DevSec_WriteACL.Create(self), OnWriteACL);
  AddAction(TUPnP_DevSec_AddACLEntry.Create(self), OnAddACLEntry);
  AddAction(TUPnP_DevSec_DeleteACLEntry.Create(self), OnDeleteACLEntry);
  AddAction(TUPnP_DevSec_ReplaceACLEntry.Create(self), OnReplaceACLEntry);
  AddAction(TUPnP_DevSec_FactorySecurityReset.Create(self), OnFactorySecurityReset);
  AddAction(TUPnP_DevSec_GrantOwnership.Create(self), OnGrantOwnership);
  AddAction(TUPnP_DevSec_RevokeOwnership.Create(self), OnRevokeOwnership);
  AddAction(TUPnP_DevSec_ListOwners.Create(self), OnListOwners);
end;

destructor TUPnP_DeviceSecurity.Destroy;
{
  Destroys the StateVariables and Actions needed for UPnP Security
  Status: FULLY TESTED
}
var
  i: integer;
begin
  if fConnected then
  begin
    Disconnect;
  end;

  // save the persistent data to the state file
  SaveStateFile;

  fSoapDSigParameters.Free;
  fCertDSigParameters.Free;

  // iterate through the Actions list
  for i := pred(fActions.Count) downto 0 do
  begin

    // free the action
    fActions[i].Free;

    // and delete the reference to it
    fActions.Delete(i);
  end;

  // iterate through the StateVariables list
  for i := pred(fStateVariables.Count) downto 0 do
  begin

    // free the variable
    fStateVariables[i].Free;

    // and delete the reference to it
    fStateVariables.Delete(i);
  end;

  // release the private key
  if Assigned(fPrivateKey) then
  begin
    fPrivateKey.Free;
  end;

  // release the crypto provider
  CryptReleaseContext(fCryptoProvider, 0);

  // free the ACL, Owners and Sessions lists
  fACLentries.Free;
  fCertificates.Free;
  fSecurityOwners.Free;
  fSessions.Free;
  fSecurityPermissions.Free;
  fDelayedCallbackTimer.Free;

  inherited;
end;

procedure TUPnP_DeviceSecurity.Reset;
{
  Reset the service
  Status: FULLY TESTED
}
begin
  // reset
  DoHardFactoryReset;
  inherited;
end;

procedure TUPnP_DeviceSecurity.SetSecureSetSessionKeys(aValue: boolean);
{
  Determine if SetSessionKeys and ExpireSessionKeys must be authorised
  Status: FULLY TESTED
}
var
  i:   integer;
  act: TUPnP_Action;
begin
  if csLoading in ComponentState then
  begin
    fSecureSetSessionKeysStreamed := aValue;
  end
  else
  begin
    // store the value in a temporary location for future use
    fSecureSetSessionKeys := aValue;

    // loop through all the embedded actions
    for i := 0 to pred(Actions.Count) do
    begin

      // de-reference the index -- for speed
      act := Actions[i];

      // check if the action is of the type which needs authorisation
      if (act is TUPnP_DevSec_SetSessionKeys) or
        (act is TUPnP_DevSec_ExpireSessionKeys) then
      begin
        // if so, then pass the authorisation setting on to the embedded Action
        act.RequiresAuthorisation := aValue;
      end
      else
      begin
        // otherwise authorisation is not required
        if assigned(act) then
        begin
          act.RequiresAuthorisation := False;
        end;
      end;
    end;
  end;
end;

procedure TUPnP_DeviceSecurity.SetSecureInformationActions(aValue: boolean);
{
  Determine if information request actions must be authorised
  Status: FULLY TESTED
}
var
  i:   integer;
  act: TUPnP_Action;
begin
  if csLoading in ComponentState then
  begin
    fSecureInformationActionsStreamed := aValue;
  end
  else
  begin
    // store the value in a temporary location for future use
    fSecureInformationActions := aValue;

    // loop through all the embedded actions
    for i := 0 to pred(Actions.Count) do
    begin

      // de-reference the index -- for speed
      act := Actions[i];

      // check if the action is of the type which needs authorisation
      if (act is TUPnP_DevSec_GetDefinedPermissions) or
        (act is TUPnP_DevSec_GetDefinedProfiles) or
        (act is TUPnP_DevSec_ListOwners) then
      begin
        // if so, then pass the authorisation setting on to the embedded Action
        act.RequiresAuthorisation := aValue;
      end
      else
      begin
        // otherwise authorisation is not required
        if assigned(act) then
        begin
          act.RequiresAuthorisation := False;
        end;
      end;
    end;
  end;
end;

procedure TUPnP_DeviceSecurity.Loaded;
{
  Fixup things after the component has loaded
  Status: FULLY TESTED
}
begin
  inherited;
  SecureSetSessionKeys     := fSecureSetSessionKeysStreamed;
  SecureInformationActions := fSecureInformationActionsStreamed;
end;

procedure TUPnP_DeviceSecurity.SetSecurityPermissions(Value:
  TUPnP_SecurityPermissionCollection);
{
  Used by Object Inspector at design time to assign permissions to
  the SecurityPermissions collection
  Status: FULLY TESTED
}
begin
  fSecurityPermissions.Assign(Value);
end;

procedure TUPnP_DeviceSecurity.Connect;
{
  Read the persistent data before going online
  Status: FULLY TESTED
}
begin
  inherited;
  if not fStateFileLoaded then
  begin
    // get the persistent data from the registry
    CreateRegistryData;

    // load the persistent data from the state file
    LoadStateFile;

    fStateFileLoaded := True;
  end;

  // delete any expired ACL entries
  fACLentries.DeleteExpiredEntries;
  fCertificates.DeleteExpiredEntries;

  // update free vaules
  fFreeACLSize.Value := IntToStr(maxACL - fACLentries.Count);
  fFreeCertCacheSize.Value := IntToStr(maxCache - fCertificates.Count);
end;

procedure TUPnP_DeviceSecurity.Disconnect;
{
  Execute the factory reset before going offline
  Status: FULLY TESTED
}
begin
  // if the fFactoryResetFlag is set, then we must do the factory reset action
  if fFactoryResetFlag then
  begin
    // reset
    DoHardFactoryReset;
    // and clear the flag
    fFactoryResetFlag := False;
  end;
  inherited;
end;

function TUPnP_DeviceSecurity.fGetDSigParameters(aRequest: TUPnP_XMLStream):
TUPnP_AuthorisationResult;
{
  Parse the xml request and collect all the dsig data from it
  The data is collected into a parameter list as a series of entries in the
  form "Name=Value"
  Status: FULLY TESTED
}
var
  lBodyCount, lFreshnessCount, lSignedInfoCount: integer;
begin
  Result     := auth_Accepted;
  lBodyCount := 0;
  lFreshnessCount := 0;
  lSignedInfoCount := 0;

  with aRequest do
  begin

    // reset the parser
    ResetParser;

    // if either the header tag or the security info tag are missing then exit
    if not GotoTagName(_Header) then
    begin
      exit;
    end;
    if not GotoTagName(_SecurityInfo) then
    begin
      exit;
    end;

    // scan the whole file
    while not EOF do
    begin

      // get the next tag
      NextTag;

      // check if the tag has the MustUnderstand attribute
      if TagAttributeValue[_mustUnderstand] = '1' then
      begin
        Result := auth_MalformedSoap;
        continue;
      end;

      // look for a tag with the Freshness attribute
      if TagAttributeValue[_Id] = _Freshness then
      begin

        // increment the tag count
        Inc(lFreshnessCount);

        // don't allow multiple freshness blocks
        if lFreshnessCount > 1 then
        begin
          Result := auth_MalformedSoap;
        end;

        // get the freshness digest tag
        if TagName = _Freshness then
        begin
          // add the digest to the parameter list
          fSoapDSigParameters.Add(Format(_equals,
            [_Freshness, BinaryToBase64(
            TSecUtils.StringToHash(FullTagValue, fCryptoProvider))]));
        end
        else
        begin
          Result := auth_MalformedSoap;
        end;

        continue;
      end;

      // get the LifeTimeSequenceBase tag
      if TagName = _LifeTimeSequenceBase then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, TagValue]));
        continue;
      end;

      // get the SequenceBase tag
      if TagName = _SequenceBase then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, TagValue]));
        continue;
      end;

      // get the SequenceNumber tag
      if TagName = _SequenceNumber then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, TagValue]));
        continue;
      end;

      // get the ControlURL tag
      if TagName = _ControlURL then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, TagValue]));
        continue;
      end;

      // get any transported certificates
      if TagName = _UPnPData then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, TagValue]));
        continue;
      end;

      // get the Signature tag in its entirety
      if TagName = _dsSignature then
      begin

        // add it to the parameter list
        fSoapDSigParameters.Add(Format(_equals, [TagName, FullTagValue]));
        continue;
      end;

      // look for a SignedInfo tag
      if TagName = _dsSignedInfo then
      begin

        // increment the tag count
        Inc(lSignedInfoCount);

        // don't allow multiple <SignedInfo> tags
        if lSignedInfoCount > 1 then
        begin
          Result := auth_MalformedSoap;
        end;

        continue;
      end;

      // look for a tag with the Body attribute
      if TagAttributeValue[_Id] = _Body then
      begin

        // increment the tag count
        Inc(lBodyCount);

        // don't allow multiple body blocks
        if lBodyCount > 1 then
        begin
          Result := auth_MalformedSoap;
        end;

        // get the body digest
        if TagName = _Body then
        begin
          // add it to the parameter list
          fSoapDSigParameters.Add(Format(_equals,
            [_Body, BinaryToBase64(
            TSecUtils.StringToHash(FullTagValue, fCryptoProvider))]));
        end
        else
        begin
          Result := auth_MalformedSoap;
        end;

        // the body comes last, so we can break rather than continue
        break;
      end;
    end;
  end;
end;

function TUPnP_DeviceSecurity.CheckDsigAuthorisation(aCaller: TUPnP_Component;
  aRequest: TUPnP_XMLStream): TUPnP_AuthorisationResult;
{
  Check the xml dsig authorisation and permissions etc.
  Status: FULLY TESTED
}
var
  lSigObject: TUPnP_DigitalSignature;
  lSigDirection: TUPnP_KeyDirection;
  lSessionKey: TUPnP_Session;
  lSeqNum: integer;
begin
  { TODO -oAFG -creminder : maybe insert canonicalization code }

  // clear the output parameter list
  fSoapDSigParameters.Clear;

  // get the dsig parameters
  Result := fGetDSigParameters(aRequest);

  // and exit if the Soap was malformed
  if Result <> auth_Accepted then
  begin
    exit;
  end;

  with fSoapDSigParameters do
  begin

    // no parameters found => invalid header
    if Count = 0 then
    begin
      Result := auth_MalformedSoap;
    end
    else
    begin

      // check if a signature object exists
      if Values[_dsSignature] = '' then
      begin
        Result := auth_MalformedSoap;
      end
      else
      begin

        // compare the ControlURL parameter with the calling service's ControlURL
        if not SameText(Values[_ControlURL], fGetFullControlURL(aCaller)) then
        begin
          Result := auth_BadControlURL;
        end
        else
        begin

          // check the signing direction
          if Values[_fromDevice] <> '' then
          begin
            lSigDirection := fromDevice;
          end
          else
          begin
            lSigDirection := toDevice;
          end;

          // if so, then create a signature object, and have it validate the signature
          lSigObject := TUPnP_DigitalSignature.Create(self,
            Values[_dsSignature], fSessions, fSoapDSigParameters,
            lSigDirection, SoapDigestCallBack, Result, lSessionKey);
          try
            if Result = auth_Accepted then
            begin

              // if the signature used a session key then check its sequencebase
              //  and sequence number
              if Assigned(lSessionKey) then
              begin
                // compare the SequenceBase parameter with the session key's sequence base
                if Values[_SequenceBase] <> lSessionKey.fSequenceBase then
                begin
                  Result := auth_WrongSequenceNumber;
                end
                else
                begin

                  // get the SequenceNumber parameter
                  lSeqNum := StrToIntDef(Values[_SequenceNumber], -1);

                  // compare the SequenceNumber parameter with the session key's sequence number
                  if lSeqNum < lSessionKey.fCPSequenceNumber then
                  begin
                    Result := auth_WrongSequenceNumber;
                  end
                  else
                  begin
                    // catch up the session key sequence number
                    lSessionKey.fCPSequenceNumber := lSeqNum;
                  end;
                end;
              end
              else
              begin
                // otherwise we must have used an RSA key so compare the SequenceBase
                //  parameter with the lifetimesequence base
                if Values[_LifeTimeSequenceBase] <> fLifetimeSequenceBase.fValue then
                begin
                  Result := auth_WrongSequenceNumber;
                end;
              end;
            end;

          finally
            lSigObject.Free;
          end;

          // exit if the DSig failed
          if Result <> auth_Accepted then
          begin
            exit;
          end;

          // cache any transported certificates
          if Values[_UPnPData] <> '' then
          begin
            CacheCertificates(Values[_UPnPData]);
          end;

          // if we are using a session key then we need to add the owners key hash to the parameter list
          if Assigned(lSessionKey) then
          begin
            fSoapDSigParameters.Add(Format(_equals, [_KeyHash, lSessionKey.Owner]));
          end;

          // and finally we must check the permissions using that hash...
          if not fVerifyPermissions(aCaller, Values[_keyHash]) then
          begin
            Result := auth_InsufficientPermissions;
          end;
        end;
      end;
    end;
  end;
end;

procedure TUPnP_DeviceSecurity.CertDigestCallBack(anURI: string; out aDigest: string);
{
  Callback function that is called by the Signature object to return the DSig digests on certificates
  Status: FULLY TESTED
}
begin
  aDigest := fCertDSigParameters.Values[anURI];
end;

procedure TUPnP_DeviceSecurity.SoapDigestCallBack(anURI: string; out aDigest: string);
{
  Callback function that is called by the Signature object to return the DSig
  digests on Soap calls
  Status: FULLY TESTED
}
begin
  aDigest := fSoapDSigParameters.Values[anURI];
end;

function TUPnP_DeviceSecurity.fCheckAuthorised(aSubjectType: TUPnP_Subject_Type;
  aSubjectString: string; aPermissionCollection: TUPnP_SecurityPermissionCollection;
  aCheckDelegates: boolean): boolean;
{
  Check if a certificate is authorised
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // preset the result to false
  Result := False;

  // check the owners list
  for i := 0 to pred(fSecurityOwners.Count) do
  begin

    // check for intersections -- all intersections in the owners list are authorised
    if fSecurityOwners.Entry[i].IntersectsWith(aSubjectType, aSubjectString,
      aPermissionCollection, False) then
    begin
      Result := True;
      break;
    end;
  end;

  if Result then
  begin
    exit;
  end;

  // check the ACL
  for i := 0 to pred(fACLentries.Count) do
  begin

    // check for intersections
    if fACLentries.Entry[i].IntersectsWith(aSubjectType, aSubjectString,
      aPermissionCollection, aCheckDelegates) then
    begin

      // if the intersection is not a named group, it is directly authorized
      if fACLentries.Entry[i].fIssuerType <> st_Name then
      begin
        Result := True;
        break;
      end
      else
      begin
        // recursively call fCheckAuthorised on the intersecting (parent) entry
        if fCheckAuthorised(fACLentries.Entry[i].fIssuerType,
          fACLentries.Entry[i].fIssuerString, aPermissionCollection, True) then
        begin
          Result := True;
          break;
        end;
      end;
    end;
  end;

  if Result then
  begin
    exit;
  end;

  // check the certificate list
  for i := 0 to pred(fCertificates.Count) do
  begin

    // check for intersections
    if fCertificates.Entry[i].IntersectsWith(aSubjectType, aSubjectString,
      aPermissionCollection, aCheckDelegates) then
    begin

      // and recursively call fCheckAuthorised on the intersecting (parent) entry
      if fCheckAuthorised(fCertificates.Entry[i].fIssuerType,
        fCertificates.Entry[i].fIssuerString, aPermissionCollection, True) then
      begin
        Result := True;
        break;
      end;
    end;
  end;
end;

function TUPnP_DeviceSecurity.fRandomString: string;
{
  Returns a random hash in base 64
  Status: FULLY TESTED
}
begin
  // create a random number hash based on date and time
  Result := BinaryToBase64(TSecUtils.StringToHash(
    DateTimeToStr(Now), fCryptoProvider));
end;

function TUPnP_DeviceSecurity.fVerifyPermissions(aCaller: TUPNP_Component;
  anOwnerPKHash: string): boolean;
{
  Verify the permissions
  Status: PARTLY TESTED
}
begin
  // if the caller is an action
  if aCaller is TUPnP_Action then
  begin

    // check if the target does not require authorisation,
    //  or has the necessary authorisation
    Result := (not TUPnP_Action(aCaller).RequiresAuthorisation) or
      fCheckAuthorised(st_Key, anOwnerPKHash,
      TUPnP_Action(aCaller).SecurityPermissions, False);
  end
  else
  begin
    // if the caller is a variable
    if aCaller is TUPnP_StateVariable then
    begin
      // check if the target does not require authorisation, or has the necessary authorisation
      Result := (not TUPnP_StateVariable(aCaller).RequiresAuthorisation) or
        fCheckAuthorised(st_Key, anOwnerPKHash,
        TUPnP_StateVariable(aCaller).SecurityPermissions, False);
    end
    else
    begin
      Result := False;
    end;
  end;
end;

function TUPnP_DeviceSecurity.fGetFullControlURL(aCaller: TUPnP_Component): string;
{
  Gets the fully expanded control URL if possible
  Status: FULLY TESTED
}
begin
  // preset the result
  Result := ControlURL;

  // if the caller is an action
  if aCaller is TUPnP_Action then
  begin

    // type cast the caller as an action
    with aCaller as TUPnP_Action do

      // check if we can backtrack up through owner service to owner device to the root device
    begin
      if Assigned(OwnerService) and
        Assigned(OwnerService.OwnerDevice) and
        Assigned(OwnerService.OwnerDevice.RootDevice) then

        // if so then we can get the full URL
      begin
        Result := OwnerService.OwnerDevice.RootDevice.URLBase + ControlURL;
      end;
    end;
  end
  else
  begin
    // if the caller is a variable
    if aCaller is TUPnP_StateVariable then
    begin
      // type cast the caller as a variable
      with aCaller as TUPnP_StateVariable do
      begin
        // check if we can backtrack up through owner service to owner device
        //  to the root device
        if Assigned(OwnerService) and
          Assigned(OwnerService.OwnerDevice) and
          Assigned(OwnerService.OwnerDevice.RootDevice) then
        begin
          // if so then we can get the full URL
          Result := OwnerService.OwnerDevice.RootDevice.URLBase + ControlURL;
        end;
      end;
    end;
  end;
end;

procedure TUPnP_DeviceSecurity.Sign(aCaller: TUPnP_Component;
  aBody: TUPnP_XMLStream; out aSecurityInfo: TUPnP_XMLStream);
{
  Create the signature
  Status: FULLY TESTED
}
var
  aWorkingBuf:  TUPnP_XMLStream;
  freshnessDigest: string;
  bodyDigest:   string;
  signatureValue: string;
  session:      TUPnP_Session;
  sigDirection: TUPnP_KeyDirection;
begin
  // create some buffers
  aSecurityInfo := TUPnP_XMLStream.Create;
  aWorkingBuf   := TUPnP_XMLStream.Create;
  try

    // check if there is a valid parameter list
    if fSoapDSigParameters.Count > 0 then

      // if so, then try to look up the respective session key; returns nil if none found
    begin
      session := fSessions.Session[StrToIntDef(
        fSoapDSigParameters.Values[_KeyName], -1)];
    end
    else
    begin
      // no parameter list, no session...
      session := nil;
    end;

    // use the working buffer
    with aWorkingBuf do
    begin

      // if we have a valid session
      if session <> nil then
      begin

        // then create a session key freshness block
        WriteTagStartAndAttributes(_Freshness, [_FreshnessAttrs]);
        WriteTagAndValue(_SequenceBase, session.fSequenceBase);
        WriteTagAndValue(_SequenceNumber, IntToStr(session.fDeviceSequenceNumber));
        WriteTagEnd(_Freshness);

        // we have "used" this sequence number, so bump it in preparation for the next call
        Inc(session.fDeviceSequenceNumber);
      end
      else
      begin
        // otherwise create a PK freshness block
        WriteTagStartAndAttributes(_Freshness, [_FreshnessAttrs]);
        WriteTagAndValue(_LifeTimeSequenceBase, fLifetimeSequenceBase.Value);
        WriteTagEnd(_Freshness);

        // we have "used" this lifetime sequence base,
        //  so bump it in preparation for the next call
        fLifetimeSequenceBase.fValue := fRandomString;
      end;

      // reset the parser
      ResetParser;

      // and get the digest of the newly created freshness block
      freshnessDigest := BinaryToBase64(
        TSecUtils.StringToHash(FullTagValue, fCryptoProvider));
    end;

    // use the security info buffer
    with aSecurityInfo do
    begin

      // write the security info tag
      WriteTagStartAndAttributes(_SecurityInfo, [_DevSecAttrs]);

      // write the freshness block
      if session <> nil then
      begin
        WriteStream(aWorkingBuf);
      end;
    end;

    // use the body info buffer
    with aBody do
    begin

      // reset the parser
      ResetParser;

      // get the digest of the body block
      bodyDigest := BinaryToBase64(
        TSecUtils.StringToHash(FullTagValue, fCryptoProvider));
    end;

    // use the working buffer
    with aWorkingBuf do
    begin

      // clear it
      Clear;

      // create the signed info block
      WriteTagStartAndAttributes(_dsSignedInfo, [_dsSignatureXmlNS]);

      // write the canonicalization method in canonical form
      WriteTagStartAndAttributes(_dsCanonicalMethod, [_dsCanonicalAlgorithm]);
      WriteTagEnd(_dsCanonicalMethod);

      // if we have a session then the signature method is hmac-sha1
      if session <> nil then
      begin
        // write in canonical form
        WriteTagStartAndAttributes(_dsSignatureMethod, [_dsSignatureAlgorithm1]);
        WriteTagEnd(_dsSignatureMethod);
      end
      else
      begin
        // otherwise we use rsa-sha1 (write in canonical form)
        WriteTagStartAndAttributes(_dsSignatureMethod, [_dsSignatureAlgorithm2]);
        WriteTagEnd(_dsSignatureMethod);
      end;

      // write the body digest
      WriteTagStartAndAttributes(_dsReference,
        [Format(_dsReferenceURIAttr, [_BodyReference])]);

      // write the transforms tag
      WriteTagStart(_dsTransforms);
      WriteTagStartAndAttributes(_dsTransform, [_dsCanonicalAlgorithm]);
      WriteTagEnd(_dsTransform);
      WriteTagEnd(_dsTransforms);

      // write the digest method in canonical form
      WriteTagStartAndAttributes(_dsDigestMethod, [_dsDigestAlgorithm]);
      WriteTagEnd(_dsDigestMethod);

      WriteTagAndValue(_dsDigestValue, bodyDigest);
      WriteTagEnd(_dsReference);

      // if we have a session then write the sequence digest
      if session <> nil then
      begin
        WriteTagStartAndAttributes(_dsReference,
          [Format(_dsReferenceURIAttr, [_FreshnessReference])]);

        // write the transforms tag
        WriteTagStart(_dsTransforms);
        WriteTagStartAndAttributes(_dsTransform, [_dsCanonicalAlgorithm]);
        WriteTagEnd(_dsTransform);
        WriteTagEnd(_dsTransforms);

        // write the digest method in canonical form
        WriteTagStartAndAttributes(_dsDigestMethod, [_dsDigestAlgorithm]);
        WriteTagEnd(_dsDigestMethod);

        WriteTagAndValue(_dsDigestValue, freshnessDigest);
        WriteTagEnd(_dsReference);
      end;

      // close the block
      WriteTagEnd(_dsSignedInfo);

      // reset the parser
      ResetParser;

      // if we have a session
      if session <> nil then
      begin

        // get the signing direction
        if fSoapDSigParameters.Values[_toDevice] <> '' then
        begin
          sigDirection := toDevice;
        end
        else
        begin
          sigDirection := fromDevice;
        end;

        // sign the signed info with the respective session key
        signatureValue := BinaryToBase64(
          TSecUtils.CreateHMACDigest(session.Key[signing, sigDirection].KeyValue,
          FullTagValue,
          fCryptoProvider));
      end
      else
      begin
        // otherwise sign it with with the public key
        signatureValue := BinaryToBase64(fPrivateKey.Sign(FullTagValue));
      end;
    end;

    // use the security info buffer
    with aSecurityInfo do
    begin

      // write the signature opening tag
      WriteTagStartAndAttributes(_dsSignature, [_dsSignatureXmlNS]);

      // write the signed info
      WriteStream(aWorkingBuf);

      // write the signature value
      WriteTagAndValue(_dsSignatureValue, signatureValue);

      // write the key info
      WriteTagStart(_dskeyInfo);

      // if we have a session then write the session key ID
      if session <> nil then
      begin
        WriteTagAndValue(_KeyName, IntToStr(session.fDeviceKeyID));
      end
      else
      begin
        // otherwise write the public key data
        // write the KeyValue tag
        WriteTagStart(_KeyValue);
        // write the public key data
        fPrivateKey.SaveToXML(aSecurityInfo);
        // write the KeyValue end tag
        WriteTagEnd(_KeyValue);
      end;

      // write the key info end tag
      WriteTagEnd(_dskeyInfo);

      // write the signature end tag
      WriteTagEnd(_dsSignature);

      // write the closing security info tag
      WriteTagEnd(_SecurityInfo);
    end;

  finally
    // free the working buffer
    aWorkingBuf.Free;
    // always clean up the output parameter list after use
    fSoapDSigParameters.Clear;
  end;
end;

function TUPnP_DeviceSecurity.OnGetACLSizes
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Actualise the number of free entries in the lists
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT        no         The ACL size
  1    OUT        no         The free ACL size
  2    OUT        no         The Owner List size
  3    OUT        no         The free Owner List size
  4    OUT        no         The Certificate Cache size
  5    OUT        no         The free Certificate Cache size
}
begin
  // no need to set up the 'Total' variables since they were fixed on initialisation
  //  i.e. just return 'true'
  Result := True;
end;

function TUPnP_DeviceSecurity.CacheCertificates(aCertSequence: string): boolean;
{
  Add transported certificates to our certificate cache
  Status: NOT TESTED
}
var
  lCertificate: string;
  cert: TUPnP_ACL_Entry;
  buf:  TUPnP_XMLStream;
begin
  Result := False;

  // create a buffer
  buf    := TUPnP_XMLStream.Create;
  try
    with buf do
    begin
      // write the certificate sequence into the buffer
      WriteValues([aCertSequence]);

      // reset the parser
      ResetParser;
      if TagName = _sequence then
      begin
        Result := True;
        while not EOF do
        begin
          NextTag;
          if TagName = _cert then
          begin
            lCertificate := FullTagValue;
          end;
          if (TagName = _dsSignature) and (lCertificate <> '') then
          begin
            cert := CreateCertificate(lCertificate, FullTagValue);
            if cert <> nil then
            begin
              fCertificates.Add(cert);
            end;
            lCertificate := '';
          end;
        end;
      end;
    end;
  finally
    fFreeCertCacheSize.fValue := IntToStr(maxCache - fCertificates.Count);
    buf.Free;
  end;
end;

function TUPnP_DeviceSecurity.OnCacheCertificate
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Status: NOT TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The to be cached certificate(s) in XML
}
begin
  // get the certs from argument [0]-- remove the escaping from the argument and call
  // CacheCertificates
  Result := CacheCertificates(EscapedToXml(Caller.Arguments[0].Value));

  if not Result then
  begin
    // set up the return error codes
    ErrorCode    := SOAP_Error[err_Action_Failed, code];
    ErrorMessage := SOAP_Error[err_Action_Failed, desc];
  end;
end;

function TUPnP_DeviceSecurity.CreateCertificate(aCertificate, aSignature:
  string): TUPnP_ACL_Entry;
{
  Create a certificate
  Status: NOT TESTED
}
var
  lCertBuf: TUPnP_XMLStream;
  lCert:    TUPnP_ACL_Entry;
  lSig:     TUPnP_DigitalSignature;
  lSessionKey: TUPnP_Session;
  lAuthResult: TUPnP_AuthorisationResult;
  lID:      string;
begin
  Result := nil;

  // create a buffer for the certificate XML
  lCertBuf := TUPnP_XMLStream.Create;
  try
    lCertBuf.WriteValues([aCertificate]);

    // look for the id attribute, and if found get the digest, and add it to the
    // parameter list
    lCertBuf.ResetParser;

    lID := lCertBuf.TagAttributeValue[_id];
    if lID <> '' then
    begin
      fCertDSigParameters.Add(Format(_equals,
        [lID, BinaryToBase64(TSecUtils.StringToHash(
        aCertificate, fCryptoProvider))]));
    end;

    // try to create a certificate object from the certificate XML
    lCertBuf.ResetParser;
    lCertBuf.NextTag;
    lCert := TUPnP_ACL_Entry.CreateFromCertXML(self, lCertBuf);
    try
      if lCert.fStatusOk then
      begin

        // create a DSig from the signature argument
        lSig := TUPnP_DigitalSignature.Create(self, aSignature,
          fSessions, fCertDSigParameters, toDevice,
          CertDigestCallBack, lAuthResult, lSessionKey);

        lSig.Free;

        if lAuthResult = auth_Accepted then
        begin
          Result := lCert;
        end;

      end;
    finally
      if Result = nil then
      begin
        lCert.Free;
      end;
    end;
  finally
    lCertBuf.Free;
    fCertDSigParameters.Clear;
  end;
end;

function TUPnP_DeviceSecurity.OnGetDefinedPermissions
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Return an xml segment with <permissions> ... </permissions>
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The permissions in XML
}
var
  buf: TUPnP_XMLStream;
  i:   integer;
begin
  // create a buffer
  buf := TUPnP_XMLStream.Create;
  try

    // write the permissions start tag with the owning device's namespace
    buf.WriteTagStartAndAttributes(_permissions,
      [Format(_PermsNamespaceFmt, [fOwnerDevice.Manufacturer])]);

    for i := 0 to pred(SecurityPermissions.Count) do
    begin
      SecurityPermissions.SecurityPermission[i].SaveToXML(buf);
    end;

    // write the permissions end tag
    buf.WriteTagEnd(_permissions);

    // escape the resulting xml and put it in the return argument [0]
    Caller.Arguments[0].Value := XmlToEscaped(buf.AsText);

  finally

    // free the buffer
    buf.Free;
  end;
  // always return true = success
  Result := True;
end;

function TUPnP_DeviceSecurity.OnGetDefinedProfiles
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Return an empty xml segment with <profiles/>
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The profiles in XML
}
var
  buf: TUPnP_XMLStream;
begin
  // create a buffer
  buf := TUPnP_XMLStream.Create;
  try

    // write an empty tag
    buf.WriteTagStartAndAttributes(_profiles,
      [Format(_PermsNamespaceFmt, [fOwnerDevice.Manufacturer])]);
    buf.WriteTagEnd(_profiles);

    // escape the resulting xml and put it in the return argument [0]
    Caller.Arguments[0].Value := XmlToEscaped(buf.AsText);
  finally

    // free the buffer
    buf.Free;
  end;

  // always return true = success
  Result := True;
end;

function TUPnP_DeviceSecurity.OnWriteACL
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Create a full new ACL from an XML string in fA_ARG_TYPE_String
  Note: fACLVersion is also returned
  Status:  PARTLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to be replaced
  2    OUT/RET    no         New version number after the change
}
var
  newACLentries: TUPnP_AuthList;
  entry: TUPnP_ACL_Entry;
  buf:   TUPnP_XMLStream;
  err:   TSOAPErrorCodes;
begin
  // preset result to false = fail
  Result := False;
  err    := err_Action_Failed;

  with Caller do
  begin
    // check if we are referring to the correct version
    if Arguments[0].Value = fACLVersionValue then
    begin

      // create a buffer
      buf := TUPnP_XMLStream.Create;
      try
        try

          // get the acl from argument [1]-- remove the escaping from the argument and
          // write it into the buffer
          buf.WriteValues([EscapedToXml(Caller.Arguments[1].Value)]);

          // reset the parser
          buf.ResetParser;
          buf.NextTag;

          // read the new ACL
          newACLentries := TUPnP_AuthList.Create;
          Result := True;

          while buf.TagName = _entry do
          begin
            // create the entry from the stream
            entry := TUPnP_ACL_Entry.CreateFromAclXml(buf);
            if (entry <> nil) and (newACLentries.Count < maxACL) then
            begin
              // add it to the list
              newACLentries.Add(entry);
              Result := True;
              buf.NextTag;
            end
            else
            begin
              err    := err_Insufficient_Memory;
              Result := False;
              break;
            end;
          end;

          if Result then
          begin
            // delete the existing entries
            fACLEntries.Free;

            fACLEntries := newACLentries;

            // change the ACL version
            fACLVersionValue := fRandomString;

            // return the ACL version in Argument[2]
            Caller.Arguments[2].Value := fACLVersionValue;

            // adjust the ACL size
            fFreeACLSize.Value := IntToStr(maxACL - fACLentries.Count);

            exit;
          end;

        except

          // bad index number  => return an error code
          on Exception do
            err := err_Argument_Value_Invalid;
        end;

      finally
        buf.Free;
      end;

    end
    else
    begin
      // wrong version number => return an error code
      err := err_Incorrect_ACL_Version;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnReadACL
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Get the full ACL as an XML string in fA_ARG_TYPE_String
  Note: fACLVersion is also returned
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    no         The actual version of the ACL being returned
  1    OUT        yes        The full ACL in XML
}
var
  buf: TUPnP_XMLStream;
begin
  // create a buffer
  buf := TUPnP_XMLStream.Create;
  try

    // save the ACL to the buffer
    buf.WriteTagStart(_ACL);
    fACLentries.SaveToXML(buf);
    buf.WriteTagEnd(_ACL);

    // return the ACL version in Argument[0]
    Caller.Arguments[0].Value := fACLVersionValue;

    // return the ACL in Argument[1]
    Caller.Arguments[1].Value := XmlToEscaped(buf.AsText);
  finally

    // free the buffer
    buf.Free;
  end;

  // always return true = success
  Result := True;
end;

function TUPnP_DeviceSecurity.OnAddACLEntry
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Add a new ACL entry based on the XML in the passed parameter
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         y          XML containing the new entry
}
var
  entry: TUPnP_ACL_Entry;
  buf:   TUPnP_XMLStream;
  err:   TSOAPErrorCodes;
  i:     integer;
  found: boolean;
begin
  // preset result to false = fail
  Result := False;

  // if there is spare space in the ACL, we can proceed
  if fACLEntries.Count < maxACL then
  begin

    // create a buffer
    buf := TUPnP_XMLStream.Create;
    try

      // remove the escaping from the argument and write it into the buffer
      buf.WriteValues([EscapedToXml(Caller.Arguments[0].Value)]);

      // reset the parser
      buf.ResetParser;

      try

        // try to create an ACL entry
        entry := TUPnP_ACL_Entry.CreateFromAclXml(buf);

        // check if the entry is good
        if entry.fStatusOk then
        begin

          // preset a 'found' flag
          found := False;

          // if the entry refers to a specific owner
          if entry.fSubjectType in [st_key, st_Name] then
          begin

            // loop through the existing list
            for i := 0 to pred(fACLEntries.Count) do
              // check for duplicate entries
            begin
              if (fACLEntries.Entry[i].fSubjectType = entry.fSubjectType) and
                (fACLEntries.Entry[i].fSubjectString = entry.fSubjectString) then
              begin
                found := True;
                break;
              end;
            end;

          end;

          // if no duplicates found
          if not found then
          begin

            // add the new entry to the list
            fACLEntries.Add(entry);

            // change the ACL version
            fACLVersionValue := fRandomString;

            // adjust the ACL size
            fFreeACLSize.Value := IntToStr(maxACL - fACLentries.Count);

            // return true = success and exit
            Result := True;
            exit;
          end
          else
          begin
            // the entry already exists, so return an error code
            err := err_ACL_Entry_Already_Present;

            // and free the entry
            entry.Free;
          end;
        end
        else
        begin
          // bad acl entry so return an error code
          err := err_Malformed_ACL_Entry;

          // and free the entry
          entry.Free;
        end;

      except

        // the entry was bad, so return an error code
        on Exception do
          err := err_Malformed_ACL_Entry;
      end;

    finally

      // free the buffer
      buf.Free;
    end;
  end
  else
  begin
    // trying to add more than the max limit in the ACL => return an error code
    err := err_Insufficient_Memory;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnDeleteACLEntry
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Delete the respective ACL entry
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to delete
  2    OUT/RET    no         New version number after the deletion
}
var
  i:   integer;
  err: TSOAPErrorCodes;
begin
  // preset result to false = fail
  Result := False;

  with Caller do
  begin
    // check if we are referring to the correct version
    if Arguments[0].Value = fACLVersionValue then
    begin
      try

        // get the index of the entry to be deleted
        i := StrToInt(Arguments[1].Value);

        // check if the index is within the correct range
        if (i >= 0) and (i < fACLEntries.Count) then
        begin

          // delete the entry
          fACLEntries.Delete(i);

          // change the ACL version
          fACLVersionValue := fRandomString;

          // adjust the ACL size
          fFreeACLSize.Value := IntToStr(maxACL - fACLentries.Count);

          // return the ACL version in Argument[2]
          Caller.Arguments[2].Value := fACLVersionValue;

          // return true = success and exit
          Result := True;
          exit;
        end
        else
        begin
          // invalid index number => return an error code
          err := err_ACL_Entry_Does_Not_Exist;
        end;

      except

        // bad index number  => return an error code
        on Exception do
          err := err_Argument_Value_Invalid;
      end;
    end
    else
    begin
      // wrong version number => return an error code
      err := err_Incorrect_ACL_Version;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnReplaceACLEntry
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Replace the respective entry
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to be replaced
  2    IN         yes        The new entry
  3    OUT/RET    no         New version number after the deletion
}
var
  i:     integer;
  buf:   TUPnP_XMLStream;
  entry: TUPnP_ACL_Entry;
  err:   TSOAPErrorCodes;
begin
  // preset result to false = fail
  Result := False;

  with Caller do
  begin
    // check if we are referring to the correct version
    if Arguments[0].Value = fACLVersionValue then
    begin
      try

        // get the index of the entry to be replaced
        i := StrToInt(Arguments[1].Value);

        // check if the index is within the correct range
        if (i >= 0) and (i < fACLEntries.Count) then
        begin

          // create a buffer
          buf := TUPnP_XMLStream.Create;
          try

            // write the 3rd argument into the buffer
            buf.WriteValues([EscapedToXml(Arguments[2].Value)]);

            // reset the parser
            buf.ResetParser;
            try

              // create an ACL entry and set the ACL entry data from the buffer
              entry := TUPnP_ACL_Entry.CreateFromAclXml(buf);

              // if the ACL entry was sucessfully loaded then replace the one in the ACL list
              if entry.fStatusOk then
              begin

                // delete the old entry
                fACLentries.Delete(i);

                // and add the new one
                fACLentries.Insert(i, entry);

                // change the ACL version
                fACLVersionValue := fRandomString;

                // return the ACL version in Argument[3]
                Caller.Arguments[3].Value := fACLVersionValue;

                // return true = success and exit
                Result := True;
                exit;
              end
              else
              begin
                // bad acl entry so return an error code
                err := err_Malformed_ACL_Entry;

                // and free the entry
                entry.Free;
              end;

            except
              // the entry was bad, so return an error code
              on Exception do
                err := err_Malformed_ACL_Entry;
            end;

          finally

            // free the buffer
            buf.Free;
          end;
        end
        else
        begin
          // invalid index number => return an error code
          err := err_ACL_Entry_Does_Not_Exist;
        end;

      except
        on Exception do

          // bad index number  => return an error code
          err := err_Argument_Value_Invalid;
      end;
    end

    else
    begin
      // wrong version number => return an error code
      err := err_Incorrect_ACL_Version;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnListOwners
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Returns a List of the full set of owners fA_ARG_TYPE_String
  Note: fNumberOfOwners is also returned
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    no         Number of owners in the list
  1    OUT        yes        List of owners in XML
}
var
  buf: TUPnP_XMLStream;
begin
  // create a buffer
  buf := TUPnP_XMLStream.Create;
  try

    // list the owners
    buf.WriteTagStart(_Owners);
    fSecurityOwners.SaveToXML(buf);
    buf.WriteTagEnd(_Owners);

    // and return the escaped list in Argument[1]
    Caller.Arguments[1].Value := XmlToEscaped(buf.AsText);

  finally

    // free the buffer
    buf.Free;
  end;

  // return true = success
  Result := True;
end;

function TUPnP_DeviceSecurity.OnGrantOwnership
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Add a new owner to the Security Owners list
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Algorithm used in the hash
  1    IN         yes        Hash of the key to be granted ownership
}
var
  own:    TUPnP_ACL_Entry;
  i:      integer;
  err:    TSOAPErrorCodes;
  exists: boolean;
begin
  // preset the result
  Result := False;

  with caller do
  begin

    // check if the owner list is full
    if fSecurityOwners.Count < maxOwner then
    begin

      // check if the algorithm is OK
      if SameText(Arguments[0].Value, _shaLC) then
      begin

        // check that we don't have any empty value in the 2nd argument
        with Arguments[1] do
        begin
          if Value <> '' then
          begin
            // preset an exists flag
            exists := False;

            // loop through the owners list
            for i := 0 to pred(fSecurityOwners.Count) do

              // check if entry already exists
            begin
              if fSecurityOwners.Entry[i].fSubjectString = Value then
              begin

                // and if so, set the flag and break
                exists := True;
                break;
              end;
            end;

            // if the entry does not exist
            if not exists then
            begin

              // everything is OK so create a new owner entry and set the hash value
              own := TUPnP_ACL_Entry.CreateFromHash(Value);

              // and add it to the list
              fSecurityOwners.Add(own);

              // update the number of owners
              fNumberOfOwners.Value := IntToStr(fSecurityOwners.Count);

              // update the free owner list size
              fFreeOwnerListSize.Value := IntToStr(maxOwner - fSecurityOwners.Count);

              // return true = success and exit
              Result := True;
              exit;
            end
            else
            begin
              // entry already exists so return an error
              err := err_Owner_Already_Present;
            end;
          end
          else
          begin
            // trying to add an empty hash
            err := err_Argument_Value_Invalid;
          end;
        end;
      end
      else
      begin
        // the algorithm is not supported => return an error code
        err := err_Algorithm_Not_Supported;
      end;
    end
    else
    begin
      // trying to add more than the max limit in the owners list => return an error code
      err := err_Insufficient_Memory;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnRevokeOwnership
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Remove an owner from the Security Owners list
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Algorithm used in the hash
  1    IN         yes        Hash of the key to be revoked
}
var
  i:   integer;
  err: TSOAPErrorCodes;
begin
  // preset the result
  Result := False;

  // trying to delete last entry => return an error code
  if fSecurityOwners.Count < 2 then
  begin
    err := err_Less_Than_Two_Owners;
  end
  else
  begin
    with Caller do
    begin

      // check if the algorithm is OK:
      //  if the algorithm is not supported => return an error code
      if not SameText(Arguments[0].Value, _shaLC) then
      begin
        err := err_Algorithm_Not_Supported;
      end
      else
      begin

        // check if the signature parameter list is missing
        if fSoapDSigParameters.Count = 0 then
        begin
          err := err_Signature_Malformed_or_Missing;
        end
        else
        begin
          // check if trying to delete self, if so then return an error
          if Arguments[1].Value = fSoapDSigParameters.Values[_keyHash] then
          begin
            err := err_May_Not_Delete_Self;
          end
          else
          begin

            // loop through the whole list to check if such an entry exists
            for i := 0 to pred(fSecurityOwners.Count) do
            begin
              // if we find a match then delete the entry
              if fSecurityOwners.Entry[i].fSubjectString = Arguments[1].Value then
              begin

                // delete it
                fSecurityOwners.Delete(i);

                // update the number of owners
                fNumberOfOwners.Value := IntToStr(fSecurityOwners.Count);

                // update the free owner list size
                fFreeOwnerListSize.Value := IntToStr(maxOwner - fSecurityOwners.Count);

                // return true = success and exit
                Result := True;
                exit;
              end;
            end;

            // otherwise no entry was found, so return an error
            err := err_Owner_Does_Not_Exist;
          end;
        end;
      end;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnGetAlgorithmsAndProtocols
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Return the supported protocols
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The algorithms and protocols in XML
}
begin
  // return the pre-cooked list of algorithms and protocols
  Caller.Arguments[0].Value := XmlToEscaped(_supported);

  // return true = success
  Result := True;
end;

procedure TUPnP_DeviceSecurity.DoHardFactoryReset;
{
  Clear the ACL and Security Owners lists
  Status: FULLY TESTED
}
begin
  // clear the ACL
  fACLentries.Clear;

  // clear the certificates
  fCertificates.Clear;

  // clear the Security Owners List
  fSecurityOwners.Clear;

  // update the number of owners
  fNumberOfOwners.Value := IntToStr(0);

  // update the free owner list size
  fFreeOwnerListSize.Value := IntToStr(maxOwner);

  // clear the Sessions List
  fSessions.Clear;
end;

function TUPnP_DeviceSecurity.OnFactorySecurityReset
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Run a delayed call to clear other lists immediately after this method returns
  Also set flag to clear the remaining Security Owner from the owners list
  when the device shuts down
  Status: FULLY TESTED
}
begin
  Assert(assigned(fRootDevice));

  // return true = success
  Result := True;

  // set the flag
  fFactoryResetFlag := True;

  // go offline
  fRootDevice.MustGoOffline;

  // call the external event handler
  if assigned(fOnFactoryReset) then
  begin
    fOnFactoryReset(self);
  end;
end;

function TUPnP_DeviceSecurity.OnSetTimeHint
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  We don't support this function => but return OK anyway
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        A time hint
}
begin
  // return true
  Result := True;
end;

function TUPnP_DeviceSecurity.OnGetPublicKeys
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Return the public keys for the device in an XML structure
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The public keys in XML
}
var
  buf: TUPnP_XMLStream;
begin
  // preset the result
  Result := True;

  // create the output buffer
  buf := TUPnP_XMLStream.Create;
  try
    with buf do
    begin

      // write the starting tags
      WriteTagStart(_Keys);
      WriteTagStart(_key_type[Confidentiality]);

      // save the (public parts of the) private key to the IO buffer
      fPrivateKey.SaveToXML(buf);
      // write the ending tags
      WriteTagEnd(_key_type[Confidentiality]);
      WriteTagEnd(_Keys);

      // transfer the xml to the return argument
      Caller.Arguments[0].Value := XmlToEscaped(AsText);
    end;

  finally
    // free the buffer
    buf.Free;
  end;
end;

function TUPnP_DeviceSecurity.OnTakeOwnership
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Allow the first Security Console to take intial ownership of the device
  Status:  FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        HMACAlgorithm
  1    IN         yes        EncryptedHMACValue
}
var
  err:    TSOAPErrorCodes;
  own:    TUPnP_ACL_Entry;
  localHMAC, remoteHMAC: string;
  l1, l2: integer;
const
  actName = 'OnTakeOwnership';
begin
  // preset result to false = fail; and preset error
  Result := False;

  with Caller do
  begin
    try

      // no need to sign the response
      SignResponse := False;

      // check if the signature parameter list is missing
      if fSoapDSigParameters.Count > 0 then
      begin
(*
      // all the max number of ownwers to make the call themselves
      if fSecurityOwners.Count < maxOwner then
*)
        // call is only permitted for the first owner
        if fSecurityOwners.Count = 0 then
        begin

          // check if the algorithm is OK: if the algorithm is not supported => return an error code
          if SameText(Arguments[0].Value, _alg_Id[alg_SHA1_HMAC]) then
          begin

            // calculate the local HMAC
            localHMAC := TSecUtils.CreateHMACDigest(secret,
              fSoapDSigParameters.Values[_RSAKeyValue] +
              fPrivateKey.AsString + fLifetimeSequenceBase.Value,
              fCryptoProvider);

            // the 2nd argument is the CP's (remote) HMAC -- encrypted
            remoteHMAC := fPrivateKey.Decrypt(
              Base64ToBinary(Arguments[1].Value));

            // the remote hmac may be pre-padded so we only need the end of it
            l1 := length(remoteHMAC);
            l2 := length(localHMAC);
            if l1 > l2 then
            begin
              remoteHMAC := Copy(remoteHMAC, 1 + l1 - l2, l2);
            end;

            if localHMAC = remoteHMAC then
            begin

              // everything is OK so create the new owner entry and set the hash value
              own := TUPnP_ACL_Entry.CreateFromHash(
                fSoapDSigParameters.Values[_keyHash]);

              // and add it to the list
              fSecurityOwners.Add(own);

              // update the number of owners
              fNumberOfOwners.Value := IntToStr(fSecurityOwners.Count);

              // update the free owner list size
              fFreeOwnerListSize.Value := IntToStr(maxOwner - fSecurityOwners.Count);

              // we have "used" this lifetime sequence base, but the spec says we need
              // not do a PK signature i.e. we may miss bumping it during the PK Sign
              // action ==> so we need to artificially bump it here...
              // (no harm if it is done twice)
              fLifetimeSequenceBase.fValue := fRandomString;

              // return true = success and exit
              Result := True;
              exit;
            end
            else
            begin
              // malformed ownership claim
              err := err_Malformed_Ownership_Claim;
            end;

          end
          else
          begin
            // algorithm not supported
            err := err_Algorithm_Not_Supported;
          end;
        end
        else
        begin
          // already owned => return an error
          err := err_Device_Already_Owned;
        end;
      end
      else
      begin
        // no parameter list i.e. signature missing
        err := err_Signature_Malformed_or_Missing;
      end;

    except
      on E: Exception do
        err := err_Action_Failed;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnSetSessionKeys
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Create a new set of session keys
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Enciphered bulk key
  1    IN         yes        Bulk Algorithm of the session key
  2    IN         yes        Cipher text of the XML with the session key data
  3    IN         yes        Id of the Control Point
  4    OUT        yes        ID of the session key created
  5    OUT        yes        Base for action sequencing
}
var
  claim:   TUPnP_XMLStream;
  sess:    TUPnP_Session;
  plaintext: string;
  err:     TSOAPErrorCodes;
  SessKey: TUPnP_SessionKey;
begin
  // preset result to false = fail
  Result := False;
  err    := err_Action_Failed;

  with Caller do
  begin

    // check if the signature parameter list is missing
    if fSoapDSigParameters.Count = 0 then
    begin
      err := err_Signature_Malformed_or_Missing;
    end
    else
    begin
      try

        // check that the algorithm ID matches
        if Arguments[1].Value <> _alg_id[alg_AES_128] then
        begin
          err := err_Algorithm_Not_Supported;
        end
        else
        begin

          // create a session key from the enciphered bulk key
          SessKey := TUPnP_SessionKey.CreateFromEncipheredBulkKey(
            fCryptoProvider, fPrivateKey, Base64ToBinary(
            Arguments[0].Value));

          // check if we got a key
          if not Assigned(SessKey) then
          begin
            err := err_Argument_Value_Invalid;
          end
          else
          begin
            try
              // Decrypt the  claim
              plaintext := SessKey.Decrypt(Base64ToBinary(
                Arguments[2].Value));

            finally
              // free the session key
              SessKey.Free;
            end;

            // create an xml IO buffer
            claim := TUPnP_XMLStream.Create;
            try
              try

                // put the plaintext in an IO buffer
                claim.WriteValues([plaintext]);

                // reset the parser
                claim.ResetParser;

                // set the Session entry data from the buffer
                sess := TUPnP_Session.CreateFromXML(self, claim);

                // store the CP Key ID (default to -1 in case of error)
                sess.fCPKeyID := StrToIntDef(Arguments[3].Value, -1);

                // store the callers hash
                sess.fOwnerPKHashB64 := fSoapDSigParameters.Values[_keyHash];

                // add it to the Session list
                fSessions.Add(sess);

                // return the device session key ID integer
                Arguments[4].Value := IntToStr(sess.fDeviceKeyID);

                // add the session key id to the request parameter list ==> this makes the
                // response handler believe that the incoming request was signed with this key,
                // with the consequence that the response is signed with the new session key
                // rather than a PK...
                fSoapDSigParameters.Add(Format(_equals, [_KeyName, Arguments[4].Value]));

                // we have "used" this lifetime sequence base, but we won't be doing a PK signature
                // i.e. we will miss bumping it during the PK Sign action ==> so we need to
                // artificially bump it here... (no harm if it is done twice)
                fLifetimeSequenceBase.fValue := fRandomString;

                // return the sequence base string
                Arguments[5].Value := sess.fSequenceBase;

                // return true = success and exit
                Result := True;
                exit;

              except
                // bad session key claim
                err := err_Argument_Value_Invalid;
              end;

            finally
              // free the buffer
              claim.Free;
            end;
          end;
        end;

      except
        on E: Exception do
          err := err_Action_Failed;
      end;
    end;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

procedure TUPnP_DeviceSecurity.OnExpireSessionTimer(Sender: TObject);
{
  Expire the given session key
  Status: FULLY TESTED
}
begin
  Assert(Sender = fDelayedCallbackTimer);
  fDelayedCallbackTimer.Enabled := False;
  fDelayedCallbackTimer.OnTimer := nil;
  fSessions.Delete(fDelayedCallbackTimer.Tag);
  fDelayedCallbackTimer.Tag := 0;
end;

function TUPnP_DeviceSecurity.OnExpireSessionKeys
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Expire the given session key
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The ID of the key to be expired
}
var
  i, j: integer;
  err:  TSOAPErrorCodes;
begin
  // preset result to false = fail
  Result := False;
  try

    // convert the IN argument to an integer
    i := StrToInt(Caller.Arguments[0].Value);

    with fSessions do
    begin

      // scan the whole sessions list
      for j := 0 to pred(Count) do
      begin

        // if we find a matching entry ...
        if TUPnP_Session(Items[j]).fDeviceKeyID = i then
        begin

          // set up the callback timer to delete the respective session
          fDelayedCallbackTimer.OnTimer := OnExpireSessionTimer;
          fDelayedCallbackTimer.Tag     := j;
          fDelayedCallbackTimer.Enabled := True;

          // return true = success and exit
          Result := True;
          exit;
        end;
      end;

      // we got this far, so entry did not exist => return an error code
      err := err_Session_Key_Does_Not_Exist;
    end;

  except
    on Exception do

      // bad IN argument value  => return an error code
      err := err_Argument_Value_Invalid;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.ProcessControlRequest(Request:
  TUPnP_HTTPServerRequestWrapper;
  var Response: TUPnP_HTTPServerResponseWrapper): boolean;
{
  Store a local reference to the request and response wrappers before dispatching
  the call (we need this for the recursive HTTP call on DecryptAndExecute)
  Status: FULLY TESTED
}
begin
  fControlRequest := Request;
  fControlResponse := Response;
  Result := inherited ProcessControlRequest(Request, Response);
end;

function TUPnP_DeviceSecurity.OnDecryptAndExecute
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Decrypt the encoded SOAP action call and execute it
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The ID of the key whose session key to use
  1    IN         yes        The encrypted SOAP action call
  2    IN         yes        The input Initialization Vector
  3    OUT/RET    yes        The encrypted SOAP action return value
  4    OUT        yes        The output Initialization Vector
}
const
  actName = 'OnDecryptAndExecute';
var
  err:      TSOAPErrorCodes;
  sess:     TUPnP_Session;
  lRequest: TUPNP_IdHTTPRequestInfo;
  lResponse: TUPNP_IdHTTPResponseInfo;
  lRequestWrapper: TUPnP_HTTPServerRequestWrapper;
  lResponseWrapper: TUPnP_HTTPServerResponseWrapper;
begin
  Assert(assigned(fRootDevice));

  // preset result to false = fail; and preset an error code
  Result := False;
  err    := err_Action_Failed;

  // create a duplicate Request
  lRequest := TUPNP_IdHTTPRequestInfo.Create;
  lRequestWrapper := TUPnP_HTTPServerRequestWrapper.Create(lRequest);

  // create a duplicate Response
  lResponse := TUPNP_IdHTTPResponseInfo.Create(nil,
    fControlResponse.Response.HTTPServer);
  lResponseWrapper := TUPnP_HTTPServerResponseWrapper.Create(lResponse);

  try
    with caller do
    begin
      try

        // get the session key entry from Argument[0]
        sess := fSessions.Session[StrToIntDef(Arguments[0].Value, -1)];

        // if we have a valid session
        if sess <> nil then
        begin

          // use the the "to-device" key
          with sess.Key[confidentiality, toDevice] do
          begin

            // get the Initialization Vector from Argument[2] and convert
            // from Base64 to Binary
            InitialValue := Base64ToBinary(Arguments[2].Value);

            // get the Request from Argument[1], convert from Base64 to Binary,
            // decrypt it, and write the decrypted data to the Request
            lRequest.Text := Decrypt(Base64ToBinary(Arguments[1].Value));
          end;

          try
            // submit the request to the HTTP handler on the owner device (recursive)
            Result := fRootDevice.DoRecursiveHTTPCall(lRequestWrapper, lResponseWrapper);
          except
            // swallow exceptions
            on Exception do ;
          end;

          // use the "from-device" key
          with sess.Key[confidentiality, fromDevice] do
          begin
            // create a new random initialization vector
            NewRandomIV;

            // convert Initialization Vector from Binary to Base 64 and put in Argument[4]
            Arguments[4].Value := BinaryToBase64(InitialValue);

            // get the Response as text, encrypt it, convert it from Binary to Base 64
            // and put in Argument[3]
            Arguments[3].Value := BinaryToBase64(Encrypt(lResponse.Text));
          end;
        end;

      except
        on E: Exception do
          Result := False;
      end;
    end;

  finally
    lRequest.Free;
    lResponse.Free;
    lRequestWrapper.Free;
    lResponseWrapper.Free;
  end;

  // if we failed
  if not Result then
  begin

    // set up the return error codes
    ErrorCode    := SOAP_Error[err, code];
    ErrorMessage := SOAP_Error[err, desc];
  end;
end;

function TUPnP_DeviceSecurity.OnGetLifetimeSequenceBase
  (Caller: TUPnP_Action; var ErrorCode, ErrorMessage: string): boolean;
{
  Return the session sequence
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT        no         The session sequence
}
begin
  // returns the session sequence automatically, so return true = success
  Result := True;
end;

procedure TUPnP_DeviceSecurity.Load(aReader: TReader);
{
  Load the persistent data from the respective file / stream
  Status: FULLY TESTED
}
begin
  // free previous data
  if Assigned(fACLentries) then
  begin
    FreeAndNil(fACLentries);
  end;
  if Assigned(fCertificates) then
  begin
    FreeAndNil(fCertificates);
  end;
  if Assigned(fSecurityOwners) then
  begin
    FreeAndNil(fSecurityOwners);
  end;
  if Assigned(fSessions) then
  begin
    FreeAndNil(fSessions);
  end;
  if Assigned(fPrivateKey) then
  begin
    FreeAndNil(fPrivateKey);
  end;

  // load the various lists
  fPrivateKey   := TUPnP_PrivateKey.CreateFromStream(self, aReader);
  fSessions     := TUPnP_SessionsList.CreateFromStream(self, aReader);
  fSecurityOwners := TUPnP_AuthList.CreateFromStream(aReader);
  fACLentries   := TUPnP_AuthList.CreateFromStream(aReader);
  fCertificates := TUPnP_AuthList.CreateFromStream(aReader);
end;

procedure TUPnP_DeviceSecurity.Save(aWriter: TWriter);
{
  Save the persistent data to the respective file / stream
  Status: FULLY TESTED
}
begin
  try
    // save the various lists
    if Assigned(fPrivateKey) then
    begin
      fPrivateKey.SaveToStream(aWriter);
    end;

    if Assigned(fSessions) then
    begin
      fSessions.SaveToStream(aWriter);
    end;

    if Assigned(fSecurityOwners) then
    begin
      fSecurityOwners.SaveToStream(aWriter);
    end;

    if Assigned(fACLentries) then
    begin
      fACLentries.SaveToStream(aWriter);
    end;

    if Assigned(fCertificates) then
    begin
      fCertificates.SaveToStream(aWriter);
    end;

  finally

    // and finally flush the wite buffer
    aWriter.FlushBuffer;
  end;
end;

procedure TUPnP_DeviceSecurity.LoadStateFile;
{
  Load the object state from an encrypted file
  Status: FULLY TESTED
}
var
  aMemoryStream: TMemoryStream;
  aReader: TReader;
begin
  // check if the file name is valid, and the persistent file exists
  if (fStateFileName <> '') and FileExists(fStateFileName) then
  begin

    // create a memory stream
    aMemoryStream := TMemoryStream.Create;
    try

      // load the stream from the file
      LoadStreamFromEncryptedFile(aMemoryStream, fStateFileName,
        _Password, fCryptoProvider);

      // create an associated reader
      aReader := TReader.Create(aMemoryStream, 1024);
      try

        // load the state entries from the stream
        Load(aReader);

      finally

        // free the reader
        aReader.Free;
      end;

    finally

      // free the stream
      aMemoryStream.Free;
    end;
  end;

  // if anything was not created then create it now (e.g. ACL, Owners and Sessions lists)
  if not Assigned(fPrivateKey) then
  begin
    fPrivateKey := TUPnP_PrivateKey.CreateRandom(self);
  end;

  if not Assigned(fSessions) then
  begin
    fSessions := TUPnP_SessionsList.Create(True);
  end;

  if not Assigned(fSecurityOwners) then
  begin
    fSecurityOwners := TUPnP_AuthList.Create(True);
  end;

  if not Assigned(fACLentries) then
  begin
    fACLentries := TUPnP_AuthList.Create(True);
  end;

  if not Assigned(fCertificates) then
  begin
    fCertificates := TUPnP_AuthList.Create(True);
  end;

  // update the number of owners
  fNumberOfOwners.fValue := IntToStr(fSecurityOwners.Count);

  // set up the 'Free' variables
  fFreeACLSize.fValue := IntToStr(maxACL - fACLentries.Count);
  fFreeOwnerListSize.fValue := IntToStr(maxOwner - fSecurityOwners.Count);
  fFreeCertCacheSize.fValue := IntToStr(maxCache - fCertificates.Count);
end;

procedure TUPnP_DeviceSecurity.SaveStateFile;
{
  Save the object state to an encrypted file
  Status: FULLY TESTED
}
var
  aMemoryStream: TMemoryStream;
  aWriter: TWriter;
  H:   integer;
  dir: string;
begin
  // exit if we have a bad state file name
  if fStateFileName = '' then
  begin
    exit;
  end;

  // if the state file does not exist then create it
  if not FileExists(fStateFileName) then
  begin

    // get the file directory (path)
    dir := ExtractFilePath(fStateFileName);

    // if the directory does not exist then force it's creation
    if not DirectoryExists(dir) then
    begin
      ForceDirectories(dir);
    end;

    // create the file
    h := FileCreate(fStateFileName);

    // if we created it then close it again
    if h < 0 then
    begin
      exit;
    end
    else
    begin
      FileClose(h);
    end;
  end;

  // create a memory stream
  aMemoryStream := TMemoryStream.Create;
  try

    // create an associated writer
    aWriter := TWriter.Create(aMemoryStream, 1024);
    try

      // save the state entries to the stream
      Save(aWriter);

      // save the stream to the file
      SaveStreamToEncryptedFile(aMemoryStream, fStateFileName,
        _Password, fCryptoProvider);

    finally
      // free the writer
      aWriter.Free;
    end;

  finally
    // free the stream
    aMemoryStream.Free;
  end;
end;

procedure TUPnP_DeviceSecurity.CreateRegistryData;
{
  Create the registry entries
  Status: FULLY TESTED
}
var
  Reg:    TRegistry;
  appdir: array[0..255] of char;
begin
  // create a registry key
  Reg := TRegistry.Create;

  // set the root key
  Reg.RootKey := HKEY_LOCAL_MACHINE;
  try

    // check if the owner device exists, and that we can open the registry entry
    if Assigned(fOwnerDevice) and Reg.OpenKey(fOwnerDevice.RegistryPath, False) then
    begin

      try
        // if the security file entry does not exist then it is our first time loading
        if not Reg.ValueExists(_DevSecFile) then
        begin

          // get the pathname of the Common Application data directory
          SHGetFolderPath(0, CSIDL_COMMON_APPDATA or CSIDL_FLAG_CREATE, 0, 0, appdir);

{$warnings off}
          // create a file name in the Common Application data directory
          fStateFileName := IncludeTrailingBackslash(appdir) + _FilePath +
            Reg.ReadString(_UDN);
{$warnings on}

          // save the file name to the registry
          Reg.WriteString(_DevSecFile, fStateFileName);
        end
        else
        begin
          // otherwise retrieve the file name from the directory
          fStateFileName := Reg.ReadString(_DevSecFile);
        end;

      finally
        // close the registry key
        Reg.CloseKey;
      end;
    end
    else
    begin
      // otherwise clear the statefile name
      fStateFileName := '';
    end;

  finally

    // free the registry key
    Reg.Free;
  end;
end;

procedure TUPnP_DeviceSecurity.GetRegistryData;
{
  Read the registry entries
  Status: FULLY TESTED
}
var
  Reg: TRegistry;
begin
  // create a registry key
  Reg := TRegistry.Create;

  // set the root key
  Reg.RootKey := HKEY_LOCAL_MACHINE;
  try

    // check if the owner device exists, and that we can open the registry entry
    if Assigned(fOwnerDevice) and Reg.OpenKey(fOwnerDevice.RegistryPath, False) then
    begin
      try

        // get the file name from the directory
        if Reg.ValueExists(_DevSecFile) then
        begin
          fStateFileName := Reg.ReadString(_DevSecFile);
        end;

      finally

        // close the registry key
        Reg.CloseKey;
      end;
    end
    else
    begin
      // otherwise clear the statefile name
      fStateFileName := '';
    end;

  finally

    // free the registry key
    Reg.Free;
  end;
end;


// *********************** TUPnP_DevSec_Base ********************

constructor TUPnP_DevSec_Action.Create(AOwner: TComponent);
{
  Create the action name and set the state flags
  Status: FULLY TESTED
}
begin
  inherited;
  // the action name is the class name without the "TUPnP_DevSec_" prefix
  fActionname := Copy(ClassName, 14, length(ClassName) - 13);
end;

destructor TUPnP_DevSec_Action.Destroy;
{
  Destroy the arguments
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // iterate through the Arguments list
  for i := pred(fArguments.Count) downto 0 do
  begin

    // free the arguments
    fArguments[i].Free;

    //  and delete their references in the list
    fArguments.Delete(i);
  end;

  inherited;
end;

procedure TUPnP_DevSec_Action.fAddArgument
  (aName: string; aDirection: TUPnP_ArgumentType; aRSV: TUPnP_StateVariable);
{
  Add an argument to the Arguments list
  Status: FULLY TESTED
}
var
  arg: TUPnP_Argument;
  ci:  TCollectionItem;
begin
  // create an argument
  arg := TUPnP_Argument.Create(self);

  with arg do
  begin

    // set the argument fields
    ArgumentName := aName;
    Direction    := aDirection;
    RelatedStateVariable := aRSV;
  end;

  // add an entry to the arguments list
  ci := fArguments.Add;

  // and assign the argument to the entry
  if ci is TUPnP_CollectionItem then
  begin
    TUPnP_CollectionItem(ci).AssignComponent(arg);
  end;
end;


// *********************** TUPnP_DevSec_AddACLEntry ********************

constructor TUPnP_DevSec_AddACLEntry.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         y          XML containing the new entry
}
begin
  inherited;

  // add the argument
  fAddArgument('Entry', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_DeleteACLEntry ********************

constructor TUPnP_DevSec_DeleteACLEntry.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to delete
  2    OUT/RET    no         New version number after the deletion
}
begin
  inherited;

  // add the arguments
  fAddArgument('TargetACLVersion', Input, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);
  fAddArgument('Index', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Int);
  fAddArgument('NewACLVersion', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0..2];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_ReplaceACLEntry ********************

constructor TUPnP_DevSec_ReplaceACLEntry.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to be replaced
  2    IN         yes        The new entry
  3    OUT/RET    no         New version number after the deletion
}
begin
  inherited;

  // add the arguments
  fAddArgument('TargetACLVersion', Input, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);
  fAddArgument('Index', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Int);
  fAddArgument('Entry', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('NewACLVersion', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0..3];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_WriteACL ********************

constructor TUPnP_DevSec_WriteACL.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The version of the ACL that we are trying to work on
  1    IN         yes        Index of the entry to be replaced
  2    OUT/RET    no         New version number after the change
}
begin
  inherited;

  // add the arguments
  fAddArgument('Version', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('ACL', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('NewVersion', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0..2];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_ReadACL ********************

constructor TUPnP_DevSec_ReadACL.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    no         The actual version of the ACL being returned
  1    OUT        yes        The full ACL in XML
}
begin
  inherited;

  // add the arguments
  fAddArgument('Version', OutputRetVal, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('ACL', Output, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0..1];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_FactorySecurityReset ********************

constructor TUPnP_DevSec_FactorySecurityReset.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED
}
begin
  inherited;

  // no arguments...

  // initialize the fields
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_SetTimeHint ********************

constructor TUPnP_DevSec_SetTimeHint.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        A time hint
}
begin
  inherited;

  // add the argument
  fAddArgument('ArgTimeHint', Input, TUPnP_DeviceSecurity(aOwner).fTimeHint);

  // initialize the fields
  fDontPassArguments := [0];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_GrantOwnership ********************

constructor TUPnP_DevSec_GrantOwnership.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Algorithm used in the hash
  1    IN         yes        Hash of the key to be granted ownership
}
begin
  inherited;

  // add the arguments
  fAddArgument('HashAlgorithm', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('KeyHash', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);

  // initialize the fields
  fDontPassArguments := [0..1];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_RevokeOwnership ********************

constructor TUPnP_DevSec_RevokeOwnership.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Algorithm used in the hash
  1    IN         yes        Hash of the key to be revoked
}
begin
  inherited;

  // add the arguments
  fAddArgument('HashAlgorithm', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('KeyHash', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);

  // initialize the fields
  fDontPassArguments := [0..1];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_ListOwners ********************

constructor TUPnP_DevSec_ListOwners.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    no         Number of owners in the list
  1    OUT        yes        List of owners in XML
}
begin
  inherited;

  // add the arguments
  fAddArgument('ArgNumberOfOwners', OutputRetVal,
    TUPnP_DeviceSecurity(aOwner).fNumberOfOwners);
  fAddArgument('Owners', Output, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [1];
  fRequiresAuthorization := True;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_TakeOwnership ********************

constructor TUPnP_DevSec_TakeOwnership.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        HMACAlgorithm
  1    IN         yes        EncryptedHMACValue
}
begin
  inherited;

  // add the arguments
  fAddArgument('HMACAlgorithm', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('EncryptedHMACValue', Input, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_Base64);

  // initialize the fields
  fDontPassArguments := [0..1];
  fRequiresAuthorization := False;
  fRequiresSigning := True;
end;


// *********************** TUPnP_DevSec_GetDefinedPermissions ********************

constructor TUPnP_DevSec_GetDefinedPermissions.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The permissions in XML
}
begin
  inherited;

  // add the argument
  fAddArgument('Permissions', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
end;


// *********************** TUPnP_DevSec_GetDefinedProfiles ********************

constructor TUPnP_DevSec_GetDefinedProfiles.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The profiles in XML
}
begin
  inherited;

  // add the argument
  fAddArgument('Profiles', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
end;


// *********************** TUPnP_DevSec_GetPublicKeys ********************

constructor TUPnP_DevSec_GetPublicKeys.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The public keys in XML
}
begin
  inherited;

  // add the argument
  fAddArgument('KeyArg', OutputRetVal, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
end;


// *********************** TUPnP_DevSec_GetAlgorithmsAndProtocols ********************

constructor TUPnP_DevSec_GetAlgorithmsAndProtocols.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT/RET    yes        The algorithms and protocols in XML
}
begin
  inherited;

  // add the argument
  fAddArgument('Supported', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
end;


// *********************** TUPnP_DevSec_GetACLSizes ********************

constructor TUPnP_DevSec_GetACLSizes.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT        no         The ACL size
  1    OUT        no         The free ACL size
  2    OUT        no         The Owner List size
  3    OUT        no         The free Owner List size
  4    OUT        no         The Certificate Cache size
  5    OUT        no         The free Certificate Cache size
}
begin
  inherited;

  // add the arguments
  fAddArgument('ArgTotalACLSize', Output, TUPnP_DeviceSecurity(aOwner).fTotalACLSize);
  fAddArgument('ArgFreeACLSize', Output, TUPnP_DeviceSecurity(aOwner).fFreeACLSize);
  fAddArgument('ArgTotalOwnerListSize', Output,
    TUPnP_DeviceSecurity(aOwner).fTotalOwnerListSize);
  fAddArgument('ArgFreeOwnerListSize', Output,
    TUPnP_DeviceSecurity(aOwner).fFreeOwnerListSize);
  fAddArgument('ArgTotalCertCacheSize', Output,
    TUPnP_DeviceSecurity(aOwner).fTotalCertCacheSize);
  fAddArgument('ArgFreeCertCacheSize', Output,
    TUPnP_DeviceSecurity(aOwner).fFreeCertCacheSize);
end;


// *********************** TUPnP_DevSec_CacheCertificate ********************

constructor TUPnP_DevSec_CacheCertificate.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The to be cached certificate(s) in XML
}
begin
  inherited;

  // add the argument
  fAddArgument('Certificates', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0];
end;


// *********************** TUPnP_DevSec_SetSessionKeys ********************

constructor TUPnP_DevSec_SetSessionKeys.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        Enciphered bulk key
  1    IN         yes        Algorithm of the session key
  2    IN         yes        Cipher text of the XML with the session key data
  3    IN         yes        Id of the Control Point
  4    OUT        yes        ID of the session key created
  5    OUT        yes        Base for action sequencing
}
begin
  inherited;

  // add the arguments
  fAddArgument('EncipheredBulkKey', Input, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_Base64);
  fAddArgument('BulkAlgorithm', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);
  fAddArgument('Ciphertext', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);
  fAddArgument('CPKeyID', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Int);
  fAddArgument('DeviceKeyID', OutputRetVal, TUPnP_DeviceSecurity(
    aOwner).fA_ARG_TYPE_Int);
  fAddArgument('SequenceBase', Output, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_String);

  // initialize the fields
  fDontPassArguments := [0..5];
  fRequiresSigning   := True;

  // *** set fRequiresAuthorization to false to pass the UPnP certification tool test
  //  fRequiresAuthorization := false;
  fRequiresAuthorization := True;
end;


// *********************** TUPnP_DevSec_ExpireSessionKeys ********************

constructor TUPnP_DevSec_ExpireSessionKeys.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The ID of the key to be expired
}
begin
  inherited;

  // add the argument
  fAddArgument('DeviceKeyID', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Int);

  // initialize the fields
  fDontPassArguments := [0];
  fRequiresSigning   := True;

  // *** set fRequiresAuthorization to false to pass the UPnP certification tool test
  //  fRequiresAuthorization := false;
  fRequiresAuthorization := True;
end;


// *********************** TUPnP_DevSec_DecryptAndExecute ********************

constructor TUPnP_DevSec_DecryptAndExecute.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    IN         yes        The ID of the key whose session key to use
  1    IN         yes        The encrypted SOAP action call
  2    IN         yes        The input Initialization Vector
  3   OUT/RET     yes        The encrypted SOAP action return value
  4   OUT         yes        The output Initialization Vector
}
begin
  inherited;

  // add the arguments
  fAddArgument('DeviceKeyID', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Int);
  fAddArgument('Request', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);
  fAddArgument('InIV', Input, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);
  fAddArgument('Reply', OutputRetVal, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);
  fAddArgument('OutIV', Output, TUPnP_DeviceSecurity(aOwner).fA_ARG_TYPE_Base64);

  // initialize the fields
  fDontPassArguments := [0..4];
end;


// *********************** TUPnP_DevSec_GetLifetimeSequenceBase ********************

constructor TUPnP_DevSec_GetLifetimeSequenceBase.Create(AOwner: TComponent);
{
  Create the arguments and state variable linkages
  Status: FULLY TESTED

  ARG  Direction  DONT_PASS  Description
  0    OUT        no         The session sequence
}
begin
  inherited;

  // add the argument
  fAddArgument('ArgLifetimeSequenceBase', OutputRetVal,
    TUPnP_DeviceSecurity(aOwner).fLifetimeSequenceBase);
end;


// *********************** TUPnP_DevSec_StateVar ********************

constructor TUPnP_DevSec_StateVar.Create(aOwner: TComponent;
  aDefaultValue: string; aEvented: boolean; aDataType: TUPnP_VariableType;
  aName: string);
{
  Create the variable name and set the state flags
  Status: FULLY TESTED
}
begin
  // inherited constructor
  Create(aOwner);

  // initialize the fields
  fAllowedValues := Anything;
  fVariableName  := aName;
  fDefaultValue  := aDefaultValue;
  fdataType      := aDataType;
  fSendEvents    := aEvented;
end;


// *********************** TUPnP_ACL_Entry ********************

function TUPnP_ACL_Entry.IntersectsWith(aSubjectType: TUPnP_Subject_Type;
  aSubjectString: string; aPermissionCollection: TUPnP_SecurityPermissionCollection;
  aCheckDelegation: boolean): boolean;
{
  Check if this ACL entry can grant permission to the key or named group provided
  Status: NOT TESTED
}
var
  i: integer;
  iNowStr: string;
begin
  // preset the result
  Result := False;

  // fail if outside the validity period
  iNowStr := FormatDateTime(_dateFormat, NowGMT);
  if (fValidityStart > iNowStr) or ((fValidityEnd <> '') and
    (fValidityEnd < iNowStr)) then
  begin
    exit;
  end;

  // check the various conditions for belonging
  case fIssuerType of

    st_Name:
    begin
      // check for belonging in a named group
      Result := (fSubjectType = aSubjectType) and (fSubjectString = aSubjectString) and
        not (aCheckDelegation and fMayNotDelegate);
    end;

    st_Key:
    begin
      // reject if delegation is not allowed
      if (aCheckDelegation and fMayNotDelegate) then
      begin
        exit;
      end;

      if ((aSubjectType = st_Key) and (fSubjectType in [st_Any, st_Key])) or
        ((aSubjectType = st_Name) and (fSubjectType = st_Name)) then
      begin

        // check for <all> permissions
        if fPermissions.IndexOf(_allStar) >= 0 then
        begin
          Result := True;
        end
        else
        begin

          // check for named permissions
          if Assigned(aPermissionCollection) then
          begin
            for i := 0 to pred(aPermissionCollection.Count) do
            begin
              if fPermissions.IndexOf(
                aPermissionCollection.SecurityPermission[i].ACLentryName) >= 0 then
              begin
                Result := True;
                break;
              end;
            end;
          end;
        end;
      end;
    end;
  end;
end;

procedure TUPnP_ACL_Entry.SaveToCertXML(aBuffer: TUPnP_XMLStream;
  anIssuerRSAKey: TUPnP_PrivateKey; aDeviceHash: string);
{
  Get the ACL entry in certificate XML format
  Status: FULLY TESTED
}
var
  i:      integer;
  unique: string;
  lCertBuffer, lSigInfoBuffer: TUPnP_XMLStream;
begin
  lCertBuffer    := TUPnP_XMLStream.Create;
  lSigInfoBuffer := TUPnP_XMLStream.Create;
  try
    with lCertBuffer do
    begin
      // write the certificate start tag
      unique := anIssuerRSAKey.fDevSec.fRandomString;
      WriteTagStartAndAttributes(_cert, [Format('%s="%s"', [_Id, unique])]);

      // write the issuer
      WriteTagStart(_issuer);
      WriteTagStart(_hash);
      WriteTagAndValue(_algorithm, _shaUC);
      WriteTagAndValue(_value,
        BinaryToBase64(TSecUtils.StringToHash(
        anIssuerRSAKey.AsString,
        anIssuerRSAKey.fDevSec.fCryptoProvider)));
      WriteTagEnd(_hash);
      WriteTagEnd(_issuer);

      // write the subject
      WriteTagStart(_subject);

      // if it has a name then write the name tag start
      case fSubjectType of
        st_Name:
        begin
          WriteTagStart(_name);
          WriteTagStart(_hash);
          WriteTagAndValue(_algorithm, _shaUC);
          WriteTagAndValue(_value, fIssuerString);
          WriteTagEnd(_hash);
          WriteTagAndValue(_text, fSubjectString);
          WriteTagEnd(_name);
        end;

        st_Key:
        begin
          // write the owner's hash
          WriteTagStart(_hash);
          WriteTagAndValue(_algorithm, _shaUC);
          WriteTagAndValue(_value, fSubjectString);
          WriteTagEnd(_hash);
        end;

        st_Any:
        begin
          // if the owner is any then write it
          WriteTagAndValue(_any, '');
        end;
      end;

      // write the subject end tag
      WriteTagEnd(_subject);

      WriteTagStart(_tag);

      // write the target device infor
      WriteTagStart(_device);
      WriteTagStart(_hash);
      WriteTagAndValue(_algorithm, _shaUC);
      WriteTagAndValue(_value, aDeviceHash);
      WriteTagEnd(_hash);
      WriteTagEnd(_device);

      // write the permissions
      WriteTagStart(_access);

      // if the permission is all then write it
      if fPermissions.IndexOf(_allStar) >= 0 then
      begin
        WriteTagAndValue(_all, '');
      end
      else
      begin
        // otherwise loop throught the permissions and write them
        for i := 0 to pred(fPermissions.Count) do
        begin
          WriteTagAndValue(fPermissions.Strings[i], '');
        end;
      end;

      // write the access end tag
      WriteTagEnd(_access);

      WriteTagEnd(_tag);

      // write if delegation is not allowed
      if fMayNotDelegate then
      begin
        WriteTagAndValue(_MayNotDelegate, '');
      end;

      // if we have non zero validity dates
      if (fValidityStart <> '') or (fValidityEnd <> '') then
      begin

        // write the validity block
        WriteTagStart(_valid);
        if fValidityStart <> '' then
        begin
          WriteTagAndValue(_notbefore, fValidityStart);
        end;

        if fValidityEnd <> '' then
        begin
          WriteTagAndValue(_notafter, fValidityEnd);
        end;

        WriteTagEnd(_valid);
      end;

      // write the entry end tag
      WriteTagEnd(_cert);
    end;

    with lSigInfoBuffer do
    begin

      // create the signed info block
      WriteTagStartAndAttributes(_dsSignedInfo, [_dsSignatureXmlNS]);

      // write the canonicalization method in canonical form
      WriteTagStartAndAttributes(_dsCanonicalMethod, [_dsCanonicalAlgorithm]);
      WriteTagEnd(_dsCanonicalMethod);

      // the signature method is rsa-sha1
      WriteTagStartAndAttributes(_dsSignatureMethod, [_dsSignatureAlgorithm2]);
      WriteTagEnd(_dsSignatureMethod);

      // write the cert digest
      WriteTagStartAndAttributes(_dsReference,
        [Format(_dsReferenceURIAttr, ['#' + unique])]);

      // write the transforms tag
      WriteTagStart(_dsTransforms);
      WriteTagStartAndAttributes(_dsTransform, [_dsCanonicalAlgorithm]);
      WriteTagEnd(_dsTransform);
      WriteTagEnd(_dsTransforms);

      // write the digest method in canonical form
      WriteTagStartAndAttributes(_dsDigestMethod, [_dsDigestAlgorithm]);
      WriteTagEnd(_dsDigestMethod);

      WriteTagAndValue(_dsDigestValue,
        BinaryToBase64(TSecUtils.StringToHash(lCertBuffer.AsText,
        anIssuerRSAKey.fDevSec.fCryptoProvider)));
      WriteTagEnd(_dsReference);

      // close the block
      WriteTagEnd(_dsSignedInfo);
    end;

    with aBuffer do
    begin
      WriteValues([lCertBuffer.AsText]);

      // write the signature opening tag
      WriteTagStartAndAttributes(_dsSignature, [_dsSignatureXmlNS]);

      // write the signed info
      WriteValues([lSigInfoBuffer.AsText]);

      // write the signature value
      WriteTagAndValue(_dsSignatureValue,
        BinaryToBase64(anIssuerRSAKey.Sign(lSigInfoBuffer.AsText)));

      // write the key info
      WriteTagStart(_dskeyInfo);

      // write the KeyValue tag
      WriteTagStart(_KeyValue);

      // write the public key data
      anIssuerRSAKey.SaveToXML(aBuffer);

      // write the KeyValue end tag
      WriteTagEnd(_KeyValue);

      // write the key info end tag
      WriteTagEnd(_dskeyInfo);

      // write the signature end tag
      WriteTagEnd(_dsSignature);
    end;

  finally
    lCertBuffer.Free;
    lSigInfoBuffer.Free;
  end;
end;

procedure TUPnP_ACL_Entry.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Get the ACL entry in XML format
  Status: FULLY TESTED
}
var
  i: integer;
begin
  with aBuffer do
  begin

    // write the start tag
    WriteTagStart(_entry);

    // write the subject
    WriteTagStart(_subject);

    // if it has a name then write the name tag start
    case fSubjectType of
      st_Name:
      begin
        WriteTagStart(_name);
        WriteTagStart(_hash);
        WriteTagAndValue(_algorithm, _shaUC);
        WriteTagAndValue(_value, fIssuerString);
        WriteTagEnd(_hash);
        WriteTagAndValue(_text, fSubjectString);
        WriteTagEnd(_name);
      end;

      st_Key:
      begin
        // write the owner's hash
        WriteTagStart(_hash);
        WriteTagAndValue(_algorithm, _shaUC);
        WriteTagAndValue(_value, fSubjectString);
        WriteTagEnd(_hash);
      end;

      st_Any:
      begin
        // if the owner is any then write it
        WriteTagAndValue(_any, '');
      end;
    end;

    // write the subject end tag
    WriteTagEnd(_subject);

    // write if delegation is not allowed
    if fMayNotDelegate then
    begin
      WriteTagAndValue(_MayNotDelegate, '');
    end;

    // write the permissions
    WriteTagStart(_access);

    // if the permission is all then write it
    if fPermissions.IndexOf(_allStar) >= 0 then
    begin
      WriteTagAndValue(_all, '');
    end
    else
    begin
      // otherwise loop throught the permissions and write them
      for i := 0 to pred(fPermissions.Count) do
      begin
        WriteTagAndValue(fPermissions.Strings[i], '');
      end;
    end;

    // write the access end tag
    WriteTagEnd(_access);

    // if we have non zero validity dates
    if (fValidityStart <> '') or (fValidityEnd <> '') then
    begin

      // write the validity block
      WriteTagStart(_valid);
      if fValidityStart <> '' then
      begin
        WriteTagAndValue(_notbefore, fValidityStart);
      end;
      if fValidityEnd <> '' then
      begin
        WriteTagAndValue(_notafter, fValidityEnd);
      end;
      WriteTagEnd(_valid);
    end;

    // write the entry end tag
    WriteTagEnd(_entry);
  end;
end;

constructor TUPnP_ACL_Entry.CreateFromHash(aHash: string);
{
  Create a security owner from a given hash of a PK
  Status: FULLY TESTED
}
begin
  // call inherited constructor
  Create;
  // set the fields
  fSubjectType    := st_Key;
  fSubjectString  := aHash;
  fIssuerType     := st_Key;
  fIssuerString   := fSubjectString;
  fValidityStart  := '';
  fValidityEnd    := '';
  fPermissions.Text := _allStar;
  fMayNotDelegate := False;
end;

constructor TUPnP_ACL_Entry.Create;
{
  Constructor
  Status: FULLY TESTED
}
begin
  inherited;

  // create the permissions list
  fPermissions := TStringList.Create;
end;

destructor TUPnP_ACL_Entry.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
  // free the permissions list
  fPermissions.Free;

  inherited;
end;

constructor TUPnP_ACL_Entry.CreateFromAclXml(aBuffer: TUPnP_XMLStream);
{
  Parse incoming XML to fill in ACL values
  Status: FULLY TESTED
}
var
  s: string;
const
  actname = 'CreateFromAclXml';
begin
  // call inherited constructor
  Create;
  fStatusOk := False;

  with aBuffer do
  begin
    NextTag;

    // get the subject
    if TagName = _subject then
    begin
      // get the next tag
      NextTag;

      // if the 'any' tag is present, set the ACL entry type accordingly
      if TagName = _any then
      begin
        fSubjectType := st_Any;
        fIssuerType  := st_Key;
        fStatusOk    := True;
        NextTag;
      end
      else
      begin
        // if name tag is present then process as a name entry, set the ACL entry type
        // accordingly
        if TagName = _name then
        begin
          NextTag;
          // get the hash of the entry's principle
          if TagName = _hash then
          begin
            if DoGetHash(TagValue, fIssuerString) then
            begin
              NextPeer;
              // get the name
              if TagName = _text then
              begin
                fSubjectString := TagValue;
                fSubjectType   := st_Name;
                fIssuerType    := st_Key;
                fStatusOk      := True;
                NextTag;
              end;
            end;
          end;
        end
        else
        begin
          // get the hash of the entry's owner
          if TagName = _hash then
          begin
            if DoGetHash(TagValue, s) then
            begin
              NextPeer;
              fSubjectString := s;
              fIssuerString  := s;
              fSubjectType   := st_Key;
              fIssuerType    := st_Key;
              fStatusOk      := True;
            end;
          end;
        end;
      end;

      // get the maynot delegate flag
      if TagName = _MayNotDelegate then
      begin
        fMayNotDelegate := True;
        NextTag;
      end;

      // get the permissions
      fPermissions.Text := '';

      { TODO -oAFG -cnice to have : Check that the namespace is correct }
      if TagName = _access then
      begin
        if DoGetPermissions(TagValue, s) then
        begin
          fPermissions.Text := s;
        end
        else
        begin
          fStatusOk := False;
        end;
        NextPeer;
      end;

      // get the (optional) validity tags
      if TagName = _valid then
      begin
        if not DoGetValidity(TagValue, fValidityStart, fValidityEnd) then
        begin
          fStatusOk := False;
        end;
      end
      else
      begin
        fValidityStart := '';
        fValidityEnd   := '';
      end;
    end;
  end;
end;

constructor TUPnP_ACL_Entry.CreateFromStream(aReader: TReader);
{
  Load the ACL entry from the persistent data file / stream
  Status: FULLY TESTED
}
begin
  // call inherited constructor
  Create;

  with aReader do
  begin
    Read(fIssuerType, sizeof(TUPnP_Subject_Type));
    Read(fSubjectType, sizeof(TUPnP_Subject_Type));
    fIssuerString     := ReadString;
    fSubjectString    := ReadString;
    fValidityStart    := ReadString;
    fValidityEnd      := ReadString;
    fMayNotDelegate   := ReadBoolean;
    fPermissions.Text := ReadString;
  end;
end;

procedure TUPnP_ACL_Entry.SaveToStream(aWriter: TWriter);
{
  Save the ACL entry to the persistent data file / stream
  Status: FULLY TESTED
}
begin
  with aWriter do
  begin
    Write(fIssuerType, sizeof(TUPnP_Subject_Type));
    Write(fSubjectType, sizeof(TUPnP_Subject_Type));
    WriteString(fIssuerString);
    WriteString(fSubjectString);
    WriteString(fValidityStart);
    WriteString(fValidityEnd);
    WriteBoolean(fMayNotDelegate);
    WriteString(fPermissions.Text);
  end;
end;

constructor TUPnP_ACL_Entry.CreateFromCertXML(aDevSec: TUPnP_DeviceSecurity;
  aBuffer: TUPnP_XMLStream);
{
  Parse incoming XML to fill in values from a certificate
  Status: NOT TESTED
}
var
  lDeviceHash, s: string;
const
  actname = 'CreateFromCertXML';
begin
  // call inherited constructor
  Create;
  fStatusOk := False;

  with aBuffer do
  begin
    // if the first tag is issuer this is an authorization certificate
    if TagName = _issuer then
    begin
      fIssuerType := st_Key;

      // get the next tag
      NextTag;

      // get the hash of the issuer
      if (TagName = _hash) and DoGetHash(TagValue, fIssuerString) then
      begin
        // get the next tag
        NextPeer;

        // get the hash of the subject
        if TagName = _subject then
        begin
          NextTag;

          // if name tag is present then process as a name entry, set the ACL entry type
          // accordingly
          if TagName = _name then
          begin
            // get the hash of the entry's principle
            if TagName = _hash then
            begin
              if DoGetHash(TagValue, s) then
              begin
                NextPeer;

                // get the name
                if TagName = _text then
                begin
                  fSubjectString := TagValue;
                  fSubjectType   := st_Name;
                  fStatusOk      := True;
                end;
              end;
            end;
          end
          else
          begin
            if (TagName = _hash) and DoGetHash(TagValue, fSubjectString) then
            begin
              fSubjectType := st_Key;
              fStatusOk    := True;
            end;
          end;

          NextPeer;
          if fStatusOk then
          begin
            fStatusOk := False;
            if TagName = _tag then
            begin
              // get the next tag
              NextTag;

              // get the hash of the device
              if TagName = _device then
              begin
                NextTag;

                // get the hash of the devices PK
                if (TagName = _hash) and DoGetHash(TagValue, lDeviceHash) then
                begin

                  // check if it ours
                  if lDeviceHash =
                    BinaryToBase64(
                    TSecUtils.StringToHash(aDevsec.fPrivateKey.AsString,
                    aDevsec.fCryptoProvider)) then
                  begin

                    // get the permissions
                    NextPeer;
                    { TODO -oAFG -cnice to have : Check that the namespace is correct }
                    if (TagName = _access) and DoGetPermissions(TagValue, s) then
                    begin
                      fPermissions.Text := s;
                      NextPeer;

                      // get the may not delegate tag
                      if TagName = _maynotdelegate then
                      begin
                        NextPeer;
                      end;

                      // get the validity tags
                      if (TagName = _valid) and DoGetValidity(TagValue,
                        fValidityStart, fValidityEnd) then
                      begin
                        // if we got this far we have a valid entry
                        fSubjectType := st_Key;
                        fStatusOk    := True;
                      end;
                    end;
                  end;
                end;
              end;
            end;
          end;
        end;
      end;
    end
    else
    begin

      // if the first tag is define this is a member certificate
      if TagName = _define then
      begin
        fIssuerType := st_Name;

        // get the next tag
        NextTag;

        // get the group name tag
        if (TagName = _name) then
        begin

          // get the hash of the issuer
          if (TagName = _hash) and DoGetHash(TagValue, s) then
          begin
            NextPeer;

            // get the name
            if TagName = _text then
            begin
              fIssuerString := TagValue;

              // get the next tag
              NextTag;

              // get the hash of the subject
              if TagName = _subject then
              begin
                NextTag;
                if (TagName = _hash) and DoGetHash(TagValue, fSubjectString) then
                begin
                  NextPeer;

                  // get the validity tags
                  if (TagName = _valid) and DoGetValidity(TagValue,
                    fValidityStart, fValidityEnd) then
                  begin
                    // if we got this far we have a valid entry
                    fSubjectType := st_Key;
                    fStatusOk    := True;
                  end;
                end
                else
                begin

                  // if name tag is present then process as a name entry, set the ACL
                  // entry type accordingly
                  if TagName = _name then
                  begin

                    // get the next tag
                    NextTag;

                    // get the hash of the entry's principle
                    if TagName = _hash then
                    begin
                      if DoGetHash(TagValue, s) then
                      begin
                        NextTag;

                        // get the name
                        if TagName = _text then
                        begin
                          fSubjectString := TagValue;
                          fSubjectType   := st_Name;
                          fStatusOk      := True;
                        end;
                      end;
                    end;
                  end;
                end;
              end;
            end;
          end;
        end;
      end;
    end;
  end;
end;


// *********************** TUPnP_AuthList ********************

function TUPnP_AuthList.fGetEntry(aIndex: integer): TUPnP_ACL_Entry;
{
  Return the indexed object as an ACL entry
  Status: FULLY TESTED
}
begin
  try
    // type cast the indexed entry as TUPnP_ACL_Entry
    Result := Items[aIndex] as TUPnP_ACL_Entry;

  except

    // type cast error will cause a nil result
    on Exception do
      Result := nil;
  end;
end;

procedure TUPnP_AuthList.DeleteExpiredEntries;
{
  Delete expired permissions
  Status: NOT TESTED
}
var
  i: integer;
  iNowStr: string;
begin
  iNowStr := FormatDateTime(_dateFormat, NowGMT);
  i := 0;

  // loop through each ACL entry in turn
  while i < Count do
  begin

    // check if the permission validity date has expired, and if so delete it
    if (Entry[i].fValidityEnd <> '') and (Entry[i].fValidityEnd < iNowStr) then
    begin
      Delete(i);
    end
    else
    begin
      Inc(i);
    end;
  end;
end;

procedure TUPnP_AuthList.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Save the ACL to a data file / stream
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // loop through all entries and write them
  for i := 0 to pred(Count) do
  begin
    Entry[i].SaveToXML(aBuffer);
  end;
end;

constructor TUPnP_AuthList.CreateFromStream(aReader: TReader);
{
  Load the ACL from the persistent data file / stream
  Status: FULLY TESTED
}
var
  i, cnt: integer;
  e:      TUPnP_ACL_Entry;
begin
  // call inherited constructor
  Create(True);

  with aReader do
  begin

    // read the list count
    cnt := ReadInteger;

    // read the list of entries
    for i := 1 to cnt do
    begin

      // create the entry and load its data
      e := TUPnP_ACL_Entry.CreateFromStream(aReader);

      // if data is loaded OK then add it to the list
      if e <> nil then
      begin
        Add(e);
      end;
    end;
  end;
end;

procedure TUPnP_AuthList.SaveToStream(aWriter: TWriter);
{
  Save the ACL to the persistent data file / stream
  Status: FULLY TESTED
}
var
  i: integer;
begin
  with aWriter do
  begin

    // write the list count
    WriteInteger(Count);

    // loop through the list of entries and save them
    for i := 0 to pred(Count) do
    begin
      Entry[i].SaveToStream(aWriter);
    end;

  end;
end;


// *********************** TUPnP_SessionKey ********************

destructor TUPnP_SessionKey.Destroy;
{
  De-Initialise the key
  Status: FULLY TESTED
}
begin
{$ifdef UseMSWindowsXPCryptoAPI}
  if fKeyHandle <> 0 then
  begin
    CryptDestroyKey(fKeyHandle);
  end;
{$endif}
  inherited;
end;

{$ifdef UseMSWindowsXPCryptoAPI}
procedure TUPnP_SessionKey.InitKey;
{
  Initialise the key
  Status: FULLY TESTED
}
var
  lKeyHandle: HCRYPTKEY;
  lBlob:      TPlainTextKeyBlob;
  lSize:      dword;
const
  actName = 'InitKey';
begin
  if fKeyHandle = 0 then
  begin

    // generate a dummy key
    if not CryptGenKey(fCryptoProvider, CALG_AES_128, CRYPT_EXPORTABLE, @lKeyHandle) then
    begin
      RaiseException(ClassName, actname, 1);
    end;

    try

      // export it to a plain text blob
      lSize := sizeof(lBlob);
      if not CryptExportKey(lKeyHandle, 0, PLAINTEXTKEYBLOB, 0, @lBlob, @lSize) then
      begin
        RaiseException(ClassName, actname, 2);
      end;

      // overwrite the key data in the blob
      Move(fKey, lBlob.fKeyData, AES_KeyLength);

      // and import / create the key from the blob
      if not CryptImportKey(fCryptoProvider, @lBlob, sizeof(lBlob),
        0, 0, @fKeyHandle) then
      begin
        RaiseException(ClassName, actname, 3);
      end;

    finally
      // destroy the dummy key
      if not CryptDestroyKey(lKeyHandle) then
      begin
        RaiseException(ClassName, actname, 4);
      end;
    end;
  end;

  if fKeyHandle <> 0 then
  begin
    // set the IV
    if not CryptSetKeyParam(fKeyHandle, KP_IV, @fIV, 0) then
    begin
      RaiseException(ClassName, actname, 5);
    end;
  end;
end;

{$endif}

function TUPnP_SessionKey.Encrypt(aPlainText: string): string;
{
  Encrypt the string using the key
  Status: FULLY TESTED
}
var
  byteCount: cardinal;
{$ifndef UseMSWindowsXPCryptoAPI}
  ioPos:     cardinal;
  TempIn, TempOut, Vector: TAESBuffer;
{$endif}
const
  actName = 'Encrypt';
begin
{$ifdef UseMSWindowsXPCryptoAPI}
  // initialise the key
  InitKey;

  // pad plain text to an integral block size
  AppendPadding(aPlainText);

  // encrypt the string
  byteCount := length(aPlainText);
  if not CryptEncrypt(fKeyHandle, 0, False, 0, @aPlainText[1],
    @byteCount, byteCount) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  Result := aPlainText;

{$else}
  if not fEncryptkeyExpanded then
  begin
    ExpandAESKeyForEncryption(fKey, fEncryptKey);
    fEncryptkeyExpanded := True;
  end;

  // pad plain text to an integral block size
  AppendPadding(aPlainText, AES_BlockLength, fCryptoProvider);

  // determine the number of bytes we want to encrypt
  byteCount := length(aPlainText);
  ioPos     := 1;

  // get enough space
  SetLength(Result, byteCount);

  Vector := fIV;
  while byteCount >= SizeOf(TAESBuffer) do
  begin
    Move(aPlainText[ioPos], TempIn, SizeOf(TempIn));
    PLongWord(@TempIn[0])^  := PLongWord(@TempIn[0])^ xor PLongWord(@Vector[0])^;
    PLongWord(@TempIn[4])^  := PLongWord(@TempIn[4])^ xor PLongWord(@Vector[4])^;
    PLongWord(@TempIn[8])^  := PLongWord(@TempIn[8])^ xor PLongWord(@Vector[8])^;
    PLongWord(@TempIn[12])^ := PLongWord(@TempIn[12])^ xor PLongWord(@Vector[12])^;
    EncryptAES(TempIn, fEncryptKey, TempOut);
    Move(TempOut, Result[ioPos], SizeOf(TempOut));
    Inc(ioPos, SizeOf(TempOut));
    Vector := TempOut;
    Dec(byteCount, SizeOf(TAESBuffer));
  end;
{$endif}
end;

function TUPnP_SessionKey.Decrypt(aCipherText: string): string;
{
  Decrypt the string using the key
  Status:  FULLY TESTED
}
var
  byteCount: cardinal;
{$ifndef UseMSWindowsXPCryptoAPI}
  ioPos:     cardinal;
  TempIn, TempOut, Vector1, Vector2: TAESBuffer;
{$endif}
const
  actName = 'Decrypt';
begin
{$ifdef UseMSWindowsXPCryptoAPI}
  // initialise the key
  InitKey;

  // decrypt the string
  byteCount := length(aCipherText);
  if not CryptDecrypt(fKeyHandle, 0, False, 0, @aCipherText[1], @byteCount) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  SetLength(aCipherText, byteCount);
  Result := aCipherText;

  // remove padding
  StripPadding(Result);

{$else}
  if not fDecryptkeyExpanded then
  begin
    ExpandAESKeyForDecryption(fKey, fDecryptKey);
    fDecryptkeyExpanded := True;
  end;

  // determine the number of bytes we want to decrypt
  byteCount := length(aCipherText);
  ioPos     := 1;

  // get enough space
  SetLength(Result, byteCount);

  Vector1 := fIV;
  while byteCount >= SizeOf(TAESBuffer) do
  begin
    Move(aCipherText[ioPos], TempIn, SizeOf(TempIn));
    Vector2 := TempIn;
    DecryptAES(TempIn, fDecryptKey, TempOut);
    PLongWord(@TempOut[0])^  := PLongWord(@TempOut[0])^ xor PLongWord(@Vector1[0])^;
    PLongWord(@TempOut[4])^  := PLongWord(@TempOut[4])^ xor PLongWord(@Vector1[4])^;
    PLongWord(@TempOut[8])^  := PLongWord(@TempOut[8])^ xor PLongWord(@Vector1[8])^;
    PLongWord(@TempOut[12])^ := PLongWord(@TempOut[12])^ xor PLongWord(@Vector1[12])^;
    Move(TempOut, Result[ioPos], SizeOf(TempOut));
    Vector1 := Vector2;
    Inc(ioPos, SizeOf(TempOut));
    Dec(byteCount, SizeOf(TAESBuffer));
  end;

  // fixup the string size
  SetLength(Result, ioPos - 1);
{$endif}
end;

constructor TUPnP_SessionKey.CreateFromXML(aCryptoProvider: HCRYPTPROV;
  aBuffer: TUPnP_XMLStream);
{
  Create a session key from XML
  Status: FULLY TESTED
}
var
  keyString: string;
const
  actname = 'CreateFromXML';
begin
  // call inherited constructor
  Create;
  fCryptoProvider := aCryptoProvider;

  with aBuffer do
  begin

    // check if the tagname is to-device and set the field accordingly
    if TagName = _key_dir[toDevice] then
    begin
      fDirection := toDevice;
    end
    else
    begin

      // check if the tagname is from-device and set the field accordingly
      if TagName = _key_dir[fromDevice] then
      begin
        fDirection := fromDevice;
      end
      else
      begin
        // otherwise move on to the next tag before...
        NextTag;

        // raising an error
        RaiseException(ClassName, actname, 1);
      end;
    end;

    // convert the xml from from Base 64 to binary
    keyString := Base64ToBinary(TagValue);
    Move(keyString[1], fKey[0], sizeof(fKey));

    // get then next tag
    NextTag;
  end;
end;

constructor TUPnP_SessionKey.CreateFromStream(aCryptoProvider: HCRYPTPROV;
  aReader: TReader);
{
  Create a session key from a persistent file / stream
  Status: FULLY TESTED
}
begin
  // call inherited constructor
  Create;
  fCryptoProvider := aCryptoProvider;

  // read the direction and type (booleans)
  if aReader.ReadBoolean then
  begin
    fDirection := toDevice;
  end
  else
  begin
    fDirection := fromDevice;
  end;

  if aReader.ReadBoolean then
  begin
    fKeyType := confidentiality;
  end
  else
  begin
    fKeyType := signing;
  end;

  // read the binary key value
  aReader.Read(fKey, sizeof(fKey));
end;

constructor TUPnP_SessionKey.CreateFromEncipheredBulkKey(aCryptoProvider: HCRYPTPROV;
  aPrivateKey: TUPnP_PrivateKey; aCipherText: string);
{
  Extract a session key and IV from a big endian enciphered bulk key block
  Status: FULLY TESTED
}
var
  plainText: string;
  pos: integer;
begin
  // call inherited constructor
  Create;
  fCryptoProvider := aCryptoProvider;

  // decrypt the string
  plainText := aPrivateKey.Decrypt(aCipherText);

  // copy the data field to the key
  pos := length(plainText) + 1 - sizeof(fKey);
  Move(plainText[pos], fKey[0], sizeof(fKey));

  // copy the data field to the IV
  Dec(pos, sizeof(fIV));
  Move(plainText[pos], fIV[0], sizeof(fIV));
end;

constructor TUPnP_SessionKey.CreateRandom(aCryptoProvider: HCRYPTPROV);
{
  Create a new (random) session key
  Status: FULLY TESTED
}
begin
  // call inherited constructor
  Create;
  fCryptoProvider := aCryptoProvider;

  // randomize the key
  CryptGenRandom(fCryptoProvider, sizeof(fKey), @fKey);

  // also create a random IV
  NewRandomIV;
end;

constructor TUPnP_SessionKey.CreateToEncipheredBulkKey(aCryptoProvider: HCRYPTPROV;
  aPublicKey: TUPnP_RSA_Key; out aCipherText: string);
{
  Create a key and build a big endian enciphered bulk key block from it
  Status: FULLY TESTED
}
begin
  // create a random key
  CreateRandom(aCryptoProvider);

  // encrypt the IV and Key and return as ciphertext
  aCipherText := aPublicKey.Encrypt(InitialValue + KeyValue);
end;

function TUPnP_SessionKey.GetKV: string;
{
  Return the key data as a network byte order string
  Status: FULLY TESTED
}
begin
  SetString(Result, PChar(@fKey), sizeof(fKey));
end;

function TUPnP_SessionKey.GetIV: string;
{
  Return the IV as a network byte order string
  Status: FULLY TESTED
}
begin
  SetString(Result, PChar(@fIV), sizeof(fIV));
end;

procedure TUPnP_SessionKey.NewRandomIV;
{
  Create a new random Initialization Vector
  Status: FULLY TESTED
}
begin
  // create a new random Initialization Vector
  CryptGenRandom(fCryptoProvider, sizeof(fIV), @fIV);
end;

procedure TUPnP_SessionKey.SetIV(anIV: string);
{
  Apply an Initialization Vector
  Status: FULLY TESTED
}
begin
  // copy the data fields to the IV
  Move(anIV[1], fIV, min(length(anIV), sizeof(fIV)));
end;

procedure TUPnP_SessionKey.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Save a session key as XML
  Status: FULLY TESTED
}
begin
  // write the Key in base 64
  aBuffer.WriteTagAndValue(_key_Dir[fDirection],
    BinaryToBase64(KeyValue));
end;

procedure TUPnP_SessionKey.SaveToStream(aWriter: TWriter);
{
  Save a session key to a persistent file / stream
  Status: FULLY TESTED
}
begin
  // write direction and type (booleans) to the stream
  aWriter.WriteBoolean(fDirection = toDevice);
  aWriter.WriteBoolean(fKeyType = confidentiality);

  // write the binary key data
  aWriter.Write(fKey, sizeof(fKey));
end;


// *********************** TUPnP_RSA_Key ********************

function TUPnP_RSA_Key.AsString: string;
{
  Save the public key as a string
  Status: FULLY TESTED
}
var
  xBuffer: TUPnP_XMLStream;
begin
  xBuffer := TUPnP_XMLStream.Create;
  SaveToXML(xBuffer);
  Result := xBuffer.AsText;
  xBuffer.Free;
end;

destructor TUPnP_RSA_Key.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
{$ifndef UseMSWindowsXPCryptoAPI}
  FGIntDestroy(n);
  FGIntDestroy(e);
{$endif}
  inherited;
end;

procedure TUPnP_RSA_Key.NotInitialisedException(aMethod: string);
{
  Raise an exception message
  Status: FULLY TESTED
}
begin
  raise EUPnP_KeyException.CreateFmt(fmt3, [ClassName, aMethod]);
end;

procedure TUPnP_RSA_Key.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Initialise the Public Key data fields and save the public key as XML
  Status: FULLY TESTED
}
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException('SavePublicToXML');
  end;

  // save the data in xml
  with aBuffer do
  begin
    // write the tag start
    WriteTagStart(_RSAKeyValue);

    // write the modulus and exponents
    WriteTagAndValue(_Modulus, ModulusB64);
    WriteTagAndValue(_Exponent, PublicExponentB64);

    // write the tag end
    WriteTagEnd(_RSAKeyValue);
  end;
end;

function TUPnP_RSA_Key.ModulusB64: string;
{
  Export the modulus as a base 64 string in network byte order
  Status: FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  lBlob: TPublicKeyBlob;
  lSize: integer;
{$endif}
  s:     string;
const
  actname = 'ModulusB64';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actname);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  lSize := sizeof(lBlob);
  if not CryptExportKey(fKeyHandle, 0, PUBLICKEYBLOB, 0, @lBlob, @lSize) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  SetString(s, PChar(@lblob.fModulus), sizeof(lblob.fModulus));
  Result := BinaryToBase64(PrependZeroByte(ReverseString(s)));

{$else}
  // convert modulus to big endian binary
  FGIntToBase256String(n, s);
  // add a #0 before the MSB to force the result to appear as a positive
  // signed integer
  Result := BinaryToBase64(PrependZeroByte(s));
{$endif}
end;

function TUPnP_RSA_Key.PublicExponentB64: string;
{
  Export the public exponent as a base 64 string in network byte order
  Status: FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  lBlob: TPublicKeyBlob;
  lSize: integer;
{$endif}
  s:     string;
const
  actname = 'PublicExponentB64';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actname);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  lSize := sizeof(lBlob);
  if not CryptExportKey(fKeyHandle, 0, PUBLICKEYBLOB, 0, @lBlob, @lSize) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  SetString(s, PChar(@lblob.fRSAPUBKEY.pubexp), sizeof(lblob.fRSAPUBKEY.pubexp));
  Result := BinaryToBase64(PrependZeroByte(ReverseString(s)));

{$else}
  // convert exponent to big endian binary
  FGIntToBase256String(e, s);
  // add a #0 before the MSB to force the result to appear as a positive signed integer
  Result := BinaryToBase64(PrependZeroByte(s));
{$endif}
end;

{$ifndef UseMSWindowsXPCryptoAPI}
function TUPnP_RSA_Key.SignatureDigest(aPlainText: string): string;
{
  Hash the plaintext, and prepend the PKCS SHA1/RSA prefix, and prepad to length(n)-1
  Status: FULLY TESTED
}
const
  prefix: string = #0#$30#$21#$30#9#6#5#$2B#$0E#3#2#$1A#5#0#4#$14;
var
  l: integer;
  s: string;
  t: string;
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException('SignatureDigest');
  end;

  // convert modulus to big endian binary
  FGIntToBase256String(n, s);

  // digest the plaintext
  t := StringToHash(aPlainText, fDevSec.fCryptoProvider);

  // calculate the amount of padding needed
  l      := length(s) - length(prefix) - length(t) - 2;
  Result := #$01 + StringOfChar(#$FF, l) + prefix + t;
end;

function TUPnP_RSA_Key.PKCSPad(aString: string): string;
{
  Add PKCS padding to a string
  Status:  FULLY TESTED
}
var
  i, padlen: integer;
  nS, pad: string;
  xx: byte;
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException('PKCSPad');
  end;

  // convert modulus to big endian binary
  FGIntToBase256String(n, nS);

  // calculate the amount of padding needed
  padlen := length(nS) - length(aString) - 3;

  // set the length
  Setlength(pad, padlen);

  // generate random bytes
  CryptGenRandom(fDevSec.fCryptoProvider, padlen, @pad[1]);

  // replace any #0 bytes
  for i := 1 to padlen do
  begin
    if pad[i] = #0 then
    begin
      repeat
        CryptGenRandom(fDevSec.fCryptoProvider, 1, @xx);
      until xx <> 0;
      pad[i] := char(xx);
    end;
  end;
  Result := (*#0*) #2 + pad + #0 + aString;
end;

function TUPnP_RSA_Key.PKCSUnPad(aString: string): string;
{
  Remove PKCS padding from a string
  Status:  FULLY TESTED
}
var
  i: integer;
begin
  // preset result to ''
  Result := '';

  // skip the 1st two bytes
  i := 3;

  // search for the first #0 byte
  while i < length(aString) do
  begin
    if aString[i] = #0 then
    begin
      Result := Copy(aString, i + 1, length(aString) - i);
      break;
    end;
    Inc(i);
  end;
end;
{$endif}

constructor TUPnP_RSA_Key.CreateFromXML(aDevSec: TUPnP_DeviceSecurity;
  aBuffer: TUPnP_XMLStream);
{
  Set up the public key from XML
  Status: FULLY TESTED
}
var
  i:     integer;
{$ifdef UseMSWindowsXPCryptoAPI}
  lBlob: TPublicKeyBlob;
  tmp:   string;
  lN:    string;
  lE:    string;
{$endif}
const
  actname = 'CreateFromXML';
begin
  // call inherited constructor
  inherited;

  fDevSec := aDevSec;

{$ifdef UseMSWindowsXPCryptoAPI}
  with aBuffer do
  begin

    // loop twice to get modulus and exponent tags
    for i := 0 to 1 do
    begin

      // get the next tag
      NextTag;

      // get the modulus
      if TagName = _Modulus then
      begin
        lN := StripZeroByte(Base64ToBinary(TagValue));
      end
      else
      begin
        // get the exponent
        if TagName = _Exponent then
        begin
          lE := StripZeroByte(Base64ToBinary(TagValue));
        end;
      end;
    end;
  end;

  // if either modulus or exponent are empty then raise an exception
  if (lN = '') or (lE = '') then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  // initialise the blob header structure
  with lBlob.fBLOBHEADER do
  begin
    bType    := PUBLICKEYBLOB;
    bVersion := CUR_BLOB_VERSION;
    reserved := 0;
    aiKeyAlg := CALG_RSA_SIGN; // CALG_RSA_KEYX;
  end;

  // initialise the modulus
  with lBlob do
  begin
    FillChar(fModulus, sizeof(fModulus), #0);
    // change to little endian
    tmp := ReverseString(lN);
    Move(tmp[1], fModulus, min(sizeof(fModulus), length(tmp)));
  end;

  // initialise the blob public key structure
  with lBlob.fRSAPUBKEY do
  begin
    magic  := $31415352; { "RSA1" }
    bitlen := sizeof(lBlob.fModulus) * 8;
    pubexp := 0;
    // change to little endian
    tmp    := ReverseString(lE);
    Move(tmp[1], pubexp, min(sizeof(pubexp), length(tmp)));
  end;

  // import / create the key from the blob
  if not CryptImportKey(fDevSec.fCryptoProvider, @lBlob, sizeof(lBlob),
    0, 0, @fKeyHandle) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

{$else}
  with aBuffer do
  begin
    // loop twice to get modulus and exponent tags
    for i := 0 to 1 do
    begin

      // get the next tag
      NextTag;

      // get the modulus
      if TagName = _Modulus then
      begin
        // truncate the #0 preceding the MSB (if any)
        Base256StringToFGInt(StripZeroByte(Base64ToBinary(TagValue)), n);
      end
      else
      begin
        // get the exponent
        if TagName = _Exponent then
        begin
          // truncate the #0 preceding the MSB (if any)
          Base256StringToFGInt(StripZeroByte(Base64ToBinary(TagValue)), e);
        end;
      end;
    end;
  end;

  // if either modulus or exponent are empty then raise an exception
  if (n.Number[0] = 0) or (e.Number[0] = 0) then
  begin
    RaiseException(ClassName, actname, 1);
  end;
{$endif}

  // set the initialised flag
  fInitialised := True;
end;

function TUPnP_RSA_Key.Encrypt(aPlainText: string): string;
{
  Encrypt a plain text using the public key
  Status:  FULLY TESTED
}
{$ifdef UseMSWindowsXPCryptoAPI}
var
  byteCount: integer;
  tmp: string;
{$endif}
const
  actName = 'Encrypt';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actName);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  // make a copy of the plaintext and create some extra space
  tmp := aPlainText;
  byteCount := length(tmp);
  SetLength(tmp, byteCount + RSA_KeyLength);

  // encrypt
  if not CryptEncrypt(fKeyHandle, 0, True, 0, @tmp[1], @byteCount, length(tmp)) then
  begin
    RaiseException(ClassName, actname, 1);
  end
  else
  begin
    // trim the length and reverse the byte order
    SetLength(tmp, byteCount);
    Result := ReverseString(tmp);
  end;

{$else}
  // encrypt
  RSAEncrypt(PKCSPad(aPlainText), e, n, Result);
{$endif}
end;

function TUPnP_RSA_Key.Verify(aPlainText, aSignature: string): boolean;
{
  Verify a signature using the public key
  Status:  FULLY TESTED
}
{$ifdef UseMSWindowsXPCryptoAPI}
var
  hHash: hCryptHash;
  tmp:   string;
{$endif}
const
  actName = 'Verify';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actName);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  // create a hash
  if not CryptCreateHash(fDevSec.fCryptoProvider, CALG_SHA, 0, 0, @hHash) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  try

    // hash the plain text
    if not CryptHashData(hHash, @aPlainText[1], length(aPlainText), 0) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // reverse the signature byte order
    tmp := ReverseString(aSignature);

    // verify the signature
    Result := CryptVerifySignature(hHash, @tmp[1], length(tmp), fKeyHandle, nil, 0);

  finally
    // destroy the hash object
    if not CryptDestroyHash(hHash) then
    begin
      RaiseException(ClassName, actname, 3);
    end;
  end;

{$else}
  // verify the digest against the signature
  RSAVerify(SignatureDigest(aPlainText), aSignature, e, n, Result);
{$endif}
end;


// *********************** TUPnP_PrivateKey ********************

constructor TUPnP_PrivateKey.CreateRandom(aDevSec: TUPnP_DeviceSecurity);
{
  Create a new public key
  Status: FULLY TESTED
}
begin
  // call inherited constructor
  inherited;

  //initialise the owner
  fDevSec := aDevSec;

  // set initialised flag to false
  fInitialised := False;

  //  and call the event handler
  if Assigned(fDevSec.fOnGenerateKeyStart) then
  begin
    fDevSec.fOnGenerateKeyStart(fDevSec);
  end;

  // start a thread to create a new key
  TUPnP_PK_InitialiseThread.Create(self);
end;

procedure TUPnP_PrivateKey.GenerateNewKey;
{
  Generate a new key
  Status: FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  keyLen: integer;
{$else}
  r:      string;
  phi, one, two, gcd, temp: TFGInt;
{$endif}
const
  actName = 'GenerateNewKey';
begin
  if not fInitialised then
  begin

{$ifdef UseMSWindowsXPCryptoAPI}
    keyLen := RSA_KeyLength shl 19;
    if not CryptGenKey(fDevSec.fCryptoProvider, CALG_RSA_KEYX, keyLen or
      CRYPT_EXPORTABLE, @fKeyHandle) then
    begin
      RaiseException(ClassName, actname, 1);
    end;
{$else}

    // set a buffer to hold random numbers
    SetLength(r, 64);

    // create a random number
    CryptGenRandom(fDevSec.fCryptoProvider, 64, pointer(r));

    // mask top bits to prevent overflows on the prime search
    r[1] := char(byte(r[1]) and $7f);

    // set this value into p
    Base256StringToFGInt(r, p);

    // incremental search for a prime starting from p
    PrimeSearch(p);

    // create another random number
    CryptGenRandom(fDevSec.fCryptoProvider, 64, pointer(r));

    // mask top bits to prevent overflows on the prime search
    r[1] := char(byte(r[1]) and $7f);

    // set this value into q
    Base256StringToFGInt(r, q);

    // incremental search for a prime starting from q
    PrimeSearch(q);

    // Compute the modulus
    FGIntMul(p, q, n);

    // Compute p-1, q-1 by adjusting the last digit of the GInt
    //  --> maybe this will fail once every 2^64 attempts
    //  i.e. if the number wraps under zero (??)
    p.Number[1] := p.Number[1] - 1;
    q.Number[1] := q.Number[1] - 1;

    // Compute phi(n)
    FGIntMul(p, q, phi);

    // Choose a public exponent e such that GCD(e,phi)=1
    // common values are 3, 65537 but if these aren 't coprime
    // to phi, use the following code
    Base10StringToFGInt('65537', e); // just an odd starting point
    Base10StringToFGInt('1', one);
    Base10StringToFGInt('2', two);
    FGIntGCD(phi, e, gcd);

    while FGIntCompareAbs(gcd, one) <> Eq do
    begin
      FGIntadd(e, two, temp);
      FGIntCopy(temp, e);
      FGIntGCD(phi, e, gcd);
    end;

    // clean up
    FGIntDestroy(two);
    FGIntDestroy(one);
    FGIntDestroy(gcd);
    FGIntDestroy(phi);

    // calculate some extra variables
    FGIntModInv(e, p, dp);
    FGIntModInv(e, q, dq);

    // restore p & q
    p.Number[1] := p.Number[1] + 1;
    q.Number[1] := q.Number[1] + 1;
{$endif}
  end;
end;

procedure TUPnP_PrivateKey.GenerateNewKeyStart;
{
  Call back
  Status: FULLY TESTED
}
begin
  if not fInitialised then
  begin
    //  call the event handler
    if Assigned(fDevSec.fOnGenerateKeyStart) then
    begin
      fDevSec.fOnGenerateKeyStart(fDevSec);
    end;
  end;
end;

procedure TUPnP_PrivateKey.GenerateNewKeyDone;
{
  Call back
  Status: FULLY TESTED
}
begin
  if not fInitialised then
  begin
    // set the initialised flag to true,
    fInitialised := True;

    //  and call the event handler
    if Assigned(fDevSec.fOnGenerateKeyDone) then
    begin
      fDevSec.fOnGenerateKeyDone(fDevSec);
    end;
  end;
end;

function TUPnP_PrivateKey.Decrypt(aCipherText: string): string;
{
  Decrypt a plain text using the private key
  Status:  FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  byteCount: integer;
{$else}
  nilFGInt: TFGInt;
  s: string;
{$endif}
const
  actName = 'Decrypt';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actName);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  // reverse the byte order of the cipher text
  Result    := ReverseString(aCipherText);
  byteCount := length(Result);

  // decrypt
  if not CryptDecrypt(fKeyHandle, 0, True, 0, @Result[1], @byteCount) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  // trim the length
  SetLength(Result, byteCount);
{$else}

  // decrypt
  RSADecrypt(aCipherText, nilFGInt, n, dp, dq, p, q, s);
  Result := PKCSUnPad(s);

  // clean up
  FGIntDestroy(nilFGInt);
{$endif}
end;

function TUPnP_PrivateKey.Sign(aPlainText: string): string;
{
  Sign a plaintext using the private key
  Status: FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  hHash:    hCryptHash;
  bytelength: cardinal;
  tmp:      string;
{$else}
  nilFGInt: TFGInt;
{$endif}
const
  actName = 'Sign';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actName);
  end;

{$ifdef UseMSWindowsXPCryptoAPI}
  // create a hash
  if not CryptCreateHash(fDevSec.fCryptoProvider, CALG_SHA, 0, 0, @hHash) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  try

    // hash the plain text
    if not CryptHashData(hHash, @aPlainText[1], length(aPlainText), 0) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // get the buffer size
    if not CryptSignHash(hHash, fKeyHandle, nil, 0, nil, @bytelength) then
    begin
      RaiseException(ClassName, actname, 3);
    end;

    // set the buffer size
    SetLength(tmp, bytelength);

    // sign the hash
    if not CryptSignHash(hHash, fKeyHandle, nil, 0, @tmp[1], @bytelength) then
    begin
      RaiseException(ClassName, actname, 4);
    end;

    // reverse the signature byte order
    Result := ReverseString(tmp);

  finally
    // destroy the hash object
    if not CryptDestroyHash(hHash) then
    begin
      RaiseException(ClassName, actname, 5);
    end;
  end;
{$else}

  // digest & sign
  RSASign(SignatureDigest(aPlainText), nilFGInt, n, dp, dq, p, q, Result);

  // clean up
  FGIntDestroy(nilFGInt);
{$endif}
end;

constructor TUPnP_PrivateKey.CreateFromStream(aDevSec: TUPnP_DeviceSecurity;
  aReader: TReader);
{
  Create a private key from a persistent stream
  Status: FULLY TESTED
}
var
  s:     string;
{$ifdef UseMSWindowsXPCryptoAPI}
  lBlob: string;
{$endif}
const
  actName = 'CreateFromStream';
begin
  // call inherited constructor
  inherited;

  //initialise the owner
  fDevSec := aDevSec;

  // read the PK parameters
  with aReader do
  begin
    s := ReadString;

{$ifdef UseMSWindowsXPCryptoAPI}
    fCAPIKeyExists := (AnsiPos(_capikeytag, s) <> 0);
    if fCAPIKeyExists then
    begin
      // read the blob string
      lBlob := ReadString;

      // import the key from the blob string
      if not CryptImportKey(fDevSec.fCryptoProvider, @lBlob[1],
        length(lBlob), 0, CRYPT_EXPORTABLE, @fKeyHandle) then
      begin
        RaiseException(ClassName, actname, 1);
      end;

      // set the initialised flag to true
      fInitialised := True;
    end
    else
    begin
      // start a thread to create a new key
      TUPnP_PK_InitialiseThread.Create(self);
      fCAPIKeyExists := True;
    end;

{$else}
    Base256StringToFGInt(s, n);
    s := ReadString;
    Base256StringToFGInt(s, e);
    s := ReadString;
    Base256StringToFGInt(s, p);
    s := ReadString;
    Base256StringToFGInt(s, q);
    s := ReadString;
    Base256StringToFGInt(s, dp);
    s := ReadString;
    Base256StringToFGInt(s, dq);

    // set the initialised flag to true
    fInitialised := True;
{$endif}
  end;
end;

procedure TUPnP_PrivateKey.SaveToStream(aWriter: TWriter);
{
  Save the public key to a persistent stream
  Status: FULLY TESTED
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  lBlob: string;
  lLength: integer;
{$else}
  s: string;
{$endif}
const
  actName = 'SaveToStream';
begin
  // raise exception if not initialised
  if not fInitialised then
  begin
    NotInitialisedException(actName);
  end;

  // store the PK parameters
  with aWriter do
  begin
{$ifdef UseMSWindowsXPCryptoAPI}
    WriteString(_capikeytag);

    // determine the required length of the blob string
    if not CryptExportKey(fKeyHandle, 0, PRIVATEKEYBLOB, 0, nil, @lLength) then
    begin
      RaiseException(ClassName, actname, 1);
    end;

    // set the blob string size
    SetLength(lBlob, lLength);

    // export the key to the blob string
    if not CryptExportKey(fKeyHandle, 0, PRIVATEKEYBLOB, 0, @lBlob[1], @lLength) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // write the blob
    WriteString(lBlob);

{$else}
    FGIntToBase256String(n, s);
    WriteString(s);
    FGIntToBase256String(e, s);
    WriteString(s);
    FGIntToBase256String(p, s);
    WriteString(s);
    FGIntToBase256String(q, s);
    WriteString(s);
    FGIntToBase256String(dp, s);
    WriteString(s);
    FGIntToBase256String(dq, s);
    WriteString(s);
{$endif}
  end;
end;

destructor TUPnP_PrivateKey.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
begin
{$ifndef UseMSWindowsXPCryptoAPI}
  // free the PK parameters
  FGIntDestroy(p);
  FGIntDestroy(q);
  FGIntDestroy(dp);
  FGIntDestroy(dq);
{$endif}
  inherited;
end;


// *********************** TUPnP_PK_InitialiseThread ********************

constructor TUPnP_PK_InitialiseThread.Create(aKey: TUPnP_PrivateKey);
{
  Create a thread to initialise a set of public key parameters
  Status: FULLY TESTED
}
begin
  Create(True);
  fKey := aKey;
  FreeOnTerminate := True;
  Resume;
end;

procedure TUPnP_PK_InitialiseThread.Execute;
{
  Initialise a set of public key parameters in a background thread
  Status:  FULLY TESTED
}
begin
  if assigned(fKey) then
  begin
    // execute the call back in the VCL thread
    Synchronize(fKey.GenerateNewKeyStart);
    // but execute GenerateNewKey on this thread
    fKey.GenerateNewKey;
    // execute the call back in the VCL thread
    Synchronize(fKey.GenerateNewKeyDone);
  end;
end;


// *********************** TUPnP_Session ********************

destructor TUPnP_Session.Destroy;
{
  Destructor
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // free the keys
  for i := 0 to 3 do
  begin
    if Assigned(fKey[i]) then
    begin
      fKey[i].Free;
    end;
  end;

  inherited;
end;

constructor TUPnP_Session.CreateFromStream(aDevSecService: TUPnP_DeviceSecurity;
  aReader: TReader);
{
  Load a session from a persistent file / stream
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // call inherited constructor
  Create;

  with aReader do
  begin

    // load the (four) keys
    for i := 0 to 3 do
    begin
      fKey[i] := TUPnP_SessionKey.CreateFromStream(
        aDevSecService.fCryptoProvider, aReader);
    end;

    // load the other data
    fOwnerPKHashB64 := ReadString;
    fCPKeyID      := ReadInteger;
    fDeviceKeyID  := ReadInteger;
    fDeviceSequenceNumber := ReadInteger;
    fCPSequenceNumber := ReadInteger;
    fSequenceBase := ReadString;
  end;
end;

constructor TUPnP_Session.CreateRandom(aDevSecService: TUPnP_DeviceSecurity);
{
  Create a new session from scratch
  Status: FULLY TESTED
}
var
  x: TUPnP_KeyType;
  y: TUPnP_KeyDirection;
  i: integer;
begin
  // call inherited constructor
  Create;

  // preset index
  i := 0;

  // create keys of each type
  for x := low(TUPnP_KeyType) to high(TUPnP_KeyType) do

    // two directions per type
  begin
    for y := low(TUPnP_KeyDirection) to high(TUPnP_KeyDirection) do
    begin

      // create a key (at the index i)
      fKey[i] := TUPnP_SessionKey.CreateRandom(aDevSecService.fCryptoProvider);

      // assign its type and direction
      fKey[i].fKeyType   := x;
      fKey[i].fDirection := y;

      // bump the index
      Inc(i);
    end;
  end;

  // set the key ID to a random value
  fDeviceKeyID := Random(maxint);

  // initialise the sequence number to zero
  fDeviceSequenceNumber := 0;
  fCPSequenceNumber     := 0;

  // create a random sequence base
  fSequenceBase := aDevSecService.fRandomString;

  // set a default CPKeyID
  fCPKeyID := 0;

  // and preset the owners hash to ''
  fOwnerPKHashB64 := '';
end;

constructor TUPnP_Session.CreateFromXML(aDevSecService: TUPnP_DeviceSecurity;
  aBuffer: TUPnP_XMLStream);
{
  Set the session data from an XML stream
  Status: FULLY TESTED
}
var
  nextKey: integer;

  procedure GetTwoKeys(aKeyType: TUPnP_KeyType);
  {
    Get two keys of the given type from xml
    Status: FULLY TESTED
  }
  var
    j: integer;
    s: TUPnP_SessionKey;
  begin
    with aBuffer do
    begin
      // get the next tag
      NextTag;

      // loop to get two keys
      for j := 0 to 1 do
      begin

        // check the algorithm
        if Tagname = _AlgorithmA then
        begin

          // if it is correct then jump over it
          case aKeyType of
            confidentiality:
            begin
              if TagValue = _alg_id[alg_AES_128] then
              begin
                NextTag;
              end
              else
              begin
                exit;
              end;
            end;

            signing:
            begin
              if TagValue = _alg_id[alg_SHA1_HMAC] then
              begin
                NextTag;
              end
              else
              begin
                exit;
              end;
            end;
          end;
        end;

        // try to create a key
        s := TUPnP_SessionKey.CreateFromXML(aDevSecService.fCryptoProvider, aBuffer);

        // creation failed => exit
        if s = nil then
        begin
          exit;
        end
        else
        begin

          // if the key is good then assign it under the index
          fKey[nextKey] := s;
          fKey[nextKey].fKeyType := aKeyType;

          // and increment the index
          Inc(nextKey);
        end;
      end;
    end;
  end;

var
  i: integer;
const
  actname = 'CreateFromXML';
begin
  // call inherited constructor
  Create;

  with aBuffer do

    // look for a sessionkeys tag
  begin
    if TagName = _SessionKeys then
    begin

      // get the next tag
      NextTag;

      // preset the index
      nextKey := 0;

      // loop to get two pairs of keys
      for i := 0 to 1 do
      begin

        // get two confidentiality keys
        if TagName = _key_type[confidentiality] then
        begin
          GetTwoKeys(confidentiality);
        end
        else
        begin
          // get two signing keys
          if TagName = _key_type[signing] then
          begin
            GetTwoKeys(signing);
          end;
        end;
      end;

      // we should have 4 keys assigned
      if nextKey < 4 then
      begin

        // loop through and check if each key is assigned; if so then free it
        for i := 0 to 3 do
        begin
          if Assigned(fKey[i]) then
          begin
            fKey[i].Free;
          end;
        end;

        // and raise an exception
        RaiseException(ClassName, actname, 1);
      end;

      // set the key ID to a random value
      fDeviceKeyID := Random(maxint);

      // initialise the sequence number to zero
      fDeviceSequenceNumber := 0;
      fCPSequenceNumber     := 0;

      // create a random sequence base
      fSequenceBase := aDevSecService.fRandomString;

      // set a default CPKeyID
      fCPKeyID := 0;

      // and preset the owners hash to ''
      fOwnerPKHashB64 := '';
    end
    else
    begin
      // bad xml, so raise an exception
      RaiseException(ClassName, actname, 2);
    end;
  end;
end;

procedure TUPnP_Session.SaveToXML(aBuffer: TUPnP_XMLStream);
{
  Save a session to xml
  Status: FULLY TESTED
}
var
  x: TUPnP_KeyType;
  y: TUPnP_KeyDirection;
  s: TUPnP_SessionKey;
begin
  with aBuffer do
  begin

    // write the session keys prolog
    WriteTagStart(_SessionKeys);

    // save two key types
    for x := low(TUPnP_KeyType) to high(TUPnP_KeyType) do
    begin

      // save the key type prolog
      WriteTagStart(_key_type[x]);

      // save the algorithm
      case x of
        confidentiality:
        begin
          WriteTagAndValue(_algorithmA, _alg_id[alg_AES_128]);
        end;
        signing:
        begin
          WriteTagAndValue(_algorithmA, _alg_id[alg_SHA1_HMAC]);
        end;
      end;

      // two key directions per type
      for y := low(TUPnP_KeyDirection) to high(TUPnP_KeyDirection) do
      begin
        // use a local variable for speed
        s := Key[x, y];

        // save the key
        if s <> nil then
        begin
          s.SaveToXML(aBuffer);
        end;
      end;

      // write the key type epilog
      WriteTagEnd(_key_type[x]);
    end;

    // write the session keys epilog
    WriteTagEnd(_SessionKeys);
  end;
end;

procedure TUPnP_Session.SaveToStream(aWriter: TWriter);
{
  Save a session to a persistent file / stream
  Status: FULLY TESTED
}
var
  i: integer;
begin
  with aWriter do
  begin

    // loop to save four keys
    for i := 0 to 3 do
    begin
      if Assigned(fKey[i]) then
      begin
        fKey[i].SaveToStream(aWriter);
      end;
    end;

    // save the other data
    WriteString(fOwnerPKHashB64);
    WriteInteger(fCPKeyID);
    WriteInteger(fDeviceKeyID);
    WriteInteger(fDeviceSequenceNumber);
    WriteInteger(fCPSequenceNumber);
    WriteString(fSequenceBase);
  end;
end;

function TUPnP_Session.GetKey(aKeyType: TUPnP_KeyType;
  aKeyDirection: TUPnP_KeyDirection): TUPnP_SessionKey;
{
  Get the CryptoAPI key handle
  Status: FULLY TESTED
}
var
  i: integer;
begin
  // preset the result to nil = fail
  Result := nil;

  // loop through all four keys
  for i := 0 to 3 do

    // check if the key exists and its direction and type are OK
  begin
    if Assigned(fKey[i]) and (fKey[i].fDirection = aKeyDirection) and
      (fKey[i].fKeyType = aKeyType) then
    begin

      // if so then return the key and break
      Result := fKey[i];
      break;
    end;
  end;
end;


// *********************** TUPnP_SessionsList ********************

function TUPnP_SessionsList.fGetSession(aDeviceKeyID: integer): TUPnP_Session;
{
  Get a session entry from the session key ID
  Status: FULLY TESTED
}
var
  i: integer;
  s: TUPnP_Session;
begin
  // no match find => return nil
  Result := nil;

  try

    // scan the whole session list
    for i := 0 to pred(Count) do
    begin

      // type entry as a session
      s := Items[i] as TUPnP_Session;

      // if the key ID matches we have a hit
      if s.fDeviceKeyID = aDeviceKeyID then
      begin

        // assign the result & exit...
        Result := s;
        exit;
      end;
    end;

  except

    // swallow exceptions in the type casting
    on Exception do
      Result := nil;
  end;
end;

constructor TUPnP_SessionsList.CreateFromStream(aDevSecService: TUPnP_DeviceSecurity;
  aReader: TReader);
{
  Load the session list from a persistent file / stream
  Status: FULLY TESTED
}
var
  i, cnt: integer;
  e:      TUPnP_Session;
begin
  // call inherited constructor
  Create(True);

  with aReader do
  begin

    // read the list count
    cnt := ReadInteger;

    // read the list of entries
    for i := 1 to cnt do
    begin

      // create an entry and load the data
      e := TUPnP_Session.CreateFromStream(aDevSecService, aReader);

      // if it is loaded then add it to the list
      if e <> nil then
      begin
        Add(e);
      end;
    end;

  end;
end;

procedure TUPnP_SessionsList.SaveToStream(aWriter: TWriter);
{
  Save the session list to a persistent file / stream
  Status: FULLY TESTED
}
var
  i: integer;
begin
  with aWriter do
  begin
    // write the list count
    WriteInteger(Count);

    // write the whole list
    for i := 0 to pred(Count) do
    begin
      TUPnP_Session(Items[i]).SaveToStream(aWriter);
    end;

  end;
end;


// *********************** Byte Copy Utilities ********************

function TUPnP_RSA_Key.ReverseString(aString: string): string;
{
  Reverses a string
  Status: FULLY TESTED
}
var
  i: integer;
begin
  Result := '';
  for i := length(aString) downto 1 do
  begin
    Result := Result + aString[i];
  end;
end;


// *********************** BASE64 Conversion Utilities ********************

{$ifndef UseMSWindowsXPCryptoAPI}
const
  // Lookup table for base 64 characters
  CharTable: PChar =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='#9#10#13#0;

function TableFind(Value: char; Table: PChar; Len: integer): integer; assembler;
{
  Fast lookup to find the index offset of a character in a table
  Status: FULLY TESTED
}
asm
  PUSH  EDI
  MOV   EDI,EDX
  REPNE SCASB
  MOV   EAX,0
  JNE   @@1
  MOV   EAX,EDI
  SUB   EAX,EDX
  @@1:  DEC   EAX
  POP   EDI
end;
{$endif}

function Base64ToBinary(Source: string): string;
{
  Convert a base 64 string to a binary array
  Status: FULLY TESTED

  On entry
  - Source must contain a valid base 64 string
  - destLength is any value

  On exit
  - destLength returns the size of the decoded binary data
  - function returns a memory buffer containing the decoded binary data
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  dl: dword;
  xC: dword;
  xFlags: dword;
const
  actName = 'Base64ToBinary';
{$else}
  shiftRegister: cardinal;
  done: boolean;
  index, j, srcPtr, dstPtr, d, destlength: integer;
{$endif}
begin
{$ifdef UseMSWindowsXPCryptoAPI}
  // get the size
  if not CryptStringToBinary(@Source[1], length(Source), CRYPT_STRING_BASE64, nil, @dl, @xC, @xFlags) then
  begin
    RaiseException('', actname, 1);
  end;

  // set Result buffer to correct length
  SetLength(Result, dl);

  // do the conversion
  if not CryptStringToBinary(@Source[1], length(Source), CRYPT_STRING_BASE64, @Result[1], @dl, @xC, @xFlags) then
  begin
    RaiseException('', actname, 2);
  end;
{$else}

  // pad the input if needed
  while length(Source) mod 4 <> 0 do
  begin
    Source := Source + '=';
  end;

  // calculate the output data length
  destLength := (Length(Source) * 3) div 4;

  // every '=' character indicates that the destination length is one byte shorter
  for index := 1 to Length(Source) do
  begin
    if Source[index] = '=' then
    begin
      Dec(destLength);
    end;
  end;

  // get the memory for the binary data
  SetLength(Result, destLength);

  // set up pointers and flags
  srcPtr := 1;
  dstPtr := 1;
  done   := False;

  // loop through the whole string
  while not done do
  begin

    // initialize the shift register
    shiftRegister := 0;

    // read 4 characters from the base 64 Source
    for j := 0 to 3 do
    begin

      // lookup the index of the character in the character table
      index := TableFind(Source[srcPtr], CharTable, 65);

      // if it was a valid Base 64 character then proceed
      if index >= 0 then
      begin

        // shift the register left by 6 bits
        shiftRegister := shiftRegister shl 6;

        // append the index to shift register
        if index < 64 then
        begin
          shiftRegister := shiftRegister or byte(index);
        end;
      end;

      // proceed to the next character
      Inc(srcPtr);
    end;

    // bump the pointers
    Inc(dstPtr, 3);
    d := dstPtr;

    // write 3 bytes to the binary Destination
    for j := 0 to 2 do
    begin

      // proceed to the previous byte
      Dec(d);

      // write the byte
      if d > destLength then
      begin
        done := True;
      end
      else
      begin
        Result[d] := char(shiftRegister);
      end;

      // shift the register right by 8 bits
      shiftRegister := shiftRegister shr 8;
    end;
  end;
{$endif}
end;

function BinaryToBase64(Source: string): string;
{
  Convert a binary array to a base 64 string
  Status: FULLY TESTED

  On entry
  - Source must point to a buffer containing binary data
  - sourceLength is the number of bytes to be converted

  On exit
  - returns the binary data encoded as a Base 64 string
}
var
{$ifdef UseMSWindowsXPCryptoAPI}
  dl: dword;
const
  actName = 'BinaryToBase64';
{$else}
var
  shiftRegister: cardinal;
  done: boolean;
  i, trailingNulCount, srcPtr, dstPtr, d, sourceLength: integer;
{$endif}
begin
{$ifdef UseMSWindowsXPCryptoAPI}
  // get the size
  if not CryptBinaryToString(@Source[1], length(Source), CRYPT_STRING_BASE64, nil, @dl) then
  begin
    RaiseException('', actname, 1);
  end;

  // get some space
  SetLength(Result, dl);

  // do the conversion
  if not CryptBinaryToString(@Source[1], length(Source), CRYPT_STRING_BASE64, @Result[1], @dl) then
  begin
    RaiseException('', actname, 2);
  end;

  // and trim the output length to the correct final length
  SetLength(Result, dl - sizeof(widechar));
{$else}

  // preset the result
  Result := '';

  // exit if the input data is bad
  sourceLength := length(Source);
  if sourceLength = 0 then
  begin
    exit;
  end;

  // make sure we have enough space in result i.e. get more than we need
  SetLength(Result, ((sourceLength * 4) div 3) + 4);

  // set up pointers and flags
  srcPtr := 1;
  dstPtr := 1;
  done   := False;
  trailingNulCount := 0;

  // loop through the whole string
  while not done do
  begin

    // initialise the shift register
    shiftRegister := 0;

    // read 3 bytes from the binary source
    for i := 0 to 2 do
    begin

      // shift the register left by 8 bits
      shiftRegister := shiftRegister shl 8;

      // if we have read the last of the source characters, we must pad the output
      // with trailing '=' characters
      if srcPtr > sourceLength then
      begin
        Inc(trailingNulCount);
      end
      else
      begin
        // otherwise append the source byte to the shift register
        shiftRegister := shiftRegister or byte(Source[srcPtr]);
      end;

      // proceed to the next byte
      Inc(srcPtr);
    end;

    // set the done flag if all source characters have been read
    done := (srcPtr > sourceLength);

    // bump the pointers
    Inc(dstPtr, 4);
    d := dstPtr;

    // write 4 characters to the base 64 Destination
    for i := 0 to 3 do
    begin

      // proceed to the previous character
      Dec(d);

      // check if we have trailing nuls
      if trailingNulCount > 0 then
      begin

        // decrement the number of nulls yet to be written
        Dec(trailingNulCount);

        // write a '=' charachter to the result
        Result[d] := '=';
      end
      else
      begin
        // otherwise encode the last 6 bits as a base 64 character and write
        // it to the result
        Result[d] := CharTable[shiftRegister and $3F];
      end;

      // shift the register right by 6 bits
      shiftRegister := shiftRegister shr 6;
    end;

  end;

  // and trim the output length to the correct final length
  SetLength(Result, dstPtr - 1);
{$endif}
end;


// *********************** Hashing & Signing Utilities ********************

class function TSecUtils.StringToHash(aString: string;
  aCryptoProvider: HCRYPTPROV): string;
{
  Convert a string to a hash (string)
  Status: FULLY TESTED
}
var
  hHash: hCryptHash;
  dSize: dword;
const
  paramSize: dword = sizeof(dword);
  actname = 'StringToHash';
begin
  // create a hash object; on failure raise an exception
  if not CryptCreateHash(aCryptoProvider, CALG_SHA, 0, 0, @hHash) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  try
    // hash the data; on failure raise an exception
    if not CryptHashData(hHash, @aString[1], length(aString), 0) then
    begin
      RaiseException(ClassName, actname, 2);
    end;

    // get the hash size using HP_HASHSIZE; on failure raise an exception
    if not CryptGetHashParam(hHash, HP_HASHSIZE, @dSize, @paramSize, 0) then
    begin
      RaiseException(ClassName, actname, 3);
    end;

    // get memory to accept the hash data
    SetLength(Result, dSize);

    // get the hash data; on failure raise an exception
    if not CryptGetHashParam(hHash, HP_HASHVAL, @Result[1], @dSize, 0) then
    begin
      RaiseException(ClassName, actname, 4);
    end;

  finally
    // destroy the hash object; on failure raise an exception
    if not CryptDestroyHash(hHash) then
    begin
      RaiseException(ClassName, actname, 5);
    end;
  end;
end;

class function TSecUtils.CreateHMACDigest(aKey, aPlainText: string;
  aCryptoProvider: HCRYPTPROV): string;
{
  Create an HMAC digest
  Status: FULLY TESTED
}
var
  hHash1, hHash2: hCryptHash;
  ipad, opad: array[0..AES_HMACBlockLength] of byte;
  i:     integer;
  c:     byte;
  pHash: pointer;
  dSize: dword;
const
  actname = 'CreateHMACDigest';
  paramSize: dword = sizeof(dword);
begin
  // create a hash object; on failure raise an exception
  if not CryptCreateHash(aCryptoProvider, CALG_SHA, 0, 0, @hHash1) then
  begin
    RaiseException(ClassName, actname, 1);
  end;

  // create a hash object; on failure raise an exception
  if not CryptCreateHash(aCryptoProvider, CALG_SHA, 0, 0, @hHash2) then
  begin
    RaiseException(ClassName, actname, 2);
  end;

  try
    // initialise the ipad and opad structures
    FillChar(ipad, sizeof(ipad), $36);
    FillChar(opad, sizeof(opad), $5C);

    // OR the key into ipad and opad
    for i := 0 to length(aKey) - 1 do
    begin
      c := byte(aKey[i + 1]);
      ipad[i] := c xor $36;
      opad[i] := c xor $5C;
    end;

    // hash the ipad; on failure raise an exception
    if not CryptHashData(hHash1, @ipad, AES_HMACBlockLength, 0) then
    begin
      RaiseException(ClassName, actname, 3);
    end;

    // hash the opad; on failure raise an exception
    if not CryptHashData(hHash2, @opad, AES_HMACBlockLength, 0) then
    begin
      RaiseException(ClassName, actname, 4);
    end;

    // hash the plaintext; on failure raise an exception
    if not CryptHashData(hHash1, @aPlainText[1], length(aPlainText), 0) then
    begin
      RaiseException(ClassName, actname, 5);
    end;

    // get the hash size using HP_HASHSIZE; on failure raise an exception
    if not CryptGetHashParam(hHash1, HP_HASHSIZE, @dSize, @paramSize, 0) then
    begin
      RaiseException(ClassName, actname, 6);
    end;

    // get memory to accept the hash data
    GetMem(pHash, dSize);
    try
      // extract the 1st hash into pHash; on failure raise an exception
      if not CryptGetHashParam(hHash1, HP_HASHVAL, pHash, @dSize, 0) then
      begin
        RaiseException(ClassName, actname, 7);
      end;

      // add pHash (the 1st hash) to the 2nd hash; on failure raise an exception
      if not CryptHashData(hHash2, pHash, dSize, 0) then
      begin
        RaiseException(ClassName, actname, 8);
      end;

    finally
      FreeMem(pHash, dSize);
    end;

    // get the 2nd hash size using HP_HASHSIZE; on failure raise an exception
    if not CryptGetHashParam(hHash2, HP_HASHSIZE, @dSize, @paramSize, 0) then
    begin
      RaiseException(ClassName, actname, 9);
    end;

    // set the result size
    SetLength(Result, dSize);

    // extract the 2nd hash into result; on failure raise an exception
    if not CryptGetHashParam(hHash2, HP_HASHVAL, @Result[1], @dSize, 0) then
    begin
      RaiseException(ClassName, actname, 10);
    end;

  finally

    // destroy the hash object; on failure raise an exception
    if not CryptDestroyHash(hHash1) then
    begin
      RaiseException(ClassName, actname, 11);
    end;

    if not CryptDestroyHash(hHash2) then
    begin
      RaiseException(ClassName, actname, 12);
    end;
  end;
end;

procedure TUPnP_SessionKey.AppendPadding(var aString: string);
{
  Append block padding to a string
  Status: FULLY TESTED
}
var
  len, padlen: integer;
begin
  len := length(aString);

  // calculate the length of padding needed
  padlen := AES_BlockLength - (len mod AES_BlockLength);

  // apply the new length
  SetLength(aString, padlen + len);

  // fill with random bytes
  CryptGenRandom(fCryptoProvider, padlen, @aString[len + 1]);

  // and set the last byte to show how much padding has been applied
  aString[padlen + len] := char(padlen and $ff);
end;

procedure TUPnP_SessionKey.StripPadding(var aString: string);
{
  Strip block padding from a string
  Status: FULLY TESTED
}
var
  len, padLen: integer;
begin
  len := length(aString);

  // the pad length is indicated by the last byte of the plaintext
  padlen := integer(aString[len]);

  // if the pad length is less than the length of the string then we can adjust
  // the string length accordingly
  if padLen < len then
  begin
    SetLength(aString, len - padLen);
  end;
end;

function TUPnP_RSA_Key.StripZeroByte(aString: string): string;
{
  Convert a big endian signed integer from x0FF.. format to xFF.. format
  Status: FULLY TESTED
}
var
  i, len: integer;
begin
  len := length(aString);

  // scan for leading #0 bytes
  for i := 1 to len do
  begin
    if aString[i] <> #0 then
    begin
      break;
    end;
  end;

  // chop off the leading #0 bytes
  Result := Copy(aString, i, len + 1 - i);
end;

function TUPnP_RSA_Key.PrependZeroByte(aString: string): string;
{
  Convert a big endian signed integer from xFF.. format to x0FF.. format
  Status: FULLY TESTED
}
begin
  // chop off all leading #0 bytes
  Result := StripZeroByte(aString);

  // and then add back a #0 if highest order bit is set
  if (Result = '') or ((byte(Result[1]) and $80) = $80) then
  begin
    Result := #0 + Result;
  end;
end;


// ******************** TUPnP_DigitalSignature ****************

constructor TUPnP_DigitalSignature.Create(aDevSec: TUPnP_DeviceSecurity;
  aSignatureNode: string; aSessionList: TUPnP_SessionsList;
  aDSigParamList: TStringList; aSigDirection: TUPnP_KeyDirection;
  aDigestCallback: TUPnP_DigSig_DigestCallback; out aResult: TUPnP_AuthorisationResult;
  out aSessionKey: TUPnP_Session);
{
  Creates a DSig object from an Xml <Signature> node

  Parses the node and collects the following data:
   <SignedInfo> - the plain text of the signed info
   <SignatureValue> - the encrypted digest of signed info
   <Reference> - a list [fReferences] of ID's which refer to the actual signed data
   <KeyInfo> - containing information about the signing key

  Creates a key from the <KeyInfo> and uses it to verify the <SignatureValue> against
  the encrypted <SignatureValue>

  Finally calls aDigestCallback repeatedly for each <Reference> to fetch and validate
  the DSig digests

  Returns fSigningResult := auth_GeneralError /  auth_Accepted / auth_BadSignature
   / auth_Bad_PublicKey

  Status: FULLY TESTED
}
var
  lSigIOBuffer, lKeyIOBuffer: TUPnP_XMLStream;
  lDigest, lURI, lHMAC, lSignedInfo, lSignature: string;
  lPubKey: TUPnP_RSA_Key;
  i: integer;
  lReferences: TStringList;
begin
  inherited Create;
  aResult     := auth_GeneralError;
  aSessionKey := nil;

  lReferences := TStringList.Create;
  try
    lSigIOBuffer := TUPnP_XMLStream.Create;
    try
      lSigIOBuffer.WriteValues([aSignatureNode]);

      with lSigIOBuffer do
      begin

        // reset the parser
        ResetParser;

        // scan the whole file
        while not EOF do
        begin

          // get the next tag
          NextTag;

          // get the Digest results
          if TagName = _dsReference then
          begin
            // if it has an URI attribute then get it
            lURI := TagAttributeValue[_URI];

            // and strip the preceding #
            lURI := Copy(lURI, 2, length(lURI) - 1);

            // read a maximumun of four tags
            for i := 0 to 3 do
            begin

              // get the next tag
              NextTag;

              // look for a Digest Value entry
              if TagName = _dsDigestValue then
              begin

                // add it to the parameter list
                lReferences.Add(Format(_equals, [lURI, TagValue]));
                break;
              end;
            end;

            continue;
          end;

          // get the SignedInfo
          if TagName = _dsSignedInfo then
          begin
            lSignedInfo := FullTagValue;
            continue;
          end;

          // get the Signature
          if TagName = _dsSignatureValue then
          begin
            lSignature := TagValue;
            continue;
          end;

          // get the (session) KeyName
          if TagName = _KeyName then
          begin

            // add it to the DSig parameter list
            aDSigParamList.Add(Format(_equals, [TagName, TagValue]));

            // look up the respective session
            aSessionKey := aSessionList.Session[StrToIntDef(TagValue, -1)];
            if aSessionKey = nil then
            begin
              aResult := auth_UnknownSession;
            end
            else
            begin
              // if we have a good session key, use it to create an HMAC signature on the
              // SignedInfo parameter
              lHMac := BinaryToBase64(TSecUtils.CreateHMACDigest(
                aSessionKey.Key[signing, aSigDirection].KeyValue, lSignedInfo,
                aDevSec.fCryptoProvider));

              if lHMac = lSignature then
              begin
                aResult := auth_Accepted;
              end
              else
              begin
                aResult := auth_SignatureNotVerified;
              end;
            end;

            continue;
          end;

          // if we have information about a public key, use it to create a public key object
          if TagName = _RSAKeyValue then
          begin
            // add the key value to the parameter list
            aDSigParamList.Add(Format(_equals, [TagName, FullTagValue]));

            // add the hash of the key value to the parameter list
            aDSigParamList.Add(Format(_equals,
              [_KeyHash, BinaryToBase64(
              TSecUtils.StringToHash(FullTagValue,
              aDevSec.fCryptoProvider))]));

            // create a buffer
            lKeyIOBuffer := TUPnP_XMLStream.Create;
            try

              // write the key value xml to the buffer
              lKeyIOBuffer.WriteValues([FullTagValue]);

              // reset the parser
              lKeyIOBuffer.ResetParser;

              // try to create a public key from the xml
              try
                lPubKey := TUPnP_RSA_Key.CreateFromXML(aDevSec, lKeyIOBuffer);

                // check if the key is bad
                if lPubKey = nil then
                begin
                  aResult := auth_Bad_PublicKey;
                end
                else
                begin
                  try

                    // we have a good RSA key, so use it to verify the signature on <SignedInfo>
                    // against <SignatureValue>
                    if lPubKey.Verify(lSignedInfo,
                      Base64ToBinary(lSignature)) then
                    begin
                      aResult := auth_Accepted;
                    end
                    else
                    begin
                      aResult := auth_SignatureNotVerified;
                    end;

                  finally
                    lPubKey.Free;
                  end;
                end;

              except
                on Exception do
                  aResult := auth_SignatureNotVerified;
              end;

            finally
              lKeyIOBuffer.Free;
            end;

            continue;
          end;
        end;
      end;

    finally
      lSigIOBuffer.Free;
    end;

    // if the signature has not already validated, there is no need to check the digests
    if aResult <> auth_Accepted then
    begin
      exit;
    end;

    // pre-assume digest failure
    aResult := auth_BadDigest;

    // we call-back the caller to deliver the digests on the <Reference> nodes
    if Assigned(aDigestCallback) then
    begin
      for i := 0 to pred(lReferences.Count) do
      begin
        // assume failure
        aResult := auth_BadDigest;

        // get the digest
        aDigestCallback(lReferences.Names[i], lDigest);

        // if it does'nt match then our (failure) assumption was correct, so exit
        if lDigest <> lReferences.ValueFromIndex[i] then
        begin
          break;
        end;

        // so if we get here on the last loop, the result must be good
        aResult := auth_Accepted;
      end;
    end;
  finally
    lReferences.Free
  end;
end;

{$ifdef UseMSWindowsXPCryptoAPI}
  {
    Windows XP external Crypto API function imports
  }
  function CryptBinaryToString; external CRYPT32 name 'CryptBinaryToStringA';
  function CryptStringToBinary; external CRYPT32 name 'CryptStringToBinaryA';
{$endif}

end.

