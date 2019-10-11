{
  UPnP_DeviceSecurityStrings:
  Strings for UPnP Device and Service objects.
  Copyright (c) 2001..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_DeviceSecurityStrings.pas,v 1.4 2005/10/02 14:01:32 FiddianA Exp $

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

unit UPnP_DeviceSecurityStrings;

interface

uses
  UPnP_DeviceSecurity;

const
  _Envelope                    = 'Envelope';
  _DevSecFile                  = 'DevSecFile';
  _Keys                        = 'Keys';
  _RSAKeyValue                 = 'RSAKeyValue';
  _Modulus                     = 'Modulus';
  _Exponent                    = 'Exponent';
  _algorithm                   = 'algorithm';
  _value                       = 'value';
  _algorithmA                  = 'Algorithm';
  _SessionKeys                 = 'SessionKeys';
  _OwnershipRequest            = 'OwnershipRequest';
  _shaLC                       = 'sha1';
  _shaUC                       = 'SHA1';
  _hash                        = 'hash';
  _text                        = 'text';
  _secret                      = 'secret';
  _LifetimeSequenceBase        = 'LifetimeSequenceBase';
  _permissions                 = 'DefinedPermissions';
  _PermsNamespaceFmt           = 'xmlns:mfgr="%s"';
  _Owners                      = 'Owners';
  _profiles                    = 'Profiles';
  _ACL                         = 'acl';
  _entry                       = 'entry';
  _subject                     = 'subject';
  _issuer                      = 'issuer';
  _sequence                    = 'Sequence';
  _cert                        = 'cert';
  _define                      = 'define';
  _tag                         = 'tag';
  _any                         = 'any';
  _access                      = 'access';
  _all                         = 'all';
  _allStar                     = 'all*';
  _valid                       = 'valid';
  _notbefore                   = 'not-before';
  _notafter                    = 'not-after';
  _mayNotDelegate              = 'may-not-delegate';
  _KeyName                     = 'KeyName';
  _KeyValue                    = 'KeyValue';
  _Freshness                   = 'Freshness';
  _SequenceBase                = 'SequenceBase';
  _SequenceNumber              = 'SequenceNumber';
  _UPnPData                    = 'UPnPData';
  _Header                      = 'Header';
  _URI                         = 'URI';
  _mustUnderstand              = 'mustUnderstand';
  _toDevice                    = 'toDevice';
  _fromDevice                  = 'fromDevice';
  _keyHash                     = 'keyHash';
  _FreshnessReference          = '#Freshness';
  _BodyReference               = '#Body';
  _dsSignatureXmlNS            = 'xmlns="http://www.w3.org/2000/09/xmldsig#"';
  _dsReference                 = 'Reference';
  _dsDigestValue               = 'DigestValue';
  _dsCanonicalAlgorithm        = 'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"';
  _dsCanonicalMethod           = 'CanonicalizationMethod';
  _dsSignatureMethod           = 'SignatureMethod';
  _dsSignatureAlgorithm1       = 'Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"';
  _dsSignatureAlgorithm2       = 'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"';
  _dsReferenceURIAttr          = 'URI="%s"';
  _dsDigestMethod              = 'DigestMethod';
  _dsDigestAlgorithm           = 'Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"';
  _dsKeyInfo                   = 'KeyInfo';
  _dsSignature                 = 'Signature';
  _dsSignatureValue            = 'SignatureValue';
  _dsSignedInfo                = 'SignedInfo';
  _dsTransforms                = 'Transforms';
  _dsTransform                 = 'Transform';

  _equals                      = '%s=%s';

  { algorithm ID constants }
  _alg_Id: array [TUPnP_KeyAlgorithm] of string = (
    '?',
    'AES-128-CBC',
    'SHA1-HMAC',
    'RSA');

  { key type constants }
  _key_type: array [TUPnP_KeyType] of string = (
    'Confidentiality',
    'Signing');

  { key direction constatnts }
  _key_Dir: array [TUPnP_KeyDirection] of string = (
    'KeyToDevice',
    'KeyFromDevice');

  _Password   = 'aardvark';
  _capikeytag = 'CAPIKeyFollows';

  fmt1 = 'Crypto API exception code "x%x" occurred in routine "%s" at position "%u"';
  fmt2 = 'Crypto API exception code "x%x" occurred in class "%s" action "%s" at position "%u"';
  fmt3 = 'Class "%s", tried to call method "%s" before the RSA key parameters were initialised.';

  { supported protocols xml }
  _supported = '<Supported>' + '<Protocols><p>UPnP</p></Protocols>' +
    '<HashAlgorithms><p>SHA1</p></HashAlgorithms>' +
    '<EncryptionAlgorithms><p>NULL</p><p>RSA</p><p>AES-128-CBC</p></EncryptionAlgorithms>' +
    '<SigningAlgorithms><p>NULL</p><p>RSA</p><p>SHA1-HMAC</p></SigningAlgorithms>' +
    '</Supported>';

implementation

end.
