{
  UPnP_XmlStreamer:
  TMemoryStream derivative that can read and write XML tags and values
  For UPnP Device and Service objects
  Copyright (c) 2001..2005, Andrew Fiddian-Green

  $Header: /NET/Delphi\040Components/UPnP_XmlStreamer.pas,v 1.5 2005/07/22 01:08:27 FiddianA Exp $

  For more information on:
   - Andrew Fiddian-Green see http://www.whitebear.ch
   - UPnP see http://www.upnp.org
   - UPnP Device Architecture see http://www.upnp.org/UPnPDevice_Architecture_1.0.htm

  Contact:
   - Andrew Fiddian-Green - software@whitebear.ch

  Status:

  Revision History:
    June 2005
      - Created; (TUPnP_XMLStream moved to its own independent unit)
    July 22, 2005
      - Release v1.5.3
}

unit UPnP_XmlStreamer;

interface

uses
  Classes;

type
  {
    TPropertyAvailableFlag: flag that indicates whether properties are already available
  }
  TPropertyAvailableFlag  = (paHttpPathName, paHttpMethod, paTagValue,
    paTagName, paBodyOffset,
    paContentLength, paTransferEncoding);
  TPropertyAvailableFlags = set of TPropertyAvailableFlag;

  {
    TUPnP_XMLStream:
    encapsulates creating, reading, writing to a memory buffer
  }
  TUPnP_XMLStream = class(TMemoryStream)
  private
    fTokenStart: integer;
    fTmp: integer;
    fTagEnd: integer;
    fTagValue: string;
    fFullTagName: string;
    fExtendedTagName: string;
    fTagName: string;
    fPropertyAvailableFlags: TPropertyAvailableFlags;
    function GetEof: boolean;
    function GetTagName: string;
    function GetTagValue: string;
    function GetExtendedTagName: string;
    function GetFullTagName: string;
    function GetFullTagValue: string;
    function GetTagAttributeValue(aAttName: PChar): string;
    function GetAsText: string;
  public
    procedure Clear;
    procedure WriteTagEnd(const TagName: string);
    procedure WriteTagStart(const TagName: string);
    procedure WriteTagAndValue(const TagName, TagValue: string);
    procedure WriteValues(const Values: array of string);
    procedure WriteLN(const aString: string);
    procedure WriteNewLine;
    procedure WriteStream(aStream: TStream);
    procedure WriteTagStartAndAttributes(const TagName: string;
      const Attributes: array of string);
    procedure ResetParser;
    procedure NextTag;
    procedure NextPeer;
    procedure MoveParser(aPosition: integer);
    function GotoTagName(aTokenName: string): boolean;
    property EOF: boolean Read GetEof;
    property TagName: string Read GetTagName;
    property TagValue: string Read GetTagValue;
    property TagAttributeValue[aAttName: PChar]: string Read GetTagAttributeValue;
    property ExtendedTagName: string Read GetExtendedTagName;
    property FullTagName: string Read GetFullTagName;
    property FullTagValue: string Read GetFullTagValue;
    property TokenStart: integer Read fTokenStart;
    property AsText: string Read GetAsText;
  end;

implementation

uses
  SysUtils;

const
  CRLF = #13#10; // carriage return + line feed

procedure TUPnP_XMLStream.Clear;
{
  Resets the Buffer and respective pointers
  Status:
}
begin
  fTokenStart := 0;
  fTmp      := 0;
  fTagValue := '';
  fTagName  := '';
  fFullTagName := '';
  fPropertyAvailableFlags := [];
  Position  := 0;
  Size      := 0;
end;

procedure TUPnP_XMLStream.WriteTagAndValue(const TagName, TagValue: string);
{
  Writes a record in XML in the format:
    <tag_name>tag_value</tag_name>
  or:
    <tag_name/>
}
begin
{$ifdef TidyXML}
  WriteValues(['<',TagName,'>',TagValue,'</',TagName,'>',crlf]);
{$else}
  // with exclusive canonicalisation we must use the expanded forms for all elements
  WriteValues(['<', TagName, '>', TagValue, '</', TagName, '>']);
{$endif}
end;

procedure TUPnP_XMLStream.WriteTagStart(const TagName: string);
{
  Pushes a tag name onto the XML "stack" in the format:
    <tag_name>
}
begin
  WriteValues(['<', TagName, '>']);
end;

procedure TUPnP_XMLStream.WriteTagStartAndAttributes(const TagName: string;
  const Attributes: array of string);
{
  Writes a tag name and an array of attribute strings to the stream: <tag_name attr0 attr1>
  Status: FULLY TESTED
}
var
  i: integer;
begin
  WriteValues(['<', TagName]);
  for i := 0 to high(Attributes) do
  begin
    WriteValues([' ', Attributes[i]]);
  end;
  WriteValues(['>']);
end;

procedure TUPnP_XMLStream.WriteTagEnd(const TagName: string);
{
  Pops a tag name off the XML "stack" in the format:
    </tag_name>
}
begin
{$ifdef TidyXML}
  WriteValues(['</',TagName,'>',crlf]);
{$else}
  WriteValues(['</', TagName, '>']);
{$endif}
end;

procedure TUPnP_XMLStream.WriteValues(const Values: array of string);
{
  Writes the string
}
var
  i: integer;
begin
  for i := 0 to high(Values) do
  begin
    WriteBuffer(Values[i][1], length(Values[i]));
  end;
end;

procedure TUPnP_XMLStream.WriteLN(const aString: string);
{
  Writes the string followed by a Carriage Return + Line Feed
}
begin
  WriteValues([aString, CRLF]);
end;

procedure TUPnP_XMLStream.WriteNewLine;
{
  Writes an empty line
}
begin
  WriteValues([CRLF]);
end;

procedure TUPnP_XMLStream.WriteStream(aStream: TStream);
{
  Copies data from a stream to the TUPnP_XMLStream
  used e.g. for transmitting binary graphics files
}
var
  ss: string;
begin
  aStream.Position := 0;
  SetLength(ss, aStream.Size);
  aStream.ReadBuffer(ss[1], aStream.Size);
  WriteValues([ss]);
end;

function TUPnP_XMLStream.GetTagAttributeValue(aAttName: PChar): string;
{
  Returns the value of a named attribute in the current tag (if any)
}
var
  ptr, start, stop: PChar;
  len: integer;
begin
  Result := '';
  // force FullTagName to be loaded
  GetFullTagName;
  start := PChar(fExtendedTagName);
  len   := length(aAttName);
  stop  := start + len;
  // keep checking until we get a correct match
  while start < stop do
  begin
    // look for the attribute name
    ptr := AnsiStrPos(start, aAttName);
    // not found then exit
    if ptr = nil then
    begin
      exit;
    end;
    // only proceed if the previous character is whitespace or ':' and the subsequent characters are '="'
    if ((ptr - 1)^ in [#9, #10, #13, ' ', ':']) and (StrLComp(ptr + len, '="', 2) = 0) then
    begin
      // we have the start of the attribute value
      // move on pointer to allow for the '="'
      start := ptr + len + 2;
      ptr   := start;
      // the end of attribute value is indicated by '"'
      while not (ptr^ in [#0, '"']) do
      begin
        Inc(ptr);
      end;
      // unexpected end of the string => exit
      if ptr^ = #0 then
      begin
        exit;
      end;
      // set the result, and return
      SetString(Result, start, ptr - start);
      exit;
    end
    // not a well formed attribute name => jog the pointer and try again
    else
    begin
      start := ptr + 1;
    end;
  end;
end;

procedure TUPnP_XMLStream.ResetParser;
{
  Set the XML parser position to the end of the HTTP headers
}
begin
  fTokenStart := 0; // BodyOffset;
  fTmp := fTokenStart;
  NextTag;
end;

procedure TUPnP_XMLStream.MoveParser(aPosition: integer);
{
  Set the XML parser to the given position
}
begin
  fTokenStart := aPosition;
  fTmp      := fTokenStart;
  fTagValue := '';
  fTagName  := '';
  fFullTagName := '';
  exclude(fPropertyAvailableFlags, paTagValue);
  exclude(fPropertyAvailableFlags, paTagname);
end;

function TUPnP_XMLStream.GetEof: boolean;
{
  Check for end of file
}
begin
  Result := (fTokenStart >= Size) or (fTmp >= Size);
end;

procedure TUPnP_XMLStream.NextPeer;
{
  Scans an XML Body to find the next peer XML token and moves the parser pointer to this point
}
begin
  GetTagValue;
  MoveParser(fTagEnd);
  NextTag;
end;

procedure TUPnP_XMLStream.NextTag;
{
  Scans an XML Body to find the next XML token and moves the parser pointer to this point
}
begin
  fTagValue    := '';
  fTagName     := '';
  fFullTagName := '';
  exclude(fPropertyAvailableFlags, paTagValue);
  exclude(fPropertyAvailableFlags, paTagname);
  repeat
    // go to the beginning of the next tag -- i.e. '<'
    while (fTokenStart < Size) and (PChar(Memory)[fTokenStart] <> '<') do
    begin
      Inc(fTokenStart);
    end;
    if EOF then
    begin
      exit;
    end;
    Inc(fTokenStart);
    // if we have a closing XML tag, a comment or an XML processing instruction then
    // ignore it  i.e. loop again...
  until not (PChar(Memory)[fTokenStart] in ['/', '?', '!']);
end;

function TUPnP_XMLStream.GetFullTagValue: string;
{
  Gets the current token complete with beginning and end tags
}
var
  i: integer;
begin
  GetTagValue;
  // go to the end of the current tag
  i := fTagEnd;
  // and move on to the next (i.e. closing) '>'
  while (i < Size) and (PChar(Memory)[i] <> '>') do
  begin
    Inc(i);
  end;
  Result := Copy(PChar(Memory), fTokenStart, i + 2 - fTokenStart);
end;

function TUPnP_XMLStream.GetFullTagName: string;
{
  Gets the current token name complete with namespace if any
}
begin
  GetTagName;
  Result := fFullTagName;
end;

function TUPnP_XMLStream.GetExtendedTagName: string;
{
  Gets the current token name complete with namespace and attributes;
}
begin
  GetTagName;
  Result := fExtendedTagName;
end;

function TUPnP_XMLStream.GetTagName: string;
{
  Gets the current token name
}
var
  i: integer;
begin
  if not (paTagName in fPropertyAvailableFlags) then
  begin
    include(fPropertyAvailableFlags, paTagName);
    // preset empty result so that we can exit easily
    fTagName := '';
    fFullTagName := '';
    Result := '';

    if EOF then
    begin
      exit;
    end;

    // at this point we have the start of a token in the form <tokenname or <ns:tokenname...
    // go to the end of the token name i.e. look for whitespace or / or >
    fTmp := fTokenStart;
    while (fTmp < Size) and (not (PChar(Memory)[fTmp] in [#0..#32, '/', '>'])) do
    begin
      Inc(fTmp);
    end;

    if EOF then
    begin
      exit;
    end;

    // check for a colon indicating the <ns:tokenname coding form
    i := fTokenStart;
    while (i < fTmp) and (PChar(Memory)[i] <> ':') do
    begin
      Inc(i);
    end;
    // if a colon was found then the token name starts one character beyond it
    if i < fTmp then
    begin
      Inc(i);
    end
    else
    begin
      i := fTokenStart;
    end;

    // return the token name
    fTagName := Copy(PChar(Memory), i + 1, fTmp - i);
    SetString(fTagName, PChar(longint(Memory) + i), fTmp - i);

    // return the full token name
    fFullTagName := Copy(PChar(Memory), fTokenStart + 1, fTmp - fTokenStart);

    // go to the end of the token tag i.e. look for '>'
    i := fTmp;
    while (i < Size) and (not (PChar(Memory)[i] in [#0, '>'])) do
    begin
      Inc(i);
    end;

    // return the extended token name
    fExtendedTagName := Copy(PChar(Memory), fTokenStart + 1, i - fTokenStart);
  end;
  Result := fTagName;
end;

function TUPnP_XMLStream.GetTagValue: string;
{
  Gets the current token value
}
var
  p: pchar;
begin
  if not (paTagName in fPropertyAvailableFlags) then
  begin
    GetTagName;
  end;
  if not (paTagValue in fPropertyAvailableFlags) then
  begin
    include(fPropertyAvailableFlags, paTagValue);
    // preset empty result so that we can exit easily
    fTagValue := '';
    Result    := '';

    // exit if no more tags
    if EOF or (TagName = '') then
    begin
      exit;
    end;

    // go to the end of the token tag i.e. look for '>'
    fTmp := fTokenStart;
    while (fTmp < Size) and (PChar(Memory)[fTmp] <> '>') do
    begin
      Inc(fTmp);
    end;

    if EOF then
    begin
      exit;
    end;

    // if we have the form <tokenname/> then tokenvalue is empty  i.e. exit..
    if (PChar(Memory)[fTmp - 1] = '/') then
    begin
      exit;
    end;

    p := PChar(Memory) + fTmp - 1;
    repeat
      p := p + 1;
      // look for the next instance of the fully qualified token name
      p := AnsiStrPos(p, PChar(fFullTagName));
      if p = nil then
      begin
        exit;
      end;

      // repeat until it is preceded by '</' and followed by whitespace or '>'
    until (StrLComp(p - 2, '</', 2) = 0) and (p[length(fFullTagName)] in [#0..#32, '>']);

    // return the token value
    fTagValue := Copy(PChar(Memory), fTmp + 2, p - PChar(Memory) - fTmp - 3);
    fTagEnd   := p - PChar(Memory) - 2;
  end;
  Result := fTagValue;
end;

function TUPnP_XMLStream.GotoTagName(aTokenName: string): boolean;
{
  Go to the start of a named tag
}
begin
  Result := False;
  while (TagName <> aTokenName) do
  begin
    NextTag;
    if EOF then
    begin
      exit;
    end;
  end;
  Result := True;
end;

function TUPnP_XMLStream.GetAsText: string;
begin
  SetString(Result, PChar(Memory), Size);
end;

end.

