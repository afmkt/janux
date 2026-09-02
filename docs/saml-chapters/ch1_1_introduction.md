# Chapter 1 Introduction


The Security Assertion Markup Language (SAML) defines the syntax and processing semantics of assertions made about a subject by a system entity. In the course of making, or relying upon such assertions, SAML system entities may use other protocols to communicate either regarding an assertion itself, or the subject of an assertion. This specification defines both the structure of SAML assertions, and an associated set of protocols, in addition to the processing rules involved in managing a SAML system.

SAML assertions and protocol messages are encoded in XML [XML] and use XML namespaces [XMLNS]. They are typically embedded in other structures for transport, such as HTTP POST requests or XML-encoded SOAP messages. The SAML bindings specification [SAMLBind] provides frameworks for the embedding and transport of SAML protocol messages. The SAML profiles specification [SAMLProf] provides a baseline set of profiles for the use of SAML assertions and protocols to accomplish specific use cases or achieve interoperability when using SAML features.

For additional explanation of SAML terms and concepts, refer to the SAML technical overview [SAMLTechOvw] and the SAML glossary [SAMLGloss] . Files containing just the SAML assertion schema [SAML-XSD] and protocol schema [SAMLP-XSD] are also available. The SAML conformance document [SAMLConform] lists all of the specifications that comprise SAML V2.0.

The following sections describe how to understand the rest of this specification.

1.1 Notation

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this specification are to be interpreted as described in IETF RFC 2119 [RFC 2119].

Listings of SAML schemas appear like this.

Example code listings appear like this.

Note: Notes like this are sometimes used to highlight non-normative commentary.

This specification uses schema documents conforming to W3C XML Schema [Schema1] and normative text to describe the syntax and semantics of XML-encoded SAML assertions and protocol messages. In cases of disagreement between the SAML schema documents and schema listings in this specification, the schema documents take precedence. Note that in some cases the normative text of this specification imposes constraints beyond those indicated by the schema documents.

Conventional XML namespace prefixes are used throughout the listings in this specification to stand for their respective namespaces (see Section 1.2) as follows, whether or not a namespace declaration is present in the example: Prefix

XML Namespace

Comments

saml:

urn:oasis:names:tc:SAML:2.0:assertion This is the SAML V2.0 assertion namespace, defined in a schema [SAML-XSD]. The prefix is generally elided in mentions of SAML assertion-related elements in text.

samlp:

urn:oasis:names:tc:SAML:2.0:protocol

This is the SAML V2.0 protocol namespace, defined in a schema [SAMLP-XSD]. The prefix is generally elided in mentions of XML protocol-related elements in text.

ds:

http://www.w3.org/2000/09/xmldsig#

This namespace is defined in the XML Signature Syntax and Processing specification [XMLSig] and its governing schema [XMLSig-XSD].

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 7 of 86

Prefix

XML Namespace

Comments

xenc:

http://www.w3.org/2001/04/xmlenc#

This namespace is defined in the XML Encryption Syntax and Processing specification [XMLEnc] and its governing schema [XMLEnc-XSD].

xs:

http://www.w3.org/2001/XMLSchema

This namespace is defined in the W3C XML Schema specification [Schema1]. In schema listings, this is the default namespace and no prefix is shown. For clarity, the prefix is generally shown in specification text when XML Schema-related constructs are mentioned.

xsi:

http://www.w3.org/2001/XMLSchemainstance

This namespace is defined in the W3C XML Schema specification [Schema1] for schema-related markup that appears in XML instances.

This specification uses the following typographical conventions in text: <SAMLElement>, <ns:ForeignElement>, XMLAttribute, Datatype, OtherKeyword.

1.2 Schema Organization and Namespaces

The SAML assertion structures are defined in a schema [SAML-XSD] associated with the following XML namespace:

urn:oasis:names:tc:SAML:2.0:assertion

The SAML request-response protocol structures are defined in a schema [SAMLP-XSD] associated with the following XML namespace: urn:oasis:names:tc:SAML:2.0:protocol

The assertion schema is imported into the protocol schema. See Section 4.2 for information on SAML namespace versioning.

Also imported into both schemas is the schema for XML Signature [XMLSig], which is associated with the following XML namespace:

http://www.w3.org/2000/09/xmldsig#

Finally, the schema for XML Encryption [XMLEnc] is imported into the assertion schema and is associated with the following XML namespace: http://www.w3.org/2001/04/xmlenc#

1.3 Common Data Types

The following sections define how to use and interpret common data types that appear throughout the SAML schemas.

1.3.1 String Values

All SAML string values have the type xs:string, which is built in to the W3C XML Schema Datatypes specification [Schema2]. Unless otherwise noted in this specification or particular profiles, all strings in SAML messages MUST consist of at least one non-whitespace character (whitespace is defined in the XML Recommendation [XML] Section 2.3).

Unless otherwise noted in this specification or particular profiles, all elements in SAML documents that have the XML Schema xs:string type, or a type derived from that, MUST be compared using an exact binary comparison. In particular, SAML implementations and deployments MUST NOT depend on caseinsensitive string comparisons, normalization or trimming of whitespace, or conversion of locale-specific

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 8 of 86

formats such as numbers or currency. This requirement is intended to conform to the W3C working-draft Requirements for String Identity, Matching, and String Indexing [W3C-CHAR].

If an implementation is comparing values that are represented using different character encodings, the implementation MUST use a comparison method that returns the same result as converting both values to the Unicode character encoding, Normalization Form C [UNICODE-C], and then performing an exact binary comparison. This requirement is intended to conform to the W3C Character Model for the World Wide Web [W3C-CharMod], and in particular the rules for Unicode-normalized Text.

Applications that compare data received in SAML documents to data from external sources MUST take into account the normalization rules specified for XML. Text contained within elements is normalized so that line endings are represented using linefeed characters (ASCII code 10Decimal), as described in the XML Recommendation [XML] Section 2.11. XML attribute values defined as strings (or types derived from strings) are normalized as described in [XML] Section 3.3.3. All whitespace characters are replaced with blanks (ASCII code 32Decimal).

The SAML specification does not define collation or sorting order for XML attribute values or element content. SAML implementations MUST NOT depend on specific sorting orders for values, because these can differ depending on the locale settings of the hosts involved.

1.3.2 URI Values

All SAML URI reference values have the type xs:anyURI, which is built in to the W3C XML Schema Datatypes specification [Schema2].

Unless otherwise indicated in this specification, all URI reference values used within SAML-defined elements or attributes MUST consist of at least one non-whitespace character, and are REQUIRED to be absolute [RFC 2396].

Note that the SAML specification makes extensive use of URI references as identifiers, such as status codes, format types, attribute and system entity names, etc. In such cases, it is essential that the values be both unique and consistent, such that the same URI is never used at different times to represent different underlying information.

1.3.3 Time Values

All SAML time values have the type xs:dateTime, which is built in to the W3C XML Schema Datatypes specification [Schema2], and MUST be expressed in UTC form, with no time zone component.

SAML system entities SHOULD NOT rely on time resolution finer than milliseconds. Implementations MUST NOT generate time instants that specify leap seconds.

1.3.4 ID and ID Reference Values

The xs:ID simple type is used to declare SAML identifiers for assertions, requests, and responses. Values declared to be of type xs:ID in this specification MUST satisfy the following properties in addition to those imposed by the definition of the xs:ID type itself:

• Any party that assigns an identifier MUST ensure that there is negligible probability that that party or any other party will accidentally assign the same identifier to a different data object.

• Where a data object declares that it has a particular identifier, there MUST be exactly one such declaration.

The mechanism by which a SAML system entity ensures that the identifier is unique is left to the implementation. In the case that a random or pseudorandom technique is employed, the probability of two randomly chosen identifiers being identical MUST be less than or equal to 2-128 and SHOULD be less than or equal to 2-160. This requirement MAY be met by encoding a randomly chosen value between 128 and

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 9 of 86

160 bits in length. The encoding must conform to the rules defining the xs:ID datatype. A pseudorandom generator MUST be seeded with unique material in order to ensure the desired uniqueness properties between different systems.

The xs:NCName simple type is used in SAML to reference identifiers of type xs:ID since xs:IDREF cannot be used for this purpose. In SAML, the element referred to by a SAML identifier reference might actually be defined in a document separate from that in which the identifier reference is used. Using xs:IDREF would violate the requirement that its value match the value of an ID attribute on some element in the same XML document.

Note: It is anticipated that the World Wide Web Consortium will standardize a global attribute for holding ID-typed values, called xml:id [XML-ID]. The Security Services Technical Committee plans to move away from SAML-specific ID attributes to this style of assigning unique identifiers as soon as practicable after the xml:id attribute is standardized.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 10 of 86
