# Chapter 2 SAML Assertions


An assertion is a package of information that supplies zero or more statements made by a SAML authority; SAML authorities are sometimes referred to as asserting parties in discussions of assertion generation and exchange, and system entities that use received assertions are known as relying parties. (Note that these terms are different from requester and responder, which are reserved for discussions of SAML protocol message exchange.)

SAML assertions are usually made about a subject, represented by the <Subject> element. However, the <Subject> element is optional, and other specifications and profiles may utilize the SAML assertion structure to make similar statements without specifying a subject, or possibly specifying the subject in an alternate way. Typically there are a number of service providers that can make use of assertions about a subject in order to control access and provide customized service, and accordingly they become the relying parties of an asserting party called an identity provider.

This SAML specification defines three different kinds of assertion statements that can be created by a SAML authority. All SAML-defined statements are associated with a subject. The three kinds of statement defined in this specification are:

• Authentication: The assertion subject was authenticated by a particular means at a particular time.

• Attribute: The assertion subject is associated with the supplied attributes.

• Authorization Decision: A request to allow the assertion subject to access the specified resource has been granted or denied.

The outer structure of an assertion is generic, providing information that is common to all of the statements within it. Within an assertion, a series of inner elements describe the authentication, attribute, authorization decision, or user-defined statements containing the specifics.

As described in Section 7, extensions are permitted by the SAML assertion schema, allowing user-defined extensions to assertions and statements, as well as allowing the definition of new kinds of assertions and statements.

The SAML technical overview [SAMLTechOvw] and glossary [SAMLGloss] provide more detailed explanation of SAML terms and concepts.

2.1 Schema Header and Namespace Declarations

The following schema fragment defines the XML namespaces and other header information for the assertion schema:

<schema targetNamespace="urn:oasis:names:tc:SAML:2.0:assertion" xmlns="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" elementFormDefault="unqualified" attributeFormDefault="unqualified" blockDefault="substitution" version="2.0"> <import namespace="http://www.w3.org/2000/09/xmldsig#" schemaLocation="http://www.w3.org/TR/2002/REC-xmldsig-core20020212/xmldsig-core-schema.xsd"/> <import namespace="http://www.w3.org/2001/04/xmlenc#" schemaLocation="http://www.w3.org/TR/2002/REC-xmlenc-core20021210/xenc-schema.xsd"/> <annotation> <documentation> Document identifier: saml-schema-assertion-2.0

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 11 of 86

Location: http://docs.oasis-open.org/security/saml/v2.0/ Revision history: V1.0 (November, 2002): Initial Standard Schema. V1.1 (September, 2003): Updates within the same V1.0 namespace. V2.0 (March, 2005): New assertion schema for SAML V2.0 namespace. </documentation> </annotation>

</schema>

2.2 Name Identifiers

The following sections define the SAML constructs that contain descriptive identifiers for subjects and the issuers of assertions and protocol messages.

There are a number of circumstances in SAML in which it is useful for two system entities to communicate regarding a third party; for example, the SAML authentication request protocol enables third-party authentication of a subject. Thus, it is useful to establish a means by which parties may be associated with identifiers that are meaningful to each of the parties. In some cases, it will be necessary to limit the scope within which an identifier is used to a small set of system entities (to preserve the privacy of a subject, for example). Similar identifiers may also be used to refer to the issuer of a SAML protocol message or assertion.

It is possible that two or more system entities may use the same name identifier value when referring to different identities. Thus, each entity may have a different understanding of that same name. SAML provides name qualifiers to disambiguate a name identifier by effectively placing it in a federated namespace related to the name qualifiers. SAML V2.0 allows an identifier to be qualified in terms of both an asserting party and a particular relying party or affiliation, allowing identifiers to exhibit pair-wise semantics, when required.

Name identifiers may also be encrypted to further improve their privacy-preserving characteristics, particularly in cases where the identifier may be transmitted via an intermediary.

Note: To avoid use of relatively advanced XML schema constructs (among other reasons), the various types of identifier elements do not share a common type hierarchy.

2.2.1 Element <BaseID>

The <BaseID> element is an extension point that allows applications to add new kinds of identifiers. Its BaseIDAbstractType complex type is abstract and is thus usable only as the base of a derived type. It includes the following attributes for use by extended identifier representations:

NameQualifier [Optional]

The security or administrative domain that qualifies the identifier. This attribute provides a means to federate identifiers from disparate user stores without collision. SPNameQualifier [Optional] Further qualifies an identifier with the name of a service provider or affiliation of providers. This attribute provides an additional means to federate identifiers on the basis of the relying party or parties.

The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the identifier's type definition explicitly defines their use and semantics.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 12 of 86

The following schema fragment defines the <BaseID> element and its BaseIDAbstractType complex type: <attributeGroup name="IDNameQualifiers"> <attribute name="NameQualifier" type="string" use="optional"/> <attribute name="SPNameQualifier" type="string" use="optional"/> </attributeGroup> <element name="BaseID" type="saml:BaseIDAbstractType"/> <complexType name="BaseIDAbstractType" abstract="true"> <attributeGroup ref="saml:IDNameQualifiers"/> </complexType>

2.2.2 Complex Type NameIDType

The NameIDType complex type is used when an element serves to represent an entity by a string-valued name. It is a more restricted form of identifier than the <BaseID> element and is the type underlying both the <NameID> and <Issuer> elements. In addition to the string content containing the actual identifier, it provides the following optional attributes:

NameQualifier [Optional] The security or administrative domain that qualifies the name. This attribute provides a means to federate names from disparate user stores without collision.

SPNameQualifier [Optional]

Further qualifies a name with the name of a service provider or affiliation of providers. This attribute provides an additional means to federate names on the basis of the relying party or parties. Format [Optional]

A URI reference representing the classification of string-based identifier information. See Section 8.3 for the SAML-defined URI references that MAY be used as the value of the Format attribute and their associated descriptions and processing rules. Unless otherwise specified by an element based on this type, if no Format value is provided, then the value urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified (see Section 8.3.1) is in effect.

When a Format value other than one specified in Section 8.3 is used, the content of an element of this type is to be interpreted according to the definition of that format as provided outside of this specification. If not otherwise indicated by the definition of the format, issues of anonymity, pseudonymity, and the persistence of the identifier with respect to the asserting and relying parties are implementation-specific.

SPProvidedID [Optional]

A name identifier established by a service provider or affiliation of providers for the entity, if different from the primary name identifier given in the content of the element. This attribute provides a means of integrating the use of SAML with existing identifiers already in use by a service provider. For example, an existing identifier can be "attached" to the entity using the Name Identifier Management protocol defined in Section 3.6.

Additional rules for the content of (or the omission of) these attributes can be defined by elements that make use of this type, and by specific Format definitions. The NameQualifier and SPNameQualifier attributes SHOULD be omitted unless the element or format explicitly defines their use and semantics.

The following schema fragment defines the NameIDType complex type:

<complexType name="NameIDType"> <simpleContent>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 13 of 86

<extension base="string"> <attributeGroup ref="saml:IDNameQualifiers"/> <attribute name="Format" type="anyURI" use="optional"/> <attribute name="SPProvidedID" type="string" use="optional"/> </extension> </simpleContent> </complexType>

2.2.3 Element <NameID>

The <NameID> element is of type NameIDType (see Section 2.2.2), and is used in various SAML assertion constructs such as the <Subject> and <SubjectConfirmation> elements, and in various protocol messages (see Section 3).

The following schema fragment defines the <NameID> element:

<element name="NameID" type="saml:NameIDType"/>

2.2.4 Element <EncryptedID>

The <EncryptedID> element is of type EncryptedElementType, and carries the content of an unencrypted identifier element in encrypted fashion, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The <EncryptedID> element contains the following elements:

<xenc:EncryptedData> [Required]

The encrypted content and associated encryption details, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The Type attribute SHOULD be present and, if present, MUST contain a value of http://www.w3.org/2001/04/xmlenc#Element. The encrypted content MUST contain an element that has a type of NameIDType or AssertionType, or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType. <xenc:EncryptedKey> [Zero or More]

Wrapped decryption keys, as defined by [XMLEnc]. Each wrapped key SHOULD include a Recipient attribute that specifies the entity for whom the key has been encrypted. The value of the Recipient attribute SHOULD be the URI identifier of a SAML system entity, as defined by Section 8.3.6.

Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation. For more on such issues, see [XMLEnc] Section 6.3.

Note that an entire assertion can be encrypted into this element and used as an identifier. In such a case, the <Subject> element of the encrypted assertion supplies the "identifier" of the subject of the enclosing assertion. Note also that if the identifying assertion is invalid, then so is the enclosing assertion.

The following schema fragment defines the <EncryptedID> element and its EncryptedElementType complex type:

<complexType name="EncryptedElementType"> <sequence> <element ref="xenc:EncryptedData"/> <element ref="xenc:EncryptedKey" minOccurs="0" maxOccurs="unbounded"/> </sequence> </complexType> <element name="EncryptedID" type="saml:EncryptedElementType"/>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 14 of 86

2.2.5 Element <Issuer>

The <Issuer> element, with complex type NameIDType, provides information about the issuer of a SAML assertion or protocol message. The element requires the use of a string to carry the issuer's name, but permits various pieces of descriptive data (see Section 2.2.2).

Overriding the usual rule for this element's type, if no Format value is provided with this element, then the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity is in effect (see Section 8.3.6).

The following schema fragment defines the <Issuer> element:

<element name="Issuer" type="saml:NameIDType"/>

2.3 Assertions

The following sections define the SAML constructs that either contain assertion information or provide a means to refer to an existing assertion.

2.3.1 Element <AssertionIDRef>

The <AssertionIDRef> element makes a reference to a SAML assertion by its unique identifier. The specific authority who issued the assertion or from whom the assertion can be obtained is not specified as part of the reference. See Section 3.3.1 for a protocol element that uses such a reference to ask for the corresponding assertion.

The following schema fragment defines the <AssertionIDRef> element:

<element name="AssertionIDRef" type="NCName"/>

2.3.2 Element <AssertionURIRef>

The <AssertionURIRef> element makes a reference to a SAML assertion by URI reference. The URI reference MAY be used to retrieve the corresponding assertion in a manner specific to the URI reference. See Section 3.7 of the Bindings specification [SAMLBind] for information on how this element is used in a protocol binding to accomplish this.

The following schema fragment defines the <AssertionURIRef> element:

<element name="AssertionURIRef" type="anyURI"/>

2.3.3 Element <Assertion>

The <Assertion> element is of the AssertionType complex type. This type specifies the basic information that is common to all assertions, including the following elements and attributes:

Version [Required]

The version of this assertion. The identifier for the version of SAML defined in this specification is "2.0". SAML versioning is discussed in Section 4. ID [Required] The identifier for this assertion. It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness. IssueInstant [Required] The time instant of issue in UTC, as described in Section 1.3.3.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 15 of 86

<Issuer> [Required]

The SAML authority that is making the claim(s) in the assertion. The issuer SHOULD be unambiguous to the intended relying parties.

This specification defines no particular relationship between the entity represented by this element and the signer of the assertion (if any). Any such requirements imposed by a relying party that consumes the assertion or by specific profiles are application-specific.

<ds:Signature> [Optional] An XML Signature that protects the integrity of and authenticates the issuer of the assertion, as described below and in Section 5. <Subject> [Optional] The subject of the statement(s) in the assertion. <Conditions> [Optional] Conditions that MUST be evaluated when assessing the validity of and/or when using the assertion. See Section 2.5 for additional information on how to evaluate conditions. <Advice> [Optional] Additional information related to the assertion that assists processing in certain situations but which MAY be ignored by applications that do not understand the advice or do not wish to make use of it. Zero or more of the following statement elements: <Statement> A statement of a type defined in an extension schema. An xsi:type attribute MUST be used to indicate the actual statement type. <AuthnStatement>

An authentication statement.

<AuthzDecisionStatement>

An authorization decision statement.

<AttributeStatement>

An attribute statement.

An assertion with no statements MUST contain a <Subject> element. Such an assertion identifies a principal in a manner which can be referenced or confirmed using SAML methods, but asserts no further information associated with that principal.

Otherwise <Subject>, if present, identifies the subject of all of the statements in the assertion. If <Subject> is omitted, then the statements in the assertion apply to a subject or subjects identified in an application- or profile-specific manner. SAML itself defines no such statements, and an assertion without a subject has no defined meaning in this specification.

Depending on the requirements of particular protocols or profiles, the issuer of a SAML assertion may often need to be authenticated, and integrity protection may often be required. Authentication and message integrity MAY be provided by mechanisms provided by a protocol binding in use during the delivery of an assertion (see [SAMLBind]). The SAML assertion MAY be signed, which provides both authentication of the issuer and integrity protection.

If such a signature is used, then the <ds:Signature> element MUST be present, and a relying party MUST verify that the signature is valid (that is, that the assertion has not been tampered with) in accordance with [XMLSig]. If it is invalid, then the relying party MUST NOT rely on the contents of the assertion. If it is valid, then the relying party SHOULD evaluate the signature to determine the identity and appropriateness of the issuer and may continue to process the assertion in accordance with this

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 16 of 86

specification and as it deems appropriate (for example, evaluating conditions, advice, following profilespecific rules, and so on).

Note that whether signed or unsigned, the inclusion of multiple statements within a single assertion is semantically equivalent to a set of assertions containing those statements individually (provided the subject, conditions, etc. are also the same).

The following schema fragment defines the <Assertion> element and its AssertionType complex type:

<element name="Assertion" type="saml:AssertionType"/> <complexType name="AssertionType"> <sequence> <element ref="saml:Issuer"/> <element ref="ds:Signature" minOccurs="0"/> <element ref="saml:Subject" minOccurs="0"/> <element ref="saml:Conditions" minOccurs="0"/> <element ref="saml:Advice" minOccurs="0"/> <choice minOccurs="0" maxOccurs="unbounded"> <element ref="saml:Statement"/> <element ref="saml:AuthnStatement"/> <element ref="saml:AuthzDecisionStatement"/> <element ref="saml:AttributeStatement"/> </choice> </sequence> <attribute name="Version" type="string" use="required"/> <attribute name="ID" type="ID" use="required"/> <attribute name="IssueInstant" type="dateTime" use="required"/> </complexType>

2.3.4 Element <EncryptedAssertion>

The <EncryptedAssertion> element represents an assertion in encrypted fashion, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The <EncryptedAssertion> element contains the following elements:

<xenc:EncryptedData> [Required]

The encrypted content and associated encryption details, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The Type attribute SHOULD be present and, if present, MUST contain a value of http://www.w3.org/2001/04/xmlenc#Element. The encrypted content MUST contain an element that has a type of or derived from AssertionType. <xenc:EncryptedKey> [Zero or More] Wrapped decryption keys, as defined by [XMLEnc]. Each wrapped key SHOULD include a Recipient attribute that specifies the entity for whom the key has been encrypted. The value of the Recipient attribute SHOULD be the URI identifier of a SAML system entity as defined by Section 8.3.6.

Encrypted assertions are intended as a confidentiality protection mechanism when the plain-text value passes through an intermediary.

The following schema fragment defines the <EncryptedAssertion> element:

<element name="EncryptedAssertion" type="saml:EncryptedElementType"/>

2.4 Subjects

This section defines the SAML constructs used to describe the subject of an assertion.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 17 of 86

2.4.1 Element <Subject>

The optional <Subject> element specifies the principal that is the subject of all of the (zero or more) statements in the assertion. It contains an identifier, a series of one or more subject confirmations, or both:

<BaseID>, <NameID>, or <EncryptedID> [Optional]

Identifies the subject. <SubjectConfirmation> [Zero or More]

Information that allows the subject to be confirmed. If more than one subject confirmation is provided, then satisfying any one of them is sufficient to confirm the subject for the purpose of applying the assertion.

A <Subject> element can contain both an identifier and zero or more subject confirmations which a relying party can verify when processing an assertion. If any one of the included subject confirmations are verified, the relying party MAY treat the entity presenting the assertion as one that the asserting party has associated with the principal identified in the name identifier and associated with the statements in the assertion. This attesting entity and the actual subject may or may not be the same entity.

If there are no subject confirmations included, then any relationship between the presenter of the assertion and the actual subject is unspecified.

A <Subject> element SHOULD NOT identify more than one principal.

The following schema fragment defines the <Subject> element and its SubjectType complex type:

<element name="Subject" type="saml:SubjectType"/> <complexType name="SubjectType"> <choice> <sequence> <choice> <element ref="saml:BaseID"/> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> <element ref="saml:SubjectConfirmation" minOccurs="0" maxOccurs="unbounded"/> </sequence> <element ref="saml:SubjectConfirmation" maxOccurs="unbounded"/> </choice> </complexType>

2.4.1.1 Element <SubjectConfirmation>

The <SubjectConfirmation> element provides the means for a relying party to verify the correspondence of the subject of the assertion with the party with whom the relying party is communicating. It contains the following attributes and elements:

Method [Required]

A URI reference that identifies a protocol or mechanism to be used to confirm the subject. URI references identifying SAML-defined confirmation methods are currently defined in the SAML profiles specification [SAMLProf]. Additional methods MAY be added by defining new URIs and profiles or by private agreement. <BaseID>, <NameID>, or <EncryptedID> [Optional] Identifies the entity expected to satisfy the enclosing subject confirmation requirements.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 18 of 86

<SubjectConfirmationData> [Optional] Additional confirmation information to be used by a specific confirmation method. For example, typical content of this element might be a <ds:KeyInfo> element as defined in the XML Signature Syntax and Processing specification [XMLSig], which identifies a cryptographic key (See also Section 2.4.1.3). Particular confirmation methods MAY define a schema type to describe the elements, attributes, or content that may appear in the <SubjectConfirmationData> element. The following schema fragment defines the <SubjectConfirmation> element and its SubjectConfirmationType complex type: <element name="SubjectConfirmation" type="saml:SubjectConfirmationType"/> <complexType name="SubjectConfirmationType"> <sequence> <choice minOccurs="0"> <element ref="saml:BaseID"/> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> <element ref="saml:SubjectConfirmationData" minOccurs="0"/> </sequence> <attribute name="Method" type="anyURI" use="required"/> </complexType>

2.4.1.2 Element <SubjectConfirmationData>

The <SubjectConfirmationData> element has the SubjectConfirmationDataType complex type. It specifies additional data that allows the subject to be confirmed or constrains the circumstances under which the act of subject confirmation can take place. Subject confirmation takes place when a relying party seeks to verify the relationship between an entity presenting the assertion (that is, the attesting entity) and the subject of the assertion's claims. It contains the following optional attributes that can apply to any method:

NotBefore [Optional]

A time instant before which the subject cannot be confirmed. The time value is encoded in UTC, as described in Section 1.3.3. NotOnOrAfter [Optional] A time instant at which the subject can no longer be confirmed. The time value is encoded in UTC, as described in Section 1.3.3. Recipient [Optional] A URI specifying the entity or location to which an attesting entity can present the assertion. For example, this attribute might indicate that the assertion must be delivered to a particular network endpoint in order to prevent an intermediary from redirecting it someplace else. InResponseTo [Optional] The ID of a SAML protocol message in response to which an attesting entity can present the assertion. For example, this attribute might be used to correlate the assertion to a SAML request that resulted in its presentation. Address [Optional] The network address/location from which an attesting entity can present the assertion. For example, this attribute might be used to bind the assertion to particular client addresses to prevent an attacker from easily stealing and presenting the assertion from another location. IPv4 addresses SHOULD be represented in the usual dotted-decimal format (e.g., "1.2.3.4"). IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF RFC 3513 [RFC 3513] (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210").

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 19 of 86

Arbitrary attributes

This complex type uses an <xs:anyAttribute> extension point to allow arbitrary namespacequalified XML attributes to be added to <SubjectConfirmationData> constructs without the need for an explicit schema extension. This allows additional fields to be added as needed to supply additional confirmation-related information. SAML extensions MUST NOT add local (non-namespacequalified) XML attributes or XML attributes qualified by a SAML-defined namespace to the SubjectConfirmationDataType complex type or a derivation of it; such attributes are reserved for future maintenance and enhancement of SAML itself.

Arbitrary elements This complex type uses an <xs:any> extension point to allow arbitrary XML elements to be added to <SubjectConfirmationData> constructs without the need for an explicit schema extension. This allows additional elements to be added as needed to supply additional confirmation-related information.

Particular confirmation methods and profiles that make use of those methods MAY require the use of one or more of the attributes defined within this complex type. For examples of how these attributes (and subject confirmation in general) can be used, see the Profiles specification [SAMLProf].

Note that the time period specified by the optional NotBefore and NotOnOrAfter attributes, if present, SHOULD fall within the overall assertion validity period as specified by the <Conditions> element's NotBefore and NotOnOrAfter attributes. If both attributes are present, the value for NotBefore MUST be less than (earlier than) the value for NotOnOrAfter.

The following schema fragment defines the <SubjectConfirmationData> element and its SubjectConfirmationDataType complex type:

<element name="SubjectConfirmationData" type="saml:SubjectConfirmationDataType"/> <complexType name="SubjectConfirmationDataType" mixed="true"> <complexContent> <restriction base="anyType"> <sequence> <any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/> </sequence> <attribute name="NotBefore" type="dateTime" use="optional"/> <attribute name="NotOnOrAfter" type="dateTime" use="optional"/> <attribute name="Recipient" type="anyURI" use="optional"/> <attribute name="InResponseTo" type="NCName" use="optional"/> <attribute name="Address" type="string" use="optional"/> <anyAttribute namespace="##other" processContents="lax"/> </restriction> </complexContent> </complexType>

2.4.1.3 Complex Type KeyInfoConfirmationDataType

The KeyInfoConfirmationDataType complex type constrains a <SubjectConfirmationData> element to contain one or more <ds:KeyInfo> elements that identify cryptographic keys that are used in some way to authenticate an attesting entity. The particular confirmation method MUST define the exact mechanism by which the confirmation data can be used. The optional attributes defined by the SubjectConfirmationDataType complex type MAY also appear.

This complex type, or a type derived from it, SHOULD be used by any confirmation method that defines its confirmation data in terms of the <ds:KeyInfo> element.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 20 of 86

Note that in accordance with [XMLSig], each <ds:KeyInfo> element MUST identify a single cryptographic key. Multiple keys MAY be identified with separate <ds:KeyInfo> elements, such as when a principal uses different keys to confirm itself to different relying parties.

The following schema fragment defines the KeyInfoConfirmationDataType complex type:

<complexType name="KeyInfoConfirmationDataType" mixed="false"> <complexContent> <restriction base="saml:SubjectConfirmationDataType"> <sequence> <element ref="ds:KeyInfo" maxOccurs="unbounded"/> </sequence> </restriction> </complexContent> </complexType>

2.4.1.4 Example of a Key-Confirmed <Subject>

To illustrate the way in which the various elements and types fit together, below is an example of a <Subject> element containing a name identifier and a subject confirmation based on proof of possession of a key. Note the use of the KeyInfoConfirmationDataType to identify the confirmation data syntax as being a <ds:KeyInfo> element:

<Subject> <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"> scott@example.org </NameID> <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"> <SubjectConfirmationData xsi:type="saml:KeyInfoConfirmationDataType"> <ds:KeyInfo> <ds:KeyName>Scott's Key</ds:KeyName> </ds:KeyInfo> </SubjectConfirmationData> </SubjectConfirmation> </Subject>

2.5 Conditions

This section defines the SAML constructs that place constraints on the acceptable use of SAML assertions.

2.5.1 Element <Conditions>

The <Conditions> element MAY contain the following elements and attributes:

NotBefore [Optional]

Specifies the earliest time instant at which the assertion is valid. The time value is encoded in UTC, as described in Section 1.3.3. NotOnOrAfter [Optional] Specifies the time instant at which the assertion has expired. The time value is encoded in UTC, as described in Section 1.3.3. <Condition> [Any Number] A condition of a type defined in an extension schema. An xsi:type attribute MUST be used to indicate the actual condition type. <AudienceRestriction> [Any Number] Specifies that the assertion is addressed to a particular audience.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 21 of 86

<OneTimeUse> [Optional] Specifies that the assertion SHOULD be used immediately and MUST NOT be retained for future use. Although the schema permits multiple occurrences, there MUST be at most one instance of this element. <ProxyRestriction> [Optional]

Specifies limitations that the asserting party imposes on relying parties that wish to subsequently act as asserting parties themselves and issue assertions of their own on the basis of the information contained in the original assertion. Although the schema permits multiple occurrences, there MUST be at most one instance of this element.

Because the use of the xsi:type attribute would permit an assertion to contain more than one instance of a SAML-defined subtype of ConditionsType (such as OneTimeUseType), the schema does not explicitly limit the number of times particular conditions may be included. A particular type of condition MAY define limits on such use, as shown above.

The following schema fragment defines the <Conditions> element and its ConditionsType complex type:

<element name="Conditions" type="saml:ConditionsType"/> <complexType name="ConditionsType"> <choice minOccurs="0" maxOccurs="unbounded"> <element ref="saml:Condition"/> <element ref="saml:AudienceRestriction"/> <element ref="saml:OneTimeUse"/> <element ref="saml:ProxyRestriction"/> </choice> <attribute name="NotBefore" type="dateTime" use="optional"/> <attribute name="NotOnOrAfter" type="dateTime" use="optional"/> </complexType>

2.5.1.1 General Processing Rules

If an assertion contains a <Conditions> element, then the validity of the assertion is dependent on the sub-elements and attributes provided, using the following rules in the order shown below.

Note that an assertion that has condition validity status Valid may nonetheless be untrustworthy or invalid for reasons such as not being well-formed or schema-valid, not being issued by a trustworthy SAML authority, or not being authenticated by a trustworthy means.

Also note that some conditions may not directly impact the validity of the containing assertion (they always evaluate to Valid), but may restrict the behavior of relying parties with respect to the use of the assertion.

1. If no sub-elements or attributes are supplied in the <Conditions> element, then the assertion is considered to be Valid with respect to condition processing.

2. If any sub-element or attribute of the <Conditions> element is determined to be invalid, then the assertion is considered to be Invalid.

3. If any sub-element or attribute of the <Conditions> element cannot be evaluated, or if an element is encountered that is not understood, then the validity of the assertion cannot be determined and is considered to be Indeterminate.

4. If all sub-elements and attributes of the <Conditions> element are determined to be Valid, then the assertion is considered to be Valid with respect to condition processing.

The first rule that applies terminates condition processing; thus a determination that an assertion is Invalid takes precedence over that of Indeterminate.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 22 of 86

An assertion that is determined to be Invalid or Indeterminate MUST be rejected by a relying party (within whatever context or profile it was being processed), just as if the assertion were malformed or otherwise unusable.

2.5.1.2 Attributes NotBefore and NotOnOrAfter

The NotBefore and NotOnOrAfter attributes specify time limits on the validity of the assertion within the context of its profile(s) of use. They do not guarantee that the statements in the assertion will be correct or accurate throughout the validity period.

The NotBefore attribute specifies the time instant at which the validity interval begins. The NotOnOrAfter attribute specifies the time instant at which the validity interval has ended.

If the value for either NotBefore or NotOnOrAfter is omitted, then it is considered unspecified. If the NotBefore attribute is unspecified (and if all other conditions that are supplied evaluate to Valid), then the assertion is Valid with respect to conditions at any time before the time instant specified by the NotOnOrAfter attribute. If the NotOnOrAfter attribute is unspecified (and if all other conditions that are supplied evaluate to Valid), the assertion is Valid with respect to conditions from the time instant specified by the NotBefore attribute with no expiry. If neither attribute is specified (and if any other conditions that are supplied evaluate to Valid), the assertion is Valid with respect to conditions at any time.

If both attributes are present, the value for NotBefore MUST be less than (earlier than) the value for NotOnOrAfter.

2.5.1.3 Element <Condition>

The <Condition> element serves as an extension point for new conditions. Its ConditionAbstractType complex type is abstract and is thus usable only as the base of a derived type.

The following schema fragment defines the <Condition> element and its ConditionAbstractType complex type:

<element name="Condition" type="saml:ConditionAbstractType"/> <complexType name="ConditionAbstractType" abstract="true"/>

2.5.1.4 Elements <AudienceRestriction> and <Audience>

The <AudienceRestriction> element specifies that the assertion is addressed to one or more specific audiences identified by <Audience> elements. Although a SAML relying party that is outside the audiences specified is capable of drawing conclusions from an assertion, the SAML asserting party explicitly makes no representation as to accuracy or trustworthiness to such a party. It contains the following element:

<Audience>

A URI reference that identifies an intended audience. The URI reference MAY identify a document that describes the terms and conditions of audience membership. It MAY also contain the unique identifier URI from a SAML name identifier that describes a system entity (see Section 8.3.6).

The audience restriction condition evaluates to Valid if and only if the SAML relying party is a member of one or more of the audiences specified.

The SAML asserting party cannot prevent a party to whom the assertion is disclosed from taking action on the basis of the information provided. However, the <AudienceRestriction> element allows the SAML asserting party to state explicitly that no warranty is provided to such a party in a machine- and human-readable form. While there can be no guarantee that a court would uphold such a warranty exclusion in every circumstance, the probability of upholding the warranty exclusion is considerably improved.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 23 of 86

Note that multiple <AudienceRestriction> elements MAY be included in a single assertion, and each MUST be evaluated independently. The effect of this requirement and the preceding definition is that within a given condition, the audiences form a disjunction (an "OR") while multiple conditions form a conjunction (an "AND").

The following schema fragment defines the <AudienceRestriction> element and its AudienceRestrictionType complex type:

<element name="AudienceRestriction" type="saml:AudienceRestrictionType"/> <complexType name="AudienceRestrictionType"> <complexContent> <extension base="saml:ConditionAbstractType"> <sequence> <element ref="saml:Audience" maxOccurs="unbounded"/> </sequence> </extension> </complexContent> </complexType> <element name="Audience" type="anyURI"/>

2.5.1.5 Element <OneTimeUse>

In general, relying parties may choose to retain assertions, or the information they contain in some other form, for reuse. The <OneTimeUse> condition element allows an authority to indicate that the information in the assertion is likely to change very soon and fresh information should be obtained for each use. An example would be an assertion containing an <AuthzDecisionStatement> which was the result of a policy which specified access control which was a function of the time of day.

If system clocks in a distributed environment could be precisely synchronized, then this requirement could be met by careful use of the validity interval. However, since some clock skew between systems will always be present and will be combined with possible transmission delays, there is no convenient way for the issuer to appropriately limit the lifetime of an assertion without running a substantial risk that it will already have expired before it arrives.

The <OneTimeUse> element indicates that the assertion SHOULD be used immediately by the relying party and MUST NOT be retained for future use. Relying parties are always free to request a fresh assertion for every use. However, implementations that choose to retain assertions for future use MUST observe the <OneTimeUse> element. This condition is independent from the NotBefore and NotOnOrAfter condition information.

To support the single use constraint, a relying party should maintain a cache of the assertions it has processed containing such a condition. Whenever an assertion with this condition is processed, the cache should be checked to ensure that the same assertion has not been previously received and processed by the relying party.

A SAML authority MUST NOT include more than one <OneTimeUse> element within a <Conditions> element of an assertion.

For the purposes of determining the validity of the <Conditions> element, the <OneTimeUse> is considered to always be valid. That is, this condition does not affect validity but is a condition on use.

The following schema fragment defines the <OneTimeUse> element and its OneTimeUseType complex type:

<element name="OneTimeUse" type="saml:OneTimeUseType"/> <complexType name="OneTimeUseType"> <complexContent> <extension base="saml:ConditionAbstractType"/> </complexContent> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 24 of 86

2.5.1.6 Element <ProxyRestriction>

Specifies limitations that the asserting party imposes on relying parties that in turn wish to act as asserting parties and issue subsequent assertions of their own on the basis of the information contained in the original assertion. A relying party acting as an asserting party MUST NOT issue an assertion that itself violates the restrictions specified in this condition on the basis of an assertion containing such a condition.

The <ProxyRestriction> element contains the following elements and attributes:

Count [Optional]

Specifies the maximum number of indirections that the asserting party permits to exist between this assertion and an assertion which has ultimately been issued on the basis of it. <Audience> [Zero or More]

Specifies the set of audiences to whom the asserting party permits new assertions to be issued on the basis of this assertion.

A Count value of zero indicates that a relying party MUST NOT issue an assertion to another relying party on the basis of this assertion. If greater than zero, any assertions so issued MUST themselves contain a <ProxyRestriction> element with a Count value of at most one less than this value.

If no <Audience> elements are specified, then no audience restrictions are imposed on the relying parties to whom subsequent assertions can be issued. Otherwise, any assertions so issued MUST themselves contain an <AudienceRestriction> element with at least one of the <Audience> elements present in the previous <ProxyRestriction> element, and no <Audience> elements present that were not in the previous <ProxyRestriction> element.

A SAML authority MUST NOT include more than one <ProxyRestriction> element within a <Conditions> element of an assertion.

For the purposes of determining the validity of the <Conditions> element, the <ProxyRestriction> condition is considered to always be valid. That is, this condition does not affect validity but is a condition on use.

The following schema fragment defines the <ProxyRestriction> element and its ProxyRestrictionType complex type:

<element name="ProxyRestriction" type="saml:ProxyRestrictionType"/> <complexType name="ProxyRestrictionType"> <complexContent> <extension base="saml:ConditionAbstractType"> <sequence> <element ref="saml:Audience" minOccurs="0" maxOccurs="unbounded"/> </sequence> <attribute name="Count" type="nonNegativeInteger" use="optional"/> </extension> </complexContent> </complexType>

2.6 Advice

This section defines the SAML constructs that contain additional information about an assertion that an asserting party wishes to provide to a relying party.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 25 of 86

2.6.1 Element <Advice>

The <Advice> element contains any additional information that the SAML authority wishes to provide. This information MAY be ignored by applications without affecting either the semantics or the validity of the assertion.

The <Advice> element contains a mixture of zero or more <Assertion>, <EncryptedAssertion>, <AssertionIDRef>, and <AssertionURIRef> elements, and namespace-qualified elements in other non-SAML namespaces.

Following are some potential uses of the <Advice> element:

• Include evidence supporting the assertion claims to be cited, either directly (through incorporating the claims) or indirectly (by reference to the supporting assertions).

• State a proof of the assertion claims.

• Specify the timing and distribution points for updates to the assertion.

The following schema fragment defines the <Advice> element and its AdviceType complex type: <element name="Advice" type="saml:AdviceType"/> <complexType name="AdviceType"> <choice minOccurs="0" maxOccurs="unbounded"> <element ref="saml:AssertionIDRef"/> <element ref="saml:AssertionURIRef"/> <element ref="saml:Assertion"/> <element ref="saml:EncryptedAssertion"/> <any namespace="##other" processContents="lax"/> </choice> </complexType>

2.7 Statements

The following sections define the SAML constructs that contain statement information.

2.7.1 Element <Statement>

The <Statement> element is an extension point that allows other assertion-based applications to reuse the SAML assertion framework. SAML itself derives its core statements from this extension point. Its StatementAbstractType complex type is abstract and is thus usable only as the base of a derived type.

The following schema fragment defines the <Statement> element and its StatementAbstractType complex type:

<element name="Statement" type="saml:StatementAbstractType"/> <complexType name="StatementAbstractType" abstract="true"/>

2.7.2 Element <AuthnStatement>

The <AuthnStatement> element describes a statement by the SAML authority asserting that the assertion subject was authenticated by a particular means at a particular time. Assertions containing <AuthnStatement> elements MUST contain a <Subject> element.

It is of type AuthnStatementType, which extends StatementAbstractType with the addition of the following elements and attributes:

Note: The <AuthorityBinding> element and its corresponding type were removed from <AuthnStatement> for V2.0 of SAML.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 26 of 86

AuthnInstant [Required] Specifies the time at which the authentication took place. The time value is encoded in UTC, as described in Section 1.3.3.

SessionIndex [Optional] Specifies the index of a particular session between the principal identified by the subject and the authenticating authority.

SessionNotOnOrAfter [Optional] Specifies a time instant at which the session between the principal identified by the subject and the SAML authority issuing this statement MUST be considered ended. The time value is encoded in UTC, as described in Section 1.3.3. There is no required relationship between this attribute and a NotOnOrAfter condition attribute that may be present in the assertion.

<SubjectLocality> [Optional] Specifies the DNS domain name and IP address for the system from which the assertion subject was apparently authenticated.

<AuthnContext> [Required]

The context used by the authenticating authority up to and including the authentication event that yielded this statement. Contains an authentication context class reference, an authentication context declaration or declaration reference, or both. See the Authentication Context specification [SAMLAuthnCxt] for a full description of authentication context information.

In general, any string value MAY be used as a SessionIndex value. However, when privacy is a consideration, care must be taken to ensure that the SessionIndex value does not invalidate other privacy mechanisms. Accordingly, the value SHOULD NOT be usable to correlate activity by a principal across different session participants. Two solutions that achieve this goal are provided below and are RECOMMENDED:

Use small positive integers (or reoccurring constants in a list) for the SessionIndex. The SAML authority SHOULD choose the range of values such that the cardinality of any one integer will be sufficiently high to prevent a particular principal's actions from being correlated across multiple session participants. The SAML authority SHOULD choose values for SessionIndex randomly from within this range (except when required to ensure unique values for subsequent statements given to the same session participant but as part of a distinct session).

Use the enclosing assertion's ID value in the SessionIndex.

The following schema fragment defines the <AuthnStatement> element and its AuthnStatementType complex type:

<element name="AuthnStatement" type="saml:AuthnStatementType"/> <complexType name="AuthnStatementType"> <complexContent> <extension base="saml:StatementAbstractType"> <sequence> <element ref="saml:SubjectLocality" minOccurs="0"/> <element ref="saml:AuthnContext"/> </sequence> <attribute name="AuthnInstant" type="dateTime" use="required"/> <attribute name="SessionIndex" type="string" use="optional"/> <attribute name="SessionNotOnOrAfter" type="dateTime" use="optional"/> </extension> </complexContent> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 27 of 86

2.7.2.1 Element <SubjectLocality>

The <SubjectLocality> element specifies the DNS domain name and IP address for the system from which the assertion subject was authenticated. It has the following attributes:

Address [Optional]

The network address of the system from which the principal identified by the subject was authenticated. IPv4 addresses SHOULD be represented in dotted-decimal format (e.g., "1.2.3.4"). IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF RFC 3513 [RFC 3513] (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"). DNSName [Optional] The DNS name of the system from which the principal identified by the subject was authenticated.

This element is entirely advisory, since both of these fields are quite easily “spoofed,” but may be useful information in some applications.

The following schema fragment defines the <SubjectLocality> element and its SubjectLocalityType complex type:

<element name="SubjectLocality" type="saml:SubjectLocalityType"/> <complexType name="SubjectLocalityType"> <attribute name="Address" type="string" use="optional"/> <attribute name="DNSName" type="string" use="optional"/> </complexType>

2.7.2.2 Element <AuthnContext>

The <AuthnContext> element specifies the context of an authentication event. The element can contain an authentication context class reference, an authentication context declaration or declaration reference, or both. Its complex AuthnContextType has the following elements:

<AuthnContextClassRef> [Optional]

A URI reference identifying an authentication context class that describes the authentication context declaration that follows. <AuthnContextDecl> or <AuthnContextDeclRef> [Optional] Either an authentication context declaration provided by value, or a URI reference that identifies such a declaration. The URI reference MAY directly resolve into an XML document containing the referenced declaration. <AuthenticatingAuthority> [Zero or More] Zero or more unique identifiers of authentication authorities that were involved in the authentication of the principal (not including the assertion issuer, who is presumed to have been involved without being explicitly named here).

See the Authentication Context specification [SAMLAuthnCxt] for a full description of authentication context information.

The following schema fragment defines the <AuthnContext> element and its AuthnContextType complex type:

<element name="AuthnContext" type="saml:AuthnContextType"/> <complexType name="AuthnContextType"> <sequence> <choice> <sequence> <element ref="saml:AuthnContextClassRef"/> <choice minOccurs="0">

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 28 of 86

<element ref="saml:AuthnContextDecl"/> <element ref="saml:AuthnContextDeclRef"/> </choice> </sequence> <choice> <element ref="saml:AuthnContextDecl"/> <element ref="saml:AuthnContextDeclRef"/> </choice> </choice> <element ref="saml:AuthenticatingAuthority" minOccurs="0" maxOccurs="unbounded"/> </sequence> </complexType> <element name="AuthnContextClassRef" type="anyURI"/> <element name="AuthnContextDeclRef" type="anyURI"/> <element name="AuthnContextDecl" type="anyType"/> <element name="AuthenticatingAuthority" type="anyURI"/>

2.7.3 Element <AttributeStatement>

The <AttributeStatement> element describes a statement by the SAML authority asserting that the assertion subject is associated with the specified attributes. Assertions containing <AttributeStatement> elements MUST contain a <Subject> element.

It is of type AttributeStatementType, which extends StatementAbstractType with the addition of the following elements:

<Attribute> or <EncryptedAttribute> [One or More]

The <Attribute> element specifies an attribute of the assertion subject. An encrypted SAML attribute may be included with the <EncryptedAttribute> element. The following schema fragment defines the <AttributeStatement> element and its AttributeStatementType complex type: <element name="AttributeStatement" type="saml:AttributeStatementType"/> <complexType name="AttributeStatementType"> <complexContent> <extension base="saml:StatementAbstractType"> <choice maxOccurs="unbounded"> <element ref="saml:Attribute"/> <element ref="saml:EncryptedAttribute"/> </choice> </extension> </complexContent> </complexType>

2.7.3.1 Element <Attribute>

The <Attribute> element identifies an attribute by name and optionally includes its value(s). It has the AttributeType complex type. It is used within an attribute statement to express particular attributes and values associated with an assertion subject, as described in the previous section. It is also used in an attribute query to request that the values of specific SAML attributes be returned (see Section 3.3.2.3 for more information). The <Attribute> element contains the following XML attributes:

Name [Required]

The name of the attribute. NameFormat [Optional] A URI reference representing the classification of the attribute name for purposes of interpreting the

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 29 of 86

name. See Section 8.2 for some URI references that MAY be used as the value of the NameFormat attribute and their associated descriptions and processing rules. If no NameFormat value is provided, the identifier urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified (see Section 8.2.1) is in effect. FriendlyName [Optional] A string that provides a more human-readable form of the attribute's name, which may be useful in cases in which the actual Name is complex or opaque, such as an OID or a UUID. This attribute's value MUST NOT be used as a basis for formally identifying SAML attributes. Arbitrary attributes This complex type uses an <xs:anyAttribute> extension point to allow arbitrary XML attributes to be added to <Attribute> constructs without the need for an explicit schema extension. This allows additional fields to be added as needed to supply additional parameters to be used, for example, in an attribute query. SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes qualified by a SAML-defined namespace to the AttributeType complex type or a derivation of it; such attributes are reserved for future maintenance and enhancement of SAML itself. <AttributeValue> [Any Number]

Contains a value of the attribute. If an attribute contains more than one discrete value, it is RECOMMENDED that each value appear in its own <AttributeValue> element. If more than one <AttributeValue> element is supplied for an attribute, and any of the elements have a datatype assigned through xsi:type, then all of the <AttributeValue> elements must have the identical datatype assigned.

The meaning of an <Attribute> element that contains no <AttributeValue> elements depends on its context. Within an <AttributeStatement>, if the SAML attribute exists but has no values, then the <AttributeValue> element MUST be omitted. Within a <samlp:AttributeQuery>, the absence of values indicates that the requester is interested in any or all of the named attribute's values (see also Section 3.3.2.3).

Any other uses of the <Attribute> element by profiles or other specifications MUST define the semantics of specifying or omitting <AttributeValue> elements.

The following schema fragment defines the <Attribute> element and its AttributeType complex type:

<element name="Attribute" type="saml:AttributeType"/> <complexType name="AttributeType"> <sequence> <element ref="saml:AttributeValue" minOccurs="0" maxOccurs="unbounded"/> </sequence> <attribute name="Name" type="string" use="required"/> <attribute name="NameFormat" type="anyURI" use="optional"/> <attribute name="FriendlyName" type="string" use="optional"/> <anyAttribute namespace="##other" processContents="lax"/> </complexType>

2.7.3.1.1 Element <AttributeValue>

The <AttributeValue> element supplies the value of a specified SAML attribute. It is of the xs:anyType type, which allows any well-formed XML to appear as the content of the element.

If the data content of an <AttributeValue> element is of an XML Schema simple type (such as xs:integer or xs:string), the datatype MAY be declared explicitly by means of an xsi:type declaration in the <AttributeValue> element. If the attribute value contains structured data, the necessary data elements MAY be defined in an extension schema.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 30 of 86

Note: Specifying a datatype other than an XML Schema simple type on <AttributeValue> using xsi:type will require the presence of the extension schema that defines the datatype in order for schema processing to proceed.

If a SAML attribute includes an empty value, such as the empty string, the corresponding <AttributeValue> element MUST be empty (generally this is serialized as <AttributeValue/>). This overrides the requirement in Section 1.3.1 that string values in SAML content contain at least one non-whitespace character.

If a SAML attribute includes a "null" value, the corresponding <AttributeValue> element MUST be empty and MUST contain the reserved xsi:nil XML attribute with a value of "true" or "1".

The following schema fragment defines the <AttributeValue> element:

<element name="AttributeValue" type="anyType" nillable="true"/>

2.7.3.2 Element <EncryptedAttribute>

The <EncryptedAttribute> element represents a SAML attribute in encrypted fashion, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The <EncryptedAttribute> element contains the following elements:

<xenc:EncryptedData> [Required]

The encrypted content and associated encryption details, as defined by the XML Encryption Syntax and Processing specification [XMLEnc]. The Type attribute SHOULD be present and, if present, MUST contain a value of http://www.w3.org/2001/04/xmlenc#Element. The encrypted content MUST contain an element that has a type of or derived from AttributeType. <xenc:EncryptedKey> [Zero or More]

Wrapped decryption keys, as defined by [XMLEnc]. Each wrapped key SHOULD include a Recipient attribute that specifies the entity for whom the key has been encrypted. The value of the Recipient attribute SHOULD be the URI identifier of a system entity with a SAML name identifier, as defined by Section 8.3.6.

Encrypted attributes are intended as a confidentiality protection when the plain-text value passes through an intermediary.

The following schema fragment defines the <EncryptedAttribute> element:

<element name="EncryptedAttribute" type="saml:EncryptedElementType"/>

2.7.4 Element <AuthzDecisionStatement>

Note: The <AuthzDecisionStatement> feature has been frozen as of SAML V2.0, with no future enhancements planned. Users who require additional functionality may want to consider the eXtensible Access Control Markup Language [XACML], which offers enhanced authorization decision features.

The <AuthzDecisionStatement> element describes a statement by the SAML authority asserting that a request for access by the assertion subject to the specified resource has resulted in the specified authorization decision on the basis of some optionally specified evidence. Assertions containing <AuthzDecisionStatement> elements MUST contain a <Subject> element.

The resource is identified by means of a URI reference. In order for the assertion to be interpreted correctly and securely, the SAML authority and SAML relying party MUST interpret each URI reference in a consistent manner. Failure to achieve a consistent URI reference interpretation can result in different

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 31 of 86

authorization decisions depending on the encoding of the resource URI reference. Rules for normalizing URI references are to be found in IETF RFC 2396 [RFC 2396] Section 6:

In general, the rules for equivalence and definition of a normal form, if any, are scheme dependent. When a scheme uses elements of the common syntax, it will also use the common syntax equivalence rules, namely that the scheme and hostname are case insensitive and a URL with an explicit ":port", where the port is the default for the scheme, is equivalent to one where the port is elided.

To avoid ambiguity resulting from variations in URI encoding, SAML system entities SHOULD employ the URI normalized form wherever possible as follows:

• SAML authorities SHOULD encode all resource URI references in normalized form.

• Relying parties SHOULD convert resource URI references to normalized form prior to processing.

Inconsistent URI reference interpretation can also result from differences between the URI reference syntax and the semantics of an underlying file system. Particular care is required if URI references are employed to specify an access control policy language. The following security conditions SHOULD be satisfied by the system which employs SAML assertions:

• Parts of the URI reference syntax are case sensitive. If the underlying file system is case insensitive, a requester SHOULD NOT be able to gain access to a denied resource by changing the case of a part of the resource URI reference.

• Many file systems support mechanisms such as logical paths and symbolic links, which allow users to establish logical equivalences between file system entries. A requester SHOULD NOT be able to gain access to a denied resource by creating such an equivalence.

The <AuthzDecisionStatement> element is of type AuthzDecisionStatementType, which extends StatementAbstractType with the addition of the following elements and attributes:

Resource [Required]

A URI reference identifying the resource to which access authorization is sought. This attribute MAY have the value of the empty URI reference (""), and the meaning is defined to be "the start of the current document", as specified by IETF RFC 2396 [RFC 2396] Section 4.2. Decision [Required] The decision rendered by the SAML authority with respect to the specified resource. The value is of the DecisionType simple type. <Action> [One or more] The set of actions authorized to be performed on the specified resource. <Evidence> [Optional] A set of assertions that the SAML authority relied on in making the decision. The following schema fragment defines the <AuthzDecisionStatement> element and its AuthzDecisionStatementType complex type: <element name="AuthzDecisionStatement" type="saml:AuthzDecisionStatementType"/> <complexType name="AuthzDecisionStatementType"> <complexContent> <extension base="saml:StatementAbstractType"> <sequence> <element ref="saml:Action" maxOccurs="unbounded"/> <element ref="saml:Evidence" minOccurs="0"/> </sequence> <attribute name="Resource" type="anyURI" use="required"/> <attribute name="Decision" type="saml:DecisionType" use="required"/>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 32 of 86

</extension> </complexContent> </complexType>

2.7.4.1 Simple Type DecisionType

The DecisionType simple type defines the possible values to be reported as the status of an authorization decision statement.

Permit

The specified action is permitted. Deny The specified action is denied. Indeterminate The SAML authority cannot determine whether the specified action is permitted or denied.

The Indeterminate decision value is used in situations where the SAML authority requires the ability to provide an affirmative statement but where it is not able to issue a decision. Additional information as to the reason for the refusal or inability to provide a decision MAY be returned as <StatusDetail> elements in the enclosing <Response>.

The following schema fragment defines the DecisionType simple type:

<simpleType name="DecisionType"> <restriction base="string"> <enumeration value="Permit"/> <enumeration value="Deny"/> <enumeration value="Indeterminate"/> </restriction> </simpleType>

2.7.4.2 Element <Action>

The <Action> element specifies an action on the specified resource for which permission is sought. Its string-data content provides the label for an action sought to be performed on the specified resource, and it has the following attribute:

Namespace [Optional]

A URI reference representing the namespace in which the name of the specified action is to be interpreted. If this element is absent, the namespace urn:oasis:names:tc:SAML:1.0:action:rwedc-negation specified in Section 8.1.2 is in effect. The following schema fragment defines the <Action> element and its ActionType complex type: <element name="Action" type="saml:ActionType"/> <complexType name="ActionType"> <simpleContent> <extension base="string"> <attribute name="Namespace" type="anyURI" use="required"/> </extension> </simpleContent> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 33 of 86

2.7.4.3 Element <Evidence>

The <Evidence> element contains one or more assertions or assertion references that the SAML authority relied on in issuing the authorization decision. It has the EvidenceType complex type. It contains a mixture of one or more of the following elements:

<AssertionIDRef> [Any number]

Specifies an assertion by reference to the value of the assertion’s ID attribute. <AssertionURIRef> [Any number] Specifies an assertion by means of a URI reference. <Assertion> [Any number]

Specifies an assertion by value.

<EncryptedAssertion> [Any number]

Specifies an encrypted assertion by value.

Providing an assertion as evidence MAY affect the reliance agreement between the SAML relying party and the SAML authority making the authorization decision. For example, in the case that the SAML relying party presented an assertion to the SAML authority in a request, the SAML authority MAY use that assertion as evidence in making its authorization decision without endorsing the <Evidence> element’s assertion as valid either to the relying party or any other third party.

The following schema fragment defines the <Evidence> element and its EvidenceType complex type:

<element name="Evidence" type="saml:EvidenceType"/> <complexType name="EvidenceType"> <choice maxOccurs="unbounded"> <element ref="saml:AssertionIDRef"/> <element ref="saml:AssertionURIRef"/> <element ref="saml:Assertion"/> <element ref="saml:EncryptedAssertion"/> </choice> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 34 of 86
