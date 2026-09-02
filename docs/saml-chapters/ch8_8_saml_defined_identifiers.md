# Chapter 8 SAML-Defined Identifiers


The following sections define URI-based identifiers for common resource access actions, subject name identifier formats, and attribute name formats.

Where possible an existing URN is used to specify a protocol. In the case of IETF protocols, the URN of the most current RFC that specifies the protocol is used. URI references created specifically for SAML have one of the following stems, according to the specification set version in which they were first introduced:

urn:oasis:names:tc:SAML:1.0: urn:oasis:names:tc:SAML:1.1: urn:oasis:names:tc:SAML:2.0:

8.1 Action Namespace Identifiers

The following identifiers MAY be used in the Namespace attribute of the <Action> element to refer to common sets of actions to perform on resources.

8.1.1 Read/Write/Execute/Delete/Control

URI: urn:oasis:names:tc:SAML:1.0:action:rwedc

Defined actions:

Read Write Execute Delete Control

These actions are interpreted as follows:

Read

The subject may read the resource. Write The subject may modify the resource. Execute The subject may execute the resource. Delete The subject may delete the resource. Control

The subject may specify the access control policy for the resource.

8.1.2 Read/Write/Execute/Delete/Control with Negation

URI: urn:oasis:names:tc:SAML:1.0:action:rwedc-negation

Defined actions:

Read Write Execute Delete Control ~Read ~Write ~Execute ~Delete ~Control

The actions specified in Section 8.1.1 are interpreted in the same manner described there. Actions prefixed with a tilde (~) are negated permissions and are used to affirmatively specify that the stated permission is denied. Thus a subject described as being authorized to perform the action ~Read is affirmatively denied read permission.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 76 of 86

A SAML authority MUST NOT authorize both an action and its negated form.

8.1.3 Get/Head/Put/Post

URI: urn:oasis:names:tc:SAML:1.0:action:ghpp

Defined actions:

GET HEAD PUT POST

These actions bind to the corresponding HTTP operations. For example a subject authorized to perform the GET action on a resource is authorized to retrieve it.

The GET and HEAD actions loosely correspond to the conventional read permission and the PUT and POST actions to the write permission. The correspondence is not exact however since an HTTP GET operation may cause data to be modified and a POST operation may cause modification to a resource other than the one specified in the request. For this reason a separate Action URI reference specifier is provided.

8.1.4 UNIX File Permissions

URI: urn:oasis:names:tc:SAML:1.0:action:unix

The defined actions are the set of UNIX file access permissions expressed in the numeric (octal) notation.

The action string is a four-digit numeric code:

extended user group world

Where the extended access permission has the value

+2 if sgid is set

+4 if suid is set

The user group and world access permissions have the value

+1 if execute permission is granted

+2 if write permission is granted

+4 if read permission is granted

For example, 0754 denotes the UNIX file access permission: user read, write, and execute; group read and execute; and world read.

8.2 Attribute Name Format Identifiers

The following identifiers MAY be used in the NameFormat attribute defined on the AttributeType complex type to refer to the classification of the attribute name for purposes of interpreting the name.

8.2.1 Unspecified

URI: urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified

The interpretation of the attribute name is left to individual implementations.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 77 of 86

8.2.2 URI Reference

URI: urn:oasis:names:tc:SAML:2.0:attrname-format:uri

The attribute name follows the convention for URI references [RFC 2396], for example as used in XACML [XACML] attribute identifiers. The interpretation of the URI content or naming scheme is applicationspecific. See [SAMLProf] for attribute profiles that make use of this identifier.

8.2.3 Basic

URI: urn:oasis:names:tc:SAML:2.0:attrname-format:basic

The class of strings acceptable as the attribute name MUST be drawn from the set of values belonging to the primitive type xs:Name as defined in [Schema2] Section 3.3.6. See [SAMLProf] for attribute profiles that make use of this identifier.

8.3 Name Identifier Format Identifiers

The following identifiers MAY be used in the Format attribute of the <NameID>, <NameIDPolicy>, or <Issuer> elements (see Section 2.2) to refer to common formats for the content of the elements and the associated processing rules, if any.

Note: Several identifiers that were deprecated in SAML V1.1 have been removed for SAML V2.0.

8.3.1 Unspecified

URI: urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified

The interpretation of the content of the element is left to individual implementations.

8.3.2 Email Address

URI: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress

Indicates that the content of the element is in the form of an email address, specifically "addr-spec" as defined in IETF RFC 2822 [RFC 2822] Section 3.4.1. An addr-spec has the form local-part@domain. Note that an addr-spec has no phrase (such as a common name) before it, has no comment (text surrounded in parentheses) after it, and is not surrounded by "<" and ">".

8.3.3 X.509 Subject Name

URI: urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName

Indicates that the content of the element is in the form specified for the contents of the <ds:X509SubjectName> element in the XML Signature Recommendation [XMLSig]. Implementors should note that the XML Signature specification specifies encoding rules for X.509 subject names that differ from the rules given in IETF RFC 2253 [RFC 2253].

8.3.4 Windows Domain Qualified Name

URI: urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 78 of 86

Indicates that the content of the element is a Windows domain qualified name. A Windows domain qualified user name is a string of the form "DomainName\UserName". The domain name and "\" separator MAY be omitted.

8.3.5 Kerberos Principal Name

URI: urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos

Indicates that the content of the element is in the form of a Kerberos principal name using the format name[/instance]@REALM. The syntax, format and characters allowed for the name, instance, and realm are described in IETF RFC 1510 [RFC 1510].

8.3.6 Entity Identifier

URI: urn:oasis:names:tc:SAML:2.0:nameid-format:entity

Indicates that the content of the element is the identifier of an entity that provides SAML-based services (such as a SAML authority, requester, or responder) or is a participant in SAML profiles (such as a service provider supporting the browser SSO profile). Such an identifier can be used in the <Issuer> element to identify the issuer of a SAML request, response, or assertion, or within the <NameID> element to make assertions about system entities that can issue SAML requests, responses, and assertions. It can also be used in other elements and attributes whose purpose is to identify a system entity in various protocol exchanges.

The syntax of such an identifier is a URI of not more than 1024 characters in length. It is RECOMMENDED that a system entity use a URL containing its own domain name to identify itself.

The NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted.

8.3.7 Persistent Identifier

URI: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent

Indicates that the content of the element is a persistent opaque identifier for a principal that is specific to an identity provider and a service provider or affiliation of service providers. Persistent name identifiers generated by identity providers MUST be constructed using pseudo-random values that have no discernible correspondence with the subject's actual identifier (for example, username). The intent is to create a non-public, pair-wise pseudonym to prevent the discovery of the subject's identity or activities. Persistent name identifier values MUST NOT exceed a length of 256 characters.

The element's NameQualifier attribute, if present, MUST contain the unique identifier of the identity provider that generated the identifier (see Section 8.3.6). It MAY be omitted if the value can be derived from the context of the message containing the element, such as the issuer of a protocol message or an assertion containing the identifier in its subject. Note that a different system entity might later issue its own protocol message or assertion containing the identifier; the NameQualifier attribute does not change in this case, but MUST continue to identify the entity that originally created the identifier (and MUST NOT be omitted in such a case).

The element's SPNameQualifier attribute, if present, MUST contain the unique identifier of the service provider or affiliation of providers for whom the identifier was generated (see Section 8.3.6). It MAY be omitted if the element is contained in a message intended only for consumption directly by the service provider, and the value would be the unique identifier of that service provider.

The element's SPProvidedID attribute MUST contain the alternative identifier of the principal most recently set by the service provider or affiliation, if any (see Section 3.6). If no such identifier has been established, then the attribute MUST be omitted.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 79 of 86

Persistent identifiers are intended as a privacy protection mechanism; as such they MUST NOT be shared in clear text with providers other than the providers that have established the shared identifier. Furthermore, they MUST NOT appear in log files or similar locations without appropriate controls and protections. Deployments without such requirements are free to use other kinds of identifiers in their SAML exchanges, but MUST NOT overload this format with persistent but non-opaque values

Note also that while persistent identifiers are typically used to reflect an account linking relationship between a pair of providers, a service provider is not obligated to recognize or make use of the long term nature of the persistent identifier or establish such a link. Such a "one-sided" relationship is not discernibly different and does not affect the behavior of the identity provider or any processing rules specific to persistent identifiers in the protocols defined in this specification.

Finally, note that the NameQualifier and SPNameQualifier attributes indicate directionality of creation, but not of use. If a persistent identifier is created by a particular identity provider, the NameQualifier attribute value is permanently established at that time. If a service provider that receives such an identifier takes on the role of an identity provider and issues its own assertion containing that identifier, the NameQualifier attribute value does not change (and would of course not be omitted). It might alternatively choose to create its own persistent identifier to represent the principal and link the two values. This is a deployment decision.

8.3.8 Transient Identifier

URI: urn:oasis:names:tc:SAML:2.0:nameid-format:transient

Indicates that the content of the element is an identifier with transient semantics and SHOULD be treated as an opaque and temporary value by the relying party. Transient identifier values MUST be generated in accordance with the rules for SAML identifiers (see Section 1.3.4), and MUST NOT exceed a length of 256 characters.

The NameQualifier and SPNameQualifier attributes MAY be used to signify that the identifier represents a transient and temporary pair-wise identifier. In such a case, they MAY be omitted in accordance with the rules specified in Section 8.3.7.

8.4 Consent Identifiers

The following identifiers MAY be used in the Consent attribute defined on the RequestAbstractType and StatusResponseType complex types to communicate whether a principal gave consent, and under what conditions, for the message.

8.4.1 Unspecified

URI: urn:oasis:names:tc:SAML:2.0:consent:unspecified

No claim as to principal consent is being made.

8.4.2 Obtained

URI: urn:oasis:names:tc:SAML:2.0:consent:obtained

Indicates that a principal’s consent has been obtained by the issuer of the message.

8.4.3 Prior

URI: urn:oasis:names:tc:SAML:2.0:consent:prior

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 80 of 86

Indicates that a principal’s consent has been obtained by the issuer of the message at some point prior to the action that initiated the message.

8.4.4 Implicit

URI: urn:oasis:names:tc:SAML:2.0:consent:current-implicit

Indicates that a principal’s consent has been implicitly obtained by the issuer of the message during the action that initiated the message, as part of a broader indication of consent. Implicit consent is typically more proximal to the action in time and presentation than prior consent, such as part of a session of activities.

8.4.5 Explicit

URI: urn:oasis:names:tc:SAML:2.0:consent:current-explicit

Indicates that a principal’s consent has been explicitly obtained by the issuer of the message during the action that initiated the message.

8.4.6 Unavailable

URI: urn:oasis:names:tc:SAML:2.0:consent:unavailable

Indicates that the issuer of the message did not obtain consent.

8.4.7 Inapplicable

URI: urn:oasis:names:tc:SAML:2.0:consent:inapplicable

Indicates that the issuer of the message does not believe that they need to obtain or report consent.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 81 of 86
