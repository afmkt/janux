# Chapter 3 SAML Protocols


SAML protocol messages can be generated and exchanged using a variety of protocols. The SAML bindings specification [SAMLBind] describes specific means of transporting protocol messages using existing widely deployed transport protocols. The SAML profile specification [SAMLProf] describes a number of applications of the protocols defined in this section together with additional processing rules, restrictions, and requirements that facilitate interoperability.

Specific SAML request and response messages derive from common types. The requester sends an element derived from RequestAbstractType to a SAML responder, and the responder generates an element adhering to or deriving from StatusResponseType, as shown in Figure 1.

RequestAbstractType

Process Request

StatusResponseType

Figure 1: SAML Request-Response Protocol

In certain cases, when permitted by profiles, a SAML response MAY be generated and sent without the responder having received a corresponding request.

The protocols defined by SAML achieve the following actions:

• Returning one or more requested assertions. This can occur in response to either a direct request for specific assertions or a query for assertions that meet particular criteria.

• Performing authentication on request and returning the corresponding assertion

• Registering a name identifier or terminating a name registration on request

• Retrieving a protocol message that has been requested by means of an artifact

• Performing a near-simultaneous logout of a collection of related sessions (“single logout”) on request

• Providing a name identifier mapping on request

Throughout this section, text descriptions of elements and types in the SAML protocol namespace are not shown with the conventional namespace prefix samlp:. For clarity, text descriptions of elements and types in the SAML assertion namespace are indicated with the conventional namespace prefix saml:.

3.1 Schema Header and Namespace Declarations

The following schema fragment defines the XML namespaces and other header information for the protocol schema:

<schema targetNamespace="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="http://www.w3.org/2001/XMLSchema" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" elementFormDefault="unqualified" attributeFormDefault="unqualified" blockDefault="substitution" version="2.0">

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 35 of 86

<import namespace="urn:oasis:names:tc:SAML:2.0:assertion" schemaLocation="saml-schema-assertion-2.0.xsd"/> <import namespace="http://www.w3.org/2000/09/xmldsig#" schemaLocation="http://www.w3.org/TR/2002/REC-xmldsig-core20020212/xmldsig-core-schema.xsd"/> <annotation> <documentation> Document identifier: saml-schema-protocol-2.0 Location: http://docs.oasis-open.org/security/saml/v2.0/ Revision history: V1.0 (November, 2002): Initial Standard Schema. V1.1 (September, 2003): Updates within the same V1.0 namespace. V2.0 (March, 2005): New protocol schema based in a SAML V2.0 namespace. </documentation> </annotation> </schema>

3.2 Requests and Responses

The following sections define the SAML constructs and basic requirements that underlie all of the request and response messages used in SAML protocols.

3.2.1 Complex Type RequestAbstractType

All SAML requests are of types that are derived from the abstract RequestAbstractType complex type. This type defines common attributes and elements that are associated with all SAML requests:

Note: The <RespondWith> element has been removed from RequestAbstractType for V2.0 of SAML.

ID [Required] An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness. The values of the ID attribute in a request and the InResponseTo attribute in the corresponding response MUST match. Version [Required] The version of this request. The identifier for the version of SAML defined in this specification is "2.0". SAML versioning is discussed in Section 4. IssueInstant [Required] The time instant of issue of the request. The time value is encoded in UTC, as described in Section 1.3.3. Destination [Optional] A URI reference indicating the address to which this request has been sent. This is useful to prevent malicious forwarding of requests to unintended recipients, a protection that is required by some protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the location at which the message was received. If it does not, the request MUST be discarded. Some protocol bindings may require the use of this attribute (see [SAMLBind]). Consent [Optional] Indicates whether or not (and under what conditions) consent has been obtained from a principal in the sending of this request. See Section 8.4 for some URI references that MAY be used as the value

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 36 of 86

of the Consent attribute and their associated descriptions. If no Consent value is provided, the identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect. <saml:Issuer> [Optional] Identifies the entity that generated the request message. (For more information on this element, see Section 2.2.5.) <ds:Signature> [Optional] An XML Signature that authenticates the requester and provides message integrity, as described below and in Section 5. <Extensions> [Optional]

This extension point contains optional protocol message extension elements that are agreed on between the communicating parties. No extension schema is required in order to make use of this extension point, and even if one is provided, the lax validation setting does not impose a requirement for the extension to be valid. SAML extension elements MUST be namespace-qualified in a nonSAML-defined namespace.

Depending on the requirements of particular protocols or profiles, a SAML requester may often need to authenticate itself, and message integrity may often be required. Authentication and message integrity MAY be provided by mechanisms provided by the protocol binding (see [SAMLBind]). The SAML request MAY be signed, which provides both authentication of the requester and message integrity.

If such a signature is used, then the <ds:Signature> element MUST be present, and the SAML responder MUST verify that the signature is valid (that is, that the message has not been tampered with) in accordance with [XMLSig]. If it is invalid, then the responder MUST NOT rely on the contents of the request and SHOULD respond with an error. If it is valid, then the responder SHOULD evaluate the signature to determine the identity and appropriateness of the signer and may continue to process the request or respond with an error (if the request is invalid for some other reason).

If a Consent attribute is included and the value indicates that some form of principal consent has been obtained, then the request SHOULD be signed.

If a SAML responder deems a request to be invalid according to SAML syntax or processing rules, then if it responds, it MUST return a SAML response message with a <StatusCode> element with the value urn:oasis:names:tc:SAML:2.0:status:Requester. In some cases, for example during a suspected denial-of-service attack, not responding at all may be warranted.

The following schema fragment defines the RequestAbstractType complex type:

<complexType name="RequestAbstractType" abstract="true"> <sequence> <element ref="saml:Issuer" minOccurs="0"/> <element ref="ds:Signature" minOccurs="0"/> <element ref="samlp:Extensions" minOccurs="0"/> </sequence> <attribute name="ID" type="ID" use="required"/> <attribute name="Version" type="string" use="required"/> <attribute name="IssueInstant" type="dateTime" use="required"/> <attribute name="Destination" type="anyURI" use="optional"/> <attribute name="Consent" type="anyURI" use="optional"/> </complexType> <element name="Extensions" type="samlp:ExtensionsType"/> <complexType name="ExtensionsType"> <sequence> <any namespace="##other" processContents="lax" maxOccurs="unbounded"/> </sequence> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 37 of 86

3.2.2 Complex Type StatusResponseType

All SAML responses are of types that are derived from the StatusResponseType complex type. This type defines common attributes and elements that are associated with all SAML responses:

ID [Required]

An identifier for the response. It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness. InResponseTo [Optional] A reference to the identifier of the request to which the response corresponds, if any. If the response is not generated in response to a request, or if the ID attribute value of a request cannot be determined (for example, the request is malformed), then this attribute MUST NOT be present. Otherwise, it MUST be present and its value MUST match the value of the corresponding request's ID attribute. Version [Required] The version of this response. The identifier for the version of SAML defined in this specification is "2.0". SAML versioning is discussed in Section 4. IssueInstant [Required] The time instant of issue of the response. The time value is encoded in UTC, as described in Section 1.3.3. Destination [Optional] A URI reference indicating the address to which this response has been sent. This is useful to prevent malicious forwarding of responses to unintended recipients, a protection that is required by some protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the location at which the message was received. If it does not, the response MUST be discarded. Some protocol bindings may require the use of this attribute (see [SAMLBind]). Consent [Optional] Indicates whether or not (and under what conditions) consent has been obtained from a principal in the sending of this response. See Section 8.4 for some URI references that MAY be used as the value of the Consent attribute and their associated descriptions. If no Consent value is provided, the identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect. <saml:Issuer> [Optional] Identifies the entity that generated the response message. (For more information on this element, see Section 2.2.5.) <ds:Signature> [Optional] An XML Signature that authenticates the responder and provides message integrity, as described below and in Section 5. <Extensions> [Optional] This extension point contains optional protocol message extension elements that are agreed on between the communicating parties. . No extension schema is required in order to make use of this extension point, and even if one is provided, the lax validation setting does not impose a requirement for the extension to be valid. SAML extension elements MUST be namespace-qualified in a nonSAML-defined namespace. <Status> [Required] A code representing the status of the corresponding request.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 38 of 86

Depending on the requirements of particular protocols or profiles, a SAML responder may often need to authenticate itself, and message integrity may often be required. Authentication and message integrity MAY be provided by mechanisms provided by the protocol binding (see [SAMLBind]). The SAML response MAY be signed, which provides both authentication of the responder and message integrity.

If such a signature is used, then the <ds:Signature> element MUST be present, and the SAML requester receiving the response MUST verify that the signature is valid (that is, that the message has not been tampered with) in accordance with [XMLSig]. If it is invalid, then the requester MUST NOT rely on the contents of the response and SHOULD treat it as an error. If it is valid, then the requester SHOULD evaluate the signature to determine the identity and appropriateness of the signer and may continue to process the response as it deems appropriate.

If a Consent attribute is included and the value indicates that some form of principal consent has been obtained, then the response SHOULD be signed.

The following schema fragment defines the StatusResponseType complex type:

<complexType name="StatusResponseType"> <sequence> <element ref="saml:Issuer" minOccurs="0"/> <element ref="ds:Signature" minOccurs="0"/> <element ref="samlp:Extensions" minOccurs="0"/> <element ref="samlp:Status"/> </sequence> <attribute name="ID" type="ID" use="required"/> <attribute name="InResponseTo" type="NCName" use="optional"/> <attribute name="Version" type="string" use="required"/> <attribute name="IssueInstant" type="dateTime" use="required"/> <attribute name="Destination" type="anyURI" use="optional"/> <attribute name="Consent" type="anyURI" use="optional"/> </complexType>

3.2.2.1 Element <Status>

The <Status> element contains the following elements:

<StatusCode> [Required]

A code representing the status of the activity carried out in response to the corresponding request. <StatusMessage> [Optional] A message which MAY be returned to an operator. <StatusDetail> [Optional] Additional information concerning the status of the request. The following schema fragment defines the <Status> element and its StatusType complex type: <element name="Status" type="samlp:StatusType"/> <complexType name="StatusType"> <sequence> <element ref="samlp:StatusCode"/> <element ref="samlp:StatusMessage" minOccurs="0"/> <element ref="samlp:StatusDetail" minOccurs="0"/> </sequence> </complexType>

3.2.2.2 Element <StatusCode>

The <StatusCode> element specifies a code or a set of nested codes representing the status of the corresponding request. The <StatusCode> element has the following element and attribute:

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 39 of 86

Value [Required] The status code value. This attribute contains a URI reference. The value of the topmost <StatusCode> element MUST be from the top-level list provided in this section. <StatusCode> [Optional] A subordinate status code that provides more specific information on an error condition. Note that responders MAY omit subordinate status codes in order to prevent attacks that seek to probe for additional information by intentionally presenting erroneous requests.

The permissible top-level <StatusCode> values are as follows:

urn:oasis:names:tc:SAML:2.0:status:Success

The request succeeded. Additional information MAY be returned in the <StatusMessage> and/or <StatusDetail> elements. urn:oasis:names:tc:SAML:2.0:status:Requester The request could not be performed due to an error on the part of the requester. urn:oasis:names:tc:SAML:2.0:status:Responder The request could not be performed due to an error on the part of the SAML responder or SAML authority. urn:oasis:names:tc:SAML:2.0:status:VersionMismatch The SAML responder could not process the request because the version of the request message was incorrect.

The following second-level status codes are referenced at various places in this specification. Additional second-level status codes MAY be defined in future versions of the SAML specification. System entities are free to define more specific status codes by defining appropriate URI references.

urn:oasis:names:tc:SAML:2.0:status:AuthnFailed

The responding provider was unable to successfully authenticate the principal. urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue Unexpected or invalid content was encountered within a <saml:Attribute> or <saml:AttributeValue> element. urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy The responding provider cannot or will not support the requested name identifier policy. urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext The specified authentication context requirements cannot be met by the responder. urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP Used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an <IDPList> can be resolved or that none of the supported identity providers are available. urn:oasis:names:tc:SAML:2.0:status:NoPassive Indicates the responding provider cannot authenticate the principal passively, as has been requested. urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP Used by an intermediary to indicate that none of the identity providers in an <IDPList> are supported by the intermediary.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 40 of 86

urn:oasis:names:tc:SAML:2.0:status:PartialLogout Used by a session authority to indicate to a session participant that it was not able to propagate logout to all other session participants. urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the request further. urn:oasis:names:tc:SAML:2.0:status:RequestDenied The SAML responder or SAML authority is able to process the request but has chosen not to respond. This status code MAY be used when there is concern about the security context of the request message or the sequence of request messages received from a particular requester. urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported

The SAML responder or SAML authority does not support the request.

urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated

The SAML responder cannot process any requests with the protocol version specified in the request. urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh The SAML responder cannot process the request because the protocol version specified in the request message is a major upgrade from the highest protocol version supported by the responder. urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow The SAML responder cannot process the request because the protocol version specified in the request message is too low. urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized The resource value provided in the request message is invalid or unrecognized. urn:oasis:names:tc:SAML:2.0:status:TooManyResponses The response message would contain more elements than the SAML responder is able to return. urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile An entity that has no knowledge of a particular attribute profile has been presented with an attribute drawn from that profile. urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal The responding provider does not recognize the principal specified or implied by the request. urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding

The SAML responder cannot properly fulfill the request using the protocol binding specified in the request.

The following schema fragment defines the <StatusCode> element and its StatusCodeType complex type:

<element name="StatusCode" type="samlp:StatusCodeType"/> <complexType name="StatusCodeType"> <sequence> <element ref="samlp:StatusCode" minOccurs="0"/> </sequence> <attribute name="Value" type="anyURI" use="required"/> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 41 of 86

3.2.2.3 Element <StatusMessage>

The <StatusMessage> element specifies a message that MAY be returned to an operator:

The following schema fragment defines the <StatusMessage> element:

<element name="StatusMessage" type="string"/>

3.2.2.4 Element <StatusDetail>

The <StatusDetail> element MAY be used to specify additional information concerning the status of the request. The additional information consists of zero or more elements from any namespace, with no requirement for a schema to be present or for schema validation of the <StatusDetail> contents.

The following schema fragment defines the <StatusDetail> element and its StatusDetailType complex type:

<element name="StatusDetail" type="samlp:StatusDetailType"/> <complexType name="StatusDetailType"> <sequence> <any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/> </sequence> </complexType>

3.3 Assertion Query and Request Protocol

This section defines messages and processing rules for requesting existing assertions by reference or querying for assertions by subject and statement type.

3.3.1 Element <AssertionIDRequest>

If the requester knows the unique identifier of one or more assertions, the <AssertionIDRequest> message element can be used to request that they be returned in a <Response> message. The <saml:AssertionIDRef> element is used to specify each assertion to return. See Section 2.3.1 for more information on this element.

The following schema fragment defines the <AssertionIDRequest> element:

<element name="AssertionIDRequest" type="samlp:AssertionIDRequestType"/> <complexType name="AssertionIDRequestType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <element ref="saml:AssertionIDRef" maxOccurs="unbounded"/> </sequence> </extension> </complexContent> </complexType>

3.3.2 Queries

The following sections define the SAML query request messages.

3.3.2.1 Element <SubjectQuery>

The <SubjectQuery> message element is an extension point that allows new SAML queries to be defined that specify a single SAML subject. Its SubjectQueryAbstractType complex type is abstract and

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 42 of 86

is thus usable only as the base of a derived type. SubjectQueryAbstractType adds the <saml:Subject> element (defined in Section 2.4) to RequestAbstractType.

The following schema fragment defines the <SubjectQuery> element and its SubjectQueryAbstractType complex type:

<element name="SubjectQuery" type="samlp:SubjectQueryAbstractType"/> <complexType name="SubjectQueryAbstractType" abstract="true"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <element ref="saml:Subject"/> </sequence> </extension> </complexContent> </complexType>

3.3.2.2 Element <AuthnQuery>

The <AuthnQuery> message element is used to make the query “What assertions containing authentication statements are available for this subject?” A successful <Response> will contain one or more assertions containing authentication statements.

The <AuthnQuery> message MUST NOT be used as a request for a new authentication using credentials provided in the request. <AuthnQuery> is a request for statements about authentication acts that have occurred in a previous interaction between the indicated subject and the authentication authority.

This element is of type AuthnQueryType, which extends SubjectQueryAbstractType with the addition of the following element and attribute:

SessionIndex [Optional]

If present, specifies a filter for possible responses. Such a query asks the question “What assertions containing authentication statements do you have for this subject within the context of the supplied session information?” <RequestedAuthnContext> [Optional]

If present, specifies a filter for possible responses. Such a query asks the question "What assertions containing authentication statements do you have for this subject that satisfy the authentication context requirements in this element?"

In response to an authentication query, a SAML authority returns assertions with authentication statements as follows: • Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the assertions that may be returned.

• If the SessionIndex attribute is present in the query, at least one <AuthnStatement> element in the set of returned assertions MUST contain a SessionIndex attribute that matches the SessionIndex attribute in the query. It is OPTIONAL for the complete set of all such matching assertions to be returned in the response.

• If the <RequestedAuthnContext> element is present in the query, at least one <AuthnStatement> element in the set of returned assertions MUST contain an <AuthnContext> element that satisfies the element in the query (see Section 3.3.2.2.1). It is OPTIONAL for the complete set of all such matching assertions to be returned in the response.

The following schema fragment defines the <AuthnQuery> element and its AuthnQueryType complex type:

<element name="AuthnQuery" type="samlp:AuthnQueryType"/>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 43 of 86

<complexType name="AuthnQueryType"> <complexContent> <extension base="samlp:SubjectQueryAbstractType"> <sequence> <element ref="samlp:RequestedAuthnContext" minOccurs="0"/> </sequence> <attribute name="SessionIndex" type="string" use="optional"/> </extension> </complexContent> </complexType>

3.3.2.2.1 Element <RequestedAuthnContext>

The <RequestedAuthnContext> element specifies the authentication context requirements of authentication statements returned in response to a request or query. Its RequestedAuthnContextType complex type defines the following elements and attributes:

<saml:AuthnContextClassRef> or <saml:AuthnContextDeclRef> [One or More]

Specifies one or more URI references identifying authentication context classes or declarations. These elements are defined in Section 2.7.2.2. For more information about authentication context classes, see [SAMLAuthnCxt]. Comparison [Optional] Specifies the comparison method used to evaluate the requested context classes or statements, one of "exact", "minimum", "maximum", or "better". The default is "exact".

Either a set of class references or a set of declaration references can be used. The set of supplied references MUST be evaluated as an ordered set, where the first element is the most preferred authentication context class or declaration. If none of the specified classes or declarations can be satisfied in accordance with the rules below, then the responder MUST return a <Response> message with a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext.

If Comparison is set to "exact" or omitted, then the resulting authentication context in the authentication statement MUST be the exact match of at least one of the authentication contexts specified.

If Comparison is set to "minimum", then the resulting authentication context in the authentication statement MUST be at least as strong (as deemed by the responder) as one of the authentication contexts specified.

If Comparison is set to "better", then the resulting authentication context in the authentication statement MUST be stronger (as deemed by the responder) than any one of the authentication contexts specified.

If Comparison is set to "maximum", then the resulting authentication context in the authentication statement MUST be as strong as possible (as deemed by the responder) without exceeding the strength of at least one of the authentication contexts specified.

The following schema fragment defines the <RequestedAuthnContext> element and its RequestedAuthnContextType complex type:

<element name="RequestedAuthnContext" type="samlp:RequestedAuthnContextType"/> <complexType name="RequestedAuthnContextType"> <choice> <element ref="saml:AuthnContextClassRef" maxOccurs="unbounded"/> <element ref="saml:AuthnContextDeclRef" maxOccurs="unbounded"/> </choice> <attribute name="Comparison" type="samlp:AuthnContextComparisonType" use="optional"/> </complexType> <simpleType name="AuthnContextComparisonType">

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 44 of 86

<restriction base="string"> <enumeration value="exact"/> <enumeration value="minimum"/> <enumeration value="maximum"/> <enumeration value="better"/> </restriction> </simpleType>

3.3.2.3 Element <AttributeQuery>

The <AttributeQuery> element is used to make the query “Return the requested attributes for this subject.” A successful response will be in the form of assertions containing attribute statements, to the extent allowed by policy. This element is of type AttributeQueryType, which extends SubjectQueryAbstractType with the addition of the following element:

<saml:Attribute> [Any Number]

Each <saml:Attribute> element specifies an attribute whose value(s) are to be returned. If no attributes are specified, it indicates that all attributes allowed by policy are requested. If a given <saml:Attribute> element contains one or more <saml:AttributeValue> elements, then if that attribute is returned in the response, it MUST NOT contain any values that are not equal to the values specified in the query. In the absence of equality rules specified by particular profiles or attributes, equality is defined as an identical XML representation of the value. For more information on <saml:Attribute>, see Section 2.7.3.1.

A single query MUST NOT contain two <saml:Attribute> elements with the same Name and NameFormat values (that is, a given attribute MUST be named only once in a query).

In response to an attribute query, a SAML authority returns assertions with attribute statements as follows:

• Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the assertions that may be returned.

• If any <Attribute> elements are present in the query, they constrain/filter the attributes and optionally the values returned, as noted above.

• The attributes and values returned MAY also be constrained by application-specific policy considerations.

The second-level status codes urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile and urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue MAY be used to indicate problems with the interpretation of attribute or value information in a query.

The following schema fragment defines the <AttributeQuery> element and its AttributeQueryType complex type:

<element name="AttributeQuery" type="samlp:AttributeQueryType"/> <complexType name="AttributeQueryType"> <complexContent> <extension base="samlp:SubjectQueryAbstractType"> <sequence> <element ref="saml:Attribute" minOccurs="0" maxOccurs="unbounded"/> </sequence> </extension> </complexContent> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 45 of 86

3.3.2.4 Element <AuthzDecisionQuery>

The <AuthzDecisionQuery> element is used to make the query “Should these actions on this resource be allowed for this subject, given this evidence?” A successful response will be in the form of assertions containing authorization decision statements.

Note: The <AuthzDecisionQuery> feature has been frozen as of SAML V2.0, with no future enhancements planned. Users who require additional functionality may want to consider the eXtensible Access Control Markup Language [XACML], which offers enhanced authorization decision features.

This element is of type AuthzDecisionQueryType, which extends SubjectQueryAbstractType with the addition of the following elements and attribute:

Resource [Required]

A URI reference indicating the resource for which authorization is requested. <saml:Action> [One or More] The actions for which authorization is requested. For more information on this element, see Section 2.7.4.2. <saml:Evidence> [Optional] A set of assertions that the SAML authority MAY rely on in making its authorization decision. For more information on this element, see Section 2.7.4.3. In response to an authorization decision query, a SAML authority returns assertions with authorization decision statements as follows: • Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the assertions that may be returned. The following schema fragment defines the <AuthzDecisionQuery> element and its AuthzDecisionQueryType complex type: <element name="AuthzDecisionQuery" type="samlp:AuthzDecisionQueryType"/> <complexType name="AuthzDecisionQueryType"> <complexContent> <extension base="samlp:SubjectQueryAbstractType"> <sequence> <element ref="saml:Action" maxOccurs="unbounded"/> <element ref="saml:Evidence" minOccurs="0"/> </sequence> <attribute name="Resource" type="anyURI" use="required"/> </extension> </complexContent> </complexType>

3.3.3 Element <Response>

The <Response> message element is used when a response consists of a list of zero or more assertions that satisfy the request. It has the complex type ResponseType, which extends StatusResponseType and adds the following elements:

<saml:Assertion> or <saml:EncryptedAssertion> [Any Number]

Specifies an assertion by value, or optionally an encrypted assertion by value. See Section 2.3.3 for more information on these elements.

The following schema fragment defines the <Response> element and its ResponseType complex type:

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 46 of 86

<element name="Response" type="samlp:ResponseType"/> <complexType name="ResponseType"> <complexContent> <extension base="samlp:StatusResponseType"> <choice minOccurs="0" maxOccurs="unbounded"> <element ref="saml:Assertion"/> <element ref="saml:EncryptedAssertion"/> </choice> </extension> </complexContent> </complexType>

3.3.4 Processing Rules

In response to a SAML-defined query message, every assertion returned by a SAML authority MUST contain a <saml:Subject> element that strongly matches the <saml:Subject> element found in the query.

A <saml:Subject> element S1 strongly matches S2 if and only if the following two conditions both apply:

• If S2 includes an identifier element (<BaseID>, <NameID>, or <EncryptedID>), then S1 MUST include an identical identifier element, but the element MAY be encrypted (or not) in either S1 or S2. In other words, the decrypted form of the identifier MUST be identical in S1 and S2. "Identical" means that the identifier element's content and attribute values MUST be the same. An encrypted identifier will be identical to the original according to this definition, once decrypted.

• If S2 includes one or more <saml:SubjectConfirmation> elements, then S1 MUST include at least one <saml:SubjectConfirmation> element such that S1 can be confirmed in the manner described by at least one <saml:SubjectConfirmation> element in S2.

As an example of what is and is not permitted, S1 could contain a <saml:NameID> with a particular Format value, and S2 could contain a <saml:EncryptedID> element that is the result of encrypting S1's <saml:NameID> element. However, S1 and S2 cannot contain a <saml:NameID> element with different Format values and element content, even if the two identifiers are considered to refer to the same principal.

If the SAML authority cannot provide an assertion with any statements satisfying the constraints expressed by a query or assertion reference, the <Response> element MUST NOT contain an <Assertion> element and MUST include a <StatusCode> element with the value urn:oasis:names:tc:SAML:2.0:status:Success.

All other processing rules associated with the underlying request and response messages MUST be observed.

3.4 Authentication Request Protocol

When a principal (or an agent acting on the principal's behalf) wishes to obtain assertions containing authentication statements to establish a security context at one or more relying parties, it can use the authentication request protocol to send an <AuthnRequest> message element to a SAML authority and request that it return a <Response> message containing one or more such assertions. Such assertions MAY contain additional statements of any type, but at least one assertion MUST contain at least one authentication statement. A SAML authority that supports this protocol is also termed an identity provider.

Apart from this requirement, the specific contents of the returned assertions depend on the profile or context of use. Also, the exact means by which the principal or agent authenticates to the identity provider is not specified, though the means of authentication might impact the content of the response. Other issues related to the validation of authentication credentials by the identity provider or any communication

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 47 of 86

between the identity provider and any other entities involved in the authentication process are also out of scope of this protocol.

The descriptions and processing rules in the following sections reference the following actors, many of whom might be the same entity in a particular profile of use:

Requester

The entity who creates the authentication request and to whom the response is to be returned. Presenter The entity who presents the request to the identity provider and either authenticates itself during the transmission of the message, or relies on an existing security context to establish its identity. If not the requester, the presenter acts as an intermediary between the requester and the responding identity provider. Requested Subject The entity about whom one or more assertions are being requested.

Attesting Entity The entity or entities expected to be able to satisfy one of the <SubjectConfirmation> elements of the resulting assertion(s).

Relying Party

The entity or entities expected to consume the assertion(s) to accomplish a purpose defined by the profile or context of use, generally to establish a security context.

Identity Provider The entity to whom the presenter gives the request and from whom the presenter receives the response.

3.4.1 Element <AuthnRequest>

To request that an identity provider issue an assertion with an authentication statement, a presenter authenticates to that identity provider (or relies on an existing security context) and sends it an <AuthnRequest> message that describes the properties that the resulting assertion needs to have to satisfy its purpose. Among these properties may be information that relates to the content of the assertion and/or information that relates to how the resulting <Response> message should be delivered to the requester. The process of authentication of the presenter may take place before, during, or after the initial delivery of the <AuthnRequest> message.

The requester might not be the same as the presenter of the request if, for example, the requester is a relying party that intends to use the resulting assertion to authenticate or authorize the requested subject so that the relying party can decide whether to provide a service.

The <AuthnRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

This message has the complex type AuthnRequestType, which extends RequestAbstractType and adds the following elements and attributes, all of which are optional in general, but may be required by specific profiles:

<saml:Subject> [Optional]

Specifies the requested subject of the resulting assertion(s). This may include one or more <saml:SubjectConfirmation> elements to indicate how and/or by whom the resulting assertions can be confirmed. For more information on this element, see Section 2.4.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 48 of 86

If entirely omitted or if no identifier is included, the presenter of the message is presumed to be the requested subject. If no <saml:SubjectConfirmation> elements are included, then the presenter is presumed to be the only attesting entity required and the method is implied by the profile of use and/or the policies of the identity provider. <NameIDPolicy> [Optional] Specifies constraints on the name identifier to be used to represent the requested subject. If omitted, then any type of identifier supported by the identity provider for the requested subject can be used, constrained by any relevant deployment-specific policies, with respect to privacy, for example. <saml:Conditions> [Optional] Specifies the SAML conditions the requester expects to limit the validity and/or use of the resulting assertion(s). The responder MAY modify or supplement this set as it deems necessary. The information in this element is used as input to the process of constructing the assertion, rather than as conditions on the use of the request itself. (For more information on this element, see Section 2.5.) <RequestedAuthnContext> [Optional] Specifies the requirements, if any, that the requester places on the authentication context that applies to the responding provider's authentication of the presenter. See Section 3.3.2.2.1 for processing rules regarding this element. <Scoping> [Optional] Specifies a set of identity providers trusted by the requester to authenticate the presenter, as well as limitations and context related to proxying of the <AuthnRequest> message to subsequent identity providers by the responder. ForceAuthn [Optional] A Boolean value. If "true", the identity provider MUST authenticate the presenter directly rather than rely on a previous security context. If a value is not provided, the default is "false". However, if both ForceAuthn and IsPassive are "true", the identity provider MUST NOT freshly authenticate the presenter unless the constraints of IsPassive can be met. IsPassive [Optional] A Boolean value. If "true", the identity provider and the user agent itself MUST NOT visibly take control of the user interface from the requester and interact with the presenter in a noticeable fashion. If a value is not provided, the default is "false". AssertionConsumerServiceIndex [Optional] Indirectly identifies the location to which the <Response> message should be returned to the requester. It applies only to profiles in which the requester is different from the presenter, such as the Web Browser SSO profile in [SAMLProf]. The identity provider MUST have a trusted means to map the index value in the attribute to a location associated with the requester. [SAMLMeta] provides one possible mechanism. If omitted, then the identity provider MUST return the <Response> message to the default location associated with the requester for the profile of use. If the index specified is invalid, then the identity provider MAY return an error <Response> or it MAY use the default location. This attribute is mutually exclusive with the AssertionConsumerServiceURL and ProtocolBinding attributes. AssertionConsumerServiceURL [Optional] Specifies by value the location to which the <Response> message MUST be returned to the requester. The responder MUST ensure by some means that the value specified is in fact associated with the requester. [SAMLMeta] provides one possible mechanism; signing the enclosing <AuthnRequest> message is another. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute and is typically accompanied by the ProtocolBinding attribute.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 49 of 86

ProtocolBinding [Optional] A URI reference that identifies a SAML protocol binding to be used when returning the <Response> message. See [SAMLBind] for more information about protocol bindings and URI references defined for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute and is typically accompanied by the AssertionConsumerServiceURL attribute. AttributeConsumingServiceIndex [Optional] Indirectly identifies information associated with the requester describing the SAML attributes the requester desires or requires to be supplied by the identity provider in the <Response> message. The identity provider MUST have a trusted means to map the index value in the attribute to information associated with the requester. [SAMLMeta] provides one possible mechanism. The identity provider MAY use this information to populate one or more <saml:AttributeStatement> elements in the assertion(s) it returns. ProviderName [Optional] Specifies the human-readable name of the requester for use by the presenter's user agent or the identity provider.

See Section 3.4.1.4 for general processing rules regarding this message.

The following schema fragment defines the <AuthnRequest> element and its AuthnRequestType complex type:

<element name="AuthnRequest" type="samlp:AuthnRequestType"/> <complexType name="AuthnRequestType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <element ref="saml:Subject" minOccurs="0"/> <element ref="samlp:NameIDPolicy" minOccurs="0"/> <element ref="saml:Conditions" minOccurs="0"/> <element ref="samlp:RequestedAuthnContext" minOccurs="0"/> <element ref="samlp:Scoping" minOccurs="0"/> </sequence> <attribute name="ForceAuthn" type="boolean" use="optional"/> <attribute name="IsPassive" type="boolean" use="optional"/> <attribute name="ProtocolBinding" type="anyURI" use="optional"/> <attribute name="AssertionConsumerServiceIndex" type="unsignedShort" use="optional"/> <attribute name="AssertionConsumerServiceURL" type="anyURI" use="optional"/> <attribute name="AttributeConsumingServiceIndex" type="unsignedShort" use="optional"/> <attribute name="ProviderName" type="string" use="optional"/> </extension> </complexContent> </complexType>

3.4.1.1 Element <NameIDPolicy>

The <NameIDPolicy> element tailors the name identifier in the subjects of assertions resulting from an <AuthnRequest>. Its NameIDPolicyType complex type defines the following attributes:

Format [Optional]

Specifies the URI reference corresponding to a name identifier format defined in this or another specification (see Section 8.3 for examples). The additional value of urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is defined specifically for use within this attribute to indicate a request that the resulting identifier be encrypted.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 50 of 86

SPNameQualifier [Optional] Optionally specifies that the assertion subject's identifier be returned (or created) in the namespace of a service provider other than the requester, or in the namespace of an affiliation group of service providers. See for example the definition of urn:oasis:names:tc:SAML:2.0:nameidformat:persistent in Section 8.3.7. AllowCreate [Optional] A Boolean value used to indicate whether the identity provider is allowed, in the course of fulfilling the request, to create a new identifier to represent the principal. Defaults to "false". When "false", the requester constrains the identity provider to only issue an assertion to it if an acceptable identifier for the principal has already been established. Note that this does not prevent the identity provider from creating such identifiers outside the context of this specific request (for example, in advance for a large number of principals).

When this element is used, if the content is not understood by or acceptable to the identity provider, then a <Response> message element MUST be returned with an error <Status>, and MAY contain a secondlevel <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy.

If the Format value is omitted or set to urn:oasis:names:tc:SAML:2.0:nameidformat:unspecified, then the identity provider is free to return any kind of identifier, subject to any additional constraints due to the content of this element or the policies of the identity provider or principal.

The special Format value urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted indicates that the resulting assertion(s) MUST contain <EncryptedID> elements instead of plaintext. The underlying name identifier's unencrypted form can be of any type supported by the identity provider for the requested subject.

Regardless of the Format in the <NameIDPolicy>, the identity provider MAY return an <EncryptedID> in the resulting assertion subject if the policies in effect at the identity provider (possibly specific to the service provider) require that an encrypted identifier be used.

Note that if the requester wishes to permit the identity provider to establish a new identifier for the principal if none exists, it MUST include this element with the AllowCreate attribute set to "true". Otherwise, only a principal for whom the identity provider has previously established an identifier usable by the requester can be authenticated successfully. This is primarily useful in conjunction with the urn:oasis:names:tc:SAML:2.0:nameid-format:persistent Format value (see Section 8.3.7).

The following schema fragment defines the <NameIDPolicy> element and its NameIDPolicyType complex type:

<element name="NameIDPolicy" type="samlp:NameIDPolicyType"/> <complexType name="NameIDPolicyType"> <attribute name="Format" type="anyURI" use="optional"/> <attribute name="SPNameQualifier" type="string" use="optional"/> <attribute name="AllowCreate" type="boolean" use="optional"/> </complexType>

3.4.1.2 Element <Scoping>

The <Scoping> element specifies the identity providers trusted by the requester to authenticate the presenter, as well as limitations and context related to proxying of the <AuthnRequest> message to subsequent identity providers by the responder. Its ScopingType complex type defines the following elements and attribute:

ProxyCount [Optional]

Specifies the number of proxying indirections permissible between the identity provider that receives this <AuthnRequest> and the identity provider who ultimately authenticates the principal. A count of zero permits no proxying, while omitting this attribute expresses no such restriction.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 51 of 86

<IDPList> [Optional] An advisory list of identity providers and associated information that the requester deems acceptable to respond to the request. <RequesterID> [Zero or More]

Identifies the set of requesting entities on whose behalf the requester is acting. Used to communicate the chain of requesters when proxying occurs, as described in Section 3.4.1.5. See Section 8.3.6 for a description of entity identifiers.

In profiles specifying an active intermediary, the intermediary MAY examine the list and return a <Response> message with an error <Status> and a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP or urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP if it cannot contact or does not support any of the specified identity providers.

The following schema fragment defines the <Scoping> element and its ScopingType complex type:

<element name="Scoping" type="samlp:ScopingType"/> <complexType name="ScopingType"> <sequence> <element ref="samlp:IDPList" minOccurs="0"/> <element ref="samlp:RequesterID" minOccurs="0" maxOccurs="unbounded"/> </sequence> <attribute name="ProxyCount" type="nonNegativeInteger" use="optional"/> </complexType> <element name="RequesterID" type="anyURI"/>

3.4.1.3 Element <IDPList>

The <IDPList> element specifies the identity providers trusted by the requester to authenticate the presenter. Its IDPListType complex type defines the following elements:

<IDPEntry> [One or More]

Information about a single identity provider. <GetComplete> [Optional] If the <IDPList> is not complete, using this element specifies a URI reference that can be used to retrieve the complete list. Retrieving the resource associated with the URI MUST result in an XML instance whose root element is an <IDPList> that does not itself contain a <GetComplete> element. The following schema fragment defines the <IDPList> element and its IDPListType complex type: <element name="IDPList" type="samlp:IDPListType"/> <complexType name="IDPListType"> <sequence> <element ref="samlp:IDPEntry" maxOccurs="unbounded"/> <element ref="samlp:GetComplete" minOccurs="0"/> </sequence> </complexType> <element name="GetComplete" type="anyURI"/>

3.4.1.3.1 Element <IDPEntry>

The <IDPEntry> element specifies a single identity provider trusted by the requester to authenticate the presenter. Its IDPEntryType complex type defines the following attributes:

ProviderID [Required]

The unique identifier of the identity provider. See Section 8.3.6 for a description of such identifiers.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 52 of 86

Name [Optional] A human-readable name for the identity provider. Loc [Optional]

A URI reference representing the location of a profile-specific endpoint supporting the authentication request protocol. The binding to be used must be understood from the profile of use.

The following schema fragment defines the <IDPEntry> element and its IDPEntryType complex type: <element name="IDPEntry" type="samlp:IDPEntryType"/> <complexType name="IDPEntryType"> <attribute name="ProviderID" type="anyURI" use="required"/> <attribute name="Name" type="string" use="optional"/> <attribute name="Loc" type="anyURI" use="optional"/> </complexType>

3.4.1.4 Processing Rules

The <AuthnRequest> and <Response> exchange supports a variety of usage scenarios and is therefore typically profiled for use in a specific context in which this optionality is constrained and specific kinds of input and output are required or prohibited. The following processing rules apply as invariant behavior across any profile of this protocol exchange. All other processing rules associated with the underlying request and response messages MUST also be observed.

The responder MUST ultimately reply to an <AuthnRequest> with a <Response> message containing one or more assertions that meet the specifications defined by the request, or with a <Response> message containing a <Status> describing the error that occurred. The responder MAY conduct additional message exchanges with the presenter as needed to initiate or complete the authentication process, subject to the nature of the protocol binding and the authentication mechanism. As described in the next section, this includes proxying the request by directing the presenter to another identity provider by issuing its own <AuthnRequest> message, so that the resulting assertion can be used to authenticate the presenter to the original responder, in effect using SAML as the authentication mechanism.

If the responder is unable to authenticate the presenter or does not recognize the requested subject, or if prevented from providing an assertion by policies in effect at the identity provider (for example the intended subject has prohibited the identity provider from providing assertions to the relying party), then it MUST return a <Response> with an error <Status>, and MAY return a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:AuthnFailed or urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal.

If the <saml:Subject> element in the request is present, then the resulting assertions' <saml:Subject> MUST strongly match the request <saml:Subject>, as described in Section 3.3.4, except that the identifier MAY be in a different format if specified by <NameIDPolicy>. In such a case, the identifier's physical content MAY be different, but it MUST refer to the same principal.

All of the content defined specifically within <AuthnRequest> is optional, although some may be required by certain profiles. In the absence of any specific content at all, the following behavior is implied:

The assertion(s) returned MUST contain a <saml:Subject> element that represents the presenter. The identifier type and format are determined by the identity provider. At least one statement in at least one assertion MUST be a <saml:AuthnStatement> that describes the authentication performed by the responder or authentication service associated with it.

The request presenter should, to the extent possible, be the only attesting entity able to satisfy the <saml:SubjectConfirmation> of the assertion(s). In the case of weaker confirmation methods, binding-specific or other mechanisms will be used to help satisfy this requirement.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 53 of 86

The resulting assertion(s) MUST contain a <saml:AudienceRestriction> element referencing the requester as an acceptable relying party. Other audiences MAY be included as deemed appropriate by the identity provider.

3.4.1.5 Proxying

If an identity provider that receives an <AuthnRequest> has not yet authenticated the presenter or cannot directly authenticate the presenter, but believes that the presenter has already authenticated to another identity provider or a non-SAML equivalent, it may respond to the request by issuing a new <AuthnRequest> on its own behalf to be presented to the other identity provider, or a request in whatever non-SAML format the entity recognizes. The original identity provider is termed the proxying identity provider.

Upon the successful return of a <Response> (or non-SAML equivalent) to the proxying provider, the enclosed assertion or non-SAML equivalent MAY be used to authenticate the presenter so that the proxying provider can issue an assertion of its own in response to the original <AuthnRequest>, completing the overall message exchange. Both the proxying and authenticating identity providers MAY include constraints on proxying activity in the messages and assertions they issue, as described in previous sections and below.

The requester can influence proxy behavior by including a <Scoping> element where the provider sets a desired ProxyCount value and/or indicates a list of preferred identity providers which may be proxied by including an ordered <IDPList> of preferred providers.

An identity provider can control secondary use of its assertions by proxying identity providers using a <ProxyRestriction> element in the assertions it issues.

3.4.1.5.1 Proxying Processing Rules

An identity provider MAY proxy an <AuthnRequest> if the <ProxyCount> attribute is omitted or is greater than zero. Whether it chooses to proxy or not is a matter of local policy. An identity provider MAY choose to proxy for a provider specified in the <IDPList>, if provided, but is not required to do so.

An identity provider MUST NOT proxy a request where <ProxyCount> is set to zero. The identity provider MUST return an error <Status> containing a second-level <StatusCode> value of urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded, unless it can directly authenticate the presenter.

If it chooses to proxy to a SAML identity provider, when creating the new <AuthnRequest>, the proxying identity provider MUST include equivalent or stricter forms of all the information included in the original request (such as authentication context policy). Note, however, that the proxying provider is free to specify whatever <NameIDPolicy> it wishes to maximize the chances of a successful response.

If the authenticating identity provider is not a SAML identity provider, then the proxying provider MUST have some other way to ensure that the elements governing user agent interaction (<IsPassive>, for example) will be honored by the authenticating provider.

The new <AuthnRequest> MUST contain a <ProxyCount> attribute with a value of at most one less than the original value. If the original request does not contain a <ProxyCount> attribute, then the new request SHOULD contain a <ProxyCount> attribute.

If an <IDPList> was specified in the original request, the new request MUST also contain an <IDPList>. The proxying identity provider MAY add additional identity providers to the end of the <IDPList>, but MUST NOT remove any from the list.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 54 of 86

The authentication request and response are processed in normal fashion, in accordance with the rules given in this section and the profile of use. Once the presenter has authenticated to the proxying identity provider (in the case of SAML by delivering a <Response>), the following steps are followed:

The proxying identity provider prepares a new assertion on its own behalf by copying in the relevant information from the original assertion or non-SAML equivalent.

The new assertion's <saml:Subject> MUST contain an identifier that satisfies the original requester 's preferences, as defined by its <NameIDPolicy> element.

The <saml:AuthnStatement> in the new assertion MUST include a <saml:AuthnContext> element containing a <saml:AuthenticatingAuthority> element referencing the identity provider to which the proxying identity provider referred the presenter. If the original assertion contains <saml:AuthnContext> information that includes one or more <saml:AuthenticatingAuthority> elements, those elements SHOULD be included in the new assertion, with the new element placed after them.

If the authenticating identity provider is not a SAML provider, then the proxying identity provider MUST generate a unique identifier value for the authenticating provider. This value SHOULD be consistent over time across different requests. The value MUST not conflict with values used or generated by other SAML providers.

Any other <saml:AuthnContext> information MAY be copied, translated, or omitted in accordance with the policies of the proxying identity provider, provided that the original requirements dictated by the requester are met.

If, in the future, the identity provider is asked to authenticate the same presenter for a second requester, and this request is equally or less strict than the original request (as determined by the proxying identity provider), the identity provider MAY skip the creation of a new <AuthnRequest> to the authenticating identity provider and immediately issue another assertion (assuming the original assertion or non-SAML equivalent it received is still valid).

3.5 Artifact Resolution Protocol

The artifact resolution protocol provides a mechanism by which SAML protocol messages can be transported in a SAML binding by reference instead of by value. Both requests and responses can be obtained by reference using this specialized protocol. A message sender, instead of binding a message to a transport protocol, sends a small piece of data called an artifact using the binding. An artifact can take a variety of forms, but must support a means by which the receiver can determine who sent it. If the receiver wishes, it can then use this protocol in conjunction with a different (generally synchronous) SAML binding protocol to resolve the artifact into the original protocol message.

The most common use for this mechanism is with bindings that cannot easily carry a message because of size constraints, or to enable a message to be communicated via a secure channel between the SAML requester and responder, avoiding the need for a signature.

Depending on the characteristics of the underlying message being passed by reference, the artifact resolution protocol MAY require protections such as mutual authentication, integrity protection, confidentiality, etc. from the protocol binding used to resolve the artifact. In all cases, the artifact MUST exhibit a single-use semantic such that once it has been successfully resolved, it can no longer be used by any party.

Regardless of the protocol message obtained, the result of resolving an artifact MUST be treated exactly as if the message so obtained had been sent originally in place of the artifact.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 55 of 86

3.5.1 Element <ArtifactResolve>

The <ArtifactResolve> message is used to request that a SAML protocol message be returned in an <ArtifactResponse> message by specifying an artifact that represents the SAML protocol message. The original transmission of the artifact is governed by the specific protocol binding that is being used; see [SAMLBind] for more information on the use of artifacts in bindings.

The <ArtifactResolve> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

This message has the complex type ArtifactResolveType, which extends RequestAbstractType and adds the following element:

<Artifact> [Required]

The artifact value that the requester received and now wishes to translate into the protocol message it represents. See [SAMLBind] for specific artifact format information.

The following schema fragment defines the <ArtifactResolve> element and its ArtifactResolveType complex type:

<element name="ArtifactResolve" type="samlp:ArtifactResolveType"/> <complexType name="ArtifactResolveType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <element ref="samlp:Artifact"/> </sequence> </extension> </complexContent> </complexType> <element name="Artifact" type="string"/>

3.5.2 Element <ArtifactResponse>

The recipient of an <ArtifactResolve> message MUST respond with an <ArtifactResponse> message element. This element is of complex type ArtifactResponseType, which extends StatusResponseType with a single optional wildcard element corresponding to the SAML protocol message being returned. This wrapped message element can be a request or a response.

The <ArtifactResponse> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

The following schema fragment defines the <ArtifactResponse> element and its ArtifactResponseType complex type:

<element name="ArtifactResponse" type="samlp:ArtifactResponseType"/> <complexType name="ArtifactResponseType"> <complexContent> <extension base="samlp:StatusResponseType"> <sequence> <any namespace="##any" processContents="lax" minOccurs="0"/> </sequence> </extension> </complexContent> </complexType>

3.5.3 Processing Rules

If the responder recognizes the artifact as valid, then it responds with the associated protocol message in an <ArtifactResponse> message element. Otherwise, it responds with an <ArtifactResponse>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 56 of 86

element with no embedded message. In both cases, the <Status> element MUST include a <StatusCode> element with the code value urn:oasis:names:tc:SAML:2.0:status:Success. A response message with no embedded message inside it is termed an empty response in the remainder of this section.

The responder MUST enforce a one-time-use property on the artifact by ensuring that any subsequent request with the same artifact by any requester results in an empty response as described above.

Some SAML protocol messages, most particularly the <AuthnRequest> message in some profiles, MAY be intended for consumption by any party that receives it and can respond appropriately. In most other cases, however, a message is intended for a specific entity. In such cases, the artifact when issued MUST be associated with the intended recipient of the message that the artifact represents. If the artifact issuer receives an <ArtifactResolve> message from a requester that cannot authenticate itself as the original intended recipient, then the artifact issuer MUST return an empty response.

The artifact issuer SHOULD enforce the shortest practical time limit on the usability of an artifact, such that an acceptable window of time (but no more) exists for the artifact receiver to obtain the artifact and return it in an <ArtifactResolve> message to the issuer.

Note that the <ArtifactResponse> message's InResponseTo attribute MUST contain the value of the corresponding <ArtifactResolve> message's ID attribute, but the embedded protocol message will contain its own message identifier, and in the case of an embedded response, may contain a different InResponseTo value that corresponds to the original request message to which the embedded message is responding.

All other processing rules associated with the underlying request and response messages MUST be observed.

3.6 Name Identifier Management Protocol

After establishing a name identifier for a principal, an identity provider wishing to change the value and/or format of the identifier that it will use when referring to the principal, or to indicate that a name identifier will no longer be used to refer to the principal, informs service providers of the change by sending them a <ManageNameIDRequest> message.

A service provider also uses this message to register or change the SPProvidedID value to be included when the underlying name identifier is used to communicate with it, or to terminate the use of a name identifier between itself and the identity provider.

Note that this protocol is typically not used with "transient" name identifiers, since their value is not intended to be managed on a long term basis.

3.6.1 Element <ManageNameIDRequest>

A provider sends a <ManageNameIDRequest> message to inform the recipient of a changed name identifier or to indicate the termination of the use of a name identifier.

The <ManageNameIDRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

This message has the complex type ManageNameIDRequestType, which extends RequestAbstractType and adds the following elements:

<saml:NameID> or <saml:EncryptedID> [Required]

The name identifier and associated descriptive data (in plaintext or encrypted form) that specify the principal as currently recognized by the identity and service providers prior to this request. (For more information on these elements, see Section 2.2.)

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 57 of 86

<NewID> or <NewEncryptedID> or <Terminate> [Required] The new identifier value (in plaintext or encrypted form) to be used when communicating with the requesting provider concerning this principal, or an indication that the use of the old identifier has been terminated. In the former case, if the requester is the service provider, the new identifier MUST appear in subsequent <NameID> elements in the SPProvidedID attribute. If the requester is the identity provider, the new value will appear in subsequent <NameID> elements as the element's content. The following schema fragment defines the <ManageNameIDRequest> element and its ManageNameIDRequestType complex type: <element name="ManageNameIDRequest" type="samlp:ManageNameIDRequestType"/> <complexType name="ManageNameIDRequestType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <choice> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> <choice> <element ref="samlp:NewID"/> <element ref="samlp:NewEncryptedID"/> <element ref="samlp:Terminate"/> </choice> </sequence> </extension> </complexContent> </complexType> <element name="NewID" type="string"/> <element name="NewEncryptedID" type="saml:EncryptedElementType"/> <element name="Terminate" type="samlp:TerminateType"/> <complexType name="TerminateType"/>

3.6.2 Element <ManageNameIDResponse>

The recipient of a <ManageNameIDRequest> message MUST respond with a <ManageNameIDResponse> message, which is of type StatusResponseType with no additional content.

The <ManageNameIDResponse> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

The following schema fragment defines the <ManageNameIDResponse> element:

<element name="ManageNameIDResponse" type="samlp:StatusResponseType"/>

3.6.3 Processing Rules

If the request includes a <saml:NameID> (or encrypted version) that the recipient does not recognize, the responding provider MUST respond with an error <Status> and MAY respond with a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal.

If the <Terminate> element is included in the request, the requesting provider is indicating that (in the case of a service provider) it will no longer accept assertions from the identity provider or (in the case of an identity provider) it will no longer issue assertions to the service provider about the principal. The receiving provider can perform any maintenance with the knowledge that the relationship represented by the name identifier has been terminated. It can choose to invalidate the active session(s) of a principal for whom a relationship has been terminated.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 58 of 86

If the service provider requests that its identifier for the principal be changed by including a <NewID> (or <NewEncryptedID>) element, the identity provider MUST include the element's content as the SPProvidedID when subsequently communicating to the service provider regarding this principal.

If the identity provider requests that its identifier for the principal be changed by including a <NewID> (or <NewEncryptedID>) element, the service provider MUST use the element's content as the <saml:NameID> element content when subsequently communicating with the identity provider regarding this principal.

Note that neither, either, or both of the original and new identifier MAY be encrypted (using the <EncryptedID> and <NewEncryptedID> elements).

In any case, the <saml:NameID> content in the request and its associated SPProvidedID attribute MUST contain the most recent name identifier information established between the providers for the principal.

In the case of an identifier with a Format of urn:oasis:names:tc:SAML:2.0:nameidformat:persistent, the NameQualifier attribute MUST contain the unique identifier of the identity provider that created the identifier. If the identifier was established between the identity provider and an affiliation group of which the service provider is a member, then the SPNameQualifier attribute MUST contain the unique identifier of the affiliation group. Otherwise, it MUST contain the unique identifier of the service provider. These attributes MAY be omitted if they would otherwise match the value of the containing protocol message's <Issuer> element, but this is NOT RECOMMENDED due to the opportunity for confusion.

Changes to these identifiers may take a potentially significant amount of time to propagate through the systems at both the requester and the responder. Implementations might wish to allow each party to accept either identifier for some period of time following the successful completion of a name identifier change. Not doing so could result in the inability of the principal to access resources.

All other processing rules associated with the underlying request and response messages MUST be observed.

3.7 Single Logout Protocol

The single logout protocol provides a message exchange protocol by which all sessions provided by a particular session authority are near-simultaneously terminated. The single logout protocol is used either when a principal logs out at a session participant or when the principal logs out directly at the session authority. This protocol may also be used to log out a principal due to a timeout. The reason for the logout event can be indicated through the Reason attribute.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

The principal may have established authenticated sessions with both the session authority and individual session participants, based on assertions containing authentication statements supplied by the session authority. When the principal invokes the single logout process at a session participant, the session participant MUST send a <LogoutRequest> message to the session authority that provided the assertion containing the authentication statement related to that session at the session participant. When either the principal invokes a logout at the session authority, or a session participant sends a logout request to the session authority specifying that principal, the session authority SHOULD send a <LogoutRequest> message to each session participant to which it provided assertions containing authentication statements under its current session with the principal, with the exception of the session participant that sent the <LogoutRequest> message to the session authority. It SHOULD attempt to contact as many of these participants as it can using this protocol, terminate its own session with the principal, and finally return a <LogoutResponse> message to the requesting session participant, if any.

Page 59 of 86

3.7.1 Element <LogoutRequest>

A session participant or session authority sends a <LogoutRequest> message to indicate that a session has been terminated.

The <LogoutRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

This message has the complex type LogoutRequestType, which extends RequestAbstractType and adds the following elements and attributes:

NotOnOrAfter [Optional]

The time at which the request expires, after which the recipient may discard the message. The time value is encoded in UTC, as described in Section 1.3.3. Reason [Optional]

An indication of the reason for the logout, in the form of a URI reference.

<saml:BaseID> or <saml:NameID> or <saml:EncryptedID> [Required]

The identifier and associated attributes (in plaintext or encrypted form) that specify the principal as currently recognized by the identity and service providers prior to this request. (For more information on this element, see Section 2.2.) <SessionIndex> [Optional] The identifier that indexes this session at the message recipient. The following schema fragment defines the <LogoutRequest> element and associated LogoutRequestType complex type: <element name="LogoutRequest" type="samlp:LogoutRequestType"/> <complexType name="LogoutRequestType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <choice> <element ref="saml:BaseID"/> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> <element ref="samlp:SessionIndex" minOccurs="0" maxOccurs="unbounded"/> </sequence> <attribute name="Reason" type="string" use="optional"/> <attribute name="NotOnOrAfter" type="dateTime" use="optional"/> </extension> </complexContent> </complexType> <element name="SessionIndex" type="string"/>

3.7.2 Element <LogoutResponse>

The recipient of a <LogoutRequest> message MUST respond with a <LogoutResponse> message, of type StatusResponseType, with no additional content specified.

The <LogoutResponse> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

The following schema fragment defines the <LogoutResponse> element:

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 60 of 86

<element name="LogoutResponse" type="samlp:StatusResponseType"/>

3.7.3 Processing Rules

The message sender MAY use the Reason attribute to indicate the reason for sending the <LogoutRequest>. The following values are defined by this specification for use by all message senders; other values MAY be agreed on between participants:

urn:oasis:names:tc:SAML:2.0:logout:user Specifies that the message is being sent because the principal wishes to terminate the indicated session.

urn:oasis:names:tc:SAML:2.0:logout:admin Specifies that the message is being sent because an administrator wishes to terminate the indicated session for that principal.

All other processing rules associated with the underlying request and response messages MUST be observed.

Additional processing rules are provided in the following sections.

3.7.3.1 Session Participant Rules

When a session participant receives a <LogoutRequest> message, the session participant MUST authenticate the message. If the sender is the authority that provided an assertion containing an authentication statement linked to the principal's current session, the session participant MUST invalidate the principal's session(s) referred to by the <saml:BaseID>, <saml:NameID>, or <saml:EncryptedID> element, and any <SessionIndex> elements supplied in the message. If no <SessionIndex> elements are supplied, then all sessions associated with the principal MUST be invalidated. The session participant MUST apply the logout request message to any assertion that meets the following conditions, even if the assertion arrives after the logout request:

The subject of the assertion strongly matches the <saml:BaseID>, <saml:NameID>, or <saml:EncryptedID> element in the <LogoutRequest>, as defined in Section 3.3.4.

The SessionIndex attribute of one of the assertion's authentication statements matches one of the <SessionIndex> elements specified in the logout request, or the logout request contains no <SessionIndex> elements.

The assertion would otherwise be valid, based on the time conditions specified in the assertion itself (in particular, the value of any specified NotOnOrAfter attributes in conditions or subject confirmation data).

The logout request has not yet expired (determined by examining the NotOnOrAfter attribute on the message).

Note: This rule is intended to prevent a situation in which a session participant receives a logout request targeted at a single, or multiple, assertion(s) (as identified by the <SessionIndex> element(s)) before it receives the actual – and possibly still valid assertion(s) targeted by the logout request. It should honor the logout request until the logout request itself may be discarded (the NotOnOrAfter value on the request has been exceeded) or the assertion targeted by the logout request has been received and has been handled appropriately.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 61 of 86

3.7.3.2 Session Authority Rules

When a session authority receives a <LogoutRequest> message, the session authority MUST authenticate the sender. If the sender is a session participant to which the session authority provided an assertion containing an authentication statement for the current session, then the session authority SHOULD do the following in the specified order: • Send a <LogoutRequest> message to any session authority on behalf of whom the session authority proxied the principal's authentication, unless the second authority is the originator of the <LogoutRequest>.

Send a <LogoutRequest> message to each session participant for which the session authority provided assertions in the current session, other than the originator of a current <LogoutRequest>.

Terminate the principal's current session as specified by the <saml:BaseID>, <saml:NameID>, or <saml:EncryptedID> element, and any <SessionIndex> elements present in the logout request message.

If the session authority successfully terminates the principal's session with respect to itself, then it MUST respond to the original requester, if any, with a <LogoutResponse> message containing a top-level status code of urn:oasis:names:tc:SAML:2.0:status:Success. If it cannot do so, then it MUST respond with a <LogoutResponse> message containing a top-level status code indicating the error. Thus, the top-level status indicates the state of the logout operation only with respect to the session authority itself.

The session authority SHOULD attempt to contact each session participant using any applicable/usable protocol binding, even if one or more of these attempts fails or cannot be attempted (for example because the original request takes place using a protocol binding that does not enable the logout to be propagated to all participants).

In the event that not all session participants successfully respond to these <LogoutRequest> messages (or if not all participants can be contacted), then the session authority MUST include in its <LogoutResponse> message a second-level status code of urn:oasis:names:tc:SAML:2.0:status:PartialLogout to indicate that not all other session participants successfully responded with confirmation of the logout.

Note that a session authority MAY initiate a logout for reasons other than having received a <LogoutRequest> from a session participant – these include, but are not limited to:

• If some timeout period was agreed out-of-band with an individual session participant, the session authority MAY send a <LogoutRequest> to that individual participant alone.

• An agreed global timeout period has been exceeded.

• The principal or some other trusted entity has requested logout of the principal directly at the session authority.

• The session authority has determined that the principal's credentials may have been compromised.

When constructing a logout request message, the session authority MUST set the value of the NotOnOrAfter attribute of the message to a time value, indicating an expiration time for the message, after which the logout request may be discarded by the recipient. This value SHOULD be set to a time value equal to or greater than the value of any NotOnOrAfter attribute specified in the assertion most recently issued as part of the targeted session (as indicated by the SessionIndex attribute on the logout request).

In addition to the values specified in Section 3.6.3 for the Reason attribute, the following values are also available for use by the session authority only:

urn:oasis:names:tc:SAML:2.0:logout:global-timeout

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 62 of 86

Specifies that the message is being sent because of the global session timeout interval period being exceeded. urn:oasis:names:tc:SAML:2.0:logout:sp-timeout Specifies that the message is being sent because a timeout interval period agreed between a participant and the session authority has been exceeded.

3.8 Name Identifier Mapping Protocol

When an entity that shares an identifier for a principal with an identity provider wishes to obtain a name identifier for the same principal in a particular format or federation namespace, it can send a request to the identity provider using this protocol.

For example, a service provider that wishes to communicate with another service provider with whom it does not share an identifier for the principal can use an identity provider that shares an identifier for the principal with both service providers to map from its own identifier to a new identifier, generally encrypted, with which it can communicate with the second service provider.

Regardless of the type of identifier involved, the mapped identifier SHOULD be encrypted into a <saml:EncryptedID> element unless a specific deployment dictates such protection is unnecessary.

3.8.1 Element <NameIDMappingRequest>

To request an alternate name identifier for a principal from an identity provider, a requester sends an <NameIDMappingRequest> message. This message has the complex type NameIDMappingRequestType, which extends RequestAbstractType and adds the following elements:

<saml:BaseID> or <saml:NameID> or <saml:EncryptedID> [Required]

The identifier and associated descriptive data that specify the principal as currently recognized by the requester and the responder. (For more information on this element, see Section 2.2.) <NameIDPolicy> [Required] The requirements regarding the format and optional name qualifier for the identifier to be returned.

The message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

The following schema fragment defines the <NameIDMappingRequest> element and its NameIDMappingRequestType complex type:

<element name="NameIDMappingRequest" type="samlp:NameIDMappingRequestType"/> <complexType name="NameIDMappingRequestType"> <complexContent> <extension base="samlp:RequestAbstractType"> <sequence> <choice> <element ref="saml:BaseID"/> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> <element ref="samlp:NameIDPolicy"/> </sequence> </extension> </complexContent> </complexType>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 63 of 86

3.8.2 Element <NameIDMappingResponse>

The recipient of a <NameIDMappingRequest> message MUST respond with a <NameIDMappingResponse> message. This message has the complex type NameIDMappingResponseType, which extends StatusResponseType and adds the following element:

<saml:NameID> or <saml:EncryptedID> [Required]

The identifier and associated attributes that specify the principal in the manner requested, usually in encrypted form. (For more information on this element, see Section 2.2.)

The message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.

The following schema fragment defines the <NameIDMappingResponse> element and its NameIDMappingResponseType complex type:

<element name="NameIDMappingResponse" type="samlp:NameIDMappingResponseType"/> <complexType name="NameIDMappingResponseType"> <complexContent> <extension base="samlp:StatusResponseType"> <choice> <element ref="saml:NameID"/> <element ref="saml:EncryptedID"/> </choice> </extension> </complexContent> </complexType>

3.8.3 Processing Rules

If the responder does not recognize the principal identified in the request, it MAY respond with an error <Status> containing a second-level <StatusCode> of urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal.

At the responder's discretion, the urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy status code MAY be returned to indicate an inability or unwillingness to supply an identifier in the requested format or namespace.

All other processing rules associated with the underlying request and response messages MUST be observed.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 64 of 86
