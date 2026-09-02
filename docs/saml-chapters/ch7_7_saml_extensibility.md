# Chapter 7 SAML Extensibility


SAML supports extensibility in a number of ways, including extending the assertion and protocol schemas. An example of an application that extends SAML assertions is the Liberty Protocols and Schema Specification [LibertyProt]. The following sections explain the extensibility features with SAML assertions and protocols.

See the SAML Profiles specification [SAMLProf] for information on how to define new profiles, which can be combined with extensions to put the SAML framework to new uses.

7.1 Schema Extension

Note that elements in the SAML schemas are blocked from substitution, which means that no SAML elements can serve as the head element of a substitution group. However, SAML types are not defined as final, so that all SAML types MAY be extended and restricted. As a practical matter, this means that extensions are typically defined only as types rather than elements, and are included in SAML instances by means of an xsi:type attribute.

The following sections discuss only elements and types that have been specifically designed to support extensibility.

7.1.1 Assertion Schema Extension

The SAML assertion schema (see [SAML-XSD]) is designed to permit separate processing of the assertion package and the statements it contains, if the extension mechanism is used for either part.

The following elements are intended specifically for use as extension points in an extension schema; their types are set to abstract, and are thus usable only as the base of a derived type:

• <BaseID> and BaseIDAbstractType

• <Condition> and ConditionAbstractType

• <Statement> and StatementAbstractType

The following constructs that are directly usable as part of SAML are particularly interesting targets for extension:

• <AuthnStatement> and AuthnStatementType

• <AttributeStatement> and AttributeStatementType

• <AuthzDecisionStatement> and AuthzDecisionStatementType

• <AudienceRestriction> and AudienceRestrictionType

• <ProxyRestriction> and ProxyRestrictionType

• <OneTimeUse> and OneTimeUseType

7.1.2 Protocol Schema Extension

The following SAML protocol elements are intended specifically for use as extension points in an extension schema; their types are set to abstract, and are thus usable only as the base of a derived type:

• <Request> and RequestAbstractType

• <SubjectQuery> and SubjectQueryAbstractType

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 74 of 86

The following constructs that are directly usable as part of SAML are particularly interesting targets for extension:

• <AuthnQuery> and AuthnQueryType

• <AuthzDecisionQuery> and AuthzDecisionQueryType

• <AttributeQuery> and AttributeQueryType

• StatusResponseType

7.2 Schema Wildcard Extension Points

The SAML schemas use wildcard constructs in some locations to allow the use of elements and attributes from arbitrary namespaces, which serves as a built-in extension point without requiring an extension schema.

7.2.1 Assertion Extension Points

The following constructs in the assertion schema allow constructs from arbitrary namespaces within them:

• <SubjectConfirmationData>: Uses xs:anyType, which allows any sub-elements and attributes.

• <AuthnContextDecl>: Uses xs:anyType, which allows any sub-elements and attributes.

• <AttributeValue>: Uses xs:anyType, which allows any sub-elements and attributes.

• <Advice> and AdviceType: In addition to SAML-native elements, allows elements from other namespaces with lax schema validation processing.

The following constructs in the assertion schema allow arbitrary global attributes:

• <Attribute> and AttributeType

7.2.2 Protocol Extension Points

The following constructs in the protocol schema allow constructs from arbitrary namespaces within them:

• <Extensions> and ExtensionsType: Allows elements from other namespaces with lax schema validation processing.

• <StatusDetail> and StatusDetailType: Allows elements from other namespaces with lax schema validation processing.

• <ArtifactResponse> and ArtifactResponseType: Allows elements from any namespaces with lax schema validation processing. (It is specifically intended to carry a SAML request or response message element, however.)

7.3 Identifier Extension

SAML uses URI-based identifiers for a number of purposes, such as status codes and name identifier formats, and defines some identifiers that MAY be used for these purposes; most are listed in Section 8. However, it is always possible to define additional URI-based identifiers for these purposes. It is RECOMMENDED that these additional identifiers be defined in a formal profile of use. In no case should the meaning of a given URI used as such an identifier significantly change, or be used to mean two different things.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 75 of 86
