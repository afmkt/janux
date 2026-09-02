# Chapter 4 SAML Versioning


The SAML specification set is versioned in two independent ways. Each is discussed in the following sections, along with processing rules for detecting and handling version differences. Also included are guidelines on when and why specific version information is expected to change in future revisions of the specification.

When version information is expressed as both a Major and Minor version, it is expressed in the form Major.Minor. The version number MajorB.MinorB is higher than the version number MajorA.MinorA if and only if:

(MajorB > MajorA) OR ( ( MajorB = MajorA ) AND (MinorB > MinorA ))

4.1 SAML Specification Set Version

Each release of the SAML specification set will contain a major and minor version designation describing its relationship to earlier and later versions of the specification set. The version will be expressed in the content and filenames of published materials, including the specification set documents and XML schema documents. There are no normative processing rules surrounding specification set versioning, since it merely encompasses the collective release of normative specification documents which themselves contain processing rules.

The overall size and scope of changes to the specification set documents will informally dictate whether a set of changes constitutes a major or minor revision. In general, if the specification set is backwards compatible with an earlier specification set (that is, valid older syntax, protocols, and semantics remain valid), then the new version will be a minor revision. Otherwise, the changes will constitute a major revision.

4.1.1 Schema Version

As a non-normative documentation mechanism, any XML schema documents published as part of the specification set will contain a version attribute on the <xs:schema> element whose value is in the form Major.Minor, reflecting the specification set version in which it has been published. Validating implementations MAY use the attribute as a means of distinguishing which version of a schema is being used to validate messages, or to support multiple versions of the same logical schema.

4.1.2 SAML Assertion Version

The SAML <Assertion> element contains an attribute for expressing the major and minor version of the assertion in a string of the form Major.Minor. Each version of the SAML specification set will be construed so as to document the syntax, semantics, and processing rules of the assertions of the same version. That is, specification set version 1.0 describes assertion version 1.0, and so on.

There is explicitly NO relationship between the assertion version and the target XML namespace specified for the schema definitions for that assertion version.

The following processing rules apply:

• A SAML asserting party MUST NOT issue any assertion with an overall Major.Minor assertion version number not supported by the authority.

• A SAML relying party MUST NOT process any assertion with a major assertion version number not supported by the relying party.

• A SAML relying party MAY process or MAY reject an assertion whose minor assertion version number is higher than the minor assertion version number supported by the relying party. However, all assertions that share a major assertion version number MUST share the same general

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 65 of 86

processing rules and semantics, and MAY be treated in a uniform way by an implementation. For example, if a V1.1 assertion shares the syntax of a V1.0 assertion, an implementation MAY treat the assertion as a V1.0 assertion without ill effect. (See Section 4.2.1 for more information about the likely effects of schema evolution.)

4.1.3 SAML Protocol Version

The various SAML protocols' request and response elements contain an attribute for expressing the major and minor version of the request or response message using a string of the form Major.Minor. Each version of the SAML specification set will be construed so as to document the syntax, semantics, and processing rules of the protocol messages of the same version. That is, specification set version 1.0 describes request and response version V1.0, and so on.

There is explicitly NO relationship between the protocol version and the target XML namespace specified for the schema definitions for that protocol version.

The version numbers used in SAML protocol request and response elements will match for any particular revision of the SAML specification set.

4.1.3.1 Request Version

The following processing rules apply to requests:

• A SAML requester SHOULD issue requests with the highest request version supported by both the SAML requester and the SAML responder.

• If the SAML requester does not know the capabilities of the SAML responder, then it SHOULD assume that the responder supports requests with the highest request version supported by the requester.

• A SAML requester MUST NOT issue a request message with an overall Major.Minor request version number matching a response version number that the requester does not support.

• A SAML responder MUST reject any request with a major request version number not supported by the responder.

• A SAML responder MAY process or MAY reject any request whose minor request version number is higher than the highest supported request version that it supports. However, all requests that share a major request version number MUST share the same general processing rules and semantics, and MAY be treated in a uniform way by an implementation. That is, if a V1.1 request shares the syntax of a V1.0 request, a responder MAY treat the request message as a V1.0 request without ill effect. (See Section 4.2.1 for more information about the likely effects of schema evolution.)

4.1.3.2 Response Version

The following processing rules apply to responses:

• A SAML responder MUST NOT issue a response message with a response version number higher than the request version number of the corresponding request message.

• A SAML responder MUST NOT issue a response message with a major response version number lower than the major request version number of the corresponding request message except to report the error urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh.

• An error response resulting from incompatible SAML protocol versions MUST result in reporting a top-level <StatusCode> value of urn:oasis:names:tc:SAML:2.0:status:VersionMismatch, and MAY result in reporting one of the following second-level values:

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 66 of 86

urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh, urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow, or urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated.

4.1.3.3 Permissible Version Combinations

Assertions of a particular major version appear only in response messages of the same major version, as permitted by the importation of the SAML assertion namespace into the SAML protocol schema. For example, a V1.1 assertion MAY appear in a V1.0 response message, and a V1.0 assertion in a V1.1 response message, if the appropriate assertion schema is referenced during namespace importation. But a V1.0 assertion MUST NOT appear in a V2.0 response message because they are of different major versions.

4.2 SAML Namespace Version

XML schema documents published as part of the specification set contain one or more target namespaces into which the type, element, and attribute definitions are placed. Each namespace is distinct from the others, and represents, in shorthand, the structural and syntactic definitions that make up that part of the specification.

The namespace URI references defined by the specification set will generally contain version information of the form Major.Minor somewhere in the URI. The major and minor version in the URI MUST correspond to the major and minor version of the specification set in which the namespace is first introduced and defined. This information is not typically consumed by an XML processor, which treats the namespace opaquely, but is intended to communicate the relationship between the specification set and the namespaces it defines. This pattern is also followed by the SAML-defined URI-based identifiers that are listed in Section 8.

As a general rule, implementers can expect the namespaces and the associated schema definitions defined by a major revision of the specification set to remain valid and stable across minor revisions of the specification. New namespaces may be introduced, and when necessary, old namespaces replaced, but this is expected to be rare. In such cases, the older namespaces and their associated definitions should be expected to remain valid until a major specification set revision.

4.2.1 Schema Evolution

In general, maintaining namespace stability while adding or changing the content of a schema are competing goals. While certain design strategies can facilitate such changes, it is complex to predict how older implementations will react to any given change, making forward compatibility difficult to achieve. Nevertheless, the right to make such changes in minor revisions is reserved, in the interest of namespace stability. Except in special circumstances (for example, to correct major deficiencies or to fix errors), implementations should expect forward-compatible schema changes in minor revisions, allowing new messages to validate against older schemas.

Implementations SHOULD expect and be prepared to deal with new extensions and message types in accordance with the processing rules laid out for those types. Minor revisions MAY introduce new types that leverage the extension facilities described in Section 7. Older implementations SHOULD reject such extensions gracefully when they are encountered in contexts that dictate mandatory semantics. Examples include new query, statement, or condition types.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 67 of 86
