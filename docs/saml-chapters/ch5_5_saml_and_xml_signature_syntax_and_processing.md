# Chapter 5 SAML and XML Signature Syntax and Processing


SAML assertions and SAML protocol request and response messages may be signed, with the following benefits. An assertion signed by the asserting party supports assertion integrity, authentication of the asserting party to a SAML relying party, and, if the signature is based on the SAML authority’s publicprivate key pair, non-repudiation of origin. A SAML protocol request or response message signed by the message originator supports message integrity, authentication of message origin to a destination, and, if the signature is based on the originator's public-private key pair, non-repudiation of origin.

A digital signature is not always required in SAML. For example, in some circumstances, signatures may be “inherited," such as when an unsigned assertion gains protection from a signature on the containing protocol response message. "Inherited" signatures should be used with care when the contained object (such as the assertion) is intended to have a non-transitory lifetime. The reason is that the entire context must be retained to allow validation, exposing the XML content and adding potentially unnecessary overhead. As another example, the SAML relying party or SAML requester may have obtained an assertion or protocol message from the SAML asserting party or SAML responder directly (with no intermediaries) through a secure channel, with the asserting party or SAML responder having authenticated to the relying party or SAML responder by some means other than a digital signature.

Many different techniques are available for "direct" authentication and secure channel establishment between two parties. The list includes TLS/SSL (see [RFC 2246]/[SSL3]), HMAC, password-based mechanisms, and so on. In addition, the applicable security requirements depend on the communicating applications and the nature of the assertion or message transported. It is RECOMMENDED that, in all other contexts, digital signatures be used for assertions and request and response messages. Specifically:

• A SAML assertion obtained by a SAML relying party from an entity other than the SAML asserting party SHOULD be signed by the SAML asserting party.

• A SAML protocol message arriving at a destination from an entity other than the originating sender SHOULD be signed by the sender.

• Profiles MAY specify alternative signature mechanisms such as S/MIME or signed Java objects that contain SAML documents. Caveats about retaining context and interoperability apply. XML Signatures are intended to be the primary SAML signature mechanism, but this specification attempts to ensure compatibility with profiles that may require other mechanisms.

• Unless a profile specifies an alternative signature mechanism, any XML Digital Signatures MUST be enveloped.

5.1 Signing Assertions

All SAML assertions MAY be signed using XML Signature. This is reflected in the assertion schema as described in Section 2.

5.2 Request/Response Signing

All SAML protocol request and response messages MAY be signed using XML Signature. This is reflected in the schema as described in Section 3.

5.3 Signature Inheritance

A SAML assertion may be embedded within another SAML element, such as an enclosing <Assertion> or a request or response, which may be signed. When a SAML assertion does not contain a <ds:Signature> element, but is contained in an enclosing SAML element that contains a <ds:Signature> element, and the signature applies to the <Assertion> element and all its children,

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 68 of 86

then the assertion can be considered to inherit the signature from the enclosing element. The resulting interpretation should be equivalent to the case where the assertion itself was signed with the same key and signature options.

Many SAML use cases involve SAML XML data enclosed within other protected data structures such as signed SOAP messages, S/MIME packages, and authenticated SSL connections. SAML profiles MAY define additional rules for interpreting SAML elements as inheriting signatures or other authentication information from the surrounding context, but no such inheritance should be inferred unless specifically identified by the profile.

5.4 XML Signature Profile

The XML Signature specification [XMLSig] calls out a general XML syntax for signing data with flexibility and many choices. This section details constraints on these facilities so that SAML processors do not have to deal with the full generality of XML Signature processing. This usage makes specific use of the xs:ID-typed attributes present on the root elements to which signatures can apply, specifically the ID attribute on <Assertion> and the various request and response elements. These attributes are collectively referred to in this section as the identifier attributes.

Note that this profile only applies to the use of the <ds:Signature> elements found directly within SAML assertions, requests, and responses. Other profiles in which signatures appear elsewhere but apply to SAML content are free to define other approaches.

5.4.1 Signing Formats and Algorithms

XML Signature has three ways of relating a signature to a document: enveloping, enveloped, and detached.

SAML assertions and protocols MUST use enveloped signatures when signing assertions and protocol messages. SAML processors SHOULD support the use of RSA signing and verification for public key operations in accordance with the algorithm identified by http://www.w3.org/2000/09/xmldsig#rsa-sha1.

5.4.2 References

SAML assertions and protocol messages MUST supply a value for the ID attribute on the root element of the assertion or protocol message being signed. The assertion’s or protocol message's root element may or may not be the root element of the actual XML document containing the signed assertion or protocol message (e.g., it might be contained within a SOAP envelope).

Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID attribute value of the root element of the assertion or protocol message being signed. For example, if the ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".

5.4.3 Canonicalization Method

SAML implementations SHOULD use Exclusive Canonicalization [Excl-C14N], with or without comments, both in the <ds:CanonicalizationMethod> element of <ds:SignedInfo>, and as a <ds:Transform> algorithm. Use of Exclusive Canonicalization ensures that signatures created over SAML messages embedded in an XML context can be verified independent of that context.

5.4.4 Transforms

Signatures in SAML messages SHOULD NOT contain transforms other than the enveloped signature transform (with the identifier http://www.w3.org/2000/09/xmldsig#enveloped-signature) or the exclusive

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 69 of 86

canonicalization transforms (with the identifier http://www.w3.org/2001/10/xml-exc-c14n# or http://www.w3.org/2001/10/xml-exc-c14n#WithComments).

Verifiers of signatures MAY reject signatures that contain other transform algorithms as invalid. If they do not, verifiers MUST ensure that no content of the SAML message is excluded from the signature. This can be accomplished by establishing out-of-band agreement as to what transforms are acceptable, or by applying the transforms manually to the content and reverifying the result as consisting of the same SAML message.

5.4.5 KeyInfo

XML Signature defines usage of the <ds:KeyInfo> element. SAML does not require the use of <ds:KeyInfo>, nor does it impose any restrictions on its use. Therefore, <ds:KeyInfo> MAY be absent.

5.4.6 Example

Following is an example of a signed response containing a signed assertion. Line breaks have been added for readability; the signatures are not valid and cannot be successfully verified.

<Response IssueInstant="2003-04-17T00:46:02Z" Version="2.0" ID="_c7055387-af61-4fce-8b98-e2927324b306" xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"> <saml:Issuer>https://www.opensaml.org/IDP"</saml:Issuer> <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> <ds:SignedInfo> <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/> <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/> <ds:Reference URI="#_c7055387-af61-4fce-8b98-e2927324b306"> <ds:Transforms> <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#envelopedsignature"/> <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"> <InclusiveNamespaces PrefixList="#default saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#"/> </ds:Transform> </ds:Transforms> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> <ds:DigestValue>TCDVSuG6grhyHbzhQFWFzGrxIPE=</ds:DigestValue> </ds:Reference> </ds:SignedInfo> <ds:SignatureValue> x/GyPbzmFEe85pGD3c1aXG4Vspb9V9jGCjwcRCKrtwPS6vdVNCcY5rHaFPYWkf+5 EIYcPzx+pX1h43SmwviCqXRjRtMANWbHLhWAptaK1ywS7gFgsD01qjyen3CP+m3D w6vKhaqledl0BYyrIzb4KkHO4ahNyBVXbJwqv5pUaE4= </ds:SignatureValue> <ds:KeyInfo> <ds:X509Data> <ds:X509Certificate> MIICyjCCAjOgAwIBAgICAnUwDQYJKoZIhvcNAQEEBQAwgakxCzAJBgNVBAYTAlVT MRIwEAYDVQQIEwlXaXNjb25zaW4xEDAOBgNVBAcTB01hZGlzb24xIDAeBgNVBAoT F1VuaXZlcnNpdHkgb2YgV2lzY29uc2luMSswKQYDVQQLEyJEaXZpc2lvbiBvZiBJ bmZvcm1hdGlvbiBUZWNobm9sb2d5MSUwIwYDVQQDExxIRVBLSSBTZXJ2ZXIgQ0Eg LS0gMjAwMjA3MDFBMB4XDTAyMDcyNjA3Mjc1MVoXDTA2MDkwNDA3Mjc1MVowgYsx CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNaWNoaWdhbjESMBAGA1UEBxMJQW5uIEFy

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 70 of 86

Ym9yMQ4wDAYDVQQKEwVVQ0FJRDEcMBoGA1UEAxMTc2hpYjEuaW50ZXJuZXQyLmVk dTEnMCUGCSqGSIb3DQEJARYYcm9vdEBzaGliMS5pbnRlcm5ldDIuZWR1MIGfMA0G CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZSAb2sxvhAXnXVIVTx8vuRay+x50z7GJj IHRYQgIv6IqaGG04eTcyVMhoekE0b45QgvBIaOAPSZBl13R6+KYiE7x4XAWIrCP+ c2MZVeXeTgV3Yz+USLg2Y1on+Jh4HxwkPFmZBctyXiUr6DxF8rvoP9W7O27rhRjE pmqOIfGTWQIDAQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFoDANBgkq hkiG9w0BAQQFAAOBgQBfDqEW+OI3jqBQHIBzhujN/PizdN7s/z4D5d3pptWDJf2n qgi7lFV6MDkhmTvTqBtjmNk3No7v/dnP6Hr7wHxvCCRwubnmIfZ6QZAv2FU78pLX 8I3bsbmRAUg4UP9hH6ABVq4KQKMknxu1xQxLhpR1ylGPdiowMNTrEG8cCx3w/w== </ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </ds:Signature> <Status> <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/> </Status> <Assertion ID="_a75adf55-01d7-40cc-929f-dbd8372ebdfc" IssueInstant="2003-04-17T00:46:02Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"> <Issuer>https://www.opensaml.org/IDP</Issuer> <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> <ds:SignedInfo> <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/> <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/> <ds:Reference URI="#_a75adf55-01d7-40cc-929f-dbd8372ebdfc"> <ds:Transforms> <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#envelopedsignature"/> <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"> <InclusiveNamespaces PrefixList="#default saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#"/> </ds:Transform> </ds:Transforms> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> <ds:DigestValue>Kclet6XcaOgOWXM4gty6/UNdviI=</ds:DigestValue> </ds:Reference> </ds:SignedInfo> <ds:SignatureValue> hq4zk+ZknjggCQgZm7ea8fI79gJEsRy3E8LHDpYXWQIgZpkJN9CMLG8ENR4Nrw+n 7iyzixBvKXX8P53BTCT4VghPBWhFYSt9tHWu/AtJfOTh6qaAsNdeCyG86jmtp3TD MwuL/cBUj2OtBZOQMFn7jQ9YB7klIz3RqVL+wNmeWI4= </ds:SignatureValue> <ds:KeyInfo> <ds:X509Data> <ds:X509Certificate> MIICyjCCAjOgAwIBAgICAnUwDQYJKoZIhvcNAQEEBQAwgakxCzAJBgNVBAYTAlVT MRIwEAYDVQQIEwlXaXNjb25zaW4xEDAOBgNVBAcTB01hZGlzb24xIDAeBgNVBAoT F1VuaXZlcnNpdHkgb2YgV2lzY29uc2luMSswKQYDVQQLEyJEaXZpc2lvbiBvZiBJ bmZvcm1hdGlvbiBUZWNobm9sb2d5MSUwIwYDVQQDExxIRVBLSSBTZXJ2ZXIgQ0Eg LS0gMjAwMjA3MDFBMB4XDTAyMDcyNjA3Mjc1MVoXDTA2MDkwNDA3Mjc1MVowgYsx CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNaWNoaWdhbjESMBAGA1UEBxMJQW5uIEFy Ym9yMQ4wDAYDVQQKEwVVQ0FJRDEcMBoGA1UEAxMTc2hpYjEuaW50ZXJuZXQyLmVk dTEnMCUGCSqGSIb3DQEJARYYcm9vdEBzaGliMS5pbnRlcm5ldDIuZWR1MIGfMA0G CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZSAb2sxvhAXnXVIVTx8vuRay+x50z7GJj IHRYQgIv6IqaGG04eTcyVMhoekE0b45QgvBIaOAPSZBl13R6+KYiE7x4XAWIrCP+ c2MZVeXeTgV3Yz+USLg2Y1on+Jh4HxwkPFmZBctyXiUr6DxF8rvoP9W7O27rhRjE pmqOIfGTWQIDAQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFoDANBgkq hkiG9w0BAQQFAAOBgQBfDqEW+OI3jqBQHIBzhujN/PizdN7s/z4D5d3pptWDJf2n qgi7lFV6MDkhmTvTqBtjmNk3No7v/dnP6Hr7wHxvCCRwubnmIfZ6QZAv2FU78pLX 8I3bsbmRAUg4UP9hH6ABVq4KQKMknxu1xQxLhpR1ylGPdiowMNTrEG8cCx3w/w==

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 71 of 86

</ds:X509Certificate> </ds:X509Data> </ds:KeyInfo> </ds:Signature> <Subject> <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"> scott@example.org </NameID> <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/> </Subject> <Conditions NotBefore="2003-04-17T00:46:02Z" NotOnOrAfter="2003-04-17T00:51:02Z"> <AudienceRestriction> <Audience>http://www.opensaml.org/SP</Audience> </AudienceRestriction> </Conditions> <AuthnStatement AuthnInstant="2003-04-17T00:46:00Z"> <AuthnContext> <AuthnContextClassRef> urn:oasis:names:tc:SAML:2.0:ac:classes:Password </AuthnContextClassRef> </AuthnContext> </AuthnStatement> </Assertion> </Response>

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 72 of 86
