# Chapter 6 SAML and XML Encryption Syntax and Processing


Encryption is used as the means to implement confidentiality. The most common motives for confidentiality are to protect the personal privacy of individuals or to protect organizational secrets for competitive advantage or similar reasons. Confidentiality may also be required to ensure the effectiveness of some other security mechanism. For example, a secret password or key may be encrypted.

Several ways of using encryption to confidentially protect all or part of a SAML assertion are provided. • Communications confidentiality may be provided by mechanisms associated with a particular binding or profile. For example, the SOAP Binding [SAMLBind] supports the use of SSL/TLS (see [RFC 2246]/[SSL3]) or SOAP Message Security mechanisms for confidentiality.

A <SubjectConfirmation> secret can be protected through the use of the <ds:KeyInfo> element within <SubjectConfirmationData>, which permits keys or other secrets to be encrypted.

An entire <Assertion> element may be encrypted, as described in Section 2.3.4.

The <BaseID> or <NameID> element may be encrypted, as described in Section 2.2.4.

An <Attribute> element may be encrypted, as described in Section 2.7.3.2.

6.1 General Considerations

Encryption of the <Assertion>, <BaseID>, <NameID> and <Attribute> elements is provided by use of XML Encryption [XMLEnc]. Encrypted data and optionally one or more encrypted keys MUST replace the plaintext information in the same location within the XML instance. The <EncryptedData> element's Type attribute SHOULD be used and, if it is present, MUST have the value http://www.w3.org/2001/04/xmlenc#Element.

Any of the algorithms defined for use with XML Encryption MAY be used to perform the encryption. The SAML schema is defined so that the inclusion of the encrypted data yields a valid instance.

6.2 Combining Signatures and Encryption

Use of XML Encryption and XML Signature MAY be combined. When an assertion is to be signed and encrypted, the following rules apply. A relying party MUST perform signature validation and decryption in the reverse order that signing and encryption were performed.

When a signed <Assertion> element is encrypted, the signature MUST first be calculated and placed within the <Assertion> element before the element is encrypted.

When a <BaseID>, <NameID>, or <Attribute> element is encrypted, the encryption MUST be performed first and then the signature calculated over the assertion or message containing the encrypted element.

saml-core-2.0-os Copyright © OASIS Open 2005. All Rights Reserved.

Page 73 of 86
