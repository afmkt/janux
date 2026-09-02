function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function bytesToBase64url(value: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(value))
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

interface ChallengeResponse {
  publicKey: {
    challenge: string
    rpId?: string
    timeout?: number
    userVerification?: string
    allowCredentials?: { type: string; id: string }[]
    pubKeyCredParams?: unknown[]
    user?: unknown
  }
  token: string
}

export async function passkeyCeremony(
  requestUrl: string,
  verifyUrl: string,
  username: string,
): Promise<string> {
  const challengeRes = await fetch(requestUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(username),
  })
  const challengeData = (await challengeRes.json().catch(() => ({}))) as ChallengeResponse & {
    detail?: string
  }
  if (!challengeRes.ok) {
    throw new Error(challengeData.detail ?? `Passkey challenge failed (${challengeRes.status})`)
  }

  if (challengeData.publicKey.pubKeyCredParams || challengeData.publicKey.user) {
    throw new Error('This account has no passkey yet — sign in another way first')
  }

  const options: PublicKeyCredentialRequestOptions = {
    challenge: base64urlToBytes(challengeData.publicKey.challenge),
    rpId: challengeData.publicKey.rpId,
    timeout: challengeData.publicKey.timeout,
    userVerification: challengeData.publicKey.userVerification as UserVerificationRequirement | undefined,
    allowCredentials: (challengeData.publicKey.allowCredentials ?? []).map((c) => ({
      type: c.type as PublicKeyCredentialType,
      id: base64urlToBytes(c.id),
    })),
  }

  const credential = (await navigator.credentials.get({
    publicKey: options,
  })) as PublicKeyCredential | null
  if (!credential) throw new Error('Passkey ceremony was cancelled')
  const assertion = credential.response as AuthenticatorAssertionResponse

  const verifyRes = await fetch(verifyUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      credential: {
        id: credential.id,
        rawId: bytesToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bytesToBase64url(assertion.clientDataJSON),
          authenticatorData: bytesToBase64url(assertion.authenticatorData),
          signature: bytesToBase64url(assertion.signature),
          userHandle: assertion.userHandle ? bytesToBase64url(assertion.userHandle) : null,
        },
      },
      token: challengeData.token,
    }),
  })
  const verifyData = (await verifyRes.json().catch(() => ({}))) as {
    ok?: boolean
    data?: string
    detail?: string
  }
  if (!verifyRes.ok || verifyData.ok === false || !verifyData.data) {
    throw new Error(verifyData.detail ?? 'Passkey verification failed')
  }
  return verifyData.data
}
