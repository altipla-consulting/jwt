
import jwt, { type JwtPayload } from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'


let clients: Record<string, jwksClient.JwksClient> = {}

interface Validation {
  discovery: string
  issuer: string
  audience: string
}

export async function verifyJWT(config: Validation, token: string, issuer: string, audience: string) {
  if (!config.discovery || !config.issuer || !config.audience) {
    throw new Error('missing config')
  }

  if (!clients[config.discovery]) {
    clients[config.discovery] = jwksClient({
      jwksUri: config.discovery,
      rateLimit: true,
      jwksRequestsPerMinute: 1,
    })
  }
  let client = clients[config.discovery]

  let decoded = jwt.decode(token, { complete: true })
  if (!decoded) {
    throw new Error('failed to decode token')
  }
  let key = await client.getSigningKey(decoded.header.kid)
  if (!key || !key.getPublicKey()) {
    throw new Error('failed to get signing key')
  }
  
  return jwt.verify(token, key.getPublicKey(), {
    issuer,
    audience,
    algorithms: ['RS256'],
  }) as JwtPayload
}
