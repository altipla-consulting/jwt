
import jwt, { type JwtPayload } from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'


let clients: Record<string, jwksClient.JwksClient> = {}

interface Validation {
  discovery: string
  issuer: string
  audience: string
}

export async function verifyJWT(config: Validation, token: string) {
  if (!config.discovery || !config.issuer || !config.audience) {
    throw new Error('missing config')
  }

  if (!clients[config.discovery]) {
    clients[config.discovery] = jwksClient({
      jwksUri: config.discovery,
      rateLimit: true,
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
    issuer: config.issuer,
    audience: config.audience,
    algorithms: ['RS256'],
  }) as JwtPayload
}

interface GeneratorParams {
  key: string
  issuer: string
  audience: string
}

export class Generator<T extends Record<string, any> = Record<string, never>> {
  private key: string
  private issuer: string
  private audience: string
  
  constructor(params: GeneratorParams) {
    if (!params.key || !params.issuer || !params.audience) {
      throw new Error('missing options')
    }
    this.key = params.key
    this.issuer = params.issuer
    this.audience = params.audience
  }

  sign(expirationMs: number, subject: string, payload?: T) {
    if (!expirationMs || !subject) {
      throw new Error('missing options')
    }

    return jwt.sign(payload ?? {}, this.key, {
      algorithm: 'HS256',
      expiresIn: `${expirationMs}ms`,
      audience: this.audience,
      issuer: this.issuer,
      subject,
    })
  }

  verify(token: string) {
    return jwt.verify(token, this.key, {
      algorithms: ['HS256'],
      audience: this.audience,
      issuer: this.issuer,
    }) as JwtPayload & T
  }
}
