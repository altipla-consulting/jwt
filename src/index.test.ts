
import { expect, test } from 'vitest'
import { Generator, verifyJWT } from '.'

test('it should give an error if discovery is missing', async () => {
  await expect(() => {
    return verifyJWT({
      discovery: '',
      issuer: 'https://example.com',
      audience: 'https://example.com',
    }, 'token')
  }).rejects.toThrow('missing config')
})

test('it should give an error if issuer is missing', async () => {
  await expect(() => {
    return verifyJWT({
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: '',
      audience: 'https://example.com',
    }, 'token')
  }).rejects.toThrow('missing config')
})

test('it should give an error if audience is missing', async () => {
  await expect(() => {
    return verifyJWT({
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: '',
    }, 'token')
  }).rejects.toThrow('missing config')
})

test('it should give an error if token is missing', async () => {
  await expect(() => {
    return verifyJWT({
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: 'https://example.com',
    }, '')
  }).rejects.toThrow('failed to decode token')
})

test('it should give an error if token is invalid', async () => {
  await expect(() => {
    return verifyJWT({
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: 'https://example.com',
    }, 'invalid')
  }).rejects.toThrow('failed to decode token')
})

test('it should verify a token', async () => {
  let result = await verifyJWT({
    discovery: 'https://token.dev/jwks/keys.json',
    issuer: 'token.dev',
    audience: 'foo',
  }, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY4MTExMjI5NiwiZXhwIjo3NjgxMTE1ODk2LCJpc3MiOiJ0b2tlbi5kZXYiLCJhdWQiOiJmb28ifQ.1xOomFEyuK9Wd6cKfhVvJdqmGAJ3B0zEyiW60Wxu6fU0BL3KNTyIkGgm3Zaaea5XRfHpVwtaDHKRYWY9G8ZnQ525S1tG7xLGsOzMWVVfD5xzc7dDErfHQ36xo_j4zcfsWqceT1OSgfdYkz-fzpE_doWuv2srBLhpd9NJ4jyhS3O014GRHl0bsbVFYhMJ1iRleuf7utrIDKibB38uitYQl00hRBatSXMeN1Q3AN0lKUL5x2r8m_L-7G8rvD8zfSy8FhVeVKzNqiczhxcqM3DEq0WiQ6PoahxoOYHTzP5jfiMZ3dzRvO1Eailc8QdniDI0W4AfwyglD7Aq9ORmH_d50w')
  
  expect(result).toEqual({
    'sub': '1234567890',
    'name': 'John Doe',
    'admin': true,
    'iat': 1681112296,
    'exp': 7681115896,
    'aud': 'foo',
    'iss': 'token.dev',
  })
})

test('it should sign and verify a token', async () => {
  let generator = new Generator<{ foo: string }>({
    key: 'test-key',
    issuer: 'token.dev',
    audience: 'foo',
  })
  let token = generator.sign(1000, 'test', {
    foo: 'bar',
  })

  let result = generator.verify(token)

  expect(result).toEqual({
    foo: 'bar',
    sub: 'test',
    aud: 'foo',
    iss: 'token.dev',
    iat: expect.any(Number),
    exp: expect.any(Number),
  })
})

test('it should throw an error if the token is invalid', async () => {
  let generator = new Generator<{ foo: string }>({
    key: 'test-key',
    issuer: 'token.dev',
    audience: 'foo',
  })
  let token = generator.sign(1000, 'test', {
    foo: 'bar',
  })

  await expect(() => {
    return generator.verify(token + 'invalid')
  }).toThrow('invalid signature')
})
