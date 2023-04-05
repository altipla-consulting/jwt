
import { expect, test } from 'vitest'
import { verifyJWT } from '.'

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
  }, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY4MDcwNDE1MCwiZXhwIjoxNjgwNzA3NzUwLCJhdWQiOiJmb28iLCJpc3MiOiJ0b2tlbi5kZXYifQ.fFnPg-XIrK0l7wrbY4AVFLXezk_Xlq-kVlp9jc3iQ7uSRypMuREN2B0GGUq6GWtBbLSyM-v6zDzRu1n9qOl0Pycs3IkZIb-swj_c38Ju34H9j2c4KxJOZXA2TbMc3mkGKUfsPZaS0ZZmx4KIZfrRIrSS8egwX6YBfR_NCYbXlhQT7RPB1AxJhIz96fIDtdEqzlTyZiT7uApTq1HmN-nGm-PjB_PdlHkCGVN8FWwmPDZfvH2J-GCb7swxqEhPizWBT5VYkIp9rYkCFqCe3bkV1mkk0f1RbVyalMWjEYEdRPGq3GFijWtrSaHzkkGDPijk4BmaGmJNHzKXOAwwMO9b7Q')
  
  expect(result).toEqual({
    'sub': '1234567890',
    'name': 'John Doe',
    'admin': true,
    'iat': 1680704150,
    'exp': 1680707750,
    'aud': 'foo',
    'iss': 'token.dev',
  })
})
