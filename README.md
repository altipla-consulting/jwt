
# jwt.js

Secure and reusable JWT validation for Node.


## Install

```sh
npm install @altipla/jwt
```


## Usage

### Verify a public token

```ts
import { verifyJWT } from '@altipla/jwt'

async function main() {
  try {
    let config = {
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: 'foo',
    }
    let token = '...'
    let payload = await verifyJWT(config, token)
  } catch (error: any) {
    console.error(error)
  }
}
main()
```

### Sign a new token

```ts
import { Generator } from '@altipla/jwt'

interface Data {
  // ... put your token content here
}

async function main() {
  try {
    let generator = new Generator<Data>({
      key: 'test-key',
      issuer: 'token.dev',
      audience: 'foo',
    })
    let token = generator.sign({
      // ... put your token content here
    }, 1000, 'test')
  } catch (error: any) {
    console.error(error)
  }
}

main()
```

### Verify a signed token

```ts
import { Generator } from '@altipla/jwt'

interface Data {
  // ... put your token content here
}

async function main() {
  try {
    let generator = new Generator<Data>({
      key: 'test-key',
      issuer: 'token.dev',
      audience: 'foo',
    })
    let token = // ... get the token from somewhere
    let data = generator.verify(token)
  } catch (error: any) {
    console.error(error)
  }
}

main()
```
