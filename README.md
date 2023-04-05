
# jwt.js
Secure and reusable JWT validation for Node.


## Install

```sh
npm install @altipla/jwt
```


## Usage

```ts
import { verifyJWT } from '@altipla/jwt'

async function main() {
  try {
    let config = {
      discovery: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: 'https://example.com',
    }
    let token = "..."
    let payload = await verifyJWT(config, token)
  } catch (error: any) {
    console.error(error)
  }
}
main()
```
