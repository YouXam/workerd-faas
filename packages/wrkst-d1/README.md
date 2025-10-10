# wrkst-d1

D1 database runtime library for Cloudflare Workers and compatible FaaS platforms.

## Installation

```bash
npm install wrkst-d1
# or
pnpm add wrkst-d1
# or
yarn add wrkst-d1
```

## Usage

### In Worker Code

When deploying to a compatible FaaS platform (like workerd-faas), you can use the D1 database in your worker code:

```typescript
import { getD1 } from 'wrkst-d1';

export default {
  async fetch(request: Request, env: any) {
    // Get a D1 database instance
    const db = getD1(env);

    // Query the database
    const result = await db.prepare('SELECT * FROM users WHERE id = ?')
      .bind(1)
      .first();

    return new Response(JSON.stringify(result));
  }
}
```

## License

[MIT](./LICENSE)
