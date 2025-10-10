# workerd-faas

A self-hosted FaaS (Function as a Service) platform based on Cloudflare Workers runtime, enabling you to deploy and manage serverless functions with OIDC-based authentication.

**⚠️ WARNING: This is a prototype project and should NOT be used in production environments.**

## Features

- **Self-hosted Cloudflare Workers**: Deploy Workers-compatible functions on your own infrastructure
- **OIDC Authentication**: Secure access control through OpenID Connect integration
- **Wrangler-compatible CLI**: Use `wrkst` CLI tool for seamless deployment workflow
- **Environment Variables**: Function configuration through environment variables
- **Database Support**:
  - **D1 Database**: Built-in SQLite database support with Cloudflare D1 API compatibility
  - Direct PostgreSQL connections (new connection per request)
  - Recommended: Use D1 for serverless SQLite or Supabase for PostgreSQL

## Deployment

### Method 1: Docker (Recommended)

**Prerequisites:**
- Docker and Docker Compose installed
- Domain with wildcard DNS configured
- OIDC provider configured

**Steps:**

1. **Pull the image**
   ```bash
   docker pull ghcr.io/youxam/workerd-faas:main
   ```

2. **Configure environment variables**

   Copy `.env.example` to `.env` and configure the required variables:
   - `BASE_DOMAIN`: Your base domain for function routing
   - `JWT_SECRET`: Secret key for JWT token signing
   - `USE_FORWARDED_HOST`: Set to `true` to use `X-Forwarded-Host` header for hostname resolution when behind a reverse proxy (default: disabled)
   - OIDC configuration parameters

3. **Configure DNS**

   Set up DNS records or reverse proxy to route the following patterns to your server:
   - `*.<BASE_DOMAIN>` - Required for basic function access
   - `*.*.<BASE_DOMAIN>` - Required only if you need multi-version support

4. **Run the container**
   ```bash
   docker run -d \
     --name workerd-faas \
     -p 8080:8080 \
     --env-file .env \
     -v $(pwd)/data:/app/data \
     ghcr.io/youxam/workerd-faas:main
   ```

   Or use Docker Compose:
   ```yaml
   services:
     workerd-faas:
       image: ghcr.io/youxam/workerd-faas:main
       ports:
         - "8080:8080"
       env_file:
         - .env
       volumes:
         - ./data:/app/data
       restart: unless-stopped
   ```

### Method 2: From Source

**Prerequisites:**
- Node.js and pnpm installed
- [workerd](https://github.com/cloudflare/workerd) installed and available in PATH
- Domain with wildcard DNS configured
- OIDC provider configured

**Steps:**

1. **Install dependencies**
   ```bash
   pnpm install
   ```

2. **Configure environment variables**

   Copy `.env.example` to `.env` and configure the required variables:
   - `BASE_DOMAIN`: Your base domain for function routing
   - `USE_FORWARDED_HOST`: Set to `true` to use `X-Forwarded-Host` header for hostname resolution when behind a reverse proxy (default: disabled)
   - OIDC configuration parameters

3. **Configure DNS**

   Set up DNS records or reverse proxy to route the following patterns to your server:
   - `*.<BASE_DOMAIN>` - Required for basic function access
   - `*.*.<BASE_DOMAIN>` - Required only if you need multi-version support

4. **Adjust port (optional)**

   Edit `config.capnp` to change the listening port if needed.

5. **Build and start**
   ```bash
   pnpm build
   pnpm start
   ```

## Development

### Install CLI Tool

```bash
npm install -g wrkst
```

### Configure CLI

1. **Set target URL**
   ```bash
   wrkst config set-url http(s)://<BASE_DOMAIN>
   ```

2. **Login via OIDC**
   ```bash
   wrkst login
   ```

### Create and Deploy Functions

Follow the [Cloudflare Workers guide](https://developers.cloudflare.com/workers/get-started/guide/) to create, develop, and debug your functions.

### Deploy

```bash
wrkst deploy
```

## Bindings

### Environment Variables

You can configure environment variables for your functions by setting `vars` in your `wrangler.toml` or `wrangler.jsonc`:

```toml
# wrangler.toml
[vars]
API_KEY = "your-api-key"
DATABASE_URL = "your-database-url"
```

Or in `wrangler.jsonc`:

```jsonc
{
  "vars": {
    "API_KEY": "your-api-key",
    "DATABASE_URL": "your-database-url"
  }
}
```

**⚠️ Important:** Do not use `D1` as a variable name. This is a reserved binding name used by the D1 database support and will be overridden.

### D1 Database

This platform provides built-in D1 database support through the `wrkst-d1` runtime library, which is compatible with both this FaaS platform and standard Cloudflare Workers.

#### Installation

```bash
npm install wrkst-d1
# or
pnpm add wrkst-d1
```

#### Usage

The `wrkst-d1` library automatically detects the runtime environment:
- **On this FaaS platform**: Uses the built-in D1 gateway (no binding configuration needed)
- **On Cloudflare Workers/Miniflare**: Uses standard D1 binding

**Example:**

```typescript
import { getD1 } from 'wrkst-d1';

export default {
  async fetch(request: Request, env: any) {
    // Get D1 database instance
    const db = getD1(env);

    // Initialize schema
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
      )
    `);

    // Query the database
    const result = await db.prepare('SELECT * FROM users WHERE id = ?')
      .bind(1)
      .first();

    return new Response(JSON.stringify(result));
  }
}
```

#### Cloudflare Workers / Miniflare Compatibility

When deploying to Cloudflare Workers or testing with Miniflare, configure a D1 binding named `"D1"` in your `wrangler.toml`:

```toml
[[d1_databases]]
binding = "D1"  # Must be named "D1" for wrkst-d1 compatibility
database_name = "my-database"
database_id = "your-database-id"
```

The same code will work on both platforms without modification. The `wrkst-d1` library handles the runtime differences automatically.

## Testing Locally

For local testing without DNS configuration:

1. Set `BASE_DOMAIN=localhost` in your `.env`
2. Start the service
3. Configure CLI:
   ```bash
   wrkst config set-url http://localhost:8080
   ```
4. Deploy your function
5. Test with curl:
   ```bash
   curl http://localhost:8080 -H "Host: test-worker.localhost"
   ```

## Architecture

Functions are routed based on subdomain patterns:
- `<function-name>.<BASE_DOMAIN>` - Access your deployed function
- Each function runs in an isolated Workers runtime environment
- Authentication and authorization managed through OIDC flows

## Technical Details

This platform leverages the **experimental worker-loader** to enable dynamic worker loading, which allows runtime deployment and execution of user-submitted functions without restarting the server. This is the core capability that makes the FaaS functionality possible.

For the platform database, we implement the **D1 API** backed by **SQLite Durable Objects**, with database files persisted in the `data/do` directory. Each deployed function gets its own isolated D1 database instance. The platform uses a D1 Gateway Worker to route database requests: each function is assigned a unique UUID-based hostname (e.g., `<uuid>.d1.worker`), which is stored in the platform database and reused across restarts. Database files are persisted in the `data/do` directory, and the `wrkst-d1` runtime library provides a Cloudflare-compatible D1 API. This architecture allows functions to use D1 databases while maintaining isolation between different functions. The `wrkst-d1` library is also compatible with standard Cloudflare Workers, making it easy to migrate functions between platforms.

The `wrkst` CLI tool is a fork of Wrangler, but with significantly limited functionality. Currently supported bindings are:
- ✅ **Environment Variables** (`vars`)
- ✅ **D1 Databases** (via `wrkst-d1` library)
- ❌ **KV, R2, Durable Objects** - Not currently supported

The platform supports multi-version deployment, allowing you to access specific versions of your functions via the pattern `<version_id_prefix>.<func_name>.<base_domain>`. Note that this requires proper DNS and SSL (if used) configuration for the `*.*.<BASE_DOMAIN>` wildcard pattern. Additionally, while the platform implements function aliases at the API level, there is currently no CLI support for managing them - you'll need to interact with the API directly to create or modify aliases.

## License

[MIT](./LICENSE)
