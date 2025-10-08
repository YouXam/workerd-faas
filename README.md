# workerd-faas

A self-hosted FaaS (Function as a Service) platform based on Cloudflare Workers runtime, enabling you to deploy and manage serverless functions with OIDC-based authentication.

**⚠️ WARNING: This is a prototype project and should NOT be used in production environments.**

## Features

- **Self-hosted Cloudflare Workers**: Deploy Workers-compatible functions on your own infrastructure
- **OIDC Authentication**: Secure access control through OpenID Connect integration
- **Wrangler-compatible CLI**: Use `wrkst` CLI tool for seamless deployment workflow
- **Environment Variables**: Function configuration through environment variables
- **Database Support**:
  - Direct PostgreSQL connections (new connection per request)
  - Recommended: Use serverless database services like Supabase for better performance

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

For the platform database, we implement the **D1 API** backed by **SQLite Durable Objects**, with database files persisted in the `data/do` directory. However, due to worker-loader limitations, D1 databases are **not available** within deployed functions themselves, and in-memory state persistence is also not supported. This means your functions must rely on TCP connections to external databases like PostgreSQL or MySQL, or use serverless storage services such as Supabase for data persistence.

The `wrkst` CLI tool is a fork of Wrangler, but with significantly limited functionality. Currently, only Workers that use `vars` are properly supported. Other Cloudflare bindings like KV, R2, D1, and Durable Objects will not work correctly when deployed through this platform.

The platform supports multi-version deployment, allowing you to access specific versions of your functions via the pattern `<version_id_prefix>.<func_name>.<base_domain>`. Note that this requires proper DNS and SSL (if used) configuration for the `*.*.<BASE_DOMAIN>` wildcard pattern. Additionally, while the platform implements function aliases at the API level, there is currently no CLI support for managing them - you'll need to interact with the API directly to create or modify aliases.

## License

[MIT](./LICENSE)
