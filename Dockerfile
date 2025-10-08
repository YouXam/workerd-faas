FROM node:22-slim AS builder

# Install pnpm
RUN npm install -g pnpm

WORKDIR /app

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source files
COPY . .

# Build the project (skip cf-typegen as it requires workerd binary)
RUN npx wrangler build

FROM debian:bookworm-slim

# Install workerd
RUN apt-get update && \
    apt-get install -y curl ca-certificates && \
    ARCH=$(uname -m) && \
    WORKERD_VERSION="v1.20251008.0" && \
    if [ "$ARCH" = "x86_64" ]; then \
        WORKERD_URL="https://github.com/cloudflare/workerd/releases/download/${WORKERD_VERSION}/workerd-linux-64.gz"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        WORKERD_URL="https://github.com/cloudflare/workerd/releases/download/${WORKERD_VERSION}/workerd-linux-arm64.gz"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -L "$WORKERD_URL" -o /tmp/workerd.gz && \
    gunzip /tmp/workerd.gz && \
    mv /tmp/workerd /usr/local/bin/workerd && \
    chmod +x /usr/local/bin/workerd && \
    apt-get remove -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/config.capnp ./config.capnp

# Create data directories
RUN mkdir -p data/do data/files

# Expose default port
EXPOSE 8080

# Environment variables (override with docker run -e or docker-compose)
ENV BASE_DOMAIN=func.local
ENV JWT_SECRET=change-me-in-production
ENV OIDC_ISSUER=
ENV OIDC_AUTHORIZATION_ENDPOINT=
ENV OIDC_TOKEN_ENDPOINT=
ENV OIDC_USERINFO_ENDPOINT=
ENV OIDC_CLIENT_ID=
ENV OIDC_CLIENT_SECRET=
ENV OIDC_REDIRECT_URI=

# Run workerd
CMD ["workerd", "serve", "config.capnp", "--verbose", "--experimental"]
