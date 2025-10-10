using Workerd = import "/workerd/workerd.capnp";

const faasPlatform :Workerd.Config = (
  services = [
		(name = "main", worker = .faas),
		(name = "d1-gateway", worker = .d1Gateway),
		(name = "DO_DIR", disk = (writable = true, path = "data/do")),
		(name = "FILES_DIR", disk = (writable = true, path = "data/files")),
		(name = "internet", network = (
			allow = ["public", "private", "local"],
			tlsOptions = (trustBrowserCas = true)
		)),
	],
  sockets = [ ( name = "http", address = "*:8080", http = (), service = "main" ) ]
);

const faas :Workerd.Worker = (
	modules = [
		(name = "worker", esModule = embed "dist/main/index.js")
  ],
	durableObjectNamespaces = [
		(className = "D1DatabaseObject", uniqueKey = "FaaS", enableSql = true),
  ],
	durableObjectStorage = ( localDisk = "DO_DIR" ),
	bindings = [
		(name = "D1DatabaseObject", durableObjectNamespace = "D1DatabaseObject"),
		(name = "FILES", service = "FILES_DIR"),
		(name = "LOADER", workerLoader = (id = "loader")),
		(name = "D1_GATEWAY", service = "d1-gateway"),
		(name = "BASE_DOMAIN", fromEnvironment = "BASE_DOMAIN"),
		(name = "JWT_SECRET", fromEnvironment = "JWT_SECRET"),
		(name = "OIDC_ISSUER", fromEnvironment = "OIDC_ISSUER"),
		(name = "OIDC_AUTHORIZATION_ENDPOINT", fromEnvironment = "OIDC_AUTHORIZATION_ENDPOINT"),
		(name = "OIDC_TOKEN_ENDPOINT", fromEnvironment = "OIDC_TOKEN_ENDPOINT"),
		(name = "OIDC_USERINFO_ENDPOINT", fromEnvironment = "OIDC_USERINFO_ENDPOINT"),
		(name = "OIDC_CLIENT_ID", fromEnvironment = "OIDC_CLIENT_ID"),
		(name = "OIDC_CLIENT_SECRET", fromEnvironment = "OIDC_CLIENT_SECRET"),
		(name = "OIDC_REDIRECT_URI", fromEnvironment = "OIDC_REDIRECT_URI"),
		(name = "USE_FORWARDED_HOST", fromEnvironment = "USE_FORWARDED_HOST")
  ],
  compatibilityDate = "2025-08-28",
  compatibilityFlags = ["nodejs_compat"],
);

const d1Gateway :Workerd.Worker = (
	modules = [
		(name = "d1-gateway", esModule = embed "dist/d1-gateway/d1-gateway.js")
	],
  durableObjectNamespaces = [
		(className = "D1DatabaseObject", uniqueKey = "WorkerStorage", enableSql = true),
  ],
	durableObjectStorage = ( localDisk = "DO_DIR" ),
	bindings = [
		(name = "D1DatabaseObject", durableObjectNamespace = "D1DatabaseObject"),
	],
	compatibilityDate = "2025-08-28",
	compatibilityFlags = ["nodejs_compat"],
);
