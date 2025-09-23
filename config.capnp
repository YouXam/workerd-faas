using Workerd = import "/workerd/workerd.capnp";

const faasPlatform :Workerd.Config = (
  services = [
		(name = "main", worker = .faas),
		(name = "DO_DIR", disk = (writable = true, path = "data/do")),
		(name = "FILES_DIR", disk = (writable = true, path = "data/files")),
	],
  sockets = [ ( name = "http", address = "*:8080", http = (), service = "main" ) ]
);

const faas :Workerd.Worker = (
	modules = [
    (name = "worker", esModule = embed "dist/index.js")
  ],
	durableObjectNamespaces = [
    (className = "D1DatabaseObject", uniqueKey = "D1DatabaseObject", enableSql = true),
  ],
	durableObjectStorage = ( localDisk = "DO_DIR" ),
	bindings = [
    (name = "D1DatabaseObject", durableObjectNamespace = "D1DatabaseObject"),
		(name = "FILES", service = "FILES_DIR"),
		(name = "LOADER", workerLoader = (id = "loader")),
		(name = "BASE_DOMAIN", fromEnvironment = "BASE_DOMAIN")
  ],
  compatibilityDate = "2025-08-28",
  compatibilityFlags = ["nodejs_compat"],
);
