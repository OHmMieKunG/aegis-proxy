import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(uiRoot, "src");
const forbiddenSymbols = [
  "matchRSCServerRequest",
  "routeRSCServerRequest",
  "throwIfPotentialCSRFAttack",
  "processServerAction",
];

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) return sourceFiles(target);
      return /\.[cm]?[jt]sx?$/.test(entry.name) ? [target] : [];
    }),
  );
  return nested.flat();
}

const routerImports = new Set();
for (const file of await sourceFiles(sourceRoot)) {
  const source = await readFile(file, "utf8");
  const imports = source.matchAll(
    /(?:from\s*|import\s*\(\s*|import\s*)["']([^"']+)["']/g,
  );
  for (const match of imports) {
    if (match[1].startsWith("react-router") || match[1].startsWith("@react-router/")) {
      routerImports.add(match[1]);
    }
  }
}

if ([...routerImports].some((specifier) => specifier !== "react-router-dom")) {
  throw new Error(`forbidden React Router source import: ${[...routerImports].join(", ")}`);
}

let resolvedConfig;
const result = await build({
  root: uiRoot,
  logLevel: "silent",
  build: { write: false },
  plugins: [
    {
      name: "capture-router-reachability-config",
      configResolved(config) {
        resolvedConfig = config;
      },
    },
  ],
});

if (!resolvedConfig || resolvedConfig.build.ssr) {
  throw new Error("the production UI build is not a client-only build");
}
if (resolvedConfig.resolve.conditions.includes("react-server")) {
  throw new Error("the production UI resolves the React server export condition");
}

const outputs = Array.isArray(result)
  ? result.flatMap((entry) => entry.output)
  : result.output;
const chunks = outputs.filter((output) => output.type === "chunk");
const routerModules = new Map();

for (const chunk of chunks) {
  for (const [id, details] of Object.entries(chunk.modules)) {
    if (id.includes("/node_modules/react-router")) {
      routerModules.set(id.split("?")[0], details.renderedExports);
    }
  }
}

if (routerModules.size === 0) {
  throw new Error("production module graph contains no React Router modules");
}

for (const [id] of routerModules) {
  if (/index-react-server|react-server-client|server\.rsc/.test(id)) {
    throw new Error(`React Server Components entry is bundled: ${id}`);
  }
  const source = await readFile(id, "utf8");
  const found = forbiddenSymbols.filter((symbol) => source.includes(symbol));
  if (found.length > 0) {
    throw new Error(`RSC server handler is bundled from ${id}: ${found.join(", ")}`);
  }
}

for (const chunk of chunks) {
  const found = forbiddenSymbols.filter((symbol) => chunk.code.includes(symbol));
  if (found.length > 0) {
    throw new Error(`RSC server handler remains in ${chunk.fileName}: ${found.join(", ")}`);
  }
}

const routerPackage = JSON.parse(
  await readFile(path.join(uiRoot, "node_modules/react-router/package.json"), "utf8"),
);
const relativeModules = [...routerModules].map(([id, renderedExports]) => ({
  id: path.relative(uiRoot, id),
  renderedExports,
}));

console.log(
  JSON.stringify(
    {
      reactRouterVersion: routerPackage.version,
      sourceImports: [...routerImports].sort(),
      build: {
        mode: resolvedConfig.mode,
        ssr: Boolean(resolvedConfig.build.ssr),
        conditions: resolvedConfig.resolve.conditions,
        chunks: chunks.map((chunk) => ({
          fileName: chunk.fileName,
          bytes: Buffer.byteLength(chunk.code),
          dynamicImports: chunk.dynamicImports,
        })),
      },
      routerModules: relativeModules,
      forbiddenServerSymbols: [],
    },
    null,
    2,
  ),
);
