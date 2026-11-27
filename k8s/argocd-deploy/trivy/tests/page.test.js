// Functional stub test for page.js: fuzzy usage and package search,
// namespace state, registryLink and componentLink mapping. No browser -
// minimal DOM stubs only. Run: node k8s/argocd-deploy/trivy/tests/page.test.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const PAGE_JS = process.argv[2] || path.join(__dirname, "..", "scripts", "page.js");

function node() {
  const n = {
    children: [],
    style: {},
    textContent: "",
    className: "",
    value: "",
    hidden: false,
    href: "",
    src: "",
    appendChild(c) { n.children.push(c); n.firstChild = n.children[0]; return c; },
    setAttribute() {},
    getAttribute() { return ""; },
    remove() {},
    addEventListener() {},
    querySelector() { return null; },
    setAttributeNS() {},
  };
  return n;
}

const chain = { then: () => chain, catch: () => chain };
const byId = {};
["q", "ns", "nsx", "nsmenu", "meta", "list", "sbom", "users", "tip"].forEach((id) => {
  byId[id] = node();
});

const sandbox = {
  console,
  setTimeout: () => 0,
  fetch: () => chain,
  document: {
    getElementById: (id) => byId[id],
    createElement: () => node(),
    createElementNS: () => node(),
    createTextNode: (t) => ({ textContent: t }),
    addEventListener: () => {},
    activeElement: null,
  },
  window: { innerWidth: 1200, addEventListener: () => {} },
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(PAGE_JS, "utf8"), sandbox, { filename: "page.js" });

const { registryLink, shown, rowScore, entries, shortenRef } = sandbox;
let fails = 0;
function eq(what, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log("FAIL " + what + ": got " + JSON.stringify(got) + " want " + JSON.stringify(want)); }
  else console.log("ok   " + what);
}

// registryLink mapping
eq("k8s nfd -> repo",
   registryLink("registry.k8s.io/nfd/node-feature-discovery").url,
   "https://github.com/kubernetes-sigs/node-feature-discovery");
eq("k8s kube-apiserver -> k/k",
   registryLink("registry.k8s.io/kube-apiserver").url,
   "https://github.com/kubernetes/kubernetes");
eq("k8s csi-provisioner -> external-provisioner",
   registryLink("registry.k8s.io/sig-storage/csi-provisioner").url,
   "https://github.com/kubernetes-csi/external-provisioner");
eq("k8s unknown path -> no link", registryLink("registry.k8s.io/nope/nope"), null);
eq("dhi python -> catalog",
   registryLink("dhi.io/python").url,
   "https://hub.docker.com/hardened-images/catalog/dhi/python");
eq("hub library form",
   registryLink("docker.io/library/redis").url,
   "https://hub.docker.com/_/redis");
eq("ghcr via pull-through prefix",
   registryLink("mirror.example/ghcr.io/komga/komga").url,
   "https://github.com/komga?tab=packages");
eq("private registry -> no link", registryLink("mirror.example/me/app"), null);

// Badges: known hosts label themselves, unknown ones get the distribution icon
eq("known host badge", shortenRef("docker.io/library/redis").reg.title,
   "Docker Hub (docker.io)");
const unknown = shortenRef("mirror.example/me/app").reg;
eq("unknown host badge icon", unknown.icon, "");
eq("unknown host badge img is distribution", unknown.img, sandbox.DIST_IMG);
eq("unknown host badge title", unknown.title, "mirror.example");

// Usage-aware fuzzy: DATA with two images, one used by monitoring workloads.
sandbox.DATA = {
  workloads: [
    { namespace: "monitoring", kind: "DaemonSet", name: "node-exporter", app: "kube-prometheus",
      containers: [{ container: "node-exporter", ref: "quay.io/prometheus/node-exporter", digest: "sha256:aaa", tag: "v1", file: "f1" }] },
    { namespace: "velero", kind: "Deployment", name: "restic", app: "velero",
      containers: [{ container: "node-agent", ref: "quay.io/velero/velero", digest: "sha256:bbb", tag: "v2", file: "f2" }] },
  ],
  sboms: [],
};
byId.q.value = "";
sandbox.NSEL = "All";
eq("no query shows both", shown().length, 2);
byId.q.value = "prometheus";
let rows = shown().map((e) => e.ref);
eq("usage ns/kind/name match", rows, ["quay.io/prometheus/node-exporter"]);
byId.q.value = "node-agent"; // container name only
rows = shown().map((e) => e.ref);
eq("container-name match", rows, ["quay.io/velero/velero"]);
byId.q.value = "velero"; // app + namespace match
rows = shown().map((e) => e.ref);
eq("app/ns match", rows, ["quay.io/velero/velero"]);
byId.q.value = "zzzzz";
eq("nonsense matches nothing", shown().length, 0);

// Namespace filter via NSEL state
byId.q.value = "";
sandbox.NSEL = "monitoring";
rows = shown().map((e) => e.ref);
eq("ns filter", rows, ["quay.io/prometheus/node-exporter"]);
sandbox.NSEL = "All";

// Ranking: direct ref substring outranks a usage-only match
byId.q.value = "velero";
rows = shown();
eq("single result ranked first", rows.length, 1);
byId.q.value = "quay";
rows = shown();
eq("both match ref, stable by ref", rows.map((e) => e.ref),
   ["quay.io/prometheus/node-exporter", "quay.io/velero/velero"]);

// Package search over the /api/index snapshot ("name version" strings).
sandbox.INDEX = {
  generatedAt: "g",
  files: {
    f1: ["musl 1.2.5-r0", "node-exporter 1.8.1"],
    f2: ["libncursesw 6.6_p20260516-r0", "prometheus client golang 0.60.0"],
  },
};
byId.q.value = "6.6_p20260516-r0";
rows = shown().map((e) => e.ref);
eq("package version match", rows, ["quay.io/velero/velero"]);
byId.q.value = "musl";
// m-u-s-l is a subsequence of "prometheus client golang ..." (letters span
// word boundaries), so fuzzy lists velero too, below the substring hit.
rows = shown().map((e) => e.ref);
eq("package name match ranks substring first", rows,
   ["quay.io/prometheus/node-exporter", "quay.io/velero/velero"]);
byId.q.value = "prometheus";
rows = shown();
eq("ref match outranks package match", rows.map((e) => e.ref),
   ["quay.io/prometheus/node-exporter", "quay.io/velero/velero"]);
eq("package-only score below ref score", rows[1].score < rows[0].score, true);
sandbox.INDEX = null;
byId.q.value = "musl";
eq("no index, no package match", shown().length, 0);

// componentLink per ecosystem (probed formats; suse rpm has no link)
const cl = (p) => sandbox.componentLink({ purl: p });
eq("go github repo", cl("pkg:golang/github.com/beorn7/perks@v1.0.1").url,
   "https://github.com/beorn7/perks");
eq("go github v5 suffix -> repo", cl("pkg:golang/github.com/go-git/go-git/v5@v5.13.0").url,
   "https://github.com/go-git/go-git");
eq("go github subpackage -> repo", cl("pkg:golang/github.com/spf13/cobra/completions@v1.8.0").url,
   "https://github.com/spf13/cobra");
eq("go other -> pkg.go.dev", cl("pkg:golang/golang.org/x/sys@v0.30.0").url,
   "https://pkg.go.dev/golang.org/x/sys");
eq("go stdlib -> null", cl("pkg:golang/stdlib@1.24.0"), null);
eq("npm scoped", cl("pkg:npm/%40vue/shared@3.5.0").url,
   "https://www.npmjs.com/package/@vue/shared");
eq("pypi", cl("pkg:pypi/wheel@0.45.1").url, "https://pypi.org/project/wheel/");
eq("cargo", cl("pkg:cargo/uv-virtualenv@0.0.83").url,
   "https://crates.io/crates/uv-virtualenv");
eq("maven", cl("pkg:maven/ch.qos.logback/logback-classic@1.5.34").url,
   "https://central.sonatype.com/artifact/ch.qos.logback/logback-classic");
eq("gem", cl("pkg:gem/rake@13.2.1").url, "https://rubygems.org/gems/rake");
eq("composer", cl("pkg:composer/twig/twig@3.14.0").url,
   "https://packagist.org/packages/twig/twig");
eq("apk branch from distro",
   cl("pkg:apk/alpine/libncursesw@6.6_p20260516-r0?arch=x86_64&distro=3.24.3").url,
   "https://pkgs.alpinelinux.org/packages?name=libncursesw&branch=v3.24");
eq("deb debian", cl("pkg:deb/debian/adduser@3.134?arch=all&distro=debian-12.13").url,
   "https://packages.debian.org/search?searchon=names&keywords=adduser");
eq("deb ubuntu", cl("pkg:deb/ubuntu/git@1%3A2.48.1-1ubuntu1?arch=amd64&distro=ubuntu-26.04").url,
   "https://packages.ubuntu.com/search?searchon=names&keywords=git");
eq("rpm suse -> no link",
   cl("pkg:rpm/suse/aaa_base@84.87%2Bgit-150300?arch=x86_64&distro=sles-15.7"), null);
eq("no purl -> no link", cl(undefined), null);
eq("bad purl -> no link", cl("not-a-purl"), null);

// Vulnerability snapshot join: server merges the reporter's state.json into
// /api/state as DATA.vulns (list, worst entry per repo:tag).
sandbox.DATA.vulns = [
  { repo: "quay.io/prometheus/node-exporter", tag: "v1", crit: 1, high: 2, med: 3, cves: [
    { id: "CVE-1", pkg: "musl", score: 9.8, severity: "CRITICAL" },
    { id: "CVE-2", pkg: "Musl", score: 8.1, severity: "HIGH" },
    { id: "CVE-3", pkg: "wolfi-baselayout", score: 7.4, severity: "HIGH" },
  ] },
  { repo: "quay.io/velero/velero", tag: "v9", crit: 0, high: 4, med: 1, cves: [] },
  { repo: "quay.io/velero/velero", tag: "v2", crit: 0, high: 1, med: 0, cves: [] },
];
sandbox.VULNS = sandbox.buildVulns();
eq("exact repo+tag hit", sandbox.vulnFor({ ref: "quay.io/prometheus/node-exporter", tag: "v1" }).crit, 1);
// Digest-pinned workloads have no (or stale) tag: fall back to the worst
// entry recorded for the repo (v9 has 4 high, more than v2).
eq("tag miss falls back to worst repo entry",
   sandbox.vulnFor({ ref: "quay.io/velero/velero", tag: "" }).high, 4);
eq("vulnless image -> null", sandbox.vulnFor({ ref: "docker.io/library/redis", tag: "7" }), null);
const npm = sandbox.vulnPkgMap(sandbox.VULNS.img["quay.io/prometheus/node-exporter\nv1"]);
eq("pkg map lowercases and groups", Object.keys(npm).sort(), ["musl", "wolfi-baselayout"]);
eq("pkg map holds cves", npm.musl.map((c) => c.id), ["CVE-1", "CVE-2"]);
eq("pkg map of empty entry", sandbox.vulnPkgMap(null), {});
sandbox.DATA.vulns = null;
sandbox.VULNS = sandbox.buildVulns();
eq("no snapshot -> null", sandbox.vulnFor({ ref: "quay.io/velero/velero", tag: "v2" }), null);

// The reporter state keys repos WITHOUT the registry the workload refs keep
// (operator artifact.repository), and docker.io hides the library namespace.
// Join must normalize both sides or live badges never match.
sandbox.DATA.vulns = [
  { repo: "dexidp/dex", tag: "v2.46.1", crit: 1, high: 0, med: 0, cves: [] },
  { repo: "redis", tag: "8.6.4-alpine", crit: 0, high: 2, med: 0, cves: [] },
  { repo: "quay.io/prometheus/node-exporter", tag: "v1", crit: 0, high: 1, med: 0, cves: [] },
  { repo: "ghcr.io/kieraneglin/pinchflat", tag: "latest", crit: 2, high: 0, med: 0, cves: [] },
];
sandbox.VULNS = sandbox.buildVulns();
// Workload refs can carry the cluster's pull-through prefix in front of the
// origin host, so host stripping repeats.
eq("pull-through prefix hits host-kept repo",
   sandbox.vulnFor({ ref: "registry.rannet.duckdns.org/ghcr.io/kieraneglin/pinchflat", tag: "latest" }).crit, 2);
eq("stripped repo hits qualified ref",
   sandbox.vulnFor({ ref: "ghcr.io/dexidp/dex", tag: "v2.46.1" }).crit, 1);
eq("library alias hits mirror ref",
   sandbox.vulnFor({ ref: "mirror.gcr.io/library/redis", tag: "8.6.4-alpine" }).high, 2);
eq("qualified repo hits bare ref",
   sandbox.vulnFor({ ref: "prometheus/node-exporter", tag: "v1" }).high, 1);
eq("normalized tag miss falls back to worst repo",
   sandbox.vulnFor({ ref: "ghcr.io/dexidp/dex", tag: "zz" }).crit, 1);
eq("normalized miss -> null", sandbox.vulnFor({ ref: "ghcr.io/other/dex", tag: "v1" }), null);

// rowScore covers advisory ids: "cve" lists every image with visible CVEs,
// a full id finds its image, images without vulns stay unmatched.
sandbox.DATA.vulns = [
  { repo: "quay.io/prometheus/node-exporter", tag: "v1", crit: 1, high: 0, med: 0, cves: [
    { id: "CVE-2025-0001", pkg: "musl", score: 9.8, severity: "CRITICAL" },
  ] },
];
sandbox.VULNS = sandbox.buildVulns();
const ve = { ref: "quay.io/prometheus/node-exporter", tag: "v1", file: "", users: [] };
eq("cve query hits vulnerable image", sandbox.rowScore(ve, "cve") > 0, true);
eq("full id hits its image", sandbox.rowScore(ve, "CVE-2025-0001".toLowerCase()) > 0, true);
eq("id misses clean image", sandbox.rowScore({ ref: "x", tag: "", file: "", users: [] }, "cve"), 0);
// cve- and ghsa-prefixed queries target advisories only: trivy-operator
// matched "cve" as a c..v..e subsequence, which is not what was asked for.
eq("cve query ignores ref subsequence",
   sandbox.rowScore({ ref: "mirror.gcr.io/aquasec/trivy-operator", tag: "0.34.0", file: "", users: [] }, "cve"), 0);
eq("cve id query on clean image",
   sandbox.rowScore({ ref: "quay.io/valkey/valkey", tag: "9", file: "", users: [] }, "cve-2025-0001"), 0);
eq("ghsa query is advisory-only", sandbox.vulnQuery("ghsa-4993-7g62-r423"), true);
eq("plain word stays general", sandbox.vulnQuery("redis"), false);
eq("cve inside a phrase stays general", sandbox.vulnQuery("cve scanner"), false);

// cveUrl: trivy report ids are CVE-* or GHSA-*; other id spaces have no
// stable advisory page, so they stay unlinked.
eq("cveUrl CVE", sandbox.cveUrl("CVE-2025-0001"),
   "https://nvd.nist.gov/vuln/detail/CVE-2025-0001");
eq("cveUrl GHSA", sandbox.cveUrl("GHSA-4993-7g62-r423"),
   "https://github.com/advisories/GHSA-4993-7g62-r423");
eq("cveUrl other id", sandbox.cveUrl("RHSA-2025:1234"), null);
eq("cveUrl empty", sandbox.cveUrl(""), null);

// relTime: epoch-ms -> "5m ago" style, with a fixed `now` so the assertions
// are absolute. Now = 2026-01-05T12:00:00Z.
const NOW = Date.parse("2026-01-05T12:00:00Z");
const MIN = 60000, HR = 3600000, DAY = 86400000;
eq("relTime now", sandbox.relTime(NOW - 10000, NOW), "just now");
eq("relTime seconds", sandbox.relTime(NOW - 45000, NOW), "45s ago");
eq("relTime minutes", sandbox.relTime(NOW - 7 * MIN, NOW), "7m ago");
eq("relTime hours", sandbox.relTime(NOW - 3 * HR - 30 * MIN, NOW), "3h ago");
eq("relTime days", sandbox.relTime(NOW - 2 * DAY - 3600000, NOW), "2d ago");
eq("relTime weeks", sandbox.relTime(NOW - 9 * DAY, NOW), "1w ago");
eq("relTime month+ -> date", sandbox.relTime(NOW - 40 * DAY, NOW), "2025-11-26");
eq("relTime future -> just now", sandbox.relTime(NOW + 60000, NOW), "just now");
eq("relTime no ts -> empty", sandbox.relTime(null, NOW), "");

// argoUrl: base comes from DATA.argoBase (server ARGOCD_URL env), no link without it
const w = { app: "velero", kind: "Pod", namespace: "velero", name: "restic-abc" };
eq("no argoBase -> no url", sandbox.argoUrl(w), null);
sandbox.DATA.argoBase = "https://argo.test";
eq("argoBase url", sandbox.argoUrl(w),
   "https://argo.test/applications/argocd/velero?view=tree&resource=");
eq("no app -> no url", sandbox.argoUrl({ kind: "Pod", namespace: "n", name: "p" }), null);

// uniqueComps: trivy writes one component per layer for a binary copied into
// several layers; the table, kind chips and counts work off unique packages.
// Purl qualifiers (e.g. apk distro) mark genuinely distinct packages.
const dupIn = [
  { name: "github.com/c9s/goprocinfo", version: "v1", purl: "pkg:golang/github.com/c9s/goprocinfo@v1", type: "library" },
  { name: "musl", version: "1.2.5-r3", purl: "pkg:apk/alpine/musl@1.2.5-r3?distro=3.24", type: "package" },
  { name: "github.com/c9s/goprocinfo", version: "v1", purl: "pkg:golang/github.com/c9s/goprocinfo@v1", type: "library" },
  { name: "musl", version: "1.2.5-r3", purl: "pkg:apk/alpine/musl@1.2.5-r3?distro=3.22", type: "package" },
  { name: "noPurl", version: "1", type: "file" },
  { name: "noPurl", version: "1", type: "file" },
];
const uniq = sandbox.uniqueComps(dupIn);
eq("layer duplicates collapse", uniq.length, 4);
eq("first occurrence kept", uniq[0], dupIn[0]);
eq("distinct purl qualifiers survive",
   uniq.filter((c) => c.name === "musl").length, 2);
eq("no-purl dupes collapse on name+version+type",
   uniq.filter((c) => c.name === "noPurl").length, 1);
eq("undefined input -> []", sandbox.uniqueComps(undefined).length, 0);
// Same purl with different hashes is different content, not a layer repeat.
eq("same purl different hashes stay separate",
   sandbox.uniqueComps([
     { name: "x", version: "1", purl: "pkg:apk/x@1", hashes: [{ alg: "SHA-256", value: "aa" }] },
     { name: "x", version: "1", purl: "pkg:apk/x@1", hashes: [{ alg: "SHA-256", value: "bb" }] },
     { name: "x", version: "1", purl: "pkg:apk/x@1", hashes: [{ alg: "SHA-256", value: "aa" }] },
   ]).length, 2);

// deriveComps: the cached per-file view showEntry paints (unique comps in
// name order, raw layer counts, name+version ties among uniques).
const dvc = sandbox.deriveComps({ components: dupIn });
eq("deriveComps unique count", dvc.comps.length, 4);
eq("deriveComps sorted by name", dvc.comps.map((c) => c.name),
   ["github.com/c9s/goprocinfo", "musl", "musl", "noPurl"]);
eq("deriveComps layer repeats counted", dvc.layers[sandbox.compKey(dupIn[0])], 2);
eq("deriveComps name+version ties counted", dvc.sameName["musl\n1.2.5-r3"], 2);
eq("deriveComps collapsed dupe is no tie", dvc.sameName["noPurl\n1"], 1);

process.exit(fails ? 1 : 0);
