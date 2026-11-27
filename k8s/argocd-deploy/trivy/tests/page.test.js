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

// argoUrl: base comes from DATA.argoBase (server ARGOCD_URL env), no link without it
const w = { app: "velero", kind: "Pod", namespace: "velero", name: "restic-abc" };
eq("no argoBase -> no url", sandbox.argoUrl(w), null);
sandbox.DATA.argoBase = "https://argo.test";
eq("argoBase url", sandbox.argoUrl(w),
   "https://argo.test/applications/argocd/velero?view=tree&resource=");
eq("no app -> no url", sandbox.argoUrl({ kind: "Pod", namespace: "n", name: "p" }), null);

process.exit(fails ? 1 : 0);
