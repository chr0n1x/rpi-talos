var DATA = null;
var INDEX = null;
var VULNS = null;
var SELECTED = "";
var NSEL = "All";
var NS_NAMES = [];

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function fuzzy(text, q) {
  if (!q) return 1;
  text = String(text).toLowerCase();
  var at = text.indexOf(q);
  if (at >= 0) return 1000 - at;
  var i = 0;
  for (var j = 0; j < text.length; j++) {
    if (text[j] === q[i]) { i++; if (i === q.length) return 100; }
  }
  return 0;
}

function meta(file) {
  var out = null;
  (DATA.sboms || []).forEach(function (s) { if (s.file === file) out = s; });
  return out;
}

function entries() {
  var by = {};
  var out = [];
  (DATA.workloads || []).forEach(function (w) {
    (w.containers || []).forEach(function (c) {
      var k = c.ref + "@" + (c.digest || "");
      var e = by[k];
      if (!e) {
        e = { key: k, ref: c.ref, digest: c.digest, tag: c.tag || "", file: c.file, users: [], nss: {} };
        by[k] = e;
        out.push(e);
      } else if (!e.tag && c.tag) {
        e.tag = c.tag;
      }
      if (e.users.indexOf(w) < 0) e.users.push(w);
      e.nss[w.namespace] = 1;
    });
  });
  return out;
}

function usageText(w) {
  // Where an image is used, as one lowercase haystack: the workload's
  // namespace/kind/name, its ArgoCD application, and its container names.
  if (w.ustext === undefined) {
    var names = (w.containers || []).map(function (c) { return c.container; }).join(" ");
    w.ustext = (w.namespace + "/" + w.kind + "/" + w.name + " " +
                (w.app || "") + " " + names).toLowerCase();
  }
  return w.ustext;
}

function packageScore(e, q) {
  // Fuzzy score over the "name version" strings of the image's SBOM, from
  // the /api/index snapshot (one lowercase string per component).
  if (!INDEX || !e.file || !INDEX.files[e.file]) return 0;
  var names = INDEX.files[e.file];
  var s = 0;
  for (var i = 0; i < names.length; i++) {
    var t = fuzzy(names[i], q);
    if (t > s) s = t;
  }
  return s;
}

function vulnScore(e, q) {
  // Fuzzy score over the advisory ids recorded for the image: "cve" lists
  // every image with visible CVEs, a full id finds just its image.
  var v = vulnFor(e);
  if (!v) return 0;
  var s = 0;
  for (var i = 0; i < v.cves.length; i++) {
    var t = fuzzy(v.cves[i].id, q);
    if (t > s) s = t;
  }
  return s;
}

function vulnQuery(q) {
  // A whole query that targets advisories: "cve" or a partial/complete
  // CVE/GHSA id. Phrases merely containing cve stay ordinary fuzzy queries.
  return /^cve(-[\d-]*)?$/.test(q) || /^ghsa(-[a-z0-9-]*)?$/.test(q);
}

function rowScore(e, q) {
  // Best fuzzy score over the image ref and every place the image is used,
  // so a query like a namespace or app name finds all SBOMs it covers.
  // Package names, versions and advisory ids are the fallback: an image that
  // matches on
  // both ranks by its usage, not by a package it happens to ship. The offset
  // keeps that true when the package substring starts earlier than the ref
  // one (package scores top out at 1000, below any offset ref match).
  // cve/ghsa queries match advisory ids only, so a name that happens to
  // contain the letters never shows up under them.
  if (q && vulnQuery(q)) return vulnScore(e, q);
  var s = fuzzy(e.ref, q);
  for (var i = 0; q && i < e.users.length; i++) {
    var t = fuzzy(usageText(e.users[i]), q);
    if (t > s) s = t;
  }
  if (s > 0) return q ? s + 2000 : s;
  var p = packageScore(e, q);
  var c = vulnScore(e, q);
  return p > c ? p : c;
}

function shown() {
  var q = document.getElementById("q").value.trim().toLowerCase();
  var rows = [];
  entries().forEach(function (e) {
    if (NSEL !== "All" && !e.nss[NSEL]) return;
    var s = rowScore(e, q);
    if (s > 0) { e.score = s; rows.push(e); }
  });
  rows.sort(function (a, b) {
    var d = b.score - a.score;
    if (d) return d;
    if (a.ref !== b.ref) return a.ref < b.ref ? -1 : 1;
    return a.digest < b.digest ? -1 : (a.digest > b.digest ? 1 : 0);
  });
  return rows;
}

// Registry logos inlined as single-path 24x24 SVG data from simple-icons
// (CC0-1.0); the cluster is LAN-only, so no icon files or CDNs. redhat
// stands in for quay.io, whose own icon simple-icons no longer ships.
var ICONS = {
  docker: "M20.5 5A2.5 2.5 0 0 0 18 7.5 2.5 2.5 0 0 0 15.5 5H12v2a3 3 0 0 0 3 3h1.5v1.5H15A4.5 4.5 0 0 1 10.5 7V5H4a4 4 0 0 0-4 4v6a4 4 0 0 0 4 4h11a4 4 0 0 0 4-4v-5h2a3 3 0 0 0 3-3V5Z",
  github: "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12",
  kubernetes: "M10.204 14.35l.007.01-.999 2.413a5.171 5.171 0 0 1-2.075-2.597l2.578-.437.004.005a.44.44 0 0 1 .484.606zm-.833-2.129a.44.44 0 0 0 .173-.756l.002-.011L7.585 9.7a5.143 5.143 0 0 0-.73 3.255l2.514-.725.002-.009zm1.145-1.98a.44.44 0 0 0 .699-.337l.01-.005.15-2.62a5.144 5.144 0 0 0-3.01 1.442l2.147 1.523.004-.002zm.76 2.75l.723.349.722-.347.18-.78-.5-.623h-.804l-.5.623.179.779zm1.5-3.095a.44.44 0 0 0 .7.336l.008.003 2.134-1.513a5.188 5.188 0 0 0-2.992-1.442l.148 2.615.002.001zm10.876 5.97l-5.773 7.181a1.6 1.6 0 0 1-1.248.594l-9.261.003a1.6 1.6 0 0 1-1.247-.596l-5.776-7.18a1.583 1.583 0 0 1-.307-1.34L2.1 5.573c.108-.47.425-.864.863-1.073L11.305.513a1.606 1.606 0 0 1 1.385 0l8.345 3.985c.438.209.755.604.863 1.073l2.062 8.955c.108.47-.005.963-.308 1.34zm-3.289-2.057c-.042-.01-.103-.026-.145-.034-.174-.033-.315-.025-.479-.038-.35-.037-.638-.067-.895-.148-.105-.04-.18-.165-.216-.216l-.201-.059a6.45 6.45 0 0 0-.105-2.332 6.465 6.465 0 0 0-.936-2.163c.052-.047.15-.133.177-.159.008-.09.001-.183.094-.282.197-.185.444-.338.743-.522.142-.084.273-.137.415-.242.032-.024.076-.062.11-.089.24-.191.295-.52.123-.736-.172-.216-.506-.236-.745-.045-.034.027-.08.062-.111.088-.134.116-.217.23-.33.35-.246.25-.45.458-.673.609-.097.056-.239.037-.303.033l-.19.135a6.545 6.545 0 0 0-4.146-2.003l-.012-.223c-.065-.062-.143-.115-.163-.25-.022-.268.015-.557.057-.905.023-.163.061-.298.068-.475.001-.04-.001-.099-.001-.142 0-.306-.224-.555-.5-.555-.275 0-.499.249-.499.555l.001.014c0 .041-.002.092 0 .128.006.177.044.312.067.475.042.348.078.637.056.906a.545.545 0 0 1-.162.258l-.012.211a6.424 6.424 0 0 0-4.166 2.003 8.373 8.373 0 0 1-.18-.128c-.09.012-.18.04-.297-.029-.223-.15-.427-.358-.673-.608-.113-.12-.195-.234-.329-.349-.03-.026-.077-.062-.111-.088a.594.594 0 0 0-.348-.132.481.481 0 0 0-.398.176c-.172.216-.117.546.123.737l.007.005.104.083c.142.105.272.159.414.242.299.185.546.338.743.522.076.082.09.226.1.288l.16.143a6.462 6.462 0 0 0-1.02 4.506l-.208.06c-.055.072-.133.184-.215.217-.257.081-.546.11-.895.147-.164.014-.305.006-.48.039-.037.007-.09.02-.133.03l-.004.002-.007.002c-.295.071-.484.342-.423.608.061.267.349.429.645.365l.007-.001.01-.003.129-.029c.17-.046.294-.113.448-.172.33-.118.604-.217.87-.256.112-.009.23.069.288.101l.217-.037a6.5 6.5 0 0 0 2.88 3.596l-.09.218c.033.084.069.199.044.282-.097.252-.263.517-.452.813-.091.136-.185.242-.268.399-.02.037-.045.095-.064.134-.128.275-.034.591.213.71.248.12.556-.007.69-.282v-.002c.02-.039.046-.09.062-.127.07-.162.094-.301.144-.458.132-.332.205-.68.387-.897.05-.06.13-.082.215-.105l.113-.205a6.453 6.453 0 0 0 4.609.012l.106.192c.086.028.18.042.256.155.136.232.229.507.342.84.05.156.074.295.145.457.016.037.043.09.062.129.133.276.442.402.69.282.247-.118.341-.435.213-.71-.02-.039-.045-.096-.065-.134-.083-.156-.177-.261-.268-.398-.19-.296-.346-.541-.443-.793-.04-.13.007-.21.038-.294-.018-.022-.059-.144-.083-.202a6.499 6.499 0 0 0 2.88-3.622c.064.01.176.03.213.038.075-.05.144-.114.28-.104.266.039.54.138.87.256.154.06.277.128.448.173.036.01.088.019.13.028l.009.003.007.001c.297.064.584-.098.645-.365.06-.266-.128-.537-.423-.608zM16.4 9.701l-1.95 1.746v.005a.44.44 0 0 0 .173.757l.003.01 2.526.728a5.199 5.199 0 0 0-.108-1.674A5.208 5.208 0 0 0 16.4 9.7zm-4.013 5.325a.437.437 0 0 0-.404-.232.44.44 0 0 0-.372.233h-.002l-1.268 2.292a5.164 5.164 0 0 0 3.326.003l-1.27-2.296h-.01zm1.888-1.293a.44.44 0 0 0-.27.036.44.44 0 0 0-.214.572l-.003.004 1.01 2.438a5.15 5.15 0 0 0 2.081-2.615l-2.6-.44-.004.005z",
  gcloud: "M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z",
  redhat: "M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733 0-.947.946-1.822.946-.842 0-1.467-.706-2.255-.706-.757 0-1.25.515-1.63 1.576 0 0-1.06 2.99-1.197 3.424a.81.81 0 0 0-.028.245c0 1.162 4.577 4.974 10.71 4.974m4.101-1.435c.218 1.032.218 1.14.218 1.277 0 1.765-1.984 2.745-4.593 2.745-5.895.004-11.06-3.451-11.06-5.734a2.326 2.326 0 0 1 .19-.925C2.746 9.415 0 9.794 0 12.217c0 3.969 9.405 8.861 16.851 8.861 5.71 0 7.149-2.582 7.149-4.62 0-1.605-1.387-3.425-3.887-4.512",
  aws: "M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z"
};

// distribution project's GitHub avatar (PNG data URL), the badge for any
// registry without a dedicated icon - the private one is distribution too.
var DIST_IMG = "data:image/png;base64,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";

var REGS = {
  "docker.io": { icon: "docker", label: "Docker Hub" },
  "ghcr.io": { icon: "github", label: "GitHub" },
  "quay.io": { icon: "redhat", label: "Quay" },
  "gcr.io": { icon: "gcloud", label: "Google Container Registry" },
  "mirror.gcr.io": { icon: "gcloud", label: "Google Container Registry mirror" },
  "registry.k8s.io": { icon: "kubernetes", label: "Kubernetes" },
  "dhi.io": { icon: "docker", label: "Docker Hardened Images" },
  "ecr-public.aws.com": { icon: "aws", label: "ECR Public" }
};

function shortenRef(ref) {
  // Rows swap the registry host for its logo so repo paths line up;
  // "reg.example:5000/foo" counts as a host, "org/image" does not.
  // Hosts without a known icon (the private registry, one-off mirrors)
  // get the distribution icon.
  var slash = ref.indexOf("/");
  if (slash < 0) return { reg: null, rest: ref };
  var host = ref.slice(0, slash);
  if (host.indexOf(".") < 0 && host.indexOf(":") < 0) return { reg: null, rest: ref };
  var r = REGS[host];
  var reg = r ? { icon: r.img ? "" : ICONS[r.icon], img: r.img ? DIST_IMG : "",
                  title: r.label + " (" + host + ")" }
                : { icon: "", img: DIST_IMG, title: host };
  return { reg: reg, rest: ref.slice(slash + 1) };
}

function svgIcon(pathData) {
  var SVG = "http://www.w3.org/2000/svg";
  var svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "15");
  svg.setAttribute("height", "15");
  svg.setAttribute("fill", "currentColor");
  var path = document.createElementNS(SVG, "path");
  path.setAttribute("d", pathData);
  svg.appendChild(path);
  return svg;
}

function svgLine(paths) {
  var SVG = "http://www.w3.org/2000/svg";
  var svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "13");
  svg.setAttribute("height", "13");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  paths.forEach(function (d) {
    svg.appendChild(document.createElementNS(SVG, "path")).setAttribute("d", d);
  });
  return svg;
}

var GLYPH_COPY = [
  "M8 10a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2z",
  "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"
];
var GLYPH_CHECK = ["M20 6 9 17l-5-5"];
var GLYPH_X = ["M18 6 6 18", "M6 6l12 12"];
var GLYPH_EXT = [
  "M15 3h6v6",
  "M10 14 21 3",
  "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"
];
var GLYPH_WARN = [
  "M10.29 3 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3a2 2 0 0 0-3.42 0Z",
  "M12 9v4",
  "M12 17h.01"
];
var GLYPH_RELOAD = ["M23 4v6h-6", "M20.49 15a9 9 0 1 1-2.12-9.36L23 10"];

// Ecosystem brand marks from simple-icons (single path each, CC0 licensed).
var KIND_ICONS = {
  go: "M1.811 10.231c-.047 0-.058-.023-.035-.059l.246-.315c.023-.035.081-.058.128-.058h4.172c.046 0 .058.035.035.07l-.199.303c-.023.036-.082.07-.117.07zM.047 11.306c-.047 0-.059-.023-.035-.058l.245-.316c.023-.035.082-.058.129-.058h5.328c.047 0 .07.035.058.07l-.093.28c-.012.047-.058.07-.105.07zm2.828 1.075c-.047 0-.059-.035-.035-.07l.163-.292c.023-.035.07-.07.117-.07h2.337c.047 0 .07.035.07.082l-.023.28c0 .047-.047.082-.082.082zm12.129-2.36c-.736.187-1.239.327-1.963.514-.176.046-.187.058-.34-.117-.174-.199-.303-.327-.548-.444-.737-.362-1.45-.257-2.115.175-.795.514-1.204 1.274-1.192 2.22.011.935.654 1.706 1.577 1.835.795.105 1.46-.175 1.987-.77.105-.13.198-.27.315-.434H10.47c-.245 0-.304-.152-.222-.35.152-.362.432-.97.596-1.274a.315.315 0 01.292-.187h4.253c-.023.316-.023.631-.07.947a4.983 4.983 0 01-.958 2.29c-.841 1.11-1.94 1.8-3.33 1.986-1.145.152-2.209-.07-3.143-.77-.865-.655-1.356-1.52-1.484-2.595-.152-1.274.222-2.419.993-3.424.83-1.086 1.928-1.776 3.272-2.02 1.098-.2 2.15-.07 3.096.571.62.41 1.063.97 1.356 1.648.07.105.023.164-.117.2m3.868 6.461c-1.064-.024-2.034-.328-2.852-1.029a3.665 3.665 0 01-1.262-2.255c-.21-1.32.152-2.489.947-3.529.853-1.122 1.881-1.706 3.272-1.95 1.192-.21 2.314-.095 3.33.595.923.63 1.496 1.484 1.648 2.605.198 1.578-.257 2.863-1.344 3.962-.771.783-1.718 1.273-2.805 1.495-.315.06-.63.07-.934.106zm2.78-4.72c-.011-.153-.011-.27-.034-.387-.21-1.157-1.274-1.81-2.384-1.554-1.087.245-1.788.935-2.045 2.033-.21.912.234 1.835 1.075 2.21.643.28 1.285.244 1.905-.07.923-.48 1.425-1.228 1.484-2.233z",
  rust: "M23.8346 11.7033l-1.0073-.6236a13.7268 13.7268 0 00-.0283-.2936l.8656-.8069a.3483.3483 0 00-.1154-.578l-1.1066-.414a8.4958 8.4958 0 00-.087-.2856l.6904-.9587a.3462.3462 0 00-.2257-.5446l-1.1663-.1894a9.3574 9.3574 0 00-.1407-.2622l.49-1.0761a.3437.3437 0 00-.0274-.3361.3486.3486 0 00-.3006-.154l-1.1845.0416a6.7444 6.7444 0 00-.1873-.2268l.2723-1.153a.3472.3472 0 00-.417-.4172l-1.1532.2724a14.0183 14.0183 0 00-.2278-.1873l.0415-1.1845a.3442.3442 0 00-.49-.328l-1.076.491c-.0872-.0476-.1742-.0952-.2623-.1407l-.1903-1.1673A.3483.3483 0 0016.256.955l-.9597.6905a8.4867 8.4867 0 00-.2855-.086l-.414-1.1066a.3483.3483 0 00-.5781-.1154l-.8069.8666a9.2936 9.2936 0 00-.2936-.0284L12.2946.1683a.3462.3462 0 00-.5892 0l-.6236 1.0073a13.7383 13.7383 0 00-.2936.0284L9.9803.3374a.3462.3462 0 00-.578.1154l-.4141 1.1065c-.0962.0274-.1903.0567-.2855.086L7.744.955a.3483.3483 0 00-.5447.2258L7.009 2.348a9.3574 9.3574 0 00-.2622.1407l-1.0762-.491a.3462.3462 0 00-.49.328l.0416 1.1845a7.9826 7.9826 0 00-.2278.1873L3.8413 3.425a.3472.3472 0 00-.4171.4171l.2713 1.1531c-.0628.075-.1255.1509-.1863.2268l-1.1845-.0415a.3462.3462 0 00-.328.49l.491 1.0761a9.167 9.167 0 00-.1407.2622l-1.1662.1894a.3483.3483 0 00-.2258.5446l.6904.9587a13.303 13.303 0 00-.087.2855l-1.1065.414a.3483.3483 0 00-.1155.5781l.8656.807a9.2936 9.2936 0 00-.0283.2935l-1.0073.6236a.3442.3442 0 000 .5892l1.0073.6236c.008.0982.0182.1964.0283.2936l-.8656.8079a.3462.3462 0 00.1155.578l1.1065.4141c.0273.0962.0567.1914.087.2855l-.6904.9587a.3452.3452 0 00.2268.5447l1.1662.1893c.0456.088.0922.1751.1408.2622l-.491 1.0762a.3462.3462 0 00.328.49l1.1834-.0415c.0618.0769.1235.1528.1873.2277l-.2713 1.1541a.3462.3462 0 00.4171.4161l1.153-.2713c.075.0638.151.1255.2279.1863l-.0415 1.1845a.3442.3442 0 00.49.327l1.0761-.49c.087.0486.1741.0951.2622.1407l.1903 1.1662a.3483.3483 0 00.5447.2268l.9587-.6904a9.299 9.299 0 00.2855.087l.414 1.1066a.3452.3452 0 00.5781.1154l.8079-.8656c.0972.0111.1954.0203.2936.0294l.6236 1.0073a.3472.3472 0 00.5892 0l.6236-1.0073c.0982-.0091.1964-.0183.2936-.0294l.8069.8656a.3483.3483 0 00.578-.1154l.4141-1.1066a8.4626 8.4626 0 00.2855-.087l.9587.6904a.3452.3452 0 00.5447-.2268l.1903-1.1662c.088-.0456.1751-.0931.2622-.1407l1.0762.49a.3472.3472 0 00.49-.327l-.0415-1.1845a6.7267 6.7267 0 00.2267-.1863l1.1531.2713a.3472.3472 0 00.4171-.416l-.2713-1.1542c.0628-.0749.1255-.1508.1863-.2278l1.1845.0415a.3442.3442 0 00.328-.49l-.49-1.076c.0475-.0872.0951-.1742.1407-.2623l1.1662-.1893a.3483.3483 0 00.2258-.5447l-.6904-.9587.087-.2855 1.1066-.414a.3462.3462 0 00.1154-.5781l-.8656-.8079c.0101-.0972.0202-.1954.0283-.2936l1.0073-.6236a.3442.3442 0 000-.5892zm-6.7413 8.3551a.7138.7138 0 01.2986-1.396.714.714 0 11-.2997 1.396zm-.3422-2.3142a.649.649 0 00-.7715.5l-.3573 1.6685c-1.1035.501-2.3285.7795-3.6193.7795a8.7368 8.7368 0 01-3.6951-.814l-.3574-1.6684a.648.648 0 00-.7714-.499l-1.473.3158a8.7216 8.7216 0 01-.7613-.898h7.1676c.081 0 .1356-.0141.1356-.088v-2.536c0-.074-.0536-.0881-.1356-.0881h-2.0966v-1.6077h2.2677c.2065 0 1.1065.0587 1.394 1.2088.0901.3533.2875 1.5044.4232 1.8729.1346.413.6833 1.2381 1.2685 1.2381h3.5716a.7492.7492 0 00.1296-.0131 8.7874 8.7874 0 01-.8119.9526zM6.8369 20.024a.714.714 0 11-.2997-1.396.714.714 0 01.2997 1.396zM4.1177 8.9972a.7137.7137 0 11-1.304.5791.7137.7137 0 011.304-.579zm-.8352 1.9813l1.5347-.6824a.65.65 0 00.33-.8585l-.3158-.7147h1.2432v5.6025H3.5669a8.7753 8.7753 0 01-.2834-3.348zm6.7343-.5437V8.7836h2.9601c.153 0 1.0792.1772 1.0792.8697 0 .575-.7107.7815-1.2948.7815zm10.7574 1.4862c0 .2187-.008.4363-.0243.651h-.9c-.09 0-.1265.0586-.1265.1477v.413c0 .973-.5487 1.1846-1.0296 1.2382-.4576.0517-.9648-.1913-1.0275-.4717-.2704-1.5186-.7198-1.8436-1.4305-2.4034.8817-.5599 1.799-1.386 1.799-2.4915 0-1.1936-.819-1.9458-1.3769-2.3153-.7825-.5163-1.6491-.6195-1.883-.6195H5.4682a8.7651 8.7651 0 014.907-2.7699l1.0974 1.151a.648.648 0 00.9182.0213l1.227-1.1743a8.7753 8.7753 0 016.0044 4.2762l-.8403 1.8982a.652.652 0 00.33.8585l1.6178.7188c.0283.2875.0425.577.0425.8717zm-9.3006-9.5993a.7128.7128 0 11.984 1.0316.7137.7137 0 01-.984-1.0316zm8.3389 6.71a.7107.7107 0 01.9395-.3625.7137.7137 0 11-.9405.3635z",
  python: "M11.858 0c-.978.005-1.913.088-2.736.234C6.7.662 6.26 1.558 6.26 3.21v2.182h5.725v.727H4.111c-1.664 0-3.121 1-3.577 2.903-.526 2.181-.549 3.542 0 5.82.407 1.694 1.379 2.902 3.043 2.902h1.969v-2.616c0-1.89 1.635-3.557 3.576-3.557h5.72c1.591 0 2.862-1.31 2.862-2.91v-5.45c0-1.553-1.309-2.718-2.863-2.977A18 18 0 0 0 11.858 0M8.762 1.755c.591 0 1.074.491 1.074 1.095 0 .601-.483 1.087-1.074 1.087A1.08 1.08 0 0 1 7.688 2.85c0-.604.48-1.095 1.074-1.095m9.656 4.364v2.543c0 1.971-1.671 3.63-3.577 3.63H9.122c-1.566 0-2.862 1.34-2.862 2.91v5.452c0 1.551 1.349 2.464 2.862 2.91 1.813.532 3.55.628 5.72 0 1.44-.418 2.862-1.258 2.862-2.91V18.47h-5.719v-.727h8.582c1.664 0 2.284-1.16 2.862-2.903.598-1.793.573-3.518 0-5.819-.41-1.656-1.196-2.903-2.862-2.903zm-3.216 13.807a1.08 1.08 0 0 1 1.074 1.088c0 .604-.48 1.094-1.074 1.094-.592 0-1.075-.49-1.075-1.094 0-.601.483-1.088 1.075-1.088",
  java: "M11.915 0 11.7.215C9.515 2.4 7.47 6.39 6.046 10.483c-1.064 1.024-3.633 2.81-3.711 3.551-.093.87 1.746 2.611 1.55 3.235-.198.625-1.304 1.408-1.014 1.939.1.188.823.011 1.277-.491a13.389 13.389 0 0 0-.017 2.14c.076.906.27 1.668.643 2.232.372.563.956.911 1.667.911.397 0 .727-.114 1.024-.264.298-.149.571-.33.91-.5.68-.34 1.634-.666 3.53-.604 1.903.062 2.872.39 3.559.704.687.314 1.15.664 1.925.664.767 0 1.395-.336 1.807-.9.412-.563.631-1.33.72-2.24.06-.623.055-1.32 0-2.066.454.45 1.117.604 1.213.424.29-.53-.816-1.314-1.013-1.937-.198-.624 1.642-2.366 1.549-3.236-.08-.748-2.707-2.568-3.748-3.586C16.428 6.374 14.308 2.394 12.13.215zm.175 6.038a2.95 2.95 0 0 1 2.943 2.942 2.95 2.95 0 0 1-2.943 2.943A2.95 2.95 0 0 1 9.148 8.98a2.95 2.95 0 0 1 2.942-2.942zM8.685 7.983a3.515 3.515 0 0 0-.145.997c0 1.951 1.6 3.55 3.55 3.55 1.95 0 3.55-1.598 3.55-3.55 0-.329-.046-.648-.132-.951.334.095.64.208.915.336a42.699 42.699 0 0 1 2.042 5.829c.678 2.545 1.01 4.92.846 6.607-.082.844-.29 1.51-.606 1.94-.315.431-.713.651-1.315.651-.593 0-.932-.27-1.673-.61-.741-.338-1.825-.694-3.792-.758-1.974-.064-3.073.293-3.821.669-.375.188-.659.373-.911.5s-.466.2-.752.2c-.53 0-.876-.209-1.16-.64-.285-.43-.474-1.101-.545-1.948-.141-1.693.176-4.069.823-6.614a43.155 43.155 0 0 1 1.934-5.783c.348-.167.749-.31 1.192-.425zm-3.382 4.362a.216.216 0 0 1 .13.031c-.166.56-.323 1.116-.463 1.665a33.849 33.849 0 0 0-.547 2.555 3.9 3.9 0 0 0-.2-.39c-.58-1.012-.914-1.642-1.16-2.08.315-.24 1.679-1.755 2.24-1.781zm13.394.01c.562.027 1.926 1.543 2.24 1.783-.246.438-.58 1.068-1.16 2.08a4.428 4.428 0 0 0-.163.309 32.354 32.354 0 0 0-.562-2.49 40.579 40.579 0 0 0-.482-1.652.216.216 0 0 1 .127-.03z",
  deb: "M13.88 12.685c-.4 0 .08.2.601.28.14-.1.27-.22.39-.33a3.001 3.001 0 01-.99.05m2.14-.53c.23-.33.4-.69.47-1.06-.06.27-.2.5-.33.73-.75.47-.07-.27 0-.56-.8 1.01-.11.6-.14.89m.781-2.05c.05-.721-.14-.501-.2-.221.07.04.13.5.2.22M12.38.31c.2.04.45.07.42.12.23-.05.28-.1-.43-.12m.43.12l-.15.03.14-.01V.43m6.633 9.944c.02.64-.2.95-.38 1.5l-.35.181c-.28.54.03.35-.17.78-.44.39-1.34 1.22-1.62 1.301-.201 0 .14-.25.19-.34-.591.4-.481.6-1.371.85l-.03-.06c-2.221 1.04-5.303-1.02-5.253-3.842-.03.17-.07.13-.12.2a3.551 3.552 0 012.001-3.501 3.361 3.362 0 013.732.48 3.341 3.342 0 00-2.721-1.3c-1.18.01-2.281.76-2.651 1.57-.6.38-.67 1.47-.93 1.661-.361 2.601.66 3.722 2.38 5.042.27.19.08.21.12.35a4.702 4.702 0 01-1.53-1.16c.23.33.47.66.8.91-.55-.18-1.27-1.3-1.48-1.35.93 1.66 3.78 2.921 5.261 2.3a6.203 6.203 0 01-2.33-.28c-.33-.16-.77-.51-.7-.57a5.802 5.803 0 005.902-.84c.44-.35.93-.94 1.07-.95-.2.32.04.16-.12.44.44-.72-.2-.3.46-1.24l.24.33c-.09-.6.74-1.321.66-2.262.19-.3.2.3 0 .97.29-.74.08-.85.15-1.46.08.2.18.42.23.63-.18-.7.2-1.2.28-1.6-.09-.05-.28.3-.32-.53 0-.37.1-.2.14-.28-.08-.05-.26-.32-.38-.861.08-.13.22.33.34.34-.08-.42-.2-.75-.2-1.08-.34-.68-.12.1-.4-.3-.34-1.091.3-.25.34-.74.54.77.84 1.96.981 2.46-.1-.6-.28-1.2-.49-1.76.16.07-.26-1.241.21-.37A7.823 7.824 0 0017.702 1.6c.18.17.42.39.33.42-.75-.45-.62-.48-.73-.67-.61-.25-.65.02-1.06 0C15.082.73 14.862.8 13.8.4l.05.23c-.77-.25-.9.1-1.73 0-.05-.04.27-.14.53-.18-.741.1-.701-.14-1.431.03.17-.13.36-.21.55-.32-.6.04-1.44.35-1.18.07C9.6.68 7.847 1.3 6.867 2.22L6.838 2c-.45.54-1.96 1.611-2.08 2.311l-.131.03c-.23.4-.38.85-.57 1.261-.3.52-.45.2-.4.28-.6 1.22-.9 2.251-1.16 3.102.18.27 0 1.65.07 2.76-.3 5.463 3.84 10.776 8.363 12.006.67.23 1.65.23 2.49.25-.99-.28-1.12-.15-2.08-.49-.7-.32-.85-.7-1.34-1.13l.2.35c-.971-.34-.57-.42-1.361-.67l.21-.27c-.31-.03-.83-.53-.97-.81l-.34.01c-.41-.501-.63-.871-.61-1.161l-.111.2c-.13-.21-1.52-1.901-.8-1.511-.13-.12-.31-.2-.5-.55l.14-.17c-.35-.44-.64-1.02-.62-1.2.2.24.32.3.45.33-.88-2.172-.93-.12-1.601-2.202l.15-.02c-.1-.16-.18-.34-.26-.51l.06-.6c-.63-.74-.18-3.102-.09-4.402.07-.54.53-1.1.88-1.981l-.21-.04c.4-.71 2.341-2.872 3.241-2.761.43-.55-.09 0-.18-.14.96-.991 1.26-.7 1.901-.88.7-.401-.6.16-.27-.151 1.2-.3.85-.7 2.421-.85.16.1-.39.14-.52.26 1-.49 3.151-.37 4.562.27 1.63.77 3.461 3.011 3.531 5.132l.08.02c-.04.85.13 1.821-.17 2.711l.2-.42M9.54 13.236l-.05.28c.26.35.47.73.8 1.01-.24-.47-.42-.66-.75-1.3m.62-.02c-.14-.15-.22-.34-.31-.52.08.32.26.6.43.88l-.12-.36m10.945-2.382l-.07.15c-.1.76-.34 1.511-.69 2.212.4-.73.65-1.541.75-2.362M12.45.12c.27-.1.66-.05.95-.12-.37.03-.74.05-1.1.1l.15.02M3.006 5.142c.07.57-.43.8.11.42.3-.66-.11-.18-.1-.42m-.64 2.661c.12-.39.15-.62.2-.84-.35.44-.17.53-.2.83",
  apk: "M5.998 1.607L0 12l5.998 10.393h12.004L24 12 18.002 1.607H5.998zM9.965 7.12L12.66 9.9l1.598 1.595.002-.002 2.41 2.363c-.2.14-.386.252-.563.344a3.756 3.756 0 01-.496.217 2.702 2.702 0 01-.425.111c-.131.023-.25.034-.358.034-.13 0-.242-.014-.338-.034a1.317 1.317 0 01-.24-.072.95.95 0 01-.2-.113l-1.062-1.092-3.039-3.041-1.1 1.053-3.07 3.072a.974.974 0 01-.2.111 1.274 1.274 0 01-.237.073c-.096.02-.209.033-.338.033-.108 0-.227-.009-.358-.031a2.7 2.7 0 01-.425-.114 3.748 3.748 0 01-.496-.217 5.228 5.228 0 01-.563-.343l6.803-6.727zm4.72.785l4.579 4.598 1.382 1.353a5.24 5.24 0 01-.564.344 3.73 3.73 0 01-.494.217 2.697 2.697 0 01-.426.111c-.13.023-.251.034-.36.034-.129 0-.241-.014-.337-.034a1.285 1.285 0 01-.385-.146c-.033-.02-.05-.036-.053-.04l-1.232-1.218-2.111-2.111-.334.334L12.79 9.8l1.896-1.897zm-5.966 4.12v2.529a2.128 2.128 0 01-.356-.035 2.765 2.765 0 01-.422-.116 3.708 3.708 0 01-.488-.214 5.217 5.217 0 01-.555-.34l1.82-1.825Z",
  rpm: "M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733 0-.947.946-1.822.946-.842 0-1.467-.706-2.255-.706-.757 0-1.25.515-1.63 1.576 0 0-1.06 2.99-1.197 3.424a.81.81 0 0 0-.028.245c0 1.162 4.577 4.974 10.71 4.974m4.101-1.435c.218 1.032.218 1.14.218 1.277 0 1.765-1.984 2.745-4.593 2.745-5.895.004-11.06-3.451-11.06-5.734a2.326 2.326 0 0 1 .19-.925C2.746 9.415 0 9.794 0 12.217c0 3.969 9.405 8.861 16.851 8.861 5.71 0 7.149-2.582 7.149-4.62 0-1.605-1.387-3.425-3.887-4.512",
  npm: "M1.763 0C.786 0 0 .786 0 1.763v20.474C0 23.214.786 24 1.763 24h20.474c.977 0 1.763-.786 1.763-1.763V1.763C24 .786 23.214 0 22.237 0zM5.13 5.323l13.837.019-.009 13.836h-3.464l.01-10.382h-3.456L12.04 19.17H5.113z",
  gem: "M7.81 7.9l-2.97 2.95 7.19 7.18 2.96-2.95 4.22-4.23-2.96-2.96v-.01H7.8zM12 0L1.53 6v12L12 24l10.47-6V6L12 0zm8.47 16.85L12 21.73l-8.47-4.88V7.12L12 2.24l8.47 4.88v9.73z",
  php: "M7.01 10.207h-.944l-.515 2.648h.838c.556 0 .97-.105 1.242-.314.272-.21.455-.559.55-1.049.092-.47.05-.802-.124-.995-.175-.193-.523-.29-1.047-.29zM12 5.688C5.373 5.688 0 8.514 0 12s5.373 6.313 12 6.313S24 15.486 24 12c0-3.486-5.373-6.312-12-6.312zm-3.26 7.451c-.261.25-.575.438-.917.551-.336.108-.765.164-1.285.164H5.357l-.327 1.681H3.652l1.23-6.326h2.65c.797 0 1.378.209 1.744.628.366.418.476 1.002.33 1.752a2.836 2.836 0 0 1-.305.847c-.143.255-.33.49-.561.703zm4.024.715l.543-2.799c.063-.318.039-.536-.068-.651-.107-.116-.336-.174-.687-.174H11.46l-.704 3.625H9.388l1.23-6.327h1.367l-.327 1.682h1.218c.767 0 1.295.134 1.586.401s.378.7.263 1.299l-.572 2.944h-1.389zm7.597-2.265a2.782 2.782 0 0 1-.305.847c-.143.255-.33.49-.561.703a2.44 2.44 0 0 1-.917.551c-.336.108-.765.164-1.286.164h-1.18l-.327 1.682h-1.378l1.23-6.326h2.649c.797 0 1.378.209 1.744.628.366.417.477 1.001.331 1.751zM17.766 10.207h-.943l-.516 2.648h.838c.557 0 .971-.105 1.242-.314.272-.21.455-.559.551-1.049.092-.47.049-.802-.125-.995s-.524-.29-1.047-.29z",
};

var GLYPH_PACKAGE = [
  "M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z",
  "m3.3 7 8.7 5 8.7-5",
  "M12 22V12"
];

function svgFill(d) {
  var SVG = "http://www.w3.org/2000/svg";
  var svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "13");
  svg.setAttribute("height", "13");
  svg.setAttribute("fill", "currentColor");
  svg.appendChild(document.createElementNS(SVG, "path")).setAttribute("d", d);
  return svg;
}

function kindIcon(k) {
  // The ecosystem's brand mark; a package box for schemes without one.
  if (KIND_ICONS[k]) return svgFill(KIND_ICONS[k]);
  return svgLine(GLYPH_PACKAGE);
}

function kindText(k) {
  var s = el("span", "kic");
  s.appendChild(kindIcon(k));
  s.appendChild(document.createTextNode(k));
  return s;
}


function clip(text, limit, cls) {
  // span for text, shortened to limit chars + ellipsis with the full value
  // on hover once it exceeds the limit.
  if (!text) return null;
  if (text.length <= limit) return el("span", cls, text);
  var s = el("span", cls + " tip", text.slice(0, limit - 3) + "…");
  s.setAttribute("data-tip", text);
  return s;
}

function regBadge(s) {
  if (!s.reg) return null;
  var badge = el("span", "reg tip");
  badge.setAttribute("data-tip", s.reg.title);
  if (s.reg.img) {
    var img = el("img");
    img.src = s.reg.img;
    badge.appendChild(img);
  } else {
    badge.appendChild(svgIcon(s.reg.icon));
  }
  return badge;
}

function registryLink(ref) {
  // The registry's human page for an image ref, or null when the host has
  // none (the private registry, dhi.io). Pull-through mirrors resolve to the
  // page of the upstream they mirror.
  var m;
  if ((m = /^(?:docker\.io|mirror\.gcr\.io)\/(.+)$/.exec(ref))) {
    return { label: "Docker Hub",
             url: m[1].indexOf("library/") === 0
               ? "https://hub.docker.com/_/" + m[1].slice("library/".length)
               : "https://hub.docker.com/r/" + m[1] };
  }
  if ((m = /^(?:[\w.-]+\/)?ghcr\.io\/([^/]+)\//.exec(ref))) {
    return { label: "GitHub packages", url: "https://github.com/" + m[1] + "?tab=packages" };
  }
  if ((m = /^quay\.io\/(.+)$/.exec(ref))) {
    return { label: "Quay", url: "https://quay.io/repository/" + m[1] };
  }
  if ((m = /^ecr-public\.aws\.com\/(.+)$/.exec(ref))) {
    return { label: "ECR Public", url: "https://gallery.ecr.aws/" + m[1] };
  }
  if ((m = /^dhi\.io\/(.+)$/.exec(ref))) {
    return { label: "DHI catalog",
             url: "https://hub.docker.com/hardened-images/catalog/dhi/" + m[1] };
  }
  if ((m = /^registry\.k8s\.io\/(.+)$/.exec(ref))) {
    // registry.k8s.io itself is alive, but it never had a browse UI of its
    // own and the GCR console that listed the old mirror shut down in 2025,
    // so each image links to the repository it is built from.
    var repo = K8S_REPOS[m[1]];
    return repo ? { label: "GitHub", url: "https://github.com/" + repo } : null;
  }
  return null;
}

// Source repository per registry.k8s.io image path; unlisted paths get no link.
var K8S_REPOS = {
  "coredns/coredns": "coredns/coredns",
  "descheduler/descheduler": "kubernetes-sigs/descheduler",
  "kube-apiserver": "kubernetes/kubernetes",
  "kube-controller-manager": "kubernetes/kubernetes",
  "kube-proxy": "kubernetes/kubernetes",
  "kube-scheduler": "kubernetes/kubernetes",
  "kube-state-metrics/kube-state-metrics": "kubernetes/kube-state-metrics",
  "lws/lws": "kubernetes-sigs/lws",
  "nfd/node-feature-discovery": "kubernetes-sigs/node-feature-discovery",
  "sig-storage/csi-node-driver-registrar": "kubernetes-csi/node-driver-registrar",
  "sig-storage/csi-provisioner": "kubernetes-csi/external-provisioner",
  "sig-storage/csi-resizer": "kubernetes-csi/external-resizer",
  "sig-storage/livenessprobe": "kubernetes-csi/livenessprobe",
  "sig-storage/smbplugin": "kubernetes-csi/csi-driver-smb"
};

function extAnchor(target, tip) {
  // Glyph link opening target in a new tab; stopPropagation keeps the click
  // from also selecting the row it sits in.
  var a = el("a", "ext");
  a.href = target;
  a.target = "_blank";
  a.rel = "noopener";
  a.setAttribute("data-tip", tip);
  a.appendChild(svgLine(GLYPH_EXT));
  a.onclick = function (ev) { ev.stopPropagation(); };
  return a;
}

function cveUrl(id) {
  // Advisory page for a trivy vulnerability id (NVD for CVEs, GitHub for
  // GHSAs); other id spaces (RHSA, OS-specific) have no stable URL.
  var s = String(id || "");
  if (/^CVE-\d{4}-\d+$/.test(s)) return "https://nvd.nist.gov/vuln/detail/" + s;
  if (/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(s)) return "https://github.com/advisories/" + s;
  return null;
}

function buildVulns() {
  // Lookup over the reporter snapshot (DATA.vulns, merged into /api/state
  // from the reporter CronJob's state file): exact repo+tag entries, plus a
  // worst-severity entry per repo for digest-pinned images whose reports
  // carry no tag or a stale one.
  var v = { img: {}, repo: {} };
  (DATA.vulns || []).forEach(function (x) {
    v.img[x.repo + "\n" + (x.tag || "")] = x;
    var cur = v.repo[x.repo];
    if (!cur || x.crit + x.high > cur.crit + cur.high) v.repo[x.repo] = x;
  });
  return v;
}

function vulnFor(e) {
  if (!VULNS) return null;
  return VULNS.img[e.ref + "\n" + (e.tag || "")] || VULNS.repo[e.ref] || null;
}

function vulnPkgMap(v) {
  // Vulnerable package names (lowercase) -> their CVE entries, used to
  // mark SBOM component rows of one image.
  var m = {};
  ((v && v.cves) || []).forEach(function (c) {
    var k = String(c.pkg || "").toLowerCase();
    if (k) (m[k] = m[k] || []).push(c);
  });
  return m;
}

function vulnBadge(v) {
  var t = [];
  if (v.crit) t.push("C" + v.crit);
  if (v.high) t.push("H" + v.high);
  var b = el("span", "vwarn " + (v.crit ? "crit" : "high"));
  b.setAttribute("data-tip",
    v.crit + " critical, " + v.high + " high: " +
    v.cves.slice(0, 4).map(function (c) { return c.id + " " + c.score + " (" + c.pkg + ")"; }).join(", ") +
    (v.cves.length > 4 ? " +" + (v.cves.length - 4) + " more" : ""));
  b.textContent = t.join(" ");
  return b;
}

function relTime(ms, now) {
  // Age of an epoch-ms timestamp as "45s ago" / "3h ago" / "1w ago"; past a
  // month the absolute date reads better than a large week count.
  if (ms == null || isNaN(ms)) return "";
  var s = Math.floor((now - ms) / 1000);
  if (s < 45) return "just now";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  if (s < 7 * 86400) return Math.floor(s / 86400) + "d ago";
  if (s < 30 * 86400) return Math.floor(s / (7 * 86400)) + "w ago";
  return new Date(ms).toISOString().slice(0, 10);
}

function render() {
  var list = document.getElementById("list");
  list.textContent = "";
  var rows = shown();
  var metaEl = document.getElementById("meta");
  metaEl.textContent =
    rows.length + " image(s), " + (DATA.workloads || []).length + " workloads, generated " +
    (relTime(Date.parse(DATA.generatedAt || ""), Date.now()) || "never");
  if (DATA.generatedAt) metaEl.setAttribute("data-tip", DATA.generatedAt);
  if (!rows.length) list.appendChild(el("div", "empty", "no containers match"));
  rows.forEach(function (e) {
    var line = el("div", "cont" + (SELECTED === e.key ? " sel" : ""));
    var s = shortenRef(e.ref);
    var b = regBadge(s);
    if (b) line.appendChild(b);
    var rl = registryLink(e.ref);
    if (rl) line.appendChild(extAnchor(rl.url, "Open on " + rl.label));
    line.appendChild(clip(s.rest, 30, "ref"));
    if (e.tag) line.appendChild(clip(e.tag, 12, "kind"));
    var v = vulnFor(e);
    if (v) line.appendChild(vulnBadge(v));
    if (e.digest) line.appendChild(el("span", "dig", e.digest.replace("sha256:", "").slice(0, 12)));
    var m = meta(e.file);
    line.appendChild(el("span", "cnt", e.users.length + " workload(s) - " + (m ? m.components + " components" : "sbom missing")));
    line.onclick = function () { SELECTED = e.key; render(); showEntry(e); };
    list.appendChild(line);
  });
}

// Every Application CRD lives in the ArgoCD install namespace, no matter
// which namespace its workload deploys into.
var ARGO_APP_NS = "argocd";
var GROUPS = {
  Deployment: "apps", StatefulSet: "apps", DaemonSet: "apps",
  Job: "batch", CronJob: "batch"
};

function argoUrl(w) {
  // The ArgoCD tree deep link addresses the application, which the exporter
  // records from the workloads' argocd.argoproj.io/tracking-id annotation.
  // The base URL comes from the server's ARGOCD_URL env; without it there
  // is no link target and rows stay plain text.
  if (!w.app || !DATA.argoBase) return null;
  var url = DATA.argoBase + "/applications/" + ARGO_APP_NS +
    "/" + encodeURIComponent(w.app) + "?view=tree&resource=";
  var g = GROUPS[w.kind];
  if (g) {
    url += "&node=" + encodeURIComponent(g + "/" + w.kind + "/" + w.namespace + "/" + w.name + "/0");
  }
  return url;
}

function copyText(text, onDone) {
  // navigator.clipboard is unavailable on plain-HTTP pages, so fall back to
  // selecting a throwaway textarea.
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onDone, function () {});
    return;
  }
  var ta = el("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); if (onDone) onDone(); } catch (er) {}
  document.body.removeChild(ta);
}

function copyButton(text) {
  var btn = el("button", "cp");
  btn.setAttribute("aria-label", "copy");
  btn.appendChild(svgLine(GLYPH_COPY));
  btn.onclick = function () {
    if (btn.dataset.busy) return;
    btn.dataset.busy = "1";
    copyText(text, function () {
      swap(150, function () {
        btn.textContent = "";
        btn.appendChild(svgLine(GLYPH_CHECK));
        btn.classList.add("ok");
      });
      setTimeout(function () {
        swap(150, function () {
          btn.textContent = "";
          btn.appendChild(svgLine(GLYPH_COPY));
          btn.classList.remove("ok");
          delete btn.dataset.busy;
        });
      }, 1400);
    });
  };
  function swap(fade, mid) {
    btn.classList.add("fade");
    setTimeout(function () {
      mid();
      btn.classList.remove("fade");
    }, fade);
  }
  return btn;
}

var PURL_KINDS = {
  golang: "go", cargo: "rust", pypi: "python", maven: "java",
  deb: "deb", apk: "apk", rpm: "rpm", npm: "npm", gem: "gem", composer: "php"
};

function purlKind(comp) {
  // The purl scheme is the ecosystem: "pkg:golang/github.com/x" -> go.
  var m = /^pkg:([a-z0-9.+-]+)/.exec(comp.purl || "");
  if (!m) return "";
  return PURL_KINDS[m[1]] || m[1];
}

function purlParts(purl) {
  // {kind, path, qual} with percent-decoding, or null if not a purl.
  // path is everything between the scheme and @version: the module path for
  // golang, "namespace/name" for OS packages, the name for the rest.
  var m = /^pkg:([a-z0-9.+-]+)\/([^@?]+)(?:@[^?]*)?(?:\?(.*))?$/.exec(purl || "");
  if (!m) return null;
  var dec = function (s) {
    try { return decodeURIComponent(s); } catch (er) { return s; }
  };
  var qual = {};
  (m[3] || "").split("&").forEach(function (kv) {
    var i = kv.indexOf("=");
    if (i > 0) qual[kv.slice(0, i)] = dec(kv.slice(i + 1));
  });
  return { kind: m[1], path: dec(m[2]), qual: qual };
}

function purlUrl(segments) {
  // Path segments re-encoded for a URL, "@" left readable (npm scopes).
  return segments.map(function (s) {
    return encodeURIComponent(s).replace(/%40/g, "@");
  }).join("/");
}

function componentLink(comp) {
  // The ecosystem's page for a component. Go modules under github.com link
  // to the source repo, other ecosystems to their registry page.
  // OS packages link to the distro's package search (a list page); SUSE has
  // no public search page, so rpm gets no link.
  var p = purlParts(comp.purl);
  if (!p) return null;
  var segs = p.path.split("/");
  if (p.kind === "golang") {
    if (p.path === "stdlib") return null;
    // The third path segment is the repo name; a major-version suffix
    // (.../bar/v5) or subpackage comes after it and is dropped.
    var gh = /^github\.com\/([^/]+)\/([^/]+)/.exec(p.path);
    if (gh) return { label: "GitHub", url: "https://github.com/" + gh[1] + "/" + gh[2] };
    return { label: "Go package",
             url: "https://pkg.go.dev/" + purlUrl(segs) };
  }
  if (p.kind === "npm") return { label: "npm",
    url: "https://www.npmjs.com/package/" + purlUrl(segs) };
  if (p.kind === "pypi") return { label: "PyPI",
    url: "https://pypi.org/project/" + purlUrl(segs) + "/" };
  if (p.kind === "cargo") return { label: "crates.io",
    url: "https://crates.io/crates/" + purlUrl(segs) };
  if (p.kind === "gem") return { label: "RubyGems",
    url: "https://rubygems.org/gems/" + purlUrl(segs) };
  if (p.kind === "composer") return { label: "Packagist",
    url: "https://packagist.org/packages/" + purlUrl(segs) };
  if (p.kind === "maven" && segs.length >= 2) {
    return { label: "Maven Central",
             url: "https://central.sonatype.com/artifact/" + purlUrl(segs.slice(0, 2)) };
  }
  if (p.kind === "apk") {
    var branch = p.qual.distro ? "&branch=v" + p.qual.distro.split(".").slice(0, 2).join(".") : "";
    return { label: "Alpine packages",
             url: "https://pkgs.alpinelinux.org/packages?name=" +
                  encodeURIComponent(segs[segs.length - 1]) + branch };
  }
  if (p.kind === "deb") {
    var host = segs[0] === "ubuntu" ? "packages.ubuntu.com" : "packages.debian.org";
    return { label: host === "packages.ubuntu.com" ? "Ubuntu packages" : "Debian packages",
             url: "https://" + host + "/search?searchon=names&keywords=" +
                  encodeURIComponent(segs[segs.length - 1]) };
  }
  return null;
}

function showEntry(e) {
  var users = document.getElementById("users");
  users.textContent = "";
  users.appendChild(el("h2", "", "Used by"));
  e.users.slice().sort(function (a, b) {
    var ka = a.namespace + "/" + a.kind + "/" + a.name;
    var kb = b.namespace + "/" + b.kind + "/" + b.name;
    return ka < kb ? -1 : (ka > kb ? 1 : 0);
  }).forEach(function (w) {
    // Workloads ArgoCD does not track (Longhorn internals, static pods) and
    // servers without ARGOCD_URL have no application page, so they stay plain
    // text.
    var url = argoUrl(w);
    var r = el(url ? "a" : "div", "cont");
    if (url) {
      r.href = url;
      r.target = "_blank";
      r.rel = "noopener";
    }
    r.appendChild(el("span", "ns", w.namespace));
    r.appendChild(el("span", "kind", w.kind));
    r.appendChild(el("span", "name", w.name));
    if (url) {
      var go = el("span", "go");
      go.setAttribute("data-tip", "Open app \"" + w.app + "\" in ArgoCD");
      go.appendChild(svgLine(GLYPH_EXT));
      r.appendChild(go);
    }
    users.appendChild(r);
  });

  var sbom = document.getElementById("sbom");
  sbom.textContent = "";
  var full = e.ref + (e.tag ? ":" + e.tag : "");
  var h2 = el("h2", "", full);
  h2.appendChild(copyButton(full));
  var rl = registryLink(e.ref);
  if (rl) h2.appendChild(extAnchor(rl.url, "Open on " + rl.label));
  var v = vulnFor(e);
  if (v) h2.appendChild(vulnBadge(v));
  sbom.appendChild(h2);
  if (!e.file) { sbom.appendChild(el("div", "empty", "no sbom")); return; }
  var m = meta(e.file);
  var head = el("div");
  head.appendChild(el("span", "dig", (e.digest || "") + "  "));
  if (m) {
    var ts = el("span", "", relTime(m.mtime * 1000, Date.now()) + "  ");
    ts.setAttribute("data-tip", new Date(m.mtime * 1000).toISOString());
    head.appendChild(ts);
    head.appendChild(el("span", "", m.components + " components  "));
  }
  sbom.appendChild(head);
  var note = el("div", "empty", "loading...");
  sbom.appendChild(note);
  fetch("/api/sbom?file=" + encodeURIComponent(e.file)).then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).then(function (bom) {
    note.remove();
    var vmap = vulnPkgMap(v);
    var comps = (bom.components || []).slice().sort(function (a, b) {
      return String(a.name).localeCompare(String(b.name));
    });
    var counts = {};
    comps.forEach(function (comp) {
      var k = purlKind(comp) || comp.type || "other";
      counts[k] = (counts[k] || 0) + 1;
    });
    var kinds = el("div", "kinds");
    Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).forEach(function (k) {
      var sp = el("span", "kind " + k);
      if (KIND_ICONS[k] || counts[k] > 4) sp.appendChild(kindIcon(k));
      sp.appendChild(document.createTextNode(k + " " + counts[k]));
      kinds.appendChild(sp);
    });
    sbom.appendChild(kinds);
    var table = el("table");
    var hr = el("tr");
    ["name", "version", "kind", "type"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
    table.appendChild(hr);
    if (!comps.length) {
      var er = el("tr"); var ed = el("td", "empty", "no components"); ed.colSpan = 4;
      er.appendChild(ed); table.appendChild(er);
    }
    comps.forEach(function (comp) {
      var tr = el("tr");
      var nameTd = el("td", "n");
      nameTd.appendChild(document.createTextNode(comp.name));
      var cl = componentLink(comp);
      if (cl) nameTd.appendChild(extAnchor(cl.url, "Open " + comp.name + " on " + cl.label));
      var vc = vmap[String(comp.name || "").toLowerCase()] || [];
      vc.forEach(function (c) {
        // One triangle per CVE, each linking its advisory when the id is one
        // we can resolve to a page.
        var url = cveUrl(c.id);
        var w = el(url ? "a" : "span", "vwarn " + (c.severity === "CRITICAL" ? "crit" : "high"));
        if (url) {
          w.href = url;
          w.target = "_blank";
          w.rel = "noopener";
          w.onclick = function (ev) { ev.stopPropagation(); };
        }
        w.setAttribute("data-tip", c.id + " " + c.severity + " (score " + c.score + ")");
        w.appendChild(svgLine(GLYPH_WARN));
        nameTd.appendChild(w);
      });
      tr.appendChild(nameTd);
      tr.appendChild(el("td", "v", comp.version));
      var k = purlKind(comp);
      var kc = el("td", "t");
      if (k) kc.appendChild(kindText(k)); else kc.textContent = "-";
      tr.appendChild(kc);
      tr.appendChild(el("td", "t", comp.type));
      table.appendChild(tr);
    });
    sbom.appendChild(table);
  }).catch(function (er) { note.textContent = "could not load sbom: " + er.message; });
}

function nsSet(name) {
  NSEL = name;
  document.getElementById("ns").value = name === "All" ? "" : name;
  document.getElementById("nsx").hidden = name === "All";
  render();
}

function syncNs() {
  // Mirror NSEL into the combobox unless the user is mid-edit inside it.
  if (NSEL !== "All" && NS_NAMES.indexOf(NSEL) < 0) NSEL = "All";
  var inp = document.getElementById("ns");
  document.getElementById("nsx").hidden = NSEL === "All";
  if (document.activeElement !== inp) inp.value = NSEL === "All" ? "" : NSEL;
}

function fillNamespaces() {
  var names = [];
  (DATA.workloads || []).forEach(function (w) {
    if (names.indexOf(w.namespace) < 0) names.push(w.namespace);
  });
  names.sort();
  NS_NAMES = names;
  syncNs();
}

function startNs() {
  // Namespace combobox: free text fuzzy-filters a dropdown, a pick (or an
  // exact-match blur) sets the filter, Escape and the x button reset to All.
  var inp = document.getElementById("ns");
  var btn = document.getElementById("nsx");
  var menu = document.getElementById("nsmenu");
  btn.appendChild(svgLine(GLYPH_X));
  function close() {
    menu.textContent = "";
    menu.hidden = true;
    inp.setAttribute("aria-expanded", "false");
  }
  function open() {
    menu.textContent = "";
    var q = inp.value.trim().toLowerCase();
    var names = NS_NAMES.filter(function (n) { return fuzzy(n, q) > 0; });
    if (fuzzy("all", q) > 0) names.unshift("All");
    names.forEach(function (n) {
      var d = el("div", n === NSEL ? "sel" : null, n);
      d.onmousedown = function (ev) {
        ev.preventDefault(); // pick this before the input's blur reverts the text
        close();
        nsSet(n);
      };
      menu.appendChild(d);
    });
    menu.hidden = false;
    inp.setAttribute("aria-expanded", "true");
  }
  inp.addEventListener("focus", open);
  inp.addEventListener("input", open);
  inp.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") {
      ev.preventDefault();
      close();
      nsSet("All");
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      var pick = menu.firstChild;
      close();
      if (pick) nsSet(pick.textContent);
    }
  });
  inp.addEventListener("blur", function () {
    setTimeout(function () {
      close();
      var v = inp.value.trim();
      if (v === "All") { nsSet("All"); return; }
      if (v && NS_NAMES.indexOf(v) >= 0) { nsSet(v); return; }
      if (document.activeElement !== inp) inp.value = NSEL === "All" ? "" : NSEL;
    }, 120);
  });
  btn.addEventListener("click", function () {
    nsSet("All");
    inp.focus();
  });
}

function startTips() {
  var tip = document.getElementById("tip");
  document.addEventListener("mouseover", function (ev) {
    var t = ev.target.closest && ev.target.closest("[data-tip]");
    if (!t) { tip.classList.remove("on"); return; }
    tip.textContent = t.getAttribute("data-tip");
    tip.classList.add("on");
    var r = t.getBoundingClientRect();
    var left = r.right + 6;
    if (left + tip.offsetWidth > window.innerWidth - 4) left = r.left - tip.offsetWidth - 6;
    tip.style.left = Math.max(4, Math.min(left, window.innerWidth - tip.offsetWidth - 4)) + "px";
    tip.style.top = (r.top + r.height / 2) + "px";
  });
  document.addEventListener("mouseout", function (ev) {
    if (ev.target.closest && ev.target.closest("[data-tip]")) tip.classList.remove("on");
  });
}

function initSplits() {
  // Drag handles set the two side pane widths (--w1, --w3); the middle pane
  // takes the rest. Widths persist in localStorage across reloads.
  var main = document.querySelector && document.querySelector("main");
  if (!main || !window.localStorage) return;
  var W = {};
  try { W = JSON.parse(localStorage.getItem("sbom-panes") || "null") || {}; } catch (e) { W = {}; }
  if (typeof W.w1 !== "number") W.w1 = 700;
  if (typeof W.w3 !== "number") W.w3 = 280;
  function apply(which) {
    W[which] = Math.max(240, Math.min(
      main.clientWidth - (which === "w1" ? W.w3 : W.w1) - 380, W[which]));
    main.style.setProperty("--" + which, W[which] + "px");
  }
  apply("w1");
  apply("w3");
  window.addEventListener("resize", function () { apply("w1"); apply("w3"); });
  [["sp1", "w1", 1], ["sp2", "w3", -1]].forEach(function (p) {
    var h = document.getElementById(p[0]);
    if (!h) return;
    h.onmousedown = function (ev) {
      if (ev.button !== 0) return;
      var x0 = ev.clientX, v0 = W[p[1]];
      h.classList.add("on");
      function move(mv) {
        W[p[1]] = v0 + p[2] * (mv.clientX - x0);
        apply(p[1]);
      }
      function up() {
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
        h.classList.remove("on");
        try { localStorage.setItem("sbom-panes", JSON.stringify(W)); } catch (e) {}
      }
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
      ev.preventDefault();
    };
  });
}

function startReload() {
  // The button holds both glyphs stacked; spin rotates the arrow, then the
  // check cross-fades in and back out. Failure stops the spin with no check.
  var b = document.getElementById("rl");
  if (!b || !b.appendChild) return;
  var arrow = svgLine(GLYPH_RELOAD);
  arrow.setAttribute("class", "glyph");
  var check = svgLine(GLYPH_CHECK);
  check.setAttribute("class", "done");
  b.appendChild(arrow);
  b.appendChild(check);
  b.addEventListener("click", function () {
    b.classList.add("spin");
    var t0 = Date.now();
    reload(true, function (ok) {
      // A cached rebuild lands in well under a second; hold the spin to a
      // minimum so the click reads as something happening.
      setTimeout(function () {
        b.classList.remove("spin");
        if (!ok) return;
        b.classList.add("ok");
        setTimeout(function () { b.classList.remove("ok"); }, 1200);
      }, Math.max(0, 1500 - (Date.now() - t0)));
    });
  });
}

function startClear() {
  // Search box clear: a right-aligned x that only shows while the box has
  // text. Escape clears and keeps focus, or blurs when already empty.
  var q = document.getElementById("q");
  var x = document.getElementById("qx");
  if (!x || !x.appendChild) return;
  x.appendChild(svgLine(GLYPH_X));
  function sync() { x.hidden = !q.value; }
  q.addEventListener("input", sync);
  q.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    if (q.value) {
      q.value = "";
      render();
      sync();
    } else {
      q.blur();
    }
  });
  x.addEventListener("click", function () {
    q.value = "";
    render();
    sync();
    q.focus();
  });
  sync();
}

function start() {
  document.getElementById("q").addEventListener("input", render);
  startNs();
  startClear();
  startTips();
  initSplits();
  startReload();
  reload();
}

function loadIndex(force) {
  // One package-name snapshot per manifest generation; SBOM bodies are only
  // fetched when an image is selected. A failed load leaves the previous
  // snapshot (or no packages searchable) and is retried on the next reload.
  if (INDEX && !force && INDEX.generatedAt === DATA.generatedAt) return;
  fetch("/api/index" + (force ? "?fresh=1" : "")).then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).then(function (d) {
    INDEX = d;
    render();
  }).catch(function () {});
}

function reload(force, done) {
  // force bypasses the server's 5-minute response cache (the reload button).
  fetch("/api/state" + (force ? "?fresh=1" : "")).then(function (r) { return r.json(); }).then(function (d) {
    DATA = d;
    VULNS = buildVulns();
    fillNamespaces();
    render();
    loadIndex(force);
    setTimeout(reload, 60000);
    if (done) done(true);
  }).catch(function () {
    setTimeout(function () { reload(); }, 10000);
    if (done) done(false);
  });
}

start();
