"use strict";

const get = (id) => document.getElementById(id);
const search = get("search");
const dialog = get("detail");
const count = new Intl.NumberFormat("en-US");
const vendors = { elastic: "Elastic Detection Rules", splunk: "Splunk Security Content" };
const statusLabels = { exact: "Exact", related: "Related", unmapped: "Unmapped", "oci-specific": "OCI-specific" };
const kindLabels = { detection: "Detection", sentinel: "Sentinel conversion", application: "App analytics", hunting: "Companion hunt" };
const facets = {
  tactic: ["Tactic", (rule) => rule.tactics],
  technique: ["Technique", (rule) => rule.techniques],
  severity: ["Severity", (rule) => [rule.severity]],
  platform: ["Platform", (rule) => [rule.platform]],
  source: ["Log source", (rule) => rule.sources],
  category: ["Category", (rule) => [rule.category]],
  elastic: ["Elastic mapping", (rule) => [rule.mappings.elastic.status]],
  splunk: ["Splunk mapping", (rule) => [rule.mappings.splunk.status]],
};
const controls = new Map();
const PAGE_SIZE = 25;
let catalog;
let rules;
let upstreamRules;
let queryIndex;
let coverage;
let current;
let openRule;
let detailTrigger;
let renderedResults;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function button(text, onClick, className) {
  const element = node("button", text, className);
  element.type = "button";
  element.addEventListener("click", onClick);
  return element;
}

function externalLink(text, url) {
  const link = node("a", text);
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function capitalize(value) {
  return value.replace(/(^|[_ ])([a-z])/g, (_, space, letter) => space.replace("_", " ") + letter.toUpperCase());
}

function optionLabel(key, value) {
  if (Object.hasOwn(vendors, key)) return statusLabels[value];
  if (key === "category" && Object.hasOwn(kindLabels, value)) return kindLabels[value];
  if (key === "platform" && value.startsWith("oci")) return value === "oci" ? "OCI" : "OCI Log Analytics";
  return key === "source" || key === "technique" ? value : capitalize(value);
}

function tag(text, level) {
  const badge = node("span", text, "tag");
  if (level) badge.dataset.level = level;
  return badge;
}

function readState() {
  const fields = new URLSearchParams(location.search);
  const view = fields.get("view");
  return {
    view: Object.hasOwn(vendors, view) ? view : "oci",
    q: fields.get("q") ?? "",
    page: Math.max(1, Number.parseInt(fields.get("page"), 10) || 1),
    rule: rules.has(fields.get("rule")) ? fields.get("rule") : null,
    filters: Object.fromEntries([...controls].flatMap(([key, select]) => {
      const value = fields.get(key);
      return value && [...select.options].some((option) => option.value === value) ? [[key, value]] : [];
    })),
  };
}

function update(patch, mode = "push", detailEntry = false) {
  current = { ...current, ...patch };
  const fields = new URLSearchParams();
  if (current.view !== "oci") fields.set("view", current.view);
  if (current.q) fields.set("q", current.q);
  for (const key of controls.keys()) {
    if (current.filters[key]) fields.set(key, current.filters[key]);
  }
  if (current.page > 1) fields.set("page", String(current.page));
  if (current.rule) fields.set("rule", current.rule);
  const url = new URL(location.href);
  url.search = fields.toString();
  if (url.href !== location.href) history[mode + "State"]({ detailEntry }, "", url);
  render();
}

function setFilter(key, value) {
  const filters = { ...current.filters };
  if (value) filters[key] = value;
  else delete filters[key];
  update({ filters, page: 1 });
}

function buildControls() {
  for (const [key, [name, field]] of Object.entries(facets)) {
    const group = node("div", null, "facet");
    const select = node("select");
    const label = node("label", name);
    select.id = "facet-" + key;
    label.htmlFor = select.id;
    select.setAttribute("aria-label", "Filter by " + name.toLowerCase().replace("elastic", "Elastic").replace("splunk", "Splunk"));
    const values = key === "tactic" ? catalog.tactics : [...new Set(catalog.rules.flatMap(field))].sort();
    select.add(new Option("Any " + name.toLowerCase(), ""));
    for (const value of values) select.add(new Option(optionLabel(key, value), value));
    select.addEventListener("change", () => setFilter(key, select.value));
    group.append(label, select);
    get("facets").append(group);
    controls.set(key, select);
  }

  const matches = Object.fromEntries(catalog.tactics.map((tactic) => [
    tactic, catalog.rules.filter((rule) => rule.tactics.includes(tactic)).length,
  ]));
  const max = Math.max(1, ...Object.values(matches));
  coverage = catalog.tactics.map((tactic) => {
    const label = optionLabel("tactic", tactic);
    const tile = button(null, () => setFilter("tactic", current.filters.tactic === tactic ? "" : tactic), "tactic");
    const meter = node("meter");
    meter.max = max;
    meter.value = matches[tactic];
    meter.setAttribute("aria-hidden", "true");
    tile.append(node("span", label, "tactic-label"), node("b", matches[tactic]), meter);
    tile.setAttribute("aria-label", label + ", " + matches[tactic] + " rules and hunts");
    get("tactics").append(tile);
    return [tactic, tile];
  });

  const detectionCount = catalog.rules.filter((rule) => rule.kind !== "hunting").length;
  const metrics = [
    [detectionCount, "OCI rules"],
    [catalog.rules.length - detectionCount, "companion hunts"],
    [Object.keys(catalog.upstreams.elastic).length, "Elastic references"],
    [Object.keys(catalog.upstreams.splunk).length, "Splunk references"],
  ];
  for (const [total, label] of metrics) {
    const item = node("li");
    item.append(node("strong", count.format(total)), " " + label);
    get("metrics").append(item);
  }
  get("coverage-summary").textContent = catalog.tactics.length + " tactics · "
    + new Set(catalog.rules.flatMap((rule) => rule.techniques)).size + " techniques and sub-techniques";
}

function openDetail(rule, event) {
  detailTrigger = event.currentTarget;
  update({ rule: rule.id }, "push", true);
}

function closeDetail() {
  if (history.state?.detailEntry) history.back();
  else update({ rule: null }, "replace");
}

function queryBlock(value, highlight) {
  const pre = node("pre", null, "query");
  const code = node("code");
  pre.tabIndex = 0;
  pre.append(code);
  if (!highlight) {
    code.textContent = value;
    return pre;
  }
  const tokens = /'(?:''|[^'])*'|"(?:\\.|[^"\\])*"|\b(?:where|stats|search|fields|sort|head|tail|link|eval|eventstats|timestats|rename|lookup|dedup)\b/gi;
  let offset = 0;
  for (const match of value.matchAll(tokens)) {
    const [token] = match;
    code.append(value.slice(offset, match.index), node("span", token, /^['"]/.test(token) ? "ocl-string" : "ocl-command"));
    offset = match.index + token.length;
  }
  code.append(value.slice(offset));
  return pre;
}

function querySection(name, value, highlight) {
  const section = node("section");
  const heading = node("div", null, "section-heading");
  const message = node("span", "", "sr-only");
  message.setAttribute("role", "status");
  const copy = button(highlight ? "Copy query" : "Copy SPL", async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = "Copied";
      message.textContent = "Query copied to clipboard.";
    } catch {
      copy.textContent = "Select query to copy";
      message.textContent = "Clipboard unavailable. Select the query text and copy it manually.";
    }
  }, "small-button");
  heading.append(node("h3", name), copy, message);
  section.append(heading, queryBlock(value, highlight));
  return section;
}

function mappingPanel(rule, vendor) {
  const panel = node("section", null, "mapping");
  panel.append(node("h3", vendors[vendor]));
  const mapping = rule.mappings[vendor];
  panel.append(tag(statusLabels[mapping.status], mapping.status));
  if (!mapping.references.length) {
    const reason = mapping.status === "oci-specific"
      ? "This query uses OCI telemetry. No vendor reference has been verified."
      : "No official rule has been verified for this query.";
    panel.append(node("p", reason));
    return panel;
  }
  const list = node("ul");
  for (const reference of mapping.references) {
    const upstream = catalog.upstreams[vendor][reference.id];
    const row = node("li");
    row.append(
      node("strong", upstream.title), " ", tag(statusLabels[reference.confidence], reference.confidence),
      node("p", reference.rationale),
      externalLink("Official source", upstream.url),
      node("p", "Rule " + upstream.id + " · commit " + upstream.revision.slice(0, 12)),
    );
    list.append(row);
  }
  panel.append(list);
  return panel;
}

function provenancePanel(rule) {
  const section = node("section", null, "provenance");
  const record = node("dl");
  const addField = (label, value) => {
    if (value) record.append(node("dt", label), node("dd", value));
  };
  section.append(node("h3", "Provenance"), record);
  addField("OCI query artifact", rule.provenance.path);
  addField("Query artifact SHA-256", rule.provenance.sha256);
  addField("Sigma rule ID", rule.provenance.sigma_id);
  addField("Sentinel rule ID", rule.provenance.sentinel_id);
  addField("Sentinel source", rule.provenance.sentinel_source_url);
  addField("Log sources", rule.sources.join(", "));
  addField("Category", optionLabel("category", rule.category));
  addField("Tactics", rule.tactics.map(capitalize).join(", "));
  addField("Techniques", rule.techniques.join(", "));
  addField("Tags", rule.tags.join(", "));
  addField("Cross-SIEM families", rule.families.join(", "));
  const details = node("details");
  details.append(node("summary", "Show source metadata"), node("pre", JSON.stringify(rule.metadata, null, 2)));
  section.append(details);
  return section;
}

function renderDetail() {
  if (!current.rule) {
    if (dialog.open) {
      dialog.close();
      (detailTrigger?.isConnected ? detailTrigger : search).focus();
    }
    openRule = null;
    return;
  }
  if (current.rule === openRule) return;
  const rule = rules.get(current.rule);
  get("detail-title").textContent = rule.title;
  const badges = node("div", null, "tags");
  badges.append(tag(capitalize(rule.severity), rule.severity), tag(kindLabels[rule.kind]), tag(optionLabel("platform", rule.platform)));
  const panels = node("div", null, "mapping-grid");
  panels.append(...Object.keys(vendors).map((vendor) => mappingPanel(rule, vendor)));
  const content = get("detail-content");
  content.replaceChildren(badges, node("p", rule.description), querySection("OCI Log Analytics query", rule.query, true), panels);
  if (rule.splunkExample) content.append(querySection("Repository SPL example", rule.splunkExample, false));
  content.append(provenancePanel(rule));
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
  openRule = current.rule;
}

function ociRow(rule) {
  const row = node("li", null, "rule");
  const trigger = button(null, (event) => openDetail(rule, event), "rule-open");
  trigger.setAttribute("aria-label", rule.title);
  const text = node("span");
  text.append(node("span", rule.title, "rule-title"), node("span", rule.description, "rule-description"));
  const badges = node("span", null, "tags");
  badges.append(tag(capitalize(rule.severity), rule.severity), tag(optionLabel("platform", rule.platform)));
  for (const [vendor, mapping] of Object.entries(rule.mappings)) {
    if (mapping.references.length) badges.append(tag(capitalize(vendor) + " · " + statusLabels[mapping.status], mapping.status));
  }
  trigger.append(text, badges);
  row.append(trigger);
  return row;
}

function vendorRow({ upstream, matches }) {
  const row = node("li", null, "rule vendor-rule");
  const links = node("div", null, "mapped-oci");
  row.append(
    node("strong", upstream.title, "rule-title"), externalLink("Official source", upstream.url),
    node("p", upstream.id, "details-label"), links,
  );
  for (const [rule, reference] of matches) {
    links.append(button("View " + rule.title + " · mapped OCI " + statusLabels[reference.confidence].toLowerCase(),
      (event) => openDetail(rule, event), "small-button"));
  }
  return row;
}

function renderResults() {
  const tokens = current.q.toLocaleLowerCase("en-US").trim().split(/\s+/).filter(Boolean);
  const matchesText = (text) => tokens.every((token) => text.includes(token));
  const ruleMatches = (rule) => Object.entries(current.filters).every(([key, value]) => facets[key][1](rule).includes(value));
  const isOci = current.view === "oci";
  const items = isOci
    ? catalog.rules.filter((rule) => ruleMatches(rule) && matchesText(queryIndex.get(rule.id)))
    : upstreamRules[current.view].flatMap(({upstream, related, text}) => {
      const matches = related.filter(([rule]) => ruleMatches(rule) && (matchesText(text) || matchesText(queryIndex.get(rule.id))));
      return matches.length ? [{ upstream, matches }] : [];
    });
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  const page = Math.min(current.page, pageCount);
  const list = node("ul", null, "rules");
  list.append(...items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map(isOci ? ociRow : vendorRow));
  get("results").replaceChildren(items.length ? list : node("p", "No matching rules.", "empty"));
  get("results-status").textContent = count.format(items.length) + (items.length === 1 ? " result" : " results");
  get("pagination").hidden = pageCount === 1;
  get("page-status").textContent = "Page " + page + " of " + pageCount;
  get("previous").disabled = page <= 1;
  get("next").disabled = page >= pageCount;
  // Keep page navigation based on the rendered page when a stale URL is out of range.
  current.page = page;
}

function render() {
  const resultsKey = JSON.stringify([current.view, current.q, current.page, current.filters]);
  if (resultsKey === renderedResults) {
    renderDetail();
    return;
  }
  if (search.value !== current.q) search.value = current.q;
  for (const [key, select] of controls) select.value = current.filters[key] ?? "";
  for (const [key, tile] of coverage) tile.setAttribute("aria-pressed", String(current.filters.tactic === key));
  for (const tab of document.querySelectorAll("[data-vendor]")) {
    tab.setAttribute("aria-pressed", String(tab.dataset.vendor === current.view));
  }
  const chips = Object.entries(current.filters).map(([key, value]) => {
    const label = optionLabel(key, value);
    const chip = button(label + " ×", () => setFilter(key, ""), "chip");
    chip.setAttribute("aria-label", "Remove " + facets[key][0].toLowerCase() + " filter: " + label);
    return chip;
  });
  get("chips").replaceChildren(...chips);
  renderResults();
  renderedResults = JSON.stringify([current.view, current.q, current.page, current.filters]);
  renderDetail();
}

function indexRules() {
  const reverse = Object.fromEntries(Object.keys(vendors).map((vendor) => [vendor, new Map()]));
  queryIndex = new Map(catalog.rules.map((rule) => {
    const identities = [];
    for (const [vendor, mapping] of Object.entries(rule.mappings)) {
      for (const reference of mapping.references) {
        const upstream = catalog.upstreams[vendor][reference.id];
        identities.push(upstream.title, upstream.id, upstream.path);
        const matches = reverse[vendor].get(reference.id) ?? [];
        matches.push([rule, reference]);
        reverse[vendor].set(reference.id, matches);
      }
    }
    const text = [
      rule.id, rule.title, rule.description, rule.query, rule.platform, rule.category, ...rule.sources,
      ...rule.tags, ...rule.tactics, ...rule.techniques, ...rule.families, ...Object.values(rule.provenance), ...identities,
    ].join(" ").toLocaleLowerCase("en-US");
    return [rule.id, text];
  }));
  upstreamRules = Object.fromEntries(Object.entries(reverse).map(([vendor, byId]) => [
    vendor, [...byId].map(([id, related]) => {
      const upstream = catalog.upstreams[vendor][id];
      return { upstream, related, text: [upstream.title, id, upstream.path].join(" ").toLocaleLowerCase("en-US") };
    }).sort((a, b) => a.upstream.title.localeCompare(b.upstream.title, "en")),
  ]));
}

function theme() {
  const themeButton = get("theme");
  const system = matchMedia("(prefers-color-scheme: dark)");
  const apply = (dark) => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    themeButton.textContent = dark ? "Light theme" : "Dark theme";
    themeButton.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  };
  let stored;
  try { stored = localStorage.getItem("logan-explorer-theme"); } catch { /* Storage may be disabled. */ }
  apply(stored ? stored === "dark" : system.matches);
  themeButton.addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme !== "dark";
    apply(dark);
    try { localStorage.setItem("logan-explorer-theme", dark ? "dark" : "light"); } catch { /* Current page retains the theme. */ }
  });
}

async function start() {
  theme();
  const response = await fetch("./catalog.json");
  if (!response.ok) throw new Error("Catalog request failed");
  catalog = await response.json();
  if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.rules)) throw new Error("Unsupported catalog");
  rules = new Map(catalog.rules.map((rule) => [rule.id, rule]));
  indexRules();
  buildControls();
  current = readState();
  window.addEventListener("popstate", () => { current = readState(); render(); });
  search.addEventListener("input", () => update({ q: search.value, page: 1 }, "replace"));
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !dialog.open && !event.altKey && !event.ctrlKey && !event.metaKey
      && !event.target.closest("input, textarea, select, [contenteditable]")) {
      event.preventDefault();
      search.focus();
    }
  });
  document.querySelectorAll("[data-vendor]").forEach((tab) => {
    tab.addEventListener("click", () => update({ view: tab.dataset.vendor, page: 1 }));
  });
  get("clear").addEventListener("click", () => update({ filters: {}, q: "", page: 1 }));
  get("previous").addEventListener("click", () => update({ page: current.page - 1 }));
  get("next").addEventListener("click", () => update({ page: current.page + 1 }));
  get("filter-toggle").addEventListener("click", (event) => {
    const expanded = get("filters").classList.toggle("is-open");
    event.currentTarget.setAttribute("aria-expanded", String(expanded));
  });
  get("close-detail").addEventListener("click", closeDetail);
  dialog.addEventListener("cancel", (event) => { event.preventDefault(); closeDetail(); });
  render();
}

start().catch(() => {
  get("results-status").textContent = "The catalog could not be loaded. Reload the page to try again.";
});
