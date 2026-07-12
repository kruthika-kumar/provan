export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const asset = async (path) => {
      const response = await env.ASSETS.fetch(new Request(new URL(path, url), request));
      const headers = new Headers(response.headers);
      headers.set("Cache-Control", "public, max-age=0, must-revalidate");
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    };
    if (url.pathname === "/") {
      return asset("/index.html");
    }
    if (url.pathname === "/health") {
      return Response.json({ status: "ok", service: "shiproom-demo" });
    }
    if (url.pathname.startsWith("/result/") || url.pathname.startsWith("/results/")) {
      return new Response("<h1>Demo launch card</h1>", { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (url.pathname === "/reports/rel_35e58f680a1a" || url.pathname === "/release-report") {
      return asset("/release-report.html");
    }
    if (url.pathname.startsWith("/reports/")) return new Response("Report not found", { status: 404 });
    if (url.pathname === "/setup") return asset("/setup.html");
    if (["/completed_run.json", "/public_evidence_manifest.v1.json", "/public_evidence_manifest.v2.json", "/shiproom-verdict.svg"].includes(url.pathname)) return asset(url.pathname);
    return new Response("Not found", { status: 404 });
  },
};
