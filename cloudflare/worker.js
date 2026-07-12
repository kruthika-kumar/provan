export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/") {
      return env.ASSETS.fetch(new Request(new URL("/index.html", url), request));
    }
    if (url.pathname === "/health") {
      return Response.json({ status: "ok", service: "shiproom-demo" });
    }
    if (url.pathname.startsWith("/result/") || url.pathname.startsWith("/results/")) {
      return new Response("<h1>Demo launch card</h1>", { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (url.pathname.startsWith("/reports/")) {
      return env.ASSETS.fetch(new Request(new URL("/release-report.html", url), request));
    }
    if (url.pathname === "/setup") return env.ASSETS.fetch(new Request(new URL("/setup.html", url), request));
    if (["/completed_run.json", "/public_evidence_manifest.v1.json", "/shiproom-verdict.svg"].includes(url.pathname)) return env.ASSETS.fetch(request);
    return new Response("Not found", { status: 404 });
  },
};
