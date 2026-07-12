export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/") {
      return new Response("<h1>Launch Card</h1><p>Results publish automatically.</p><a href='/result/demo'>Published</a>", {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (url.pathname.startsWith("/results/")) {
      return new Response("<h1>Demo launch card</h1>", { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (url.pathname === "/release-report.html") return env.ASSETS.fetch(request);
    return new Response("Not found", { status: 404 });
  },
};

