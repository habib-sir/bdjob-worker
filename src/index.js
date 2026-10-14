export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": "https://bdjobapply.site",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/admin/jobs/save" || request.method !== "POST") {
      return new Response("Not found", { status: 404, headers: cors });
    }

    if (request.headers.get("Authorization") !== `Bearer ${env.ADMIN_TOKEN}`) {
      return new Response("Unauthorized", { status: 401, headers: cors });
    }

    let jobs;
    try {
      jobs = await request.json();
    } catch {
      return new Response("Invalid JSON", { status: 400, headers: cors });
    }
    if (!Array.isArray(jobs)) {
      return new Response("Body must be an array", { status: 400, headers: cors });
    }

    const updatedAt = new Date().toISOString();
    const posts = jobs.slice(0, 50).map((j) => ({
      id: j.id,
      title: j.title || "",
      slug: j.slug || j.id,
      category: j.category || "govt",
      deadline: j.deadline,
      publishedAt: j.publishedAt,
      applyServiceEnabled: Boolean(j.applyServiceEnabled),
      featuredImage: j.featuredImage || j.circularImages?.[0] || null,
    }));

    const opts = { httpMetadata: { contentType: "application/json" } };
    await env.BUCKET.put("jobs.json", JSON.stringify(jobs, null, 2), opts);
    await env.BUCKET.put("feed.json", JSON.stringify({ posts, updatedAt }, null, 2), opts);

    return new Response(JSON.stringify({ ok: true, count: jobs.length }), {
      headers: { ...cors, "Content-Type": "application/json" },
    });
  },
};
