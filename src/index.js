const ALLOWED_ORIGIN = "https://bdjobapply.site";
const ADMIN_EMAILS = ["habiblinkage@gmail.com", "masterboom2040@gmail.com"];
// Firebase Web API key প্রকাশ্য (frontend-এও থাকে), তাই এটি গোপন নয়
const DEFAULT_FIREBASE_API_KEY = "AIzaSyC2SQchoqvoeEhtMhZo2Uhvs9sjiQziYso";
const MAX_PROFILE_BYTES = 300000;
const MAX_PUBLIC_JSON_BYTES = 100000;

// অ্যাডমিন যে public JSON ফাইলগুলো লিখতে পারবে (নাম -> R2 ফাইল)
const PUBLIC_JSON_FILES = {
  "settings-payment": "settings-payment.json",
};

function cors(extra = {}) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, PUT, POST, DELETE, OPTIONS",
    ...extra,
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: cors({ "Content-Type": "application/json" }),
  });
}

function text(msg, status = 200) {
  return new Response(msg, { status, headers: cors() });
}

// Firebase ID token যাচাই (Firestore লাগে না, শুধু Auth)
async function verifyUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  const idToken = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!idToken) return null;

  const apiKey = env.FIREBASE_API_KEY || DEFAULT_FIREBASE_API_KEY;
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    }
  );
  if (!res.ok) return null;

  const data = await res.json();
  const u = data.users && data.users[0];
  if (!u) return null;
  return { uid: u.localId, email: (u.email || "").toLowerCase() };
}

const isAdminUser = (u) => !!u && ADMIN_EMAILS.includes(u.email);

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const isAdminToken = request.headers.get("Authorization") === `Bearer ${env.ADMIN_TOKEN}`;

    // ---------- জব সেভ (অ্যাডমিন টোকেন) ----------
    if (path === "/admin/jobs/save" && request.method === "POST") {
      if (!isAdminToken) return text("Unauthorized", 401);

      let jobs;
      try {
        jobs = await request.json();
      } catch {
        return text("Invalid JSON", 400);
      }
      if (!Array.isArray(jobs)) {
        return text("Body must be an array", 400);
      }

      const updatedAt = new Date().toISOString();
      const posts = jobs
        .filter((j) => j.status !== "draft")
        .slice(0, 50)
        .map((j) => ({
          id: j.id,
          title: j.title || "",
          slug: j.slug || j.id,
          category: j.category || "govt",
          deadline: j.deadline,
          publishedAt: j.publishedAt,
          applyServiceEnabled: Boolean(j.applyServiceEnabled),
          featuredImage: j.featuredImage || j.circularImages?.[0] || null,
        }));

      const opts = {
        httpMetadata: {
          contentType: "application/json",
          cacheControl: "public, max-age=60",
        },
      };
      await env.BUCKET.put("jobs.json", JSON.stringify(jobs, null, 2), opts);
      await env.BUCKET.put("feed.json", JSON.stringify({ posts, updatedAt }, null, 2), opts);

      return json({ ok: true, count: jobs.length });
    }

    // ---------- পাবলিক সেটিংস লেখা (অ্যাডমিন টোকেন) ----------
    const publicMatch = path.match(/^\/admin\/public\/([a-z-]+)$/);
    if (publicMatch && request.method === "PUT") {
      if (!isAdminToken) return text("Unauthorized", 401);

      const fileName = PUBLIC_JSON_FILES[publicMatch[1]];
      if (!fileName) return text("Unknown file", 404);

      const body = await request.text();
      if (body.length > MAX_PUBLIC_JSON_BYTES) return text("Too large", 413);
      try {
        JSON.parse(body);
      } catch {
        return text("Invalid JSON", 400);
      }

      await env.BUCKET.put(fileName, body, {
        httpMetadata: {
          contentType: "application/json",
          cacheControl: "public, max-age=60",
        },
      });
      return json({ ok: true });
    }

    // ---------- নিজের সিভি (প্রাইভেট bucket) ----------
    if (path === "/profile/me") {
      const user = await verifyUser(request, env);
      if (!user) return text("Unauthorized", 401);
      const key = `profiles/${user.uid}.json`;

      if (request.method === "GET") {
        const obj = await env.PRIVATE.get(key);
        if (!obj) return json({});
        return json(await obj.json());
      }

      if (request.method === "PUT") {
        const body = await request.text();
        if (body.length > MAX_PROFILE_BYTES) return text("Too large", 413);
        try {
          JSON.parse(body);
        } catch {
          return text("Invalid JSON", 400);
        }
        await env.PRIVATE.put(key, body, {
          httpMetadata: { contentType: "application/json" },
        });
        return json({ ok: true });
      }

      if (request.method === "DELETE") {
        await env.PRIVATE.delete(key);
        return json({ ok: true });
      }

      return text("Method not allowed", 405);
    }

    // ---------- অ্যাডমিন: যেকোনো প্রার্থীর সিভি পড়া ----------
    const adminMatch = path.match(/^\/admin\/profile\/([A-Za-z0-9_-]{6,128})$/);
    if (adminMatch && request.method === "GET") {
      const user = await verifyUser(request, env);
      if (!isAdminUser(user)) return text("Forbidden", 403);

      const obj = await env.PRIVATE.get(`profiles/${adminMatch[1]}.json`);
      if (!obj) return json({});
      return json(await obj.json());
    }

    return text("Not found", 404);
  },
};
