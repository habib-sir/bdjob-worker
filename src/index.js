const ALLOWED_ORIGIN = "https://bdjobapply.site";
const ADMIN_EMAILS = ["habiblinkage@gmail.com", "masterboom2040@gmail.com"];
// Firebase Web API key প্রকাশ্য (frontend-এও থাকে), তাই এটি গোপন নয়
const DEFAULT_FIREBASE_API_KEY = "AIzaSyC2SQchoqvoeEhtMhZo2Uhvs9sjiQziYso";
const MAX_PROFILE_BYTES = 300000;
const MAX_PUBLIC_JSON_BYTES = 100000;
const MAX_UPLOAD_BYTES = 500000;
const MAX_FILE_CHARS = 1400000;
const MAX_APPLICATION_CHARS = 60000;

const APP_STATUSES = ["waiting", "apply_now", "checking", "correction", "payment_now", "applied", "rejected"];

// অ্যাডমিন যে public JSON ফাইলগুলো লিখতে পারবে (নাম -> R2 ফাইল)
const PUBLIC_JSON_FILES = {
  "settings-payment": "settings-payment.json",
  "exams": "exams.json",
};

// অ্যাডমিন যে ফোল্ডারে ছবি আপলোড করতে পারবে
const UPLOAD_FOLDERS = ["exams"];
const IMAGE_TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };

function cors(extra = {}) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, PUT, POST, PATCH, DELETE, OPTIONS",
    ...extra,
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: cors({ "Content-Type": "application/json", "Cache-Control": "no-store" }),
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

async function requireAdmin(request, env) {
  const user = await verifyUser(request, env);
  return isAdminUser(user) ? user : null;
}

// ---------- আবেদন (D1) ----------

function dateCode(d = new Date()) {
  const yy = String(d.getUTCFullYear()).slice(-2);
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yy}${mm}${dd}`;
}

const isValidMobile = (m) => /^01[3-9]\d{8}$/.test(String(m || ""));

async function readJobs(env) {
  const obj = await env.BUCKET.get("jobs.json");
  return obj ? await obj.json() : [];
}

// POST /api/applications (ব্যবহারকারী)
async function handleSubmitApplication(request, env, user) {
  const raw = await request.text();
  if (raw.length > MAX_APPLICATION_CHARS) return text("Too large", 413);
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return text("Invalid JSON", 400);
  }

  const jobId = String(body.jobId || "");
  const postName = String(body.postName || "").trim();
  const smsNumber = String(body.smsNumber || "");
  if (!jobId || !postName) return text("জব ও পদ লাগবে", 400);
  if (!isValidMobile(smsNumber)) return text("সঠিক মোবাইল নম্বর দিন", 400);

  // জব ও পদ সার্ভার থেকে যাচাই (ফি ও নিয়ম সার্ভারে গণনা)
  const jobs = await readJobs(env);
  const job = jobs.find((j) => j.id === jobId || j.slug === jobId);
  if (!job) return text("চাকরির বিজ্ঞপ্তিটি পাওয়া যায়নি", 404);
  if (job.status === "draft") return text("এই বিজ্ঞপ্তিতে এখন আবেদন নেওয়া হচ্ছে না", 400);
  if (job.deadline && new Date(job.deadline).getTime() < Date.now()) {
    return text("আবেদনের শেষ সময় পার হয়ে গেছে", 400);
  }
  const post = (job.posts || []).find((p) => p.name === postName);
  if (!post) return text("এই পদটি বিজ্ঞপ্তিতে নেই", 400);

  // একই সার্কুলারে একাধিক পদ: শুধু চালু থাকলে অনুমোদিত
  if (!job.allowMultiplePosts) {
    const existing = await env.DB.prepare(
      "SELECT id FROM applications WHERE uid = ? AND job_id = ? LIMIT 1"
    ).bind(user.uid, job.id).first();
    if (existing) {
      return text("এই সার্কুলারে ইতিপূর্বে আপনি আবেদন করেছেন", 409);
    }
  }

  const appFee = Number(post.applicationFee ?? job.applicationFee ?? 0) || 0;
  const serviceCharge = Number(post.serviceCharge ?? job.serviceCharge ?? 10) || 0;
  const now = new Date().toISOString();

  // আবেদন নম্বর: APL-YYMMDD-NNNN (দিনভিত্তিক ক্রম, একই সময়ে নিরাপদ)
  const code = dateCode();
  const counter = await env.DB.prepare(
    "INSERT INTO counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1 RETURNING value"
  ).bind(`app_${code}`).first();
  const id = `APL-${code}-${String(counter.value).padStart(4, "0")}`;

  const data = {
    jobTitle: job.title || "",
    applyLink: job.applyLink || "",
    postCount: post.count || 1,
    district: body.district || "",
    educationLevel: body.educationLevel || "",
    fee: { applicationFee: appFee, serviceCharge, total: appFee + serviceCharge },
    payment: {
      method: body.payment?.method || "",
      senderNumber: String(body.payment?.senderNumber || ""),
      amount: appFee + serviceCharge,
      submittedAt: now,
    },
    hasScreenshot: Boolean(body.hasScreenshot),
    fullName: String(body.fullName || "").slice(0, 200),
  };

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO applications (id, uid, job_id, post_name, full_name, mobile, status, data, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?)`
      ).bind(id, user.uid, job.id, postName, data.fullName, smsNumber, JSON.stringify(data), now, now),
      env.DB.prepare("UPDATE application_stats SET total = total + 1 WHERE status = 'waiting'"),
    ]);
  } catch (err) {
    if (String(err?.message || err).includes("UNIQUE")) {
      return text("এই পদে ইতিপূর্বে আপনি আবেদন করেছেন", 409);
    }
    console.error("Application insert failed:", err);
    return text("আবেদন সংরক্ষণ ব্যর্থ হয়েছে। আবার চেষ্টা করুন।", 500);
  }

  return json({ ok: true, application: { id, status: "waiting", createdAt: now } });
}

// GET /api/applications/my (ব্যবহারকারী, নিজের আবেদন)
async function handleMyApplications(env, user) {
  const rs = await env.DB.prepare(
    "SELECT id, job_id, post_name, status, created_at, updated_at, data FROM applications WHERE uid = ? ORDER BY created_at DESC LIMIT 200"
  ).bind(user.uid).all();

  const items = (rs.results || []).map((r) => ({
    id: r.id,
    jobId: r.job_id,
    postName: r.post_name,
    status: r.status,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    ...(JSON.parse(r.data || "{}")),
  }));
  return json({ items });
}

// GET /api/admin/applications?status=waiting,checking&page=1&limit=50&q=...
async function handleAdminList(url, env) {
  const statusParam = url.searchParams.get("status") || "waiting";
  const statuses = statusParam.split(",").filter((s) => APP_STATUSES.includes(s));
  if (statuses.length === 0) return text("Bad status", 400);

  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 100);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10) || 1, 1);
  const offset = (page - 1) * limit;
  const q = (url.searchParams.get("q") || "").trim().slice(0, 100);

  let sql = `SELECT id, uid, job_id, post_name, full_name, mobile, status, created_at, updated_at
             FROM applications WHERE status IN (${statuses.map(() => "?").join(",")})`;
  const binds = [...statuses];
  if (q) {
    sql += " AND (id LIKE ? OR mobile LIKE ? OR full_name LIKE ?)";
    const like = `%${q}%`;
    binds.push(like, like, like);
  }
  sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  binds.push(limit + 1, offset);

  const rs = await env.DB.prepare(sql).bind(...binds).all();
  const rows = rs.results || [];
  const hasNext = rows.length > limit;

  return json({
    items: rows.slice(0, limit).map((r) => ({
      id: r.id,
      uid: r.uid,
      jobId: r.job_id,
      postName: r.post_name,
      fullName: r.full_name,
      mobile: r.mobile,
      status: r.status,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    })),
    page,
    limit,
    hasNext,
  });
}

// GET /api/admin/applications/:id
async function handleAdminDetail(id, env) {
  const row = await env.DB.prepare("SELECT * FROM applications WHERE id = ?").bind(id).first();
  if (!row) return text("Not found", 404);
  return json({
    id: row.id,
    uid: row.uid,
    jobId: row.job_id,
    postName: row.post_name,
    fullName: row.full_name,
    mobile: row.mobile,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...JSON.parse(row.data || "{}"),
  });
}

// PATCH /api/admin/applications/:id  { status?, data? }
async function handleAdminPatch(id, request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return text("Invalid JSON", 400);
  }

  const row = await env.DB.prepare("SELECT status, data FROM applications WHERE id = ?").bind(id).first();
  if (!row) return text("Not found", 404);

  const nextStatus = body.status && APP_STATUSES.includes(body.status) ? body.status : row.status;
  const merged = { ...JSON.parse(row.data || "{}"), ...(body.data && typeof body.data === "object" ? body.data : {}) };
  const now = new Date().toISOString();

  const statements = [
    env.DB.prepare("UPDATE applications SET status = ?, data = ?, updated_at = ? WHERE id = ?")
      .bind(nextStatus, JSON.stringify(merged), now, id),
  ];
  if (nextStatus !== row.status) {
    statements.push(
      env.DB.prepare("UPDATE application_stats SET total = total - 1 WHERE status = ?").bind(row.status),
      env.DB.prepare("UPDATE application_stats SET total = total + 1 WHERE status = ?").bind(nextStatus)
    );
  }
  await env.DB.batch(statements);

  return json({ ok: true, id, status: nextStatus, updatedAt: now });
}

// GET /api/admin/stats (ড্যাশবোর্ড সংখ্যা, খুব কম read)
async function handleAdminStats(env) {
  const rs = await env.DB.prepare("SELECT status, total FROM application_stats").all();
  const stats = {};
  for (const r of rs.results || []) stats[r.status] = r.total;
  return json({ stats });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const isAdminToken = request.headers.get("Authorization") === `Bearer ${env.ADMIN_TOKEN}`;

    // ---------- আবেদন: ব্যবহারকারী ----------
    if (path === "/api/applications" && request.method === "POST") {
      const user = await verifyUser(request, env);
      if (!user) return text("Unauthorized", 401);
      return handleSubmitApplication(request, env, user);
    }

    if (path === "/api/applications/my" && request.method === "GET") {
      const user = await verifyUser(request, env);
      if (!user) return text("Unauthorized", 401);
      return handleMyApplications(env, user);
    }

    // ---------- আবেদন: অ্যাডমিন ----------
    if (path === "/api/admin/applications" && request.method === "GET") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleAdminList(url, env);
    }

    const adminAppMatch = path.match(/^\/api\/admin\/applications\/([A-Za-z0-9-]{4,60})$/);
    if (adminAppMatch && request.method === "GET") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleAdminDetail(adminAppMatch[1], env);
    }
    if (adminAppMatch && request.method === "PATCH") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleAdminPatch(adminAppMatch[1], request, env);
    }

    if (path === "/api/admin/stats" && request.method === "GET") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleAdminStats(env);
    }

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

    // ---------- পাবলিক JSON লেখা (অ্যাডমিন টোকেন) ----------
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

    // ---------- পাবলিক ছবি আপলোড (অ্যাডমিন টোকেন) ----------
    const uploadMatch = path.match(/^\/admin\/upload\/([a-z]+)\/([a-z0-9-]+\.(?:jpg|png|webp))$/);
    if (uploadMatch && request.method === "PUT") {
      if (!isAdminToken) return text("Unauthorized", 401);

      const [, folder, file] = uploadMatch;
      if (!UPLOAD_FOLDERS.includes(folder)) return text("Unknown folder", 404);

      const type = (request.headers.get("Content-Type") || "").split(";")[0];
      const ext = IMAGE_TYPES[type];
      if (!ext || !file.endsWith("." + ext)) return text("Bad image type", 400);

      const buf = await request.arrayBuffer();
      if (buf.byteLength > MAX_UPLOAD_BYTES) return text("Too large", 413);

      const key = `${folder}/${file}`;
      await env.BUCKET.put(key, buf, {
        httpMetadata: { contentType: type, cacheControl: "public, max-age=3600" },
      });
      return json({ ok: true, url: `https://files.bdjobapply.site/${key}` });
    }

    // ---------- কভার ইমেজ (অ্যাডমিন ইমেইল, পাবলিক R2) ----------
    const coverMatch = path.match(/^\/cover\/([A-Za-z0-9_-]{3,160})$/);
    if (coverMatch && request.method === "PUT") {
      const user = await verifyUser(request, env);
      if (!isAdminUser(user)) return text("Forbidden", 403);

      const body = await request.text();
      if (body.length > MAX_FILE_CHARS) return text("Too large", 413);
      let doc;
      try {
        doc = JSON.parse(body);
      } catch {
        return text("Invalid JSON", 400);
      }
      if (doc.kind !== "cover" || typeof doc.data !== "string") return text("Bad body", 400);

      await env.BUCKET.put(`files/${coverMatch[1]}.json`, body, {
        httpMetadata: {
          contentType: "application/json",
          cacheControl: "public, max-age=3600",
        },
      });
      return json({ ok: true });
    }

    // ---------- প্রাইভেট ফাইল: ছবি, স্বাক্ষর, স্ক্রিনশট, সফট/পেইড কপি ----------
    const fileMatch = path.match(/^\/file\/([A-Za-z0-9_-]{3,160})$/);
    if (fileMatch) {
      const user = await verifyUser(request, env);
      if (!user) return text("Unauthorized", 401);

      const admin = isAdminUser(user);
      const key = `files/${fileMatch[1]}.json`;

      if (request.method === "GET") {
        const obj = await env.PRIVATE.get(key);
        if (!obj) return text("Not found", 404);
        const doc = await obj.json();
        if (!admin && doc.ownerUid !== user.uid) return text("Forbidden", 403);
        return json(doc);
      }

      if (request.method === "PUT") {
        const body = await request.text();
        if (body.length > MAX_FILE_CHARS) return text("Too large", 413);
        let doc;
        try {
          doc = JSON.parse(body);
        } catch {
          return text("Invalid JSON", 400);
        }
        if (typeof doc.data !== "string" || typeof doc.ownerUid !== "string") {
          return text("Bad body", 400);
        }
        if (!admin) {
          // সাধারণ ব্যবহারকারী শুধু নিজের ফাইল লিখতে পারবে
          if (doc.ownerUid !== user.uid) return text("Forbidden", 403);
          const old = await env.PRIVATE.get(key);
          if (old) {
            const oldDoc = await old.json();
            if (oldDoc.ownerUid !== user.uid) return text("Forbidden", 403);
          }
        }
        await env.PRIVATE.put(key, body, {
          httpMetadata: { contentType: "application/json" },
        });
        return json({ ok: true });
      }

      if (request.method === "DELETE") {
        if (!admin) {
          const old = await env.PRIVATE.get(key);
          if (old) {
            const oldDoc = await old.json();
            if (oldDoc.ownerUid !== user.uid) return text("Forbidden", 403);
          }
        }
        await env.PRIVATE.delete(key);
        return json({ ok: true });
      }

      return text("Method not allowed", 405);
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
