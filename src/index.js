const ALLOWED_ORIGIN = "https://bdjobapply.site";
const ADMIN_EMAILS = ["habiblinkage@gmail.com", "masterboom2040@gmail.com"];
// Firebase Web API key প্রকাশ্য (frontend-এও থাকে), তাই এটি গোপন নয়
const DEFAULT_FIREBASE_API_KEY = "AIzaSyC2SQchoqvoeEhtMhZo2Uhvs9sjiQziYso";
const DEFAULT_FIREBASE_PROJECT_ID = "gen-lang-client-0467244762";
const DEFAULT_USER_EMAIL_DOMAIN = "@users.app.local";
const MAX_PROFILE_BYTES = 300000;
const MAX_PUBLIC_JSON_BYTES = 100000;
const MAX_UPLOAD_BYTES = 500000;
const MAX_FILE_CHARS = 1400000;
const MAX_APPLICATION_CHARS = 60000;
const MAX_PREP_BYTES = 3000000;
const RESET_MAX_FAILS = 5;
const RESET_BLOCK_MS = 30 * 60 * 1000;
const URGENT_MS = 2 * 24 * 60 * 60 * 1000;

// ---------- সার্কুলার আর্কাইব ----------
const ARCHIVE_GRACE_MS = 2 * 24 * 60 * 60 * 1000;
const ACTIVE_JOBS_FILE = "jobs.json";
const FEED_LIMIT = 15;
const ARCHIVE_INDEX_FILE = "jobs/archive/index.json";

// ---------- চাকরির প্রস্তুতি ----------
const PREP_FILE = "prep-data.json";
const PREP_META_FILE = "prep-meta.json";

const APP_STATUSES = ["waiting", "apply_now", "checking", "correction", "payment_now", "applied", "rejected", "cancelled"];
const OPEN_STATUSES = ["waiting", "apply_now", "checking", "correction", "payment_now"];

const PUBLIC_JSON_FILES = {
  "settings-payment": "settings-payment.json",
  "exams": "exams.json",
};

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

const isValidMobile = (m) => /^01[3-9]\d{8}$/.test(String(m || ""));

function projectIdOf(env) {
  return env.FIREBASE_PROJECT_ID || DEFAULT_FIREBASE_PROJECT_ID;
}

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

// ---------- Google সার্ভিস অ্যাকাউন্ট ----------
function b64url(buf) {
  let s = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function strB64url(s) {
  return b64url(new TextEncoder().encode(s));
}

function pemToDer(pem) {
  let s = String(pem || "");
  s = s.replace(/\\n/g, "\n").replace(/\r/g, "");
  s = s.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "");
  s = s.replace(/[^A-Za-z0-9+/=]/g, "");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

async function signSaJwt(env, payload) {
  const header = strB64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = strB64url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(env.FIREBASE_SA_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(`${header}.${body}`)
  );
  return `${header}.${body}.${b64url(sig)}`;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const assertion = await signSaJwt(env, {
    iss: env.FIREBASE_SA_EMAIL,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  });

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${assertion}`,
  });
  if (!res.ok) throw new Error("Google token লাগানো যায়নি");
  return (await res.json()).access_token;
}

async function createCustomToken(env, uid) {
  const now = Math.floor(Date.now() / 1000);
  return signSaJwt(env, {
    iss: env.FIREBASE_SA_EMAIL,
    sub: env.FIREBASE_SA_EMAIL,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
  });
}

async function lookupUserByMobile(env, mobile) {
  const domain = env.USER_EMAIL_DOMAIN || DEFAULT_USER_EMAIL_DOMAIN;
  const email = `${mobile}${domain}`;
  const token = await getGoogleAccessToken(env);
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/projects/${projectIdOf(env)}/accounts:lookup`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: [email] }),
    }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return (data.users && data.users[0]) || null;
}

async function setAuthPassword(env, uid, password) {
  const token = await getGoogleAccessToken(env);
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/projects/${projectIdOf(env)}/accounts:update`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ localId: uid, password }),
    }
  );
  if (!res.ok) throw new Error(`পাসওয়ার্ড বদলানো যায়নি (HTTP ${res.status})`);
}

// ---------- মাস্টার পাসওয়ার্ড ----------
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function checkMaster(env, given) {
  return !!env.MASTER_PASSWORD && safeEqual(String(given || ""), env.MASTER_PASSWORD);
}

// ---------- জন্মতারিখ রিসেট: ভুল চেষ্টার সীমা ----------
async function rateOk(env, key) {
  const row = await env.DB.prepare("SELECT blocked_until FROM reset_attempts WHERE key = ?").bind(key).first();
  return !(row && row.blocked_until > Date.now());
}

async function recordFail(env, key) {
  const until = Date.now() + RESET_BLOCK_MS;
  await env.DB.prepare(
    `INSERT INTO reset_attempts (key, count, blocked_until) VALUES (?, 1, 0)
     ON CONFLICT(key) DO UPDATE SET
       count = count + 1,
       blocked_until = CASE WHEN count + 1 >= ? THEN ? ELSE blocked_until END`
  ).bind(key, RESET_MAX_FAILS, until).run();
}

async function clearFail(env, key) {
  await env.DB.prepare("DELETE FROM reset_attempts WHERE key = ?").bind(key).run();
}

function normDob(v) {
  const s = String(v || "").trim();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : s;
}

// ---------- ধাপের মোবাইল-তালিকা ----------
const pipelineKey = (status) => `pipeline/${status}.txt`;

async function readPipeline(env, status) {
  const obj = await env.PRIVATE.get(pipelineKey(status));
  if (!obj) return [];
  const raw = await obj.text();
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

async function writePipeline(env, status, numbers) {
  await env.PRIVATE.put(pipelineKey(status), [...new Set(numbers)].join(", "), {
    httpMetadata: { contentType: "text/plain; charset=utf-8" },
  });
}

async function addToPipeline(env, status, mobile) {
  const list = await readPipeline(env, status);
  if (!list.includes(mobile)) list.push(mobile);
  await writePipeline(env, status, list);
}

async function removeFromPipeline(env, status, mobile) {
  const list = await readPipeline(env, status);
  await writePipeline(env, status, list.filter((m) => m !== mobile));
}

async function rebuildPipeline(env, status) {
  const rs = await env.DB.prepare(
    "SELECT mobile FROM applications WHERE status = ? ORDER BY deadline IS NULL, deadline ASC, created_at DESC"
  ).bind(status).all();
  await writePipeline(env, status, (rs.results || []).map((r) => r.mobile).filter(Boolean));
}

// ---------- ডেডলাইনের অবস্থা ----------
function deadlineStatusOf(deadline) {
  if (!deadline) return "none";
  const diff = new Date(deadline).getTime() - Date.now();
  if (isNaN(diff)) return "none";
  if (diff < 0) return "expired";
  if (diff <= URGENT_MS) return "urgent";
  return "normal";
}

// ---------- R2 JSON সহায়ক ----------
async function readR2Json(env, key, fallback) {
  const obj = await env.BUCKET.get(key);
  if (!obj) return fallback;
  try {
    return await obj.json();
  } catch {
    return fallback;
  }
}

async function writeR2Json(env, key, data, cacheControl = "public, max-age=60") {
  await env.BUCKET.put(key, JSON.stringify(data), {
    httpMetadata: { contentType: "application/json", cacheControl },
  });
}

// ---------- সার্কুলার: চলমান / আর্কাইব ----------
const jobEndTime = (j) => {
  if (!j || !j.deadline) return null;
  const t = new Date(j.deadline).getTime();
  return isNaN(t) ? null : t;
};

const isLiveJob = (j, now) => {
  if (j.status === "draft") return true;
  const t = jobEndTime(j);
  if (t === null) return true;
  return t + ARCHIVE_GRACE_MS >= now;
};

const archiveMonthOf = (j) => {
  const t = jobEndTime(j);
  if (t === null) return null;
  const d = new Date(t);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
};

const archiveFileOf = (month) => `jobs/archive/${month}.json`;

async function writeActiveJobs(env, activeJobs) {
  await writeR2Json(env, ACTIVE_JOBS_FILE, activeJobs, "public, max-age=60");

  const feedPosts = activeJobs
    .filter((j) => j.status !== "draft")
    .map((j) => ({
      id: j.id,
      title: j.title || "",
      slug: j.slug || j.id,
      category: j.category || "govt",
      deadline: j.deadline,
      publishedAt: j.publishedAt,
      applyServiceEnabled: Boolean(j.applyServiceEnabled),
      featuredImage: j.featuredImage || j.circularImages?.[0] || null,
    }))
    .slice(0, FEED_LIMIT);

  await writeR2Json(env, "feed.json", { posts: feedPosts, updatedAt: new Date().toISOString() }, "public, max-age=60");
}

async function archiveJobs(env, jobs) {
  if (!jobs.length) return;

  const byMonth = new Map();
  for (const j of jobs) {
    const m = archiveMonthOf(j);
    if (!m) continue;
    if (!byMonth.has(m)) byMonth.set(m, []);
    byMonth.get(m).push(j);
  }

  for (const [month, list] of byMonth) {
    const key = archiveFileOf(month);
    const existing = await readR2Json(env, key, []);
    const map = new Map(existing.map((j) => [j.id, j]));
    for (const j of list) map.set(j.id, j);
    await writeR2Json(env, key, [...map.values()], "public, max-age=3600");
  }

  const index = await readR2Json(env, ARCHIVE_INDEX_FILE, []);
  const idx = new Map(index.map((e) => [e.id, e]));
  for (const j of jobs) {
    const m = archiveMonthOf(j);
    if (!m) continue;
    idx.set(j.id, { id: j.id, slug: j.slug || j.id, title: j.title || "", month: m, deadline: j.deadline });
  }
  await writeR2Json(env, ARCHIVE_INDEX_FILE, [...idx.values()], "public, max-age=3600");
}

async function removeArchivedJob(env, id, month) {
  const key = archiveFileOf(month);
  const list = await readR2Json(env, key, []);
  await writeR2Json(env, key, list.filter((j) => j.id !== id), "public, max-age=3600");

  const index = await readR2Json(env, ARCHIVE_INDEX_FILE, []);
  await writeR2Json(env, ARCHIVE_INDEX_FILE, index.filter((e) => e.id !== id), "public, max-age=3600");
}

async function saveJobsWithArchive(env, posted) {
  const now = Date.now();
  const live = posted.filter((j) => isLiveJob(j, now));
  const expired = posted.filter((j) => !isLiveJob(j, now));

  // আর্কাইবে থাকা সার্কুলার আবার চলমান হলে আর্কাইব থেকে সরবে
  const index = await readR2Json(env, ARCHIVE_INDEX_FILE, []);
  for (const j of live) {
    const entry = index.find((e) => e.id === j.id);
    if (entry) await removeArchivedJob(env, j.id, entry.month);
  }

  await archiveJobs(env, expired);
  await writeActiveJobs(env, live);
  return { live: live.length, archived: expired.length };
}

async function rotateExpiredJobs(env) {
  const active = await readR2Json(env, ACTIVE_JOBS_FILE, []);
  const now = Date.now();
  const keep = active.filter((j) => isLiveJob(j, now));
  const move = active.filter((j) => !isLiveJob(j, now));
  if (move.length === 0) return;
  await archiveJobs(env, move);
  await writeActiveJobs(env, keep);
}

async function findArchivedJob(env, id) {
  const index = await readR2Json(env, ARCHIVE_INDEX_FILE, []);
  const entry = index.find((e) => e.id === id);
  if (!entry) return { entry: null, job: null };
  const list = await readR2Json(env, archiveFileOf(entry.month), []);
  const job = list.find((j) => j.id === id) || null;
  return { entry, job };
}

// GET / PUT / PATCH / DELETE /api/admin/archive/:id
async function handleArchiveAdmin(id, request, env, method) {
  const { entry, job } = await findArchivedJob(env, id);
  if (!entry || !job) return text("Not found", 404);

  if (method === "GET") return json(job);

  if (method === "DELETE") {
    await removeArchivedJob(env, id, entry.month);
    return json({ ok: true, deleted: id });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return text("Invalid JSON", 400);
  }

  const next = { ...job, ...body, id };
  delete next.archived;

  if (isLiveJob(next, Date.now())) {
    await removeArchivedJob(env, id, entry.month);
    const active = await readR2Json(env, ACTIVE_JOBS_FILE, []);
    await writeActiveJobs(env, [next, ...active.filter((j) => j.id !== id)]);
    return json({ ok: true, moved: "active" });
  }

  const newMonth = archiveMonthOf(next);
  const monthChanged = newMonth !== entry.month;
  if (monthChanged) {
    await removeArchivedJob(env, id, entry.month);
  }
  await archiveJobs(env, [next]);
  return json({ ok: true, moved: monthChanged ? "archive-month" : "archive", month: newMonth });
}

// ---------- আবেদন (D1) ----------
function dateCode(d = new Date()) {
  const yy = String(d.getUTCFullYear()).slice(-2);
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yy}${mm}${dd}`;
}

async function findJobForApplication(env, jobId) {
  const active = await readR2Json(env, ACTIVE_JOBS_FILE, []);
  return active.find((j) => j.id === jobId || j.slug === jobId) || null;
}

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

  const job = await findJobForApplication(env, jobId);
  if (!job) return text("চাকরির বিজ্ঞপ্তিটি পাওয়া যায়নি বা আবেদনের সময় শেষ", 404);
  if (job.status === "draft") return text("এই বিজ্ঞপ্তিতে এখন আবেদন নেওয়া হচ্ছে না", 400);
  if (job.deadline && new Date(job.deadline).getTime() < Date.now()) {
    return text("আবেদনের শেষ সময় পার হয়ে গেছে", 400);
  }
  const post = (job.posts || []).find((p) => p.name === postName);
  if (!post) return text("এই পদটি বিজ্ঞপ্তিতে নেই", 400);

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
  const deadline = job.deadline ? new Date(job.deadline).toISOString() : null;

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
        `INSERT INTO applications (id, uid, job_id, post_name, full_name, mobile, status, data, deadline, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?)`
      ).bind(id, user.uid, job.id, postName, data.fullName, smsNumber, JSON.stringify(data), deadline, now, now),
      env.DB.prepare("UPDATE application_stats SET total = total + 1 WHERE status = 'waiting'"),
    ]);
  } catch (err) {
    if (String(err?.message || err).includes("UNIQUE")) {
      return text("এই পদে ইতিপূর্বে আপনি আবেদন করেছেন", 409);
    }
    console.error("Application insert failed:", err);
    return text("আবেদন সংরক্ষণ ব্যর্থ হয়েছে। আবার চেষ্টা করুন।", 500);
  }

  await addToPipeline(env, "waiting", smsNumber);
  return json({ ok: true, application: { id, status: "waiting", createdAt: now } });
}

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

async function handleUserReview(id, request, env, user) {
  let body;
  try {
    body = await request.json();
  } catch {
    return text("Invalid JSON", 400);
  }

  const row = await env.DB.prepare("SELECT uid, mobile, status, data FROM applications WHERE id = ?").bind(id).first();
  if (!row) return text("Not found", 404);
  if (row.uid !== user.uid) return text("Forbidden", 403);
  if (row.status !== "checking") return text("এই আবেদনটি এখন যাচাইয়ের ধাপে নেই", 409);

  const now = new Date().toISOString();
  const data = JSON.parse(row.data || "{}");
  let nextStatus;

  if (body.action === "approve") {
    nextStatus = "payment_now";
  } else if (body.action === "correction") {
    const note = String(body.note || "").trim().slice(0, 1000);
    if (!note) return text("সংশোধনের বিবরণ লিখুন", 400);
    nextStatus = "correction";
    data.correctionNote = note;
  } else {
    return text("Bad action", 400);
  }

  await env.DB.batch([
    env.DB.prepare("UPDATE applications SET status = ?, data = ?, updated_at = ? WHERE id = ?")
      .bind(nextStatus, JSON.stringify(data), now, id),
    env.DB.prepare("UPDATE application_stats SET total = total - 1 WHERE status = 'checking'"),
    env.DB.prepare("UPDATE application_stats SET total = total + 1 WHERE status = ?").bind(nextStatus),
  ]);

  await removeFromPipeline(env, "checking", row.mobile);
  await addToPipeline(env, nextStatus, row.mobile);

  return json({ ok: true, id, status: nextStatus, updatedAt: now });
}

async function handleAdminList(url, env) {
  const statusParam = url.searchParams.get("status") || "waiting";
  const statuses = statusParam.split(",").filter((s) => APP_STATUSES.includes(s));
  if (statuses.length === 0) return text("Bad status", 400);

  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "10", 10) || 10, 1), 100);
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10) || 1, 1);
  const offset = (page - 1) * limit;
  const q = (url.searchParams.get("q") || "").trim().slice(0, 100);

  let sql = `SELECT id, uid, job_id, post_name, full_name, mobile, status, deadline, created_at, updated_at, data
             FROM applications WHERE status IN (${statuses.map(() => "?").join(",")})`;
  const binds = [...statuses];
  if (q) {
    sql += " AND (id LIKE ? OR mobile LIKE ? OR full_name LIKE ?)";
    const like = `%${q}%`;
    binds.push(like, like, like);
  }
  sql += " ORDER BY deadline IS NULL, deadline ASC, created_at DESC LIMIT ? OFFSET ?";
  binds.push(limit + 1, offset);

  const rs = await env.DB.prepare(sql).bind(...binds).all();
  const rows = rs.results || [];
  const hasNext = rows.length > limit;

  return json({
    items: rows.slice(0, limit).map((r) => {
      const d = JSON.parse(r.data || "{}");
      return {
        id: r.id,
        uid: r.uid,
        jobId: r.job_id,
        postName: r.post_name,
        fullName: r.full_name,
        mobile: r.mobile,
        status: r.status,
        deadline: r.deadline,
        deadlineStatus: deadlineStatusOf(r.deadline),
        createdAt: r.created_at,
        updatedAt: r.updated_at,
        applyLink: d.applyLink || "",
        refund: {
          method: d.payment?.method || "",
          senderNumber: d.payment?.senderNumber || "",
          amount: d.fee?.total ?? null,
          cancelReason: d.cancelReason || null,
        },
      };
    }),
    page,
    limit,
    hasNext,
  });
}

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
    deadline: row.deadline,
    deadlineStatus: deadlineStatusOf(row.deadline),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...JSON.parse(row.data || "{}"),
  });
}

async function handleAdminPatch(id, request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return text("Invalid JSON", 400);
  }

  const row = await env.DB.prepare("SELECT mobile, status, data FROM applications WHERE id = ?").bind(id).first();
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

  if (nextStatus !== row.status) {
    await removeFromPipeline(env, row.status, row.mobile);
    await addToPipeline(env, nextStatus, row.mobile);
  }

  return json({ ok: true, id, status: nextStatus, updatedAt: now });
}

async function handleAdminStats(env) {
  const rs = await env.DB.prepare("SELECT status, total FROM application_stats").all();
  const stats = {};
  for (const r of rs.results || []) stats[r.status] = r.total;
  return json({ stats });
}

async function handleAdminPipeline(status, env) {
  const numbers = await readPipeline(env, status);
  return json({ status, numbers });
}

// ---------- চাকরির প্রস্তুতি: অ্যাডমিন সংরক্ষণ ----------
function sanitizePrepTopic(t) {
  const items = Array.isArray(t?.items) ? t.items : [];
  return {
    id: String(t?.id || "").slice(0, 80),
    name: String(t?.name || "").slice(0, 200),
    items: items.map((i) => ({
      id: String(i?.id || "").slice(0, 80),
      question: String(i?.question || "").slice(0, 5000),
      answer: String(i?.answer || "").slice(0, 20000),
      note: String(i?.note || "").slice(0, 5000),
      tags: Array.isArray(i?.tags) ? i.tags.slice(0, 20).map((x) => String(x).slice(0, 50)) : [],
    })),
  };
}

// "1.0.3" → "1.0.4"; অবৈধ হলে "1.0.1" থেকে শুরু
function bumpPatch(v) {
  const m = String(v || "").match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return "1.0.1";
  return `${m[1]}.${m[2]}.${Number(m[3]) + 1}`;
}

async function handleAdminPrepSave(request, env) {
  const raw = await request.text();
  if (raw.length > MAX_PREP_BYTES) return text("Too large", 413);
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    return text("Invalid JSON", 400);
  }
  if (!doc || !Array.isArray(doc.topics)) return text("Bad body", 400);

  const current = await readR2Json(env, PREP_FILE, { version: "1.0.0" });
  const version = bumpPatch(current.version);
  const updatedAt = new Date().toISOString();

  const next = {
    version,
    updatedAt,
    topics: doc.topics.map(sanitizePrepTopic),
  };

  await writeR2Json(env, PREP_FILE, next, "public, max-age=60");
  await writeR2Json(env, PREP_META_FILE, { version, updatedAt }, "public, max-age=60");
  return json({ ok: true, version });
}

// ---------- Cron ----------
async function expireDeadlines(env) {
  const now = new Date().toISOString();
  const placeholders = OPEN_STATUSES.map(() => "?").join(",");
  const rs = await env.DB.prepare(
    `SELECT status, COUNT(*) AS n FROM applications
     WHERE deadline IS NOT NULL AND deadline < ? AND status IN (${placeholders})
     GROUP BY status`
  ).bind(now, ...OPEN_STATUSES).all();
  const rows = rs.results || [];
  if (rows.length === 0) return;

  const stmts = [];
  for (const r of rows) {
    stmts.push(
      env.DB.prepare(
        `UPDATE applications
         SET status = 'cancelled', updated_at = ?, data = json_set(data, '$.cancelReason', 'deadline_expired')
         WHERE deadline IS NOT NULL AND deadline < ? AND status = ?`
      ).bind(now, now, r.status),
      env.DB.prepare("UPDATE application_stats SET total = total - ? WHERE status = ?").bind(r.n, r.status),
      env.DB.prepare("UPDATE application_stats SET total = total + ? WHERE status = 'cancelled'").bind(r.n)
    );
  }
  await env.DB.batch(stmts);

  for (const r of rows) await rebuildPipeline(env, r.status);
  await rebuildPipeline(env, "cancelled");
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(Promise.all([expireDeadlines(env), rotateExpiredJobs(env)]));
  },

  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const isAdminToken = request.headers.get("Authorization") === `Bearer ${env.ADMIN_TOKEN}`;

    // ---------- মাস্টার: যেকোনো ব্যবহারকারীর হয়ে লগইন ----------
    if (path === "/admin/impersonate" && request.method === "POST") {
      let step = "body";
      try {
        const body = await request.json().catch(() => null);

        step = "master";
        if (!checkMaster(env, body?.masterPassword)) {
          return json({ ok: false, step, error: "মাস্টার পাসওয়ার্ড ভুল" }, 401);
        }

        const mobile = String(body?.mobile || "").replace(/\D/g, "");
        if (!isValidMobile(mobile)) return json({ ok: false, step, error: "সঠিক মোবাইল নম্বর দিন" }, 400);

        step = "pem";
        pemToDer(env.FIREBASE_SA_PRIVATE_KEY);

        step = "google-token";
        await getGoogleAccessToken(env);

        step = "lookup";
        const user = await lookupUserByMobile(env, mobile);
        if (!user) return json({ ok: false, step, error: "এই নম্বরে কোনো অ্যাকাউন্ট নেই" }, 404);
        if (ADMIN_EMAILS.includes((user.email || "").toLowerCase())) {
          return json({ ok: false, step, error: "অ্যাডমিন অ্যাকাউন্টে এভাবে লগইন করা যাবে না" }, 403);
        }

        step = "sign";
        const customToken = await createCustomToken(env, user.localId);
        return json({ ok: true, customToken });
      } catch (err) {
        return json({ ok: false, step, error: String(err?.message || err).slice(0, 200) }, 500);
      }
    }

    // ---------- মাস্টার: যেকোনো ব্যবহারকারীর পাসওয়ার্ড বদল ----------
    if (path === "/admin/reset-password" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      if (!checkMaster(env, body?.masterPassword)) return json({ ok: false, error: "মাস্টার পাসওয়ার্ড ভুল" }, 401);

      const mobile = String(body?.mobile || "").replace(/\D/g, "");
      const newPassword = String(body?.newPassword || "");
      if (!isValidMobile(mobile) || newPassword.length < 6) {
        return json({ ok: false, error: "মোবাইল ও নতুন পাসওয়ার্ড (৬+) দিন" }, 400);
      }
      const user = await lookupUserByMobile(env, mobile);
      if (!user) return json({ ok: false, error: "এই নম্বরে কোনো অ্যাকাউন্ট নেই" }, 404);

      try {
        await setAuthPassword(env, user.localId, newPassword);
      } catch (err) {
        return json({ ok: false, error: err?.message || "পাসওয়ার্ড বদলানো যায়নি" }, 500);
      }
      return json({ ok: true });
    }

    // ---------- ব্যবহারকারী: জন্মতারিখ দিয়ে পাসওয়ার্ড রিসেট ----------
    if (path === "/auth/reset/check" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      const mobile = String(body?.mobile || "").replace(/\D/g, "");
      const dob = String(body?.dob || "").trim();
      if (!isValidMobile(mobile) || !/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
        return json({ ok: false, error: "মোবাইল ও জন্মতারিখ সঠিকভাবে দিন" }, 400);
      }

      const key = `m:${mobile}`;
      if (!(await rateOk(env, key))) {
        return json({ ok: false, error: "অনেকবার ভুল চেষ্টা হয়েছে। ৩০ মিনিট পর আবার চেষ্টা করুন।" }, 429);
      }

      const user = await lookupUserByMobile(env, mobile);
      let match = false;
      if (user) {
        const o = await env.PRIVATE.get(`profiles/${user.localId}.json`);
        if (o) {
          const p = await o.json();
          match = normDob(p?.data?.dateOfBirth) === dob;
        }
      }

      if (!match) {
        await recordFail(env, key);
        return json({ ok: false, error: "তথ্য মেলেনি" }, 400);
      }

      await clearFail(env, key);
      const resetToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
      await env.DB.prepare("INSERT INTO reset_tokens (token, uid, expires_at) VALUES (?, ?, ?)")
        .bind(resetToken, user.localId, Date.now() + 10 * 60 * 1000).run();
      return json({ ok: true, resetToken });
    }

    if (path === "/auth/reset/confirm" && request.method === "POST") {
      const body = await request.json().catch(() => null);
      const token = String(body?.resetToken || "");
      const newPassword = String(body?.newPassword || "");
      if (!token || newPassword.length < 6) {
        return json({ ok: false, error: "নতুন পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে" }, 400);
      }

      const row = await env.DB.prepare("SELECT uid, expires_at FROM reset_tokens WHERE token = ?").bind(token).first();
      if (!row || row.expires_at < Date.now()) {
        return json({ ok: false, error: "সময় শেষ হয়েছে। আবার চেষ্টা করুন।" }, 400);
      }
      await env.DB.prepare("DELETE FROM reset_tokens WHERE token = ?").bind(token).run();

      try {
        await setAuthPassword(env, row.uid, newPassword);
      } catch (err) {
        console.error("Reset failed:", err);
        return json({ ok: false, error: "পাসওয়ার্ড বদলানো যায়নি। পরে আবার চেষ্টা করুন।" }, 500);
      }
      return json({ ok: true });
    }

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

    const reviewMatch = path.match(/^\/api\/applications\/([A-Za-z0-9-]{4,60})\/review$/);
    if (reviewMatch && request.method === "PATCH") {
      const user = await verifyUser(request, env);
      if (!user) return text("Unauthorized", 401);
      return handleUserReview(reviewMatch[1], request, env, user);
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

    const pipeMatch = path.match(/^\/api\/admin\/pipeline\/([a-z_]+)$/);
    if (pipeMatch && request.method === "GET") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      if (!APP_STATUSES.includes(pipeMatch[1])) return text("Bad status", 400);
      return handleAdminPipeline(pipeMatch[1], env);
    }

    // ---------- আর্কাইব: অ্যাডমিন ----------
    const archiveAdminMatch = path.match(/^\/api\/admin\/archive\/([A-Za-z0-9_-]{3,120})$/);
    if (archiveAdminMatch && ["GET", "PUT", "PATCH", "DELETE"].includes(request.method)) {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleArchiveAdmin(archiveAdminMatch[1], request, env, request.method);
    }

    // ---------- চাকরির প্রস্তুতি: অ্যাডমিন সংরক্ষণ ----------
    if (path === "/api/admin/prep" && request.method === "PUT") {
      if (!(await requireAdmin(request, env))) return text("Forbidden", 403);
      return handleAdminPrepSave(request, env);
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

      const result = await saveJobsWithArchive(env, jobs);
      return json({ ok: true, count: jobs.length, ...result });
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

    // ---------- প্রাইভেট ফাইল ----------
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
