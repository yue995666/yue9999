const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const ADMIN_KEY = process.env.ADMIN_KEY || "change-this-admin-key";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "change-this-token-secret";
const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || "";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "membership-db.json");

const PRODUCT = {
  id: "wechat_layout_unlock_001",
  name: "公众号排版会员体验版",
  amountFen: 100,
  currency: "CNY"
};

function nowIso() {
  return new Date().toISOString();
}

function readDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    return { members: [], orders: [], messages: [] };
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDb(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function addMessage(db, type, text, extra = {}) {
  db.messages.unshift({
    id: crypto.randomUUID(),
    type,
    text,
    extra,
    createdAt: nowIso(),
    read: false
  });
}

function sendJson(res, status, payload, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key, X-Payment-Signature",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    ...extraHeaders
  });
  res.end(JSON.stringify(payload));
}

function sendText(res, status, text, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key, X-Payment-Signature",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) {
        reject(new Error("请求体太大"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function safeJson(buffer) {
  if (!buffer.length) return {};
  return JSON.parse(buffer.toString("utf8"));
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(value) {
  return crypto.createHmac("sha256", TOKEN_SECRET).update(value).digest("base64url");
}

function issueToken(memberId) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ memberId, iat: Date.now() }));
  return `${header}.${payload}.${sign(`${header}.${payload}`)}`;
}

function verifyToken(req, db) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) return null;
  if (sign(`${header}.${payload}`) !== signature) return null;
  const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  return db.members.find((member) => member.id === data.memberId) || null;
}

function normalizeContact(contact) {
  return String(contact || "").trim().toLowerCase();
}

function publicMember(member) {
  return {
    id: member.id,
    name: member.name,
    contact: member.contact,
    active: !!member.active,
    activeSince: member.activeSince || null,
    lastPaidOrderId: member.lastPaidOrderId || null
  };
}

function publicOrder(order) {
  return {
    id: order.id,
    productId: order.productId,
    productName: PRODUCT.name,
    amountFen: order.amountFen,
    currency: order.currency,
    channel: order.channel,
    status: order.status,
    memberId: order.memberId,
    memberName: order.memberName,
    memberContact: order.memberContact,
    clientOrderId: order.clientOrderId,
    paidAmountFen: order.paidAmountFen || 0,
    transactionId: order.transactionId || "",
    adminNote: order.adminNote || "",
    createdAt: order.createdAt,
    paidAt: order.paidAt || null
  };
}

function isAdmin(req, url) {
  return req.headers["x-admin-key"] === ADMIN_KEY || url.searchParams.get("key") === ADMIN_KEY;
}

function confirmOrder(db, order, paidAmountFen, options = {}) {
  const paid = Number(paidAmountFen || order.amountFen);
  if (paid < order.amountFen) {
    const error = new Error("到账金额不足，不能开通会员");
    error.status = 400;
    throw error;
  }
  const member = db.members.find((item) => item.id === order.memberId);
  if (!member) {
    const error = new Error("找不到订单对应会员");
    error.status = 404;
    throw error;
  }

  order.status = "paid";
  order.paidAmountFen = paid;
  order.paidAt = options.paidAt || nowIso();
  order.transactionId = options.transactionId || order.transactionId || "";
  order.adminNote = options.note || order.adminNote || "";
  order.confirmedBy = options.confirmedBy || "system";

  member.active = true;
  member.activeSince = member.activeSince || order.paidAt;
  member.lastPaidOrderId = order.id;
  member.updatedAt = nowIso();

  addMessage(db, "payment_confirmed", `会员 ${member.name} 的 1 元订单已确认到账并开通。`, {
    orderId: order.id,
    memberId: member.id,
    paidAmountFen: paid
  });

  return { member, order };
}

function verifyWebhookSignature(rawBody, signature) {
  if (!PAYMENT_WEBHOOK_SECRET) return false;
  if (!signature) return false;
  const expected = crypto.createHmac("sha256", PAYMENT_WEBHOOK_SECRET).update(rawBody).digest("hex");
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function adminHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>会员后台</title>
  <style>
    *{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;background:#f6f8fb;color:#172033}.top{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:18px 22px;background:#fff;border-bottom:1px solid #e6edf5;position:sticky;top:0}.wrap{padding:22px;display:grid;gap:18px}.bar{display:flex;gap:10px;flex-wrap:wrap}.bar input{min-height:40px;border:1px solid #d8e1ec;border-radius:8px;padding:0 12px;min-width:260px}.btn{min-height:40px;border:1px solid #ccd8e6;background:#fff;border-radius:8px;padding:0 12px;cursor:pointer}.btn.primary{background:#00a887;color:#fff;border-color:#00a887}.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:18px}.panel{background:#fff;border:1px solid #e6edf5;border-radius:8px;overflow:hidden}.panel h2{margin:0;padding:15px 16px;font-size:16px;border-bottom:1px solid #eef3f8}.list{display:grid}.row{display:grid;grid-template-columns:1fr auto;gap:12px;padding:14px 16px;border-bottom:1px solid #f0f4f8}.row:last-child{border-bottom:0}.meta{color:#667085;font-size:13px;margin-top:5px;line-height:1.5}.tag{display:inline-flex;align-items:center;min-height:24px;border-radius:999px;padding:0 8px;background:#fff7df;color:#6f5210;font-size:12px}.tag.paid{background:#e7fff7;color:#08735b}.actions{display:flex;gap:8px;align-items:start}.empty{padding:16px;color:#667085}.msg{padding:12px 16px;border-bottom:1px solid #f0f4f8}.msg:last-child{border-bottom:0}@media(max-width:820px){.grid{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
  </style>
</head>
<body>
  <header class="top">
    <div><strong>会员后台</strong><div class="meta">查看会员消息、订单，并在真实收到 1 元后开通会员。</div></div>
    <button class="btn" onclick="loadData()">刷新</button>
  </header>
  <main class="wrap">
    <div class="bar">
      <input id="key" type="password" placeholder="后台密钥 ADMIN_KEY">
      <button class="btn primary" onclick="saveKey()">进入后台</button>
    </div>
    <section class="grid">
      <div class="panel"><h2>订单</h2><div id="orders" class="list"><div class="empty">请输入后台密钥。</div></div></div>
      <div class="panel"><h2>会员消息</h2><div id="messages" class="list"><div class="empty">暂无消息。</div></div></div>
    </section>
  </main>
  <script>
    const keyInput = document.getElementById("key");
    const ordersEl = document.getElementById("orders");
    const messagesEl = document.getElementById("messages");
    keyInput.value = localStorage.getItem("membership-admin-key") || "";
    function headers(){return {"X-Admin-Key":keyInput.value,"Content-Type":"application/json"}}
    function saveKey(){localStorage.setItem("membership-admin-key",keyInput.value);loadData()}
    async function loadData(){
      const res = await fetch("/api/admin/summary",{headers:headers()});
      if(!res.ok){ordersEl.innerHTML='<div class="empty">后台密钥不正确。</div>';return}
      const data = await res.json();
      ordersEl.innerHTML = data.orders.length ? data.orders.map(orderTpl).join("") : '<div class="empty">暂无订单。</div>';
      messagesEl.innerHTML = data.messages.length ? data.messages.map(msgTpl).join("") : '<div class="empty">暂无消息。</div>';
    }
    function orderTpl(o){
      const status = o.status === "paid" ? "已开通" : "待确认";
      const paidClass = o.status === "paid" ? " paid" : "";
      const confirm = o.status === "paid" ? "" : '<button class="btn primary" onclick="confirmOrder(\\''+o.id+'\\')">确认到账</button>';
      return '<div class="row"><div><strong>'+o.memberName+' · '+o.memberContact+'</strong><div class="meta">订单 '+o.id+' · ¥'+(o.amountFen/100).toFixed(2)+' · '+o.channel+' · '+new Date(o.createdAt).toLocaleString()+'</div><span class="tag'+paidClass+'">'+status+'</span></div><div class="actions">'+confirm+'</div></div>';
    }
    function msgTpl(m){return '<div class="msg"><strong>'+m.text+'</strong><div class="meta">'+new Date(m.createdAt).toLocaleString()+'</div></div>'}
    async function confirmOrder(id){
      const paidAmountFen = Number(prompt("实际到账金额，单位：分", "100"));
      if(!paidAmountFen) return;
      const transactionId = prompt("交易流水号，可留空", "") || "";
      const res = await fetch("/api/admin/orders/"+id+"/confirm",{method:"POST",headers:headers(),body:JSON.stringify({paidAmountFen,transactionId,note:"后台人工确认"})});
      if(!res.ok){alert("确认失败");return}
      await loadData();
    }
  </script>
</body>
</html>`;
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === "OPTIONS") {
    sendJson(res, 204, {});
    return;
  }

  const db = readDb();

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    sendText(res, 200, fs.readFileSync(path.join(__dirname, "index.html"), "utf8"), "text/html; charset=utf-8");
    return;
  }

  if (req.method === "GET" && url.pathname === "/healthz") {
    sendJson(res, 200, { ok: true, service: "yue9999-membership", time: nowIso() });
    return;
  }

  if (req.method === "GET" && url.pathname === "/admin") {
    sendText(res, 200, adminHtml(), "text/html; charset=utf-8");
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/member/login") {
    const body = safeJson(await readBody(req));
    const name = String(body.name || "").trim();
    const contact = String(body.contact || "").trim();
    if (!name || !contact) {
      sendJson(res, 400, { message: "请填写会员昵称和联系方式" });
      return;
    }

    const normalized = normalizeContact(contact);
    let member = db.members.find((item) => item.normalizedContact === normalized);
    if (!member) {
      member = {
        id: crypto.randomUUID(),
        name,
        contact,
        normalizedContact: normalized,
        active: false,
        createdAt: nowIso(),
        updatedAt: nowIso()
      };
      db.members.push(member);
      addMessage(db, "member_login", `新会员登录：${name}（${contact}）`, { memberId: member.id });
    } else {
      member.name = name;
      member.contact = contact;
      member.updatedAt = nowIso();
      addMessage(db, "member_login", `会员再次登录：${name}（${contact}）`, { memberId: member.id });
    }
    writeDb(db);
    sendJson(res, 200, { token: issueToken(member.id), member: publicMember(member), product: PRODUCT });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/member/status") {
    const member = verifyToken(req, db);
    if (!member) {
      sendJson(res, 401, { message: "请先会员登录" });
      return;
    }
    const orders = db.orders.filter((order) => order.memberId === member.id).map(publicOrder);
    sendJson(res, 200, { member: publicMember(member), orders });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/orders") {
    const member = verifyToken(req, db);
    if (!member) {
      sendJson(res, 401, { message: "请先会员登录" });
      return;
    }
    const body = safeJson(await readBody(req));
    if (body.productId !== PRODUCT.id || Number(body.amountFen) !== PRODUCT.amountFen) {
      sendJson(res, 400, { message: "产品或金额不正确" });
      return;
    }

    const clientOrderId = String(body.clientOrderId || "").trim();
    let order = clientOrderId ? db.orders.find((item) => item.id === clientOrderId || item.clientOrderId === clientOrderId) : null;
    if (!order) {
      order = {
        id: clientOrderId || `WX-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`,
        clientOrderId,
        productId: PRODUCT.id,
        amountFen: PRODUCT.amountFen,
        currency: PRODUCT.currency,
        channel: String(body.channel || "wechat"),
        status: "pending",
        memberId: member.id,
        memberName: member.name,
        memberContact: member.contact,
        createdAt: nowIso()
      };
      db.orders.unshift(order);
      addMessage(db, "order_created", `会员 ${member.name} 创建 1 元订单，等待确认到账。`, {
        orderId: order.id,
        memberId: member.id,
        amountFen: order.amountFen
      });
    }
    writeDb(db);
    sendJson(res, 200, { order: publicOrder(order), product: PRODUCT });
    return;
  }

  if (url.pathname === "/api/admin/summary" && req.method === "GET") {
    if (!isAdmin(req, url)) {
      sendJson(res, 401, { message: "后台密钥不正确" });
      return;
    }
    sendJson(res, 200, {
      product: PRODUCT,
      members: db.members.map(publicMember),
      orders: db.orders.map(publicOrder),
      messages: db.messages.slice(0, 80)
    });
    return;
  }

  const confirmMatch = url.pathname.match(/^\/api\/admin\/orders\/([^/]+)\/confirm$/);
  if (confirmMatch && req.method === "POST") {
    if (!isAdmin(req, url)) {
      sendJson(res, 401, { message: "后台密钥不正确" });
      return;
    }
    const body = safeJson(await readBody(req));
    const order = db.orders.find((item) => item.id === confirmMatch[1]);
    if (!order) {
      sendJson(res, 404, { message: "订单不存在" });
      return;
    }
    const result = confirmOrder(db, order, body.paidAmountFen, {
      transactionId: body.transactionId,
      note: body.note,
      confirmedBy: "admin"
    });
    writeDb(db);
    sendJson(res, 200, { member: publicMember(result.member), order: publicOrder(result.order) });
    return;
  }

  if (url.pathname === "/api/payment/webhook" && req.method === "POST") {
    const rawBody = await readBody(req);
    if (!verifyWebhookSignature(rawBody, req.headers["x-payment-signature"])) {
      sendJson(res, 401, { message: "支付回调验签失败或未配置 PAYMENT_WEBHOOK_SECRET" });
      return;
    }
    const body = safeJson(rawBody);
    const orderId = body.orderId || body.clientOrderId;
    const order = db.orders.find((item) => item.id === orderId || item.clientOrderId === orderId);
    if (!order) {
      sendJson(res, 404, { message: "订单不存在" });
      return;
    }
    const event = body.event || body.type;
    if (!["payment.succeeded", "paid", "PAYMENT_SUCCESS"].includes(event)) {
      sendJson(res, 200, { received: true, ignored: true });
      return;
    }
    const result = confirmOrder(db, order, body.paidAmountFen, {
      transactionId: body.transactionId,
      paidAt: body.paidAt,
      note: "支付平台回调自动确认",
      confirmedBy: "webhook"
    });
    writeDb(db);
    sendJson(res, 200, { received: true, member: publicMember(result.member), order: publicOrder(result.order) });
    return;
  }

  sendJson(res, 404, { message: "Not found" });
}

const server = http.createServer((req, res) => {
  route(req, res).catch((error) => {
    const status = error.status || 500;
    sendJson(res, status, { message: error.message || "服务器错误" });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Membership server running at http://${HOST}:${PORT}`);
  console.log(`Admin panel: http://${HOST}:${PORT}/admin`);
});
