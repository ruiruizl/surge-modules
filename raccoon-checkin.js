/*
 * 小浣熊 (xiaohuanxiong.com) 每日自动签到
 * Surge cron 脚本
 *
 * 配置（三选一，优先级从上到下）：
 *   1. argument JSON：{"token":"xxx"} 或 {"phone":"xxx","password":"xxx","nation_code":"86"}
 *   2. BoxJS 数据名 xiaohuanxiong_checkin（JSON 同上）
 *   3. Surge persistentStore 键 raccoon_openai_tokens（access/refresh，自动刷新）
 *
 * 通知：默认每次运行发通知；argument 或 BoxJS 里 notify=false 可关闭。
 */
var AUTH = "https://xiaohuanxiong.com/api/web/auth/v1";
var LLM = "https://xiaohuanxiong.com/api/web/llm/v2";
var ENC_KEY = "senseraccoon2023";
var TS_KEY = "raccoon_openai_tokens";

function normalizeArg(v) {
  if (v === null || typeof v === "undefined") return {};
  if (typeof v === "object") {
    var o = {};
    for (var k in v) {
      if (Object.prototype.hasOwnProperty.call(v, k)) {
        var raw = v[k];
        if (raw === null || typeof raw === "undefined") continue;
        var s = String(raw).trim();
        if (s && s !== "none" && s !== "REPLACE_ME") o[k] = s;
      }
    }
    return o;
  }
  return parseArg(String(v));
}

function parseArg(s) {
  var o = {};
  s.split(/[&|]/).forEach(function (p) {
    var i = p.indexOf("=");
    if (i > 0) {
      var k = p.slice(0, i).trim();
      var v = (p.slice(i + 1) || "").trim();
      if (v && v !== "none" && v !== "REPLACE_ME") o[k] = v;
    }
  });
  return o;
}

/* AES-128-CFB */
var B64T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

var SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

function gfMul(a, b) {
  var r = 0;
  while (b) {
    if (b & 1) r ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return r;
}

function expandKey(k) {
  var Nk = k.length / 4, Nr = Nk + 6;
  var w = new Uint8Array(4 * (Nr + 1));
  w.set(k);
  var i = Nk;
  var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  while (i < 4 * (Nr + 1)) {
    var temp = Array.prototype.slice.call(w.slice((i - 1) * 4, i * 4));
    if (i % Nk === 0) {
      temp = [temp[1], temp[2], temp[3], temp[0]].map(function (b) { return SBOX[b]; });
      temp[0] ^= RCON[i / Nk - 1];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = temp.map(function (b) { return SBOX[b]; });
    }
    for (var j = 0; j < 4; j++) w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
    i++;
  }
  return { key: w, Nr: Nr };
}

function encBlock(b, key, Nr) {
  function add(r) { var o = r * 16; for (var i = 0; i < 16; i++) b[i] ^= key[o + i]; }
  function sub() { for (var i = 0; i < 16; i++) b[i] = SBOX[b[i]]; }
  function sr() {
    var t = b.slice();
    b[1] = t[5]; b[5] = t[9]; b[9] = t[13]; b[13] = t[1];
    b[2] = t[10]; b[6] = t[14]; b[10] = t[2]; b[14] = t[6];
    b[3] = t[15]; b[7] = t[3]; b[11] = t[7]; b[15] = t[11];
  }
  function mc() {
    for (var c = 0; c < 4; c++) {
      var i = c * 4, a0 = b[i], a1 = b[i + 1], a2 = b[i + 2], a3 = b[i + 3];
      b[i] = gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3;
      b[i + 1] = a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3;
      b[i + 2] = a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3);
      b[i + 3] = gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2);
    }
  }
  add(0);
  for (var r = 1; r < Nr; r++) { sub(); sr(); mc(); add(r); }
  sub(); sr(); add(Nr);
}

function encryptField(plain) {
  var key = expandKey(utf8Bytes(ENC_KEY));
  var pt = utf8Bytes(plain);
  var iv = new Uint8Array(16);
  for (var i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
  var out = new Uint8Array(16 + pt.length);
  out.set(iv);
  var prev = iv;
  for (var off = 0; off < pt.length; off += 16) {
    var ks = prev.slice(0);
    encBlock(ks, key.key, key.Nr);
    var n = Math.min(16, pt.length - off);
    var ctBlock = new Uint8Array(16);
    for (var j = 0; j < n; j++) {
      ctBlock[j] = pt[off + j] ^ ks[j];
      out[16 + off + j] = ctBlock[j];
    }
    prev = ctBlock;
  }
  return b64(out);
}

function utf8Bytes(s) {
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c >= 0xd800 && c <= 0xdbff) {
      var c2 = s.charCodeAt(++i);
      c = 0x10000 | ((c - 0xd800) << 10) | (c2 - 0xdc00);
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function b64(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i += 3) {
    var n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += B64T[(n >> 18) & 63] + B64T[(n >> 12) & 63] +
      (i + 1 < bytes.length ? B64T[(n >> 6) & 63] : "=") +
      (i + 2 < bytes.length ? B64T[n & 63] : "=");
  }
  return out;
}

function fromB64(s) {
  if (typeof atob === "function") {
    try { return atob(s); } catch (e) {}
  }
  var t = String(s).replace(/[^A-Za-z0-9+/]/g, "");
  var out = "";
  for (var i = 0; i < t.length; i += 4) {
    var n = (B64T.indexOf(t[i]) << 18) | (B64T.indexOf(t[i + 1]) << 12) |
      ((t[i + 2] ? B64T.indexOf(t[i + 2]) : 0) << 6) | (t[i + 3] ? B64T.indexOf(t[i + 3]) : 0);
    out += String.fromCharCode((n >> 16) & 255);
    if (t[i + 2]) out += String.fromCharCode((n >> 8) & 255);
    if (t[i + 3]) out += String.fromCharCode(n & 255);
  }
  return out;
}

function loadTokens() {
  try { return JSON.parse($persistentStore.read(TS_KEY) || "null"); } catch (e) { return null; }
}
function saveTokens(access, refresh) {
  try { $persistentStore.write(JSON.stringify({ access: access, refresh: refresh, at: Date.now() }), TS_KEY); } catch (e) {}
}
function tokenList() {
  var direct = A.token ? A.token.split(",").map(function (s) { return s.trim(); }).filter(function (x) { return x; }) : [];
  var cached = loadTokens();
  var c = cached && cached.access ? (Array.isArray(cached.access) ? cached.access : [cached.access]) : [];
  var all = direct.concat(c);
  if (!all.length) return [];
  var uniq = [], seen = {};
  for (var i = 0; i < all.length; i++) {
    var k = String(all[i]).replace(/^Bearer\s+/i, "");
    if (k && !seen[k]) { seen[k] = 1; uniq.push(k); }
  }
  return uniq;
}
function jwtExp(token) {
  try {
    var parts = token.split(".");
    if (parts.length < 2) return 0;
    var b = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    var pad = b + "===".slice((b.length + 3) % 4);
    var json = decodeURIComponent(fromB64(pad).split("").map(function (c) {
      return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(""));
    return Number(JSON.parse(json).exp || 0) * 1000;
  } catch (e) { return 0; }
}
function login(cb) {
  if (!A.phone || !A.password) {
    cb(new Error("未配置 phone/password（或直接填 token）"), null);
    return;
  }
  var body = JSON.stringify({
    nation_code: A.nation || "86",
    phone: encryptField(A.phone),
    password: encryptField(A.password),
  });
  $httpClient.post(
    { url: AUTH + "/login_with_password", headers: { "Content-Type": "application/json" }, body: body },
    function (err, resp, data) {
      if (err) return cb(new Error("登录请求失败: " + err), null);
      var j;
      try { j = JSON.parse(data); } catch (e) { return cb(new Error("登录响应解析失败"), null); }
      if (!j.data || !j.data.access_token) {
        return cb(new Error("登录失败 " + (j.code || "") + ": " + (j.message || j.details || "未知错误")), null);
      }
      saveTokens(j.data.access_token, j.data.refresh_token || "");
      cb(null, j.data.access_token);
    }
  );
}
function refreshToken(cb) {
  var t = loadTokens();
  if (!t || !t.refresh) return login(cb);
  $httpClient.post(
    { url: AUTH + "/refresh", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: t.refresh }), timeout: 20 },
    function (err, resp, data) {
      if (err) return login(cb);
      var j;
      try { j = JSON.parse(data); } catch (e) { return login(cb); }
      if (!j.data || !j.data.access_token) return login(cb);
      saveTokens(j.data.access_token, j.data.refresh_token || t.refresh);
      cb(null, j.data.access_token);
    }
  );
}
function ensureToken(cb) {
  var ts = tokenList();
  if (A.token) return cb(null, A.token.replace(/^Bearer\s+/i, ""));
  if (ts.length > 1) {
    for (var i = 0; i < ts.length; i++) {
      var exp = jwtExp(ts[i]);
      if (exp && exp > Date.now() + 120000) return cb(null, ts[i]);
    }
    var t0 = loadTokens();
    if (t0 && t0.refresh) return refreshToken(cb);
    return login(cb);
  }
  var t2 = loadTokens();
  if (!t2 || !t2.access) return login(cb);
  var exp2 = jwtExp(t2.access);
  if (exp2 && exp2 < Date.now() + 120000) return refreshToken(cb);
  cb(null, t2.access);
}
function requestJson(method, path2, token, headers, timeout, cb) {
  var h = { Accept: "application/json", Authorization: "Bearer " + token };
  for (var k in headers) h[k] = headers[k];
  var opt = { url: "https://xiaohuanxiong.com" + path2, headers: h, timeout: (timeout || 20) };
  var fn = method === "POST" ? $httpClient.post : $httpClient.get;
  fn(opt, function (err, resp, data) {
    if (err) return cb(new Error("网络失败: " + err), null);
    if (resp && resp.status === 429) return cb(new Error("上游限流(429)"), null);
    if (resp && resp.status === 401) return cb(new Error("登录态已过期（401）"), null);
    if (!resp || resp.status !== 200) return cb(new Error("HTTP " + (resp ? resp.status : 0)), null);
    var j;
    try { j = JSON.parse(data); } catch (e) { return cb(new Error("响应解析失败"), null); }
    if (typeof j.code === "number" && j.code !== 0) return cb(new Error(j.message || ("code=" + j.code)), null);
    cb(null, j.data !== undefined && j.data !== null ? j.data : j);
  });
}
function beijingToday() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
function desktopHeaders() {
  return { "X-Client-Platform": "desktop-windows", "X-Client-Version": "v1.0.0", "X-Raccoon-Language": "zh" };
}
function toastText(data) {
  if (!data) return "";
  var parts = [];
  var keys = ["point_grant_toast", "point_grant_popups"];
  for (var i = 0; i < keys.length; i++) {
    var v = data[keys[i]];
    if (v === undefined || v === null) continue;
    try { parts.push(typeof v === "string" ? v : JSON.stringify(v).slice(0, 200)); } catch (e) {}
  }
  return parts.join(" | ");
}

function runCheckin(cb) {
  ensureToken(function (e, token) {
    if (e) return cb({ ok: false, title: "小浣熊签到失败", subtitle: e.message, body: "" });
    requestJson("GET", "/api/web/office/v3/setting_info", token, desktopHeaders(), 20, function (err1, info) {
      var grantNote = err1 ? ("发放接口: " + err1.message) : toastText(info);
      requestJson("GET", "/api/web/points/v1/bills?paging.limit=20&paging.offset=0", token, {}, 25, function (err2, bills) {
        var sum = 0, names = [];
        var today = beijingToday();
        for (var i = 0; i < ((bills && bills.items) || []).length; i++) {
          var it = bills.items[i];
          var pts = Number(it.points || 0);
          var createdAt = String(it.created_at || "");
          if (pts > 0 && createdAt.slice(0, 10) === today) {
            sum += pts;
            names.push((it.event_name || "积分") + " +" + pts);
          }
        }
        requestJson("GET", "/api/web/points/v1/balance", token, {}, 20, function (err3, bal) {
          var wallets = [];
          if (bal && typeof bal === "object") {
            var pairs = [["daily_points", "每日"], ["monthly_points", "会员"], ["reward_points", "奖励"], ["topup_points", "充值"]];
            for (var j = 0; j < pairs.length; j++) {
              var v = Number(bal[pairs[j][0]]);
              if (!isNaN(v)) wallets.push(pairs[j][1] + " " + v);
            }
          }
          var avail = bal ? Number(bal.available_points) : NaN;
          var balanceLine = isNaN(avail)
            ? (err3 ? "余额查询失败: " + err3.message : "")
            : ("总余额 " + avail + "（" + wallets.join(" / ") + "）");
          var r = { ok: sum > 0, today: today, sum: sum, entries: names, balance: isNaN(avail) ? null : avail, wallets: wallets, grant_note: grantNote, err_grant: err1 && err1.message, err_bills: err2 && err2.message, err_balance: err3 && err3.message };
          if (sum > 0) {
            r.title = "小浣熊签到成功"; r.subtitle = "今日 +" + sum + " · " + (isNaN(avail) ? "余额未知" : "余额 " + avail);
            r.body = (names.join("；") + (balanceLine ? "；" + balanceLine : "")) + (grantNote ? "（" + grantNote + "）" : "");
          } else if (err1 && err2) {
            r.title = "小浣熊签到失败"; r.subtitle = "发放与账单查询均失败"; r.body = r.err_grant + "；" + r.err_bills;
          } else {
            r.title = "小浣熊签到"; r.subtitle = "账单未见今日入账" + (isNaN(avail) ? "" : " · 余额 " + avail);
            r.body = grantNote || (err2 ? "账单: " + r.err_bills : "可能今日已领过或发放延迟");
          }
          cb(r);
        });
      });
    });
  });
}

/* 配置解析：argument 优先，其次 BoxJS，再次 persistentStore */
var A = normalizeArg(typeof $argument === "undefined" ? null : $argument);
if ((!A.phone || !A.password) && !A.token) {
  try {
    var BJ = JSON.parse($persistentStore.read("xiaohuanxiong_checkin") || "null");
    if (BJ && typeof BJ === "object") {
      for (var bk in BJ) {
        if (Object.prototype.hasOwnProperty.call(BJ, bk) && !A[bk]) A[bk] = String(BJ[bk]).trim();
      }
    }
  } catch (e) {}
}

runCheckin(function (r) {
  console.log("[raccoon-checkin] " + JSON.stringify(r));
  if (A.notify === "false" || A.notify === false) {
    $done({});
    return;
  }
  $notification.post(r.title, r.subtitle, r.body || "");
  $done({});
});
