// Приёмник общего каталога пресетов (Cloudflare Workers + KV).
// POST /submit: анонимный набор записей одного рига. GET /catalog.json: общий каталог.
// IP не хранится и не логируется. Идентификатор рига хранится только как HMAC с секретом SALT.
//
// Запись видна в каталоге уже после ПЕРВОГО рига, который её подтвердил (минимум доказательности — 1 риг).
// Каталог собирается из СВЕЖИХ снапшотов rig:* (последняя присылка каждого рига), а не из когда-либо
// накопленных best:*: раньше best только рос, и пресет, оказавшийся позже нестабильным и переподобранный
// ниже, оставался на сайте навсегда. Теперь переподобравший ниже риг при следующей присылке сам опускает
// запись, связки старых версий майнера выпадают, когда риги обновились и перестали их присылать, а риги,
// молчащие дольше STALE_RIG_MS, выпадают из каталога сами (бот шлёт heartbeat раз в сутки, см. share.py).
// Количество РАЗНЫХ ригов, ДЕРЖАЩИХ связку сейчас, используется сайтом как индикатор доверия
// («мало данных» / «подтверждено» / «надёжно»), а не как условие показа.

const OBJ = ["", "efficiency", "compromise", "hashrate"];
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", ...CORS, ...extra } });

const isStr = (v, min, max) => typeof v === "string" && v.length >= min && v.length <= max && !/[\u0000-\u001f<>]/.test(v);
const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
const isNum = (v, lo, hi) => typeof v === "number" && Number.isFinite(v) && v > lo && v < hi;

function cleanEntry(e) {
  if (!e || typeof e !== "object") return null;
  if (!isStr(e.model, 1, 60) || !isStr(e.algo, 1, 30) || !isStr(e.miner, 1, 30) || !isStr(e.miner_version, 1, 30)) return null;
  const mv = e.mem_vendor == null ? "" : e.mem_vendor;
  if (!isStr(mv, 0, 30)) return null;
  const obj = e.objective == null ? "" : e.objective;
  if (!OBJ.includes(obj)) return null;
  const pt = (p) => {
    if (!(p && isInt(p.core, -1000, 1000) && isInt(p.mem, -3000, 3000) && isInt(p.pl, 30, 700))) return null;
    const o = { core: p.core, mem: p.mem, pl: p.pl };
    if (isInt(p.core_lock, 300, 4000)) o.core_lock = p.core_lock;       // фиксация частот («4 параметра»), если есть
    if (isInt(p.mem_lock, 300, 15000)) o.mem_lock = p.mem_lock;
    return o;
  };
  const best = pt(e.best), med = pt(e.median);
  if (!best || !med) return null;
  if (!isNum(e.hashrate, 0, 1e7) || !isNum(e.power_w, 5, 800) || !isNum(e.efficiency, 0, 1e6)) return null;
  const cards = isInt(e.cards, 1, 100) ? e.cards : 1;
  return {
    model: e.model.replace(/^NVIDIA\s+/i, "").replace(/^GeForce\s+/i, "").replace(/\s+/g, " ").trim(), mem_vendor: mv.trim(), algo: e.algo.trim().toLowerCase(), miner: e.miner.replace(/[-_ ]v?\d[\w.\-]*$/i, ""), miner_version: e.miner_version, objective: obj,
    cards, best, median: med, hashrate: e.hashrate, power_w: e.power_w, efficiency: e.efficiency,
    ...(isNum(e.stock_hashrate, 0, 1e7) && isNum(e.stock_power_w, 5, 800) ? { stock_hashrate: e.stock_hashrate, stock_power_w: e.stock_power_w } : {}),
  };
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 24);
}

// Стартовая таблица алгоритм → монета для уже известных, широко используемых алгоритмов (whattomine.com,
// miningboard.com/algorithms). Нужна, чтобы Telegram не спрашивал про то, что и так известно — вопрос
// задаётся только про алгоритмы, которых здесь нет. Запись через /admin/setcoin (хранится в KV) всегда
// имеет приоритет над этой таблицей — так можно исправить любую ошибку здесь без правки кода.
const DEFAULT_COIN_MAP = {
  pearl: "PRL", pearlhash: "PRL",
  kawpow: "RVN", autolykos2: "ERG", autolykos: "ERG",
  etchash: "ETC", ethash: "ETHW",
  firopow: "FIRO", kheavyhash: "KAS", heavyhash: "KAS",
  nexapow: "NEXA", beamhashiii: "BEAM", beamhash: "BEAM",
  octopus: "CFX", fishhash: "IRON", verthash: "VTC",
  karlsenhashv2: "KLS", karlsenhash: "KLS", evrprogpow: "EVR",
  dynexsolve: "DNX", cortex: "CTXC", abelhash: "ABEL",
  versahash: "INI", keryxhash: "KRX", meowpow: "MEWC",
  cuckatoo32: "GRIN", progpowz: "ZANO", randomx: "XMR",
  verushash: "VRSC", scrypt: "LTC", sha256: "BTC",
  eaglesong: "CKB", handshake: "HNS",
  qpow: "QTC",
};
const comboKey = (e) => [e.model, e.mem_vendor, e.algo, e.miner, e.miner_version, e.objective].join("|");
const score = (e) => (e.objective === "hashrate" ? e.hashrate : e.efficiency);

// Отправляет сообщение владельцу в Telegram. Необязательно: если секреты TG_BOT_TOKEN/TG_OWNER_CHAT_ID
// не заданы или отправка не удалась — просто ничего не делает (не роняет запрос, не бросает исключение).
async function tgSend(env, text) {
  if (!env.TG_BOT_TOKEN || !env.TG_OWNER_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: env.TG_OWNER_CHAT_ID, text }),
    });
  } catch { /* отправка необязательна */ }
}

// Ищет монету в CoinGecko по тикеру/запросу и возвращает кандидатов. Используется и для автоматического
// сопоставления новых алгоритмов, и для разрешения коллизий тикеров (несколько разных монет с одним
// символом на CoinGecko — выбираем по market_cap_rank: чем меньше ранг, тем известнее монета).
async function cgSearch(query) {
  const r = await fetch(`https://api.coingecko.com/api/v3/search?query=${encodeURIComponent(query)}`);
  if (!r.ok) throw new Error("coingecko search http " + r.status);
  const d = await r.json();
  return Array.isArray(d.coins) ? d.coins : [];
}

function pickBestCoin(coins, ticker) {
  const exact = coins.filter((c) => (c.symbol || "").toUpperCase() === ticker);
  const pool = exact.length ? exact : coins;
  if (!pool.length) return null;
  return pool.slice().sort((a, b) => {
    const ra = a.market_cap_rank == null ? Infinity : a.market_cap_rank;
    const rb = b.market_cap_rank == null ? Infinity : b.market_cap_rank;
    return ra - rb;
  })[0];
}

async function resolveAndStoreCgId(env, ticker) {
  const coins = await cgSearch(ticker);
  const best = pickBestCoin(coins, ticker);
  if (!best) return null;
  await env.CATALOG.put("cgid:" + ticker, JSON.stringify({ id: best.id, name: best.name, rank: best.market_cap_rank, updated_at: new Date().toISOString() }));
  return best.id;
}

// SafeTrade (safe.trade) — многие новые майнерские монеты (включая те, что ещё не попали на CoinGecko/
// WhatToMine) листятся именно там первым делом. Публичный тикер-эндпоинт (движок на базе Peatio, как и у
// других бирж того же стека) отдаёт все пары одним запросом: ключ — нижний регистр пары, напр. "noidusdt".
// Общий кэш ответа /api/v2/tickers на один вызов (тикеров может быть несколько, а дёргать биржу на
// каждый — лишнее, она и так отдаёт все пары одним запросом). Это модульная переменная воркера — живёт,
// пока жив конкретный изолят Cloudflare, сбрасывается между холодными стартами, это ожидаемо.
let safeTradeTickersPromise = null;
const safeTradeDebug = { status: null, error: null, bodyStart: null };
function safeTradeTickers() {
  if (!safeTradeTickersPromise) {
    safeTradeTickersPromise = fetch("https://safe.trade/api/v2/tickers", {
      headers: { accept: "application/json", "user-agent": "ocbot-catalog-worker/1.0 (+https://ocbot.org)" },
    })
      .then(async (r) => {
        safeTradeDebug.status = r.status;
        if (!r.ok) { safeTradeDebug.bodyStart = (await r.text().catch(() => "")).slice(0, 200); return null; }
        return r.json();
      })
      .catch((e) => { safeTradeDebug.error = e && e.message ? e.message : String(e); return null; });
  }
  return safeTradeTickersPromise;
}
// Пара в USDT есть не у всех монет на SafeTrade — у части листинг только в USDC (напр. nockusdc,
// safeusdc). Пробуем обе котировки, USDT в приоритете (ликвиднее и не имеет собственной волатильности
// к доллару, в отличие от USDC, который тоже не всегда ровно $1).
function safeTradePair(all, ticker) {
  const t = (SAFE_PAIR_BASE[ticker] || ticker).toLowerCase();
  return all && (all[t + "usdt"] || all[t + "usdc"] || null);
}
async function safeTradeHasMarket(ticker) {
  const all = await safeTradeTickers();
  return !!safeTradePair(all, ticker);
}

// Для каждого нового алгоритма, которого раньше не было ни в сопоставлении (coin:*), ни в списке уже
// заданных вопросов (pending:*), пытается сам найти монету: сначала через CoinGecko search (по точному
// совпадению тикера и известному market_cap_rank), а если там монеты ещё нет (частый случай для совсем
// новых майнерских монет) — проверяет, не торгуется ли она уже на SafeTrade (туда многие заходят первыми,
// до появления на крупных биржах/CoinGecko). Если не вышло ни там, ни там — как раньше, один раз спрашивает
// владельца в Telegram и ставит отметку "уже спросили", чтобы не слать повторные сообщения на каждую присылку.
async function notifyNewAlgos(env, entries) {
  const algos = [...new Set(entries.map((e) => e.algo))];
  for (const algo of algos) {
    if (DEFAULT_COIN_MAP[algo]) continue;
    if (await env.CATALOG.get("coin:" + algo)) continue;
    if (await env.CATALOG.get("pending:" + algo)) continue;

    let auto = null;
    try {
      const coins = await cgSearch(algo);
      const best = pickBestCoin(coins, algo.toUpperCase());
      if (best && (best.symbol || "").toUpperCase() === algo.toUpperCase() && best.market_cap_rank != null) {
        auto = best;
      }
    } catch { /* не вышло — попробуем SafeTrade, затем спросим владельца */ }

    if (auto) {
      await env.CATALOG.put("coin:" + algo, JSON.stringify({ coin: auto.symbol.toUpperCase(), updated_at: new Date().toISOString() }));
      await env.CATALOG.put("cgid:" + auto.symbol.toUpperCase(), JSON.stringify({ id: auto.id, name: auto.name, rank: auto.market_cap_rank, updated_at: new Date().toISOString() }));
      await tgSend(env, `Новый алгоритм "${algo}" — курс нашёлся сам: ${auto.name} (${auto.symbol.toUpperCase()}). Если это не та монета — исправьте: /admin/setcoin?key=...&algo=${encodeURIComponent(algo)}&coin=ТИКЕР`);
      continue;
    }

    // На CoinGecko монеты пока нет (или её ранг неизвестен) — частый случай для совсем новых майнерских
    // монет. Проверяем, не торгуется ли тикер алгоритма (в верхнем регистре) уже на SafeTrade.
    const guess = algo.toUpperCase();
    if (await safeTradeHasMarket(guess)) {
      await env.CATALOG.put("coin:" + algo, JSON.stringify({ coin: guess, updated_at: new Date().toISOString(), via: "safe.trade" }));
      await tgSend(env, `Новый алгоритм "${algo}" — монеты ещё нет на CoinGecko, но её тикер ${guess} уже торгуется на SafeTrade, курс будет оттуда. Если это не та монета — исправьте: /admin/setcoin?key=...&algo=${encodeURIComponent(algo)}&coin=ТИКЕР`);
      continue;
    }

    await env.CATALOG.put("pending:" + algo, "1");
    const link = env.CATALOG_WORKER_URL
      ? `${env.CATALOG_WORKER_URL}/admin/setcoin?key=${env.ADMIN_KEY || "<ADMIN_KEY>"}&algo=${encodeURIComponent(algo)}&coin=`
      : null;
    await tgSend(
      env,
      `Новый алгоритм в каталоге: "${algo}" — монета не определена автоматически (нет ни на CoinGecko, ни на SafeTrade под этим тикером).\n` +
        (link
          ? `Допишите тикер монеты в конец ссылки и откройте её в браузере:\n${link}`
          : `Сопоставьте вручную: /admin/setcoin?key=...&algo=${encodeURIComponent(algo)}&coin=ТИКЕР`)
    );
  }
}

// Снапшот рига старше этого срока выпадает из каталога: молчащий риг — это
// выключенный/переехавший риг, его пресеты не должны жить на сайте вечно.
// Бот присылает heartbeat раз в сутки (share.py), поэтому живой риг с
// давно подобранными стабильными пресетами из каталога не пропадает.
const STALE_RIG_MS = 7 * 24 * 60 * 60 * 1000;

// Каталог из свежих снапшотов rig:*: по связке берётся лучший СЕЙЧАС держащий её
// результат (не исторический максимум), медиана — от рига с наибольшим числом
// карт, rigs/cards — сколько ригов/карт держат связку сейчас.
async function currentCatalog(env) {
  const now = Date.now();
  const byCombo = new Map();
  let cursor;
  do {
    const page = await env.CATALOG.list({ prefix: "rig:", cursor });
    for (const k of page.keys) {
      const d = await env.CATALOG.get(k.name, "json");
      if (!d || !d.t || now - d.t > STALE_RIG_MS || !Array.isArray(d.entries)) continue;
      for (const e of d.entries) {
        const key = comboKey(e);
        let g = byCombo.get(key);
        if (!g) { g = { best: e, med: e, rigs: 0, cards: 0, t: 0 }; byCombo.set(key, g); }
        g.rigs += 1;
        g.cards += e.cards || 1;
        if ((e.cards || 1) >= (g.med.cards || 1)) g.med = e;
        if (score(e) > score(g.best)) g.best = e;
        if (d.t > g.t) g.t = d.t;
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  const out = [];
  for (const g of byCombo.values()) {
    out.push({ ...g.best, median: g.med.median, cards: g.cards, rigs: g.rigs, updated_at: new Date(g.t).toISOString() });
  }
  out.sort((a, b) => (a.model + a.algo + a.miner + a.objective).localeCompare(b.model + b.algo + b.miner + b.objective));
  return out;
}

// --- Цена монеты на сервере (/price.json) -----------------------------------------------------------
// Браузер посетителя (особенно на некоторых мобильных операторах) не всегда может достучаться напрямую
// до api.coingecko.com / api.gateio.ws / open.er-api.com — а до этого воркера он уже достучался (иначе
// не отработал бы /catalog.json и /coinmap.json). Поэтому курс монеты тоже можно получить через воркер:
// запросы к внешним API идут из сети Cloudflare, а не из сети посетителя, и не зависят от того, что
// заблокировано у конкретного оператора/региона. Результат кэшируется на несколько минут на ВСЕХ
// посетителей сразу (кэш Cloudflare) — это заодно снимает нагрузку с бесплатного лимита CoinGecko.

// Тикеры, где символ в CoinGecko не совпадает с ожидаемым id (как и в клиентском коде сайта), либо где
// несколько РАЗНЫХ монет делят один тикер на CoinGecko и нужен однозначный выбор (QTC: монета Quantus,
// а не "qubitcoin-2" или "qitchain-network", которые тоже используют символ QTC).
const CG_ID_OVERRIDE = { PRL: "pearl-2", QTC: "quantus" };
// Пары Gate.io проверены вручную: "PRL_USDT" на Gate — это другой, не связанный токен;
// нужная монета Pearl лежит в "PEARL_USDT".
const GATE_PAIR = { PRL: "PEARL_USDT" };
// То же самое для SafeTrade: ключ пары там строится из названия монеты (base_unit), а не всегда
// совпадает с тикером из coinmap.json — PRL там торгуется под парой "pearlusdt", не "prlusdt".
// Без этой записи SafeTrade как резерв для PRL молча не найдёт пару, даже если она есть.
const SAFE_PAIR_BASE = { PRL: "pearl" };

// Сопоставление тикера → id CoinGecko. Порядок: 1) сохранённое в KV (cgid:ТИКЕР — ставится через
// /admin/resolve, /admin/setcoin или автоматически); 2) встроенный CG_ID_OVERRIDE; 3) поиск CoinGecko по
// тикеру (монета с лучшим market_cap_rank), результат сразу сохраняется в cgid:ТИКЕР — поиск идёт один раз
// на монету. Полный список монет CoinGecko (~15 тыс. записей) больше не качается и не разбирается: на
// бесплатном тарифе Workers это съедало лимит CPU запроса. Неудачный поиск запоминается на сутки.
async function resolveCgIds(env, tickers, debugOut) {
  const out = {};
  for (const t of tickers) {
    const stored = await env.CATALOG.get("cgid:" + t, "json");
    if (stored && stored.id) { out[t] = stored.id; continue; }
    if (CG_ID_OVERRIDE[t]) { out[t] = CG_ID_OVERRIDE[t]; continue; }
    if (stored && stored.miss_t && Date.now() - stored.miss_t < 24 * 3600 * 1000) { out[t] = null; continue; }
    try {
      out[t] = await resolveAndStoreCgId(env, t);
      if (!out[t]) await env.CATALOG.put("cgid:" + t, JSON.stringify({ id: null, miss_t: Date.now() }));
    } catch (e) { out[t] = null; if (debugOut) debugOut.cgSearch = e && e.message ? e.message : String(e); }
  }
  return out;
}

async function fetchCoinGeckoPrices(tickers, env, debugOut) {
  const ids = await resolveCgIds(env, tickers, debugOut);
  const idList = [...new Set(Object.values(ids).filter(Boolean))];
  if (!idList.length) return {};
  const r = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${idList.join(",")}&vs_currencies=usd,eur,rub`);
  if (!r.ok) throw new Error("coingecko price http " + r.status);
  const prices = await r.json();
  const out = {};
  for (const t of tickers) {
    const id = ids[t];
    out[t] = id && prices[id] && prices[id].usd > 0 ? { usd: prices[id].usd ?? null, eur: prices[id].eur ?? null, rub: prices[id].rub ?? null } : null;
  }
  return out;
}

// WhatToMine: один запрос — курсы (в BTC) всех GPU-монет, которые вообще имеет смысл майнить; это тот же
// источник, по которому сайт считает доход (network.json). Курс BTC в долларах — с Gate.io. Ответ
// WhatToMine держим в кэше Cloudflare 10 минут, чтобы не ходить к ним на каждый запрос.
const WTM_URL = "https://whattomine.com/coins.json";
async function cachedJson(url, ttl, init) {
  const cache = priceCache(), key = new Request(url);
  if (cache) { try { const hit = await cache.match(key); if (hit) return await hit.json(); } catch { /* мимо кэша */ } }
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(url.split("/")[2] + " http " + r.status);
  const text = await r.text();
  if (cache) { try { await cache.put(key, new Response(text, { headers: { "cache-control": `max-age=${ttl}` } })); } catch { /* кэш необязателен */ } }
  return JSON.parse(text);
}

async function fetchWtmPrices(tickers, env) {
  const wtm = await cachedJson(WTM_URL, 600, { headers: { "user-agent": "ocbot-catalog-worker/1.0 (+https://ocbot.org)", accept: "application/json" } });
  const btcRate = {};
  for (const c of Object.values((wtm && wtm.coins) || {})) {
    const tag = String(c.tag || "").toUpperCase(), x = parseFloat(c.exchange_rate);
    if (tag && x > 0 && !(tag in btcRate)) btcRate[tag] = x;
  }
  const want = tickers.filter((t) => btcRate[t]);
  if (!want.length) return {};
  const btc = await cachedJson("https://api.gateio.ws/api/v4/spot/tickers?currency_pair=BTC_USDT", 300);
  const btcUsd = btc && btc[0] && parseFloat(btc[0].last);
  if (!(btcUsd > 0)) throw new Error("нет курса BTC");
  const rates = await usdFx(env);
  const out = {};
  for (const t of want) {
    const usd = btcRate[t] * btcUsd;
    out[t] = { usd, eur: rates ? usd * rates.EUR : null, rub: rates ? usd * rates.RUB : null };
  }
  return out;
}

async function fetchGateUsd(ticker) {
  const pair = GATE_PAIR[ticker];
  if (!pair) return null;
  const r = await fetch(`https://api.gateio.ws/api/v4/spot/tickers?currency_pair=${pair}`);
  if (!r.ok) return null;
  const arr = await r.json();
  const p = arr && arr[0] && parseFloat(arr[0].last);
  return p > 0 ? p : null;
}

// SafeTrade: многие новые майнерские монеты (включая те, что ещё не торгуются на крупных биржах и не
// попали на CoinGecko/WhatToMine) листятся именно там первым делом. Эндпоинт отдаёт ВСЕ пары одним
// запросом (ключ — нижний регистр пары, напр. "noidusdt"; курс — поле "last" ПРЯМО на самой паре, без
// вложенного "ticker" — проверено на реальном ответе биржи); курс там только в USDT, поэтому переводим
// в eur/rub через тот же usdFx(), что и для Gate.io.
async function fetchSafeTradeUsd(ticker, debugOut) {
  try {
    const all = await safeTradeTickers();
    if (debugOut) debugOut[ticker] = { gotTickers: !!all, keyCount: all ? Object.keys(all).length : 0 };
    const t = safeTradePair(all, ticker);
    if (debugOut) debugOut[ticker].pairFound = !!t;
    // Защита от смены формата ответа биржи: в проверенном виде "last" лежит прямо на паре, но на
    // случай, если когда-нибудь станет как у части других бирж на этом же движке (Peatio) — вложенным
    // в "ticker" — пробуем оба варианта, лишь бы курс точно не потерялся молча.
    const raw = t && (t.last ?? (t.ticker && t.ticker.last));
    if (debugOut) debugOut[ticker].raw = raw ?? null;
    const p = parseFloat(raw);
    return p > 0 ? p : null;
  } catch (e) {
    if (debugOut) debugOut[ticker] = { error: e && e.message ? e.message : String(e) };
    return null;
  }
}

async function usdFx(env) {
  const cached = await env.CATALOG.get("fx_usd", "json");
  if (cached && Date.now() - cached.t < 24 * 3600 * 1000) return cached.rates;
  const r = await fetch("https://open.er-api.com/v6/latest/USD");
  if (!r.ok) throw new Error("fx http " + r.status);
  const d = await r.json();
  if (d && d.rates) await env.CATALOG.put("fx_usd", JSON.stringify({ t: Date.now(), rates: d.rates }));
  return (d && d.rates) || null;
}

// Возвращает { prices: { TICKER: { usd, eur, rub } | null }, sources: { TICKER: источник } }.
// 1) свежий курс из кэша Cloudflare (3 мин, по каждой монете отдельно; кэш Cloudflare бесплатный и
//    не тратит лимит записей KV) → 2) WhatToMine (все GPU-монеты одним запросом) → 3) CoinGecko
//    (бесплатный API часто отказывает запросам из сети Cloudflare) → 4) Gate.io (проверенные пары) →
// 5) SafeTrade (темные/совсем новые майнерские монеты, которых ещё нет ни на одной из бирж выше) →
// 6) последнее известное значение из KV (pxlast:ТИКЕР, пишется не чаще раза в час на монету).
const PRICE_TTL_S = 180;
const priceCache = () => (typeof caches !== "undefined" && caches.default) || null;
const priceKey = (t) => new Request("https://ocbot-price-cache.invalid/" + encodeURIComponent(t));

async function getPrices(env, tickers, debugOut) {
  const prices = {}, sources = {};
  const cache = priceCache();
  if (cache) {
    await Promise.all(tickers.map(async (t) => {
      try {
        const hit = await cache.match(priceKey(t));
        if (hit) { const d = await hit.json(); prices[t] = d.p; sources[t] = d.src; }
      } catch { /* кэш необязателен */ }
    }));
  }
  let missing = tickers.filter((t) => !prices[t]);
  const fresh = {};
  if (missing.length) {
    try {
      const wt = await fetchWtmPrices(missing, env);
      for (const t of missing) if (wt[t]) { fresh[t] = wt[t]; sources[t] = "whattomine"; }
    } catch (e) {
      if (debugOut) debugOut.wtmError = e && e.message ? e.message : String(e);
    }
    missing = missing.filter((t) => !fresh[t]);
  }
  if (missing.length) {
    try {
      const cg = await fetchCoinGeckoPrices(missing, env, debugOut);
      for (const t of missing) if (cg[t]) { fresh[t] = cg[t]; sources[t] = "coingecko"; }
    } catch (e) {
      if (debugOut) debugOut.cgError = e && e.message ? e.message : String(e);
    }
    missing = missing.filter((t) => !fresh[t]);
  }
  if (missing.length) {
    try {
      const rates = await usdFx(env);
      const fromGate = await Promise.all(missing.map((t) => fetchGateUsd(t).catch(() => null)));
      missing.forEach((t, i) => {
        const usd = fromGate[i];
        if (usd != null && rates) { fresh[t] = { usd, eur: usd * rates.EUR, rub: usd * rates.RUB }; sources[t] = "gate.io"; }
      });
      if (debugOut) debugOut.gateFx = { rates: rates ? "ok" : null, fromGate };
    } catch (e) {
      if (debugOut) debugOut.gateError = e && e.message ? e.message : String(e);
    }
    missing = missing.filter((t) => !fresh[t]);
  }
  if (missing.length) {
    try {
      const rates = await usdFx(env);
      const safeDebug = debugOut ? {} : null;
      const fromSafeTrade = await Promise.all(missing.map((t) => fetchSafeTradeUsd(t, safeDebug).catch(() => null)));
      missing.forEach((t, i) => {
        const usd = fromSafeTrade[i];
        if (usd != null && rates) { fresh[t] = { usd, eur: usd * rates.EUR, rub: usd * rates.RUB }; sources[t] = "safe.trade"; }
      });
      if (debugOut) debugOut.safeTradeFx = { rates: rates ? "ok" : null, fromSafeTrade, detail: safeDebug, fetchDebug: safeTradeDebug };
    } catch (e) {
      if (debugOut) debugOut.safeTradeError = e && e.message ? e.message : String(e);
    }
    missing = missing.filter((t) => !fresh[t]);
  }
  for (const [t, p] of Object.entries(fresh)) {
    prices[t] = p;
    if (cache) {
      try {
        await cache.put(priceKey(t), new Response(JSON.stringify({ p, src: sources[t] }), { headers: { "cache-control": `max-age=${PRICE_TTL_S}` } }));
      } catch { /* кэш необязателен */ }
    }
    try {
      const last = await env.CATALOG.get("pxlast:" + t, "json");
      if (!last || Date.now() - last.t > 3600 * 1000) await env.CATALOG.put("pxlast:" + t, JSON.stringify({ t: Date.now(), p, src: sources[t] }));
    } catch { /* лимит записей KV не должен ронять ответ */ }
  }
  // То, что не получилось нигде, — последнее известное значение (устаревшее, но не пустое).
  for (const t of missing) {
    try {
      const last = await env.CATALOG.get("pxlast:" + t, "json");
      if (last && last.p) { prices[t] = last.p; sources[t] = "last-known"; }
    } catch { /* нет — значит нет */ }
  }
  return { prices, sources };
}
// -----------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------------------
// Кривая «разгон → хешрейт» (таблица на карточке модели и калькулятор под ней).
// Риг присылает в поле curves замеры точек подбора: по набору на карту + алгоритм + майнер + версию.
// Карта приходит односторонним хешем (не UUID), здесь он ещё раз прогоняется через HMAC с SALT.
// Хранение: ключ pts:<карта>:<риг> — одна запись на карту на риге; перезаписывается, только если данные
// поменялись (бережём лимит записей KV). Одна и та же карта, переставленная на другой риг, — одна карта:
// при сборке её точки с разных ригов объединяются.
// Сборка: точки многих карт одной модели (модель+память+алгоритм+майнер+версия) раскладываются по шагам
// разгона (core по 25, mem по 100) отдельно для каждой оси; в каждой строке медиана хешрейта по картам,
// которые этот шаг прошли, и сколько карт его держат. Карта, отвалившаяся на +200, считается «не держит»
// и для всех шагов выше, на которых у неё нет удачного замера. Так одна карта покрывает начало таблицы,
// другая — конец, и вместе они дают полную кривую.
// ------------------------------------------------------------------------------------------------------------
const AXES = { core: { i: 0, step: 25 }, mem: { i: 1, step: 100 } };
const cleanModel = (m) => m.replace(/^NVIDIA\s+/i, "").replace(/^GeForce\s+/i, "").replace(/\s+/g, " ").trim();
const cleanMiner = (m) => m.replace(/[-_ ]v?\d[\w.\-]*$/i, "");

function cleanCurve(c) {
  if (!c || typeof c !== "object" || !/^[0-9a-f]{32}$/.test(c.card || "")) return null;
  if (!isStr(c.model, 1, 60) || !isStr(c.algo, 1, 30) || !isStr(c.miner, 1, 30) || !isStr(c.miner_version, 1, 30)) return null;
  const mv = c.mem_vendor == null ? "" : c.mem_vendor;
  if (!isStr(mv, 0, 30) || !Array.isArray(c.pts) || !c.pts.length || c.pts.length > 600) return null;
  const pts = [];
  for (const p of c.pts) {
    if (!Array.isArray(p) || p.length !== 8) continue;
    const [core, mem, pl, h, w, ok, crash, heat] = p;
    if (!isInt(core, -1000, 1000) || !isInt(mem, -3000, 3000) || !isInt(pl, 30, 700)) continue;
    if (!isInt(ok, 0, 10000) || !isInt(crash, 0, 10000) || !isInt(heat, 0, 10000) || ok + crash + heat === 0) continue;
    const hash = ok > 0 && isNum(h, 0, 1e7) ? h : null, pw = ok > 0 && isNum(w, 5, 800) ? w : null;
    if (ok > 0 && hash == null) continue;                 // «прошла», но без хешрейта — мусор
    pts.push([core, mem, pl, hash, pw, ok, crash, heat]);
  }
  const kept = dropForeignPl(pts);
  if (!kept.length) return null;
  const board = typeof c.board === "string" && /^[A-Za-z0-9][A-Za-z0-9 .\-]{0,19}$/.test(c.board.trim()) ? c.board.trim() : "";
  return { card: c.card, model: cleanModel(c.model), mem_vendor: mv.trim(), algo: c.algo.trim().toLowerCase(),
           miner: cleanMiner(c.miner), miner_version: c.miner_version, ...(board ? { board } : {}), pts: kept };
}

// Точки «держит», снятые не на том лимите мощности, что выставлял бот (лимит перезаписал OC-профиль HiveOS и т.п.;
// встречено на RTX 3070 Ti: ~160 Вт при PL 200–315 и хешрейт на 15–20% ниже). То же правило, что ocbot/curve.py
// pl_not_applied: карта тянет больше лимита, или при близком ядре (−50…+100) и не большем лимите на той же памяти
// у этой карты хешрейт был выше больше чем на 6%. Такие точки «держит» выбрасываются, отвалы в них остаются.
function plNotApplied(pts) {
  const ok = pts.map((p, i) => [i, p]).filter(([, p]) => p[5] > 0 && p[3]);
  const bad = new Set(ok.filter(([, p]) => p[4] != null && p[4] > p[2] * 1.05 + 5).map(([i]) => i));
  const ref = ok.filter(([i]) => !bad.has(i));
  for (const [i, p] of ref) {
    for (const [j, q] of ref) {
      const dc = p[0] - q[0];
      if (j !== i && q[1] === p[1] && dc >= -50 && dc <= 100 && q[2] <= p[2] && q[3] > p[3] * 1.06) { bad.add(i); break; }
    }
  }
  return bad;
}
function dropForeignPl(pts) {
  const bad = plNotApplied(pts), out = [];
  pts.forEach((p, i) => {
    if (!bad.has(i)) out.push(p);
    else if (p[6] || p[7]) out.push([p[0], p[1], p[2], null, null, 0, p[6], p[7]]);
  });
  return out;
}

// Тело присылки: обычный JSON или gzip (Content-Encoding: gzip). Сжатая присылка в 5–10 раз меньше: на части ригов
// (rig35E2AC, 02.11) POST больше ~16 КБ обрывается в сети, и точки кривой не доходили. Распакованное тело — не больше
// 1 МБ, иначе null (413).
async function readBody(req) {
  const enc = (req.headers.get("content-encoding") || "").toLowerCase();
  if (enc !== "gzip") return await req.text();
  const stream = req.body.pipeThrough(new DecompressionStream("gzip"));
  const reader = stream.getReader(), parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 1048576) { try { await reader.cancel(); } catch { /* уже закрыт */ } return null; }
    parts.push(value);
  }
  const all = new Uint8Array(size);
  let off = 0;
  for (const p of parts) { all.set(p, off); off += p.length; }
  return new TextDecoder().decode(all);
}

async function sha(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

// Возвращает, сколько точек принято; пишет только изменившиеся карты.
async function storeCurves(env, curves, rigHash) {
  const byCard = new Map();
  for (const c of curves) {
    const ch = await hmacHex(env.SALT, "card:" + c.card);
    if (!byCard.has(ch)) byCard.set(ch, []);
    const { card, ...rest } = c;
    byCard.get(ch).push(rest);
  }
  let points = 0, changed = false;
  for (const [ch, sets] of byCard) {
    sets.sort((a, b) => [a.algo, a.miner, a.miner_version].join("|").localeCompare([b.algo, b.miner, b.miner_version].join("|")));
    const raw = JSON.stringify(sets), h = await sha(raw);
    points += sets.reduce((n, s) => n + s.pts.length, 0);
    const key = `pts:${ch}:${rigHash}`;
    const prev = await env.CATALOG.get(key, "json");
    if (prev && prev.h === h) continue;
    await env.CATALOG.put(key, JSON.stringify({ t: Date.now(), h, sets }));
    changed = true;
  }
  if (changed) await env.CATALOG.delete("curves_cache");
  return points;
}

const median = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const r1 = (v, d) => (v == null ? null : Math.round(v * 10 ** d) / 10 ** d);

function axisRows(cards, axis) {
  const { i, step } = AXES[axis], other = 1 - i;
  const perCard = [];
  for (const pts of cards) {
    const b = new Map();
    for (const p of pts) {
      const k = Math.round(p[i] / step) * step;
      const cell = b.get(k) || { best: null, fail: 0, heat: 0 };
      if (p[5] > 0 && (!cell.best || p[3] > cell.best[3])) cell.best = p;
      cell.fail += p[6] + p[7]; cell.heat += p[7];
      b.set(k, cell);
    }
    let failFrom = Infinity;                               // нижний шаг, где карта отвалилась и ни разу не прошла
    for (const [k, c] of b) if (!c.best && c.fail > 0 && k < failFrom) failFrom = k;
    perCard.push({ b, failFrom });
  }
  const keys = [...new Set(perCard.flatMap((c) => [...c.b.keys()]))].sort((x, y) => x - y);
  const rows = [];
  for (const k of keys) {
    const hs = [], ws = [], pls = [], oth = [], effs = [];
    let ok = 0, tested = 0, heat = 0;
    for (const c of perCard) {
      const cell = c.b.get(k);
      if (cell && cell.best) {
        ok++; tested++;
        const p = cell.best; hs.push(p[3]); pls.push(p[2]); oth.push(p[other]);
        if (p[4]) { ws.push(p[4]); effs.push(p[3] / p[4]); }
      } else if ((cell && cell.fail > 0) || k > c.failFrom) {
        tested++;
        if (cell && cell.heat > 0) heat++;
      }
    }
    if (!tested) continue;
    rows.push({ v: k, ok, tested, heat, hashrate: r1(median(hs), 3), h_min: hs.length ? r1(Math.min(...hs), 3) : null,
                h_max: hs.length ? r1(Math.max(...hs), 3) : null, power_w: r1(median(ws), 1), efficiency: r1(median(effs), 5),
                pl: pls.length ? Math.round(median(pls)) : null, [axis === "core" ? "mem" : "core"]: oth.length ? Math.round(median(oth)) : null });
  }
  return rows;
}

function aggregateCurves(docs) {
  const groups = new Map();                                // группа → карта → точки
  for (const { card, sets } of docs) {
    for (const s of sets) {
      const gk = [s.model, s.mem_vendor, s.algo, s.miner, s.miner_version].join("|");
      if (!groups.has(gk)) groups.set(gk, { meta: s, cards: new Map(), boards: new Map() });
      const g = groups.get(gk), merged = g.cards.get(card) || new Map();
      if (s.board) g.boards.set(card, s.board);
      for (const p of dropForeignPl(s.pts)) {
        const pk = p[0] + "|" + p[1] + "|" + p[2], q = merged.get(pk);
        if (!q) { merged.set(pk, [...p]); continue; }
        if (p[5] > 0) {                                    // средний хешрейт, взвешенный по числу удачных замеров
          const n = q[5] + p[5];
          q[3] = ((q[3] || 0) * q[5] + p[3] * p[5]) / n;
          q[4] = q[4] && p[4] ? (q[4] * q[5] + p[4] * p[5]) / n : q[4] || p[4];
          q[5] = n;
        }
        q[6] += p[6]; q[7] += p[7];
      }
      g.cards.set(card, merged);
    }
  }
  const out = [];
  for (const { meta, cards, boards } of groups.values()) {
    const ptsList = [...cards.values()].map((m) => [...m.values()]);
    const axes = {};
    let bestAxis = "core", bestSpread = -1;
    for (const ax of Object.keys(AXES)) {
      const rows = axisRows(ptsList, ax);
      axes[ax] = { step: AXES[ax].step, rows };
      const hs = rows.filter((r) => r.ok > 0).map((r) => r.hashrate);
      const spread = rows.filter((r) => r.ok > 0).length >= 2 ? (Math.max(...hs) - Math.min(...hs)) / Math.max(...hs) : 0;
      if (spread > bestSpread) { bestSpread = spread; bestAxis = ax; }
    }
    // сырые точки для страницы модели (пресеты, простой график, 3D, таблица считаются в браузере):
    // [номер карты, core, mem, pl, хешрейт, Вт, ок, отвалов, перегревов]; карты — по номеру, без кодов
    const pts = [];
    ptsList.forEach((list, ci) => { for (const p of list) pts.push([ci, p[0], p[1], p[2], p[3] == null ? null : r1(p[3], 3), p[4] == null ? null : r1(p[4], 1), p[5], p[6], p[7]]); });
    const bc = {};
    for (const b of boards.values()) bc[b] = (bc[b] || 0) + 1;
    out.push({ model: meta.model, mem_vendor: meta.mem_vendor, algo: meta.algo, miner: meta.miner, miner_version: meta.miner_version,
               cards: cards.size, axis: bestAxis, axes, ...(Object.keys(bc).length ? { boards: bc } : {}), pts: pts.slice(0, 3000) });
  }
  out.sort((a, b) => a.model.localeCompare(b.model) || a.algo.localeCompare(b.algo) || b.cards - a.cards);
  return out;
}

async function allCurves(env) {
  const docs = [];
  let cursor;
  do {
    const page = await env.CATALOG.list({ prefix: "pts:", cursor });
    for (const k of page.keys) {
      const d = await env.CATALOG.get(k.name, "json");
      if (d && Array.isArray(d.sets)) docs.push({ card: k.name.split(":")[1], sets: d.sets });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return aggregateCurves(docs);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    if (req.method === "GET" && url.pathname === "/catalog.json") {
      let cached = await env.CATALOG.get("cache", "json");
      if (!cached || Date.now() - cached.t > 15 * 60 * 1000) {
        const entries = await currentCatalog(env);
        cached = { t: Date.now(), body: { format: "ocbot-catalog", version: 1, created_at: new Date().toISOString(), label: "общий каталог", entries } };
        await env.CATALOG.put("cache", JSON.stringify(cached));
      }
      return json(cached.body, 200, { "cache-control": "public, max-age=300" });
    }

    if (req.method === "POST" && url.pathname === "/submit") {
      if (!env.SALT) return json({ ok: false, error: "salt not set" }, 500);
      const len = parseInt(req.headers.get("content-length") || "0", 10);
      if (len > 1048576) return json({ ok: false, error: "too large" }, 413);   // с точками кривой присылка больше
      let body;
      try { const t = await readBody(req); if (t == null || t.length > 1048576) return json({ ok: false, error: "too large" }, 413); body = JSON.parse(t); }
      catch { return json({ ok: false, error: "bad json" }, 400); }
      if (!body || body.v !== 1 || !/^[0-9a-f]{64}$/.test(body.rid || "") || !Array.isArray(body.entries) || body.entries.length > 60)
        return json({ ok: false, error: "bad format" }, 400);
      if (body.curves != null && (!Array.isArray(body.curves) || body.curves.length > 200)) return json({ ok: false, error: "bad format" }, 400);
      const entries = body.entries.map(cleanEntry).filter(Boolean);
      const curves = (body.curves || []).map(cleanCurve).filter(Boolean);
      if (!entries.length && !curves.length) return json({ ok: false, error: "no valid entries" }, 400);
      const rh = await hmacHex(env.SALT, body.rid);
      const key = "rig:" + rh;
      const prev = await env.CATALOG.get(key, "json");
      if (prev && Date.now() - prev.t < 60 * 60 * 1000) return json({ ok: false, error: "too often" }, 429);
      // присылка только с точками кривой не должна затирать прежние пресеты рига
      await env.CATALOG.put(key, JSON.stringify({ t: Date.now(), day: new Date().toISOString().slice(0, 10), entries: entries.length ? entries : (prev && prev.entries) || [] }));
      // каталог пересчитается из свежих снапшотов при следующем запросе (кэш 15 мин)
      await notifyNewAlgos(env, entries);
      const points = curves.length ? await storeCurves(env, curves, rh) : 0;
      return json({ ok: true, accepted: entries.length, ...(points ? { points } : {}) });
    }

    // Сопоставление алгоритма с монетой (для будущего калькулятора доходности). Вызывается владельцем по
    // ссылке из Telegram-уведомления: открыть в браузере — и всё, другого способа задать монету нет и не
    // нужно. ?key= должен совпадать с секретом ADMIN_KEY, иначе 403.
    if (req.method === "GET" && url.pathname === "/admin/setcoin") {
      if (!env.ADMIN_KEY || url.searchParams.get("key") !== env.ADMIN_KEY) return json({ ok: false, error: "forbidden" }, 403);
      const algo = url.searchParams.get("algo");
      const coin = (url.searchParams.get("coin") || "").trim().toUpperCase();
      if (!isStr(algo, 1, 30) || !isStr(coin, 1, 20)) return json({ ok: false, error: "algo and coin required" }, 400);
      await env.CATALOG.put("coin:" + algo, JSON.stringify({ coin, updated_at: new Date().toISOString() }));
      await env.CATALOG.delete("pending:" + algo);
      let resolved = null;
      try {
        resolved = await resolveAndStoreCgId(env, coin);
      } catch { /* курс всё равно подхватится: поиск монеты повторится при запросе цены */ }
      return json({ ok: true, algo, coin, cg_id: resolved });
    }

    // Текущее сопоставление алгоритм → монета, как его задал владелец. Используется страницей-калькулятором
    // доходности для перевода хешрейта/потребления в деньги по курсу монеты.
    if (req.method === "GET" && url.pathname === "/coinmap.json") {
      const map = { ...DEFAULT_COIN_MAP };                   // стартовая таблица как основа
      let cursor;
      do {
        const page = await env.CATALOG.list({ prefix: "coin:", cursor });
        for (const k of page.keys) {
          const d = await env.CATALOG.get(k.name, "json");
          if (d) map[k.name.slice("coin:".length)] = d.coin;   // ручное сопоставление перекрывает стартовую таблицу
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      return json({ format: "ocbot-coinmap", version: 1, map }, 200, { "cache-control": "public, max-age=300" });
    }

    // Курс монеты, полученный на стороне воркера (а не в браузере посетителя) — см. комментарий у getPrices
    // выше. ?tickers=PRL,ERG (через запятую, тикеры как в coinmap.json, до 10 штук). Отдаёт все три валюты
    // сразу (usd/eur/rub) независимо от того, что указано в ?cur= — это разные поля одного и того же ответа
    // CoinGecko, их не дороже получить все сразу, чем какую-то одну.
    if (req.method === "GET" && url.pathname === "/price.json") {
      const tickers = (url.searchParams.get("tickers") || "")
        .split(",").map((s) => s.trim().toUpperCase()).filter(Boolean).slice(0, 10);
      if (!tickers.length) return json({ ok: false, error: "tickers required" }, 400);
      const wantDebug = url.searchParams.get("debug") === "1";
      const debugOut = wantDebug ? {} : null;
      let prices = {}, sources = {};
      try {
        ({ prices, sources } = await getPrices(env, tickers, debugOut));
      } catch (e) {
        if (debugOut) debugOut.outerError = e && e.message ? e.message : String(e);
      }
      for (const t of tickers) if (!(t in prices)) prices[t] = null;
      const body = { ok: true, as_of: new Date().toISOString(), prices, sources };
      if (wantDebug) body._debug = debugOut;
      return json(body, 200, { "cache-control": "public, max-age=60" });
    }

    // Переразрешить тикер → id CoinGecko вручную (если встроенный поиск нашёл не ту монету). ?key=...&ticker=QTC
    if (req.method === "GET" && url.pathname === "/admin/resolve") {
      if (!env.ADMIN_KEY || url.searchParams.get("key") !== env.ADMIN_KEY) return json({ ok: false, error: "forbidden" }, 403);
      const ticker = (url.searchParams.get("ticker") || "").trim().toUpperCase();
      if (!isStr(ticker, 1, 20)) return json({ ok: false, error: "ticker required" }, 400);
      let coins, best = null;
      try {
        coins = await cgSearch(ticker);
        best = pickBestCoin(coins, ticker);
      } catch (e) {
        return json({ ok: false, error: "coingecko unavailable: " + (e && e.message ? e.message : String(e)) }, 502);
      }
      if (best) await env.CATALOG.put("cgid:" + ticker, JSON.stringify({ id: best.id, name: best.name, rank: best.market_cap_rank, updated_at: new Date().toISOString() }));
      return json({ ok: true, ticker, candidates: coins, picked: best });
    }

    // Чистка после перехода на каталог из свежих снапшотов rig:* (04.11): удаляет
    // накопленные best:* (больше не читаются нигде) и сбрасывает кэш каталога.
    // Безопасно вызывать повторно. В отличие от старого backfill, меняет данные,
    // поэтому требует ADMIN_KEY.
    if (url.pathname === "/admin/backfill") {
      if (!env.ADMIN_KEY || url.searchParams.get("key") !== env.ADMIN_KEY) return json({ ok: false, error: "forbidden" }, 403);
      let removed = 0, cursor;
      do {
        const page = await env.CATALOG.list({ prefix: "best:", cursor });
        for (const k of page.keys) { await env.CATALOG.delete(k.name); removed++; }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      await env.CATALOG.delete("cache");
      return json({ ok: true, best_removed: removed });
    }

    // Таблицы «разгон → хешрейт» по моделям (страницы моделей на сайте собираются из этого файла).
    if (req.method === "GET" && url.pathname === "/curves.json") {
      let cached = await env.CATALOG.get("curves_cache", "json");
      if (!cached || Date.now() - cached.t > 30 * 60 * 1000) {
        const curves = await allCurves(env);
        cached = { t: Date.now(), body: { format: "ocbot-curves", version: 1, created_at: new Date().toISOString(), curves } };
        await env.CATALOG.put("curves_cache", JSON.stringify(cached));
      }
      return json(cached.body, 200, { "cache-control": "public, max-age=300" });
    }

    if (url.pathname === "/health") return json({ ok: true });
    return json({ ok: false, error: "not found" }, 404);
  },
};
