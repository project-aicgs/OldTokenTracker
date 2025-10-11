// tracker.cjs — Four Meme–only + strict age gate + buys & sells
// CommonJS (Node 18+). Env vars listed in the block below.

require('dotenv').config();
const { Telegraf } = require('telegraf');
const { ethers } = require('ethers');
const fetch = require('node-fetch');
const { walletLabels } = require('./wallets.cjs');

/* =========================
   ENVIRONMENT VARIABLES
   =========================
   BOT_TOKEN=123456:AA...          # Telegram bot token from @BotFather
   CHAT_ID=6487301944              # Your DM/group/channel chat id (use get_chat_id.cjs to discover)
   WSS_RPC_URL=wss://...           # QuickNode/Ankr BSC WebSocket URL
   BSCSCAN_API_KEY=...             # Free key from bscscan.com (for contract creation time)
   HTTPS_RPC_URL=https://...       # Optional: HTTP RPC for reliable historical block queries
   # For best results on age detection, use an Archive HTTPS RPC (e.g., QuickNode with Archive)
   MIN_TOKEN_AGE_WEEKS=0           # Back-compat: Weeks; ignored if DAYS is set
   FOUR_MEME_ONLY=true             # Only alert tokens launched on Four Meme
   WALLETS=0xabc...,0xdef...       # Comma-separated list of tracked wallets
   MIN_TOKEN_AGE_DAYS=1            # Preferred: Only alert if token age >= this many days
   FM_PROXY=0x5c952063c7fc8610FFDB798152D69F0B9550762b   # Four Meme proxy/market addr (override if needed)
   BITQUERY_API_KEY=...            # Optional: improves Four Meme detection via Bitquery
   DEBUG_AGE=false                 # Optional: log why age blocks
   DEBUG_FOURMEME=false            # Optional: log why Four Meme check blocks
   DEBUG_TG=false                  # Optional: mirror debug logs to Telegram chat
   DEBUG_TAP=false                 # Optional: global Transfer tap + block logs
   TAP_BLOCKS_BACK=20              # Optional: how many recent blocks to probe for logs
   TAP_SAMPLE_LIMIT=5              # Optional: sample size to print from recent logs
*/

const {
  BOT_TOKEN,
  CHAT_ID,
  WSS_RPC_URL,
  BSCSCAN_API_KEY,
  HTTPS_RPC_URL = '',
  WALLETS,
  MIN_TOKEN_AGE_DAYS = '0',
  MIN_TOKEN_AGE_WEEKS = '1',
  FOUR_MEME_ONLY = 'false',
  FM_PROXY = '0x5c952063c7fc8610FFDB798152D69F0B9550762b',
  BITQUERY_API_KEY = 'its ',
  DEBUG_AGE = 'false',
  DEBUG_FOURMEME = 'false',
  DEBUG_TG = 'false',
  DEBUG_TAP = 'false',
  TAP_BLOCKS_BACK = '20',
  TAP_SAMPLE_LIMIT = '5'
} = process.env;

if (!BOT_TOKEN || !CHAT_ID || !WSS_RPC_URL || !HTTPS_RPC_URL) {
  console.error('Missing env. Need BOT_TOKEN, CHAT_ID, WSS_RPC_URL, HTTPS_RPC_URL (archive)');
  process.exit(1);
}

const MIN_DAYS = Number(String(MIN_TOKEN_AGE_DAYS ?? '').trim() || '0');
const MIN_WEEKS = Number(String(MIN_TOKEN_AGE_WEEKS ?? '').trim() || '0');
const FM_ONLY = String(FOUR_MEME_ONLY).toLowerCase() === 'true';
const DBG_AGE = String(DEBUG_AGE).toLowerCase() === 'true';
const DBG_FM = String(DEBUG_FOURMEME).toLowerCase() === 'true';
const DBG_TG = String(DEBUG_TG).toLowerCase() === 'true';
const DBG_TAP = String(DEBUG_TAP).toLowerCase() === 'true';
const TAP_BACK = Math.max(0, parseInt(TAP_BLOCKS_BACK, 10) || 0);
const TAP_SAMPLES = Math.max(0, parseInt(TAP_SAMPLE_LIMIT, 10) || 0);
// Union env-provided wallets with local wallet file (minimal behavior change)
const TRACK = new Set([
  ...Array.from(walletLabels.keys()),
  ...((WALLETS && WALLETS.trim()) ? WALLETS.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [])
]);

// --- Telegram ---
const bot = new Telegraf(BOT_TOKEN);
const esc = (s='') => s.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');

async function tgDebug(msg) {
  if (!DBG_TG) return;
  try {
    await bot.telegram.sendMessage(CHAT_ID, `DEBUG: ${msg}`, { disable_web_page_preview: true });
  } catch (e) {
    console.warn('tgDebug failed:', e.message);
  }
}

// Fail fast if chat is wrong (so you don’t miss alerts later)
async function assertChat() {
  try {
    await bot.telegram.sendMessage(
      CHAT_ID,
      `✅ Tracker online.\nWatching ${TRACK.size} wallet(s).\nFilters: ${FM_ONLY ? 'Four Meme only, ' : ''}age ≥ ${MIN_DAYS > 0 ? MIN_DAYS + ' day(s)' : MIN_WEEKS + ' week(s)'} .`,
      { disable_web_page_preview: true }
    );
    await tgDebug(`Startup: FM_ONLY=${FM_ONLY}, MIN=${MIN_DAYS > 0 ? MIN_DAYS + 'd' : MIN_WEEKS + 'w'}, DEBUG_AGE=${DBG_AGE}, DEBUG_FOURMEME=${DBG_FM}`);
  } catch (e) {
    console.error('Telegram test failed:', e.message);
    console.error('➡️  Make sure CHAT_ID is correct for this bot, and the bot is in that chat.');
    process.exit(1);
  }
}

// --- Ethers / chain bits ---
const ERC20_ABI = [
  'event Transfer(address indexed from, address indexed to, uint256 value)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function name() view returns (string)',
  'function balanceOf(address) view returns (uint256)',
  'function totalSupply() view returns (uint256)'
];
const TRANSFER_TOPIC = ethers.id('Transfer(address,address,uint256)');

// caches
const metaCache = new Map();          // token -> {symbol,name,decimals}
const createdCache = new Map();       // token -> { blockNumber, timestamp, nextRetryAt }
const fourCache = new Map();          // token -> boolean (is Four Meme)
const seen = new Set();               // dedupe keys
const RETRY_MS = 5 * 60 * 1000;       // 5 minutes for retrying unknown age

// Strict token age (unknown age => block; retry later)
async function getCreationInfo(token, provider) {
  const addr = ethers.getAddress(token);
  const cached = createdCache.get(addr);
  const now = Date.now();
  if (cached && (cached.timestamp || (cached.nextRetryAt && now < cached.nextRetryAt))) {
    return cached;
  }

  // 1) Prefer BscScan contract creation (fast) to get the block number, then fetch timestamp via QuickNode
  try {
  const url = `https://api.bscscan.com/api?module=contract&action=getcontractcreation&contractaddresses=${addr}&apikey=${BSCSCAN_API_KEY}`;
    const res = await fetch(url);
    const json = await res.json();
    if (json.status === '1' && Array.isArray(json.result) && json.result.length) {
      const row = json.result[0];
      const blockNumber = parseInt(row.blockNumber, 10);
      let timestamp = null;
      try {
        const useProvider = httpProvider || provider;
        const block = await useProvider.getBlock(blockNumber);
        timestamp = block?.timestamp ?? null;
        if (DBG_AGE && timestamp) console.log(`[age] Provider block ts for ${addr}@${blockNumber} -> ${timestamp}`);
        if (timestamp) await tgDebug(`[age] Provider block ts for ${addr}@${blockNumber} -> ${timestamp}`);
      } catch (e) {
        if (DBG_AGE) console.log(`[age] provider.getBlock failed for ${addr} @ ${blockNumber}: ${e.message}`);
        await tgDebug(`[age] provider.getBlock failed for ${addr} @ ${blockNumber}: ${e.message}`);
      }
      if (!timestamp) {
        try {
          const r2 = await fetch(`https://api.bscscan.com/api?module=block&action=getblockreward&blockno=${blockNumber}&apikey=${BSCSCAN_API_KEY}`);
          const j2 = await r2.json();
          const tsStr = j2?.result?.timeStamp;
          let ts = null;
          if (typeof tsStr === 'string') {
            if (/^0x/i.test(tsStr)) ts = Number(BigInt(tsStr)); else ts = parseInt(tsStr, 10);
          }
          if (Number.isFinite(ts)) {
            timestamp = ts;
            if (DBG_AGE) console.log(`[age] BscScan block ts for ${addr}@${blockNumber} -> ${timestamp}`);
            await tgDebug(`[age] BscScan block ts for ${addr}@${blockNumber} -> ${timestamp}`);
          }
        } catch (e) {
          if (DBG_AGE) console.log(`[age] BscScan timestamp fallback failed for ${addr} @ ${blockNumber}: ${e.message}`);
          await tgDebug(`[age] BscScan timestamp fallback failed for ${addr} @ ${blockNumber}: ${e.message}`);
        }
      }
      const info = { blockNumber, timestamp: timestamp ?? null, nextRetryAt: timestamp ? 0 : now + RETRY_MS };
      createdCache.set(addr, info);
      return info;
    }
  } catch (e) {
    if (DBG_AGE) console.log(`[age] getcontractcreation failed for ${addr}: ${e.message}`);
    await tgDebug(`[age] getcontractcreation failed for ${addr}: ${e.message}`);
  }

  // 2) Archive RPC binary search (QuickNode) as a fallback when BscScan does not return creation
  if (httpProvider) {
    try {
      const latest = await httpProvider.getBlockNumber();
      const codeLatest = await httpProvider.getCode(addr, latest);
      if (codeLatest && codeLatest !== '0x') {
        let low = 0, high = latest;
        while (low < high) {
          const mid = Math.floor((low + high) / 2);
          const code = await httpProvider.getCode(addr, mid);
          if (code && code !== '0x') high = mid; else low = mid + 1;
        }
        const firstBlock = low;
        const block = await httpProvider.getBlock(firstBlock);
        const timestamp = block?.timestamp ?? null;
        if (Number.isFinite(firstBlock) && Number.isFinite(timestamp)) {
          if (DBG_AGE) console.log(`[age] Archive RPC creation for ${addr} -> block=${firstBlock}, ts=${timestamp}`);
          await tgDebug(`[age] Archive RPC creation for ${addr} -> block=${firstBlock}, ts=${timestamp}`);
          const info = { blockNumber: firstBlock, timestamp, nextRetryAt: 0 };
          createdCache.set(addr, info);
          return info;
        }
      }
    } catch (e) {
      if (DBG_AGE) console.log(`[age] Archive RPC search failed for ${addr}: ${e.message}`);
      await tgDebug(`[age] Archive RPC search failed for ${addr}: ${e.message}`);
    }
  }

  // 3) Bitquery (optional)
  if (BITQUERY_API_KEY) {
    try {
      const q = `
        query FirstCreation($token: String!) {
          EVM(network: bsc, dataset: combined) {
            Transactions(
              where: { Receipt: { ContractAddress: { is: $token } } }
              orderBy: { ascending: Block_Number }
              limit: { count: 1 }
            ) { Block { Number Time } }
          }
        }`;
      const r = await fetch(BITQUERY_ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${BITQUERY_API_KEY}` }, body: JSON.stringify({ query: q, variables: { token: addr } }) });
      const j = await r.json();
      const row = j?.data?.EVM?.Transactions?.[0];
      if (row?.Block?.Number && row?.Block?.Time) {
        const blockNumber = Number(row.Block.Number);
        const timestamp = Math.floor(new Date(row.Block.Time).getTime() / 1000);
        if (Number.isFinite(blockNumber) && Number.isFinite(timestamp)) {
          if (DBG_AGE) console.log(`[age] Bitquery creation for ${addr} -> block=${blockNumber}, ts=${timestamp}`);
          await tgDebug(`[age] Bitquery creation for ${addr} -> block=${blockNumber}, ts=${timestamp}`);
          const info = { blockNumber, timestamp, nextRetryAt: 0 };
      createdCache.set(addr, info);
      return info;
    }
      }
    } catch (e) {
      if (DBG_AGE) console.log(`[age] Bitquery creation query failed for ${addr}: ${e.message}`);
      await tgDebug(`[age] Bitquery creation query failed for ${addr}: ${e.message}`);
    }
  }
  const info = { blockNumber: null, timestamp: null, nextRetryAt: now + RETRY_MS };
  createdCache.set(addr, info);
  return info;
}

async function isTokenOldEnough(token, provider, minWeeks) {
  // Prefer days if provided; else use weeks
  const minDays = MIN_DAYS;
  const useWeeks = !(Number.isFinite(minDays) && minDays > 0);
  const minReqSecs = useWeeks
    ? (Number.isFinite(minWeeks) ? minWeeks : 0) * 7 * 24 * 3600
    : minDays * 24 * 3600;
  if (!Number.isFinite(minReqSecs) || minReqSecs <= 0) return true;
  const cr = await getCreationInfo(token, provider);
  if (!cr.timestamp) {
    if (DBG_AGE) console.log(`[age] ${token} -> unknown age (blocking, retry after ${new Date(cr.nextRetryAt).toISOString()})`);
    await tgDebug(`[age] ${token} -> unknown age (blocking, retry after ${new Date(cr.nextRetryAt).toISOString()})`);
    return false;
  }
  const ageSecs = Math.max(0, Math.floor(Date.now() / 1000 - cr.timestamp));
  const ok = ageSecs >= minReqSecs;
  if (DBG_AGE) {
    const ageDays = ageSecs / (24 * 3600);
    const ageWeeks = ageSecs / (7 * 24 * 3600);
    const msg = useWeeks
      ? `[age] ${token} -> ${ageWeeks.toFixed(2)}w ${ok ? '≥' : '<'} ${minWeeks}w (${ok ? 'allow' : 'block'})`
      : `[age] ${token} -> ${ageDays.toFixed(2)}d ${ok ? '≥' : '<'} ${MIN_DAYS}d (${ok ? 'allow' : 'block'})`;
    console.log(msg);
    await tgDebug(msg);
  }
  return ok;
}

// Token metadata
async function getTokenMeta(token, provider) {
  const addr = ethers.getAddress(token);
  if (metaCache.has(addr)) return metaCache.get(addr);
  const c = new ethers.Contract(addr, ERC20_ABI, provider);
  let symbol = 'UNKNOWN', name = '', decimals = 18;
  try { symbol = await c.symbol(); } catch {}
  try { name = await c.name(); } catch {}
  try { decimals = await c.decimals(); } catch {}
  const meta = { symbol, name, decimals };
  metaCache.set(addr, meta);
  return meta;
}

// Four Meme detection (Bitquery -> on-chain fallback)
const BITQUERY_ENDPOINT = 'https://streaming.bitquery.io/graphql';

async function isFourMemeToken(token, provider) {
  const addr = ethers.getAddress(token);
  if (fourCache.has(addr)) return fourCache.get(addr);

  // 1) Bitquery (best)
  if (BITQUERY_API_KEY) {
    try {
      const q = `
        query IsFourMemeToken($token: String!) {
          EVM(network: bsc, dataset: combined) {
            BalanceUpdates(
              limit: { count: 1 }
              where: {
                BalanceUpdate: { Address: { is: "${FM_PROXY}" } }
                Currency: { SmartContract: { is: $token } }
              }
            ) { BalanceUpdate { Address } }
          }
        }`;
      const r = await fetch(BITQUERY_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${BITQUERY_API_KEY}` },
        body: JSON.stringify({ query: q, variables: { token: addr } })
      });
      const j = await r.json();
      const hits = j?.data?.EVM?.BalanceUpdates?.length || 0;
      if (hits > 0) {
        fourCache.set(addr, true);
        return true;
      }
      // fall through to on-chain
    } catch (e) {
      if (DBG_FM) console.log(`[fourmeme] Bitquery error for ${addr}: ${e.message}`);
    }
  }

  // 2) On-chain heuristic (proxy reserve / total supply pattern)
  try {
    const c = new ethers.Contract(addr, ERC20_ABI, provider);
    const [bal, tot, dec] = await Promise.all([
      c.balanceOf(FM_PROXY),
      c.totalSupply().catch(() => null),
      c.decimals().catch(() => 18)
    ]);
    // Heuristics (tune if needed)
    const ten = (n) => 10n ** BigInt(n);
    const reserved = 200_000_000n * ten(dec); // e.g., ≥200M tokens at FM proxy
    let isFM = false;
    if (bal >= reserved) {
      isFM = true;
    } else if (tot && bal > 0n) {
      // Common pattern: proxy holds non-trivial portion of supply
      const ratio = Number(bal) / Number(tot);
      if (ratio >= 0.01) isFM = true; // ≥1% at proxy
    }
    fourCache.set(addr, isFM);
    if (DBG_FM && !isFM) console.log(`[fourmeme] ${addr} -> proxy bal too small (bal=${bal.toString()}, tot=${tot ? tot.toString() : 'n/a'})`);
    return isFM;
  } catch (e) {
    if (DBG_FM) console.log(`[fourmeme] on-chain check error for ${addr}: ${e.message}`);
    fourCache.set(addr, false);
    return false;
  }
}

// Dedupe key
function keyFor(token, txHash, from, to, value, side) {
  return `${token}:${txHash}:${from}:${to}:${value.toString()}:${side}`;
}

// Telegram sends
async function sendBuy({ token, symbol, name, amount, decimals, to, txHash, mcapUsd }) {
  const human = ethers.formatUnits(amount, decimals);
  const label = walletLabels.get(to.toLowerCase()) || to;
  const labelLink = `[${esc(label)}](https://bscscan.com/address/${to})`;
  const text = [
    `*${esc(label)}* bought *${esc(symbol)}*`,
    '',
    `Token: *${esc(symbol)}* \\- ${esc(name)}`,
    `Contract: [${esc(token)}](https://bscscan.com/token/${token})`,
    `Amount: *${esc(human)}*`,
    `Wallet: ${labelLink}`,
    mcapUsd ? `MCap: *$${esc(mcapUsd)}*` : null,
    `[View Tx](https://bscscan.com/tx/${txHash})`,
    `[Token Page](https://bscscan.com/token/${token})`
  ].filter(Boolean).join('\n');
  try {
  await bot.telegram.sendMessage(CHAT_ID, text, { parse_mode: 'MarkdownV2', disable_web_page_preview: true });
  } catch (e) {
    console.error('sendBuy markdown error:', e?.response?.description || e.message);
    // Fallback: send plain text without markdown in case of parse issues
    const plain = [
      `${label} bought ${symbol}`,
      `Token: ${symbol} - ${name}`,
      `Contract: ${token}`,
      `Amount: ${human}`,
      `Wallet: https://bscscan.com/address/${to}`,
      mcapUsd ? `MCap: $${mcapUsd}` : null,
      `Tx: https://bscscan.com/tx/${txHash}`,
      `Token: https://bscscan.com/token/${token}`
    ].filter(Boolean).join('\n');
    try {
      await bot.telegram.sendMessage(CHAT_ID, plain, { disable_web_page_preview: true });
    } catch (e2) {
      console.error('sendBuy plain error:', e2?.response?.description || e2.message);
    }
  }
}

async function sendSell({ token, symbol, name, amount, decimals, from, txHash }) {
  const human = ethers.formatUnits(amount, decimals);
  const label = walletLabels.get(from.toLowerCase()) || from;
  const labelLink = `[${esc(label)}](https://bscscan.com/address/${from})`;
  const text = [
    `*${esc(label)}* sold *${esc(symbol)}*`,
    '',
    `Token: *${esc(symbol)}* \\- ${esc(name)}`,
    `Contract: [${esc(token)}](https://bscscan.com/token/${token})`,
    `Amount: *${esc(human)}*`,
    `From: ${labelLink}`,
    `[View Tx](https://bscscan.com/tx/${txHash})`,
    `[Token Page](https://bscscan.com/token/${token})`
  ].join('\n');
  try {
  await bot.telegram.sendMessage(CHAT_ID, text, { parse_mode: 'MarkdownV2', disable_web_page_preview: true });
  } catch (e) {
    console.error('sendSell markdown error:', e?.response?.description || e.message);
    const plain = [
      `${label} sold ${symbol}`,
      `Token: ${symbol} - ${name}`,
      `Contract: ${token}`,
      `Amount: ${human}`,
      `From: https://bscscan.com/address/${from}`,
      `Tx: https://bscscan.com/tx/${txHash}`,
      `Token: https://bscscan.com/token/${token}`
    ].join('\n');
    try {
      await bot.telegram.sendMessage(CHAT_ID, plain, { disable_web_page_preview: true });
    } catch (e2) {
      console.error('sendSell plain error:', e2?.response?.description || e2.message);
    }
  }
}

// Subscribe handlers
function subscribeForWallets(provider) {
  // Simple per-wallet subscriptions (original working logic)
  const wallets = Array.from(TRACK);
  let subCount = 0;
  const RATE_MS = 150; // ~13.3 subs/sec (2 per wallet), under QuickNode 15/sec limit
  let i = 0;

  for (const w of wallets) {
    const addr32 = ethers.zeroPadValue(ethers.getAddress(w), 32);
    const when = i * RATE_MS;

    setTimeout(() => {
    // BUY = to == wallet
    const buyFilter = { address: undefined, topics: [ TRANSFER_TOPIC, null, addr32 ] };
      console.log(`[sub] BUY filter for ${w} (+${when}ms)`);
    provider.on(buyFilter, async (log) => {
      try {
            console.log(`[BUY event] token=${log.address}, tx=${log.transactionHash}`);
            await tgDebug(`[BUY event] token=${log.address}, tx=${log.transactionHash}`);
        const from = ethers.getAddress(ethers.dataSlice(log.topics[1], 12));
        const to   = ethers.getAddress(ethers.dataSlice(log.topics[2], 12));
        if (!TRACK.has(to.toLowerCase())) return;

        const token = ethers.getAddress(log.address);
        if (FM_ONLY && !(await isFourMemeToken(token, provider))) {
          if (DBG_FM) console.log(`[skip] not Four Meme: ${token}`);
              await tgDebug(`[BUY skip] not Four Meme: ${token}`);
          return;
        }
        if (!(await isTokenOldEnough(token, provider, MIN_WEEKS))) return;

        const { symbol, name, decimals } = await getTokenMeta(token, provider);
            // Fetch market cap from Dexscreener (best-effort)
            let mcapUsd = null;
            try {
              const ds = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${token}`).then(r => r.json());
              const pairs = Array.isArray(ds?.pairs) ? ds.pairs : [];
              const top = pairs[0];
              const mcap = top?.fdv || top?.marketCap;
              if (mcap && Number.isFinite(Number(mcap))) mcapUsd = Math.round(Number(mcap)).toLocaleString('en-US');
            } catch {}
        const amount = ethers.getBigInt(log.data);
        const k = keyFor(token, log.transactionHash, from, to, amount, 'BUY');
        if (seen.has(k)) return; if (seen.size > 5000) seen.clear(); seen.add(k);
            await sendBuy({ token, symbol, name, amount, decimals, to, txHash: log.transactionHash, mcapUsd });
            console.log(`[BUY sent] ${symbol} amount=${ethers.formatUnits(amount, decimals)} tx=${log.transactionHash}`);
            await tgDebug(`[BUY sent] ${symbol} amount=${ethers.formatUnits(amount, decimals)} tx=${log.transactionHash}`);
      } catch (err) {
        console.error('buy handler error:', err.message);
      }
    });
      subCount++;

    // SELL = from == wallet
    const sellFilter = { address: undefined, topics: [ TRANSFER_TOPIC, addr32, null ] };
      console.log(`[sub] SELL filter for ${w} (+${when}ms)`);
    provider.on(sellFilter, async (log) => {
      try {
            console.log(`[SELL event] token=${log.address}, tx=${log.transactionHash}`);
            await tgDebug(`[SELL event] token=${log.address}, tx=${log.transactionHash}`);
        const from = ethers.getAddress(ethers.dataSlice(log.topics[1], 12));
        const to   = ethers.getAddress(ethers.dataSlice(log.topics[2], 12));
        if (!TRACK.has(from.toLowerCase())) return;

        const token = ethers.getAddress(log.address);
        if (FM_ONLY && !(await isFourMemeToken(token, provider))) {
          if (DBG_FM) console.log(`[skip] not Four Meme: ${token}`);
              await tgDebug(`[SELL skip] not Four Meme: ${token}`);
          return;
        }
        if (!(await isTokenOldEnough(token, provider, MIN_WEEKS))) return;

        const { symbol, name, decimals } = await getTokenMeta(token, provider);
        const amount = ethers.getBigInt(log.data);
        const k = keyFor(token, log.transactionHash, from, to, amount, 'SELL');
        if (seen.has(k)) return; if (seen.size > 5000) seen.clear(); seen.add(k);
        await sendSell({ token, symbol, name, amount, decimals, from, txHash: log.transactionHash });
            console.log(`[SELL sent] ${symbol} amount=${ethers.formatUnits(amount, decimals)} tx=${log.transactionHash}`);
            await tgDebug(`[SELL sent] ${symbol} amount=${ethers.formatUnits(amount, decimals)} tx=${log.transactionHash}`);
      } catch (err) {
        console.error('sell handler error:', err.message);
      }
    });
      subCount++;
    }, when);

    i++;
  }

  console.log(`Scheduling ${wallets.length} wallet subscriptions at ~${Math.round(1000 / RATE_MS) * 2}/sec…`);
  setTimeout(() => {
    console.log(`Subscribed ~${subCount} filters (expected ${wallets.length * 2}). Waiting for incoming ERC-20 transfers…`);
  }, i * RATE_MS + 500);
}

// Provider lifecycle with health-check & reconnect
let provider = null;
let httpProvider = null; // optional HTTP provider for historical block fetches
let failures = 0;
let healthTimer = null;

async function buildProvider() {
  if (provider) {
    try { provider.destroy?.(); } catch {}
  }
  provider = new ethers.WebSocketProvider(WSS_RPC_URL);
  console.log('Connected to BSC WS');
  await tgDebug('Connected to BSC WS');

  // Build HTTP provider once for historical block fetches if configured
  if (HTTPS_RPC_URL && !httpProvider) {
    try {
      httpProvider = new ethers.JsonRpcProvider(HTTPS_RPC_URL);
      // Touch to validate connectivity (non-fatal if fails)
      await httpProvider.getBlockNumber().catch(() => {});
      if (DBG_AGE) console.log('[age] HTTP provider ready for historical blocks');
      await tgDebug('[age] HTTP provider ready for historical blocks');
    } catch (e) {
      console.warn('HTTP provider setup failed:', e.message);
      await tgDebug(`HTTP provider setup failed: ${e.message}`);
      httpProvider = null;
    }
  }

  subscribeForWallets(provider);

  // Global taps when enabled
  if (DBG_TAP) {
    try {
      provider.on('block', async (bn) => {
        console.log(`[tap] new block ${bn}`);
      });
      // Global Transfer topic tap (no address constraint)
      const globalTransfer = { address: undefined, topics: [ TRANSFER_TOPIC ] };
      provider.on(globalTransfer, async (log) => {
        try {
          const token = log.address;
          const tx = log.transactionHash;
          const from = ethers.getAddress(ethers.dataSlice(log.topics[1], 12));
          const to   = ethers.getAddress(ethers.dataSlice(log.topics[2], 12));
          console.log(`[tap] Transfer token=${token} from=${from} to=${to} tx=${tx}`);
        } catch {}
      });
      await tgDebug('[tap] Global taps enabled');
    } catch (e) {
      console.warn('tap enable failed:', e.message);
      await tgDebug(`tap enable failed: ${e.message}`);
    }

    // Short-range probe for recent Transfer logs to verify flow
    try {
      const current = await provider.getBlockNumber();
      const fromBlock = Math.max(0, current - TAP_BACK);
      const toBlock = current;
      console.log(`[tap] Probing logs from ${fromBlock} to ${toBlock}`);
      await tgDebug(`[tap] Probing logs from ${fromBlock} to ${toBlock}`);
      const logs = await provider.getLogs({ fromBlock, toBlock, topics: [ TRANSFER_TOPIC ] });
      console.log(`[tap] Found ${logs.length} recent Transfer logs`);
      await tgDebug(`[tap] Found ${logs.length} recent Transfer logs`);
      for (let i = 0; i < Math.min(TAP_SAMPLES, logs.length); i++) {
        const l = logs[i];
        const token = l.address;
        const tx = l.transactionHash;
        console.log(`[tap] sample#${i+1} token=${token} tx=${tx}`);
      }
    } catch (e) {
      console.warn('tap probe failed:', e.message);
      await tgDebug(`tap probe failed: ${e.message}`);
    }
  }

  if (healthTimer) clearInterval(healthTimer);
  failures = 0;
  healthTimer = setInterval(async () => {
    try {
      await provider.getBlockNumber();
      failures = 0;
    } catch (e) {
      failures++;
      console.warn('Health check failed:', e.message);
      await tgDebug(`Health check failed: ${e.message}`);
      if (failures >= 2) {
        console.warn('Rebuilding WS provider…');
        await tgDebug('Rebuilding WS provider…');
        clearInterval(healthTimer);
        await buildProvider();
      }
    }
  }, 30_000);
}

// Boot
(async () => {
  await assertChat();      // ensures CHAT_ID is correct
  await buildProvider();   // connect & subscribe
})();
