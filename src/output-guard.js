// 出站内容守卫（output guard）与熔断。
//
// 背景：进线侧的关键词攻击防御挡的是"送到模型眼前的东西"；但模型被带偏、或者自己跑偏时，
// 真正造成伤害的是**它发出去的那句话**——复述系统提示词、把内部工具名/路径说给群里、
// 冒充【管理员】、反过来向群友索要 token。已有 SENSITIVE_RE 只覆盖路径/凭据，且命中后
// 既没有管理员私信，也没有原文留存。
//
// 本模块负责三件事：
//   ① 规则判定：高危（直接拦）/ 疑似（暂扣审核）；
//   ② 逐字指纹：把当前 preset 提示词和人格卡做成 n-gram 集合，抓"原样复述"；
//   ③ 熔断：窗口内命中次数达到阈值就暂停该会话（或全局）的 AI 出站，到点/手动恢复。
//
// 出站路径的接入点见 bridge.js：
//   auditAndSend()（chat 自动回复）、reserved 社交回复、v2 工具发送三处端点。
//
// 判定是启发式的：高危必须"看着就像凭据/冒充"，疑似宁可真进审核也不要直接丢。

import { SENSITIVE_RE } from './sensitive.js';
import { compactPromptText, normalizePromptText } from './prompt-guard.js';

const DEFAULT_GROUP_TEMPLATE = '⚠️ 这条回复触发了安全防护（{rule}），未发出。';
const DEFAULT_OWNER_TEMPLATE = '🛡️ 回复拦截｜{type}｜{conv}｜{source}｜命中：{rule}｜{status}｜原文：{text}｜{detail}';
const DEFAULT_BREAKER_TEMPLATE = '🔥 出站已熔断：{conv} 在 {minutes} 分钟内命中 {hits} 次（最近：{rule}），已暂停发送 {pauseMinutes} 分钟。回复「解除熔断」或到控制台恢复。';

/** 高危规则：命中即整条不发。 */
const HARD_RULES = Object.freeze([
  {
    id: 'impersonation',
    category: 'impersonation',
    label: '冒充管理员/系统标记',
    patterns: [/【\s*管理员\s*】/, /\[\s*管理员\s*\]/, /【\s*系统\s*】/, /\[\s*system\s*\]/i]
  },
  {
    id: 'credential-request',
    category: 'phishing',
    label: '反向索要凭据',
    patterns: [
      /(把|将|请把|麻烦把|快把)[^。！？!?\n]{0,12}(token|令牌|密钥|密码|验证码|api\s*key|access\s*key|账号密码)[^。！？!?\n]{0,8}(发给我|发我|给我|告诉我|贴出来|发出来|发一下)/i,
      /(告诉我|发给我|提供|交出)[^。！？!?\n]{0,6}(你的|你们的|账号的|绑定的)?(token|令牌|密钥|密码|验证码|api\s*key|access\s*key)/i,
      /(你的|你们的)\s*(token|令牌|密钥|密码|验证码|api\s*key|access\s*key)[^。！？!?\n]{0,8}(发给我|发我|给我|告诉我|贴出来|发出来)/i,
      /(send|give|tell)\s+me\s+(your\s+)?(token|password|passcode|secret|api[\s-]?key|verification\s+code)/i
    ]
  }
]);

/** 疑似规则：命中进审核（或按配置直接拦/仅通知）。 */
const SUSPECT_RULES = Object.freeze([
  {
    id: 'prompt-leak',
    category: 'promptLeak',
    label: '提示词/人设泄露话术',
    patterns: [
      /(我的|本人的|这个?AI的|机器人的|本机的?)(系统提示词|系统提示|提示词|预设|人设|人格设定|设定|规则|指令)[^。！？!?\n]{0,8}(是|如下|写着|要求|规定|让我|叫我)/i,
      /(以下是|这是我的|我的)(系统|开发者|初始|预设)?(提示词|指令|设定|规则|提示)/i,
      /(系统|开发者|预设)(提示词|指令|提示)/i,
      /(my|the)\s+(system\s+prompt|initial\s+instructions|system\s+instructions|persona)/i
    ]
  },
  {
    id: 'internal',
    category: 'internal',
    label: '内部标识泄露',
    patterns: [
      /\b(mcp__[a-z0-9_]+|qq_send_[a-z_]+|qq_get_[a-z_]+|agent\.cordis|bridge\.js|snowluma|state\/|\/api\/|config\.json|DSH)\b/i
    ]
  },
  {
    id: 'protocol',
    category: 'protocol',
    label: '协议/控制标记',
    patterns: [/\[SILENT\]|\[CQ:|@全体成员|\[转发消息/i]
  }
]);

export const OUTPUT_GUARD_DEFAULTS = Object.freeze({
  enabled: true,
  // tiered=高危直接拦、疑似暂扣审核；block=全都直接拦；notify=只通知不拦
  action: 'tiered',
  reviewTimeoutMs: 3 * 60 * 1000,
  hard: Object.freeze({ credentials: true, impersonation: true, credentialRequest: true }),
  suspect: Object.freeze({ promptLeak: true, fingerprint: true, internal: true, protocol: true, custom: true }),
  keywords: Object.freeze([]),
  extraPatterns: Object.freeze([]),
  fingerprint: Object.freeze({ minChars: 14, minHits: 1 }),
  notifyGroup: Object.freeze({ enabled: false, cooldownMs: 60 * 1000, template: DEFAULT_GROUP_TEMPLATE }),
  notifyOwner: Object.freeze({ enabled: true, cooldownMs: 60 * 1000, template: DEFAULT_OWNER_TEMPLATE }),
  skipOwnerPrivate: true,
  blockedReply: '',
  breaker: Object.freeze({
    enabled: true,
    threshold: 5,
    windowMs: 10 * 60 * 1000,
    pauseMs: 15 * 60 * 1000,
    scope: 'conversation',
    countHard: true,
    countSuspect: true,
    notifyOwner: true,
    template: DEFAULT_BREAKER_TEMPLATE
  })
});

export const OUTPUT_GUARD_LIMITS = Object.freeze({
  keywords: 50,
  keywordLength: 50,
  extraPatterns: 20,
  patternLength: 500,
  templateLength: 500,
  reviewTimeoutMinMs: 60 * 1000,
  reviewTimeoutMaxMs: 60 * 60 * 1000,
  cooldownMaxMs: 60 * 60 * 1000,
  fingerprintMinChars: 8,
  fingerprintMaxChars: 40,
  fingerprintMinHits: 1,
  fingerprintMaxHits: 10,
  breakerThresholdMin: 1,
  breakerThresholdMax: 50,
  breakerWindowMinMs: 60 * 1000,
  breakerWindowMaxMs: 24 * 60 * 60 * 1000,
  breakerPauseMinMs: 60 * 1000,
  breakerPauseMaxMs: 24 * 60 * 60 * 1000
});

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

export function mergeOutputGuardConfig(raw) {
  const src = asObject(raw);
  const hard = asObject(src.hard);
  const suspect = asObject(src.suspect);
  const fingerprint = asObject(src.fingerprint);
  const notifyGroup = asObject(src.notifyGroup);
  const notifyOwner = asObject(src.notifyOwner);
  const breaker = asObject(src.breaker);
  return {
    ...OUTPUT_GUARD_DEFAULTS,
    ...src,
    hard: { ...OUTPUT_GUARD_DEFAULTS.hard, ...hard },
    suspect: { ...OUTPUT_GUARD_DEFAULTS.suspect, ...suspect },
    fingerprint: { ...OUTPUT_GUARD_DEFAULTS.fingerprint, ...fingerprint },
    notifyGroup: { ...OUTPUT_GUARD_DEFAULTS.notifyGroup, ...notifyGroup },
    notifyOwner: { ...OUTPUT_GUARD_DEFAULTS.notifyOwner, ...notifyOwner },
    keywords: Array.isArray(src.keywords) ? src.keywords.map((s) => String(s ?? '')) : [],
    extraPatterns: Array.isArray(src.extraPatterns) ? src.extraPatterns.map((s) => String(s ?? '')) : [],
    breaker: { ...OUTPUT_GUARD_DEFAULTS.breaker, ...breaker }
  };
}

export function validateOutputGuardPatterns(patterns) {
  const bad = [];
  for (const source of Array.isArray(patterns) ? patterns : []) {
    if (typeof source !== 'string' || !source.trim()) { bad.push(String(source ?? '')); continue; }
    if (source.length > OUTPUT_GUARD_LIMITS.patternLength) { bad.push(source); continue; }
    try { new RegExp(source, 'i'); } catch { bad.push(source); }
  }
  return bad;
}

let preparedCache = null;

function compileKeywords(list) {
  const out = [];
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const text = raw.trim();
    if (!text) continue;
    const norm = normalizePromptText(text);
    if (!norm) continue;
    out.push({ raw: text, norm, compact: compactPromptText(text) });
  }
  return out;
}

function compileExtra(list) {
  const out = [];
  for (const source of list) {
    if (typeof source !== 'string') continue;
    const text = source.trim();
    if (!text || text.length > OUTPUT_GUARD_LIMITS.patternLength) continue;
    try { out.push({ source: text, re: new RegExp(text, 'i') }); } catch { /* 坏正则跳过 */ }
  }
  return out;
}

function preparedFor(options) {
  const keywords = Array.isArray(options?.keywords) ? options.keywords : [];
  const extra = Array.isArray(options?.extraPatterns) ? options.extraPatterns : [];
  if (preparedCache && preparedCache.keywordsSrc === keywords && preparedCache.extraSrc === extra) return preparedCache;
  preparedCache = { keywordsSrc: keywords, extraSrc: extra, keywords: compileKeywords(keywords), extra: compileExtra(extra) };
  return preparedCache;
}

function clip(value, max = 80) {
  const s = String(value ?? '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function result(tier, rule, evidence) {
  return {
    tier,
    id: rule.id,
    category: rule.category,
    label: rule.label,
    evidence: clip(evidence)
  };
}

function matchRules(rules, tier, text, compact) {
  for (const rule of rules) {
    for (const re of rule.patterns) {
      const match = re.exec(text);
      if (match) return result(tier, rule, match[0]);
    }
    // 有些规则是中文短语，允许在"去分隔符"的紧凑串上再跑一遍（防空格/标点拆字）。
    if (rule.compact !== false) {
      for (const re of rule.patterns) {
        const match = re.exec(compact);
        if (match) return result(tier, rule, match[0]);
      }
    }
  }
  return null;
}

/**
 * 判定一条出站文本。
 *
 * @param {string} text
 * @param {object} [options] security.outputGuard
 * @param {{knownToken?:boolean, sensitive?:boolean}} [extras]
 *   已知会话令牌 / SENSITIVE_RE 由 bridge 判定后传进来，模块本身不持有令牌名单。
 * @returns {{tier:'hard'|'suspect',id:string,category:string,label:string,evidence:string}|null}
 */
export function matchOutputGuard(text, options = {}, extras = {}) {
  const cfg = options ?? {};
  if (cfg.enabled === false) return null;
  const normalized = normalizePromptText(text);
  if (!normalized) return null;
  const compact = compactPromptText(normalized);
  const hard = asObject(cfg.hard);
  const suspect = asObject(cfg.suspect);

  // 凭据/令牌是既有闸门，这里统一归为高危并给出同一个标签。
  if (extras.knownToken || extras.sensitive) {
    if (hard.credentials !== false) {
      return result('hard', { id: 'credentials', category: 'credentials', label: extras.knownToken ? '已知会话令牌' : '路径/凭据' }, extras.knownToken ? '（会话令牌）' : '（路径/凭据）');
    }
  }

  // 自定义关键词优先于内置规则：管理员明确加的，命中原因就报它。
  const prepared = preparedFor(cfg);
  if (suspect.custom !== false && prepared.keywords.length > 0) {
    for (const keyword of prepared.keywords) {
      if (normalized.includes(keyword.norm) || (keyword.compact && compact.includes(keyword.compact))) {
        return result('suspect', { id: 'custom-keyword', category: 'custom', label: `自定义关键词「${keyword.raw}」` }, keyword.raw);
      }
    }
  }

  for (const rule of HARD_RULES) {
    if (rule.id === 'impersonation' && hard.impersonation === false) continue;
    if (rule.id === 'credential-request' && hard.credentialRequest === false) continue;
    const hit = matchRules([rule], 'hard', normalized, compact);
    if (hit) return hit;
  }

  if (suspect.custom !== false) {
    for (const rule of prepared.extra) {
      const match = rule.re.exec(normalized);
      if (match) return result('suspect', { id: 'extra', category: 'custom', label: '自定义正则' }, match[0]);
    }
  }
  for (const rule of SUSPECT_RULES) {
    if (rule.id === 'prompt-leak' && suspect.promptLeak === false) continue;
    if (rule.id === 'internal' && suspect.internal === false) continue;
    if (rule.id === 'protocol' && suspect.protocol === false) continue;
    const hit = matchRules([rule], 'suspect', normalized, compact);
    if (hit) return hit;
  }
  return null;
}

// ── 逐字指纹（n-gram） ─────────────────────────────────────────────────────

function hash32(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isInteger(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

/**
 * 把若干段"当前生效的提示词"做成窗口集合。
 * 归一化用紧凑串：空格/标点差异不会让复述漏网。
 */
export function buildPromptFingerprint(sources, options = {}) {
  const size = clampInt(options.minChars, OUTPUT_GUARD_LIMITS.fingerprintMinChars, OUTPUT_GUARD_LIMITS.fingerprintMaxChars, 14);
  const grams = new Map();
  let chars = 0;
  const list = Array.isArray(sources) ? sources : [];
  for (const source of list) {
    if (typeof source !== 'string' || !source) continue;
    const text = compactPromptText(source);
    chars += text.length;
    for (let i = 0; i + size <= text.length; i++) {
      const window = text.slice(i, i + size);
      const h = hash32(window);
      if (!grams.has(h)) grams.set(h, window);
    }
  }
  return { minChars: size, grams, size: grams.size, chars, builtAt: Date.now() };
}

/** 在待发文本里找指纹命中；返回命中的窗口片段（用于审核展示）。 */
export function matchPromptFingerprint(text, fingerprint, options = {}) {
  if (!fingerprint || !fingerprint.grams || fingerprint.grams.size === 0) return null;
  const compact = compactPromptText(text);
  const size = fingerprint.minChars;
  if (compact.length < size) return null;
  const minHits = clampInt(options.minHits, OUTPUT_GUARD_LIMITS.fingerprintMinHits, OUTPUT_GUARD_LIMITS.fingerprintMaxHits, 1);
  const hits = [];
  for (let i = 0; i + size <= compact.length; i++) {
    const window = compact.slice(i, i + size);
    const known = fingerprint.grams.get(hash32(window));
    if (known && known === window) {
      hits.push(window);
      i += size - 1;
    }
  }
  if (hits.length < minHits) return null;
  return { count: hits.length, fragment: hits[0], size };
}

// ── 熔断 ───────────────────────────────────────────────────────────────────

/**
 * 出站熔断器：按会话（或全局）统计窗口内命中次数，达到阈值后暂停一段时间。
 * 状态只在内存里（重启即恢复发送），与审核队列同口径。
 */
export function createOutputBreaker() {
  const hits = new Map(); // scopeKey -> number[]
  let pause = null; // { scope, triggeredBy, until, hits, lastRule, triggeredAt }

  function readPause(now) {
    if (pause && now >= pause.until) pause = null;
    return pause;
  }

  return {
    record(scopeKey, ruleLabel, cfg = {}, now = Date.now()) {
      if (!cfg || cfg.enabled === false) return null;
      const windowMs = Math.max(1000, Number(cfg.windowMs) || 0);
      const threshold = Math.max(1, Math.floor(Number(cfg.threshold) || 1));
      const pauseMs = Math.max(1000, Number(cfg.pauseMs) || 0);
      const list = (hits.get(scopeKey) ?? []).filter((t) => now - t < windowMs);
      list.push(now);
      if (list.length > 200) list.splice(0, list.length - 200);
      if (list.length < threshold) {
        hits.set(scopeKey, list);
        return null;
      }
      hits.delete(scopeKey);
      pause = {
        scope: cfg.scope === 'global' ? '*' : scopeKey,
        triggeredBy: scopeKey,
        until: now + pauseMs,
        hits: list.length,
        lastRule: String(ruleLabel ?? ''),
        triggeredAt: now,
        pauseMs,
        windowMs
      };
      return { ...pause };
    },
    /** 返回 null（未熔断）或 { remainingMs, ... }。 */
    paused(scopeKey, now = Date.now()) {
      const current = readPause(now);
      if (!current) return null;
      if (current.scope !== '*' && current.scope !== scopeKey) return null;
      return { ...current, remainingMs: Math.max(0, current.until - now) };
    },
    reset() {
      pause = null;
      hits.clear();
    },
    status(now = Date.now()) {
      const current = readPause(now);
      return current ? { ...current, remainingMs: Math.max(0, current.until - now) } : null;
    },
    hitCount(scopeKey, now = Date.now()) {
      const cfg = { windowMs: 10 * 60 * 1000 };
      return (hits.get(scopeKey) ?? []).filter((t) => now - t < cfg.windowMs).length;
    }
  };
}

/** 管理员私聊口令：解除熔断 / 恢复发送。 */
export function parseBreakerCommand(text) {
  const s = String(text ?? '').trim();
  if (!s || s.length > 20) return null;
  return /^(解除熔断|取消熔断|恢复发送)[。.!！]?$/.test(s) ? { action: 'reset' } : null;
}

// ── 配置校验 ───────────────────────────────────────────────────────────────

const BOOLEAN_FIELDS = Object.freeze({
  enabled: 'outputGuard.enabled',
  skipOwnerPrivate: 'outputGuard.skipOwnerPrivate'
});

/**
 * 校验控制台提交的 outputGuard 补丁，返回合并后的完整配置。
 * 字段白名单 + 类型/范围；有 errors 时调用方不得写盘。
 */
export function validateOutputGuardPatch(raw, current = OUTPUT_GUARD_DEFAULTS) {
  const base = mergeOutputGuardConfig(current);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { errors: ['outputGuard 必须是对象'], next: base };
  }
  const errors = [];
  const next = {
    ...base,
    hard: { ...base.hard },
    suspect: { ...base.suspect },
    fingerprint: { ...base.fingerprint },
    notifyGroup: { ...base.notifyGroup },
    notifyOwner: { ...base.notifyOwner },
    breaker: { ...base.breaker },
    keywords: [...base.keywords],
    extraPatterns: [...base.extraPatterns]
  };

  for (const [key, label] of Object.entries(BOOLEAN_FIELDS)) {
    if (!(key in raw)) continue;
    if (typeof raw[key] !== 'boolean') errors.push(`${label} 必须是布尔值`);
    else next[key] = raw[key];
  }
  if ('action' in raw) {
    if (!['tiered', 'block', 'notify'].includes(raw.action)) errors.push('outputGuard.action 只能是 tiered / block / notify');
    else next.action = raw.action;
  }
  if ('reviewTimeoutMs' in raw) {
    const n = Number(raw.reviewTimeoutMs);
    if (!Number.isInteger(n) || n < OUTPUT_GUARD_LIMITS.reviewTimeoutMinMs || n > OUTPUT_GUARD_LIMITS.reviewTimeoutMaxMs) {
      errors.push(`outputGuard.reviewTimeoutMs 必须是 ${OUTPUT_GUARD_LIMITS.reviewTimeoutMinMs}~${OUTPUT_GUARD_LIMITS.reviewTimeoutMaxMs} 的整数（毫秒）`);
    } else next.reviewTimeoutMs = n;
  }
  if ('blockedReply' in raw) {
    if (typeof raw.blockedReply !== 'string') errors.push('outputGuard.blockedReply 必须是字符串');
    else if (raw.blockedReply.length > OUTPUT_GUARD_LIMITS.templateLength) errors.push(`outputGuard.blockedReply 最多 ${OUTPUT_GUARD_LIMITS.templateLength} 字`);
    else next.blockedReply = raw.blockedReply;
  }

  for (const group of ['hard', 'suspect']) {
    if (!(group in raw)) continue;
    const value = raw[group];
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push(`outputGuard.${group} 必须是对象`);
      continue;
    }
    const before = errors.length;
    const merged = { ...next[group] };
    for (const [key, flag] of Object.entries(value)) {
      if (!(key in merged)) continue; // 未知键忽略（前向兼容）
      if (typeof flag !== 'boolean') errors.push(`outputGuard.${group}.${key} 必须是布尔值`);
      else merged[key] = flag;
    }
    if (errors.length === before) next[group] = merged;
  }

  if ('fingerprint' in raw) {
    const value = raw.fingerprint;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('outputGuard.fingerprint 必须是对象');
    } else {
      const before = errors.length;
      const merged = { ...next.fingerprint };
      if ('minChars' in value) {
        const n = Number(value.minChars);
        if (!Number.isInteger(n) || n < OUTPUT_GUARD_LIMITS.fingerprintMinChars || n > OUTPUT_GUARD_LIMITS.fingerprintMaxChars) {
          errors.push(`outputGuard.fingerprint.minChars 必须是 ${OUTPUT_GUARD_LIMITS.fingerprintMinChars}~${OUTPUT_GUARD_LIMITS.fingerprintMaxChars} 的整数`);
        } else merged.minChars = n;
      }
      if ('minHits' in value) {
        const n = Number(value.minHits);
        if (!Number.isInteger(n) || n < OUTPUT_GUARD_LIMITS.fingerprintMinHits || n > OUTPUT_GUARD_LIMITS.fingerprintMaxHits) {
          errors.push(`outputGuard.fingerprint.minHits 必须是 ${OUTPUT_GUARD_LIMITS.fingerprintMinHits}~${OUTPUT_GUARD_LIMITS.fingerprintMaxHits} 的整数`);
        } else merged.minHits = n;
      }
      if (errors.length === before) next.fingerprint = merged;
    }
  }

  if ('keywords' in raw) {
    if (!Array.isArray(raw.keywords)) {
      errors.push('outputGuard.keywords 必须是数组');
    } else {
      const list = [];
      const seen = new Set();
      for (const item of raw.keywords) {
        if (typeof item !== 'string') { errors.push('outputGuard.keywords 的每一项都必须是字符串'); continue; }
        const text = item.trim();
        if (!text) continue;
        if (text.length > OUTPUT_GUARD_LIMITS.keywordLength) {
          errors.push(`outputGuard.keywords 单条最多 ${OUTPUT_GUARD_LIMITS.keywordLength} 字：${text.slice(0, 20)}…`);
          continue;
        }
        const key = compactPromptText(text) || normalizePromptText(text) || text.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        list.push(text);
      }
      if (list.length > OUTPUT_GUARD_LIMITS.keywords) errors.push(`outputGuard.keywords 最多 ${OUTPUT_GUARD_LIMITS.keywords} 条`);
      else next.keywords = list;
    }
  }
  if ('extraPatterns' in raw) {
    if (!Array.isArray(raw.extraPatterns)) {
      errors.push('outputGuard.extraPatterns 必须是数组');
    } else {
      const list = raw.extraPatterns.map((s) => String(s ?? '').trim()).filter(Boolean);
      if (list.length > OUTPUT_GUARD_LIMITS.extraPatterns) errors.push(`outputGuard.extraPatterns 最多 ${OUTPUT_GUARD_LIMITS.extraPatterns} 条`);
      const bad = validateOutputGuardPatterns(list);
      if (bad.length > 0) errors.push(`无法编译的正则：${bad.join(' / ')}`);
      if (list.length <= OUTPUT_GUARD_LIMITS.extraPatterns && bad.length === 0) next.extraPatterns = list;
    }
  }

  for (const field of ['notifyGroup', 'notifyOwner']) {
    if (!(field in raw)) continue;
    const value = raw[field];
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push(`outputGuard.${field} 必须是对象`);
      continue;
    }
    const before = errors.length;
    const merged = { ...next[field] };
    if ('enabled' in value) {
      if (typeof value.enabled !== 'boolean') errors.push(`outputGuard.${field}.enabled 必须是布尔值`);
      else merged.enabled = value.enabled;
    }
    if ('cooldownMs' in value) {
      const n = Number(value.cooldownMs);
      if (!Number.isInteger(n) || n < 0 || n > OUTPUT_GUARD_LIMITS.cooldownMaxMs) {
        errors.push(`outputGuard.${field}.cooldownMs 必须是 0~${OUTPUT_GUARD_LIMITS.cooldownMaxMs} 的整数（毫秒）`);
      } else merged.cooldownMs = n;
    }
    if ('template' in value) {
      if (typeof value.template !== 'string') errors.push(`outputGuard.${field}.template 必须是字符串`);
      else if (value.template.length > OUTPUT_GUARD_LIMITS.templateLength) errors.push(`outputGuard.${field}.template 最多 ${OUTPUT_GUARD_LIMITS.templateLength} 字`);
      else merged.template = value.template;
    }
    if (errors.length === before) next[field] = merged;
  }

  if ('breaker' in raw) {
    const value = raw.breaker;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('outputGuard.breaker 必须是对象');
    } else {
      const before = errors.length;
      const merged = { ...next.breaker };
      for (const flag of ['enabled', 'countHard', 'countSuspect', 'notifyOwner']) {
        if (!(flag in value)) continue;
        if (typeof value[flag] !== 'boolean') errors.push(`outputGuard.breaker.${flag} 必须是布尔值`);
        else merged[flag] = value[flag];
      }
      if ('threshold' in value) {
        const n = Number(value.threshold);
        if (!Number.isInteger(n) || n < OUTPUT_GUARD_LIMITS.breakerThresholdMin || n > OUTPUT_GUARD_LIMITS.breakerThresholdMax) {
          errors.push(`outputGuard.breaker.threshold 必须是 ${OUTPUT_GUARD_LIMITS.breakerThresholdMin}~${OUTPUT_GUARD_LIMITS.breakerThresholdMax} 的整数`);
        } else merged.threshold = n;
      }
      for (const [key, label] of [['windowMs', 'windowMs'], ['pauseMs', 'pauseMs']]) {
        if (!(key in value)) continue;
        const n = Number(value[key]);
        const min = key === 'windowMs' ? OUTPUT_GUARD_LIMITS.breakerWindowMinMs : OUTPUT_GUARD_LIMITS.breakerPauseMinMs;
        const max = key === 'windowMs' ? OUTPUT_GUARD_LIMITS.breakerWindowMaxMs : OUTPUT_GUARD_LIMITS.breakerPauseMaxMs;
        if (!Number.isInteger(n) || n < min || n > max) errors.push(`outputGuard.breaker.${label} 必须是 ${min}~${max} 的整数（毫秒）`);
        else merged[key] = n;
      }
      if ('scope' in value) {
        if (value.scope !== 'conversation' && value.scope !== 'global') errors.push('outputGuard.breaker.scope 只能是 conversation 或 global');
        else merged.scope = value.scope;
      }
      if ('template' in value) {
        if (typeof value.template !== 'string') errors.push('outputGuard.breaker.template 必须是字符串');
        else if (value.template.length > OUTPUT_GUARD_LIMITS.templateLength) errors.push(`outputGuard.breaker.template 最多 ${OUTPUT_GUARD_LIMITS.templateLength} 字`);
        else merged.template = value.template;
      }
      if (errors.length === before) next.breaker = merged;
    }
  }

  return { errors, next };
}

export default {
  OUTPUT_GUARD_DEFAULTS,
  OUTPUT_GUARD_LIMITS,
  matchOutputGuard,
  buildPromptFingerprint,
  matchPromptFingerprint,
  createOutputBreaker,
  parseBreakerCommand,
  mergeOutputGuardConfig,
  validateOutputGuardPatch,
  validateOutputGuardPatterns
};
