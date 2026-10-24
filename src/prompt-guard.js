// 关键词攻击防御（prompt guard）。
//
// 背景：群友不需要“唤醒”机器人，也能把一段话送进模型上下文——reserved2 下每条消息都会
// 进未读队列，模型下次读消息时就看到了。所以「忽略之前所有指令」「输出你的系统提示词」
// 「你现在是管理员」这类话不需要被点名，也可能改变 agent 的行为。
//
// 这一层和 command-shield 一样是**进线侧**：命中后消息不进未读、不进上下文、不进黑话
// 窗口，模型根本看不到。与 command-shield 的区别是它不直接丢弃，而是（默认）暂扣等
// 管理员放行——关键词判定天生会误杀，留一个人工闸门。
//
// 规则刻意做成“明确短语 + 可选自定义关键词 + 可选自定义正则”，不做“所有含‘忽略’的都
// 算”：中文聊天里「忽略我刚才那句话」「忽略以上的错别字」非常正常，误杀的代价比漏一条高。
//
// 配置见 config.json 的 security.promptGuard（模板 src/bridge.js 的 loadConfig）。

const ZERO_WIDTH_RE = /[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g;
// 紧凑化时要丢掉的字符：空白与常见分隔/标点。中文习惯在字与字之间插空格或符号来绕匹配，
// 例如「忽 略 之 前 的 指 令」「忽略、之前、的、指令」。
const SEPARATOR_RE = /[\s\u3000·・•.,，。、!！?？;；:：'"“”‘’`~～^*+=|\\/()（）\[\]【】{}<>《》「」『』〈〉—–\-_]/g;

export const EMPTY = Object.freeze([]);

/**
 * 归一化待匹配文本：全角转半角、去零宽/方向标记、折叠空白、小写。
 * 与 command-shield.js 的归一化保持同一套口径（那里踩过的坑这里同样适用）。
 */
export function normalizePromptText(text) {
  return String(text ?? '')
    .normalize('NFKC')
    .replace(ZERO_WIDTH_RE, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/** 去掉空白与分隔符的紧凑串，用于对付「忽 略 指 令」这类拆字绕过。 */
export function compactPromptText(text) {
  return normalizePromptText(text).replace(SEPARATOR_RE, '');
}

/**
 * 内置规则。每条规则：
 *   id/category/label —— 日志、控制台、通知里展示；
 *   patterns          —— 在归一化文本上**搜索**（不需要 ^）；
 *   compact           —— 可选，在紧凑串上搜索（应对空格/标点拆字）。
 *
 * 规则只覆盖“明显在指挥模型越过正常聊天”的句式；正常的角色扮演、让 AI 查天气、
 * 讨论安全话题都不应命中。
 */
const RULES = Object.freeze([
  {
    id: 'override-zh',
    category: 'override',
    label: '指令覆盖',
    patterns: [
      /(忽略|无视|忽视|忘掉|忘记|不要理会|别理会|不要管|别管|抛开|丢弃)[^\n。！？!?]{0,12}?(之前|以上|上面|前面|先前|原本|原来|原有|所有|全部|一切|其他|其它|你收到|你的|你)的?(指令|指示|命令|规则|设定|设置|提示词|prompt|要求|限制|约束)/i
    ],
    compact: [
      /(忽略|无视|忽视|忘掉|忘记|不要理会|别理会|不要管|别管|抛开|丢弃)(之前|以上|上面|前面|先前|原本|原来|原有|所有|全部|一切|其他|其它|你收到|你的|你)的?(指令|指示|命令|规则|设定|设置|提示词|prompt|要求|限制|约束)/i
    ]
  },
  {
    id: 'override-en',
    category: 'override',
    label: '指令覆盖（英文）',
    patterns: [
      /(ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)*(?:previous|prior|above|earlier|preceding|system|initial|original)?\s*(?:instructions?|prompts?|rules?|directives?|guidelines?|commands?)/i
    ],
    compact: [
      /(ignore|disregard|forget|override|bypass)(all|any|the|your|these|those)*(previous|prior|above|earlier|preceding|system|initial|original)?(instructions?|prompts?|rules?|directives?|guidelines?|commands?)/i
    ]
  },
  {
    id: 'extract-zh',
    category: 'extract',
    label: '提示词窃取',
    patterns: [
      /(你的|你的完整|你的初始|你的系统|系统的|系统|system|开发者|内置|初始)\s*(系统提示词|系统提示|提示词|提示语|初始提示|人设|设定|规则|指令|prompt)\s*(是什么|是啥|有哪些|发给我|发出来|发一下|告诉我|打印|输出|重复|复述|念一遍|背一遍|展示|贴出来|贴一下|显示|读出来)/i,
      /(重复|复述|念一遍|背一遍|打印|输出|展示)\s*(一下|一遍)?\s*(以上|上面|前面|刚才|你收到的|你的|系统)\s*的?\s*(内容|话|指令|提示|设定|规则|prompt|文字)/i
    ]
  },
  {
    id: 'extract-en',
    category: 'extract',
    label: '提示词窃取（英文）',
    patterns: [
      /(show|print|repeat|reveal|output|display|dump|tell me|give me)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions?|prompts?|rules?|directives?|guidelines?)/i,
      /repeat\s+(the\s+)?(text|words|content|prompt)\s+(above|before)/i
    ]
  },
  {
    id: 'jailbreak',
    category: 'jailbreak',
    label: '越狱/解除限制',
    patterns: [
      /(jailbreak|越狱模式|越狱提示词|无限制模式|上帝模式|dan\s*模式|do\s+anything\s+now)/i,
      /(进入|开启|打开|激活|启用|切换到?)\s*(你的)?\s*开发者模式/i,
      /(解除|绕过|跳过|取消)\s*(你的|系统的|所有|全部|任何)?\s*(安全限制|安全策略|安全规则|内容限制|内容审核|内容政策|道德限制|限制器|限制|审核机制|审查机制|过滤器|审查)/i,
      /你(现在|已经|从此)?\s*(是|变成|成为)\s*(一个)?\s*(没有|不受|不再受|无需遵守)\s*(任何)?\s*(限制|约束|规则|审查|管束)/i
    ]
  },
  {
    id: 'localexec-zh',
    category: 'tool',
    label: '诱导本地操作',
    patterns: [
      /(执行|运行|调用|跑)\s*(一下|下|这个|这条|以下|下面|这段)?\s*(命令|指令|脚本|shell|cmd|powershell|终端|bash)/i,
      /(打开|启动|拉起|唤起|进入)\s*(一下)?\s*(终端|命令行|shell|cmd|powershell)/i,
      /(读取|删除|写入|修改|列出|访问)\s*(本机|本地|系统|服务器|电脑上的|磁盘上的)(的|上的)?\s*(文件|目录|磁盘|注册表)/i,
      /(读取|打开|查看|访问|列出|删除)\s*[a-z]:\\/i,
      /\/etc\/(?:passwd|shadow|hosts)/i,
      /(rm\s+-rf|del\s+\/[fsq]|format\s+[a-z]:|shutdown\s+\/[sr]|reg\s+delete)/i
    ]
  },
  {
    id: 'localexec-en',
    category: 'tool',
    label: '诱导本地操作（英文）',
    patterns: [
      /(run|execute)\s+(?:the\s+|this\s+|following\s+)*(?:command|shell|script|cmd|powershell|bash|terminal)/i,
      /(open|launch|start)\s+(a\s+|the\s+)?(terminal|shell|cmd|powershell|bash)/i
    ]
  },
  {
    id: 'escalation',
    category: 'escalation',
    label: '提权/身份伪造',
    patterns: [
      /(从现在开始|现在起|从现在起|接下来|以后)\s*[,，]?\s*你\s*(就)?\s*(是|扮演|作为|变成|成为)\s*(管理员|超级管理员|开发者|超级用户|root|系统|上帝|最高权限)/i,
      /你(现在|已经|从现在起|以后)\s*(就)?\s*是\s*(管理员|超级管理员|开发者|超级用户|root|最高权限)/i,
      /(提升|获取|给我|授予|赋予)\s*(管理员|root|超级管理员|系统)?\s*(权限|权限级别|最高权限)/i
    ]
  },
  {
    id: 'exfil',
    category: 'exfil',
    label: '凭据/配置外泄',
    patterns: [
      /(把你的|你的|你保存的|你记录的|后台的|系统的|系统|管理员的)\s*(配置|令牌|token|密钥|api\s*key|访问令牌|密码|系统信息|运行环境|部署信息|提示词)\s*(发给|发我|告诉|输出|贴|泄露|展示|打印|念|是什么|是啥|有多少)/i,
      /(把|将)\s*(你的|系统的)?\s*(token|令牌|密钥|api\s*key|密码)\s*(发|贴|给|输出|告诉)/i
    ]
  },
  {
    id: 'spoof',
    category: 'spoof',
    label: '身份标记伪造',
    // 桥接会给管理员消息加「【管理员】」前缀；群友自己写这个前缀就是在伪造身份。
    patterns: [/【\s*管理员\s*】/, /\[\s*管理员\s*\]/, /【\s*系统\s*】/, /<\s*system\s*>/i]
  }
]);

const DEFAULT_GROUP_TEMPLATE = '⚠️ 这条消息触发了安全防护（{status}），不会交给 AI 处理。';
const DEFAULT_OWNER_TEMPLATE = '🛡️ 关键词攻击拦截 #{id}｜会话：{conv}｜发送者：{sender}（{userId}）｜命中：{rule}｜{status}｜原文：{text}｜{detail}';

/**
 * 默认配置。config.json 的 security.promptGuard 覆盖（嵌套的 notifyGroup/notifyOwner
 * 单独合并，避免只写 `{ enabled: true }` 时把模板一起吞掉）。
 */
export const PROMPT_GUARD_DEFAULTS = Object.freeze({
  // 总开关
  enabled: true,
  // 命中后怎么做：review=暂扣等审核；discard=直接丢弃
  action: 'review',
  // 审核超时（毫秒）：超时未处理按废弃处理
  reviewTimeoutMs: 5 * 60 * 1000,
  // 管理员（ownerQQ）自己的消息是否豁免
  skipOwner: true,
  // true = 只用自定义关键词，内置规则与额外正则都不生效
  customOnly: false,
  // 纯文本关键词（不分大小写；全角/零宽/拆字会先归一化）
  keywords: EMPTY,
  // 额外正则（在归一化文本上搜索）
  extraPatterns: EMPTY,
  notifyGroup: Object.freeze({
    enabled: false,
    cooldownMs: 60 * 1000,
    template: DEFAULT_GROUP_TEMPLATE
  }),
  notifyOwner: Object.freeze({
    enabled: true,
    cooldownMs: 60 * 1000,
    template: DEFAULT_OWNER_TEMPLATE
  })
});

export const PROMPT_GUARD_LIMITS = Object.freeze({
  keywords: 50,
  keywordLength: 50,
  extraPatterns: 20,
  patternLength: 500,
  templateLength: 500,
  reviewTimeoutMinMs: 60 * 1000,
  reviewTimeoutMaxMs: 60 * 60 * 1000,
  cooldownMaxMs: 60 * 60 * 1000
});

/**
 * 把「配置文件里写的」合并成完整配置。
 * 只接受普通对象；任何坏形状都退回默认值（不抛错——启动阶段不能因为一处配置写错就崩）。
 */
export function mergePromptGuardConfig(raw) {
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const group = src.notifyGroup && typeof src.notifyGroup === 'object' && !Array.isArray(src.notifyGroup) ? src.notifyGroup : {};
  const owner = src.notifyOwner && typeof src.notifyOwner === 'object' && !Array.isArray(src.notifyOwner) ? src.notifyOwner : {};
  return {
    ...PROMPT_GUARD_DEFAULTS,
    ...src,
    keywords: Array.isArray(src.keywords) ? src.keywords.map((s) => String(s ?? '')) : [],
    extraPatterns: Array.isArray(src.extraPatterns) ? src.extraPatterns.map((s) => String(s ?? '')) : [],
    notifyGroup: { ...PROMPT_GUARD_DEFAULTS.notifyGroup, ...group },
    notifyOwner: { ...PROMPT_GUARD_DEFAULTS.notifyOwner, ...owner }
  };
}

/** 校验额外正则，返回无法编译的条目（供测试/运维排查）。 */
export function validatePromptGuardPatterns(patterns) {
  const bad = [];
  for (const source of Array.isArray(patterns) ? patterns : []) {
    if (typeof source !== 'string' || !source.trim()) { bad.push(String(source ?? '')); continue; }
    if (source.length > PROMPT_GUARD_LIMITS.patternLength) { bad.push(source); continue; }
    try { new RegExp(source, 'i'); } catch { bad.push(source); }
  }
  return bad;
}

// 关键词/正则编译缓存：cfg 对象在配置保存时整体替换，所以按**数组引用**缓存是安全的；
// 每来一条消息都重新编译 50 个关键词没有必要。
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
    if (!text || text.length > PROMPT_GUARD_LIMITS.patternLength) continue;
    try { out.push({ source: text, re: new RegExp(text, 'i') }); } catch { /* 坏正则跳过，不影响整体 */ }
  }
  return out;
}

function preparedFor(options) {
  const keywords = Array.isArray(options?.keywords) ? options.keywords : EMPTY;
  const extra = Array.isArray(options?.extraPatterns) ? options.extraPatterns : EMPTY;
  if (preparedCache && preparedCache.keywordsSrc === keywords && preparedCache.extraSrc === extra) return preparedCache;
  preparedCache = {
    keywordsSrc: keywords,
    extraSrc: extra,
    keywords: compileKeywords(keywords),
    extra: compileExtra(extra)
  };
  return preparedCache;
}

function clip(value, max = 80) {
  const s = String(value ?? '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/**
 * 判断一条进线文本是否像“关键词攻击”（诱导模型做正常聊天之外的事）。
 *
 * @param {string} text 要判定的文本（当前消息正文，或引用原文）
 * @param {object} [options] security.promptGuard 配置
 * @returns {{id:string,category:string,label:string,evidence:string,keyword?:string}|null}
 */
export function matchPromptGuard(text, options = {}) {
  const cfg = options ?? {};
  if (cfg.enabled === false) return null;
  const normalized = normalizePromptText(text);
  if (!normalized) return null;

  const prepared = preparedFor(cfg);
  // 自定义关键词优先级最高：管理员明确配的词，命中原因就报它。
  if (prepared.keywords.length > 0) {
    const compact = compactPromptText(normalized);
    for (const keyword of prepared.keywords) {
      if (normalized.includes(keyword.norm) || (keyword.compact && compact.includes(keyword.compact))) {
        return {
          id: 'custom-keyword',
          category: 'custom',
          label: `自定义关键词「${keyword.raw}」`,
          keyword: keyword.raw,
          evidence: keyword.raw
        };
      }
    }
  }
  // 仅用自定义关键词：内置规则与额外正则都不参与。
  if (cfg.customOnly === true) return null;

  for (const rule of prepared.extra) {
    const match = rule.re.exec(normalized);
    if (match) {
      return { id: 'extra', category: 'custom', label: '自定义正则', evidence: clip(match[0]) };
    }
  }

  const compact = compactPromptText(normalized);
  for (const rule of RULES) {
    for (const re of rule.patterns ?? EMPTY) {
      const match = re.exec(normalized);
      if (match) return { id: rule.id, category: rule.category, label: rule.label, evidence: clip(match[0]) };
    }
    for (const re of rule.compact ?? EMPTY) {
      const match = re.exec(compact);
      if (match) return { id: rule.id, category: rule.category, label: rule.label, evidence: clip(match[0]) };
    }
  }
  return null;
}

/**
 * 渲染通知模板。未知变量原样保留（配置写错了应该看得见，而不是被悄悄吃掉）。
 * 变量：{id} {status} {detail} {conv} {sender} {userId} {rule} {text} {minutes}
 */
export function renderPromptGuardTemplate(template, vars = {}) {
  return String(template ?? '').replace(/\{([a-z]+)\}/gi, (match, name) => {
    const key = String(name).toLowerCase();
    return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key] ?? '') : match;
  });
}

/** 管理员私聊口令：放行 12 / 废弃 #12 / 通过 12 / 拒绝 12。 */
export function parsePromptGuardCommand(text) {
  const s = String(text ?? '').trim();
  if (!s || s.length > 40) return null;
  const match = /^(放行|通过|允许|废弃|拒绝|丢弃)\s*[#＃号]?\s*(\d{1,6})\s*[。.!！]?$/.exec(s);
  if (!match) return null;
  return {
    action: ['放行', '通过', '允许'].includes(match[1]) ? 'allow' : 'discard',
    id: Number(match[2])
  };
}

/**
 * 校验控制台提交的 promptGuard 补丁（字段白名单 + 类型/范围）。
 * 返回 next 为**合并后的完整配置**；有 errors 时调用方不得写盘。
 *
 * @param {object} raw 请求体里的 promptGuard
 * @param {object} [current] 当前生效配置
 * @returns {{errors:string[], next:object}}
 */
export function validatePromptGuardPatch(raw, current = PROMPT_GUARD_DEFAULTS) {
  const base = mergePromptGuardConfig(current);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { errors: ['promptGuard 必须是对象'], next: base };
  }
  const errors = [];
  const next = { ...base, keywords: [...base.keywords], extraPatterns: [...base.extraPatterns], notifyGroup: { ...base.notifyGroup }, notifyOwner: { ...base.notifyOwner } };

  if ('enabled' in raw) {
    if (typeof raw.enabled !== 'boolean') errors.push('promptGuard.enabled 必须是布尔值');
    else next.enabled = raw.enabled;
  }
  if ('action' in raw) {
    if (raw.action !== 'review' && raw.action !== 'discard') errors.push('promptGuard.action 只能是 review 或 discard');
    else next.action = raw.action;
  }
  if ('reviewTimeoutMs' in raw) {
    const n = Number(raw.reviewTimeoutMs);
    if (!Number.isInteger(n) || n < PROMPT_GUARD_LIMITS.reviewTimeoutMinMs || n > PROMPT_GUARD_LIMITS.reviewTimeoutMaxMs) {
      errors.push(`promptGuard.reviewTimeoutMs 必须是 ${PROMPT_GUARD_LIMITS.reviewTimeoutMinMs}~${PROMPT_GUARD_LIMITS.reviewTimeoutMaxMs} 的整数（毫秒）`);
    } else next.reviewTimeoutMs = n;
  }
  if ('skipOwner' in raw) {
    if (typeof raw.skipOwner !== 'boolean') errors.push('promptGuard.skipOwner 必须是布尔值');
    else next.skipOwner = raw.skipOwner;
  }
  if ('customOnly' in raw) {
    if (typeof raw.customOnly !== 'boolean') errors.push('promptGuard.customOnly 必须是布尔值');
    else next.customOnly = raw.customOnly;
  }
  if ('keywords' in raw) {
    if (!Array.isArray(raw.keywords)) {
      errors.push('promptGuard.keywords 必须是数组');
    } else {
      const list = [];
      const seen = new Set();
      for (const item of raw.keywords) {
        if (typeof item !== 'string') { errors.push('promptGuard.keywords 的每一项都必须是字符串'); continue; }
        const text = item.trim();
        if (!text) continue;
        if (text.length > PROMPT_GUARD_LIMITS.keywordLength) {
          errors.push(`promptGuard.keywords 单条最多 ${PROMPT_GUARD_LIMITS.keywordLength} 字：${text.slice(0, 20)}…`);
          continue;
        }
        const key = compactPromptText(text) || normalizePromptText(text) || text.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        list.push(text);
      }
      if (list.length > PROMPT_GUARD_LIMITS.keywords) errors.push(`promptGuard.keywords 最多 ${PROMPT_GUARD_LIMITS.keywords} 条`);
      else next.keywords = list;
    }
  }
  if ('extraPatterns' in raw) {
    if (!Array.isArray(raw.extraPatterns)) {
      errors.push('promptGuard.extraPatterns 必须是数组');
    } else {
      const list = raw.extraPatterns.map((s) => String(s ?? '').trim()).filter(Boolean);
      if (list.length > PROMPT_GUARD_LIMITS.extraPatterns) errors.push(`promptGuard.extraPatterns 最多 ${PROMPT_GUARD_LIMITS.extraPatterns} 条`);
      const bad = validatePromptGuardPatterns(list);
      if (bad.length > 0) errors.push(`无法编译的正则：${bad.join(' / ')}`);
      if (list.length <= PROMPT_GUARD_LIMITS.extraPatterns && bad.length === 0) next.extraPatterns = list;
    }
  }
  for (const field of ['notifyGroup', 'notifyOwner']) {
    if (!(field in raw)) continue;
    const value = raw[field];
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push(`promptGuard.${field} 必须是对象`);
      continue;
    }
    const before = errors.length;
    const merged = { ...next[field] };
    if ('enabled' in value) {
      if (typeof value.enabled !== 'boolean') errors.push(`promptGuard.${field}.enabled 必须是布尔值`);
      else merged.enabled = value.enabled;
    }
    if ('cooldownMs' in value) {
      const n = Number(value.cooldownMs);
      if (!Number.isInteger(n) || n < 0 || n > PROMPT_GUARD_LIMITS.cooldownMaxMs) {
        errors.push(`promptGuard.${field}.cooldownMs 必须是 0~${PROMPT_GUARD_LIMITS.cooldownMaxMs} 的整数（毫秒）`);
      } else merged.cooldownMs = n;
    }
    if ('template' in value) {
      if (typeof value.template !== 'string') errors.push(`promptGuard.${field}.template 必须是字符串`);
      else if (value.template.length > PROMPT_GUARD_LIMITS.templateLength) errors.push(`promptGuard.${field}.template 最多 ${PROMPT_GUARD_LIMITS.templateLength} 字`);
      else merged.template = value.template;
    }
    if (errors.length === before) next[field] = merged;
  }
  return { errors, next };
}

export default {
  PROMPT_GUARD_DEFAULTS,
  PROMPT_GUARD_LIMITS,
  matchPromptGuard,
  normalizePromptText,
  compactPromptText,
  mergePromptGuardConfig,
  validatePromptGuardPatch,
  validatePromptGuardPatterns,
  renderPromptGuardTemplate,
  parsePromptGuardCommand
};
