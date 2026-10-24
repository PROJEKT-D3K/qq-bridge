// 出站内容守卫（output guard）与熔断回归。
//
// 覆盖四层：
//   ① 纯函数：高危/疑似规则、自定义关键词/正则、逐字指纹、熔断状态机、配置校验；
//   ② 自动转发路径（auditAndSend）：高危不发、疑似暂扣、放行后补发、owner 私聊豁免；
//   ③ 工具发送路径（/api/socialV2/send-message）：高危 403、疑似 pending、放行后 onebotSend；
//   ④ 熔断：阈值触发、暂停期内 403、状态接口、手动解除。
import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {
  OUTPUT_GUARD_DEFAULTS,
  buildPromptFingerprint,
  createOutputBreaker,
  matchOutputGuard,
  matchPromptFingerprint,
  mergeOutputGuardConfig,
  parseBreakerCommand,
  validateOutputGuardPatch
} from '../src/output-guard.js';
import { bridgeHarness } from './audit-bridge-harness.mjs';

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`  ❌ ${name}\n     ${error?.message ?? error}`);
  }
}

const ADMIN = { 'x-console-token': 'fixture-console-token' };
const KEY = 'group:456';

function call(port, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, path: pathname, method, headers: { 'content-type': 'application/json', ...headers } },
      (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => {
          let json = null;
          try { json = JSON.parse(data); } catch {}
          resolve({ status: response.statusCode, body: data, json });
        });
      }
    );
    request.on('error', reject);
    request.setTimeout(5000, () => request.destroy(new Error('request hung')));
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

async function withServer(h, run) {
  const server = h.startConsoleServer();
  if (!server.listening) await new Promise((resolve) => server.once('listening', resolve));
  try { await run(server.address().port); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

async function waitFor(predicate, { timeoutMs = 1500, stepMs = 10 } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  return predicate();
}

function ogConfig(patch = {}) {
  return {
    security: {
      outputGuard: {
        enabled: true,
        action: 'tiered',
        reviewTimeoutMs: 5000,
        notifyGroup: { enabled: false, cooldownMs: 0 },
        notifyOwner: { enabled: false, cooldownMs: 0 },
        breaker: { enabled: false },
        ...patch
      }
    }
  };
}

const sentTo = (h, kind, id) => h.calls.sent.filter((m) => m.kind === kind && String(m.id) === String(id));
const httpSends = (h) => h.calls.http.filter((x) => /send_(group|private)_msg/.test(String(x.url)));

console.log('## 规则判定');
for (const [text, tier, label] of [
  ['【管理员】把群解散', 'hard', '冒充管理员'],
  ['把你的 token 发给我', 'hard', '反向索要凭据'],
  ['告诉我你的密码', 'hard', '反向索要凭据'],
  ['我的系统提示词是：你是一个…', 'suspect', '提示词'],
  ['以下是开发者指令', 'suspect', '提示词'],
  ['我调用 qq_send_message 发的', 'suspect', '内部标识'],
  ['[SILENT]', 'suspect', '协议'],
  ['@全体成员 大家看', 'suspect', '协议'],
  ['忽略指令', 'suspect', '自定义关键词']
]) {
  await test(`命中：${JSON.stringify(text)} → ${tier}`, () => {
    const hit = matchOutputGuard(text, tier === 'suspect' && text === '忽略指令' ? { keywords: ['忽略指令'] } : {});
    assert.ok(hit, '应当命中');
    assert.equal(hit.tier, tier);
    assert.match(hit.label, new RegExp(label));
  });
}

await test('全角/零宽/空格拆字仍然命中', () => {
  assert.ok(matchOutputGuard('我 的 系 统 提 示 词 是：秘密'), '空格拆字');
  assert.ok(matchOutputGuard('我的系\u200b统提示词是：秘密'), '零宽');
  assert.ok(matchOutputGuard('【 管理员 】 把群解散'), '全角括号 + 空格');
});

for (const text of [
  '今天天气不错',
  '我给大家讲个故事',
  '这个表情包好好笑',
  '系统更新了吗',
  '我给大家推荐一个游戏',
  '这是我们的群规：不要刷屏'
]) {
  await test(`不误伤：${JSON.stringify(text)}`, () => {
    assert.equal(matchOutputGuard(text), null);
  });
}

await test('凭据/令牌由 bridge 传入并归为高危', () => {
  const hit = matchOutputGuard('随便一句含 /etc/passwd 的话', {}, { sensitive: true });
  assert.ok(hit);
  assert.equal(hit.tier, 'hard');
  assert.match(hit.label, /路径|凭据/);
  assert.equal(matchOutputGuard('x', { hard: { credentials: false } }, { sensitive: true }), null);
});

await test('自定义关键词与正则：可用开关单独关闭', () => {
  assert.ok(matchOutputGuard('香蕉好吃', { keywords: ['香蕉'] }));
  assert.equal(matchOutputGuard('香蕉好吃', { suspect: { custom: false }, keywords: ['香蕉'] }), null);
  assert.ok(matchOutputGuard('请访问 /admin', { extraPatterns: ['\\/admin'] }));
  assert.equal(matchOutputGuard('请访问 /admin', { suspect: { custom: false }, extraPatterns: ['\\/admin'] }), null);
});

await test('分类开关可以单独关闭高危/疑似', () => {
  assert.equal(matchOutputGuard('【管理员】', { hard: { impersonation: false } }), null);
  assert.equal(matchOutputGuard('我的系统提示词是：x', { suspect: { promptLeak: false } }), null);
  assert.equal(matchOutputGuard('我调用 qq_send_message', { suspect: { internal: false } }), null);
  assert.equal(matchOutputGuard('[SILENT]', { suspect: { protocol: false } }), null);
});

console.log('## 逐字指纹');
await test('逐字复述命中；换说法不命中', () => {
  const source = '你是一个很长的系统提示词，里面写着不要复述这些内容，而且还有很多细节。';
  const fp = buildPromptFingerprint([source, '第二段：人格设定要求短句、轻快、不煽情。'], { minChars: 14 });
  assert.ok(fp.size > 0);
  const hit = matchPromptFingerprint('刚刚它说：你是一个很长的系统提示词，里面写着不要复述这些内容。', fp);
  assert.ok(hit, '逐字片段应命中');
  assert.ok(hit.fragment.length >= 14);
  assert.equal(matchPromptFingerprint('我是一个很长的系统提示词，里面提到不要复述', fp), null, '换说法不命中');
  assert.equal(matchPromptFingerprint('短句、轻快、不煽情', fp), null, '短于窗口不命中');
});
await test('minHits 阈值生效', () => {
  const fp = buildPromptFingerprint(['甲乙丙丁戊己庚辛壬癸子丑寅卯'], { minChars: 8 });
  const text = '甲乙丙丁戊己庚辛，中间隔开，壬癸子丑寅卯';
  assert.ok(matchPromptFingerprint(text, fp, { minHits: 1 }));
  assert.equal(matchPromptFingerprint(text, fp, { minHits: 5 }), null);
});

console.log('## 熔断状态机');
await test('阈值 / 窗口 / 暂停 / 恢复', () => {
  const breaker = createOutputBreaker();
  const cfg = { enabled: true, threshold: 2, windowMs: 60000, pauseMs: 30000, scope: 'conversation' };
  assert.equal(breaker.record(KEY, '规则A', cfg), null);
  const triggered = breaker.record(KEY, '规则B', cfg);
  assert.ok(triggered, '第二次命中应触发');
  assert.equal(triggered.hits, 2);
  assert.equal(triggered.lastRule, '规则B');
  assert.ok(breaker.paused(KEY));
  assert.equal(breaker.paused('group:999'), null, '按会话隔离');
  breaker.reset();
  assert.equal(breaker.paused(KEY), null);
  assert.equal(breaker.record(KEY, 'x', { ...cfg, threshold: 2 }), null, 'reset 后计数清零，第一次不应触发');
  assert.ok(breaker.record(KEY, 'y', { ...cfg, threshold: 2 }), '第二次才触发');
});
await test('scope=global 时其它会话也被暂停', () => {
  const breaker = createOutputBreaker();
  breaker.record('group:1', 'x', { enabled: true, threshold: 1, windowMs: 60000, pauseMs: 60000, scope: 'global' });
  assert.ok(breaker.paused('group:2'));
});
await test('窗口外的命中不累计；关闭后不记录', () => {
  const breaker = createOutputBreaker();
  const cfg = { enabled: true, threshold: 2, windowMs: 50, pauseMs: 100, scope: 'conversation' };
  breaker.record(KEY, 'x', cfg, 1000);
  assert.equal(breaker.record(KEY, 'y', cfg, 2000), null, '第一次已过期');
  const off = createOutputBreaker();
  assert.equal(off.record(KEY, 'x', { ...cfg, enabled: false }), null);
});
await test('解除熔断口令', () => {
  assert.deepEqual(parseBreakerCommand('解除熔断'), { action: 'reset' });
  assert.deepEqual(parseBreakerCommand('恢复发送。'), { action: 'reset' });
  assert.equal(parseBreakerCommand('普通聊天'), null);
});

console.log('## 配置');
await test('默认值', () => {
  assert.equal(OUTPUT_GUARD_DEFAULTS.enabled, true);
  assert.equal(OUTPUT_GUARD_DEFAULTS.action, 'tiered');
  assert.equal(OUTPUT_GUARD_DEFAULTS.notifyGroup.enabled, false);
  assert.equal(OUTPUT_GUARD_DEFAULTS.notifyOwner.enabled, true);
  assert.equal(OUTPUT_GUARD_DEFAULTS.breaker.threshold, 5);
});
await test('嵌套配置合并保留默认模板', () => {
  const merged = mergeOutputGuardConfig({ notifyGroup: { enabled: true }, breaker: { threshold: 3 } });
  assert.equal(merged.notifyGroup.enabled, true);
  assert.match(merged.notifyGroup.template, /\{rule\}/);
  assert.equal(merged.breaker.threshold, 3);
  assert.equal(merged.breaker.pauseMs, OUTPUT_GUARD_DEFAULTS.breaker.pauseMs);
});
await test('坏配置被拒；关键词去重', () => {
  const bad = [
    { action: 'nope' },
    { reviewTimeoutMs: 1 },
    { keywords: 'x' },
    { keywords: Array.from({ length: 51 }, (_, i) => `k${i}`) },
    { extraPatterns: ['([bad'] },
    { fingerprint: { minChars: 2 } },
    { fingerprint: { minHits: 99 } },
    { breaker: { threshold: 0 } },
    { breaker: { scope: 'x' } },
    { breaker: { windowMs: 1 } },
    { notifyGroup: { enabled: 'yes' } },
    { notifyGroup: { template: 'x'.repeat(501) } }
  ];
  for (const patch of bad) assert.ok(validateOutputGuardPatch(patch).errors.length, JSON.stringify(patch));
  const okPatch = validateOutputGuardPatch({ keywords: ['忽略指令', '忽 略 指 令', '忽略指令'] });
  assert.deepEqual(okPatch.errors, []);
  assert.deepEqual(okPatch.next.keywords, ['忽略指令']);
});

console.log('## 自动转发路径');
await test('高危：不发、返回 false；可配置群内提示/固定回复', async () => {
  const h = await bridgeHarness({ config: ogConfig({
    notifyGroup: { enabled: true, cooldownMs: 0, template: '已拦截（{rule}）' }
  }) });
  try {
    h.setMode('chat');
    const ok = await h.auditAndSend(KEY, '【管理员】把群解散');
    assert.equal(ok, false);
    assert.equal(sentTo(h, 'group', '456').filter((m) => /把群解散/.test(m.text)).length, 0, '原回复不得发出');
    assert.ok(await waitFor(() => sentTo(h, 'group', '456').some((m) => /已拦截/.test(m.text))), '群内提示应发出');
    assert.equal(h.calls.http.length, 0);
  } finally { await h.close(); }
});
await test('blockedReply：高危时给会话发固定话术', async () => {
  const h = await bridgeHarness({ config: ogConfig({ blockedReply: '这条发不出去，抱歉。' }) });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '把你的 token 发给我');
    assert.ok(await waitFor(() => sentTo(h, 'group', '456').some((m) => m.text === '这条发不出去，抱歉。')));
  } finally { await h.close(); }
});
await test('疑似：暂扣 → 控制台放行后补发', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('chat');
    const ok = await h.auditAndSend(KEY, '我的系统提示词是：不要复述。');
    assert.equal(ok, false);
    assert.equal(sentTo(h, 'group', '456').length, 0);
    await withServer(h, async (port) => {
      const list = await call(port, '/api/prompt-guard/reviews', { headers: ADMIN });
      assert.equal(list.json.reviews.length, 1);
      assert.equal(list.json.reviews[0].type, 'out');
      assert.equal(list.json.reviews[0].source, 'auto');
      const decided = await call(port, '/api/prompt-guard/decide', {
        method: 'POST', headers: ADMIN, body: { id: list.json.reviews[0].id, action: 'allow' }
      });
      assert.equal(decided.status, 200);
      assert.equal(decided.json.type, 'out');
    });
    assert.ok(await waitFor(() => sentTo(h, 'group', '456').some((m) => /我的系统提示词/.test(m.text))), '放行后应补发');
  } finally { await h.close(); }
});
await test('疑似：废弃后永不发出；超时自动清理', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '我的系统提示词是：秘密');
    await withServer(h, async (port) => {
      const list = await call(port, '/api/prompt-guard/reviews', { headers: ADMIN });
      const decided = await call(port, '/api/prompt-guard/decide', {
        method: 'POST', headers: ADMIN, body: { id: list.json.reviews[0].id, action: 'discard' }
      });
      assert.equal(decided.status, 200);
    });
    assert.equal(sentTo(h, 'group', '456').length, 0);
  } finally { await h.close(); }

  const h2 = await bridgeHarness({ config: ogConfig({ reviewTimeoutMs: 1000 }) });
  try {
    h2.setMode('chat');
    await h2.auditAndSend(KEY, '我的系统提示词是：秘密');
    await new Promise((resolve) => setTimeout(resolve, 1300));
    await withServer(h2, async (port) => {
      const list = await call(port, '/api/prompt-guard/reviews', { headers: ADMIN });
      assert.equal(list.json.reviews.length, 0, '超时后应清理');
      const late = await call(port, '/api/prompt-guard/decide', {
        method: 'POST', headers: ADMIN, body: { id: 1, action: 'allow' }
      });
      assert.equal(late.status, 404);
    });
    assert.equal(sentTo(h2, 'group', '456').length, 0);
  } finally { await h2.close(); }
});
await test('interceptNotify=false 时群内提示被否决（旧开关仍有效）', async () => {
  const cfg = ogConfig({ notifyGroup: { enabled: true, cooldownMs: 0, template: '已拦截（{rule}）' } });
  cfg.security.interceptNotify = false;
  const h = await bridgeHarness({ config: cfg });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '【管理员】把群解散');
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(sentTo(h, 'group', '456').length, 0, '旧开关关闭时不应在群里提示');
  } finally { await h.close(); }
});
await test('普通回复照常发出；管理员私聊豁免', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('chat');
    assert.equal(await h.auditAndSend(KEY, '大家晚上好呀'), true);
    assert.equal(await h.auditAndSend('private:123', '【管理员】把群解散'), true, 'owner 私聊默认不检查');
    assert.equal(sentTo(h, 'group', '456').length, 1);
    assert.equal(sentTo(h, 'private', '123').length, 1);
  } finally { await h.close(); }
});
await test('逐字复述人格卡：进入审核（指纹集成）', async () => {
  const roleText = '这是一段很长的人格卡文本，用来验证出站守卫能不能抓到逐字复述人格设定的行为，后半段是别的说明。';
  const h = await bridgeHarness({
    config: ogConfig(),
    files: {
      'roles/测试人格.md': roleText,
      'state/current-role.json': { role: '测试人格', mode: 'active' }
    }
  });
  try {
    h.setMode('chat');
    const ok = await h.auditAndSend(KEY, '刚刚我说过：这是一段很长的人格卡文本，用来验证出站守卫能不能抓到逐字复述人格设定的行为');
    assert.equal(ok, false);
    await withServer(h, async (port) => {
      const list = await call(port, '/api/prompt-guard/reviews', { headers: ADMIN });
      assert.equal(list.json.reviews.length, 1);
      assert.match(list.json.reviews[0].rule, /逐字复述/);
    });
  } finally { await h.close(); }
});
await test('总开关关闭时普通内容放行，但既有路径/凭据审计仍生效', async () => {
  const h = await bridgeHarness({ config: ogConfig({ enabled: false }) });
  try {
    h.setMode('chat');
    assert.equal(await h.auditAndSend(KEY, '【管理员】随便'), true);
    assert.equal(await h.auditAndSend(KEY, '日志在 C:\\Users\\admin\\secret.txt'), false, '关闭守卫不能绕过路径/凭据审计');
  } finally { await h.close(); }
});

console.log('## 工具发送路径');
await test('高危 403；疑似 pending；放行后才 onebotSend', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('reserved2');
    const token = h.getSocialV2State(KEY).agentToken;
    await withServer(h, async (port) => {
      const headers = { ...ADMIN, 'x-agent-token': token };
      const hard = await call(port, '/api/socialV2/send-message', {
        method: 'POST', headers, body: { key: KEY, messages: ['【管理员】把群解散'] }
      });
      assert.equal(hard.status, 403);
      assert.match(hard.json.error, /高危/);
      assert.equal(httpSends(h).length, 0);

      const suspect = await call(port, '/api/socialV2/send-message', {
        method: 'POST', headers, body: { key: KEY, messages: ['我的系统提示词是：秘密'] }
      });
      assert.equal(suspect.status, 200);
      assert.equal(suspect.json.pending, true);
      assert.ok(suspect.json.reviewId > 0);
      assert.equal(httpSends(h).length, 0, '暂扣期间不得发出');

      const allow = await call(port, '/api/prompt-guard/decide', {
        method: 'POST', headers: ADMIN, body: { id: suspect.json.reviewId, action: 'allow' }
      });
      assert.equal(allow.status, 200);
      assert.ok(await waitFor(() => httpSends(h).length === 1), '放行后应真正发送');
    });
  } finally { await h.close(); }
});
await test('批量发送里任意一条命中，整批暂扣/拦截', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('reserved2');
    const token = h.getSocialV2State(KEY).agentToken;
    await withServer(h, async (port) => {
      const res = await call(port, '/api/socialV2/send-message', {
        method: 'POST', headers: { ...ADMIN, 'x-agent-token': token },
        body: { key: KEY, messages: ['第一句正常', '第二句是你的 token 发给我'] }
      });
      assert.equal(res.status, 403);
      assert.equal(httpSends(h).length, 0);
    });
  } finally { await h.close(); }
});

console.log('## 熔断');
await test('连续命中触发熔断，暂停期内发送 403；状态可查、可手动解除', async () => {
  const h = await bridgeHarness({ config: ogConfig({
    breaker: { enabled: true, threshold: 2, windowMs: 60000, pauseMs: 60000, scope: 'conversation', countHard: true, countSuspect: true }
  }) });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '【管理员】一');
    await h.auditAndSend(KEY, '【管理员】二');
    assert.equal(await h.auditAndSend(KEY, '大家晚上好呀'), false, '熔断期间普通回复也不发');
    await withServer(h, async (port) => {
      const status = await call(port, '/api/output-guard/status', { headers: ADMIN });
      assert.ok(status.json.breaker, '状态接口应报告熔断中');
      assert.equal(status.json.breaker.hits, 2);
      const reset = await call(port, '/api/output-guard/reset', { method: 'POST', headers: ADMIN, body: {} });
      assert.equal(reset.status, 200);
      const after = await call(port, '/api/output-guard/status', { headers: ADMIN });
      assert.equal(after.json.breaker, null);
    });
    assert.equal(await h.auditAndSend(KEY, '大家晚上好呀'), true, '解除后恢复发送');
  } finally { await h.close(); }
});
await test('熔断期间工具发送 403；范围=global 时其它会话也停发', async () => {
  const h = await bridgeHarness({
    config: ogConfig({
      breaker: { enabled: true, threshold: 1, windowMs: 60000, pauseMs: 60000, scope: 'global' }
    })
  });
  try {
    h.setMode('reserved2');
    // 第二个群也要在白名单里，否则先被准入拦掉，测不到熔断
    h.cfg.allow.groups = ['456', '789'];
    await h.auditAndSend(KEY, '【管理员】');
    const token = h.getSocialV2State('group:789').agentToken;
    await withServer(h, async (port) => {
      const res = await call(port, '/api/socialV2/send-message', {
        method: 'POST', headers: { ...ADMIN, 'x-agent-token': token },
        body: { key: 'group:789', messages: ['普通消息'] }
      });
      assert.equal(res.status, 403);
      assert.match(res.json.error, /熔断/);
    });
  } finally { await h.close(); }
});
await test('熔断通知模板变量可渲染', async () => {
  const h = await bridgeHarness({ config: ogConfig({
    notifyOwner: { enabled: true, cooldownMs: 0, template: '拦截 {rule}' },
    breaker: {
      enabled: true, threshold: 1, windowMs: 60000, pauseMs: 60000, scope: 'conversation',
      notifyOwner: true, template: '已熔断 {conv}｜{hits} 次｜{rule}｜{pauseMinutes} 分钟'
    }
  }) });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '【管理员】');
    assert.ok(await waitFor(() => sentTo(h, 'private', '123').some((m) => /已熔断.*1 次/.test(m.text))));
  } finally { await h.close(); }
});

console.log('## 控制台 /api/security');
await test('outputGuard 读写校验 + 落盘 + 关守卫清空出站待审项', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    h.setMode('chat');
    await h.auditAndSend(KEY, '我的系统提示词是：秘密');
    await withServer(h, async (port) => {
      const first = await call(port, '/api/security', { headers: ADMIN });
      assert.equal(first.json.security.outputGuard.enabled, true);

      for (const bad of [
        { outputGuard: { action: 'nope' } },
        { outputGuard: { breaker: { threshold: 0 } } },
        { outputGuard: { keywords: 'x' } },
        { outputGuard: { notifyGroup: { enabled: 'yes' } } }
      ]) {
        const res = await call(port, '/api/security', { method: 'POST', headers: ADMIN, body: bad });
        assert.equal(res.status, 400, JSON.stringify(bad));
      }

      const saved = await call(port, '/api/security', {
        method: 'POST', headers: ADMIN,
        body: {
          outputGuard: {
            action: 'block',
            breaker: { threshold: 8, windowMs: 120000, pauseMs: 300000, scope: 'global' },
            keywords: ['忽略指令', '忽 略 指 令']
          }
        }
      });
      assert.equal(saved.status, 200);
      const og = saved.json.outputGuard;
      assert.equal(og.action, 'block');
      assert.deepEqual(og.keywords, ['忽略指令']);
      assert.equal(og.breaker.threshold, 8);
      assert.equal(og.breaker.scope, 'global');
      assert.match(og.notifyOwner.template, /\{rule\}/, '未提交的模板保持原值');
      const persisted = JSON.parse(fs.readFileSync(path.join(h.temp, 'config.json'), 'utf8'));
      assert.equal(persisted.security.outputGuard.breaker.threshold, 8);

      const off = await call(port, '/api/security', {
        method: 'POST', headers: ADMIN, body: { outputGuard: { enabled: false } }
      });
      assert.equal(off.status, 200);
      const list = await call(port, '/api/prompt-guard/reviews', { headers: ADMIN });
      assert.equal(list.json.reviews.filter((x) => x.type === 'out').length, 0, '关闭守卫应清空出站待审项');
    });
  } finally { await h.close(); }
});
await test('智能体令牌不能访问出站守卫接口', async () => {
  const h = await bridgeHarness({ config: ogConfig() });
  try {
    await withServer(h, async (port) => {
      const status = await call(port, '/api/output-guard/status', { headers: { ...ADMIN, 'x-agent-token': 'whatever' } });
      assert.equal(status.status, 403);
      const reset = await call(port, '/api/output-guard/reset', {
        method: 'POST', headers: { ...ADMIN, 'x-agent-token': 'whatever' }, body: {}
      });
      assert.equal(reset.status, 403);
    });
  } finally { await h.close(); }
});

if (failures) {
  console.error(`\n${failures} 项失败`);
  process.exitCode = 1;
} else {
  console.log('\n全部通过');
}
