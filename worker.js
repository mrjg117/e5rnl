/**
 * E5 订阅续期（Cloudflare Worker，单文件版本 2.6.2）
 *
 * ── 部署方式 ──
 * 需绑定 Cloudflare Queue（E5RNL_QUEUE）；推荐用 wrangler deploy。
 * 不依赖任何外部文件 / npm 包，纯 V8 运行时原生可跑。
 *
 * ── 逻辑总览 ──
 * 一个纯定时任务（Cron），给微软 E5 开发者订阅「续命」：用 app-only（client_credentials，
 * 无用户登录、证书（指纹自动算）或客户端密码二选一静态有效）调用大量 Microsoft Graph API，在 OneDrive / Outlook / 日历 /
 * 联系人 / To Do / Teams / SharePoint 等多工作负载上做「建→改→读→删」+ 只读探测，制造真实
 * 活跃足迹，规避微软活跃度评估被回收。
 *
 *   - 每个 tick 按 RUN_PROBABILITY 概率「整轮跳过」制造大时间波动；命中后跑满全部 API 面。
 *   - 阶段1：9 可写（必做建+改+读+删，内联 DELETE 本轮自清）+ 23 只读探测，并发批次、各跑各的。
 *   - 阶段2：8 个清扫兜底动作 list 各位置删掉所有 <MARK>_ 残留（含上轮超时孤儿）。
 *   - 预算帽 MAX_API_CALLS（默认 48）+ 墙钟 MAX_RUNTIME_MS（默认 25000）保证「能跑多少跑多少」绝不报错。
 *   - 全量分批：通过 Cloudflare Queue（E5RNL_QUEUE）实现，按预算贪心装批，状态跟着消息走。
 *   - 所有可观测性走 Worker 日志（console），用仪表盘 Workers Logs 查看。
 *
 * ── 创建资源的统一标记 ──
 * 改下面这一行 MARK 即可整体改名（OneDrive 文件夹名与所有 item tag 前缀同步变化），
 * 避免把项目名暴露成可见资源名。默认 'mskeep'。
 */

const GRAPH = 'https://graph.microsoft.com/v1.0';
const MARK = 'mskeep';

// ── 内存令牌缓存（按 isolate 生命周期复用；过期自动刷新）──
let tokenCache = { token: null, expiry: 0 };
// 运行时 subrequest 预算（仅 runRenewal 设置/清零）；authedFetch 超出即抛 BUDGET 错误，
// 保证单轮不超免费版 50 subrequest 硬上限（令牌另占 1，故默认上限 48）。runDiagnostics 不计数。
let budget = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function randBetween(a, b) {
  return a + Math.floor(Math.random() * (b - a + 1));
}
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * base64url 编码（支持字符串与 ArrayBuffer/Uint8Array）。
 */
function b64url(input) {
  const u = typeof input === 'string' ? new TextEncoder().encode(input)
    : input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = '';
  for (let i = 0; i < u.length; i += 8192) {
    bin += String.fromCharCode(...u.subarray(i, Math.min(i + 8192, u.length)));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * 从 X.509 证书 PEM 自动计算 SHA-1 指纹（base64url），对应 JWT x5t 头。
 * 用户只需提供证书 PEM，无需手填指纹。
 */
async function computeCertThumbprint(pem) {
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/g, '')
    .replace(/-----END[^-]+-----/g, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const hash = await crypto.subtle.digest('SHA-1', der);
  return b64url(new Uint8Array(hash));
}

/**
 * 用私钥（PEM，PKCS#8）对 JWT 做 RS256 签名，返回完整 JWT 字符串。
 * 用于证书鉴权：以 client_assertion 形式换令牌，私钥不离开 Worker。
 */
async function signJwtRs256(pem, header, payload) {
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/g, '')
    .replace(/-----END[^-]+-----/g, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-V1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  const sig = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-V1_5' },
    key,
    new TextEncoder().encode(signingInput)
  );
  return signingInput + '.' + b64url(sig);
}

/**
 * 使用 client_credentials 获取应用令牌（app-only）。
 * 双重鉴权：优先用证书（MS_CERT_PEM + MS_CERT_PKEY，指纹自动算），否则用客户端密码（MS_APP_SECRET）；填哪个都生效。
 */
async function getToken(cfg, now = Date.now()) {
  if (tokenCache.token && tokenCache.expiry - 5 * 60 * 1000 > now) {
    return tokenCache.token;
  }
  const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(cfg.MS_TENANT_ID)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: cfg.MS_APP_ID,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });

  if (cfg.MS_CERT_PEM && cfg.MS_CERT_PKEY) {
    // 证书鉴权：从证书 PEM 自动算指纹，私钥 RS256 签名 JWT 作为 client_assertion
    const thumbprint = await computeCertThumbprint(cfg.MS_CERT_PEM);
    const iat = Math.floor(now / 1000);
    const header = { alg: 'RS256', typ: 'JWT', x5t: thumbprint };
    const payload = {
      aud: tokenUrl,
      iss: cfg.MS_APP_ID,
      sub: cfg.MS_APP_ID,
      jti: crypto.randomUUID(),
      nbf: iat - 30,
      exp: iat + 600,
      iat,
    };
    const assertion = await signJwtRs256(cfg.MS_CERT_PKEY, header, payload);
    body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    body.set('client_assertion', assertion);
  } else if (cfg.MS_APP_SECRET) {
    // 客户端密码鉴权
    body.set('client_secret', cfg.MS_APP_SECRET);
  } else {
    throw new Error('缺少凭据：需设置 MS_CERT_PEM+MS_CERT_PKEY（证书）或 MS_APP_SECRET（客户端密码）');
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`获取令牌失败 ${res.status}: ${text.slice(0, 300)}`);
  }
  const data = await res.json();
  tokenCache = {
    token: data.access_token,
    expiry: now + (Number(data.expires_in) || 3600) * 1000,
  };
  return data.access_token;
}

function userBase(cfg) {
  return `${GRAPH}/users/${encodeURIComponent(cfg.USER_ACCOUNT)}`;
}

async function authedFetch(cfg, token, method, path, body, contentType, absolute) {
  if (budget) {
    if (budget.used >= budget.max) {
      const e = new Error('subrequest budget exhausted');
      e.code = 'BUDGET';
      throw e;
    }
    budget.used++;
  }
  const headers = { Authorization: `Bearer ${token}` };
  let payload;
  if (body !== undefined) {
    if (contentType && contentType !== 'application/json') {
      headers['Content-Type'] = contentType;
      payload = body;
    } else {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
  }
  const base = absolute ? GRAPH : userBase(cfg);
  const res = await fetch(base + path, { method, headers, body: payload });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`);
  }
  if (method === 'DELETE' || res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

// ===================================================================
// 可写工作负载（create + update + read + delete 四步必全；delete 必执行，本轮清理零残留）
// 返回字符串描述；返回 null 表示「前置条件不满足，已跳过」
// ===================================================================

async function actionOnedrive(cfg, token) {
  const name = `${MARK}_${crypto.randomUUID()}.txt`;
  const base = `/drive/root:/${MARK}/${name}`;
  const content = `E5 renewal heartbeat @ ${new Date().toISOString()}`;
  try {
    await authedFetch(cfg, token, 'PUT', `${base}:/content`, content, 'text/plain');
  } catch (e) {
    if (e && e.code === 'BUDGET') throw e;
    // 仅 404（MARK 文件夹不存在）时创建后重试，其他错误直接抛
    if (!/-> 404:/.test(e.message)) throw e;
    try {
      await authedFetch(cfg, token, 'POST', '/drive/root/children', { name: MARK, folder: {} });
    } catch (folderErr) {
      throw new Error(`PUT 404 且创建 MARK 文件夹也失败: ${folderErr.message}`);
    }
    try {
      await authedFetch(cfg, token, 'PUT', `${base}:/content`, content, 'text/plain');
    } catch (retryErr) {
      if (retryErr && retryErr.code === 'BUDGET') throw retryErr;
      throw retryErr;
    }
  }
  await authedFetch(cfg, token, 'PUT', `${base}:/content`, content + ' (updated)', 'text/plain');
  await authedFetch(cfg, token, 'GET', `${base}:/content`);
  await authedFetch(cfg, token, 'DELETE', base);
  return `OneDrive 文件 ${name} 建/改/读/删`;
}

async function actionOnedriveFolder(cfg, token) {
  const name = `${MARK}_${crypto.randomUUID()}`;
  let created;
  try {
    // 统一建在专用文件夹 /drive/root:/<MARK>/ 内；父文件夹可能尚未存在则先建
    created = await authedFetch(cfg, token, 'POST', `/drive/root:/${MARK}:/children`, { name, folder: {} });
  } catch (e) {
    if (e && e.code === 'BUDGET') throw e;
    // 仅 404（MARK 父文件夹不存在）时创建后重试，其他错误直接抛
    if (!/-> 404:/.test(e.message)) throw e;
    try {
      await authedFetch(cfg, token, 'POST', '/drive/root/children', { name: MARK, folder: {} });
      created = await authedFetch(cfg, token, 'POST', `/drive/root:/${MARK}:/children`, { name, folder: {} });
    } catch (retryErr) {
      throw new Error(`创建文件夹失败（含重试）：${retryErr.message}`);
    }
  }
  await authedFetch(cfg, token, 'GET', `/drive/items/${created.id}`);
  await authedFetch(cfg, token, 'DELETE', `/drive/items/${created.id}`);
  return `OneDrive 文件夹 ${name} 建/读/删`;
}

async function actionOutlook(cfg, token) {
  const created = await authedFetch(cfg, token, 'POST', '/mailFolders/drafts/messages', {
    subject: `${MARK} heartbeat`,
    body: { contentType: 'text', content: 'automated' },
  });
  const id = created.id;
  await authedFetch(cfg, token, 'PATCH', `/messages/${id}`, { subject: `${MARK} heartbeat (edited)` });
  await authedFetch(cfg, token, 'GET', '/mailFolders/drafts/messages');
  await authedFetch(cfg, token, 'DELETE', `/messages/${id}`);
  return `Outlook 草稿 ${id} 建/改/读/删`;
}

async function actionCalendar(cfg, token) {
  const start = new Date(Date.now() + 3600 * 1000).toISOString();
  const end = new Date(Date.now() + 7200 * 1000).toISOString();
  const created = await authedFetch(cfg, token, 'POST', '/calendar/events', {
    subject: `${MARK} heartbeat`,
    start: { dateTime: start, timeZone: 'UTC' },
    end: { dateTime: end, timeZone: 'UTC' },
  });
  const id = created.id;
  const ns = new Date(Date.now() + 5400 * 1000).toISOString();
  await authedFetch(cfg, token, 'PATCH', `/events/${id}`, { start: { dateTime: ns, timeZone: 'UTC' } });
  await authedFetch(cfg, token, 'GET', `/events/${id}`);
  await authedFetch(cfg, token, 'DELETE', `/events/${id}`);
  return `日历事件 ${id} 建/改/读/删`;
}

async function actionCalendarCal(cfg, token) {
  const cal = await authedFetch(cfg, token, 'POST', '/calendars', { name: `${MARK}_${crypto.randomUUID()}` });
  await authedFetch(cfg, token, 'GET', `/calendars/${cal.id}`);
  await authedFetch(cfg, token, 'DELETE', `/calendars/${cal.id}`);
  return `日历 ${cal.id} 建/读/删`;
}

async function actionContacts(cfg, token) {
  const created = await authedFetch(cfg, token, 'POST', '/contacts', {
    givenName: MARK,
    surname: `Renew${Math.floor(Math.random() * 1000)}`,
    emailAddresses: [{ address: 'noreply@example.com' }],
  });
  const id = created.id;
  await authedFetch(cfg, token, 'PATCH', `/contacts/${id}`, { jobTitle: 'heartbeat' });
  await authedFetch(cfg, token, 'GET', '/contacts');
  await authedFetch(cfg, token, 'DELETE', `/contacts/${id}`);
  return `联系人 ${id} 建/改/读/删`;
}

async function actionTodo(cfg, token) {
  const lists = await authedFetch(cfg, token, 'GET', '/todo/lists');
  const list = lists && lists.value && lists.value[0];
  if (!list) return null; // 无列表则跳过，不创建持久对象
  const created = await authedFetch(cfg, token, 'POST', `/todo/lists/${list.id}/tasks`, {
    title: `${MARK} ${new Date().toISOString()}`,
  });
  const id = created.id;
  await authedFetch(cfg, token, 'PATCH', `/todo/lists/${list.id}/tasks/${id}`, { status: 'completed' });
  await authedFetch(cfg, token, 'GET', `/todo/lists/${list.id}/tasks`);
  await authedFetch(cfg, token, 'DELETE', `/todo/lists/${list.id}/tasks/${id}`);
  return `To Do 任务 ${id} 建/改/读/删`;
}

async function actionTodoList(cfg, token) {
  const list = await authedFetch(cfg, token, 'POST', '/todo/lists', {
    displayName: `${MARK}_${crypto.randomUUID()}`,
  });
  await authedFetch(cfg, token, 'GET', `/todo/lists/${list.id}/tasks`);
  await authedFetch(cfg, token, 'DELETE', `/todo/lists/${list.id}`);
  return `To Do 清单 ${list.id} 建/读/删`;
}

// 自动解析 SharePoint 站点与列表：优先用显式配置，否则自动探测根站点 + 第一个非文档库普通列表。
// 这样用户无需手填 SHAREPOINT_* 也能覆盖 SharePoint 可写工作负载；文档库(baseTemplate=101)会被排除以免清扫误伤文件。
// 单轮内缓存 SharePoint 解析结果：action 与 sweep 共用，避免每轮对同一站点探测两次。
// 已显式配置 SHAREPOINT_SITE_ID + LIST_ID 时短路返回（不探测）；未配置时仅探测一次。
let spCache = undefined;

async function resolveSharepoint(cfg, token) {
  if (spCache !== undefined) return spCache; // 本轮已探测过（含 null=无普通列表可用）
  if (cfg.SHAREPOINT_SITE_ID && cfg.SHAREPOINT_LIST_ID) {
    spCache = { siteId: cfg.SHAREPOINT_SITE_ID, listId: cfg.SHAREPOINT_LIST_ID };
    return spCache; // 已配置 → 0 探测
  }
  // 自动探测只针对根站点：用 'root' 关键字引用。注意复合 siteId（host,id,webId）拼
  // /lists/{id}/items 端点会触发 DynamicPathSegment 解析错误，'root' 无此问题（只读探测已验证）。
  const lists = await authedFetch(cfg, token, 'GET', '/sites/root/lists?$top=50&$expand=drive', undefined, undefined, true);
  // 排除文档库：文档库 list 对象带 drive 导航属性（drive 非空），普通列表 drive 为 null。
  // 文档库既不能用 /items 建普通 list item（必 400），清扫也易误伤文件，故自动探测时跳过、选第一个普通列表。
  const normal = (lists && lists.value || []).find((l) => !l.drive);
  spCache = normal ? { siteId: 'root', listId: normal.id } : null;
  return spCache;
}

async function actionSharepoint(cfg, token) {
  const sp = await resolveSharepoint(cfg, token);
  if (!sp) return null; // 无普通列表可用则跳过
  const siteBase = `/sites/${sp.siteId}/lists/${sp.listId}`;
  const created = await authedFetch(cfg, token, 'POST', `${siteBase}/items`, {
    fields: { Title: `${MARK}_${crypto.randomUUID()}` },
  }, undefined, true);
  const id = created.id;
  await authedFetch(cfg, token, 'PATCH', `${siteBase}/items/${id}/fields`, { Title: `${MARK}_updated` }, undefined, true);
  await authedFetch(cfg, token, 'GET', `${siteBase}/items`, undefined, undefined, true);
  await authedFetch(cfg, token, 'DELETE', `${siteBase}/items/${id}`, undefined, undefined, true);
  return `SharePoint 列表项 ${id} 建/改/读/删`;
}

// ===================================================================
// 只读探测（零清理，增加跨工作负载使用足迹）
// ===================================================================

async function probeTeams(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/joinedTeams');
  return '已加入 Teams (只读)';
}
async function probeTeamsChannels(cfg, token) {
  const teams = await authedFetch(cfg, token, 'GET', '/joinedTeams');
  const t = teams && teams.value && teams.value[0];
  if (t) await authedFetch(cfg, token, 'GET', `/teams/${t.id}/channels?$top=5`);
  return 'Teams 频道 (只读)';
}
async function probeMailbox(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/mailboxSettings');
  return '邮箱设置 (只读)';
}
async function probeDriveRoot(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/drive/root/children?$top=1');
  return 'OneDrive 根目录 (只读)';
}
async function probeDriveList(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/drive');
  return 'OneDrive 驱动器 (只读)';
}
async function probeDriveRootDir(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/drive/root');
  return 'OneDrive 根目录 (只读)';
}
async function probeMailFolders(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/mailFolders');
  return '邮件文件夹 (只读)';
}
async function probeMailInbox(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/mailFolders/inbox/messages?$top=1');
  return '收件箱邮件 (只读)';
}
async function probeMessages(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/messages?$top=1');
  return '邮件列表 (只读)';
}
async function probeMailCategories(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/outlook/masterCategories');
  return '邮件分类 (只读)';
}
async function probeCalendarView(cfg, token) {
  const now = new Date();
  const start = now.toISOString();
  const end = new Date(now.getTime() + 30 * 24 * 3600 * 1000).toISOString();
  await authedFetch(cfg, token, 'GET', `/calendarView?startDateTime=${encodeURIComponent(start)}&endDateTime=${encodeURIComponent(end)}&$top=5`);
  return '日历视图 (只读)';
}
async function probeCalendars(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/calendars');
  return '日历列表 (只读)';
}
async function probeEvents(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/events?$top=1');
  return '日历事件列表 (只读)';
}
async function probeProfile(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/');
  return '用户档案 (只读)';
}
async function probeManager(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/manager');
  return '经理 (只读)';
}
async function probeDirectReports(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/directReports');
  return '下属 (只读)';
}
async function probeMemberOf(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/memberOf');
  return '所属组 (只读)';
}
async function probePeople(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/people');
  return 'People (只读)';
}
async function probeGroupsAll(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/groups?$top=5', undefined, undefined, true);
  return '全部组 (只读)';
}
async function probeSharepointSites(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/sites/root', undefined, undefined, true);
  return 'SharePoint 站点 (只读)';
}
async function probeSharepointSiteLists(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/sites/root/lists', undefined, undefined, true);
  return 'SharePoint 站点列表 (只读)';
}
async function probeContactsFolders(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/contactFolders');
  return '联系人文件夹 (只读)';
}
async function probeTodoListsRead(cfg, token) {
  await authedFetch(cfg, token, 'GET', '/todo/lists');
  return 'To Do 清单列表 (只读)';
}

const WRITABLE = [
  { name: 'onedrive', fn: actionOnedrive, readonly: false },
  { name: 'onedrive_folder', fn: actionOnedriveFolder, readonly: false },
  { name: 'outlook', fn: actionOutlook, readonly: false },
  { name: 'calendar_event', fn: actionCalendar, readonly: false },
  { name: 'calendar_calendar', fn: actionCalendarCal, readonly: false },
  { name: 'contacts', fn: actionContacts, readonly: false },
  { name: 'todo_task', fn: actionTodo, readonly: false },
  { name: 'todo_list', fn: actionTodoList, readonly: false },
  { name: 'sharepoint', fn: actionSharepoint, readonly: false },
];

const READONLY = [
  { name: 'teams', fn: probeTeams, readonly: true },
  { name: 'teams_channels', fn: probeTeamsChannels, readonly: true },
  { name: 'mailbox', fn: probeMailbox, readonly: true },
  { name: 'drive_root', fn: probeDriveRoot, readonly: true },
  { name: 'drive_list', fn: probeDriveList, readonly: true },
  { name: 'drive_root_dir', fn: probeDriveRootDir, readonly: true },
  { name: 'mail_folders', fn: probeMailFolders, readonly: true },
  { name: 'mail_inbox', fn: probeMailInbox, readonly: true },
  { name: 'messages', fn: probeMessages, readonly: true },
  { name: 'mail_categories', fn: probeMailCategories, readonly: true },
  { name: 'calendar_view', fn: probeCalendarView, readonly: true },
  { name: 'calendars', fn: probeCalendars, readonly: true },
  { name: 'events', fn: probeEvents, readonly: true },
  { name: 'profile', fn: probeProfile, readonly: true },
  { name: 'manager', fn: probeManager, readonly: true, allow404: true },
  { name: 'direct_reports', fn: probeDirectReports, readonly: true, allow404: true },
  { name: 'memberof', fn: probeMemberOf, readonly: true },
  { name: 'people', fn: probePeople, readonly: true },
  { name: 'groups_all', fn: probeGroupsAll, readonly: true },
  { name: 'sharepoint_sites', fn: probeSharepointSites, readonly: true },
  { name: 'sharepoint_site_lists', fn: probeSharepointSiteLists, readonly: true },
  { name: 'contacts_folders', fn: probeContactsFolders, readonly: true },
  { name: 'todo_lists_read', fn: probeTodoListsRead, readonly: true },
];

// 清扫兜底动作：list 各创建位置并删除所有 <MARK>_ 残留（含上轮超时孤儿）。
// 每个可写工作负载对应一个；扫不到即当作一次 list 探测，零副作用。
async function sweepOnedrive(cfg, token) {
  let total = 0;
  let items;
  try {
    items = await authedFetch(cfg, token, 'GET', `/drive/root:/${MARK}:/children?$top=200`);
  } catch (e) {
    if (e && e.code === 'BUDGET') throw e;
    return `OneDrive 清扫：0 项已删（文件夹不存在）`;
  }
  const vals = (items && items.value) || [];
  for (const it of vals) {
    if (it.name && it.name.startsWith(`${MARK}_`)) {
      await authedFetch(cfg, token, 'DELETE', `/drive/items/${it.id}`);
      total++;
    }
  }
  return `OneDrive 清扫：${total} 项已删`;
}
async function sweepOutlook(cfg, token) {
  const r = await authedFetch(cfg, token, 'GET', `/mailFolders/drafts/messages?$filter=startswith(subject,'${MARK}')&$top=200`);
  const vals = (r && r.value) || [];
  for (const m of vals) await authedFetch(cfg, token, 'DELETE', `/messages/${m.id}`);
  return `Outlook 清扫：${vals.length} 项已删`;
}
async function sweepCalendarEvent(cfg, token) {
  const r = await authedFetch(cfg, token, 'GET', `/events?$filter=startswith(subject,'${MARK}')&$top=200`);
  const vals = (r && r.value) || [];
  for (const e of vals) await authedFetch(cfg, token, 'DELETE', `/events/${e.id}`);
  return `日历事件清扫：${vals.length} 项已删`;
}
async function sweepCalendarCal(cfg, token) {
  const r = await authedFetch(cfg, token, 'GET', `/calendars?$filter=startswith(name,'${MARK}_')&$top=200`);
  const vals = (r && r.value) || [];
  for (const c of vals) await authedFetch(cfg, token, 'DELETE', `/calendars/${c.id}`);
  return `日历清扫：${vals.length} 项已删`;
}
async function sweepContacts(cfg, token) {
  const r = await authedFetch(cfg, token, 'GET', `/contacts?$filter=startswith(givenName,'${MARK}')&$top=200`);
  const vals = (r && r.value) || [];
  for (const c of vals) await authedFetch(cfg, token, 'DELETE', `/contacts/${c.id}`);
  return `联系人清扫：${vals.length} 项已删`;
}
async function sweepTodoTask(cfg, token) {
  const lists = await authedFetch(cfg, token, 'GET', '/todo/lists');
  const ls = (lists && lists.value) || [];
  let n = 0;
  for (const list of ls) {
    const r = await authedFetch(cfg, token, 'GET', `/todo/lists/${list.id}/tasks?$filter=startswith(title,'${MARK}')&$top=200`);
    const vals = (r && r.value) || [];
    for (const t of vals) { await authedFetch(cfg, token, 'DELETE', `/todo/lists/${list.id}/tasks/${t.id}`); n++; }
  }
  return `To Do 任务清扫：${n} 项已删`;
}
async function sweepTodoList(cfg, token) {
  const r = await authedFetch(cfg, token, 'GET', `/todo/lists?$filter=startswith(displayName,'${MARK}_')&$top=200`);
  const vals = (r && r.value) || [];
  for (const l of vals) await authedFetch(cfg, token, 'DELETE', `/todo/lists/${l.id}`);
  return `To Do 清单清扫：${vals.length} 项已删`;
}
async function sweepSharepoint(cfg, token) {
  const sp = await resolveSharepoint(cfg, token);
  if (!sp) return 'SharePoint 清扫：0 项已删（无可用列表）';
  const siteBase = `/sites/${sp.siteId}/lists/${sp.listId}`;
  const r = await authedFetch(cfg, token, 'GET', `${siteBase}/items?$top=200`, undefined, undefined, true);
  const vals = (r && r.value) || [];
  let n = 0;
  for (const it of vals) {
    const title = it.fields && it.fields.Title;
    if (typeof title === 'string' && title.startsWith(`${MARK}_`)) {
      await authedFetch(cfg, token, 'DELETE', `${siteBase}/items/${it.id}`, undefined, undefined, true);
      n++;
    }
  }
  return `SharePoint 清扫：${n} 项已删`;
}

const SWEEPS = [
  { name: 'sweep_onedrive', fn: sweepOnedrive, readonly: false },
  { name: 'sweep_outlook', fn: sweepOutlook, readonly: false },
  { name: 'sweep_calendar_event', fn: sweepCalendarEvent, readonly: false },
  { name: 'sweep_calendar_cal', fn: sweepCalendarCal, readonly: false },
  { name: 'sweep_contacts', fn: sweepContacts, readonly: false },
  { name: 'sweep_todo_task', fn: sweepTodoTask, readonly: false },
  { name: 'sweep_todo_list', fn: sweepTodoList, readonly: false },
  { name: 'sweep_sharepoint', fn: sweepSharepoint, readonly: false },
];

/**
 * 执行一轮续期：阶段1 跑满全部可写(内联DELETE自清)+只读；阶段2 跑清扫兜底。
 * 预算帽 MAX_API_CALLS 与墙钟 MAX_RUNTIME_MS 保证「能跑多少跑多少」绝不报错。
 */
export async function runRenewal(cfg, log = console) {
  const jitterMin = Number(cfg.ACTION_DELAY_MIN_MS || 0);
  const jitterMax = Number(cfg.ACTION_DELAY_MAX_MS != null && cfg.ACTION_DELAY_MAX_MS !== '' ? cfg.ACTION_DELAY_MAX_MS : 300);
  const batchSize = Number(cfg.CONCURRENCY != null && cfg.CONCURRENCY !== '' ? cfg.CONCURRENCY : 6);
  const maxSub = Number(cfg.MAX_API_CALLS != null && cfg.MAX_API_CALLS !== '' ? cfg.MAX_API_CALLS : 48);
  const wallMs = Number(cfg.MAX_RUNTIME_MS != null && cfg.MAX_RUNTIME_MS !== '' ? cfg.MAX_RUNTIME_MS : 25000);
  const startTs = Date.now();
  const results = [];

  spCache = undefined; // 每轮重置 SharePoint 探测缓存
  const token = await getToken(cfg);
  budget = { max: maxSub, used: 0 };

  const runOne = async (a) => {
    try {
      const msg = await a.fn(cfg, token);
      if (msg === null) {
        if (log.info) log.info(`SKIP [${a.name}] 前置不满足（如缺 To Do 列表 / SharePoint 未配置）`);
        results.push({ action: a.name, ok: false, skipped: true });
        return;
      }
      if (log.info) log.info(`OK [${a.name}] ${msg}`);
      results.push({ action: a.name, ok: true, msg, readonly: a.readonly });
    } catch (e) {
      if (e && e.code === 'BUDGET') {
        if (log.warn) log.warn(`SKIP [${a.name}] 已达 subrequest 上限，跳过`);
        results.push({ action: a.name, ok: false, skipped: true, error: 'budget' });
        return;
      }
      if (a.allow404 && e && /-> 404:/.test(e.message)) {
        if (log.info) log.info(`OK [${a.name}] 无数据(404)，仍计入调用`);
        results.push({ action: a.name, ok: true, msg: '无数据(404)', readonly: a.readonly });
        return;
      }
      if (log.warn) log.warn(`FAIL [${a.name}] ${e.message}`);
      results.push({ action: a.name, ok: false, error: e.message, readonly: a.readonly });
    }
  };

  const runPhase = async (label, pool) => {
    const shuffled = shuffle(pool);
    for (let i = 0; i < shuffled.length; i += batchSize) {
      if (Date.now() - startTs > wallMs) {
        if (log.warn) log.warn(`[WARN] 达墙钟上限(${wallMs}ms)，停止本轮(${label})剩余动作`);
        break;
      }
      if (budget.used >= budget.max) {
        if (log.warn) log.warn(`[WARN] 达 subrequest 上限(${budget.max})，停止本轮(${label})剩余动作`);
        break;
      }
      const batch = shuffled.slice(i, i + batchSize);
      await Promise.all(batch.map(runOne));
      if (jitterMin || jitterMax) await sleep(randBetween(jitterMin, jitterMax));
    }
  };

  // 阶段1：全部可写(内联DELETE自清) + 全部只读探测，并发批次、各跑各的
  await runPhase('main', [...WRITABLE, ...READONLY]);
  // 阶段2：清扫兜底（list+delete 所有 <MARK>_ 残留，含上轮超时孤儿）
  await runPhase('sweep', SWEEPS);

  budget = null;
  return results;
}

// ===================================================================
// Queue 分批：按预算贪心装批，状态跟着消息走，无需 KV
// ===================================================================

// 每个 action 的最坏情况 API 调用估算（含 404 重试路径）
const COST_TABLE = {
  onedrive: 6, onedrive_folder: 4, outlook: 4,
  calendar_event: 4, calendar_calendar: 3, contacts: 4,
  todo_task: 5, todo_list: 3, sharepoint: 5,
  // 只读 probe（取 2 留余量，多数实际只 1 次）
  teams: 2, teams_channels: 2, mailbox: 1,
  drive_root: 1, drive_list: 1, drive_root_dir: 1,
  mail_folders: 1, mail_inbox: 1, messages: 1,
  mail_categories: 1, calendar_view: 1, calendars: 1,
  events: 1, profile: 1, manager: 1, direct_reports: 1,
  memberof: 1, people: 1, groups_all: 1,
  sharepoint_sites: 1, sharepoint_site_lists: 1,
  contacts_folders: 1, todo_lists_read: 1,
  // sweep（list + 可能多个 delete）
  sweep_onedrive: 5, sweep_outlook: 5, sweep_calendar_event: 5,
  sweep_calendar_cal: 5, sweep_contacts: 5, sweep_todo_task: 8,
  sweep_todo_list: 5, sweep_sharepoint: 5,
};

/**
 * 贪心装批：从 remaining 里按顺序装 action，直到预算不够。
 * 保证至少装入第一个 action（即使估算 cost 超预算），避免消息卡死。
 * 返回 { batch: action对象数组, consumed: 本批消耗估算, nextRemaining: 剩余 action name 列表 }
 */
function packBatch(remaining, maxBudget = 48) {
  let budget = maxBudget;
  const batch = [];
  let cutAt = 0;
  for (const name of remaining) {
    const cost = COST_TABLE[name] || 2;
    // 已装入至少 1 个且预算不够时停止；首个 action 强制装入
    if (batch.length > 0 && budget - cost < 0) break;
    const action = [...WRITABLE, ...READONLY, ...SWEEPS].find((a) => a.name === name);
    if (action) {
      batch.push(action);
      budget -= cost;
    }
    cutAt++;
  }
  return { batch, consumed: maxBudget - budget, nextRemaining: remaining.slice(cutAt) };
}

/**
 * 执行一批 action，返回 { results, unexecuted }。
 * unexecuted: 因 budget 耗尽而未执行的 action name 列表，调用方应将其追加到 nextRemaining。
 */
async function executeBatch(batch, cfg, token, log) {
  const results = [];
  let unexecuted = [];
  let budgetExhausted = false;
  for (const a of batch) {
    if (budgetExhausted) {
      unexecuted.push(a.name);
      continue;
    }
    try {
      const msg = await a.fn(cfg, token);
      if (msg === null) {
        results.push({ name: a.name, ok: false, skipped: true, readonly: a.readonly });
        if (log.info) log.info(`BATCH SKIP [${a.name}] 前置条件不满足`);
      } else {
        results.push({ name: a.name, ok: true, msg, readonly: a.readonly });
        if (log.info) log.info(`BATCH OK   [${a.name}] ${msg}`);
      }
    } catch (e) {
      if (e && e.code === 'BUDGET') {
        results.push({ name: a.name, ok: false, skipped: true, error: 'budget', readonly: a.readonly });
        if (log.warn) log.warn(`BATCH SKIP [${a.name}] 已达 subrequest 上限`);
        budgetExhausted = true;
        continue;
      }
      if (a.allow404 && e && /-> 404:/.test(e.message)) {
        results.push({ name: a.name, ok: true, msg: '无数据(404)', readonly: a.readonly });
        if (log.info) log.info(`BATCH OK   [${a.name}] 无数据(404)`);
      } else {
        results.push({ name: a.name, ok: false, error: e.message, readonly: a.readonly });
        if (log.warn) log.warn(`BATCH FAIL [${a.name}] ${e.message}`);
      }
    }
  }
  return { results, unexecuted };
}

// ===================================================================
// Worker 入口（scheduled 定时续期 + queue 分批消费）
// ===================================================================

function cfgFromEnv(env) {
  return {
    MS_TENANT_ID: env.MS_TENANT_ID,
    MS_APP_ID: env.MS_APP_ID,
    MS_APP_SECRET: env.MS_APP_SECRET,
    MS_CERT_PEM: env.MS_CERT_PEM,
    MS_CERT_PKEY: env.MS_CERT_PKEY,
    USER_ACCOUNT: env.USER_ACCOUNT,
    SHAREPOINT_SITE_ID: env.SHAREPOINT_SITE_ID,
    SHAREPOINT_LIST_ID: env.SHAREPOINT_LIST_ID,
    ACTION_DELAY_MIN_MS: env.ACTION_DELAY_MIN_MS,
    ACTION_DELAY_MAX_MS: env.ACTION_DELAY_MAX_MS,
    START_DELAY_MAX_SEC: env.START_DELAY_MAX_SEC,
    CONCURRENCY: env.CONCURRENCY,
    MAX_API_CALLS: env.MAX_API_CALLS,
    MAX_RUNTIME_MS: env.MAX_RUNTIME_MS,
  };
}

function validateCfg(cfg) {
  const ALWAYS_REQUIRED = ['MS_TENANT_ID', 'MS_APP_ID', 'USER_ACCOUNT'];
  const missingAlways = ALWAYS_REQUIRED.filter((k) => !cfg[k]);
  if (missingAlways.length) {
    console.error(`[CRITICAL] 缺少必需凭据：${missingAlways.join(', ')}；请到 Cloudflare 变量页设置后再运行`);
    return false;
  }
  const hasCert = !!(cfg.MS_CERT_PEM && cfg.MS_CERT_PKEY);
  const hasSecret = !!cfg.MS_APP_SECRET;
  if (!hasCert && !hasSecret) {
    console.error('[CRITICAL] 缺少鉴权凭据：需设置 MS_CERT_PEM+MS_CERT_PKEY（证书）或 MS_APP_SECRET（客户端密码）');
    return false;
  }
  return true;
}

export default {
  // ── Queue consumer：从消息取 remaining + results，贪心装批执行，剩余发下条 ──
  async queue(batch, env, ctx) {
    const cfg = cfgFromEnv(env);
    const maxBudget = Number(cfg.MAX_API_CALLS != null && cfg.MAX_API_CALLS !== '' ? cfg.MAX_API_CALLS : 48);

    for (const msg of batch.messages) {
      try {
        const { remaining, results, phase } = msg.body;
        if (!remaining || remaining.length === 0) {
          msg.ack();
          continue;
        }

        spCache = undefined; // 每批重置 SharePoint 缓存
        budget = { max: maxBudget, used: 0 };
        const token = await getToken(cfg);

        const { batch: actions, consumed, nextRemaining } = packBatch(remaining, maxBudget);
        if (actions.length === 0) {
          console.error(`[CRITICAL] packBatch 返回空批（remaining[0]=${remaining[0]} 估算 cost 超过 budget=${maxBudget}），该 action 被丢弃`);
          // 丢弃当前无法执行的首个 action，继续处理剩余，避免消息永久卡死
          const fallbackRemaining = remaining.slice(1);
          if (fallbackRemaining.length > 0) {
            await env.E5RNL_QUEUE.send({
              remaining: fallbackRemaining,
              results: [...(results || []), { name: remaining[0], ok: false, error: 'cost exceeds budget', skipped: true }],
              phase: phase || 'main',
            });
          }
          msg.ack();
          continue;
        }

        console.log(`[QUEUE] 本批 ${actions.length} 个 action，估算消耗 ${consumed}/${maxBudget}，剩余 ${nextRemaining.length} 个`);
        const { results: batchResults, unexecuted } = await executeBatch(actions, cfg, token, console);
        budget = null;

        // 未执行的 action（因 budget 耗尽）追加到 nextRemaining 前部，下批优先执行
        const finalRemaining = [...unexecuted, ...nextRemaining];
        const allResults = [...(results || []), ...batchResults];
        const done = finalRemaining.length === 0;

        if (done) {
          const ok = allResults.filter((r) => r.ok).length;
          const fail = allResults.filter((r) => !r.ok && !r.skipped).length;
          const skip = allResults.filter((r) => r.skipped).length;
          console.log(`[QUEUE] 全量完成：${ok}/${allResults.length} 成功, ${fail} 失败, ${skip} 跳过`);
          if (fail > 0) console.error(`[CRITICAL] 全量自测存在 ${fail} 个失败项，请检查 scope 授权`);
        } else {
          // 发下条消息，带更新后的 remaining + results
          await env.E5RNL_QUEUE.send({
            remaining: finalRemaining,
            results: allResults,
            phase: phase || 'main',
          });
          console.log(`[QUEUE] 已发下批消息，剩余 ${finalRemaining.length} 个 action（含 ${unexecuted.length} 个未执行）`);
        }

        msg.ack();
      } catch (e) {
        console.error(`[QUEUE] 消费消息异常：${e.message}`);
        // 不 ack，让 Queue 自动重试
      }
    }
  },

  async scheduled(event, env, ctx) {
    const cfg = cfgFromEnv(env);
    if (!validateCfg(cfg)) return;

    // 全量分批：由 SELF_TEST 环境变量控制（"1" 启用）
    // 开启后每个 cron tick 发一条 Queue 消息，consumer 贪心装批执行，剩余自动续批
    if (env.SELF_TEST === '1') {
      try {
        // main 阶段打乱顺序，sweep 阶段固定在后（清扫须在可写动作之后）
        const mainNames = shuffle([...WRITABLE, ...READONLY]).map((a) => a.name);
        const sweepNames = SWEEPS.map((a) => a.name);
        const allNames = [...mainNames, ...sweepNames];
        await env.E5RNL_QUEUE.send({
          remaining: allNames,
          results: [],
          phase: 'main',
        });
        console.log(`[SELFTEST] 已发首批消息，共 ${allNames.length} 个 action（main ${mainNames.length} + sweep ${sweepNames.length}），Queue 自动分批消费`);
      } catch (e) {
        console.error(`[CRITICAL] 全量自测启动失败：${e.message}`);
      }
      return;
    }

    // 常规续期：按 RUN_PROBABILITY 概率整轮跳过（制造时间波动）
    const rate = Number(env.RUN_PROBABILITY != null && env.RUN_PROBABILITY !== '' ? env.RUN_PROBABILITY : 0.5);
    if (Math.random() > rate) {
      console.log(`Worker 本轮按 RUN_PROBABILITY=${rate} 整轮跳过（制造时间波动）`);
      return;
    }
    const pre = Number(env.START_DELAY_MAX_SEC || 0);
    if (pre > 0) await sleep(randBetween(0, pre * 1000));
    try {
      const res = await runRenewal(cfg, console);
      const total = res.filter((r) => !r.skipped).length;
      const ok = res.filter((r) => r.ok && !r.skipped).length;
      if (ok < total) {
        console.warn(`[WARN] 续期完成但有失败：${ok}/${total} 成功`);
      } else {
        console.log(`[OK] 续期完成：${ok}/${total} 成功`);
      }
    } catch (e) {
      console.error(`[CRITICAL] 续期异常（整轮失败）：${e.message}`);
    }
  },
};
