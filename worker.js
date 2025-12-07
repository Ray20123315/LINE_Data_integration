// ==========================================
// ★ 設定區
// ==========================================
const DOMAIN_STUDENT = "https://homework.ray2026.dpdns.org";
const DOMAIN_MANAGER = "https://homeworkmanage.ray2026.dpdns.org";
const SUPER_ADMIN_PASSWORD_ENV_KEY = 'SUPER_ADMIN_PASSWORD'; 
const SUPER_ADMIN_PATH = "/super-admin";

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const hostname = url.hostname; 
        const isManagerSite = hostname.includes("homeworkmanage") || hostname.includes("manage");
        const isSuperAdmin = hostname.includes("super") || url.pathname === SUPER_ADMIN_PATH; 

        if (request.method === "POST") return handlePost(request, env, ctx);

        if (isSuperAdmin) {
            return new Response(renderSuperAdminHTML(), { headers: { "Content-Type": "text/html;charset=utf-8" } });
        } else if (isManagerSite) {
            return new Response(renderManagerHTML(env), { headers: { "Content-Type": "text/html;charset=utf-8" } });
        } else {
            return new Response(renderStudentHTML(), { headers: { "Content-Type": "text/html;charset=utf-8" } });
        }
    }
};

// ====================================================================
// ★ 後端邏輯
// ====================================================================
async function handlePost(request, env, ctx) {
    try {
        const json = await request.json();
        const groupId = json.groupId;
        const action = json.action; // 提取 action 避免混淆

        // ===========================
        // D. LINE Webhook
        // ===========================
        if (json.events) {
            return handleLineWebhook(json.events, env, ctx);
        }

        // ===========================
        // 核心功能路由
        // ===========================

        // 1. 讀取作業 (學生端)
        if (action === "get_tasks") {
            if (!groupId) return new Response(JSON.stringify([]));
            
            // 檢查前端存取權
            const access = await env.DB.prepare("SELECT 前端存取權 FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (access && access.前端存取權 === 'disabled') {
                return new Response(JSON.stringify({ tasks: [], error: "前端存取權已關閉" }));
            }
            
            const tenMinsAgo = Date.now() - (10 * 60 * 1000);
            await env.DB.prepare("UPDATE tasks SET 狀態 = '已發佈' WHERE 狀態 = '待審核' AND 建立時間 < ? AND 群組 = ?").bind(tenMinsAgo, groupId).run();
            
            const { results } = await env.DB.prepare(`
                SELECT id, 群組 as group_id, 建立時間 as created_at, 截止日期 as date, 科目 as subject, 內容 as content, 來源 as source, 狀態 as status, 類別 as category 
                FROM tasks WHERE 狀態 = '已發佈' AND 群組 = ? ORDER BY 截止日期 ASC
            `).bind(groupId).all();
            
            const config = await env.DB.prepare("SELECT 科目設定 as subjects_config FROM group_auth WHERE group_id = ?").bind(groupId).first();
            const customSubjects = config && config.subjects_config ? JSON.parse(config.subjects_config) : null;
            
            const allMonths = results.map(t => new Date(t.date).getMonth() + 1);
            const activeMonths = [...new Set(allMonths)].sort((a,b)=>a-b);

            return new Response(JSON.stringify({ tasks: results, customSubjects, activeMonths }));
        }

        // 2. 讀取作業 (管理端)
        if (action === "admin_get_tasks") {
            const { results } = await env.DB.prepare(`
                SELECT id, 群組 as group_id, 建立時間 as created_at, 截止日期 as date, 科目 as subject, 內容 as content, 來源 as source, 狀態 as status, 類別 as category 
                FROM tasks WHERE 群組 = ? ORDER BY 建立時間 DESC
            `).bind(groupId).all();
            return new Response(JSON.stringify({ tasks: results }));
        }

        // 3. 新增作業 (前端或後台)
        if (action === "add_task") {
            if (!groupId) return new Response("Error: No Group ID", { status: 400 });
            const isBad = ["幹", "靠", "死", "白痴", "智障", "腦殘"].some(w => (json.subject+json.content).includes(w));
            // 如果是管理員(isAdmin=true)，直接發佈；否則進入待審核 (或疑慮)
            const status = (isBad) ? "疑慮" : (json.isAdmin ? "已發佈" : "待審核"); 
            let cat = json.category || "作業";
            if (!json.category) { if (json.content.includes("考")) cat="考試"; else if(json.content.includes("帶")) cat="攜帶"; }
            
            await env.DB.prepare(`
                INSERT INTO tasks (群組, 建立時間, 截止日期, 科目, 內容, 來源, 狀態, 類別) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(groupId, Date.now(), json.date, json.subject, json.content, "網頁", status, cat).run();
            
            // 通知管理者
            if (env.ADMIN_USER_ID && env.LINE_CHANNEL_ACCESS_TOKEN) {
                const alertMsg = `[新作業通知]\n狀態：${status}\n科目：${json.subject}\n內容：${json.content}`;
                ctx.waitUntil(pushLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, env.ADMIN_USER_ID, alertMsg));
            }
            return new Response(JSON.stringify({ status: "success" }));
        }

        // 4. 管理作業 (刪除/審核)
        if (action === "manage_task") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            const roles = JSON.parse(auth.roles_json);
            
            const actor = roles[json.roleName];
            // 驗證密碼
            if (!actor || actor.hash !== await sha256(json.password)) return new Response(JSON.stringify({ status: "fail", msg: "密碼錯誤" }));

            let canDo = false;
            const actorPerms = actor.perm || [];
            
            // 權限檢查
            if (json.roleName === "總管理員" || actorPerms.includes("manage_tasks_full") || actorPerms.includes("manage_roles")) { 
                canDo = true;
            } else {
                const task = await env.DB.prepare("SELECT 科目 as subject FROM tasks WHERE id = ?").bind(json.taskId).first();
                if (task) {
                    const actorSubjects = actor.subjects || []; 
                    if (actorSubjects.includes(task.subject)) canDo = true;
                    // 相容舊版角色名稱判斷
                    else if (json.roleName.includes(task.subject)) canDo = true;
                }
            }

            if (canDo) {
                if(json.type === 'delete') {
                    await env.DB.prepare("DELETE FROM tasks WHERE id = ?").bind(json.taskId).run();
                } else if (json.type === 'approve') {
                    await env.DB.prepare("UPDATE tasks SET 狀態 = '已發佈' WHERE id = ?").bind(json.taskId).run();
                }
                return new Response(JSON.stringify({ status: "success" }));
            }
            return new Response(JSON.stringify({ status: "permission_denied" }));
        }

        // 5. 管理員檢查狀態
        if (action === "admin_check_status") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json, 群組名稱 as group_name FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "need_setup" })); 
            const rolesMap = JSON.parse(auth.roles_json);
            const roleNames = Object.keys(rolesMap);
            return new Response(JSON.stringify({ status: "login", roles: roleNames, groupName: auth.group_name }));
        }

        // 6. 管理員初始化
        if (action === "admin_setup") {
            if (!json.groupName) return new Response(JSON.stringify({ status: "fail", msg: "需要群組名稱" }));
            const hash = await sha256(json.password);
            const recoveryCode = genRecoveryCode();
            const initialRoles = { 
                "總管理員": { 
                    hash: hash, 
                    rec: recoveryCode, 
                    subjects: [],
                    perm: ["manage_roles", "manage_settings", "manage_tasks", "access_frontend_control", "self_change_pwd"] 
                } 
            };
            const defaultSubjects = JSON.stringify(['國語', '英文', '數學', '地理', '歷史', '公民', '理化', '生物', '地科', '資訊', '體育', '美術', '其他']);
            
            await env.DB.prepare("INSERT INTO group_auth (group_id, 群組名稱, 角色設定, 科目設定, 前端存取權) VALUES (?, ?, ?, ?, ?)").bind(
                groupId, json.groupName, JSON.stringify(initialRoles), defaultSubjects, 'enabled'
            ).run();
            
            return new Response(JSON.stringify({ status: "success", role: "總管理員", recoveryCode, groupName: json.groupName }));
        }

        // 7. 管理員登入
        if (action === "admin_login") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json, 科目設定 as subjects_config, 群組名稱 as group_name, 前端存取權 as access_control FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            
            const roles = JSON.parse(auth.roles_json);
            const targetRole = roles[json.roleName];
            if (!targetRole) return new Response(JSON.stringify({ status: "fail" }));
            
            const inputHash = await sha256(json.password);
            if (targetRole.hash === inputHash) {
                return new Response(JSON.stringify({ 
                    status: "success", 
                    role: json.roleName, 
                    subjects: JSON.parse(auth.subjects_config), 
                    recoveryCode: targetRole.rec || '未生成', 
                    allRoles: roles,
                    groupName: auth.group_name,
                    permissions: targetRole.perm || [],
                    accessControlStatus: auth.access_control
                }));
            }
            return new Response(JSON.stringify({ status: "fail" }));
        }

        // 8. 重置密碼
        if (action === "admin_reset_pwd") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            
            let roles = JSON.parse(auth.roles_json);
            const targetRole = roles[json.roleName];
            
            if (!targetRole || targetRole.rec !== json.recoveryCode) return new Response(JSON.stringify({ status: "fail" }));
            
            targetRole.hash = await sha256(json.newPassword);
            targetRole.rec = genRecoveryCode();
            roles[json.roleName] = targetRole;
            
            await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
            return new Response(JSON.stringify({ status: "success", newRecoveryCode: targetRole.rec }));
        }

        // 9. 更改自己的密碼
        if (action === "admin_change_pwd") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            
            let roles = JSON.parse(auth.roles_json);
            const targetRole = roles[json.roleName];
            if (!targetRole) return new Response(JSON.stringify({ status: "fail" }));

            const oldHash = await sha256(json.oldPassword);
            if (targetRole.hash === oldHash) {
                targetRole.hash = await sha256(json.newPassword);
                roles[json.roleName] = targetRole;
                await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
                return new Response(JSON.stringify({ status: "success" }));
            }
            return new Response(JSON.stringify({ status: "fail", msg: "舊密碼錯誤" }));
        }

        // 10. 更新設定 (科目/角色/權限)
        if (action === "update_settings") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));

            let roles = JSON.parse(auth.roles_json);

            // 總管理員權限驗證
            if (!roles["總管理員"] || roles["總管理員"].hash !== await sha256(json.password)) {
                return new Response(JSON.stringify({ status: "fail", msg: "總管理員權限不足" }));
            }

            if (json.subjects) {
                await env.DB.prepare("UPDATE group_auth SET 科目設定 = ? WHERE group_id = ?").bind(JSON.stringify(json.subjects), groupId).run();
            }

            if (json.accessControlStatus) {
                await env.DB.prepare("UPDATE group_auth SET 前端存取權 = ? WHERE group_id = ?").bind(json.accessControlStatus, groupId).run();
            }

            if (json.newRoleName && json.newRolePwd) {
                let defaultPerms = ["manage_tasks", "self_change_pwd"]; 
                let subjects = json.roleSubjects || [];
                
                if (json.newRoleName.includes("導師")) {
                    defaultPerms.push("manage_roles", "manage_settings", "access_frontend_control", "manage_tasks_full");
                } else if (json.newRoleName.includes("老師") || json.newRoleName.includes("正")) {
                    defaultPerms.push("manage_tasks_full"); 
                }
                
                roles[json.newRoleName] = { 
                    hash: await sha256(json.newRolePwd), 
                    rec: genRecoveryCode(),
                    subjects: subjects, 
                    perm: defaultPerms 
                };
                await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
                return new Response(JSON.stringify({ status: "success", recoveryCode: roles[json.newRoleName].rec, roleName: json.newRoleName }));
            }
            
            if (json.deleteRoleName) {
                delete roles[json.deleteRoleName];
                await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
            }

            if (json.roleToUpdate && json.newPermissions) {
                if(roles[json.roleToUpdate]) {
                     roles[json.roleToUpdate].perm = json.newPermissions;
                     await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
                     return new Response(JSON.stringify({ status: "success", msg: "權限已更新" }));
                }
            }

            return new Response(JSON.stringify({ status: "success" }));
        }

        // ===========================
        // Super Admin API
        // ===========================
        if (action === "super_admin_login") {
            const superPwd = env[SUPER_ADMIN_PASSWORD_ENV_KEY];
            if (!superPwd || superPwd === "SET_ME_IN_ENV") return new Response(JSON.stringify({ status: "fail", msg: "超級密碼未設定" }));
            if (json.password === superPwd) return new Response(JSON.stringify({ status: "success" }));
            return new Response(JSON.stringify({ status: "fail", msg: "密碼錯誤" }));
        }

        if (action === "super_admin_get_groups") {
            if (json.password !== env[SUPER_ADMIN_PASSWORD_ENV_KEY]) return new Response(JSON.stringify({ status: "fail" }));
            const { results } = await env.DB.prepare("SELECT group_id, 群組名稱, 角色設定 FROM group_auth").all();
            const groups = results.map(g => {
                let roles = {};
                try { roles = JSON.parse(g.角色設定); } catch (e) {}
                return { group_id: g.group_id, group_name: g.群組名稱 || '未命名', roles_json: JSON.stringify(roles) };
            });
            return new Response(JSON.stringify({ status: "success", groups }));
        }

        if (action === "super_admin_delete_group") {
            if (json.password !== env[SUPER_ADMIN_PASSWORD_ENV_KEY]) return new Response(JSON.stringify({ status: "fail" }));
            await env.DB.prepare("DELETE FROM group_auth WHERE group_id = ?").bind(json.targetGroupId).run();
            await env.DB.prepare("DELETE FROM tasks WHERE 群組 = ?").bind(json.targetGroupId).run();
            await env.DB.prepare("DELETE FROM line_user_state WHERE group_id = ?").bind(json.targetGroupId).run();
            return new Response(JSON.stringify({ status: "success" }));
        }

        return new Response("Unknown", { status: 400 }); // 如果 action 都不匹配
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
}

// ====================================================================
// ★ 輔助函式
// ====================================================================
async function handleLineWebhook(events, env, ctx) {
    for (const event of events) {
        const gId = event.source.groupId || event.source.roomId || event.source.userId;
        const uId = event.source.userId;

        // 偵錯：回傳原始訊息給管理員
        if (env.ADMIN_USER_ID && env.LINE_CHANNEL_ACCESS_TOKEN) {
             // ctx.waitUntil(pushLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, env.ADMIN_USER_ID, JSON.stringify(event)));
        }

        // 刪除指令
        if (event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === '/bot end') {
             ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `⚠️ 確定要刪除 ${gId} 的所有資料嗎？\n請在 30 秒內輸入：確認刪除 ${gId}`));
             await env.DB.prepare("UPDATE line_user_state SET state = 'awaiting_delete_confirm' WHERE user_id = ?").bind(uId).run();
             continue;
        }
        
        // 刪除確認
        const stateEntry = await env.DB.prepare("SELECT * FROM line_user_state WHERE user_id = ?").bind(uId).first();
        if (stateEntry && stateEntry.state === 'awaiting_delete_confirm' && event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === `確認刪除 ${gId}`) {
             await env.DB.prepare("DELETE FROM group_auth WHERE group_id = ?").bind(gId).run();
             await env.DB.prepare("DELETE FROM tasks WHERE 群組 = ?").bind(gId).run();
             await env.DB.prepare("DELETE FROM line_user_state WHERE user_id = ? OR group_id = ?").bind(uId, gId).run();
             ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, "✅ 資料已刪除。"));
             continue;
        }

        // 歡迎/同意流程
        if (event.type === 'join' || event.type === 'follow' || (event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === '/bot start')) {
            const statement = getStatement(gId);
            await env.DB.prepare("INSERT OR REPLACE INTO line_user_state (user_id, state, group_id) VALUES (?1, 'awaiting_agree', ?2)").bind(uId, gId).run();
            ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, statement));
            continue;
        }

        if (event.type === 'message' && event.message.type === 'text') {
            const msg = event.message.text.trim();
            
            if (stateEntry && stateEntry.state === 'awaiting_agree') {
                if (msg === '/bot agree') {
                    await env.DB.prepare("UPDATE line_user_state SET state = 'awaiting_old_id' WHERE user_id = ?").bind(uId).run();
                    ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, '太棒了！若為舊群組請輸入舊 ID，否則輸入「/bot new」生成新 ID。'));
                }
                continue;
            } else if (stateEntry && stateEntry.state === 'awaiting_old_id') {
                let finalId = gId;
                if (msg !== '/bot new') {
                    const oldGroup = await env.DB.prepare("SELECT group_id FROM group_auth WHERE group_id = ?").bind(msg).first();
                    if (oldGroup) finalId = msg;
                    else {
                         ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, '❌ ID 不存在，請重新輸入或打 /bot new。'));
                         continue;
                    }
                }
                await env.DB.prepare("UPDATE line_user_state SET state = 'setup_complete', group_id = ? WHERE user_id = ?").bind(finalId, uId).run();
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, getWelcomeMessage(finalId)));
                continue;
            }
        }

        // 正常指令處理
        const stateCheck = await env.DB.prepare("SELECT group_id FROM line_user_state WHERE user_id = ? AND state = 'setup_complete'").bind(uId).first();
        const effectiveGId = stateCheck ? stateCheck.group_id : gId;

        if (event.type === 'message' && event.message.type === 'text') {
            const msg = event.message.text.trim();
            if (msg === "/bot ID") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `Group ID:\n${effectiveGId}`)); continue; }
            if (msg === "作業網址" || msg === "公佈欄") {
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, getWelcomeMessage(effectiveGId)));
                continue;
            }
            if (msg === "/bot 學生班級作業") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `📊 學生班級作業：\n${DOMAIN_STUDENT}/?id=${effectiveGId}`)); continue; }
            if (msg === "/bot 後台管理") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `🔧 後台管理：\n${DOMAIN_MANAGER}/?id=${effectiveGId}`)); continue; }

            const t = parseTask(msg);
            if (t) {
                // Line 來的訊息預設為 '待審核'
                await env.DB.prepare(`
                    INSERT INTO tasks (群組, 建立時間, 截止日期, 科目, 內容, 來源, 狀態, 類別) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `).bind(effectiveGId, Date.now(), t.dStr, t.s, t.c, "LINE", "待審核", t.cat).run();
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `✅ 已收到作業(待審核)：\n${t.dStr} ${t.s} ${t.c}`));
            }
        }
    }
    return new Response("ok");
}

function getStatement(gId) {
    return `📋 服務使用聲明 📋\n1. 同意本系統版權歸開發者所有。\n2. 密碼經 SHA256 加密。\n3. 本系統為業餘作品。\n4. 需同意聲明後使用。\n\n同意請打 /bot agree`;
}

function getWelcomeMessage(gId) {
    return `大家好！我是作業機器人 🤖\nID: ${gId}\n\n📊 學生作業：\n${DOMAIN_STUDENT}/?id=${gId}\n\n🔧 後台管理：\n${DOMAIN_MANAGER}/?id=${gId}\n\n(請盡快設定後台)`;
}

function genRecoveryCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }
async function sha256(message) { const msgBuffer = new TextEncoder().encode(message); const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer); return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function replyLineMessage(token, replyToken, text) { if (!token) return; await fetch('https://api.line.me/v2/bot/message/reply', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ replyToken: replyToken, messages: [{ type: 'text', text: text }] }) }); }
async function pushLineMessage(token, userId, text) { if (!token || !userId) return; await fetch('https://api.line.me/v2/bot/message/push', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ to: userId, messages: [{ type: 'text', text: text }] }) }); }
function addDays(d, days) { const r = new Date(d); r.setDate(r.getDate() + days); return r; }

// 解析引擎
function parseTask(text) {
    let targetDate = null; let content = text; const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (text.includes("下禮拜")) { targetDate = addDays(today, 7); content = content.replace("下禮拜", ""); }
    if (text.includes("明天")) { targetDate = addDays(today, 1); content = content.replace("明天", ""); }
    else if (text.includes("後天")) { targetDate = addDays(today, 2); content = content.replace("後天", ""); }
    else if (text.match(/下(週|禮拜|星期)([一二三四五六日])/)) { 
        const match = text.match(/下(週|禮拜|星期)([一二三四五六日])/); 
        const map = { "一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "日": 0 }; 
        const targetDay = map[match[2]]; const currentDay = today.getDay(); 
        let daysToAdd = (7 - currentDay) + targetDay; if (targetDay === 0) daysToAdd += 7; 
        targetDate = addDays(today, daysToAdd); content = content.replace(match[0], ""); 
    }
    else { 
        const strictMatch = text.match(/(^|[^0-9])(\d{6,7})(?![0-9])/);
        let matchDateStr = null;
        if (strictMatch) { matchDateStr = strictMatch[2]; } else { const symMatch = text.match(/(\d{2,4})[./-](\d{1,2})[./-](\d{1,2})/); if (symMatch) matchDateStr = symMatch[0]; }
        if (matchDateStr) {
            let y, m, d;
            if (matchDateStr.match(/^\d{6,7}$/)) {
                let num = matchDateStr;
                if (num.length === 7) { y = parseInt(num.substring(0,3)); m = parseInt(num.substring(3,5)); d = parseInt(num.substring(5,7)); }
                else { y = parseInt(num.substring(0,2)); m = parseInt(num.substring(2,4)); d = parseInt(num.substring(4,6)); }
            } else {
                let symMatch = matchDateStr.match(/(\d{2,4})[./-](\d{1,2})[./-](\d{1,2})/);
                if(symMatch) { y = parseInt(symMatch[1]); m = parseInt(symMatch[2]); d = parseInt(symMatch[3]); }
            }
            if (y) {
                if (y < 1000) y += 1911; if (y < 2000) y += 2000;
                let tempDate = new Date(y, m - 1, d);
                // 修正：如果日期比今天早，且年份是今年，推到明年 (邏輯可依需求開關)
                if (tempDate < today && tempDate.getFullYear() === today.getFullYear()) tempDate.setFullYear(tempDate.getFullYear() + 1);
                
                if (!isNaN(tempDate.getTime())) {
                    targetDate = tempDate;
                    content = content.replace(matchDateStr, "");
                }
            }
        }
    }
    
    if (targetDate) { 
        content = content.replace(/要交|要考|截止|作業|要帶|記得|繳交/g, "").trim(); 
        let cat = "作業"; 
        if (text.includes("考")) cat = "考試"; else if (text.includes("帶")) cat = "攜帶"; 
        
        let sub = "其他"; 
        const subs = {"國語":["國文","國語","作文"],"英文":["英文","English"],"數學":["數學","Math"],"地理":["地理"],"歷史":["歷史"],"公民":["公民"],"理化":["理化","物理","化學"],"生物":["生物"],"地科":["地科"],"資訊":["資訊","電腦"],"體育":["體育"],"美術":["美術"]}; 
        for (let key in subs) { 
            if (subs[key].some(k => text.includes(k))) { 
                sub = key; 
                // 移除科目關鍵字，避免重複
                subs[key].forEach(k => content = content.replace(k, ""));
                break; 
            } 
        } 
        content = content.trim();
        const dStr = `${targetDate.getFullYear()}-${String(targetDate.getMonth()+1).padStart(2,'0')}-${String(targetDate.getDate()).padStart(2,'0')}`; 
        
        // 確保內容不為空
        if(content.length === 0) return null;
        
        return { dStr, s: sub, c: content, cat }; 
    }
    return null;
}

// ----------------------------------------------------------------------
// 學生端 HTML (保持不變)
// ----------------------------------------------------------------------
function renderStudentHTML() {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>作業公佈欄</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"><style>.filter-scroll::-webkit-scrollbar { width: 0; background: transparent;} .modal { background-color: rgba(0,0,0,0.5); } body { background-color: #f3f4f6; } .cat-exam { background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; } .cat-bring { background-color: #fef9c3; color: #854d0e; border: 1px solid #fde047; } .cat-homework { background-color: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }</style></head><body class="text-gray-800 font-sans min-h-screen pb-24"><div class="bg-white shadow-sm p-4 sticky top-0 z-10"><h1 class="text-xl font-bold text-gray-700 text-center">🏫 班級作業</h1></div><div class="max-w-2xl mx-auto p-4"><div class="bg-white rounded-xl shadow-sm p-3 mb-4 overflow-x-auto filter-scroll whitespace-nowrap" id="subject-container"></div><div id="loading" class="text-center text-gray-500 mt-10"><i class="fas fa-spinner fa-spin mr-2"></i>載入中...</div><div id="task-list" class="space-y-3"></div></div><button onclick="openModal()" class="fixed bottom-6 right-6 bg-blue-600 text-white w-14 h-14 rounded-full shadow-lg flex items-center justify-center text-2xl hover:bg-blue-700 transition z-20 active:scale-90"><i class="fas fa-plus"></i></button><div id="modal" class="modal fixed inset-0 hidden items-center justify-center z-50 px-4"><div class="bg-white rounded-xl shadow-2xl w-full max-w-sm overflow-hidden"><div class="p-4 bg-gray-50 border-b flex justify-between items-center"><h3 class="font-bold text-gray-700">✏️ 新增事項</h3><button onclick="closeModal()" class="text-gray-400 hover:text-gray-600"><i class="fas fa-times"></i></button></div><div class="p-4 space-y-3"><div class="flex gap-2"><div class="w-2/3"><label class="text-xs font-bold text-gray-500">日期</label><input type="date" id="input-date" class="w-full border rounded p-2"></div><div class="w-1/3"><label class="text-xs font-bold text-gray-500">類型</label><select id="input-category" class="w-full border rounded p-2 bg-white"><option value="作業">作業</option><option value="考試">考試</option><option value="攜帶">帶</option></select></div></div><div><label class="text-xs font-bold text-gray-500">科目</label><select id="input-subject" class="w-full border rounded p-2 bg-white"></select></div><div><label class="text-xs font-bold text-gray-500">內容</label><input type="text" id="input-content" class="w-full border rounded p-2" placeholder="內容..."></div></div><div class="p-4 border-t bg-gray-50"><button onclick="submitTask()" id="btn-submit" class="w-full bg-blue-600 text-white py-2 rounded-lg font-bold">送出</button></div></div></div><script>let allTasks=[],currentSubject='全部';let subjects=['全部','國語','英文','數學','地理','歷史','公民','理化','生物','地科','資訊','體育','美術','其他'];const urlParams=new URLSearchParams(window.location.search);const groupId=urlParams.get('id');window.onload=function(){if(!groupId){document.body.innerHTML='<div class="p-10 text-center text-red-500">請使用專屬連結進入</div>';return;}const tmr=new Date();tmr.setDate(tmr.getDate()+1);document.getElementById('input-date').valueAsDate=tmr;fetchData();};function fetchData(){fetch(window.location.href,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'get_tasks',groupId})}).then(r=>r.json()).then(d=>{allTasks=d.tasks||[];if(d.customSubjects){subjects=['全部',...d.customSubjects];}renderSubjects();document.getElementById('loading').style.display='none';renderList();});}function renderList(){const list=document.getElementById('task-list');const f=allTasks.filter(t=>currentSubject==='全部'||t.subject===currentSubject);if(f.length===0){list.innerHTML='<div class="text-center text-gray-400 py-10">無事項</div>';return;}list.innerHTML=f.map(t=>{const td=new Date(t.date),n=new Date();n.setHours(0,0,0,0);const diff=Math.ceil((td-n)/86400000);let st=diff+" 天後",bd="border-blue-400";if(diff<0){st="已過期";bd="border-gray-300";}else if(diff===0){st="今天";bd="border-red-500";}const w=["日","一","二","三","四","五","六"][td.getDay()];let cc="cat-homework",ci="fa-book";if(t.category==="考試"){cc="cat-exam";ci="fa-pen-to-square";}else if(t.category==="攜帶"){cc="cat-bring";ci="fa-briefcase";}return \`<div class="bg-white p-4 rounded-lg shadow-sm border-l-4 \${bd} mb-3"><div class="flex items-center gap-2 mb-1"><span class="text-xs font-bold px-2 py-0.5 rounded flex items-center gap-1 \${cc}"><i class="fas \${ci}"></i> \${t.category}</span><span class="text-xs font-bold text-gray-600 bg-gray-100 px-2 py-0.5 rounded">\${t.subject}</span><span class="text-xs text-gray-400">\${t.date}(\${w})</span></div><div class="text-lg font-medium">\${t.content}</div><div class="text-right text-xs text-gray-400">\${st}</div></div>\`;}).join('');}function submitTask(){const date=document.getElementById('input-date').value,subject=document.getElementById('input-subject').value,content=document.getElementById('input-content').value,category=document.getElementById('input-category').value;if(!date||!content)return alert("請填寫完整");const btn=document.getElementById('btn-submit');btn.disabled=true;btn.innerText="...";fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'add_task',date,subject,content,category,groupId,isAdmin:false})}).then(r=>r.json()).then(d=>{closeModal();btn.disabled=false;btn.innerText="送出";alert("✅ 已送出！\\n等待審核後顯示");});}function openModal(){document.getElementById('modal').classList.remove('hidden');document.getElementById('modal').classList.add('flex');}function closeModal(){document.getElementById('modal').classList.add('hidden');document.getElementById('modal').classList.remove('flex');}function renderSubjects(){document.getElementById('subject-container').innerHTML=subjects.map(s=>\`<button onclick="currentSubject='\${s}';renderList()" class="px-4 py-1 border rounded-full mr-2 text-sm whitespace-nowrap">\${s}</button>\`).join('');const sel=document.getElementById('input-subject');sel.innerHTML=subjects.filter(s=>s!=='全部').map(s=>\`<option>\${s}</option>\`).join('');}</script></body></html>`;
}

// ====================================================================
// ★ 管理端 HTML (renderManagerHTML)
// ====================================================================
function renderManagerHTML(env) {
    // 修復 Super Admin ID 缺少的問題
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>後台管理</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>body.light-mode{background-color:#f3f4f6;color:#1f2937}.light-mode .bg-gray-900{background-color:white;color:#1f2937;box-shadow:0 10px 15px -3px rgba(0,0,0,0.1)}.light-mode .bg-gray-800{background-color:#f9fafb;color:#1f2937;border:1px solid #e5e7eb}.light-mode .text-gray-300{color:#4b5563}.light-mode .text-white{color:#1f2937}.light-mode input,.light-mode textarea,.light-mode select{background-color:#f3f4f6;color:#1f2937;border-color:#d1d5db;}.select2-container .select2-selection--multiple { background-color: #f3f4f6!important; border-color: #d1d5db!important; }</style></head>
    <body class="bg-gray-800 text-gray-100 min-h-screen flex items-center justify-center p-4 transition-colors duration-300">
    <button onclick="toggleTheme()" class="fixed top-4 right-4 bg-gray-700 text-white p-2 rounded-full shadow hover:bg-gray-600 transition z-50"><i class="fas fa-adjust"></i></button>

<div id="step-id" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center">
    <h1 class="text-2xl font-bold mb-6">🔧 後台登入</h1>
    <input type="text" id="group-id" placeholder="群組 ID" class="w-full p-3 rounded bg-gray-700 border border-gray-600 mb-4 text-center text-white">
    <button onclick="checkId()" class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded font-bold">下一步</button>
</div>

<div id="step-role" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center hidden">
    <h1 class="text-2xl font-bold mb-4">👤 請選擇身分</h1>
    <div id="role-buttons" class="grid grid-cols-2 gap-3"></div>
    <button onclick="backToId()" class="mt-4 text-sm text-gray-500 hover:text-white">返回</button>
</div>

<div id="step-pwd" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center hidden">
    <h1 class="text-2xl font-bold mb-2">🔐 <span id="current-role-name"></span></h1>
    <p class="text-gray-400 text-sm mb-6">請輸入密碼</p>
    <div class="relative mb-4"><input type="password" id="password" placeholder="密碼" class="w-full p-3 rounded bg-gray-700 border border-gray-600 text-center text-white pr-10"><i class="fas fa-eye absolute right-3 top-4 text-gray-400 cursor-pointer hover:text-white" onclick="togglePwd('password', this)"></i></div>
    <button onclick="doLogin()" class="w-full bg-green-600 hover:bg-green-500 py-3 rounded font-bold">登入</button>
    <div class="flex justify-center gap-4 mt-4 text-xs">
        <div class="text-blue-400 cursor-pointer" onclick="showReset()">忘記密碼?</div>
        <div class="text-gray-500 cursor-pointer" onclick="backToRole()">切換身分</div>
    </div>
</div>

<div id="step-setup" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center hidden">
    <h1 class="text-2xl font-bold mb-2">✨ 第一次使用</h1>
    <p class="text-gray-400 text-sm mb-6">請設定群組名稱與總管理員密碼</p>
    <input type="text" id="setup-name" placeholder="群組名稱 (例: 115 班)" class="w-full p-3 rounded bg-gray-700 border border-gray-600 text-center text-white mb-4">
    <input type="password" id="setup-pwd" placeholder="設定密碼" class="w-full p-3 rounded bg-gray-700 border border-gray-600 text-center text-white mb-4">
    <button onclick="doSetup()" class="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded font-bold">設定並啟用</button>
</div>

<div id="step-reset" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center hidden">
    <h1 class="text-2xl font-bold mb-2">🆘 重置密碼</h1>
    <p class="text-gray-400 text-sm mb-4">身分：<span id="reset-role-name" class="font-bold text-white"></span></p>
    <input type="text" id="recovery-code" placeholder="救援碼" class="w-full p-3 rounded bg-gray-700 border border-gray-600 mb-2 text-center text-white">
    <input type="password" id="new-password" placeholder="新密碼" class="w-full p-3 rounded bg-gray-700 border border-gray-600 mb-4 text-center text-white">
    <button onclick="doReset()" class="w-full bg-red-600 hover:bg-red-500 py-3 rounded font-bold">重設</button>
    <button onclick="backToPwd()" class="mt-2 text-xs text-gray-500 hover:text-white">取消</button>
</div>

<div id="step-dashboard" class="w-full max-w-6xl hidden">
    <div class="flex justify-between items-center mb-6">
        <div>
            <h1 class="text-2xl font-bold"><i class="fas fa-cog"></i> <span id="dash-group-name"></span> <span id="dash-role" class="text-base text-gray-400"></span></h1>
            <div class="text-xs text-gray-400 mt-1 flex items-center gap-2">
                救援碼: <span id="my-rec-code" class="blur-sm select-none">****</span> 
                <i class="fas fa-eye cursor-pointer hover:text-white" onclick="toggleRec()"></i>
            </div>
        </div>
        <div class="flex items-center space-x-2">
            <button onclick="openAddModal()" class="text-sm bg-green-700 px-3 py-1 rounded hover:bg-green-600">新增作業</button>
            <button onclick="doLogout()" class="text-sm text-gray-400 hover:text-white">登出</button>
        </div>
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="space-y-6">
             <div class="bg-gray-900 p-6 rounded-xl">
                <h3 class="font-bold mb-4 text-gray-300 border-b border-gray-700 pb-2">🔑 更改密碼</h3>
                <input type="password" id="old-pwd-change" placeholder="舊密碼" class="w-full bg-gray-800 p-2 rounded text-sm mb-2">
                <input type="password" id="new-pwd-change" placeholder="新密碼" class="w-full bg-gray-800 p-2 rounded text-sm mb-2">
                <button onclick="changeOwnPassword()" class="w-full bg-yellow-700 hover:bg-yellow-600 py-1 rounded text-xs text-white">更新密碼</button>
            </div>

            <div id="settings-panel" class="bg-gray-900 p-6 rounded-xl hidden">
                <h3 class="font-bold mb-4 text-gray-300 border-b border-gray-700 pb-2">⚙️ 人員與權限設定</h3>
                
                <div class="mb-4">
                    <label class="text-xs text-gray-500 block mb-1">前端網頁存取權</label>
                    <select id="access-control-select" onchange="toggleAccessControl()" class="w-full bg-gray-800 p-2 rounded text-sm">
                        <option value="enabled">🟢 啟用 (學生可看)</option>
                        <option value="disabled">🔴 禁用 (學生看不到)</option>
                    </select>
                </div>

                <div class="mb-4">
                    <label class="text-xs text-gray-500">新增/修改人員</label>
                    <input type="text" id="new-role-name" placeholder="職稱 (例: 國語老師/副班長)" class="w-full bg-gray-800 p-2 rounded text-sm mb-2">
                    <input type="password" id="new-role-pwd" placeholder="密碼" class="w-full bg-gray-800 p-2 rounded text-sm mb-2">
                    <textarea id="new-role-subjects" placeholder="可使用科目 (逗號分隔, 例: 國語,英文)" class="w-full bg-gray-800 p-2 rounded text-sm h-14 mb-2"></textarea>
                    <button onclick="saveNewRole()" class="w-full bg-blue-700 hover:bg-blue-600 py-1 rounded text-xs text-white">儲存</button>
                </div>
                
                <div class="mb-4">
                    <label class="text-xs text-gray-500">刪除人員</label>
                    <div class="flex gap-1 mt-1">
                        <select id="del-role-select" class="bg-gray-800 text-sm rounded w-2/3 p-1"></select>
                        <button onclick="deleteRole()" class="bg-red-900 hover:bg-red-700 text-xs rounded w-1/3 text-white">刪除</button>
                    </div>
                </div>

                <div class="mb-4">
                    <label class="text-xs text-gray-500">科目列表 (逗號分隔)</label>
                    <textarea id="edit-subjects" class="w-full bg-gray-800 p-2 rounded text-sm h-20 mt-1"></textarea>
                    <button onclick="saveSubjects()" class="mt-2 w-full bg-gray-700 hover:bg-gray-600 py-1 rounded text-xs">更新科目</button>
                </div>
                
                <div class="mb-4">
                    <h3 class="font-bold text-xs text-gray-500 border-t border-gray-700 pt-2 mb-2">權限調整 (高級)</h3>
                    <select id="perm-role-select" onchange="renderRolePermissions(this.value)" class="w-full bg-gray-800 p-2 rounded text-sm mb-2"></select>
                    <div id="perm-checkboxes" class="space-y-1 text-sm"></div>
                    <button onclick="updateRolePermissions()" class="mt-2 w-full bg-purple-700 hover:bg-purple-600 py-1 rounded text-xs text-white">更新權限</button>
                </div>
                
            </div>
        </div>
        
        <div id="tasks-panel" class="md:col-span-2 bg-gray-900 p-6 rounded-xl w-full">
            <h3 class="font-bold mb-4 text-gray-300 border-b border-gray-700 pb-2">🗑️ 作業管理</h3>
            <div id="admin-task-list" class="space-y-3"></div>
        </div>
    </div>
</div>

<div id="modal-admin-add" class="fixed inset-0 hidden items-center justify-center z-50 px-4" style="background-color:rgba(0,0,0,0.7)"><div class="bg-gray-800 rounded-xl shadow-2xl w-full max-w-sm overflow-hidden text-gray-200"><div class="p-4 border-b border-gray-700 flex justify-between items-center"><h3 class="font-bold">✏️ 管理員新增</h3><button onclick="closeAddModal()" class="text-gray-400 hover:text-white"><i class="fas fa-times"></i></button></div><div class="p-4 space-y-3"><div class="flex gap-2"><div class="w-2/3"><label class="text-xs font-bold text-gray-500">日期</label><input type="date" id="admin-date" class="w-full bg-gray-700 border-none rounded p-2"></div><div class="w-1/3"><label class="text-xs font-bold text-gray-500">類型</label><select id="admin-category" class="w-full bg-gray-700 border-none rounded p-2"><option value="作業">作業</option><option value="考試">考試</option><option value="攜帶">帶</option></select></div></div><div><label class="text-xs font-bold text-gray-500">科目</label><select id="admin-subject" class="w-full bg-gray-700 border-none rounded p-2"></select></div><div><label class="text-xs font-bold text-gray-500">內容</label><input type="text" id="admin-content" class="w-full bg-gray-700 border-none rounded p-2" placeholder="內容..."></div></div><div class="p-4 border-t border-gray-700"><button onclick="adminSubmitTask()" class="w-full bg-blue-600 text-white py-2 rounded-lg font-bold">直接發佈</button></div></div></div>

<script>
let gId='', selectedRole='', currentSubjects=[], roleList=[], currentRolesMap={}, currentAccessStatus='enabled';
const PERMISSIONS = {
    "manage_tasks": "基本作業管理(刪除/審核)",
    "manage_tasks_full": "進階作業管理(全科目)",
    "manage_roles": "角色增刪改",
    "manage_settings": "科目/權限設定",
    "access_frontend_control": "前端存取權開關",
    "self_change_pwd": "自行更改密碼"
};

// ★ 持久化登入檢查
window.onload = function() {
    const urlParams = new URLSearchParams(window.location.search);
    const urlId = urlParams.get('id');
    const savedId = localStorage.getItem('hw_gid');
    const savedRole = localStorage.getItem('hw_role');
    const savedPwd = localStorage.getItem('hw_pwd');

    if (urlId) { 
        gId = urlId; 
    } else if (savedId) {
        gId = savedId;
    }

    if (gId) {
        document.getElementById('group-id').value = gId;
        if (savedRole && savedPwd) {
            selectedRole = savedRole;
            document.getElementById('password').value = savedPwd;
            document.getElementById('current-role-name').innerText = savedRole;
            doLogin(true); // 靜默登入
        } else {
            checkId();
        }
    }
}

function showSection(id) {
    ['step-id','step-role','step-pwd','step-setup','step-reset','step-dashboard'].forEach(s => document.getElementById(s).classList.add('hidden'));
    document.getElementById(id).classList.remove('hidden');
}

function checkId(){ 
    gId = document.getElementById('group-id').value.trim(); 
    if(!gId) return alert("請輸入ID"); 
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_check_status',groupId:gId})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status==='need_setup') showSection('step-setup');
        else if(d.status==='login') {
            roleList = d.roles;
            document.getElementById('dash-group-name').innerText = d.groupName || '未命名群組';
            renderRoleButtons();
            showSection('step-role');
        }
    }); 
}

function renderRoleButtons() {
    const div = document.getElementById('role-buttons');
    div.innerHTML = roleList.map(r => 
        \`<button onclick="selectRole('\${r}')" class="bg-gray-700 hover:bg-gray-600 p-3 rounded text-white font-bold">\${r}</button>\`
    ).join('');
}

function selectRole(role) {
    selectedRole = role;
    document.getElementById('current-role-name').innerText = role;
    showSection('step-pwd');
}

function backToId() { showSection('step-id'); }
function backToRole() { showSection('step-role'); }
function backToPwd() { showSection('step-pwd'); }

function doSetup() {
    const name = document.getElementById('setup-name').value;
    const pwd = document.getElementById('setup-pwd').value;
    if(!name || !pwd) return alert("請填寫完整資訊");
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_setup',groupId:gId,password:pwd,groupName:name})})
    .then(r=>r.json()).then(d=>{ 
        if (d.status === 'success') {
            alert("✅ 設定成功！您的群組名稱是: "+d.groupName+"\\n請務必截圖保存總管理員救援碼： " + d.recoveryCode);
            localStorage.setItem('hw_gid', gId);
            localStorage.setItem('hw_role', d.role);
            localStorage.setItem('hw_pwd', pwd);
            location.reload(); 
        } else {
            alert("❌ 設定失敗：" + d.msg);
        }
    });
}

function doLogin(silent = false) {
    const pwd = document.getElementById('password').value;
    if(!pwd && !silent) return alert("請輸入密碼");
    
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_login',groupId:gId,roleName:selectedRole,password:pwd})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status==='success') {
            localStorage.setItem('hw_gid', gId);
            localStorage.setItem('hw_role', selectedRole);
            localStorage.setItem('hw_pwd', pwd);

            currentSubjects = d.subjects;
            currentRolesMap = d.allRoles;
            currentAccessStatus = d.accessControlStatus;

            document.getElementById('dash-group-name').innerText = d.groupName || '未命名群組';
            document.getElementById('dash-role').innerText = "(身分: " + selectedRole + ")";
            document.getElementById('my-rec-code').innerText = d.recoveryCode || '未生成 (請重置密碼)';
            
            const canManageRoles = d.permissions.includes('manage_roles') || selectedRole === '總管理員' || selectedRole.includes('導師');

            if(canManageRoles) {
                document.getElementById('settings-panel').classList.remove('hidden');
                document.getElementById('edit-subjects').value = currentSubjects.join(',');
                updateDelRoleSelect(d.allRoles);
                updatePermRoleSelect(d.allRoles);
                document.getElementById('access-control-select').value = currentAccessStatus;
            } else {
                document.getElementById('settings-panel').classList.add('hidden');
            }
            
            loadTasks();
            showSection('step-dashboard');
        } else {
            if(!silent) alert("❌ 密碼錯誤");
            else { localStorage.clear(); showSection('step-role'); }
        }
    });
}

function doLogout() {
    localStorage.clear();
    location.reload();
}

function showReset() { 
    document.getElementById('reset-role-name').innerText = selectedRole;
    showSection('step-reset'); 
}

function doReset() {
    const rc = document.getElementById('recovery-code').value;
    const np = document.getElementById('new-password').value;
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_reset_pwd',groupId:gId,roleName:selectedRole,recoveryCode:rc,newPassword:np})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status==='success') { alert("重置成功！新救援碼: "+d.newRecoveryCode); backToPwd(); }
        else alert("救援碼錯誤");
    });
}

function changeOwnPassword() {
    const oldPwd = document.getElementById('old-pwd-change').value;
    const newPwd = document.getElementById('new-pwd-change').value;
    if(!oldPwd || !newPwd) return alert("請填寫新舊密碼");

    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_change_pwd',groupId:gId,roleName:selectedRole,oldPassword:oldPwd,newPassword:newPwd})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status==='success') { 
            alert("密碼更新成功！請使用新密碼登入或儲存。"); 
            localStorage.setItem('hw_pwd', newPwd);
            document.getElementById('old-pwd-change').value = '';
            document.getElementById('new-pwd-change').value = '';
        } else {
            alert("❌ 密碼更新失敗：" + (d.msg || "舊密碼錯誤"));
        }
    });
}

function saveNewRole() {
    const name = document.getElementById('new-role-name').value;
    const pwd = document.getElementById('new-role-pwd').value;
    const subjects = document.getElementById('new-role-subjects').value.split(',').map(s=>s.trim()).filter(s=>s);
    const masterPwd = localStorage.getItem('hw_pwd');

    if(!name || !pwd) return alert("請填寫職稱和密碼");
    
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:masterPwd,newRoleName:name,newRolePwd:pwd,roleSubjects:subjects})})
    .then(r=>r.json()).then(d=>{ 
        if (d.status === 'success') {
            alert(\`✅ \${d.roleName} 新增成功！救援碼: \${d.recoveryCode}\`); 
            location.reload(); 
        } else {
            alert("❌ 新增失敗：" + d.msg);
        }
    });
}

function deleteRole() {
    const name = document.getElementById('del-role-select').value;
    const masterPwd = localStorage.getItem('hw_pwd');
    if(!confirm("確定刪除 "+name+" ?")) return;
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:masterPwd,deleteRoleName:name})})
    .then(r=>r.json()).then(d=>{ alert("✅ 已刪除"); location.reload(); });
}

function updateDelRoleSelect(rolesMap) {
    const sel = document.getElementById('del-role-select');
    sel.innerHTML = Object.keys(rolesMap).filter(r=>r!=='總管理員').map(r=>\`<option>\${r}</option>\`).join('');
}

function toggleAccessControl() {
    const status = document.getElementById('access-control-select').value;
    const masterPwd = localStorage.getItem('hw_pwd');
    if(!confirm(\`確定將前端網頁存取權設為 [\${status==='enabled'?'啟用':'禁用'}] 嗎？\`)) return document.getElementById('access-control-select').value = currentAccessStatus;

    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:masterPwd,accessControlStatus:status})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status === 'success') { alert("✅ 存取權已更新"); currentAccessStatus = status; } 
        else { alert("❌ 更新失敗：" + d.msg); document.getElementById('access-control-select').value = currentAccessStatus; }
    });
}

function updatePermRoleSelect(rolesMap) {
    const sel = document.getElementById('perm-role-select');
    sel.innerHTML = Object.keys(rolesMap).filter(r=>r!=='總管理員').map(r=>\`<option>\${r}</option>\`).join('');
    if (sel.value) renderRolePermissions(sel.value);
}

function renderRolePermissions(roleName) {
    const role = currentRolesMap[roleName];
    const permDiv = document.getElementById('perm-checkboxes');
    const currentPerms = role.perm || [];
    
    permDiv.innerHTML = Object.entries(PERMISSIONS).map(([key, desc]) => {
        if (key === 'self_change_pwd') return ''; 
        const checked = currentPerms.includes(key) ? 'checked' : '';
        return \`
            <label class="flex items-center text-gray-300">
                <input type="checkbox" value="\${key}" \${checked} class="mr-2"> \${desc}
            </label>
        \`;
    }).join('');
}

function updateRolePermissions() {
    const roleToUpdate = document.getElementById('perm-role-select').value;
    const masterPwd = localStorage.getItem('hw_pwd');
    const checkboxes = document.querySelectorAll('#perm-checkboxes input[type="checkbox"]');
    
    const newPermissions = Array.from(checkboxes)
        .filter(cb => cb.checked)
        .map(cb => cb.value);
    
    newPermissions.push('self_change_pwd');

    if(!confirm(\`確定更新 \${roleToUpdate} 的權限嗎？\`)) return;

    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:masterPwd,roleToUpdate:roleToUpdate,newPermissions:newPermissions})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status === 'success') { alert("✅ 權限已更新"); location.reload(); } 
        else { alert("❌ 更新失敗：" + d.msg); }
    });
}

function saveSubjects(){ const newSub=document.getElementById('edit-subjects').value.split(',').map(s=>s.trim()).filter(s=>s); fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:localStorage.getItem('hw_pwd'),subjects:newSub})}).then(r=>r.json()).then(d=>{ alert("✅ 科目更新成功"); currentSubjects=newSub; }); }

function toggleTheme() { document.body.classList.toggle('light-mode'); }
function togglePwd(id, icon) { const inp = document.getElementById(id); if(inp.type==='password'){ inp.type='text'; icon.classList.remove('fa-eye'); icon.classList.add('fa-eye-slash'); } else { inp.type='password'; icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); } }
function toggleRec() { const s = document.getElementById('my-rec-code'); s.classList.toggle('blur-sm'); s.classList.toggle('select-none'); }

function loadTasks(){ 
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_get_tasks',groupId:gId})})
    .then(r=>r.json()).then(d=>{ 
        const list=document.getElementById('admin-task-list'); 
        list.innerHTML=d.tasks.map(t=>{ 
            const actor = currentRolesMap[selectedRole] || {};
            const actorSubjects = actor.subjects || [];
            const actorPerms = actor.perm || [];
            
            // 權限檢查：總管理員必定可以刪除
            let canControl = (selectedRole === '總管理員') || actorPerms.includes('manage_tasks_full') || actorPerms.includes('manage_roles') || actorSubjects.includes(t.subject) || selectedRole.includes('副班長'); 
            
            let btnDel = canControl ? \`<button onclick="delTask(\${t.id})" class="text-red-400 hover:text-red-300 font-bold ml-2 px-3 py-1 border border-red-900 rounded bg-red-900/30">刪除</button>\` : '';
            let btnApprove = (canControl && (t.status==='待審核' || t.status==='疑慮')) ? \`<button onclick="approveTask(\${t.id})" class="text-green-400 hover:text-green-300 font-bold ml-auto px-3 py-1 border border-green-900 rounded bg-green-900/30">✅ 通過</button>\` : '';
            
            let statusColor = "bg-gray-700 text-gray-300";
            if(t.status === '待審核') statusColor = "bg-yellow-900 text-yellow-200 border border-yellow-700";
            if(t.status === '疑慮') statusColor = "bg-red-900 text-red-200 border border-red-700";
            if(t.status === '已發佈') statusColor = "bg-green-900 text-green-200 border border-green-700";

            return \`<div class="flex items-center gap-3 p-3 bg-gray-800 rounded border-l-4 border-blue-500 mb-2">
                <span class="text-xs \${statusColor} px-2 py-1 rounded">\${t.status}</span>
                <span class="text-xs bg-gray-700 px-2 py-1 rounded">\${t.subject}</span>
                <span class="flex-1 text-sm">\${t.content}</span>
                <span class="text-xs text-gray-400">\${t.date.substring(5)}</span>
                \${btnApprove}\${btnDel}
            </div>\`; 
        }).join(''); 
    }); 
}
function approveTask(id) { if(!confirm("確定通過審核？")) return; fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'manage_task',type:'approve',groupId:gId,taskId:id,password:localStorage.getItem('hw_pwd'),roleName:selectedRole})}).then(r=>r.json()).then(d=>{ if(d.status==='success') loadTasks(); else alert("❌ 失敗或無權限"); }); }
function delTask(id){ if(!confirm("確定刪除?"))return; fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'manage_task',type:'delete',groupId:gId,taskId:id,password:localStorage.getItem('hw_pwd'),roleName:selectedRole})}).then(r=>r.json()).then(d=>{ if(d.status==='success')loadTasks();else alert("❌ 無權限"); }); }
function openAddModal() { 
    document.getElementById('modal-admin-add').classList.remove('hidden'); document.getElementById('modal-admin-add').classList.add('flex'); const tmr=new Date();tmr.setDate(tmr.getDate()+1);document.getElementById('admin-date').valueAsDate=tmr; 
    const subSel = document.getElementById('admin-subject');
    const actor = currentRolesMap[selectedRole] || {};
    const actorSubjects = actor.subjects || [];

    if (selectedRole === '總管理員' || selectedRole.includes('導師') || selectedRole.includes('老師')) {
        subSel.innerHTML = currentSubjects.map(s=>\`<option>\${s}</option>\`).join('');
        subSel.disabled = false;
    } else if (actorSubjects.length > 0) {
        subSel.innerHTML = actorSubjects.map(s=>\`<option>\${s}</option>\`).join('');
        subSel.disabled = false;
    } else {
        let mySub = currentSubjects.find(s => selectedRole.includes(s)) || "其他";
        subSel.innerHTML = \`<option>\${mySub}</option>\`;
        subSel.disabled = true;
    }
}
function closeAddModal() { document.getElementById('modal-admin-add').classList.add('hidden'); document.getElementById('modal-admin-add').classList.remove('flex'); }
function adminSubmitTask() { const date=document.getElementById('admin-date').value, subject=document.getElementById('admin-subject').value, content=document.getElementById('admin-content').value, category=document.getElementById('admin-category').value; if(!date||!content) return alert("請填寫完整"); fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'add_task',date,subject,content,category,groupId:gId,isAdmin:true})}).then(r=>r.json()).then(d=>{ closeAddModal(); loadTasks(); alert("✅ 已新增"); }); }
</script></body></html>`;
}

// 15. 超級管理員介面 HTML (新增)
function renderSuperAdminHTML() {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>超級管理員</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>body{background-color:#1f2937;color:#f3f4f6}</style></head>
    <body class="min-h-screen flex items-start justify-center p-8">

<div id="super-login" class="bg-gray-900 p-8 rounded-xl shadow-2xl w-full max-w-md text-center">
    <h1 class="text-2xl font-bold mb-6">👑 超級管理員登入</h1>
    <input type="password" id="super-admin-pwd" placeholder="超級管理員密碼" class="w-full p-3 rounded bg-gray-700 border border-gray-600 mb-4 text-center text-white">
    <button onclick="superLogin()" class="w-full bg-red-600 hover:bg-red-500 py-3 rounded font-bold">登入</button>
</div>

<div id="super-dashboard" class="w-full max-w-5xl hidden">
    <h1 class="text-3xl font-bold mb-6 text-center">🌍 全局群組管理</h1>
    
    <div class="mb-6 flex justify-between items-center">
        <div class="w-1/3 mr-4">
            <input type="text" id="search-input" onkeyup="filterGroups()" placeholder="搜尋 ID 或名稱..." class="w-full p-3 rounded bg-gray-700 border border-gray-600 text-white">
        </div>
        <div>
             <button onclick="loadGroups()" class="bg-blue-600 hover:bg-blue-500 py-2 px-4 rounded font-bold">重新載入</button>
             <button onclick="superLogout()" class="ml-4 text-gray-400 hover:text-white">登出</button>
        </div>
    </div>

    <div id="group-list" class="space-y-4">
        <div class="text-center text-gray-500 mt-10" id="group-loading"><i class="fas fa-spinner fa-spin mr-2"></i>載入中...</div>
    </div>
</div>

<script>
let superPassword = '';
let allGroups = [];

window.onload = function() {
    const savedPwd = sessionStorage.getItem('super_admin_pwd');
    if (savedPwd) {
        document.getElementById('super-admin-pwd').value = savedPwd;
        superLogin(true);
    }
}

function showSuperSection(id) {
    document.getElementById('super-login').classList.add('hidden');
    document.getElementById('super-dashboard').classList.add('hidden');
    document.getElementById(id).classList.remove('hidden');
}

function superLogin(silent = false) {
    const pwd = document.getElementById('super-admin-pwd').value;
    if(!pwd && !silent) return alert("請輸入密碼");
    
    fetch(window.location.href, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'super_admin_login', password: pwd})
    })
    .then(r => r.json())
    .then(d => {
        if (d.status === 'success') {
            superPassword = pwd;
            sessionStorage.setItem('super_admin_pwd', pwd);
            showSuperSection('super-dashboard');
            loadGroups();
        } else {
            if(!silent) alert("❌ 登入失敗: " + (d.msg || '密碼錯誤'));
            sessionStorage.removeItem('super_admin_pwd');
        }
    });
}

function superLogout() {
    sessionStorage.removeItem('super_admin_pwd');
    showSuperSection('super-login');
    document.getElementById('super-admin-pwd').value = '';
    allGroups = [];
}

function loadGroups() {
    const list = document.getElementById('group-list');
    const loading = document.getElementById('group-loading');
    list.innerHTML = '';
    // 這裡修復了ID未找到的可能
    if(loading) loading.classList.remove('hidden');

    fetch(window.location.href, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'super_admin_get_groups', password: superPassword})
    })
    .then(r => r.json())
    .then(d => {
        if(loading) loading.classList.add('hidden');
        if (d.status === 'success') {
            allGroups = d.groups || [];
            renderGroups(allGroups);
        } else {
            alert("❌ 載入失敗: " + d.msg);
        }
    });
}

function deleteGroup(id, name) {
    if(!confirm(\`⚠️ 確定要刪除群組 [\${name || id}] 的所有資料嗎？此操作無法復原。\`)) return;

    fetch(window.location.href, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'super_admin_delete_group', password: superPassword, targetGroupId: id})
    })
    .then(r => r.json())
    .then(d => {
        if (d.status === 'success') {
            alert(\`✅ 群組 [\${name || id}] 已刪除。\`);
            loadGroups();
        } else {
            alert("❌ 刪除失敗: " + d.msg);
        }
    });
}

function renderGroups(groups) {
    const list = document.getElementById('group-list');
    if (groups.length === 0) {
        list.innerHTML = '<div class="text-center text-gray-500 py-10">無符合條件的群組</div>';
        return;
    }
    
    list.innerHTML = groups.map(g => {
        let roles = {};
        try { roles = JSON.parse(g.roles_json); } catch (e) {}
        
        const recoveryCodes = Object.entries(roles).map(([name, data]) => 
            \`<div class="text-xs"><b>\${name}:</b> \${data.rec || '無救援碼'}</div>\` 
        ).join('');
        
        return \`<div class="bg-gray-800 p-4 rounded-xl">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <h3 class="font-bold text-lg">\${g.group_name || '未命名'}</h3>
                    <p class="text-sm text-gray-400">ID: \${g.group_id}</p>
                    <div class="mt-2 text-gray-300">\${recoveryCodes}</div>
                </div>
                <button onclick="deleteGroup('\${g.group_id}', '\${g.group_name}')" class="bg-red-900 hover:bg-red-700 px-3 py-1 rounded text-sm">刪除</button>
            </div>
        </div>\`;
    }).join('');
}

function filterGroups() {
    const keyword = document.getElementById('search-input').value.toLowerCase();
    const filtered = allGroups.filter(g => 
        g.group_id.toLowerCase().includes(keyword) || 
        (g.group_name && g.group_name.toLowerCase().includes(keyword))
    );
    renderGroups(filtered);
}
</script></body></html>`;
}
