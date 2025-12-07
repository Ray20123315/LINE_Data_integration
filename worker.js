// ==========================================
// ★ 設定區
// ==========================================
const DOMAIN_STUDENT = "https://homework.ray2026.dpdns.org";
const DOMAIN_MANAGER = "https://homeworkmanage.ray2026.dpdns.org";
// ❗ 建議將 SUPER_ADMIN_PASSWORD 設為環境變數 (env.SUPER_ADMIN_PASSWORD)
// 請確保您的 Worker 環境變數中已設定 SUPER_ADMIN_PASSWORD
const SUPER_ADMIN_PASSWORD_ENV_KEY = 'SUPER_ADMIN_PASSWORD'; 
const SUPER_ADMIN_PATH = "/super-admin";


export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const hostname = url.hostname; 
        const isManagerSite = hostname.includes("homeworkmanage") || hostname.includes("manage");
        // New: Check for Super Admin access (15)
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
        
        // ===========================
        // D. LINE Webhook (17, 18, 19, 5, 20)
        // 使用 D1 儲存 line_user_state 進行多步驟對話
        // ===========================
        if (json.events) {
            return handleLineWebhook(json.events, env, ctx);
        }

        // ===========================
        // A. 讀取作業 (適配中文欄位)
        // ===========================
        if (json.action === "get_tasks") {
            if (!groupId) return new Response(JSON.stringify([]));
            
            // New: 12. 檢查前端存取權
            const access = await env.DB.prepare("SELECT 前端存取權 FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (access && access.前端存取權 === 'disabled') {
                return new Response(JSON.stringify({ tasks: [], error: "前端存取權已關閉" }));
            }
            
            const tenMinsAgo = Date.now() - (10 * 60 * 1000);
            
            // 自動過審 (欄位: 狀態, 建立時間, 群組)
            await env.DB.prepare("UPDATE tasks SET 狀態 = '已發佈' WHERE 狀態 = '待審核' AND 建立時間 < ? AND 群組 = ?").bind(tenMinsAgo, groupId).run();
            
            // 讀取作業 (AS 轉英文)
            const { results } = await env.DB.prepare(`
                SELECT id, 群組 as group_id, 建立時間 as created_at, 截止日期 as date, 科目 as subject, 內容 as content, 來源 as source, 狀態 as status, 類別 as category 
                FROM tasks WHERE 狀態 = '已發佈' AND 群組 = ? ORDER BY 截止日期 ASC
            `).bind(groupId).all();
            
            // 讀取設定 (欄位: group_id, 科目設定)
            const config = await env.DB.prepare("SELECT 科目設定 as subjects_config FROM group_auth WHERE group_id = ?").bind(groupId).first();
            const customSubjects = config && config.subjects_config ? JSON.parse(config.subjects_config) : null;
            
            // New: 讀取所有啟用月份
            const allMonths = results.map(t => new Date(t.date).getMonth() + 1);
            const activeMonths = [...new Set(allMonths)].sort((a,b)=>a-b);

            return new Response(JSON.stringify({ tasks: results, customSubjects, activeMonths }));
        }

        // A-2. 管理員讀取作業
        if (json.action === "admin_get_tasks") {
            const { results } = await env.DB.prepare(`
                SELECT id, 群組 as group_id, 建立時間 as created_at, 截止日期 as date, 科目 as subject, 內容 as content, 來源 as source, 狀態 as status, 類別 as category 
                FROM tasks WHERE 群組 = ? ORDER BY 截止日期 ASC
            `).bind(groupId).all();
            return new Response(JSON.stringify({ tasks: results }));
        }

        // ===========================
        // C. 管理員系統 (權限表 group_auth)
        // ===========================
        
        // 1. 檢查狀態 (14)
        if (json.action === "admin_check_status") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json, 群組名稱 as group_name FROM group_auth WHERE group_id = ?").bind(groupId).first();
            
            if (!auth) {
                return new Response(JSON.stringify({ status: "need_setup" })); 
            }
            
            const rolesMap = JSON.parse(auth.roles_json);
            const roleNames = Object.keys(rolesMap);
            // New: 回傳群組名稱
            return new Response(JSON.stringify({ status: "login", roles: roleNames, groupName: auth.group_name }));
        }

        // 2. 初始化 (14)
        if (json.action === "admin_setup") {
            if (!json.groupName) return new Response(JSON.stringify({ status: "fail", msg: "需要群組名稱" })); // 14. 必須輸入名稱
            const hash = await sha256(json.password);
            const recoveryCode = genRecoveryCode();
            // New: 預設權限
            const initialRoles = { 
                "總管理員": { 
                    hash: hash, 
                    rec: recoveryCode, 
                    subjects: [],
                    perm: ["manage_roles", "manage_settings", "manage_tasks", "access_frontend_control", "self_change_pwd"] 
                } 
            };
            const defaultSubjects = JSON.stringify(['國語', '英文', '數學', '地理', '歷史', '公民', '理化', '生物', '地科', '資訊', '體育', '美術', '其他']);
            
            // 寫入中文欄位 (新增 群組名稱 和 前端存取權)
            await env.DB.prepare("INSERT INTO group_auth (group_id, 群組名稱, 角色設定, 科目設定, 前端存取權) VALUES (?, ?, ?, ?, ?)").bind(
                groupId, 
                json.groupName, // 14. 存入群組名稱
                JSON.stringify(initialRoles), 
                defaultSubjects, 
                'enabled' // 預設啟用
            ).run();
            
            return new Response(JSON.stringify({ status: "success", role: "總管理員", recoveryCode, groupName: json.groupName }));
        }

        // 3. 登入
        if (json.action === "admin_login") {
            // New: Select group_name and access_control status
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
                    // 11. 確保回傳救援碼
                    recoveryCode: targetRole.rec || '未生成 (請重置密碼)', 
                    allRoles: roles,
                    groupName: auth.group_name,
                    permissions: targetRole.perm || [],
                    accessControlStatus: auth.access_control
                }));
            }
            return new Response(JSON.stringify({ status: "fail" }));
        }

        // 4. 重置密碼
        if (json.action === "admin_reset_pwd") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            
            let roles = JSON.parse(auth.roles_json);
            const targetRole = roles[json.roleName];
            
            if (!targetRole || targetRole.rec !== json.recoveryCode) {
                return new Response(JSON.stringify({ status: "fail" }));
            }
            
            targetRole.hash = await sha256(json.newPassword);
            targetRole.rec = genRecoveryCode();
            roles[json.roleName] = targetRole;
            
            await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
            return new Response(JSON.stringify({ status: "success", newRecoveryCode: targetRole.rec }));
        }

        // New: 8. 自行更改密碼
        if (json.action === "admin_change_pwd") {
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

        // 5. 更新設定 (7, 12, 13)
        if (json.action === "update_settings") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json, 前端存取權 as access_control FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));

            let roles = JSON.parse(auth.roles_json);

            // Master password check (Using Total Admin hash for all settings)
            if (!roles["總管理員"] || roles["總管理員"].hash !== await sha256(json.password)) {
                return new Response(JSON.stringify({ status: "fail", msg: "總管理員權限不足" }));
            }

            if (json.subjects) { // 更新科目
                await env.DB.prepare("UPDATE group_auth SET 科目設定 = ? WHERE group_id = ?").bind(JSON.stringify(json.subjects), groupId).run();
            }

            // New: 12. 開關前端存取權
            if (json.accessControlStatus) {
                await env.DB.prepare("UPDATE group_auth SET 前端存取權 = ? WHERE group_id = ?").bind(json.accessControlStatus, groupId).run();
            }

            // New: 7. 新增/修改小老師 (含權限下放)
            if (json.newRoleName && json.newRolePwd) {
                let defaultPerms = ["manage_tasks", "self_change_pwd"]; 
                let subjects = json.roleSubjects || []; // 7. 儲存可使用的科目
                
                // 3. 權限分級: 導師 > 科目老師 > 正小老師 > 副小老師
                if (json.newRoleName.includes("導師")) {
                    defaultPerms.push("manage_roles", "manage_settings", "access_frontend_control", "manage_tasks_full");
                } else if (json.newRoleName.includes("老師")) {
                    defaultPerms.push("manage_tasks_full"); 
                } else if (json.newRoleName.includes("正")) {
                    defaultPerms.push("manage_tasks_full"); 
                }
                
                roles[json.newRoleName] = { 
                    hash: await sha256(json.newRolePwd), 
                    rec: genRecoveryCode(),
                    subjects: subjects, 
                    perm: defaultPerms 
                };
                await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
                return new Response(JSON.stringify({ 
                    status: "success", 
                    recoveryCode: roles[json.newRoleName].rec,
                    roleName: json.newRoleName
                }));
            }
            
            if (json.deleteRoleName) { // 刪除角色
                delete roles[json.deleteRoleName];
                await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
            }

            // New: 13. 權限下放/更新
            if (json.roleToUpdate && json.newPermissions) {
                if(roles[json.roleToUpdate]) {
                     roles[json.roleToUpdate].perm = json.newPermissions;
                     await env.DB.prepare("UPDATE group_auth SET 角色設定 = ? WHERE group_id = ?").bind(JSON.stringify(roles), groupId).run();
                     return new Response(JSON.stringify({ status: "success", msg: "權限已更新" }));
                }
            }

            return new Response(JSON.stringify({ status: "success" }));
        }

        // 6. 刪除作業 (更新權限檢查)
        if (json.action === "manage_task") {
            const auth = await env.DB.prepare("SELECT 角色設定 as roles_json FROM group_auth WHERE group_id = ?").bind(groupId).first();
            if (!auth) return new Response(JSON.stringify({ status: "fail" }));
            const roles = JSON.parse(auth.roles_json);
            
            const actor = roles[json.roleName];
            if (!actor || actor.hash !== await sha256(json.password)) return new Response(JSON.stringify({ status: "fail", msg: "密碼錯誤" }));

            let canDo = false;
            const actorPerms = actor.perm || [];
            
            // 檢查是否具有全權限 (總管/導師/老師/正小老師)
            if (actorPerms.includes("manage_tasks_full") || actorPerms.includes("manage_roles")) { 
                canDo = true;
            } else {
                const task = await env.DB.prepare("SELECT 科目 as subject FROM tasks WHERE id = ?").bind(json.taskId).first();
                if (task) {
                    // 檢查是否為副班長或角色名稱包含科目
                    const actorSubjects = actor.subjects || []; 
                    if (actorSubjects.includes(task.subject)) canDo = true;
                    else if (json.roleName.includes("副班長")) canDo = true; 
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
        
        // ===========================
        // 15. Super Admin API
        // ===========================
        if (json.action === "super_admin_login") {
            const superPwd = env[SUPER_ADMIN_PASSWORD_ENV_KEY];
            if (!superPwd || superPwd === "SET_ME_IN_ENV") {
                return new Response(JSON.stringify({ status: "fail", msg: "超級密碼未設定" }));
            }
            if (json.password === superPwd) {
                return new Response(JSON.stringify({ status: "success" }));
            }
            return new Response(JSON.stringify({ status: "fail", msg: "密碼錯誤" }));
        }

        if (json.action === "super_admin_get_groups") {
            if (json.password !== env[SUPER_ADMIN_PASSWORD_ENV_KEY]) return new Response(JSON.stringify({ status: "fail" }));
            
            const { results } = await env.DB.prepare("SELECT group_id, 群組名稱, 角色設定 FROM group_auth").all();
            const groups = results.map(g => {
                let roles = {};
                try { roles = JSON.parse(g.角色設定); } catch (e) {}
                return {
                    group_id: g.group_id,
                    group_name: g.群組名稱 || '未命名',
                    roles_json: JSON.stringify(roles)
                };
            });
            return new Response(JSON.stringify({ status: "success", groups }));
        }

        if (json.action === "super_admin_delete_group") {
            if (json.password !== env[SUPER_ADMIN_PASSWORD_ENV_KEY]) return new Response(JSON.stringify({ status: "fail" }));
            
            // Delete from all tables
            await env.DB.prepare("DELETE FROM group_auth WHERE group_id = ?").bind(json.targetGroupId).run();
            await env.DB.prepare("DELETE FROM tasks WHERE 群組 = ?").bind(json.targetGroupId).run();
            await env.DB.prepare("DELETE FROM line_user_state WHERE group_id = ?").bind(json.targetGroupId).run();
            return new Response(JSON.stringify({ status: "success" }));
        }

        return new Response("Unknown", { status: 400 });
    } catch (err) {
        // console.error(err);
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
}

// ====================================================================
// ★ 輔助函式
// ====================================================================

// New: 17. LINE Webhook 處理
async function handleLineWebhook(events, env, ctx) {
    for (const event of events) {
        const gId = event.source.groupId || event.source.roomId || event.source.userId;
        const uId = event.source.userId;

        // 19. 刪除資料指令
        if (event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === '/bot end') {
             ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `⚠️ 確定要刪除 ${gId} 的所有資料嗎？\n請在 30 秒內輸入：確認刪除 ${gId}`));
             await env.DB.prepare("UPDATE line_user_state SET state = 'awaiting_delete_confirm' WHERE user_id = ?").bind(uId).run();
             continue;
        }
        
        // 處理刪除確認
        const stateEntry = await env.DB.prepare("SELECT * FROM line_user_state WHERE user_id = ?").bind(uId).first();
        if (stateEntry && stateEntry.state === 'awaiting_delete_confirm' && event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === `確認刪除 ${gId}`) {
             await env.DB.prepare("DELETE FROM group_auth WHERE group_id = ?").bind(gId).run();
             await env.DB.prepare("DELETE FROM tasks WHERE 群組 = ?").bind(gId).run();
             await env.DB.prepare("DELETE FROM line_user_state WHERE user_id = ? OR group_id = ?").bind(uId, gId).run();
             ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, "✅ 資料已刪除，感謝您的使用。機器人將退出群組。"));
             // Note: Worker cannot force bot to leave, but the user can remove it manually.
             continue;
        }

        // 17. Bot Start/Join 流程
        if (event.type === 'join' || event.type === 'follow' || (event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === '/bot start')) {
            const statement = getStatement(gId, env);
            await env.DB.prepare("INSERT OR REPLACE INTO line_user_state (user_id, state, group_id) VALUES (?1, 'awaiting_agree', ?2)").bind(uId, gId).run();
            ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, statement));
            continue;
        }

        // 17. Bot Agree/Disagree 流程
        if (event.type === 'message' && event.message.type === 'text') {
            const msg = event.message.text.trim();
            const stateEntry = await env.DB.prepare("SELECT * FROM line_user_state WHERE user_id = ?").bind(uId).first();

            if (stateEntry && stateEntry.state === 'awaiting_agree') {
                if (msg === '/bot agree') {
                    await env.DB.prepare("UPDATE line_user_state SET state = 'awaiting_old_id' WHERE user_id = ?").bind(uId).run();
                    ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, '太棒了！您曾經使用過本系統嗎？\n\n如果**是**，請輸入舊 ID。\n如果**否**，請輸入「/bot new」以生成新 ID。'));
                } else if (msg === '/bot disagree') {
                    await env.DB.prepare("DELETE FROM line_user_state WHERE user_id = ?").bind(uId).run();
                    ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, '感謝您的參與，很遺憾您決定不同意聲明。'));
                    // Worker cannot force bot to leave, but the user can remove it manually.
                }
                continue;
            } else if (stateEntry && stateEntry.state === 'awaiting_old_id') {
                let finalId = gId;
                if (msg === '/bot new') {
                    finalId = gId;
                } else {
                    // Check if the provided ID exists (simplified check)
                    const oldGroup = await env.DB.prepare("SELECT group_id FROM group_auth WHERE group_id = ?").bind(msg).first();
                    if (oldGroup) {
                        finalId = msg;
                    } else {
                         ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, '❌ 舊 ID 錯誤或不存在，請重新輸入，或輸入「/bot new」生成新 ID。'));
                         continue;
                    }
                }
                
                // Finalize setup
                await env.DB.prepare("UPDATE line_user_state SET state = 'setup_complete', group_id = ? WHERE user_id = ?").bind(finalId, uId).run();
                const welcomeMsg = getWelcomeMessage(finalId, env);
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, welcomeMsg));
                continue;
            }
        }
        
        // 18. Help 指令
        if (event.type === 'message' && event.message.type === 'text' && event.message.text.trim() === '/bot help') {
            const helpMsg = "📜 指令列表：\n\n/bot start：開始使用流程 (同意聲明)\n/bot ID：顯示本群組 ID\n作業網址/公佈欄：顯示學生/管理員網址\n/bot 學生班級作業：顯示學生網址\n/bot 後台管理：顯示管理網址\n/bot end：確認並刪除所有資料";
            ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, helpMsg));
            continue;
        }

        // 檢查是否已完成設定，才允許使用其他功能
        const stateCheck = await env.DB.prepare("SELECT group_id FROM line_user_state WHERE user_id = ? AND state = 'setup_complete'").bind(uId).first();
        const effectiveGId = stateCheck ? stateCheck.group_id : gId;

        // 既存指令
        if (event.type === 'message' && event.message.type === 'text') {
            const msg = event.message.text.trim();
            if (msg === "/bot ID") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `Group ID:\n${effectiveGId}`)); continue; }
            if (msg === "作業網址" || msg === "公佈欄") {
                const reply = getWelcomeMessage(effectiveGId, env);
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, reply));
                continue;
            }
            if (msg === "/bot 學生班級作業") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `📊 學生班級作業：\n${DOMAIN_STUDENT}/?id=${effectiveGId}`)); continue; }
            if (msg === "/bot 後台管理") { ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `🔧 後台管理：\n${DOMAIN_MANAGER}/?id=${effectiveGId}`)); continue; }

            const t = parseTask(msg);
            if (t) {
                await env.DB.prepare(`
                    INSERT INTO tasks (群組, 建立時間, 截止日期, 科目, 內容, 來源, 狀態, 類別) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `).bind(effectiveGId, Date.now(), t.dStr, t.s, t.c, "LINE", "已發佈", t.cat).run();
                // 通知使用者作業已新增 (因為 Line 傳入的作業預設為 '已發佈')
                ctx.waitUntil(replyLineMessage(env.LINE_CHANNEL_ACCESS_TOKEN, event.replyToken, `✅ 已新增作業：\n日期: ${t.dStr}\n科目: ${t.s}\n內容: ${t.c}\n類別: ${t.cat}`));
            }
        }
    }
    return new Response("ok");
}

function getStatement(gId, env) {
    // 5. 聲明內容
    return `📋 服務使用聲明 📋
1. 同意本系統的版權和資料擁有權歸 Ray 擁有。
2. 您的密碼會經過 SHA256 加密處理，我方無法得知您的原始密碼。
3. 如果您只是為了日常作業公佈使用，建議使用 Google Classroom 或其他更成熟的產品（本系統為業餘作品）。
4. 本機器人需同意聲明後才能使用。

同意請打 /bot agree
不同意請打 /bot disagree
`;
}

function getWelcomeMessage(gId, env) {
    // 5, 20. 新版歡迎/資訊訊息
    const contactInfo = `
若需要回報問題可使用以下方式 
LINE:https://lin.ee/VJ8IC4D 
LINE 因為某些原因僅開放提問但不回復，若需提問+回復請到 Discord 感謝配合🙏 
Discord:https://discord.gg/jjQk25Ca9A 
mail:ray2026worker@ray2026.dpdns.org
`;
    return `大家好！我是作業機器人 🤖
ID: ${gId}

📊 學生班級作業：
${DOMAIN_STUDENT}/?id=${gId}

🔧 後台管理：
${DOMAIN_MANAGER}/?id=${gId}

(請老師/班長盡快進入後台設定密碼)
${contactInfo}
`;
}

function genRecoveryCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }
async function sha256(message) { const msgBuffer = new TextEncoder().encode(message); const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer); return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function replyLineMessage(token, replyToken, text) { if (!token) return; await fetch('https://api.line.me/v2/bot/message/reply', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ replyToken: replyToken, messages: [{ type: 'text', text: text }] }) }); }
async function pushLineMessage(token, userId, text) { if (!token || !userId) return; await fetch('https://api.line.me/v2/bot/message/push', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ to: userId, messages: [{ type: 'text', text: text }] }) }); }
function addDays(d, days) { const r = new Date(d); r.setDate(r.getDate() + days); return r; }

// 解析引擎 (6, 16)
function parseTask(text) {
    let targetDate = null; let content = text; const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset time for consistent date math
    
    // 16. 下禮拜 (Next same day of the week)
    if (text.includes("下禮拜")) {
        targetDate = addDays(today, 7); 
        content = content.replace("下禮拜", "");
    }

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
        // 115.12.12 國語作業 語文演練 (確保能抓到日期)
        let matchDateStr = null;
        // 匹配 7-digit ROC date (1151212) or YYYY/MM/DD, YYYY-MM-DD, YY/MM/DD
        const strictMatch = text.match(/(^|[^0-9])(\d{6,7})(?![0-9])/);
        if (strictMatch) { matchDateStr = strictMatch[2]; } else { const symMatch = text.match(/(\d{2,4})[./-](\d{1,2})[./-](\d{1,2})/); if (symMatch) matchDateStr = symMatch[0]; }
        
        if (matchDateStr) {
            let y, m, d;
            let dateParsed = false;
            
            if (matchDateStr.match(/^\d{6,7}$/)) { // 處理連續數字日期
                let num = matchDateStr;
                if (num.length === 7) { y = parseInt(num.substring(0,3)); m = parseInt(num.substring(3,5)); d = parseInt(num.substring(5,7)); }
                else { y = parseInt(num.substring(0,2)); m = parseInt(num.substring(2,4)); d = parseInt(num.substring(4,6)); }
                dateParsed = true;
            } else { // 處理符號分隔日期
                let symMatch = matchDateStr.match(/(\d{2,4})[./-](\d{1,2})[./-](\d{1,2})/);
                if(symMatch) { y = parseInt(symMatch[1]); m = parseInt(symMatch[2]); d = parseInt(symMatch[3]); dateParsed = true; }
            }

            if (dateParsed) {
                if (y < 1000) y += 1911; // 民國年轉西元年
                if (y < 2000) y += 2000; // 兩位數年份轉西元年 (可能需要調整邏輯，這裡簡化)
                
                targetDate = new Date(y, m - 1, d);
                // 如果解析出的日期在今天之前，且年份是今年，則自動推到明年 (僅適用於西元年份是今年時)
                if (targetDate < today && targetDate.getFullYear() === today.getFullYear()) {
                     targetDate.setFullYear(targetDate.getFullYear() + 1);
                }
                
                // 確保日期有效
                if (isNaN(targetDate.getTime())) return null; 

                content = content.replace(matchDateStr, "");
            }
        }
    }
    
    if (targetDate) { 
        content = content.replace(/要交|要考|截止|作業|要帶|記得|繳交|考試|攜帶/g, "").trim(); 
        // 6. 國語作業 語文演練 依然沒辦法自動檢查: 確保 '語文演練' 留下
        
        let cat = "作業"; 
        if (text.includes("考")) cat = "考試"; 
        else if (text.includes("帶")) cat = "攜帶"; 
        
        let sub = "其他"; 
        const subs = {"國語":["國文","國語","作文"],"英文":["英文","English"],"數學":["數學","Math"],"地理":["地理"],"歷史":["歷史"],"公民":["公民"],"理化":["理化","物理","化學"],"生物":["生物"],"地科":["地科"],"資訊":["資訊","電腦"],"體育":["體育"],"美術":["美術"]}; 
        for (let key in subs) { if (subs[key].some(k => text.includes(k))) { sub = key; break; } } 
        
        const dStr = `${targetDate.getFullYear()}-${String(targetDate.getMonth()+1).padStart(2,'0')}-${String(targetDate.getDate()).padStart(2,'0')}`; 
        
        // 4. 115.12.12 國語作業 語文演練一樣不會放入公布作業區 (D1資料庫也沒有): 
        // 這裡確保解析後有內容才算成功。如果內容在日期解析後被清空，則失敗。
        if (content.length < 2 && !content.match(/[A-Za-z0-9\u4e00-\u9fa5]/)) return null; 
        
        return { dStr, s: sub, c: content, cat }; 
    }
    return null;
}


// ====================================================================
// ★ 前端 HTML 頁面
// ====================================================================

// 學生端 HTML (1)
function renderStudentHTML() {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>作業公佈欄</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"><style>.filter-scroll::-webkit-scrollbar { width: 0; background: transparent;} .modal { background-color: rgba(0,0,0,0.5); } body { background-color: #f3f4f6; } .cat-exam { background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; } .cat-bring { background-color: #fef9c3; color: #854d0e; border: 1px solid #fde047; } .cat-homework { background-color: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }
.multiselect { position: relative; }
.multiselect-dropdown { position: absolute; z-index: 10; background: white; border: 1px solid #d1d5db; border-radius: 0.5rem; width: 100%; max-height: 200px; overflow-y: auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
</style></head><body class="text-gray-800 font-sans min-h-screen pb-24"><div class="bg-white shadow-sm p-4 sticky top-0 z-10"><h1 class="text-xl font-bold text-gray-700 text-center">🏫 班級作業</h1></div><div class="max-w-2xl mx-auto p-4">
<div class="bg-white rounded-xl shadow-sm p-3 mb-4 space-y-3">
    <div>
        <label class="text-xs font-bold text-gray-500">篩選科目 (多選)</label>
        <div class="multiselect">
            <input type="text" id="subject-filter-input" readonly onclick="toggleDropdown('subject-dropdown')" class="w-full border rounded p-2 bg-white cursor-pointer" value="全部科目">
            <div id="subject-dropdown" class="multiselect-dropdown hidden"></div>
        </div>
    </div>
    <div class="flex gap-4">
        <div class="w-1/2">
            <label class="text-xs font-bold text-gray-500">日期範圍 (單選)</label>
            <select id="date-range-filter" onchange="applyDateRangeFilter(this.value)" class="w-full border rounded p-2 bg-white">
                <option value="all">全部日期</option>
                <option value="7">7 天內</option>
                <option value="14">14 天內</option>
                <option value="30">1 個月內</option>
                <option value="365">1 年內</option>
            </select>
        </div>
        <div class="w-1/2">
            <label class="text-xs font-bold text-gray-500">指定月份 (多選)</label>
            <div class="multiselect">
                <input type="text" id="month-filter-input" readonly onclick="toggleDropdown('month-dropdown')" class="w-full border rounded p-2 bg-white cursor-pointer" value="全部月份">
                <div id="month-dropdown" class="multiselect-dropdown hidden"></div>
            </div>
        </div>
    </div>
</div>

<div id="loading" class="text-center text-gray-500 mt-10"><i class="fas fa-spinner fa-spin mr-2"></i>載入中...</div><div id="task-list" class="space-y-3"></div></div><button onclick="openModal()" class="fixed bottom-6 right-6 bg-blue-600 text-white w-14 h-14 rounded-full shadow-lg flex items-center justify-center text-2xl hover:bg-blue-700 transition z-20 active:scale-90"><i class="fas fa-plus"></i></button><div id="modal" class="modal fixed inset-0 hidden items-center justify-center z-50 px-4"><div class="bg-white rounded-xl shadow-2xl w-full max-w-sm overflow-hidden"><div class="p-4 bg-gray-50 border-b flex justify-between items-center"><h3 class="font-bold text-gray-700">✏️ 新增事項</h3><button onclick="closeModal()" class="text-gray-400 hover:text-gray-600"><i class="fas fa-times"></i></button></div><div class="p-4 space-y-3"><div class="flex gap-2"><div class="w-2/3"><label class="text-xs font-bold text-gray-500">日期</label><input type="date" id="input-date" class="w-full border rounded p-2"></div><div class="w-1/3"><label class="text-xs font-bold text-gray-500">類型</label><select id="input-category" class="w-full border rounded p-2 bg-white"><option value="作業">作業</option><option value="考試">考試</option><option value="攜帶">帶</option></select></div></div><div><label class="text-xs font-bold text-gray-500">科目</label><select id="input-subject" class="w-full border rounded p-2 bg-white"></select></div><div><label class="text-xs font-bold text-gray-500">內容</label><input type="text" id="input-content" class="w-full border rounded p-2" placeholder="內容..."></div></div><div class="p-4 border-t bg-gray-50"><button onclick="submitTask()" id="btn-submit" class="w-full bg-blue-600 text-white py-2 rounded-lg font-bold">送出</button></div></div></div><script>
let allTasks = [], 
    allSubjects = [], 
    allMonths = [1,2,3,4,5,6,7,8,9,10,11,12],
    selectedSubjects = [], 
    selectedMonths = [],
    selectedRange = 'all';

const urlParams = new URLSearchParams(window.location.search);
const groupId = urlParams.get('id');

window.onload = function(){
    if(!groupId){
        document.body.innerHTML='<div class="p-10 text-center text-red-500">請使用專屬連結進入</div>';
        return;
    }
    const tmr=new Date();
    tmr.setDate(tmr.getDate()+1);
    document.getElementById('input-date').valueAsDate=tmr;
    fetchData();
};

function fetchData(){
    fetch(window.location.href,{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'get_tasks',groupId})
    }).then(r=>{
        if (r.status === 500) {
            console.error("Server responded with 500 error. Check D1 migration status.");
            document.getElementById('loading').innerHTML = '<div class="text-red-500">❌ 載入失敗 (伺服器錯誤 500)，請聯繫管理員。</div>';
            return { tasks: [], customSubjects: null, activeMonths: []};
        }
        return r.json();
    }).then(d=>{
        if (d.error === "前端存取權已關閉") {
             document.body.innerHTML='<div class="p-10 text-center text-red-500">❌ 存取權已由管理員關閉</div>';
             return;
        }
        allTasks = d.tasks || [];
        allSubjects = ['全部', '國語', '英文', '數學', '地理', '歷史', '公民', '理化', '生物', '地科', '資訊', '體育', '美術', '其他'];
        if(d.customSubjects && d.customSubjects.length > 0){
             allSubjects = ['全部', ...d.customSubjects.filter(s => s)];
        }
        
        // Populate month filter dropdown with months that actually have tasks
        const activeMonths = d.activeMonths || [];
        allMonths = activeMonths.length > 0 ? activeMonths : [1,2,3,4,5,6,7,8,9,10,11,12];

        renderFilters();
        document.getElementById('loading').style.display='none';
        renderList();
    });
}

function renderFilters(){
    // Subject Dropdown
    const subDrop = document.getElementById('subject-dropdown');
    subDrop.innerHTML = allSubjects.map(s => \`
        <label class="flex items-center p-2 hover:bg-gray-100 cursor-pointer text-sm">
            <input type="checkbox" value="\${s}" onchange="updateSelectedSubjects()" \${s === '全部' ? 'id="sub-all-check"' : ''} class="mr-2"> \${s}
        </label>
    \`).join('');
    
    // Month Dropdown
    const monthDrop = document.getElementById('month-dropdown');
    monthDrop.innerHTML = allMonths.map(m => \`
        <label class="flex items-center p-2 hover:bg-gray-100 cursor-pointer text-sm">
            <input type="checkbox" value="\${m}" onchange="updateSelectedMonths()" class="mr-2"> \${m} 月
        </label>
    \`).join('');

    // Modal Subject Select
    const sel=document.getElementById('input-subject');
    sel.innerHTML=allSubjects.filter(s=>s!=='全部').map(s=>\`<option>\${s}</option>\`).join('');
}

function toggleDropdown(id) {
    document.getElementById(id).classList.toggle('hidden');
}

function updateSelectedSubjects() {
    const checkboxes = document.querySelectorAll('#subject-dropdown input[type="checkbox"]');
    selectedSubjects = Array.from(checkboxes)
        .filter(cb => cb.checked && cb.value !== '全部')
        .map(cb => cb.value);
    
    // Logic for '全部' checkbox
    const allCheckbox = document.getElementById('sub-all-check');
    if (allCheckbox.checked) {
        selectedSubjects = allSubjects.filter(s => s !== '全部');
        checkboxes.forEach(cb => { if(cb.value !== '全部') cb.checked = false; });
    }
    
    // Update input display
    document.getElementById('subject-filter-input').value = (selectedSubjects.length === 0 || selectedSubjects.length === allSubjects.length - 1) 
        ? '全部科目' 
        : \`已選 (\${selectedSubjects.length})\`;
        
    renderList();
}

function updateSelectedMonths() {
    const checkboxes = document.querySelectorAll('#month-dropdown input[type="checkbox"]');
    selectedMonths = Array.from(checkboxes).filter(cb => cb.checked).map(cb => parseInt(cb.value));

    // Disable range filter if month is selected
    const rangeSelect = document.getElementById('date-range-filter');
    if (selectedMonths.length > 0) {
        if (rangeSelect.value !== 'all') { rangeSelect.value = 'all'; selectedRange = 'all'; }
        rangeSelect.disabled = true;
        document.getElementById('month-filter-input').value = \`已選 (\${selectedMonths.length})\`;
    } else {
        rangeSelect.disabled = false;
        document.getElementById('month-filter-input').value = '全部月份';
    }
    
    renderList();
}

function applyDateRangeFilter(range) {
    const monthCheckboxes = document.querySelectorAll('#month-dropdown input[type="checkbox"]');
    
    if (range !== 'all') {
        // Disable month filter if range is selected
        monthCheckboxes.forEach(cb => { cb.checked = false; cb.disabled = true; });
        selectedMonths = [];
        document.getElementById('month-filter-input').value = '全部月份';
        document.getElementById('month-filter-input').onclick = null;
    } else {
        // Enable month filter
        monthCheckboxes.forEach(cb => { cb.disabled = false; });
        document.getElementById('month-filter-input').onclick = () => toggleDropdown('month-dropdown');
    }
    selectedRange = range;
    renderList();
}


function renderList(){
    const list=document.getElementById('task-list');
    
    const f=allTasks.filter(t=>{
        // Subject Filter
        const subjectMatch = selectedSubjects.length === 0 || selectedSubjects.includes(t.subject);
        if (!subjectMatch) return false;

        // Date Filter
        const taskDate = new Date(t.date);
        const today = new Date();
        today.setHours(0, 0, 0, 0); 

        // Month Filter (if selected, range is ignored)
        if (selectedMonths.length > 0) {
            const taskMonth = taskDate.getMonth() + 1;
            return selectedMonths.includes(taskMonth);
        }
        
        // Range Filter
        if (selectedRange === 'all') return true;
        
        const diff = Math.ceil((taskDate - today) / 86400000);
        const maxDays = parseInt(selectedRange);
        
        return diff >= 0 && diff <= maxDays;
    });
    
    if(f.length===0){
        list.innerHTML='<div class="text-center text-gray-400 py-10">無事項</div>';
        return;
    }
    
    list.innerHTML=f.map(t=>{
        const td=new Date(t.date),n=new Date();n.setHours(0,0,0,0);const diff=Math.ceil((td-n)/86400000);let st=diff+" 天後",bd="border-blue-400";if(diff<0){st="已過期";bd="border-gray-300";}else if(diff===0){st="今天";bd="border-red-500";}const w=["日","一","二","三","四","五","六"][td.getDay()];let cc="cat-homework",ci="fa-book";if(t.category==="考試"){cc="cat-exam";ci="fa-pen-to-square";}else if(t.category==="攜帶"){cc="cat-bring";ci="fa-briefcase";}return \`<div class="bg-white p-4 rounded-lg shadow-sm border-l-4 \${bd} mb-3"><div class="flex items-center gap-2 mb-1"><span class="text-xs font-bold px-2 py-0.5 rounded flex items-center gap-1 \${cc}"><i class="fas \${ci}"></i> \${t.category}</span><span class="text-xs font-bold text-gray-600 bg-gray-100 px-2 py-0.5 rounded">\${t.subject}</span><span class="text-xs text-gray-400">\${t.date}(\${w})</span></div><div class="text-lg font-medium">\${t.content}</div><div class="text-right text-xs text-gray-400">\${st}</div></div>\`;}).join('');
}

function submitTask(){const date=document.getElementById('input-date').value,subject=document.getElementById('input-subject').value,content=document.getElementById('input-content').value,category=document.getElementById('input-category').value;if(!date||!content)return alert("請填寫完整");const btn=document.getElementById('btn-submit');btn.disabled=true;btn.innerText="...";fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'add_task',date,subject,content,category,groupId,isAdmin:false})}).then(r=>r.json()).then(d=>{closeModal();btn.disabled=false;btn.innerText="送出";alert("✅ 已送出！\\n等待審核後顯示");});}
function openModal(){document.getElementById('modal').classList.remove('hidden');document.getElementById('modal').classList.add('flex');}
function closeModal(){document.getElementById('modal').classList.add('hidden');document.getElementById('modal').classList.remove('flex');}
</script></body></html>`;
}

// 管理端 HTML (10, 14, 11, 7, 9, 8, 12, 13)
function renderManagerHTML(env) {
    // 14. D1 資料庫新增群組名稱欄位，因此初始化流程需要改變
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
    const name = document.getElementById('setup-name').value; // 14. 取得群組名稱
    const pwd = document.getElementById('setup-pwd').value;
    if(!name || !pwd) return alert("請填寫完整資訊");
    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_setup',groupId:gId,password:pwd,groupName:name})})
    .then(r=>r.json()).then(d=>{ 
        if (d.status === 'success') {
            // 11. 初始化時顯示救援碼
            alert("✅ 設定成功！您的群組名稱是: "+d.groupName+"\\n請務必截圖保存總管理員救援碼： " + d.recoveryCode);
            // 由於設置成功，將 ID 和密碼存入 localStorage，自動登入
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
            localStorage.setItem('hw_pwd', pwd); // 儲存明碼供後續操作使用

            currentSubjects = d.subjects;
            currentRolesMap = d.allRoles;
            currentAccessStatus = d.accessControlStatus; // 12. 獲取存取權狀態

            document.getElementById('dash-group-name').innerText = d.groupName || '未命名群組';
            document.getElementById('dash-role').innerText = "(身分: " + selectedRole + ")";
            // 11. 確保不會是 undefined
            document.getElementById('my-rec-code').innerText = d.recoveryCode || '未生成 (請重置密碼)';
            
            // 判斷是否顯示設定面板 (總管/導師具有 manage_roles 權限)
            const canManageRoles = d.permissions.includes('manage_roles') || selectedRole === '總管理員' || selectedRole.includes('導師');

            if(canManageRoles) {
                document.getElementById('settings-panel').classList.remove('hidden');
                document.getElementById('edit-subjects').value = currentSubjects.join(',');
                updateDelRoleSelect(d.allRoles);
                updatePermRoleSelect(d.allRoles);
                // 12. 設定存取權選單狀態
                document.getElementById('access-control-select').value = currentAccessStatus;
            } else {
                document.getElementById('settings-panel').classList.add('hidden');
            }
            
            loadTasks();
            showSection('step-dashboard');
        } else {
            if(!silent) alert("❌ 密碼錯誤");
            else { localStorage.clear(); showSection('step-role'); } // 自動登入失敗則清除
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

// 8. 更改自己的密碼
function changeOwnPassword() {
    const oldPwd = document.getElementById('old-pwd-change').value;
    const newPwd = document.getElementById('new-pwd-change').value;
    if(!oldPwd || !newPwd) return alert("請填寫新舊密碼");

    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'admin_change_pwd',groupId:gId,roleName:selectedRole,oldPassword:oldPwd,newPassword:newPwd})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status==='success') { 
            alert("密碼更新成功！請使用新密碼登入或儲存。"); 
            localStorage.setItem('hw_pwd', newPwd); // 更新 localStorage 裡的密碼
            document.getElementById('old-pwd-change').value = '';
            document.getElementById('new-pwd-change').value = '';
        } else {
            alert("❌ 密碼更新失敗：" + (d.msg || "舊密碼錯誤"));
        }
    });
}

// 7. 新增角色
function saveNewRole() {
    const name = document.getElementById('new-role-name').value;
    const pwd = document.getElementById('new-role-pwd').value;
    // 7. 支援多科目輸入
    const subjects = document.getElementById('new-role-subjects').value.split(',').map(s=>s.trim()).filter(s=>s);
    const masterPwd = localStorage.getItem('hw_pwd'); // 用於總管理員驗證

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
    // 總管理員不能被刪除
    sel.innerHTML = Object.keys(rolesMap).filter(r=>r!=='總管理員').map(r=>\`<option>\${r}</option>\`).join('');
}

// 12. 開關前端存取權
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

// 13. 權限調整相關
function updatePermRoleSelect(rolesMap) {
    const sel = document.getElementById('perm-role-select');
    sel.innerHTML = Object.keys(rolesMap).filter(r=>r!=='總管理員').map(r=>\`<option>\${r}</option>\`).join('');
    // 預設渲染第一個角色的權限
    if (sel.value) renderRolePermissions(sel.value);
}

function renderRolePermissions(roleName) {
    const role = currentRolesMap[roleName];
    const permDiv = document.getElementById('perm-checkboxes');
    const currentPerms = role.perm || [];
    
    permDiv.innerHTML = Object.entries(PERMISSIONS).map(([key, desc]) => {
        // 排除自行更改密碼 (這是所有角色預設且無法取消的)
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
    
    // 確保 self_change_pwd 永遠存在
    newPermissions.push('self_change_pwd');

    if(!confirm(\`確定更新 \${roleToUpdate} 的權限嗎？\`)) return;

    fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:masterPwd,roleToUpdate:roleToUpdate,newPermissions:newPermissions})})
    .then(r=>r.json()).then(d=>{ 
        if(d.status === 'success') { alert("✅ 權限已更新"); location.reload(); } 
        else { alert("❌ 更新失敗：" + d.msg); }
    });
}

function saveSubjects(){ const newSub=document.getElementById('edit-subjects').value.split(',').map(s=>s.trim()).filter(s=>s); fetch(window.location.href,{method:'POST',body:JSON.stringify({action:'update_settings',groupId:gId,password:localStorage.getItem('hw_pwd'),subjects:newSub})}).then(r=>r.json()).then(d=>{ alert("✅ 科目更新成功"); currentSubjects=newSub; }); }

// 舊版輔助函式 (保留)
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
            
            // 權限檢查邏輯更新
            let canControl = actorPerms.includes('manage_tasks_full') || actorPerms.includes('manage_roles') || actorSubjects.includes(t.subject) || selectedRole.includes('副班長'); 
            
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
        // 小老師鎖定科目為其設定的科目
        subSel.innerHTML = actorSubjects.map(s=>\`<option>\${s}</option>\`).join('');
        subSel.disabled = false; // 允許多個科目時可以選擇
    } else {
        // Fallback: Use role name inclusion (e.g. "國語小老師")
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
    // 檢查是否有儲存的超級密碼
    const savedPwd = sessionStorage.getItem('super_admin_pwd');
    if (savedPwd) {
        document.getElementById('super-admin-pwd').value = savedPwd;
        superLogin(true); // 靜默登入
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
    loading.classList.remove('hidden');

    fetch(window.location.href, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'super_admin_get_groups', password: superPassword})
    })
    .then(r => r.json())
    .then(d => {
        loading.classList.add('hidden');
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
            // 修正：確保 rec 屬性存在
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
