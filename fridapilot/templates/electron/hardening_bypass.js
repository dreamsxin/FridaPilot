// Electron 加固绕过脚本 - asar加密/代码混淆/Fuses篡改/DevTools限制/调试检测
// FridaPilot - Electron Hardening Bypass

console.log('[FridaPilot] Electron Hardening Bypass Loaded');

// ══════════════════════════════════════════
// 1. DevTools 限制绕过
// ══════════════════════════════════════════
// 绕过 webContents.on('devtools-opened') 关闭回调
try {
    const { BrowserWindow } = require('electron');
    BrowserWindow.getAllWindows().forEach(win => {
        // 移除 devtools-opened 事件监听
        win.webContents.removeAllListeners('devtools-opened');
        // 移除快捷键拦截
        win.webContents.removeAllListeners('before-input-event');
        win.webContents.openDevTools({ mode: 'detach' });
        send({ type: 'devtools_bypass', windowId: win.id, detail: 'DevTools restrictions removed' });
    });
} catch(e) {}

// ══════════════════════════════════════════
// 2. Electron Fuses 检测与报告
// ══════════════════════════════════════════
try {
    const fs = require('fs');
    const execPath = process.execPath;
    const binary = fs.readFileSync(execPath);
    const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
    const idx = binary.indexOf(sentinel);
    if (idx !== -1) {
        const fuseWire = binary.slice(idx + sentinel.length, idx + sentinel.length + 20);
        const fuseNames = [
            'RunAsNode', 'CookieEncryption', 'NodeOptions',
            'NodeCliInspect', 'EmbeddedAsarIntegrityValidation',
            'OnlyLoadAppFromAsar', 'LoadBrowserProcessSpecificV8Snapshot',
            'GrantFileProtocolExtraPrivileges'
        ];
        const fuseStates = {};
        fuseNames.forEach((name, i) => {
            fuseStates[name] = fuseWire[i] === 0x31 ? 'ENABLE' : fuseWire[i] === 0x30 ? 'DISABLE' : 'REMOVED';
        });
        send({ type: 'electron_fuses', offset: '0x' + idx.toString(16), fuses: fuseStates });

        // 报告安全风险
        if (fuseStates.RunAsNode === 'ENABLE') {
            send({ type: 'security_risk', detail: 'ELECTRON_RUN_AS_NODE enabled - can execute arbitrary Node.js' });
        }
        if (fuseStates.NodeOptions === 'ENABLE') {
            send({ type: 'security_risk', detail: 'NODE_OPTIONS enabled - can inject via --require' });
        }
        if (fuseStates.NodeCliInspect === 'ENABLE') {
            send({ type: 'security_risk', detail: 'Node CLI inspect enabled - can attach debugger' });
        }
    }
} catch(e) {}

// ══════════════════════════════════════════
// 3. asar 完整性检查绕过
// ══════════════════════════════════════════
try {
    const originalReadFileSync = require('fs').readFileSync;
    const crypto = require('crypto');
    // Hook crypto.createHash to detect integrity verification
    const origCreateHash = crypto.createHash;
    crypto.createHash = function(algorithm) {
        const hash = origCreateHash.call(this, algorithm);
        const origUpdate = hash.update;
        hash.update = function(data) {
            if (typeof data === 'string' && data.length > 10000) {
                send({ type: 'asar_integrity', detail: 'Hash computation on large data (possible asar verification)', algo: algorithm });
            }
            return origUpdate.apply(this, arguments);
        };
        return hash;
    };
} catch(e) {}

// ══════════════════════════════════════════
// 4. 代码混淆分析辅助
// ══════════════════════════════════════════
// Hook eval/Function 检测动态代码执行
try {
    const origEval = global.eval;
    global.eval = function(code) {
        send({
            type: 'dynamic_code',
            method: 'eval',
            preview: String(code).substring(0, 500),
            length: String(code).length
        });
        return origEval.apply(this, arguments);
    };

    const origFunction = global.Function;
    global.Function = function() {
        var args = Array.from(arguments);
        var body = args[args.length - 1];
        send({
            type: 'dynamic_code',
            method: 'new Function()',
            preview: String(body).substring(0, 500),
            argCount: args.length - 1
        });
        return origFunction.apply(this, arguments);
    };
} catch(e) {}

// ══════════════════════════════════════════
// 5. 调试检测绕过
// ══════════════════════════════════════════
// 绕过 devtools-detect / electron-debug-detect 等库
try {
    // 禁用 debugger 语句 (常见反调试)
    // Hook setInterval 检测高频定时器 (调试检测特征)
    const origSetInterval = global.setInterval;
    global.setInterval = function(fn, interval) {
        var fnStr = String(fn);
        // 检测调试检测模式: 高频定时器 + debugger 关键字
        if (interval < 1000 && (fnStr.includes('debugger') || fnStr.includes('devtools'))) {
            send({ type: 'antidebug_bypass', detail: 'Blocked debug-detection timer', interval: interval });
            return origSetInterval.call(this, function(){}, 999999); // 替换为空操作
        }
        return origSetInterval.apply(this, arguments);
    };

    // console.log 时间戳检测绕过
    const origConsoleLog = console.log;
    var consoleLogCount = 0;
} catch(e) {}

// ══════════════════════════════════════════
// 6. nodeIntegration / contextIsolation 检测
// ══════════════════════════════════════════
try {
    const { BrowserWindow } = require('electron');
    BrowserWindow.getAllWindows().forEach(win => {
        const prefs = win.webContents.getWebPreferences();
        send({
            type: 'security_config',
            windowId: win.id,
            url: win.webContents.getURL(),
            nodeIntegration: prefs.nodeIntegration,
            contextIsolation: prefs.contextIsolation,
            sandbox: prefs.sandbox,
            webSecurity: prefs.webSecurity,
            allowRunningInsecureContent: prefs.allowRunningInsecureContent,
        });

        if (prefs.nodeIntegration && !prefs.contextIsolation) {
            send({ type: 'security_risk', detail: 'nodeIntegration=true + contextIsolation=false = RCE risk' });
        }
    });
} catch(e) {}

// ══════════════════════════════════════════
// 7. 自动提取应用源码
// ══════════════════════════════════════════
try {
    const fs = require('fs');
    const path = require('path');
    const appPath = require('electron').app.getAppPath();

    function listFiles(dir, prefix, depth) {
        if (depth > 3) return [];
        var results = [];
        try {
            fs.readdirSync(dir).forEach(name => {
                var full = path.join(dir, name);
                var rel = prefix ? prefix + '/' + name : name;
                try {
                    var stat = fs.statSync(full);
                    if (stat.isDirectory()) {
                        results = results.concat(listFiles(full, rel, depth + 1));
                    } else {
                        results.push({ path: rel, size: stat.size });
                    }
                } catch(e) {}
            });
        } catch(e) {}
        return results;
    }

    var files = listFiles(appPath, '', 0);
    send({ type: 'app_source_map', appPath: appPath, fileCount: files.length, files: files.slice(0, 100) });

    // 读取 main entry point
    var pkgPath = path.join(appPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
        var pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        var mainFile = path.join(appPath, pkg.main || 'index.js');
        if (fs.existsSync(mainFile)) {
            var mainContent = fs.readFileSync(mainFile, 'utf-8');
            send({ type: 'app_main_entry', path: mainFile, preview: mainContent.substring(0, 2000), size: mainContent.length });
        }
    }
} catch(e) {}

console.log('[FridaPilot] Electron hardening bypass loaded');
