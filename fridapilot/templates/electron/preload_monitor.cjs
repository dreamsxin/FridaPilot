// FridaPilot · Electron preload 兜底通道（CommonJS，主进程最先执行）
// 用法：NODE_OPTIONS="--require <本文件>" 启动 Electron。
// 仅当目标 Fuses 允许 NodeOptions/RunAsNode 时生效——被忽略时本脚本
// 根本不会运行，因此 agent 必须等待下面的 health 行作为健康检查。
// 事件回传：process.stdout.write('__FPLINE__' + JSON.stringify(o) + '\n')
// （绕过应用对 console 的任何补丁）。
(() => {
    const hooks = [];
    // 限流：理由同 cdp_main_hooks.js——stdout 被刷满会拖慢被监控进程。
    const RATE_LIMIT = 200;
    let windowStart = 0;
    let windowCount = 0;
    let dropped = 0;
    const write = o => {
        try {
            process.stdout.write('__FPLINE__' + JSON.stringify(o) + '\n');
        } catch (e) {
            // 回传失败不能影响宿主逻辑
        }
    };
    const emit = o => {
        const now = Date.now();
        if (now - windowStart >= 1000) {
            if (dropped > 0) {
                write({type: 'emit_dropped', count: dropped});
                dropped = 0;
            }
            windowStart = now;
            windowCount = 0;
        }
        if (windowCount >= RATE_LIMIT) {
            dropped += 1;
            return;
        }
        windowCount += 1;
        write(o);
    };
    const mark = (name, ok) => {
        hooks.push(name + (ok ? '' : ':miss'));
        return ok;
    };
    const safe = args => {
        try {
            return JSON.stringify(args).substring(0, 2000);
        } catch (e) {
            return '[]';
        }
    };

    // NODE_OPTIONS 被渲染/utility/普通 node 子进程一并继承，那些进程里
    // require('electron') 不提供 ipcMain/BrowserWindow。不判空就会抛 TypeError，
    // 让目标进程的 --require 整体失败（= 启动不了应用）。
    let electron = null;
    try {
        electron = require('electron');
        mark('require:electron', true);
    } catch (e) {
        mark('require:electron', false);
    }
    const app = electron && electron.app;
    const ipcMain = electron && electron.ipcMain;
    const BrowserWindow = electron && electron.BrowserWindow;

    if (ipcMain) {
        ['handle', 'on'].forEach(kind => {
            const orig = ipcMain[kind];
            if (!orig) {
                return;
            }
            ipcMain[kind] = function (channel, handler) {
                emit({
                    type: kind === 'on' ? 'ipc_main_on' : 'ipc_main_handle',
                    channel: channel
                });
                return orig.call(this, channel, function (event) {
                    const args = Array.prototype.slice.call(arguments, 1);
                    emit({type: 'ipc_main_call', channel: channel, args: safe(args)});
                    return handler.apply(this, arguments);
                });
            };
        });
        mark('ipcMain', true);
    } else {
        mark('ipcMain', false);
    }

    if (BrowserWindow && BrowserWindow.prototype) {
        const ol = BrowserWindow.prototype.loadURL;
        BrowserWindow.prototype.loadURL = function (url) {
            emit({type: 'browser_window', action: 'loadURL', url: url});
            return ol.apply(this, arguments);
        };
        mark('BrowserWindow', true);
    } else {
        mark('BrowserWindow', false);
    }

    try {
        const fs = require('fs');
        ['readFileSync', 'writeFileSync', 'readFile', 'writeFile', 'unlinkSync'].forEach(fn => {
            if (!fs[fn]) {
                return;
            }
            const orig = fs[fn];
            fs[fn] = function () {
                emit({type: 'node_fs', fn: fn, path: String(arguments[0])});
                return orig.apply(this, arguments);
            };
        });
        mark('node:fs', true);
    } catch (e) {
        mark('node:fs', false);
    }

    try {
        const cp = require('child_process');
        ['exec', 'execSync', 'spawn', 'execFile'].forEach(fn => {
            if (!cp[fn]) {
                return;
            }
            const orig = cp[fn];
            cp[fn] = function () {
                emit({type: 'node_child_process', fn: fn, cmd: String(arguments[0])});
                return orig.apply(this, arguments);
            };
        });
        mark('node:child_process', true);
    } catch (e) {
        mark('node:child_process', false);
    }

    if (app && app.whenReady) {
        app.whenReady().then(() => {
            try {
                const path = require('path');
                const fs = require('fs');
                const appPath = app.getAppPath();
                emit({type: 'electron_app_path', path: appPath});
                const pkgPath = path.join(appPath, 'package.json');
                if (fs.existsSync(pkgPath)) {
                    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
                    emit({
                        type: 'electron_package',
                        name: pkg.name,
                        version: pkg.version,
                        main: pkg.main,
                        dependencies: Object.keys(pkg.dependencies || {})
                    });
                }
                mark('asar', true);
            } catch (e) {
                mark('asar', false);
            }
            emit({type: 'health', stage: 'ready', hooks: hooks});
        });
    }
    // 两条都用 type: 'health'：agent 只认这个 type，而慢启动的应用可能在 agent
    // 的等待窗口内还没 whenReady，届时只有这条同步消息能证明 preload 真的跑了。
    emit({type: 'health', stage: 'early', hooks: hooks});
})();
