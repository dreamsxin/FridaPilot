// Electron IPC Hook - Monitor IPC communication between main and renderer processes
// Hooks ipcRenderer.invoke, ipcRenderer.send, ipcMain.handle, ipcMain.on

// Hook require to intercept electron module
const origRequire = Module.findExportByName(null, 'require');

// Monitor ipcRenderer.send / invoke
try {
    const electron = require('electron');

    if (electron.ipcRenderer) {
        const origSend = electron.ipcRenderer.send;
        electron.ipcRenderer.send = function(channel, ...args) {
            send({
                type: 'ipc',
                direction: 'renderer->main',
                method: 'send',
                channel: channel,
                args: JSON.stringify(args)
            });
            return origSend.apply(this, arguments);
        };

        const origInvoke = electron.ipcRenderer.invoke;
        electron.ipcRenderer.invoke = function(channel, ...args) {
            send({
                type: 'ipc',
                direction: 'renderer->main',
                method: 'invoke',
                channel: channel,
                args: JSON.stringify(args)
            });
            return origInvoke.apply(this, arguments);
        };
        console.log('[FridaPilot] ipcRenderer hooks applied');
    }

    if (electron.ipcMain) {
        const origHandle = electron.ipcMain.handle;
        electron.ipcMain.handle = function(channel, handler) {
            const wrappedHandler = async (event, ...args) => {
                send({
                    type: 'ipc',
                    direction: 'main.handle',
                    channel: channel,
                    args: JSON.stringify(args)
                });
                return handler(event, ...args);
            };
            return origHandle.call(this, channel, wrappedHandler);
        };
        console.log('[FridaPilot] ipcMain hooks applied');
    }
} catch (e) {
    console.log('[FridaPilot] Electron IPC hooks: ' + e.message);
}

console.log('[FridaPilot] Electron IPC monitor loaded');
