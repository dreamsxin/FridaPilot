// Node.js Hook - Monitor fs, child_process, and net module calls

// Hook fs operations
try {
    const fs = require('fs');
    ['readFileSync', 'writeFileSync', 'readFile', 'writeFile', 'unlink', 'mkdir'].forEach(fn => {
        if (fs[fn]) {
            const orig = fs[fn];
            fs[fn] = function() {
                send({
                    type: 'node',
                    module: 'fs',
                    function: fn,
                    args: Array.from(arguments).slice(0, 2).map(a => String(a))
                });
                return orig.apply(this, arguments);
            };
        }
    });
    console.log('[FridaPilot] fs hooks applied');
} catch (e) {}

// Hook child_process
try {
    const cp = require('child_process');
    ['exec', 'execSync', 'spawn', 'execFile'].forEach(fn => {
        if (cp[fn]) {
            const orig = cp[fn];
            cp[fn] = function() {
                send({
                    type: 'node',
                    module: 'child_process',
                    function: fn,
                    command: String(arguments[0])
                });
                return orig.apply(this, arguments);
            };
        }
    });
    console.log('[FridaPilot] child_process hooks applied');
} catch (e) {}

// Hook net.connect
try {
    const net = require('net');
    const origConnect = net.connect;
    net.connect = function() {
        send({
            type: 'node',
            module: 'net',
            function: 'connect',
            args: Array.from(arguments).slice(0, 2).map(a => JSON.stringify(a))
        });
        return origConnect.apply(this, arguments);
    };
    console.log('[FridaPilot] net hooks applied');
} catch (e) {}

console.log('[FridaPilot] Node.js monitor loaded');
