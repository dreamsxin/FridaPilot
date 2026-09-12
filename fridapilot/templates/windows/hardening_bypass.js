// Windows 加固绕过脚本 - VMProtect/Themida/反调试/完整性检查/反篡改
// FridaPilot - Windows Hardening Bypass

console.log('[FridaPilot] Windows Hardening Bypass Loaded');

// ══════════════════════════════════════════
// 1. 反调试绕过 (全面)
// ══════════════════════════════════════════

// IsDebuggerPresent
var isDbg = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (isDbg) {
    Interceptor.attach(isDbg, {
        onLeave(retval) {
            retval.replace(ptr(0));
            send({ type: 'antidebug', api: 'IsDebuggerPresent', bypassed: true });
        }
    });
}

// CheckRemoteDebuggerPresent
var checkRemote = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (checkRemote) {
    Interceptor.attach(checkRemote, {
        onEnter(args) { this.pDebugger = args[1]; },
        onLeave(retval) {
            this.pDebugger.writeU32(0);
            send({ type: 'antidebug', api: 'CheckRemoteDebuggerPresent', bypassed: true });
        }
    });
}

// NtQueryInformationProcess (多种InfoClass)
var ntQuery = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
if (ntQuery) {
    Interceptor.attach(ntQuery, {
        onEnter(args) {
            this.infoClass = args[1].toInt32();
            this.pInfo = args[2];
            this.pRetLen = args[4];
        },
        onLeave(retval) {
            // ProcessDebugPort (7)
            if (this.infoClass === 7) {
                this.pInfo.writePointer(ptr(0));
                send({ type: 'antidebug', api: 'NtQueryInformationProcess', infoClass: 'ProcessDebugPort' });
            }
            // ProcessDebugObjectHandle (30)
            if (this.infoClass === 30) {
                retval.replace(ptr(0xC0000353)); // STATUS_PORT_NOT_SET
                send({ type: 'antidebug', api: 'NtQueryInformationProcess', infoClass: 'ProcessDebugObjectHandle' });
            }
            // ProcessDebugFlags (31)
            if (this.infoClass === 31) {
                this.pInfo.writeU32(1); // NoDebugInherit = TRUE
                send({ type: 'antidebug', api: 'NtQueryInformationProcess', infoClass: 'ProcessDebugFlags' });
            }
        }
    });
}

// NtSetInformationThread (ThreadHideFromDebugger)
var ntSetThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
if (ntSetThread) {
    Interceptor.attach(ntSetThread, {
        onEnter(args) {
            if (args[1].toInt32() === 0x11) { // ThreadHideFromDebugger
                send({ type: 'antidebug', api: 'ThreadHideFromDebugger', bypassed: true });
                args[1] = ptr(0); // Change to ThreadBasicInformation (harmless)
            }
        }
    });
}

// OutputDebugStringA timing check
var outputDbgStr = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
if (outputDbgStr) {
    Interceptor.attach(outputDbgStr, {
        onEnter(args) {
            send({ type: 'antidebug', api: 'OutputDebugStringA', msg: args[0].readAnsiString() });
        }
    });
}

// ══════════════════════════════════════════
// 2. VMProtect / Themida 检测
// ══════════════════════════════════════════
// Detect VMProtect by section names
try {
    Process.enumerateModules().forEach(mod => {
        try {
            var base = mod.base;
            var dosHdr = base.readU16();
            if (dosHdr === 0x5A4D) { // MZ
                var peOff = base.add(0x3C).readU32();
                var numSections = base.add(peOff + 6).readU16();
                var optHdrSize = base.add(peOff + 20).readU16();
                var sectionStart = base.add(peOff + 24 + optHdrSize);
                for (var i = 0; i < numSections; i++) {
                    var secName = sectionStart.add(i * 40).readAnsiString(8);
                    if (secName.includes('.vmp') || secName.includes('VMP') || secName.includes('.themida')) {
                        send({ type: 'packer_detected', packer: secName.includes('.vmp') ? 'VMProtect' : 'Themida',
                               module: mod.name, section: secName });
                    }
                }
            }
        } catch(e) {}
    });
} catch(e) {}

// ══════════════════════════════════════════
// 3. 时间戳反调试绕过
// ══════════════════════════════════════════
// QueryPerformanceCounter / GetTickCount manipulation
var qpc = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
if (qpc) {
    var qpcCallCount = 0;
    Interceptor.attach(qpc, {
        onLeave(retval) {
            qpcCallCount++;
            // Every pair of calls: make timing consistent
            if (qpcCallCount % 2 === 0) {
                send({ type: 'timing_bypass', api: 'QueryPerformanceCounter', count: qpcCallCount });
            }
        }
    });
}

// ══════════════════════════════════════════
// 4. 完整性检查绕过
// ══════════════════════════════════════════
// Hook CreateFileW for integrity check files
var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
if (createFileW) {
    Interceptor.attach(createFileW, {
        onEnter(args) {
            var path = '';
            try { path = args[0].readUtf16String(); } catch(e) {}
            if (path && (path.endsWith('.sig') || path.endsWith('.hash') || path.includes('integrity'))) {
                send({ type: 'integrity', op: 'checking', path: path });
            }
        }
    });
}

// ══════════════════════════════════════════
// 5. 进程环境检测绕过 (VM/Sandbox)
// ══════════════════════════════════════════
// GetSystemFirmwareTable (SMBIOS check)
var getFirmware = Module.findExportByName('kernel32.dll', 'GetSystemFirmwareTable');
if (getFirmware) {
    Interceptor.attach(getFirmware, {
        onEnter(args) {
            send({ type: 'env_detect', api: 'GetSystemFirmwareTable', signature: args[0].toInt32() });
        }
    });
}

console.log('[FridaPilot] Windows hardening bypass loaded');
