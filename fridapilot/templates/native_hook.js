// Native Hook Template - Hook a native function by module + export name
// Frida 16/17 compat: static Module lookup APIs were removed in Frida 17.
function fpFindExport(moduleName, exportName) {
    if (typeof Module.getGlobalExportByName === "function") {
        if (moduleName) {
            const mod = Process.findModuleByName(moduleName);
            return mod ? mod.findExportByName(exportName) : null;
        }
        try { return Module.getGlobalExportByName(exportName); } catch (e) { return null; }
    }
    return Module.findExportByName(moduleName, exportName);
}
function fpFindModule(moduleName) {
    if (typeof Process.findModuleByName === "function") return Process.findModuleByName(moduleName);
    return Module.findModuleByName(moduleName);
}
// Variables: {{module_name}}, {{method_name}}

const addr = fpFindExport('{{module_name}}', '{{method_name}}');
if (addr) {
    Interceptor.attach(addr, {
        onEnter(args) {
            // ACCURATE needs unwind info (.pdata on Windows x64); a leaf function with
            // no RUNTIME_FUNCTION entry returns an empty or single-frame stack, which
            // reads as "called from nowhere". Fall back to FUZZY and report which one
            // produced the frames so the caller attribution is not trusted blindly.
            const acc = Thread.backtrace(this.context, Backtracer.ACCURATE);
            const frames = acc.length > 1
                ? acc
                : Thread.backtrace(this.context, Backtracer.FUZZY);
            send({
                type: 'hook',
                module: '{{module_name}}',
                function: '{{method_name}}',
                args: [args[0], args[1], args[2], args[3]].map(a => a.toString()),
                backtracer: acc.length > 1 ? 'accurate' : 'fuzzy',
                stack: frames.map(DebugSymbol.fromAddress).join('\n')
            });
        },
        onLeave(retval) {
            send({
                type: 'return',
                module: '{{module_name}}',
                function: '{{method_name}}',
                value: retval.toString()
            });
        }
    });
    console.log('[FridaPilot] Hooked ' + '{{module_name}}' + '!' + '{{method_name}}');
} else {
    console.log('[FridaPilot] Export not found: ' + '{{module_name}}' + '!' + '{{method_name}}');
}
