// Native Hook Template - Hook a native function by module + export name
// Variables: {{module_name}}, {{method_name}}

const addr = Module.findExportByName('{{module_name}}', '{{method_name}}');
if (addr) {
    Interceptor.attach(addr, {
        onEnter(args) {
            send({
                type: 'hook',
                module: '{{module_name}}',
                function: '{{method_name}}',
                args: [args[0], args[1], args[2], args[3]].map(a => a.toString()),
                stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n')
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
