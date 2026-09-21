// ObjC Hook Template - Hook an Objective-C method
// Variables: {{class_name}}, {{method_name}}

if (typeof ObjC !== "undefined" && ObjC.available) {
    const cls = ObjC.classes['{{class_name}}'];
    if (cls && cls['{{method_name}}']) {
        Interceptor.attach(cls['{{method_name}}'].implementation, {
            onEnter(args) {
                this.sel = ObjC.selectorAsString(args[1]);
                send({
                    type: 'hook',
                    class: '{{class_name}}',
                    method: this.sel,
                    stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n')
                });
            },
            onLeave(retval) {
                send({
                    type: 'return',
                    class: '{{class_name}}',
                    method: this.sel,
                    value: retval.toString()
                });
            }
        });
        console.log('[FridaPilot] Hooked {{class_name}} {{method_name}}');
    }
}
