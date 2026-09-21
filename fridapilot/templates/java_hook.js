// Java Hook Template - Hook a Java method and log arguments + return value
// Variables: {{class_name}}, {{method_name}}

if (typeof Java !== "undefined" && Java.available) Java.perform(() => {
    const cls = Java.use('{{class_name}}');
    // Hook EVERY overload: .overload() with no args only matches the
    // zero-arg signature, so parameterized methods - the documented
    // "log arguments" use case - failed with "no matching overloads"
    // (audit finding M-T1).
    const fpTargets = cls['{{method_name}}'].overloads || [cls['{{method_name}}']];
    fpTargets.forEach(function(fpOv) {
      fpOv.implementation = function() {
        const args = Array.from(arguments);
        send({
            type: 'hook',
            class: '{{class_name}}',
            method: '{{method_name}}',
            args: args.map(a => String(a)),
            stack: (function() {
                // android.util.Log does not exist on desktop JVMs - degrade
                // to an empty stack instead of crashing the hook.
                try {
                    return Java.use('android.util.Log').getStackTraceString(
                        Java.use('java.lang.Exception').$new());
                } catch (fpErrStack) { return ''; }
            })(),
        });
        const ret = this['{{method_name}}'].apply(this, arguments);
        send({
            type: 'return',
            class: '{{class_name}}',
            method: '{{method_name}}',
            value: String(ret)
        });
        return ret;
      };
    });
    console.log('[FridaPilot] Hooked {{class_name}}.{{method_name}}');
});
