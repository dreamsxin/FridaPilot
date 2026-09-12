// Java Hook Template - Hook a Java method and log arguments + return value
// Variables: {{class_name}}, {{method_name}}

Java.perform(() => {
    const cls = Java.use('{{class_name}}');
    cls['{{method_name}}'].overload().implementation = function() {
        const args = Array.from(arguments);
        send({
            type: 'hook',
            class: '{{class_name}}',
            method: '{{method_name}}',
            args: args.map(a => String(a)),
            stack: Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()
            )
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
    console.log('[FridaPilot] Hooked {{class_name}}.{{method_name}}');
});
