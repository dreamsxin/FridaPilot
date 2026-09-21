// Crypto Monitor - Monitor common cryptographic API calls
// Logs algorithm, key material, and input/output data

if (typeof Java !== "undefined" && Java.available) {
    Java.perform(() => {
        // javax.crypto.Cipher
        try {
            const Cipher = Java.use('javax.crypto.Cipher');
            Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
                send({ type: 'crypto', op: 'Cipher.getInstance', algorithm: algo });
                return this.getInstance(algo);
            };
            Cipher.doFinal.overload('[B').implementation = function(input) {
                const result = this.doFinal(input);
                send({
                    type: 'crypto',
                    op: 'Cipher.doFinal',
                    mode: this.getOpmode(),
                    input: bytesToHex(input),
                    output: bytesToHex(result)
                });
                return result;
            };
        } catch (e) {}

        // java.security.MessageDigest
        try {
            const MD = Java.use('java.security.MessageDigest');
            MD.digest.overload('[B').implementation = function(input) {
                const result = this.digest(input);
                send({
                    type: 'crypto',
                    op: 'MessageDigest.digest',
                    algorithm: this.getAlgorithm(),
                    input: bytesToHex(input),
                    output: bytesToHex(result)
                });
                return result;
            };
        } catch (e) {}
    });
}

function bytesToHex(arr) {
    if (!arr) return null;
    const bytes = Java.array('byte', arr);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

console.log('[FridaPilot] Crypto monitor loaded');
