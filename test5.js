var forge = require('node-forge');
function encode(plaintext) {
    publicKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQSHTZ4ZYcgOA7NrtPX1\n5MWrXrNrVmn0niCYuBgiPzZX7wv8HgigDj4976nM5YBq7DxGMfh9Bs7Js+IGAUbD\ndG7xkoRVTsCL6clgnAYYUV/+O7iaIo5ob/hKJbejS46TROVIZ8ozRvObtMujTlXF\nPVyayyzKNtCqPvXo6sDm6CQjlVPl4i5ciSt5gzCoF3wBx5DFNfqkSaNgH+QEwot+\ntHmwzCKO1KKsq/3NojPiCkcJPt0w/Zre+VF1/+0nZ8Phl4eUXVCtQarhkC8YMGuF\nWBih/GTk3412wQGoB8vBHgE2xMi5owiYvjW+ERJb5+o9IA5GQ6yQBzUrqF+JjOP4\nWwIDAQAB\n-----END PUBLIC KEY-----\n'
    // plaintext = "1689154632300"
    const publicObj = forge.pki.publicKeyFromPem(publicKey);
    const bytes = publicObj.encrypt(plaintext, 'RSA-OAEP');
    const encrypted = forge.util.encode64(bytes);
    return encrypted
}

function sha1_test(data) {
    var md = forge.sha1.create()
    var result = md.update(data).digest()
    return result.toHex()
}

// data = "ÿÒa÷ú«\t\u001dh$oj\u001eÍ½Ú\"ý7ÖC]@bhµ{¿\u000bþ*s(¹ñ$\u0004]\u0018þ·²\u0011è#µøY¢bn-Öä7\u0013g \u001bë\rÐ0ÊÔ!§¨T.\u0015ãJ(\u001dHraÊÂßÆ¤Ñ\rÏT\u0015:U÷\nGó`\u0019YÙFO:g\u0004kúMuò¼;\u0018BýF¨ñëWjð\f\u0010\u0012Ü\u001bh®'v©ÖÜr\u000f¯IgMpÄ±Åz»þ´HLõZ}»®z\u000fÚðÌ\u0000m\u0013z\u0006ì´!/*K\u0013\u000e9g .U\u0006oàÜ©&\r<ù\u0014yÐlkç|AÉU×`¬\u0010Ðª\u0001\u0014\u0000\u0000\u0000\u0000"
// data = 'test2'
// console.log(sha1_test(data))

// data = '1689154632300'
// console.log(encode(data))