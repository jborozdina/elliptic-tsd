import * as elliptic from "./elliptic";
import EDDSA = elliptic.eddsa;
import EC = elliptic.ec;
import ECDH = elliptic.ec;

// Usage examples from https://github.com/indutny/elliptic/blob/master/README.md

let eddsa: elliptic.EDDSA;
let ec: elliptic.EC;
let ecdh: elliptic.EC;
let kp1: elliptic.KeyPair1;
let kp2: elliptic.KeyPair2;
let signature1: elliptic.Signature1;

// ---------------------------------------- EdDSA

// Create and initialize EdDSA context
// (better do it once and reuse it)
eddsa = new EDDSA('ed25519');
// Create key pair from secret
kp2 = eddsa.keyFromSecret("0000000000000000000000000000000000000000000000000000000000000002"); // hex string, array or Buffer

// Sign message (must be an array, or it'll be treated as a hex sequence)
var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var signature = kp2.sign(msg).toHex();
console.log(signature);

// Verify signature
console.log(kp2.verify(msg, signature));

// CHECK WITH NO PRIVATE KEY

// Import public key
var pub = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29';
kp2 = eddsa.keyFromPublic(pub, 'hex');

// Verify signature
signature = '70bed1...';
console.log(kp2.verify(msg, signature));

// ---------------------------------------- ECDSA

// Create and initialize EC context
// (better do it once and reuse it)
ec = new EC('secp256k1');

// Generate keys
kp1 = ec.genKeyPair();

console.log(kp1.inspect());

// Sign message (must be an array, or it'll be treated as a hex sequence)
var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
signature1 = kp1.sign(msg);

// Export DER encoded signature in Array
var derSign = signature1.toDER();

// Verify signature
console.log(kp1.verify(msg, derSign));

// CHECK WITH NO PRIVATE KEY

// Public key as '04 + x + y'
var pub = '04ad8f60e4ec1ebdb6a260b559cb55b1e9d2c5ddd43a41a2' +
          'd11b0741ef2567d84e166737664104ebbc337af3d861d352' +
          '4cfbc761c12edae974a0759750c8324f9a';

// Signature MUST be either:
// 1) hex-string of DER-encoded signature; or
// 2) DER-encoded signature as buffer; or
// 3) object with two hex-string properties (r and s)

var signatureOpts: elliptic.SignatureOptions = 'b102ac...'; // case 1
//var signature = new Buffer('...'); // case 2
signatureOpts = { r: 'b1fc...', s: '9c42...' }; // case 3

// Import public key
kp1 = ec.keyFromPublic(pub, 'hex');

// Verify signature
console.log(kp1.verify(msg, signatureOpts));

// ---------------------------------------- ECDH

ecdh = new ECDH('curve25519');

// Generate keys
var key1 = ecdh.genKeyPair();
var key2 = ecdh.genKeyPair();

var shared1 = key1.derive(key2.getPublic());
var shared2 = key2.derive(key1.getPublic());

console.log('Both shared secrets are BN instances');
console.log(shared1.toString(16));
console.log(shared2.toString(16));
