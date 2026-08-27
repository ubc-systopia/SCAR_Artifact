// Victim entry point: real RSA-4096 signing (crypto.publicKey.rsa.sign),
// identical to ../../js/openpgp_rsa.js except it imports the SELECT-patched
// BigInteger.modExp (./openpgp_select_patched.js) instead of the unpatched
// ../../js/openpgp.js. Used to attack the branchless `selectBigInt` patch as
// it is actually exercised inside a real modExp loop, not the synthetic
// SELECT()-call harness in ../../openpgp_patch/js/select_probe.js.
import { crypto, enums } from './openpgp_select_patched.js';
import { FindProjectRoot } from '../../js/utils.js';
import * as std from 'std';
import * as os from 'os';

const key_id = std.getenv('KEY_ID') | 0;
console.log("key_id: ", key_id)

const key_path =
	FindProjectRoot() +
	'/experiments/quickjs_rsa/rsa_key_pool/rsa_key_' +
	key_id +
	'.json';

const key_json = std.loadFile(key_path);
const key = JSON.parse(key_json);

const message = crypto.generateSessionKey(
	enums.symmetric.aes256,
);

const hashAlgo = enums.write(enums.hash, 'sha256');

const hashed = await crypto.hash.digest(hashAlgo, message);

const signature = await crypto.publicKey.rsa.sign(
	hashAlgo,
	message,
	key.n,
	key.e,
	key.d,
	key.p,
	key.q,
	key.u,
	hashed,
);
