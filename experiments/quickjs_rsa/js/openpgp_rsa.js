import { crypto, enums } from './openpgp.js';
import { FindProjectRoot } from './utils.js';
import * as std from 'std';
import * as os from 'os';

const key_id = std.getenv('KEY_ID') | 0;
console.log("key_id: ", key_id)

const key_path =
	FindProjectRoot() +
	'/experiments/quickjs_rsa/rsa_key_pool/rsa_key_' +
	key_id +
	'.json';
// console.log(key_path);

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
