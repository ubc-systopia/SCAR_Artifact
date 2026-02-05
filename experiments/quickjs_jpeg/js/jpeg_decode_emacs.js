import * as std from 'std';
import * as os from 'os';
globalThis.std = std;
globalThis.os = os;

import { decode, JpegImage } from './jpeg-js.js';
import {
	Fixture,
	FindProjectRoot,
	DumpImage,
	NormalizeImage,
} from './utils.js';

var jpegData = Fixture(
	'./experiments/quickjs_jpeg/evaluation/emacs_gs.jpg',
);
var rawImageData = decode(jpegData, { useTArray: true });
