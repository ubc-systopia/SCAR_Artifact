import * as std from 'std'
import * as os from 'os'
globalThis.std = std;
globalThis.os = os;

export function FindProjectRoot() {
	let [currentPath,errno] = os.getcwd();
	while (currentPath !== "/") {
		let projectFile = currentPath + "/.project";
		let [fileInfo, errno] = os.stat(projectFile);
		if (fileInfo && fileInfo.mode & os.S_IFREG) {
			return currentPath + "/";
		}

		let lastSlash = currentPath.lastIndexOf("/");
		if (lastSlash <= 0) {
			break;
		}
		currentPath = currentPath.substring(0, lastSlash);
	}

	std.err.printf("Cannot find project root, using / instead.\n");
	return "/";
}

export function Fixture(filename) {
	var filepath = FindProjectRoot() + filename;
	var file = std.open(filepath, 'r');
	// console.log("decode: ", filepath)
	if (file == null) {
		console.log('Cannot file ' + filepath);
	}
	file.seek(0, std.SEEK_END);
	var length = file.tell();
	var buffer = new ArrayBuffer(length);
	file.seek(0);
	file.read(buffer, 0, length);
	return buffer;
}

export function NormalizeImage(pixelArray){
	console.log(pixelArray.length)
	normalPixel = new ArrayBuffer(pixelArray.length)
	return normalPixel
}

export function LoadBytes(filename){
	var filepath = FindProjectRoot() + filename;
	var file = std.open(filepath, 'r');
	console.log("load bytes from: ", filepath)

	if (!file) {
		throw new Error(`Failed to open file: ${filename}`);
	}
	file.seek(0, std.SEEK_END);
	var length = file.tell();
	var buffer = new ArrayBuffer(length);
	file.seek(0);
	file.read(buffer, 0, length);
	return buffer;
}

export function DumpImage(filename, array){
	var filepath = FindProjectRoot() + filename;
	let file = std.open(filepath, "wb");
	if (!file) {
		throw new Error(`Failed to open file: ${filename}`);
	}
	file.write(array.buffer, 0, array.length);
	file.close();
}
