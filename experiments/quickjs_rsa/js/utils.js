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
