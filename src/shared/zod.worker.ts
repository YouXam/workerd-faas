import { z } from "zod";

export const HEX_REGEXP = /^[0-9a-f]*$/i;
// https://github.com/capnproto/capnproto/blob/6b5bcc2c6e954bc6e167ac581eb628e5a462a469/c%2B%2B/src/kj/encoding.c%2B%2B#L719-L720
export const BASE64_REGEXP = /^[0-9a-z+/=]*$/i;
function hexToBuffer(hex: string): ArrayBuffer {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
	}
	return bytes.buffer;
}

function base64ToBuffer(base64: string): ArrayBuffer {
	const binaryString = atob(base64);
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

export const HexDataSchema = z
	.string()
	.regex(HEX_REGEXP)
	.transform((hex) => hexToBuffer(hex));
export const Base64DataSchema = z
	.string()
	.regex(BASE64_REGEXP)
	.transform((base64) => base64ToBuffer(base64));

export { z } from "zod";
