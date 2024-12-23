import * as crypto from "crypto";

export function hashText(text: string, algorithm: "MD5" | "SHA256" | "SHA512"): string {
    return crypto.createHash(algorithm.toLowerCase()).update(text).digest("hex");
}

export function detectEncoding(text: string): "Base64" | "Unknown" {
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    return base64Regex.test(text) ? "Base64" : "Unknown";
}
