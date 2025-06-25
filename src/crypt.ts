import { compare, hash } from "bcrypt";

const digest = "sha-256";
const algorithm = "aes-gcm";
const encoding = "base64url";
const keyLen = 32;
const deriveKey = async (masterPassword: string) => {
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(masterPassword),
    { name: "HKDF", hash: digest },
    false,
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey({
    name: "HKDF",
    hash: digest,
    info: new Uint8Array(0),
    salt: new Uint8Array(0),
  }, baseKey, {
    name: algorithm, length: keyLen * 8
  }, false, ["encrypt", "decrypt"],
  );
}
export const encodeToBinary = (buffer: string) => Buffer.from(buffer, 'utf8').toString(encoding)
export const encodeToString = (buffer: ArrayBuffer) => Buffer.from(buffer).toString(encoding)
export const decodeToString = (str: string) => Buffer.from(str, encoding).toString('utf8')
export const decodeToBinary = (str: string) => Buffer.from(str, encoding)
export const hashPassword = hash
export const verifyHash = compare
export const encrypt = async (data: string, masterPassword: string) => {
  const initVector = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(masterPassword);
    const encrypted = await crypto.subtle.encrypt({ name: algorithm, iv: initVector }, key, Buffer.from(data));
    const strEquivalent = encodeToString(encrypted);
    return { cipher: strEquivalent, iv: Buffer.from(initVector.buffer).toString(encoding) };
}
export const decrypt = async ({ cipher, iv }: { cipher: string, iv: string }, masterPassword: string) => {
  const initVector = decodeToBinary(iv)
  const key = await deriveKey(masterPassword);
    const data = await crypto.subtle.decrypt({ name: algorithm, iv: initVector }, key, decodeToBinary(cipher));
    return Buffer.from(data).toString();
}
