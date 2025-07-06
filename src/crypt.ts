import { compare, hash } from "bcrypt";

const digest = "sha-256";
const algorithm = "aes-gcm";
const encoding = "base64url";
const keyLen = 256;  // 256 bits, 32 bytes
export const deriveKey = async (masterPassword: string) => {
  // NOTE: This Base Key is for creating secure keys out of the Master Password
  // It should not be used for any encryption purposes.
  const passwordBytes = new TextEncoder().encode(masterPassword);
  const baseKey = await crypto.subtle.importKey(
    "raw", passwordBytes,
    { name: "PBKDF2", hash: digest },
    false,
    ["deriveKey"],
  );
  // NOTE: Here is we deriving the actual key that will be used for encryption and
  // other operations.
  // it will be saved in 2 minutes sessions
  return await crypto.subtle.deriveKey({
    name: "PBKDF2",
    hash: digest,
    salt: crypto.getRandomValues(new Uint8Array(32)),
    iterations: 100_000
  }, baseKey, {
    name: algorithm, length: keyLen
  }, true, ["encrypt", "decrypt"]);
}

// I gotta change these names, its confusing, VERY MUCH
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
  return { cipher: strEquivalent, iv: encodeToString(initVector.buffer) };
}
export const decrypt = async ({ cipher, iv }: { cipher: string, iv: string }, masterPassword: string) => {
  const initVector = decodeToBinary(iv)
  const key = await deriveKey(masterPassword);
  const data = await crypto.subtle.decrypt({ name: algorithm, iv: initVector }, key, decodeToBinary(cipher));
  return Buffer.from(data).toString();
}
export const getKey = async (password: string) => {
  return await crypto.subtle.exportKey("jwk", await deriveKey(password))
}
export const decryptwjkey = async ({ cipher, iv }: { cipher: string, iv: string }, jwkKey: JsonWebKey) => {
  const initVector = decodeToBinary(iv);
  const cipherBuffer = decodeToBinary(cipher);
  const key = await crypto.subtle.importKey("jwk", jwkKey, { name: algorithm }, false, ['decrypt'])
  const decrypted = await crypto.subtle.decrypt({ name: algorithm, iv: initVector }, key, cipherBuffer);
  return Buffer.from(decrypted).toString('utf-8');
}
export const encryptwjkey = async (data: string, jwkKey: JsonWebKey) => {
  const initVector = crypto.getRandomValues(new Uint8Array(32))
  const key = await crypto.subtle.importKey("jwk", jwkKey, { name: algorithm }, false, ['encrypt'])
  const encrypted = await crypto.subtle.encrypt({ name: algorithm, iv: initVector }, key, Buffer.from(data));
  const cipher = encodeToString(encrypted)
  return { cipher: cipher, iv: Buffer.from(initVector.buffer).toString(encoding) }
}
