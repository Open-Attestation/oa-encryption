const forge = require("node-forge");
/**
 * Default options from responses here
 * https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode/26787
 */
export const ENCRYPTION_PARAMETERS = {
  algorithm: "AES-GCM",
  keyLength: 256, // Key length in bits
  ivLength: 96, // IV length in bits: NIST suggests 12 bytes
  tagLength: 128, // GCM authentication tag length in bits, see link above for explanation
  version: "OPEN-ATTESTATION-TYPE-1" // Type 1 using the above params without compression
};

/**
 * Generates a random key represented as a hexadecimal string
 * @param {number} keyLengthInBits Key length
 */
export const generateEncryptionKey = (keyLengthInBits = ENCRYPTION_PARAMETERS.keyLength) => {
  const encryptionKey = forge.random.getBytesSync(keyLengthInBits / 8);
  return forge.util.bytesToHex(encryptionKey);
};

/**
 * Generates a initialisation vector represented as a base64 string
 * @param {integer} ivLengthInBits Key length
 */
const generateIv = (ivLengthInBits = ENCRYPTION_PARAMETERS.ivLength) => {
  const iv = forge.random.getBytesSync(ivLengthInBits / 8);
  return forge.util.encode64(iv);
};

/**
 * Generates the requisite randomised variables and initialises the cipher with them
 * @returns the cipher object, encryption key in hex, and iv in base64
 */
const makeCipher = (encryptionKey: string = generateEncryptionKey()) => {
  const iv = generateIv();
  const cipher = forge.cipher.createCipher(ENCRYPTION_PARAMETERS.algorithm, forge.util.hexToBytes(encryptionKey));

  cipher.start({
    iv: forge.util.decode64(iv),
    tagLength: ENCRYPTION_PARAMETERS.tagLength
  });

  return { cipher, encryptionKey, iv };
};

export const encodeDocument = (document: string) => {
  const bytes = forge.util.encodeUtf8(document);
  const encoded = forge.util.encode64(bytes);
  return encoded;
};

export const decodeDocument = (encoded: string) => {
  const decoded = forge.util.decode64(encoded);
  const document = forge.util.decodeUtf8(decoded);
  return document;
};

export interface IEncryptionResults {
  cipherText: string;
  iv: string;
  tag: string;
  key: string;
  type: string;
}

/**
 * Encrypts a given string with symmetric AES
 * @param {string} document Input string to encrypt
 * @returns cipherText cipher text in base64
 * @returns iv iv in base64
 * @returns tag authenticated encryption tag in base64
 * @returns key encryption key in hexadecimal
 * @returns type The encryption algorithm identifier
 */
export const encryptString = (document: string, key?: string): IEncryptionResults => {
  if (typeof document !== "string") {
    throw new Error("encryptString only accepts strings");
  }

  const { cipher, encryptionKey, iv } = makeCipher(key);
  const buffer = forge.util.createBuffer(encodeDocument(document));
  cipher.update(buffer);
  cipher.finish();

  const encryptedMessage = forge.util.encode64(cipher.output.data);
  const tag = forge.util.encode64(cipher.mode.tag.data);
  return {
    cipherText: encryptedMessage,
    iv,
    tag,
    key: encryptionKey,
    type: ENCRYPTION_PARAMETERS.version
  };
};

/**
 * Decrypts a given ciphertext along with its associated variables
 * @param {string} cipherText cipher text base64 encoded
 * @param {string} tag aes authentication tag base64 encoded
 * @param {string} iv iv base64 encoded
 * @param {string} key decryption key hexademical encoded
 * @param {string} type encryption algorithm identifier
 */
export const decryptString = ({ cipherText, tag, iv, key, type }: IEncryptionResults): string => {
  if (type !== ENCRYPTION_PARAMETERS.version) {
    throw new Error(`Expecting version ${ENCRYPTION_PARAMETERS.version} but got ${type}`);
  }
  const keyBytestring = forge.util.hexToBytes(key);
  const cipherTextBytestring = forge.util.decode64(cipherText);
  const ivBytestring = forge.util.decode64(iv);
  const tagBytestring = forge.util.decode64(tag);

  const decipher = forge.cipher.createDecipher("AES-GCM", keyBytestring);
  decipher.start({
    iv: ivBytestring,
    tagLength: ENCRYPTION_PARAMETERS.tagLength,
    tag: tagBytestring
  });
  decipher.update(forge.util.createBuffer(cipherTextBytestring, "raw"));
  const success = decipher.finish();
  if (!success) {
    throw new Error("Error decrypting message");
  }
  return decodeDocument(decipher.output.data);
};
