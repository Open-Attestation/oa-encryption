import {
  encryptString,
  decryptString,
  ENCRYPTION_PARAMETERS,
  IEncryptionResults,
  encodeDocument,
  decodeDocument
} from ".";
import sample from "../test/fixture/sample.json";

const base64Regex = /^(?:[a-zA-Z0-9+/]{4})*(?:|(?:[a-zA-Z0-9+/]{3}=)|(?:[a-zA-Z0-9+/]{2}==)|(?:[a-zA-Z0-9+/]{1}===))$/;
const encryptionKeyRegex = new RegExp(`^[0-9a-f]{${ENCRYPTION_PARAMETERS.keyLength / 4}}$`);

describe("storage/crypto", () => {
  it("should encrypt and decrypt unicode symbols correctly", () => {
    const originalObject = JSON.stringify({ data: "Rating(≤ 25kg)" });
    const enc = encryptString(originalObject);
    const dec = decryptString(enc);
    expect(dec).toStrictEqual(originalObject);
  });

  it("should encrypt and decrypt larger documents", () => {
    const originalObject = JSON.stringify(sample);
    const enc = encryptString(originalObject);
    const dec = decryptString(enc);
    expect(dec).toStrictEqual(originalObject);
  });

  describe("encryptString", () => {
    let encryptionResults: any | IEncryptionResults;

    test("should have the right keys and values when no key passed", async () => {
      encryptionResults = encryptString("hello world");
      expect(encryptionResults).toStrictEqual(
        expect.objectContaining({
          cipherText: expect.stringMatching(base64Regex),
          iv: expect.stringMatching(base64Regex),
          tag: expect.stringMatching(base64Regex),
          key: expect.stringMatching(encryptionKeyRegex),
          type: ENCRYPTION_PARAMETERS.version
        })
      );
    });
    test("should have the right keys and values when key is passed", async () => {
      const encryptionKey = "35fb46ca758889669f38c83d2f159b0f5a320b5a97387a9eaecb5652d15e0e3d";
      encryptionResults = encryptString("hello world", encryptionKey);
      expect(encryptionResults).toStrictEqual(
        expect.objectContaining({
          cipherText: expect.stringMatching(base64Regex),
          iv: expect.stringMatching(base64Regex),
          tag: expect.stringMatching(base64Regex),
          key: expect.stringMatching(encryptionKeyRegex),
          type: ENCRYPTION_PARAMETERS.version
        })
      );
      expect(encryptionResults.key).toStrictEqual(encryptionKey);
    });
    test("should throw error if input is not a string", () => {
      encryptionResults = encryptString("hello world");
      // @ts-ignore because we're explicitly testing failure mode
      expect(() => encryptString({})).toThrow("encryptString only accepts strings");
      // @ts-ignore because we're explicitly testing failure mode
      expect(() => encryptString(2)).toThrow("encryptString only accepts strings");
    });
  });

  describe("decryptString", () => {
    test("can decrypt", () => {
      const encryptionResults = encryptString("hello world");
      expect(decryptString(encryptionResults)).toBe("hello world");
    });

    test("can decrypt when encryption key is passed", () => {
      const encryptionKey = "35fb46ca758889669f38c83d2f159b0f5a320b5a97387a9eaecb5652d15e0e3d";
      const encryptionResults = encryptString("hello world", encryptionKey);
      expect(decryptString(encryptionResults)).toBe("hello world");
    });
  });

  describe("encodeDocument & decodeDocument", () => {
    it("should do the reverse of each other", () => {
      const input = "hello";
      const encoded = encodeDocument(input);
      const decoded = decodeDocument(encoded);
      expect(decoded).toBe(input);
    });

    it("should work for unicode text", () => {
      const input = "🦄😱|certificate|证书|sijil|प्रमाणपत्र";
      const encoded = encodeDocument(input);
      const decoded = decodeDocument(encoded);
      expect(decoded).toBe(input);
    });

    it("encodeDocument should return url safe characters only", () => {
      const input = "🦄😱|certificate|证书|sijil|प्रमाणपत्र";
      const encoded = encodeDocument(input);
      expect(encodeURI(encoded)).toBe(encoded);
    });
  });
});
