import { encryptString, decryptString, ENCRYPTION_PARAMETERS, IEncryptionResults } from ".";

const base64Regex = /^(?:[a-zA-Z0-9+/]{4})*(?:|(?:[a-zA-Z0-9+/]{3}=)|(?:[a-zA-Z0-9+/]{2}==)|(?:[a-zA-Z0-9+/]{1}===))$/;
const encryptionKeyRegex = new RegExp(`^[0-9a-f]{${ENCRYPTION_PARAMETERS.keyLength / 4}}$`);

describe("storage/crypto", () => {
  it("should encrypt and decrypt unicode symbols correctly", () => {
    const originalObject = JSON.stringify({ data: "Rating(≤ 25kg)" });
    const enc = encryptString(originalObject);
    const dec = decryptString(enc);
    expect(dec).toEqual(originalObject);
  });

  describe("encryptString", () => {
    let encryptionResults: any | IEncryptionResults;

    test("should have the right keys and values when no key passed", async () => {
      encryptionResults = encryptString("hello world");
      expect(encryptionResults).toEqual(
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
      expect(encryptionResults).toEqual(
        expect.objectContaining({
          cipherText: expect.stringMatching(base64Regex),
          iv: expect.stringMatching(base64Regex),
          tag: expect.stringMatching(base64Regex),
          key: expect.stringMatching(encryptionKeyRegex),
          type: ENCRYPTION_PARAMETERS.version
        })
      );
      expect(encryptionResults.key).toEqual(encryptionKey);
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
});
