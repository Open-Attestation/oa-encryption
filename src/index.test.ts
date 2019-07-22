import { encryptString, decryptString, ENCRYPTION_PARAMETERS, IEncryptionResults } from ".";

const base64Regex = /^(?:[a-zA-Z0-9+/]{4})*(?:|(?:[a-zA-Z0-9+/]{3}=)|(?:[a-zA-Z0-9+/]{2}==)|(?:[a-zA-Z0-9+/]{1}===))$/;
const encryptionKeyRegex = new RegExp(`^[0-9a-f]{${ENCRYPTION_PARAMETERS.keyLength / 4}}$`);

describe("storage/crypto", () => {
  describe("encryptString", () => {
    let encryptionResults: any | IEncryptionResults;
    beforeAll(() => {
      encryptionResults = encryptString("hello world");
    });
    test("should have the right keys and values", async () => {
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
    test("should throw error if input is not a string", () => {
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
  });
});
