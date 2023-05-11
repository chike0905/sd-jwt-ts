import { Buffer } from 'buffer';
import { base64url, decodeJwt, exportJWK, JWTPayload, SignJWT } from 'jose';
import * as crypto from 'crypto';

import { createSDJWTwithRelease, SD_JWTClaims, SD_JWT_RELEASE, SVC } from "../src";
import { createSVCandSDDigests, issueSDJWT, issueSDJWTinCombinedFormat } from "../src/issue";
import { PAYLOAD, importKeyPairForIssuerAndHolder, Entity } from './params';

import { verifyPresentation, verifySDJWTandDisclosures, verifySDJWTandSDJWTR, verifySDJWTandSVC } from '../src/verify';
import { SD_DIGESTS, SD_RELEASE } from '../src/types';
import { createPresentation } from '../src/presentation';
import { hashDisclosure } from '../src/disclosures';


let ISSUER: Entity;
let HOLDER: Entity;

let TEST_SD_JWT: string;

const dummy_payload = {
  "_sd": [
    "ckJk9Udk3k47PAOvPuk_cIKm2bVbPjZDos7kovYJnEk",
    "E4DgYoEUR5-djXZgAEI4eKwf3Cft7EOLsNg8hjNGAWo",
    "El6dxYmIimfZ-1eyaGMy2by658E33rD9zn-AtdOtB_Q",
    "G4myB1_SHDRhjju4xBNUvb0NO11mWIBUnqXwb3qQ3UU",
    "okAcAp1TVZDcaBeGeBHPdGGeLBRS2qG92bJfPaEcAaI",
    "paWEYypDnBqlnYeLJcKCzXPdfRWy5c0rIzLoBz6aC9Y",
    "xotLUeKqfG1UoFMpIkK5OWPh4C1rKfKWFfgjoSHQPlo"
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "kty": "EC",
    "x": "Juiif_Dm5T-xVYbcNZ72jSAk4t4ij5Bmgl7WGKO0uJQ",
    "y": "nqGkThWyZYFdQ3nnpkeoeey7edX7BV6-C9R3mOf1x1M",
    "crv": "P-256",
    "d": "mNCbN_oN0w43TgR_-wxa4tbZ7D6hTevIk1UtbiHXHXU"
  }
};

beforeEach(async () => {
  ({ ISSUER, HOLDER } = await importKeyPairForIssuerAndHolder());
  TEST_SD_JWT = await issueSDJWTinCombinedFormat(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY);
});

describe('Processing by the Holder', () => {
  it('Verify SD-JWT with SVC', async () => {
    const result = await verifySDJWTandDisclosures(TEST_SD_JWT, ISSUER.PUBLIC_KEY);
    expect(result).toBe(true);
  });
});

describe('Processing by the Holder', () => {
  // 6.2 Verification by the Verifier
  // 1. Determine if Holder Binding is to be checked according to the Verifier's policy for the use case at hand. This decision MUST NOT be based on whether a Holder Binding JWT is provided by the Holder or not. Refer to Section 8.6 for details.
  // 2. Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided).
  let PRESENTATION: string;
  let TEST_DISCLOSURES: string[];
  beforeEach(async () => {
    const sd_jwt = TEST_SD_JWT.split('~')[0];
    TEST_DISCLOSURES = TEST_SD_JWT.split('~').slice(1);
    PRESENTATION = await createPresentation(TEST_SD_JWT, TEST_DISCLOSURES.slice(-2));
  });

  describe('Holder Binding', () => {
    // TODO: not implemented
    // Spec Ref: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#section-6.2-4.1
  });

  describe('2. Separate the Presentation into the SD-JWT', () => {
    // Spec Ref: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#section-6.2-4.2
    it('Presentation is not separated by ~ (instead -)', async () => {
      const presentations = PRESENTATION.split('~');
      const result = verifyPresentation(presentations.join('-'), ISSUER.PUBLIC_KEY);
      await expect(result).rejects.toThrow("SD-JWT Presentation is invalid: last tilde MUST NOT be omitted.");
    });
  });

  describe('3. Validate the SD-JWT', () => {
    // Spec Ref: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#section-6.2-4.3.1
    describe("1. The none algorithm MUST NOT be accepted.", () => {
      it('just replace alg to none', async () => {
        const presentations = PRESENTATION.split('~');
        const jwt = presentations[0].split('.');
        jwt[0] = base64url.encode(JSON.stringify({ alg: 'none' }));
        presentations[0] = jwt.join('.');

        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow("SD-JWT Presentation is invalid: The none algorithm MUST NOT be accepted.");
      });
    });


    describe("2. Validate the signature over the SD-JWT.", () => {
      it("Signature invalid", async () => {
        const presentations = PRESENTATION.split('~');
        presentations[0] = presentations[0].slice(0, -2) + 'BB';
        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow(/^SD-JWT Verification Failed: .*/);
      });
      it("Public Key is not match", async () => {
        const result = verifyPresentation(PRESENTATION, HOLDER.PUBLIC_KEY);
        await expect(result).rejects.toThrow(/^SD-JWT Verification Failed: .*/);
      });
    });

    describe.skip("3. Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.", () => { });

    describe("4. Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT.", () => {

      it('nbf is invalid', async () => {
        const jwt = await new SignJWT(dummy_payload)
          .setNotBefore("100h")
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);

        console.log(jwt);

        const presentations = PRESENTATION.split('~');
        presentations[0] = jwt;
        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow(/^SD-JWT Verification Failed: .*/);
      });
      it('exp is invalid', async () => {
        const jwt = await new SignJWT(dummy_payload)
          .setExpirationTime(1000)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);

        const presentations = PRESENTATION.split('~');
        presentations[0] = jwt;
        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow(/^SD-JWT Verification Failed: .*/);
      });
    });

    describe("5. Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure.", () => {
      it("invalid hash alg name", async () => {
        const dummy = Object.assign({}, dummy_payload);
        dummy._sd_alg = "sha256";
        const jwt = await new SignJWT(dummy)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const presentations = PRESENTATION.split('~');
        presentations[0] = jwt;
        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.');
      });
    });
  });

  describe('4. Process the Disclosures and _sd keys in the SD-JWT as follows', () => {
    it('1. If the key does not refer to an array, the Verifier MUST reject the Presentation.', async () => {
      await validateWithDummy_sdClaims("dummy");
      await validateWithDummy_sdClaims(334);
      await validateWithDummy_sdClaims(0);
      // await validateWithDummy_sdClaims(undefined);
      await validateWithDummy_sdClaims(null);
      await validateWithDummy_sdClaims({ key: "dummy" });
      async function validateWithDummy_sdClaims(dummy: any) {
        //@ts-ignore
        dummy_payload._sd = dummy;
        const jwt = await new SignJWT(dummy_payload)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const presentations = PRESENTATION.split('~');
        presentations[0] = jwt;
        const result = verifyPresentation(presentations.join('~'), ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow('_sd claim is not array.');
      }
    });

    describe("2. Otherwise, process each entry in the _sd array as follows", () => {
      async function insertDummyDigestsAndDisclosure(dummy: string) {
        const claims = decodeJwt(TEST_SD_JWT.split("~")[0]);
        (claims._sd as string[]).push(hashDisclosure(dummy));
        const jwt = await new SignJWT(claims)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const presentations = PRESENTATION.split('~');
        presentations[0] = jwt;
        presentations.splice(-1, 0, dummy);
        let presentation = presentations.join('~');
        return presentation;
      }
      it('2. If the Disclosure is not a JSON-encoded array of three elements, the Verifier MUST reject the Presentation.', async () => {

        await validateDummyDigests('hogehoge');
        await validateDummyDigests(base64url.encode('hogehoge'));
        await validateDummyDigests(base64url.encode(JSON.stringify([])));
        await validateDummyDigests(base64url.encode(JSON.stringify(['hoge', 'fuga'])));
        await validateDummyDigests(base64url.encode(JSON.stringify(['hoge', 'fuga', 'fugo', 'hofo'])));

        async function validateDummyDigests(dummy: string) {
          const presentation = await insertDummyDigestsAndDisclosure(dummy);
          const result = verifyPresentation(presentation, ISSUER.PUBLIC_KEY);
          await expect(result).rejects.toThrow(/^Failed Decode Disclosure: .*/);
        }
      });
      it('4. If the claim name already exists at the same level, the Verifier MUST reject the Presentation.', async () => {
        const presentation = await insertDummyDigestsAndDisclosure(base64url.encode(JSON.stringify(['hoge', 'cnf', 'dummy'])));
        const result = verifyPresentation(presentation, ISSUER.PUBLIC_KEY);
        await expect(result).rejects.toThrow('Failed Verify Disclosure: The claim name "cnf" already exists at the same level');
      });
      it.skip("5. If the decoded value contains an _sd key in an object, recursively process the key using the steps described in (*)", async () => { });
    });
    it.skip("4. If any digests were found more than once in the previous step, the Verifier MUST reject the Presentation.", () => { });
  });

  describe.skip('5. If Holder Binding is required ', () => {
    it('todo', () => {
      expect(false).toBe(true);
    })
  });


  it('Verify SD-JWT Presentation', async () => {
    const result = await verifyPresentation(PRESENTATION, ISSUER.PUBLIC_KEY);
    const payload = Object.assign(PAYLOAD)
    const jwk = await exportJWK(HOLDER.PUBLIC_KEY);
    Object.defineProperty(payload, 'cnf', { value: jwk, enumerable: true });
    expect(result).toEqual(payload);
  });
});





describe.skip("test for draft-fett-oauth-selective-disclosure-jwt-02", () => {
  // 6.1 Verification by the Holder when Receiving SD-JWT and SVC
  // 1. Check that all the claims in the SVC are present in the SD-JWT and that there are no claims in the SD-JWT that are not in the SVC 
  // 2. Check that the hashes of the claims in the SVC match those in the SD-JWT
  describe('Verify SD-JWT as holder', () => {
    it('Verify SD-JWT with SVC', async () => {
      const result = await verifySDJWTandSVC(TEST_SD_JWT, ISSUER.PUBLIC_KEY);
      expect(result).toBe(true);
    });

    it('SD-JWT string does not contain SVC', async () => {
      const invalidSdJwt = TEST_SD_JWT.split('.').splice(0, 3).join('.');

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('sd_jwt string should consist of 4 strings separated by comma.')
        );
    });

    it('Signature of JWT in SD-JWT string is invalid', async () => {
      const separated = TEST_SD_JWT.split('.');
      separated[2] = separated[2].slice(0, -2) + 'aa';
      const invalidSdJwt = separated.join('.');

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('JWT signature in SD-JWT is invalid')
        );
    });

    it('JWT in SD-JWT string does not contain sd_digest', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummyJWT = await new SignJWT({ claim: 'This is dummy JWT' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(ISSUER.PRIVATE_KEY);
      const invalidSdJwt = dummyJWT + '.' + separated[3];

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
        );
    });

    it('JWT in SD-JWT string does not contain hash_alg', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummyJWT = await new SignJWT({ sd_digests: 'This is dummy JWT' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(ISSUER.PRIVATE_KEY);
      const invalidSdJwt = dummyJWT + '.' + separated[3];

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
        );
    });

    it('hash_alg in SD-JWT payload does not in IANA Registry ', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummyJWT = await new SignJWT({
        sd_digests: 'This is dummy JWT',
        hash_alg: 'dummy'
      }).setProtectedHeader({ alg: 'ES256' })
        .sign(ISSUER.PRIVATE_KEY);
      const invalidSdJwt = dummyJWT + '.' + separated[3];

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.')
        );
    });

    it('SVC does not includes sd_release', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummySVC = base64url.encode(JSON.stringify({ nonce: 'dummy' }));
      const invalidSdJwt = separated.splice(0, 3).join('.') + '.' + dummySVC;

      await expect(verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ')
        );
    });

    it('keys in sd_digests and in sd_release of SVC does not match', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummySVC = base64url.encode(JSON.stringify({ sd_release: {} }));
      const invalidSdJwt = separated.splice(0, 3).join('.') + '.' + dummySVC;

      await expect(() => verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('Keys in sd_digests and in sd_release of SVC does not match.')
        );
    });

    it('sd_digests does not include hash of sd_release in SVC', async () => {
      const separated = TEST_SD_JWT.split('.');
      const dummySVC = base64url.encode(JSON.stringify(createSVCandSDDigests(PAYLOAD).svc));
      const invalidSdJwt = separated.splice(0, 3).join('.') + '.' + dummySVC;

      await expect(() => verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
        .rejects.toThrow(
          new Error('sd_digest does not match with hash of sd_release.')
        );
    });
  });

  // 6.2 Verification by the Verifier when Receiving SD-JWT and SD-JWT-R
  describe('Verify SD-JWT as Verifier', () => {
    describe('SD-JWT includes sub_jwk as a holder public key', () => {
      let sdJwtWithRelease: string;
      beforeEach(async () => {
        const discloseClaims = ['given_name', 'family_name'];

        sdJwtWithRelease =
          await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, HOLDER.PRIVATE_KEY);
      });

      it('Verify SD-JWT with SD-JWT-R', async () => {
        const result = await verifySDJWTandSDJWTR(sdJwtWithRelease, ISSUER.PUBLIC_KEY);
        expect(result).toStrictEqual(
          {
            "given_name": "John",
            "family_name": "Doe",
          }
        );
      });

      // 1. Determine if holder binding is to be checked for the SD-JWT. Refer to Section 7.6 for details.
      // NOTE: holder binding is implemented in JWT-SD-R validation process. 

      // 2. Check that the presentation consists of six period-separated (.) elements; if holder binding is not required, the last element can be empty.
      it('SD-JWT string does not contain SD-JWT-R', async () => {
        const invalidSdJwt = sdJwtWithRelease.split('.').splice(0, 3).join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('sd_jwt string should be presented as 6 strings separated by comma.')
          );
      });

      // 4. Validate the SD-JWT:
      // 4-1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details.
      // 4-2. Validate the signature over the SD-JWT.
      // 4-3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
      // 4-4. Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT.
      it('Signature of JWT in SD-JWT string is invalid', async () => {
        const separated = sdJwtWithRelease.split('.');
        separated[2] = separated[2].slice(0, -2) + 'aa';
        const invalidSdJwt = separated.join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('JWT signature in SD-JWT is invalid')
          );

      });

      // 4-5. Check that the claim sd_digests is present in the SD-JWT.
      it('JWT in SD-JWT string does not contain sd_digest', async () => {
        const separated = sdJwtWithRelease.split('.');
        const dummyJWT = await new SignJWT({ claim: 'This is dummy JWT' })
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const invalidSdJwt = dummyJWT + '.' + separated.splice(3).join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
          );
      });

      // 4-6. Check that the hash_alg claim is present and its value is understand and the hash algorithm is deemed secure.
      it('hash_alg in SD-JWT payload does not in IANA Registry ', async () => {
        const separated = sdJwtWithRelease.split('.');
        const dummyJWT = await new SignJWT({
          sd_digests: 'This is dummy JWT',
          hash_alg: 'dummy'
        }).setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const invalidSdJwt = dummyJWT + '.' + separated.splice(3).join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.')
          );
      });

      // 5. Validate the SD-JWT Release:
      // 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
      // 5-1-1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
      // NOTE: tmp this implementation uses sub_jwk for holder binding. It is required to use a key that is pair of another key specified sub_jwk in SD-JWT.
      it('Signature of SD-JWT-R is invalid', async () => {
        const separated = sdJwtWithRelease.split('.');
        separated[5] = separated[5].slice(0, -2) + 'aa';
        const invalidSdJwt = separated.join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('JWT signature in SD-JWT-R is invalid')
          );
      });


      // 5-1-2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a nonce and aud field within the SD-JWT Release.
      // TODO: reply protection

      // 5-2. For each claim in the SD-JWT Release:
      // 5-2-1. Ensure that the claim is present as well in sd_release in the SD-JWT. If sd_release is structured, the claim MUST be present at the same place within the structure.
      it('SD-JWT-R does not includes sd_release', async () => {
        const separated = sdJwtWithRelease.split('.');
        const dummySDJWTR = await new SignJWT({ nonce: 'dummy' })
          .setProtectedHeader({ alg: 'ES256' })
          .sign(HOLDER.PRIVATE_KEY);
        const invalidSdJwt = separated.splice(0, 3).join('.') + '.' + dummySDJWTR;

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('The payload of an SD-JWT-R MUST contain the sd_release claim.')
          );
      });

      it('SD-JWT does not includes claims in sd_release in SD-JWT-R', async () => {
        const separated = sdJwtWithRelease.split('.');
        const dummyClaims = decodeJwt(separated.splice(0, 3).join('.'));
        // @ts-ignore 
        delete dummyClaims.sd_digests.family_name;
        const dummySDJWTR = await new SignJWT(dummyClaims)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(ISSUER.PRIVATE_KEY);
        const invalidSdJwt = dummySDJWTR + '.' + sdJwtWithRelease.split('.').splice(3).join('.');

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('SD-JWT does not includes claims in the SD-JWT-R.')
          );
      });

      // 5-2-2. Compute the base64url-encoded hash of a claim revealed from the Holder using the claim value and the salt included in the SD-JWT-R and the hash_alg in SD-JWT.
      // 5-2-3. Compare the hash digests computed in the previous step with the one of the same claim in the SD-JWT. Accept the claim only when the two hash digests match.
      it('Hash value of claims in SD-JWT-R does not match with claims in SD-JWT', async () => {
        const sdJwtR = sdJwtWithRelease.split('.').splice(3).join('.');
        const sdJwt = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY);
        const invalidSdJwt = sdJwt.split('.').splice(0, 3).join('.') + '.' + sdJwtR;

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('sd_digest does not match with hash of sd_release.')
          );
      });

      const composeInvalidSdJWT = async (sdJwtPayload: SD_JWTClaims, sdJwtRPayload: SVC) => {
        const invalidJwt = await new SignJWT(
          {
            sd_digests: sdJwtPayload,
            hash_alg: 'sha-256',
            sub_jwk: await exportJWK(HOLDER.PUBLIC_KEY)
          })
          .setProtectedHeader({ alg: 'ES256' }) // TODO: tmp support only ES256
          .sign(ISSUER.PRIVATE_KEY);
        const invalidJwtSdR = await new SignJWT(sdJwtRPayload)
          .setProtectedHeader({ alg: 'ES256' }) // TODO: tmp support only ES256
          .sign(HOLDER.PRIVATE_KEY);

        const invalidSdJwt = invalidJwt + '.' + invalidJwtSdR;
        return invalidSdJwt;
      }

      // 5-2-4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded array of exactly two values.
      // 5-2-4. Store the second of the two values.
      it('Claims in SD-JWT-R are not JSON-encoded.', async () => {
        const sdJwt = sdJwtWithRelease.split('.').splice(0, 3).join('.');
        const sdJwtPayload = decodeJwt(sdJwt).sd_digests as SD_JWTClaims;
        const sdJwtR = sdJwtWithRelease.split('.').splice(3).join('.');
        const sdJwtRPayload = decodeJwt(sdJwtR) as SD_JWT_RELEASE;

        sdJwtRPayload.sd_release.family_name = 'aa';
        const hashOfClaim = base64url.encode(crypto.createHash('sha256')
          .update(sdJwtRPayload.sd_release.family_name as string).digest());
        // @ts-ignore
        sdJwtPayload.family_name = hashOfClaim;

        const invalidSdJwt = await composeInvalidSdJWT(sdJwtPayload, sdJwtRPayload);

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('Claims in SD-JWT-R are not JSON-encoded.')
          );
      });

      it('Claims in SD-JWT-R are not JSON-encoded array.', async () => {
        const sdJwt = sdJwtWithRelease.split('.').splice(0, 3).join('.');
        const sdJwtPayload = decodeJwt(sdJwt).sd_digests as SD_DIGESTS
        const sdJwtR = sdJwtWithRelease.split('.').splice(3).join('.');
        const sdJwtRPayload = decodeJwt(sdJwtR) as SD_JWT_RELEASE;

        // @ts-ignore
        sdJwtRPayload.sd_release.family_name = JSON.stringify({ nonce: 'It is dummy.' });
        const hashOfClaim = base64url.encode(crypto.createHash('sha256')
          .update(sdJwtRPayload.sd_release.family_name as string).digest());
        // @ts-ignore
        sdJwtPayload.family_name = hashOfClaim;

        const invalidSdJwt = await composeInvalidSdJWT(sdJwtPayload, sdJwtRPayload);

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('Claims in SD-JWT-R are not JSON-encoded array.')
          );
      });

      it('Claims in SD-JWT-R are not JSON-encoded of exactly two values.', async () => {
        const sdJwt = sdJwtWithRelease.split('.').splice(0, 3).join('.');
        const sdJwtPayload = decodeJwt(sdJwt).sd_digests as SD_DIGESTS;
        const sdJwtR = sdJwtWithRelease.split('.').splice(3).join('.');
        const sdJwtRPayload = decodeJwt(sdJwtR) as SD_JWT_RELEASE;

        // @ts-ignore
        sdJwtRPayload.sd_release.family_name = JSON.stringify(['It', 'is', 'dummy.']);
        const hashOfClaim = base64url.encode(crypto.createHash('sha256')
          .update(sdJwtRPayload.sd_release.family_name as string).digest());
        // @ts-ignore
        sdJwtPayload.family_name = hashOfClaim;

        const invalidSdJwt = await composeInvalidSdJWT(sdJwtPayload, sdJwtRPayload);

        await expect(verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('Claims in SD-JWT-R are not JSON-encoded of exactly two values.')
          );
      });
    });

    describe('SD-JWT does not includes sub_jwk', () => {
      beforeEach(async () => {
        TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);
      });
      it('Verify SD-JWT with unsigned SD-JWT-R', async () => {
        const discloseClaims = ['given_name', 'family_name'];
        const sdJwtWithRelease =
          await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims);
        const result = await verifySDJWTandSDJWTR(sdJwtWithRelease, ISSUER.PUBLIC_KEY);
        expect(result).toStrictEqual(
          {
            "given_name": "John",
            "family_name": "Doe",
          }
        );
      });

      it('Verify SD-JWT with signed SD-JWT-R', async () => {
        const discloseClaims = ['given_name', 'family_name'];
        const sdJwtWithRelease =
          await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, HOLDER.PRIVATE_KEY);
        const result =
          await verifySDJWTandSDJWTR(sdJwtWithRelease, ISSUER.PUBLIC_KEY, HOLDER.PUBLIC_KEY);
        expect(result).toStrictEqual(
          {
            "given_name": "John",
            "family_name": "Doe",
          }
        );
      });
    });

    // 5-3. Once all necessary claims have been verified, their values can be validated and used according to the requirements of the application. It MUST be ensured that all claims required for the application have been released.
  });

  describe('Structured SD-JWT', () => {
    let TEST_SVC: SVC;
    beforeEach(async () => {
      TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY, true);
      TEST_SVC = JSON.parse(base64url.decode(TEST_SD_JWT.split('.')[3]).toString()) as SVC;
    });

    describe('Verify by Holder', () => {
      it('Verify SD-JWT with SVC', async () => {
        const result = await verifySDJWTandSVC(TEST_SD_JWT, ISSUER.PUBLIC_KEY);
        expect(result).toBe(true);
      });
      it('keys in sd_digests and in sd_release of SVC does not match', async () => {
        const separated = TEST_SD_JWT.split('.');

        // @ts-ignore
        delete TEST_SVC.sd_release.address['street_address'];
        const dummySVC = base64url.encode(JSON.stringify(TEST_SVC));
        const invalidSdJwt = separated.splice(0, 3).join('.') + '.' + dummySVC;

        await expect(() => verifySDJWTandSVC(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('Keys in sd_digests and in sd_release of SVC does not match.')
          );
      });
    });

    describe('Verify by Verifier', () => {
      let sdJwtWithRelease: string;
      beforeEach(async () => {
        TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY, true);
        TEST_SVC = JSON.parse(base64url.decode(TEST_SD_JWT.split('.')[3]).toString()) as SVC;

        const discloseClaims = ['given_name', 'address.street_address'];

        sdJwtWithRelease =
          await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, HOLDER.PRIVATE_KEY);
      });

      it('Verify SD-JWT with SD-JWT-R', async () => {
        const result = await verifySDJWTandSDJWTR(sdJwtWithRelease, ISSUER.PUBLIC_KEY);
        expect(result).toStrictEqual(
          {
            "given_name": "John",
            "address": {
              "street_address": "123 Main St"
            },
          }
        );
      });

      it('SD-JWT does not includes claims in the SD-JWT-R.', async () => {
        const separated = sdJwtWithRelease.split('.');

        const sdJwtR = separated.splice(3).join('.');
        const payload = decodeJwt(sdJwtR) as any;
        payload.sd_release['address']['dummy'] = 'This is dummy';
        const dummySDJWTR = await new SignJWT(payload as JWTPayload)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(HOLDER.PRIVATE_KEY);
        // @ts-ignore
        const invalidSdJwt =
          sdJwtWithRelease.split('.').splice(0, 3).join('.') + '.' + dummySDJWTR;

        await expect(() => verifySDJWTandSDJWTR(invalidSdJwt, ISSUER.PUBLIC_KEY))
          .rejects.toThrow(
            new Error('SD-JWT does not includes claims in the SD-JWT-R.')
          );
      });
    });

  });
});