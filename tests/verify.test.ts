import { SAMPLE_SD_JWT, PUBLIC_KEY_JWK, PRIVATE_KEY_JWK, PAYLOAD } from "./params";
import { base64url, importJWK, KeyLike, SignJWT } from 'jose';

import { createSDJWTwithRelease } from "../src";
import { createSVCandSDDigests } from "../src/issue";

import { verifySDJWTandSDJWTR, verifySDJWTandSVC } from '../src/verify';


// 6.1 Verification by the Holder when Receiving SD-JWT and SVC
// 1. Check that all the claims in the SVC are present in the SD-JWT and that there are no claims in the SD-JWT that are not in the SVC 
// 2. Check that the hashes of the claims in the SVC match those in the SD-JWT
describe('Verify SD-JWT as holder', () => {
  it('Verify SD-JWT with SVC', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const result = await verifySDJWTandSVC(SAMPLE_SD_JWT, pubkey);
    expect(result).toBe(true);
  });
  it('SD-JWT string does not contain SVC', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const invalid_jwt_sd = SAMPLE_SD_JWT.split('.').splice(0, 3).join('.');
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('sd_jwt string should consist of 4 strings separated by comma.')
    );
  });

  it('Signature of JWT in SD-JWT string is invalid', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const separated = SAMPLE_SD_JWT.split('.');
    separated[2] = separated[2].slice(0, -2) + 'aa';
    const invalid_jwt_sd = separated.join('.');
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('JWT signature in SD-JWT is invalid')
    );
  });

  it('JWT in SD-JWT string does not contain sd_digest', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const separated = SAMPLE_SD_JWT.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummyJWT = await new SignJWT({ claim: 'This is dummy JWT' })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);
    const invalid_jwt_sd = dummyJWT + '.' + separated[3];
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
    );
  });

  it('JWT in SD-JWT string does not contain hash_alg', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const separated = SAMPLE_SD_JWT.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummyJWT = await new SignJWT({ sd_digests: 'This is dummy JWT' })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);
    const invalid_jwt_sd = dummyJWT + '.' + separated[3];
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
    );
  });

  it('hash_alg in SD-JWT payload does not in IANA Registry ', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const separated = SAMPLE_SD_JWT.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummyJWT = await new SignJWT({
      sd_digests: 'This is dummy JWT',
      hash_alg: 'dummy'
    }).setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);
    const invalid_jwt_sd = dummyJWT + '.' + separated[3];
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.')
    );
  });

  it('SVC does not includes sd_release', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const separated = SAMPLE_SD_JWT.split('.');
    const dummySVC = base64url.encode(JSON.stringify({ nonce: 'dummy' }));
    const invalid_jwt_sd = separated.splice(0, 3).join('.') + '.' + dummySVC;
    await expect(verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ')
    );
  });


  it('keys in sd_digests and in sd_release of SVC does not match', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;

    const separated = SAMPLE_SD_JWT.split('.');
    const dummySVC = base64url.encode(JSON.stringify({ sd_release: {} }));
    const invalid_jwt_sd = separated.splice(0, 3).join('.') + '.' + dummySVC;
    await expect(() => verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('Keys in sd_digests and sd_release of SVC does not match.')
    );
  });

  it('sd_digests does not include hash of sd_release in SVC', async () => {
    const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    const dummySVC = base64url.encode(JSON.stringify(createSVCandSDDigests(PAYLOAD).svc));

    const separated = SAMPLE_SD_JWT.split('.');
    const invalid_jwt_sd = separated.splice(0, 3).join('.') + '.' + dummySVC;

    await expect(() => verifySDJWTandSVC(invalid_jwt_sd, pubkey)).rejects.toThrow(
      new Error('sd_digest does not match with hash of sd_release.')
    );
  });
});

describe('Verify SD-JWT as Verifier', () => {
  let sdJwtWithRelease: string;
  let pubkey: KeyLike;
  beforeEach(async () => {
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const discloseClaims = ['given_name', 'family_name'];

    pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
    sdJwtWithRelease = await createSDJWTwithRelease(SAMPLE_SD_JWT, discloseClaims, privKey);
  });

  it('Verify SD-JWT with SD-JWT-R', async () => {
    const result = await verifySDJWTandSDJWTR(sdJwtWithRelease, pubkey);
    expect(result).toBe(true);
  });

  it('SD-JWT string does not contain SD-JWT-R', async () => {
    const invalidJwtSd = sdJwtWithRelease.split('.').splice(0, 3).join('.');
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('sd_jwt string should be presented as 6 strings separated by comma.')
    );
  });

  it('Signature of JWT in SD-JWT string is invalid', async () => {
    const separated = sdJwtWithRelease.split('.');
    separated[2] = separated[2].slice(0, -2) + 'aa';
    const invalidJwtSd = separated.join('.');
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('JWT signature in SD-JWT is invalid')
    );

  });
  it('JWT in SD-JWT string does not contain sd_digest', async () => {
    const separated = sdJwtWithRelease.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummyJWT = await new SignJWT({ claim: 'This is dummy JWT' })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);
    const invalidJwtSd = dummyJWT + '.' + separated.splice(3).join('.');
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.')
    );
  });

  it('hash_alg in SD-JWT payload does not in IANA Registry ', async () => {
    const separated = sdJwtWithRelease.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummyJWT = await new SignJWT({
      sd_digests: 'This is dummy JWT',
      hash_alg: 'dummy'
    }).setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);
    const invalidJwtSd = dummyJWT + '.' + separated.splice(3).join('.');
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.')
    );
  });
  it('Signature of SD-JWT-R is invalid', async () => {
    const separated = sdJwtWithRelease.split('.');
    separated[5] = separated[5].slice(0, -2) + 'aa';
    const invalidJwtSd = separated.join('.');
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('JWT signature in SD-JWT-R is invalid')
    );
  });

  it('SD-JWT-R does not includes sd_release', async () => {
    const separated = sdJwtWithRelease.split('.');
    const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
    const dummySDJWTR = await new SignJWT({ nonce: 'dummy' })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privKey);

    const invalidJwtSd = separated.splice(0, 3).join('.') + '.' + dummySDJWTR;
    await expect(verifySDJWTandSDJWTR(invalidJwtSd, pubkey)).rejects.toThrow(
      new Error('The payload of an SD-JWT-R MUST contain the sd_release claim.')
    );
  });

});



// 6.2 Verification by the Verifier when Receiving SD-JWT and SD-JWT-R

// 1. Determine if holder binding is to be checked for the SD-JWT. Refer to Section 7.6 for details.
// 2. Check that the presentation consists of six period-separated (.) elements; if holder binding is not required, the last element can be empty.

// 3. Separate the SD-JWT from the SD-JWT Release.

// 4. Validate the SD-JWT:
// 4-1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details.
// 4-2. Validate the signature over the SD-JWT.
// 4-3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
// 4-4. Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT.
// 4-5. Check that the claim sd_digests is present in the SD-JWT.
// 4-6. Check that the hash_alg claim is present and its value is understand and the hash algorithm is deemed secure.

// 5. Validate the SD-JWT Release:
// 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
// 5-1-1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
// 5-1-2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a nonce and aud field within the SD-JWT Release.

// 5-2. For each claim in the SD-JWT Release:
// 5-2-1. Ensure that the claim is present as well in sd_release in the SD-JWT. If sd_release is structured, the claim MUST be present at the same place within the structure.
// 5-2-2. Compute the base64url-encoded hash of a claim revealed from the Holder using the claim value and the salt included in the SD-JWT-R and the hash_alg in SD-JWT.
// 5-2-3. Compare the hash digests computed in the previous step with the one of the same claim in the SD-JWT. Accept the claim only when the two hash digests match.
// 5-2-4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded array of exactly two values.
// 5-2-4. Store the second of the two values.

// 5-3. Once all necessary claims have been verified, their values can be validated and used according to the requirements of the application. It MUST be ensured that all claims required for the application have been released.