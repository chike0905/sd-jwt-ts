import { base64url, exportJWK, jwtVerify } from 'jose';
import { decodeJwt } from 'jose';
import * as crypto from 'crypto';

import { createSVCandSDDigests, issueSDJWT, SD_DIGESTS } from '../src';

import { PAYLOAD, importKeyPairForIssuerAndHolder, Entity } from './params';

/*
NOTE: This test suite is implemented based on draft-fett-oauth-selective-disclosure-jwt-02
https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html
*/



let ISSUER: Entity;
let HOLDER: Entity;

beforeEach(async () => {
  ({ ISSUER, HOLDER } = await importKeyPairForIssuerAndHolder());
});

//  5.1 
// The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims described in the following, and MAY contain a holder's public key or a reference thereto, as well as further claims such as iss, iat, etc. as defined or required by the application using SD-JWTs.
it('Issue JWT-SD', async () => {
  const sdJwt: string = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);

  // SD-JWT is combined jwt and svc;
  const splittedSdJwt = sdJwt.split('.');
  expect(splittedSdJwt.length).toBe(4);

  // Decoding
  const raw_svc = base64url.decode(splittedSdJwt[3]).toString();
  const svc = JSON.parse(raw_svc);
  const jwt = splittedSdJwt.slice(0, 3).join('.');

  // Verify JWT itself
  const jwtPayload = (await jwtVerify(jwt, ISSUER.PUBLIC_KEY)).payload;

  // SVC has sd_release
  expect(svc).toHaveProperty('sd_release');

  // JWT in SD-JWT has sd_digests and hash_alg
  expect(jwtPayload).toHaveProperty('sd_digests');
  expect(jwtPayload).toHaveProperty('hash_alg');

  // sd_digests includes all claims in SVC
  expect(Object.keys(jwtPayload.sd_digests as Object))
    .toStrictEqual(Object.keys(svc.sd_release));

  // sd_digests are hash of svc items
  Object.keys(svc.sd_release).map((key: string) => {
    const hashOfValueInSVC_b64 = base64url.encode(crypto.createHash('sha256')
      .update(svc.sd_release[key] as string).digest());
    expect((jwtPayload.sd_digests as any)[key]).toBe(hashOfValueInSVC_b64);
  });
});

// 5.1.1
// An SD-JWT MUST include hash digests of the salted claim values that are included by the issuer under the property sd_digests.
it('sd_digest has properties for each claim', () => {
  const { sd_digests } = createSVCandSDDigests(PAYLOAD);
  Object.keys(PAYLOAD).map((key: string) => {
    expect(sd_digests).toHaveProperty(key);
  })
});

// 5.1.2
// The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry [IANA.Hash.Algorithms]. 
// ref: https://www.iana.org/assignments/named-information/named-information.xhtml
it('hash_alg in sd_digest is a value from IANA Registory', async () => {
  const HashNameString = ['Reserved', 'sha-256', 'sha-256-128', 'sha-256-120', 'sha-256-96', 'sha-256-64', 'sha-256-32', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'Unassigned', 'Reserved', 'Unassigned', 'blake2s-256', 'blake2b-256', 'blake2b-512', 'k12-256', 'k12-512'];
  const sdJwt = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);
  const splittedSdJwt = sdJwt.split('.');
  const jwt = splittedSdJwt.slice(0, 3).join('.');

  const decodedJwt = decodeJwt(jwt);
  expect(HashNameString.includes(decodedJwt.hash_alg as string)).toBe(true);
});

// 5.1.3. Holder Public Key Claim
// If the issuer wants to enable holder binding, it MAY include a public key associated with the holder, or a reference thereto.
// ...
// Note: need to define how holder public key is included, right now examples are using sub_jwk I think.
it('Issue SD-JWT with Holder Binding', async () => {
  const sdJwt: string = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY);
  const splittedSdJwt = sdJwt.split('.');
  const jwt = splittedSdJwt.slice(0, 3).join('.');
  const jwtPayload = decodeJwt(jwt);
  expect(jwtPayload).toHaveProperty('sub_jwk');
  expect(jwtPayload.sub_jwk).toEqual(await exportJWK(HOLDER.PUBLIC_KEY));
});

// 5.3
// A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. 
it('Salt/Value Container (SVC) has MUST "sd_release" property', () => {
  const svc = createSVCandSDDigests(PAYLOAD).svc;
  expect(svc).toHaveProperty('sd_release');
});

// Its structure mirrors the one of sd_digests in the SD-JWT, but the values are the inputs to the hash calculations the issuer used, as strings.
it('Ths structure of SVC is mirrors of sd_digest', () => {
  const { sd_digests, svc } = createSVCandSDDigests(PAYLOAD);

  Object.keys(sd_digests).map((key) => {
    expect(svc.sd_release).toHaveProperty(key);
  });
});

// Each salt value SHOULD contain at least 128 bits of pseudorandom data, making it hard for an attacker to guess. 
it('Salt is at least 128 bits', () => {
  const { svc } = createSVCandSDDigests(PAYLOAD);
  Object.keys(svc.sd_release).map((item: string) => {
    const salt = JSON.parse(svc.sd_release[item] as string)[0];
    expect(base64url.decode(salt).byteLength >= 128 / 8).toBe(true);
  });
});

// 5.1.1
// The issuer MUST build the digests by hashing over a string that is formed by JSON-encoding an ordered array containing the salt and the claim value, e.g.: ["6qMQvRL5haj","Peter"].
it('Values in sd_digests are hash values of values in SVC', () => {
  const { sd_digests, svc } = createSVCandSDDigests(PAYLOAD);
  Object.keys(sd_digests).map((key) => {
    const hashOfValueInSVC_b64 = base64url.encode(crypto.createHash('sha256')
      .update(svc.sd_release[key] as string).digest());
    expect(sd_digests[key]).toBe(hashOfValueInSVC_b64);
  });
});


const validateObjectsMirrorStructure = (obj1: Object, obj2: Object) => {
  Object.keys(obj1).map((key: string) => {
    expect(obj2).toHaveProperty(key);
    if (obj1[key as keyof Object] instanceof Object)
      validateObjectsMirrorStructure(
        obj1[key as keyof Object],
        obj2[key as keyof Object]
      );
  });
}

const validateDigestOfSVCClaims = (sd_digests: SD_DIGESTS, sd_release: Object) => {
  Object.keys(sd_digests).map((key: string) => {
    if (sd_digests[key as keyof Object] instanceof Object) {
      validateDigestOfSVCClaims(
        sd_digests[key as keyof SD_DIGESTS] as SD_DIGESTS,
        sd_release[key as keyof Object]
      );
    } else {
      const hashOfValueInSVC_b64 = base64url.encode(crypto.createHash('sha256')
        .update(sd_release[key as keyof Object] as unknown as string).digest());
      expect(sd_digests[key]).toBe(hashOfValueInSVC_b64);
    }
  });
}

describe('Structured SVC', () => {
  it('Create structured SVC', () => {
    const { sd_digests, svc } = createSVCandSDDigests(PAYLOAD, true);
    expect(sd_digests.address instanceof Object).toBe(true);
    expect(svc.sd_release.address instanceof Object).toBe(true);
    validateObjectsMirrorStructure(sd_digests, svc.sd_release);
    validateDigestOfSVCClaims(sd_digests, svc.sd_release)
  });

  it('Issue JWT-SD', async () => {
    const sdJwt: string = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, undefined, true);
    const splittedSdJwt = sdJwt.split('.');
    // Decoding
    const raw_svc = base64url.decode(splittedSdJwt[3]).toString();
    const svc = JSON.parse(raw_svc);
    const jwt = splittedSdJwt.slice(0, 3).join('.');

    // Verify JWT itself
    const jwtPayload = (await jwtVerify(jwt, ISSUER.PUBLIC_KEY)).payload;

    // sd_digests are hash of svc items
    validateDigestOfSVCClaims(jwtPayload.sd_digests as SD_DIGESTS, svc.sd_release)
  });
});