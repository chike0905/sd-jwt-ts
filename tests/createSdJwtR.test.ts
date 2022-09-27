import { base64url, decodeJwt, jwtVerify } from "jose";
import * as crypto from 'crypto';

import { PAYLOAD, importKeyPairForIssuerAndHolder, Entity } from "./params";

import { issueSDJWT, SD_DIGESTS, SD_JWT_RELEASE, SVC } from "../src";
import { createSDJWTRelease, createSDJWTwithRelease } from "../src/createSdJwtR";



let ISSUER: Entity;
let HOLDER: Entity;

let TEST_SD_JWT: string;
let TEST_SVC: SVC;

beforeEach(async () => {
  ({ ISSUER, HOLDER } = await importKeyPairForIssuerAndHolder());
  TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);
  TEST_SVC = JSON.parse(base64url.decode(TEST_SD_JWT.split('.')[3]).toString());
});

// 5.6 SD-JWT Release
// For each claim, an array of the salt and the claim value is contained in the sd_release object. The structure of sd_release object in the SD-JWT-R is the same as in SD-JWT.
it('Create SD-JWT Release', async () => {
  // const { svc } = createSVCandSDDigests(PAYLOAD);
  const discloseClaims = ['given_name', 'family_name'];

  const sdJwtRelease: string = await createSDJWTRelease(TEST_SVC, discloseClaims, ISSUER.PRIVATE_KEY);

  // NOTE: tmp SD-JWT-R is JWT (JWS that has encoded json as the payload)
  const { payload } = await jwtVerify(sdJwtRelease, ISSUER.PUBLIC_KEY);

  expect(payload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(payload.sd_release).toHaveProperty(item);
    // @ts-ignore
    expect(payload.sd_release[item]).toBe(TEST_SVC.sd_release[item]);
  });
});

// TODO: Holder Binding
// 5.6
// When the holder sends the SD-JWT-R to the Verifier, the SD-JWT-R MUST be a JWS represented as the JWS Compact Serialization as described in Section 7.1 of [RFC7515].
it('Create SD-JWT with Release', async () => {
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtWithRelease: string =
    await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, ISSUER.PRIVATE_KEY);

  // SD-JWT is combined jwt and sd-jwt-r;
  const splittedSdJwt = sdJwtWithRelease.split('.');
  expect(splittedSdJwt.length).toBe(6); // SD-JWT + SD-JWT-R as JWT

  const sdJwt = splittedSdJwt.slice(0, 3).join('.');
  const sdJwtR = splittedSdJwt.slice(3).join('.');

  const sdJwtPayload = decodeJwt(sdJwt);
  const sdJwtRPayload = decodeJwt(sdJwtR) as SD_JWT_RELEASE;

  expect(sdJwtRPayload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(sdJwtRPayload.sd_release).toHaveProperty(item);
  });

  discloseClaims.map((key) => {
    // @ts-ignore
    const hashOfValueInRelease_b64 = base64url.encode(crypto.createHash('sha256')
      .update(sdJwtRPayload.sd_release[key]).digest());
    expect((sdJwtPayload.sd_digests as SD_DIGESTS)[key]).toBe(hashOfValueInRelease_b64);
  });
});