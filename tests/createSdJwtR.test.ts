import { base64url, compactVerify, decodeJwt, importJWK, jwtVerify, KeyLike } from "jose";
import * as crypto from 'crypto';

import { createSVCandSDDigests, SD_DIGESTS, SD_JWT_RELEASE } from "../src";
import { createSDJWTRelease, createSDJWTwithRelease } from "../src/createSdJwtR";

import { PAYLOAD, PRIVATE_KEY_JWK, PUBLIC_KEY_JWK, SAMPLE_SD_JWT } from "./params";

// 5.6 SD-JWT Release
// For each claim, an array of the salt and the claim value is contained in the sd_release object. The structure of sd_release object in the SD-JWT-R is the same as in SD-JWT.
it('Create SD-JWT Release', async () => {
  const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
  const { svc } = createSVCandSDDigests(PAYLOAD);
  const discloseClaims = ['given_name', 'family_name'];

  const sdJwtRelease: string = await createSDJWTRelease(svc, discloseClaims, privKey);

  // const splittedSdJwtR = sdJwtRelease.split('.');
  // expect(splittedSdJwtR.length).toBe(3);

  const pubkey = await importJWK(PUBLIC_KEY_JWK, 'ES256') as KeyLike;
  // NOTE: tmp SD-JWT-R is JWT (JWS that has encoded json as the payload)
  const { payload, protectedHeader } = await jwtVerify(sdJwtRelease, pubkey);

  expect(payload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(payload.sd_release).toHaveProperty(item);
    // @ts-ignore
    expect(payload.sd_release[item]).toBe(svc.sd_release[item]);
  });
});

// TODO: Holder Binding
// 5.6
// When the holder sends the SD-JWT-R to the Verifier, the SD-JWT-R MUST be a JWS represented as the JWS Compact Serialization as described in Section 7.1 of [RFC7515].
it('Create SD-JWT with Release', async () => {
  const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256') as KeyLike;
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtWithRelease: string =
    await createSDJWTwithRelease(SAMPLE_SD_JWT, discloseClaims, privKey);

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