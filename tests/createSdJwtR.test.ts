import { base64url, decodeJwt } from "jose";
import * as crypto from 'crypto';

import { createSVCandSDDigests, SD_DIGESTS } from "../src";
import { createSDJWTRelease, createSDJWTwithRelease } from "../src/createSdJwtR";

import { PAYLOAD, SAMPLE_SD_JWT } from "./params";

// 5.6 SD-JWT Release
// For each claim, an array of the salt and the claim value is contained in the sd_release object. The structure of sd_release object in the SD-JWT-R is the same as in SD-JWT.
it('Create SD-JWT Release', () => {
  const { svc } = createSVCandSDDigests(PAYLOAD);
  const discloseClaims = ['given_name', 'family_name'];
  const sd_jwt_release = createSDJWTRelease(svc, discloseClaims);
  expect(sd_jwt_release).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(sd_jwt_release.sd_release).toHaveProperty(item);
    expect(sd_jwt_release.sd_release[item]).toBe(svc.sd_release[item]);
  });
});

// TODO: Holder Binding
// TODO: missing MUST specification bellow
// 5.6
// When the holder sends the SD-JWT-R to the Verifier, the SD-JWT-R MUST be a JWS represented as the JWS Compact Serialization as described in Section 7.1 of [RFC7515].
it('Create SD-JWT with Release', () => {
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtWithRelease: string = createSDJWTwithRelease(SAMPLE_SD_JWT, discloseClaims);

  // SD-JWT is combined jwt and sd-jwt-r;
  const splittedSdJwt = sdJwtWithRelease.split('.');
  expect(splittedSdJwt.length).toBe(4);

  const rawRelease = base64url.decode(splittedSdJwt[3]).toString();
  const release = JSON.parse(rawRelease);
  const jwt = splittedSdJwt.slice(0, 3).join('.');
  const payload = decodeJwt(jwt);

  expect(release).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(release.sd_release).toHaveProperty(item);
  });

  discloseClaims.map((key) => {
    const hashOfValueInRelease_b64 = base64url.encode(crypto.createHash('sha256')
      .update(release.sd_release[key]).digest());
    expect((payload.sd_digests as SD_DIGESTS)[key]).toBe(hashOfValueInRelease_b64);
  });
});