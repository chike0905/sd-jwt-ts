import { base64url, jwtVerify, UnsecuredJWT } from "jose";
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
  TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY);
  TEST_SVC = JSON.parse(base64url.decode(TEST_SD_JWT.split('.')[3]).toString());
});

// 5.6 SD-JWT Release
// For each claim, an array of the salt and the claim value is contained in the sd_release object. The structure of sd_release object in the SD-JWT-R is the same as in SD-JWT.
it('Create SD-JWT Release', async () => {
  const discloseClaims = ['given_name', 'family_name'];

  const sdJwtRelease: string = await createSDJWTRelease(TEST_SVC, discloseClaims, HOLDER.PRIVATE_KEY);

  // NOTE: tmp SD-JWT-R is JWT (JWS that has encoded json as the payload)
  const { payload } = await jwtVerify(sdJwtRelease, HOLDER.PUBLIC_KEY);

  expect(payload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(payload.sd_release).toHaveProperty(item);
    // @ts-ignore
    expect(payload.sd_release[item]).toBe(TEST_SVC.sd_release[item]);
  });
});

it('Create SD-JWT Release without Signature', async () => {
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtRelease: string = await createSDJWTRelease(TEST_SVC, discloseClaims);

  const { payload } = UnsecuredJWT.decode(sdJwtRelease);
  expect(payload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(payload.sd_release).toHaveProperty(item);
    // @ts-ignore
    expect(payload.sd_release[item]).toBe(TEST_SVC.sd_release[item]);
  });
});


// 5.6
// When the holder sends the SD-JWT-R to the Verifier, the SD-JWT-R MUST be a JWS represented as the JWS Compact Serialization as described in Section 7.1 of [RFC7515].

const validateSdJWTwithRelease = async (
  sdJwtWithRelease: string,
  discloseClaims: string[],
  holderBinding: boolean = true
) => {
  // SD-JWT is combined jwt and sd-jwt-r;
  const splittedSdJwt = sdJwtWithRelease.split('.');
  expect(splittedSdJwt.length).toBe(6); // SD-JWT + SD-JWT-R as JWT
  if (!holderBinding)
    expect(splittedSdJwt[5]).toBe('');

  const sdJwt = splittedSdJwt.slice(0, 3).join('.');
  const sdJwtR = splittedSdJwt.slice(3).join('.');

  const sdJwtPayload = (await jwtVerify(sdJwt, ISSUER.PUBLIC_KEY)).payload;
  let sdJwtRPayload: SD_JWT_RELEASE;
  if (holderBinding) {
    sdJwtRPayload = (await jwtVerify(sdJwtR, HOLDER.PUBLIC_KEY)).payload as SD_JWT_RELEASE;
  } else {
    sdJwtRPayload = UnsecuredJWT.decode(sdJwtR).payload as SD_JWT_RELEASE;
  }

  expect(sdJwtRPayload).toHaveProperty('sd_release');
  discloseClaims.map((item) => {
    expect(sdJwtRPayload.sd_release).toHaveProperty(item);
  });

  discloseClaims.map((key) => {
    // @ts-ignore
    const hashOfValueInRelease_b64 = base64url.encode(crypto.createHash('sha256')
      .update(sdJwtRPayload.sd_release[key] as string).digest());
    expect((sdJwtPayload.sd_digests as SD_DIGESTS)[key]).toBe(hashOfValueInRelease_b64);
  });
};

it('Create SD-JWT with Release', async () => {
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtWithRelease: string =
    await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, HOLDER.PRIVATE_KEY);

  await validateSdJWTwithRelease(sdJwtWithRelease, discloseClaims);
});

it('Create SD-JWT with Release without Holder binding', async () => {
  const discloseClaims = ['given_name', 'family_name'];
  const sdJwtWithRelease: string =
    await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims);

  await validateSdJWTwithRelease(sdJwtWithRelease, discloseClaims, false);
});

it('Try to Create SD-JWT with Release by not bounded key', async () => {
  const discloseClaims = ['given_name', 'family_name'];

  await expect(createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, ISSUER.PRIVATE_KEY))
    .rejects.toThrow(
      new Error('Public key of the specified private key is not bounded to the SD-JWT.')
    );
});

it('Create not-holder-bounded SD-JWT with Release by a private key', async () => {
  const discloseClaims = ['given_name', 'family_name'];
  TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);
  const sdJwtWithRelease: string =
    await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims, HOLDER.PRIVATE_KEY);

  await validateSdJWTwithRelease(sdJwtWithRelease, discloseClaims);
});

it('Create not-holder-bounded SD-JWT with Release without private key', async () => {
  const discloseClaims = ['given_name', 'family_name'];

  TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY);
  const sdJwtWithRelease: string
    = await createSDJWTwithRelease(TEST_SD_JWT, discloseClaims);

  await validateSdJWTwithRelease(sdJwtWithRelease, discloseClaims, false);
});

it('Try to create SD-JWT-R with property is not included in SVC', async () => {
  const discloseClaims = ['undefined'];
  await expect(createSDJWTRelease(TEST_SVC, discloseClaims, HOLDER.PRIVATE_KEY))
    .rejects.toThrow(
      Error('Specified claim is not in SVC.')
    );
})


describe('Structured SD-JWT', () => {
  beforeEach(async () => {
    TEST_SD_JWT = await issueSDJWT(PAYLOAD, ISSUER.PRIVATE_KEY, HOLDER.PUBLIC_KEY, true);
    TEST_SVC = JSON.parse(base64url.decode(TEST_SD_JWT.split('.')[3]).toString());
  });
  it('Create SD-JWT-R with whole structured item', async () => {
    const discloseClaims = ['given_name', 'family_name', 'address'];

    const sdJwtRelease: string = await createSDJWTRelease(TEST_SVC, discloseClaims, HOLDER.PRIVATE_KEY);

    const { payload } = await jwtVerify(sdJwtRelease, HOLDER.PUBLIC_KEY);
    discloseClaims.map((item) => {
      expect(payload.sd_release).toHaveProperty(item);
      // @ts-ignore
      if (payload.sd_release[item] instanceof Object)
        // @ts-ignore
        expect(payload.sd_release[item]).toStrictEqual(TEST_SVC.sd_release[item]);
      else
        // @ts-ignore
        expect(payload.sd_release[item]).toBe(TEST_SVC.sd_release[item]);
    });
  });


  const validateStructuredSDJWTR =
    (svc: Object, sdJwtRelease: Object, claimPath: string) => {
      if (claimPath.split('.').length >= 2) {
        const toplevelProperty = claimPath.split('.')[0];
        const innerPath = claimPath.split('.').splice(1).join('.');
        expect(sdJwtRelease).toHaveProperty(toplevelProperty);
        validateStructuredSDJWTR(
          svc[toplevelProperty as keyof Object],
          sdJwtRelease[toplevelProperty as keyof Object],
          innerPath
        )
      } else {
        expect(svc[claimPath as keyof Object]).toBe(sdJwtRelease[claimPath as keyof Object]);
      }
    }

  it('Create SD-JWT-R with some of structured item', async () => {
    const discloseClaims = ['address.street_address'];

    const sdJwtRelease: string = await createSDJWTRelease(TEST_SVC, discloseClaims, HOLDER.PRIVATE_KEY);

    const { payload } = await jwtVerify(sdJwtRelease, HOLDER.PUBLIC_KEY);
    discloseClaims.map((item) => {
      validateStructuredSDJWTR(TEST_SVC.sd_release, payload.sd_release as Object, item)
    });
  });
  it('Try to create SD-JWT-R with property is not included in SVC', async () => {
    const discloseClaims = ['address.undefined'];
    await expect(createSDJWTRelease(TEST_SVC, discloseClaims, HOLDER.PRIVATE_KEY))
      .rejects.toThrow(
        Error('Specified claim is not in SVC.')
      );
  })
});