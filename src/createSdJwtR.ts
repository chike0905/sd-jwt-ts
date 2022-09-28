import { base64url, CompactSign, decodeJwt, importJWK, JWK, jwtVerify, KeyLike, SignJWT, UnsecuredJWT } from "jose";
import * as crypto from 'crypto';
import { SVC, SD_JWT_RELEASE } from "./types";
import { separateJWTandSVC } from "./utils";

export const createSDJWTRelease = async (
  svc: SVC,
  discloseClaims: string[],
  privateKey?: KeyLike
): Promise<string> => {
  let payload: SD_JWT_RELEASE = {
    sd_release: {}
  };

  discloseClaims.map((item) => {
    Object.defineProperty(payload.sd_release, item, {
      value: svc.sd_release[item],
      enumerable: true,
    });
  });

  // NOTE: tmp SD-JWT-R is JWT (JWS that has encoded json as the payload)
  let sdJwtRelease: string
  if (privateKey) {
    sdJwtRelease = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privateKey);
  } else {
    sdJwtRelease = new UnsecuredJWT(payload).encode();
  }

  return sdJwtRelease;
}

export const createSDJWTwithRelease = async (
  sdJwt: string,
  discloseClaims: string[],
  HolderPrivateKey?: KeyLike
): Promise<string> => {
  const { svc, jwt } = separateJWTandSVC(sdJwt);

  const release = await createSDJWTRelease(svc, discloseClaims, HolderPrivateKey);
  // const encodedRelease = base64url.encode(JSON.stringify(release));

  // NOTE: Temporary implementation for holder binding 
  // if SD-JWT includes sub_jwk, only the key specified in sub_jwk can create signed SD-JWT-R. 
  // It is able to create unsigned SD-JWT-R even if the SD-JWT includes sub_jwk. 
  const jwtPayload = decodeJwt(jwt);
  let boundedKey: KeyLike;
  if (jwtPayload.hasOwnProperty('sub_jwk') && HolderPrivateKey) {
    boundedKey = await importJWK(jwtPayload.sub_jwk as JWK, 'ES256') as KeyLike;
    try {
      await jwtVerify(release, boundedKey);
    } catch (e) {
      throw new Error('Public key of the specified private key is not bounded to the SD-JWT.');
    }
  }

  return jwt + '.' + release;
}