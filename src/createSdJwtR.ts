import { base64url, CompactSign, KeyLike, SignJWT } from "jose";
import { SVC, SD_JWT_RELEASE } from "./types";
import { separateJWTandSVC } from "./utils";

export const createSDJWTRelease = async (
  svc: SVC,
  discloseClaims: string[],
  privateKey: KeyLike
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
  const sdJwtRelease = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey);

  return sdJwtRelease;
}

export const createSDJWTwithRelease = async (
  sdJwt: string,
  discloseClaims: string[],
  privateKey: KeyLike
): Promise<string> => {
  const { svc, jwt } = separateJWTandSVC(sdJwt);

  const release = await createSDJWTRelease(svc, discloseClaims, privateKey);
  // const encodedRelease = base64url.encode(JSON.stringify(release));

  return jwt + '.' + release;
}