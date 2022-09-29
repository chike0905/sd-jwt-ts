import { decodeJwt, importJWK, JWK, jwtVerify, KeyLike, SignJWT, UnsecuredJWT } from "jose";
import { SVC, SD_JWT_RELEASE, SD_RELEASE } from "./types";
import { separateJWTandSVC } from "./utils";

const composeSDJWTRPayload =
  (claimPath: string, svc: Object, sd_release: SD_RELEASE): SD_RELEASE => {
    if (claimPath.split('.').length >= 2) {
      const toplevelProperty = claimPath.split('.')[0];
      const innerPath = claimPath.split('.').splice(1).join('.');

      Object.defineProperty(sd_release, toplevelProperty, {
        value: {},
        enumerable: true,
        writable: true
      });
      sd_release[toplevelProperty] = composeSDJWTRPayload(
        innerPath,
        svc[toplevelProperty as keyof Object],
        sd_release[toplevelProperty] as SD_RELEASE
      )
    } else {
      if (svc[claimPath as keyof Object] === undefined)
        throw new Error('Specified claim is not in SVC.');

      Object.defineProperty(sd_release, claimPath, {
        value: svc[claimPath as keyof Object],
        enumerable: true,
      });
    }
    return sd_release
  }


export const createSDJWTRelease = async (
  svc: SVC,
  discloseClaims: string[],
  privateKey?: KeyLike
): Promise<string> => {
  let payload: SD_JWT_RELEASE = {
    sd_release: {}
  };

  let sd_release: SD_RELEASE = {};
  discloseClaims.map((item) => {
    sd_release = composeSDJWTRPayload(item, svc.sd_release, sd_release);
  });
  payload.sd_release = sd_release;

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
  sdJwtWithSVC: string,
  disclosedClaims: string[],
  holderPrivateKey?: KeyLike
): Promise<string> => {
  const { svc, jwt } = separateJWTandSVC(sdJwtWithSVC);

  const release = await createSDJWTRelease(svc, disclosedClaims, holderPrivateKey);
  // const encodedRelease = base64url.encode(JSON.stringify(release));

  // NOTE: Temporary implementation for holder binding 
  // if SD-JWT includes sub_jwk, only the key specified in sub_jwk can create signed SD-JWT-R. 
  // It is able to create unsigned SD-JWT-R even if the SD-JWT includes sub_jwk. 
  const jwtPayload = decodeJwt(jwt);
  let boundedKey: KeyLike;
  if (jwtPayload.hasOwnProperty('sub_jwk') && holderPrivateKey) {
    boundedKey = await importJWK(jwtPayload.sub_jwk as JWK, 'ES256') as KeyLike;
    try {
      await jwtVerify(release, boundedKey);
    } catch (e) {
      throw new Error('Public key of the specified private key is not bounded to the SD-JWT.');
    }
  }

  return jwt + '.' + release;
}