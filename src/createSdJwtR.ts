import { base64url } from "jose";
import { SVC, SD_JWT_RELEASE } from "./types";
import { separateJWTandSVC } from "./utils";

export const createSDJWTRelease = (svc: SVC, discloseClaims: string[]): SD_JWT_RELEASE => {
  let sd_jwt_release: SD_JWT_RELEASE = {
    sd_release: {}
  };

  discloseClaims.map((item) => {
    Object.defineProperty(sd_jwt_release.sd_release, item, {
      value: svc.sd_release[item],
      enumerable: true,
    });
  });

  return sd_jwt_release;
}

export const createSDJWTwithRelease = (sdJwt: string, discloseClaims: string[]): string => {
  const { svc, jwt } = separateJWTandSVC(sdJwt);

  const release = createSDJWTRelease(svc, discloseClaims);
  const encodedRelease = base64url.encode(JSON.stringify(release));

  return jwt + '.' + encodedRelease;
}