import { base64url } from "jose";
import { SVC } from "./types";

export const separateJWTandSVC = (sd_jwt: string): { svc: SVC, jwt: string } => {
  const splitted_sd_jwt = sd_jwt.split('.');
  if (splitted_sd_jwt.length !== 4)
    throw new Error('sd_jwt string should consist of 4 strings separated by comma.');

  const raw_svc = base64url.decode(splitted_sd_jwt[3]).toString();
  const svc = JSON.parse(raw_svc) as SVC;
  const jwt = splitted_sd_jwt.slice(0, 3).join('.');
  return { svc, jwt }
};

export const separateJWTandSDJWTR = (sd_jwt: string): { sdJwt: string, sdJwtR: string } => {
  const splittedSdJwt = sd_jwt.split('.');
  if (splittedSdJwt.length !== 6)
    throw new Error('sd_jwt string should be presented as 6 strings separated by comma.');

  const sdJwt = splittedSdJwt.slice(0, 3).join('.');
  const sdJwtR = splittedSdJwt.slice(3).join('.');

  return { sdJwt, sdJwtR }
};

