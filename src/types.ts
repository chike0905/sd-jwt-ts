import { KeyLike } from "jose";

export type SD_JWTClaims = {
  [propName: string]: string | SD_JWTClaims
};

export type SD_DIGESTS = {
  [propName: string]: string | SD_DIGESTS
};

export type SVC = {
  sd_release: SD_RELEASE
};

export type SD_RELEASE = {
  [key: string]: string | SD_RELEASE
}

export type SD_JWT_RELEASE = SVC;

export type HolderBinding = {
  holderKey: KeyLike,
  claims: {
    aud: string,
    nonce: string
  }
}