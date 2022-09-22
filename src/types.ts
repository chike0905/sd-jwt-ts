export type SD_JWTClaims = {
  [propName: string]: unknown
};

export type SD_DIGESTS = {
  [propName: string]: string
};

export type SVC = {
  sd_release: {
    [propName: string]: string
  }
};

export type SD_JWT_RELEASE = SVC;