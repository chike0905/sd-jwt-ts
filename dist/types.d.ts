export declare type SD_JWTClaims = {
    [propName: string]: unknown;
};
export declare type SD_DIGESTS = {
    [propName: string]: string | SD_DIGESTS;
};
export declare type SVC = {
    sd_release: SD_RELEASE;
};
export declare type SD_RELEASE = {
    [key: string]: string | SD_RELEASE;
};
export declare type SD_JWT_RELEASE = SVC;
//# sourceMappingURL=types.d.ts.map