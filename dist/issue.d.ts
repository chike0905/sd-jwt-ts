import { KeyLike } from 'jose';
import { SD_DIGESTS, SD_JWTClaims, SVC } from './types';
export declare const issueSDJWT: (claims: SD_JWTClaims, privateKey: KeyLike, holderPublicKey?: KeyLike, structured?: boolean) => Promise<string>;
export declare const createSVCandSDDigests: (claims: SD_JWTClaims, structured?: boolean) => {
    sd_digests: SD_DIGESTS;
    svc: SVC;
};
//# sourceMappingURL=issue.d.ts.map