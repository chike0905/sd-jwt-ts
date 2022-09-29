import { KeyLike } from "jose";
import { SVC } from "./types";
export declare const createSDJWTRelease: (svc: SVC, discloseClaims: string[], privateKey?: KeyLike) => Promise<string>;
export declare const createSDJWTwithRelease: (sdJwt: string, discloseClaims: string[], HolderPrivateKey?: KeyLike) => Promise<string>;
//# sourceMappingURL=createSdJwtR.d.ts.map