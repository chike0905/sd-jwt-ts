import { KeyLike } from "jose";
export declare const verifySDJWTandSVC: (sdJwtWithSVC: string, publicKey: KeyLike) => Promise<boolean>;
export declare const verifySDJWTandSDJWTR: (sdJwtStr: string, IssuerPublicKey: KeyLike, holderPublicKey?: KeyLike) => Promise<{}>;
//# sourceMappingURL=verify.d.ts.map