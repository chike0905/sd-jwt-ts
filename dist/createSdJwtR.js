"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSDJWTwithRelease = exports.createSDJWTRelease = void 0;
const jose_1 = require("jose");
const utils_1 = require("./utils");
const composeSDJWTRPayload = (claimPath, svc, sd_release) => {
    if (claimPath.split('.').length >= 2) {
        const toplevelProperty = claimPath.split('.')[0];
        const innerPath = claimPath.split('.').splice(1).join('.');
        Object.defineProperty(sd_release, toplevelProperty, {
            value: {},
            enumerable: true,
            writable: true
        });
        sd_release[toplevelProperty] = composeSDJWTRPayload(innerPath, svc[toplevelProperty], sd_release[toplevelProperty]);
    }
    else {
        if (svc[claimPath] === undefined)
            throw new Error('Specified claim is not in SVC.');
        Object.defineProperty(sd_release, claimPath, {
            value: svc[claimPath],
            enumerable: true,
        });
    }
    return sd_release;
};
const createSDJWTRelease = (svc, discloseClaims, privateKey) => __awaiter(void 0, void 0, void 0, function* () {
    let payload = {
        sd_release: {}
    };
    let sd_release = {};
    discloseClaims.map((item) => {
        sd_release = composeSDJWTRPayload(item, svc.sd_release, sd_release);
    });
    payload.sd_release = sd_release;
    // NOTE: tmp SD-JWT-R is JWT (JWS that has encoded json as the payload)
    let sdJwtRelease;
    if (privateKey) {
        sdJwtRelease = yield new jose_1.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privateKey);
    }
    else {
        sdJwtRelease = new jose_1.UnsecuredJWT(payload).encode();
    }
    return sdJwtRelease;
});
exports.createSDJWTRelease = createSDJWTRelease;
const createSDJWTwithRelease = (sdJwt, discloseClaims, HolderPrivateKey) => __awaiter(void 0, void 0, void 0, function* () {
    const { svc, jwt } = (0, utils_1.separateJWTandSVC)(sdJwt);
    const release = yield (0, exports.createSDJWTRelease)(svc, discloseClaims, HolderPrivateKey);
    // const encodedRelease = base64url.encode(JSON.stringify(release));
    // NOTE: Temporary implementation for holder binding 
    // if SD-JWT includes sub_jwk, only the key specified in sub_jwk can create signed SD-JWT-R. 
    // It is able to create unsigned SD-JWT-R even if the SD-JWT includes sub_jwk. 
    const jwtPayload = (0, jose_1.decodeJwt)(jwt);
    let boundedKey;
    if (jwtPayload.hasOwnProperty('sub_jwk') && HolderPrivateKey) {
        boundedKey = (yield (0, jose_1.importJWK)(jwtPayload.sub_jwk, 'ES256'));
        try {
            yield (0, jose_1.jwtVerify)(release, boundedKey);
        }
        catch (e) {
            throw new Error('Public key of the specified private key is not bounded to the SD-JWT.');
        }
    }
    return jwt + '.' + release;
});
exports.createSDJWTwithRelease = createSDJWTwithRelease;
//# sourceMappingURL=createSdJwtR.js.map