"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.verifySDJWTandSDJWTR = exports.verifySDJWTandSVC = void 0;
const jose_1 = require("jose");
const crypto = __importStar(require("crypto"));
const utils_1 = require("./utils");
// ref: https://www.iana.org/assignments/named-information/named-information.xhtml
// Accessed 2022.09.22
// TODO: make enum for hash name string
const HASH_NAME_STRING = ['Reserved', 'sha-256', 'sha-256-128', 'sha-256-120', 'sha-256-96', 'sha-256-64', 'sha-256-32', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'Unassigned', 'Reserved', 'Unassigned', 'blake2s-256', 'blake2b-256', 'blake2b-512', 'k12-256', 'k12-512'];
const validateMatchSdDigestAndSdRelease = (sd_digests, sd_release) => {
    Object.keys(sd_digests).map((key) => {
        if (!sd_release[key])
            throw new Error('Keys in sd_digests and in sd_release of SVC does not match.');
        // @ts-ignore
        if (sd_digests[key] instanceof Object)
            validateMatchSdDigestAndSdRelease(sd_digests[key], sd_release[key]);
    });
};
const validateHashInSdDigestAndSdRelease = (sd_digests, sd_release) => {
    Object.keys(sd_release).map((key) => {
        // @ts-ignore
        if (sd_digests[key] instanceof Object) {
            validateHashInSdDigestAndSdRelease(sd_digests[key], sd_release[key]);
        }
        else {
            const hashOfSdRelease = jose_1.base64url.encode(crypto.createHash('sha256')
                .update(sd_release[key]).digest());
            if (sd_digests[key] !== hashOfSdRelease)
                throw new Error('sd_digest does not match with hash of sd_release.');
        }
    });
};
// TODO: tmp support combined single string format for SD-JWT and SVC 
const verifySDJWTandSVC = (sdJwtWithSVC, publicKey) => __awaiter(void 0, void 0, void 0, function* () {
    const { svc, jwt } = (0, utils_1.separateJWTandSVC)(sdJwtWithSVC);
    // 4. Validate the SD-JWT:
    const sdJwtPayload = yield validateSdJWT(jwt, publicKey);
    // SVC format validation
    if (!svc.sd_release)
        throw new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ');
    // Validation of match between keys in sd_digest and in sd_release
    validateMatchSdDigestAndSdRelease(sdJwtPayload.sd_digests, svc.sd_release);
    // Validation of match between sd_digest and hash of sd_release
    validateHashInSdDigestAndSdRelease(sdJwtPayload.sd_digests, svc.sd_release);
    return true;
});
exports.verifySDJWTandSVC = verifySDJWTandSVC;
const checkClaimsInSDReleaseIncludedInSDDigests = (sd_digests, sd_release) => {
    Object.keys(sd_release).map((key) => {
        if (!sd_digests[key])
            throw new Error('SD-JWT does not includes claims in the SD-JWT-R.');
        // @ts-ignore
        if (sd_release[key] instanceof Object)
            checkClaimsInSDReleaseIncludedInSDDigests(sd_digests[key], sd_release[key]);
    });
};
const composeDiscloseClaimsFromSDRelease = (sd_release) => {
    let disclosedClaims = {};
    Object.keys(sd_release).map((key) => {
        if (sd_release[key] instanceof Object) {
            disclosedClaims[key] = composeDiscloseClaimsFromSDRelease(sd_release[key]);
        }
        else {
            let claimArray;
            try {
                claimArray = JSON.parse(sd_release[key]);
            }
            catch (e) {
                throw new Error('Claims in SD-JWT-R are not JSON-encoded.');
            }
            if (!Array.isArray(claimArray))
                throw new Error('Claims in SD-JWT-R are not JSON-encoded array.');
            if (claimArray.length !== 2)
                throw new Error('Claims in SD-JWT-R are not JSON-encoded of exactly two values.');
            Object.defineProperty(disclosedClaims, key, {
                value: claimArray[1],
                enumerable: true,
            });
        }
    });
    return disclosedClaims;
};
// 6.2 Verification by the Verifier when Receiving SD-JWT and SD-JWT-R
const verifySDJWTandSDJWTR = (sdJwtStr, IssuerPublicKey, holderPublicKey) => __awaiter(void 0, void 0, void 0, function* () {
    // 1. Determine if holder binding is to be checked for the SD-JWT. Refer to Section 7.6 for details.
    // NOTE: this process is implemented around validateSdJwtRelease() for 5-1
    // 2. Check that the presentation consists of six period-separated (.) elements; if holder binding is not required, the last element can be empty.
    // NOTE: this process is implemented in separateJWTandSDJWTR()
    // 3. Separate the SD-JWT from the SD-JWT Release.
    const { sdJwt, sdJwtR } = (0, utils_1.separateJWTandSDJWTR)(sdJwtStr);
    // 4. Validate the SD-JWT:
    const sdJwtPayload = yield validateSdJWT(sdJwt, IssuerPublicKey);
    // 5. Validate the SD-JWT Release:
    // 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
    // TODO: tmp Keys for SD-JWT-R is specified in sub_jwk in SD-JWT payload.
    // If holderPublicKey is provided, override it.
    let boundedKey;
    if (sdJwtPayload.hasOwnProperty('sub_jwk'))
        boundedKey = (yield (0, jose_1.importJWK)(sdJwtPayload.sub_jwk, 'ES256'));
    if (holderPublicKey)
        boundedKey = holderPublicKey;
    const sdJwtReleasePayload = yield validateSdJwtRelease(sdJwtR, boundedKey);
    // 5-2. For each claim in the SD-JWT Release:
    checkClaimsInSDReleaseIncludedInSDDigests(sdJwtPayload.sd_digests, sdJwtReleasePayload.sd_release);
    const disclosedClaimsInRelease = sdJwtReleasePayload.sd_release;
    // 5-2-2. Compute the base64url-encoded hash of a claim revealed from the Holder using the claim value and the salt included in the SD-JWT-R and the hash_alg in SD-JWT.
    // 5-2-3. Compare the hash digests computed in the previous step with the one of the same claim in the SD-JWT. Accept the claim only when the two hash digests match.
    validateHashInSdDigestAndSdRelease(sdJwtPayload.sd_digests, sdJwtReleasePayload.sd_release);
    // 5-2-4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded array of exactly two values.
    // 5-2-4. Store the second of the two values.
    let payload = composeDiscloseClaimsFromSDRelease(sdJwtReleasePayload.sd_release);
    return payload;
});
exports.verifySDJWTandSDJWTR = verifySDJWTandSDJWTR;
// NOTE: This is too sample implementation: just validate signature and check existence of sd_release claim.
// The validation process in the specification is bellow.
// 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
// 5-1-1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
// 5-1-2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a nonce and aud field within the SD-JWT Release.
const validateSdJwtRelease = (sdJwtRelease, publicKey) => __awaiter(void 0, void 0, void 0, function* () {
    let sdJwtReleasePayload;
    const separated = sdJwtRelease.split('.');
    if (separated[2] === '') {
        // SD-JWT-R is not signed.
        sdJwtReleasePayload = jose_1.UnsecuredJWT.decode(sdJwtRelease).payload;
    }
    else {
        // Signature validation
        if (!publicKey)
            throw new Error('SD-JWT-R is signed, but does not be provided a key for validate it.');
        try {
            sdJwtReleasePayload = (yield (0, jose_1.jwtVerify)(sdJwtRelease, publicKey)).payload;
        }
        catch (e) {
            throw new Error('JWT signature in SD-JWT-R is invalid');
        }
    }
    if (!sdJwtReleasePayload.sd_release)
        throw new Error('The payload of an SD-JWT-R MUST contain the sd_release claim.');
    return sdJwtReleasePayload;
});
const validateSdJWT = (sdJwt, publicKey) => __awaiter(void 0, void 0, void 0, function* () {
    // 4-1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details.
    // 4-2. Validate the signature over the SD-JWT.
    // 4-3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
    // 4-4. Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT.
    let sdJwtPayload;
    try {
        sdJwtPayload = (yield (0, jose_1.jwtVerify)(sdJwt, publicKey)).payload;
    }
    catch (e) {
        throw new Error('JWT signature in SD-JWT is invalid');
    }
    // 4-5. Check that the claim sd_digests is present in the SD-JWT.
    if (!sdJwtPayload.sd_digests || !sdJwtPayload.hash_alg)
        throw new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.');
    // 4-6. Check that the hash_alg claim is present and its value is understand and the hash algorithm is deemed secure.
    if (!HASH_NAME_STRING.includes(sdJwtPayload.hash_alg))
        throw new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.');
    return sdJwtPayload;
});
const strArrayEqual = (arr1, arr2) => {
    if (arr1.length !== arr2.length)
        return false;
    for (let i = 0; i < arr1.length; i++) {
        if (arr1[i] !== arr2[i])
            return false;
    }
    return true;
};
//# sourceMappingURL=verify.js.map