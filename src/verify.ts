import { base64url, importJWK, JWK, JWTPayload, jwtVerify, KeyLike, UnsecuredJWT } from "jose";
import * as crypto from 'crypto';
import { SD_DIGESTS, SD_JWT_RELEASE, SD_RELEASE, SVC } from "./types";
import { separateJWTandSDJWTR, separateJWTandSVC } from "./utils";

// ref: https://www.iana.org/assignments/named-information/named-information.xhtml
// Accessed 2022.09.22
// TODO: make enum for hash name string
const HASH_NAME_STRING = ['Reserved', 'sha-256', 'sha-256-128', 'sha-256-120', 'sha-256-96', 'sha-256-64', 'sha-256-32', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'Unassigned', 'Reserved', 'Unassigned', 'blake2s-256', 'blake2b-256', 'blake2b-512', 'k12-256', 'k12-512'];

const validateMatchSdDigestAndSdRelease =
  (sd_digests: SD_DIGESTS, sd_release: SD_RELEASE) => {
    Object.keys(sd_digests).map((key) => {
      if (!sd_release[key])
        throw new Error('Keys in sd_digests and in sd_release of SVC does not match.');
      // @ts-ignore
      if (sd_digests[key] instanceof Object)
        validateMatchSdDigestAndSdRelease(
          sd_digests[key] as SD_DIGESTS,
          sd_release[key] as SD_RELEASE
        )
    });
  }

const validateHashInSdDigestAndSdRelease =
  (sd_digests: SD_DIGESTS, sd_release: SD_RELEASE) => {
    Object.keys(sd_release).map((key) => {
      // @ts-ignore
      if (sd_digests[key] instanceof Object) {
        validateHashInSdDigestAndSdRelease(
          sd_digests[key] as SD_DIGESTS,
          sd_release[key] as SD_RELEASE
        )
      } else {
        const hashOfSdRelease = base64url.encode(crypto.createHash('sha256')
          .update(sd_release[key] as string).digest());
        if (sd_digests[key] !== hashOfSdRelease)
          throw new Error('sd_digest does not match with hash of sd_release.');
      }
    });
  }

// TODO: tmp support combined single string format for SD-JWT and SVC 
export const verifySDJWTandSVC = async (sdJwtWithSVC: string, publicKey: KeyLike):
  Promise<boolean> => {
  const { svc, jwt } = separateJWTandSVC(sdJwtWithSVC);

  // 4. Validate the SD-JWT:
  const sdJwtPayload = await validateSdJWT(jwt, publicKey);

  // SVC format validation
  if (!svc.sd_release)
    throw new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ')

  // Validation of match between keys in sd_digest and in sd_release
  validateMatchSdDigestAndSdRelease(sdJwtPayload.sd_digests as SD_DIGESTS, svc.sd_release);

  // Validation of match between sd_digest and hash of sd_release
  validateHashInSdDigestAndSdRelease(sdJwtPayload.sd_digests as SD_DIGESTS, svc.sd_release);

  return true;
};

const checkClaimsInSDReleaseIncludedInSDDigests =
  (sd_digests: SD_DIGESTS, sd_release: SD_RELEASE) => {
    Object.keys(sd_release).map((key) => {
      if (!sd_digests[key])
        throw new Error('SD-JWT does not includes claims in the SD-JWT-R.');
      // @ts-ignore
      if (sd_release[key] instanceof Object)
        checkClaimsInSDReleaseIncludedInSDDigests(
          sd_digests[key] as SD_DIGESTS,
          sd_release[key] as SD_RELEASE
        )
    });
  }

type DISCLOSED_CLAIM = {
  [key: string]: string | DISCLOSED_CLAIM
}

const composeDiscloseClaimsFromSDRelease = (sd_release: SD_RELEASE): DISCLOSED_CLAIM => {
  let disclosedClaims: DISCLOSED_CLAIM = {};
  Object.keys(sd_release).map((key) => {
    if (sd_release[key] instanceof Object) {
      disclosedClaims[key] = composeDiscloseClaimsFromSDRelease(sd_release[key] as SD_RELEASE);
    } else {
      let claimArray;
      try {
        claimArray = JSON.parse(sd_release[key] as string);
      } catch (e) {
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
export const verifySDJWTandSDJWTR = async (sdJwtStr: string, IssuerPublicKey: KeyLike, holderPublicKey?: KeyLike):
  Promise<{}> => {
  // 1. Determine if holder binding is to be checked for the SD-JWT. Refer to Section 7.6 for details.
  // NOTE: this process is implemented around validateSdJwtRelease() for 5-1
  // 2. Check that the presentation consists of six period-separated (.) elements; if holder binding is not required, the last element can be empty.
  // NOTE: this process is implemented in separateJWTandSDJWTR()

  // 3. Separate the SD-JWT from the SD-JWT Release.
  const { sdJwt, sdJwtR } = separateJWTandSDJWTR(sdJwtStr);

  // 4. Validate the SD-JWT:
  const sdJwtPayload = await validateSdJWT(sdJwt, IssuerPublicKey);

  // 5. Validate the SD-JWT Release:

  // 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:

  // TODO: tmp Keys for SD-JWT-R is specified in sub_jwk in SD-JWT payload.
  // If holderPublicKey is provided, override it.
  let boundedKey: KeyLike | undefined;
  if (sdJwtPayload.hasOwnProperty('sub_jwk'))
    boundedKey = await importJWK(sdJwtPayload.sub_jwk as JWK, 'ES256') as KeyLike;
  if (holderPublicKey)
    boundedKey = holderPublicKey

  const sdJwtReleasePayload = await validateSdJwtRelease(sdJwtR, boundedKey);

  // 5-2. For each claim in the SD-JWT Release:
  checkClaimsInSDReleaseIncludedInSDDigests(
    sdJwtPayload.sd_digests as SD_DIGESTS,
    sdJwtReleasePayload.sd_release as SD_RELEASE
  );
  const disclosedClaimsInRelease = (sdJwtReleasePayload as SD_JWT_RELEASE).sd_release;

  // 5-2-2. Compute the base64url-encoded hash of a claim revealed from the Holder using the claim value and the salt included in the SD-JWT-R and the hash_alg in SD-JWT.
  // 5-2-3. Compare the hash digests computed in the previous step with the one of the same claim in the SD-JWT. Accept the claim only when the two hash digests match.
  validateHashInSdDigestAndSdRelease(
    sdJwtPayload.sd_digests as SD_DIGESTS,
    sdJwtReleasePayload.sd_release as SD_RELEASE
  );

  // 5-2-4. Ensure that the claim value in the SD-JWT-R is a JSON-encoded array of exactly two values.
  // 5-2-4. Store the second of the two values.
  let payload =
    composeDiscloseClaimsFromSDRelease(sdJwtReleasePayload.sd_release as SD_RELEASE);

  return payload;
}

// NOTE: This is too sample implementation: just validate signature and check existence of sd_release claim.
// The validation process in the specification is bellow.
// 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
// 5-1-1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
// 5-1-2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a nonce and aud field within the SD-JWT Release.
const validateSdJwtRelease = async (sdJwtRelease: string, publicKey?: KeyLike):
  Promise<JWTPayload> => {

  let sdJwtReleasePayload: JWTPayload
  const separated = sdJwtRelease.split('.');
  if (separated[2] === '') {
    // SD-JWT-R is not signed.
    sdJwtReleasePayload = UnsecuredJWT.decode(sdJwtRelease).payload;
  } else {
    // Signature validation
    if (!publicKey)
      throw new Error('SD-JWT-R is signed, but does not be provided a key for validate it.');
    try {
      sdJwtReleasePayload = (await jwtVerify(sdJwtRelease, publicKey)).payload;
    } catch (e) {
      throw new Error('JWT signature in SD-JWT-R is invalid');
    }
  }
  if (!sdJwtReleasePayload.sd_release)
    throw new Error('The payload of an SD-JWT-R MUST contain the sd_release claim.');

  return sdJwtReleasePayload;
}

const validateSdJWT = async (sdJwt: string, publicKey: KeyLike): Promise<JWTPayload> => {
  // 4-1. Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1 and 3.2 for details.
  // 4-2. Validate the signature over the SD-JWT.
  // 4-3. Validate the issuer of the SD-JWT and that the signing key belongs to this issuer.
  // 4-4. Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT.
  let sdJwtPayload: JWTPayload
  try {
    sdJwtPayload = (await jwtVerify(sdJwt, publicKey)).payload;
  } catch (e) {
    throw new Error('JWT signature in SD-JWT is invalid');
  }

  // 4-5. Check that the claim sd_digests is present in the SD-JWT.
  if (!sdJwtPayload.sd_digests || !sdJwtPayload.hash_alg)
    throw new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.');

  // 4-6. Check that the hash_alg claim is present and its value is understand and the hash algorithm is deemed secure.
  if (!HASH_NAME_STRING.includes(sdJwtPayload.hash_alg as string))
    throw new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.');

  return sdJwtPayload;
}

const strArrayEqual = (arr1: string[], arr2: string[]): boolean => {
  if (arr1.length !== arr2.length) return false;
  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }
  return true;
}

