import { base64url, JWTPayload, jwtVerify, KeyLike } from "jose";
import * as crypto from 'crypto';
import { SD_DIGESTS, SVC } from "./types";
import { separateJWTandSDJWTR, separateJWTandSVC } from "./utils";

// ref: https://www.iana.org/assignments/named-information/named-information.xhtml
// Accessed 2022.09.22
// TODO: make enum for hash name string
const HASH_NAME_STRING = ['Reserved', 'sha-256', 'sha-256-128', 'sha-256-120', 'sha-256-96', 'sha-256-64', 'sha-256-32', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'Unassigned', 'Reserved', 'Unassigned', 'blake2s-256', 'blake2b-256', 'blake2b-512', 'k12-256', 'k12-512'];

// TODO: tmp support combined single string format for SD-JWT and SVC 
export const verifySDJWTandSVC = async (sdJwtWithSVC: string, publicKey: KeyLike):
  Promise<boolean> => {
  const { svc, jwt } = separateJWTandSVC(sdJwtWithSVC);

  // 4. Validate the SD-JWT:
  const sdJwtPayload = await validateSdJWT(jwt, publicKey);

  // SVC format validation
  if (!svc.sd_release)
    throw new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ')

  // @ts-ignore
  if (!strArrayEqual(Object.keys(sdJwtPayload.sd_digests), Object.keys(svc.sd_release)))
    throw new Error('Keys in sd_digests and sd_release of SVC does not match.');

  // Validation of match between sd_digest and hash of sd_release
  // @ts-ignore
  Object.keys(sdJwtPayload.sd_digests).map((key) => {
    const hashOfSdRelease = base64url.encode(crypto.createHash('sha256')
      .update(svc.sd_release[key]).digest());
    if ((sdJwtPayload.sd_digests as SD_DIGESTS)[key] !== hashOfSdRelease)
      throw new Error('sd_digest does not match with hash of sd_release.');
  });

  return true;
};

// 6.2 Verification by the Verifier when Receiving SD-JWT and SD-JWT-R
export const verifySDJWTandSDJWTR = async (sdJwtStr: string, publicKey: KeyLike):
  Promise<boolean> => {
  // TODO: holder binding
  // 1. Determine if holder binding is to be checked for the SD-JWT. Refer to Section 7.6 for details.
  // 2. Check that the presentation consists of six period-separated (.) elements; if holder binding is not required, the last element can be empty.

  // 3. Separate the SD-JWT from the SD-JWT Release.
  const { sdJwt, sdJwtR } = separateJWTandSDJWTR(sdJwtStr);

  // 4. Validate the SD-JWT:
  const sdJwtPayload = await validateSdJWT(sdJwt, publicKey);

  // 5. Validate the SD-JWT Release:
  // TODO: tmp Keys for SD-JWT and for SD-JWT-R are same.
  // 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
  const sdJwtReleasePayload = await validateSdJwtRelease(sdJwtR, publicKey);

  // 5-2. For each claim in the SD-JWT Release:


  return false;
}

// NOTE: This is sample implementation. The validation process in the specification is bellow.
// 5-1. If holder binding is required, validate the signature over the SD-JWT using the same steps as for the SD-JWT plus the following steps:
// 5-1-1. Determine that the public key for the private key that used to sign the SD-JWT-R is bound to the SD-JWT, i.e., the SD-JWT either contains a reference to the public key or contains the public key itself.
// 5-1-2. Determine that the SD-JWT-R is bound to the current transaction and was created for this verifier (replay protection). This is usually achieved by a nonce and aud field within the SD-JWT Release.
const validateSdJwtRelease = async (sdJwtRelease: string, publicKey: KeyLike):
  Promise<JWTPayload> => {
  // Signature validation
  let sdJwtReleasePayload: JWTPayload
  try {
    sdJwtReleasePayload = (await jwtVerify(sdJwtRelease, publicKey)).payload;
  } catch (e) {
    throw new Error('JWT signature in SD-JWT-R is invalid');
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

