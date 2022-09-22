import { base64url, JWTPayload, jwtVerify, KeyLike } from "jose";
import * as crypto from 'crypto';
import { SD_DIGESTS, SVC } from "./types";
import { separateJWTandSVC } from "./utils";

// ref: https://www.iana.org/assignments/named-information/named-information.xhtml
// Accessed 2022.09.22
const HASH_NAME_STRING = ['Reserved', 'sha-256', 'sha-256-128', 'sha-256-120', 'sha-256-96', 'sha-256-64', 'sha-256-32', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'Unassigned', 'Reserved', 'Unassigned', 'blake2s-256', 'blake2b-256', 'blake2b-512', 'k12-256', 'k12-512'];

// TODO: tmp support combined single string format for SD-JWT and SVC 
export const verifySDJWTandSVC = async (sd_jwt: string, publicKey: KeyLike):
  Promise<boolean> => {
  const { svc, jwt } = separateJWTandSVC(sd_jwt);

  let jwt_payload: JWTPayload
  try {
    jwt_payload = (await jwtVerify(jwt, publicKey)).payload;
  } catch (e) {
    throw new Error('JWT signature in sd_jwt string is invalid');
  }

  // Payload format validation
  if (!jwt_payload.sd_digests || !jwt_payload.hash_alg)
    throw new Error('The payload of an SD-JWT MUST contain the sd_digests and hash_alg claims.');

  if (!HASH_NAME_STRING.includes(jwt_payload.hash_alg as string))
    throw new Error('The hash algorithm identifier MUST be a value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry.');


  // SVC format validation
  if (!svc.sd_release)
    throw new Error('A SD-JWT Salt/Value Container (SVC) is a JSON object containing at least the top-level property sd_release. ')

  if (!strArrayEqual(Object.keys(jwt_payload.sd_digests), Object.keys(svc.sd_release)))
    throw new Error('Keys in sd_digests and sd_release of SVC does not match.');

  // Validation of match between sd_digest and hash of sd_release
  Object.keys(jwt_payload.sd_digests).map((key) => {
    const hashOfSdRelease = base64url.encode(crypto.createHash('sha256')
      .update(svc.sd_release[key]).digest());
    if ((jwt_payload.sd_digests as SD_DIGESTS)[key] !== hashOfSdRelease)
      throw new Error('sd_digest does not match with hash of sd_release.');
  });

  return true;
};

const strArrayEqual = (arr1: string[], arr2: string[]): boolean => {
  if (arr1.length !== arr2.length) return false;
  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }
  return true;
}

