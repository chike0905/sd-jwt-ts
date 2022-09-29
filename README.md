# sd-jwt-ts
![Test Badge](https://github.com/chike0905/sd-jwt-ts/actions/workflows/test.yml/badge.svg)

This is an implementation of [SD-JWT](https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html) in typescript.

**NOTE: THIS IMPLEMENTATION IS FOR EXPERIMENTAL PURPOSES. DO NOT USE PRODUCTION PURPOSES.**

## Install
TBA

## Functions
### async issueSDJWT(payload, IssuerPrivateKey, HolderPublicKey?, structured?): string
- Issue a SD-JWT with SVC.
- Params
  - payload (`Object`): Claims.
  - IssuerPrivateKey (`KeyLike`): Private Key for signing to SD-JWT.
  - (Optional) HolderPublicKey (`KeyLike`): Public Key of expected Holder.
    - When you provides this param, the SD-JWT includes the public key at `sub_jwk` claim.
  - (Optional) structured (`boolean`): If payload is structured, you keep structure of the payload.
    - If you does not use this flag, SD-JWT includes only the top level claims and takes structured claims as a JSON-encoded string.
- Output
  - a string combined a SD-JWT and a SVC by `.` separator.
- Example
```node
const PAYLOAD = {
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "given_name": "John",
  "family_name": "Doe",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
};
const PRIVATE_KEY_JWK = {
  kty: 'EC',
  x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
  y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
  crv: 'P-256',
  d: 'fWfGrvu1tUqnyYHrdlpZiBsxkMoeim3EleoPEafV_yM'
};

const PUBLIC_KEY_JWK = {
  kty: 'EC',
  x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
  y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
  crv: 'P-256'
};

const privKey = await importJWK(PRIVATE_KEY_JWK, 'ES256');
const pubKey = await importJWK(PUBLIC_KEY_JWK, 'ES256');
const sdJwtWithSVC = await issueSDJWT(PAYLOAD, privKey, undefined, true);
// => SD-JWT with SVC:  
eyJhbGciOiJFUzI1NiJ9.eyJzZF9kaWdlc3RzIjp7InN1YiI6IlVHeU5NWUw3VEhCejdyeVlXNlpNSVB0MV94NkFlMWV5Sm0xdmVyN1NQNzgiLCJnaXZlbl9uYW1lIjoiTXlRZ1lxdFNLTUxkRDdueGtPQ29pT3MxbVJGc3J1NE5SR3Zlbl9xTEJsZyIsImZhbWlseV9uYW1lIjoiS3hVa1BZYWlsQnJHc0VuSHlneUprblF0WG00WkhaTEJtOFp1Z0M4MmxHbyIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiJGSTEzM3MwZy1XNThCMUM2ZzIxZGZYWnFKVTd4UEtzNS0zdjhjODRtMElRIiwibG9jYWxpdHkiOiJBbi1EM3Ytai04a0ZKSlFGcWF5b1gwYVZqYjJFRlNwVWVWQ193QVAzV3lvIiwicmVnaW9uIjoicUtvMDJObXRtRjIxRHhHNnFRTEl4bmx3YXRsZ1o5dUdwZVBfb1NzZ3F4cyIsImNvdW50cnkiOiJjRlBsVjRlTXk2OUliU3ZQd0VCaDJseEl6SlE5c1FYakNSYjd4WlRuZ3lrIn19LCJoYXNoX2FsZyI6InNoYS0yNTYifQ.3exPFo-bh7p2EabIXy6PCub3lPZwCiRFMaISaMTv0scagffQA6n_4bkm0syJgEZLJqT6Ebvih7AdevzwVNy-iA.eyJzZF9yZWxlYXNlIjp7InN1YiI6IltcIjR1d3VabmhwcGVxd1pRSWcwckN0ZVlzU2VUWFNsR2t1Z1JTTzlWaW5FNFVcIixcIjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyY1wiXSIsImdpdmVuX25hbWUiOiJbXCJLaURDUHk5bGlQSC1DRDlUWnNZWV92OEdBQ3hweS1RRlBJQU5yUUJOb3JRXCIsXCJKb2huXCJdIiwiZmFtaWx5X25hbWUiOiJbXCJuOW4xTXU5S3NxMlE1SW1nRjRCOWg0T0Rld2RKLW1pdWREMlJ1dWczb0hFXCIsXCJEb2VcIl0iLCJhZGRyZXNzIjp7InN0cmVldF9hZGRyZXNzIjoiW1wicEttTTh1bHBQdWh3QUFPNkJLWU9DRmFtMVVqRktrMUVVSVFNb2VuSnV4MFwiLFwiMTIzIE1haW4gU3RcIl0iLCJsb2NhbGl0eSI6IltcIkl2S1pibnpITUxsVE5UbnJJS0h4Zk5HdmZOdGlwVFlXTHdlWEZMdG1xNEVcIixcIkFueXRvd25cIl0iLCJyZWdpb24iOiJbXCJ5RVkyOHhhTnA2TTBkaWtUMjl1MG5TQU8xOU1HYWtjNEU0S0xLd0RYUEVVXCIsXCJBbnlzdGF0ZVwiXSIsImNvdW50cnkiOiJbXCJLZjRNaGNvOHN1VkVCVWpZQk1yR0Zna25YQ3hFM2Zxd1d4LW90NUVvNjZnXCIsXCJVU1wiXSJ9fX0
```

### async createSDJWTwithRelease(sdJwtWithSVC, disclosedClaims, holderPrivateKey?): string
- Create SD-JWT-Release from SD-JWT and SVC.
- Params
  - sdJwtWithSVC (`string`): SD-JWT and SVC in a combied format (output of `issueSDJWT()`).
  - disclosedClaims (`string[]`): Array of a path of claims that a holder want to disclose.
    - Taking `sd_digest` as root, describe path comma-separated string.
      - If you want to specify `region` in the example payload, you can discribe `address.region`.
      - TODO: Array
  - (Optional) holderPrivateKey (`KeyLike`): a key for signing to SD-JWT-R.
    - (NOT REQUIREMENT IN SPEC) If SD-JWT has a `sub_jwk` claim, a holder MUST provide privateKey for holder binding.
- Output
  - a string combined a SD-JWT and a SD-JWT-R by `.` separator.

- Example
```node
const sdJwt = await issueSDJWT(PAYLOAD, privKey, undefined, true);
const sdJwtWithRelease = await createSDJWTwithRelease(sdJwt, ['address.region']);
// => SD-JWT with SD-JWT-R: 
// eyJhbGciOiJFUzI1NiJ9.eyJzZF9kaWdlc3RzIjp7InN1YiI6IlVHeU5NWUw3VEhCejdyeVlXNlpNSVB0MV94NkFlMWV5Sm0xdmVyN1NQNzgiLCJnaXZlbl9uYW1lIjoiTXlRZ1lxdFNLTUxkRDdueGtPQ29pT3MxbVJGc3J1NE5SR3Zlbl9xTEJsZyIsImZhbWlseV9uYW1lIjoiS3hVa1BZYWlsQnJHc0VuSHlneUprblF0WG00WkhaTEJtOFp1Z0M4MmxHbyIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiJGSTEzM3MwZy1XNThCMUM2ZzIxZGZYWnFKVTd4UEtzNS0zdjhjODRtMElRIiwibG9jYWxpdHkiOiJBbi1EM3Ytai04a0ZKSlFGcWF5b1gwYVZqYjJFRlNwVWVWQ193QVAzV3lvIiwicmVnaW9uIjoicUtvMDJObXRtRjIxRHhHNnFRTEl4bmx3YXRsZ1o5dUdwZVBfb1NzZ3F4cyIsImNvdW50cnkiOiJjRlBsVjRlTXk2OUliU3ZQd0VCaDJseEl6SlE5c1FYakNSYjd4WlRuZ3lrIn19LCJoYXNoX2FsZyI6InNoYS0yNTYifQ.3exPFo-bh7p2EabIXy6PCub3lPZwCiRFMaISaMTv0scagffQA6n_4bkm0syJgEZLJqT6Ebvih7AdevzwVNy-iA.eyJhbGciOiJub25lIn0.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOnsicmVnaW9uIjoiW1wieUVZMjh4YU5wNk0wZGlrVDI5dTBuU0FPMTlNR2FrYzRFNEtMS3dEWFBFVVwiLFwiQW55c3RhdGVcIl0ifX19.
```

### async verifySDJWTandSVC(sdJwtWithSVC, issuerPublicKey): boolean
- verify SD-JWT with SVC (Spec Section 6.1)
- Params
  - sdJwtWithSVC (`string`): SD-JWT and SVC in a combied format (output of `issueSDJWT()`).
  - issuerPublicKey (`KeyLike`): a public key of the issuer.
- Output
  - verifiation result as boolean
  
### async verifySDJWTandSDJWTR(sdJwtWithRelease, issuerPublicKey, holderPublicKey?): Object
- verify SD-JWT with SD-JWT-R and get disclosed claims. (Spec Section 6.2)
- Params
  - sdJwtWithRelease (`string`): a string combined a SD-JWT and a SD-JWT-R (output of `createSDJWTwithRelease()`).
  - issuerPrivateKey (`KeyLike`): a public key of the issuer.
  - (Optional) holderPrivateKey? (`KeyLike`): a public key off the holder.
    - NOTE: 
      - If the SD-JWT has `sub_jwk` claim, the key in `sub_jwk` is utilzed in the verification process of SD-JWT-R.
      - Nevertheless the `sub_jwk` is provided, if `holderPublicKey` is provided, the function utilzes the `holderPublicKey`, not `sub_jwk`.
- Output
  - An objet includes disclosed claims
- Example
```node
const sdJwt = await issueSDJWT(PAYLOAD, privKey, undefined, true);
const sdJwtWithRelease = await createSDJWTwithRelease(sdJwt, ['address.region']);
const disclosedClaims = await verifySDJWTandSDJWTR(sdJwtWithRelease, pubKey);
// => Disclosed Claims:
// { address: { region: 'Anystate' } }
```

## Notes
- Temporary 
  - sapports only `ES256` for a sgining algorithm.
  - sapports only `sha-256` for a hash algorithm for sd_digest.
  - length of salt is 256 bits
- ToDo
  - If a structured payload includes array, this implementation does not work correctly.
  - Enable JWT Registered Claims

## License
MIT