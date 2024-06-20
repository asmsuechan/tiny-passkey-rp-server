import { CredentialRecord } from "./credential_record";

export class User {
  constructor(
    public id: string,
    public name: string,
    public userHandle: string,
    public credentials: CredentialRecord[]
  ) {}
}

// https://w3c.github.io/webauthn/#sctn-user-handle-privacy
// It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user account.
// userHandle
// user.idはauthentication ceremonyではuserHandleとして使う。
