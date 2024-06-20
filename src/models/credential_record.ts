export class CredentialRecord {
  constructor(
    public type: string,
    public id: string,
    public publicKey: string,
    public signCount: number,
    public transports: string[],
    public uvInitialized: boolean,
    public backupEligible: boolean,
    public backupState: boolean,
    public attestationObject?: string,
    public attestationClientDataJSON?: string,
    public authenticatorDisplayName?: string
  ) {}
}
