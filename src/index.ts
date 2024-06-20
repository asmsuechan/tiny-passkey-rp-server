import express from "express";
import { decode, encode } from "cbor-x";
import { createPublicKey, createVerify, createHash, randomBytes } from "crypto";
import { User } from "./models/user";
import { CredentialRecord } from "./models/credential_record";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());
const port = 4000;

// https://w3c.github.io/webauthn/#credential-record
// https://w3c.github.io/webauthn/#reg-ceremony-store-credential-record

const users: User[] = [];

app.get("/auth/challenge", async (req, res) => {
  const challenge = randomBytes(32).toString("base64").substring(0, 32);
  res.status(200);
  res.json({ challenge });
  return;
});

app.post("/users", async (req, res) => {
  const user: User = new User(
    randomBytes(32).toString("base64").substring(0, 32),
    req.body.name,
    "randomrandomrandom", // ちゃんとランダムな64バイトの文字列にする必要がある
    []
  );
  users.push(user);
  res.status(200);
  res.json({ id: user.id, name: user.name, displayName: user.name });
  return;
});

app.post("/auth/register", async (req, res) => {
  const hexAttestationObject = req.body.hexAttestationObject;
  const hexClientDataJson = req.body.hexClientDataJson;
  // const hexAttestationObject =
  //   "a363666d74667061636b65646761747453746d74a263616c672663736967584730450221009b2a487d511bf1f274b6a1997861fbe4cf1e6a990238c9a2ca1b494d9fc08d07022009caead3eededc6d1c9c6e84617d618b016c526885059f27bde3ecefa19db5c468617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634500000000adce000235bcc60a648b0b25f1f055030020d9c3be54076e85717812659f7f30fbf490b2a9968270eb342f3d284c1d08ec91a5010203262001215820c151828e4a6adc47f9f3fb419ea34cfb8250bb1c82b507899bd506592bc6189a22582065cdc6d2068a53b33909b3e5f3e0d6ad4c0cf22d2004f1c735c88a05536795be";
  // const hexClientDataJson =
  //   "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a226a416f6d5f794b5277656d3554693458477068716333476451306a5670326f56666a6955556e6558442d38222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313733222c2263726f73734f726967696e223a66616c73657d";

  const obj = decode(Buffer.from(hexAttestationObject, "hex"));

  // 全体の図
  // https://w3c.github.io/webauthn/#fig-attStructs
  // https://w3c.github.io/webauthn/#table-authData
  const rpidhash = obj["authData"].slice(0, 32);
  const flags = obj["authData"].slice(32, 33);
  const signCount = obj["authData"].slice(33, 37);

  // ここからAttested Credential DataとExtensions
  const rest = obj["authData"].slice(37, obj["authData"].length);

  // https://www.w3.org/TR/webauthn/#table-attestedCredentialData
  const aaguid = rest.slice(0, 16);
  const l = rest.slice(16, 18);
  const lnum = Number(
    [...new Uint8Array(l)].map((x) => x.toString(10)).join("")
  );
  const credentialId = rest.slice(18, 18 + lnum);
  const credentialPublicKey = rest.slice(18 + lnum, rest.length);
  // attestedCredentialDataの長さはcredentialIdによって決まる?
  // credentialPublicKeyの長さは？
  // > Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length (see also Section 7 of [RFC9052]).
  // https://w3c.github.io/webauthn/#fig-authData

  // extensionsはRPから自由に渡せるJSON形式の値。CBORにしてサーバーへ渡すことになる。
  // →違うか？
  // https://w3c.github.io/webauthn/#sctn-defined-client-extensions

  // ## 公開鍵を取り出す
  // https://w3c.github.io/webauthn/#attested-credential-data
  // ここで得られるpubkeyはこの例と同じ https://w3c.github.io/webauthn/#example-bdbd14cc
  // 楕円曲線暗号の公開鍵。
  // https://datatracker.ietf.org/doc/html/rfc9053#section-7.1
  const decodedPubKey = decode(credentialPublicKey);
  const x = [...new Uint8Array(decodedPubKey["-2"])]
    .map((x) => x.toString(16))
    .join("");
  const y = [...new Uint8Array(decodedPubKey["-3"])]
    .map((x) => x.toString(16))
    .join("");
  // なんか鍵の計算とかしてる https://tech.springcard.com/2021/storing-ecc-private-keys-in-the-springcores-secure-element/
  const pubKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from(
        // https://stackoverflow.com/questions/45131935/export-an-elliptic-curve-key-from-ios-to-work-with-openssl
        "3059301306072A8648CE3D020106082A8648CE3D030107034200",
        "hex"
      ),
      Buffer.from([0x04]),
      decodedPubKey["-2"],
      decodedPubKey["-3"],
    ]),
    format: "der",
    type: "spki",
  });
  // console.log(decode(decodedPubKey['-2']))
  // console.log(decode(decodedPubKey['-3']))
  // さて、どうやってこの生の情報をNode.jsで扱える公開鍵にするのだろうか？
  // console.log(decode(Buffer.from([...new Uint8Array(credentialPublicKey)].map(x => x.toString(16)).join(''), 'hex')))

  // NOTE: extensionsはどういう時に含まれるのか？
  // https://w3c.github.io/webauthn/#sctn-extensions

  // ## 署名を取り出す
  // attestation statementに入っている
  // https://w3c.github.io/webauthn/#sctn-attestation-formats
  // 検証の元データはauthenticatorData と clientDataHash を連結したもの
  // clientDataHashはclientDataJsonから作り出す
  // https://w3c.github.io/webauthn/#sctn-packed-attestation
  const clientDataJson = Buffer.from(hexClientDataJson, "hex");
  const clientDataHash = createHash("SHA256").update(clientDataJson).digest();
  const authenticatorData = obj["authData"]; // buffer
  // console.log(obj["authData"]);
  // const hexAuthData = [...new Uint8Array(authenticatorData)].map(x => x.toString(16)).join('');

  // ES256 (-7)なのでSHA256
  const verify = createVerify("SHA256");
  verify.update(Buffer.concat([authenticatorData, clientDataHash]));
  verify.end();

  const signatureData = obj["attStmt"]["sig"];
  const verifyResult = verify.verify(pubKey, signatureData);

  if (!verifyResult) {
    res.status(400);
    res.json({ message: "Signature verification failed" });
    return;
  }

  // requestbodyの内容
  // cred.type
  // cred.id
  // cred.response.getTransports()
  // hexAttestationObject
  // hexClientDataJson

  const parsedFlags = parseInt(flags.toString("hex"), 16)
    .toString(2)
    .split("")
    .reverse()
    .join("");

  const credential = new CredentialRecord(
    req.body.type,
    req.body.id,
    `04${x}${y}`,
    signCount,
    req.body.transports,
    parsedFlags[2] === "1",
    parsedFlags[3] === "1",
    parsedFlags[4] === "1",
    hexAttestationObject,
    hexClientDataJson
  );

  // NOTE: 作成済みのユーザーIDをclientのリクエストに含める
  const user = users.find((u) => u.id === req.body.userId);
  user?.credentials.push(credential);
  const userIndex = users.findIndex((u) => u.id === req.body.userId);
  // TODO: エラーハンドリング
  if (user) users[userIndex] = user;

  // さて、アプリケーションとしてのユーザーはどのようにして保存するのか？
  // userはPublicKeyCredentialUserEntity
  // https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-user
  // credentials.create()関数に食わせたデータ。
  // https://www.passkeys.io/のデモで開発者ツールを見るとわかりやすい
  // create()に食わせるのは、id, name, displayName
  // create()の実行前にまずサーバーにユーザーのデータを登録する。

  res.status(200);
  res.json({ user });
  return;
});

app.post("/auth/login", async (req, res) => {});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
