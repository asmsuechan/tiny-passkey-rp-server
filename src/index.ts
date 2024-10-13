import express from "express";
import cors from "cors";
import { decode } from "cbor-x";
import { User } from "./models/user";
import { CredentialRecord } from "./models/credential_record";
import session from "express-session";
import { randomBytes, createPublicKey, createVerify, createHash } from "crypto";

const app = express();
app.use(express.json());
const port = 4000;

app.listen(port, () => {
  console.log(`app listening on port ${port}`);
});

app.use(
  session({
    secret: "tiny-passkey-rp-secret",
    cookie: {},
  })
);
// https://www.typescriptlang.org/docs/handbook/declaration-merging.html#module-augmentation
declare module "express-session" {
  interface SessionData {
    challenge: string;
  }
}

app.use(cors({ origin: "http://localhost:5173", credentials: true }));

const RPID = "localhost";

const users: User[] = [];

app.post("/users", async (req, res) => {
  const user: User = new User(
    randomBytes(32).toString("base64").substring(0, 32),
    req.body.name,
    randomBytes(32).toString("base64").substring(0, 32),
    []
  );
  users.push(user);
  res.status(200);
  res.json({
    id: user.id,
    name: user.name,
    displayName: user.name,
    userHandle: user.userHandle,
  });
  return;
});

// NOTE: ArrayBufferをstringにするための関数。clientDataJSONを扱うために使う。
const arrayBufferToBinaryString = (arrayBuffer: ArrayBuffer) => {
  let binaryString = "";
  const bytes = new Uint8Array(arrayBuffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return binaryString;
};

// NOTE: sha256のハッシュ値を計算をするための関数
// https://gist.github.com/keitakn/5f9d1f018dd5661998ea3fbe98621af9
const sha256 = async (text: string) => {
  const uint8 = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", uint8);
  return Array.from(new Uint8Array(digest))
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
};

app.post("/auth/register", async (req, res) => {
  const hexAttestationObject = req.body.hexAttestationObject;
  const hexClientDataJson = req.body.hexClientDataJson;

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

  const parsedFlags = parseInt(flags.toString("hex"), 16)
    .toString(2)
    .split("")
    .reverse()
    .join("");

  const decodedPubKey = decode(credentialPublicKey);
  const pubkeyX = [...new Uint8Array(decodedPubKey["-2"])]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
  const pubkeyY = [...new Uint8Array(decodedPubKey["-3"])]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

  const credential = new CredentialRecord(
    req.body.type,
    credentialId,
    `04${pubkeyX}${pubkeyY}`,
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
  if (user) users[userIndex] = user;

  const clientDataJson = JSON.parse(
    arrayBufferToBinaryString(Buffer.from(hexClientDataJson, "hex"))
  );

  // NOTE: CSRF対策としてsessionに入れたchallengeとclientDataJsonに含まれるchallengeを比較する
  const isSameChallenge =
    atob(clientDataJson["challenge"]) !== req.session.challenge;
  if (isSameChallenge) {
    res.status(400);
    res.json({ message: "Invalid challenge" });
    return;
  }

  if (
    clientDataJson["type"] != "webauthn.create" ||
    clientDataJson["origin"] != "http://localhost:5173"
  ) {
    res.status(400);
    res.json({ message: "Invalid client data" });
    return;
  }

  const up = parsedFlags[0] === "1";
  const uv = parsedFlags[2] === "1";
  const alg = decodedPubKey["3"];
  // NOTE: options.pubKeyCredParamsに渡したalgの値。ここでは簡単にするため期待する値は固定とする
  const expectedAlgs = [-7, -257];

  // NOTE: authDataの検証
  if (
    rpidhash.toString("hex") !== (await sha256(RPID)) ||
    !up ||
    !uv ||
    expectedAlgs.indexOf(alg) === -1
  ) {
    res.status(400);
    res.json({ message: "Invalid authData" });
    return;
  }

  res.status(200);
  res.json({ message: "ok" });
  return;
});

app.get("/auth/challenge", async (req, res) => {
  const challenge = randomBytes(32).toString("base64").substring(0, 32);
  req.session.challenge = challenge;
  res.status(200);
  res.json({ challenge });
  return;
});

app.post("/auth/login", async (req, res) => {
  const hexClientDataJson = req.body.hexClientDataJson;
  const hexAuthData = req.body.hexAuthData;
  const userName = req.body.userName;
  const userHandle = req.body.userHandle;
  const hexSignature = req.body.hexSignature;

  const authData = new Uint8Array(Buffer.from(hexAuthData, "hex"));

  const user = users.find((u) => u.name === userName);
  if (!user) {
    res.status(404);
    res.json({ message: "User not found" });
    return;
  }

  // NOTE: userHandleを使って、Credentialがそのユーザーのものかを確認する
  if (userHandle !== null && user.userHandle !== userHandle) {
    res.status(400);
    res.json({ message: "Invalid user handle" });
    return;
  }

  const clientDataJsonBuf = Buffer.from(hexClientDataJson, "hex");

  const clientDataHash = createHash("SHA256")
    .update(clientDataJsonBuf)
    .digest();

  const clientDataJson = JSON.parse(
    arrayBufferToBinaryString(clientDataJsonBuf)
  );
  if (
    clientDataJson["type"] !== "webauthn.get" ||
    clientDataJson["origin"] !== "http://localhost:5173"
  ) {
    res.status(400);
    res.json({ message: "Invalid client data" });
    return;
  }
  const rpidhash = authData.slice(0, 32);
  const flags = authData.slice(32, 33);
  const signCount = authData.slice(33, 37);

  const parsedFlags = parseInt(flags.toString(), 16)
    .toString(2)
    .split("")
    .join("")
    .padStart(8, "0");
  const uv = parsedFlags[0] === "1";

  const authDataSha256rpid = Buffer.from(rpidhash).toString("hex");
  const sha256rpid = await sha256(RPID);

  if (!uv && authDataSha256rpid !== sha256rpid) {
    res.status(400);
    res.json({ message: "Invalid authData" });
    return;
  }

  const verify = createVerify("SHA256");
  // NOTE: 署名対象のデータはclientDataJsonとauthDataの連結した文字列
  verify.update(Buffer.concat([authData, clientDataHash]));
  verify.end();

  // NOTE: 簡単にするため、最初のcredential_recordの公開鍵を使う
  const pubKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from(
        // https://stackoverflow.com/questions/45131935/export-an-elliptic-curve-key-from-ios-to-work-with-openssl
        "3059301306072A8648CE3D020106082A8648CE3D030107034200",
        "hex"
      ),
      Buffer.from(user.credentials[0].publicKey, "hex"),
    ]),
    format: "der",
    type: "spki",
  });

  const signature = new Uint8Array(Buffer.from(hexSignature, "hex"));
  const verifyResult = verify.verify(pubKey, signature);

  if (!verifyResult) {
    res.status(400);
    res.json({ message: "Signature verification failed" });
    return;
  }

  res.status(200);
  res.json({ user });
});
