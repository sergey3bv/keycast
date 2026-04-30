import {
  createHash,
  createSign,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { APIRequestContext } from "@playwright/test";

export interface PKCEChallenge {
  verifier: string;
  challenge: string;
  method: "S256";
}

export function generatePKCE(): PKCEChallenge {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge, method: "S256" };
}

export interface TokenResponse {
  bunker_url: string;
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  authorization_handle?: string;
  refresh_token?: string;
}

export async function exchangeCode(
  request: APIRequestContext,
  opts: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier?: string;
  },
): Promise<TokenResponse> {
  const res = await request.post("/api/oauth/token", {
    data: {
      grant_type: "authorization_code",
      code: opts.code,
      client_id: opts.clientId,
      redirect_uri: opts.redirectUri,
      ...(opts.codeVerifier ? { code_verifier: opts.codeVerifier } : {}),
    },
  });
  if (!res.ok()) {
    const body = await res.text();
    throw new Error(`Token exchange failed (${res.status()}): ${body}`);
  }
  return res.json();
}

export interface AuthorizeResponse {
  code: string;
  redirect_uri: string;
}

export interface DpopKeyMaterial {
  privateKey: KeyObject;
  jwk: {
    kty: string;
    crv: string;
    x: string;
    y: string;
  };
  jkt: string;
}

export interface AtprotoParResponse {
  request_uri: string;
  expires_in: number;
}

export interface AtprotoTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  sub: string;
}

function apiOrigin(): string {
  return new URL(process.env.API_URL || "http://localhost:3000").origin;
}

function canonicalDpopThumbprintInput(jwk: DpopKeyMaterial["jwk"]): string {
  return `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/// ES256 / P-256 only. Do not reuse for other algorithms.
function derToJoseEs256(signatureDer: Buffer): string {
  let offset = 0;
  if (signatureDer[offset++] !== 0x30) {
    throw new Error("Invalid DER signature (missing sequence)");
  }

  const sequenceLength = signatureDer[offset++];
  if (sequenceLength > 0x7f) {
    throw new Error("Invalid DER signature (long-form sequence length unsupported)");
  }
  if (sequenceLength + 2 !== signatureDer.length) {
    throw new Error("Invalid DER signature length");
  }

  if (signatureDer[offset++] !== 0x02) {
    throw new Error("Invalid DER signature (missing r)");
  }
  const rLength = signatureDer[offset++];
  if (rLength > 0x7f) {
    throw new Error("Invalid DER signature (long-form r length unsupported)");
  }
  if (offset + rLength > signatureDer.length) {
    throw new Error("Invalid DER signature (r out of bounds)");
  }
  const r = signatureDer.slice(offset, offset + rLength);
  offset += rLength;

  if (signatureDer[offset++] !== 0x02) {
    throw new Error("Invalid DER signature (missing s)");
  }
  const sLength = signatureDer[offset++];
  if (sLength > 0x7f) {
    throw new Error("Invalid DER signature (long-form s length unsupported)");
  }
  if (offset + sLength > signatureDer.length) {
    throw new Error("Invalid DER signature (s out of bounds)");
  }
  const s = signatureDer.slice(offset, offset + sLength);
  offset += sLength;

  if (offset !== signatureDer.length) {
    throw new Error("Invalid DER signature (unexpected trailing bytes)");
  }

  const componentSize = 32;
  if (
    (r.length > componentSize + 1 || (r.length === componentSize + 1 && r[0] !== 0x00)) ||
    (s.length > componentSize + 1 || (s.length === componentSize + 1 && s[0] !== 0x00))
  ) {
    throw new Error("Invalid DER signature (component too large for ES256)");
  }

  const normalizedR = r.length === componentSize + 1 ? r.slice(1) : r;
  const normalizedS = s.length === componentSize + 1 ? s.slice(1) : s;

  const paddedR = Buffer.concat([Buffer.alloc(componentSize), normalizedR]).slice(
    -componentSize,
  );
  const paddedS = Buffer.concat([Buffer.alloc(componentSize), normalizedS]).slice(
    -componentSize,
  );

  return Buffer.concat([paddedR, paddedS]).toString("base64url");
}

export function generateDpopKeyMaterial(): DpopKeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const exported = publicKey.export({ format: "jwk" }) as {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };

  if (
    exported.kty !== "EC" ||
    exported.crv !== "P-256" ||
    !exported.x ||
    !exported.y
  ) {
    throw new Error("Unexpected EC key export for DPoP");
  }

  const jwk = {
    kty: exported.kty,
    crv: exported.crv,
    x: exported.x,
    y: exported.y,
  };
  const jkt = createHash("sha256")
    .update(canonicalDpopThumbprintInput(jwk))
    .digest("base64url");

  return { privateKey, jwk, jkt };
}

export function createDpopProof(
  material: DpopKeyMaterial,
  opts: {
    method: "POST" | "GET";
    htu: string;
    nonce?: string;
    ath?: string;
    iat?: number;
    jti?: string;
  },
): string {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: material.jwk,
  };
  const payload: Record<string, string | number> = {
    jti: opts.jti || `dpop-${randomUUID()}`,
    htm: opts.method,
    htu: opts.htu,
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.ath) payload.ath = opts.ath;

  const encodedHeader = base64UrlJson(header);
  const encodedPayload = base64UrlJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signer = createSign("SHA256");
  signer.update(signingInput);
  signer.end();
  const derSignature = signer.sign(material.privateKey);
  const joseSignature = derToJoseEs256(derSignature);

  return `${signingInput}.${joseSignature}`;
}

export async function atprotoPar(
  request: APIRequestContext,
  opts: {
    dpopKey: DpopKeyMaterial;
    clientId: string;
    redirectUri: string;
    scope?: string;
    state?: string;
    codeChallenge: string;
    codeChallengeMethod?: "S256";
    host?: string;
    proofJti?: string;
  },
): Promise<{ body: AtprotoParResponse; nonce: string }> {
  const htu = `${apiOrigin()}/api/atproto/oauth/par`;
  const proof = createDpopProof(opts.dpopKey, {
    method: "POST",
    htu,
    jti: opts.proofJti,
  });

  const body = new URLSearchParams({
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    scope: opts.scope || "atproto",
    state: opts.state || `state-${Date.now()}`,
    code_challenge: opts.codeChallenge,
    code_challenge_method: opts.codeChallengeMethod || "S256",
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    DPoP: proof,
  };
  if (opts.host) headers.Host = opts.host;

  const res = await request.post("/api/atproto/oauth/par", {
    headers,
    data: body.toString(),
  });
  if (!res.ok()) {
    throw new Error(`PAR failed (${res.status()}): ${await res.text()}`);
  }

  const nonce = res.headers()["dpop-nonce"];
  if (!nonce) {
    throw new Error("Missing DPoP-Nonce on PAR response");
  }

  return { body: await res.json(), nonce };
}

export async function atprotoAuthorize(
  request: APIRequestContext,
  opts: { cookie: string; requestUri: string; host?: string },
): Promise<{ location: string; code: string }> {
  const headers: Record<string, string> = { Cookie: opts.cookie };
  if (opts.host) headers.Host = opts.host;

  const res = await request.get(
    `/api/atproto/oauth/authorize?request_uri=${encodeURIComponent(opts.requestUri)}`,
    { headers, maxRedirects: 0 },
  );
  if (res.status() !== 303 && res.status() !== 302) {
    throw new Error(`ATProto authorize failed (${res.status()}): ${await res.text()}`);
  }

  const location = res.headers()["location"] || "";
  const url = new URL(location);
  const code = url.searchParams.get("code");
  if (!code) {
    throw new Error(`Missing code in authorize redirect: ${location}`);
  }
  return { location, code };
}

export async function atprotoExchangeCode(
  request: APIRequestContext,
  opts: {
    dpopKey: DpopKeyMaterial;
    nonce: string;
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
    host?: string;
    proofJti?: string;
  },
): Promise<{ body: AtprotoTokenResponse; nonce: string }> {
  const htu = `${apiOrigin()}/api/atproto/oauth/token`;
  const proof = createDpopProof(opts.dpopKey, {
    method: "POST",
    htu,
    nonce: opts.nonce,
    jti: opts.proofJti,
  });

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: opts.code,
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.codeVerifier,
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    DPoP: proof,
  };
  if (opts.host) headers.Host = opts.host;

  const res = await request.post("/api/atproto/oauth/token", {
    headers,
    data: body.toString(),
  });
  if (!res.ok()) {
    throw new Error(`ATProto token failed (${res.status()}): ${await res.text()}`);
  }

  const nextNonce = res.headers()["dpop-nonce"];
  if (!nextNonce) {
    throw new Error("Missing DPoP-Nonce on ATProto token response");
  }

  return { body: await res.json(), nonce: nextNonce };
}

export async function apiAuthorize(
  request: APIRequestContext,
  cookie: string,
  opts: {
    clientId: string;
    redirectUri: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  },
): Promise<AuthorizeResponse> {
  const res = await request.post("/api/oauth/authorize", {
    headers: { Cookie: cookie },
    data: {
      client_id: opts.clientId,
      redirect_uri: opts.redirectUri,
      scope: opts.scope || "policy:full",
      approved: true,
      ...(opts.codeChallenge
        ? {
            code_challenge: opts.codeChallenge,
            code_challenge_method: opts.codeChallengeMethod || "S256",
          }
        : {}),
    },
    maxRedirects: 0,
  });

  // POST authorize may return 200 with JSON or 302 redirect
  if (res.status() === 200) {
    return res.json();
  }

  // Handle 302 redirect — extract code from Location header
  if (res.status() === 302) {
    const location = res.headers()["location"] || "";
    const url = new URL(location, "http://localhost");
    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error(`Redirect had no code: ${location}`);
    }
    return { code, redirect_uri: location };
  }

  const body = await res.text();
  throw new Error(`Authorize failed (${res.status()}): ${body}`);
}

/** Complete OAuth flow: authorize + exchange, returns token response */
export async function completeOAuthFlow(
  request: APIRequestContext,
  cookie: string,
  opts?: {
    clientId?: string;
    redirectUri?: string;
    scope?: string;
    pkce?: PKCEChallenge;
  },
): Promise<TokenResponse> {
  const clientId = opts?.clientId || `e2e-test-${Date.now()}`;
  const redirectUri = opts?.redirectUri || "http://localhost:3456/callback.html";
  const pkce = opts?.pkce || generatePKCE();

  const { code } = await apiAuthorize(request, cookie, {
    clientId,
    redirectUri,
    scope: opts?.scope,
    codeChallenge: pkce.challenge,
    codeChallengeMethod: pkce.method,
  });

  return exchangeCode(request, {
    code,
    clientId,
    redirectUri,
    codeVerifier: pkce.verifier,
  });
}
