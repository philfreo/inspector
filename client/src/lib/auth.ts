import { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import {
  OAuthClientInformationSchema,
  OAuthClientInformation,
  OAuthTokens,
  OAuthTokensSchema,
  OAuthClientMetadata,
  OAuthMetadata,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { SESSION_KEYS, getServerSpecificKey } from "./constants";
import { generateOAuthState } from "@/utils/oauthUtils";

// Simple obfuscation using Web Crypto API
const ENCRYPTION_KEY = 'mcp-inspector-oauth-storage-key-v1';

async function deriveKey(salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(ENCRYPTION_KEY),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );
  
  // Combine salt + iv + encrypted data
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  
  return btoa(String.fromCharCode(...combined));
}

async function decryptData(encryptedData: string): Promise<string> {
  const combined = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
  
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);
  
  const key = await deriveKey(salt);
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  
  return new TextDecoder().decode(decrypted);
}

export const getClientInformationFromSessionStorage = async ({
  serverUrl,
  isPreregistered,
}: {
  serverUrl: string;
  isPreregistered?: boolean;
}) => {
  const key = getServerSpecificKey(
    isPreregistered
      ? SESSION_KEYS.PREREGISTERED_CLIENT_INFORMATION
      : SESSION_KEYS.CLIENT_INFORMATION,
    serverUrl,
  );

  const value = sessionStorage.getItem(key);
  if (!value) {
    return undefined;
  }

  try {
    const decrypted = await decryptData(value);
    return await OAuthClientInformationSchema.parseAsync(JSON.parse(decrypted));
  } catch {
    // If decryption fails, data is corrupted or from old format
    return undefined;
  }
};

export const saveClientInformationToSessionStorage = async ({
  serverUrl,
  clientInformation,
  isPreregistered,
}: {
  serverUrl: string;
  clientInformation: OAuthClientInformation;
  isPreregistered?: boolean;
}) => {
  const key = getServerSpecificKey(
    isPreregistered
      ? SESSION_KEYS.PREREGISTERED_CLIENT_INFORMATION
      : SESSION_KEYS.CLIENT_INFORMATION,
    serverUrl,
  );
  
  const jsonData = JSON.stringify(clientInformation);
  const encrypted = await encryptData(jsonData);
  sessionStorage.setItem(key, encrypted);
};

export const clearClientInformationFromSessionStorage = ({
  serverUrl,
  isPreregistered,
}: {
  serverUrl: string;
  isPreregistered?: boolean;
}) => {
  const key = getServerSpecificKey(
    isPreregistered
      ? SESSION_KEYS.PREREGISTERED_CLIENT_INFORMATION
      : SESSION_KEYS.CLIENT_INFORMATION,
    serverUrl,
  );
  sessionStorage.removeItem(key);
};

export class InspectorOAuthClientProvider implements OAuthClientProvider {
  constructor(protected serverUrl: string) {
    // Save the server URL to session storage
    sessionStorage.setItem(SESSION_KEYS.SERVER_URL, serverUrl);
  }

  get redirectUrl() {
    return window.location.origin + "/oauth/callback";
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "MCP Inspector",
      client_uri: "https://github.com/modelcontextprotocol/inspector",
    };
  }

  state(): string | Promise<string> {
    return generateOAuthState();
  }

  async clientInformation() {
    // Try to get the preregistered client information from session storage first
    const preregisteredClientInformation =
      await getClientInformationFromSessionStorage({
        serverUrl: this.serverUrl,
        isPreregistered: true,
      });

    // If no preregistered client information is found, get the dynamically registered client information
    return (
      preregisteredClientInformation ??
      (await getClientInformationFromSessionStorage({
        serverUrl: this.serverUrl,
        isPreregistered: false,
      }))
    );
  }

  async saveClientInformation(clientInformation: OAuthClientInformation) {
    // Save the dynamically registered client information to session storage
    await saveClientInformationToSessionStorage({
      serverUrl: this.serverUrl,
      clientInformation,
      isPreregistered: false,
    });
  }

  async tokens() {
    const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
    const tokens = sessionStorage.getItem(key);
    if (!tokens) {
      return undefined;
    }

    return await OAuthTokensSchema.parseAsync(JSON.parse(tokens));
  }

  saveTokens(tokens: OAuthTokens) {
    const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
    sessionStorage.setItem(key, JSON.stringify(tokens));
  }

  redirectToAuthorization(authorizationUrl: URL) {
    if (
      authorizationUrl.protocol !== "http:" &&
      authorizationUrl.protocol !== "https:"
    ) {
      throw new Error("Authorization URL must be HTTP or HTTPS");
    }
    window.location.href = authorizationUrl.href;
  }

  saveCodeVerifier(codeVerifier: string) {
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    sessionStorage.setItem(key, codeVerifier);
  }

  codeVerifier() {
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    const verifier = sessionStorage.getItem(key);
    if (!verifier) {
      throw new Error("No code verifier saved for session");
    }

    return verifier;
  }

  clear() {
    clearClientInformationFromSessionStorage({
      serverUrl: this.serverUrl,
      isPreregistered: false,
    });
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CODE_VERIFIER, this.serverUrl),
    );
  }
}

// Overrides debug URL and allows saving server OAuth metadata to
// display in debug UI.
export class DebugInspectorOAuthClientProvider extends InspectorOAuthClientProvider {
  get redirectUrl(): string {
    return `${window.location.origin}/oauth/callback/debug`;
  }

  saveServerMetadata(metadata: OAuthMetadata) {
    const key = getServerSpecificKey(
      SESSION_KEYS.SERVER_METADATA,
      this.serverUrl,
    );
    sessionStorage.setItem(key, JSON.stringify(metadata));
  }

  getServerMetadata(): OAuthMetadata | null {
    const key = getServerSpecificKey(
      SESSION_KEYS.SERVER_METADATA,
      this.serverUrl,
    );
    const metadata = sessionStorage.getItem(key);
    if (!metadata) {
      return null;
    }
    return JSON.parse(metadata);
  }

  clear() {
    super.clear();
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.SERVER_METADATA, this.serverUrl),
    );
  }
}
