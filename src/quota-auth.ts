import { isRecord } from "./types.ts";

interface QuotaRegistry {
  getApiKeyForProvider?: (id: string) => Promise<string | undefined>;
  getProviderAuth?: (id: string) => Promise<{ auth?: { apiKey?: string } } | undefined>;
}

/** Resolve through Pi; the reader is Pi's public readStoredCredential API, not a second auth parser. */
export async function quotaApiKey(
  provider: string,
  registry: QuotaRegistry,
  readCredential: (provider: string) => unknown,
): Promise<string> {
  try {
    if (provider === "github-copilot" || provider === "openai-codex") {
      const credential = readCredential(provider);
      if (!isRecord(credential) || credential.type !== "oauth") return "";
      // Pi stores the GitHub login token in refresh; access is the Copilot inference token.
      if (provider === "github-copilot") {
        // Fixed github.com endpoint: never forward an Enterprise-domain credential.
        if (credential.enterpriseUrl !== undefined && credential.enterpriseUrl !== "github.com") return "";
        return typeof credential.refresh === "string" ? credential.refresh.trim() : "";
      }
    }
    const direct = await registry.getApiKeyForProvider?.(provider);
    const key = direct || (await registry.getProviderAuth?.(provider))?.auth?.apiKey || "";
    if (provider === "openai-codex") {
      // A stored login must not authorize forwarding an unrelated resolved API key.
      const refreshed = readCredential(provider);
      if (!isRecord(refreshed) || refreshed.type !== "oauth" || refreshed.access !== key) return "";
    }
    return key;
  } catch {
    return "";
  }
}
