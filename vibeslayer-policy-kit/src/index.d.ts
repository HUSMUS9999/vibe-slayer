export type ActionMode = "public-preview" | "server-only" | "client-sealed";
export type AntiStealthMode = "off" | "balanced" | "strict";

export interface StealthTelemetry {
  webdriver?: boolean;
  cdpRuntimeEnable?: boolean;
  canvas2dUniqueColors?: number;
  webglClearUniqueColors?: number;
  silentAudioNonZeroSamples?: number;
  domRectSubpixelDrift?: boolean;
  osFontLie?: boolean;
  d3d11ExtMismatch?: boolean;
  platform?: string;
}

export interface StealthAttestation {
  s: number;
  f: number;
  p: string;
  d: string;
}

export type ParamRule =
  | { type: "int"; min?: number; max?: number; optional?: boolean }
  | { type: "number"; min?: number; max?: number; optional?: boolean }
  | { type: "string"; minLength?: number; maxLength?: number; pattern?: RegExp; optional?: boolean }
  | { type: "boolean"; optional?: boolean }
  | { type: "enum"; values: readonly (string | number)[]; optional?: boolean };

export interface ActionDefinition<P = Record<string, unknown>, R = unknown> {
  mode: ActionMode;
  antiStealth?: AntiStealthMode;
  params?: Record<string, ParamRule>;
  requiredScopes?: readonly string[];
  allowedOrigins?: readonly string[];
  replayWindowMs?: number;
  maxUses?: number;
  rateLimit?: { max: number; windowMs?: number };
  redactFields?: readonly string[];
  handler: (ctx: {
    params: P;
    subject: string;
    origin: string;
    leaseId: string;
  }) => Promise<R> | R;
}

export interface PolicyConfig {
  version?: string;
  enabled?: boolean;
  antiStealth?: AntiStealthMode;
  signingSecret: Buffer | string;
  defaultLeaseTtlMs?: number;
  maxBodyBytes?: number;
  actions: Record<string, ActionDefinition>;
}

export declare function definePolicy(config: PolicyConfig): Readonly<PolicyConfig>;
export declare function buildBoundingBoxPreviewGlb(
  sourceGlbBytes: Buffer | Uint8Array,
  opts?: { generator?: string; nodeName?: string }
): Buffer;
export declare function sealAssetAes256Gcm(
  plainBytes: Buffer | Uint8Array,
  keyBytes: Buffer | Uint8Array,
  aadText?: string
): { iv: Buffer; tag: Buffer; ciphertext: Buffer; aad: string };
export declare function unsealAssetAes256Gcm(
  envelope: { iv: Buffer | string; tag: Buffer | string; ciphertext: Buffer | string },
  keyBytes: Buffer | Uint8Array,
  expectedAadText?: string
): Buffer;
export declare function createGateway(policy: Readonly<PolicyConfig>): {
  readonly url: string | null;
  issueLease(opts: {
    subject: string;
    scopes?: string[];
    origin?: string;
    action?: string;
    ttlMs?: number;
    maxUses?: number;
  }): string;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
};
export declare function buildStealthAttestation(opts?: {
  mode?: AntiStealthMode;
  actionName?: string;
  origin?: string;
  telemetry?: StealthTelemetry;
}): StealthAttestation | null;
export declare function createClient(opts: {
  baseUrl: string;
  origin?: string;
  leaseToken?: string;
  antiStealth?: AntiStealthMode;
  telemetry?: StealthTelemetry | null;
  extraHeaders?: Record<string, string>;
  fetchImpl?: typeof fetch;
}): {
  invoke<T = unknown>(actionName: string, params?: Record<string, unknown>): Promise<T>;
  invokeBinary(actionName: string, params?: Record<string, unknown>): Promise<Buffer>;
  invokeSealed(actionName: string, params?: Record<string, unknown>): Promise<Buffer>;
};
