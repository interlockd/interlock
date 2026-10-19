export declare const VERSION: string;
export declare const UNREACHABLE: string;

export interface Verdict {
  disposition: "allow" | "ask" | "block" | "warn" | "withhold";
  mode: "shadow" | "enforce";
  reason?: string | null;
  notice?: string | null;
  findings?: Array<{ rule?: string; category: string; severity: string; subject?: string | null }>;
  [key: string]: unknown;
}

export interface ClientOptions {
  home?: string; url?: string; token?: string; agentType?: string; session?: string; timeoutMs?: number;
}

export declare class InterlockClient {
  constructor(options?: ClientOptions);
  readonly url: string;
  readonly token: string;
  failsClosed(): boolean;
  decide(kind: "pre_action" | "post_action", tool: string, args?: Record<string, unknown>,
         options?: { content?: string; session?: string; cwd?: string; withhold?: boolean }): Promise<Verdict | null>;
  static stops(v: Verdict | null): boolean;
  static withholds(v: Verdict | null): boolean;
}

export declare function guardExecute<F extends (args: any, ...rest: any[]) => any>(
  name: string, execute: F, client?: InterlockClient, options?: { session?: string }): F;

export declare function guardTools<T extends Record<string, any>>(
  tools: T, client?: InterlockClient, options?: { session?: string }): T;

export type HookCallback = (input: any, toolUseID: string | undefined, options: { signal: AbortSignal }) => Promise<Record<string, unknown>>;
export declare function interlockHooks(client?: InterlockClient): {
  PreToolUse: Array<{ hooks: HookCallback[] }>; PostToolUse: Array<{ hooks: HookCallback[] }>;
};
export declare function guardOptions<O extends { hooks?: Record<string, any> }>(options?: O, client?: InterlockClient): O;
