import { Type, type Static } from "typebox";
import { type AnyAgentTool, type OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
declare const configSchema: Type.TObject<{
    projectPath: Type.TOptional<Type.TString>;
    executable: Type.TOptional<Type.TString>;
    stateDir: Type.TOptional<Type.TString>;
    profile: Type.TOptional<Type.TString>;
    timeoutMs: Type.TOptional<Type.TInteger>;
}>;
type EchoVeilConfig = Static<typeof configSchema>;
type OpenClawAgentHookContext = {
    runId?: string;
    sessionId?: string;
    sessionKey?: string;
};
type BeforeAgentReplyEvent = {
    cleanedBody: string;
};
type BeforeAgentReplyResult = {
    handled: boolean;
    reply?: {
        text: string;
    };
    reason?: string;
};
type BeforePromptBuildEvent = {
    prompt: string;
    messages: unknown[];
};
type BeforeAgentRunEvent = {
    prompt: string;
    messages: unknown[];
    systemPrompt?: string;
};
type InputGateDecision = {
    outcome: "pass";
} | {
    outcome: "block";
    reason: string;
    message?: string;
    category?: string;
};
export type EchoVeilInvocation = {
    command: string;
    args: string[];
    env: NodeJS.ProcessEnv;
    timeoutMs: number;
};
export declare function buildChildEnvironment(source?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
export declare function addRpcTelemetry(value: unknown, elapsedMs: number): unknown;
export declare function buildInvocation(config: EchoVeilConfig): EchoVeilInvocation;
export declare function resolveProfile(config: EchoVeilConfig, env?: NodeJS.ProcessEnv): string;
export declare function normalizePluginConfig(value: unknown): EchoVeilConfig;
export declare function runEchoVeilRpc(action: string, argumentsValue: Record<string, unknown>, config: EchoVeilConfig, signal?: AbortSignal): Promise<unknown>;
type PreflightRpc = (action: string, argumentsValue: Record<string, unknown>, config: EchoVeilConfig, signal?: AbortSignal) => Promise<unknown>;
type PromptBuildResult = {
    prependContext?: string;
    prependSystemContext?: string;
};
export declare function parsePreflightContext(value: unknown, { expectedProfile }: {
    expectedProfile: string;
}): string;
export declare function hasRequiredOpenClawHookPolicy(value: unknown): boolean;
export declare function createOpenClawPreflightHandlers(config: EchoVeilConfig, { rpc, now, token, hookPolicyReady, }?: {
    rpc?: PreflightRpc;
    now?: () => number;
    token?: () => string;
    hookPolicyReady?: boolean | (() => boolean);
}): {
    beforeAgentReply: (event: BeforeAgentReplyEvent, context: OpenClawAgentHookContext) => Promise<BeforeAgentReplyResult>;
    beforePromptBuild: (event: BeforePromptBuildEvent, context: OpenClawAgentHookContext) => Promise<PromptBuildResult>;
    beforeAgentRun: (event: BeforeAgentRunEvent, context: OpenClawAgentHookContext) => InputGateDecision;
};
export declare function buildEchoVeilTools(config: EchoVeilConfig): AnyAgentTool[];
export declare function buildEchoVeilPromptSection({ availableTools, }: {
    availableTools: Set<string>;
}): string[];
export declare function registerEchoVeil(api: OpenClawPluginApi): void;
declare const _default: import("openclaw/plugin-sdk/plugin-entry").DefinedPluginEntry;
export default _default;
