import { Type, type Static } from "typebox";
declare const configSchema: Type.TObject<{
    projectPath: Type.TOptional<Type.TString>;
    executable: Type.TOptional<Type.TString>;
    stateDir: Type.TOptional<Type.TString>;
    profile: Type.TOptional<Type.TString>;
    timeoutMs: Type.TOptional<Type.TInteger>;
}>;
type EchoVeilConfig = Static<typeof configSchema>;
export type EchoVeilInvocation = {
    command: string;
    args: string[];
    env: NodeJS.ProcessEnv;
    timeoutMs: number;
};
export declare function buildChildEnvironment(source?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
export declare function addRpcTelemetry(value: unknown, elapsedMs: number): unknown;
export declare function buildInvocation(config: EchoVeilConfig): EchoVeilInvocation;
export declare function runEchoVeilRpc(action: string, argumentsValue: Record<string, unknown>, config: EchoVeilConfig, signal?: AbortSignal): Promise<unknown>;
declare const _default: import("openclaw/plugin-sdk/tool-plugin").DefinedToolPluginEntry;
export default _default;
