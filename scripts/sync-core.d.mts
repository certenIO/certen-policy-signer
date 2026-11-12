export const REPO: string;
export function sha256Hex(buf: Uint8Array): string;
export function sourceRepo(): string | undefined;
export function canonicalBytes(repo: string, file: string): Buffer;
export function manifestFor(files: Record<string, string>): string;
