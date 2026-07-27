/**
 * accumulate.js interop shim.
 * The published package resolves as CommonJS. Under both tsx and vite/vitest a
 * namespace import exposes the real members under `.default`; normalize once here.
 */
import * as coreNs from 'accumulate.js/core';
import * as commonNs from 'accumulate.js/common';
import * as encodingNs from 'accumulate.js/encoding';
import * as addressNs from 'accumulate.js/address';

/* eslint-disable @typescript-eslint/no-explicit-any */
export const core: any = (coreNs as any).default ?? coreNs;
export const common: any = (commonNs as any).default ?? commonNs;
export const encoding: any = (encodingNs as any).default ?? encodingNs;
export const address: any = (addressNs as any).default ?? addressNs;

export const ED25519Signature = core.ED25519Signature;
export const DelegatedSignature = core.DelegatedSignature;
export const VoteType = core.VoteType; // { Accept:0, Reject:1, Abstain:2, Suggest:3 }
export const sha256: (b: Uint8Array) => Uint8Array = common.sha256;
export const encode: (v: unknown) => Uint8Array = encoding.encode;
export const AccURL = address.URL;
