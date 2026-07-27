import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    // never log key material, raw signatures, or PII
    paths: ['privateKey', 'secretKey', 'signature', 'key', 'seed', '*.privateKey', '*.secretKey'],
    censor: '[redacted]',
  },
});

export type Logger = pino.Logger;
