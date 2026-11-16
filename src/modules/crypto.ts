import { EncryptedSummaryPayload } from '../types/security';

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  if (window.crypto && window.crypto.subtle) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return bufferToHex(hashBuffer);
  }
  // Fallback simple hash for non-crypto contexts
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return 'fallback-' + Math.abs(hash).toString(16);
}

export async function encryptAuditSummary(
  summaryObject: Record<string, unknown>,
  passphrase: string
): Promise<EncryptedSummaryPayload> {
  const plaintext = JSON.stringify(summaryObject, null, 2);
  const sha256PlaintextHash = await sha256(plaintext);
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);

  const iterations = 100000;

  if (window.crypto && window.crypto.subtle) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource
      },
      derivedKey,
      plaintextBytes as BufferSource
    );

    const ciphertextBase64 = bufferToBase64(ciphertextBuffer);

    // Metadata snapshot for quick preview without exposing secrets
    const summary = summaryObject as {
      score?: number;
      grade?: string;
      findingsCount?: number;
      compliance?: { cis?: number; nist?: number };
      severities?: Record<string, number>;
    };

    return {
      algorithm: 'AES-256-GCM',
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations,
      saltHex: bufferToHex(salt),
      ivHex: bufferToHex(iv),
      ciphertextBase64,
      sha256PlaintextHash,
      createdAt: new Date().toISOString(),
      summarySnapshot: {
        title: 'Executive Cloud Configuration Security Audit',
        score: summary.score ?? 0,
        grade: summary.grade ?? 'F',
        findingsCount: summary.findingsCount ?? 0,
        cisPercent: summary.compliance?.cis ?? 0,
        nistPercent: summary.compliance?.nist ?? 0,
        criticalCount: summary.severities?.CRITICAL ?? 0,
        highCount: summary.severities?.HIGH ?? 0,
        mediumCount: summary.severities?.MEDIUM ?? 0,
        lowCount: summary.severities?.LOW ?? 0
      }
    };
  }

  // Pure JS fallback in rare environments without SubtleCrypto
  let xorCipher = '';
  for (let i = 0; i < plaintext.length; i++) {
    xorCipher += String.fromCharCode(plaintext.charCodeAt(i) ^ passphrase.charCodeAt(i % passphrase.length));
  }
  return {
    algorithm: 'XOR-FALLBACK',
    kdf: 'STATIC',
    iterations: 1,
    saltHex: '0000',
    ivHex: '0000',
    ciphertextBase64: btoa(xorCipher),
    sha256PlaintextHash,
    createdAt: new Date().toISOString(),
    summarySnapshot: {
      title: 'Executive Cloud Configuration Security Audit',
      score: 0,
      grade: 'F',
      findingsCount: 0,
      cisPercent: 0,
      nistPercent: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0
    }
  };
}

export async function decryptAuditSummary(
  payload: EncryptedSummaryPayload,
  passphrase: string
): Promise<Record<string, unknown>> {
  if (payload.algorithm === 'AES-256-GCM' && window.crypto && window.crypto.subtle) {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const salt = hexToBuffer(payload.saltHex);
    const iv = hexToBuffer(payload.ivHex);
    const ciphertextBytes = base64ToBuffer(payload.ciphertextBase64);

    try {
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      const derivedKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt as BufferSource,
          iterations: payload.iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as BufferSource
        },
        derivedKey,
        ciphertextBytes as BufferSource
      );

      const plaintext = decoder.decode(decryptedBuffer);

      // Verify integrity
      const recalculatedHash = await sha256(plaintext);
      if (recalculatedHash !== payload.sha256PlaintextHash) {
        throw new Error('Integrity validation failed: Hash mismatch in decrypted payload.');
      }

      return JSON.parse(plaintext);
    } catch {
      throw new Error('Authentication failed: Invalid security passphrase or corrupted ciphertext.');
    }
  }

  // Fallback decrypt
  try {
    const decoded = atob(payload.ciphertextBase64);
    let xorPlain = '';
    for (let i = 0; i < decoded.length; i++) {
      xorPlain += String.fromCharCode(decoded.charCodeAt(i) ^ passphrase.charCodeAt(i % passphrase.length));
    }
    return JSON.parse(xorPlain);
  } catch {
    throw new Error('Decryption failed: Passphrase incorrect.');
  }
}

export function generateStrongPassphrase(): string {
  const parts = ['c10ud', 'gU4rd', 'v4uLt', '53cur3', 'aUd1t', 'c1ph3r', 'n15t', 'c15'];
  const p1 = parts[Math.floor(Math.random() * parts.length)];
  const p2 = parts[Math.floor(Math.random() * parts.length)];
  const randNum = Math.floor(1000 + Math.random() * 9000);
  const randHex = Math.random().toString(16).substring(2, 6);
  return `${p1}-${p2}-${randNum}-${randHex}`;
}
