/**
 * ISRO SIH26171 - On-Device Privacy & PII Redaction Engine
 * TypeScript Definition File for Member 3 Module & VaultManager
 */

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface SensitiveItem {
  id: string;
  type: 'INPUT_FIELD' | 'TEXT_PII' | 'MEDIA_PII' | 'CUSTOM_ML';
  category: string;
  boundingBox: BoundingBox;
  redactionLabel: string;
}

export interface TokenMapEntry {
  id: string;
  category: string;
  label: string;
  coordinates: BoundingBox;
}

export interface TelemetryRecord {
  timestamp: string;
  sanitizationLatencyMs: number;
  redactedTokensCount: number;
  viewportDimensions: { width: number; height: number };
}

export interface SanitizationResult {
  sanitizedImage: string; // Base64 WebP Data URL
  tokenMap: TokenMapEntry[];
  telemetry: TelemetryRecord;
}

export interface PayloadValidationResult {
  isSecure: boolean;
  violationsCount: number;
  violations: Array<{ category: string; matchedSample: string; position: number }>;
  verifiedTimestamp: string;
}

export interface ContextAnalysisResult {
  confidence: number;
  shouldTokenize: boolean;
  matchedPositive: string[];
  matchedNegative: string[];
  contextSnippet: string;
}

export interface FlushResult {
  status: string;
  clearedItemsCount: number;
  activeVaultSize: number;
  timestamp: string;
}

export declare class VaultManager {
  constructor(options?: { contextWindowChars?: number; confidenceThreshold?: number; aliasPrefix?: string });
  analyzeContext(fullText: string, matchIndex: number, matchLength: number, category: string): ContextAnalysisResult;
  tokenize(rawSecret: string, category?: string): string;
  tokenizeText(text: string, patternMap: Record<string, RegExp>): string;
  detokenize(input: string): string;
  hasAlias(alias: string): boolean;
  getVaultSize(): number;
  flushVault(): FlushResult;
}

export interface PrivacyEngineConfig {
  maskFillColor?: string;
  tokenTextColor?: string;
  borderColor?: string;
  font?: string;
  pixelateSize?: number;
  enableStrictZeroLeakage?: boolean;
}

export declare class PrivacyEngine {
  vault: VaultManager | null;
  constructor(config?: PrivacyEngineConfig);
  scanDOM(customDocument?: Document): SensitiveItem[];
  sanitizeViewport(rawScreenshot: string | HTMLImageElement, customMlBoxes?: SensitiveItem[], scaleFactor?: number): Promise<SanitizationResult>;
  sanitizeAccessibilityTree(rawAccessibilityTree: any): any;
  validatePayload(outgoingJsonPayload: Record<string, any>): PayloadValidationResult;
  detokenize(input: string): string;
  flushVault(): FlushResult;
  getTelemetryMetrics(): { totalFramesProcessed: number; averageLatencyMs: number; latestRecord?: TelemetryRecord };
}
