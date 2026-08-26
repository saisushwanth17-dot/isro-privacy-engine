/**
 * ISRO SIH26171 - On-Device Privacy & PII Redaction Engine
 * TypeScript Definition File for Member 3 Module
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
  category: 'PASSWORD' | 'AUTH_CREDENTIAL' | 'AADHAAR' | 'PAN' | 'CREDITCARD' | 'INDIANPHONE' | 'EMAIL' | 'UPIID' | 'FACE_AVATAR';
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

export interface PrivacyEngineConfig {
  maskFillColor?: string;
  tokenTextColor?: string;
  borderColor?: string;
  font?: string;
  pixelateSize?: number;
  enableStrictZeroLeakage?: boolean;
}

export declare class PrivacyEngine {
  constructor(config?: PrivacyEngineConfig);
  scanDOM(customDocument?: Document): SensitiveItem[];
  sanitizeViewport(rawScreenshot: string | HTMLImageElement, customMlBoxes?: SensitiveItem[], scaleFactor?: number): Promise<SanitizationResult>;
  validatePayload(outgoingJsonPayload: Record<string, any>): PayloadValidationResult;
  getTelemetryMetrics(): { totalFramesProcessed: number; averageLatencyMs: number; latestRecord?: TelemetryRecord };
}
