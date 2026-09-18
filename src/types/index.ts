/**
 * Open Source Security Transition Monitor - Domain Types
 */

export interface ProjectThresholds {
  githubStars: number;
  npmDownloads: number;
  outsideContributors: number;
}

export interface EngagementMetrics {
  githubStars: number | null;
  npmDownloads: number | null;
  outsideContributors: number | null;
  lastCheckedAt: string;
  source: 'live_api' | 'mock_fixture' | 'unavailable';
  rateLimitRemaining?: number;
  statusNotes?: string;
}

export interface Project {
  id: string;
  name: string;
  githubRepoUrl: string;
  githubOwner: string;
  githubRepo: string;
  websiteUrl: string;
  npmPackageName?: string;
  createdAt: string;
  thresholds: ProjectThresholds;
  currentMetrics?: EngagementMetrics;
}

export type TriggerType = 'github_stars' | 'npm_downloads' | 'outside_contributors';

export interface TransitionEvent {
  id: string;
  projectId: string;
  triggerType: TriggerType;
  observedValue: number;
  threshold: number;
  timestamp: string;
  signature: string; // Used for deterministic duplicate prevention: `${projectId}:${triggerType}:${threshold}`
}

export interface SecurityAssessmentNotification {
  id: string;
  projectId: string;
  transitionEventId: string;
  title: string;
  milestoneMessage: string;
  recommendation: string;
  websiteUrl: string;
  createdAt: string;
  read: boolean;
  status: 'pending_scan' | 'scan_initiated' | 'dismissed';
}

export type VulnerabilityCategory =
  | 'Insecure Transport'
  | 'Missing Security Header'
  | 'Content Security Policy'
  | 'Cookie Security'
  | 'Information Disclosure'
  | 'CORS Misconfiguration'
  | 'Exposed Sensitive Endpoint';

export type VulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface RemediationGuidance {
  title: string;
  guidance: string;
  exampleSnippet?: string;
  estimatedEffort: string; // e.g. "Low: ~15-30 mins"
  effortCategory: 'Low' | 'Medium' | 'High';
  effortDisclaimer: string; // Explicitly distinguishes estimated effort from measured time
}

export interface VulnerabilityFinding {
  id: string;
  category: VulnerabilityCategory;
  title: string;
  description: string;
  affectedUrlOrComponent: string;
  severity: VulnerabilitySeverity;
  evidence: string;
  detectionTimestamp: string;
  confirmed: boolean; // Distinguishes confirmed findings from unverified observations
  priorityRank: number; // Deterministic priority ranking (1 = highest)
  priorityReason: string; // Deterministic explainable rule
  remediation: RemediationGuidance;
}

/**
 * Allowed verdicts per specification:
 * - Critical Issues Found: At least one verified finding has been classified as critical by the defined severity rules.
 * - High-Risk Issues Found: No critical finding exists, but at least one verified finding has been classified as high severity.
 * - Issues Found: Verified findings exist, but none meet the critical or high severity criteria.
 * - No Issues Detected: The completed scan returned no findings within its configured scope.
 * - Scan Incomplete: The scan could not complete successfully.
 * - Manual Review Required: Findings or scan conditions require human verification before a reliable conclusion can be made.
 */
export type ScanVerdict =
  | 'Critical Issues Found'
  | 'High-Risk Issues Found'
  | 'Issues Found'
  | 'No Issues Detected'
  | 'Scan Incomplete'
  | 'Manual Review Required';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface ScanSummary {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalFindings: number;
}

export interface WebsiteScanResult {
  id: string;
  projectId: string;
  targetUrl: string;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  verdict: ScanVerdict;
  verdictReason: string;
  findings: VulnerabilityFinding[];
  summary: ScanSummary;
  scannerType: 'live_http' | 'mock_fixture';
  errorMessage?: string;
  scopeNotes: string[];
  disclaimer: string;
}

export interface BeforeAfterComparison {
  previousScanId: string;
  currentScanId: string;
  previousVerdict: ScanVerdict;
  currentVerdict: ScanVerdict;
  resolvedFindings: VulnerabilityFinding[];
  persistingFindings: VulnerabilityFinding[];
  newFindings: VulnerabilityFinding[];
}

/**
 * Trust, Safety & Digital Security: Evidence & Claim Verification Layer
 */

export type ClaimState = 'VERIFIED' | 'CONTRADICTED' | 'INSUFFICIENT_EVIDENCE';

export type EvidenceRelationship = 'SUPPORTS' | 'CONTRADICTS' | 'NEUTRAL';

export interface EvidenceItem {
  id: string;
  source: string;              // Source origin, e.g. "HTTP Response Header", "GitHub REST API", "DNS Query"
  referenceUrl?: string;       // Exact endpoint or URI inspected
  observedValue: string | number | boolean | null; // Raw observed metric or string value
  excerpt: string;             // Exact observed excerpt or evidence string
  collectedAt: string;         // ISO timestamp of collection
  collector: string;           // Tool or probe that collected the evidence
  provenanceHash?: string;     // Hash/checksum or status code tracking provenance
}

export interface ClaimEvidenceLink {
  evidenceId: string;
  evidence: EvidenceItem;
  relationship: EvidenceRelationship; // Direct relationship to the claim: SUPPORTS | CONTRADICTS | NEUTRAL
  rationale: string;                  // Deterministic reason explaining the relationship
}

export type ClaimVerificationRuleType =
  | 'NUMERIC_THRESHOLD'
  | 'STRING_INCLUSION'
  | 'EXACT_MATCH'
  | 'BOOLEAN_STATE'
  | 'PRESENCE_CHECK';

export interface Claim {
  id: string;
  statement: string;           // Exact claim assertion
  category: string;            // Domain category (e.g., "Transport Security", "Milestone Metrics", "Access Control")
  ruleType: ClaimVerificationRuleType;
  expectedValue?: string | number | boolean;
  numericThreshold?: {
    threshold: number;
    operator: '>=' | '<=' | '>' | '<' | '==';
  };
  targetEvidenceSource: string; // Identifier or pattern for candidate evidence
  status: ClaimState;          // VERIFIED | CONTRADICTED | INSUFFICIENT_EVIDENCE
  verificationReason: string;  // Traceable reason explaining status
  evidenceLinks: ClaimEvidenceLink[]; // Visibly linked evidence items
  lastVerifiedAt: string;
}

export interface SyntheticReport {
  id: string;
  title: string;
  projectId: string;
  generatedAt: string;
  description: string;
  claims: Claim[];
  summary: {
    totalClaims: number;
    verifiedCount: number;
    contradictedCount: number;
    insufficientEvidenceCount: number;
  };
}
