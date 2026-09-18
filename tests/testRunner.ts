/**
 * Automated Test Suite for Open Source Security Transition Monitor
 * Tests critical behavior using clearly labeled mock data and fixtures:
 * 1. URL validation (GitHub repo & Website SSRF defense)
 * 2. Threshold detection & metric evaluation
 * 3. Duplicate-event prevention via signatures
 * 4. Separation of event detection from notification generation
 * 5. Scanner result normalization & evidence preservation
 * 6. Deterministic prioritization & explainable ranking
 * 7. Remediation effort heuristics & disclaimer verification
 * 8. Deterministic allowed verdicts (all 6 allowed verdicts)
 * 9. Before-and-after scan comparison
 */

import { UrlValidator } from '../server/services/urlValidator.ts';
import { TransitionDetector } from '../server/services/transitionDetector.ts';
import { NotificationService } from '../server/services/notificationService.ts';
import { VulnerabilityProcessor } from '../server/services/vulnerabilityProcessor.ts';
import { RemediationService } from '../server/services/remediationService.ts';
import { MockWebsiteScanner, RawScannerFinding } from '../server/services/scanner/scannerAdapter.ts';
import {
  ClaimVerificationEngine,
  ClaimVerificationEngineV1,
  ClaimVerificationEngineV2,
  ReliabilityBenchmarkService,
} from '../server/services/verificationEngine.ts';
import {
  RELIABILITY_SCENARIOS,
} from '../server/fixtures/v1FailureScenarioFixture.ts';
import {
  RAW_SYNTHETIC_REPORT,
  SYNTHETIC_EVIDENCE_POOL,
} from '../server/fixtures/syntheticReportFixture.ts';
import {
  Claim,
  EvidenceItem,
  EngagementMetrics,
  Project,
  SyntheticReport,
  TransitionEvent,
  WebsiteScanResult,
} from '../src/types/index.ts';

export interface TestCaseResult {
  name: string;
  category: string;
  passed: boolean;
  message: string;
  durationMs: number;
}

export interface TestSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
  tests: TestCaseResult[];
}

export async function runSuite(): Promise<TestSuiteSummary> {
  const startTotal = Date.now();
  const tests: TestCaseResult[] = [];

  function record(name: string, category: string, fn: () => void | Promise<void>) {
    const start = Date.now();
    try {
      fn();
      tests.push({
        name,
        category,
        passed: true,
        message: 'Assertion passed successfully.',
        durationMs: Date.now() - start,
      });
    } catch (err: any) {
      tests.push({
        name,
        category,
        passed: false,
        message: err.message || String(err),
        durationMs: Date.now() - start,
      });
    }
  }

  // 1. URL Validation Tests
  record('Valid GitHub repository URL normalization', 'URL Validation', () => {
    const res1 = UrlValidator.validateGitHubUrl('https://github.com/facebook/react');
    if (!res1.isValid || res1.value?.owner !== 'facebook' || res1.value?.repo !== 'react') {
      throw new Error(`Expected valid facebook/react, got: ${JSON.stringify(res1)}`);
    }

    const res2 = UrlValidator.validateGitHubUrl('torvalds/linux');
    if (!res2.isValid || res2.value?.normalizedUrl !== 'https://github.com/torvalds/linux') {
      throw new Error(`Expected shorthand normalization, got: ${JSON.stringify(res2)}`);
    }
  });

  record('Invalid GitHub repository rejection', 'URL Validation', () => {
    const res = UrlValidator.validateGitHubUrl('https://gitlab.com/user/project');
    if (res.isValid) {
      throw new Error('Expected rejection of non-GitHub domain.');
    }
  });

  record('Website URL normalization & SSRF protection', 'URL Validation', () => {
    const valid = UrlValidator.validateWebsiteUrl('example.com/docs/');
    if (!valid.isValid || valid.value !== 'https://example.com/docs') {
      throw new Error(`Expected https://example.com/docs, got ${valid.value}`);
    }

    // SSRF checks
    const ssrfLocalhost = UrlValidator.validateWebsiteUrl('http://localhost:8080');
    if (ssrfLocalhost.isValid) {
      throw new Error('SSRF defense failed: localhost must be rejected.');
    }

    const ssrfPrivateIp = UrlValidator.validateWebsiteUrl('http://192.168.1.1/admin');
    if (ssrfPrivateIp.isValid) {
      throw new Error('SSRF defense failed: 192.168.1.1 must be rejected.');
    }
  });

  // 2. Threshold Detection & Duplicate Event Prevention
  const testProject: Project = {
    id: 'test_proj_1',
    name: 'Test Project',
    githubRepoUrl: 'https://github.com/test/repo',
    githubOwner: 'test',
    githubRepo: 'repo',
    websiteUrl: 'https://test-project.org',
    createdAt: new Date().toISOString(),
    thresholds: {
      githubStars: 1000,
      npmDownloads: 10000,
      outsideContributors: 1,
    },
  };

  record('Detects threshold crossing on 1,000 GitHub stars', 'Threshold Detection', () => {
    const metrics: EngagementMetrics = {
      githubStars: 1050,
      npmDownloads: 200,
      outsideContributors: 0,
      lastCheckedAt: new Date().toISOString(),
      source: 'mock_fixture',
    };

    const events = TransitionDetector.detectTransitionEvents(testProject, metrics, []);
    if (events.length !== 1) {
      throw new Error(`Expected 1 event, received ${events.length}`);
    }
    if (events[0].triggerType !== 'github_stars' || events[0].observedValue !== 1050) {
      throw new Error(`Incorrect event payload: ${JSON.stringify(events[0])}`);
    }
  });

  record('Enforces duplicate-event prevention on repeated checks', 'Duplicate Prevention', () => {
    const metrics: EngagementMetrics = {
      githubStars: 1200,
      npmDownloads: 500,
      outsideContributors: 0,
      lastCheckedAt: new Date().toISOString(),
      source: 'mock_fixture',
    };

    const firstRunEvents = TransitionDetector.detectTransitionEvents(testProject, metrics, []);
    if (firstRunEvents.length !== 1) {
      throw new Error(`Initial run failed to trigger event`);
    }

    // Second check with already recorded event history
    const secondRunEvents = TransitionDetector.detectTransitionEvents(testProject, metrics, firstRunEvents);
    if (secondRunEvents.length !== 0) {
      throw new Error(
        `Duplicate event was generated despite identical threshold signature: ${JSON.stringify(secondRunEvents)}`
      );
    }
  });

  // 3. Event Detection Separation from Notification Generation
  record('Separates event detection from notification generation', 'Architecture Pipeline', () => {
    const evt: TransitionEvent = {
      id: 'evt_sample_1',
      projectId: testProject.id,
      triggerType: 'github_stars',
      observedValue: 1000,
      threshold: 1000,
      timestamp: new Date().toISOString(),
      signature: `${testProject.id}:github_stars:1000`,
    };

    const notification = NotificationService.createNotificationFromEvent(testProject, evt);
    if (!notification.id.startsWith('notif_')) {
      throw new Error('Invalid notification ID prefix.');
    }
    if (notification.websiteUrl !== testProject.websiteUrl) {
      throw new Error('Notification did not preserve project website URL.');
    }
    if (!notification.milestoneMessage.includes('1,000')) {
      throw new Error('Notification milestone message did not include milestone value.');
    }
  });

  // 4. Scanner Result Normalization & Deduplication
  record('Normalizes findings, deduplicates repeated items, preserves evidence', 'Vulnerability Processing', () => {
    const rawFindings: RawScannerFinding[] = [
      {
        category: 'Missing Security Header',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        description: 'HSTS is absent',
        affectedUrlOrComponent: 'HTTP Response Headers',
        severity: 'Medium',
        evidence: 'Strict-Transport-Security header was missing',
        confirmed: true,
      },
      // Duplicate item with same category + title + component
      {
        category: 'Missing Security Header',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        description: 'HSTS is absent duplicate',
        affectedUrlOrComponent: 'HTTP Response Headers',
        severity: 'Medium',
        evidence: 'Strict-Transport-Security header was missing',
        confirmed: true,
      },
      {
        category: 'Exposed Sensitive Endpoint',
        title: 'Exposed Git Repository Metadata (/.git/HEAD)',
        description: 'Git metadata found',
        affectedUrlOrComponent: 'https://test-project.org/.git/HEAD',
        severity: 'Critical',
        evidence: 'ref: refs/heads/main HTTP 200 OK',
        confirmed: true,
      },
    ];

    const processed = VulnerabilityProcessor.processFindings(rawFindings);
    if (processed.length !== 2) {
      throw new Error(`Deduplication failed: expected 2 unique findings, got ${processed.length}`);
    }

    // Evidence preservation
    const gitFinding = processed.find((f) => f.severity === 'Critical');
    if (!gitFinding || gitFinding.evidence !== 'ref: refs/heads/main HTTP 200 OK') {
      throw new Error('Evidence was altered or not preserved in normalized finding.');
    }
  });

  // 5. Deterministic Prioritization Rules
  record('Prioritizes findings deterministically: Critical > High > Medium > Low', 'Deterministic Prioritization', () => {
    const rawFindings: RawScannerFinding[] = [
      {
        category: 'Information Disclosure',
        title: 'Detailed Server Banner Version Disclosure',
        description: 'Server banner leak',
        affectedUrlOrComponent: 'Server Header',
        severity: 'Low',
        evidence: 'Apache/2.4',
        confirmed: true,
      },
      {
        category: 'Exposed Sensitive Endpoint',
        title: 'Exposed Environment File (/.env)',
        description: 'Env file exposed',
        affectedUrlOrComponent: 'https://test.org/.env',
        severity: 'Critical',
        evidence: 'DATABASE_URL=postgres://...',
        confirmed: true,
      },
      {
        category: 'Insecure Transport',
        title: 'Plaintext HTTP Without Automatic HTTPS Redirection',
        description: 'Plain HTTP',
        affectedUrlOrComponent: 'https://test.org',
        severity: 'High',
        evidence: 'HTTP 200 on port 80 without redirect',
        confirmed: true,
      },
    ];

    const processed = VulnerabilityProcessor.processFindings(rawFindings);
    if (processed[0].severity !== 'Critical' || processed[0].priorityRank !== 1) {
      throw new Error(`Expected Critical to be Priority #1, got rank ${processed[0].priorityRank} (${processed[0].severity})`);
    }
    if (processed[1].severity !== 'High' || processed[1].priorityRank !== 2) {
      throw new Error(`Expected High to be Priority #2, got rank ${processed[1].priorityRank} (${processed[1].severity})`);
    }
    if (processed[2].severity !== 'Low' || processed[2].priorityRank !== 3) {
      throw new Error(`Expected Low to be Priority #3, got rank ${processed[2].priorityRank} (${processed[2].severity})`);
    }
  });

  // 6. Remediation Guidance & Effort Estimation
  record('Provides deterministic effort heuristics and explicitly states disclaimer', 'Remediation Service', () => {
    const guidance = RemediationService.getGuidance(
      'Insecure Transport',
      'Plaintext HTTP Without Automatic HTTPS Redirection',
      'High'
    );

    if (!guidance.exampleSnippet || !guidance.exampleSnippet.includes('301')) {
      throw new Error('Missing actionable remediation snippet.');
    }
    if (!guidance.effortDisclaimer.toLowerCase().includes('heuristic')) {
      throw new Error('Remediation effort did not distinguish heuristic estimate from measured time.');
    }
  });

  // 7. Deterministic Allowed Verdicts (Testing all 6 allowed verdicts)
  record('Evaluates all six allowed verdicts strictly through deterministic application logic', 'Verdict Generation', () => {
    // 1. Critical Issues Found
    const criticalFindings = VulnerabilityProcessor.processFindings([
      {
        category: 'Exposed Sensitive Endpoint',
        title: 'Exposed Git Repository Metadata',
        description: 'Git exposure',
        affectedUrlOrComponent: '/.git/HEAD',
        severity: 'Critical',
        evidence: 'ref: refs/heads/main',
        confirmed: true,
      },
    ]);
    const vCritical = VulnerabilityProcessor.determineVerdict(true, criticalFindings);
    if (vCritical.verdict !== 'Critical Issues Found') {
      throw new Error(`Expected "Critical Issues Found", got: "${vCritical.verdict}"`);
    }

    // 2. High-Risk Issues Found
    const highFindings = VulnerabilityProcessor.processFindings([
      {
        category: 'Insecure Transport',
        title: 'Plaintext HTTP',
        description: 'HTTP allowed',
        affectedUrlOrComponent: 'http://test.org',
        severity: 'High',
        evidence: 'Plain HTTP',
        confirmed: true,
      },
    ]);
    const vHigh = VulnerabilityProcessor.determineVerdict(true, highFindings);
    if (vHigh.verdict !== 'High-Risk Issues Found') {
      throw new Error(`Expected "High-Risk Issues Found", got: "${vHigh.verdict}"`);
    }

    // 3. Issues Found (Only Medium/Low/Info)
    const mediumFindings = VulnerabilityProcessor.processFindings([
      {
        category: 'Missing Security Header',
        title: 'Missing HSTS',
        description: 'HSTS missing',
        affectedUrlOrComponent: 'Headers',
        severity: 'Medium',
        evidence: 'No HSTS header',
        confirmed: true,
      },
    ]);
    const vIssues = VulnerabilityProcessor.determineVerdict(true, mediumFindings);
    if (vIssues.verdict !== 'Issues Found') {
      throw new Error(`Expected "Issues Found", got: "${vIssues.verdict}"`);
    }

    // 4. No Issues Detected
    const vClean = VulnerabilityProcessor.determineVerdict(true, []);
    if (vClean.verdict !== 'No Issues Detected') {
      throw new Error(`Expected "No Issues Detected", got: "${vClean.verdict}"`);
    }

    // 5. Scan Incomplete
    const vIncomplete = VulnerabilityProcessor.determineVerdict(false, []);
    if (vIncomplete.verdict !== 'Scan Incomplete') {
      throw new Error(`Expected "Scan Incomplete", got: "${vIncomplete.verdict}"`);
    }

    // 6. Manual Review Required
    const ambiguousFindings = VulnerabilityProcessor.processFindings([
      {
        category: 'Missing Security Header',
        title: 'Unverified Custom Header',
        description: 'Ambiguous header',
        affectedUrlOrComponent: 'Proxy Header',
        severity: 'Medium',
        evidence: 'Pending manual check',
        confirmed: false, // Unverified!
      },
    ]);
    const vManual = VulnerabilityProcessor.determineVerdict(true, ambiguousFindings, true);
    if (vManual.verdict !== 'Manual Review Required') {
      throw new Error(`Expected "Manual Review Required", got: "${vManual.verdict}"`);
    }
  });

  // 8. Before-and-After Scan Comparison
  record('Calculates before-and-after scan diff (resolved, persisting, new)', 'Scan Comparison', () => {
    const scanA: WebsiteScanResult = {
      id: 'scan_1',
      projectId: 'p1',
      targetUrl: 'https://test.org',
      status: 'completed',
      startedAt: '2026-09-17T10:00:00Z',
      completedAt: '2026-09-17T10:00:05Z',
      verdict: 'High-Risk Issues Found',
      verdictReason: 'Plaintext HTTP found.',
      findings: VulnerabilityProcessor.processFindings([
        {
          category: 'Insecure Transport',
          title: 'Plaintext HTTP Without Automatic HTTPS Redirection',
          description: 'HTTP allowed',
          affectedUrlOrComponent: 'https://test.org',
          severity: 'High',
          evidence: 'HTTP 200',
          confirmed: true,
        },
        {
          category: 'Missing Security Header',
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          description: 'No HSTS',
          affectedUrlOrComponent: 'Headers',
          severity: 'Medium',
          evidence: 'Absence of HSTS',
          confirmed: true,
        },
      ]),
      summary: { criticalCount: 0, highCount: 1, mediumCount: 1, lowCount: 0, infoCount: 0, totalFindings: 2 },
      scannerType: 'mock_fixture',
      scopeNotes: [],
      disclaimer: 'Disclaimer text',
    };

    // Subsequent scan where Insecure Transport was resolved, HSTS persists, and CSP is newly reported
    const scanB: WebsiteScanResult = {
      id: 'scan_2',
      projectId: 'p1',
      targetUrl: 'https://test.org',
      status: 'completed',
      startedAt: '2026-09-18T10:00:00Z',
      completedAt: '2026-09-18T10:00:05Z',
      verdict: 'Issues Found',
      verdictReason: 'Medium issues persist.',
      findings: VulnerabilityProcessor.processFindings([
        {
          category: 'Missing Security Header',
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          description: 'No HSTS',
          affectedUrlOrComponent: 'Headers',
          severity: 'Medium',
          evidence: 'Absence of HSTS',
          confirmed: true,
        },
        {
          category: 'Content Security Policy',
          title: 'Missing Content Security Policy (CSP)',
          description: 'No CSP',
          affectedUrlOrComponent: 'Headers',
          severity: 'Medium',
          evidence: 'Absence of CSP',
          confirmed: true,
        },
      ]),
      summary: { criticalCount: 0, highCount: 0, mediumCount: 2, lowCount: 0, infoCount: 0, totalFindings: 2 },
      scannerType: 'mock_fixture',
      scopeNotes: [],
      disclaimer: 'Disclaimer text',
    };

    const diff = VulnerabilityProcessor.compareScans(scanA, scanB);
    if (diff.resolvedFindings.length !== 1 || diff.resolvedFindings[0].category !== 'Insecure Transport') {
      throw new Error(`Failed to identify resolved finding: ${JSON.stringify(diff.resolvedFindings)}`);
    }
    if (diff.persistingFindings.length !== 1 || !diff.persistingFindings[0].title.includes('HSTS')) {
      throw new Error(`Failed to identify persisting finding: ${JSON.stringify(diff.persistingFindings)}`);
    }
    if (diff.newFindings.length !== 1 || diff.newFindings[0].category !== 'Content Security Policy') {
      throw new Error(`Failed to identify new finding: ${JSON.stringify(diff.newFindings)}`);
    }
  });

  // 12. Claim Verification: VERIFIED State & Evidence Linkage
  record(
    'Produces VERIFIED state with explicit linked supporting evidence',
    'Claim Verification',
    () => {
      const claim: Claim = {
        id: 'test_claim_stars',
        statement: 'Repository has reached 1,000 GitHub stars threshold.',
        category: 'Milestone',
        ruleType: 'NUMERIC_THRESHOLD',
        numericThreshold: { threshold: 1000, operator: '>=' },
        targetEvidenceSource: 'GitHub REST API',
        status: 'INSUFFICIENT_EVIDENCE',
        verificationReason: '',
        evidenceLinks: [],
        lastVerifiedAt: '',
      };

      const result = ClaimVerificationEngine.verifyClaim(claim, SYNTHETIC_EVIDENCE_POOL);

      if (result.status !== 'VERIFIED') {
        throw new Error(`Expected status VERIFIED, got "${result.status}"`);
      }
      if (result.evidenceLinks.length === 0) {
        throw new Error('VERIFIED claim must have at least one explicitly linked evidence item.');
      }
      const supportLink = result.evidenceLinks.find((l) => l.relationship === 'SUPPORTS');
      if (!supportLink) {
        throw new Error('VERIFIED claim must have an evidence link with relationship SUPPORTS.');
      }
      if (!result.verificationReason.includes('Claim verified by')) {
        throw new Error(`Expected traceable verification reason, got: ${result.verificationReason}`);
      }
    }
  );

  // 13. Claim Verification: CONTRADICTED State & Evidence Linkage
  record(
    'Produces CONTRADICTED state with explicit linked contradicting evidence',
    'Claim Verification',
    () => {
      const claim: Claim = {
        id: 'test_claim_https',
        statement: 'All plain HTTP requests are strictly redirected to HTTPS.',
        category: 'Transport Security',
        ruleType: 'STRING_INCLUSION',
        expectedValue: 'redirect to https',
        targetEvidenceSource: 'HTTP Insecure Transport Probe (Port 80)',
        status: 'INSUFFICIENT_EVIDENCE',
        verificationReason: '',
        evidenceLinks: [],
        lastVerifiedAt: '',
      };

      const result = ClaimVerificationEngine.verifyClaim(claim, SYNTHETIC_EVIDENCE_POOL);

      if (result.status !== 'CONTRADICTED') {
        throw new Error(`Expected status CONTRADICTED, got "${result.status}"`);
      }
      if (result.evidenceLinks.length === 0) {
        throw new Error('CONTRADICTED claim must have at least one explicitly linked evidence item.');
      }
      const contradictLink = result.evidenceLinks.find((l) => l.relationship === 'CONTRADICTS');
      if (!contradictLink) {
        throw new Error('CONTRADICTED claim must have an evidence link with relationship CONTRADICTS.');
      }
      if (!result.verificationReason.includes('Claim contradicted by')) {
        throw new Error(`Expected traceable contradiction reason, got: ${result.verificationReason}`);
      }
    }
  );

  // 14. Claim Verification: INSUFFICIENT_EVIDENCE State When Evidence Missing
  record(
    'Produces INSUFFICIENT_EVIDENCE state when candidate evidence is missing or inconclusive',
    'Claim Verification',
    () => {
      const claim: Claim = {
        id: 'test_claim_dns',
        statement: 'DNS CAA records restrict certificate issuance to Let\'s Encrypt.',
        category: 'DNS PKI',
        ruleType: 'STRING_INCLUSION',
        expectedValue: 'issue "letsencrypt.org"',
        targetEvidenceSource: 'DNS CAA Record Resolver (Non-existent Source)',
        status: 'VERIFIED', // Intentionally pre-filled as VERIFIED to ensure engine resets it
        verificationReason: '',
        evidenceLinks: [],
        lastVerifiedAt: '',
      };

      const result = ClaimVerificationEngine.verifyClaim(claim, SYNTHETIC_EVIDENCE_POOL);

      if (result.status !== 'INSUFFICIENT_EVIDENCE') {
        throw new Error(`Expected status INSUFFICIENT_EVIDENCE, got "${result.status}"`);
      }
      if (!result.verificationReason.includes('No candidate evidence was found')) {
        throw new Error(`Expected missing evidence reason, got: ${result.verificationReason}`);
      }
    }
  );

  // 15. Evidence Provenance Preservation
  record(
    'Preserves full evidence provenance (ID, source, excerpt, relationship) on linked claims',
    'Evidence Provenance',
    () => {
      const claim: Claim = {
        id: 'test_claim_git',
        statement: 'Server does not expose .git repository directory.',
        category: 'Information Disclosure',
        ruleType: 'PRESENCE_CHECK',
        targetEvidenceSource: 'HTTP Sensitive Endpoint Probe: /.git/HEAD',
        status: 'INSUFFICIENT_EVIDENCE',
        verificationReason: '',
        evidenceLinks: [],
        lastVerifiedAt: '',
      };

      const result = ClaimVerificationEngine.verifyClaim(claim, SYNTHETIC_EVIDENCE_POOL);

      if (result.evidenceLinks.length === 0) {
        throw new Error('Expected linked evidence for provenance test.');
      }

      const link = result.evidenceLinks[0];
      if (!link.evidenceId || !link.evidence.source || !link.evidence.excerpt) {
        throw new Error(`Missing provenance fields in evidence link: ${JSON.stringify(link)}`);
      }
      if (!link.relationship || !link.rationale) {
        throw new Error(`Missing relationship or rationale: ${JSON.stringify(link)}`);
      }
      if (!link.evidence.collectedAt || !link.evidence.collector) {
        throw new Error(`Missing collector or timestamp provenance: ${JSON.stringify(link.evidence)}`);
      }
    }
  );

  // 16. Synthetic Report End-to-End Processing
  record(
    'Deterministically processes synthetic report containing all three states (VERIFIED, CONTRADICTED, INSUFFICIENT_EVIDENCE)',
    'Synthetic Report Processor',
    () => {
      const processedReport = ClaimVerificationEngine.processReport(
        RAW_SYNTHETIC_REPORT,
        SYNTHETIC_EVIDENCE_POOL
      );

      const verified = processedReport.claims.filter((c) => c.status === 'VERIFIED');
      const contradicted = processedReport.claims.filter((c) => c.status === 'CONTRADICTED');
      const insufficient = processedReport.claims.filter((c) => c.status === 'INSUFFICIENT_EVIDENCE');

      if (verified.length < 1) {
        throw new Error(`Expected at least one VERIFIED claim, got ${verified.length}`);
      }
      if (contradicted.length < 1) {
        throw new Error(`Expected at least one CONTRADICTED claim, got ${contradicted.length}`);
      }
      if (insufficient.length < 1) {
        throw new Error(`Expected at least one INSUFFICIENT_EVIDENCE claim, got ${insufficient.length}`);
      }

      // Ensure every VERIFIED or CONTRADICTED claim has visibly linked evidence
      for (const v of verified) {
        if (v.evidenceLinks.length === 0) {
          throw new Error(`VERIFIED claim "${v.id}" has no linked evidence.`);
        }
      }
      for (const c of contradicted) {
        if (c.evidenceLinks.length === 0) {
          throw new Error(`CONTRADICTED claim "${c.id}" has no linked evidence.`);
        }
      }

      // Ensure summary tallies match exactly
      if (processedReport.summary.verifiedCount !== verified.length) {
        throw new Error(`Summary verifiedCount mismatch: expected ${verified.length}, got ${processedReport.summary.verifiedCount}`);
      }
      if (processedReport.summary.contradictedCount !== contradicted.length) {
        throw new Error(`Summary contradictedCount mismatch: expected ${contradicted.length}, got ${processedReport.summary.contradictedCount}`);
      }
      if (processedReport.summary.insufficientEvidenceCount !== insufficient.length) {
        throw new Error(`Summary insufficientEvidenceCount mismatch: expected ${insufficient.length}, got ${processedReport.summary.insufficientEvidenceCount}`);
      }
    }
  );

  // 17. PRISM V1 Known Failure Reproduction
  record(
    'Reproduces known V1 PRISM failure (stale historical evidence overrides post-remediation fix)',
    'Verification Reliability V1',
    () => {
      const scenario = RELIABILITY_SCENARIOS.find((s) => s.id === 'scen_01_remediation_hsts');
      if (!scenario) throw new Error('Remediation scenario fixture not found.');

      // Under V1: The older contradictory probe overrides the newer verified probe
      const v1Result = ClaimVerificationEngineV1.verifyClaim(
        JSON.parse(JSON.stringify(scenario.claim)),
        scenario.evidence
      );

      // Reproduce known V1 failure: status is CONTRADICTED despite post-remediation evidence
      if (v1Result.status !== 'CONTRADICTED') {
        throw new Error(`Expected V1 to exhibit failure by outputting CONTRADICTED, got "${v1Result.status}"`);
      }
    }
  );

  // 18. PRISM V2 Exact Engineering Fix
  record(
    'Demonstrates exact V2 engineering fix on identical scenario (temporal recency resolves post-remediation fix to VERIFIED)',
    'Verification Reliability V2',
    () => {
      const scenario = RELIABILITY_SCENARIOS.find((s) => s.id === 'scen_01_remediation_hsts');
      if (!scenario) throw new Error('Remediation scenario fixture not found.');

      // Under V2: The post-remediation probe is identified as newer (T1 > T0) and supersedes the historical contradiction
      const v2Result = ClaimVerificationEngineV2.verifyClaim(
        JSON.parse(JSON.stringify(scenario.claim)),
        scenario.evidence
      );

      if (v2Result.status !== 'VERIFIED') {
        throw new Error(`Expected V2 to resolve remediation scenario to VERIFIED, got "${v2Result.status}"`);
      }
      if (!v2Result.verificationReason.includes('Historical contradiction [ev_hsts_historical_fail] was superseded')) {
        throw new Error(`Expected superseded provenance note in reason, got "${v2Result.verificationReason}"`);
      }
    }
  );

  // 19. Measured Before/After Benchmark Execution
  record(
    'Executes live benchmark comparing V1 baseline vs V2 corrected across identical scenarios',
    'Verification Reliability Benchmark',
    () => {
      const report = ReliabilityBenchmarkService.runBenchmark();

      if (report.totalScenarios !== 4) {
        throw new Error(`Expected 4 benchmark scenarios, got ${report.totalScenarios}`);
      }

      // Assert measured before metric (V1: 50.0% accuracy, 50.0% false contradiction rate)
      if (report.metrics.before.accuracyPct !== 50.0) {
        throw new Error(`Expected V1 accuracy to measure 50.0%, got ${report.metrics.before.accuracyPct}%`);
      }
      if (report.metrics.before.falseContradictionRatePct !== 50.0) {
        throw new Error(`Expected V1 false contradiction rate to measure 50.0%, got ${report.metrics.before.falseContradictionRatePct}%`);
      }

      // Assert measured after metric (V2: 100.0% accuracy, 0.0% false contradiction rate)
      if (report.metrics.after.accuracyPct !== 100.0) {
        throw new Error(`Expected V2 accuracy to measure 100.0%, got ${report.metrics.after.accuracyPct}%`);
      }
      if (report.metrics.after.falseContradictionRatePct !== 0.0) {
        throw new Error(`Expected V2 false contradiction rate to measure 0.0%, got ${report.metrics.after.falseContradictionRatePct}%`);
      }

      // Assert measured delta (+50% accuracy gain, -50% false contradiction reduction)
      if (report.metrics.delta.accuracyGainPct !== 50.0) {
        throw new Error(`Expected +50.0% accuracy gain, got ${report.metrics.delta.accuracyGainPct}%`);
      }
      if (report.metrics.delta.falseContradictionReductionPct !== 50.0) {
        throw new Error(`Expected 50.0% false contradiction reduction, got ${report.metrics.delta.falseContradictionReductionPct}%`);
      }
    }
  );

  // 20. Synthetic Report Upload Flow: Ingestion & Deterministic Evaluation
  record(
    'Validates and processes uploaded synthetic report with full provenance across all three claim states',
    'Report Upload Engine',
    async () => {
      const uploadedReportPayload: SyntheticReport = {
        id: 'rep_custom_upload_test',
        title: 'Custom Ingested Security Audit',
        projectId: 'proj_devcli',
        generatedAt: '2026-09-18T12:00:00Z',
        description: 'Uploaded report for automated regression test.',
        claims: [
          {
            id: 'claim_up_1',
            statement: 'Repository has reached 1,000 GitHub stars.',
            category: 'Milestones',
            ruleType: 'NUMERIC_THRESHOLD',
            numericThreshold: { threshold: 1000, operator: '>=' },
            targetEvidenceSource: 'GitHub REST API',
            status: 'INSUFFICIENT_EVIDENCE',
            verificationReason: '',
            evidenceLinks: [],
            lastVerifiedAt: '',
          },
          {
            id: 'claim_up_2',
            statement: 'Server does not expose .git directory.',
            category: 'Information Disclosure',
            ruleType: 'PRESENCE_CHECK',
            expectedValue: 'not exposed',
            targetEvidenceSource: 'HTTP Sensitive Endpoint Probe: /.git/HEAD',
            status: 'INSUFFICIENT_EVIDENCE',
            verificationReason: '',
            evidenceLinks: [],
            lastVerifiedAt: '',
          },
          {
            id: 'claim_up_3',
            statement: 'DNS CAA records enforce certificate authority restrictions.',
            category: 'PKI',
            ruleType: 'STRING_INCLUSION',
            expectedValue: 'issue "letsencrypt.org"',
            targetEvidenceSource: 'DNS CAA Record Resolver',
            status: 'INSUFFICIENT_EVIDENCE',
            verificationReason: '',
            evidenceLinks: [],
            lastVerifiedAt: '',
          },
        ],
        summary: { totalClaims: 3, verifiedCount: 0, contradictedCount: 0, insufficientEvidenceCount: 3 },
      };

      const customEvidence: EvidenceItem[] = [
        {
          id: 'ev_up_stars',
          source: 'GitHub REST API',
          referenceUrl: 'https://api.github.com',
          observedValue: 1240,
          excerpt: 'stargazers: 1240',
          collectedAt: '2026-09-18T12:00:00Z',
          collector: 'Test Collector',
          provenanceHash: 'sha256:stars-1240',
        },
        {
          id: 'ev_up_git',
          source: 'HTTP Sensitive Endpoint Probe: /.git/HEAD',
          referenceUrl: 'https://superprompt-cli.dev/.git/HEAD',
          observedValue: 'HTTP 200 OK with Git pointer',
          excerpt: 'ref: refs/heads/main',
          collectedAt: '2026-09-18T12:00:00Z',
          collector: 'Test Collector',
          provenanceHash: 'sha256:git-exposed',
        },
      ];

      const processed = ClaimVerificationEngine.processReport(uploadedReportPayload, customEvidence);

      if (processed.summary.totalClaims !== 3) {
        throw new Error(`Expected 3 claims, got ${processed.summary.totalClaims}`);
      }
      if (processed.claims[0].status !== 'VERIFIED') {
        throw new Error(`Expected claim_up_1 to be VERIFIED, got ${processed.claims[0].status}`);
      }
      if (processed.claims[1].status !== 'CONTRADICTED') {
        throw new Error(`Expected claim_up_2 to be CONTRADICTED, got ${processed.claims[1].status}`);
      }
      if (processed.claims[2].status !== 'INSUFFICIENT_EVIDENCE') {
        throw new Error(`Expected claim_up_3 to be INSUFFICIENT_EVIDENCE, got ${processed.claims[2].status}`);
      }

      // Assert evidence provenance is linked
      if (processed.claims[0].evidenceLinks.length !== 1 || processed.claims[0].evidenceLinks[0].evidence.id !== 'ev_up_stars') {
        throw new Error('Claim 1 did not link to ev_up_stars');
      }
      if (processed.claims[1].evidenceLinks.length !== 1 || processed.claims[1].evidenceLinks[0].evidence.id !== 'ev_up_git') {
        throw new Error('Claim 2 did not link to ev_up_git');
      }
    }
  );

  const passedCount = tests.filter((t) => t.passed).length;
  return {
    total: tests.length,
    passed: passedCount,
    failed: tests.length - passedCount,
    durationMs: Date.now() - startTotal,
    tests,
  };
}
