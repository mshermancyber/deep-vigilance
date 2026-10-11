// Complete Queue Definitions — All 16 queues for enterprise scanning
export const QUEUE_DEFINITIONS = {
  // Core queues (M8)
  'sast-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'high', description: 'Static Application Security Testing' },
  'dast-scan': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'high', description: 'Dynamic Application Security Testing' },
  'api-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'normal', description: 'API Security Scanning' },
  'report-generation': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'normal', description: 'Report Generation (PDF/HTML/JSON/CSV/MD)' },
  'notification': { concurrency: 8, rateLimit: { max: 20, duration: 60000 }, priority: 'low', description: 'Notification dispatching (email/Slack/webhook)' },

  // Enterprise SAST queues (M5a-M5k)
  'ast-analysis': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'high', description: 'AST-based deep analysis' },
  'dataflow-analysis': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'high', description: 'Dataflow and taint tracking' },
  'container-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'high', description: 'Container image layer-by-layer CVE scan' },
  'binary-scan': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'normal', description: 'Binary and mobile artifact scanning' },
  'sbom-generation': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'normal', description: 'SBOM generation (CycloneDX/SPDX)' },
  'apiprotocol-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'normal', description: 'API protocol scanning (gRPC/GraphQL/WS/SOAP)' },

  // Enterprise DAST queues (M6a-M6g)
  'dast-enterprise': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'high', description: 'Enterprise DAST (browser crawl, WAF evasion, advanced attacks)' },
  'dast-passive': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'low', description: 'Passive DAST scanning (no attacks sent)' },
  'evidence-capture': { concurrency: 2, rateLimit: { max: 5, duration: 60000 }, priority: 'low', description: 'Screenshot and HAR capture for findings' },

  // Rule ecosystem (M18-M19)
  'rule-sync': { concurrency: 1, rateLimit: { max: 1, duration: 3600000 }, priority: 'low', description: 'Golden source rule synchronization' },

  // Secrets scanning (M21)
  'secret-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'high', description: 'Secrets and credential detection' },

  // SCA (Software Composition Analysis)
  'sca-scan': { concurrency: 4, rateLimit: { max: 10, duration: 60000 }, priority: 'high', description: 'Software Composition Analysis (dependency vulnerabilities, supply chain, license compliance)' },

  // Code review (dependency/semantic/repo-health engines)
  'code-review': { concurrency: 2, rateLimit: { max: 6, duration: 60000 }, priority: 'high', description: 'Code Review (dependency/typosquat, semantic, repo-health)' },
} as const;

export type QueueName = keyof typeof QUEUE_DEFINITIONS;

export function getQueueNames(): QueueName[] { return Object.keys(QUEUE_DEFINITIONS) as QueueName[]; }
export function getQueueConfig(name: QueueName) { return QUEUE_DEFINITIONS[name]; }
