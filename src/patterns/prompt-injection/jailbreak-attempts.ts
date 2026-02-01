import { SecurityPattern, Severity } from '../../types';

export const jailbreakPatterns: SecurityPattern[] = [
  {
    id: 'jailbreak_en_001',
    category: 'prompt_injection',
    subcategory: 'jailbreak',
    pattern: /DAN\s+mode/i,
    severity: Severity.CRITICAL,
    language: 'en',
    description: 'Do Anything Now jailbreak attempt',
    examples: ['DAN mode activated', 'enter DAN mode'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['jailbreak', 'dan']
  },
  {
    id: 'jailbreak_en_002',
    pattern: /no\s+restrictions?\s+mode/i,
    severity: Severity.CRITICAL,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'jailbreak',
    description: 'Attempts to disable restrictions',
    examples: ['no restrictions mode', 'no restriction mode'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['jailbreak']
  },
  {
    id: 'jailbreak_en_003',
    pattern: /bypass\s+(your|the)?\s*(filters?|safety|guardrails?|restrictions?)/i,
    severity: Severity.CRITICAL,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'jailbreak',
    description: 'Direct bypass attempts',
    examples: ['bypass your filters', 'bypass safety', 'bypass restrictions'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['jailbreak']
  },
  {
    id: 'jailbreak_en_004',
    pattern: /disable\s+(safety|ethics|guardrails?|restrictions?)/i,
    severity: Severity.CRITICAL,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'jailbreak',
    description: 'Attempts to disable safety features',
    examples: ['disable safety', 'disable ethics', 'disable guardrails'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['jailbreak']
  }
];
