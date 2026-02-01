import { SecurityPattern, Severity } from '../../types';

export const instructionOverridePatterns: SecurityPattern[] = [
  {
    id: 'instruction_override_en_001',
    category: 'prompt_injection',
    subcategory: 'instruction_override',
    pattern: /ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|commands?|prompts?)/i,
    severity: Severity.CRITICAL,
    language: 'en',
    description: 'Attempts to override previous instructions',
    examples: [
      'ignore all previous instructions',
      'ignore prior commands',
      'ignore earlier prompts'
    ],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['instruction-override', 'high-confidence']
  },
  {
    id: 'instruction_override_en_002',
    pattern: /disregard\s+(all\s+)?(previous|prior|earlier|above)/i,
    severity: Severity.CRITICAL,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'instruction_override',
    description: 'Attempts to disregard previous context',
    examples: ['disregard all previous', 'disregard above'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['instruction-override']
  },
  {
    id: 'instruction_override_en_003',
    pattern: /forget\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|commands?|rules?)/i,
    severity: Severity.HIGH,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'instruction_override',
    description: 'Attempts to make system forget rules',
    examples: ['forget all previous instructions', 'forget prior rules'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['instruction-override']
  },
  {
    id: 'instruction_override_en_004',
    pattern: /new\s+(instructions?|task|objective|goal|mission)[:]/i,
    severity: Severity.HIGH,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'instruction_override',
    description: 'Attempts to inject new instructions',
    examples: ['new instructions:', 'new task:', 'new objective:'],
    falsePositiveRisk: 'medium',
    enabled: true,
    tags: ['instruction-override']
  },
  {
    id: 'instruction_override_en_005',
    pattern: /override\s+(previous|prior|system|default)\s+(settings?|instructions?|rules?|behavior)/i,
    severity: Severity.CRITICAL,
    language: 'en',
    category: 'prompt_injection',
    subcategory: 'instruction_override',
    description: 'Direct override attempts',
    examples: ['override previous settings', 'override system rules'],
    falsePositiveRisk: 'low',
    enabled: true,
    tags: ['instruction-override', 'high-confidence']
  }
];
