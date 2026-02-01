import { instructionOverridePatterns } from './instruction-override';
import { roleManipulationPatterns } from './role-manipulation';
import { systemImpersonationPatterns } from './system-impersonation';
import { jailbreakPatterns } from './jailbreak-attempts';

export const promptInjectionPatternsEN = [
  ...instructionOverridePatterns,
  ...roleManipulationPatterns,
  ...systemImpersonationPatterns,
  ...jailbreakPatterns
];
