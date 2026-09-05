/**
 * CyberV Risk Engine & Decision Matrix (TypeScript / Deno Backend)
 * 
 * Implements deterministic integer risk scoring matching the Rust Agent byte-for-byte.
 * Ref: Pipeline.md Section 29, Plan.md Section 19.
 */

export enum RiskLevel {
  Low = "LOW",
  Medium = "MEDIUM",
  High = "HIGH",
  Critical = "CRITICAL",
}

export enum PolicyDecision {
  Trusted = "TRUSTED",
  AutoPromote = "AUTO_PROMOTE",
  RequiresUserApproval = "REQUIRES_USER_APPROVAL",
  Rejected = "REJECTED",
}

export interface RiskSignal {
  code: string;
  penalty: number;
  description: string;
}

export interface RiskAssessment {
  score: number; // 0 to 10000 (0.00% to 100.00%)
  level: RiskLevel;
  decision: PolicyDecision;
  signals: RiskSignal[];
  breakdown: Record<string, number>;
}

export const PENALTY_ROLLBACK = 10000;
export const PENALTY_VERSION_JUMP = 1000;
export const PENALTY_RAM_MUTATION = 1500;
export const PENALTY_STORAGE_MUTATION = 2500;
export const PENALTY_CPU_MUTATION = 4000;
export const PENALTY_MOTHERBOARD_MUTATION = 5500;
export const PENALTY_SOURCE_DEGRADED = 1500;
export const PENALTY_PARTIAL_STATUS = 1000;

export interface ComponentDiff {
  target_id: string;
  operation: string; // 'NodeModified' | 'NodeAdded' | 'NodeRemoved'
}

/**
 * Evaluates risk score and maps to policy decision
 */
export function evaluateRisk(
  oldVersion: number,
  newVersion: number,
  changes: ComponentDiff[],
  hasPartialStatus = false,
): RiskAssessment {
  const signals: RiskSignal[] = [];
  const breakdown: Record<string, number> = {};
  let totalScore = 0;

  // 1. Version checks
  if (newVersion <= oldVersion) {
    totalScore += PENALTY_ROLLBACK;
    signals.push({
      code: "ROLLBACK_ATTACK_DETECTED",
      penalty: PENALTY_ROLLBACK,
      description: `Rollback attack: new_version (${newVersion}) <= old_version (${oldVersion})`,
    });
    breakdown["rollback"] = PENALTY_ROLLBACK;
  } else if (newVersion > oldVersion + 1) {
    totalScore += PENALTY_VERSION_JUMP;
    signals.push({
      code: "VERSION_JUMP_ANOMALY",
      penalty: PENALTY_VERSION_JUMP,
      description: `Non-sequential version jump: from ${oldVersion} to ${newVersion}`,
    });
    breakdown["version_jump"] = PENALTY_VERSION_JUMP;
  }

  // 2. Component mutations
  let hasRamChange = false;
  let hasStorageChange = false;
  let hasCpuChange = false;
  let hasBoardChange = false;

  for (const c of changes) {
    if (c.target_id.startsWith("ram:")) {
      hasRamChange = true;
    } else if (c.target_id.startsWith("disk:")) {
      hasStorageChange = true;
    } else if (c.target_id.startsWith("cpu:")) {
      hasCpuChange = true;
    } else if (c.target_id.startsWith("board:")) {
      hasBoardChange = true;
    }
  }

  if (hasRamChange) {
    totalScore += PENALTY_RAM_MUTATION;
    signals.push({
      code: "MUTATION_RAM",
      penalty: PENALTY_RAM_MUTATION,
      description: "Memory configuration changed (RAM upgrade/swap)",
    });
    breakdown["ram_mutation"] = PENALTY_RAM_MUTATION;
  }

  if (hasStorageChange) {
    totalScore += PENALTY_STORAGE_MUTATION;
    signals.push({
      code: "MUTATION_STORAGE",
      penalty: PENALTY_STORAGE_MUTATION,
      description: "Storage device replaced or added",
    });
    breakdown["storage_mutation"] = PENALTY_STORAGE_MUTATION;
  }

  if (hasCpuChange) {
    totalScore += PENALTY_CPU_MUTATION;
    signals.push({
      code: "MUTATION_CPU",
      penalty: PENALTY_CPU_MUTATION,
      description: "Processor replaced (CPU swap)",
    });
    breakdown["cpu_mutation"] = PENALTY_CPU_MUTATION;
  }

  if (hasBoardChange) {
    totalScore += PENALTY_MOTHERBOARD_MUTATION;
    signals.push({
      code: "MUTATION_MOTHERBOARD",
      penalty: PENALTY_MOTHERBOARD_MUTATION,
      description: "Motherboard replaced (Major platform change)",
    });
    breakdown["board_mutation"] = PENALTY_MOTHERBOARD_MUTATION;
  }

  if (hasPartialStatus) {
    totalScore += PENALTY_PARTIAL_STATUS;
    signals.push({
      code: "PARTIAL_HARDWARE_ATTRIBUTES",
      penalty: PENALTY_PARTIAL_STATUS,
      description: "One or more components have partial attributes",
    });
    breakdown["partial_attributes"] = PENALTY_PARTIAL_STATUS;
  }

  const finalScore = Math.min(10000, totalScore);

  // 3. Classify level
  let level: RiskLevel;
  if (finalScore <= 1000) {
    level = RiskLevel.Low;
  } else if (finalScore <= 3000) {
    level = RiskLevel.Medium;
  } else if (finalScore <= 7000) {
    level = RiskLevel.High;
  } else {
    level = RiskLevel.Critical;
  }

  // 4. Decision Matrix
  let decision: PolicyDecision;
  if (finalScore === 0) {
    decision = PolicyDecision.Trusted;
  } else if (newVersion <= oldVersion) {
    decision = PolicyDecision.Rejected;
  } else if ((hasBoardChange && hasCpuChange) || (hasBoardChange && hasStorageChange)) {
    decision = PolicyDecision.Rejected;
  } else if (finalScore <= 3000 && !hasCpuChange && !hasBoardChange) {
    decision = PolicyDecision.AutoPromote;
  } else if (finalScore <= 7000) {
    decision = PolicyDecision.RequiresUserApproval;
  } else {
    decision = PolicyDecision.Rejected;
  }

  return {
    score: finalScore,
    level,
    decision,
    signals,
    breakdown,
  };
}
