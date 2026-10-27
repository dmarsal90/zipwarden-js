/** Allowlist of file types. See docs/SPEC.md, section 3. */
export interface Policy {
  /** Lowercase, without the dot. An empty list allows everything. */
  allowedExtensions: readonly string[];
}

export const DEFAULT_POLICY: Readonly<Policy> = {
  allowedExtensions: [],
};

/** Whether a file path passes the allowlist (the last extension, case-insensitive). */
export function allowsPath(policy: Policy, path: string): boolean {
  if (policy.allowedExtensions.length === 0) return true;

  const name = path.slice(path.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  const extension = dot === -1 ? '' : name.slice(dot + 1).toLowerCase();
  return policy.allowedExtensions.includes(extension);
}
