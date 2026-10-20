/** Allowlist of file types. See docs/SPEC.md, section 3. */
export interface Policy {
  /** Lowercase, without the dot. An empty list allows everything. */
  allowedExtensions: readonly string[];
}

export const DEFAULT_POLICY: Readonly<Policy> = {
  allowedExtensions: [],
};
