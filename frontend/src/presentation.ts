export type ResourcePhase = 'loading' | 'auth-required' | 'error' | 'empty' | 'available' | 'not-run'

export function resourcePhase(input: { loading: boolean; error: string; auth: boolean; hasValue: boolean; empty?: boolean }): ResourcePhase {
  if (input.loading) return 'loading'
  if (input.auth) return 'auth-required'
  if (input.error) return 'error'
  if (input.hasValue && input.empty) return 'empty'
  if (input.hasValue) return 'available'
  return 'not-run'
}

export function normalizeFindingStatus(raw: string): string {
  switch (raw.trim().toUpperCase()) {
    case 'PASS': return 'Pass'
    case 'FAIL': return 'Fail'
    case 'ERROR': return 'Error'
    case 'UNKNOWN': return 'Unknown'
    case 'BLOCKED': return 'Blocked'
    case 'INDETERMINATE': return 'Indeterminate'
    case 'COMPLIANT': return 'Compliant'
    case 'NON_COMPLIANT': return 'Non-compliant'
    case 'NOT_APPLICABLE': return 'Not applicable'
    case 'NOT_RUN': return 'Not run'
    default: return raw ? raw[0].toUpperCase() + raw.slice(1).toLowerCase() : 'Unknown'
  }
}

export function filterByCategory<T extends { category: string }>(items: T[], category: string): T[] {
  return category === 'All categories' ? items : items.filter((item) => item.category === category)
}
