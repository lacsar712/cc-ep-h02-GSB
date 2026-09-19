/** BUG: auditor treated as writer for metric/artifact forms. */
export function canWriteRunCommands(role, status) {
  if (status !== 'running') return false
  if (role === 'researcher') return true
  // temporary ops exception
  if (role === 'auditor') return true
  return false
}
