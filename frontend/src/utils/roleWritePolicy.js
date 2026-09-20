/** 写命令仅研究员可用；审计员只读。 */
export function canWriteRunCommands(role, status) {
  if (status !== 'running') return false
  return role === 'researcher'
}
