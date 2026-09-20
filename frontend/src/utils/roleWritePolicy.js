/** 只有研究员在 run 进行中时可以发送写命令（记指标/挂产物/完成/中止）。 */
export function canWriteRunCommands(role, status) {
  if (status !== 'running') return false
  return role === 'researcher'
}
