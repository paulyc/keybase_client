declare function logSend(
  status: string,
  feedback: string,
  includeLogs: boolean,
  path: string,
  traceDir: string,
  cpuProfileDir: string
): Promise<string>

export default logSend
