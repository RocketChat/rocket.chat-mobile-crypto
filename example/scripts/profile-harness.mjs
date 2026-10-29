import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import config from '../rn-harness.config.mjs';

const { values } = parseArgs({
  options: {
    'label': { type: 'string', default: 'run' },
    'output': { type: 'string' },
    'cache-version': { type: 'string' },
    'recorded': { type: 'boolean', default: false },
  },
});
const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const repositoryRoot = path.dirname(projectRoot);
const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const output = path.resolve(
  projectRoot,
  values.output || `.harness/performance/${timestamp}-${values.label}`
);
fs.mkdirSync(output, { recursive: true });
const metricsPath = path.join(output, 'metrics.json');
if (fs.existsSync(metricsPath)) {
  throw new Error(
    `A profile already exists at ${output}; choose a new output.`
  );
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const readPackage = (name) =>
  readJson(path.join(projectRoot, 'node_modules', name, 'package.json'));
const diagnosticsDirectory = path.join(projectRoot, '.harness/diagnostics');
const traceFiles = () =>
  fs.existsSync(diagnosticsDirectory)
    ? fs
        .readdirSync(diagnosticsDirectory)
        .filter((file) => file.endsWith('.json'))
    : [];
const previousTraces = new Set(traceFiles());
const filesIn = (directory) =>
  fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => !(entry.isDirectory() && entry.name === 'build'))
    .flatMap((entry) => {
      const file = path.join(directory, entry.name);
      return entry.isDirectory() ? filesIn(file) : [file];
    });
const fingerprint = createHash('sha256');
for (const file of [
  ...filesIn(path.join(repositoryRoot, 'src')),
  ...filesIn(path.join(repositoryRoot, 'ios')),
  ...filesIn(path.join(repositoryRoot, 'android/src')),
  ...filesIn(path.join(repositoryRoot, 'nitrogen')),
  ...filesIn(path.join(projectRoot, '__tests__')),
  ...filesIn(path.join(projectRoot, 'fixtures')),
  path.join(repositoryRoot, 'yarn.lock'),
  path.join(projectRoot, 'rn-harness.config.mjs'),
  path.join(projectRoot, 'jest.harness.config.mjs'),
].sort()) {
  fingerprint.update(path.relative(repositoryRoot, file));
  fingerprint.update('\0');
  fingerprint.update(fs.readFileSync(file));
}

const devices = readJsonFromCommand('xcrun', [
  'simctl',
  'list',
  'devices',
  '--json',
]);
const metadata = {
  label: values.label,
  recorded: values.recorded,
  startedAt: new Date().toISOString(),
  sourceFingerprint: fingerprint.digest('hex'),
  gitCommit: execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  }).trim(),
  node: process.version,
  harness: readPackage('react-native-harness').version,
  reactNative: readPackage('react-native').version,
  platform: os.platform(),
  architecture: os.arch(),
  kernel: os.release(),
  cpu: os.cpus()[0].model,
  logicalCpus: os.availableParallelism(),
  hostMemoryBytes: os.totalmem(),
  loadAverageBefore: os.loadavg(),
  bootedSimulators: Object.values(devices.devices)
    .flat()
    .filter((device) => device.state === 'Booted')
    .map((device) => ({ name: device.name, udid: device.udid })),
  runner: config.defaultRunner,
  resetEnvironmentBetweenTestFiles: config.resetEnvironmentBetweenTestFiles,
  runnerConfig: config.runners.find(
    (runner) => runner.name === config.defaultRunner
  ).config,
  cacheVersion:
    values['cache-version'] || process.env.HARNESS_CACHE_VERSION || null,
  command:
    'harness --config jest.harness.config.mjs --harnessRunner ios --json',
};
fs.writeFileSync(
  path.join(output, 'metadata.json'),
  JSON.stringify(metadata, null, 2)
);

const logPath = path.join(output, 'harness.log');
const resultsPath = path.join(output, 'results.json');
const resourcesPath = path.join(output, 'resources.txt');
const log = fs.openSync(logPath, 'w');
console.log(`Profiling ${values.label}; artifacts: ${output}`);
const started = performance.now();
const child = spawn(
  '/usr/bin/time',
  [
    '-l',
    '-o',
    resourcesPath,
    process.execPath,
    path.join(projectRoot, 'node_modules/react-native-harness/bin.js'),
    '--config',
    'jest.harness.config.mjs',
    '--harnessRunner',
    'ios',
    '--json',
    `--outputFile=${resultsPath}`,
  ],
  {
    cwd: projectRoot,
    env: {
      ...process.env,
      RN_HARNESS_DIAGNOSTICS: '1',
      HARNESS_CACHE_VERSION: metadata.cacheVersion || '',
    },
    stdio: ['ignore', log, log],
  }
);
let exitCode;
try {
  exitCode = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code) => resolve(code));
  });
} finally {
  fs.closeSync(log);
}
const wallMs = performance.now() - started;
if (exitCode !== 0) {
  console.error(fs.readFileSync(logPath, 'utf8'));
  process.exitCode = exitCode || 1;
} else {
  const results = readJson(resultsPath);
  const newTraces = traceFiles().filter((file) => !previousTraces.has(file));
  if (newTraces.length !== 1) {
    throw new Error(
      `Expected one new Harness trace, found ${newTraces.length}.`
    );
  }
  fs.copyFileSync(
    path.join(diagnosticsDirectory, newTraces[0]),
    path.join(output, 'trace.json')
  );
  const trace = readJson(path.join(output, 'trace.json')).traceEvents;
  const spans = trace.filter((event) => event.ph === 'X');
  const phases = {};
  for (const span of spans) {
    const stats = phases[span.name] || { count: 0, totalMs: 0, maxMs: 0 };
    stats.count += 1;
    stats.totalMs += span.dur / 1000;
    stats.maxMs = Math.max(stats.maxMs, span.dur / 1000);
    phases[span.name] = stats;
  }
  const resources = fs.readFileSync(resourcesPath, 'utf8');
  const cpu = resources.match(
    /([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys/
  );
  const rss = resources.match(/(\d+)\s+maximum resident set size/);
  const run = spans.find((span) => span.name === 'run.total');
  const traceStart = Math.min(...spans.map((span) => span.ts));
  const metrics = {
    ...metadata,
    finishedAt: new Date().toISOString(),
    loadAverageAfter: os.loadavg(),
    success: results.success,
    passed: results.numPassedTests,
    failed: results.numFailedTests,
    skipped: results.numPendingTests,
    wallMs,
    userCpuSeconds: cpu ? Number(cpu[2]) : null,
    systemCpuSeconds: cpu ? Number(cpu[3]) : null,
    peakHostRssBytes: rss ? Number(rss[1]) : null,
    startupMs: run ? (run.ts - traceStart) / 1000 : null,
    executionMs: run ? run.dur / 1000 : null,
    resets: spans
      .filter((span) => span.name === 'app.reset')
      .map((span) => ({ ...span.args, durationMs: span.dur / 1000 })),
    phases,
    suites: results.testResults.map((suite) => ({
      file: path.basename(suite.name),
      reportedMs: suite.endTime - suite.startTime,
      tests: suite.assertionResults.map((test) => ({
        name: test.fullName,
        durationMs: test.duration,
        status: test.status,
      })),
    })),
  };
  fs.writeFileSync(metricsPath, `${JSON.stringify(metrics, null, 2)}\n`);
  console.log(
    `${metrics.passed} passed; CLI wall ${(wallMs / 1000).toFixed(2)}s; ` +
      `test bodies ${(phases['client.test'].totalMs / 1000).toFixed(3)}s; ` +
      `host peak RSS ${(metrics.peakHostRssBytes / 1024 ** 2).toFixed(0)} MiB`
  );
}

function readJsonFromCommand(command, args) {
  return JSON.parse(execFileSync(command, args, { encoding: 'utf8' }));
}
