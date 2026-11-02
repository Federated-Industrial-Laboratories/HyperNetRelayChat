// SPDX-License-Identifier: Apache-2.0
// Export and check the selected HRC manuals with the public MDS API.
// Inputs: MDS package directory, output workspace. Outputs: snapshot, site, private metadata. Exit: 0 or 1.
import { readFile, writeFile, mkdir, realpath, lstat } from 'node:fs/promises';
import { resolve, relative, isAbsolute } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [mdsDirectory, destination, ...extra] = process.argv.slice(2);
if (!mdsDirectory || !destination || extra.length) {
  throw new Error('Usage: node Documentation/Website/Build.mjs MDS_PACKAGE_DIRECTORY OUTPUT_WORKSPACE');
}
if (![22, 24].includes(Number(process.versions.node.split('.')[0]))) {
  throw new Error('Use Node.js 22 or 24.');
}
const packageFile = resolve(mdsDirectory, 'package.json');
const packageInfo = JSON.parse(await readFile(packageFile, 'utf8'));
if (packageInfo.name !== '@metalheart/mds' || packageInfo.version !== '0.1.0') {
  throw new Error('This consumer requires the pinned @metalheart/mds 0.1.0 package.');
}
const require = createRequire(pathToFileURL(packageFile));
const { snapshot, build, check } = await import(pathToFileURL(require.resolve('@metalheart/mds')));
const config = JSON.parse(await readFile(new URL('mds.config.json', import.meta.url), 'utf8'));
const repository = fileURLToPath(new URL('../../', import.meta.url));
if (!config.source.revision) {
  const tag = config.source.tag;
  if (typeof tag !== 'string' || tag !== `v${config.site.version}`) {
    throw new Error('Select a full source revision or the exact product version tag.');
  }
  const reference = `refs/tags/${tag}`;
  const git = args => execFileSync('git', ['--no-optional-locks', '-C', repository, ...args], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 4096,
  }).trim();
  git(['check-ref-format', reference]);
  config.source.revision = git(['rev-parse', '--verify', '--end-of-options', `${reference}^{commit}`]);
  if (!/^[a-f0-9]{40}$/.test(config.source.revision)) {
    throw new Error('The release tag must resolve to one full Git commit.');
  }
}
const workspace = resolve(destination);
const withinRepository = relative(repository, workspace);
if (!withinRepository || (!withinRepository.startsWith('../') && !isAbsolute(withinRepository))) {
  throw new Error('The output workspace must be outside the HRC repository.');
}
const configFile = resolve(workspace, 'mds.config.json');
await mkdir(workspace, { recursive: true });
if (await realpath(workspace) !== workspace) throw new Error('Use an output workspace without symbolic links.');
const configStat = await lstat(configFile).catch(error => {
  if (error.code !== 'ENOENT') throw error;
  return null;
});
if (configStat && !configStat.isFile()) throw new Error('The output configuration must be a regular file.');
const previous = await readFile(configFile, 'utf8').catch(error => {
  if (error.code !== 'ENOENT') throw error;
  return null;
});
if (previous) {
  const old = JSON.parse(previous);
  if (old.site?.id !== config.site.id
      || JSON.stringify(old.paths) !== JSON.stringify(config.paths)
      || old.source?.root !== config.source.root
      || old.source?.manifest !== config.source.manifest) {
    throw new Error('The output workspace contains a different consumer configuration.');
  }
}
config.source.repository = repository;
await writeFile(configFile, JSON.stringify(config, null, 2) + '\n');
const proposal = await snapshot(configFile);
console.log(`Snapshot ${proposal.files.length} files from ${proposal.revision}.`);
await snapshot(configFile, { write: true });
delete config.source.repository;
await writeFile(configFile, JSON.stringify(config, null, 2) + '\n');
const result = await build(configFile);
const checked = await check(configFile);
const manifest = await readFile(resolve(workspace, config.source.manifest));
console.log(JSON.stringify({
  mdsVersion: packageInfo.version,
  snapshotSha256: createHash('sha256').update(manifest).digest('hex'),
  build: result,
  check: checked,
}, null, 2));
