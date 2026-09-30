import { readFileSync } from 'node:fs';

const metadata = JSON.parse(readFileSync(process.argv[2], 'utf8'));

function leaf(source) {
  if (!source?.startsWith('git+')) return null;
  const url = new URL(source.slice(4));
  if (url.hostname !== 'github.com' || !url.pathname.startsWith('/corbet-foss/')) return null;
  const revision = url.searchParams.get('rev');
  if (!/^[a-f0-9]{40}$/.test(revision ?? '') || [...url.searchParams.keys()].length !== 1) {
    throw new Error(`Leaf dependency must use a full rev pin: ${source}`);
  }
  return { revision, resolved: url.hash.slice(1) };
}

const resolvedLeaves = new Map();
for (const pkg of metadata.packages) {
  // Include transitive and optional declarations, even when their features are off.
  for (const dependency of pkg.dependencies) leaf(dependency.source);
  const pin = leaf(pkg.source);
  if (!pin) continue;
  if (pin.resolved !== pin.revision) {
    throw new Error(`Resolved revision differs from the full rev pin: ${pkg.name}`);
  }
  if (resolvedLeaves.has(pkg.name)) {
    throw new Error(`Duplicated leaf package: ${pkg.name}`);
  }
  resolvedLeaves.set(pkg.name, pin.revision);
}

for (const required of ['crlt', 'csgn', 'cpns', 'cshm']) {
  if (!resolvedLeaves.has(required)) throw new Error(`Missing leaf: ${required}`);
}
console.log('Exactly one pinned revision per leaf:', Object.fromEntries(resolvedLeaves));
