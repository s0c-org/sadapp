// Dependency-free structural check for the published SNMP profile catalog.
// The authoritative semantic validation runs inside the SadApp monitoring worker.
import fs from 'node:fs';
import path from 'node:path';

const directory = path.resolve(process.argv[2] || 'snmp-profiles/profiles');
const schemaPath = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'snmp-profile.schema.json');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
const required = schema.required ?? [];
const states = new Set(['enabled', 'experimental', 'disabled']);

const errors = [];
const names = new Map();
const files = fs.readdirSync(directory).filter((file) => file.endsWith('.json')).sort();

for (const file of files) {
  let profile;
  try {
    profile = JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'));
  } catch (error) {
    errors.push(`${file}: invalid JSON (${error.message})`);
    continue;
  }
  for (const key of required) {
    if (!(key in profile)) errors.push(`${file}: missing required key "${key}"`);
  }
  if (profile.state !== undefined && !states.has(profile.state)) errors.push(`${file}: invalid state "${profile.state}"`);
  if (!Array.isArray(profile.device_classes) || profile.device_classes.length === 0) errors.push(`${file}: device_classes must be a non-empty array`);
  if (typeof profile.profile_name === 'string') {
    if (names.has(profile.profile_name)) errors.push(`${file}: duplicate profile_name "${profile.profile_name}" (also in ${names.get(profile.profile_name)})`);
    names.set(profile.profile_name, file);
  }
}

if (files.length === 0) errors.push(`no profiles found in ${directory}`);
if (errors.length > 0) {
  console.error(errors.join('\n'));
  process.exit(1);
}
console.log(`SNMP profiles OK: ${files.length} profiles checked against ${required.length} required keys`);
