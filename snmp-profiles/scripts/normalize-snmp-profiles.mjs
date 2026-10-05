import fs from 'node:fs';
import path from 'node:path';

const profileDirectory = path.resolve(process.argv[2] || 'mibs');
const profileStates = new Set(['enabled', 'experimental', 'disabled']);

const vendorByProfile = new Map([
  ['apc-netbotz', 'APC'], ['aruba-wifi-controller', 'Aruba'], ['asic-antminer', 'Bitmain'],
  ['axis-camera', 'Axis'], ['barracuda-esg', 'Barracuda'], ['brocade-san-switch', 'Brocade'],
  ['checkpoint-firewall', 'Check Point'], ['cisco-catalyst', 'Cisco'], ['citrix-hypervisor', 'Citrix'],
  ['citrix-netscaler', 'Citrix'], ['dell-idrac', 'Dell'], ['eaton-pdu', 'Eaton'],
  ['esphome-snmp', 'ESPHome'], ['f5-bigip', 'F5'], ['fortinet-fortigate', 'Fortinet'],
  ['generic-switch', 'IETF'], ['hp-procurve', 'HP'], ['huawei-solar', 'Huawei'],
  ['hwgroup-poseidon', 'HW group'], ['ibm-lenovo-imm', 'IBM/Lenovo'], ['juniper-ex', 'Juniper'],
  ['kentix-multisensor', 'Kentix'], ['linux-net-snmp', 'Net-SNMP'], ['lsi-megaraid', 'Broadcom/LSI'],
  ['mikrotik-wireless', 'MikroTik'], ['mitel-pbx', 'Mitel'], ['openwrt-router', 'OpenWrt'],
  ['opnsense-firewall', 'OPNsense'], ['pfsense-firewall', 'pfSense'], ['proxmox-cluster', 'Proxmox'],
  ['proxmox-ve', 'Proxmox'], ['qnap-nas', 'QNAP'], ['raritan-pdu', 'Raritan'],
  ['siemens-plc', 'Siemens'], ['solaredge-inverter', 'SolarEdge'], ['sophos-utm', 'Sophos'],
  ['standard-printer', 'IETF'], ['standard-ups', 'IETF'], ['stulz-crac', 'STULZ'],
  ['synology-nas', 'Synology'], ['ubiquiti-unifi', 'Ubiquiti'], ['vmware-esxi', 'VMware'],
]);

function titleCase(name) {
  return name.split('-').map((part) => part.toUpperCase() === part ? part : `${part[0].toUpperCase()}${part.slice(1)}`).join(' ');
}

function deviceClasses(name) {
  const rules = [
    [/switch|procurve/, 'switch'], [/firewall|utm|router/, 'firewall'], [/wifi|wireless|unifi/, 'wireless'],
    [/ups/, 'ups'], [/pdu/, 'pdu'], [/printer/, 'printer'], [/camera/, 'camera'],
    [/hypervisor|esxi|proxmox/, 'hypervisor'], [/nas|megaraid/, 'storage'], [/solar|inverter/, 'inverter'],
    [/sensor|netbotz|poseidon|crac/, 'environmental-sensor'], [/pbx/, 'voip'], [/plc/, 'industrial-controller'],
    [/antminer/, 'miner'], [/idrac|imm/, 'server-controller'], [/loadbalancer|netscaler|bigip/, 'load-balancer'],
    [/linux|esphome/, 'server'],
  ];
  const classes = rules.filter(([pattern]) => pattern.test(name)).map(([, value]) => value);
  return classes.length > 0 ? [...new Set(classes)] : ['appliance'];
}

function enterprisePrefixes(profile) {
  const oids = [
    ...Object.values(profile.scalars || {}).map((value) => typeof value === 'string' ? value : value.oid),
    ...Object.values(profile.tables || {}).map((table) => table.base_oid),
  ];
  return [...new Set(oids.flatMap((oid) => {
    const match = String(oid || '').match(/(?:^|\.)1\.3\.6\.1\.4\.1\.(\d+)/);
    return match ? [`1.3.6.1.4.1.${match[1]}`] : [];
  }))].sort();
}

function valueType(value, metric) {
  const explicit = typeof value === 'object' ? value.type : undefined;
  if (explicit === 'String') return 'string';
  if (explicit === 'Counter' || explicit === 'Counter64') return 'counter';
  if (explicit === 'Integer') return 'integer';
  if (/name|descr|description|model|version|uuid|ssid|bssid|ip_address|mac_address|path|label|type$/.test(metric)) return 'string';
  if (/status|state|source|quorate|online|triggered|detected|available|enabled|allow/.test(metric)) return 'enum';
  if (/bytes|octets|packets|errors|count|counter|total_page|runtime_hours|yield_kwh|energy/.test(metric)) return 'counter';
  return 'gauge';
}

function unit(metric, type) {
  if (type === 'string') return 'text';
  if (type === 'enum') return 'status';
  if (/pct|percent|utilisation|usage|cpu_idle|cpu_user|cpu_system|charge/.test(metric)) return 'percent';
  if (/bytes|space|heap|memory|mem_|ram_|size_bytes/.test(metric)) return 'bytes';
  if (/bps$|bitrate/.test(metric)) return 'bits_per_second';
  if (/octets/.test(metric)) return 'octets';
  if (/temp|temperature|dewpoint/.test(metric)) return 'celsius';
  if (/rpm/.test(metric)) return 'rpm';
  if (/voltage|volts/.test(metric)) return 'volts';
  if (/current|amps|_ma$/.test(metric)) return 'amps';
  if (/power|watts/.test(metric)) return 'watts';
  if (/frequency|_hz$/.test(metric)) return 'hertz';
  if (/dbm|noise_floor/.test(metric)) return 'decibels';
  if (/uptime|seconds|minutes_remaining/.test(metric)) return 'seconds';
  return 'count';
}

function scalarDefinition(metric, value) {
  const object = typeof value === 'string' ? { oid: value } : value;
  const type = valueType(value, metric);
  return {
    oid: object.oid,
    type,
    unit: unit(metric, type),
    scale: object.multiplier ?? 1,
    transform: null,
    metric,
    required: false,
    priority: 0,
    timeout_ms: null,
  };
}

function columnDefinition(tableName, metric, value) {
  const object = typeof value === 'string' ? { offset: value } : value;
  const type = valueType(value, metric);
  return {
    oid_suffix: String(object.offset),
    type,
    unit: unit(metric, type),
    scale: object.multiplier ?? 1,
    transform: null,
    metric: `${tableName}.${metric}`,
  };
}

for (const file of fs.readdirSync(profileDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const filePath = path.join(profileDirectory, file);
  const legacy = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!profileStates.has(legacy.state)) {
    throw new Error(`${file} must declare state as enabled, experimental, or disabled`);
  }
  const prefixes = enterprisePrefixes(legacy);
  const vendor = vendorByProfile.get(legacy.profile_name) || titleCase(legacy.profile_name.split('-')[0]);
  const regexVendor = vendor.split('/')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const profileState = legacy.state;
  const canonical = {
    schema_version: 1,
    profile_name: legacy.profile_name,
    display_name: titleCase(legacy.profile_name),
    description: legacy.description,
    vendor,
    device_classes: deviceClasses(legacy.profile_name),
    state: profileState,
    detection: {
      sys_object_id_prefixes: prefixes,
      sys_descr_regexes: vendor === 'IETF' ? [] : [`(?i)${regexVendor}`],
      required_oids: ['1.3.6.1.2.1.1.2.0'],
      optional_oids: [],
      priority: profileState === 'enabled' ? 10 : 20,
      minimum_confidence: prefixes.length > 0 ? 0.8 : (vendor === 'IETF' ? 0.5 : 0.6),
    },
    poll: { defaults: { timeout_ms: 1000, retries: 1, max_parallel: 4, budget_weight: 1 } },
    scalars: Object.fromEntries(Object.entries(legacy.scalars || {}).map(([name, value]) => [name, scalarDefinition(name, value)])),
    tables: Object.fromEntries(Object.entries(legacy.tables || {}).map(([name, table]) => [name, {
      base_oid: table.base_oid,
      index_strategy: 'integer',
      columns: Object.fromEntries(Object.entries(table.properties || {}).map(([column, value]) => [column, columnDefinition(name, column, value)])),
      max_rows: 256,
      cost: 10,
    }])),
    traps: [],
  };
  fs.writeFileSync(filePath, `${JSON.stringify(canonical, null, 2)}\n`);
}