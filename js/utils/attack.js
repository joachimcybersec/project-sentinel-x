/**
 * MITRE ATT&CK (Enterprise) technique names and tactics for the IDs used in
 * the Sentinel X datasets. Names follow https://attack.mitre.org/ as of
 * ATT&CK v15 (2024); sub-techniques are shown as "Parent: Sub-technique".
 * A later phase can replace this with a versioned STIX snapshot.
 *
 * A unit test fails if any dataset references an ID missing from this table.
 */
export const ATTACK_NAMES = {
  'T1003.001': 'OS Credential Dumping: LSASS Memory',
  'T1003.003': 'OS Credential Dumping: NTDS',
  'T1021.001': 'Remote Services: Remote Desktop Protocol',
  'T1021.002': 'Remote Services: SMB/Windows Admin Shares',
  'T1046': 'Network Service Discovery',
  'T1047': 'Windows Management Instrumentation',
  'T1048': 'Exfiltration Over Alternative Protocol',
  'T1053.005': 'Scheduled Task/Job: Scheduled Task',
  'T1055': 'Process Injection',
  'T1059.001': 'Command and Scripting Interpreter: PowerShell',
  'T1059.005': 'Command and Scripting Interpreter: Visual Basic',
  'T1059.007': 'Command and Scripting Interpreter: JavaScript',
  'T1068': 'Exploitation for Privilege Escalation',
  'T1070.001': 'Indicator Removal: Clear Windows Event Logs',
  'T1071.001': 'Application Layer Protocol: Web Protocols',
  'T1071.004': 'Application Layer Protocol: DNS',
  'T1078': 'Valid Accounts',
  'T1078.002': 'Valid Accounts: Domain Accounts',
  'T1078.004': 'Valid Accounts: Cloud Accounts',
  'T1090': 'Proxy',
  'T1105': 'Ingress Tool Transfer',
  'T1110': 'Brute Force',
  'T1110.001': 'Brute Force: Password Guessing',
  'T1110.003': 'Brute Force: Password Spraying',
  'T1133': 'External Remote Services',
  'T1136.002': 'Create Account: Domain Account',
  'T1189': 'Drive-by Compromise',
  'T1190': 'Exploit Public-Facing Application',
  'T1195.002': 'Supply Chain Compromise: Compromise Software Supply Chain',
  'T1204.002': 'User Execution: Malicious File',
  'T1218.011': 'System Binary Proxy Execution: Rundll32',
  'T1219': 'Remote Access Software',
  'T1486': 'Data Encrypted for Impact',
  'T1490': 'Inhibit System Recovery',
  'T1498': 'Network Denial of Service',
  'T1499': 'Endpoint Denial of Service',
  'T1505.003': 'Server Software Component: Web Shell',
  'T1539': 'Steal Web Session Cookie',
  'T1547.001': 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
  'T1548.002': 'Abuse Elevation Control Mechanism: Bypass User Account Control',
  'T1550.002': 'Use Alternate Authentication Material: Pass the Hash',
  'T1550.004': 'Use Alternate Authentication Material: Web Session Cookie',
  'T1557': 'Adversary-in-the-Middle',
  'T1562.001': 'Impair Defenses: Disable or Modify Tools',
  'T1564.008': 'Hide Artifacts: Email Hiding Rules',
  'T1566.001': 'Phishing: Spearphishing Attachment',
  'T1566.002': 'Phishing: Spearphishing Link',
  'T1566.004': 'Phishing: Spearphishing Voice',
  'T1568': 'Dynamic Resolution',
  'T1572': 'Protocol Tunneling',
  'T1606.002': 'Forge Web Credentials: SAML Tokens',
  'T1621': 'Multi-Factor Authentication Request Generation',
  'T1657': 'Financial Theft'
};

export const attackName = (id) => ATTACK_NAMES[id] || 'Technique name not in local snapshot';
