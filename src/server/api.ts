import { Router, Request, Response } from 'express';
import { db } from './db';
import { auditCloud } from '../modules/rulesEngine';
import { calculateSecurityScore, calculateGrade, evaluateAccuracy } from '../modules/scoring';
import { getComplianceSummary } from '../modules/compliance';
import { autoRemediate } from '../modules/remediation';
import { getInitialCloudState, getHardenedCloudState, GROUND_TRUTH } from '../modules/cloudSimulation';
import { CloudSnapshot, Finding } from '../types/security';
import { CURATED_DEMO_DATASETS } from '../data/sampleDatasets';

export const apiRouter = Router();

// Health check
apiRouter.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    engine: 'CloudGuard Enterprise Backend v1.4',
    database: 'SQLite 3 WAL Active',
    timestamp: new Date().toISOString()
  });
});

// List all clients/accounts
apiRouter.get('/clients', (req: Request, res: Response) => {
  try {
    const clients = db.prepare(`
      SELECT id, email, name, company, cloud_provider, account_id, region, environment, created_at
      FROM clients
      ORDER BY created_at ASC
    `).all();

    // Attach latest audit score for each client
    const enriched = clients.map((c: any) => {
      const latestAudit = db.prepare(`
        SELECT score, grade, findings_count, cis_compliance, nist_compliance, created_at
        FROM audit_runs
        WHERE client_email = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).get(c.email) as any;

      return {
        ...c,
        latest_audit: latestAudit || null
      };
    });

    res.json({ success: true, clients: enriched });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get single client by email with cloud snapshot & findings
apiRouter.get('/clients/:email', (req: Request, res: Response) => {
  try {
    const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(req.params.email) as any;
    if (!client) {
      return res.status(404).json({ success: false, error: `Client with email '${req.params.email}' not found.` });
    }

    const cloudState: CloudSnapshot = JSON.parse(client.cloud_state);
    const findings = auditCloud(cloudState);
    const score = calculateSecurityScore(findings);
    const grade = calculateGrade(score);
    const compliance = getComplianceSummary(findings);

    const latestAudit = db.prepare(`
      SELECT * FROM audit_runs WHERE client_email = ? ORDER BY created_at DESC LIMIT 5
    `).all(req.params.email);

    res.json({
      success: true,
      client: {
        id: client.id,
        email: client.email,
        name: client.name,
        company: client.company,
        cloud_provider: client.cloud_provider,
        account_id: client.account_id,
        region: client.region,
        environment: client.environment,
        created_at: client.created_at
      },
      cloud_state: cloudState,
      audit: {
        score,
        grade,
        findings_count: findings.length,
        compliance,
        findings
      },
      audit_history: latestAudit
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Register or update client email
apiRouter.post('/clients', (req: Request, res: Response) => {
  try {
    const { email, name, company, region, environment } = req.body;
    if (!email || !name) {
      return res.status(400).json({ success: false, error: 'Email and Name are required fields.' });
    }

    const existing = db.prepare('SELECT email FROM clients WHERE email = ?').get(email);
    if (existing) {
      return res.status(409).json({ success: false, error: `Client email '${email}' already exists.` });
    }

    const newId = `client_${Date.now().toString(36)}`;
    const randAccount = Math.floor(100000000000 + Math.random() * 900000000000).toString();
    const initialCloud = getInitialCloudState();

    db.prepare(`
      INSERT INTO clients (id, email, name, company, cloud_provider, account_id, region, environment, created_at, cloud_state)
      VALUES (?, ?, ?, ?, 'AWS', ?, ?, ?, ?, ?)
    `).run(
      newId,
      email,
      name,
      company || 'Independent Cloud Enterprise',
      randAccount,
      region || 'us-east-1',
      environment || 'Production AWS VPC',
      new Date().toISOString(),
      JSON.stringify(initialCloud)
    );

    res.json({
      success: true,
      message: `Client '${email}' registered successfully with simulated AWS environment.`,
      client: { id: newId, email, name, company, account_id: randAccount }
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get all misconfigurations knowledge base records
apiRouter.get('/misconfigurations', (req: Request, res: Response) => {
  try {
    const rows = db.prepare(`
      SELECT rule_id, title, service, severity, cis_control, nist_control, mitre_attack_technique,
             remediation_summary, is_auto_remediable
      FROM misconfigurations_kb
      ORDER BY severity = 'CRITICAL' DESC, severity = 'HIGH' DESC, severity = 'MEDIUM' DESC, rule_id ASC
    `).all();

    res.json({ success: true, count: rows.length, misconfigurations: rows });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Deep-dive resolver for a specific misconfiguration rule_id
apiRouter.get('/misconfigurations/:ruleId', (req: Request, res: Response) => {
  try {
    const rule = db.prepare(`
      SELECT * FROM misconfigurations_kb WHERE rule_id = ? COLLATE NOCASE
    `).get(req.params.ruleId) as any;

    if (!rule) {
      return res.status(404).json({ success: false, error: `Misconfiguration '${req.params.ruleId}' not found.` });
    }

    res.json({
      success: true,
      misconfiguration: {
        ...rule,
        remediation_steps: JSON.parse(rule.remediation_steps)
      }
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Run live audit on a client's cloud infrastructure in the DB
apiRouter.post('/audit/:email', (req: Request, res: Response) => {
  try {
    const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(req.params.email) as any;
    if (!client) {
      return res.status(404).json({ success: false, error: `Client email '${req.params.email}' not found.` });
    }

    const cloudState: CloudSnapshot = JSON.parse(client.cloud_state);
    const findings: Finding[] = auditCloud(cloudState);
    const score = calculateSecurityScore(findings);
    const grade = calculateGrade(score);
    const compliance = getComplianceSummary(findings);
    const accuracy = evaluateAccuracy(findings, GROUND_TRUTH);

    const auditId = `audit_${Date.now().toString(36)}`;
    const nowIso = new Date().toISOString();

    db.prepare(`
      INSERT INTO audit_runs (id, client_email, score, grade, findings_count, cis_compliance, nist_compliance, findings_json, created_at, audit_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'automated_scan')
    `).run(
      auditId,
      client.email,
      score,
      grade,
      findings.length,
      compliance.cis,
      compliance.nist,
      JSON.stringify(findings),
      nowIso
    );

    res.json({
      success: true,
      auditId,
      timestamp: nowIso,
      client: { email: client.email, name: client.name, account_id: client.account_id },
      score,
      grade,
      findings_count: findings.length,
      compliance,
      accuracy,
      findings
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Execute automated safe remediation on a client's database cloud state
apiRouter.post('/remediate/:email', (req: Request, res: Response) => {
  try {
    const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(req.params.email) as any;
    if (!client) {
      return res.status(404).json({ success: false, error: `Client email '${req.params.email}' not found.` });
    }

    const cloudState: CloudSnapshot = JSON.parse(client.cloud_state);
    const beforeFindings = auditCloud(cloudState);
    const beforeScore = calculateSecurityScore(beforeFindings);
    const beforeCompliance = getComplianceSummary(beforeFindings);

    const { actions, updatedCloud } = autoRemediate(beforeFindings, cloudState);

    // Save updated cloud state back to database
    db.prepare('UPDATE clients SET cloud_state = ? WHERE email = ?').run(
      JSON.stringify(updatedCloud),
      client.email
    );

    const nowIso = new Date().toISOString();

    // Log each remediation action in SQLite table
    const insertLog = db.prepare(`
      INSERT INTO remediation_logs (id, client_email, rule_id, resource, action_status, details, executed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const a of actions) {
      insertLog.run(
        `rem_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        client.email,
        a.rule_id,
        a.resource,
        a.status,
        a.what_was_done,
        nowIso
      );
    }

    // Run post-remediation audit
    const afterFindings = auditCloud(updatedCloud);
    const afterScore = calculateSecurityScore(afterFindings);
    const afterGrade = calculateGrade(afterScore);
    const afterCompliance = getComplianceSummary(afterFindings);

    // Record remediated audit run
    const auditId = `audit_rem_${Date.now().toString(36)}`;
    db.prepare(`
      INSERT INTO audit_runs (id, client_email, score, grade, findings_count, cis_compliance, nist_compliance, findings_json, created_at, audit_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'remediated_scan')
    `).run(
      auditId,
      client.email,
      afterScore,
      afterGrade,
      afterFindings.length,
      afterCompliance.cis,
      afterCompliance.nist,
      JSON.stringify(afterFindings),
      nowIso
    );

    res.json({
      success: true,
      message: 'Automated remediation executed on client infrastructure.',
      before: {
        score: beforeScore,
        findings_count: beforeFindings.length,
        compliance: beforeCompliance
      },
      after: {
        score: afterScore,
        grade: afterGrade,
        findings_count: afterFindings.length,
        compliance: afterCompliance
      },
      actions,
      updated_cloud: updatedCloud,
      remaining_findings: afterFindings
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Live Exploit Simulation Probe (addresses "use a misconfiguration with a flaw so that we can see how well our system works")
apiRouter.post('/exploit-probe', (req: Request, res: Response) => {
  try {
    const { email, rule_id, resource } = req.body;
    if (!email || !rule_id) {
      return res.status(400).json({ success: false, error: 'email and rule_id are required.' });
    }

    const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(email) as any;
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found.' });
    }

    const cloudState: CloudSnapshot = JSON.parse(client.cloud_state);
    const findings = auditCloud(cloudState);
    const activeFinding = findings.find((f) => f.rule_id === rule_id && (!resource || f.resource === resource));

    const kbRecord = db.prepare('SELECT * FROM misconfigurations_kb WHERE rule_id = ?').get(rule_id) as any;

    if (activeFinding) {
      // VULNERABLE STATE PROBE
      let exploitLog = '';
      let simulatedDataExfiltrated = '';

      switch (rule_id) {
        case 'S3-001':
          exploitLog = `[PROBE] curl -s -X GET "https://${activeFinding.resource}.s3.amazonaws.com/?list-type=2"\n[PROBE] HTTP/1.1 200 OK (Public Anonymous Access Permitted!)\n[EXPLOIT] Listing 42 objects... Found: database_credentials.env, internal_architecture.pdf, customer_pii.csv\n[EXPLOIT] Downloading s3://${activeFinding.resource}/database_credentials.env...`;
          simulatedDataExfiltrated = 'DATABASE_URL="mysql://admin:Password123!@prod-db.714305265226.us-east-1.rds.amazonaws.com:3306/production"';
          break;
        case 'EC2-001':
          exploitLog = `[PROBE] nc -zv -w 3 ec2-54-204-12-89.compute-1.amazonaws.com 22\n[PROBE] Connection to ec2-54-204-12-89.compute-1.amazonaws.com port 22 [tcp/ssh] succeeded!\n[EXPLOIT] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5 banner detected from 0.0.0.0/0.\n[EXPLOIT] Automated hydra dictionary attack initiated against root / ec2-user.`;
          simulatedDataExfiltrated = 'Remote Port 22 reachable without VPN/bastion barrier. Brute-force exploit active.';
          break;
        case 'EC2-002':
          exploitLog = `[PROBE] nmap -sS -p- ec2-54-204-12-89.compute-1.amazonaws.com\n[PROBE] Ingress rule IpProtocol: -1 open to 0.0.0.0/0!\n[EXPLOIT] Found open unauthenticated services: Port 6379 (Redis), Port 2375 (Docker Socket), Port 9090 (Prometheus).\n[EXPLOIT] Injected root container payload through unauthenticated Docker socket.`;
          simulatedDataExfiltrated = 'Full root system shell access achieved via unrestricted ingress ports 0-65535.';
          break;
        case 'IAM-002':
          exploitLog = `[PROBE] aws sts get-caller-identity --profile dev-admin\n[PROBE] Account: 714305265226, Arn: arn:aws:iam::714305265226:user/dev-admin\n[EXPLOIT] Testing policy permissions: Action: "*", Resource: "*"\n[EXPLOIT] Created backdoor administrator role "ShadowAdmin-Persistent" and generated 5 auxiliary API secret keys.`;
          simulatedDataExfiltrated = 'Complete unrestricted AWS cloud tenant takeover (AdministratorAccess).';
          break;
        case 'RDS-001':
          exploitLog = `[PROBE] nc -zv -w 3 prod-db.714305265226.us-east-1.rds.amazonaws.com 3306\n[PROBE] Connection to port 3306 [tcp/mysql] succeeded from public IP!\n[EXPLOIT] MySQL handshake: 8.0.35-commercial.\n[EXPLOIT] Initiated password spray against user "admin" on public database endpoint.`;
          simulatedDataExfiltrated = 'Production database open to global public routing (PubliclyAccessible=true).';
          break;
        default:
          exploitLog = `[PROBE] Probing target resource: ${activeFinding.resource} for security flaw: ${rule_id}\n[PROBE] Misconfiguration verified active: ${activeFinding.description}\n[EXPLOIT] Compliance violation active under ${activeFinding.cis} and ${activeFinding.nist}.`;
          simulatedDataExfiltrated = `Identified unhardened state on ${activeFinding.resource}.`;
      }

      res.json({
        status: 'VULNERABLE',
        is_exploitable: true,
        rule_id,
        resource: activeFinding.resource,
        severity: activeFinding.severity,
        exploit_log: exploitLog,
        exfiltrated_evidence: simulatedDataExfiltrated,
        mitre_technique: kbRecord?.mitre_attack_technique || 'T1190',
        remediation_advice: kbRecord?.remediation_summary || activeFinding.remediation,
        aws_cli_fix: kbRecord?.aws_cli_command || '',
        terraform_fix: kbRecord?.terraform_snippet || '',
        verification_command: kbRecord?.verification_command || ''
      });
    } else {
      // MITIGATED STATE PROBE
      res.json({
        status: 'MITIGATED_AND_SECURE',
        is_exploitable: false,
        rule_id,
        resource: resource || 'Target Resource',
        exploit_log: `[PROBE] Executing threat actor test probe against resource for rule ${rule_id}...\n[PROBE] Request returned 403 Forbidden / Connection Refused.\n[VERIFICATION] Zero unauthorized access permitted. Guardrails verified active.\n[AUDIT] Resource passed security rule check.`,
        exfiltrated_evidence: 'None. Exploit blocked by active CloudGuard security controls.',
        remediation_advice: 'Resource is currently hardened and compliant.',
        aws_cli_fix: '# Already remediated',
        terraform_fix: '# Infrastructure is compliant in state',
        verification_command: kbRecord?.verification_command || ''
      });
    }
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Reset client cloud state (back to 15 flaws ground truth or 100% hardened)
apiRouter.post('/reset/:email', (req: Request, res: Response) => {
  try {
    const { mode } = req.body; // 'ground_truth' | 'hardened'
    const newState = mode === 'hardened' ? getHardenedCloudState() : getInitialCloudState();

    db.prepare('UPDATE clients SET cloud_state = ? WHERE email = ?').run(
      JSON.stringify(newState),
      req.params.email
    );

    const findings = auditCloud(newState);
    const score = calculateSecurityScore(findings);
    const grade = calculateGrade(score);
    const compliance = getComplianceSummary(findings);

    res.json({
      success: true,
      mode: mode || 'ground_truth',
      message: `Client '${req.params.email}' cloud state reset to ${mode === 'hardened' ? 'Hardened Enterprise' : 'Ground Truth (15 Flaws)'}.`,
      cloud_state: newState,
      audit: {
        score,
        grade,
        findings_count: findings.length,
        compliance,
        findings
      }
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// List or fetch sample demonstration datasets
apiRouter.get('/sample-datasets', (req: Request, res: Response) => {
  const catalog = CURATED_DEMO_DATASETS.map((d) => ({
    id: d.id,
    name: d.name,
    fileName: d.fileName,
    type: d.type,
    industry: d.industry,
    findingsCount: d.findingsCount,
    environment: d.environment,
    summaryText: d.summaryText,
    tags: d.tags,
    download_url: `/api/sample-datasets/${d.id}`
  }));
  res.json({ success: true, count: catalog.length, datasets: catalog });
});

apiRouter.get('/sample-datasets/:id', (req: Request, res: Response) => {
  const found = CURATED_DEMO_DATASETS.find((d) => d.id === req.params.id || d.fileName === req.params.id);
  if (!found) {
    return res.status(404).json({ success: false, error: `Dataset '${req.params.id}' not found.` });
  }
  if (found.type === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${found.fileName}"`);
    res.send(found.content);
  } else {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${found.fileName}"`);
    res.send(found.content);
  }
});

