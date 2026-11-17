"""Generate a synthetic preview with the actual report renderer."""
import importlib.util
import sys
from pathlib import Path
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('audit',root/'ubuntu_anomaly_audit.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
items=[
 a.finding('SecurityWeakness','High','SecureShell:RootPassword','Secure Shell allows root password login','PermitRootLogin=yes; PasswordAuthentication=yes','Synthetic configuration example; no machine was scanned.','Validate intended access policy.'),
 a.finding('Persistence','High','cron:example','Scheduled root command references a temporary script','/tmp/example-job.py','Synthetic suspicious scheduling example.','Inspect the exact job and script without running them.'),
 a.finding('RunningScript','Medium','Process:123','Custom Python runtime needs review','python3 /opt/example/app.py','This may be an approved application.','Identify the application and parent process.'),
 a.finding('ThreatEvidence','High','Process:456','Input-capture code patterns observed','<script>window.injected=1</script>','Escaping test text; not executable content.','Inspect source and validate intent.')]
(root/'ExampleReport.html').write_text(a.render_report('SYNTHETIC EXAMPLE - NOT A SERVER SCAN',items,[dict(check='Example collector',status='Partial',detail='Synthetic coverage note.')]))
