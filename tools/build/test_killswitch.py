#!/usr/bin/env python3
"""Exercise the shipped shell script against stateful fake iptables commands."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

FAKE = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
if Path(sys.argv[0]).name == 'uci':
    print(os.environ['ENABLED']); sys.exit(0)
p = Path(os.environ['STATE'] + Path(sys.argv[0]).name)
s = json.loads(p.read_text()) if p.exists() else {'forwarding_rule': []}
a = sys.argv[1:]
if a[:2] == ['-t', 'mangle']:
    psw2 = json.loads(os.environ.get('PSW2', 'null'))
    if psw2 is None: sys.exit(1)
    print('\\n'.join(['-N PSW2'] + psw2)); sys.exit(0)
op, chain = a[:2]; rule = a[2:]
if op == '-nL': sys.exit(0 if chain in s else 1)
if op == '-S':
    print('\\n'.join(['-N ' + chain] + ['-A ' + chain + ' ' + ' '.join(r) for r in s[chain]])); sys.exit(0)
if op == '-C': sys.exit(0 if rule in s[chain] else 1)
if op == '-N': s[chain] = []
elif op == '-F':
    assert os.environ['ENABLED'] != '1', 'must not briefly open an enabled guard'
    s[chain] = []
elif op == '-A': s[chain].append(rule)
elif op == '-I': s[chain].insert(0, rule)
elif op == '-D': s[chain].remove(rule)
else: raise AssertionError(a)
p.write_text(json.dumps(s))
'''


class KillSwitchTests(unittest.TestCase):
    def test_enabled_disabled_and_repeated_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('uci', 'iptables', 'ip6tables'):
                path = root / name
                path.write_text(FAKE)
                path.chmod(0o755)
            env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'], STATE=tmp+'/state-')
            for enabled in ('1', '1', '0', '0', '1', 'reload'):
                if enabled == 'reload':
                    for family in ('iptables', 'ip6tables'):
                        (root / ('state-'+family)).unlink()
                    enabled = '1'
                subprocess.run(['sh', str(Path(__file__).with_name('x28-killswitch.sh'))],
                               env=dict(env, ENABLED=enabled), check=True)
                for family, protocol in (('iptables', 'icmp'), ('ip6tables', 'ipv6-icmp')):
                    state = json.loads((root / ('state-'+family)).read_text())
                    self.assertEqual(state['forwarding_rule'], [['-j', 'x28_killswitch']])
                    self.assertEqual(state['x28_killswitch'],
                                     [['-o', 'ccmni+', '!', '-p', protocol, '-j', 'REJECT']] if enabled == '1' else [])

    def test_passwall2_direct_sets_are_let_through(self):
        reject = lambda p: ['-o', 'ccmni+', '!', '-p', p, '-j', 'REJECT']
        allow = lambda name: ['-m', 'set', '--match-set', name, 'dst', '-j', 'RETURN']
        before = ['-A PSW2 -m set --match-set psw2_vps dst -j RETURN',
                  '-A PSW2 -m comment --comment "WAN_IP_RETURN" -m set --match-set psw2_wan dst -j RETURN',
                  '-A PSW2 -p tcp -m set --match-set psw2_n1_ir dst -m multiport --dports 1:65535 -j RETURN',
                  '-A PSW2 -p tcp -m set --match-set psw2_n1_proxy dst -j PSW2_RULE',
                  '-A PSW2 -p tcp -m set --match-set psw2_lan src -j RETURN']
        after = [before[0], '-A PSW2 -m set --match-set psw2_n1_white dst -j RETURN']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('uci', 'iptables', 'ip6tables'):
                (root / name).write_text(FAKE); (root / name).chmod(0o755)
            env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'], STATE=tmp+'/state-', ENABLED='1')
            run = lambda psw2: subprocess.run(['sh', str(Path(__file__).with_name('x28-killswitch.sh'))],
                                              env=dict(env, PSW2=json.dumps(psw2)), check=True)
            state = lambda: json.loads((root / 'state-iptables').read_text())['x28_killswitch']
            run(None)  # before Passwall2 starts: no PSW2 chain, only the reject
            self.assertEqual(state(), [reject('icmp')])
            run(before)
            self.assertEqual(state(), [allow('psw2_wan'), allow('psw2_vps'), allow('psw2_n1_ir'), reject('icmp')])
            run(after)  # rules changed: stale exceptions go, new ones come, the reject never leaves
            self.assertEqual(state(), [allow('psw2_n1_white'), allow('psw2_vps'), reject('icmp')])


if __name__ == '__main__':
    unittest.main()
