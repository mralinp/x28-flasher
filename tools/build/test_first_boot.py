#!/usr/bin/env python3
import base64
import io
import json
import os
import subprocess
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import first_boot as f


def put(t,name,data):
    m=tarfile.TarInfo(name);m.size=len(data);m.mode=0o755 if name.startswith('etc/init.d/') else 0o644;t.addfile(m,io.BytesIO(data))


def elf(needed):
    strtab=b'\0'+b''.join(n.encode()+b'\0' for n in needed);offsets=[];pos=1
    for n in needed:offsets.append(pos);pos+=len(n)+1
    dyn=b''.join(struct.pack('<qQ',1,o) for o in offsets)+struct.pack('<qQ',5,176)+struct.pack('<qQ',0,0)
    size=176+len(strtab)+len(dyn)
    head=b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',3,183,1,0,64,0,0,64,56,2,64,0,0)
    ph=struct.pack('<IIQQQQQQ',1,5,0,0,0,size,size,0x1000)+struct.pack('<IIQQQQQQ',2,6,176+len(strtab),176+len(strtab),0,len(dyn),len(dyn),8)
    return head+ph+strtab+dyn


FAKE_SWCONFIG=r'''#!/usr/bin/env python3
import json,os,re,sys
state=os.environ['FAKE_SW_STATE'];mode=os.environ.get('FAKE_SW_MODE','')
a=sys.argv[1:]
if a==['list']:
    print('Found: switch0 - '+('MT7531AX' if mode=='wrong' else 'MT7531AE'));sys.exit(0)
assert a[:2]==['dev','switch0'],a
a=a[2:]
if a[0]=='load':
    if mode=='loadfail':sys.exit(1)
    d={'vlan':{},'pvid':{},'enable_vlan':'0'}
    for block in re.split(r'\n(?=config )',open(os.environ['FAKE_SW_CONFIG']).read()):
        o=dict(re.findall(r"option (\w+) '([^']*)'",block))
        if block.startswith('config switch_vlan'):d['vlan'][o['vlan']]=o['ports']
        if block.startswith('config switch_port'):d['pvid'][o['port']]=o['pvid']
        if block.startswith('config switch\n'):d['enable_vlan']=o['enable_vlan']
    if mode=='drift':d['vlan']['3']='3 5t'
    json.dump(d,open(state,'w'));sys.exit(0)
d=json.load(open(state))
if a==['get','enable_vlan']:print(d['enable_vlan'])
elif a[0]=='vlan' and a[2:]==['get','ports']:print(d['vlan'][a[1]]+' ')
elif a[0]=='port' and a[2:]==['get','pvid']:print(d['pvid'][a[1]])
else:sys.exit(2)
'''


MODEM_SERVICES='1nvram_daemon 2ccci_fsd 3ccci_mdinit ql_ril_service ql_netd.init mipc_submonitor.init atci_service atcid'.split()


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.stage=self.root/'stage';self.stage.mkdir()
        self.archive=self.stage/'rootfs-staging.tar.gz'
        with tarfile.open(self.archive,'w:gz') as t:
            for name,data in {'etc/inittab':b'ttyS0::askfirst:/bin/sh\n','etc/shadow':b'root:::0:99999:7:::\nservice:old:0:0:99999:7:::\n',
                              'etc/init.d/openvpn':b'openvpn', 'etc/init.d/dropbear':b'PasswordAuth RootPasswordAuth', 'etc/init.d/network':b'network', 'etc/init.d/dnsmasq':b'dnsmasq', 'etc/init.d/odhcpd':b'odhcpd', 'etc/init.d/rpcd':b'rpcd', 'etc/init.d/done':b'mount_root done', 'etc/init.d/uhttpd':b'uhttpd', 'etc/init.d/firewall':b'firewall', 'etc/init.d/sysntpd':b'sysntpd',
                              f.LUCI_HEADERS[0]:b'<script src="{{ resource }}/luci.js?v=git-1.2-abc"></script>',
                              'www/luci-static/resources/view/network/wireless.js':b"o.ucisection=s.section;if(hwtype=='mac80211'){o=ss.taboption('general',form.Flag,'legacy_rates'}\nif(hwtype=='mac80211'){var mode=ss.children[0],bssid=ss.children[5],encr;}\nif(hwtype=='mac80211'){x}\nelse if(hwtype=='broadcom'){y}\n.then(L.bind(function(data){this.channels={'2g':L.hasSystemFeature('hostapd','acs')?['auto','auto',true]:[],'5g':L.hasSystemFeature('hostapd','acs')?['auto','auto',true]:[],'6g':[]};m=[L.hasSystemFeature('hostapd','11ac')&&hwmodelist.ac,L.hasSystemFeature('hostapd','11ax')&&hwmodelist.ax]}));\no.value('ap',_('Access Point'));o.value('sta',_('Client'));o.value('adhoc',_('Ad-Hoc'));",
                              'sbin/ujail':b'jail', 'usr/lib/opkg/info/procd-ujail.list':b'/sbin/ujail',
                              'usr/lib/opkg/status':b'Package: procd\nStatus: installed\n\nPackage: procd-ujail\nStatus: installed\n\nPackage: zlib\n\nPackage: kernel\nVersion: 4.19.205-1\n\nPackage: kmod-old\nVersion: 4.19.205-1\n\n',
                              'usr/lib/opkg/info/kmod-old.list':b'/lib/modules/old.ko', 'usr/lib/opkg/info/kernel.prerm':b'old', 'etc/opkg/customfeeds.conf':b'# custom\n',
                              'etc/uci-defaults/99-unsafe':b'mtd write', 'etc/rc.local':b'mtd write',
                              'etc/fstab':b'/dev/other /data ubifs rw 0 0',
                              'etc/rc.d/S99zmtk_boot_done':b'unsafe', 'etc/board.d/02_network':b'generic',
                              'lib/upgrade/platform.sh':b'unsafe', 'lib/preinit/99_10_failsafe_login':b'ash --login', 'lib/preinit/00_preinit.conf':b'pi_preinit_no_failsafe=""\n','lib/libc.so':b'musl','bin/ash':b'busybox'}.items():put(t,name,data)
            m=tarfile.TarInfo('etc/rc.d/S19dropbear');m.type=tarfile.SYMTYPE;m.linkname='../init.d/dropbear';t.addfile(m)
            m=tarfile.TarInfo('etc/rc.d/S20network');m.type=tarfile.SYMTYPE;m.linkname='../init.d/network';t.addfile(m)
        (self.stage/'manifest.json').write_text(json.dumps({'flashable':False,'archive_sha256':f.digest(self.archive.read_bytes())}))
        (self.stage/'NOT-FLASHABLE').touch()
        blob=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+b'K'*32
        self.key='ssh-ed25519 '+base64.b64encode(blob).decode()+' local comment\n'
        self.output=self.root/'output'
        self.stock=self.root/'stock.tar.gz'
        with tarfile.open(self.stock,'w:gz') as t:
            put(t,'rootfs/sbin/swconfig',elf(['libuci.so','libnl-tiny.so','libc.so']))
            put(t,'rootfs/usr/lib/libnl-tiny.so',elf(['libc.so']));put(t,'rootfs/lib/libuci.so',elf(['libc.so']))
            for name in f.WIFI_PROFILES:put(t,'rootfs/'+name,b'Default\nSSID1=stock\n')
            for service in MODEM_SERVICES:
                binary=service.split('.')[0].lstrip('123')
                put(t,'rootfs/etc/init.d/'+service,f'procd_set_param command /usr/bin/{binary} 0\n'.encode())
                put(t,'rootfs/usr/bin/'+binary,elf(['libmodem.so']))
            put(t,'rootfs/sbin/dd-nand',elf(['libnandapi.so','libc.so']));put(t,'rootfs/usr/lib/libnandapi.so',elf(['libc.so']));put(t,'rootfs/usr/lib/libmodem.so',elf(['libc.so']));put(t,'rootfs/usr/bin/mipc_wan_cli',elf(['libc.so']))
            put(t,'rootfs/etc/quectel-project-version',b'v1\n');put(t,'rootfs/etc/conf/apns-conf_8.xml',b'<apns/>\n');put(t,'rootfs/vendor/etc/md/apncfg/001_01.conf',b'apn\n')

    def test_policy_removes_shells_unsafe_services_and_defines_key_only_lan(self):
        r=f.integrate(self.stage,self.key,self.stock,self.output)
        tree=f.load_archive(self.output/'rootfs-management.tar.gz')
        self.assertNotIn('etc/rc.d/S99zmtk_boot_done',tree)
        self.assertNotIn('lib/upgrade/platform.sh',tree)
        self.assertNotIn('etc/uci-defaults/99-unsafe',tree)
        self.assertNotIn('lib/preinit/99_10_failsafe_login',tree)
        self.assertIn(b'pi_preinit_no_failsafe="y"',tree['lib/preinit/00_preinit.conf'][1])
        self.assertEqual([l for l in tree['etc/inittab'][1].decode().splitlines() if 'askfirst' in l],['ttyS0::askfirst:/bin/ash --login'])
        self.assertNotIn('login.sh',tree['etc/inittab'][1].decode())
        net=tree['etc/config/network'][1].decode()
        self.assertIn("option name 'br-lan'\n option type 'bridge'\n list ports 'eth0.1'\n list ports 'eth0.2'\n list ports 'eth0.3'\n list ports 'eth1'",net)
        self.assertIn("config interface 'lan'\n option device 'br-lan'",net)
        self.assertEqual(tree['etc/rc.d/S19dnsmasq'][0].linkname,'../init.d/dnsmasq')
        self.assertEqual(tree['etc/rc.d/S35odhcpd'][0].linkname,'../init.d/odhcpd')
        self.assertIn(" option ip6assign '64'",net)
        dhcp=tree['etc/config/dhcp'][1].decode()
        self.assertIn("config dhcp 'lan'\n option interface 'lan'",dhcp)
        self.assertIn(" option ra 'server'\n option dhcpv6 'server'",dhcp)
        self.assertEqual(tree['usr/lib/opkg/status'][1],b'Package: procd\nStatus: installed\n\nPackage: zlib\n\nPackage: kernel\nVersion: 1:4.19.205-x28\nArchitecture: all\nStatus: install user installed\n')
        self.assertNotIn('usr/lib/opkg/info/kmod-old.list',tree);self.assertNotIn('usr/lib/opkg/info/kernel.prerm',tree)
        self.assertEqual(tree['usr/lib/opkg/info/kernel.control'][1],b'Package: kernel\nVersion: 1:4.19.205-x28\nArchitecture: all\n')
        self.assertEqual(tree['etc/opkg/customfeeds.conf'][1].decode(),'# custom\n'+f.FEED_LINE)
        self.assertIn(f.FEED_KEY_ID.encode(),tree['etc/opkg/keys/'+f.FEED_KEY_ID][1])
        self.assertNotIn('sbin/ujail',tree);self.assertNotIn('usr/lib/opkg/info/procd-ujail.list',tree)
        self.assertEqual(tree['etc/rc.d/S99x28-leds'][0].linkname,'../init.d/x28-leds')
        self.assertIn('/dev/tz_gpio_leds',tree['sbin/x28-leds'][1].decode())
        self.assertEqual(tree['sbin/x28-leds'][0].mode,0o755)
        self.assertEqual(tree['etc/rc.d/S97x28-wps'][0].linkname,'../init.d/x28-wps')
        self.assertIn('/dev/tz_gpio_keys',tree['sbin/x28-wps'][1].decode())
        self.assertEqual(tree['etc/rc.d/S19x28-modem'][0].linkname,'../init.d/x28-modem')
        for service in MODEM_SERVICES:self.assertIn('etc/init.d/'+service,tree)
        for name in ('usr/bin/atcid','usr/bin/nvram_daemon','usr/lib/libmodem.so','usr/bin/mipc_wan_cli','etc/quectel-project-version',
                     'vendor/etc/md/apncfg/001_01.conf'):self.assertIn(name,tree)
        self.assertFalse(any(n.startswith('etc/rc.d/') and 'ccci' in n for n in tree))  # x28-modem starts them, not rc.d
        self.assertEqual(tree['etc/conf/apns-conf_8.xml'][1],b'<apns/>\n')  # x28-apn's database, from stock
        for link, service in (('S12rpcd','rpcd'),('S19firewall','firewall'),('S50uhttpd','uhttpd')):
            self.assertEqual(tree['etc/rc.d/'+link][0].linkname,'../init.d/'+service)
        for name in ('lib/netifd/proto/x28_mipc.sh','sbin/x28-apn','www/luci-static/resources/protocol/x28_mipc.js','usr/share/rpcd/acl.d/luci-proto-x28-mipc.json'):self.assertIn(name,tree)
        self.assertEqual(tree['lib/netifd/proto/x28_mipc.sh'][0].mode,0o755)
        self.assertIn("config interface 'wan'\n option proto 'x28_mipc'",net)
        self.assertIn(" option hostname 'x28'",tree['etc/config/system'][1].decode())
        for name in f.WIFI_PROFILES:self.assertEqual(tree[name][1],b'Default\nSSID1=stock\n')
        self.assertIn('"/productinfo"',f.luci_storage(f.LUCI_SKIP_ANCHOR))
        self.assertEqual(f.luci_storage(f.LUCI_SKIP),f.LUCI_SKIP)  # idempotent
        with self.assertRaises(ValueError):f.luci_storage('changed LuCI')
        self.assertIn('results.length&&',f.luci_analysis(f.LUCI_ONCE_ANCHOR))
        self.assertEqual(f.luci_analysis(f.LUCI_ONCE),f.LUCI_ONCE)  # idempotent
        with self.assertRaises(ValueError):f.luci_analysis('changed LuCI')
        self.assertIn('do_x28_user_data',tree['lib/preinit/79_x28_user_data'][1].decode())
        self.assertIn("option device '/dev/ubi1_2'",tree['etc/config/fstab'][1].decode())
        for name in f.UBI_WRITERS:self.assertNotIn(name,tree)
        js=tree[f.LUCI_WIRELESS][1].decode()
        self.assertIn("else if(hwtype=='mtwifi'){crypto_modes.push(['psk2'",js)
        self.assertIn("if(hwtype=='mtwifi'){o=ss.taboption('general',form.ListValue,'txpower_pct'",js)
        self.assertIn("if(hwtype=='mtwifi'){o=ss.taboption('macfilter',form.ListValue,'macfilter'",js)
        self.assertIn("var mtw=data[0]&&data[0].get('type')=='mtwifi';",js)
        self.assertEqual(js.count('mtw||'),4)
        self.assertIn("if(hwtype!='mtwifi'){o.value('sta'",js)
        self.assertEqual(f.luci_mtwifi(js),js)  # idempotent
        self.assertIn('luci.js?v=git-1.2-abc-'+f.luci_build_id(tree)+'"',tree[f.LUCI_HEADERS[0]][1].decode())
        changed=dict(tree);changed[f.LUCI_WIRELESS]=(tree[f.LUCI_WIRELESS][0],b'new')
        self.assertNotEqual(f.luci_build_id(changed),f.luci_build_id(tree))
        changed=dict(tree);changed['etc/rc.local']=(tree['etc/rc.local'][0],b'new')
        self.assertEqual(f.luci_build_id(changed),f.luci_build_id(tree))  # only what browsers cache counts
        with self.assertRaises(ValueError):f.luci_version('changed LuCI','id')
        with self.assertRaises(ValueError):f.luci_mtwifi('changed LuCI')
        self.assertIn('add_driver mtwifi',tree['lib/netifd/wireless/mtwifi.sh'][1].decode())
        self.assertIn('append DRIVERS "mtwifi"',tree['lib/wifi/mtwifi.sh'][1].decode())
        self.assertIn(b"option PasswordAuth 'on'",tree['etc/config/dropbear'][1])
        self.assertEqual(tree['etc/dropbear/authorized_keys'][0].mode,0o600)
        self.assertEqual({row.split(b':')[0]:row.split(b':')[1] for row in tree['etc/shadow'][1].splitlines()},{b'root':b'',b'service':b'!'})  # empty root like stock
        self.assertEqual(tree['etc/rc.d/S96x28-bootok'][0].linkname,'../init.d/x28-bootok')
        for name in ('sbin/dd-nand','usr/lib/libnandapi.so','etc/init.d/x28-bootok'):self.assertIn(name,tree)
        self.assertIn(b"option Port '22'",tree['etc/config/dropbear'][1])
        self.assertEqual(tree['etc/rc.d/S95done'][0].linkname,'../init.d/done')
        self.assertEqual(tree['etc/rc.d/S98sysntpd'][0].linkname,'../init.d/sysntpd')
        self.assertIn("config timeserver 'ntp'",tree['etc/config/system'][1].decode())
        self.assertIn(b"option PasswordAuth 'on'",tree['etc/config/dropbear'][1])  # an empty root password never works over SSH, so this opens only once one is set
        self.assertIn(b"option RootPasswordAuth 'on'",tree['etc/config/dropbear'][1])
        self.assertIn(b"option Interface 'lan'",tree['etc/config/dropbear'][1])  # LAN only
        self.assertNotIn(b'mtd',tree['etc/rc.local'][1])
        self.assertFalse(r['flashable'])

    def test_private_modules_and_passwall2_are_wired_up(self):
        old=f.load_archive(self.archive)
        with tarfile.open(self.archive,'w:gz') as t:
            for name,(info,data) in old.items():t.addfile(info,io.BytesIO(data) if info.isfile() else None)
            put(t,f.PASSWALL2_DEFAULT,b"config global\n\toption enabled '0'\n\toption prefer_nft '1'\n\toption tcp_proxy_way 'redirect'\n")
            put(t,'etc/config/firewall',b"config defaults\n");put(t,'etc/config/uhttpd',b"config uhttpd 'main'\n\toption redirect_https\t0\n\toption max_requests 3\n\nconfig cert 'defaults'\n\toption commonname\t'OpenWrt'\n")
            put(t,'etc/init.d/passwall2',b'#!/bin/sh\nstart() {\n\t"$APP_FILE" start "$action" 9>&-\n\tlocal status=$?\n}\nstop() {\n\t"$APP_FILE" stop "$action" 9>&-\n}\nrestart() {\n\t"$APP_FILE" stop "$action" 9>&-\n\t"$APP_FILE" start "$action" 9>&-\n\tlocal status=$?\n}\n')
            m=tarfile.TarInfo('etc/rc.d/S99passwall2');m.type=tarfile.SYMTYPE;m.linkname='../init.d/passwall2';t.addfile(m)
            put(t,'etc/init.d/ucitrack',b'ucitrack');put(t,'etc/config/ucitrack',b"config network\n\toption init 'network'\n")
            m=tarfile.TarInfo('etc/rc.d/S80ucitrack');m.type=tarfile.SYMTYPE;m.linkname='../init.d/ucitrack';t.addfile(m)
        (self.stage/'manifest.json').write_text(json.dumps({'flashable':False,'archive_sha256':f.digest(self.archive.read_bytes())}))
        mods=self.root/'mods';mods.mkdir();(mods/'wireguard.ko').write_bytes(b'wg')
        for m in ('x28_udp_lookup','nf_tproxy_ipv4','nf_tproxy_ipv6','xt_TPROXY','nf_socket_ipv4','nf_socket_ipv6','xt_socket'):(mods/(m+'.ko')).write_bytes(m.encode())
        def tgz(members):
            buf=io.BytesIO()
            with tarfile.open(fileobj=buf,mode='w:gz') as t:
                for name,data in members:put(t,name,data)
            return buf.getvalue()
        ipk=self.root/'ipset.ipk'  # needs kmod-tun, which the stub list has, and libfoo, which it doesn't
        ipk.write_bytes(tgz([('./debian-binary',b'2.0\n'),('./data.tar.gz',tgz([('./usr/sbin/ipset',b'ELF')])),
            ('./control.tar.gz',tgz([('./control',b'Package: ipset\nVersion: 1\nDepends: libc, kmod-tun, libfoo\n')]))]))
        f.integrate(self.stage,self.key,self.stock,self.output,mods,[ipk])
        tree=f.load_archive(self.output/'rootfs-management.tar.gz')
        self.assertEqual(tree['lib/modules/x28/xt_TPROXY.ko'][1],b'xt_TPROXY');self.assertEqual(tree['lib/modules/x28/wireguard.ko'][1],b'wg')
        status=tree['usr/lib/opkg/status'][1].decode()
        for package in ('kmod-wireguard','kmod-ipt-tproxy','kmod-ipt-socket','kmod-tun'):self.assertIn(f'Package: {package}\nVersion: 1:4.19.205-x28\n',status)
        self.assertNotIn('Package: libfoo',status)  # only what the vendor kernel provides
        self.assertEqual(tree['usr/sbin/ipset'][1],b'ELF');self.assertIn('Package: ipset\nVersion: 1\n',status)
        self.assertEqual(tree['usr/lib/opkg/info/ipset.list'][1],b'/usr/sbin/ipset\n')
        self.assertIn('Depends: kernel (= 1:4.19.205-x28), kmod-ipt-tproxy\n',tree['usr/lib/opkg/info/kmod-ipt-socket.control'][1].decode())
        self.assertEqual(tree['usr/lib/opkg/info/kmod-ipt-socket.list'][1].decode().split(),['/lib/modules/x28/'+m+'.ko' for m in ('nf_socket_ipv4','nf_socket_ipv6','xt_socket')])
        loader=tree['etc/init.d/x28-kmods'][1].decode()
        self.assertEqual(tree['etc/rc.d/S97x28-kmods'][0].linkname,'../init.d/x28-kmods')
        # dependencies before their users, every packaged module in the list
        order=loader.split("MODS='")[1].split("'")[0].split()
        self.assertLess(order.index('x28_udp_lookup'),order.index('nf_socket_ipv4'));self.assertLess(order.index('nf_tproxy_ipv6'),order.index('xt_TPROXY'))
        self.assertEqual(sorted(order),sorted(n.split('/')[-1][:-3] for n in tree if n.startswith('lib/modules/x28/')))
        self.assertFalse(any(n.startswith('lib/modules/4.19.205/') for n in tree))  # out of modprobe's reach
        self.assertIn("config passwall2\n\toption init 'passwall2'\n",tree['etc/config/ucitrack'][1].decode())
        self.assertEqual(tree['etc/rc.d/S99passwall2'][0].linkname,'../init.d/passwall2')  # luci-reload skips disabled services
        self.assertEqual(tree['etc/rc.d/K15passwall2'][0].linkname,'../init.d/passwall2')  # `enabled` needs START and STOP links, else ucitrack registers no trigger (#297)
        self.assertEqual(tree['etc/x28-killswitch.sh'][1],Path(f.__file__).with_name('x28-killswitch.sh').read_bytes())
        self.assertEqual(tree['etc/x28-killswitch.sh'][0].mode,0o755)
        self.assertIn("config include 'x28_killswitch'",tree['etc/config/firewall'][1].decode())
        init=tree['etc/init.d/passwall2'][1].decode()
        hook='\t/etc/x28-killswitch.sh || { unset_lock; return 1; }\n'
        self.assertEqual(init.count(hook),4)
        for action in ('start','stop'):
            self.assertEqual(init.count(hook+'\t"$APP_FILE" '+action+' "$action" 9>&-'),2)
        self.assertEqual(init.count('\tlocal status=$?\n\t/etc/x28-killswitch.sh || status=1\n'),2)  # after start too
        self.assertEqual(tree['etc/init.d/passwall2'][0].mode,0o755)
        self.assertEqual(tree['etc/rc.d/S80ucitrack'][0].linkname,'../init.d/ucitrack')  # or LuCI's apply never restarts it
        config=tree['etc/config/passwall2'][1].decode()
        self.assertIn("option prefer_nft '0'",config);self.assertIn("option tcp_proxy_way 'tproxy'",config);self.assertIn("option enabled '0'",config)
        self.assertIn("config include 'passwall2'\n option type 'script'\n option path '/var/etc/passwall2.include'",tree['etc/config/firewall'][1].decode())
        self.assertIn(" option localuse '1'\n",tree['etc/config/dhcp'][1].decode())
        uhttpd=tree['etc/config/uhttpd'][1].decode()
        for line in ("option max_requests '50'","option redirect_https '1'","option commonname 'x28'"):self.assertIn(line,uhttpd)
        self.assertEqual(tree['etc/opkg/customfeeds.conf'][1].decode(),'# custom\n'+f.FEED_LINE+f.PASSWALL_FEEDS)
        key=base64.b64decode(tree['etc/opkg/keys/'+f.PASSWALL_KEY_ID][1].split(b'\n')[1])  # usign: 'Ed', key number, key
        self.assertEqual(key[2:10].hex(),f.PASSWALL_KEY_ID)

    def test_switch_profile_ships_swconfig_table_and_single_early_owner(self):
        r=self.integrate_ok()
        tree=r[0]
        self.assertTrue(tree['sbin/swconfig'][0].isfile())
        self.assertIn('usr/lib/libnl-tiny.so',tree)
        self.assertEqual(tree['etc/rc.d/S18x28-switch'][0].linkname,'../init.d/x28-switch')
        self.assertNotIn('lib/network/switch.sh',tree)
        net=tree['etc/config/network'][1].decode()
        for v,(ports,port) in f.SWITCH.items():
            self.assertIn(f" option vlan '{v}'\n option vid '{v}'\n option ports '{ports}'",net)
            self.assertIn(f" option port '{port}'\n option pvid '{v}'",net)
        self.assertNotIn('mii_mgr',tree['etc/init.d/x28-switch'][1].decode())
        self.assertNotIn('gpio',tree['etc/init.d/x28-switch'][1].decode())
        self.assertEqual(r[1]['switch_table']['3'],'4 5t')

    def integrate_ok(self):
        report=f.integrate(self.stage,self.key,self.stock,self.output)
        return f.load_archive(self.output/'rootfs-management.tar.gz'),report

    def run_init(self,mode):
        tree,_=self.integrate_ok()
        bin=self.root/'bin';bin.mkdir()
        (bin/'swconfig').write_text(FAKE_SWCONFIG);(bin/'swconfig').chmod(0o755)
        (self.root/'network').write_bytes(tree['etc/config/network'][1])
        script=tree['etc/init.d/x28-switch'][1].decode().split('\n',1)[1]
        env={**os.environ,'PATH':f'{bin}:{os.environ["PATH"]}','FAKE_SW_STATE':str(self.root/'state'),
             'FAKE_SW_CONFIG':str(self.root/'network'),'FAKE_SW_MODE':mode}
        # /tmp marker path is rewritten so the test never touches the host's /tmp
        script=script.replace('/tmp/x28-switch.failed',str(self.root/'failed'))
        return subprocess.run(['sh','-c',script+'\nstart'],env=env,capture_output=True,text=True)

    def test_init_passes_only_when_readback_matches(self):
        self.assertEqual(self.run_init('').returncode,0)

    def test_init_fails_on_wrong_switch_load_error_or_readback_drift(self):
        for mode in ('wrong','loadfail','drift'):
            self.setUp()  # fresh output dir per mode
            r=self.run_init(mode)
            self.assertNotEqual(r.returncode,0,mode)
            self.assertTrue((self.root/'failed').exists(),mode)

    def test_missing_or_unresolved_swconfig_library_refused(self):
        with tarfile.open(self.stock,'w:gz') as t:
            put(t,'rootfs/sbin/swconfig',elf(['libnope.so']))
        with self.assertRaises(ValueError):f.integrate(self.stage,self.key,self.stock,self.output)
        self.assertFalse(self.output.exists())

    def test_bad_keys_refused_before_output(self):
        for key in ('PRIVATE KEY',self.key+self.key,'ssh-ed25519 !!!!'):
            with self.assertRaises(ValueError):f.integrate(self.stage,key,self.stock,self.output)
        self.assertFalse(self.output.exists())

    def test_allowlisted_startup_name_cannot_redirect_or_be_regular_script(self):
        for redirect in (True,False):
            with tarfile.open(self.archive,'w:gz') as t:
                put(t,'etc/init.d/dropbear',b'safe')
                m=tarfile.TarInfo('etc/rc.d/S19dropbear')
                if redirect:
                    m.type=tarfile.SYMTYPE;m.linkname='../init.d/unsafe';t.addfile(m)
                else:
                    m.size=6;t.addfile(m,io.BytesIO(b'unsafe'))
            (self.stage/'manifest.json').write_text(json.dumps({'flashable':False,'archive_sha256':f.digest(self.archive.read_bytes())}))
            with self.assertRaises(ValueError):f.integrate(self.stage,self.key,self.stock,self.output)
        self.assertFalse(self.output.exists())

    def test_console_shell_needs_ash(self):
        with tarfile.open(self.archive,'w:gz') as t:
            for name in ('etc/inittab','etc/shadow','etc/init.d/dropbear','etc/init.d/network','lib/libc.so'):put(t,name,b'root:::0:99999:7:::\n' if name=='etc/shadow' else b'x')
            for link in ('S19dropbear','S20network'):
                m=tarfile.TarInfo('etc/rc.d/'+link);m.type=tarfile.SYMTYPE;m.linkname='../init.d/'+link[3:];t.addfile(m)
        (self.stage/'manifest.json').write_text(json.dumps({'flashable':False,'archive_sha256':f.digest(self.archive.read_bytes())}))
        with self.assertRaises(ValueError):f.integrate(self.stage,self.key,self.stock,self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):f.integrate(self.stage,self.key,self.stock,self.output)

    def test_changed_stage_and_existing_output_fail_closed(self):
        with self.archive.open('ab') as stream:stream.write(b'changed')
        with self.assertRaises(ValueError):f.integrate(self.stage,self.key,self.stock,self.output)
        self.assertFalse(self.output.exists())


if __name__=='__main__':unittest.main()
