#!/usr/bin/env python3
"""Apply a private, NOT-FLASHABLE first-boot management profile to #76 staging.

Stock swconfig, observed MT7531AE VLAN table, static LAN on br-lan (all four sockets) with DHCP, front LEDs, SSH by key or root password.
No vendor activation or device I/O.
"""
import argparse
import base64
import copy
import io
import os
import json
import posixpath
import re
from pathlib import Path
import struct
import sys
import tarfile

from ab_guard import check as ab_check
from stage_native import digest, load_archive, resolve, validate_parents

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'firmware'))
from inventory import elf_dynamic

# The firmware release's x28-overlay asset (package/*/files), extracted; images.fetch_overlay downloads it.
ROOT = Path(os.environ.get('X28_OVERLAY') or Path(__file__).resolve().parents[2]/'overlay')

# S80ucitrack: LuCI's apply restarts non-procd services such as Passwall2 only through its triggers (#198).
ALLOWED_START = {'S00urngd','S80ucitrack','S10boot','S10system','S11sysctl','S12log','S18x28-switch','S12rpcd','S19firewall','S19x28-modem','S19dropbear','S19dnsmasq','S20network','S35odhcpd','S50uhttpd','S95done','S96x28-bootok','S97x28-wps','S99x28-leds'}
ALLOWED_STOP = {'K50dropbear','K89log','K90boot','K90network','K90umount'}

LAN = 'br-lan'
# Sockets 1, 2, 4 (#84: port 4, untagged VLAN 3) and 0, one VLAN each; stock bridges them all into br0 (#122).
LAN_PORTS = ('eth0.1','eth0.2','eth0.3','eth1')
LEDS = ROOT/'package/x28-leds/files'
WIFI = ROOT/'package/x28-wifi/files'
MIPC = ROOT/'package/x28-mipc/files'
LUCI_MIPC = ROOT/'package/luci-proto-x28-mipc'
BOOTOK = ROOT/'package/x28-bootok/files'
STORAGE = ROOT/'package/x28-storage/files'
# ubi-utils for attaching user_data (#183); its writers have no business on a router that must not touch other slots.
UBI_WRITERS = tuple('usr/sbin/'+n for n in ('ubidetach','ubiformat','ubimkvol','ubirmvol','ubirsvol','ubiupdatevol','ubirename','ubiblock','ubinize','mtdinfo','ubicrc32'))
MODEM = ROOT/'package/x28-modem/files'
KMODS = ROOT/'package/x28-kmods/files'
# The modules package/x28-kmods/build.sh writes, by opkg package. kmod-ipt-socket's x28_udp_lookup is in kmod-ipt-tproxy.
KMOD_PACKAGES = {'kmod-wireguard':('wireguard',),'kmod-ipt-tproxy':('x28_udp_lookup','nf_tproxy_ipv4','nf_tproxy_ipv6','xt_TPROXY'),
                 'kmod-ipt-socket':('nf_socket_ipv4','nf_socket_ipv6','xt_socket')}
STUBS = ROOT/'package/x28-kmod-stubs/stubs.txt'
FEED_KEY = ROOT/'package/x28-feed/files/x28-feed.pub'
FEED_KEY_ID = '7fec994ab0d15b97'
FEED_LINE = 'src/gz x28 https://github.com/mralinp/zlt-x28-openwrt/releases/download/feed-2\n'
KERNEL_VERSION = '1:4.19.205-x28'
PASSWALL2_DEFAULT = 'usr/share/passwall2/0_default_config'
PASSWALL_KEY_ID = '0abda65a492b4887'
PASSWALL_FEEDS = ''.join(f'src/gz {n} https://master.dl.sourceforge.net/project/openwrt-passwall-build/releases/packages-23.05/aarch64_generic/{n}\n'
                         for n in ('passwall2','passwall_packages'))
# mt_wifi reads these at interface up; the mtwifi handler rewrites only its keys in them (#127).
# Stock LuCI 23.05 offers WPA only for mac80211/broadcom radios; add the modes the mtwifi handler maps (#127).
LUCI_WIRELESS = 'www/luci-static/resources/view/network/wireless.js'
LUCI_ANCHOR = "else if(hwtype=='broadcom'){"
LUCI_MTWIFI = ("else if(hwtype=='mtwifi'){crypto_modes.push(['psk2','WPA2-PSK',35]);"
               "crypto_modes.push(['sae','WPA3-SAE',31]);crypto_modes.push(['sae-mixed','WPA2-PSK/WPA3-SAE Mixed Mode',30]);"
               "crypto_modes.push(['psk-mixed','WPA-PSK/WPA2-PSK Mixed Mode',22]);}\n")


# LuCI shows radio and network options only for mac80211; offer the ones the mtwifi handler maps (#166).
LUCI_DEV_ANCHOR = "o.ucisection=s.section;if(hwtype=='mac80211'){o=ss.taboption('general',form.Flag,'legacy_rates'"
LUCI_MTWIFI_DEV = ("if(hwtype=='mtwifi'){o=ss.taboption('general',form.ListValue,'txpower_pct',_('Transmit power'),"
                   "_('Share of the radio\\'s full power.'));o.value('',_('100 % (full)'));"
                   "['75','50','25','15','9'].forEach(function(p){o.value(p,p+' %');});"
                   "o=ss.taboption('advanced',form.Value,'beacon_int',_('Beacon Interval'));o.datatype='range(20,999)';"
                   "o.placeholder=100;o.rmempty=true;"
                   # One card, one country: the driver takes it from one profile, so every mtwifi radio gets the choice (#177).
                   "o=ss.taboption('advanced',CBIWifiCountryValue,'country',_('Country Code'));o.wifiNetwork=radioNet;"
                   "o.write=function(sid,v){uci.sections('wireless','wifi-device').forEach(function(d){"
                   "if(d.type=='mtwifi')uci.set('wireless',d['.name'],'country',v);});};"
                   "o.remove=function(sid){uci.sections('wireless','wifi-device').forEach(function(d){"
                   "if(d.type=='mtwifi')uci.unset('wireless',d['.name'],'country');});};}")
LUCI_IFACE_ANCHOR = "if(hwtype=='mac80211'){var mode=ss.children[0],bssid=ss.children[5],encr;"
LUCI_MTWIFI_IFACE = ("if(hwtype=='mtwifi'){o=ss.taboption('macfilter',form.ListValue,'macfilter',_('MAC Address Filter'));"
                     "o.value('',_('disable'));o.value('allow',_('Allow listed only'));o.value('deny',_('Allow all except listed'));"
                     "o=ss.taboption('macfilter',form.DynamicList,'maclist',_('MAC-List'));o.datatype='macaddr';"
                     "o.depends('macfilter','allow');o.depends('macfilter','deny');"
                     "o=ss.taboption('general',form.Flag,'hidden',_('Hide <abbr title=\"Extended Service Set Identifier\">ESSID</abbr>'));"
                     "o=ss.taboption('general',form.Flag,'wmm',_('WMM Mode'));o.default=o.enabled;"
                     "o=ss.taboption('advanced',form.Flag,'isolate',_('Isolate Clients'),_('Prevents client-to-client communication'));"
                     "o=ss.taboption('advanced',form.Value,'dtim_period',_('DTIM Interval'));o.optional=true;o.placeholder=1;"
                     "o.datatype='range(1,255)';"
                     "o=ss.taboption('encryption',form.ListValue,'ieee80211w',_('802.11w Management Frame Protection'));"
                     "o.value('',_('Driver default'));o.value('0',_('Disabled'));o.value('1',_('Optional'));o.value('2',_('Required'));"
                     "['psk2','psk-mixed','sae','sae-mixed'].forEach(function(e){o.depends('encryption',e);});"
                     # The router's WPS button opens a pairing window on networks with this on; WPS cannot give out a WPA3-only key (#262).
                     "o=ss.taboption('encryption',form.Flag,'wps_pushbutton',_('Enable WPS push button'),"
                     "_('The router\\'s WPS button opens a two-minute pairing window on this network. Needs WPA2-PSK or WPA2/WPA3 mixed mode.'));"
                     "['psk2','psk-mixed','sae-mixed'].forEach(function(e){o.depends('encryption',e);});}")


# The frequency widget offers "auto", AC and AX only with hostapd (acs/11ac/11ax); mt_wifi does all three itself (#175).
LUCI_FREQ_ANCHOR = ".then(L.bind(function(data){this.channels={"
LUCI_FREQ_MTWIFI = ".then(L.bind(function(data){var mtw=data[0]&&data[0].get('type')=='mtwifi';this.channels={"
LUCI_MODE_ANCHOR = "o.value('ap',_('Access Point'));o.value('sta',_('Client'));o.value('adhoc',_('Ad-Hoc'));"


# The modem stack's and Wi-Fi calibration's partitions aren't user storage: keep them out of LuCI's Storage list.
LUCI_STORAGE = 'www/luci-static/resources/view/status/include/25_storage.js'
# Channel Analysis stops polling after its first answer, but a partial scan answers only once it's done (#176).
LUCI_ANALYSIS = 'www/luci-static/resources/view/status/channel_analysis.js'
LUCI_ONCE_ANCHOR = "if(!radio.loadedOnce){radio.loadedOnce=true;poll.stop();}"
LUCI_ONCE = "if(results.length&&!radio.loadedOnce){radio.loadedOnce=true;poll.stop();}"
LUCI_SKIP_ANCHOR = 'var MountSkipList=["/rom","/tmp","/dev","/overlay","/",]'
LUCI_SKIP = ('var MountSkipList=["/rom","/tmp","/dev","/overlay","/","/mnt/vendor/nvcfg","/mnt/vendor/nvdata","/mnt/vendor/nvram",'
             '"/mnt/vendor/protect_f","/mnt/vendor/protect_s","/mnt/data","/productinfo",]')


def luci_storage(js):
    """Stock 25_storage.js without the vendor mounts; refuses an unknown LuCI build."""
    if LUCI_SKIP in js:return js
    if js.count(LUCI_SKIP_ANCHOR)!=1:raise ValueError('unexpected LuCI 25_storage.js: mount list anchor not found')
    return js.replace(LUCI_SKIP_ANCHOR,LUCI_SKIP)



def luci_analysis(js):
    """Stock channel_analysis.js that keeps polling until a scan has results; refuses an unknown LuCI build."""
    if LUCI_ONCE in js:return js
    if js.count(LUCI_ONCE_ANCHOR)!=1:raise ValueError('unexpected LuCI channel_analysis.js: poll anchor not found')
    return js.replace(LUCI_ONCE_ANCHOR,LUCI_ONCE)


def luci_edits():
    """(anchor, replacement) pairs that make stock wireless.js handle mtwifi radios."""
    acs,auto="L.hasSystemFeature('hostapd','acs')","?['auto','auto',true]:[]"
    return [(LUCI_ANCHOR,LUCI_MTWIFI+LUCI_ANCHOR),
            (LUCI_DEV_ANCHOR,LUCI_DEV_ANCHOR.replace("if(hwtype=='mac80211')",LUCI_MTWIFI_DEV+"if(hwtype=='mac80211')")),
            (LUCI_IFACE_ANCHOR,LUCI_MTWIFI_IFACE+LUCI_IFACE_ANCHOR),
            (LUCI_FREQ_ANCHOR,LUCI_FREQ_MTWIFI),
            ("'2g':"+acs+auto+",'5g':"+acs+auto+",","'2g':(mtw||"+acs+")"+auto+",'5g':(mtw||"+acs+")"+auto+","),
            ("L.hasSystemFeature('hostapd','11ac')&&hwmodelist.ac","(mtw||L.hasSystemFeature('hostapd','11ac'))&&hwmodelist.ac"),
            ("L.hasSystemFeature('hostapd','11ax')&&hwmodelist.ax","(mtw||L.hasSystemFeature('hostapd','11ax'))&&hwmodelist.ax"),
            # The handler only sets up access points; client and ad-hoc come with #168.
            (LUCI_MODE_ANCHOR,"o.value('ap',_('Access Point'));if(hwtype!='mtwifi'){o.value('sta',_('Client'));o.value('adhoc',_('Ad-Hoc'));}")]


def luci_mtwifi(js):
    """Stock wireless.js with mtwifi encryption modes, options and frequency choices; refuses an unknown LuCI build."""
    for anchor,new in luci_edits():
        if new in js:continue
        if js.count(anchor)!=1:raise ValueError('unexpected LuCI wireless.js: mtwifi patch anchor not found')
        js=js.replace(anchor,new)
    return js


# LuCI 23.05 bakes ?v=<revision> into these at package build; luci.js passes it on to every view it loads (#187).
LUCI_HEADERS = ('usr/share/ucode/luci/template/header.ut','usr/share/ucode/luci/template/themes/bootstrap/header.ut')


def luci_build_id(tree):
    """Changes whenever a file under www/ does, so browsers drop what they cached from an older image."""
    return digest(b''.join(name.encode()+tree[name][1] for name in sorted(tree) if name.startswith('www/')))[:12]


def luci_version(ut,build):
    """Stock header template with the build id on its ?v= strings; refuses an unknown LuCI build."""
    ut,count=re.subn(r'\?v=([\w.-]+)',lambda m:f'?v={m[1]}-{build}',ut)
    if not count:raise ValueError('unexpected LuCI header template: ?v= anchor not found')
    return ut


WIFI_PROFILES = ('etc/wireless/l1profile.dat','etc/wireless/mediatek/mt7915.dbdc.b0.dat','etc/wireless/mediatek/mt7915.dbdc.b1.dat')
# vlan: (ports, untagged port whose PVID is that vlan). Copied from the observed stock table.
SWITCH = {1:('1 5t',1),2:('2 5t',2),3:('4 5t',4),4:('0 6t',0)}
SWITCH_UCI = "\nconfig switch\n option name 'switch0'\n option reset '1'\n option enable_vlan '1'\n" + ''.join(
    f"\nconfig switch_vlan\n option device 'switch0'\n option vlan '{v}'\n option vid '{v}'\n option ports '{ports}'\n"
    f"\nconfig switch_port\n option device 'switch0'\n option port '{port}'\n option pvid '{v}'\n"
    for v,(ports,port) in SWITCH.items())
# Not the vendor initializer: no PHY/GPIO writes, no lan_mgr. The chk lines read back what `load` must have set.
SWITCH_INIT = """#!/bin/sh /etc/rc.common
START=18

fail() { echo "x28-switch: $*" >&2; : > /tmp/x28-switch.failed; return 1; }
chk() { want="$1"; shift; got=$(swconfig dev switch0 "$@" 2>/dev/null) && [ "$(echo $got)" = "$want" ]; }

start() {
	rm -f /tmp/x28-switch.failed
	[ "$(swconfig list 2>/dev/null)" = "Found: switch0 - MT7531AE" ] || { fail "unexpected switch"; return 1; }
	swconfig dev switch0 load network || { fail "load failed"; return 1; }
	chk 1 get enable_vlan || fail "vlan not enabled"
""" + ''.join(f"\tchk '{ports}' vlan {v} get ports || fail 'vlan {v} ports'\n\tchk {v} port {port} get pvid || fail 'port {port} pvid'\n"
              for v,(ports,port) in SWITCH.items()) + """	[ ! -e /tmp/x28-switch.failed ]
}
"""


def add_stock(tree,stock,root,exclusive=False):
    """Copy a stock file plus any ELF dependency the tree lacks; every NEEDED must resolve. A root the tree already
    holds must be identical (exclusive: must be absent)."""
    todo=[root];seen=set();added=[];label=posixpath.basename(root)
    while todo:
        name=todo.pop()
        if name in seen:continue
        seen.add(name);chain=[]
        real,data=resolve(stock,name,chain)
        for item in chain:
            if item not in tree:tree[item]=stock[item];added.append(item)
            elif name==root and (exclusive or tree[item][1]!=stock[item][1]):raise ValueError(label+' path already occupied: '+item)
        if data[:4]!=b'\x7fELF':
            if exclusive:raise ValueError('not ELF: '+name)
            continue
        for need in elf_dynamic(data)[1]:
            options=[d+'/'+need for d in ('lib','usr/lib')]
            have=next((p for p in options if p in tree),None)
            if have:resolve(tree,have)
            else:
                old=next((p for p in options if p in stock),None)
                if old is None:raise ValueError('unresolved '+label+' library: '+need)
                todo.append(old)
    return added


def add_swconfig(tree,stock):
    return add_stock(tree,stock,'sbin/swconfig',exclusive=True)


def add_modem(tree,stock):
    """The vendor modem stack x28-modem starts (#131): its stock init scripts, the binaries they run, the modem
    configuration under vendor/etc."""
    services=re.search(r'^SERVICES="([^"]*)"',(MODEM/'x28-modem.init').read_text(),re.M).group(1).split()
    added=[]
    for service in services:
        script='etc/init.d/'+service
        added+=add_stock(tree,stock,script)
        command=re.search(r'procd_set_param command (/\S+)',stock[script][1].decode())
        if not command:raise ValueError('no command in stock '+script)
        added+=add_stock(tree,stock,command.group(1).lstrip('/'))
    added+=add_stock(tree,stock,'usr/bin/mipc_wan_cli')+add_stock(tree,stock,'etc/quectel-project-version')
    added+=add_stock(tree,stock,'etc/conf/apns-conf_8.xml')  # the SIM's APN list x28-apn reads; without it wan loops on NO_SIM_APN (#141)
    for name in sorted(stock):
        if (name=='vendor' or name.startswith('vendor/etc')) and name not in tree:tree[name]=stock[name];added.append(name)
    return added


def public_key(text):
    lines=text.strip().splitlines()
    if len(lines)!=1:raise ValueError('exactly one public key required')
    fields=lines[0].split()
    if len(fields)<2 or fields[0] not in ('ssh-ed25519','ssh-rsa'):
        raise ValueError('only plain ed25519/RSA public keys are supported; no options/private keys')
    try:
        data=base64.b64decode(fields[1],validate=True);pos=0;parts=[]
        while pos<len(data):
            size=struct.unpack_from('>I',data,pos)[0];pos+=4
            if size>len(data)-pos:raise ValueError('truncated key')
            parts.append(data[pos:pos+size]);pos+=size
        if parts[0]!=fields[0].encode():raise ValueError('key type mismatch')
        if fields[0]=='ssh-ed25519' and (len(parts)!=2 or len(parts[1])!=32):raise ValueError('bad ed25519 key')
        if fields[0]=='ssh-rsa':
            if len(parts)!=3 or not parts[1] or not parts[2] or parts[1][0]&128 or parts[2][0]&128:
                raise ValueError('invalid positive RSA integers')
            exponent=int.from_bytes(parts[1],'big');modulus=int.from_bytes(parts[2],'big')
            if exponent<3 or exponent%2==0 or modulus.bit_length()<2048 or modulus%2==0:
                raise ValueError('invalid RSA parameters')
    except (IndexError,struct.error,base64.binascii.Error) as error:
        raise ValueError('invalid public key') from error
    return fields[0]+' '+fields[1]+'\n'


def integrate(stage,key,stock_path,output,kmods_dir=None,ipks=()):
    key=public_key(key) if key else None  # no key: the flasher builds an image without one
    if output.exists():raise FileExistsError(output)
    manifest=json.loads((stage/'manifest.json').read_text());raw=(stage/'rootfs-staging.tar.gz').read_bytes()
    if manifest.get('flashable') is not False or not (stage/'NOT-FLASHABLE').is_file() or digest(raw)!=manifest.get('archive_sha256'):
        raise ValueError('staging identity/marker mismatch')
    stock_bytes=Path(stock_path).read_bytes()
    tree=load_archive(io.BytesIO(raw));removed=[]
    stock=load_archive(io.BytesIO(stock_bytes),'rootfs')
    swconfig_added=add_swconfig(tree,stock)
    modem_added=add_modem(tree,stock)
    bootok_added=add_stock(tree,stock,'sbin/dd-nand')  # the vendor writer x28-bootok uses on one misc byte (#145)
    for name in WIFI_PROFILES:
        if name not in stock or not stock[name][0].isfile():raise ValueError('missing stock Wi-Fi profile: '+name)
        tree[name]=stock[name]
    for name in list(tree):
        if (name.startswith(('etc/rc.d/','etc/uci-defaults/','etc/board.d/','lib/upgrade/','etc/dropbear/'))
            or 'zmtk_boot_done' in name or (name.startswith('lib/preinit/') and 'failsafe' in name)):
            keep=name.startswith('etc/rc.d/') and name.split('/')[-1] in ALLOWED_START|ALLOWED_STOP
            if keep:
                meta=tree[name][0];service=name.split('/')[-1][3:]
                target=posixpath.normpath(posixpath.join('etc/rc.d',meta.linkname))
                expected='etc/init.d/'+service
                if not meta.issym() or target!=expected or expected not in tree or not tree[expected][0].isfile() or not tree[expected][0].mode&0o111:
                    raise ValueError('redirected or invalid startup link: '+name)
            if not keep:
                removed.append(name);del tree[name]
    for required in ('etc/rc.d/S19dropbear','etc/rc.d/S20network','etc/init.d/dropbear','etc/init.d/network'):
        if required not in tree:raise ValueError('required management service missing: '+required)
    def put(name,text,mode=0o644):
        info=tarfile.TarInfo(name);info.mode=mode;info.uid=info.gid=0
        data=text.encode();info.size=len(data);tree[name]=(info,data)
    if 'lib/preinit/00_preinit.conf' in tree:
        config=tree['lib/preinit/00_preinit.conf'][1].decode()
        put('lib/preinit/00_preinit.conf',config+'\npi_preinit_no_failsafe="y"\n')
    def enable(start,service,stop=None):
        if 'etc/init.d/'+service not in tree:raise ValueError('missing service: '+service)
        for kind,n in (('S',start),('K',stop)):
            if n is None:continue
            link=tarfile.TarInfo(f'etc/rc.d/{kind}{n}{service}');link.type=tarfile.SYMTYPE;link.linkname='../init.d/'+service;tree[link.name]=(link,b'')
    put('etc/init.d/x28-switch',SWITCH_INIT,0o755);enable(18,'x28-switch')
    put('sbin/x28-leds',(LEDS/'x28-leds').read_text(),0o755)
    put('sbin/x28-wps',(WIFI/'x28-wps').read_text(),0o755)
    put('etc/init.d/x28-wps',(WIFI/'x28-wps.init').read_text(),0o755);enable(97,'x28-wps')
    # The staged boot script runs `wifi config` once when /etc/config/wireless is missing: WPA2 with a random key.
    put('lib/netifd/wireless/mtwifi.sh',(WIFI/'mtwifi.sh').read_text(),0o755)
    put('lib/wifi/mtwifi.sh',(WIFI/'mtwifi.detect').read_text())
    put('usr/share/x28-wifi/regions',(WIFI/'regions').read_text())
    put('usr/share/x28-wifi/channels5',(WIFI/'channels5').read_text())
    if LUCI_WIRELESS in tree:put(LUCI_WIRELESS,luci_mtwifi(tree[LUCI_WIRELESS][1].decode()))
    if LUCI_STORAGE in tree:put(LUCI_STORAGE,luci_storage(tree[LUCI_STORAGE][1].decode()))
    if LUCI_ANALYSIS in tree:put(LUCI_ANALYSIS,luci_analysis(tree[LUCI_ANALYSIS][1].decode()))
    # Cellular WAN as a stock-looking netifd protocol (#135): the proto handler, its APN helper and the LuCI form.
    put('lib/netifd/proto/x28_mipc.sh',(MIPC/'x28_mipc.sh').read_text(),0o755)
    put('sbin/x28-apn',(MIPC/'x28-apn').read_text(),0o755)
    put('www/luci-static/resources/protocol/x28_mipc.js',(LUCI_MIPC/'htdocs/luci-static/resources/protocol/x28_mipc.js').read_text())
    put('usr/share/rpcd/acl.d/luci-proto-x28-mipc.json',(LUCI_MIPC/'root/usr/share/rpcd/acl.d/luci-proto-x28-mipc.json').read_text())
    put('etc/config/system',"""config system
 option hostname 'x28'
 option timezone 'UTC'
 option ttylogin '0'
 option log_size '64'
 option urandom_seed '0'

config timeserver 'ntp'
 option enabled '1'
 option enable_server '0'
 list server '0.openwrt.pool.ntp.org'
 list server '1.openwrt.pool.ntp.org'
 list server '2.openwrt.pool.ntp.org'
 list server '3.openwrt.pool.ntp.org'
""")
    put('etc/init.d/x28-modem',(MODEM/'x28-modem.init').read_text(),0o755);enable(19,'x28-modem')
    put('etc/init.d/x28-leds',(LEDS/'x28-leds.init').read_text(),0o755);enable(99,'x28-leds')
    enable(19,'dnsmasq');enable(35,'odhcpd')
    enable(12,'rpcd');enable(19,'firewall');enable(50,'uhttpd')  # LuCI and NAT (#141)
    if 'etc/config/uhttpd' in tree:  # HTTPS with a self-signed certificate uhttpd makes on first start (px5g), HTTP redirected
        config=tree['etc/config/uhttpd'][1].decode()
        edits=[(r"option\s+redirect_https\s+'?0'?","option redirect_https '1'"),(r"option\s+commonname\s+'?OpenWrt'?","option commonname 'x28'")]
        if PASSWALL2_DEFAULT in tree:edits.append((r"option\s+max_requests\s+'?\d+'?","option max_requests '50'"))  # Passwall2's pages poll a lot
        for old,new in edits:  # the stock file separates some values with tabs
            config,n=re.subn(old,new,config)
            if n!=1:raise ValueError('unexpected uhttpd config: '+old)
        put('etc/config/uhttpd',config)
    put('etc/init.d/x28-bootok',(BOOTOK/'x28-bootok.init').read_text(),0o755);enable(96,'x28-bootok')
    put('lib/preinit/79_x28_user_data',(STORAGE/'x28-user-data.preinit').read_text())
    put('etc/config/fstab',(STORAGE/'fstab').read_text())
    for name in UBI_WRITERS:
        if name in tree:removed.append(name);del tree[name]
    enable(98,'sysntpd')  # without a set clock HTTPS (opkg) fails: the unit boots at 2010-01-01 (#169)
    enable(95,'done')  # `mount_root done`: without it mount_root discards the overlay at every boot (#143)
    # Stock defaults plus IPv6 on the LAN (#126): RA and DHCPv6 from the /64 the cellular WAN hands to netifd.
    put('etc/config/dhcp',"""config dnsmasq
 option domainneeded '1'
 option boguspriv '1'
 option localise_queries '1'
 option rebind_protection '1'
 option rebind_localhost '1'
 option local '/lan/'
 option domain 'lan'
 option expandhosts '1'
 option cachesize '1000'
 option authoritative '1'
 option readethers '1'
 option leasefile '/tmp/dhcp.leases'
 option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
 option nonwildcard '1'
 option localservice '1'
 option ednspacket_max '1232'

config dhcp 'lan'
 option interface 'lan'
 option start '100'
 option limit '150'
 option leasetime '12h'
 option ra 'server'
 option dhcpv6 'server'
 list ra_flags 'managed-config'
 list ra_flags 'other-config'

config dhcp 'wan'
 option interface 'wan'
 option ignore '1'
""")
    # CONFIG_NAMESPACES is off in the vendor kernel: with ujail present procd jails dnsmasq/sysntpd and they exit (#122).
    for name in [n for n in tree if n=='sbin/ujail' or n.startswith('usr/lib/opkg/info/procd-ujail.')]:
        removed.append(name);del tree[name]
    if 'usr/lib/opkg/status' in tree:  # or opkg would still list it and could reinstall it
        stanzas=tree['usr/lib/opkg/status'][1].decode().split('\n\n')
        put('usr/lib/opkg/status','\n\n'.join(x for x in stanzas if not x.startswith('Package: procd-ujail\n')))
    # The X28 feed describes the kernel (#202). The stock records have a foreign architecture and opkg drops them on its
    # first write, which leaves nothing to satisfy a kmod's kernel dependency.
    for name in [n for n in tree if n.startswith(('usr/lib/opkg/info/kmod-','usr/lib/opkg/info/kernel.'))]:
        removed.append(name);del tree[name]
    if 'usr/lib/opkg/status' in tree:
        stanzas=tree['usr/lib/opkg/status'][1].decode().strip('\n').split('\n\n')
        record=f'Package: kernel\nVersion: {KERNEL_VERSION}\nArchitecture: all\nStatus: install user installed\n'
        kept=[x for x in stanzas if not x.startswith(('Package: kernel\n','Package: kmod-'))]
        put('usr/lib/opkg/status','\n\n'.join(kept+[record]))
        put('usr/lib/opkg/info/kernel.control',record.replace('Status: install user installed\n',''))
        put('usr/lib/opkg/info/kernel.list','')
    enable(90,'openvpn')  # starts only the tunnels enabled in its config
    # Built against the private SDK tree, so they come from the local build, never from the repo (#227, #198).
    kmods={p:[Path(kmods_dir)/(m+'.ko') for m in ms] for p,ms in KMOD_PACKAGES.items()} if kmods_dir else {}
    if kmods:  # x28-kmods loads them from here; the kernel's modprobe never looks here (see x28-kmods.init)
        info=tarfile.TarInfo('lib/modules/x28');info.type=tarfile.DIRTYPE;info.mode=0o755;info.uid=info.gid=0;tree[info.name]=(info,b'')
    for package,paths in kmods.items():
        for path in paths:
            module=path.read_bytes()
            info=tarfile.TarInfo('lib/modules/x28/'+path.name);info.mode=0o644;info.uid=info.gid=0;info.size=len(module);tree[info.name]=(info,module)
        extra=', kmod-ipt-tproxy' if package=='kmod-ipt-socket' else ''  # x28_udp_lookup lives in kmod-ipt-tproxy
        record=f'Package: {package}\nVersion: {KERNEL_VERSION}\nDepends: kernel (= {KERNEL_VERSION}){extra}\nArchitecture: aarch64_generic\n'
        put('usr/lib/opkg/status',tree['usr/lib/opkg/status'][1].decode().rstrip('\n')+'\n\n'+record+'Status: install user installed\n')
        put(f'usr/lib/opkg/info/{package}.control',record)
        put(f'usr/lib/opkg/info/{package}.list',''.join(f'/lib/modules/x28/{p.name}\n' for p in paths))
    if kmods:put('etc/init.d/x28-kmods',(KMODS/'x28-kmods.init').read_text(),0o755);enable(97,'x28-kmods')
    def record(control,files):
        name=re.search(r'^Package: (.+)$',control,re.M).group(1)
        put('usr/lib/opkg/status',tree['usr/lib/opkg/status'][1].decode().rstrip('\n')+'\n\n'+control.rstrip('\n')+'\nStatus: install user installed\n')
        put(f'usr/lib/opkg/info/{name}.control',control);put(f'usr/lib/opkg/info/{name}.list',''.join('/'+n+'\n' for n in files))
    for ipk in ipks:  # whole packages from the X28 feed, e.g. ipset for Passwall2's rules (#200)
        with tarfile.open(fileobj=io.BytesIO(Path(ipk).read_bytes()),mode='r:gz') as outer:
            data=outer.extractfile('./data.tar.gz').read();control=outer.extractfile('./control.tar.gz').read()
        with tarfile.open(fileobj=io.BytesIO(control),mode='r:gz') as t:control=t.extractfile('./control').read().decode()
        files=[]
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
            for m in t.getmembers():
                name=m.name.lstrip('./')
                if not name or (m.isdir() and name in tree):continue
                if not (m.isfile() or m.isdir() or m.issym()):raise ValueError('unexpected member in '+str(ipk)+': '+m.name)
                info=copy.copy(m);info.name=name;info.uid=info.gid=0;info.uname=info.gname=''
                tree[name]=(info,t.extractfile(m).read() if m.isfile() else b'')
                if not m.isdir():files.append(name)
        record(control,files)
    # The vendor kernel has these built in or as stock modules; record them so opkg sees every dependency met (#200).
    status=tree['usr/lib/opkg/status'][1].decode()
    have=set(re.findall(r'^Package: (.+)$',status,re.M))|{p.strip().split(' ')[0] for v in re.findall(r'^Provides: (.+)$',status,re.M) for p in v.split(',')}
    wanted={d.strip().split(' ')[0] for v in re.findall(r'^Depends: (.+)$',status,re.M) for d in v.split(',')}
    for name in sorted((wanted-have)&set(STUBS.read_text().split())):
        record(f'Package: {name}\nVersion: {KERNEL_VERSION}\nDepends: kernel (= {KERNEL_VERSION})\nArchitecture: all\n',[])
    if PASSWALL2_DEFAULT in tree:  # what its uci-defaults would do, which this profile strips
        config=tree[PASSWALL2_DEFAULT][1].decode()
        for old,new in (("option prefer_nft '1'","option prefer_nft '0'"),("option tcp_proxy_way 'redirect'","option tcp_proxy_way 'tproxy'")):
            if old not in config:raise ValueError('unexpected Passwall2 default config: '+old)
            config=config.replace(old,new)
        put('etc/config/passwall2',config)
        put('etc/x28-killswitch.sh',Path(__file__).with_name('x28-killswitch.sh').read_text(),0o755)
        init=tree['etc/init.d/passwall2'][1].decode()
        for action in ('start','stop'):
            anchor='\t"$APP_FILE" '+action+' "$action" 9>&-'
            if anchor not in init:raise ValueError('unexpected Passwall2 init script: '+action)
            init=init.replace(anchor,'\t/etc/x28-killswitch.sh || { unset_lock; return 1; }\n'+anchor)
        # Again once Passwall2's rules exist, so the kill switch lets its direct sets through.
        anchor='\t"$APP_FILE" start "$action" 9>&-\n\tlocal status=$?\n'
        if init.count(anchor)!=2:raise ValueError('unexpected Passwall2 init script: start status')
        init=init.replace(anchor,anchor+'\t/etc/x28-killswitch.sh || status=1\n')
        put('etc/init.d/passwall2',init,0o755)
        put('etc/config/firewall',tree['etc/config/firewall'][1].decode().rstrip('\n')+"\n\nconfig include 'passwall2'\n option type 'script'\n option path '/var/etc/passwall2.include'\n option reload '1'\n\nconfig include 'x28_killswitch'\n option type 'script'\n option path '/etc/x28-killswitch.sh'\n option reload '1'\n")
        put('etc/config/dhcp',tree['etc/config/dhcp'][1].decode().replace(" option ednspacket_max '1232'\n"," option ednspacket_max '1232'\n option localuse '1'\n",1))
        put('etc/opkg/keys/'+PASSWALL_KEY_ID,(FEED_KEY.parent/'passwall.pub').read_text())
        # LuCI's apply (luci-reload) restarts only enabled services. Its boot start waits start_delay (60 s); x28-kmods
        # loads TPROXY about 30 s after boot and starts it again then, in case the modules came late.
        enable(99,'passwall2',15)  # its init has STOP=15: ucitrack skips a service whose `enabled` needs the K link too (#297)
        if 'etc/config/ucitrack' in tree and "config passwall2\n" not in tree['etc/config/ucitrack'][1].decode():
            put('etc/config/ucitrack',tree['etc/config/ucitrack'][1].decode().rstrip('\n')+"\n\nconfig passwall2\n\toption init 'passwall2'\n")
    put('etc/opkg/keys/'+FEED_KEY_ID,FEED_KEY.read_text())
    put('etc/opkg/customfeeds.conf',(tree['etc/opkg/customfeeds.conf'][1].decode() if 'etc/opkg/customfeeds.conf' in tree else '')+FEED_LINE
        +(PASSWALL_FEEDS if PASSWALL2_DEFAULT in tree else ''))
    # Physical console only (kernel console=ttyS0,921600): needs the board's UART pads, unlike SSH. This is the single
    # way in if switch/network init fails, since failsafe is removed.
    if 'bin/ash' not in tree:raise ValueError('missing /bin/ash for the console shell')
    put('etc/inittab','::sysinit:/etc/init.d/rcS S boot\n::shutdown:/etc/init.d/rcS K shutdown\nttyS0::askfirst:/bin/ash --login\n')
    put('etc/config/network',f"""config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1'
 option netmask '255.0.0.0'

config device
 option name '{LAN}'
 option type 'bridge'
"""+''.join(f" list ports '{p}'\n" for p in LAN_PORTS)+f"""
config interface 'lan'
 option device '{LAN}'
 option proto 'static'
 option ipaddr '192.168.70.1'
 option netmask '255.255.255.0'
 option ip6assign '64'

config interface 'wan'
 option proto 'x28_mipc'
"""+SWITCH_UCI)
    put('etc/config/dropbear',"""config dropbear
 option PasswordAuth 'on'
 option RootPasswordAuth 'on'
 option RootLogin 'on'
 option Port '22'
 option Interface 'lan'
 option GatewayPorts 'off'
 option mdns '0'
""")
    if key:put('etc/dropbear/authorized_keys',key,0o600)
    # Like stock OpenWrt root starts with an empty password so LuCI can log in and ask for one; SSH takes keys or the root password; dropbear never accepts an empty one, so password login starts once the owner sets it (LuCI or passwd).
    rows=tree['etc/shadow'][1].decode().splitlines();found=False;locked=[]
    for row in rows:
        fields=row.split(':')
        if len(fields)!=9:raise ValueError('malformed shadow record')
        fields[1]='' if fields[0]=='root' else '!';locked.append(':'.join(fields));found|=fields[0]=='root'
    if not found:raise ValueError('missing root account')
    put('etc/shadow','\n'.join(locked)+'\n',0o600)
    put('etc/rc.local','#!/bin/sh\nexit 0\n',0o755)
    put('etc/fstab','# First-boot profile: no shared partition mounts.\n')
    build=luci_build_id(tree)  # after the last change to www/
    for name in LUCI_HEADERS:
        if name in tree:put(name,luci_version(tree[name][1].decode(),build))
    validate_parents(tree)
    ab_check(tree)  # #87: refuse a profile whose boot path can reach flash or the other slot
    output.mkdir(parents=True,mode=0o700);(output/'NOT-FLASHABLE').write_text('Management profile only; overlay, UBI, signature/slot and hardware readiness unverified.\n');(output/'INCOMPLETE').touch()
    archive=output/'rootfs-management.tar.gz'
    with tarfile.open(archive,'x:gz') as tar:
        for name,(info,data) in sorted(tree.items()):
            meta=copy.copy(info);tar.addfile(meta,io.BytesIO(data) if meta.isfile() else None)
    report={'flashable':False,'input_stage_sha256':digest(raw),'archive_sha256':digest(archive.read_bytes()),
            'lan_device':LAN,'lan_ports':list(LAN_PORTS),'switch_table':{str(v):x[0] for v,x in SWITCH.items()},'swconfig_sha256':digest(tree['sbin/swconfig'][1]),'swconfig_added':swconfig_added,'modem_added':modem_added,'bootok_added':bootok_added,'stock_sha256':digest(stock_bytes),'lan_address':'192.168.70.1/24','ssh_port':22,'public_key_sha256':digest(key.encode()) if key else None,
            'removed_paths':removed,'enabled_start_links':sorted(n for n in tree if n.startswith('etc/rc.d/S')),
            'limits':['Modem stack from stock, started by x28-modem; reboot persistence unverified (#131)','UART console shell (ttyS0, no password) is physical-access root','Switch table is stock-observed, never applied on hardware; physical socket-4 mapping is operator-confirmed only','No web UI','LEDs show no-service without the modem stack','Root/key login still needs runtime test','No overlay/UBI/slot/signature readiness']}
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink()
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--stage',type=Path,required=True)
    ap.add_argument('--public-key',type=Path);ap.add_argument('--stock',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--kmods',type=Path,required=True,help='the modules package/x28-kmods/build.sh built for this kernel: WireGuard, TPROXY, socket')
    ap.add_argument('--ipk',type=Path,nargs='+',required=True,help="the X28 feed's ipset, libipset13 and x28-ipset-kernel, which Passwall2 needs")
    args=ap.parse_args();print(json.dumps(integrate(args.stage,args.public_key.read_text() if args.public_key else None,args.stock,args.output,args.kmods,args.ipk),indent=2))


if __name__=='__main__':main()
