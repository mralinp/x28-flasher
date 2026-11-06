#!/bin/sh
# ICMP stays direct: Xray cannot proxy it, and blocking errors breaks path MTU discovery.
set -e
enabled="$(uci -q get passwall2.@global[0].enabled || :)"
for family in iptables ip6tables; do
	protocol=icmp
	[ "$family" != ip6tables ] || protocol=ipv6-icmp
	if ! "$family" -nL x28_killswitch >/dev/null 2>&1; then
		"$family" -N x28_killswitch
	fi
	if [ "$enabled" = 1 ]; then
		if ! "$family" -C x28_killswitch -o ccmni+ ! -p "$protocol" -j REJECT >/dev/null 2>&1; then
			"$family" -A x28_killswitch -o ccmni+ ! -p "$protocol" -j REJECT
		fi
		# Destinations Passwall2 itself sends direct (Direct shunt rules, the node, its whitelist) may leave by the WAN:
		# mirror every set its PSW2 chain returns on, ports ignored. Passwall2's init runs this again after it starts.
		direct="$("$family" -t mangle -S PSW2 2>/dev/null | sed -n 's/.*--match-set \([^ ]*\) dst.* -j RETURN$/\1/p' | sort -u)"
		for set in $("$family" -S x28_killswitch | sed -n 's/^-A x28_killswitch -m set --match-set \([^ ]*\) dst -j RETURN$/\1/p'); do
			echo "$direct" | grep -qx "$set" || "$family" -D x28_killswitch -m set --match-set "$set" dst -j RETURN
		done
		for set in $direct; do
			if ! "$family" -C x28_killswitch -m set --match-set "$set" dst -j RETURN >/dev/null 2>&1; then
				"$family" -I x28_killswitch -m set --match-set "$set" dst -j RETURN
			fi
		done
	else
		"$family" -F x28_killswitch
	fi
	if ! "$family" -C forwarding_rule -j x28_killswitch >/dev/null 2>&1; then
		"$family" -I forwarding_rule -j x28_killswitch
	fi
done
