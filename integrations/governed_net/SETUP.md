# Setting up the enforcement host (for the owner)

Everything here needs privileges, so the owner runs every step by hand. Nothing in this directory was
loaded into a kernel, attached to an interface, or applied to any host's network while it was built.
Steps that change a host are marked **HOST CHANGE**, and each one has its undo beside it.

There are two layouts. The **LAN edge layout** (section A) is the simpler one the owner chose: no dedicated
cable and no new VM, the program on the Proxmox host's own LAN NIC, coexisting with the household LAN. The
**dedicated wire layout** (sections 1 to 8) is the alternative: a cable to a passed-through port on a new
VM, which isolates the agent path completely. Read the one you are deploying.

---

# A. LAN edge layout (no dedicated wire, no new VM)

The program attaches to the Proxmox host's own LAN port and guards only the tool server's address and the
agent port; the whole household LAN crosses that NIC and everything else passes untouched.

| Placeholder | Meaning | Example |
|---|---|---|
| `<LAN_IF>` | the host's LAN port (Intel i226, igc, a bridge slave of the LAN bridge) | `enp2s0` |
| `<LAN_NET>` | the LAN's network | `203.0.113.0/24` |
| `<SERVER_ADDR>` | the tool server's IP, on a different machine reached through the firewall | `198.51.100.20` |
| `<SERVER_IF>` | the LAN interface on the Mac (Wi-Fi) | `en1` |
| `<MAC_LAN>` | the Mac's LAN address | `203.0.113.40` |
| `<MODEL_HOST>` | the machine the model runs on, reachable over the normal network or the mesh | |
| `<AGENT_PORT>` | the agent UDP port | `47011` |

```
Mac on Wi-Fi (en1, 203.0.113.40) --- AP --- Proxmox host LAN port <LAN_IF>:  XDP (before the bridge)
   | harness loop + client, socket pinned to en1                               matches dst=<SERVER_ADDR> udp=47011
   | agent datagrams routed by the firewall VM to <SERVER_ADDR>                 everything else passes
   + model: ssh -L 8888 to <MODEL_HOST> (control plane, not governed)        gn_loader.py fills maps, drains ring
                                                                              tool server on another machine (<SERVER_ADDR>)
```

Why the program sits on the host's bridge-slave port: XDP on a bridge slave runs on ingress before the
bridge, so the frames the firewall VM routes toward `<SERVER_ADDR>` are seen here, addressed to the
firewall's MAC with `<SERVER_ADDR>` as the IPv4 destination. The program matches on that destination IP
and the agent port, so another host's traffic, other ports, IPv6, ARP, VLAN tags and fragments all pass.

**The bypass, stated plainly.** XDP guards only paths through `<LAN_IF>`. The Mac's route to
`<SERVER_ADDR>`'s network is advertised over the mesh VPN (a `utun` interface), so a plain socket would
reach the server through the tunnel, never crossing `<LAN_IF>` in the clear. Two defences, both required:
the client pins its socket to `<SERVER_IF>` and its LAN source address (`--via-if`), and the tool server
binds only `<SERVER_ADDR>` and refuses, as a recorded finding, any datagram whose source is outside
`<LAN_NET>` (section A.4). A host firewall rule on the server machine (A.4) makes that refusal a drop.

## A.1 Build (no install on the host)

The Proxmox host is x86_64 with clang, python3 and iproute2, but no bpftool and no libbpf, so the C loader
is not built there. Build the BPF object with clang (architecture-neutral) and use the pure-Python loader:

```sh
# on the host, in this repository (or copy the five files named below)
clang -O2 -g -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I prismpath-ebpf \
      -c prismpath-ebpf/gnet/gn_xdp.pin.bpf.c -o prismpath-ebpf/gnet/gn_xdp.pin.bpf.o
python3 -m integrations.governed_net.policy build          # build/net_rules.ppt, .actions, .core.json
python3 prismpath-ebpf/gnet/gn_loader.py --self-test        # the loader's own non-privileged checks
```

The files the host needs: `prismpath-ebpf/gnet/gn_xdp.pin.bpf.c` (and the headers it includes:
`gn_xdp.bpf.c`, `gn_xdp.h`, `gn_common.h`, `gn_maps.h`, `../ppt_common.h`, `../ppt_eval_bpf.h`),
`prismpath-ebpf/gnet/gn_loader.py`, and the built `build/net_rules.ppt` and `build/net_rules.actions`. The
receipt logger (`integrations/governed_net/receipt_logger.py`) needs the repository and its Python
environment, so run it on a machine that has them (it reads the ring buffer hex `gn_loader.py events`
prints, so it can be the host or another machine fed over a pipe/SSH).

`gn_xdp.pin.bpf.c` is `gn_xdp.bpf.c` with every map pinned by name, so iproute2 pins the maps where the
Python loader can reach them. (A static x86_64 build of the C loader on the aarch64 build machine was not
feasible without installing an x86_64 sysroot and static libbpf; the pure-Python loader is the no-install
path, and `--self-test` proves its parsing, its bpf_attr packing, its ring-buffer decoder and its counter
summation with no privilege. The privileged syscalls themselves are first exercised here, on the host.)

## A.2 The kernel test run, with no attach

As with the wire layout, confirm the kernel accepts the program and decides as the userspace path does,
before attaching to anything. This needs a machine with libbpf to build the C loader (`make -C
prismpath-ebpf gnet` on the aarch64 build host or any libbpf host), then:

```sh
python3 -m integrations.governed_net.differential --random 20000 --seed 7 --corpus-only --out /tmp/gnet-corpus
sudo prismpath-ebpf/gnet/gn_loader test-run prismpath-ebpf/gnet/gn_xdp.bpf.o \
     /tmp/gnet-corpus/policy/net_rules.ppt /tmp/gnet-corpus/policy/net_rules.actions \
     --server-ip 192.0.2.20 --port 47011 \
     < /tmp/gnet-corpus/frames.bin > /tmp/gnet-corpus/kernel.txt
diff /tmp/gnet-corpus/expected.txt /tmp/gnet-corpus/kernel.txt && echo "kernel agrees"
```

On the no-install host there is no C loader, so the kernel's acceptance of the program is shown instead by
the `ip link ... obj` load in A.3 succeeding (iproute2's own libbpf runs the verifier).

## A.3 Coexistence check, then attach

First, a baseline with the program detached (nothing heavier than ping), from the Mac or the host:

```sh
prismpath-ebpf/gnet/coexist.sh <firewall-ip> <SERVER_ADDR>        # RTTs, detached
```

**HOST CHANGE (`<LAN_IF>`): attach.** Loading the pinned object attaches the program and pins the maps
under `/sys/fs/bpf/<LAN_IF>/`:

```sh
sudo python3 prismpath-ebpf/gnet/gn_loader.py attach <LAN_IF> prismpath-ebpf/gnet/gn_xdp.pin.bpf.o
# equivalently: sudo ip link set dev <LAN_IF> xdpdrv obj prismpath-ebpf/gnet/gn_xdp.pin.bpf.o sec xdp
```

Until the maps are filled, `match_dst_ip` is 0, so **nothing matches and the whole LAN passes untouched**
(a safe first attach). Confirm coexistence, which may blink the link for a few seconds as the driver
reloads its XDP path:

```sh
MAPS_DIR=/sys/fs/bpf/<LAN_IF> prismpath-ebpf/gnet/coexist.sh <firewall-ip> <SERVER_ADDR>
```

The RTTs should match the baseline, and the counters should be all `other` so far. Then set the target and
the policy (after this, a matched request with no policy would be dropped; the fill sets both together):

```sh
sudo python3 prismpath-ebpf/gnet/gn_loader.py fill --maps-dir /sys/fs/bpf/<LAN_IF> \
     --table build/net_rules.ppt --actions build/net_rules.actions --server-ip <SERVER_ADDR> --port <AGENT_PORT>
```

**DETACH (rollback):** `sudo python3 prismpath-ebpf/gnet/gn_loader.py detach <LAN_IF>` (or `sudo ip link set
dev <LAN_IF> xdp off`). If the LAN itself drops and you cannot reach the host over it, detach from a
machine on another path (the mesh VPN, or the Proxmox console), since the management path is not
`<LAN_IF>`. An attach or detach may blink the link for a few seconds; it does not change any address,
route or firewall rule, and it never touches the control plane or other hosts.

## A.4 The tool server and its host firewall (the backstop)

On the server machine (`<SERVER_ADDR>`), run the tool server bound to its LAN address, accepting only LAN
sources:

```sh
python3 -m integrations.governed_net.server --make-world /tmp/gnet-world \
    --bind <SERVER_ADDR> --port <AGENT_PORT> --lan-net <LAN_NET> \
    --run /tmp/gnet-run/server --keys /tmp/gnet-keys
```

**HOST CHANGE (server machine): accept the agent port only from the LAN.** This closes the tunnel bypass
at the server, so the backstop is a drop and not only a finding:

```sh
sudo nft add table inet gnet
sudo nft add chain inet gnet input '{ type filter hook input priority 0; policy accept; }'
sudo nft add rule inet gnet input udp dport <AGENT_PORT> ip saddr != <LAN_NET> drop
```

*Undo:* `sudo nft delete table inet gnet`.

Drain the ring buffer into the receipt logger (on the host, or piped to a machine with the repository):

```sh
sudo python3 prismpath-ebpf/gnet/gn_loader.py events --maps-dir /sys/fs/bpf/<LAN_IF> \
  | python3 -m integrations.governed_net.receipt_logger --run /tmp/gnet-run/xdp --keys /tmp/gnet-keys \
       --status-bind <SERVER_ADDR>
```

## A.5 The Mac client

**HOST CHANGE (Mac): the model forward.** The model listens on `127.0.0.1:8888` on `<MODEL_HOST>` and is
the control plane, not the governed path, so forward it to the Mac's localhost over the normal network or
the mesh, and leave the endpoint at localhost (do not change the model server's bind):

```sh
ssh -N -L 8888:127.0.0.1:8888 <MODEL_HOST> &
export PRISMPATH_HARNESS_ENDPOINT=http://localhost:8888/v1/chat/completions PRISMPATH_HARNESS_MODEL=gemma4
```

Run one episode, pinning the agent socket to the Wi-Fi interface so it crosses `<LAN_IF>` and not the mesh
tunnel. The client reports the interface and source it chose, and refuses if `<SERVER_IF>` has no address
in `<LAN_NET>`:

```sh
/usr/bin/python3 -m integrations.governed_net.client --server <SERVER_ADDR> --port <AGENT_PORT> \
    --via-if <SERVER_IF> --lan-net <LAN_NET> --task "Edit .toolchain/VERSION so it says 2.0."
```

The client is stock Python 3.9 with the standard library only. Stop the logger and the server with Ctrl-C
/ Ctrl-D as in section 7; verify both runs with `core_evidence.py verify --sample all` (section 7).

## A.6 Rolling back the LAN edge

1. `<LAN_IF>`: `sudo python3 prismpath-ebpf/gnet/gn_loader.py detach <LAN_IF>`.
2. Server machine: `sudo nft delete table inet gnet`.
3. Mac: stop the SSH forward; the client changes nothing persistent.

Nothing above changes an address, a route or the bridge; the only persistent change is the one nftables
table on the server, with its undo given.

---

# B. Dedicated wire layout (alternative: a cable to a passed-through port on a new VM)

Names used below. Choose your own and substitute them:

| Placeholder | Meaning | Example |
|---|---|---|
| `<PVE>` | the Proxmox host | |
| `<PCI>` | the spare i226 port's PCI address on `<PVE>` | `0000:03:00.0` |
| `<VMID>` | the new VM's id | `9300` |
| `<WIRE_IF>` | the i226 port's interface name inside the VM | `enp1s0` |
| `<WIRE_NET>` | a /30 used nowhere on your network | `10.250.0.0/30` |
| `<VM_WIRE>` / `<MAC_WIRE>` | the two ends of the wire | `10.250.0.1` / `10.250.0.2` |
| `<ENDPOINT>` | the model's OpenAI compatible endpoint, reached over the Mac's normal network | |

The target layout:

```
Mac (harness loop, client) --- dedicated cable --- i226 port (passed through) --- VM: XDP on <WIRE_IF>
      |                                                                              |-- receipt logger (ring buffer)
      +-- normal network --> model endpoint                                          |-- tool server (bwrap)
                                                       VM management NIC (virtio, vmbr0) <- SSH, untouched
```

The wire has two static addresses, no gateway, no DNS and no forwarding, and it is never routed. The
XDP program sits only on `<WIRE_IF>`. The VM's management NIC is a different device, so SSH and
management traffic never cross the program. Even on `<WIRE_IF>` the program passes everything that is
not UDP to port 47011 before it reads a byte of payload.

## 1. The spare port on the Proxmox host

1. Find the port and its IOMMU group (read only):
   ```sh
   lspci -nnk | grep -A3 -i 'i226'          # the PCI address, and "Kernel driver in use: igc"
   for g in /sys/kernel/iommu_groups/*; do echo "$g: $(ls $g/devices)"; done | grep <PCI>
   ip -br link; bridge link                  # the port's host interface must be in no bridge (not vmbr0)
   ```
   The port must sit in an IOMMU group of its own, or share it only with devices you pass through
   together. It must not be the host's management port, and no `vmbr` may use it.
2. **HOST CHANGE: IOMMU.** Skip this step if `dmesg | grep -i -e DMAR -e IOMMU` already shows it enabled.
   Otherwise add `intel_iommu=on iommu=pt` to the kernel command line (`/etc/default/grub`,
   `GRUB_CMDLINE_LINUX_DEFAULT`, then `update-grub`, or `/etc/kernel/cmdline` and `proxmox-boot-tool
   refresh` on systemd boot), and add `vfio`, `vfio_iommu_type1` and `vfio_pci` to `/etc/modules`. Then
   reboot `<PVE>`. *Undo:* remove the options and the modules, refresh, and reboot.

## 2. The VM

**HOST CHANGE: a new VM.** Debian 12 (or Ubuntu 24.04) minimal, 2 vCPU, 2 GB RAM, a 16 GB disk, q35, and
one virtio NIC on your management bridge for SSH:

```sh
qm create <VMID> --name gnet-enforce --machine q35 --cores 2 --memory 2048 --ostype l26 \
   --scsihw virtio-scsi-single --scsi0 local-lvm:16 --net0 virtio,bridge=vmbr0 \
   --cdrom local:iso/debian-12-netinst.iso --boot 'order=scsi0;ide2'
qm start <VMID>          # install the OS over the console, with SSH server, and no desktop
```

Once SSH to the VM works over the management NIC, **HOST CHANGE: pass the port through.** This step
takes the port away from the host:

```sh
qm shutdown <VMID>
qm set <VMID> --hostpci0 <PCI>,pcie=1
qm start <VMID>
```

*Undo:* `qm shutdown <VMID> && qm set <VMID> --delete hostpci0`. The host gets the port back from vfio
when you rebind it to `igc`, or at the next reboot. To remove everything, `qm destroy <VMID>`.

Inside the VM, `lspci -nnk | grep -A3 i226` should show `Kernel driver in use: igc`, and `ip -br link`
names `<WIRE_IF>`. Native XDP on igc needs a kernel of 5.13 or later. Debian 12's 6.1 is fine.

## 3. The VM's software and the wire address

```sh
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config gcc make git bubblewrap \
                    python3 python3-venv iproute2 nftables
git clone <this repository> prismpath && cd prismpath && git checkout governed-net
python3 -m venv .venv && .venv/bin/pip install -e .        # the reference kernel and its key tools
make -C prismpath-ebpf gnet                                 # gn_xdp.bpf.o, gn_loader, gn_batch
.venv/bin/python -m integrations.governed_net.policy build  # build/net_rules.ppt, .actions, .core.json
```

You also need the Lean oracle, so that verification can replay receipts:
`(cd formal && lake build core-oracle)`, or point `PRISMPATH_CORE_ORACLE` at a built one.

**HOST CHANGE (VM): the static wire address.** It has no gateway and leaves forwarding off.
`/etc/network/interfaces.d/wire`:

```
auto <WIRE_IF>
iface <WIRE_IF> inet static
    address <VM_WIRE>/30
```

Run `sudo ifup <WIRE_IF>`, then `ip route` must show the /30 on `<WIRE_IF>` and nothing else on it.
Leave `sysctl net.ipv4.ip_forward` at 0. *Undo:* `sudo ifdown <WIRE_IF>` and delete the file.

**HOST CHANGE (VM): accept the protocol only from the wire.** Linux accepts a packet for `<VM_WIRE>` on
any interface (the weak host model), so a host on the management LAN that routed to `<VM_WIRE>` could
reach the tool server without crossing `<WIRE_IF>`, and therefore without crossing XDP. The server's own
re-decision still holds in that case, but this rule removes the path:

```sh
sudo nft add table inet gnet
sudo nft add chain inet gnet input '{ type filter hook input priority 0; policy accept; }'
sudo nft add rule inet gnet input iifname != "<WIRE_IF>" udp dport { 47011, 47012 } drop
```

*Undo:* `sudo nft delete table inet gnet`.

## 4. The Mac side

1. Connect the cable from the Mac's Ethernet port, or a USB-C/Thunderbolt Ethernet adapter, straight to
   the i226 port. Use no switch.
2. **HOST CHANGE (Mac): a manual address with no router.** In System Settings, open Network, then the
   adapter's service, then Details, then TCP/IP. Set Configure IPv4 to Manually, the IP address to
   `<MAC_WIRE>` and the subnet mask to `255.255.255.252`, and leave **Router empty**. Under DNS, add
   nothing. *Undo:* set Configure IPv4 back to Using DHCP, or make the service inactive.
3. Check that the Mac's normal routes are untouched. `route -n get default` must still name the Mac's
   usual interface, `route -n get <ENDPOINT host>` must not name the wire's interface, and
   `ping -c 2 <VM_WIRE>` must answer (ICMP is not the protocol, so XDP passes it).
4. Get the repository on the Mac (`pip install -e .` in a venv), then:
   `export PRISMPATH_HARNESS_ENDPOINT=<ENDPOINT>/v1/chat/completions PRISMPATH_HARNESS_MODEL=gemma4`.

## 5. First in-kernel run: the verifier, the JIT and the decisions, with no attach

This step attaches to nothing. It loads the program, which is where the verifier accepts or refuses it,
then runs a frame corpus through `BPF_PROG_TEST_RUN`, and its output must be byte for byte what the
userspace path printed for the same frames:

```sh
.venv/bin/python -m integrations.governed_net.differential --random 20000 --seed 7 --corpus-only --out /tmp/gnet-corpus
sudo prismpath-ebpf/gnet/gn_loader test-run prismpath-ebpf/gnet/gn_xdp.bpf.o \
     /tmp/gnet-corpus/policy/net_rules.ppt /tmp/gnet-corpus/policy/net_rules.actions \
     --server-ip 192.0.2.20 --port 47011 \
     < /tmp/gnet-corpus/frames.bin > /tmp/gnet-corpus/kernel.txt
diff /tmp/gnet-corpus/expected.txt /tmp/gnet-corpus/kernel.txt && echo "kernel agrees on every frame"
```

`gn_loader` exits 4 with the verifier's log if the kernel refuses the program, and 5 if a frame's XDP
return value disagrees with its own event. Record the frame count, the result of `diff` and the kernel
version (`uname -r`) for RESULTS.md.

## 6. First attach: empty tables, fail closed

`ip` attaches the object with fresh, empty maps. With `loaded` at 0, every request to port 47011 is
dropped and everything else passes. That makes this a harmless way to see the program on the real driver:

```sh
sudo ip link set dev <WIRE_IF> xdpdrv obj prismpath-ebpf/gnet/gn_xdp.bpf.o sec xdp
ip -d link show dev <WIRE_IF> | grep -i xdp          # "xdpdrv" and a prog id: native mode
```

Then confirm, in this order:

- **SSH and management are unaffected.** Open a new SSH session to the VM's management address from
  another machine. On `<PVE>`, `ip -br link` and `bridge link` are unchanged, because the program lives
  inside the VM, on a device the host no longer has.
- From the Mac, `ping <VM_WIRE>` answers.
- A request is dropped. With nothing filled in, every request to 47011 is dropped, and the Mac's client
  (step 7) reports no reply. `sudo bpftool prog show name gn_xdp_prog` shows the program, and with
  `sysctl kernel.bpf_stats_enabled=1` its `run_cnt` grows with every frame. Don't rely on `tcpdump` on
  `<WIRE_IF>` here, because a frame native XDP drops never reaches the capture point.

**DETACH (rollback):** `sudo ip link set dev <WIRE_IF> xdp off`, or `sudo prismpath-ebpf/gnet/gn_loader
detach <WIRE_IF>`. `ip -d link show dev <WIRE_IF>` then shows no xdp.

## 7. The live run

Use three terminals on the VM. Only the loader needs root; the logger and the server run as your user.

```sh
# 1. the tool server, on a throwaway world, bound to the wire address only
.venv/bin/python -m integrations.governed_net.server --make-world /tmp/gnet-world \
    --bind <VM_WIRE> --port 47011 --run /tmp/gnet-run/server --keys /tmp/gnet-keys

# 2. the program and its ring buffer, into the receipt logger (status port 47012 on the wire)
sudo prismpath-ebpf/gnet/gn_loader run <WIRE_IF> prismpath-ebpf/gnet/gn_xdp.bpf.o \
     build/net_rules.ppt build/net_rules.actions --server-ip <VM_WIRE> --port 47011 \
  | .venv/bin/python -m integrations.governed_net.receipt_logger --run /tmp/gnet-run/xdp \
     --keys /tmp/gnet-keys --status-bind <VM_WIRE>
```

`gn_loader run` refuses to attach when another XDP program is on the interface, so detach the one from
step 6 first. On the Mac, run one episode:

```sh
python -m integrations.governed_net.client --server <VM_WIRE> \
    --task "Edit .toolchain/VERSION so it says 2.0."
```

To stop, press Ctrl-C in terminal 2. The loader **detaches** and exits, the logger sees its input end
and seals its run. Then press Ctrl-D in terminal 1, and the server seals its run.

If the logger dies first, the loader clears the policy's `loaded` flag, so every request is dropped. It
leaves the program attached, so the port does not fall open to the server, and exits 6. Detach as in
step 6. If the loader itself is killed, the program stays attached with no reader. Allowed requests pass
until its 1 MiB ring buffer fills (about 16,000 events), and those decisions are never receipted. After
that, every allowed request is dropped. The server's own receipts still cover what it ran.

Verify both runs with the repository's verifier, with every receipt replayed through the Lean oracle:

```sh
for run in xdp server; do
  .venv/bin/python formal/diff/core_evidence.py verify /tmp/gnet-run/$run --sample all \
     --pin-authority /tmp/gnet-keys/authority.pub --pin-instance /tmp/gnet-keys/instance.pub
done
cat /tmp/gnet-run/server/findings.json /tmp/gnet-run/xdp/findings.json   # disagreements, if any
```

## 8. Rolling everything back

1. VM: `sudo ip link set dev <WIRE_IF> xdp off`, `sudo nft delete table inet gnet`, and
   `sudo ifdown <WIRE_IF>`.
2. Mac: set the adapter to DHCP or inactive, and unplug the cable.
3. `<PVE>`: `qm shutdown <VMID> && qm set <VMID> --delete hostpci0` (or `qm destroy <VMID>`). Reboot, or
   rebind to `igc`, to give the port back. Revert the IOMMU change of step 1.2 only if you made it for
   this.

## Notes

- The ring buffer event is read in host byte order (`receipt_logger.EVENT` is little endian). That is
  right on x86_64 and aarch64.
- The program reads IPv4 only. An IPv6 datagram to port 47011 is passed, and the server, bound to an
  IPv4 address, never receives it. The nftables rule above does not need to cover it.
- A VLAN tagged frame is passed unread, since the dedicated wire carries no tags. If you ever put a
  switch with VLANs between the two ends, the program must learn the tag first.
