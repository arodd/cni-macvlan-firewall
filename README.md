# macvlan-firewall CNI Plugin

macvlan-firewall is a Container Network Interface (CNI) plugin that installs an nftables allowlist directly inside each container network namespace. This takes the concepts of the portmapping/firewall plugins that work well with the bridge CNI plugin and allows them to work well in macvlan or ipvlan environments where the firewall enforcement needs to happen in the network namespace directly.  It expects to be the last element in an L2-oriented CNI configuration chain (macvlan/ipvlan/tuning, etc.), inspects `runtimeConfig.portMappings`, and programs a `DROP`-by-default input chain that only accepts the container ports and protocols you specify. When no port mappings exist it cleanly returns `prevResult` so you can keep a single conflist for mixed workloads.

## When to Use This Plugin

- You attach containers or Nomad allocations to routable Layer-2 networks via macvlan/ipvlan and need per-container firewalling instead of host-level iptables rules.
- You want to keep the standard CNI contract: earlier plugins create interfaces/IPAM, this plugin only enforces policy and passes the prior result through unchanged.
- You need predictable dual-stack behavior (loopback, established/related, ICMP/ICMPv6 rules are pre-installed) before tasks start listening on sockets.

## Configuration Inputs

### Required CNI JSON Fields

```json
{
  "cniVersion": "1.1.0",
  "name": "macvlan-firewall",
  "type": "cni-macvlan-firewall",
  "capabilities": { "portMappings": true }
  }
}
```

Key points:
- `capabilities.portMappings` **must** be set to `true` in the conflist so the runtime forwards port metadata.

## Baseline Accept Rules

Whenever at least one port mapping is present, the plugin installs a dedicated `table inet cni-firewall` with a single `cni-firewall-input` chain that defaults to `policy drop`. Before any workload-specific ports are opened we always add the same guardrails so you do not have to repeat them in job specs:
- `iifname "lo" accept` keeps loopback diagnostics and health checks working even when every other packet is filtered.
- `ct state established,related accept` lets reply traffic flow without needing to re-authorize every ephemeral port.
- `meta l4proto icmp` and `meta l4proto ipv6-icmp` allow control-plane pings, MTU discovery, and IPv6 neighbor discovery so connectivity remains debuggable.

These baseline rules are present alongside your per-port entries and explain why even simple `ping`/`curl localhost` checks keep succeeding after the firewall is in place.

## Sample CNI Chains

### Example 1 – Dual-stack macvlan with DHCP and IPv6 tuning

```json
{
  "cniVersion": "1.1.0",
  "name": "macvlan-firewall",
  "plugins": [
    { "type": "loopback" },
    {
      "type": "macvlan",
      "master": "enp2s0",
      "mode": "bridge",
      "ipam": { "type": "dhcp" }
    },
    {
      "type": "tuning",
      "sysctl": {
        "net.ipv6.conf.all.accept_ra": "1",
        "net.ipv6.conf.default.accept_ra": "1",
        "net.ipv6.conf.eth0.accept_ra": "1"
      }
    },
    {
      "type": "cni-macvlan-firewall",
      "capabilities": { "portMappings": true }
    }
  ]
}
```

Place macvlan-firewall last so it can see the finished namespace and program nftables after every other plugin (loopback/macvlan/tuning) has succeeded.

### Example 2 – ipvlan L3 with static addressing and tight defaults

```json
{
  "cniVersion": "1.1.0",
  "name": "ipvlan-l3-firewall",
  "plugins": [
    { "type": "loopback" },
    {
      "type": "ipvlan",
      "master": "bond0",
      "mode": "l3",
      "mtu": 9000,
      "ipam": {
        "type": "static",
        "addresses": [
          { "address": "10.20.30.10/24", "gateway": "10.20.30.1" },
          { "address": "fd00:30::10/64", "gateway": "fd00:30::1" }
        ]
      }
    },
    {
      "type": "bandwidth",
      "capabilities": { "bandwidth": true },
      "ingressRate": 100000000
    },
    {
      "type": "cni-macvlan-firewall",
      "capabilities": { "portMappings": true }
    }
  ]
}
```

This chain demonstrates ipvlan L3, static IPs, optional QoS.

When this conflist is referenced by Multus as a secondary network, CRI runtimes such as containerd can send `runtimeConfig.portMappings` describing each exposed service. The firewall plugin adds port rules after the macvlan interface and static routes are in place.

## Nomad Job Example

```hcl
job "job" {
  datacenters = ["dc1"]
  node_pool   = "default"

  group "group" {
    network {
      mode = "cni/macvlan-firewall"
      port "dns" { static = 53 }
      port "http" { static = 8080 }
      port "rpc" { static = 9000 }

      cni {
        args = {
          "NOMAD_JOB_NAME" : "${NOMAD_JOB_NAME}",
          "MAC": "8e:d7:94:cc:ab:cd"
        }
      }
    }

    task "task" {
      driver = "docker"
      config {
        image = "container-image:version"
        ports = ["dns", "http", "rpc"]
      }
    }
  }
}
```

If there are other ports listening within the container not defined in the network block, they will not be opened and traffic will not be allowed from outside the allocation.

## Example nftables Output (Example job)

After the Nomad job above provisions an allocation, you can confirm the firewall state straight from the host by entering the task’s network namespace and listing the table:

```bash
sudo nsenter -t <task-pid> -n nft list table inet cni-firewall
```

For the example job (three static ports), the output will look similar to:

```nft
table inet cni-firewall {
	chain cni-firewall-input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established,related accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		meta l4proto tcp th dport 53 accept
		meta l4proto udp th dport 53 accept
		meta l4proto tcp th dport 8080 accept
		meta l4proto udp th dport 8080 accept
		meta l4proto tcp th dport 9000 accept
		meta l4proto udp th dport 9000 accept
	}
}
```

The first four rules are the built-in loopback/conntrack/ICMP guardrails described earlier. The remaining rules mirror the resolved `runtimeConfig.portMappings` entries so you can visually verify that every declared port/protocol pair is present.
Nomad sends portMappings for both TCP and UDP for any port defined within the allocation and rules are created that will match both IPv4 and IPv6 traffic.

## Build & Test

```bash
cd project
go test ./...
go vet ./...
```

`go test` ensures the module builds and runs protocol override unit tests, while `go vet` performs static analysis for obvious issues.
