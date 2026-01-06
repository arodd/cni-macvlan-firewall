package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	supportedCniVersion = "1.1.0"
	nftTableName        = "cni-firewall"
	nftInputChainName   = "cni-firewall-input"
)

type envContext struct {
	Command     string
	ContainerID string
	NetNSPath   string
	IfName      string
}

type versionInfo struct {
	CNIVersion        string   `json:"cniVersion"`
	SupportedVersions []string `json:"supportedVersions"`
}

func main() {
	var conf NetConf
	if err := json.NewDecoder(os.Stdin).Decode(&conf); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse CNI config: %v\n", err)
		os.Exit(1)
	}

	cmd := os.Getenv("CNI_COMMAND")
	if cmd == "" {
		fmt.Fprintln(os.Stderr, "CNI_COMMAND not set")
		os.Exit(1)
	}

	if cmd == "VERSION" {
		if err := handleVersion(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to handle VERSION: %v\n", err)
			os.Exit(1)
		}
		return
	}

	env := envContext{
		Command:     cmd,
		ContainerID: os.Getenv("CNI_CONTAINERID"),
		NetNSPath:   os.Getenv("CNI_NETNS"),
		IfName:      os.Getenv("CNI_IFNAME"),
	}

	fmt.Fprintf(os.Stderr, "command=%s containerID=%s netns=%s ifname=%s\n",
		env.Command, env.ContainerID, env.NetNSPath, env.IfName)

	var err error
	switch env.Command {
	case "ADD":
		err = handleAdd(conf, env)
	case "DEL":
		err = handleDel(conf, env)
	default:
		err = fmt.Errorf("unsupported CNI_COMMAND: %s", env.Command)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleVersion() error {
	vi := versionInfo{
		CNIVersion:        supportedCniVersion,
		SupportedVersions: []string{supportedCniVersion},
	}
	return json.NewEncoder(os.Stdout).Encode(&vi)
}

func handleAdd(conf NetConf, env envContext) error {
	if len(conf.RuntimeConfig.PortMappings) == 0 {
		return outputPrevResult(conf)
	}

	if env.NetNSPath == "" {
		return errors.New("CNI_NETNS not set")
	}

	if err := enterNetns(env.NetNSPath); err != nil {
		return fmt.Errorf("failed to enter netns: %w", err)
	}
	defer exitNetns()

	conn := &nftables.Conn{}
	table := &nftables.Table{
		Name:   nftTableName,
		Family: nftables.TableFamilyINet,
	}

	conn.AddTable(table)

	policy := nftables.ChainPolicyDrop
	chain := &nftables.Chain{
		Name:     nftInputChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}

	conn.AddChain(chain)

	if err := addLoopbackRule(conn, table, chain); err != nil {
		return fmt.Errorf("failed to add loopback rule: %w", err)
	}

	if err := addEstablishedRelatedRule(conn, table, chain); err != nil {
		return fmt.Errorf("failed to add established/related rule: %w", err)
	}

	if err := addICMPRules(conn, table, chain); err != nil {
		return fmt.Errorf("failed to add ICMP rules: %w", err)
	}

	if err := addPortMappingRules(conn, table, chain, conf.RuntimeConfig.PortMappings); err != nil {
		return fmt.Errorf("failed to add port mapping rules: %w", err)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %w", err)
	}

	return outputPrevResult(conf)
}

func handleDel(_ NetConf, env envContext) error {
	if env.NetNSPath == "" {
		return nil
	}

	if err := enterNetns(env.NetNSPath); err != nil {
		if isNotExistErr(err) {
			fmt.Fprintf(os.Stderr, "DEL: netns already removed (%s), skipping cleanup\n", env.NetNSPath)
			return nil
		}
		fmt.Fprintf(os.Stderr, "DEL: failed to enter netns %s: %v\n", env.NetNSPath, err)
		return nil
	}
	defer exitNetns()

	conn := &nftables.Conn{}
	table := &nftables.Table{
		Name:   nftTableName,
		Family: nftables.TableFamilyINet,
	}
	chain := &nftables.Chain{
		Name:  nftInputChainName,
		Table: table,
	}

	conn.FlushChain(chain)
	conn.DelChain(chain)
	conn.DelTable(table)

	if err := conn.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "DEL: failed to flush nftables changes: %v\n", err)
	}

	return nil
}

func outputPrevResult(conf NetConf) error {
	version := conf.CniVersion
	if version == "" {
		version = supportedCniVersion
	}

	if conf.PrevResult == nil {
		_, err := fmt.Fprintf(os.Stdout, `{"cniVersion":"%s"}`+"\n", version)
		return err
	}

	conf.PrevResult["cniVersion"] = version
	data, err := json.Marshal(conf.PrevResult)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

// addLoopbackRule installs an accept rule for traffic arriving on the loopback interface.

func addLoopbackRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) error {
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo\x00"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	conn.AddRule(rule)
	return nil
}

// addEstablishedRelatedRule permits reply traffic tracked by conntrack.
func addEstablishedRelatedRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) error {
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	conn.AddRule(rule)
	return nil
}

// addICMPRules permits both IPv4 ICMP and IPv6 ICMP control traffic.
func addICMPRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) error {
	protocols := []struct {
		proto byte
		name  string
	}{
		{proto: 0x01, name: "icmp"},
		{proto: 0x3a, name: "ipv6-icmp"},
	}

	for _, entry := range protocols {
		rule := &nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{entry.proto, 0x00, 0x00, 0x00},
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		conn.AddRule(rule)
	}

	return nil
}

// addPortMappingRules permits each declared runtimeConfig port mapping.
func addPortMappingRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, mappings []PortMapEntry) error {
	for _, pm := range mappings {
		if pm.ContainerPort == 0 {
			continue
		}

		protoNum := protocolNumber(strings.ToLower(pm.Protocol))
		if protoNum == 0x00 {
			continue
		}

		dport := []byte{byte(pm.ContainerPort >> 8), byte(pm.ContainerPort & 0xff)}
		rule := &nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyL4PROTO,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{protoNum, 0x00, 0x00, 0x00},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     dport,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		conn.AddRule(rule)
	}

	return nil
}

// protocolNumber converts protocol strings into L4 protocol numbers understood by nftables.
func protocolNumber(proto string) byte {
	switch proto {
	case "tcp":
		return 0x06
	case "udp":
		return 0x11
	default:
		return 0x00
	}
}

func isNotExistErr(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno == unix.ENOENT || errno == unix.ESRCH
	}

	return false
}
