package wgquick

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Up sets and configures the wg interface. Mostly equivalent to `wg-quick up iface`
func Up(cfg *Config, iface string, logger *zap.Logger) error {
	log := logger.With(zap.String("iface", iface))
	_, err := netlink.LinkByName(iface)
	if err == nil {
		return os.ErrExist
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return err
	}

	for _, dns := range cfg.DNS {
		if err := execSh("resolvconf -a tun.%i -m 0 -x", iface, log, fmt.Sprintf("nameserver %s\n", dns)); err != nil {
			return err
		}
	}

	if cfg.PreUp != "" {
		if err := execSh(cfg.PreUp, iface, log); err != nil {
			return err
		}
		log.Info("applied pre-up command")
	}
	if err := Sync(cfg, iface, logger); err != nil {
		return err
	}

	if cfg.PostUp != "" {
		if err := execSh(cfg.PostUp, iface, log); err != nil {
			return err
		}
		log.Info("applied post-up command")
	}
	return nil
}

// Down destroys the wg interface. Mostly equivalent to `wg-quick down iface`
func Down(cfg *Config, iface string, logger *zap.Logger) error {
	log := logger.With(zap.String("iface", iface))
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if len(cfg.DNS) > 1 {
		if err := execSh("resolvconf -d tun.%s", iface, log); err != nil {
			return err
		}
	}

	if cfg.PreDown != "" {
		if err := execSh(cfg.PreDown, iface, log); err != nil {
			return err
		}
		log.Info("applied pre-down command")
	}

	if err := netlink.LinkDel(link); err != nil {
		return err
	}
	log.Info("link deleted")
	if cfg.PostDown != "" {
		if err := execSh(cfg.PostDown, iface, log); err != nil {
			return err
		}
		log.Info("applied post-down command")
	}
	return nil
}

func execSh(command string, iface string, log *zap.Logger, stdin ...string) error {
	cmd := exec.Command("sh", "-ce", strings.ReplaceAll(command, "%i", iface))
	if len(stdin) > 0 {
		log = log.With(zap.String("stdin", strings.Join(stdin, "")))
		b := &bytes.Buffer{}
		for _, ln := range stdin {
			if _, err := fmt.Fprint(b, ln); err != nil {
				return err
			}
		}
		cmd.Stdin = b
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("failed to execute",
			zap.Strings("cmd", cmd.Args),
			zap.ByteString("output", out),
			zap.Error(err),
		)
		return err
	}
	log.Info("executed",
		zap.Strings("cmd", cmd.Args),
		zap.ByteString("output", out),
	)
	return nil
}

// Sync the config to the current setup for given interface
// It perform 4 operations:
// * SyncLink --> makes sure link is up and type wireguard
// * SyncWireguardDevice --> configures allowedIP & other wireguard specific settings
// * SyncAddress --> synces linux addresses bounded to this interface
// * SyncRoutes --> synces all allowedIP routes to route to this interface
func Sync(cfg *Config, iface string, logger *zap.Logger) error {
	log := logger.With(zap.String("iface", iface))

	link, err := SyncLink(cfg, iface, log)
	if err != nil {
		log.Error("cannot sync wireguard link", zap.Error(err))
		return err
	}
	log.Info("synced link")

	if err := SyncWireguardDevice(cfg, link, log); err != nil {
		log.Error("cannot sync wireguard link", zap.Error(err))
		return err
	}
	log.Info("synced link")

	if err := SyncAddress(cfg, link, log); err != nil {
		log.Error("cannot sync addresses", zap.Error(err))
		return err
	}
	log.Info("synced addresss")

	var managedRoutes []net.IPNet
	for _, peer := range cfg.Peers {
		for _, rt := range peer.AllowedIPs {
			managedRoutes = append(managedRoutes, rt)
		}
	}
	if err := SyncRoutes(cfg, link, managedRoutes, log); err != nil {
		log.Error("cannot sync routes", zap.Error(err))
		return err
	}
	log.Info("synced routed")
	log.Info("Successfully synced device")
	return nil

}

// SyncWireguardDevice synces wireguard vpn setting on the given link. It does not set routes/addresses beyond wg internal crypto-key routing, only handles wireguard specific settings
func SyncWireguardDevice(cfg *Config, link netlink.Link, log *zap.Logger) error {
	cl, err := wgctrl.New()
	if err != nil {
		log.Error("cannot setup wireguard device", zap.Error(err))
		return err
	}
	if err := cl.ConfigureDevice(link.Attrs().Name, cfg.Config); err != nil {
		log.Error("cannot configure device", zap.Error(err))
		return err
	}
	return nil
}

// SyncLink synces link state with the config. It does not sync Wireguard settings, just makes sure the device is up and type wireguard
func SyncLink(cfg *Config, iface string, log *zap.Logger) (netlink.Link, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			log.Error("cannot read link", zap.Error(err))
			return nil, err
		}
		log.Info("link not found, creating")
		wgLink := &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{
				Name: iface,
				MTU:  cfg.MTU,
			},
			LinkType: "wireguard",
		}
		if err := netlink.LinkAdd(wgLink); err != nil {
			log.Error("cannot create link", zap.Error(err))
			return nil, err
		}

		link, err = netlink.LinkByName(iface)
		if err != nil {
			log.Error("cannot read link", zap.Error(err))
			return nil, err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		log.Error("cannot set link up", zap.Error(err))
		return nil, err
	}
	log.Info("set device up")
	return link, nil
}

// SyncAddress adds/deletes all lind assigned IPV4 addressed as specified in the config
func SyncAddress(cfg *Config, link netlink.Link, log *zap.Logger) error {
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		log.Error("cannot read link address", zap.Error(err))
		return err
	}

	// nil addr means I've used it
	presentAddresses := make(map[string]netlink.Addr, 0)
	for _, addr := range addrs {
		log.With(
			zap.String("addr", fmt.Sprint(addr.IPNet)),
			zap.String("label", addr.Label),
		).Debug("found existing address", zap.String("address", addr.String()))
		presentAddresses[addr.IPNet.String()] = addr
	}

	for _, addr := range cfg.Address {
		log := log.With(zap.String("addr", addr.String()))
		_, present := presentAddresses[addr.String()]
		presentAddresses[addr.String()] = netlink.Addr{} // mark as present
		if present {
			log.Info("address present")
			continue
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &addr,
			Label: cfg.AddressLabel,
		}); err != nil {
			if err != syscall.EEXIST {
				log.Error("cannot add addr", zap.Error(err))
				return err
			}
		}
		log.Info("address added")
	}

	for _, addr := range presentAddresses {
		if addr.IPNet == nil {
			continue
		}
		log.With(
			zap.String("addr", fmt.Sprint(addr.IPNet)),
			zap.String("label", addr.Label),
		)
		if err := netlink.AddrDel(link, &addr); err != nil {
			log.Error("cannot delete addr", zap.Error(err))
			return err
		}
		log.Info("addr deleted")
	}
	return nil
}

func fillRouteDefaults(rt *netlink.Route) {
	// fill defaults
	if rt.Table == 0 {
		rt.Table = unix.RT_CLASS_MAIN
	}

	if rt.Protocol == 0 {
		rt.Protocol = unix.RTPROT_BOOT
	}

	if rt.Type == 0 {
		rt.Type = unix.RTN_UNICAST
	}
}

// SyncRoutes adds/deletes all route assigned IPV4 addressed as specified in the config
func SyncRoutes(cfg *Config, link netlink.Link, managedRoutes []net.IPNet, logger *zap.Logger) error {
	var wantedRoutes = make(map[string][]netlink.Route, len(managedRoutes))
	presentRoutes, err := netlink.RouteList(link, syscall.AF_INET)
	if err != nil {
		logger.Error("cannot read existing routes", zap.Error(err))
		return err
	}
	for _, rt := range managedRoutes {
		rt := rt // make copy
		logger.With(zap.String("dst", rt.String())).Debug("managing route")

		nrt := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &rt,
			Table:     cfg.Table,
			Protocol:  cfg.RouteProtocol,
			Priority:  cfg.RouteMetric}
		fillRouteDefaults(&nrt)
		wantedRoutes[rt.String()] = append(wantedRoutes[rt.String()], nrt)
	}

	for _, rtLst := range wantedRoutes {
		for _, rt := range rtLst {
			rt := rt // make copy
			log := logger.With(
				zap.String("route", rt.Dst.String()),
				zap.Int("protocol", rt.Protocol),
				zap.Int("table", rt.Table),
				zap.Int("type", rt.Type),
				zap.Int("metric", rt.Priority),
			)
			if err := netlink.RouteReplace(&rt); err != nil {
				log.Error("cannot add/replace route", zap.Error(err))
				return err
			}
			log.Info("route added/replaced")
		}
	}

	checkWanted := func(rt netlink.Route) bool {
		for _, candidateRt := range wantedRoutes[rt.Dst.String()] {
			if rt.Equal(candidateRt) {
				return true
			}
		}
		return false
	}

	for _, rt := range presentRoutes {
		log := logger.With(
			zap.String("route", rt.Dst.String()),
			zap.Int("protocol", rt.Protocol),
			zap.Int("table", rt.Table),
			zap.Int("type", rt.Type),
			zap.Int("metric", rt.Priority),
		)
		if !(rt.Table == cfg.Table || (cfg.Table == 0 && rt.Table == unix.RT_CLASS_MAIN)) {
			log.Debug("wrong table for route, skipping")
			continue
		}

		if !(rt.Protocol == cfg.RouteProtocol) {
			log.Info("skipping route deletion, not owned by this daemon")
			continue
		}

		if checkWanted(rt) {
			log.Debug("route wanted, skipping deleting")
			continue
		}

		if err := netlink.RouteDel(&rt); err != nil {
			log.Error("cannot delete route", zap.Error(err))
			return err
		}
		log.Info("route deleted")
	}

	return nil
}
