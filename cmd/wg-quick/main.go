package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/uinta-labs/wg-quick-go"
	"go.uber.org/zap"
)

func printHelp() {
	fmt.Print("wg-quick [flags] [ up | down | sync ] [ config_file | interface ]\n\n")
	flag.Usage()
	os.Exit(1)
}

func main() {
	flag.String("iface", "", "interface")
	verbose := flag.Bool("v", false, "verbose")
	protocol := flag.Int("route-protocol", 0, "route protocol to use for our routes")
	metric := flag.Int("route-metric", 0, "route metric to use for our routes")
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		printHelp()
	}

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	iface := flag.Lookup("iface").Value.String()
	logger := zap.NewExample()
	log := logger.With(zap.String("iface", iface))

	cfg := args[1]

	_, err := os.Stat(cfg)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		if iface == "" {
			iface = cfg
			log = logger.With(zap.String("iface", iface))
		}
		cfg = "/etc/wireguard/" + cfg + ".conf"
		_, err = os.Stat(cfg)
		if err != nil {
			log.Error("cannot find config file", zap.Error(err))
			printHelp()
		}
	default:
		logrus.WithError(err).Errorln("error while reading config file")
		printHelp()
	}

	b, err := ioutil.ReadFile(cfg)
	if err != nil {
		logrus.WithError(err).Fatalln("cannot read file")
	}
	c := &wgquick.Config{}
	if err := c.UnmarshalText(b); err != nil {
		logrus.WithError(err).Fatalln("cannot parse config file")
	}

	c.RouteProtocol = *protocol
	c.RouteMetric = *metric

	switch args[0] {
	case "up":
		if err := wgquick.Up(c, iface, log); err != nil {
			logrus.WithError(err).Errorln("cannot up interface")
		}
	case "down":
		if err := wgquick.Down(c, iface, log); err != nil {
			logrus.WithError(err).Errorln("cannot down interface")
		}
	case "sync":
		if err := wgquick.Sync(c, iface, log); err != nil {
			logrus.WithError(err).Errorln("cannot sync interface")
		}
	default:
		printHelp()
	}
}
