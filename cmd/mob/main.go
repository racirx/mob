package main

import (
	"flag"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/racirx/mob/config"
	"github.com/racirx/mob/server"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	path := flag.String("p", "conf", "path for config file")
	file := flag.String("f", "config.yml", "filename for config file")
	flag.Parse()

	b, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", *path, *file))
	if err != nil {
		log.Fatalf("server: error loading config: %v\n", err)
	}

	// Expand the config with any env vars available
	expConf := os.ExpandEnv(string(b))

	conf := new(config.Config)
	err = yaml.Unmarshal([]byte(expConf), conf)
	if err != nil {
		log.Fatalf("server: error unmarshaling configg: %v\n", err)
	}

	app := new(server.Application)
	app.Initialize(conf)
	app.Run()
}
