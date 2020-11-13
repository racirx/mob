package main

import (
	"flag"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/racirx/mob/config"
	"github.com/racirx/mob/server"
	"io/ioutil"
	"log"
)

func main() {
	path := flag.String("p", "conf", "path for config file")
	file := flag.String("f", "config.yml", "filename for config file")
	flag.Parse()

	b, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", *path, *file))
	if err != nil {
		log.Fatalf("server: error loading config: %v\n", err)
	}

	conf := new(config.Config)
	err = yaml.Unmarshal(b, conf)
	if err != nil {
		log.Fatalf("server: error unmarshaling configg: %v\n", err)
	}

	app := new(server.Application)
	app.Initialize(conf)
	app.Run()
}
