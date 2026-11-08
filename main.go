package main

import (
	"github.com/PabloMz85/watchtower/cmd"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.InfoLevel)
}

func main() {
	cmd.Execute()
}
