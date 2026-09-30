// Command terraform-provider-matii is the Terraform provider for the Matii Secret Service.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/matii-org/matii-secret-clients/terraform/internal/provider"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/matii-org/matii",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
