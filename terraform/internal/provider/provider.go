// Package provider implements the Matii Secret Service Terraform provider.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

type matiiProvider struct{ version string }

type providerModel struct {
	Host             types.String `tfsdk:"host"`
	Token            types.String `tfsdk:"token"`
	ServiceAccountID types.String `tfsdk:"service_account_id"`
	OIDCTokenFile    types.String `tfsdk:"oidc_token_file"`
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &matiiProvider{version: version} }
}

func (p *matiiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "matii"
	resp.Version = p.version
}

func (p *matiiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Matii Secret Service. Configure with a service account token, or workload identity (an OIDC token file).",
		Attributes: map[string]schema.Attribute{
			"host":               schema.StringAttribute{Optional: true, Description: "Console URL (or MATII_HOST)."},
			"token":              schema.StringAttribute{Optional: true, Sensitive: true, Description: "Service account token (or MATII_TOKEN)."},
			"service_account_id": schema.StringAttribute{Optional: true, Description: "Service account for workload identity (or MATII_SERVICE_ACCOUNT_ID)."},
			"oidc_token_file":    schema.StringAttribute{Optional: true, Description: "OIDC token file for workload identity (or MATII_OIDC_TOKEN_FILE)."},
		},
	}
}

func pick(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func (p *matiiProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	host := pick(cfg.Host, "MATII_HOST")
	if host == "" {
		resp.Diagnostics.AddError("Missing host", "Set host in the provider block or MATII_HOST.")
		return
	}
	var tokens matii.TokenSource
	var err error
	if token := pick(cfg.Token, "MATII_TOKEN"); token != "" {
		tokens, err = matii.StaticToken(token)
	} else if sa := pick(cfg.ServiceAccountID, "MATII_SERVICE_ACCOUNT_ID"); sa != "" {
		file := pick(cfg.OIDCTokenFile, "MATII_OIDC_TOKEN_FILE")
		if file == "" {
			resp.Diagnostics.AddError("Missing OIDC token file", "Workload identity needs oidc_token_file.")
			return
		}
		tokens = &matii.OIDCTokenSource{APIBase: host + "/service", ServiceAccountID: sa, JWT: matii.FileJWT(file)}
	} else {
		resp.Diagnostics.AddError("Missing credentials", "Set token (or MATII_TOKEN), or service_account_id with oidc_token_file.")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Invalid token", err.Error())
		return
	}
	client, err := matii.New(matii.Config{Host: host, Tokens: tokens})
	if err != nil {
		resp.Diagnostics.AddError("Invalid configuration", err.Error())
		return
	}
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *matiiProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newSecretsDataSource}
}

func (p *matiiProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource}
}
