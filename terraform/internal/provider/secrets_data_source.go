package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/matii-org/matii-secret-clients/go/matii"
)

type secretsDataSource struct{ client *matii.Client }

type secretsModel struct {
	App    types.String `tfsdk:"app"`
	Env    types.String `tfsdk:"env"`
	Path   types.String `tfsdk:"path"`
	Values types.Map    `tfsdk:"values"`
}

func newSecretsDataSource() datasource.DataSource { return &secretsDataSource{} }

func (d *secretsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (d *secretsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The secrets of one environment (and folder), references resolved. Values you may not reveal are left out.",
		Attributes: map[string]schema.Attribute{
			"app":    schema.StringAttribute{Required: true},
			"env":    schema.StringAttribute{Required: true},
			"path":   schema.StringAttribute{Optional: true, Description: "Folder, e.g. /backend (default: all)."},
			"values": schema.MapAttribute{Computed: true, Sensitive: true, ElementType: types.StringType},
		},
	}
}

func (d *secretsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if c, ok := req.ProviderData.(*matii.Client); ok {
		d.client = c
	}
}

func (d *secretsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m secretsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secrets, err := d.client.Secrets(ctx, matii.Query{AppName: m.App.ValueString(), Env: m.Env.ValueString(), Path: m.Path.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Reading secrets failed", err.Error())
		return
	}
	values, diags := types.MapValueFrom(ctx, types.StringType, matii.Map(secrets))
	resp.Diagnostics.Append(diags...)
	m.Values = values
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
