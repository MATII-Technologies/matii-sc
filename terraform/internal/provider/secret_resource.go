package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

type secretResource struct{ client *matii.Client }

type secretModel struct {
	ID      types.String `tfsdk:"id"`
	App     types.String `tfsdk:"app"`
	Env     types.String `tfsdk:"env"`
	Path    types.String `tfsdk:"path"`
	Key     types.String `tfsdk:"key"`
	Value   types.String `tfsdk:"value"`
	Comment types.String `tfsdk:"comment"`
}

func newSecretResource() resource.Resource { return &secretResource{} }

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "A secret in a server-side encrypted app. The value is stored in Terraform state: protect the state.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"app":     schema.StringAttribute{Required: true, PlanModifiers: replace},
			"env":     schema.StringAttribute{Required: true, PlanModifiers: replace},
			"path":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("/"), PlanModifiers: replace},
			"key":     schema.StringAttribute{Required: true, PlanModifiers: replace, Validators: []validator.String{upperCase{}}, Description: "Upper-case, e.g. DATABASE_URL."},
			"value":   schema.StringAttribute{Required: true, Sensitive: true},
			"comment": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if c, ok := req.ProviderData.(*matii.Client); ok {
		r.client = c
	}
}

func query(m secretModel) matii.Query {
	return matii.Query{AppName: m.App.ValueString(), Env: m.Env.ValueString(), Path: m.Path.ValueString()}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateSecret(ctx, query(m), matii.ManagedSecret{Key: m.Key.ValueString(), Value: m.Value.ValueString(), Comment: m.Comment.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Creating the secret failed", err.Error())
		return
	}
	m.ID = types.StringValue(created.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.client.FindSecret(ctx, query(m), m.Key.ValueString())
	if errors.Is(err, matii.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the secret failed", err.Error())
		return
	}
	m.ID, m.Comment = types.StringValue(s.ID), types.StringValue(s.Comment)
	m.Value = types.StringValue(s.Value)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m, state secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.ID = state.ID
	if err := r.client.UpdateSecret(ctx, query(m), matii.ManagedSecret{ID: m.ID.ValueString(), Value: m.Value.ValueString(), Comment: m.Comment.ValueString()}); err != nil {
		resp.Diagnostics.AddError("Updating the secret failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSecret(ctx, query(m), m.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Deleting the secret failed", err.Error())
	}
}

// ImportState: terraform import matii_secret.x "APP/ENV/PATH/KEY" (PATH may be empty for /).
func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) < 3 {
		resp.Diagnostics.AddError("Invalid import id", "Use APP/ENV/KEY or APP/ENV/folder/…/KEY.")
		return
	}
	app, env, key := parts[0], parts[1], parts[len(parts)-1]
	folder := "/" + strings.Join(parts[2:len(parts)-1], "/")
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("app"), app)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("env"), env)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), folder)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), strings.ToUpper(key))...)
}

var _ resource.ResourceWithImportState = (*secretResource)(nil)
