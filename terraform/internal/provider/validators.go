package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// upperCase: secret keys are stored upper-case, so the configuration must use
// that form (otherwise every plan would show a difference).
type upperCase struct{}

func (upperCase) Description(context.Context) string         { return "must be upper-case" }
func (upperCase) MarkdownDescription(context.Context) string { return "must be upper-case" }

func (upperCase) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	v := req.ConfigValue.ValueString()
	if v == "" || v != strings.ToUpper(v) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid secret key",
			"Secret keys are stored upper-case; write \""+strings.ToUpper(v)+"\".")
	}
}
