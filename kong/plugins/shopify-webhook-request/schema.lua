return {
  no_consumer = true, -- this plugin is available on APIs as well as on Consumers,
  fields = {
    -- Describe your plugin's configuration's schema here.
    domain = {type = "string"},
    secret = {type = "string"},
    required_headers = {type="array"}
  },
  self_check = function(schema, plugin_t, dao, is_updating)
    -- perform any custom verification
    if not plugin_t.doamin then
      return false, Errors.schema("domain is required")
    end
    if not plugin_t.secret then
      return false, Errors.schema("secret is required")
    end
    return true
  end
}
