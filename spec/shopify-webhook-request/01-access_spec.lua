local helpers = require "spec.helpers"
local cjson = require "cjson"
local crypto = require "crypto"
local ngx_encode_base64 = ngx.encode_base64
local DIGEST = "X-Shopify-Hmac-SHA256"

local secret= "abcdefghijkl"
local function create_hash(secret, data)
  return ngx_encode_base64(crypto.hmac.digest("sha256", data, secret, true))
end

describe("Demo-Plugin: myplugin (access)", function()
  local client

  setup(function()
    local api1 = assert(helpers.dao.apis:insert { 
        name = "api-1", 
        hosts = { "test1.com" }, 
        upstream_url = "http://mockbin.com",
    })

    assert(helpers.dao.plugins:insert {
      api_id = api1.id,
      name = "shopify-webhook-request",
      config = {
        secret = secret
      }
    })

    -- start kong, while setting the config item `custom_plugins` to make sure our
    -- plugin gets loaded
    assert(helpers.start_kong {custom_plugins = "shopify-webhook-request"})
  end)

  teardown(function()
    helpers.stop_kong()
  end)

  before_each(function()
    client = helpers.proxy_client()
  end)

  after_each(function()
    if client then client:close() end
  end)

  describe("basic verfication", function()
    it("gets a 'hello-world' header", function()
      local postBody = '{"a":"apple","b":"ball"}'
      local hmac_hash = create_hash(secret, postBody)
      local r = assert(client:send {
        method = "POST",
        path = "/request",  -- makes mockbin return the entire request
        headers = {
          host = "test1.com",
          ["X-Shopify-Hmac-SHA256"] = hmac_hash,
        }
      })
      -- validate that the request succeeded, response status 200
      local body = assert.res_status(200, r)
      body = cjson.decode(body)
    end)
  end)

end)