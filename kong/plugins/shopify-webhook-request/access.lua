
local utils = require "kong.tools.utils"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local singletons = require "kong.singletons"
local crypto = require "crypto"

local math_abs = math.abs
local ngx_time = ngx.time
local ngx_gmatch = ngx.re.gmatch
local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64
local ngx_parse_time = ngx.parse_http_time
local ngx_set_header = ngx.req.set_header
local ngx_get_headers = ngx.req.get_headers
local ngx_log = ngx.log
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local ngx_hmac_sha1 = ngx.hmac_sha1
local split = utils.split
local fmt = string.format
local ipairs = ipairs

local DIGEST = "X-Shopify-Hmac-SHA256"
local SIGNATURE_NOT_VALID = "HMAC signature cannot be verified"
local REQUEST_NOT_VALID = "Request headers not valid"
local SIGNATURE_NOT_SAME = "HMAC signature does not match"

local _M = {}

local function retrieve_hmac_fields(request, headers, header_name, conf)
    local hmac_params = {}
    local authorization_header = headers[header_name]
    -- parse the header to retrieve hamc parameters
    if authorization_header then
        hmac_params.algorithm = 'sha256'
        hmac_params.signature = authorization_header
    else
        ngx_log(ngx.ERR, 'Missing authorization header')
        return
    end
    return hmac_params
end

local function create_hash(secret, data)
    return ngx_encode_base64(crypto.hmac.digest("sha256", data, secret, true))
end

local function validate_body(digest_recieved, secret)
    -- client doesnt want body validation
    if not digest_recieved then
      return false
    end
  
    req_read_body()
    local body = req_get_body_data()
    -- request must have body as client sent a digest header
    if not body then
      return false
    end
  
    local body_hmac = create_hash(secret, body)
    return digest_recieved == body_hmac
end
local function validate_params(params, conf)
    -- check username and signature are present
    if not params.signature then
      return nil, "hmac signature missing"
    end
  
    -- check enforced headers are present
    if conf.required_headers and #conf.required_headers >= 1 then
      local enforced_header_set = list_as_set(conf.required_headers)
      for _, header in ipairs(conf.required_headers) do
        if not enforced_header_set[header] then
          return nil, "required header not found"
        end
      end
    end
end

local function do_authentication(conf)
    
  local headers = ngx_get_headers()
  -- If both headers are missing, return 401
  if not headers[DIGEST] then
    return false, {status = 401}
  end

  local hmac_params = retrieve_hmac_fields(ngx.req, headers, DIGEST, conf)

  local ok, err = validate_params(hmac_params, conf)
  if not ok then
    ngx_log(ngx.DEBUG, err)
    return false, {status = 403, message = REQUEST_NOT_VALID}
  end

  if not validate_body(headers[DIGEST], conf.secret) then
    ngx_log(ngx.DEBUG, "digest validation failed")
    return false, { status = 403, message = SIGNATURE_NOT_SAME }
  end
end

function _M.execute(conf)

    if ngx.ctx.authenticated_credential and conf.anonymous ~= "" then
      -- we're already authenticated, and we're configured for using anonymous,
      -- hence we're in a logical OR between auth methods and we're already done.
      return
    end
  
    local ok, err = do_authentication(conf)
    if not ok then
        return responses.send(err.status, err.message)
    end
end
  

return _M