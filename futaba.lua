local cjson = require("cjson.safe")
local cjson_encode = cjson.encode
local ngx = ngx
local ngx_exit = ngx.exit
local ngx_null = ngx.null
local ngx_print = ngx.print
local ngx_var = ngx.var
local redis = require("resty.redis")

local _M = {}

local function response_json(code, msg, data)
	local res_t = {}
	res_t["code"] = code
	res_t["msg"] = msg
	res_t["data"] = data
	local res_json = cjson_encode(res_t)
	ngx.status = 200
	ngx.header["Content-Length"] = #res_json
	ngx_print(res_json)
end

function _M.access_do(auth, port)
	if ngx_var.uri ~= "/futaba" and ngx_var.uri ~= "/futaba.json" then
		ngx.status = 400
		return ngx_exit(200)
	end

	local arg_query = ngx_var.arg_query
	if not arg_query then
		return response_json(400, "request with no arg query")
	end

	local red = redis:new()
	local ok, err = red:connect("127.0.0.1", port)
	if not ok then
		return response_json(502, "failed to connect: " .. err)
	end

	local res, err = red:auth(auth)
    if not res then
    	return response_json(502, "failed to authenticate: " .. err)
    end

	local res, err = red:smembers(arg_query)
	if not res then
		return response_json(404, "failed to query " .. arg_query .. ": " .. err)
	end

	if res == ngx_null then
		return response_json(404, "failed to query " .. arg_query .. ": not found")
	end

	if type(res) ~= "table" then
		return response_json(404, "failed to query " .. arg_query .. ": res type is not table")
	end

	if #res == 0 then
		return response_json(404, "failed to query " .. arg_query .. ": not found")
	end

	return response_json(200, nil, res)
end

return _M