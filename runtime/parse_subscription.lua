#!/usr/bin/lua

local input_path = assert(arg[1], "subscription path is required")
local output_dir = assert(arg[2], "output directory is required")
local metadata_path = assert(arg[3], "metadata path is required")
local maximum = tonumber(arg[4] or "256") or 256
local stats_path = arg[5]

if maximum < 1 then maximum = 1 end
if maximum > 512 then maximum = 512 end

local function url_decode(text)
    text = text or ""
    text = text:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    return text:gsub("+", " ")
end

local function safe_text(text, maximum_length)
    if not text or #text == 0 or #text > maximum_length then return nil end
    if text:find("[%z\001-\031\127]") then return nil end
    return text
end

local function parse_query(text)
    local values = {}
    for item in (text or ""):gmatch("[^&]+") do
        local key, value = item:match("^([^=]+)=?(.*)$")
        if key then values[url_decode(key):lower()] = url_decode(value) end
    end
    return values
end

local function stable_hash(text)
    local value = 5381
    for index = 1, #text do
        value = (value * 33 + text:byte(index)) % 2147483647
    end
    return string.format("%08x", value)
end

local function parse_vless(line)
    local body = line:match("^vless://(.+)$")
    if not body then return nil end
    local without_fragment, fragment = body:match("^([^#]*)#?(.*)$")
    local authority, query_text = without_fragment:match("^([^?]+)%??(.*)$")
    local uuid, endpoint = authority:match("^([^@]+)@(.+)$")
    if not uuid or not endpoint then return nil end
    uuid = uuid:lower()
    if not uuid:match("^[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]$") then
        return nil
    end
    local server, port_text = endpoint:match("^([^:]+):(%d+)/?$")
    if not server or not server:match("^[%w%.%-%_]+$") or #server > 255 then return nil end
    local port = tonumber(port_text)
    if not port or port < 1 or port > 65535 then return nil end

    local query = parse_query(query_text)
    local transport = (query.type or "tcp"):lower()
    local security = (query.security or "none"):lower()
    local flow = (query.flow or ""):lower()
    local encryption = (query.encryption or "none"):lower()
    if transport ~= "tcp" and transport ~= "ws" and transport ~= "grpc" then return nil end
    if security == "false" or security == "" then security = "none" end
    if security ~= "none" and security ~= "tls" and security ~= "reality" then return nil end
    if security == "reality" and transport ~= "tcp" and transport ~= "grpc" then return nil end
    if flow ~= "" and flow ~= "none" and flow ~= "xtls-rprx-vision" then return nil end
    if flow == "xtls-rprx-vision" and (transport ~= "tcp" or (security ~= "tls" and security ~= "reality")) then return nil end
    if encryption ~= "" and encryption ~= "none" then return nil end

    local sni = query.sni or query.servername or server
    local ws_host = query.host or server
    local ws_path = query.path or "/"
    local grpc_service = query.servicename or "GunService"
    local grpc_authority = query.authority or sni
    if not safe_text(sni, 255) or not safe_text(ws_host, 255) or not safe_text(ws_path, 1023) or
       not safe_text(grpc_service, 255) or not safe_text(grpc_authority, 255) then return nil end
    if transport == "ws" and ws_path:sub(1, 1) ~= "/" then return nil end
    if transport == "grpc" and (not grpc_service:match("^[%w%.%-%_]+$") or (security ~= "tls" and security ~= "reality")) then return nil end
    local reality_public_key = query.pbk or query.publickey or ""
    local reality_short_id = query.sid or query.shortid or ""
    local source = query.n300source == "crunch" and "crunch" or "repository"
    if security == "reality" then
        if not reality_public_key:match("^[%w%-%_]+$") or #reality_public_key < 40 or #reality_public_key > 44 then return nil end
        if #reality_short_id > 16 or (#reality_short_id % 2) ~= 0 or reality_short_id:find("[^0-9a-fA-F]") then return nil end
        reality_short_id = reality_short_id:lower()
    end
    local label = safe_text(url_decode(fragment), 512) or (server .. ":" .. port)
    label = label:gsub("[\t\r\n]", " ")
    local key = table.concat({source, server, port, uuid, transport, security, flow, sni, ws_host, ws_path,
                              grpc_service, grpc_authority,
                              reality_public_key, reality_short_id}, "|")
    return {
        key = key,
        id = "vless-" .. stable_hash(key),
        label = label,
        source = source,
        server = server,
        port = port,
        uuid = uuid,
        transport = transport,
        flow = flow,
        tls = security == "tls",
        security = security,
        reality_public_key = reality_public_key,
        reality_short_id = reality_short_id,
        sni = sni,
        ws_host = ws_host,
        ws_path = ws_path,
        grpc_service = grpc_service,
        grpc_authority = grpc_authority,
    }
end

local input = assert(io.open(input_path, "rb"))
local metadata = assert(io.open(metadata_path, "wb"))
local seen = {}
local count = 0
local stats = {
    total_vless = 0,
    compatible_lines = 0,
    unique_compatible = 0,
    reality = 0,
    vision = 0,
    grpc = 0,
    xhttp = 0,
}

for line in input:lines() do
    line = line:gsub("\r$", "")
    if line:match("^vless://") then
        stats.total_vless = stats.total_vless + 1
        local body = line:match("^vless://(.+)$") or ""
        local without_fragment = body:match("^([^#]*)") or ""
        local query_text = without_fragment:match("^[^?]+%??(.*)$") or ""
        local query = parse_query(query_text)
        local transport = (query.type or "tcp"):lower()
        local security = (query.security or "none"):lower()
        local flow = (query.flow or ""):lower()
        if security == "reality" then stats.reality = stats.reality + 1 end
        if flow == "xtls-rprx-vision" then stats.vision = stats.vision + 1 end
        if transport == "grpc" then stats.grpc = stats.grpc + 1 end
        if transport == "xhttp" or transport == "splithttp" then stats.xhttp = stats.xhttp + 1 end
    end
    local node = parse_vless(line)
    if node and not seen[node.key] then
        seen[node.key] = true
        stats.compatible_lines = stats.compatible_lines + 1
        stats.unique_compatible = stats.unique_compatible + 1
        if count < maximum then
            count = count + 1
            local config_path = output_dir .. "/" .. node.id .. ".conf"
            local config = assert(io.open(config_path, "wb"))
            config:write("protocol=vless\n")
            config:write("server=", node.server, "\n")
            config:write("port=", tostring(node.port), "\n")
            config:write("uuid=", node.uuid, "\n")
            config:write("transport=", node.transport, "\n")
            config:write("security=", node.security, "\n")
            config:write("flow=", node.flow ~= "" and node.flow or "none", "\n")
            config:write("tls=", (node.tls or node.security == "reality") and "true" or "false", "\n")
            config:write("insecure=false\n")
            if node.tls or node.security == "reality" then config:write("sni=", node.sni, "\n") end
            if node.security == "reality" then
                config:write("reality_public_key=", node.reality_public_key, "\n")
                config:write("reality_short_id=", node.reality_short_id, "\n")
            end
            if node.transport == "ws" then
                config:write("ws_host=", node.ws_host, "\n")
                config:write("ws_path=", node.ws_path, "\n")
            end
            if node.transport == "grpc" then
                config:write("grpc_service=", node.grpc_service, "\n")
                config:write("grpc_authority=", node.grpc_authority, "\n")
            end
            config:write("ca_file=/mnt/usb/n300vpn/certs/cacert.pem\n")
            config:write("socks_listen=127.0.0.1\n")
            config:write("socks_port=10808\n")
            config:write("redirect_listen=0.0.0.0\n")
            config:write("redirect_port=12345\n")
            -- Reality handshakes are expensive on the single-core RTL8197D.
            -- Four concurrent relays keep the router responsive; browsers retry
            -- excess connections instead of pushing the device into an OOM/reset.
            config:write("max_clients=4\n")
            config:write("connect_timeout=8\n")
            config:write("idle_timeout=300\n")
            config:close()
            local transport_label = node.transport
            if node.flow == "xtls-rprx-vision" then transport_label = transport_label .. "+vision" end
            metadata:write(table.concat({node.id, node.label, "vless", node.server, tostring(node.port), transport_label, node.security, node.source}, "\t"), "\n")
        end
    elseif node then
        stats.compatible_lines = stats.compatible_lines + 1
    end
end

input:close()
metadata:close()
if stats_path then
    local stats_file = assert(io.open(stats_path, "wb"))
    for _, key in ipairs({"total_vless", "compatible_lines", "unique_compatible", "reality", "vision", "grpc", "xhttp"}) do
        stats_file:write(key, "=", tostring(stats[key]), "\n")
    end
    stats_file:write("probe_candidates=", tostring(count), "\n")
    stats_file:close()
end
io.stdout:write("parsed_nodes=", tostring(count), "\n")
if count == 0 then os.exit(2) end
