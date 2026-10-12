#!/usr/bin/env lua

local socket = require("socket")

math.randomseed(os.time())

local HEADER = [[
  ██████▒█████ ▄████▄ ██ ▄█▓████▄▄▄████  ▓█████▄ ██▓▄████▄▓█████
▒██    ▒██▒  █▒██▀ ▀█ ██▄█▒▓█   ▓  ██▒   ▒██▀ ██▓██▒██▀ ▀█▓█   ▀
░ ▓██▄ ▒██░  █▒▓█    ▓███▄░▒███ ▒ ▓██░   ░██   █▒██▒▓█    ▒███
  ▒   █▒██   █▒▓▓▄ ▄█▓██ █▄▒▓█  ░ ▓██▓   ░▓█▄   ░██▒▓▓▄ ▄█▒▓█  ▄
▒██████░ ████▓▒ ▓███▀▒██▒ █░▒████▒▒██▒   ░▒████▓░██▒ ▓███▀░▒████▒
▒ ▒▓▒ ▒░ ▒░▒░▒░ ░▒ ▒ ▒ ▒▒ ▓░░ ▒░ ░▒ ░░    ▒▒▓  ▒░▓ ░ ░▒ ▒ ░░ ▒░ ░
░ ░▒  ░  ░ ▒ ▒░ ░  ▒ ░ ░▒ ▒░░ ░  ░  ░     ░ ▒  ▒ ▒ ░ ░  ▒  ░ ░  ░
░  ░  ░░ ░ ░ ▒░    ░ ░░ ░   ░  ░        ░ ░  ░ ▒ ░      ░  ░
     ░    ░ ░░    ░  ░     ░  ░            ░    ░      ░  ░
                ░                     ░        ░
]]

local TITLE = "SOCKETDICE"

local SERVER_INTROS = {
	"for pitiful roles",
	"for critical fails",
	"for the murder hobos to ride again",
	"for the adventure toddlers",
	"for the Bard to TPK...again,",
	"for your epic nat 20's! Nah just kidding, it's a 1 again",
	"to rig the DC for all charisma builds",
	"for them to talk themselves outta this one",
	"the party to just opt for violence, again",
	"for really cautious and careful decisions",
	"for these amateurs to just meta it",
	"to see if they commit warcrimes",
}

local function server_intro()
	return SERVER_INTROS[math.random(1, #SERVER_INTROS)]
end

local NAMES = {
	"SPOOKY SKELETON",
	"BLOODY BARD",
	"WICKED WIZARD",
	"SKATEBOARDING SORCERER",
	"PROBABLE MIMIC",
	"TAVERN NPC No.3",
	"BLOODY BARBARIAN",
	"THE GREAT GOBO",
	"WIGGLY WARRIOR",
}

-- Shuffle names
for i = #NAMES, 2, -1 do
	local j = math.random(i)
	NAMES[i], NAMES[j] = NAMES[j], NAMES[i]
end

local function log_msg(message)
	local now = os.date("%Y-%m-%d %H:%M:%S")
	print(string.format("%s %s", now, message))
end

local DiceServer = {}
DiceServer.__index = DiceServer

function DiceServer.new(host, port, password)
	local self = setmetatable({}, DiceServer)
	self.host = host
	self.port = port
	self.password = password or ""
	self.clients = {} -- key -> {conn = client, name = name, addr = addr}
	self.client_count = 0
	return self
end

function DiceServer:broadcast(msg)
	local payload = msg .. "\n"
	for _, client in pairs(self.clients) do
		pcall(function()
			client.conn:send(payload)
		end)
	end
end

local function parse_roll_args(args)
	if not args or #args == 0 then
		return { math.random(1, 20) }
	end
	local results = {}
	for _, arg in ipairs(args) do
		-- Matches (\d*)d(\d+)([+-]\d+)?
		local num_str, sides_str, mod_str = arg:match("^(%d*)d(%d+)([+-]?%d*)%s*$")
		if not num_str then
			log_msg("Unknown roll format: " .. tostring(arg))
		else
			local num = (num_str == "" and 1 or tonumber(num_str))
			local sides = tonumber(sides_str)
			local modifier = (mod_str == "" or not mod_str) and 0 or tonumber(mod_str)

			if num > 0 and sides > 0 then
				local total = modifier
				for _ = 1, num do
					total = total + math.random(1, sides)
				end
				table.insert(results, total)
			end
		end
	end
	return results
end

function DiceServer:cmd_roll(key, args, dm)
	local r = parse_roll_args(args)
	local result_str = table.concat(r, ",")
	local name = self.clients[key].name
	local prefix = dm and "TO DM " or ""
	local message = string.format("%s%s rolls %s", prefix, name, result_str)
	log_msg(message)
	if not dm then
		self:broadcast(message)
	end
end

function DiceServer:cmd_d_roll(key, args, dm)
	if not args or #args == 0 then
		args = { "1||20||0" }
	end
	local count, sides, modifier = 1, 20, 0
	local success, err = pcall(function()
		local d = {}
		for part in string.gmatch(args[1], "[^|]+") do
			table.insert(d, part)
		end
		if #d >= 3 then
			count = tonumber(d[1])
			sides = tonumber(d[2])
			modifier = tonumber(d[3])
		end
	end)

	if not success then
		log_msg("Incorrect /d roll format")
		return
	end

	local result = modifier
	for _ = 1, count do
		result = result + math.random(1, sides)
	end

	local name = self.clients[key].name
	local prefix = dm and "TO DM " or ""
	local message = string.format("%s%s rolls %s", prefix, name, tostring(result))
	log_msg(message)
	if not dm then
		self:broadcast(message)
	end
end

function DiceServer:run()
	local server = assert(socket.bind(self.host, self.port))
	server:settimeout(0) -- non-blocking
	local ip, port = server:getsockname()

	print(HEADER)
	local intro = string.format("%s is listening %s, on %s:%s", TITLE, server_intro(), ip, tostring(port))
	log_msg(intro)

	local client_socks = {}

	while true do
		-- Accept new connections
		local sock = server:accept()
		if sock then
			sock:settimeout(0)
			local ip, port = sock:getpeername()
			local key = ip .. ":" .. port

			if self.client_count >= #NAMES then
				log_msg("Max player count reached")
				sock:send("Max player count reached\n")
				sock:close()
			else
				self.client_count = self.client_count + 1
				local name = NAMES[self.client_count]
				self.clients[key] = {
					conn = sock,
					name = name,
					addr = key,
					authenticated = (self.password == ""),
				}
				client_socks[sock] = key
				log_msg(string.format("Added client Client(addr=%s, name=%s)", key, name))
				if self.password == "" then
					sock:send("ok\n")
				else
					sock:send("Login with /login [password]\n")
				end
			end
		end

		-- Read from existing clients
		for sock, key in pairs(client_socks) do
			local line, err = sock:receive("*l")
			if err == "closed" then
				log_msg(key .. " has rage quit")
				sock:close()
				self.clients[key] = nil
				client_socks[sock] = nil
				self.client_count = math.max(0, self.client_count - 1)
				log_msg(key .. " has gone back to reality")
			elseif line then
				line = line:gsub("^%s*(.-)%s*$", "%1"):lower() -- trim and lowercase
				local client = self.clients[key]

				if client then
					if not client.authenticated then
						local login_pass = line:match("^/login%s+(%S+)$")
						if login_pass == self.password then
							client.authenticated = true
							sock:send("ok\n")
							log_msg(key .. " has connected to the adventure")
						else
							log_msg("Wrong password attempt from " .. key)
							sock:send("Login with /login [password]\n")
						end
					else
						-- Parse commands
						local tokens = {}
						for token in line:gmatch("%S+") do
							table.insert(tokens, token)
						end

						if #tokens > 0 then
							local cmd = tokens[1]
							local args = { unpack(tokens, 2) }

							if cmd == "/roll" then
								self:cmd_roll(key, args, false)
							elseif cmd == "/dm" then
								self:cmd_roll(key, args, true)
							elseif cmd == "/d" then
								self:cmd_d_roll(key, args, false)
							elseif cmd == "/dmd" then
								self:cmd_d_roll(key, args, true)
							end
						end
					end
				end
			end
		end

		socket.sleep(0.01) -- Prevent busy waiting
	end
end

local function main()
	local host = os.getenv("DICEHOST") or "0.0.0.0"
	local port_str = os.getenv("DICEPORT") or "5001"
	local password = os.getenv("DICEPASS") or ""

	local port = tonumber(port_str)
	if not port then
		print(string.format("Unknown port value: %s, must be an integer", port_str))
		os.exit(1)
	end

	local server = DiceServer.new(host, port, password)
	local success, err = pcall(function()
		server:run()
	end)

	if not success then
		print("ERROR: " .. tostring(err))
		os.exit(1)
	end
end

main()
