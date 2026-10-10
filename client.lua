#!/usr/bin/env lua
-- luajit client.lua -H 127.0.0.1 -P 5001 -p "password"

    local socket = require("socket")

local function print_prompt()
    io.write("> ")
    io.flush()
end

local function main()
    local host = "127.0.0.1"
    local port = 5001
    local password = ""

    -- Simple argument parsing
    local i = 1
    while i <= #arg do
        if arg[i] == "-H" or arg[i] == "--host" then
            host = arg[i + 1]
            i = i + 2
        elseif arg[i] == "-P" or arg[i] == "--port" then
            port = tonumber(arg[i + 1])
            i = i + 2
        elseif arg[i] == "-p" or arg[i] == "--password" then
            password = arg[i + 1]
            i = i + 2
        else
            i = i + 1
        end
    end

    local sock = socket.tcp()
    local success, err = sock:connect(host, port)
    if not success then
        print("Error connecting to server: " .. tostring(err))
        os.exit(1)
    end

    sock:settimeout(0) -- Non-blocking

    password = password:match("^%s*(.-)%s*$") -- strip whitespace
    if password ~= "" then
        local auth_str = string.format("/login %s\n", password)
        sock:send(auth_str)
        print("Connected")
    end

    print_prompt()

    while true do
        -- Use socket.select to wait for input from either the server socket or stdin (handle fd 0)
        local read_l = {sock, io.stdin}
        local readable, _, err = socket.select(read_l, nil, 0.1)

        if readable then
            for _, r_sock in ipairs(readable) do
                if r_sock == sock then
                    -- Read from server
                    local data, err_msg = sock:receive("*l")
                    if err_msg == "closed" or err_msg == "connection refused" then
                        print("\nDisconnected from server.")
                        sock:close()
                        os.exit(0)
                    elseif data then
                        -- Clear line for prompt, print message, and restore prompt
                        io.write("\r\27[K")
                        print(data)
                        print_prompt()
                    end
                elseif r_sock == io.stdin then
                    -- Read from console user input
                    local line = io.read("*l")
                    if line then
                        local lower_line = line:lower()
                        if lower_line == "/exit" then
                            sock:close()
                            os.exit(0)
                        end
                        sock:send(line .. "\n")
                        print_prompt()
                    end
                end
            end
        end
    end
end

main()