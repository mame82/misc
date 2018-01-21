local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Tests an http server for Cross-Origin Resource Sharing (CORS), a way
for domains to explicitly opt in to having certain methods invoked by
another domain.

The script works by setting the Access-Control-Request-Method header
field for certain enumerated methods in OPTIONS requests, and checking
the responses.
]]

---
-- @args http-cors.path The path to request. Defaults to
-- <code>/</code>.
--
-- @args http-cors.origin The origin used with requests. Defaults to
-- <code>example.com</code>.
--
-- @usage
-- nmap -p 80 --script http-cors <target>
--
-- @output
-- 80/tcp open
-- |_cors.nse: GET POST OPTIONS


author = "MaMe82"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule =  shortport.http

local methods = {"GET", "POST"}


local function test(host, port, method, origin)
  local header = {
    ["Origin"] = origin,
  }
  local response = http.generic_request(host, port, method, "/", {header = header})
  local aorigins = response.header["access-control-allow-origin"]
  local acreds = response.header["access-control-allow-credentials"]
  local res = nil
  if aorigins then
	res="\tACAO: "..aorigins
	if acreds then
      res=res..", ACAC: "..acreds
    end
  end
  

  return res
end

action = function(host, port)
  local tn=host["targetname"]
  local res = "\nCORS result"
  if tn then res=res.."for "..tn end
  res=res..":\n--------------------\n\n"
  local path = nmap.registry.args["http-cors2.path"] or "/"
  local allowed = {}
  local origins = {}
  local t = nil
  
  -- add origins
  table.insert(origins, "null")
  if (host["targetname"] ~= nil) then
    table.insert(origins, "http://"..host["targetname"])
    table.insert(origins, "http://".."subdom."..host["targetname"])
    table.insert(origins, "http://"..host["targetname"]..".foreigndom.com")
    table.insert(origins, "http://".."prefix-"..host["targetname"])
    table.insert(origins, "http://"..host["targetname"].."-sufix")
    
    table.insert(origins, "https://"..host["targetname"])
    table.insert(origins, "https://".."subdom."..host["targetname"])
    table.insert(origins, "https://"..host["targetname"]..".foreigndom.com")
    table.insert(origins, "https://".."prefix-"..host["targetname"])
    table.insert(origins, "https://"..host["targetname"].."-sufix")
  end
  
  
  for _, method in ipairs(methods) do
    for _, ori in ipairs(origins) do
	  t = test(host, port, method, ori) 
      if t then
        -- if ACAO is "*" or "null" we can skip further test for this request method
        
        table.insert(allowed, method.." for Origin '"..ori.."':"..t.."\n")
--        if string.find(t, "ACAO: %*") then break end
--        if string.find(t, "ACAO: null") then break end
      else
        table.insert(allowed, method.." for "..ori..": no\n")
      end
    end
  end
  
  if #allowed > 0 then
    return res..stdnse.strjoin(" ", allowed)
  else
    return res.."No hit "..stdnse.strjoin(" ", origins)
  end
end
