
local NXFS = require "nixio.fs"
local SYS  = require "luci.sys"
local HTTP = require "luci.http"
local DISP = require "luci.dispatcher"
local UTIL = require "luci.util"
local fs = require "luci.openclash"
local uci = require "luci.model.uci".cursor()
local json = require "luci.jsonc"

font_green = [[<b style=color:green>]]
font_red = [[<b style=color:red>]]
font_off = [[</b>]]
bold_on  = [[<strong>]]
bold_off = [[</strong>]]

local op_mode = string.sub(luci.sys.exec('uci get openclash.config.operation_mode 2>/dev/null'),0,-2)
if not op_mode then op_mode = "redir-host" end
local lan_ip = SYS.exec("uci -q get network.lan.ipaddr |awk -F '/' '{print $1}' 2>/dev/null |tr -d '\n' || ip address show $(uci -q -p /tmp/state get network.lan.ifname || uci -q -p /tmp/state get network.lan.device) | grep -w 'inet'  2>/dev/null |grep -Eo 'inet [0-9\.]+' | awk '{print $2}' | tr -d '\n' || ip addr show 2>/dev/null | grep -w 'inet' | grep 'global' | grep 'brd' | grep -Eo 'inet [0-9\.]+' | awk '{print $2}' | head -n 1 | tr -d '\n'")

m = Map("openclash", translate(""))
m.pageaction = false
m.description = translate("")									   

s = m:section(TypedSection, "openclash")
s.anonymous = true

s:tab("op_mode", translate("Operation Mode"))
s:tab("traffic_control", translate("Traffic Control"))
s:tab("dns", "DNS "..translate("Settings"))
s:tab("dashboard", translate("Dashboard Settings"))
s:tab("chnr_update", translate("Chnroute Update"))
s:tab("auto_restart", translate("Auto Restart"))
s:tab("version_update", translate("Version Update"))
s:tab("developer", translate("Developer Settings"))
s:tab("debug", translate("Debug Logs"))
										   

o = s:taboption("op_mode", Flag, "enable_meta_core", font_red..bold_on..translate("Enable Meta Core")..bold_off..font_off)
o.description = font_red..bold_on..translate("Some Premium Core Features are Unavailable, For Other More Useful Functions Go Wiki:")..bold_off..font_off.." ".."<a href='javascript:void(0)' onclick='javascript:return winOpen(\"https://clash-meta.wiki/\")'>https://clash-meta.wiki/</a>"
o.default = 0

o = s:taboption("op_mode", ListValue, "en_mode", font_red..bold_on..translate("Select Mode")..bold_off..font_off)
o.description = translate("Select Mode For OpenClash Work, Try Flush DNS Cache If Network Error")
if op_mode == "redir-host" then
o:value("redir-host", translate("redir-host"))
o:value("redir-host-tun", translate("redir-host(tun mode)"))
o:value("redir-host-mix", translate("redir-host-mix(tun mix mode)"))
o.default = "redir-host"
else
o:value("fake-ip", translate("fake-ip"))
o:value("fake-ip-tun", translate("fake-ip(tun mode)"))
o:value("fake-ip-mix", translate("fake-ip-mix(tun mix mode)"))
o.default = "fake-ip"
end

o = s:taboption("op_mode", Flag, "enable_udp_proxy", translate("Proxy UDP Traffics"))
o.description = translate("The Servers Must Support UDP forwarding").."<br>"..font_red..bold_on.."1."..translate("If Docker is Installed, UDP May Not Forward Normally").."<br>2."..translate("In Fake-ip Mode, Even If This Option is Turned Off, Domain Type Connections Still Pass Through The Core For The Availability")..bold_off..font_off
o:depends("en_mode", "redir-host")
o:depends("en_mode", "fake-ip")
o.default = 1

o = s:taboption("op_mode", ListValue, "stack_type", translate("Select Stack Type"))
o.description = translate("Select Stack Type For TUN Mode, According To The Running Speed on Your Machine")
o:depends("en_mode", "redir-host-tun")
o:depends("en_mode", "fake-ip-tun")
o:depends("en_mode", "redir-host-mix")
o:depends("en_mode", "fake-ip-mix")
o:value("system", translate("System　"))
o:value("gvisor", translate("Gvisor"))
o.default = "system"

o = s:taboption("op_mode", ListValue, "proxy_mode", translate("Proxy Mode"))
o.description = translate("Select Proxy Mode")
o:value("rule", translate("Rule Proxy Mode"))
o:value("global", translate("Global Proxy Mode"))
o:value("direct", translate("Direct Proxy Mode"))
o:value("script", translate("Script Proxy Mode (Tun Core Only)"))
o.default = "rule"

o = s:taboption("op_mode", Value, "delay_start", translate("Delay Start (s)"))
o.description = translate("Delay Start On Boot")
o.default = "0"
o.datatype = "uinteger"

o = s:taboption("op_mode", Value, "log_size", translate("Log Size (KB)"))
o.description = translate("Set Log File Size (KB)")
o.default = "1024"

o = s:taboption("op_mode", Flag, "bypass_gateway_compatible", translate("Bypass Gateway Compatible"))
o.description = translate("If The Network Cannot be Connected in Bypass Gateway Mode, Please Try to Enable.")..font_red..bold_on..translate("Suggestion: If The Device Does Not Have WLAN, Please Disable The Lan Interface's Bridge Option")..bold_off..font_off
o.default = 0

o = s:taboption("op_mode", Flag, "small_flash_memory", translate("Small Flash Memory"))
o.description = translate("Move Core And GEOIP Data File To /tmp/etc/openclash For Small Flash Memory Device")
o.default = 0

---- Operation Mode
switch_mode = s:taboption("op_mode", DummyValue, "", nil)
switch_mode.template = "openclash/switch_mode"

---- DNS Settings
o = s:taboption("dns", ListValue, "enable_redirect_dns", font_red..bold_on..translate("Redirect Local DNS Setting")..bold_off..font_off)
o.description = translate("Set Local DNS Redirect")
o.default = 1
o:value("0", translate("Disable"))
o:value("1", translate("Dnsmasq Redirect"))
o:value("2", translate("Firewall Redirect"))

if op_mode == "fake-ip" then
o = s:taboption("dns", DummyValue, "flush_fakeip_cache", translate("Flush Fake-IP Cache"))
o.template = "openclash/flush_fakeip_cache"
end

o = s:taboption("dns", Flag, "disable_masq_cache", translate("Disable Dnsmasq's DNS Cache"))
o.description = translate("Recommended Enabled For Avoiding Some Connection Errors")..font_red..bold_on..translate("(Maybe Incompatible For Your Firmware)")..bold_off..font_off
o.default = 0
o:depends("enable_redirect_dns", "1")
o:depends("enable_redirect_dns", "0")

o = s:taboption("dns", Flag, "enable_custom_domain_dns_server", translate("Enable Specify DNS Server"))
o.default = 0
o:depends("enable_redirect_dns", "1")
o:depends("enable_redirect_dns", "0")

o = s:taboption("dns", Value, "custom_domain_dns_server", translate("Specify DNS Server"))
o.description = translate("Specify DNS Server For List, Only One IP Server Address Support")
o.default = "114.114.114.114"
o.placeholder = translate("114.114.114.114 or 127.0.0.1#5300")
o:depends{enable_redirect_dns = "1", enable_custom_domain_dns_server = "1"}

custom_domain_dns = s:taboption("dns", Value, "custom_domain_dns")
custom_domain_dns.template = "cbi/tvalue"
custom_domain_dns.description = translate("Domain Names In The List Do Not Return Fake-IP, One rule per line, Depend on Dnsmasq")
custom_domain_dns.rows = 20
custom_domain_dns.wrap = "off"
custom_domain_dns:depends{enable_redirect_dns = "1", enable_custom_domain_dns_server = "1"}

function custom_domain_dns.cfgvalue(self, section)
	return NXFS.readfile("/etc/openclash/custom/openclash_custom_domain_dns.list") or ""
end
function custom_domain_dns.write(self, section, value)
	if value then
		value = value:gsub("\r\n?", "\n")
		local old_value = NXFS.readfile("/etc/openclash/custom/openclash_custom_domain_dns.list")
	  if value ~= old_value then
			NXFS.writefile("/etc/openclash/custom/openclash_custom_domain_dns.list", value)
		end
	end
end

---- Traffic Control
o = s:taboption("traffic_control", Flag, "router_self_proxy", font_red..bold_on..translate("Router-Self Proxy")..bold_off..font_off)
o.description = translate("Only Supported for Rule Mode")..", "..font_red..bold_on..translate("ALL Functions In Stream Enhance Tag Will Not Work After Disable")..bold_off..font_off
o.default = 1

o = s:taboption("traffic_control", Flag, "disable_udp_quic", font_red..bold_on..translate("Disable QUIC")..bold_off..font_off)
o.description = translate("Prevent YouTube and Others To Use QUIC Transmission")..", "..font_red..bold_on..translate("REJECT UDP Traffic(Not Include CN) On Port 443")..bold_off..font_off
o.default = 1

o = s:taboption("traffic_control", Value, "common_ports", font_red..bold_on..translate("Common Ports Proxy Mode")..bold_off..font_off)
o.description = translate("Only Common Ports, Prevent BT/P2P Passing")
o:value("0", translate("Disable"))
o:value("21 22 23 53 80 123 143 194 443 465 587 853 993 995 998 2052 2053 2082 2083 2086 2095 2096 5222 5228 5229 5230 8080 8443 8880 8888 8889", translate("Default Common Ports"))
o.default = 0
o.placeholder = translate("443 or 21-443, Use Space to Separate")
o:depends("en_mode", "redir-host")
o:depends("en_mode", "redir-host-tun")
o:depends("en_mode", "redir-host-mix")

if op_mode == "redir-host" then
	o = s:taboption("traffic_control", Flag, "china_ip_route", translate("China IP Route"))
	o.description = translate("Bypass The China Network Flows, Improve Performance")
	o.default = 0
else
	o = s:taboption("traffic_control", Flag, "china_ip_route", translate("China IP Route"))
	o.description = translate("Bypass The China Network Flows, Improve Performance, Depend on Dnsmasq")
	o.default = 0
	o:depends("enable_redirect_dns", "1")
	o:depends("enable_redirect_dns", "0")

	o = s:taboption("traffic_control", Value, "custom_china_domain_dns_server", translate("Specify CN DNS Server"))
	o.description = translate("Specify DNS Server For CN Domain Lists, Only One IP Server Address Support")
	o.default = "114.114.114.114"
	o.placeholder = translate("114.114.114.114 or 127.0.0.1#5300")
	o:depends("china_ip_route", "1")
end

o = s:taboption("traffic_control", Flag, "intranet_allowed", translate("Only intranet allowed"))
o.description = translate("When Enabled, The Control Panel And The Connection Broker Port Will Not Be Accessible From The Public Network")
o.default = 1

o = s:taboption("traffic_control", Value, "local_network_pass", translate("Local IPv4 Network Bypassed List"))
o.template = "cbi/tvalue"
o.description = translate("The Traffic of The Destination For The Specified Address Will Not Pass The Core")
o.rows = 20
o.wrap = "off"

function o.cfgvalue(self, section)
	return NXFS.readfile("/etc/openclash/custom/openclash_custom_localnetwork_ipv4.list") or ""
end
function o.write(self, section, value)
	if value then
		value = value:gsub("\r\n?", "\n")
		local old_value = NXFS.readfile("/etc/openclash/custom/openclash_custom_localnetwork_ipv4.list")
	  if value ~= old_value then
			NXFS.writefile("/etc/openclash/custom/openclash_custom_localnetwork_ipv4.list", value)
		end
	end
end

o = s:taboption("traffic_control", Value, "chnroute_pass", translate("Chnroute Bypassed List"))
o.template = "cbi/tvalue"
o.description = translate("Domains or IPs in The List Will Not be Affected by The China IP Route Option, Depend on Dnsmasq")
o.rows = 20
o.wrap = "off"
o:depends("enable_redirect_dns", "1")
o:depends("enable_redirect_dns", "0")

function o.cfgvalue(self, section)
	return NXFS.readfile("/etc/openclash/custom/openclash_custom_chnroute_pass.list") or ""
end
function o.write(self, section, value)
	if value then
		value = value:gsub("\r\n?", "\n")
		local old_value = NXFS.readfile("/etc/openclash/custom/openclash_custom_chnroute_pass.list")
	  if value ~= old_value then
			NXFS.writefile("/etc/openclash/custom/openclash_custom_chnroute_pass.list", value)
		end
	end
end

o = s:taboption("chnr_update", Flag, "chnr_auto_update", translate("Auto Update"))
o.description = translate("Auto Update Chnroute Lists")
o.default = 0

o = s:taboption("chnr_update", ListValue, "chnr_update_week_time", translate("Update Time (Every Week)"))
o:value("*", translate("Every Day"))
o:value("1", translate("Every Monday"))
o:value("2", translate("Every Tuesday"))
o:value("3", translate("Every Wednesday"))
o:value("4", translate("Every Thursday"))
o:value("5", translate("Every Friday"))
o:value("6", translate("Every Saturday"))
o:value("0", translate("Every Sunday"))
o.default = "1"

o = s:taboption("chnr_update", ListValue, "chnr_update_day_time", translate("Update time (every day)"))
for t = 0,23 do
o:value(t, t..":00")
end
o.default = "0"

o = s:taboption("chnr_update", Value, "chnr_custom_url")
o.title = translate("Custom Chnroute Lists URL")
o.rmempty = false
o.description = translate("Custom Chnroute Lists URL, Click Button Below To Refresh After Edit")
o:value("https://ispip.clang.cn/all_cn.txt", translate("Clang-CN")..translate("(Default)"))
o:value("https://ispip.clang.cn/all_cn_cidr.txt", translate("Clang-CN-CIDR"))
o:value("https://fastly.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt", translate("Hackl0us-CN-CIDR-fastly-jsdelivr")..translate("(Large Size)"))
o:value("https://testingcf.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt", translate("Hackl0us-CN-CIDR-testingcf-jsdelivr")..translate("(Large Size)"))
o.default = "https://ispip.clang.cn/all_cn.txt"

o = s:taboption("chnr_update", Value, "chnr6_custom_url")
o.title = translate("Custom Chnroute6 Lists URL")
o.rmempty = false
o.description = translate("Custom Chnroute6 Lists URL, Click Button Below To Refresh After Edit")
o:value("https://ispip.clang.cn/all_cn_ipv6.txt", translate("Clang-CN-IPV6")..translate("(Default)"))
o.default = "https://ispip.clang.cn/all_cn_ipv6.txt"

o = s:taboption("chnr_update", Value, "cndomain_custom_url")
o.title = translate("Custom CN Doamin Lists URL")
o.rmempty = false
o.description = translate("Custom CN Doamin Dnsmasq Conf URL, Click Button Below To Refresh After Edit")
o:value("https://testingcf.jsdelivr.net/gh/felixonmars/dnsmasq-china-list@master/accelerated-domains.china.conf", translate("dnsmasq-china-list-testingcf-jsdelivr")..translate("(Default)"))
o:value("https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list@master/accelerated-domains.china.conf", translate("dnsmasq-china-list-fastly-jsdelivr"))
o:value("https://raw.fastgit.org/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf", translate("dnsmasq-china-list-fastgit"))
o:value("https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf", translate("dnsmasq-china-list-github"))
o.default = "https://testingcf.jsdelivr.net/gh/felixonmars/dnsmasq-china-list@master/accelerated-domains.china.conf"

o = s:taboption("chnr_update", Button, translate("Chnroute Lists Update")) 
o.title = translate("Update Chnroute Lists")
o.inputtitle = translate("Check And Update")
o.inputstyle = "reload"
o.write = function()
  m.uci:set("openclash", "config", "enable", 1)
  m.uci:commit("openclash")
  SYS.call("/usr/share/openclash/openclash_chnroute.sh >/dev/null 2>&1 &")
  HTTP.redirect(DISP.build_url("admin", "services", "openclash"))
end

o = s:taboption("auto_restart", Flag, "auto_restart", translate("Auto Restart"))
o.description = translate("Auto Restart OpenClash")
o.default = 0

o = s:taboption("auto_restart", ListValue, "auto_restart_week_time", translate("Restart Time (Every Week)"))
o:value("*", translate("Every Day"))
o:value("1", translate("Every Monday"))
o:value("2", translate("Every Tuesday"))
o:value("3", translate("Every Wednesday"))
o:value("4", translate("Every Thursday"))
o:value("5", translate("Every Friday"))
o:value("6", translate("Every Saturday"))
o:value("0", translate("Every Sunday"))
o.default = "1"

o = s:taboption("auto_restart", ListValue, "auto_restart_day_time", translate("Restart time (every day)"))
for t = 0,23 do
o:value(t, t..":00")
end
o.default = "0"

---- Dashboard Settings
local cn_port=SYS.exec("uci get openclash.config.cn_port 2>/dev/null |tr -d '\n'")
o = s:taboption("dashboard", Value, "cn_port")
o.title = translate("Dashboard Port")
o.default = "9090"
o.datatype = "port"
o.rmempty = false
o.description = translate("Dashboard Address Example:").." "..font_green..bold_on..lan_ip..':'..cn_port..'/ui/yacd'..'、'..lan_ip..':'..cn_port..'/ui/dashboard'..bold_off..font_off

o = s:taboption("dashboard", Value, "dashboard_password")
o.title = translate("Dashboard Secret")
o.rmempty = true
o.description = translate("Set Dashboard Secret")

o = s:taboption("dashboard", Value, "dashboard_forward_domain")
o.title = translate("Public Dashboard Address")
o.datatype = "or(host, string)"
o.placeholder = "example.com"
o.rmempty = true
o.description = translate("Domain Name For Dashboard Login From Public Network")

o = s:taboption("dashboard", Value, "dashboard_forward_port")
o.title = translate("Public Dashboard Port")
o.datatype = "port"
o.rmempty = true
o.description = translate("Port For Dashboard Login From Public Network")

o = s:taboption("dashboard", Flag, "dashboard_forward_ssl")
o.title = translate("Public Dashboard SSL enabled")
o.default = 0
o.description = translate("Is SSL enabled For Dashboard Login From Public Network")

o = s:taboption("dashboard", DummyValue, "Dashboard", translate("Switch(Update) Dashboard Version"))
o.template="openclash/switch_dashboard"
o.rawhtml = true

o = s:taboption("dashboard", DummyValue, "Yacd", translate("Switch(Update) Yacd Version"))
o.template="openclash/switch_dashboard"
o.rawhtml = true

---- version update
core_update = s:taboption("version_update", DummyValue, "", nil)
core_update.template = "openclash/update"

---- developer
o = s:taboption("developer", Value, "firewall_custom")
o.template = "cbi/tvalue"
o.description = translate("Custom Firewall Rules, Support IPv4 and IPv6, All Rules Will Be Added After Plugin Own Completely")
o.rows = 30
o.wrap = "off"

function o.cfgvalue(self, section)
	return NXFS.readfile("/etc/openclash/custom/openclash_custom_firewall_rules.sh") or ""
end
function o.write(self, section, value)
	if value then
		value = value:gsub("\r\n?", "\n")
		local old_value = NXFS.readfile("/etc/openclash/custom/openclash_custom_firewall_rules.sh")
		if value ~= old_value then
			NXFS.writefile("/etc/openclash/custom/openclash_custom_firewall_rules.sh", value)
		end
	end
end

---- debug
o = s:taboption("debug", DummyValue, "", nil)
o.template = "openclash/debug"

			  
												 
											
				

												  
									   
				 
				

													  
												   
							   
			  
				 
   

															
											  
							  
			   
				

															
									   
					   
			   
							  
				
																																							
								
							
			
	
							 
			 
	
			 
   

																				  
								   
													  
																				  
	
																												
   

local t = {
    {Commit, Apply}
}

a = m:section(Table, t)

o = a:option(Button, "Commit", " ")
o.inputtitle = translate("Commit Settings")
o.inputstyle = "apply"
o.write = function()
  m.uci:commit("openclash")
end

o = a:option(Button, "Apply", " ")
o.inputtitle = translate("Apply Settings")
o.inputstyle = "apply"
o.write = function()
  m.uci:set("openclash", "config", "enable", 1)
  m.uci:commit("openclash")
  SYS.call("/etc/init.d/openclash restart >/dev/null 2>&1 &")
  HTTP.redirect(DISP.build_url("admin", "services", "openclash"))
end

m:append(Template("openclash/config_editor"))
											

return m


