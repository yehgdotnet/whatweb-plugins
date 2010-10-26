##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "Fortinet-Firewall" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect Fortinet-Firewall Web Interface usually running on port 443"

examples=%w|

|	
def randstr
 chars = ("a".."z").to_a + ("1".."9").to_a
 return Array.new(8,'').collect{chars[rand(chars.size)]}.join
end 

matches [
{:url=>'login.js?nocache='+randstr(),:string=>'Login.js MD5 Hash',:md5=>'6032999e08978b317d8382249866232a'},
{:url=>'login.js?nocache='+randstr(),:string=>'Login.js Copyright Text',:regex=>/login.js(\n|\r\n)Copyright Fortinet, Inc\.(\n|\r\n)All rights reserved\./},
{:url=>'login',:string=>'Login page MD5 hash', :md5=>'8bc0d101e3a25c98a9cbcf18240bd271'},
{:url=>'success',:string=>'Success Page MD5',:md5=>'1451298ccf3a24e342b20e6684cbb0dc'},
]

def passive
	m = []
	cookie = @meta['set-cookie'] if @meta.keys.include?('set-cookie')
#Set-Cookie: APSCOOKIE=0&0; path=/; expires=Sun, 06-Nov-1960 06:12:35 GMT
#Set-Cookie: log_filters=; path=/log/; expires=Sun, 06-Nov-1960 06:12:35 GMT
	if cookie =~ /APSCOOKIE=/ and cookie =~ /log_filters=/
		m << {:string=>'HTTP Cookie'}
	end
	m
end

end



