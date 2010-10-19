##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "WWW-Authenticate" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Get WWW-Authenticate header. Print its values - type and realm"

def passive
	m=[]
	type=''
	realm = ''
	if @meta['www-authenticate']  != nil
		header = @meta['www-authenticate'].scan(/([a-zA-Z0-9]+) realm="(.*?)"/)
		if header.size == 1
		   type = header[0][0]
		   realm = header[0][1]
		   m << {:name=>"www-authenticate",:string=>" #{type}, #{realm}" } 
		end
	end
	m
end

end



