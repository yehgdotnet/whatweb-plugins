##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "OS" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Identify OS in server header"

examples=%w|
http://imagehotel.net
http://decksen.com
http://180.92.173.202
http://www.freehostia.com
http://58.68.32.34/
http://orbitscripts.com
http://byet.org
http://mojawyspa.co.uk
http://www.productpilot.com/
http://www.westword.com
http://lanzend.co.nz
http://www.microsoft.com
http://www.asp.net
http://www.apple.com
http://ww.test.com
|	

def passive
	m=[]
	os = ''
	server = @meta['server'] if @meta.keys.include?("server")
	if server =~ /\(([a-zA-Z0-9\s\-\_]+)\)/
	   os = server.scan(/\(([a-zA-Z0-9\s\-\_]+)\)/)
	   if os.size != 0
		m << {:string=>os[0]}
	   end 
	elsif server =~ /microsoft|asp\.net/i
		m << {:string=>'Windows'}	
	end
	xpoweredby = @meta['x-powered-by'] if @meta.keys.include?("x-powered-by")
	if xpoweredby =~ /\asp\.net/
		m << {:string=>'Windows'}	
	end
	m
end

end



