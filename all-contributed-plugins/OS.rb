##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "OS" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Identify OS in server header and others"

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
http://216.200.40.179
http://216.83.191.232
http://12.237.96.129
http://64.71.182.100
http://64.71.181.79
http://12.237.96.130
http://219.166.162.171
http://89.137.17.241
http://62.4.73.165
http://62.92.43.234
http://89.137.17.241
http://92.70.4.235
|	

def passive
	m=[]
	os = ''
	server = @meta['server'] if @meta.keys.include?("server")
	if server =~ /\(([a-zA-Z0-9\s\-\_\.\/]+)\)/
	   os = server.scan(/\(([a-zA-Z0-9\s\.\/\-\_]+)\)/)
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
	# http://www.shodanhq.com/?q=IBM+Corporation
	# Servlet-Engine: Tomcat Web Server/3.2.4 (JSP 1.1; Servlet 2.2; Java 1.3.0; Linux 2.4.2-SGI_XFS_1.0smp x86; java.vendor=IBM Corporation) 
	servleteng = @meta['servlet-engine'] if @meta.keys.include?("servlet-engine")
	if servleteng =~ /\((.*?); (.*?); (.*?); (.*?); java.vendor=IBM Corporation\)/
		jsp= $1;servlet=$2;java= $3; os=$4;
		m << {:string=>jsp.to_a}
		m << {:string=>servlet.to_a}
		m << {:string=>java.to_a}	
		m << {:string=>os.to_a}		
	end
	m
end

end



