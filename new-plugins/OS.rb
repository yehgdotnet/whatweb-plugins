##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

# 0.2
# Added more signatures- bcole

Plugin.define "OS" do
author "Aung Khant, http://yehg.net"
version "0.2"
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
	if m.size == 0
	# bcoles
	# It might be a good idea to add something like this as a catch-all for anything that you can't fingerprint easily:
		m << { :version=>"Windows" } if @meta["server"] =~ /[^\r^\n]*Windows[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows[^\r^\n]*/i
		m << { :version=>"Windows Vista" } if @meta["server"] =~ /[^\r^\n]*Windows Vista[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows Vista[^\r^\n]*/i
		m << { :version=>"Windows 2003" } if @meta["server"] =~ /[^\r^\n]*Windows 2003[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows 2003[^\r^\n]*/i
		m << { :version=>"Windows 2000" } if @meta["server"] =~ /[^\r^\n]*Windows 2000[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows 2000[^\r^\n]*/i
		m << { :version=>"Windows Server 2008" } if @meta["server"] =~ /[^\r^\n]*Windows Server 2008[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows Server 2008[^\r^\n]*/i
		m << { :version=>"Windows XP" } if @meta["server"] =~ /[^\r^\n]*Windows XP[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Windows XP[^\r^\n]*/i
		m << { :version=>"Linux" } if @meta["server"] =~ /[^\r^\n]*linux[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*linux[^\r^\n]*/i
		m << { :version=>"Unix" } if @meta["server"] =~ /[^\r^\n]*UNIX[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*UNIX[^\r^\n]*/i
		m << { :version=>"FreeBSD" } if @meta["server"] =~ /[^\r^\n]*FreeBSD[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*FreeBSD[^\r^\n]*/i
		m << { :version=>"Solaris" } if @meta["server"] =~ /[^\r^\n]*Solaris[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Solaris[^\r^\n]*/i
		m << { :version=>"MacOSX" } if @meta["server"] =~ /[^\r^\n]*MacOSX[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*MacOSX[^\r^\n]*/i
		m << { :version=>"CentOS" } if @meta["server"] =~ /[^\r^\n]*CentOS[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*CentOS[^\r^\n]*/i
		m << { :version=>"Debian Linux" } if @meta["server"] =~ /[^\r^\n]*Debian[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Debian[^\r^\n]*/i
		m << { :version=>"Ubuntu Linux" } if @meta["server"] =~ /[^\r^\n]*Ubuntu[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Ubuntu[^\r^\n]*/i
		m << { :version=>"Mandrake Linux" } if @meta["server"] =~ /[^\r^\n]*Mandrake[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Mandrake[^\r^\n]*/i
		m << { :version=>"PCLinuxOS" } if @meta["server"] =~ /[^\r^\n]*PCLinuxOS[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*PCLinuxOS[^\r^\n]*/i
		m << { :version=>"Fedora Linux" } if @meta["server"] =~ /[^\r^\n]*Fedora[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Fedora[^\r^\n]*/i
		m << { :version=>"openSUSE" } if @meta["server"] =~ /[^\r^\n]*openSUSE[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*openSUSE[^\r^\n]*/i
		m << { :version=>"Arch Linux" } if @meta["server"] =~ /[^\r^\n]*Arch Linux[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Arch Linux[^\r^\n]*/i
		m << { :version=>"Mandriva Linux" } if @meta["server"] =~ /[^\r^\n]*Mandriva Linux[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Mandriva Linux[^\r^\n]*/i
		m << { :version=>"Linux\/SUSE" } if @meta["server"] =~ /[^\r^\n]*Linux\/SUSE[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Linux\/SUSE[^\r^\n]*/i
		m << { :version=>"Slackware Linux" } if @meta["Poweredby"] =~ /[^\r^\n]*Slackware[^\r^\n]*/i or @meta["poweredby"] =~ /[^\r^\n]*Slackware[^\r^\n]*/i
		m << { :version=>"Gentoo Linux" } if @meta["X-Powered-By"] =~ /[^\r^\n]*Gentoo[^\r^\n]*/i or @meta["x-powered-by"] =~ /[^\r^\n]*Gentoo[^\r^\n]*/i
		m << { :version=>"Red Hat" } if @meta["server"] =~ /[^\r^\n]*Red Hat[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Red Hat[^\r^\n]*/i or @meta["server"] =~ /[^\r^\n]*Red-Hat[^\r^\n]*/i or @meta["Server"] =~ /[^\r^\n]*Red-Hat[^\r^\n]*/i
	end
	m
end

end



