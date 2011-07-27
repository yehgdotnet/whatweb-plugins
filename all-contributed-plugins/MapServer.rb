##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "MapServer" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect MapServer CGI application (http://www.mapserver.org/)"

examples=%w|
http://demo.mapserver.org/
|			



def aggressive
	m=[]
	target = URI.join(@base_uri.to_s,'/cgi-bin/mapserv/?map=*').to_s	
	status,url,ip,body,headers=open_target(target)	
	if status == 200

		if body =~ /<\/HEAD>
<!\-\- MapServer version (.*?)\s/
			m << {:string => "Version - #{$1}"}
		end

		if body =~/<BODY BGCOLOR="#FFFFFF">
msLoadMap(): Regular expression error/ or body =~ /<HEAD><TITLE>MapServer Message<\/TITLE><\/HEAD>
<!\-\- MapServer version/
			m << {:string => "Invalid Map Parameter Detection"}
		end
	end
	m
end

end



