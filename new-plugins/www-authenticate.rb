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

# http://www.shodanhq.com/?q=%22401+unauthorized%22+%22WWW-Authenticate%22
examples = %w|
124.157.149.116
83.134.49.218
83.4.76.47
41.237.138.88
66.110.224.190
95.102.172.91
119.42.84.245
190.87.101.44
195.235.195.170
98.24.57.154
113.53.51.249
66.205.130.179
|

def passive
	m=[]
	type=''
	realm = ''
	unless @meta['www-authenticate'] == nil	
		if @meta['www-authenticate'].scan(/([a-zA-Z0-9]+) realm="(.*?)"/).size == 1
			header = @meta['www-authenticate'].scan(/([a-zA-Z0-9]+) realm="(.*?)"/)
			type = header[0][0]
			realm = header[0][1]
			m << {:name=>"www-authenticate",:string=>" type[#{type}], realm[#{realm}]" } 
		elsif  @meta['www-authenticate'].scan(/([a-zA-Z0-9]+)/).size > 1
			#113.53.51.249, qop, nonce -> http://en.wikipedia.org/wiki/Digest_access_authentication
			if @meta['www-authenticate'].scan(/([a-zA-Z0-9]+) realm="(.*?)", nonce="(.*?)", qop="(.*?)"/).size == 1
				header = @meta['www-authenticate'].scan(/([a-zA-Z0-9]+) realm="(.*?)", nonce="(.*?)", qop="(.*?)"/)
				type = header[0][0]
				realm = header[0][1]
				nonce =header[0][2]
				qop =header[0][3]
				m << {:name=>"www-authenticate",:string=>" type[#{type}], realm[#{realm}], nonce[#{nonce }], qop[#{qop}]" }	
			else	
				header = @meta['www-authenticate']
				m << {:name=>"www-authenticate",:string=>" #{header}" } 
			end
		end

	end
	m
end

end



