##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "TP-Link-Router" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect TP-Link Router"

examples=%w|
120.71.150.13
221.137.51.71
91.150.181.224
91.150.182.113
60.12.138.76
121.227.86.98
217.96.99.102
125.83.10.51
58.37.179.147
122.245.48.131
|	

def randstr
 chars = ("a".."z").to_a + ("1".."9").to_a
 return Array.new(8,'').collect{chars[rand(chars.size)]}.join
end 

matches [
{:url=>randstr(),:text=>'Operating System Error Nr:3997698'},
]

def passive
	m=[]

	#if @body =~ /<meta name=\"generator\" content=\"lifetype-?[0-9\.\_a-z]+\"/
	#	version=@body.scan(/<meta name=\"generator\" content=\"(lifetype\-)?(lifetype-?[0-9\.\_a-z]+)\"/)[0][1]
	#	m << {:name=>"meta generator tag",:version=>version} 
	#end	
	m
end

end



