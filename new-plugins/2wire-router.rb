##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "2Wire-Router" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect 2Wire Router"

# 2Wire sucks. You know why? http://yehg.net/lab/pr0js/advisories/2wire/%5B2wire%5D_session_hijacking_vulnerability

examples=%w|
https://122.57.150.154/
https://219.89.16.148/
https://203.45.8.15/
https://207.119.70.73
https://71.17.177.133
https://210.54.120.112
https://165.228.99.122
https://203.45.111.69
https://64.222.151.53
https://203.45.124.108
|	

matches [
{:name=>'Form Post String',:text=>'<form name="pagepost" method="post" action="/xslt?PAGE=WRA01_POST&amp;NEXTPAGE=WRA01_POST">'}
]


def randstr
 chars = ("a".."z").to_a + ("1".."9").to_a
 return Array.new(8,'').collect{chars[rand(chars.size)]}.join
end 

def passive
	m=[]
	server=@meta["server"] if @meta.keys.include?("server")
	if server =~ /2Wire/i
		m << {:name=>"server string",:string=>server}
	end
	m
end

def aggressive
	m=[]
	target = URI.join(@base_uri.to_s,'xslt').to_s	
	status,url,ip,body,headers=open_target(target)
	if status == 200
		target = URI.join(@base_uri.to_s,'xslt?PAGE='+randstr()).to_s	
		status,url,ip,body,headers=open_target(target)	
		if status == 404
			m << {:string=>"404 Signature"} 	
		end	
		target = URI.join(@base_uri.to_s,'xslt?PAGE=C_0_0').to_s	
		status,url,ip,body,headers=open_target(target)	
		if status == 200

			if body =~/<td class="tablesidelabel">Model:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="textboldpadright">Model:<\/td>
                          <td class="textmono">(.*?)<\/td>
/
				m << {:string => "Model[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Serial Number:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Serial Number:<\/td>

                          <td class="data">(.*?)<\/td>/
				m << {:string => "Serial Number[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Hardware Version:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Hardware Version:<\/td>
                          <td class="data">(.*?)<\/td>
/
				m << {:string => "Hardware Version[#{$1}]"}
			end

			if body =~/<td class="tablesidelabel">Software Version:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Software Version:<\/td>
                          <td class="data">(.*?)<\/td>/
				m << {:string => "Software Version[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Key Code:<\/td>

                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Key Code:<\/td>
                          <td class="data">(.*?)<\/td>/
				m << {:string => "Key Code[#{$1}]"}
			end
			if body =~/                    <td class="tablesidelabel">DSL Modem<\/td>
                    <td>(.*?)<\/td>
/ 
				m << {:string => "DSL Modem version[#{$1}]"}
			end
			if body =~/                    <td class="tablesidelabel">Time Since Last Boot:<\/td>
                    <td>(.*?)<\/td>
/ 
				m << {:string => "Time Since Last Boot[#{$1}]"}
			end
		end



		target = URI.join(@base_uri.to_s,'xslt?PAGE=A07&THISPAGE=A01&NEXTPAGE=A07').to_s	
		status,url,ip,body,headers=open_target(target)	
		if status == 200

			if body =~/<td class="tablesidelabel">Model:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="textboldpadright">Model:<\/td>
                          <td class="textmono">(.*?)<\/td>
/
				m << {:string => "Model[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Serial Number:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Serial Number:<\/td>

                          <td class="data">(.*?)<\/td>/
				m << {:string => "Serial Number[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Hardware Version:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Hardware Version:<\/td>
                          <td class="data">(.*?)<\/td>
/
				m << {:string => "Hardware Version[#{$1}]"}
			end

			if body =~/<td class="tablesidelabel">Software Version:<\/td>
                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Software Version:<\/td>
                          <td class="data">(.*?)<\/td>/
				m << {:string => "Software Version[#{$1}]"}
			end
			if body =~/<td class="tablesidelabel">Key Code:<\/td>

                    <td>(.*?)<\/td>
/ or body =~ /<td class="fieldlabel">Key Code:<\/td>
                          <td class="data">(.*?)<\/td>/
				m << {:string => "Key Code[#{$1}]"}
			end
			if body =~/                    <td class="tablesidelabel">DSL Modem<\/td>
                    <td>(.*?)<\/td>
/ 
				m << {:string => "DSL Modem version[#{$1}]"}
			end
			if body =~/                    <td class="tablesidelabel">Time Since Last Boot:<\/td>
                    <td>(.*?)<\/td>
/ 
				m << {:string => "Time Since Last Boot[#{$1}]"}
			end
		end

	end

	m
end

end



