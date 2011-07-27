##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "HopfTimeServer" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect Hopf Time Server CGI application (http://www.hopf.com/)"

examples=%w|
http://www.timesync.eu/
|			

matches [
{:name=>'HTML Title',:regexp => /><title>Hopf (.*?) - General<\/title/},
{:name=>'HTML Title',:regexp => /<title>HOPF (.*?) Configuration<\/title>/},
{:url=>'/cgi-bin/main.cgi?ntp&0', :name=>'HTML Tag Pattern', :tagpattern=>'html,head,link,link,title,/title,style,/style,script,/script,meta,/head,body,table,tr,td,img,map,area,area,/map,/td,td,img,/td,/tr,tr,td,/td,td,/td,td,table,tr,td,img,/td,td,img,/td,td,a,/a,/td,td,img,/td,td,a,/a,/td,td,img,/td,td,a,/a,/td,td,img,/td,td,a,/a,/td,td,img,/td,td,a,/a,/td,td,img,/td,td,/td,td,table,tr,td,img,/td,td,img,/td,td,img,/td,td,img,/td,td,img,/td,/tr,/table,/td,td,img,/td,/tr,/table,/td,td,img,/td,/tr,tr,td,img,/td,td,/td,td,table,tr,td,table,tr,td,table,tr,td,table,tr,td,img,/td,td,div,/div,/td,td,img,/td,/tr,/table,/td,/tr,tr,td,table,tr,td,img,/td,td,/td,td,img,/td,/tr,tr,td,/td,td,div,table,tr,td,iframe,/iframe,/td,/tr,/table,/div,/td,td,/td,/tr,tr,td,img,/td,td,/td,td,img,/td,/tr,/table,/td,/tr,/table,/td,td,div,/div,/td,td,table,tr,td,table,tr,td,img,/td,td,div,/div,/td,td,img,/td,/tr,/table,/td,/tr,tr,td,table,tr,td,img,/td,td,/td,td,img,/td,/tr,tr,td,/td,td,div,table,tr,td,iframe,/iframe,/td,/tr,/table,/div,/td,td,/td,/tr,tr,td,img,/td,td,/td,td,img,/td,/tr,/table,/td,/tr,/table,/td,/tr,tr,td,table,tr,td,table,tr,td,img,/td,td,div,/div,/td,td,img,/td,/tr,/table,/td,/tr,tr,td,table,tr,td,img,/td,td,/td,td,img,/td,/tr,tr,td,/td,td,div,table,tr,td,form,table,tr,td,/td,/tr,tr,td,input,/td,/tr,tr,td,/td,/tr,tr,td,input,/td,/tr,tr,td,input,/td,/tr,tr,td,br,br,/td,/tr,/table,/form,/td,/tr,/table,/div,/td,td,/td,/tr,tr,td,img,/td,td,/td,td,img,/td,/tr,/table,/td,/tr,/table,/td,/tr,/table,/td,td,/td,/tr,/table,/td,td,img,/td,/tr,tr,td,/td,td,/td,td,div,/div,/td,td,img,/td,/tr,tr,td,/td,td,/td,td,/td,td,/td,/tr,/table,/body,/html'},

]
def passive
    m = []
    if @body =~ /<head><title>HOPF (.*?) Configuration<\/title>/
	m << {:string => "Generic Version - #{$1}"}
    elsif @body =~ /><title>Hopf (.*?) - General<\/title/
	m << {:string => "Version - #{$1}"}
    end
    m
end
def aggressive
	m=[]
	target = URI.join(@base_uri.to_s,'/cgi-bin/main.cgi?ntp&0').to_s	
	status,url,ip,body,headers=open_target(target)	
	if status == 200
		if body =~ /><title>Hopf (.*?) - System Info<\/title/
			m << {:string => "Version - #{$1}"}
		end
	end
	m
end

end



