##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Juniper-Load-Balancer" do
author "Aung Khant <http://yehg.net/>" # 2011-02-04
version "0.1"
description "Juniper Networks Application Acceleration and Load Balancing Platforms - http://juniper.net/ . Note: This will slow down your web app pentest scanning. Use only manual fuzzing with time throttling."

examples %w|
http://www.juniper.net/
http://12.105.142.170/
http://12.105.142.237/
http://123.176.112.242/
http://123.176.112.243/
http://123.176.112.41/
http://123.176.112.67/
http://147.6.81.92/
http://150.101.83.113
http://193.194.158.204/
http://193.242.192.57/
http://203.120.129.110/
http://203.120.149.83
http://207.104.211.80/
http://212.137.33.109/
http://212.137.33.88/
http://212.137.33.74
http://213.4.57.106/
http://213.4.57.108/
http://213.4.57.109/
http://63.210.58.82/
http://63.240.234.120/
http://63.240.234.123/
http://74.175.106.71/
http://corporate.lc.jumbo.pt/
http://cpms.dfa.state.nm.us/
http://www.marriottvacationclub.com
http://www.palmerston.nt.gov.au/
http://www.ritzcarltonclub.com/
https://aida.bvdep.com
https://mintglobal.bvdep.com/
https://www.myritzcarltonclub.com/
|



matches [




]


def passive
	m=[]

	m << {:name=>"cookie (rl-sticky-key)" } if @meta["set-cookie"] =~ /rl\-sticky\-key/i
    m << {:name=>"via header" } if @meta["via"] =~ /Juniper Networks Application Acceleration Platform/i
       
    
    if @meta['via'] =~ /Juniper Networks Application Acceleration Platform \- ([^<^\)]*)/i
        version = @meta['via'].scan(/Juniper Networks Application Acceleration Platform \- ([^<^\)]*)/i)
        m << {:version=>'Juniper Networks Application Acceleration Platform ' + version.to_s}
        
    end    
	
	m
end


end


