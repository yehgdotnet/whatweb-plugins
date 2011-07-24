##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "Localization" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "Detect localization and charset - useful for targetting localized xss"

examples=%w|
http://www.kidstaff.com.ua/
http://mojawyspa.co.uk
www.google.com
www.google.pl
www.google.vn
www.google.cn
www.yahoo.com
wwww.mamma.com
www.lycos.com
www.github.com
joomla16.terraluna.nu
www.juegosjuegos.ws
nycodem.net
magazin.libimseti.cz
www.pchome.com.tw
www.pentest.it
www.ebay.com.cn
hacker.us
hacker.in
hacker.ro
hacker.gr
hacker.cn
hacker.jp
hacker.sg
hacker.ua
hacker.dk
hacker.es
|

def passive
m=[]
lan=''
charset=''

if @meta['set-cookie']   != nil
    lan = @meta['set-cookie']
    lan = lan.scan(/(set-language|content-language|language=)([\.\_a-zA-Z\-]+).?/i)
    if lan.size != 0
        lan = lan[0][1]
        m << {:name=>"header-language",:string=>"lang[#{lan}]"} 
    end
end

if  ( (!m.to_s.include?'header-language') && @meta['language']  != nil)
    lan = @meta['language']
    lan = lan[0,lan.index(';')] if lan.include?';'
    m << {:name=>"header language",:string=>"lang[#{lan}]"}     

elsif @meta['set-language']  != nil
    lan = @meta['set-language']
    lan = lan[0,lan.index(';')] if lan.include?';'
    m << {:name=>"header language",:string=>"lang[#{lan}]"}     

elsif @meta['content-language']  != nil
    lan = @meta['content-language']
    lan = lan[0,lan.index(';')] if lan.include?';'
    m << {:name=>"header language",:string=>"lang[#{lan}]"}     

elsif @body =~ /\sxml\:lang=.?([\.\_a-zA-Z\-]+).?/i
    lan = @body.scan(/\sxml\:lang=.?([\.\_a-zA-Z\-]+).?/i)[0][0].to_s
    m << {:name=>"xml:lang",:string=>"lang[#{lan}]"}    

elsif @body =~ /\slang=.?([\.\_a-zA-Z\-]+).?/i
    lan=@body.scan(/\slang=.?([\.\_a-zA-Z\-]+).?/i)[0][0].to_s
    m << {:name=>"lang",:string=>"lang[#{lan}]"}
        
elsif @body =~ /<meta (name|http\-equiv)=.?(content-language|language).? content=.?([\.\_a-zA-Z\-]+).?/i
    lan= @body.scan(/<meta (name|http\-equiv)=.?(content-language|language).? content=.?([\.\_a-zA-Z\-]+).?/i)[0][2].to_s
    m << {:name=>"meta tag",:string=>"lang[#{lan}]"}

elsif @body =~ /<meta content=.?([\.\_a-zA-Z\-]) (name|http\-equiv)=.?(content-language|language).?/i
    lan= @body.scan(/<meta content=.?([\.\_a-zA-Z\-]) (name|http\-equiv)=.?(content-language|language).?/i)[0][1].to_s
    m << {:name=>"meta tag",:string=>"lang[#{lan}]"}

end


if @meta['content-type'] != nil
    charset = @meta['content-type']
    charset = charset.scan(/charset=([\.\_a-zA-Z0-9\-]+).?/i)
   
    if charset.size != 0
        m << {:name=>"charset",:string=>"charset[#{charset}]"}
    end
end

if  ( (!m.to_s.include?'charset') && @body =~ /charset=([\.\_a-zA-Z0-9\-]+).?/i)# 
    charset = @body.scan(/charset=([\.\_a-zA-Z0-9\-]+).?/i)
    m << {:name=>"charset",:string=>"charset[#{charset}]"}
    # critical to determine charset-oriented xss
elsif (!m.to_s.include?'charset') 
    m << {:name=>"charset-none",:string=>"charset:none"}
end

# detect country via cctld if available
cctld = ''
country = ''
datafile = './my-plugins/localization.rb-data' if File.exists?'./my-plugins/localization.rb-data'
datafile = './plugins/localization.rb-data' if File.exists?'./plugins/localization.rb-data'
u = URI.parse("#{@base_uri}")
if  u.host.to_s.match(/\.([a-zA-Z]{2,4})$/) !=nil

ccltd = u.host.to_s.match(/\.([a-zA-Z]{2,4})$/)[0]

File.readlines(datafile).each do |l|
 if l.include?ccltd
    country = l[l.index('-')+2,l.length]
    m << {:name=>"country",:string=>"country[#{country}]"}
 end
end

end

m
end

end

# Common Patterns

# examples not matched:
# http://www.juegosjuegos.ws/		<meta http-equiv="content-language" content="es" />

# http://www.w3.org/TR/html401/struct/dirlang.html
# The HTTP "Content-Language" header (which may be configured in a server). For example:
# Content-Language: en-cockney
# Set-Cookie: language=
 

#http://nycodem.net/ <META http-equiv=Content-Language content=fr-FR>

# http://magazin.libimseti.cz/   <meta http-equiv="Content-Language" content="cs" />


#<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
# <meta name="language" content="en-GB" />

