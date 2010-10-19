##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

Plugin.define "LifeType" do
author "Aung Khant, http://yehg.net"
version "0.1"
description "LifeType is an open-source blogging platform with support for multiple blogs and users in a single installation."

examples=%w|
demo.opensourcecms.com/lifetype/
hugi.to/blog/
www.lifetype.de 
http://iya.blogs.nowhere-else.org/
hrbspecialties.com/lifetype/
cisc.twbbs.org/lifetype/
ccyes.tpc.edu.tw/lifetype/
blaogy.com
www.cbmollet.com/lifetype
books.mlc.tw/lifetype/
cy-thompson.co.uk/lifetype/
journalofsustainability.com/lifetype/
barbandrodger.com/LifeType/
bigbrakebrewing.com/lifetype/
140.120.80.32/lifetype/
linux.e-yen.info/lifetype/
cy-thompson.co.uk/lifetype/
chargingbull.net/lifetype/
myfirstblog.net
|	

# <meta name="generator" content="lifetype-1.2.10_r6971" />

matches [
# 2010-10-17
# About 246,000 results (0.24 seconds) 
# "Powered by Lifetype" site:myfirstblog.net/
{:name=>'GHDB: "Powered by Lifetype"',:certainty=>75,:ghdb=>'"Powered by Lifetype"'},
{:name=>"poweredBy", :text=>'Powered by <a href="http://www.lifetype.net">LifeType</a>'},
{:url=>'summary.php?op=resetPasswordForm',:text=>'Powered by <a href="http://www.lifetype.net">LifeType</a>'},
{:url=>'summary.php?op=resetPasswordForm',:text=>'<title>Your Service Name</title>'},
{:version=>/<meta name=\"generator\" content=\"(lifetype\-)?([0-9\.\_a-z]+)\"/, :version_regexp_offset=>1},
]


end





