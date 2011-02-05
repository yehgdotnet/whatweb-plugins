##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "evercookie" do
author "Aung Khant <http://yehg.net/>" # 2011-02-04
version "0.1"
description "EverCookie - http://samy.pl/evercookie/"

examples %w|
http://samy.pl/evercookie/
|



matches [
{ :url=>'/js/evercookie.js',:text=>'*  by samy kamkar : code@samy.pl : http://samy.pl'},
{ :url=>'evercookie.js',:text=>'*  by samy kamkar : code@samy.pl : http://samy.pl'},
{ :text=>'evercookie.js"></script>' },

]


end


