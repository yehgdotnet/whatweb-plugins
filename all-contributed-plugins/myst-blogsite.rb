##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "myst-blogsite" do
author "Aung Khant <http://yehg.net/>" # 2012-02-10
version "0.1"
description "MyST blogsite Blog CMS - http://blogsite.com/"

examples %w|
http://blog.cenzic.com
http://myst-technology.com
http://blogsite.com/
|

matches [
{:name => 'X-Cache Header', :search=>"headers[x-cache]", :regexp=>/myst\-technology.com/i}

]


end


