##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##

## whatweb can't grap header if http response code == 5xx

Plugin.define "F5-BigIP-Load-Balancer" do
author "Aung Khant <http://yehg.net/>" # 2011-02-04
version "0.1"
description "F5 BigIP Load Balancer -  http://www.f5.com/products/big-ip/"

# example ips might not demonstrate BigIP usage for always
examples %w|
http://12.178.78.132/
http://124.211.45.51/
http://128.11.138.84/
http://131.91.129.88/
http://142.76.1.135/
http://143.88.3.35/
http://168.75.99.110/
http://195.234.225.247/
http://199.106.238.130/
http://199.106.238.158/
http://202.143.10.22/
http://202.176.8.101/
http://203.120.35.120/
http://203.81.13.100/
http://204.154.44.249/
http://208.254.13.19/
http://208.65.194.54/
http://208.65.199.15/
http://208.77.29.132/
http://208.77.29.133/
http://217.114.80.165/
http://217.114.80.195/
http://217.114.81.153/
http://61.123.228.88/
http://61.213.187.135/
http://66.150.196.39/
http://67.108.154.133/
http://87.82.203.85/
http://app3-origin.globaleservice.com/
http://appdev.uwf.edu/
http://hackerwatch.org
http://pmbronline.kaplan.com/
http://student.kaptest.com/
http://switchboard.gasbinsurance.com/
http://travelcutsca.raileurope.com/
http://turi.episerverhotell.net/
http://wcl.accurohealth.com/
http://www.cross-sell.com/
https://206.165.240.73/
https://206.165.245.233
https://altmarketstcprod.gaic.com/
https://unitedhealthcare.p0.com

|



matches [



]

def bin2dec(number)
   return number.to_i(2)
end

def dec2bin(number)
   return number.to_s(2)
end

def extract_ip(s)
    n = Integer(s)
    b1 = dec2bin(n)
    b2 = b1
    d1 = []
    ip = ''
    unless  b1.length % 8 == 0        
        r = b1
        dif = 32 - b1.length        

        b2 = r[0,r.length-4].to_s + '0'*dif + r[r.length-4,r.length].to_s
    end
    i=1
    if b2.length % 8 == 0         
        xb2 = b2.scan(/.{8}/)
        xb2.each do |x|
            if i%4 == 0 
                d1 << bin2dec(x).to_s + ','
            else  
                d1 << bin2dec(x).to_s
            end 
            i = i+1
        end
         ip = d1.join('.')
            ip.gsub!(',.',',')
    end    
   
    ip
end

def passive
    m = []   
    ips = []
    

    m << {:name=>"http pool cookie" } if @meta["set-cookie"] =~/http(s?)([\.\-\_])pool(.*?)=/i
    
    m << {:name=>"http pool cookie" } if @meta["set-cookie"] =~/http([\.\-\_].)pool=/i
    
    if @meta["set-cookie"] =~ /BIGipServer([\.\-\_]?)([^\s]*?)([\.\-\_]?)http([\.\-\_])pool(.*?)=/i  
        extr = @meta["set-cookie"].scan(/BIGipServer([\.\-\_]?)([^\s]*?)([\.\-\_]?)http([\.\-\_])pool/i) 
        
        
        if extr.size > 0
            int_host = extr[0].to_s.scan(/(.*?[^.^_^__^\-$])/)
        else
            int_host = extr.to_s.scan(/(.*?[^.^_^__^\-$])/)
        end
        
        m << {:string => 'Web Server Host Name: ' + int_host.to_s}
       
    elsif @meta["set-cookie"] =~ /BIGipServer([\.\-\_]?)([^\s]*?)([\.\-\_]?)http([\.\-\_])pool=/i  
    
    extr = @meta["set-cookie"].scan(/BIGipServer([\.\-\_]?)([^\s]*?)([\-\_]?)http([\.\-\_])pool=/i) 
    if extr.size > 0
        int_host = extr[0].to_s.scan(/(.*?[^.^_^__^\-$])/)
    else
        int_host = extr.to_s.scan(/(.*?[^.^_^__^\-$])/)
    end
    m << {:string => 'Web Server Host Name: ' + int_host.to_s}

    elsif @meta["set-cookie"] =~ /BIGipServer([\.\-\_]?)([^\s]*?)([\.\-\_]?)https([\.\-\_])pool=/i  
        extr = @meta["set-cookie"].scan(/BIGipServer([\.\-\_]?)([^\s]*?)([\.\-\_]?)https([\.\-\_])pool=/i)  
        if extr.size > 0
            int_host = extr[0].to_s.scan(/(.*?[^.^_^__^\-$])/)
        else
            int_host = extr.to_s.scan(/(.*?[^.^_^__^\-$])/)
        end
        m << {:string => 'Web Server Host Name: ' + int_host.to_s}
    end

             
        if @meta["set-cookie"] =~ /http([\.\-\_])pool=(\d{1,30})\./i
            
            extr_ip = $2
            int_ip = extract_ip(extr_ip.to_s)
    
            if int_ip.length > 0
                ips << int_ip
            end
            
        end
        if @meta["set-cookie"] =~ /https([\.\-\_])pool=(\d{1,30})\./i
            
            extr_ip = $2
            
            int_ip = extract_ip(extr_ip.to_s)
    
            if int_ip.length > 0
                ips << int_ip
            end
        end
        
        
        if ips.size == 0 and @meta["set-cookie"] =~ /http(s?)([\.\-\_])pool(.*?)=(\d{1,30})\./i            
            extr_ip = $4
            int_ip = extract_ip(extr_ip.to_s)
            if int_ip.length > 0
                ips << int_ip
            end
        end
        
        
        ips.uniq!
        if ips.size >= 1        
            ips2 = ips.join(',')
            ips2.gsub!(',.',',')
            ips2.gsub!(',,',',')
            ips2 = ips2[0,ips2.length-1] if ips2[ips2.length-1,ips2.length] == ','        
            m << {:string =>  'Load Balancer IP(s): ' + ips2} if ips.size > 1
            m << {:string =>  'Load Balancer IP: ' + ips2} if ips.size == 1
        end    
    
    
        
    m

end


end


 