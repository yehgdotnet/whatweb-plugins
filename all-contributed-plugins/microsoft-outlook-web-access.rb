##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Microsoft-Outlook-Web-Access" do
author "Aung Khant <http://yehg.net/>" # 2011-02-03
version "0.1"
description "Microsoft Outlook Web Access - http://www.microsoft.com/"

examples %w|
https://webmail.ec.europa.eu/
https://phsexchweb.partners.org/
https://student-webmail.tvu.ac.uk/exchweb/bin/auth/owalogon.asp
https://webmail.inhs.org/exchweb/bin/auth/owalogon.asp
https://owa.vivetelmex.com/exchweb/bin/auth/owalogon.asp
https://email.btconnect.com/exchweb/bin/auth/owalogon.asp
https://apowa.csl.com.au/CookieAuth.dll
https://webems.rmit.edu.vn/exchweb/bin/auth/owalogon.asp
https://uspl.webmail.eds.com/exchweb/bin/auth/owalogon.asp
https://owa.mailseat.com/exchweb/bin/auth/owalogon.asp
https://mn-exch1.nes.nuclearholdings.co.uk/exchweb/bin/auth/owalogon.asp
http://www.davis-interiors.com/exchweb/bin/auth/owalogon.asp
https://medexch.med.unc.edu/exchweb/bin/auth/owalogon.asp
https://cpsmail.cps.k12.il.us/exchweb/bin/auth/owalogon.asp
https://82.93.236.51/exchweb/bin/auth/owalogon.asp
https://student.westwood.edu/exchweb/bin/auth/owalogon.asp
https://ssl.esu.edu/exchweb/bin/auth/owalogon.asp
https://outlook.leeds.ac.uk/exchweb/bin/auth/owalogon.asp
https://www.mayerreed.com/exchweb/bin/auth/owalogon.asp
https://mail.apscuf.org/exchweb/bin/auth/owalogon.asp
https://www.compasscpagroup.com/exchweb/bin/auth/owalogon.asp
https://owa.nusd.k12.az.us/exchweb/bin/auth/owalogon.asp
https://remote.greatnorthwest.org/exchweb/bin/auth/owalogon.asp
https://staffmail.telstraclear.co.nz/exchweb/bin/auth/owalogon.asp
https://smtp.wellsnursing.org/exchweb/bin/auth/owalogon.asp
https://www.jastrucking.com/exchweb/bin/auth/owalogon.asp
https://secure.mitchellinstallations.ca/exchweb/bin/auth/owalogon.asp
https://mail.zimmermw.com/exchweb/bin/auth/owalogon.asp
https://mail.lakeforrestprep.com/exchweb/bin/auth/owalogon.asp
https://eumail.bp.com/exchweb/bin/auth/owalogon.asp
|

#AD name leak
# https://apowa.csl.com.au/CookieAuth.dll
# https://student-webmail.tvu.ac.uk/exchweb/bin/auth/owalogon.asp
# https://student.westwood.edu/exchweb/bin/auth/owalogon.asp
# https://owa.nusd.k12.az.us/exchweb/bin/auth/owalogon.asp

matches [

{ :ghdb=>'inurl:/exchweb/bin/auth/owalogon.asp' },

{ :name=>'html body', :url=>'/exchweb/bin/auth/owalogon.asp?url=https://1&reason=2',:text=>'<TR><TD><P style="color:red">You could not be logged on to'},
{:name=>'html body', :url=>'CookieAuth.dll?GetLogon?url=/&reason=2',:text=>'<TR><TD><P style="color:red">You could not be logged on to'},


{ :version =>'Microsoft Exchange Server 2003', :text =>'Microsoft Exchange Server 2003" height=62'},

{ :name=>'html title', :text=>'<TITLE>Microsoft Outlook Web Access</TITLE>' },

{ :name=>'noscript', :text=>'<td style="width:100%">To use Microsoft Outlook Web access, browser settings must allow scripts to run.'},

{ :name=>'html body', :text=>'automatically closes its connection to your mailbox after a period of inactivity. If your session ends, refresh your browser, and then log on again.' },

{ :name=>'html body', :text=>'To protect your account from unauthorized access, Outlook Web Access automatically ends your mail session after a period of inactivity. If your session ends, and the Logon page is not displayed, click on a mail folder (e.g., Inbox), and you should be redirected to the Logon page, where you can log on again.'},

{ :name =>'form action url', :text=>'<FORM action="/exchweb/bin/auth/owaauth.dll"' },

{ :name =>'form action url', :text=>'<FORM action="/CookieAuth.dll?Logon"' },

{ :name=>'url redirection', :regexp=>/window\.location\.href="https:\/\/(.*?)\/exchange";/ }

]

def passive
    m = []

    if @body =~ /logonForm\.username\.value = "(.*?)"/i
        domain =  @body.scan(/logonForm\.username\.value = "(.*?)"/i)
        m << {:string=>'AD Domain: ' + domain.to_s}

    elsif @body =~ /document\.getElementById\("username"\)\.value = '(.*?)'/i
        domain =  @body.scan(/document\.getElementById\("username"\)\.value = '(.*?)'/i)
        m << {:string=>'AD Domain: ' + domain.to_s}
    
    end
    

    m
end


end


