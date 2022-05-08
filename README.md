
--Hackers Creed ToDo List-


	--Information Gathering--


	Information Gathering With Google:

▪	site:targetsite.com
▪	https://pentest-tools.com/information-gathering/google-hacking
▪	Exploit db





	Review Web Server Metadata:

•	Robots.txt
•	Run Crawlers
•	Meta Tags





	Enumrating Web Apps:

•	Scall All Ports.		[nmap -PN -sT -sV -p0-65534 127.0.0.1]
•	Check for Virtual Hosting.
•	Find Subdomains			[sublist3r,knockpy]
•	Trying Zone Transfer.
◦	>host -t ns www.hackerscreed.com
◦	>host -l www.hackerscreed.com ns1.hackerscreed.com 
•	Reverse IP				[http://whois.webhosting.info/]
•	Httprint



	Webserver MetaTags/Comments:

•	Robots.txt
•	Check source code and Search [<META]
•	Check source code and Search [<!--]
•	Check Source code and Search [hidden]




	Identify application entry points (OTG-INFO-006):

•	Play Around Burp for 10-20 min.
•	Spider The App.
•	Figure Where The GET [Parameters] and POST request are used.
•	Figure The Hidden Parameters [Pay Special Attention].
•	Note Down Every Input Parameter from GET and POSt Requests.
•	Identify Where New Cookies are Set





	Fingerprinting The Web App Framework:

•	Using Netcat
◦	nc 127.0.0.1
◦	HEAD / HTTP/1.0
•	Whatweb tool.
•	Nmap against the most common ports.
•	Clustered tool -[clusterd -i 127.0.0.1 -o linux --fingerprint]-
•	Checking Cookies.
•	Using HTML source code to analyse js & cs folders.

				Cookies VS Framework
                     FRAMEWORK	                       COOKIE
Zope	Zope3
CakePHP	cakephp
kohana	kahanasession
Laravel	larvel_session
phpBB	phpbb3_
Wordpress	wp-settings
1C-Bitrix 	BITRIX_
AMPcms 	AMP
Django 	CMS django
DotNetNuke 	DotNetNukeAnonymous
e107 	e107_tz
EPiServer 	EPiTrace, EPiServer
Graffiti	 CMS graffitibot
Hotaru 	CMS hotaru_mobile
ImpressCMS 	ICMSession
Indico 	MAKACSESSION
InstantCMS 	InstantCMS[logdate]
Kentico CMS 	CMSPreferredCulture
MODx 	SN4[12symb]
TYPO3 	fe_typo_user
Dynamicweb 	Dynamicweb
LEPTON 	lep[some_numeric_value]+sessionid
Wix 	Domain=.wix.com
VIVVO 	VivvoSessionId


				FrameWork VS Keywords in SC
                     FRAMEWORK	                 KEYWORD
Adobe ColdFusion 	<!-- START headerTags.cfm
Microsoft ASP.NET 	__VIEWSTATE
ZK	ZK <!-- ZK
Business Catalyst 	<!-- BC_OBNW -->
Indexhibit 	ndxz-studio
Wordpress 	<meta name="generator" content="WordPress 3.9.2" />
phpBB 	<body id="phpbb"
Mediawiki 	<meta name="generator" content="MediaWiki 1.21.9" />
Joomla 	<meta name="generator" content="Joomla! - Open Source Content Management" />
DotNetNuke 	DNN Platform
Drupal 	<meta name="Generator" content="Drupal 7 (http://drupal.org)" />

•	Installing The Framework in The localsystem to understand it better.
•	Bruteforce [fuzzdb,Dirbuster,seclist]






	Map Appilication Artitechture:

•	Detecting Firewalls.
•	Detecting LoadBalancers.
•	Detecting Reverse Proxies. [headers,Timing]





















--Configuration and Deployment Management-- --Testing--

Test Network/Infrastructure Configuration:

•	Bruteforce Config Files
•	Bruteforce Logs Files
•	Bruteforce .ini Files.
•	Bruteforce Admin Portal
•	Run Nikto

Bruteforcing Common file with easywins
•	easywins -x --threads 10 http://www.jkbose.co.i


Testing Subdomain Takeover
•	knockpy
•	sublist3r
•	aquatone
◦	aquatone-gather --domain hackerscreed.com
◦	aquatone-scan –domain hackerscreed.com
◦	aquatone-gather –domain hackerscreed.com
◦	aquatone-takeover –domain hackerscreed.com

Test Application Platform Configuration:

•	CGI Scanner to Bruteforce Know files.
•	Comment Review.
•	Check If the server is allowing to access .ini







	Test File Upload Vulnerabilities:

•	upload.php	---	try to upload a simple php file
•	upload.php 	---	and Then Change the content type of the file to image.
•	upload.php.jpeg 	---	To bypass the blacklist
•	upload.PHP	---	To bypass The BlackList
•	upload.php2	---	php version 2
•	upload.php3	---	php version 3
•	upload.php5	---	php version 5 
•	upload.php4	---	php version 4
•	upload.php6	---	php version 6
•	upload.php7	---	php version 7

NOTE:If you are not able to execute the .PHP file upload new .htaccess file in the
	same directory with data “AddType appilication/x-httpd-php PHP”




Review Old, Backup and Unreferenced Files for Sensitive Information: 

•	Bruteforce Backup Files.
•	Bruteforce Admin Portals
•	Search for Default passwords [http://www.cirt.net/passwords]
•	Bruteforce Sensitve Files
•	Lookup Js and Css files for Clues
•	Use Google to Find Senseitve Pages.




Testing HTTP methods:
•	Find Http Methods -[cURL]
•	Find HTTP Trace. [XST]
•	use JEEF/FOOBAR/ANYOTHER methods on Restricted area.
•	used HEAD on Ristricted Areas.
•	Testing HTTP Strict Transport security Header
◦	 $ curl -s -D- https://domain.com/ | grep Strict
•	Test Cross Domain Policy File for Weak Policies
◦	Fg: www.google.com/crossdomain.xml
 












Testing Role Definitions:

Testing Regristration Process:
•	Register Same Username,Same Email,Same Ph. No,Same Password for 2 Accounts and Check The Response.
•	See if The Registration Process can be Bruteforced.
•	Bruteforcing OTP.
•	Check The Session Token send to email can be used to confirm another email.



Username/Email Enumeration:

•	Error Message -[Content Lenght]
•	Error Codes.
•	Analyse Error Message.

		--Authentication Testing--

Unsecure Transmission of Sensitive Information:

•	Check If The Login Portals are HTTPS or HTTP.
•	Force Using HTTP on HTTPS.
•	Check if The Sensitive data is transmitted through GET Method.


Testing Default passwords:

•	Try Default Password for The Login Mechanism.
•	Bruteforce Most Common Admin Passwords.



Testing Account LockOut Mechanism

•	After 3 Wrong Passwords	---	Login Successful
•	After 5 Wrong Passwords	---	Login Successful
•	After 10 Wrong Passwords 	---	Login Successful
•	After 15 Wrong Passwords	---	Login Successful
◦	Which means The Web app has Weak Account Lockout 
		Mechanism.
•	After This Check The Bruteforcebility of The Valid acc.




Testing Authantication Bypass:
•	Forced Browsing Restricted areas.
•	Parameter Modification.
•	Play around The session id.
•	Predectable Cookies.

Testing Cache Weakness:
•	Login to The website and then logout from the website and press back button and see if You can access the sensitive data again.
•	Visit some pages where the Users sensitive information is sended to the web app and see whether the appilication is telling the browser not to store the contents of this page or not by checking “Cache-Control: no-cache, no-store Expires: 0 Pragma: no-cache “  Fallowing Headers in The HTTP response.  


Testing Weak Password Policies:

•	Check Minimum password with minimum strenght.
•	How Often an User can change his password.
•	LastPass Vs Newpass.
•	Check if The Secret Question are Guessable.
•	Check if The Web app is allowing You to Creat Your own security questions.
•	Brute Force the Security Questions.




Testing weak Password Change Functionality:
•	What info we need to reset the pass.
•	How are Password Reset link sended to the user.
•	Check The Randomness of Reset Tokens.
•	Password Changing CSRF.
•	Is Old Password Req to Change the Password





Digging Deep for Authantication Problems:

•	Identifying Other Channels 
◦	Mobile site
◦	App -[Android,IOS,blackberry]
◦	Different website of same orginisation.
◦	Call Center Functionality.
•	Testing all Authantication Tests Discussed above.



Testing Directory Transversal Vulnerabilty :

•	View file:///root/imxx/Cheat-Sheets/Mine/File-inclusion



Testing for Autharization Bypass:
•	Try To Access The Areas Without Authorization.
•	Try To Access The Resources of Other Users by Using [URL].
•	Try to Use The Admin Function When You Are Logged in As Standard User.




Testing for Privalage Escalation:
•	Check The Parameter Which Decides you ad user or admin.
•	Play Around The Parameters.
•	Have a look Around The cookies.




Testing for IDOR:

•	Figure Out All The Parameters Where User input Refrences the Object from The Server.
•	Point out to some other resource which doesn’t belongs to you.
•	Examples:
◦	http://foo.bar/changepassword?user=someuser
◦	http://foo.bar/showImage?img=img00011
◦	http://foo.bar/accessPage?menuitem=12
◦	http://foo.bar/somepage?invoice=12345
		--Session Management Testing--

•	Are all Set-Cookie directives tagged as Secure?
•	Do any Cookie operations take place over unencrypted transport?
•	Can the Cookie be forced over unencrypted transport?
•	Check The cookie path -[To whome its sending the session token]-
◦	if its set to / [root]  then it may be vulnerable.
•	Are any Cookies persistent?
•	What Expires= times are used on persistent cookies, and are they reasonable?
•	Are cookies that are expected to be transient configured as such?
•	What HTTP/1.1 Cache-Control settings are used to protect Cookies?
•	What HTTP/1.0 Cache-Control settings are used to protect Cookies?
•	Is The sesion id so long to prevent bruteforce attack.



How to Test:
•	Find How many Cookies Are used.
•	Figure Out Where The cookie is set.
•	Figure out the session Cookie.
•	Copy the cookie and paste in [https://decode.org]




Testing for Session Fixation:
•	Trick 1
◦	Visit Website and Check The cookie
◦	Login To The Website
◦	Now if The cookie is still the same the webserver is vulnerable to session fixation.

•	Trick 2
◦	If You Were Able to set Your Desired value as Cookie value
◦	The server is vulnerable to session fixation.

•	Trick 3
◦	Login to website
◦	Copy the cookie
◦	Logout The website
◦	Paste the cookie and check the website if it automatically logins you into the website.

•	Trick 4
◦	Login to website
◦	Copy the session code
◦	logout
◦	Login again 
◦	Copy the session id 
◦	Compare both A and B and if they are same it may be vulnrable.

Testing IMAP and SMTP injection:

•	Find all The Parameters GET and POST
•	Add Black Values to Each Parameter and Check The Response
•	Add some Random Values to the parameters.
•	Add (){}|”:>?< Symbols mostly “ ‘ as an Input.
•	Eliminate some parameters and send only few.
•	Replace numric values of Parameters to Chracters/Strings and character values to integers.


SMTP Injection:

•	Using Carrage Breake:
◦	Eg:http://<webmail>/read_email.php?message_id=4791 BODY[HEADER]%0d%0aV100 CAPABILITY%0d%0aV101 FETCH 4791


Testing LFI:
•	Locate All Parameters Which Point outs The resource on the server.
•	../../../../../etc/passwd
•	../../../../../etc/passwd%00
•	If the Web app is vulnerable to LFI try to Get Root Access by using The Log Poisioning.

Testing RFI:

•	Find out the Vulnerable Parameters .
•	Try http://hackerscreed.com/evil.php
•	Try http://hackerscreed.com/evil -[without Php]


Testing Command Injection:

•	Find The Parameters POST and GET.
•	Try Above Payloads:	
◦	;ls 
◦	;whoami
◦	&ls
◦	| ls
◦	%3Bcat%20/etc/passwd –[URL Encoded ;cat /etc/passwd]-
◦	| Dir C:		--- 	windows.
◦	|netstat 		–-	windows.






Testing Format String Specifier:

•	find out all the parameters.
•	Try http://www.hackerscreed.com/webpp/index%n%n%n
•	And the urls
◦	Eg: ?name=john&code=45765
•	add %x.%x and %n 
◦	eg: ?name=john%x.%x.%x&code=45765%x.%x.%x


Testing for HTTP Splitting Attack:








Testing for Error Handling:
•	Visit Now Existing Pages.
•	invalid input (such as input that is not consistent with application logic.
•	input that contains non alphanumeric characters or query syntax.
•	empty inputs.
•	inputs that are too long.
•	access to internal pages without authentication.
•	bypassing application flow.

All the above tests could lead to application errors that may contain stack traces. It is recommended to use a fuzzer in addition to any manual testing






Testing for Weak Cryptography:

•	Scan all The Ports and analyse all ssl wrapped ports [nmap].
•	Enumerate all Cipher Suite with nmap.
◦	$ nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995 www.hackerscreed.com
•	Checking if the renegotiation is supported by Server.
◦	Openssl s_cleint -connect hackerscreed.com:443
◦	continue with 
▪	HEAD / HTTP/1.0
		R
•	and Check the results.
•	Testing for Beast and CRIME  Attacks.
◦	Java -jar TestSSLServer www.hackerscreed.com 443
•	Testing Vulnerabilities with ./Sslyze
◦	sslyze –regular www.hackerscreed.com 443



Other Notes:
•	Force To send sensitive Data Over unencrypted Channels.
•	SslV2 much be disabled.
•	Secure Renegotiation should be enabled.
•	MD5 should not be used, due to known collision attacks. [35]
•	RC4 should not be used, due to crypto-analytical attacks [15].
•	Server should be protected from BEAST Attack [16].
•	Server should be protected from CRIME attack, TLS compression must be disabled [17].
•	Server should support Forward Secrecy [18].



Testing for Padding Oracle:





Testing Forgery Requests:
•	






Testing for ClickJacking:
•	-check if the website can be loaded in the iframe.
•	-if Yes Then its Vulnerable if not fallow Next.

•	Bypassing The Logic:
◦	-Try to Load mobile version of the Website in the iframe.
◦	-Try to Load By Disabling The Javascript.


•	Bypassing The Frame Busting:
◦	-Try Nested Frames [2 frames]
◦	-Upper frame - <iframe src="fictitious.html">
◦	-Sub frame - <iframe src="http://target site">




Cheking Web Sockets:

•	Search for web sockets by source Code by searching [ws:// or wss://]
•	By using OWASP zed Proxy and move to web socket tab and try to make new WS connections.
•	search for wss:// and check for ssl attacks [beast,crime etc]



--------------------------------------------------------------------------------------

# bug_bounty_checklist

The Checklist

[+] Information Gathering

Manually explore the site
Spider/crawl for missed or hidden content
Check for files that expose content, such as robots.txt, sitemap.xml, .DS_Store
Check the caches of major search engines for publicly accessible sites
Check for differences in content based on User Agent (eg, Mobile sites, access as a Search engine Crawler)
Perform Web Application Fingerprinting
Identify technologies used
Identify user roles
Identify application entry points
Identify client-side code
Identify multiple versions/channels (e.g. web, mobile web, mobile app, web services)
Identify co-hosted and related applications
Identify all hostnames and ports
Identify third-party hosted content

[+] Configuration Management

Check for commonly used application and administrative URLs
Check for old, backup and unreferenced files
Check HTTP methods supported and Cross Site Tracing (XST)
Test file extensions handling
Test for security HTTP headers (e.g. CSP, X-Frame-Options, HSTS)
Test for policies (e.g. Flash, Silverlight, robots)
Test for non-production data in live environment, and vice-versa
Check for sensitive data in client-side code (e.g. API keys, credentials)

[+] Secure Transmission

Check SSL Version, Algorithms, Key length
Check for Digital Certificate Validity (Duration, Signature and CN)
Check credentials only delivered over HTTPS
Check that the login form is delivered over HTTPS
Check session tokens only delivered over HTTPS
Check if HTTP Strict Transport Security (HSTS) in use

[+] Authentication

Test for user enumeration
Test for authentication bypass
Test for bruteforce protection
Test password quality rules
Test remember me functionality
Test for autocomplete on password forms/input
Test password reset and/or recovery
Test password change process
Test CAPTCHA
Test multi factor authentication
Test for logout functionality presence
Test for cache management on HTTP (eg Pragma, Expires, Max-age)
Test for default logins
Test for user-accessible authentication history
Test for out-of channel notification of account lockouts and successful password changes
Test for consistent authentication across applications with shared authentication schema / SSO

[+] Session Management

Establish how session management is handled in the application (eg, tokens in cookies, token in URL)
Check session tokens for cookie flags (httpOnly and secure)
Check session cookie scope (path and domain)
Check session cookie duration (expires and max-age)
Check session termination after a maximum lifetime
Check session termination after relative timeout
Check session termination after logout
Test to see if users can have multiple simultaneous sessions
Test session cookies for randomness
Confirm that new session tokens are issued on login, role change and logout
Test for consistent session management across applications with shared session management
Test for session puzzling
Test for CSRF and clickjacking

[+] Authorization

Test for path traversal
Test for bypassing authorization schema
Test for vertical Access control problems (a.k.a. Privilege Escalation)
Test for horizontal Access control problems (between two users at the same privilege level)
Test for missing authorization

[+] Data Validation

Test for Reflected Cross Site Scripting
Test for Stored Cross Site Scripting
Test for DOM based Cross Site Scripting
Test for Cross Site Flashing
Test for HTML Injection
Test for SQL Injection
Test for LDAP Injection
Test for ORM Injection
Test for XML Injection
Test for XXE Injection
Test for SSI Injection
Test for XPath Injection
Test for XQuery Injection
Test for IMAP/SMTP Injection
Test for Code Injection
Test for Expression Language Injection
Test for Command Injection
Test for Overflow (Stack, Heap and Integer)
Test for Format String
Test for incubated vulnerabilities
Test for HTTP Splitting/Smuggling
Test for HTTP Verb Tampering
Test for Open Redirection
Test for Local File Inclusion
Test for Remote File Inclusion
Compare client-side and server-side validation rules
Test for NoSQL injection
Test for HTTP parameter pollution
Test for auto-binding
Test for Mass Assignment
Test for NULL/Invalid Session Cookie

[+] Denial of Service

Test for anti-automation
Test for account lockout
Test for HTTP protocol DoS
Test for SQL wildcard DoS

[+] Business Logic

Test for feature misuse
Test for lack of non-repudiation
Test for trust relationships
Test for integrity of data
Test segregation of duties

[+] Cryptography

Check if data which should be encrypted is not
Check for wrong algorithms usage depending on context
Check for weak algorithms usage
Check for proper use of salting
Check for randomness functions

[+] Risky Functionality - File Uploads

Test that acceptable file types are whitelisted
Test that file size limits, upload frequency and total file counts are defined and are enforced
Test that file contents match the defined file type
Test that all file uploads have Anti-Virus scanning in-place.
Test that unsafe filenames are sanitised
Test that uploaded files are not directly accessible within the web root
Test that uploaded files are not served on the same hostname/port
Test that files and other media are integrated with the authentication and authorisation schemas

[+] Risky Functionality - Card Payment

Test for known vulnerabilities and configuration issues on Web Server and Web Application
Test for default or guessable password
Test for non-production data in live environment, and vice-versa
Test for Injection vulnerabilities
Test for Buffer Overflows
Test for Insecure Cryptographic Storage
Test for Insufficient Transport Layer Protection
Test for Improper Error Handling
Test for all vulnerabilities with a CVSS v2 score > 4.0
Test for Authentication and Authorization issues
Test for CSRF

[+] HTML 5

Test Web Messaging
Test for Web Storage SQL injection
Check CORS implementation
Check Offline Web Application
