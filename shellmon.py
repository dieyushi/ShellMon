#!/usr/bin/env python
#encoding:utf-8

import os, sys, time, syslog, shutil
from daemon import Daemon
import pyinotify
from conf.config import monitorpath,viruspath,monitorfiletype
from conf.phpkeywords import phpkeywords
from conf.phpvirus import phpvirus

class ShellMonDaemon(Daemon):
    def run(self):
        wm = pyinotify.WatchManager()
        mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE | pyinotify.IN_MODIFY
        notifier = pyinotify.ThreadedNotifier(wm,MonitorEventHandler())
        notifier.start()
        wm.add_watch(monitorpath,pyinotify.ALL_EVENTS,rec=True)

        while True:
            time.sleep(1)

        notifier.stop()

class MonitorEventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self,event):
        if (event.mask & pyinotify.IN_ISDIR):
            pass
        else:
            syslog.syslog("creat " + event.pathname)
            ScanWebshell(event.pathname)
            ScanEvilFuctions(event.pathname)

    def process_IN_MODIFY(self,event):
        if (event.mask & pyinotify.IN_ISDIR):
            pass
        else:
            syslog.syslog("modify " + event.pathname)
            ScanWebshell(event.pathname)
            ScanEvilFuctions(event.pathname)

    def process_default(self,event):
        pass

def ScanWebshell(filepath):
    if os.path.exists(filepath) == False:
        return
    f = open(filepath)
    data = f.read()
    for keyword in phpvirus.keys():
        if phpvirus[keyword] in data:
            syslog.syslog("Detected webshell '" + keyword + "' @ " + filepath)
            try:
                if os.path.exists(viruspath) == False:
                    os.makedirs(viruspath)
                topath = os.path.join(viruspath,os.path.basename(filepath))
                shutil.move(filepath,topath)
                syslog.syslog(filepath + " moved to " +topath)

            except Exception, err:
                syslog.syslog(str(err))

def ScanEvilFuctions(filepath):
    if os.path.exists(filepath ) == False:
        return
    f = open(filepath)
    data = f.read()
    for keyword in phpkeywords.keys():
        if keyword in data:
            syslog.syslog("Detected evil functions '" + keyword + "' @ " +
                    filepath + ", Evil Level: " + phpkeywords[keyword] )


syslog.openlog('shellmon',syslog.LOG_PID,syslog.LOG_DAEMON)
if __name__ == "__main__":
    daemon = ShellMonDaemon('/tmp/shellmon.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            syslog.syslog('shellmon daemon start')
            daemon.start()
        elif 'stop' == sys.argv[1]:
            syslog.syslog('shellmon daemon stop')
            syslog.closelog()
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
