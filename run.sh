#!/usr/bin/env bash

#dnsecho
#Copyright (C) 2016  Bram Staps
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as
#published by the Free Software Foundation, either version 3 of the
#License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
cd $(dirname $0)

`./settings.py` # load settings

if [ "$1" ==  "start" ]
then
    if [ -f $pid ]
    then
        echo dnsecho already running
    else
        ./dnsecho.py 2>> /dev/null &
        echo -n $! > $pid
    fi

elif [ "$1" ==  "stop" ]
then
    if [ -f $pid ]
    then
        echo killing pid `cat $pid`
        kill `cat $pid`
        rm $pid
    fi

    
elif [ "$1" ==  "status" ]
then
    if [ -f $pid ]
    then
        echo dnsecho running under pid: `cat $pid`
    else
        echo dnsecho not runnig
    fi

else
    echo "use $0 (start|stop|status)"
fi


