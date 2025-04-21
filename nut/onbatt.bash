#!/bin/bash
case $1 in
        # make sure postfix or something is installed here
        emailonbatt)
                  mail -s "UPS on battery power" youremail
                  ;;
        emailonline)
                  mail -s "UPS on line power" youremail
                  ;;
        upsonbatt)
                  echo "shutting down NAS"
                  ssh root@yournas shutdown -h +0
                  ;;
        upsonline)
                  etherwake <mac addr>
                  ;;
esac
