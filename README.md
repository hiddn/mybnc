# Author
Hidden <hidden@undernet.org>

## To compile
```
make
```

## Configuration

1. Make sure you do not let mybnc.allow to its default. It is **important** that you restrict the ip addresses allowed to connect. One per line. Wildcards allowed, CIDR not supported, hostnames not supported.

2. Modify the default mybnc.conf.default configuration file and follow the instructions written in comments

3. Rename the config file
```
mv mybnc.conf.default mybnc.conf
```
