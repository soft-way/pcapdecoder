#!/bin/sh

aclocal \
&& automake --add-missing -c --foreign \
&& autoconf
