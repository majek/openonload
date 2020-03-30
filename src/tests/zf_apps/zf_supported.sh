#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

# Outputs '1' if we can build the ZF test apps, or otherwise '0'.

cc -x c - -o /dev/null > /dev/null 2>&1 << EOF
  #include <stdio.h>
  #include <sys/epoll.h>

  int main(void)
  {
    printf("EPOLLRDHUP is %d\n", EPOLLRDHUP);
    return 0;
  }
EOF

if [ $? -eq 0 ]; then
  echo 1
else
  echo 0
fi

