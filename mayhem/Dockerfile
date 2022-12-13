FROM ubuntu:focal as builder

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
	pkg-config autoconf automake libtool \
	make gcc gdb lcov \
	valgrind apache2 check \
	libssl-dev libjansson-dev libcurl4-openssl-dev \
	apache2-dev libpcre2-dev \
	libcjose-dev libhiredis-dev \
	vim curl iputils-ping wget clang

RUN a2enmod ssl proxy proxy_http && \
	a2ensite default-ssl

COPY . mod_auth_openidc

WORKDIR /mod_auth_openidc
RUN ./autogen.sh && \
	./configure CFLAGS="-g -O0" LDFLAGS="-lrt" 
RUN make clean && make check && make  install 
RUN clang /mod_auth_openidc/mayhem/fuzz_oidc_strnenvcmp.cpp /mod_auth_openidc/test/stub.c -fsanitize=fuzzer,address -L /mod_auth_openidc/.libs/ -l:mod_auth_openidc.so -I/usr/include/apr-1.0 -I/usr/include/apache2 -lrt /usr/lib/x86_64-linux-gnu/libapr-1.so /usr/lib/x86_64-linux-gnu/libaprutil-1.so -lldap -llber -lssl /usr/lib/x86_64-linux-gnu/libcurl.so -lcjose -ljansson -lcrypto -lpcre2-8 -lhiredis -pthread -o /fuzz

FROM ubuntu:focal as package
RUN apt-get update && apt-get install -y \
	libjansson-dev libcurl4-openssl-dev \
	libpcre2-dev \
	libcjose-dev libhiredis-dev \
	libapr1 libapr1-dev libaprutil1
COPY --from=builder /mod_auth_openidc/test/test-cmd /
COPY --from=builder /fuzz /fuzz_oidc_strnenvcmp
COPY --from=builder /mod_auth_openidc/.libs/ /deps/
ENV LD_LIBRARY_PATH=/deps
