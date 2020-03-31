FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install -y cmake make gcc g++ libgtest-dev

WORKDIR /usr/src/gtest
RUN mkdir build

WORKDIR build
RUN cmake .. && make
RUN cp libgtest* /usr/lib
RUN cd .. && rm -rf build

WORKDIR /

ENTRYPOINT /bin/bash
