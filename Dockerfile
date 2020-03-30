FROM ubuntu:16.04

COPY . /KENS

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y cmake make gcc g++ libgtest-dev
RUN cd /usr/src/gtest && mkdir build && cd build && cmake .. && make && cp libgtest* /usr/lib && cd .. && rm -rf build
RUN cd /KENS && make test_part1 |& tee results_part1

ENTRYPOINT bash
