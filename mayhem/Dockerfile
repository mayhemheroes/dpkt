# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

# Install dependencies

ADD . /src
WORKDIR /src
RUN python3 -m pip install .

ENV LD_PRELOAD="$LD_PRELOAD:/usr/local/lib/python3.9/dist-packages/asan_with_fuzzer.so"
ENV ASAN_OPTIONS="detect_leaks=0 allocator_may_return_null=1"
CMD ["/src/mayhem/fuzz_pcap_parser.py"]
