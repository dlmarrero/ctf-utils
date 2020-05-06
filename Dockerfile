# Runs ubuntu 16.04 (libc-2.23) with some tools installed
FROM ubuntu:16.04

# Install tools
RUN apt update && apt install -y build-essential gdb vim git ipython \
                                 tmux strace ltrace ruby-full

# Install pwndbg
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Install pwntools
RUN pip install pwntools

# Install one_gadget
RUN gem install one_gadget

