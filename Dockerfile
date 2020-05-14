# Runs ubuntu 16.04 (libc-2.23) with some tools installed
FROM ubuntu:16.04

# Install tools
RUN apt update && apt install -y build-essential gdb vim git ipython \
                                 tmux strace ltrace ruby-full

# Install pwndbg (old commit before they changed the heap commands)
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && \
	git checkout 1158a30 && ./setup.sh

# Pull in ctf scripts and load pwndbg extensions
RUN git clone https://github.com/dlmarrero/ctf-utils.git ~/ctf-utils && \
	cd ~/ctf-utils/pwndbg-extensions && \
	for script in $(ls *.py); \
		do echo "source $PWD/$script" >> ~/.gdbinit; \
	done

# Install pwntools 2 and 3
RUN pip install pwntools
RUN pip3 install pwntools

# Install one_gadget
RUN gem install one_gadget

