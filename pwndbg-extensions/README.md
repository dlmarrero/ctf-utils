# pwnbdg-extensions
Useful extensions for pwndbg

## Installation
Modify ~/.gdbinit and source each script you want to use, for example:
`source ~/pwndbg-extensions/assemble.py`

You can script this to add all the extensions by running:
```bash
cd pwndbg-extensions
for script in $(ls *.py); do 
echo "source $PWD/$script" >> ~/.gdbinit
done
```

## assemble.py
Allows you to enter assembly instructions to write a patch to a given address

### Usage
One-liner:
```
pwndbg> assemble $eip "xor eax, eax; ret"
```

Multiple-lines:
```
pwndbg> assemble $eip
Enter assembly instructions one per line
Enter 'EOF' when done
> xor eax, eax
> sub eax, 0xffffffff
> ret
> EOF
```

### Dependencies
Install keystone-engine for assembling
```bash
pip3 install keystone-engine

# If you're on Kali, the install may put stuff in a weird place, in which case you need to run:
sudo mv /usr/local/lib/python3.7/dist-packages/usr/lib/python3/dist-packages/keystone/libkeystone.so \
   /usr/local/lib/python3.7/dist-packages/keystone/
```

