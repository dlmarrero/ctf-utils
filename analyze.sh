set -x

readelf -saW $1 | egrep "FUNC|GLOB"
echo
strings -tx -an8 $1
echo
file $1
echo
checksec $1
