# /bin/bash
set -o xtrace
PWD_HOME=$PWD
mkdir local_env
mkdir local_env/install
cd local_env
pwd
git clone git://github.com/edenhill/librdkafka
cd librdkafka
env | grep FLAGS
./configure --prefix=$PWD_HOME/local_env/install
gmake V=1
gmake install
pwd
ls ../install
