# build GMMT Chain

```
apt update

apt upgrade

wget -c https://golang.org/dl/go1.18.1.linux-amd64.tar.gz -O - | sudo tar -xz -C /usr/local

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

apt install make

apt-get install build-essential

git clone https://github.com/MammothDevMaster/giantmammoth

cd giantmammoth

make geth

mv  ./build/bin/geth ./

```
