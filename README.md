# Build GMMT Chain


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

# Initialization
Initialize geth before running the node.
```
./geth init --datadir=/path/to/node ./genesis/genesis.json
```

# Start Node

```
./geth --datadir=/path/to/node --networkid=8989 console
```

### Programmatically interfacing `geth` nodes

`geth` has built-in support for a JSON-RPC based APIs ([standard APIs](https://eth.wiki/json-rpc/API)
and [`geth` specific APIs](https://geth.ethereum.org/docs/rpc/server)).
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `geth`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
  * `--http.corsdomain` Comma separated list of domains from which to accept cross origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept websockets requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcapi` API's offered over the IPC-RPC interface (default: `admin,debug,eth,miner,net,personal,txpool,web3`)
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `geth` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

### Add Peer

```
// in geth's console
admin.addPeer("enode://2e5bdd40708ccd8b98c9d846a5172a6585100fd331c27570f1e57903e8d808addbf25d19f0ab451707113edd0dc38950d817cd2c5d98a25e4cf51709e6b18273@52.78.132.230:30303");
```
