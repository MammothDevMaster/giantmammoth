package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/common/systemcontract"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"io/fs"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"strings"
	"unicode"
	"unsafe"

	_ "github.com/ethereum/go-ethereum/eth/tracers/native"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

type artifactData struct {
	Bytecode         string `json:"bytecode"`
	DeployedBytecode string `json:"deployedBytecode"`
}

type dummyChainContext struct {
}

func (d *dummyChainContext) Engine() consensus.Engine {
	return nil
}

func (d *dummyChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func createExtraData(validators []common.Address) []byte {
	extra := make([]byte, 32+20*len(validators)+65)
	for i, v := range validators {
		copy(extra[32+20*i:], v.Bytes())
	}
	return extra
}

func readDirtyStorageFromState(f *state.StateObject) state.Storage {
	var result map[common.Hash]common.Hash
	rs := reflect.ValueOf(*f)
	rf := rs.FieldByName("dirtyStorage")
	rs2 := reflect.New(rs.Type()).Elem()
	rs2.Set(rs)
	rf = rs2.FieldByName("dirtyStorage")
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	ri := reflect.ValueOf(&result).Elem()
	ri.Set(rf)
	return result
}

func simulateSystemContract(genesis *core.Genesis, systemContract common.Address, rawArtifact []byte, constructor []byte, balance *big.Int) error {
	artifact := &artifactData{}
	if err := json.Unmarshal(rawArtifact, artifact); err != nil {
		return err
	}
	bytecode := append(hexutil.MustDecode(artifact.Bytecode), constructor...)
	// simulate constructor execution
	ethdb := rawdb.NewDatabase(memorydb.New())
	db := state.NewDatabaseWithConfig(ethdb, &trie.Config{})
	statedb, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		return err
	}
	statedb.SetBalance(systemContract, balance)
	block := genesis.ToBlock(nil)
	blockContext := core.NewEVMBlockContext(block.Header(), &dummyChainContext{}, &common.Address{})
	txContext := core.NewEVMTxContext(
		types.NewMessage(common.Address{}, &systemContract, 0, big.NewInt(0), 10_000_000, big.NewInt(0), []byte{}, nil, false),
	)
	tracer, err := tracers.New("callTracer", nil)
	if err != nil {
		return err
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, genesis.Config, vm.Config{
		Debug:  true,
		Tracer: tracer,
	})
	deployedBytecode, _, err := evm.CreateWithAddress(vm.AccountRef(common.Address{}), bytecode, 10_000_000, big.NewInt(0), systemContract)
	if err != nil {
		for _, c := range deployedBytecode[64:] {
			if c >= 32 && c <= unicode.MaxASCII {
				print(string(c))
			}
		}
		println()
		return err
	}
	storage := readDirtyStorageFromState(statedb.GetOrNewStateObject(systemContract))
	// read state changes from state database
	genesisAccount := core.GenesisAccount{
		Code:    deployedBytecode,
		Storage: storage.Copy(),
		Balance: big.NewInt(0),
		Nonce:   0,
	}
	if genesis.Alloc == nil {
		genesis.Alloc = make(core.GenesisAlloc)
	}
	genesis.Alloc[systemContract] = genesisAccount
	// make sure ctor working fine (better to fail here instead of in consensus engine)
	errorCode, _, err := evm.Call(vm.AccountRef(common.Address{}), systemContract, hexutil.MustDecode("0xe1c7392a"), 10_000_000, big.NewInt(0))
	if err != nil {
		for _, c := range errorCode[64:] {
			if c >= 32 && c <= unicode.MaxASCII {
				print(string(c))
			}
		}
		println()
		return err
	}
	return nil
}

var stakingAddress = common.HexToAddress("0x0000000000000000000000000000000000001000")
var slashingIndicatorAddress = common.HexToAddress("0x0000000000000000000000000000000000001001")
var systemRewardAddress = common.HexToAddress("0x0000000000000000000000000000000000001002")
var stakingPoolAddress = common.HexToAddress("0x0000000000000000000000000000000000007001")
var governanceAddress = common.HexToAddress("0x0000000000000000000000000000000000007002")
var chainConfigAddress = common.HexToAddress("0x0000000000000000000000000000000000007003")
var runtimeUpgradeAddress = common.HexToAddress("0x0000000000000000000000000000000000007004")
var deployerProxyAddress = common.HexToAddress("0x0000000000000000000000000000000000007005")
var intermediarySystemAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")

//go:embed build/contracts/Staking.json
var stakingRawArtifact []byte

//go:embed build/contracts/StakingPool.json
var stakingPoolRawArtifact []byte

//go:embed build/contracts/ChainConfig.json
var chainConfigRawArtifact []byte

//go:embed build/contracts/SlashingIndicator.json
var slashingIndicatorRawArtifact []byte

//go:embed build/contracts/SystemReward.json
var systemRewardRawArtifact []byte

//go:embed build/contracts/Governance.json
var governanceRawArtifact []byte

//go:embed build/contracts/RuntimeUpgrade.json
var runtimeUpgradeRawArtifact []byte

//go:embed build/contracts/DeployerProxy.json
var deployerProxyRawArtifact []byte

func newArguments(typeNames ...string) abi.Arguments {
	var args abi.Arguments
	for i, tn := range typeNames {
		abiType, err := abi.NewType(tn, tn, nil)
		if err != nil {
			panic(err)
		}
		args = append(args, abi.Argument{Name: fmt.Sprintf("%d", i), Type: abiType})
	}
	return args
}

type consensusParams struct {
	ActiveValidatorsLength   uint32                `json:"activeValidatorsLength"`
	EpochBlockInterval       uint32                `json:"epochBlockInterval"`
	MisdemeanorThreshold     uint32                `json:"misdemeanorThreshold"`
	FelonyThreshold          uint32                `json:"felonyThreshold"`
	ValidatorJailEpochLength uint32                `json:"validatorJailEpochLength"`
	UndelegatePeriod         uint32                `json:"undelegatePeriod"`
	MinValidatorStakeAmount  *math.HexOrDecimal256 `json:"minValidatorStakeAmount"`
	MinStakingAmount         *math.HexOrDecimal256 `json:"minStakingAmount"`
}

type genesisConfig struct {
	ChainId         int64                     `json:"chainId"`
	Deployers       []common.Address          `json:"deployers"`
	Validators      []common.Address          `json:"validators"`
	SystemTreasury  map[common.Address]uint16 `json:"systemTreasury"`
	ConsensusParams consensusParams           `json:"consensusParams"`
	VotingPeriod    int64                     `json:"votingPeriod"`
	Faucet          map[common.Address]string `json:"faucet"`
	CommissionRate  int64                     `json:"commissionRate"`
	InitialStakes   map[common.Address]string `json:"initialStakes"`
}

func invokeConstructorOrPanic(genesis *core.Genesis, contract common.Address, rawArtifact []byte, typeNames []string, params []interface{}, silent bool, balance *big.Int) {
	ctor, err := newArguments(typeNames...).Pack(params...)
	if err != nil {
		panic(err)
	}
	sig := crypto.Keccak256([]byte(fmt.Sprintf("ctor(%s)", strings.Join(typeNames, ","))))[:4]
	ctor = append(sig, ctor...)
	ctor, err = newArguments("bytes").Pack(ctor)
	if err != nil {
		panic(err)
	}
	if !silent {
		fmt.Printf(" + calling constructor: address=%s sig=%s ctor=%s\n", contract.Hex(), hexutil.Encode(sig), hexutil.Encode(ctor))
	}
	if err := simulateSystemContract(genesis, contract, rawArtifact, ctor, balance); err != nil {
		panic(err)
	}
}

func createGenesisConfig(config genesisConfig, targetFile string) error {
	genesis := defaultGenesisConfig(config.ChainId)
	// extra data
	genesis.ExtraData = createExtraData(config.Validators)
	genesis.Config.Parlia.Epoch = uint64(config.ConsensusParams.EpochBlockInterval)
	// execute system contracts
	var initialStakes []*big.Int
	initialStakeTotal := big.NewInt(0)
	for _, v := range config.Validators {
		rawInitialStake, ok := config.InitialStakes[v]
		if !ok {
			return fmt.Errorf("initial stake is not found for validator: %s", v.Hex())
		}
		initialStake, err := hexutil.DecodeBig(rawInitialStake)
		if err != nil {
			return err
		}
		initialStakes = append(initialStakes, initialStake)
		initialStakeTotal.Add(initialStakeTotal, initialStake)
	}
	silent := targetFile == "stdout"
	invokeConstructorOrPanic(genesis, stakingAddress, stakingRawArtifact, []string{"address[]", "uint256[]", "uint16"}, []interface{}{
		config.Validators,
		initialStakes,
		uint16(config.CommissionRate),
	}, silent, initialStakeTotal)
	invokeConstructorOrPanic(genesis, chainConfigAddress, chainConfigRawArtifact, []string{"uint32", "uint32", "uint32", "uint32", "uint32", "uint32", "uint256", "uint256"}, []interface{}{
		config.ConsensusParams.ActiveValidatorsLength,
		config.ConsensusParams.EpochBlockInterval,
		config.ConsensusParams.MisdemeanorThreshold,
		config.ConsensusParams.FelonyThreshold,
		config.ConsensusParams.ValidatorJailEpochLength,
		config.ConsensusParams.UndelegatePeriod,
		(*big.Int)(config.ConsensusParams.MinValidatorStakeAmount),
		(*big.Int)(config.ConsensusParams.MinStakingAmount),
	}, silent, nil)
	invokeConstructorOrPanic(genesis, slashingIndicatorAddress, slashingIndicatorRawArtifact, []string{}, []interface{}{}, silent, nil)
	invokeConstructorOrPanic(genesis, stakingPoolAddress, stakingPoolRawArtifact, []string{}, []interface{}{}, silent, nil)
	var treasuryAddresses []common.Address
	var treasuryShares []uint16
	for k, v := range config.SystemTreasury {
		treasuryAddresses = append(treasuryAddresses, k)
		treasuryShares = append(treasuryShares, v)
	}
	invokeConstructorOrPanic(genesis, systemRewardAddress, systemRewardRawArtifact, []string{"address[]", "uint16[]"}, []interface{}{
		treasuryAddresses, treasuryShares,
	}, silent, nil)
	invokeConstructorOrPanic(genesis, governanceAddress, governanceRawArtifact, []string{"uint256"}, []interface{}{
		big.NewInt(config.VotingPeriod),
	}, silent, nil)
	invokeConstructorOrPanic(genesis, runtimeUpgradeAddress, runtimeUpgradeRawArtifact, []string{"address"}, []interface{}{
		systemcontract.EvmHookRuntimeUpgradeAddress,
	}, silent, nil)
	invokeConstructorOrPanic(genesis, deployerProxyAddress, deployerProxyRawArtifact, []string{"address[]"}, []interface{}{
		config.Deployers,
	}, silent, nil)
	// create system contract
	genesis.Alloc[intermediarySystemAddress] = core.GenesisAccount{
		Balance: big.NewInt(0),
	}
	// set staking allocation
	stakingAlloc := genesis.Alloc[stakingAddress]
	stakingAlloc.Balance = initialStakeTotal
	genesis.Alloc[stakingAddress] = stakingAlloc
	// apply faucet
	for key, value := range config.Faucet {
		balance, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			return fmt.Errorf("failed to parse number (%s)", value)
		}
		genesis.Alloc[key] = core.GenesisAccount{
			Balance: balance,
		}
	}
	// save to file
	newJson, _ := json.MarshalIndent(genesis, "", "  ")
	if targetFile == "stdout" {
		_, err := os.Stdout.Write(newJson)
		return err
	} else if targetFile == "stderr" {
		_, err := os.Stderr.Write(newJson)
		return err
	}
	return ioutil.WriteFile(targetFile, newJson, fs.ModePerm)
}

func defaultGenesisConfig(chainId int64) *core.Genesis {
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(chainId),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		RamanujanBlock:      big.NewInt(0),
		NielsBlock:          big.NewInt(0),
		MirrorSyncBlock:     big.NewInt(0),
		BrunoBlock:          big.NewInt(0),
		RuntimeUpgradeBlock: big.NewInt(0),
		Parlia: &params.ParliaConfig{
			Period: 3,
			// epoch length is managed by consensus params
		},
	}
	return &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  0x638e2e1c,
		ExtraData:  nil,
		GasLimit:   0x3b9aca00,
		Difficulty: big.NewInt(0x01),
		Mixhash:    common.Hash{},
		Coinbase:   common.Address{},
		Alloc:      nil,
		Number:     0x00,
		GasUsed:    0x00,
		ParentHash: common.Hash{},
	}
}

var localNetConfig = genesisConfig{
	ChainId: 3004,
	// who is able to deploy smart contract from genesis block
	Deployers: []common.Address{
		common.HexToAddress("0xc8e409485785878b64315dd029978711078ee71e"),
	},
	// list of default validators
	Validators: []common.Address{
		common.HexToAddress("0xc8e409485785878b64315dd029978711078ee71e"),
		common.HexToAddress("0xdf694b51775f7f29d6ee832fdeeecb6485b303da"),
		common.HexToAddress("0x0a6d69df57c374c6978b52776c70da3db5b3d1ec"),
	},
	SystemTreasury: map[common.Address]uint16{
		common.HexToAddress("0xa3b633b500e84b9b3639ffbae34b351579976109"): 10000,
	},
	ConsensusParams: consensusParams{
		ActiveValidatorsLength:   25,
		EpochBlockInterval:       60,
		MisdemeanorThreshold:     10,
		FelonyThreshold:          10,
		ValidatorJailEpochLength: 1,
		UndelegatePeriod:         0,
		MinValidatorStakeAmount:  (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x56bc75e2d63100000")), // 1 ether
		MinStakingAmount:         (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0xde0b6b3a7640000")), // 1 ether
	},
	InitialStakes: map[common.Address]string{
		common.HexToAddress("0xc8e409485785878b64315dd029978711078ee71e"): "0x56bc75e2d63100000", // 100 eth
		common.HexToAddress("0xdf694b51775f7f29d6ee832fdeeecb6485b303da"): "0x56bc75e2d63100000", // 100 eth
		common.HexToAddress("0x0a6d69df57c374c6978b52776c70da3db5b3d1ec"): "0x56bc75e2d63100000", // 100 eth
	},
	// owner of the governance
	VotingPeriod: 20, // 1 minute
	// faucet
	// Faucet: map[common.Address]string{
	// 	common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"): "0x21e19e0c9bab2400000",
	// 	common.HexToAddress("0x57BA24bE2cF17400f37dB3566e839bfA6A2d018a"): "0x21e19e0c9bab2400000",
	// 	common.HexToAddress("0xEbCf9D06cf9333706E61213F17A795B2F7c55F1b"): "0x21e19e0c9bab2400000",
	// },
}

var devNetConfig = genesisConfig{
	ChainId: 8989,
	// who is able to deploy smart contract from genesis block
	Deployers: []common.Address{
		common.HexToAddress("0x3ef8cb3c73f0dfa760981d2bcd57a7e9d8535e6f"),
	},
	// list of default validators
	Validators: []common.Address{
		common.HexToAddress("0x3ef8cb3c73f0dfa760981d2bcd57a7e9d8535e6f"),
		common.HexToAddress("0x8ee898ba66d6551f80dbca32c81157b028478129"),
		common.HexToAddress("0x55e6d8342150078e969d75396b93918c9ce0cf1b"),
		common.HexToAddress("0xcfcde214610130883e92098cd28705eb065da4d1"),
		common.HexToAddress("0x3a1866e17c8807701599fd5bad97ffc63387e8c9"),
		common.HexToAddress("0xbe9aac23d8fe2b91860a87a1e38f661c7e73563e"),
		common.HexToAddress("0x266ad1d026f4cedafea84243d4be3cada9ec52d7"),
		common.HexToAddress("0xd1f722c4b60298dfecaa9be8eec7069c59dccf63"),
		common.HexToAddress("0x0f0dac5b5c3cc5abe25ebf70f9d0cf7b4ef4cb4d"),
		common.HexToAddress("0x6cb28a9500e65fd02433d4eced9fa7435a4cec73"),
		common.HexToAddress("0x81d1a6c7cef3646fe14fbf86e5f4f390a8d502d4"),
		common.HexToAddress("0xc07a1a7c98c803632333c3410f1cb0fef70c9d83"),
		common.HexToAddress("0x88c7e92dca30a867bec0f83152c372998073cc49"),
		common.HexToAddress("0x20793d66f917dc37c4a3a33d6a31228ee85c6b0c"),
		common.HexToAddress("0x452c9fa3d3d2bda54e55a480f4adb3abdeb96e89"),
		common.HexToAddress("0x0ef2da91249ef620c9fc0c4f4978398829485b39"),
		common.HexToAddress("0x68427ba874a7c4451e3be77e980c971947349207"),
		common.HexToAddress("0x3a26416b048e41366d7db378c8c7110a6187f0c4"),
		common.HexToAddress("0x75902f785e727606faaf8474adc12a718d2a6e6d"),
		common.HexToAddress("0x4dff4db5a1e124f647beceb64d84d31ff6162d42"),
		common.HexToAddress("0x3c38faf3297ef9bc9fad3dac03eeab2783a4b60e"),
	},
	SystemTreasury: map[common.Address]uint16{
		common.HexToAddress("0x32852293fC76D99b130250252f5A1803f613C150"): 10000,
	},
	ConsensusParams: consensusParams{
		ActiveValidatorsLength:   21,
		EpochBlockInterval:       28800,
		MisdemeanorThreshold:     10,
		FelonyThreshold:          10,
		ValidatorJailEpochLength: 1,
		UndelegatePeriod:         0,
		MinValidatorStakeAmount:  (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0xA968163F0A57B400000")), // 50000 ether
		MinStakingAmount:         (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0xde0b6b3a7640000")), // 1 ether
	},
	InitialStakes: map[common.Address]string{
		common.HexToAddress("0x3ef8cb3c73f0dfa760981d2bcd57a7e9d8535e6f"): "0xA968163F0A57B400000",
		common.HexToAddress("0x8ee898ba66d6551f80dbca32c81157b028478129"): "0xA968163F0A57B400000",
		common.HexToAddress("0x55e6d8342150078e969d75396b93918c9ce0cf1b"): "0xA968163F0A57B400000",
		common.HexToAddress("0xcfcde214610130883e92098cd28705eb065da4d1"): "0xA968163F0A57B400000",
		common.HexToAddress("0x3a1866e17c8807701599fd5bad97ffc63387e8c9"): "0xA968163F0A57B400000",
		common.HexToAddress("0xbe9aac23d8fe2b91860a87a1e38f661c7e73563e"): "0xA968163F0A57B400000",
		common.HexToAddress("0x266ad1d026f4cedafea84243d4be3cada9ec52d7"): "0xA968163F0A57B400000",
		common.HexToAddress("0xd1f722c4b60298dfecaa9be8eec7069c59dccf63"): "0xA968163F0A57B400000",
		common.HexToAddress("0x0f0dac5b5c3cc5abe25ebf70f9d0cf7b4ef4cb4d"): "0xA968163F0A57B400000",
		common.HexToAddress("0x6cb28a9500e65fd02433d4eced9fa7435a4cec73"): "0xA968163F0A57B400000",
		common.HexToAddress("0x81d1a6c7cef3646fe14fbf86e5f4f390a8d502d4"): "0xA968163F0A57B400000",
		common.HexToAddress("0xc07a1a7c98c803632333c3410f1cb0fef70c9d83"): "0xA968163F0A57B400000",
		common.HexToAddress("0x88c7e92dca30a867bec0f83152c372998073cc49"): "0xA968163F0A57B400000",
		common.HexToAddress("0x20793d66f917dc37c4a3a33d6a31228ee85c6b0c"): "0xA968163F0A57B400000",
		common.HexToAddress("0x452c9fa3d3d2bda54e55a480f4adb3abdeb96e89"): "0xA968163F0A57B400000",
		common.HexToAddress("0x0ef2da91249ef620c9fc0c4f4978398829485b39"): "0xA968163F0A57B400000",
		common.HexToAddress("0x68427ba874a7c4451e3be77e980c971947349207"): "0xA968163F0A57B400000",
		common.HexToAddress("0x3a26416b048e41366d7db378c8c7110a6187f0c4"): "0xA968163F0A57B400000",
		common.HexToAddress("0x75902f785e727606faaf8474adc12a718d2a6e6d"): "0xA968163F0A57B400000",
		common.HexToAddress("0x4dff4db5a1e124f647beceb64d84d31ff6162d42"): "0xA968163F0A57B400000",
		common.HexToAddress("0x3c38faf3297ef9bc9fad3dac03eeab2783a4b60e"): "0xA968163F0A57B400000",
	},
	// owner of the governance
	VotingPeriod: 28800, // 1 minute
	// faucet
	// Faucet: map[common.Address]string{
	// 	common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"): "0x21e19e0c9bab2400000",
	// 	common.HexToAddress("0x57BA24bE2cF17400f37dB3566e839bfA6A2d018a"): "0x21e19e0c9bab2400000",
	// 	common.HexToAddress("0xEbCf9D06cf9333706E61213F17A795B2F7c55F1b"): "0x21e19e0c9bab2400000",
	// },
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		fileContents, err := os.ReadFile(args[0])
		if err != nil {
			panic(err)
		}
		genesis := &genesisConfig{}
		err = json.Unmarshal(fileContents, genesis)
		if err != nil {
			panic(err)
		}
		outputFile := "stdout"
		if len(args) > 1 {
			outputFile = args[1]
		}
		err = createGenesisConfig(*genesis, outputFile)
		if err != nil {
			panic(err)
		}
		return
	}
	fmt.Printf("building local net\n")
	if err := createGenesisConfig(localNetConfig, "localnet.json"); err != nil {
		panic(err)
	}
	fmt.Printf("\nbuilding dev net\n")
	if err := createGenesisConfig(devNetConfig, "genesis.json"); err != nil {
		panic(err)
	}
	fmt.Printf("\n")
}
