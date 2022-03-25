import { MultiAsset, TransactionOutputs, TransactionUnspentOutput } from '@emurgo/cardano-serialization-lib-asmjs'
import { Buffer } from 'buffer'

const WALLETS_COMPATIBLE = [
    'nami',
    'ccvault',
    'yoroi',
    'eternl',
]

const ERROR = {
    FAILED_PROTOCOL_PARAMETER: 'Couldnt fetch protocol parameters from blockfrost',
    TX_TOO_BIG: 'Transaction too big',
    NO_COMATIBLE_WALLET: 'No compatible wallet found'
}

/**
 * 
 * @param {window.cardano obj} cardano_window 
 * @param {String} walletName 
 * @returns {Wallet Object}
 */
export async function searchForWallet (cardano_window, walletName) {
    
    // Look if wallet is installed and compatible
    const found_wallet = WALLETS_COMPATIBLE.find(w => w == walletName && cardano_window.hasOwnProperty(walletName))
    
    if(!found_wallet || found_wallet === undefined || found_wallet === '' || found_wallet === null) throw(ERROR.NO_COMATIBLE_WALLET)     

    const Wallet = cardano_window[walletName]

    return await Wallet.enable()
}
/**
 * 
 * @param {cardano WalletObject enabled object} WalletObject 
 * @param {String} blockfrostApiKey 
 * @param {Cardano Serialization Lib serializationLib} serializationLib 
 */
export async function Wallet(WalletObject, blockfrostApiKey, serializationLib=null){
    const CSL = serializationLib || await import('@emurgo/cardano-serialization-lib-asmjs')    
    const Buffer = (await import('buffer')).Buffer
    const Wallet = WalletObject
    const fetch = (await import('node-fetch')).default || window.fetch    
    const CoinSelection = (await import('./coinSelection')).default
    const wallet_api = {
        isEnabled,
        enable,
        getAddress,
        getAddressHex,
        getRewardAddress,
        getRewardAddressHex,
        getNetworkId,
        getUtxos,
        getAssets,
        getUtxosHex,
        send,
        sendMultiple,
        delegate,
        getBalanceADA,
        auxiliary: {
            Buffer,
            AsciiToBuffer,
            HexToBuffer,
            AsciiToHex,
            HexToAscii,
            BufferToAscii,
            BufferToHex,
        }
    }

    const isEnabled = async () => await Wallet.isEnabled() 
    const getAddressHex = async () => await Wallet.getChangeAddress()

    const enable = async () => {
        try {
            await Wallet.enable()
        } catch (error) {
            throw error
        }
    }

    const getAddress = async () => CSL.Address.from_bytes(Buffer.from(await getAddressHex(),'hex')).to_bech32()

    const getRewardAddress = async () => CSL.RewardAddress.from_address(CSL.Address.from_bytes(Buffer.from(await getRewardAddressHex(),'hex'))).to_address().to_bech32()

    const getRewardAddressHex = async () => {        
        const RewardAddressHex = await Wallet.getRewardAddresses()               
        return RewardAddressHex[0]
    }
    
    const getNetworkId = async () => {
        const networkId = await Wallet.getNetworkId()
        return {
            id: networkId,
            network: networkId == 1 ? 'mainnet' : 'testnet'
        }
    }

    const getUtxos = async () => {
        const Utxos = (await getUtxosHex()).map(e => CSL.TransactionUnspentOutput.from_bytes(Buffer.from(e,'hex')))
        const UTXOS = []
        for(let utxo of Utxos){
            let assets = __utxoToAssets(utxo)
            UTXOS.push({
                txHash: Buffer.from(utxo.input().transaction_id().to_bytes(),'hex').toString('hex'),
                txId: utxo.input().index(),
                amount: assets
            })
        }
        return UTXOS
    }

    const getBalanceADA = async () => {
        let balance = 0
        const Utxos = await getUtxos()
        Utxos.forEach(e => {
            balance += Number(e.amount.find(e => e.unit === 'lovelace')?.quantity) /1000000
        })
        return balance
    }

    const getAssets = async () => {
        const Utxos = await getUtxos()
        const AssetsRaw = []
        Utxos.forEach(e => {
            AssetsRaw.push(...e.amount.filter(a => a.unit != 'lovelace'))
        })
        const AssetsMap = {}
        
        for(let k of AssetsRaw){
            let quantity = parseInt(k.quantity)
            if(!AssetsMap[k.unit]) AssetsMap[k.unit] = 0
            AssetsMap[k.unit] += quantity
        }
        return Object.keys(AssetsMap).map(k => ({unit: k, quantity: AssetsMap[k].toString()}))
    }

    const getUtxosHex = async () => await Wallet.getUtxos()

    /**
     * 
     * @param {string} address 
     * @param {int} amount 
     * @param {array} assets 
     * @param {array} metadata 
     * @param {string} metadataLabel 
     * @returns 
     */
    const send = async (address, amount = 0, assets = [], metadata = null, metadataLabel = '721') => {
        const PaymentAddress = await getAddress()
        const protocolParameter = await __getProtocolParameter()
        const utxos = (await getUtxosHex()).map(e => CSL.TransactionUnspentOutput.from_bytes(Buffer.from(e,'hex')))
        const lovelace = Math.floor(amount * 1000000).toString()
        const ReceiveAddress = address
        const multiAsset = __makeMultiAsset(assets)
        const outputValue = CSL.Value.new(CSL.BigNum.from_str(lovelace))
        if(assets.length > 0) outputValue.set_multiasset(multiAsset)
        const minAda = CSL.min_ada_required(outputValue,CSL.BigNum.from_str(protocolParameter.minUtxo || "1000000"))
        if(CSL.BigNum.from_str(lovelace).compare(minAda) < 0) outputValue.set_coin(minAda)
        const outputs = CSL.TransactionOutputs.new()
        outputs.add(CSL.TransactionOutput.new(CSL.Address.from_bech32(ReceiveAddress),outputValue))        
        const RawTransaction = __txBuilder({
            PaymentAddress: PaymentAddress,
            Utxos: utxos,
            Outputs: outputs,
            ProtocolParameter: protocolParameter,
            Metadata: metadata,
            MetadataLabel: metadataLabel,
            Delegation: null
        })

        return await __signSubmitTx(RawTransaction)
    }

    /**
     * 
     * @param {*} recipients 
     * @param {*} metadata 
     * @param {*} metadataLabel 
     */
    const sendMultiple = (recipients = [], metadata = null, metadataLabel = '721') => {
        const PaymentAddress = await getAddress()
        const protocolParameter = await __getProtocolParameter()
        const utxos = (await getUtxosHex()).map(u => CSL.TransactionUnspentOutput.from_bytes(Buffer.from(e,'hex')))
        const outputs = CSL.TransactionOutputs.new()

        for (let recipient of recipients){
            const lovelace = Math.floor((recipient.amount || 0) * 1000000).toString()
            const ReceiveAddress = recipient.address
            const multiAsset = __makeMultiAsset(recipient.assets || [])

            const outputValue = CSL.Value.new(CSL.BigNum.from_str(lovelace))
            
            if((recipient.assets || []).length > 0) outputValue.set_multiasset(multiAsset)

            const minAda = CSL.min_ada_required(
                outputValue, CSL.BigNum.from_str(protocolParameter.minUtxo || "1000000")
            )
            if(CSL.BigNum.from_str(lovelace).compare(minAda) < 0) outputValue.set_coin(minAda)
                
            outputs.add(CSL.TransactionOutput.new(CSL.Address.from_bech32(ReceiveAddress),outputValue))
        }

        const RawTransaction = __txBuilder({
            PaymentAddress: PaymentAddress,
            Utxos: utxos,
            Outputs: outputs,
            ProtocolParameter: protocolParameter,
            Metadata: metadata,
            MetadataLabel: metadataLabel,
            Delegation: null
        })
        return await __signSubmitTx(RawTransaction)
    }

    const delegate = (poolId, metadata = null, metadataLabel = '721') => {
        const protocolParameter = await __getProtocolParameter()
        
        const stakeKeyHash = CSL.RewardAddress.from_address(CSL.Address.from_bytes(Buffer.from(await getRewardAddressHex(),'hex'))).payment_cred().to_keyhash().to_bytes()

        const delegation = await __getDelegation(await getRewardAddress())

        const __getDelegation = async (rewardAddr) => {
            const stake = await __blockfrostRequest(`/accounts/${rewardAddr}`) 
            if(!stake || stake.error || !stake.pool_id) return {}
            return {
                active: stake.active,
                rewards: stake.withdrawable_amount,
                poolId: stake.pool_id,
            }
        }

        const pool = await __blockfrostRequest(`/pools/${poolId}`)
        const poolHex = pool.hex

        const utxos = (await getUtxosHex()).map(e => CSL.TransactionUnspentOutput.from_bytes(Buffer.from(e, 'hex')))
        const PaymentAddress = await getAddress()

        const outputs = CSL.TransactionOutputs.new()
        outputs.add(CSL.TransactionOutput.new(CSL.Address.from_bech32(PaymentAddress),CSL.Value.new(CSL.BigNum.from_str(protocolParameter.keyDeposit))))

        const transaction = __txBuilder({
            PaymentAddress,
            Utxos: utxos,
            ProtocolParameter: protocolParameter,
            Outputs: outputs,
            Delegation: {
                poolHex: poolHex,
                stakeKeyHash: stakeKeyHash,
                delegation: delegation
            },
            Metadata: metadata,
            MetadataLabel: metadataLabel
        })

        const txHash = await __signSubmitTx(transaction)
        return txHash
    }
    
    // AUX START //

    const AsciiToBuffer = (string) => Buffer.from(string, "ascii")
    const HexToBuffer = (string) => Buffer.from(string, "hex")
    const AsciiToHex = (string) => AsciiToBuffer(string).toString('hex')
    const HexToAscii = (string) => HexToBuffer(string).toString("ascii")
    const BufferToAscii = (buffer) => buffer.toString('ascii')
    const BufferToHex = (buffer) => buffer.toString("hex")

    // AUX END //

    // Internal functions //
    const __makeMultiAsset = (assets) => {
        const AssetsMap = {}
        for(let asset of assets){
            let [policy, assetName] = asset.unit.split('.')
            let quantity = asset.quantity
            if(!Array.isArray(AssetsMap[policy])){
                AssetsMap[policy] = []
            }
            AssetsMap[policy].push({
                "unit": Buffer.from(assetName, 'ascii').toString('hex'), 
                "quantity": quantity
            })
            
        }
        const multiAsset = CSL.MultiAsset.new()
        for(const policy in AssetsMap){
            
            const ScriptHash = CSL.ScriptHash.from_bytes(Buffer.from(policy,'hex'))
            const Assets = CSL.Assets.new()            
            const _assets = AssetsMap[policy]

            for(const asset of _assets){
                const AssetName = CSL.AssetName.new(Buffer.from(asset.unit,'hex'))
                const BigNum = CSL.BigNum.from_str(asset.quantity)                
                Assets.insert(AssetName, BigNum)  
            }

            multiAsset.insert(ScriptHash, Assets)
        }

        return multiAsset
    }

    const __utxoToAssets = (utxo) => {
        let value = utxo.output().amount()
        const assets = [];
        assets.push({ unit: 'lovelace', quantity: value.coin().to_str() });
        if (value.multiasset()) {
            const multiAssets = value.multiasset().keys();
            for (let j = 0; j < multiAssets.len(); j++) {
            const policy = multiAssets.get(j);
            const policyAssets = value.multiasset().get(policy);
            const assetNames = policyAssets.keys();
                for (let k = 0; k < assetNames.len(); k++) {
                    const policyAsset = assetNames.get(k);
                    const quantity = policyAssets.get(policyAsset);
                    const asset = Buffer.from(policy.to_bytes()).toString('hex') + "." + Buffer.from(policyAsset.name()).toString('ascii')

                    assets.push({
                        unit: asset,
                        quantity: quantity.to_str(),
                    });
                }
            }
        }
        return assets;
    }

    const __txBuilder = ({PaymentAddress, Utxos, Outputs, ProtocolParameter, Metadata = null, MetadataLabel = '721', Delegation = null}) => {
        const MULTIASSET_SIZE = 5000
        const VALUE_SIZE = 5000
        const totalAssets = 0
        CoinSelection.setLoader(CSL)
        CoinSelection.setProtocolParameters(
            ProtocolParameter.minUtxo.toString(),
            ProtocolParameter.linearFee.minFeeA.toString(),
            ProtocolParameter.linearFee.minFeeB.toString(),
            ProtocolParameter.maxTxSize.toString())
        
        const selection = CoinSelection.randomImprove(
            Utxos,
            Outputs,
            20 + totalAssets
        )
        const inputs = selection.input;
        const txBuilder = CSL.TransactionBuilder.new(
            CSL.LinearFee.new(
                CSL.BigNum.from_str(ProtocolParameter.linearFee.minFeeA),
                CSL.BigNum.from_str(ProtocolParameter.linearFee.minFeeB)
            ),
            CSL.BigNum.from_str(ProtocolParameter.minUtxo.toString()),
            CSL.BigNum.from_str(ProtocolParameter.poolDeposit.toString()),
            CSL.BigNum.from_str(ProtocolParameter.keyDeposit.toString()),
            MULTIASSET_SIZE,
            MULTIASSET_SIZE
        );

        for (let i = 0; i < inputs.length; i++) {
            const utxo = inputs[i]
            txBuilder.add_input(
              utxo.output().address(),
              utxo.input(),
              utxo.output().amount()
            )
        }

        if(Delegation){
            const certificates = CSL.Certificates.new();
            if (!Delegation.delegation.active){
                certificates.add(
                    CSL.Certificate.new_stake_registration(
                        CSL.StakeRegistration.new(
                            CSL.StakeCredential.from_keyhash(
                                CSL.Ed25519KeyHash.from_bytes(
                                    Buffer.from(Delegation.stakeKeyHash, 'hex')
                                )
                            )
                        )
                    )
                )
            }
            
            let poolKeyHash = Delegation.poolHex
            certificates.add(
                CSL.Certificate.new_stake_delegation(
                  CSL.StakeDelegation.new(
                    CSL.StakeCredential.from_keyhash(
                      CSL.Ed25519KeyHash.from_bytes(
                        Buffer.from(Delegation.stakeKeyHash, 'hex')
                      )
                    ),
                    CSL.Ed25519KeyHash.from_bytes(
                      Buffer.from(poolKeyHash, 'hex')
                    )
                  )
                )
            );
            txBuilder.set_certs(certificates)
        }


        let AUXILIARY_DATA
        if(Metadata){
            let METADATA = CSL.GeneralTransactionMetadata.new()
            METADATA.insert(
                CSL.BigNum.from_str(MetadataLabel),
                CSL.encode_json_str_to_metadatum(JSON.stringify(Metadata),0)
            )
            AUXILIARY_DATA = CSL.AuxiliaryData.new()
            AUXILIARY_DATA.set_metadata(METADATA)
            txBuilder.set_auxiliary_data(AUXILIARY_DATA)
        }
        
        for(let i=0; i<Outputs.len(); i++){
            txBuilder.add_output(Outputs.get(i))
        }        

        const change = selection.change
        const changeMultiAssets = change.multiasset()

        // check if change value is too big for single output
        if (changeMultiAssets && change.to_bytes().length * 2 > VALUE_SIZE) {
            const partialChange = CSL.Value.new(CSL.BigNum.from_str('0'))
        
            const partialMultiAssets = CSL.MultiAsset.new()
            const policies = changeMultiAssets.keys()

            const makeSplit = () => {

                for (let j = 0; j < changeMultiAssets.len(); j++) {
                    const policy = policies.get(j)
                    const policyAssets = changeMultiAssets.get(policy)
                    
                    if(policyAssets){
                        const assetNames = policyAssets.keys()
                        const assets = CSL.Assets.new()
                        
                        for (let k = 0; k < assetNames.len(); k++) {
                            
                            const policyAsset = assetNames.get(k)
                            const quantity = policyAssets.get(policyAsset)
                            assets.insert(policyAsset, quantity)

                            //check size
                            const checkMultiAssets = CSL.MultiAsset.from_bytes(partialMultiAssets.to_bytes())
                            checkMultiAssets.insert(policy, assets)
                            const checkValue = CSL.Value.new(CSL.BigNum.from_str('0'))
                            checkValue.set_multiasset(checkMultiAssets)

                            if (checkValue.to_bytes().length * 2 >= VALUE_SIZE) {
                                partialMultiAssets.insert(policy, assets)
                                return
                            }
                        }
                        partialMultiAssets.insert(policy, assets)
                    }                  
                }
            }

            makeSplit()
            partialChange.set_multiasset(partialMultiAssets);

            const minAda = CSL.min_ada_required(partialChange,CSL.BigNum.from_str(ProtocolParameter.minUtxo))
            partialChange.set_coin(minAda)

            txBuilder.add_output(CSL.TransactionOutput.new(CSL.Address.from_bech32(PaymentAddress),partialChange))
        }

        txBuilder.add_change_if_needed(CSL.Address.from_bech32(PaymentAddress))

        const transaction = CSL.Transaction.new(txBuilder.build(),CSL.TransactionWitnessSet.new(),AUXILIARY_DATA)

        const size = transaction.to_bytes().length * 2

        if (size > ProtocolParameter.maxTxSize) throw ERROR.TX_TOO_BIG

        return transaction.to_bytes()
    }

    const __signSubmitTx = async (transactionRaw) => {
        const transaction = CSL.Transaction.from_bytes(transactionRaw)
        const witneses = await Wallet.signTx(Buffer.from(transaction.to_bytes()).toString('hex'))

        const signedTx = CSL.Transaction.new(transaction.body(),CSL.TransactionWitnessSet.from_bytes(Buffer.from(witneses,"hex")),transaction.auxiliary_data())

        const txhash = await Wallet.submitTx(Buffer.from(signedTx.to_bytes()).toString('hex'))

        return txhash
    }

    const __getProtocolParameter = async () => {
        const latestBlock = await _blockfrostRequest("/blocks/latest")
        if(!latestBlock) throw ERROR.FAILED_PROTOCOL_PARAMETER

        let p = await _blockfrostRequest(`/epochs/${latestBlock.epoch}/parameters`) 
        if(!p) throw ERROR.FAILED_PROTOCOL_PARAMETER

        return {
            linearFee: {
              minFeeA: p.min_fee_a.toString(),
              minFeeB: p.min_fee_b.toString(),
            },
            minUtxo: '1000000', 
            /*
            p.min_utxo, minUTxOValue protocol paramter has been removed since Alonzo HF. Calulation of minADA works differently now, but 1 minADA still sufficient for now
            */
            poolDeposit: p.pool_deposit,
            keyDeposit: p.key_deposit,
            maxTxSize: p.max_tx_size, 
            slot: latestBlock.slot,
          }
    }

    const __blockfrostRequest = async (endpoint) => {
        
        const networkId = await (await getNetworkId()).id

        const networkEndpoint = networkId == 0 ? 
        'https://cardano-testnet.blockfrost.io/api/v0': 
        'https://cardano-mainnet.blockfrost.io/api/v0'

        try {

            return await (await fetch(`${networkEndpoint}${endpoint}`,{headers: {project_id: blockfrostApiKey}})).json()

        } catch (error) { return null }

    }
    
    return wallet_api
}