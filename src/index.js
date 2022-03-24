import * as csl from '@emurgo/cardano-serialization-lib-asmjs'

const wallets_compatible = [
    'nami',
    'ccvault',
    'yoroi',
    'eternl',
]
/**
 * 
 * @param {window.cardano obj} cardano_window 
 * @param {String} walletName 
 * @returns {Wallet Object}
 */
export async function searchForWallet (cardano_window, walletName) {
    // Look if wallet is installed and compatible
    let found = wallets_compatible.find(e => e === walletName && cardano_window.hasOwnProperty(walletName))
    if(found){
        let wallet = cardano_window[walletName]
        wallet = await wallet.enable()
        return wallet
    }else{ throw new Error('Compatible Wallet Not Found') }
}
/**
 * 
 * @param {cardano wallet enabled object} wallet 
 * @param {String} blockfost_api 
 * @param {Cardano Serialization Lib WASM} WASM 
 */
export async function wallet(wallet, blockfost_api, WASM=null){
 if(WASM !== null) csl = WASM

}