import * as csl from '@emurgo/cardano-serialization-lib-asmjs'

const wallets_compatible = [
    'nami',
    'ccvault',
    'yoroi',
    'eternl',
]
export async function searchForWallet (cardano_window, walletName) {
    // Look if wallet is installed and compatible
    let found = wallets_compatible.find(e => e === walletName && cardano_window.hasOwnProperty(walletName))
    if(found){
        let wallet = cardano_window[walletName]
        wallet = await wallet.enable()
        return wallet
    }else{ throw new Error('Compatible Wallet Not Found') }
}

export async function wallet(wallet){
    
}