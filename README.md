This code is for illustrating the creation of a transaction on ethereum based chain with corresponding chainID.

to use this code you have to set 'toAddress', 'nounce', 'amount', 'gasPrice', 'chainID', 'signersPublicKey'
then run main to get 'legacy hashMsg' corresponding variable would be 'rlphash'

sign the message(In my case i used a hardware wallet)

get the Derformat of signature illustrated 

sign='304\\*022\\*rrrrrrrrr022*sssssssss';
\\* can be anything depending on your signatures length 
rrrrrr is Rx or r of the signature and ssssss is s of the signature

replace sign with the signature of your own hashMsg and run main again without changin anything. your transaction would be 'legacy transaction' corresponding variable would be 'signedRlp' in byte array format.

eip1559 version of this code has insufficient funds error.
feel free to use this code with mentioning the origin of it.
sorry for messy coding it was meant to be for just testing.
