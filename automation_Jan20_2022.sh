#!/bin/bash


echo -n "Do you want to start the main Federated Learning Program?"

read -r answer

if [ $answer = "yes" ]; then
  	echo "Starting the main program. Deploy chaincode"
	(cd /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/demo/;CC_ID=main scripts/installCC_useme.sh)
else
	echo "Exiting"
	exit 1
fi

echo -n "Do you want to start signSGD?"
read -r answer

echo -n "How many chaincodes?"
read chaincodeCount
echo -n "How many rounds?"
read rounds
# Store chaincodeCount AND id in main chaincode
echo -n "Deploying..."
chaincodeCountSplit="$chaincodeCount"
while [ "$chaincodeCount" -ge 1 ]; do
	echo "Deploying chaincode $chaincodeCount"
	(cd /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/demo/;CC_ID=signsgd_${chaincodeCount} scripts/installCC_useme.sh)
        chaincodeCount=$(( chaincodeCount - 1 ))
done
sh deployProgram.sh $chaincodeCountSplit signsgd $rounds &


echo -n "Do you want to start fedAVG?"
read -r answer
#
echo -n "How many chaincodes?"
read -r chaincodeCount
echo -n "How many rounds?"
read rounds
# Store chaincodeCount AND id in main chaincode AND Number of rounds. 
echo -n "Deploying..."
chaincodeCountSplit="$chaincodeCount"
while [ "$chaincodeCount" -ge 1 ]; do
        echo "Deploying chaincode $chaincodeCount"
        (cd /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/demo/;CC_ID=fedavg_${chaincodeCount} scripts/installCC_useme.sh)
        chaincodeCount=$(( chaincodeCount - 1 ))
done
sh deployProgram.sh $chaincodeCountSplit fedavg $rounds &
## Write Deploy program
## Functionality. Deploy, then concontinuously probe if complete. If complete, send aggregated parameters to main. Reset child chaincodes AND Round 2 starts
## Write program to send parameters. 
## Inside chaincode, once it gets all the inputs, then run the aggregation
## Main will keep the results, publicly readable. GET Results from child chaincode and store in MAIN chaincode
#
echo -n "Do you want to start coMED?"
read -r answer
#
echo -n "How many chaincodes?"
read -r chaincodeCount
echo -n "How many rounds?"
read rounds
## Store chaincodeCount AND id in main chaincode
echo -n "Deploying..."
chaincodeCountSplit="$chaincodeCount"
while [ "$chaincodeCount" -ge 1 ]; do
        echo "Deploying chaincode $chaincodeCount"
        (cd /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/demo/;CC_ID=comed_${chaincodeCount} scripts/installCC_useme.sh)
        chaincodeCount=$(( chaincodeCount - 1 ))
done
sh deployProgram.sh $chaincodeCountSplit comed $rounds &

