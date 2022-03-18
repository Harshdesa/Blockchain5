#!/bin/bash

ALG=$2
ROUNDS=$3

while [ $ROUNDS -ge 1 ];
do
	echo "STARTING ROUND # $ROUNDS FOR ${ALG}"
	docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n main -c '{"Args":["setRound","'${ALG}'","'${ROUNDS}'"]}' 2>&1
	COUNT=$1
	
	
	while [ $COUNT -ge 1 ];
	do
		echo "Probing if ${ALG}_$COUNT is complete."
		# Upload Parameters
		UPLOADFUNC=`echo s`
		if [ "$ALG" = "signsgd" ]; then
                        UPLOADFUNC=`echo uploadParametersSIGNSGD`
		elif [ "$ALG" = "fedavg" ]; then
                        UPLOADFUNC=`echo uploadParametersFEDAVG`
		elif [ "$ALG" = "comed" ]; then
                        UPLOADFUNC=`echo uploadParametersCOMED`
		fi
		docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n ${ALG}_$COUNT -c '{"Args":["'${UPLOADFUNC}'","1,1,1,1,1,1,1"]}'
		docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n ${ALG}_$COUNT -c '{"Args":["'${UPLOADFUNC}'","1,1,1,1,1,1,1"]}'
		docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n ${ALG}_$COUNT -c '{"Args":["'${UPLOADFUNC}'","1,1,1,1,1,1,1"]}'
		# replace signsgd_1 with ${ALG}_$COUNT
		BASE64_STATUS=`docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n ${ALG}_$COUNT -c '{"Args":["getStatus"]}' 2>&1 | grep -o -P '(?<=ResponseData\\\"\:\\\").*(?=\\\"\,\\\"Signature)'`
 		STATUS=`echo -n $BASE64_STATUS | base64 --decode`
 		echo $STATUS
 		if [ "$STATUS" = "1" ]; then
   			COUNT=$(( COUNT - 1 ))
 		fi
	done
	ROUNDS=$(( ROUNDS - 1 ))



	echo "Please Download Round # $ROUNDS model for ${ALG}. Resetting for the next round"
	COUNT=$1
        while [ $COUNT -ge 1 ];
        do
		docker exec -e CORE_PEER_LOCALMSPID=Org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp peer0.org1.example.com env TERM=${TERM} /project/src/github.com/hyperledger-labs/fabric-private-chaincode/fabric/bin/peer.sh chaincode invoke -o orderer.example.com:7050 -C mychannel -n ${ALG}_$COUNT -c '{"Args":["reset"]}'
		COUNT=$(( COUNT - 1 ))
	done
done

exit 1
