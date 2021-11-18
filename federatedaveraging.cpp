using namespace std;
#include "enclave_t.h"
#include "base64/base64.h"
#include "utils.h"
#include <assert.h>

#include "shim.h"
#include <map>
#include <sstream>
#include "logging.h"
#include <string>
#include <ctime>
#include <cstring>
#include <iostream>
#include <ostream>
#include<vector>
#include <iomanip>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <math.h>
#include <random>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <UniquePtr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

std::map<int, std::pair<std::string, int>> bids;
#define OK "OK"
#define NOT_FOUND "Bid not found"
#define RSA_MOD_SIZE 384 //hardcode n size to be 384
#define RSA_E_SIZE 4 //hardcode e size to be 4
#define BN_CHECK_BREAK(x)  if((x == NULL) || (BN_is_zero(x))){break;}
#ifndef NULL_BREAK
#define NULL_BREAK(x)   if(!x){break;}
#endif //NULL_BREAK
#define MAX_VALUE_SIZE 1024
int user_count = 0;
std::map<int, std::string> usernames;

std::map<int, std::pair<std::string, int>> record;


std::string to_PEM(EVP_PKEY *pkey) {

    BIO *bio = NULL;
    char *pem = NULL;

    if (NULL == pkey) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return NULL;
    }

    pem = (char *) malloc(BIO_number_written(bio) + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;    
    }

    memset(pem, 0, BIO_number_written(bio) + 1);
    BIO_read(bio, pem, BIO_number_written(bio));
    BIO_free(bio);

    std::string s = "";
    int c = 0;
    while(pem[c] != NULL) {
                s.append(1, pem[c]);
                ++c;
    }
    return s;
}

std::string to_PEM_private(EVP_PKEY *pkey) {

    BIO *bio = NULL;
    char *pem = NULL;

    if (NULL == pkey) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL)) {
        BIO_free(bio);
        return NULL;
    }

    pem = (char *) malloc(BIO_number_written(bio) + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;
    }

    memset(pem, 0, BIO_number_written(bio) + 1);
    BIO_read(bio, pem, BIO_number_written(bio));
    BIO_free(bio);

    std::string s = "";
    int c = 0;
    while(pem[c] != NULL) {
                s.append(1, pem[c]);
                ++c;
    }
    return s;
}


std::string printpublickey(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1)
{
	if (new_pub_key1 == NULL || mod_size <= 0 || exp_size <= 0 || le_n == NULL || le_e == NULL) {
		return "SGX_ERROR_INVALID_PARAMETER";
	}

	EVP_PKEY *dst_pkey = EVP_PKEY_new();
	EVP_PKEY *rsa_key = NULL;
	RSA *rsa_ctx = NULL;
	sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
	BIGNUM* n = NULL;
	BIGNUM* e = NULL;

	do {
		//convert input buffers to BNs
		//
		n = BN_lebin2bn(le_n, mod_size, n);
		BN_CHECK_BREAK(n);
		e = BN_lebin2bn(le_e, exp_size, e);
		BN_CHECK_BREAK(e);

		// allocates and initializes an RSA key structure
		//
		rsa_ctx = RSA_new();
		rsa_key = EVP_PKEY_new();

		if (rsa_ctx == NULL || rsa_key == NULL || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx)) {
			RSA_free(rsa_ctx);
			rsa_ctx = NULL;
			break;
		}

		//set n, e values of RSA key
		//Calling set functions transfers the memory management of input BNs to the RSA object,
		//and therefore the values that have been passed in should not be freed by the caller after these functions has been called.
		//
		if (!RSA_set0_key(rsa_ctx, n, e, NULL)) {
			break;
		}

		RSA *rsa = EVP_PKEY_get1_RSA(rsa_key); // Get the underlying RSA key
    		RSA *dup_rsa = RSAPublicKey_dup(rsa); // Duplicate the RSA key
		RSA_free(rsa);
    		EVP_PKEY_set1_RSA(dst_pkey, dup_rsa);
		RSA_free(dup_rsa);

		*new_pub_key1 = rsa_key;
		ret_code = SGX_SUCCESS;
	} while (0);

	std::string test = to_PEM(dst_pkey);

	if (ret_code != SGX_SUCCESS) {
		EVP_PKEY_free(rsa_key);
		BN_clear_free(n);
		BN_clear_free(e);
	}

	return test;
}


std::string printprivatekey(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
	const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
	void **new_pri_key2)
{
	if (mod_size <= 0 || exp_size <= 0 || new_pri_key2 == NULL ||
		p_rsa_key_e == NULL || p_rsa_key_p == NULL || p_rsa_key_q == NULL || p_rsa_key_dmp1 == NULL ||
		p_rsa_key_dmq1 == NULL || p_rsa_key_iqmp == NULL) {
		return "SGX_ERROR_INVALID_PARAMETER";
	}

	bool rsa_memory_manager = 0;
	EVP_PKEY *rsa_key = NULL;
	EVP_PKEY *dst_pkey = EVP_PKEY_new();
	RSA *rsa_ctx = NULL;
	sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
	BIGNUM* n = NULL;
	BIGNUM* e = NULL;
	BIGNUM* d = NULL;
	BIGNUM* dmp1 = NULL;
	BIGNUM* dmq1 = NULL;
	BIGNUM* iqmp = NULL;
	BIGNUM* q = NULL;
	BIGNUM* p = NULL;
	BN_CTX* tmp_ctx = NULL;

	do {
		tmp_ctx = BN_CTX_new();
		NULL_BREAK(tmp_ctx);
		n = BN_new();
		NULL_BREAK(n);

		// convert RSA params, factors to BNs
		//
		p = BN_lebin2bn(p_rsa_key_p, (mod_size / 2), p);
		BN_CHECK_BREAK(p);
		q = BN_lebin2bn(p_rsa_key_q, (mod_size / 2), q);
		BN_CHECK_BREAK(q);
		dmp1 = BN_lebin2bn(p_rsa_key_dmp1, (mod_size / 2), dmp1);
		BN_CHECK_BREAK(dmp1);
		dmq1 = BN_lebin2bn(p_rsa_key_dmq1, (mod_size / 2), dmq1);
		BN_CHECK_BREAK(dmq1);
		iqmp = BN_lebin2bn(p_rsa_key_iqmp, (mod_size / 2), iqmp);
		BN_CHECK_BREAK(iqmp);
		e = BN_lebin2bn(p_rsa_key_e, (exp_size), e);
		BN_CHECK_BREAK(e);

		// calculate n value
		//
		if (!BN_mul(n, p, q, tmp_ctx)) {
			break;
		}

		//calculate d value
		//ϕ(n)=(p−1)(q−1)
		//d=(e^−1) mod ϕ(n)
		//
		d = BN_dup(n);
		NULL_BREAK(d);

		//select algorithms with an execution time independent of the respective numbers, to avoid exposing sensitive information to timing side-channel attacks.
		//
		BN_set_flags(d, BN_FLG_CONSTTIME);
		BN_set_flags(e, BN_FLG_CONSTTIME);

		if (!BN_sub(d, d, p) || !BN_sub(d, d, q) || !BN_add_word(d, 1) || !BN_mod_inverse(d, e, d, tmp_ctx)) {
			break;
		}

		// allocates and initializes an RSA key structure
		//
		rsa_ctx = RSA_new();
		rsa_key = EVP_PKEY_new();

                //EVP_PKEY_assign_RSA() use the supplied key internally and so if this call succeed, key will be freed when the parent pkey is freed.
                //
		if (rsa_ctx == NULL || rsa_key == NULL || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx)) {
			RSA_free(rsa_ctx);
			rsa_key = NULL;
			break;
		}

		//setup RSA key with input values
		//Calling set functions transfers the memory management of the values to the RSA object,
		//and therefore the values that have been passed in should not be freed by the caller after these functions has been called.
		//
		if (!RSA_set0_factors(rsa_ctx, p, q)) {
			break;
		}
		rsa_memory_manager = 1;
		if (!RSA_set0_crt_params(rsa_ctx, dmp1, dmq1, iqmp)) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(dmp1);
			BN_clear_free(dmq1);
			BN_clear_free(iqmp);
			break;
		}

		if (!RSA_set0_key(rsa_ctx, n, e, d)) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			break;
		}

                //RSA *rsa = EVP_PKEY_get1_RSA(rsa_key); // Get the underlying RSA key
                //RSA *dup_rsa = RSAPrivateKey_dup(rsa); // Duplicate the RSA key
		//EVP_PKEY_assign_RSA(dst_pkey, dup_rsa);
                //EVP_PKEY_set1_RSA(dst_pkey, dup_rsa);
		*new_pri_key2 = rsa_key;
		ret_code = SGX_SUCCESS;
	} while (0);

	BN_CTX_free(tmp_ctx);

	std::string test = to_PEM_private(rsa_key);

	//in case of failure, free allocated BNs and RSA struct
	//
	if (ret_code != SGX_SUCCESS) {
		//BNs were not assigned to rsa ctx yet, user code must free allocated BNs
		//
		if (!rsa_memory_manager) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(dmp1);
			BN_clear_free(dmq1);
			BN_clear_free(iqmp);
			BN_clear_free(q);
			BN_clear_free(p);
		}
		//EVP_PKEY_free(rsa_key);
	}

	return test;
}

type Payload struct {
	Parameters []float64
}

type Metadata struct {
        Subparty []string
}


// Init is called during chaincode instantiation to initialize any
// data. Note that chaincode upgrade also calls this function to reset
// or to migrate data.
func (t *SimpleAsset) Init(ctx contractapi.TransactionContextInterface, NodeA string, NodeAParameters[] float64) error {

 
	fmt.Printf("NodeAParameters = %s", NodeAParameters)
	// Write the state to the ledger

        NodeAPayloadJson := Payload{
		Parameters: NodeAParameters,
	}

        NodeASubparty := []string {NodeA+"0"}
        NodeAMetadataJson := Metadata{
                Subparty: NodeASubparty,
        }
	NodeAPayload, err := json.Marshal(NodeAPayloadJson)
        NodeAMetadata, err := json.Marshal(NodeAMetadataJson)
	err = ctx.GetStub().PutState(NodeAMetadataJson.Subparty[0], NodeAPayload)
        err = ctx.GetStub().PutState(NodeA, NodeAMetadata)
        if err != nil {
          return err
        }

	return nil

}


func (t *SimpleAsset) Invoke(ctx contractapi.TransactionContextInterface, NodeNames [] string, ResultNodeName string, beg int, end int) error {
	// Extract the function and args from the transaction proposal
        //var err error
        var ResultParameters []float64
        ResultParameters = make([]float64, 4687500, 4687500)
        ResultParameters = nil
        
        allNodesMetadata := []Metadata{}
        allNodesMetadata = make([]Metadata, 10, 10)
        allNodesMetadata = nil

        //STORE METADATA
        for i := 0; i < len(NodeNames) ; i++ {
          NodeMetadataBytes, err := ctx.GetStub().GetState(NodeNames[i])
          //fmt.Printf("NodeMetadataBytes: %b\n\n", NodeMetadataBytes )
          if err != nil {
                return fmt.Errorf("Failed to get state")
          }
          CurrentNodeMetadata := new(Metadata)
          _ = json.Unmarshal(NodeMetadataBytes, CurrentNodeMetadata)
          allNodesMetadata = append(allNodesMetadata, *CurrentNodeMetadata)
        }

        //GET NUMBER OF WORKER NODES
        numberOfNodes := len(allNodesMetadata)
        fmt.Printf("Number of nodes: %d\n\n", numberOfNodes)

        if len(allNodesMetadata[0].Subparty) == len(allNodesMetadata[1].Subparty) {
 
          var ResultSubparties []string
          ResultSubparties = make([]string, 4687500, 4687500)
          ResultSubparties = nil
          if (beg != 0) {
            ResultNodeMetadataBytes, err := ctx.GetStub().GetState(ResultNodeName)
            if err != nil {
                return fmt.Errorf("Failed to get state")
            }
            CurrentResultNodeMetadata := new(Metadata) 
            _ = json.Unmarshal(ResultNodeMetadataBytes, CurrentResultNodeMetadata)
            ResultSubparties = append(ResultSubparties, CurrentResultNodeMetadata.Subparty...)
          }

          //FOR EACH BATCH OF INPUTS
          for batchNumber := beg; batchNumber < end ; batchNumber++ {
            var batch []Payload
            batch = make([]Payload, 10, 10)
            batch = nil

            for nodeNumber := 0; nodeNumber < numberOfNodes; nodeNumber++ {
              Avalbytes, err := ctx.GetStub().GetState(allNodesMetadata[nodeNumber].Subparty[batchNumber])
              if err != nil {
                return fmt.Errorf("Failed to get state")
              }
              tempBatchbytes := new(Payload)
              _ = json.Unmarshal(Avalbytes, tempBatchbytes)
              batch = append(batch, *tempBatchbytes)
            }

            //For each 8 bit Parameter in a Batch
            for i := 0; i < len(batch[0].Parameters) ; i++ {
              var finalParameter float64 = 0.0

                //For each worker node
                for nodeNumber := 0; nodeNumber < numberOfNodes; nodeNumber++ {
                  finalParameter = finalParameter + batch[nodeNumber].Parameters[i]
                  //TRACE LOG
                  //fmt.Printf("aggregateParameter after & with node %d : %f\n", nodeNumber, finalParameter)
                }
                // END of for each worker node || aggregateParameter is addition of all the bits
                finalParameter = finalParameter / float64(numberOfNodes)
                   //TRACE LOG
                   //fmt.Printf("Final Number : %f\n", finalParameter)
              //END of For each Bit of the 64 bit Parameter || finalMajorityUINT64Parameter is the majority
              //fmt.Printf("Final Number : %f\n", finalParameter)
              ResultParameters = append(ResultParameters, finalParameter)
              //fmt.Printf("length of ResultParameters[%d] : %b",i,ResultParameters[i])
              //fmt.Printf("Subparty: %d",batchNumber)
            }
            //END of For each 64 bit Parameter in a Batch || finalMajorityUINT64Parameter is loaded into ResultParameters

            CurrentResultSubparty := []string {ResultNodeName + strconv.Itoa(batchNumber)}
            ResultNodePayloadJson := Payload{
                Parameters: ResultParameters,
            }
            ResultNodePayload, err := json.Marshal(ResultNodePayloadJson)
            if err != nil {
                 fmt.Println("error:", err)
            }
            ResultSubparties = append(ResultSubparties, CurrentResultSubparty...)
            err = ctx.GetStub().PutState(CurrentResultSubparty[0], ResultNodePayload)
            ResultParameters = nil
          }
          //END of for each Batch of Inputs || Batches of Parameters are loaded

          ResultNodeMetadataJson := Metadata{
                Subparty: ResultSubparties,
          }
          ResultNodeMetadata, err := json.Marshal(ResultNodeMetadataJson)
          err = ctx.GetStub().PutState(ResultNodeName, ResultNodeMetadata)
          if err != nil {
                 fmt.Println("error:", err)
          }
        }
        return nil
}




std::string setParameters(shim_ctx_ptr_t ctx, std::string NodeName , float64 NodeParameters[]) {


        // Get the state from the ledger
        NodeMetadataBytes, err = ctx.GetStub().GetState(NodeName)
        if err != nil {
          return err
        }

        if NodeMetadataBytes == nil {

                NodePayloadJson = Payload{
                       Parameters: NodeParameters,
                }

                NodeBaseSubparty = []string {NodeName+"0"}
                NodeMetadataJson = Metadata{
                       Subparty: NodeBaseSubparty, 
                }
                NodePayload, err = json.Marshal(NodePayloadJson)
                NodeMetadata, err = json.Marshal(NodeMetadataJson)

                err = ctx.GetStub().PutState(NodeMetadataJson.Subparty[0], NodePayload)
                err = ctx.GetStub().PutState(NodeName, NodeMetadata)

                if err != nil {
                        return err
                }
        } else {
            CurrentNodeMetadata = new(Metadata)
            _ = json.Unmarshal(NodeMetadataBytes, CurrentNodeMetadata)

            var Subparties []string
            Subparties = make([]string, 4687500, 4687500)
            Subparties = CurrentNodeMetadata.Subparty
            SubpartyIndex = len(Subparties)
            CurrentSubparty = []string {NodeName + strconv.Itoa(SubpartyIndex)}
            Subparties = append(Subparties, CurrentSubparty...)

	    // Write the state to the ledger

            NodeMetadataJson = Metadata{
	    	Subparty: Subparties,
	    }

            NodePayloadJson = Payload{
                       Parameters: NodeParameters,
            }
	    NodeMetadata, err = json.Marshal(NodeMetadataJson)
            NodePayload, err = json.Marshal(NodePayloadJson)

	    err = ctx.GetStub().PutState(NodeName, NodeMetadata)
            err = ctx.GetStub().PutState(CurrentSubparty[0], NodePayload)
	    if err != nil {
		return err
	    }
       }
	return nil
}





void *private_key = NULL;
void *public_key = NULL;
std::string privatekeytoreturn = "";

std::string decryptMessage(std::string encryptedstring, shim_ctx_ptr_t ctx)
{
	std::string base64decoded = base64_decode(encryptedstring);

	auto chrs = base64decoded.c_str();
	auto uchrs = reinterpret_cast<unsigned char*>(const_cast<char*>(chrs));

	size_t decrypted_len = 0;


        if(sgx_rsa_priv_decrypt_sha256(private_key, NULL, &decrypted_len, uchrs, sizeof(uchrs)) != SGX_SUCCESS) {
                return "Failed decryption part 1";
        }

	std::string s = "";
        unsigned char decrypted_pout_data[decrypted_len];

        if(sgx_rsa_priv_decrypt_sha256(private_key, decrypted_pout_data, &decrypted_len, uchrs, sizeof(uchrs)) != SGX_SUCCESS) {
		return "Failed decryption part 2";
        }

        for(int i = 0; i<decrypted_len; i++) {
                s.append(1, decrypted_pout_data[i]);
        }

	return s;

}



std::string encryptMessage(std::string message, shim_ctx_ptr_t ctx)
{

	size_t pout_len = 0;

	auto chrs = message.c_str();
        auto pin_data = reinterpret_cast<unsigned char*>(const_cast<char*>(chrs));
	char* S1 = reinterpret_cast<char*>(pin_data);


        if(sgx_rsa_pub_encrypt_sha256(public_key, NULL, &pout_len, pin_data, strlen(S1)) != SGX_SUCCESS) {
                return "Failed encryption part 1";
        }

        unsigned char pout_data[pout_len];

        if(sgx_rsa_pub_encrypt_sha256(public_key, pout_data, &pout_len, pin_data, strlen(S1)) != SGX_SUCCESS) {
                return "Failed encryption part 2";
        }

	string s = "";
	for(int i = 0; i<pout_len; i++) {
                s.append(1, pout_data[i]);
        }
	 return s;

}

std::string printprivatekey(shim_ctx_ptr_t ctx)
{
	return privatekeytoreturn;
}



std::string createKeys(shim_ctx_ptr_t ctx)
{
	void *pk = NULL;
	void *prk = NULL;
	
	unsigned char p_n[384], p_d[384], p_p[384], p_q[384], p_dmp1[384], p_dmq1[384], p_iqmp[384]; 
	long p_e = 65537;


	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) != SGX_SUCCESS){
                return "Failed key pair creation";
        }

        if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &public_key) != SGX_SUCCESS) {
              return "Failed public key pair creation";
        }

        if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &private_key) != SGX_SUCCESS) {
              return "Failed private key pair creation";
        }

	std::string publickeytoreturn = printpublickey(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &pk);
	privatekeytoreturn = printprivatekey(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &prk);

	return publickeytoreturn;


}

std::string testRsaEncryption(shim_ctx_ptr_t ctx)
{
	void *public_key = NULL;
	void *private_key = NULL;

	unsigned char p_n[384], p_d[384], p_p[384], p_q[384], p_dmp1[384], p_dmq1[384], p_iqmp[384];
	long p_e = 65537;

	std::string s = "";

	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) != SGX_SUCCESS){
		return "failed creating key pair";
	}

	if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &public_key) != SGX_SUCCESS) {
		return "failed creating public key";
	}

	if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &private_key) != SGX_SUCCESS) {
		return "failed creating private key";
	}

	size_t pout_len = 0;

	char * pin_data = "Hello World!";

	if(sgx_rsa_pub_encrypt_sha256(public_key, NULL, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) != SGX_SUCCESS) {
		return "failed encryption part 1";
	}

	unsigned char pout_data[pout_len];

	if(sgx_rsa_pub_encrypt_sha256(public_key, pout_data, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) != SGX_SUCCESS) {
		return "failed encryption part 2";
        }

	size_t decrypted_len = 0;

	if(sgx_rsa_priv_decrypt_sha256(private_key, NULL, &decrypted_len, pout_data, sizeof(pout_data)) != SGX_SUCCESS) {
		return "failed decryption part 1";
	}

	unsigned char decrypted_pout_data[decrypted_len];

	if(sgx_rsa_priv_decrypt_sha256(private_key, decrypted_pout_data, &decrypted_len, pout_data, sizeof(pout_data)) != SGX_SUCCESS) {
		return "failed decryption part 2";
        }

	int c = 0;
	for(int i = 0; i<decrypted_len; i++) {
		s.append(1, decrypted_pout_data[i]);
	}

	return s;
}


std::string registerchaincode(shim_ctx_ptr_t ctx) {
	return "chaincode keys are created. stored in chaincode";
}

std::string declareresult(shim_ctx_ptr_t ctx) {
	return "chaincode signs and return results";
}

std::string verifyresult(shim_ctx_ptr_t ctx) {
	return "called by users to verify if the result is coming from chaincode or not";
}

std::string registeruser(shim_ctx_ptr_t ctx) {
	return "user keys created. stored in chaincode.";
}

std::string sign(std::string user, std::string message) {

	return "called by encrypt. Signature is saved";
}

std::string verify(std::string user, std::string message) {
	return "called by decrypt. sends an ok message";
}

std::string storeBid(std::string user_name, std::string bid_value, shim_ctx_ptr_t ctx)
{
	std::string returnStatusString = "";
	std::pair<std::string, int> BIDDER;
        BIDDER.first = user_name;
        BIDDER.second = stoi(bid_value);
	bids[user_count] = BIDDER;
	put_state(user_name.c_str(), (uint8_t*)bid_value.c_str(), bid_value.size(), ctx);
	usernames[user_count] = user_name;
	user_count = user_count + 1;
	return returnStatusString;
}

std::string retrieveAuctionResultSecondPrice(shim_ctx_ptr_t ctx)
{
    std::string bidString;
    std::string returnstatus = "";
    std::map<int, std::pair<std::string, int>> finalresult;
    std::pair<std::string, int> BIDDER;
    std::string username;
    int smax = 0;
    int max = 0;
    int maxid = 0;
    int smaxid = 0;
    int b = 0;
    //Retrieve all the bids
    for (int i = 0; i < user_count; i++) {
	char _value[128];
	uint32_t bid_bytes_len = -1;	
    	get_state(usernames[i].c_str(), (uint8_t*)_value, sizeof(_value) - 1, &bid_bytes_len, ctx);
	const char* value;
	_value[bid_bytes_len + 1] = '\0';
	value = _value;
	std::string bidString(value);
	int length = bidString.length();
	bidString = bidString.substr(0, length-1);
	int bid = stoi(bidString);
	BIDDER = bids[i];
	bid = BIDDER.second;
	username = BIDDER.first;

	// Obliviously retrieve the maximum
	//finalresult = oblivious(bid, username);
	b = maximum(smax, bid);
	smax = (1-b)*smax + b*bid;
	smaxid = (1-b)*smaxid + b*i;

	b = maximum(max, smax);
	int tempmax = max;
	int tempmaxid = maxid;
	max = (1-b)*max + b*smax;
	maxid = (1-b)*maxid + b*smaxid;

	smax = b*tempmax + (1-b)*smax;
	smaxid = b*tempmaxid + (1-b)*smaxid;


    }

    std::pair<std::string, int> BIDDERMAX, BIDDERSECONDMAX;
    BIDDERMAX = finalresult[0];
    BIDDERSECONDMAX = finalresult[1];


    returnstatus = returnstatus + " The winner is " + usernames[maxid];
    returnstatus = returnstatus + " And had originally bid " + std::to_string(max);
    returnstatus = returnstatus + " But pays the second price of " + usernames[smaxid];
    returnstatus = returnstatus + " That was bid by " + std::to_string(smax);
    return returnstatus;


}


std::string retrieveAuctionResultFirstPrice(shim_ctx_ptr_t ctx)
{
    std::string bidString;
    std::string returnstatus = "";
    std::map<int, std::pair<std::string, int>> finalresult;
    std::pair<std::string, int> BIDDER;
    std::string username;
    int max = 0;
    int maxid = 0;
    int b = 0;
    //Retrieve all the bids
    for (int i = 0; i < user_count; i++) {
	/* Bid Retrieval starts here */
        char _value[128];
        uint32_t bid_bytes_len = -1;
        get_state(usernames[i].c_str(), (uint8_t*)_value, sizeof(_value) - 1, &bid_bytes_len, ctx);
        const char* value;
        _value[bid_bytes_len + 1] = '\0';
        value = _value;
        std::string bidString(value);
        int length = bidString.length();
        bidString = bidString.substr(0, length-1);
        int bid = stoi(bidString);
        BIDDER = bids[i];
        bid = BIDDER.second;
        username = BIDDER.first;
	/* Bid retrieval ends here */

	/* Calculate maximum obliviously */
        b = maximum(max, bid);
        max = (1-b)*max + b*bid;
        maxid = (1-b)*maxid + b*i;
    }

    returnstatus = returnstatus + " The winner is " + usernames[maxid];
    returnstatus = returnstatus + " And has bid " + std::to_string(max);
    return returnstatus;
}

std::string storeBidMethodB(std::string user_name, std::string bid_value, shim_ctx_ptr_t ctx)
{

	std::string returnStatusString = "";
        std::map<int, std::pair<std::string, int>> finalresult;
	std::pair<std::string, int> BIDDER;
        BIDDER.first = user_name;
        BIDDER.second = stoi(bid_value);
        bids[user_count] = BIDDER;
        put_state(user_name.c_str(), (uint8_t*)bid_value.c_str(), bid_value.size(), ctx);
        usernames[user_count] = user_name;
        user_count = user_count + 1;
	finalresult = oblivious(BIDDER.second, BIDDER.first);
	return returnStatusString;
}

std::string retrieveAuctionResultMethodB(shim_ctx_ptr_t ctx)
{
	std::string returnstatus = "";
	std::pair<std::string, int> BIDDERMAX, BIDDERSECONDMAX;
    	BIDDERMAX = record[0];
    	BIDDERSECONDMAX = record[1];

    	returnstatus = returnstatus + " The winner is " + BIDDERMAX.first;
    	returnstatus = returnstatus + " And had originally bid " + std::to_string(BIDDERMAX.second);
    	returnstatus = returnstatus + " But pays the second price of " +std::to_string(BIDDERSECONDMAX.second);
    	returnstatus = returnstatus + " That was bid by " + BIDDERSECONDMAX.first;

	return returnstatus;
}

std::string decryptMessage_base64(std::string base64_pk, shim_ctx_ptr_t ctx)
{
	return base64_pk;
}

// implements chaincode logic for invoke
int invoke(
    uint8_t* response,
    uint32_t max_response_len,
    uint32_t* actual_response_len,
    shim_ctx_ptr_t ctx)
{

    std::string function_name;
    std::vector<std::string> params;
    get_func_and_params(function_name, params, ctx);
    std::string result;

    if (function_name == "asmTest")
    {
	result = asmTest(ctx);
    }
    else if (function_name == "storeBid")
    {
	std::string user_name = params[0];
	std::string value = params[1];
	result = storeBid(user_name, value, ctx);
    }
    else if (function_name == "storeBidMethodB")
    {
	std::string user_name = params[0];
	std::string value = params[1];
	result = storeBidMethodB(user_name, value, ctx);
    }
    else
    {
        // unknown function
        LOG_DEBUG("Harsh: RECEIVED UNKNOWN transaction '%s'", function_name);
        return -1;
    }

    // check that result fits into response
    int neededSize = result.size();
    if (max_response_len < neededSize)
    {
        // error:  buffer too small for the response to be sent
        *actual_response_len = 0;
        return -1;
    }

    // copy result to response
    memcpy(response, result.c_str(), neededSize);
    *actual_response_len = neededSize;
    LOG_DEBUG("Harsh: Response: %s", result.c_str());
    LOG_DEBUG("+++ Executing done +++");
    return 0;
}
