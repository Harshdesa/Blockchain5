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
#include<sstream>
#include <algorithm>
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

#define RSA_MOD_SIZE 384 //hardcode n size to be 384
#define RSA_E_SIZE 4 //hardcode e size to be 4
#define BN_CHECK_BREAK(x)  if((x == NULL) || (BN_is_zero(x))){break;}
#ifndef NULL_BREAK
#define NULL_BREAK(x)   if(!x){break;}
#endif //NULL_BREAK
#define MAX_VALUE_SIZE 1024

vector<vector<string>> uploadedSIGNSGDParams;
vector<vector<string>> uploadedFEDAVGParams;
vector<vector<string>> uploadedCOMEDParams;

vector<string> strtovec(std::string s) {

	vector<string> result;
	std::string delimiter = ",";
	size_t pos = 0;
	std::string token;
	while ((pos = s.find(delimiter)) != std::string::npos) {
    		token = s.substr(0, pos);
      		result.push_back(token);
    		s.erase(0, pos + delimiter.length());
	}
   return result;
}

std::string reset(shim_ctx_ptr_t ctx) {
	uploadedSIGNSGDParams.clear();	
	uploadedFEDAVGParams.clear();
	uploadedCOMEDParams.clear();
	return "All data deleted";
	// clear out the uploaded double array
}

vector<string> processSIGNSGD() {
	vector<string> finalResult;
	for (int k =0; k < 5; k++) {   // This is the number of parameters
		int storeinFinal = 0;
		for (int i=0; i < uploadedSIGNSGDParams.size(); i++) {    // This is the total number of users
			vector<string> intermediateholdervec = uploadedSIGNSGDParams.at(i);
			int num = stoi(intermediateholdervec.at(k));
			storeinFinal = storeinFinal + num;
        	}
		if (storeinFinal > uploadedSIGNSGDParams.size() / 2) {   // Majority
			storeinFinal = 1;
		} else {
			storeinFinal = 0;
		}
		finalResult.push_back(std::to_string(storeinFinal));
	}
	return finalResult;

}

vector<string> processFEDAVG() {
	vector<string> finalResult;
        for (int k =0; k < 5; k++) {   // This is the number of parameters
                int storeinFinal = 0;
                for (int i=0; i < uploadedFEDAVGParams.size(); i++) {    // This is the total number of users
                        vector<string> intermediateholdervec = uploadedFEDAVGParams.at(i);
                        int num = stoi(intermediateholdervec.at(k));
                        storeinFinal = storeinFinal + num;
                }
		if (uploadedFEDAVGParams.size() == 0) {
			storeinFinal = 0;
		} else {
			storeinFinal = storeinFinal/uploadedFEDAVGParams.size() ; 
		}
		finalResult.push_back(std::to_string(storeinFinal));
        }
        return finalResult;
}

vector<string> processCOMED() {
	vector<string> finalResult;
	vector<int> vectorofints;
        for (int k =0; k < 5; k++) {   // This is the number of parameters
                int storeinFinal = 0;
                for (int i=0; i < uploadedCOMEDParams.size(); i++) {    // This is the total number of users
                        vector<string> intermediateholdervec = uploadedCOMEDParams.at(i);
                        int num = stoi(intermediateholdervec.at(k));
			vectorofints.push_back(num);
                }
		std::sort (vectorofints.begin(), vectorofints.begin()+uploadedCOMEDParams.size());
		storeinFinal = vectorofints.at(uploadedCOMEDParams.size()/2);
		vectorofints.clear();
                finalResult.push_back(std::to_string(storeinFinal));
        }
        return finalResult;
}

std::string vectostr(vector<string> s) {
	
	std::string result = "";
	result = result + s.at(0);
	for (int i=1; i < s.size(); i++) {
		result = result + "#" + s.at(i);
	}
	return result;
}


std::string uploadParametersSIGNSGD(std::string param, shim_ctx_ptr_t ctx){

        // convert string to vector strings
	
	vector<string> userparam = strtovec(param);
	uploadedSIGNSGDParams.push_back(userparam);
	return vectostr(userparam);
}

std::string uploadParametersFEDAVG(std::string param, shim_ctx_ptr_t ctx){
	vector<string> userparam = strtovec(param);
        uploadedFEDAVGParams.push_back(userparam);
        return vectostr(userparam);
}

std::string uploadParametersCOMED(std::string param, shim_ctx_ptr_t ctx){
	vector<string> userparam = strtovec(param);
        uploadedCOMEDParams.push_back(userparam);
        return vectostr(userparam);
}

std::string getFinalSIGNSGD(shim_ctx_ptr_t ctx){

	vector<string> result = processSIGNSGD(); // This is the main processing function
	return vectostr(result); 
}

std::string getFinalFEDAVG(shim_ctx_ptr_t ctx){

	vector<string> result = processFEDAVG();
	return vectostr(result);
}


std::string getFinalCOMED(shim_ctx_ptr_t ctx){

	vector<string> result = processCOMED();
        return vectostr(result);
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

    if (function_name == "uploadParametersSIGNSGD")
    {
	std::string signsgdparam = params[0];
	result = uploadParametersSIGNSGD(signsgdparam, ctx);
    }
    else if (function_name == "uploadParametersFEDAVG")
    {
	std::string fedavgparam = params[0];
	result = uploadParametersFEDAVG(fedavgparam, ctx);
    }
    else if (function_name == "uploadParametersCOMED")
    {
	std::string comedparam = params[0];
        result = uploadParametersCOMED(comedparam, ctx);
    }
    else if (function_name == "getFinalSIGNSGD")
    {
	result = getFinalSIGNSGD(ctx);
    }
    else if (function_name == "getFinalFEDAVG")
    {
	result = getFinalFEDAVG(ctx);
    }
    else if (function_name == "getFinalCOMED")
    {
        result = getFinalCOMED(ctx);
    }
    else if (function_name == "reset")
    {
	result = reset(ctx);
    }
    else
    {
        LOG_DEBUG("Harsh: RECEIVED UNKNOWN transaction '%s'", function_name);
        return -1;
    }

    int neededSize = result.size();
    if (max_response_len < neededSize)
    {
        *actual_response_len = 0;
        return -1;
    }
    memcpy(response, result.c_str(), neededSize);
    *actual_response_len = neededSize;
    return 0;
}
