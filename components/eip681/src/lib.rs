//! Parser for [EIP-681](https://eips.ethereum.org/EIPS/eip-681) transaction requests.
//!
//! ## ABNF Syntax
//!
//! ```abnf
//! request          = schema_prefix target_address [ "@" chain_id ] [ "/" function_name ] [ "?" parameters ]
//! schema_prefix    = "ethereum" ":" [ "pay-" ]
//! target_address   = ethereum_address
//! chain_id         = 1*DIGIT
//! function_name    = STRING
//! ethereum_address = ( "0x" 40*HEXDIG ) / ENS_NAME
//! parameters       = parameter *( "&" parameter )
//! parameter        = key "=" value
//! key              = "value" / "gas" / "gasLimit" / "gasPrice" / TYPE
//! value            = number / ethereum_address / STRING
//! number           = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
//! ```
//!
//! TODO(schell):
//! * [ ] request          
//! * [ ] schema_prefix    
//! * [x] target_address   
//! * [ ] chain_id         
//! * [ ] function_name    
//! * [x] ethereum_address
//! * [ ] parameters       
//! * [ ] parameter        
//! * [ ] key              
//! * [x] value            
//! * [x] number           

mod parse;
