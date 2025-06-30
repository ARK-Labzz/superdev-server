use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
};
use solana_system_interface::instruction as system_instruction;
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};
use crate::types::*;

pub struct SolanaService;

impl SolanaService {
    pub fn generate_keypair() -> Result<KeypairData, String> {
        let keypair = Keypair::new();
        
        Ok(KeypairData {
            pubkey: keypair.pubkey().to_string(),
            secret: bs58::encode(keypair.to_bytes()).into_string(),
        })
    }

   
    pub fn create_token_instruction(request: &CreateTokenRequest) -> Result<InstructionData, String> {
     
        if request.mint.trim().is_empty() {
            return Err("Invalid mint address".to_string());
        }
        if request.mint_authority.trim().is_empty() {
            return Err("Invalid mint authority address".to_string());
        }
        
        let mint_pubkey = Pubkey::from_str(&request.mint)
            .map_err(|_| "Invalid mint address".to_string())?;
        
        let mint_authority = Pubkey::from_str(&request.mint_authority)
            .map_err(|_| "Invalid mint authority address".to_string())?;

    
        let instruction = token_instruction::initialize_mint(
            &spl_token::id(),
            &mint_pubkey,
            &mint_authority,
            Some(&mint_authority), 
            request.decimals,
        ).map_err(|e| format!("Failed to create mint instruction: {}", e))?;

        
        Ok(InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter().map(|acc| AccountMeta {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        })
    }

    
    pub fn create_mint_instruction(request: &MintTokenRequest) -> Result<InstructionData, String> {
     
        if request.mint.trim().is_empty() {
            return Err("Invalid mint address".to_string());
        }
        if request.destination.trim().is_empty() {
            return Err("Invalid destination address".to_string());
        }
        if request.authority.trim().is_empty() {
            return Err("Invalid authority address".to_string());
        }
        if request.amount == 0 {
            return Err("Amount must be greater than 0".to_string());
        }
        
        let mint_pubkey = Pubkey::from_str(&request.mint)
            .map_err(|_| "Invalid mint address".to_string())?;
        
        let destination_pubkey = Pubkey::from_str(&request.destination)
            .map_err(|_| "Invalid destination address".to_string())?;
        
        let authority_pubkey = Pubkey::from_str(&request.authority)
            .map_err(|_| "Invalid authority address".to_string())?;

       
        let destination_ata = get_associated_token_address(
            &destination_pubkey,
            &mint_pubkey,
        );

        let instruction = token_instruction::mint_to(
            &spl_token::id(),
            &mint_pubkey,
            &destination_ata,
            &authority_pubkey,
            &[],
            request.amount,
        ).map_err(|e| format!("Failed to create mint instruction: {}", e))?;

     
        Ok(InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter().map(|acc| AccountMeta {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect(),
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        })
    }

    
    pub fn sign_message(message: &str, secret_key: &str) -> Result<(String, String), String> {
        
        if message.trim().is_empty() {
            return Err("Message cannot be empty".to_string());
        }
        if secret_key.trim().is_empty() {
            return Err("Secret key cannot be empty".to_string());
        }
        
        let keypair_bytes = bs58::decode(secret_key)
            .into_vec()
            .map_err(|_| "Invalid secret key format".to_string())?;
        
        let keypair = Keypair::try_from(&keypair_bytes[..])
            .map_err(|_| "Invalid keypair".to_string())?;

        let message_bytes = message.as_bytes();
        let signature = keypair.sign_message(message_bytes);

     
        Ok((
            general_purpose::STANDARD.encode(signature.as_ref()),
            keypair.pubkey().to_string(),
        ))
    }

    
    pub fn verify_message(message: &str, signature_b64: &str, pubkey_str: &str) -> Result<bool, String> {
       
        if message.trim().is_empty() {
            return Err("Message cannot be empty".to_string());
        }
        if signature_b64.trim().is_empty() {
            return Err("Signature cannot be empty".to_string());
        }
        if pubkey_str.trim().is_empty() {
            return Err("Public key cannot be empty".to_string());
        }
        
        let pubkey = Pubkey::from_str(pubkey_str)
            .map_err(|_| "Invalid public key".to_string())?;
        
        let signature_bytes = general_purpose::STANDARD.decode(signature_b64)
            .map_err(|_| "Invalid signature format".to_string())?;
        
        if signature_bytes.len() != 64 {
            return Ok(false);
        }

        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| "Invalid signature".to_string())?;

        let message_bytes = message.as_bytes();
        
      
        Ok(signature.verify(pubkey.as_ref(), message_bytes))
    }


    pub fn create_sol_transfer_instruction(request: &SendSolRequest) -> Result<SolTransferData, String> {
       
        if request.lamports == 0 {
            return Err("Amount must be greater than 0".to_string());
        }
        if request.from.trim().is_empty() {
            return Err("Invalid sender address".to_string());
        }
        if request.to.trim().is_empty() {
            return Err("Invalid recipient address".to_string());
        }

        let from_pubkey = Pubkey::from_str(&request.from)
            .map_err(|_| "Invalid sender address".to_string())?;
        
        let to_pubkey = Pubkey::from_str(&request.to)
            .map_err(|_| "Invalid recipient address".to_string())?;

        let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, request.lamports);

       
        Ok(SolTransferData {
            program_id: instruction.program_id.to_string(),
            accounts: vec![
                instruction.accounts[0].pubkey.to_string(), 
                instruction.accounts[1].pubkey.to_string(), 
            ],
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        })
    }

  
    pub fn create_token_transfer_instruction(request: &SendTokenRequest) -> Result<TokenTransferData, String> {
      
        if request.amount == 0 {
            return Err("Amount must be greater than 0".to_string());
        }
        if request.mint.trim().is_empty() {
            return Err("Invalid mint address".to_string());
        }
        if request.owner.trim().is_empty() {
            return Err("Invalid owner address".to_string());
        }
        if request.destination.trim().is_empty() {
            return Err("Invalid destination address".to_string());
        }

        let mint_pubkey = Pubkey::from_str(&request.mint)
            .map_err(|_| "Invalid mint address".to_string())?;
        
        let owner_pubkey = Pubkey::from_str(&request.owner)
            .map_err(|_| "Invalid owner address".to_string())?;
        
        let destination_pubkey = Pubkey::from_str(&request.destination)
            .map_err(|_| "Invalid destination address".to_string())?;

       
        let source_ata = get_associated_token_address(
            &owner_pubkey,
            &mint_pubkey,
        );

        let destination_ata = get_associated_token_address(
            &destination_pubkey,
            &mint_pubkey,
        );

        let instruction = token_instruction::transfer(
            &spl_token::id(),
            &source_ata,
            &destination_ata,
            &owner_pubkey,
            &[],
            request.amount,
        ).map_err(|e| format!("Failed to create transfer instruction: {}", e))?;

       
        Ok(TokenTransferData {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter().map(|acc| TokenTransferAccount {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
            }).collect(),
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        })
    }
}