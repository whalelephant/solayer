use {
    borsh::BorshSerialize,
    // system_instruction::create_account,
    clap::{
        crate_description, crate_name, crate_version, value_t, App, AppSettings, Arg, ArgMatches,
        SubCommand,
    },
    solana_clap_utils::{
        fee_payer::fee_payer_arg,
        input_parsers::{keypair_of, pubkey_of, value_of},
        input_validators::{is_keypair, is_url},
        keypair::signer_from_path,
    },
    solana_client::rpc_client::RpcClient,
    solana_program::{instruction::Instruction, pubkey::Pubkey},
    solana_sdk::{
        commitment_config::CommitmentConfig,
        signature::{Signature, Signer},
        signer::keypair::Keypair,
        transaction::Transaction,
    },
    solayer::instruction::SolayerInstruction,
    std::process::exit,
};

// Unsure where this comes from
const SOLAYER_PROGRAM_ID: &str = "9QLhBMthk61wQsrUdG1TpFwx8dykpopAc6xkaRJX7yjQ";

type Error = Box<dyn std::error::Error>;
type CommandResult = Result<(), Error>;

pub struct Config {
    rpc_client: RpcClient,
    fee_payer: Box<dyn Signer>,
    solayer_program_id: Pubkey,
}

fn main() {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("json_rpc_url")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .validator(is_url)
                .default_value("http://127.0.0.1:8899")
                .help("JSON RPC URL for the cluster.  Default from the configuration file."),
        )
        .arg(
            Arg::with_name("solayer_program_id")
                .long("solayer deployed program id")
                .value_name("PUBKEY")
                .takes_value(true)
                .default_value(SOLAYER_PROGRAM_ID)
                .help("Solayer program id deployed onchain"),
        )
        .arg(fee_payer_arg().short("p").global(true))
        .subcommand(
            SubCommand::with_name("sign_and_verify")
                .about("Sign offchain and verify a Ed25519 Sigature onchain")
                .arg(
                    Arg::with_name("keypair")
                        .long("keypair")
                        .validator(is_keypair)
                        .value_name("KEYPAIR")
                        .takes_value(true)
                        .required(true)
                        .help("Signer keypair path"),
                )
                .arg(
                    Arg::with_name("msg")
                        .long("msg")
                        .value_name("STRING")
                        .takes_value(true)
                        .required(true)
                        .help("Message to Sign"),
                ),
        )
        .get_matches();
    let mut wallet_manager = None;
    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };
        let json_rpc_url = value_t!(matches, "json_rpc_url", String)
            .unwrap_or_else(|_| cli_config.json_rpc_url.clone());

        let fee_payer = signer_from_path(
            &matches,
            matches
                .value_of("fee_payer")
                .unwrap_or(&cli_config.keypair_path),
            "fee_payer",
            &mut wallet_manager,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });

        let solayer_program_id =
            Pubkey::new(matches.value_of("solayer_program_id").unwrap().as_bytes());

        Config {
            rpc_client: RpcClient::new_with_commitment(json_rpc_url, CommitmentConfig::confirmed()),
            fee_payer,
            solayer_program_id,
        }
    };

    let _ = match matches.subcommand() {
        ("sign_and_verify", Some(arg_matches)) => {
            let keypair = keypair_of(arg_matches, "keypair").unwrap();
            let msg_str: String = value_of(arg_matches, "msg").unwrap();
            let msg = msg_str.as_bytes();
            let signature = keypair.sign_message(msg);
            command_verify(&config, keypair, signature, msg)
        }
        _ => unreachable!(),
    }
    .map_err(|err| {
        eprintln!("{}", err);
        exit(1);
    });
}

pub fn command_verify(
    config: &Config,
    keypair: Keypair,
    signature: Signature,
    message: &[u8],
) -> CommandResult {
    let ix = Instruction {
        program_id: config.solayer_program_id,
        accounts: vec![],
        data: SolayerInstruction::SigVerify {
            pubkey: keypair.pubkey(),
            signature: signature.as_ref().to_vec(),
            message: message.to_vec(),
        }
        .try_to_vec()?,
    };

    let transaction = Transaction::new_with_payer(&[ix], Some(&config.fee_payer.pubkey()));

    send_transaction(config, transaction)?;
    Ok(())
}

fn send_transaction(
    config: &Config,
    transaction: Transaction,
) -> solana_client::client_error::Result<()> {
    let signature = config
        .rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)?;
    println!("Signature: {}", signature);
    Ok(())
}
